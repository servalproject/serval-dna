/*
 Copyright (C) 2012-2013 Serval Project Inc.
 
 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License
 as published by the Free Software Foundation; either version 2
 of the License, or (at your option) any later version.
 
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */


#include <assert.h>
#include "serval.h"
#include "conf.h"
#include "overlay_buffer.h"
#include "overlay_interface.h"
#include "overlay_packet.h"
#include "radio_link.h"
#include "str.h"
#include "strbuf.h"
#include "route_link.h"

typedef struct overlay_txqueue {
  struct overlay_frame *first;
  struct overlay_frame *last;
  int length; /* # frames in queue */
  int maxLength; /* max # frames in queue before we consider ourselves congested */
  int small_packet_grace_interval;
  /* Latency target in ms for this traffic class.
   Frames older than the latency target will get dropped. */
  int latencyTarget;
} overlay_txqueue;

overlay_txqueue overlay_tx[OQ_MAX];

// short lived data while we are constructing an outgoing packet
struct outgoing_packet{
  struct network_destination *destination;
  int seq;
  int packet_version;
  int header_length;
  struct overlay_buffer *buffer;
  struct decode_context context;
};

#define SMALL_PACKET_SIZE (400)

int32_t mdp_sequence=0;
struct sched_ent next_packet;
struct profile_total send_packet;

static void overlay_send_packet(struct sched_ent *alarm);
static int overlay_calc_queue_time(struct overlay_frame *frame);

int overlay_queue_init(){
  /* Set default congestion levels for queues */
  int i;
  for(i=0;i<OQ_MAX;i++) {
    overlay_tx[i].maxLength=100;
    overlay_tx[i].latencyTarget=0; // no QOS time limit by default, depend on per destination timeouts
    overlay_tx[i].small_packet_grace_interval = 5;
  }
  /* expire voice/video call packets much sooner, as they just aren't any use if late */
  overlay_tx[OQ_ISOCHRONOUS_VOICE].maxLength=20;
  overlay_tx[OQ_ISOCHRONOUS_VOICE].latencyTarget=200;

  overlay_tx[OQ_ISOCHRONOUS_VIDEO].latencyTarget=200;

  overlay_tx[OQ_OPPORTUNISTIC].small_packet_grace_interval = 100;
  return 0;
}

/* remove and free a payload from the queue */
static struct overlay_frame *
overlay_queue_remove(overlay_txqueue *queue, struct overlay_frame *frame){
  struct overlay_frame *prev = frame->prev;
  struct overlay_frame *next = frame->next;
  if (prev)
    prev->next = next;
  else if(frame == queue->first)
    queue->first = next;
  
  if (next)
    next->prev = prev;
  else if(frame == queue->last)
    queue->last = prev;
  
  queue->length--;
  
  while(frame->destination_count>0)
    release_destination_ref(frame->destinations[--frame->destination_count].destination);
    
  op_free(frame);
  
  return next;
}

#if 0 // unused
static int
overlay_queue_dump(overlay_txqueue *q)
{
  strbuf b = strbuf_alloca(8192);
  struct overlay_frame *f;
  strbuf_sprintf(b,"overlay_txqueue @ 0x%p\n",q);
  strbuf_sprintf(b,"  length=%d\n",q->length);
  strbuf_sprintf(b,"  maxLenght=%d\n",q->maxLength);
  strbuf_sprintf(b,"  latencyTarget=%d milli-seconds\n",q->latencyTarget);
  strbuf_sprintf(b,"  first=%p\n",q->first);
  f=q->first;
  while(f) {
    strbuf_sprintf(b,"    %p: ->next=%p, ->prev=%p\n",
		   f,f->next,f->prev);
    if (f==f->next) {
      strbuf_sprintf(b,"        LOOP!\n"); break;
    }
    f=f->next;
  }
  strbuf_sprintf(b,"  last=%p\n",q->last);
  f=q->last;
  while(f) {
    strbuf_sprintf(b,"    %p: ->next=%p, ->prev=%p\n",
		   f,f->next,f->prev);
    if (f==f->prev) {
      strbuf_sprintf(b,"        LOOP!\n"); break;
    }
    f=f->prev;
  }
  _DEBUG(strbuf_str(b));
  return 0;
}
#endif

int overlay_queue_remaining(int queue){
  if (queue<0 || queue>=OQ_MAX)
    return -1;
  return overlay_tx[queue].maxLength - overlay_tx[queue].length;
}

int _overlay_payload_enqueue(struct __sourceloc __whence, struct overlay_frame *p)
{
  /* Add payload p to queue q.
   
   Queues get scanned from first to last, so we should append new entries
   on the end of the queue.
   
   Complain if there are too many frames in the queue.
   */
  
  assert(p != NULL);
  assert(p->queue < OQ_MAX);
  assert(p->payload != NULL);
  p->whence = __whence;
  overlay_txqueue *queue = &overlay_tx[p->queue];

  
  if (ob_overrun(p->payload))
    return WHY("Packet content overrun -- not queueing");
  
  if (ob_position(p->payload) >= MDP_OVERLAY_MTU)
    FATALF("Queued packet len %u is too big", ob_position(p->payload));

  if (queue->length>=queue->maxLength) 
    return WHYF("Queue #%d congested (size = %d)",p->queue,queue->maxLength);
    
  // it should be safe to try sending all packets with an mdp sequence
  if (p->packet_version<=0)
    p->packet_version=1;

  if (IF_DEBUG(verbose))
    DEBUGF(overlayframes, "Enqueue packet to %s",
	   p->destination?alloca_tohex_sid_t_trunc(p->destination->sid, 14): "broadcast");
  
  if (p->destination_count==0){
    if (!p->destination){
      // hook to allow for flooding via olsr
      olsr_send(p);
      
      link_add_destinations(p);

      // just drop it now
      if (p->destination_count == 0){
	DEBUGF(mdprequests, "Not transmitting, as we have nowhere to send it");
	// free the packet and return success.
	op_free(p);
	return 0;
      }
    }
    
    // allow the packet to be resent
    if (p->resend == 0)
      p->resend = 1;
  }else{
    p->manual_destinations = 1;
  }
  
  int i=0;
  for (i=0;i<p->destination_count;i++){
    p->destinations[i].sent_sequence=-1;
    if (IF_DEBUG(verbose))
      DEBUGF(overlayframes, "Sending %s on interface %s", 
	     p->destinations[i].destination->unicast?"unicast":"broadcast",
	     p->destinations[i].destination->interface->name);
  }
  
  struct overlay_frame *l=queue->last;
  if (l) l->next=p;
  p->prev=l;
  p->next=NULL;
  p->enqueued_at=gettime_ms();
  p->mdp_sequence = -1;
  queue->last=p;
  if (!queue->first) queue->first=p;
  queue->length++;
  if (p->queue==OQ_ISOCHRONOUS_VOICE)
    rhizome_saw_voice_traffic();
  
  overlay_calc_queue_time(p);
  return 0;
}

static int
overlay_init_packet(struct outgoing_packet *packet, int packet_version,
		    struct network_destination *destination)
{
  packet->context.interface = destination->interface;
  if ((packet->buffer = ob_new()) == NULL)
    return -1;
  packet->packet_version = packet_version;
  packet->context.packet_version = packet_version;
  packet->destination = add_destination_ref(destination);
  if (destination->sequence_number<0)
    packet->seq=-1;
  else
    packet->seq = destination->sequence_number = (destination->sequence_number + 1) & 0xFFFF;
  ob_limitsize(packet->buffer, destination->ifconfig.mtu);
  int i = destination->interface - overlay_interfaces;
  if (overlay_packet_init_header(packet_version, destination->ifconfig.encapsulation, 
				 &packet->context, packet->buffer, 
				 destination->unicast, 
				 i, packet->seq) == -1
  ) {
    ob_free(packet->buffer);
    packet->buffer = NULL;
    return -1;
  }
  packet->header_length = ob_position(packet->buffer);
  DEBUGF(overlayframes, "Creating %d packet for interface %s, seq %d, %s", 
	 packet_version,
	 destination->interface->name, destination->sequence_number,
	 alloca_socket_address(&destination->address)
	);
  return 0;
}

int overlay_queue_schedule_next(time_ms_t next_allowed_packet){
  if (next_packet.alarm==0 || next_allowed_packet < next_packet.alarm){
    
    if (!next_packet.function){
      next_packet.function=overlay_send_packet;
      send_packet.name="overlay_send_packet";
      next_packet.stats=&send_packet;
    }
    unschedule(&next_packet);
    next_packet.alarm=next_allowed_packet;
    // small grace period, we want to read incoming IO first
    next_packet.deadline=next_allowed_packet+15;
    schedule(&next_packet);
  }
  return 0;  
}

void frame_remove_destination(struct overlay_frame *frame, int i){
  DEBUGF(overlayframes, "Remove %s destination on interface %s", 
	 frame->destinations[i].destination->unicast?"unicast":"broadcast",
	 frame->destinations[i].destination->interface->name
	);
  release_destination_ref(frame->destinations[i].destination);
  frame->destination_count --;
  if (i<frame->destination_count)
    frame->destinations[i]=frame->destinations[frame->destination_count];
}

void frame_add_destination(struct overlay_frame *frame, struct subscriber *next_hop, struct network_destination *dest){
  if ((!dest->ifconfig.send)||frame->destination_count >= MAX_PACKET_DESTINATIONS)
    return;
  
  unsigned i = frame->destination_count++;
  frame->destinations[i].destination=add_destination_ref(dest);
  frame->destinations[i].next_hop = next_hop;
  frame->destinations[i].sent_sequence=-1;
  DEBUGF(overlayframes, "Add %s destination on interface %s", 
	 frame->destinations[i].destination->unicast?"unicast":"broadcast",
	 frame->destinations[i].destination->interface->name
	);
}

// update the alarm time and return 1 if changed
static int
overlay_calc_queue_time(struct overlay_frame *frame)
{
  
  time_ms_t next_allowed_packet=0;
  // check all interfaces
  if (frame->destination_count>0){
    int i;
    for(i=0;i<frame->destination_count;i++)
    {
      if (radio_link_is_busy(frame->destinations[i].destination->interface))
	continue;
      time_ms_t next_packet = limit_next_allowed(&frame->destinations[i].destination->transfer_limit);
      if (frame->destinations[i].transmit_time){
	time_ms_t delay_until = frame->destinations[i].transmit_time + frame->destinations[i].destination->resend_delay;
	if (next_packet < delay_until)
	  next_packet = delay_until;
      }
      if (next_allowed_packet==0||next_packet < next_allowed_packet)
	next_allowed_packet = next_packet;
    }
    
    if (next_allowed_packet==0){
      return 0;
    }
  }else{
    if (!frame->destination){
      return 0;
    }
  }
  
  if (next_allowed_packet < frame->delay_until)
    next_allowed_packet = frame->delay_until;
  if (next_allowed_packet < frame->enqueued_at)
    next_allowed_packet = frame->enqueued_at;

  if (ob_position(frame->payload)<SMALL_PACKET_SIZE &&
      next_allowed_packet < frame->enqueued_at + overlay_tx[frame->queue].small_packet_grace_interval)
    next_allowed_packet = frame->enqueued_at + overlay_tx[frame->queue].small_packet_grace_interval;

  overlay_queue_schedule_next(next_allowed_packet);
  
  return 0;
}

static void
overlay_stuff_packet(struct outgoing_packet *packet, overlay_txqueue *queue, time_ms_t now, strbuf debug){
  struct overlay_frame *frame = queue->first;
  
  // TODO stop when the packet is nearly full?
  while(frame){
    if (queue->latencyTarget!=0 && frame->enqueued_at + queue->latencyTarget < now){
      DEBUGF(ack,"Dropping frame (%p) type %x (length %zu) for %s due to expiry timeout", 
	     frame, frame->type, frame->payload->checkpointLength,
	     frame->destination?alloca_tohex_sid_t(frame->destination->sid):"All"
	    );
      frame = overlay_queue_remove(queue, frame);
      continue;
    }
    
    /* Note, once we queue a broadcast packet we are currently 
     * committed to sending it to every destination, 
     * even if we hear it from somewhere else in the mean time
     */
    
    // ignore payloads that are waiting for ack / nack resends
    if (frame->delay_until > now)
      goto skip;

    if (packet->buffer && packet->destination->ifconfig.encapsulation==ENCAP_SINGLE)
      goto skip;
      
    // quickly skip payloads that have no chance of fitting
    if (packet->buffer && ob_position(frame->payload) > ob_remaining(packet->buffer))
      goto skip;
    
    if (!frame->manual_destinations)
      link_add_destinations(frame);
    
    if(frame->mdp_sequence != -1 && ((mdp_sequence - frame->mdp_sequence)&0xFFFF) >= 64){
      // too late, we've sent too many packets for the next hop to correctly de-duplicate
      DEBUGF(overlayframes, "Retransmition of frame %p mdp seq %d, is too late to be de-duplicated", 
	     frame, frame->mdp_sequence);
      frame = overlay_queue_remove(queue, frame);
      continue;
    }
    
    int destination_index=-1;
    {
      int i;
      for (i=frame->destination_count -1;i>=0;i--){
	struct network_destination *dest = frame->destinations[i].destination;
	if (!dest)
	  FATALF("Destination %d is NULL", i);
	if (!dest->interface)
	  FATALF("Destination interface %d is NULL", i);
	if (dest->interface->state!=INTERFACE_STATE_UP){
	  // remove this destination
	  frame_remove_destination(frame, i);
	  continue;
	}
	if (frame->enqueued_at + dest->ifconfig.transmit_timeout_ms < now){
	  DEBUGF(ack,"Dropping %p, %s packet destination for %s sent w. seq %d, %dms ago", 
	    frame, dest->unicast?"unicast":"broadcast",
	    frame->whence.function, frame->destinations[i].sent_sequence,
	    (int)(gettime_ms() - frame->destinations[i].transmit_time));
	  frame_remove_destination(frame, i);
	  continue;
	}
	if (ob_position(frame->payload) > (unsigned)dest->ifconfig.mtu){
	  WARNF("Skipping packet destination as size %zu > destination mtu %zd", 
	  ob_position(frame->payload), dest->ifconfig.mtu);
	  frame_remove_destination(frame, i);
	  continue;
	}
	// degrade packet version if required to reach the destination
	if (frame->destinations[i].next_hop 
	  && frame->packet_version > frame->destinations[i].next_hop->max_packet_version)
	  frame->packet_version = frame->destinations[i].next_hop->max_packet_version;
	
	if (frame->destinations[i].transmit_time && 
	  frame->destinations[i].transmit_time + frame->destinations[i].destination->resend_delay > now)
	  continue;
	
	if (packet->buffer){
	  if (frame->packet_version!=packet->packet_version)
	    continue;
	  
	  // is this packet going our way?
	  if (dest==packet->destination){
	    destination_index=i;
	    break;
	  }
	}else{
	  // skip this interface if the stream tx buffer has data
	  if (radio_link_is_busy(dest->interface))
	    continue;
	    
	  // can we send a packet to this destination now?
	  if (limit_is_allowed(&dest->transfer_limit))
	    continue;
      
	  // send a packet to this destination
	  if (frame->source_full)
	    get_my_subscriber()->send_full=1;
	  if (overlay_init_packet(packet, frame->packet_version, dest) != -1) {
	    if (debug){
	      strbuf_sprintf(debug, "building packet %s %s %d [", 
		packet->destination->interface->name, 
		alloca_socket_address(&packet->destination->address),
		packet->seq);
	    }
	    destination_index=i;
	    frame->destinations[i].sent_sequence = dest->sequence_number;
	    break;
	  }
	}
      }
    }
    
    if (frame->destination_count==0){
      frame = overlay_queue_remove(queue, frame);
      continue;
    }
    
    if (destination_index==-1)
      goto skip;
    
    if (frame->send_hook){
      // last minute check if we really want to send this frame, or track when we sent it
      if (frame->send_hook(frame, packet->destination, packet->seq, frame->send_context)){
        // drop packet
        frame = overlay_queue_remove(queue, frame);
        continue;
      }
    }
    
    if (frame->mdp_sequence == -1){
      frame->mdp_sequence = mdp_sequence = (mdp_sequence+1)&0xFFFF;
    }
    
    char will_retransmit=1;
    if (frame->packet_version<1 || frame->resend<=0 || packet->seq==-1)
      will_retransmit=0;
    
    if (overlay_frame_append_payload(&packet->context, packet->destination->ifconfig.encapsulation, frame, 
	frame->destinations[destination_index].next_hop, packet->buffer, will_retransmit)){
      // payload was not queued, delay the next attempt slightly
      frame->delay_until = now + 5;
      goto skip;
    }
    
    frame->transmit_count++;
    
    {
      struct packet_destination *dest = &frame->destinations[destination_index];
      dest->sent_sequence = dest->destination->sequence_number;
      dest->transmit_time = now;
      if (debug)
	strbuf_sprintf(debug, "%d(%s), ", frame->mdp_sequence, frame->whence.function);
      DEBUGF(overlayframes, "Appended payload %p, %d type %x len %zd for %s via %s", 
	     frame, frame->mdp_sequence,
	     frame->type, ob_position(frame->payload),
	     frame->destination?alloca_tohex_sid_t(frame->destination->sid):"All",
	     dest->next_hop?alloca_tohex_sid_t(dest->next_hop->sid):alloca_tohex(frame->broadcast_id.id, BROADCAST_LEN)
	    );
    }
    
    
    // dont retransmit if we aren't sending sequence numbers, or we've been asked not to
    if (!will_retransmit){
      DEBUGF(overlayframes, "Not waiting for retransmission (%d, %d, %d)", frame->packet_version, frame->resend, packet->seq);
      frame_remove_destination(frame, destination_index);
      if (frame->destination_count==0){
	frame = overlay_queue_remove(queue, frame);
	continue;
      }
    }
    
  skip:
    // if we can't send the payload now, check when we should try next
    overlay_calc_queue_time(frame);
    frame = frame->next;
  }
}

// fill a packet from our outgoing queues and send it
static int
overlay_fill_send_packet(struct outgoing_packet *packet, time_ms_t now, strbuf debug) {
  IN();
  int i;
  int ret=0;
    
  // while we're looking at queues, work out when to schedule another packet
  unschedule(&next_packet);
  next_packet.alarm=0;
  next_packet.deadline=0;
  
  for (i=0;i<OQ_MAX;i++){
    overlay_txqueue *queue=&overlay_tx[i];
    
    overlay_stuff_packet(packet, queue, now, debug);
  }
  
  if(packet->buffer){
    if (debug){
      strbuf_sprintf(debug, "]");
      _DEBUGF("%s", strbuf_str(debug));
    }
      
    overlay_broadcast_ensemble(packet->destination, packet->buffer);
    ret=1;
  }
  if (packet->destination)
    release_destination_ref(packet->destination);
  RETURN(ret);
  OUT();
}

// when the queue timer elapses, send a packet
static void overlay_send_packet(struct sched_ent *UNUSED(alarm))
{
  struct outgoing_packet packet;
  bzero(&packet, sizeof(struct outgoing_packet));
  packet.seq=-1;
  strbuf debug = IF_DEBUG(packets_sent) ? strbuf_alloca(256) : NULL;
  overlay_fill_send_packet(&packet, gettime_ms(), debug);
}

int overlay_send_tick_packet(struct network_destination *destination)
{
  struct outgoing_packet packet;
  bzero(&packet, sizeof(struct outgoing_packet));
  if (overlay_init_packet(&packet, 0, destination) != -1){
    strbuf debug = NULL;
    if (IF_DEBUG(packets_sent)) {
      debug = strbuf_alloca(256);
      strbuf_sprintf(debug, "building packet %s %s %d [", 
	packet.destination->interface->name, 
	alloca_socket_address(&packet.destination->address),
	packet.seq);
    }
    overlay_fill_send_packet(&packet, gettime_ms(), debug);
  }
  return 0;
}

// de-queue all packets that have been sent to this subscriber & have arrived.
int overlay_queue_ack(struct subscriber *neighbour, struct network_destination *destination, uint32_t ack_mask, int ack_seq)
{
  int i, j;
  time_ms_t now = gettime_ms();
  int rtt=0;
  
  for (i=0;i<OQ_MAX;i++){
    struct overlay_frame *frame = overlay_tx[i].first;

    while(frame){
      
      for (j=frame->destination_count -1;j>=0;j--)
	if (frame->destinations[j].destination==destination)
	  break;
	  
      if (j>=0){
	int frame_seq = frame->destinations[j].sent_sequence;
	if (frame_seq >=0 && (frame->destinations[j].next_hop == neighbour || !frame->destination)){
	  int seq_delta = (ack_seq - frame_seq)&0xFF;
	  char acked = (seq_delta==0 || (seq_delta <= 32 && ack_mask&((uint32_t)1<<(seq_delta-1))))?1:0;

	  if (acked){
	    int this_rtt = now - frame->destinations[j].transmit_time;
	    // if we're on a fake network, the actual rtt can be unrealistic
	    if (this_rtt < 10)
	      this_rtt = 10;
	    if (!rtt || this_rtt < rtt)
	      rtt = this_rtt;
	    
	    DEBUGF(ack, "DROPPED DUE TO ACK: Packet %p to %s sent by seq %d, acked with seq %d", 
		   frame, alloca_tohex_sid_t(neighbour->sid), frame_seq, ack_seq);
		
	    // drop packets that don't need to be retransmitted
	    if (frame->destination || frame->destination_count<=1){
	      frame = overlay_queue_remove(&overlay_tx[i], frame);
	      continue;
	    }
	    frame_remove_destination(frame, j);
	    
	  }else if (seq_delta < 128 && frame->destination && frame->delay_until>now){
	    // retransmit asap
	    DEBUGF(ack, "RE-TX DUE TO NACK: Requeue packet %p to %s sent by seq %d due to ack of seq %d", frame, alloca_tohex_sid_t(neighbour->sid), frame_seq, ack_seq);
	    frame->delay_until = now;
	    overlay_calc_queue_time(frame);
	  }
	}
      }
      
      frame = frame->next;
    }
  }
  
  if (rtt){
    if (!destination->min_rtt || rtt < destination->min_rtt){
      destination->min_rtt = rtt;
      int delay = rtt * 2 + 40;
      if (delay < destination->resend_delay){
	destination->resend_delay = delay;
	DEBUGF(linkstate, "Adjusting resend delay to %d", destination->resend_delay);
      }
    }
    if (!destination->max_rtt || rtt > destination->max_rtt)
      destination->max_rtt = rtt;
  }
  return 0;
}
