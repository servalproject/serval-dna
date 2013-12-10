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
#include "overlay_packet.h"
#include "radio_link.h"
#include "str.h"
#include "strbuf.h"

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
    overlay_tx[i].latencyTarget=1000; /* Keep packets in queue for 1 second by default */
    overlay_tx[i].small_packet_grace_interval = 5;
  }
  /* expire voice/video call packets much sooner, as they just aren't any use if late */
  overlay_tx[OQ_ISOCHRONOUS_VOICE].maxLength=20;
  overlay_tx[OQ_ISOCHRONOUS_VOICE].latencyTarget=200;

  overlay_tx[OQ_ISOCHRONOUS_VIDEO].latencyTarget=200;

  overlay_tx[OQ_OPPORTUNISTIC].small_packet_grace_interval = 20;
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
  DEBUG(strbuf_str(b));
  return 0;
}
#endif

int overlay_queue_remaining(int queue){
  if (queue<0 || queue>=OQ_MAX)
    return -1;
  return overlay_tx[queue].maxLength - overlay_tx[queue].length;
}

int overlay_payload_enqueue(struct overlay_frame *p)
{
  /* Add payload p to queue q.
   
   Queues get scanned from first to last, so we should append new entries
   on the end of the queue.
   
   Complain if there are too many frames in the queue.
   */
  
  assert(p != NULL);
  assert(p->queue < OQ_MAX);
  assert(p->payload != NULL);
  overlay_txqueue *queue = &overlay_tx[p->queue];

  if (config.debug.packettx)
    DEBUGF("Enqueuing packet for %s* (q[%d].length = %d)",
	   p->destination?alloca_tohex_sid_t_trunc(p->destination->sid, 14): alloca_tohex(p->broadcast_id.id, BROADCAST_LEN),
	   p->queue, queue->length);
  
  if (ob_overrun(p->payload))
    return WHY("Packet content overrun -- not queueing");
  
  if (ob_position(p->payload) >= MDP_MTU)
    FATAL("Queued packet is too big");

  if (queue->length>=queue->maxLength) 
    return WHYF("Queue #%d congested (size = %d)",p->queue,queue->maxLength);
    
  // it should be safe to try sending all packets with an mdp sequence
  if (p->packet_version<=0)
    p->packet_version=1;

  if (config.debug.verbose && config.debug.overlayframes)
    DEBUGF("Enqueue packet %p", p);
  
  if (p->destination_count==0){
    if (!p->destination){
      // hook to allow for flooding via olsr
      olsr_send(p);
      
      link_add_destinations(p);

      // just drop it now
      if (p->destination_count == 0){
        if (config.debug.verbose && config.debug.overlayframes)
	  DEBUGF("Not transmitting, as we have no neighbours on any interface");
	return -1;
      }
    }
    
    // allow the packet to be resent
    if (p->resend == 0)
      p->resend = 1;
  }
  
  int i=0;
  for (i=0;i<p->destination_count;i++){
    p->destinations[i].sent_sequence=-1;
    if (config.debug.verbose && config.debug.overlayframes)
      DEBUGF("Sending %s on interface %s", 
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
  ob_limitsize(packet->buffer, destination->interface->mtu);
  int i = destination->interface - overlay_interfaces;
  if (overlay_packet_init_header(packet_version, destination->encapsulation, 
				 &packet->context, packet->buffer, 
				 destination->unicast, 
				 i, packet->seq) == -1
  ) {
    ob_free(packet->buffer);
    packet->buffer = NULL;
    return -1;
  }
  packet->header_length = ob_position(packet->buffer);
  if (config.debug.overlayframes)
    DEBUGF("Creating %d packet for interface %s, seq %d, %s", 
      packet_version,
      destination->interface->name, destination->sequence_number,
      destination->unicast?"unicast":"broadcast");
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

static void remove_destination(struct overlay_frame *frame, int i){
  release_destination_ref(frame->destinations[i].destination);
  frame->destination_count --;
  if (i<frame->destination_count)
    frame->destinations[i]=frame->destinations[frame->destination_count];
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
overlay_stuff_packet(struct outgoing_packet *packet, overlay_txqueue *queue, time_ms_t now){
  struct overlay_frame *frame = queue->first;
  
  // TODO stop when the packet is nearly full?
  while(frame){
    if (frame->enqueued_at + queue->latencyTarget < now){
      if (config.debug.overlayframes)
	DEBUGF("Dropping frame type %x (length %zu) for %s due to expiry timeout", 
	       frame->type, frame->payload->checkpointLength,
	       frame->destination?alloca_tohex_sid_t(frame->destination->sid):"All");
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

    if (packet->buffer && packet->destination->encapsulation==ENCAP_SINGLE)
      goto skip;
      
    // quickly skip payloads that have no chance of fitting
    if (packet->buffer && ob_limit(frame->payload) > ob_remaining(packet->buffer))
      goto skip;
    
    if (frame->destination_count==0 && frame->destination){
      link_add_destinations(frame);
      
      int i=0;
      for (i=0;i<frame->destination_count;i++){
	frame->destinations[i].sent_sequence=-1;
	if (config.debug.verbose && config.debug.overlayframes)
	  DEBUGF("Sending %s on interface %s", 
	      frame->destinations[i].destination->unicast?"unicast":"broadcast",
	      frame->destinations[i].destination->interface->name);
      }
      
      // degrade packet version if required to reach the destination
      if (frame->packet_version > frame->next_hop->max_packet_version)
	frame->packet_version = frame->next_hop->max_packet_version;
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
	  remove_destination(frame, i);
	  continue;
	}
	
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
	    
	  // can we send a packet on this interface now?
	  if (limit_is_allowed(&dest->transfer_limit))
	    continue;
      
	  // send a packet to this destination
	  if (frame->source_full)
	    my_subscriber->send_full=1;
	  if (overlay_init_packet(packet, frame->packet_version, dest) != -1) {
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
      if (frame->send_hook(frame, packet->seq, frame->send_context)){
        // drop packet
        frame = overlay_queue_remove(queue, frame);
        continue;
      }
    }

    if (frame->mdp_sequence == -1){
      frame->mdp_sequence = mdp_sequence = (mdp_sequence+1)&0xFFFF;
    }else if(((mdp_sequence - frame->mdp_sequence)&0xFFFF) >= 64){
      // too late, we've sent too many packets for the next hop to correctly de-duplicate
      if (config.debug.overlayframes)
        DEBUGF("Retransmition of frame %p mdp seq %d, is too late to be de-duplicated", 
	  frame, frame->mdp_sequence);
      frame = overlay_queue_remove(queue, frame);
      continue;
    }
    
    char will_retransmit=1;
    if (frame->packet_version<1 || frame->resend<=0 || packet->seq==-1)
      will_retransmit=0;
    
    if (overlay_frame_append_payload(&packet->context, packet->destination->encapsulation, frame, packet->buffer, will_retransmit)){
      // payload was not queued, delay the next attempt slightly
      frame->delay_until = now + 5;
      goto skip;
    }
    
    {
      struct packet_destination *dest = &frame->destinations[destination_index];
      dest->sent_sequence = dest->destination->sequence_number;
      dest->transmit_time = now;
    }
    
    frame->transmit_count++;
    
    if (config.debug.overlayframes){
      DEBUGF("Appended payload %p, %d type %x len %d for %s via %s", 
	     frame, frame->mdp_sequence,
	     frame->type, ob_position(frame->payload),
	     frame->destination?alloca_tohex_sid_t(frame->destination->sid):"All",
	     frame->next_hop?alloca_tohex_sid_t(frame->next_hop->sid):alloca_tohex(frame->broadcast_id.id, BROADCAST_LEN));
    }
    
    // dont retransmit if we aren't sending sequence numbers, or we've been asked not to
    if (!will_retransmit){
      if (config.debug.overlayframes)
	DEBUGF("Not waiting for retransmission (%d, %d, %d)", frame->packet_version, frame->resend, packet->seq);
      remove_destination(frame, destination_index);
      if (frame->destination_count==0){
	frame = overlay_queue_remove(queue, frame);
	continue;
      }
    }
    
    // TODO recalc route on retransmittion??
    
  skip:
    // if we can't send the payload now, check when we should try next
    overlay_calc_queue_time(frame);
    frame = frame->next;
  }
}

// fill a packet from our outgoing queues and send it
static int
overlay_fill_send_packet(struct outgoing_packet *packet, time_ms_t now) {
  IN();
  int i;
  int ret=0;
  // while we're looking at queues, work out when to schedule another packet
  unschedule(&next_packet);
  next_packet.alarm=0;
  next_packet.deadline=0;
  
  for (i=0;i<OQ_MAX;i++){
    overlay_txqueue *queue=&overlay_tx[i];
    
    overlay_stuff_packet(packet, queue, now);
  }
  
  if(packet->buffer){
    if (config.debug.packetconstruction)
      ob_dump(packet->buffer,"assembled packet");
      
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
  overlay_fill_send_packet(&packet, gettime_ms());
}

int overlay_send_tick_packet(struct network_destination *destination)
{
  struct outgoing_packet packet;
  bzero(&packet, sizeof(struct outgoing_packet));
  if (overlay_init_packet(&packet, 0, destination) != -1)
    overlay_fill_send_packet(&packet, gettime_ms());
  return 0;
}

// de-queue all packets that have been sent to this subscriber & have arrived.
int overlay_queue_ack(struct subscriber *neighbour, struct network_destination *destination, uint32_t ack_mask, int ack_seq)
{
  int i, j;
  time_ms_t now = gettime_ms();
  for (i=0;i<OQ_MAX;i++){
    struct overlay_frame *frame = overlay_tx[i].first;

    while(frame){
      
      for (j=frame->destination_count -1;j>=0;j--)
	if (frame->destinations[j].destination==destination)
	  break;
	  
      if (j>=0){
	int frame_seq = frame->destinations[j].sent_sequence;
	if (frame_seq >=0 && (frame->next_hop == neighbour || !frame->destination)){
	  int seq_delta = (ack_seq - frame_seq)&0xFF;
	  char acked = (seq_delta==0 || (seq_delta <= 32 && ack_mask&(1<<(seq_delta-1))))?1:0;

	  if (acked){
	    int rtt = now - frame->destinations[j].transmit_time;
	    if (!destination->min_rtt || rtt < destination->min_rtt){
	      destination->min_rtt = rtt;
	      int delay = rtt * 2 + 40;
	      if (delay < destination->resend_delay){
		destination->resend_delay = delay;
		if (config.debug.linkstate)
		  DEBUGF("Adjusting resend delay to %d", destination->resend_delay);
	      }
	    }
	    if (!destination->max_rtt || rtt > destination->max_rtt)
	      destination->max_rtt = rtt;
	    
	    if (config.debug.ack)
	      DEBUGF("DROPPED DUE TO ACK: Packet %p to %s sent by seq %d, acked with seq %d", 
		frame, alloca_tohex_sid_t(neighbour->sid), frame_seq, ack_seq);
		
	    // drop packets that don't need to be retransmitted
	    if (frame->destination || frame->destination_count<=1){
	      frame = overlay_queue_remove(&overlay_tx[i], frame);
	      continue;
	    }
	    remove_destination(frame, j);
	    
	  }else if (seq_delta < 128 && frame->destination && frame->delay_until>now){
	    // retransmit asap
	    if (config.debug.ack)
	      DEBUGF("RE-TX DUE TO NACK: Requeue packet %p to %s sent by seq %d due to ack of seq %d", frame, alloca_tohex_sid_t(neighbour->sid), frame_seq, ack_seq);
	    frame->delay_until = now;
	    overlay_calc_queue_time(frame);
	  }
	}
      }
      
      frame = frame->next;
    }
  }
  return 0;
}
