/*
 Copyright (C) 2012 Serval Project Inc
 
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


#include "serval.h"
#include "conf.h"
#include "overlay_buffer.h"
#include "overlay_packet.h"
#include "str.h"
#include "strbuf.h"

typedef struct overlay_txqueue {
  struct overlay_frame *first;
  struct overlay_frame *last;
  int length; /* # frames in queue */
  int maxLength; /* max # frames in queue before we consider ourselves congested */
  
  /* Latency target in ms for this traffic class.
   Frames older than the latency target will get dropped. */
  int latencyTarget;
} overlay_txqueue;

overlay_txqueue overlay_tx[OQ_MAX];

struct outgoing_packet{
  overlay_interface *interface;
  int seq;
  int i;
  struct subscriber *unicast_subscriber;
  struct sockaddr_in dest;
  int header_length;
  struct overlay_buffer *buffer;
  struct decode_context context;
};

struct sched_ent next_packet;
struct profile_total send_packet;

static void overlay_send_packet(struct sched_ent *alarm);
static int overlay_calc_queue_time(overlay_txqueue *queue, struct overlay_frame *frame);

int overlay_queue_init(){
  /* Set default congestion levels for queues */
  int i;
  for(i=0;i<OQ_MAX;i++) {
    overlay_tx[i].maxLength=100;
    overlay_tx[i].latencyTarget=1000; /* Keep packets in queue for 1 second by default */
  }
  /* expire voice/video call packets much sooner, as they just aren't any use if late */
  overlay_tx[OQ_ISOCHRONOUS_VOICE].maxLength=20;
  overlay_tx[OQ_ISOCHRONOUS_VOICE].latencyTarget=200;
  overlay_tx[OQ_ISOCHRONOUS_VIDEO].latencyTarget=200;
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
  
  if (!p) return WHY("Cannot queue NULL");
  
  do{
    if (p->destination_resolved)
      break;
    if (!p->destination)
      break;
    int r = subscriber_is_reachable(p->destination);
    if (r&REACHABLE)
      break;
    
    if (directory_service){
      r = subscriber_is_reachable(directory_service);
      if (r&REACHABLE)
	break;
    }
    
    return WHYF("Cannot send %x packet, destination %s is %s", p->type, 
		alloca_tohex_sid(p->destination->sid), r==REACHABLE_SELF?"myself":"unreachable");
  } while(0);
  
  if (p->queue>=OQ_MAX) 
    return WHY("Invalid queue specified");
  
  /* queue a unicast probe if we haven't for a while. */
  if (p->destination && (p->destination->last_probe==0 || gettime_ms() - p->destination->last_probe > 5000))
    overlay_send_probe(p->destination, p->destination->address, p->destination->interface, OQ_MESH_MANAGEMENT);
  
  overlay_txqueue *queue = &overlay_tx[p->queue];

  if (config.debug.packettx)
    DEBUGF("Enqueuing packet for %s* (q[%d]length = %d)",
	   p->destination?alloca_tohex(p->destination->sid, 7): alloca_tohex(p->broadcast_id.id,BROADCAST_LEN),
	   p->queue, queue->length);
  
  if (p->payload && ob_remaining(p->payload)<0){
    // HACK, maybe should be done in each caller
    // set the size of the payload based on the position written
    ob_limitsize(p->payload,ob_position(p->payload));
  }
  
  if (queue->length>=queue->maxLength) 
    return WHYF("Queue #%d congested (size = %d)",p->queue,queue->maxLength);
  {
    int i;
    for(i=0;i<OVERLAY_MAX_INTERFACES;i++)
      p->interface_sent_sequence[i]=FRAME_DONT_SEND;
  }

  if (p->destination_resolved){
    p->interface_sent_sequence[p->interface - overlay_interfaces]=FRAME_NOT_SENT;
  }else{
    if (p->destination){
      // allow the packet to be resent
      if (p->resend == 0)
        p->resend = 3;
    }else{
      int i;
      int interface_copies = 0;
      
      // hook to allow for flooding via olsr
      olsr_send(p);
      
      // make sure there is an interface up that allows broadcasts
      for(i=0;i<OVERLAY_MAX_INTERFACES;i++){
	if (overlay_interfaces[i].state==INTERFACE_STATE_UP
	    && overlay_interfaces[i].send_broadcasts
	    && link_state_interface_has_neighbour(&overlay_interfaces[i])){
	  p->interface_sent_sequence[i]=FRAME_NOT_SENT;
	  interface_copies++;
	}
      }
      
      // just drop it now
      if (interface_copies == 0){
	WARN("No broadcast interfaces to send with");
	return -1;
      }

      // allow the packet to be resent
      if (p->resend == 0)
        p->resend = 3 * interface_copies;
    }
  }
  
  struct overlay_frame *l=queue->last;
  if (l) l->next=p;
  p->prev=l;
  p->next=NULL;
  p->enqueued_at=gettime_ms();
  
  queue->last=p;
  if (!queue->first) queue->first=p;
  queue->length++;
  if (p->queue==OQ_ISOCHRONOUS_VOICE)
    rhizome_saw_voice_traffic();
  
  overlay_calc_queue_time(queue, p);
  return 0;
}

static void
overlay_init_packet(struct outgoing_packet *packet, struct subscriber *destination, int unicast,
		    overlay_interface *interface, struct sockaddr_in addr){
  packet->interface = interface;
  packet->i = (interface - overlay_interfaces);
  packet->dest=addr;
  packet->buffer=ob_new();
  packet->seq=-1;
  if (unicast)
    packet->unicast_subscriber = destination;
  else
    packet->seq = interface->sequence_number = (interface->sequence_number + 1)&0xFF;
  ob_limitsize(packet->buffer, packet->interface->mtu);
  
  overlay_packet_init_header(ENCAP_OVERLAY, &packet->context, packet->buffer, 
			     destination, unicast, packet->i, packet->seq);
  packet->header_length = ob_position(packet->buffer);
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

// update the alarm time and return 1 if changed
static int
overlay_calc_queue_time(overlay_txqueue *queue, struct overlay_frame *frame){
  do{
    if (frame->destination_resolved)
      break;
    if (!frame->destination)
      break;
    if (subscriber_is_reachable(frame->destination)&REACHABLE)
      break;
    if (directory_service){
      if (subscriber_is_reachable(directory_service)&REACHABLE)
	break;
    }
    // ignore payload alarm if the destination is currently unreachable
    return 0;
  }while(0);

  time_ms_t next_allowed_packet=0;
  if (frame->destination_resolved && frame->interface){
    // don't include interfaces which are currently transmitting using a serial buffer
    if (frame->interface->tx_bytes_pending>0)
      return 0;
    next_allowed_packet = limit_next_allowed(&frame->interface->transfer_limit);
  }else if(!frame->destination){
    // check all interfaces
    int i;
    for(i=0;i<OVERLAY_MAX_INTERFACES;i++)
    {
      if (overlay_interfaces[i].state!=INTERFACE_STATE_UP ||
	  frame->interface_sent_sequence[i]==FRAME_DONT_SEND ||
	  !link_state_interface_has_neighbour(&overlay_interfaces[i]))
	continue;
      time_ms_t next_packet = limit_next_allowed(&overlay_interfaces[i].transfer_limit);
      if (next_packet < frame->interface_dont_send_until[i])
        next_packet = frame->interface_dont_send_until[i];
      if (next_allowed_packet==0||next_packet < next_allowed_packet)
	next_allowed_packet = next_packet;
    }
    if (next_allowed_packet==0)
      return 0;
  }
  
  if (next_allowed_packet < frame->dont_send_until)
    next_allowed_packet = frame->dont_send_until;

  overlay_queue_schedule_next(next_allowed_packet);
  
  return 0;
}

static void
overlay_stuff_packet(struct outgoing_packet *packet, overlay_txqueue *queue, time_ms_t now){
  struct overlay_frame *frame = queue->first;
  
  // TODO stop when the packet is nearly full?
  while(frame){
    if (frame->enqueued_at + queue->latencyTarget < now){
      if (config.debug.rejecteddata)
	DEBUGF("Dropping frame type %x for %s due to expiry timeout", 
	       frame->type, frame->destination?alloca_tohex_sid(frame->destination->sid):"All");
      frame = overlay_queue_remove(queue, frame);
      continue;
    }
    
    /* Note, once we queue a broadcast packet we are committed to sending it out every interface, 
     even if we hear it from somewhere else in the mean time
     */
    
    // ignore payloads that are waiting for ack / nack resends
    if (frame->dont_send_until > now)
      goto skip;

    // quickly skip payloads that have no chance of fitting
    if (packet->buffer && ob_limit(frame->payload) > ob_remaining(packet->buffer))
      goto skip;
    
    if (!frame->destination_resolved){
      frame->next_hop = frame->destination;
      
      if (frame->next_hop){
	// Where do we need to route this payload next?
	
	int r = subscriber_is_reachable(frame->next_hop);
	
	// first, should we try to bounce this payload off the directory service?
	if (r==REACHABLE_NONE && 
	    directory_service && 
	    frame->next_hop!=directory_service){
	  frame->next_hop=directory_service;
	  r=subscriber_is_reachable(directory_service);
	}
	
	// do we need to route via a neighbour?
	if (r&REACHABLE_INDIRECT){
	  frame->next_hop = frame->next_hop->next_hop;
	  r = subscriber_is_reachable(frame->next_hop);
	}
	
	if (!(r&REACHABLE_DIRECT)){
	  goto skip;
	}
	
	frame->interface = frame->next_hop->interface;
	
	// if both broadcast and unicast are available, pick on based on interface preference
	if ((r&(REACHABLE_UNICAST|REACHABLE_BROADCAST))==(REACHABLE_UNICAST|REACHABLE_BROADCAST)){
	  if (frame->interface->prefer_unicast){
	    r=REACHABLE_UNICAST;
	    // used by tests
	    if (config.debug.overlayframes)
	      DEBUGF("Choosing to send via unicast for %s", alloca_tohex_sid(frame->destination->sid));
	  }else
	    r=REACHABLE_BROADCAST;
	}
	
	if(r&REACHABLE_UNICAST){
	  frame->recvaddr = frame->next_hop->address;
	  frame->unicast = 1;
	}else
	  frame->recvaddr = frame->interface->broadcast_address;
	
	frame->destination_resolved=1;
      }else{
	
	if (packet->buffer){
	  // check if we can stuff into this packet
	  if (frame->interface_sent_sequence[packet->i]==FRAME_DONT_SEND || frame->interface_dont_send_until[packet->i] >now)
	    goto skip;
	  frame->interface = packet->interface;
	  frame->recvaddr = packet->interface->broadcast_address;
	  
	}else{
	  // find an interface that we haven't broadcast on yet
	  frame->interface = NULL;
	  int i, keep=0;
	  for(i=0;i<OVERLAY_MAX_INTERFACES;i++)
	  {
	    if (overlay_interfaces[i].state!=INTERFACE_STATE_UP || 
                frame->interface_sent_sequence[i]==FRAME_DONT_SEND ||
	        !link_state_interface_has_neighbour(&overlay_interfaces[i]))
	      continue;
	    keep=1;
	    if (frame->interface_dont_send_until[i] >now)
	      continue;
	    time_ms_t next_allowed = limit_next_allowed(&overlay_interfaces[i].transfer_limit);
	    if (next_allowed > now)
	      continue;
	    frame->interface = &overlay_interfaces[i];
	    frame->recvaddr = overlay_interfaces[i].broadcast_address;
	    break;
	  }
	  
	  if (!keep){
	    // huh, we don't need to send it anywhere?
	    frame = overlay_queue_remove(queue, frame);
	    continue;
	  }
	  
	  if (!frame->interface)
	    goto skip;
	}
      }
    }
    
    if (!packet->buffer){
      if (frame->interface->socket_type==SOCK_STREAM){
	// skip this interface if the stream tx buffer has data
	if (frame->interface->tx_bytes_pending>0)
	  goto skip;
      }
      
      // can we send a packet on this interface now?
      if (limit_is_allowed(&frame->interface->transfer_limit))
	goto skip;
      
      if (frame->interface->encapsulation==ENCAP_SINGLE){
	// send MDP packets without aggregating them together
	struct overlay_buffer *buff = ob_new();
	
	int ret=single_packet_encapsulation(buff, frame);
	if (!ret){
	  ret=overlay_broadcast_ensemble(frame->interface, &frame->recvaddr, ob_ptr(buff), ob_position(buff));
	}
	
	ob_free(buff);
	
	if (ret)
	  goto skip;
	
	goto sent;
      }
      
      if (frame->source_full)
	my_subscriber->send_full=1;
      overlay_init_packet(packet, frame->next_hop, frame->unicast, frame->interface, frame->recvaddr);
    }else{
      // is this packet going our way?
      if (frame->interface!=packet->interface || memcmp(&packet->dest, &frame->recvaddr, sizeof(packet->dest))!=0){
	goto skip;
      }
    }
    
    if (frame->send_hook){
      // last minute check if we really want to send this frame, or track when we sent it
      if (frame->send_hook(frame, packet->seq, frame->send_context)){
        // drop packet
        frame = overlay_queue_remove(queue, frame);
        continue;
      }
    }

    if (overlay_frame_append_payload(&packet->context, packet->interface, frame, packet->buffer)){
      // payload was not queued
      goto skip;
    }

  sent:
    if (frame->interface_sent_sequence[packet->i]>=0 && config.debug.overlayframes)
      DEBUGF("Retransmitted frame %p from seq %d in seq %d", frame, frame->interface_sent_sequence[packet->i], packet->seq);

    frame->interface_sent_sequence[packet->i] = packet->seq;
    frame->interface_dont_send_until[packet->i] = now+200;

    if (config.debug.overlayframes){
      DEBUGF("Sent payload %p type %x len %d for %s via %s, seq %d", 
	     frame,
	     frame->type, ob_position(frame->payload),
	     frame->destination?alloca_tohex_sid(frame->destination->sid):"All",
	     frame->next_hop?alloca_tohex_sid(frame->next_hop->sid):alloca_tohex(frame->broadcast_id.id, BROADCAST_LEN),
             frame->interface_sent_sequence[packet->i]);
    }
    
    if (frame->destination)
      frame->destination->last_tx=now;
    if (frame->next_hop)
      frame->next_hop->last_tx=now;
    
    // mark the payload as sent
    int keep_payload = 0;
    
    frame->resend --;
    if (frame->destination_resolved){
      if (frame->resend>0 && frame->next_hop && packet->seq!=-1 && (!frame->unicast)){
        frame->dont_send_until = now+200;
	frame->destination_resolved = 0;
	keep_payload = 1;
	if (config.debug.overlayframes)
	  DEBUGF("Holding onto payload for ack/nack resend in %lldms", frame->dont_send_until - now);
      }
    }else{
      if (frame->resend<=0 || packet->seq==-1 || frame->unicast){
	// dont retransmit if we aren't sending sequence numbers, or we've run out of allowed resends
        frame->interface_sent_sequence[packet->i] = FRAME_DONT_SEND;
      }
      int i;
      for(i=0;i<OVERLAY_MAX_INTERFACES;i++){
	if (overlay_interfaces[i].state==INTERFACE_STATE_UP &&
	    link_state_interface_has_neighbour(&overlay_interfaces[i]) &&
            frame->interface_sent_sequence[i]!=FRAME_DONT_SEND){
          keep_payload = 1;
	  break;
	}
      }
    }

    if (!keep_payload){
      frame = overlay_queue_remove(queue, frame);
      continue;
    }
    
  skip:
    // if we can't send the payload now, check when we should try next
    overlay_calc_queue_time(queue, frame);
    frame = frame->next;
  }
}

// fill a packet from our outgoing queues and send it
static int
overlay_fill_send_packet(struct outgoing_packet *packet, time_ms_t now) {
  int i;
  IN();
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
      
    if (overlay_broadcast_ensemble(packet->interface, &packet->dest, ob_ptr(packet->buffer), ob_position(packet->buffer))){
      // sendto failed. We probably don't have a valid route
      if (packet->unicast_subscriber){
	set_reachable(packet->unicast_subscriber, REACHABLE_NONE);
      }
    }
    ob_free(packet->buffer);
    RETURN(1);
  }
  RETURN(0);
  OUT();
}

// when the queue timer elapses, send a packet
static void overlay_send_packet(struct sched_ent *alarm){
  struct outgoing_packet packet;
  bzero(&packet, sizeof(struct outgoing_packet));
  overlay_fill_send_packet(&packet, gettime_ms());
}

int overlay_send_tick_packet(struct overlay_interface *interface){
  struct outgoing_packet packet;
  bzero(&packet, sizeof(struct outgoing_packet));
  overlay_init_packet(&packet, NULL, 0, interface, interface->broadcast_address);
  
  overlay_fill_send_packet(&packet, gettime_ms());
  return 0;
}

// de-queue all packets that have been sent to this subscriber & have arrived.
int overlay_queue_ack(struct subscriber *neighbour, struct overlay_interface *interface, uint32_t ack_mask, int ack_seq)
{
  int interface_id = interface - overlay_interfaces;
  int i;
  time_ms_t now = gettime_ms();
  for (i=0;i<OQ_MAX;i++){
    struct overlay_frame *frame = overlay_tx[i].first;

    while(frame){
      int frame_seq = frame->interface_sent_sequence[interface_id];
      if (frame_seq >=0 && (frame->next_hop == neighbour || !frame->destination)){
	int seq_delta = (ack_seq - frame_seq)&0xFF;
	char acked = (seq_delta==0 || (seq_delta <= 32 && ack_mask&(1<<(seq_delta-1))))?1:0;

	if (acked){
          frame->interface_sent_sequence[interface_id] = FRAME_DONT_SEND;
	  int discard = 1;
	  if (!frame->destination){
            int j;
            for(j=0;j<OVERLAY_MAX_INTERFACES;j++){
	      if (overlay_interfaces[j].state==INTERFACE_STATE_UP &&
                  frame->interface_sent_sequence[j]!=FRAME_DONT_SEND){
	        discard = 0;
	        break;
	      }
	    }
	  }
	  if (discard){
	    if (config.debug.overlayframes)
	      DEBUGF("Dequeing packet %p to %s sent by seq %d, due to ack of seq %d", frame, alloca_tohex_sid(neighbour->sid), frame_seq, ack_seq);
            frame = overlay_queue_remove(&overlay_tx[i], frame);
	    continue;
	  }
	}

	if (seq_delta < 128 && frame->destination && frame->dont_send_until>now){
	  // resend immediately
	  if (config.debug.overlayframes)
	    DEBUGF("Requeue packet %p to %s sent by seq %d due to ack of seq %d", frame, alloca_tohex_sid(neighbour->sid), frame_seq, ack_seq);
	  frame->dont_send_until = now;
	  // dont count the next retransmission against the time based retries
	  frame->resend ++;
	  overlay_calc_queue_time(&overlay_tx[i], frame);
	}
      }
      frame = frame->next;
    }
  }
  return 0;
}
