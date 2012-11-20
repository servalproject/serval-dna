#include "serval.h"
#include "overlay_buffer.h"
#include "overlay_packet.h"
#include "str.h"

typedef struct overlay_txqueue {
  struct overlay_frame *first;
  struct overlay_frame *last;
  int length; /* # frames in queue */
  int maxLength; /* max # frames in queue before we consider ourselves congested */
  
  /* wait until first->enqueued_at+transmit_delay before trying to force the transmission of a packet */
  int transmit_delay;
  
  /* if servald is busy, wait this long before trying to force the transmission of a packet */
  int grace_period;
  
  /* Latency target in ms for this traffic class.
   Frames older than the latency target will get dropped. */
  int latencyTarget;
  
  /* XXX Need to initialise these:
   Real-time queue for voice (<200ms ?)
   Real-time queue for video (<200ms ?) (lower priority than voice)
   Ordinary service queue (<3 sec ?)
   Rhizome opportunistic queue (infinity)
   
   (Mesh management doesn't need a queue, as each overlay packet is tagged with some mesh management information)
   */
} overlay_txqueue;

overlay_txqueue overlay_tx[OQ_MAX];

unsigned char magic_header[]={/* Magic */ 'O',0x10,
  /* Version */ 0x00,0x01};

struct outgoing_packet{
  overlay_interface *interface;
  int i;
  struct subscriber *unicast_subscriber;
  int unicast;
  int add_advertisements;
  struct sockaddr_in dest;
  struct overlay_buffer *buffer;
};

struct sched_ent next_packet;
struct profile_total send_packet;

static void overlay_send_packet(struct sched_ent *alarm);
static void overlay_update_queue_schedule(overlay_txqueue *queue, struct overlay_frame *frame);

int overlay_queue_init(){
  /* Set default congestion levels for queues */
  int i;
  for(i=0;i<OQ_MAX;i++) {
    overlay_tx[i].maxLength=100;
    overlay_tx[i].latencyTarget=1000; /* Keep packets in queue for 1 second by default */
    overlay_tx[i].transmit_delay=5; /* Hold onto packets for 10ms before trying to send a full packet */
    overlay_tx[i].grace_period=100; /* Delay sending a packet for up to 100ms if servald has other processing to do */
  }
  /* expire voice/video call packets much sooner, as they just aren't any use if late */
  overlay_tx[OQ_ISOCHRONOUS_VOICE].latencyTarget=200;
  overlay_tx[OQ_ISOCHRONOUS_VIDEO].latencyTarget=200;
  
  /* try to send voice packets without any delay, and before other background processing */
  overlay_tx[OQ_ISOCHRONOUS_VOICE].transmit_delay=0;
  overlay_tx[OQ_ISOCHRONOUS_VOICE].grace_period=0;
  
  /* Routing payloads, ack's and nacks need to be sent immediately */
  overlay_tx[OQ_MESH_MANAGEMENT].transmit_delay=0;
  
  /* opportunistic traffic can be significantly delayed */
  overlay_tx[OQ_OPPORTUNISTIC].transmit_delay=200;
  overlay_tx[OQ_OPPORTUNISTIC].grace_period=500;
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

int overlay_payload_enqueue(struct overlay_frame *p)
{
  /* Add payload p to queue q.
   
   Queues get scanned from first to last, so we should append new entries
   on the end of the queue.
   
   Complain if there are too many frames in the queue.
   */
  
  if (!p) return WHY("Cannot queue NULL");
  
  if (p->destination){
    int r = subscriber_is_reachable(p->destination);
    if (r == REACHABLE_SELF || r == REACHABLE_NONE)
      return WHYF("Destination %s is unreachable (%d)", alloca_tohex_sid(p->destination->sid), r);
  }
  
  if (p->queue>=OQ_MAX) 
    return WHY("Invalid queue specified");
  
  overlay_txqueue *queue = &overlay_tx[p->queue];
  
  if (debug&DEBUG_PACKETTX)
    DEBUGF("Enqueuing packet for %s* (q[%d]length = %d)",
	   p->destination?alloca_tohex(p->destination->sid, 7): alloca_tohex(p->broadcast_id.id,BROADCAST_LEN),
	   p->queue, queue->length);
  
  if (p->payload && p->payload->position > p->payload->sizeLimit){
    // HACK, maybe should be done in each caller
    // set the size of the payload based on the position written
    p->payload->sizeLimit=p->payload->position;
  }
  
  if (queue->length>=queue->maxLength) 
    return WHYF("Queue #%d congested (size = %d)",p->queue,queue->maxLength);
  
  if (p->send_copies<=0)
    p->send_copies=1;
  else if(p->send_copies>5)
    return WHY("Too many copies requested");
  
  if (!p->destination){
    int i;
    int drop=1;
    
    // hook to allow for flooding via olsr
    olsr_send(p);
    
    // make sure there is an interface up that allows broadcasts
    for(i=0;i<OVERLAY_MAX_INTERFACES;i++){
      if (overlay_interfaces[i].state==INTERFACE_STATE_UP
	  && overlay_interfaces[i].send_broadcasts){
	p->broadcast_sent_via[i]=0;
	drop=0;
      }else
	p->broadcast_sent_via[i]=1;
    }
    
    // just drop it now
    if (drop)
      return -1;
    
    p->sendBroadcast=1;
  }
  
  struct overlay_frame *l=queue->last;
  if (l) l->next=p;
  p->prev=l;
  p->next=NULL;
  p->enqueued_at=gettime_ms();
  
  queue->last=p;
  if (!queue->first) queue->first=p;
  queue->length++;
  
  overlay_update_queue_schedule(queue, p);
  
  if (0) overlay_queue_dump(queue);
  
  return 0;
}

static void
overlay_init_packet(struct outgoing_packet *packet, overlay_interface *interface, int tick){
  packet->interface = interface;
  packet->i = (interface - overlay_interfaces);
  packet->dest=interface->broadcast_address;
  packet->buffer=ob_new();
  packet->add_advertisements=1;
  ob_limitsize(packet->buffer, packet->interface->mtu);
  ob_append_bytes(packet->buffer,magic_header,4);
  
  overlay_address_clear();
  
  if (tick){
    /* 1. Send announcement about ourselves, including one SID that we host if we host more than one SID
     (the first SID we host becomes our own identity, saving a little bit of data here).
     */
    overlay_add_selfannouncement(packet->i, packet->buffer);
    
    /* Add advertisements for ROUTES */
    overlay_route_add_advertisements(packet->interface, packet->buffer);
    
  }else{
    // add a badly formatted dummy self announce payload to tell people we sent this.
    ob_append_byte(packet->buffer, OF_TYPE_SELFANNOUNCE);
    ob_append_byte(packet->buffer, 1);
    ob_append_rfs(packet->buffer, SID_SIZE + 2);
    
    /* from me, to me, via me 
     (it's shorter than an actual broadcast, 
     and receivers wont try to process it 
     since its not going to have a payload body anyway) */
    overlay_address_append_self(interface, packet->buffer);
    overlay_address_set_sender(my_subscriber);
    ob_append_byte(packet->buffer, OA_CODE_PREVIOUS);
    ob_append_byte(packet->buffer, OA_CODE_PREVIOUS);
    
    ob_patch_rfs(packet->buffer, COMPUTE_RFS_LENGTH);
  }
}

// update the alarm time and return 1 if changed
static int
overlay_calc_queue_time(overlay_txqueue *queue, struct overlay_frame *frame){
  int ret=0;
  time_ms_t send_time;
  
  // ignore packet if the destination is currently unreachable
  if (frame->destination && subscriber_is_reachable(frame->destination)==REACHABLE_NONE)
    return 0;
  
  // when is the next packet from this queue due?
  send_time=queue->first->enqueued_at + queue->transmit_delay;
  if (next_packet.alarm==0 || send_time < next_packet.alarm){
    next_packet.alarm=send_time;
    ret = 1;
  }
  
  // how long can we wait if the server is busy?
  send_time += queue->grace_period;
  if (next_packet.deadline==0 || send_time < next_packet.deadline){
    next_packet.deadline=send_time;
    ret = 1;
  }
  if (!next_packet.function){
    next_packet.function=overlay_send_packet;
    send_packet.name="overlay_send_packet";
    next_packet.stats=&send_packet;
  }
  return ret;
}

static void
overlay_stuff_packet(struct outgoing_packet *packet, overlay_txqueue *queue, time_ms_t now){
  struct overlay_frame *frame = queue->first;
  
  // TODO stop when the packet is nearly full?
  
  while(frame){
    if (frame->enqueued_at + queue->latencyTarget < now){
      DEBUGF("Dropping frame type %x for %s due to expiry timeout", 
	     frame->type, frame->destination?alloca_tohex_sid(frame->destination->sid):"All");
      frame = overlay_queue_remove(queue, frame);
      continue;
    }
    /* Note, once we queue a broadcast packet we are committed to sending it out every interface, 
     even if we hear it from somewhere else in the mean time
     */
    
    struct subscriber *next_hop = frame->destination;
    
    if (next_hop){
      switch(subscriber_is_reachable(next_hop)){
	case REACHABLE_NONE:
	  goto skip;
	  
	case REACHABLE_INDIRECT:
	  next_hop=next_hop->next_hop;
	  frame->sendBroadcast=0;
	  break;
	  
	case REACHABLE_DEFAULT_ROUTE:
	  next_hop=directory_service;
	  frame->sendBroadcast=0;
	  break;
	  
	case REACHABLE_DIRECT:
	case REACHABLE_UNICAST:
	  frame->sendBroadcast=0;
	  break;
	  
	case REACHABLE_BROADCAST:
	  if (!frame->sendBroadcast){
	    if (frame->ttl>2)
	      frame->ttl=2;
	    frame->sendBroadcast=1;
	    if (is_all_matching(frame->broadcast_id.id, BROADCAST_LEN, 0)){
	      overlay_broadcast_generate_address(&frame->broadcast_id);
	      // mark it as already seen so we don't immediately retransmit it
	      overlay_broadcast_drop_check(&frame->broadcast_id);
	    }
	    int i;
	    for(i=0;i<OVERLAY_MAX_INTERFACES;i++)
	      frame->broadcast_sent_via[i]=0;
	  }
	  break;
      }
    }
    
    if (!packet->buffer){
      // use the interface of the first payload we find
      if (frame->sendBroadcast){
	// find an interface that we haven't broadcast on yet
	int i;
	for(i=0;i<OVERLAY_MAX_INTERFACES;i++)
	{
	  if (overlay_interfaces[i].state==INTERFACE_STATE_UP
	      && !frame->broadcast_sent_via[i]){
	    overlay_init_packet(packet, &overlay_interfaces[i], 0);
	    break;
	  }
	}
	
	if (!packet->buffer){
	  // oh dear, why is this broadcast still in the queue?
	  frame = overlay_queue_remove(queue, frame);
	  continue;
	}
      }else{
	overlay_init_packet(packet, next_hop->interface, 0);
	if (next_hop->reachable==REACHABLE_UNICAST){
	  packet->unicast_subscriber = next_hop;
	  packet->dest = next_hop->address;
	  packet->unicast=1;
	}
      }
      
    }else{
      // make sure this payload can be sent via this interface
      if (frame->sendBroadcast){
	if (frame->broadcast_sent_via[packet->i]){
	  goto skip;
	}
      }else{
	if(packet->interface != next_hop->interface)
	  goto skip;
	if (next_hop->reachable==REACHABLE_DIRECT && packet->unicast)
	  goto skip;
	if (next_hop->reachable==REACHABLE_UNICAST && 
	    ((!packet->unicast) ||
	     packet->dest.sin_addr.s_addr != next_hop->address.sin_addr.s_addr))
	  goto skip;
      }
    }
    
    if (debug&DEBUG_OVERLAYFRAMES){
      DEBUGF("Sending payload type %x len %d for %s via %s", frame->type, frame->payload->position,
	     frame->destination?alloca_tohex_sid(frame->destination->sid):"All",
	     frame->sendBroadcast?alloca_tohex(frame->broadcast_id.id, BROADCAST_LEN):alloca_tohex_sid(next_hop->sid));
    }
    
    if (overlay_frame_append_payload(packet->interface, frame, next_hop, packet->buffer))
      // payload was not queued
      goto skip;
    
    // don't send rhizome adverts if the packet contains a voice payload
    if (frame->queue==OQ_ISOCHRONOUS_VOICE)
      packet->add_advertisements=0;
    
    // mark the payload as sent
    int keep_payload = 0;
    
    if (frame->sendBroadcast){
      int i;
      frame->broadcast_sent_via[packet->i]=1;
      
      // check if there is still a broadcast to be sent      
      for(i=0;i<OVERLAY_MAX_INTERFACES;i++)
      {
	if (overlay_interfaces[i].state==INTERFACE_STATE_UP)
	  if (!frame->broadcast_sent_via[i]){
	    keep_payload=1;
	    break;
	  }
      }
    }else{
      frame->send_copies --;
      // ignore resend logic for unicast packets, where wifi gives better resilience
      if (frame->send_copies>0 && !packet->unicast)
	keep_payload=1;
    }
    
    if (!keep_payload){
      frame = overlay_queue_remove(queue, frame);
      continue;
    }
    
  skip:
    // if we can't send the payload now, check when we should try
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
  
  if (next_packet.alarm)
    schedule(&next_packet);
  
  if(packet->buffer){
    // send the packet
    if (packet->buffer->position>=HEADERFIELDS_LEN){
      // stuff rhizome announcements at the last moment
      if (packet->add_advertisements)
	overlay_rhizome_add_advertisements(packet->i,packet->buffer);
      
      if (debug&DEBUG_PACKETCONSTRUCTION)
	dump("assembled packet",&packet->buffer->bytes[0],packet->buffer->position);
      
      if (overlay_broadcast_ensemble(packet->i, &packet->dest, packet->buffer->bytes, packet->buffer->position)){
	// sendto failed. We probably don't have a valid route
	if (packet->unicast_subscriber){
	  set_reachable(packet->unicast_subscriber, REACHABLE_NONE);
	}
      }
    }
    ob_free(packet->buffer);
    overlay_address_clear();
    RETURN(1);
  }
  RETURN(0);
}

// when the queue timer elapses, send a packet
static void overlay_send_packet(struct sched_ent *alarm){
  struct outgoing_packet packet;
  bzero(&packet, sizeof(struct outgoing_packet));
  
  overlay_fill_send_packet(&packet, gettime_ms());
}

// update time for next alarm and reschedule
static void overlay_update_queue_schedule(overlay_txqueue *queue, struct overlay_frame *frame){
  if (overlay_calc_queue_time(queue, frame)){
    unschedule(&next_packet);
    schedule(&next_packet);
  }
}

int
overlay_tick_interface(int i, time_ms_t now) {
  struct outgoing_packet packet;
  IN();
  
  /* An interface with no speed budget is for listening only, so doesn't get ticked */
  if (overlay_interfaces[i].bits_per_second<1
      || overlay_interfaces[i].state!=INTERFACE_STATE_UP) {
    RETURN(0);
  }
  
  if (debug&DEBUG_OVERLAYINTERFACES) DEBUGF("Ticking interface #%d",i);
  
  // initialise the packet buffer
  bzero(&packet, sizeof(struct outgoing_packet));
  overlay_init_packet(&packet, &overlay_interfaces[i], 1);
  
  /* Stuff more payloads from queues and send it */
  overlay_fill_send_packet(&packet, now);
  RETURN(0);
}