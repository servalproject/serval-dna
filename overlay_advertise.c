/*
Serval Distributed Numbering Architecture (DNA)
Copyright (C) 2010 Paul Gardner-Stephen
 
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
#include "str.h"
#include "overlay_address.h"
#include "overlay_buffer.h"
#include "overlay_packet.h"

/* List of prioritised advertisements */
#define OVERLAY_MAX_ADVERTISEMENT_REQUESTS 16
overlay_node *oad_requests[OVERLAY_MAX_ADVERTISEMENT_REQUESTS];
int oad_request_count=0;

/* Where we are up to in the node list for round-robin advertising */
int oad_bin=0;
int oad_slot=0;

/* Which round of the node list we are up to.
   This is used for reducing the advertisement rate for stable nodes.
   Initially this will just mean advertising higher-scoring nodes
   less often.

   Our goal is to advertise all nodes often enough to maintain connectivity,
   without wasting any packets.

   Basically high-scoring nodes can be advertised less often than low-scoring
   nodes.
   
   Let's advertise nodes <100 every round, <200 every 2 rounds, and >=200
   every 4th round.
*/
int oad_round=0;

/* Request that this node be advertised as a matter of priority */
int overlay_route_please_advertise(overlay_node *n)
{
  if (oad_request_count<OVERLAY_MAX_ADVERTISEMENT_REQUESTS)
    {
      oad_requests[oad_request_count++]=n;
      return 0;
    }
  else return 1;
}

struct advertisement_state{
  struct overlay_buffer *payload;
  struct subscriber *next_advertisement;
};

int add_advertisement(struct subscriber *subscriber, void *context){
  struct advertisement_state *state=context;
  
  if (subscriber->node){
    overlay_node *n=subscriber->node;
    
    if ((subscriber->reachable&REACHABLE) && (!(subscriber->reachable&REACHABLE_ASSUMED)) 
	&& n->best_link_score>0 && n->observations[n->best_observation].gateways_en_route < 64){
      // never send the full sid in an advertisement
      subscriber->send_full=0;
      
      if (overlay_address_append(NULL,state->payload,subscriber) ||
	  ob_append_byte(state->payload,n->best_link_score -1) ||
	  ob_append_byte(state->payload,n->observations[n->best_observation].gateways_en_route +1)){
	
	// stop if we run out of space, remember where we should start next time.
	state->next_advertisement=subscriber;
	ob_rewind(state->payload);
	return 1;
      }
      ob_checkpoint(state->payload);
    }
  }
  
  return 0;
}

int overlay_route_queue_advertisements(overlay_interface *interface)
{
  /* Construct a route advertisement frame and append it to e.
     
     Work out available space in packet for advertisments, and fit the 
     highest scoring nodes from the current portion in.
     
     Each advertisement consists of an address prefix followed by score.
     We will use 6 bytes of prefix to make it reasonably hard to generate
     collisions, including by birthday paradox (good for networks upto about
     20million nodes), and one byte each for score gateways_en_route.

     XXX - We need to send full addresses sometimes so that receiver can
     resolve them. Either that or we need to start supporting the PLEASEEXPLAIN
     packets, which is probably a better solution.

     The receiver will discount the score based on their measured reliability
     for packets to arrive from us; we just repeat what discounted score
     we have remembered.

     Hacking the frame together this way is less flexible, but much faster
     than messing about with malloc() and setting address fields.

     The src,dst and nexthop can each be encoded with a single byte.
     Thus using a fixed 1-byte RFS field we are limited to RFS<0xfa,
     which gives us 30 available advertisement slots per packet.
   */
  
  if (!my_subscriber)
    return WHY("Cannot advertise because I don't know who I am");
  struct overlay_frame *frame=malloc(sizeof(struct overlay_frame));
  bzero(frame,sizeof(struct overlay_frame));
  frame->type=OF_TYPE_NODEANNOUNCE;
  frame->source = my_subscriber;
  frame->ttl=1;
  frame->queue=OQ_MESH_MANAGEMENT;
  frame->destination_resolved=1;
  frame->recvaddr=interface->broadcast_address;
  frame->interface=interface;
  frame->payload = ob_new();
  ob_limitsize(frame->payload, 400);
  
  struct advertisement_state state={.payload = frame->payload,};
  
  // TODO high priority advertisements first....
  /*
  while (slots>0&&oad_request_count) {
      oad_request_count--;
      ob_append_bytes(e,oad_requests[oad_request_count]->subscriber->sid,6);
      ob_append_byte(e,oad_requests[oad_request_count]->best_link_score);
      ob_append_byte(e,oad_requests[oad_request_count]
		     ->observations[oad_requests[oad_request_count]
				    ->best_observation].gateways_en_route);
      slots--;
      slots_used++;
    } 
*/
  ob_checkpoint(frame->payload);
  // append announcements starting from the last node we couldn't advertise last time
  enum_subscribers(interface->next_advert, add_advertisement, &state);

  // if we didn't start at the beginning and still have space, start again from the beginning
  if (interface->next_advert && !state.next_advertisement && ob_remaining(frame->payload) > 0){
    enum_subscribers(NULL, add_advertisement, &state);
  }
  
  interface->next_advert=state.next_advertisement;
  ob_limitsize(frame->payload, ob_position(frame->payload));
  
  if (overlay_payload_enqueue(frame)){
    op_free(frame);
    return -1;
  }
  return 0;
}

/* Pull out the advertisements and update our routing table accordingly.
   Because we are using a non-standard abbreviation scheme, we have to extract
   and search for the nodes ourselves.

   Also, we need to discount the scores based on the score of the sender.
   We can either do this once now (more computationally efficient), or have 
   a rather complicated scheme whereby we attempt to trace through the list
   of nodes from here to there.  That seems silly, and is agains't the BATMAN
   approach of each node just knowing single-hop information.
 */
int overlay_route_saw_advertisements(int i, struct overlay_frame *f, struct decode_context *context, time_ms_t now)
{
  IN();
  struct subscriber *previous=context->previous;
  // minimum record length is (address code, 3 byte sid, score, gateways)
  while(ob_remaining(f->payload)>0)
    {
      struct subscriber *subscriber;
      context->invalid_addresses=0;
      
      if (overlay_address_parse(context, f->payload, &subscriber)){
	WHY("Failed to parse address");
	break;
      }
      
      int score=ob_get(f->payload);
      int gateways_en_route=ob_get(f->payload);

      // stop if hit end of payload
      if (score<0 || gateways_en_route<0){
	WHY("Unexpected end of payload");
	break;
      }
      
      // skip if we can't parse the subscriber id
      if (context->invalid_addresses || !subscriber)
	continue;
      
      /* Don't record routes to ourselves */
      if (subscriber->reachable==REACHABLE_SELF) {
	if (config.debug.overlayrouting)
	  DEBUGF("Ignore announcement about me (%s)", alloca_tohex_sid(subscriber->sid));
	continue;
      }
      
      /* File it */
      overlay_route_record_link(now, subscriber, f->source,
				i,
				/* time range that this advertisement covers.
				   XXX - Make it up for now. */
				now-2500,now,
				score,gateways_en_route);
      
    }
  // restore the previous subscriber id for parsing the next header
  context->previous=previous;
  RETURN(0);
}
