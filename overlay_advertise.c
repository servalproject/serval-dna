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

int overlay_route_add_advertisements(overlay_buffer *e)
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
  int i;
  int bytes=e->sizeLimit-e->length;
  int overhead=1+8+1+3+32+1+1; /* maximum overhead */
  int slots=(bytes-overhead)/8;
  if (slots>30) slots=30;
  int slots_used=0;

  if (slots<1) return WHY("No room for node advertisements");

  if (ob_append_byte(e,OF_TYPE_NODEANNOUNCE))
    return WHY("could not add node advertisement header");
  ob_append_byte(e,1); /* TTL */
  
  ob_append_rfs(e,1+8+1+1+8*slots_used);

  /* Stuff in dummy address fields */
  ob_append_byte(e,OA_CODE_BROADCAST);
  for(i=0;i<8;i++) ob_append_byte(e,random()&0xff); /* random BPI */
  ob_append_byte(e,OA_CODE_PREVIOUS);
  
  overlay_abbreviate_clear_most_recent_address();
  overlay_abbreviate_append_address(e, overlay_get_my_sid());
  
  while (slots>0&&oad_request_count) {
      oad_request_count--;
      ob_append_bytes(e,oad_requests[oad_request_count]->sid,6);
      ob_append_byte(e,oad_requests[oad_request_count]->best_link_score);
      ob_append_byte(e,oad_requests[oad_request_count]
		     ->observations[oad_requests[oad_request_count]
				    ->best_observation].gateways_en_route);
      slots--;
      slots_used++;
    } 

  while(slots>0)
    {
      /* find next node */
      int bin=oad_bin;
      int slot=oad_slot;

      /* XXX Skipping priority advertised nodes could be done faster, e.g.,
	 by adding a flag to the overlay_node structure to indicate if it
	 has been sent priority, and if so, skip it.
	 The flags could then be reset at the end of this function.
	 But this will do for now. 
      */
      int skip=0;
      for(i=0;i<oad_request_count;i++) 
	if (oad_requests[i]==&overlay_nodes[oad_bin][oad_slot])
	  skip=1;
      
      if (!skip)
	{
	  if(overlay_nodes[oad_bin][oad_slot].sid[0]) {
	    overlay_node *n=&overlay_nodes[oad_bin][oad_slot];
	    
	    ob_append_bytes(e,n->sid,6);
	    ob_append_byte(e,n->best_link_score);
	    ob_append_byte(e,n->observations[n->best_observation].gateways_en_route);

	    slots--;
	    slots_used++;
	  }
	}
      
      /* Find next node */
      oad_slot++; 
      if (oad_slot>=overlay_bin_size) { oad_slot=0; oad_bin++; }

      /* Stop stuffing if we get to the end of the node list so that 
	 we can implement an appropriate pause between rounds to avoid
	 unneeded repeated TX of nodes. */
      if (oad_bin>=overlay_bin_count) { oad_bin=0; oad_round++; break; }
      
      /* Stop if we have advertised everyone */
      if (oad_bin==bin&&oad_slot==slot) break;
    }
  
  ob_patch_rfs(e,COMPUTE_RFS_LENGTH);

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
int overlay_route_saw_advertisements(int i,overlay_frame *f, long long now)
{
  int ofs=0;

  /* lookup score of current sender */
  overlay_node *sender = overlay_route_find_node(f->source, SID_SIZE, 0);
  if (sender == NULL) {
    WARNF("Cannot advertise %s -- overlay node not found", alloca_tohex_sid(f->source));
    return -1;
  }
  int sender_score=sender->best_link_score;
  if (debug&DEBUG_OVERLAYROUTEMONITOR)
    DEBUGF("score to reach %s is %d", alloca_tohex_sid(f->source),sender_score);

  while(ofs<f->payload->length)
    {
      unsigned char to[SID_SIZE];
      int out_len=0;
      int r
	=overlay_abbreviate_cache_lookup(&f->payload->bytes[ofs],to,&out_len,
					 6 /* prefix length */,
					 0 /* no index code to process */);
      if (r==OA_PLEASEEXPLAIN) {
	/* Unresolved address -- TODO ask someone to resolve it for us. */
	WARN("Dispatch PLEASEEXPLAIN not implemented");
	goto next;
      }
      
      int score=f->payload->bytes[6];
      int gateways_en_route=f->payload->bytes[7];

      /* Don't record routes to ourselves */
      if (overlay_address_is_local(to)) {
	if (debug & DEBUG_OVERLAYROUTING)
	  DEBUGF("Ignore announcement about me (%s)", alloca_tohex_sid(to));
	goto next;
      }
      
      /* Don't let nodes advertise paths to themselves!
	 (paths to self get detected through selfannouncements and selfannouncement acks) */
      if (!memcmp(&overlay_abbreviate_current_sender.b[0],to,SID_SIZE)){
	if (debug & DEBUG_OVERLAYROUTING)
	  DEBUGF("Ignore announcement about neighbour (%s)", alloca_tohex_sid(to));
	goto next;
      }
      
      if (r==OA_RESOLVED) {
	/* File it */
	overlay_route_record_link(now,to,&overlay_abbreviate_current_sender.b[0],
				  i,
				  /* time range that this advertisement covers.
				     XXX - Make it up for now. */
				  now-2500,now,
				  score,gateways_en_route);
      } 
      
    next:			  
      ofs+=8;
    }
  
  return 0;
}
