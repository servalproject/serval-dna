#include "mphlr.h"

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

int overlay_route_add_advertisements(int interface,overlay_buffer *e)
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
  int overhead=1+1+3+32+1+1; /* maximum overhead */
  int slots=(bytes-overhead)/8;
  if (slots>30) slots=30;
  int slots_used=0;

  if (slots<1) return WHY("No room for node advertisements");

  if (ob_append_byte(e,OF_TYPE_NODEANNOUNCE))
    return WHY("could not add node advertisement header");
  ob_append_byte(e,1); /* TTL */
  int rfs_offset=e->length; /* remember where the RFS byte gets stored 
			       so that we can patch it later */
  ob_append_byte(e,1+1+1+8*slots_used/* RFS */);

  /* Stuff in dummy address fields */
  ob_append_byte(e,OA_CODE_BROADCAST);
  ob_append_byte(e,OA_CODE_BROADCAST);
  ob_append_byte(e,OA_CODE_SELF);
  
  int count;
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
      for(i=0;i<count;i++) 
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
  
  e->bytes[rfs_offset]=1+1+1+8*slots_used;

  return 0;
}
