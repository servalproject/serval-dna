/*
Serval DNA MDP trace service
Copyright (C) 2016 Flinders University
Copyright (C) 2012-2015 Serval Project Inc.
Copyright (C) 2012 Paul Gardner-Stephen
 
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

#include "overlay_buffer.h"
#include "overlay_address.h"
#include "overlay_packet.h"
#include "mdp_client.h"
#include "fdqueue.h"
#include "str.h"

/*
 * Trace packets are a little weird so that they can be modified by every node
 * and so they can bypass the routing table.
 * 
 * The true source and destination addresses are encoded inside the payload
 * each node that processes the packet appends their own address before forwarding it to the next hop
 * if their SID is already in the packet, the next hop is chosen from the immediately preceeding SID in the list.
 * otherwise the next SID is chosen based on the current routing table.
 * 
 * In this way the packet can follow the path defined by each node's routing table
 * Until the packet reaches the destination, the destination is unreachable, or the packet loops around the network
 * Once any of these end states occurs, the packet attempts to travel back to the source node, 
 * while using the source addresses in the trace packet for guidance instead of trusting the routing table.
 * 
 * It is hoped that this information can be useful to better understand the current network state 
 * in situations where a routing protocol is in development.
 */

DEFINE_BINDING(MDP_PORT_TRACE, overlay_mdp_service_trace);
static int overlay_mdp_service_trace(struct internal_mdp_header *header, struct overlay_buffer *payload){
  IN();
  struct overlay_buffer *next_payload = ob_new();
  if (!next_payload)
    RETURN(-1);
  ob_append_bytes(next_payload, ob_current_ptr(payload), ob_remaining(payload));
  
  int ret=0;
  struct subscriber *src=NULL, *dst=NULL, *last=NULL;
  struct decode_context context;
  bzero(&context, sizeof context);
  
  if (header->source_port == MDP_PORT_TRACE){
    ret=WHYF("Invalid source port");
    goto end;
  }
  if (overlay_address_parse(&context, payload, &src)){
    ret=WHYF("Invalid source SID");
    goto end;
  }
  if (overlay_address_parse(&context, payload, &dst)){
    ret=WHYF("Invalid destination SID");
    goto end;
  }
  if (context.flags & DECODE_FLAG_INVALID_ADDRESS){
    ret=WHYF("Unknown address in trace packet");
    goto end;
  }

  INFOF("Trace from %s to %s", alloca_tohex_sid_t(src->sid), alloca_tohex_sid_t(dst->sid));
  struct internal_mdp_header next_header;
  next_header = *header;
  next_header.source = get_my_subscriber(1);
  next_header.destination = NULL;
  
  while(ob_remaining(payload)>0){
    struct subscriber *trace=NULL;
    if (overlay_address_parse(&context, payload, &trace)){
      ret=WHYF("Invalid SID in packet payload");
      goto end;
    }
    if (context.flags & DECODE_FLAG_INVALID_ADDRESS){
      ret=WHYF("Unknown SID in packet payload");
      goto end;
    }
    INFOF("Via %s", alloca_tohex_sid_t(trace->sid));
    
    if (trace->reachable==REACHABLE_SELF && !next_header.destination)
      // We're already in this trace, send the next packet to the node before us in the list
      next_header.destination = last;
    last = trace;
  }
  
  if (src->reachable==REACHABLE_SELF && last){
    // it came back to us, we can send the reply to our mdp client...
    next_header.destination=src;
    next_header.destination_port = header->source_port;
    next_header.source_port = MDP_PORT_TRACE;
  }
  
  if (!next_header.destination){
    // destination is our neighbour?
    if (dst->reachable & REACHABLE_DIRECT)
      next_header.destination = dst;
    // destination is indirect?
    else if (dst->reachable & REACHABLE_INDIRECT)
      next_header.destination = dst->next_hop;
    // destination is not reachable or is ourselves? bounce back to the previous node or the sender.
    else if (last)
      next_header.destination = last;
    else
      next_header.destination = src;
  }
  
  INFOF("Next node is %s", alloca_tohex_sid_t(next_header.destination->sid));
  
  // always write a full sid into the payload
  next_header.source->send_full=1;
  overlay_address_append(&context, next_payload, next_header.source);
  if (ob_overrun(next_payload)) {
    ret = WHYF("Unable to append my address to the trace");
    goto end;
  }
  ob_flip(next_payload);
  ret = overlay_send_frame(&next_header, next_payload);
end:
  ob_free(next_payload);
  RETURN(ret);
}
