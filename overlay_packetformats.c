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
#include "socket.h"
#include "str.h"
#include "strbuf.h"
#include "strbuf_helpers.h"
#include "overlay_buffer.h"
#include "overlay_interface.h"
#include "overlay_packet.h"
#include "route_link.h"

struct sockaddr_in loopback;


#define PACKET_UNICAST (1<<0)
#define PACKET_INTERFACE (1<<1)
#define PACKET_SEQ (1<<2)

#define SUPPORTED_PACKET_VERSION 1

int overlay_packet_init_header(int packet_version, int encapsulation, 
			       struct decode_context *context, struct overlay_buffer *buff, 
			       char unicast, char interface, int seq){
  
  if (packet_version <0 || packet_version > SUPPORTED_PACKET_VERSION)
    return WHY("Invalid packet version");
  if (encapsulation !=ENCAP_OVERLAY && encapsulation !=ENCAP_SINGLE)
    return WHY("Invalid packet encapsulation");
  
  ob_append_byte(buff, packet_version);
  ob_append_byte(buff, encapsulation);
  
  if (   context->interface->ifconfig.point_to_point 
      && context->interface->other_device 
      && packet_version>=1
  )
    context->point_to_point_device = context->interface->other_device;
  context->flags = DECODE_FLAG_ENCODING_HEADER;
  overlay_address_append(context, buff, get_my_subscriber());
  
  context->flags = 0;
  context->sender = get_my_subscriber();
  
  int flags=0;
  
  if (unicast)
    flags |= PACKET_UNICAST;
  if (interface)
    flags |= PACKET_INTERFACE;
  if (seq>=0)
    flags |= PACKET_SEQ;
  
  ob_append_byte(buff,flags);
  
  if (flags & PACKET_INTERFACE)
    ob_append_byte(buff,interface);
  
  if (flags & PACKET_SEQ)
    ob_append_byte(buff,seq);
  
  return 0;
}

// a frame destined for one of our local addresses, or broadcast, has arrived. Process it.
int process_incoming_frame(time_ms_t now, struct overlay_interface *UNUSED(interface), struct overlay_frame *f, struct decode_context *context)
{
  IN();
  switch(f->type)
  {
    case OF_TYPE_SELFANNOUNCE_ACK:
      link_state_legacy_ack(f, now);
      break;
      // data frames
    case OF_TYPE_RHIZOME_ADVERT:
      overlay_rhizome_saw_advertisements(context,f);
      break;
    case OF_TYPE_DATA:
      overlay_saw_mdp_containing_frame(f);
      break;
    case OF_TYPE_PLEASEEXPLAIN:
      process_explain(f);
      break;
    default:
      if (IF_DEBUG(verbose))
	DEBUGF(overlayframes, "Overlay type f->type=0x%x not supported", f->type);
  }
  RETURN(0);
  OUT();
}

// duplicate the frame and queue it
int overlay_forward_payload(struct overlay_frame *f){
  IN();
  if (f->ttl == 0){
    if (IF_DEBUG(verbose))
      DEBUGF(overlayframes, "NOT FORWARDING, due to ttl=0");
    RETURN(0);
  }
  
  if (IF_DEBUG(verbose))
    DEBUGF(overlayframes, "Forwarding payload for %s, ttl=%u",
	  (f->destination?alloca_tohex_sid_t(f->destination->sid):"broadcast"),
	  (unsigned)f->ttl);

  /* Queue frame for dispatch.
   Don't forget to put packet in the correct queue based on type.
   (e.g., mesh management, voice, video, ordinary or opportunistic).
   
   But the really important bit is to clone the frame, since the
   structure we are looking at here must be left as is and returned
   to the caller to do as they please */	  
  struct overlay_frame *qf=op_dup(f);
  if (!qf) 
    RETURN(WHY("Could not clone frame for queuing"));
  
  if (overlay_payload_enqueue(qf)) {
    op_free(qf);
    RETURN(WHY("failed to enqueue forwarded payload"));
  }
  
  RETURN(0);
  OUT();
}

// Parse the mdp envelope header
// may return (HEADER_PROCESS|HEADER_FORWARD) || -1
int parseMdpPacketHeader(struct decode_context *context, struct overlay_frame *frame, 
			 struct overlay_buffer *buffer, struct subscriber **nexthop)
{
  IN();
  int process=1;
  int forward=2;
  
  int flags = ob_get(buffer);
  if (flags<0)
    RETURN(WHY("Unable to read flags"));
  
  if (flags & PAYLOAD_FLAG_SENDER_SAME){
    if (!context->sender)
      context->flags |= DECODE_FLAG_INVALID_ADDRESS;
    frame->source = context->sender;
  }else{
    int ret=overlay_address_parse(context, buffer, &frame->source);
    if (ret<0)
      RETURN(WHY("Unable to parse payload source"));
    if (!frame->source || frame->source->reachable==REACHABLE_SELF){
      process=forward=0;
      if (IF_DEBUG(verbose))
	DEBUGF(overlayframes, "Ignoring my packet (or unparsable source)");
    }
  }
  
  if (flags & PAYLOAD_FLAG_TO_BROADCAST){
    if (!(flags & PAYLOAD_FLAG_ONE_HOP)){
      if (overlay_broadcast_parse(buffer, &frame->broadcast_id))
	RETURN(WHY("Unable to read broadcast address"));
      if (overlay_broadcast_drop_check(&frame->broadcast_id)){
	process=forward=0;
	if (IF_DEBUG(verbose))
	  DEBUGF(overlayframes, "Ignoring duplicate broadcast (%s)", alloca_tohex(frame->broadcast_id.id, BROADCAST_LEN));
      }
      if (link_state_should_forward_broadcast(context->sender)==0){
	forward=0;
	if (IF_DEBUG(verbose))
	  DEBUGF(overlayframes, "Not forwarding broadcast (%s), as we aren't a relay in the senders routing table", alloca_tohex(frame->broadcast_id.id, BROADCAST_LEN));
      }
    }
    frame->destination=NULL;
  }else{
    int ret=overlay_address_parse(context, buffer, &frame->destination);
    if (ret<0)
      RETURN(WHY("Unable to parse payload destination"));
    
    if (!frame->destination || frame->destination->reachable!=REACHABLE_SELF){
      process=0;
      if (IF_DEBUG(verbose))
	DEBUGF(overlayframes, "Don't process packet not addressed to me");
    }
    
    if (!(flags & PAYLOAD_FLAG_ONE_HOP)){
      ret=overlay_address_parse(context, buffer, nexthop);
      if (ret<0)
	RETURN(WHY("Unable to parse payload nexthop"));
      
      if (!(*nexthop) || (*nexthop)->reachable!=REACHABLE_SELF){
	forward=0;
	if (IF_DEBUG(verbose))
	  DEBUGF(overlayframes, "Don't forward packet not addressed to me");
      }
    }
  }
  
  if (flags & PAYLOAD_FLAG_ONE_HOP) {
    frame->ttl=1;
  } else {
    int ttl_qos = ob_get(buffer);
    if (ttl_qos<0)
      RETURN(WHY("Unable to read ttl"));
    frame->ttl = ttl_qos & 0x1F;
    frame->queue = (ttl_qos >> 5) & 3;
  }
  if (frame->ttl)
    --frame->ttl;
  if (frame->ttl == 0) {
    forward = 0;
    if (IF_DEBUG(verbose))
      DEBUGF(overlayframes, "NOT FORWARDING, due to ttl=0");
  }
  
  if (flags & PAYLOAD_FLAG_LEGACY_TYPE){
    int ftype = ob_get(buffer);
    if (ftype == -1)
      RETURN(WHY("Unable to read type"));
    frame->type = ftype;
  }else
    frame->type=OF_TYPE_DATA;

  if (context->packet_version >= 1){
    int seq = ob_get(buffer);
    if (seq == -1)
      RETURN(WHY("Unable to read packet seq"));
    if (link_received_duplicate(context, seq)){
      if (IF_DEBUG(verbose))
	DEBUG(overlayframes, "Don't process or forward duplicate payloads");
      forward=process=0;
    }
  }
  frame->modifiers=flags;
  frame->packet_version = context->packet_version;
  
  // if we can't understand one of the addresses, skip processing the payload
  if ((forward||process)&& (context->flags & DECODE_FLAG_INVALID_ADDRESS)){
    if (IF_DEBUG(verbose))
      DEBUG(overlayframes, "Don't process or forward with invalid addresses");
    forward=process=0;
  }
  RETURN(forward|process);
  OUT();
}

int parseEnvelopeHeader(struct decode_context *context, struct overlay_interface *interface, 
			struct socket_address *addr, struct overlay_buffer *buffer){
  IN();

  context->interface = interface;
  if (interface->ifconfig.point_to_point && interface->other_device)
    context->point_to_point_device = interface->other_device;
  
  context->sender_interface = 0;

  context->packet_version = ob_get(buffer);

  if (context->packet_version < 0 || context->packet_version > SUPPORTED_PACKET_VERSION)
    RETURN(WHYF("Packet version %d not recognised.", context->packet_version));
  
  context->encapsulation = ob_get(buffer);
  if (context->encapsulation !=ENCAP_OVERLAY && context->encapsulation !=ENCAP_SINGLE)
    RETURN(WHYF("Invalid packet encapsulation, %d", context->encapsulation));
  
  if (overlay_address_parse(context, buffer, &context->sender))
    RETURN(WHY("Unable to parse sender"));
  
  int packet_flags = ob_get(buffer);
  
  int sender_seq = -1;

  if (packet_flags & PACKET_INTERFACE)
    context->sender_interface = ob_get(buffer);
  
  if (packet_flags & PACKET_SEQ)
    sender_seq = ob_get(buffer)&0xFF;
  
  if (addr)
    context->addr=*addr;

  if (context->sender){
    if (context->sender->reachable==REACHABLE_SELF){
      if (IF_DEBUG(verbose))
	DEBUG(overlayframes, "Completely ignore packets I sent");
      RETURN(1);
    }
    
    if (context->packet_version > context->sender->max_packet_version)
      context->sender->max_packet_version=context->packet_version;
    
    if (interface->ifconfig.point_to_point && interface->other_device!=context->sender){
      INFOF("Established point to point link with %s on %s", alloca_tohex_sid_t(context->sender->sid), interface->name);
      context->point_to_point_device = context->interface->other_device = context->sender;
    }
    
    DEBUGF(overlayframes, "Received %s packet seq %d from %s on %s %s", 
	packet_flags & PACKET_UNICAST?"unicast":"broadcast",
	sender_seq, alloca_tohex_sid_t(context->sender->sid), 
	interface->name, alloca_socket_address(addr));
  }
  
  RETURN(link_received_packet(context, sender_seq, packet_flags & PACKET_UNICAST));
  OUT();
}

int packetOkOverlay(struct overlay_interface *interface,unsigned char *packet, size_t len,
		    struct socket_address *recvaddr)
{
  IN();
  /* 
     This function decodes overlay packets which have been assembled for delivery overy IP networks.
     IP based wireless networks have a high, but limited rate of packets that can be sent. In order 
     to increase throughput of small payloads, we ammend many payloads together and have used a scheme 
     to compress common network identifiers.
   
     A different network type may have very different constraints on the number and size of packets,
     and may need a different encoding scheme to use the bandwidth efficiently.
   
     The current structure of an overlay packet is as follows;
     Fixed header [0x4F, 0x10]
     Version [0x00, 0x01]
     
     Each frame within the packet has the following fields:
     Frame type (8-24bits)
     TTL (8bits)
     Remaining frame size (RFS) (see overlay_payload.c or overlay_buffer.c for explanation of format)
     Next hop (variable length due to address abbreviation)
     Destination (variable length due to address abbreviation)
     Source (variable length due to address abbreviation)
     Payload (length = RFS- len(frame type) - len(next hop)

     This structure is intended to allow relaying nodes to quickly ignore frames that are
     not addressed to them as either the next hop or final destination.

     The RFS field uses additional bytes to encode the length of longer frames.  
     This provides us with a slight space saving for the common case of short frames.
     
     The frame payload itself can be enciphered with the final destination's public key, so 
     that it is not possible for the relaying 3rd parties to observe the content.  

     Naturally some information will leak simply based on the size, periodicity and other 
     characteristics of the traffic, and some 3rd parties may be malevolent, so noone should
     assume that this provides complete security.

     It would be possible to design a super-paranoid mode where onion routing is used with
     concentric shells of encryption so that each hop can only work out the next node to send it
     to.  However, that would result in rather large frames, which may well betray more information 
     than the super-paranoid mode would hide.

     Note also that it is possible to dispatch frames on a local link which are addressed to
     broadcast, but are enciphered.  In that situation only the intended recipient can
     decode the frame, but at the cost of having all nodes on the local link having to decrypt
     frame. Of course the nodes may elect to not decrypt such anonymous frames.  

     Such frames could even be flooded throughout part of the mesh by having the TTL>1, and
     optionally with an anonymous source address to provide some plausible deniability for both
     sending and reception if combined with a randomly selected TTL to give the impression of
     the source having received the frame from elsewhere.
  */

  if (IF_DEBUG(packetrx) || interface->ifconfig.debug) {
    _DEBUGF("Received on %s, len %d", interface->name, (int)len);
    DEBUG_packet_visualise("Received packet",packet,len);
  }
  
  struct overlay_frame f;
  struct decode_context context;
  bzero(&context, sizeof context);
  bzero(&f,sizeof f);
  
  time_ms_t now = gettime_ms();
  struct overlay_buffer *b = ob_static(packet, len);
  ob_limitsize(b, len);
  
  f.interface = interface;
  
  int ret=parseEnvelopeHeader(&context, interface, recvaddr, b);
  if (ret){
    ob_free(b);
    RETURN(ret);
  }
  f.sender_interface = context.sender_interface;
  interface->recv_count++;
  
  while(ob_remaining(b)>0){
    context.flags = 0;
    struct subscriber *nexthop=NULL;
    bzero(f.broadcast_id.id, BROADCAST_LEN);
    
    unsigned char *header_start = ob_ptr(b)+ob_position(b);
    int header_valid = parseMdpPacketHeader(&context, &f, b, &nexthop);
    if (header_valid<0){
      ret = WHY("Header is too short");
      break;
    }
    
    // TODO allow for single byte length?
    size_t payload_len;
    
    switch (context.encapsulation){
      case ENCAP_SINGLE:
	payload_len = ob_remaining(b);
	break;
      default:
      case ENCAP_OVERLAY:
	payload_len = ob_get_ui16(b);
	if (payload_len > ob_remaining(b)){
	  unsigned char *current = ob_ptr(b)+ob_position(b);
	  if (IF_DEBUG(overlayframes))
	    dump("Payload Header", header_start, current - header_start);
	  ret = WHYF("Payload length %zd suggests frame should be %zd bytes, but was only %zd", 
	             payload_len, ob_position(b)+payload_len, len);
	  
	  // TODO signal reduced MTU?
	  goto end;
	}
	break;
    }

    int next_payload = ob_position(b) + payload_len;
    
    if (IF_DEBUG(overlayframes)) {
      DEBUGF(overlayframes, "Received payload type %x, len %zd", f.type, payload_len);
      DEBUGF(overlayframes, "Payload from %s", f.source?alloca_tohex_sid_t(f.source->sid):"NULL");
      DEBUGF(overlayframes, "Payload to %s", (f.destination?alloca_tohex_sid_t(f.destination->sid):"broadcast"));
      if (!is_all_matching(f.broadcast_id.id, BROADCAST_LEN, 0))
	DEBUGF(overlayframes, "Broadcast id %s", alloca_tohex(f.broadcast_id.id, BROADCAST_LEN));
      if (nexthop)
	DEBUGF(overlayframes, "Next hop %s", alloca_tohex_sid_t(nexthop->sid));
    }
    
    if (header_valid!=0){

      f.payload = ob_slice(b, ob_position(b), payload_len);
      if (!f.payload){
	// out of memory?
	WHY("Unable to slice payload");
	break;
      }
      // mark the entire payload as having valid data
      ob_limitsize(f.payload, payload_len);
    
      // forward payloads that are for someone else or everyone
      if (header_valid&HEADER_FORWARD)
	overlay_forward_payload(&f);
      
      // process payloads that are for me or everyone
      if (header_valid&HEADER_PROCESS)
	process_incoming_frame(now, interface, &f, &context);

      // We may need to schedule an ACK / NACK soon when we receive a payload addressed to us, or broadcast
      if (f.modifiers & PAYLOAD_FLAG_ACK_SOON && 
	(f.next_hop == get_my_subscriber() || f.destination == get_my_subscriber() || !f.destination))
        link_state_ack_soon(context.sender);
    }
    
    if (f.payload){
      ob_free(f.payload);
      f.payload=NULL;
    }
    b->position=next_payload;
  }
  
end:
  send_please_explain(&context, get_my_subscriber(), context.sender);
  
  ob_free(b);
  
  RETURN(ret);
  OUT();
}
