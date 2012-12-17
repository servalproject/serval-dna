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
#include "strbuf.h"
#include "overlay_buffer.h"
#include "overlay_packet.h"

struct sockaddr_in loopback;

unsigned char magic_header[]={0x00, 0x01};

#define PACKET_UNICAST (1<<0)
#define PACKET_INTERFACE (1<<1)
#define PACKET_SEQ (1<<2)

int overlay_packet_init_header(struct decode_context *context, struct overlay_buffer *buff, 
			       struct subscriber *destination, 
			       char unicast, char interface, char seq){
  
  if (ob_append_bytes(buff,magic_header,sizeof magic_header))
    return -1;
  if (overlay_address_append(context, buff, my_subscriber))
    return -1;
  context->sender = my_subscriber;
  
  int flags=0;
  
  if (unicast)
    flags |= PACKET_UNICAST;
  if (interface)
    flags |= PACKET_INTERFACE;
  if (seq)
    flags |= PACKET_SEQ;
  
  ob_append_byte(buff,flags);
  
  if (flags & PACKET_INTERFACE)
    ob_append_byte(buff,interface);
  
  if (flags & PACKET_SEQ)
    ob_append_byte(buff,seq);
  
  return 0;
}

// a frame destined for one of our local addresses, or broadcast, has arrived. Process it.
int process_incoming_frame(time_ms_t now, struct overlay_interface *interface, struct overlay_frame *f, struct decode_context *context){
  IN();
  int id = (interface - overlay_interfaces);
  switch(f->type)
  {
    case OF_TYPE_SELFANNOUNCE_ACK:
      if (config.debug.overlayframes)
	DEBUG("Processing OF_TYPE_SELFANNOUNCE_ACK");
      overlay_route_saw_selfannounce_ack(f,now);
      break;
    case OF_TYPE_NODEANNOUNCE:
      if (config.debug.overlayframes)
	DEBUG("Processing OF_TYPE_NODEANNOUNCE");
      overlay_route_saw_advertisements(id,f,context,now);
      break;
      
      // data frames
    case OF_TYPE_RHIZOME_ADVERT:
      if (config.debug.overlayframes)
	DEBUG("Processing OF_TYPE_RHIZOME_ADVERT");
      overlay_rhizome_saw_advertisements(id,f,now);
      break;
    case OF_TYPE_DATA:
    case OF_TYPE_DATA_VOICE:
      if (config.debug.overlayframes)
	DEBUG("Processing OF_TYPE_DATA");
      overlay_saw_mdp_containing_frame(f,now);
      break;
    case OF_TYPE_PLEASEEXPLAIN:
      if (config.debug.overlayframes)
	DEBUG("Processing OF_TYPE_PLEASEEXPLAIN");
      process_explain(f);
      break;
    default:
      RETURN(WHYF("Support for f->type=0x%x not implemented",f->type));
  }
  RETURN(0);
}

// duplicate the frame and queue it
int overlay_forward_payload(struct overlay_frame *f){
  IN();
  if (f->ttl<=0)
    RETURN(0);
  
  if (config.debug.overlayframes)
    DEBUGF("Forwarding payload for %s, ttl=%d",
	  (f->destination?alloca_tohex_sid(f->destination->sid):"broadcast"),
	  f->ttl);

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
}

int packetOkOverlay(struct overlay_interface *interface,unsigned char *packet, size_t len,
		    int recvttl, struct sockaddr *recvaddr, size_t recvaddrlen)
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

  if (recvaddr->sa_family!=AF_INET)
    RETURN(WHYF("Unexpected protocol family %d",recvaddr->sa_family));
  
  struct overlay_frame f;
  struct decode_context context;
  bzero(&context, sizeof context);
  bzero(&f,sizeof f);
  
  time_ms_t now = gettime_ms();
  struct overlay_buffer *b = ob_static(packet, len);
  ob_limitsize(b, len);
  
  if (ob_get(b)!=magic_header[0] || ob_get(b)!=magic_header[1]){
    ob_free(b);
    RETURN(WHY("Packet type not recognised."));
  }
  
  context.interface = f.interface = interface;
  
  f.recvaddr = *((struct sockaddr_in *)recvaddr); 

  if (config.debug.overlayframes)
    DEBUG("Received overlay packet");
  
  if (overlay_address_parse(&context, b, &context.sender)){
    WHY("Unable to parse sender");
  }
  
  int packet_flags = ob_get(b);
  
  int sender_interface = 0;
  if (packet_flags & PACKET_INTERFACE)
    sender_interface = ob_get(b);
  
  if (packet_flags & PACKET_SEQ)
    ob_get(b); // sequence number, not implemented yet
  
  if (context.sender){
    
    if (context.sender->reachable==REACHABLE_SELF){
      ob_free(b);
      RETURN(0);
    }
    
    context.sender->last_rx = now;
    
    // TODO probe unicast links when we detect an address change.
    
    // always update the IP address we heard them from, even if we don't need to use it right now
    context.sender->address = f.recvaddr;
    
    // if this is a dummy announcement for a node that isn't in our routing table
    if (context.sender->reachable == REACHABLE_NONE) {
      context.sender->interface = interface;
      
      // assume for the moment, that we can reply with the same packet type
      if (packet_flags&PACKET_UNICAST){
	/* Note the probe payload must be queued before any SID/SAS request so we can force the packet to have a full sid */
	overlay_send_probe(context.sender, f.recvaddr, interface, OQ_MESH_MANAGEMENT);
	set_reachable(context.sender, REACHABLE_UNICAST|REACHABLE_ASSUMED);
      }else{
	set_reachable(context.sender, REACHABLE_BROADCAST|REACHABLE_ASSUMED);
      }
    }
    
    if ((!(packet_flags&PACKET_UNICAST)) && context.sender->last_acked + interface->tick_ms <= now){
      overlay_route_ack_selfannounce(interface,
				     context.sender->last_acked>now - 3*interface->tick_ms?context.sender->last_acked:now,
				     now,sender_interface,context.sender);
      
      context.sender->last_acked = now;
    }
  }
  
  if (packet_flags & PACKET_UNICAST)
    context.addr=f.recvaddr;
  else
    context.addr=interface->broadcast_address;
  
  while(b->position < b->sizeLimit){
    context.invalid_addresses=0;
    struct subscriber *nexthop=NULL;
    bzero(f.broadcast_id.id, BROADCAST_LEN);
    int process=1;
    int forward=1;
    int flags = ob_get(b);
    if (flags<0){
      WHY("Unable to parse payload flags");
      break;
    }
      
    if (flags & PAYLOAD_FLAG_SENDER_SAME){
      if (!context.sender)
	context.invalid_addresses=1;
      f.source = context.sender;
    }else{
      if (overlay_address_parse(&context, b, &f.source)){
	WHY("Unable to parse payload source");
	break;
      }
      if (!f.source || f.source->reachable==REACHABLE_SELF)
	process=forward=0;
    }
    
    if (flags & PAYLOAD_FLAG_TO_BROADCAST){
      if (!(flags & PAYLOAD_FLAG_ONE_HOP)){
	if (overlay_broadcast_parse(b, &f.broadcast_id)){
	  WHY("Unable to parse payload broadcast id");
	  break;
	}
	if (overlay_broadcast_drop_check(&f.broadcast_id)){
	  process=forward=0;
	  if (config.debug.overlayframes)
	    DEBUGF("Ignoring duplicate broadcast (%s)", alloca_tohex(f.broadcast_id.id, BROADCAST_LEN));
	}
      }
      f.destination=NULL;
    }else{
      if (overlay_address_parse(&context, b, &f.destination)){
	WHY("Unable to parse payload destination");
	break;
      }
      
      if (!f.destination || f.destination->reachable!=REACHABLE_SELF){
	process=0;
      }
      
      if (!(flags & PAYLOAD_FLAG_ONE_HOP)){
	if (overlay_address_parse(&context, b, &nexthop)){
	  WHY("Unable to parse payload nexthop");
	  break;
	}
	
	if (!nexthop || nexthop->reachable!=REACHABLE_SELF){
	  forward=0;
	}
      }
    }
    
    if (flags & PAYLOAD_FLAG_ONE_HOP){
      f.ttl=1;
    }else{
      int ttl_qos = ob_get(b);
      if (ttl_qos<0){
	WHY("Unable to parse ttl/qos");
	break;
      }
      f.ttl = ttl_qos & 0x1F;
      f.queue = (ttl_qos >> 5) & 3;
    }
    f.ttl--;
    if (f.ttl<=0)
      forward=0;
    
    if (flags & PAYLOAD_FLAG_LEGACY_TYPE){
      f.type=ob_get(b);
      if (f.type<0){
	WHY("Unable to parse payload type");
	break;
      }
    }else
      f.type=OF_TYPE_DATA;
    
    f.modifiers=flags;

    // TODO allow for one byte length
    unsigned int payload_len = ob_get_ui16(b);

    if (payload_len > ob_remaining(b)){
      WHYF("Unable to parse payload length (%d)", payload_len);
      break;
    }
    
    int next_payload = ob_position(b) + payload_len;
    
    if (f.source)
      f.source->last_rx = now;
    
    // if we can't understand one of the addresses, skip processing the payload
    if (context.invalid_addresses){
      if (config.debug.overlayframes)
	DEBUG("Skipping payload due to unknown addresses");
      goto next;
    }

    if (config.debug.overlayframes){
      DEBUGF("Received payload type %x, len %d", f.type, next_payload - b->position);
      DEBUGF("Payload from %s", alloca_tohex_sid(f.source->sid));
      DEBUGF("Payload to %s", (f.destination?alloca_tohex_sid(f.destination->sid):"broadcast"));
      if (!is_all_matching(f.broadcast_id.id, BROADCAST_LEN, 0))
	DEBUGF("Broadcast id %s", alloca_tohex(f.broadcast_id.id, BROADCAST_LEN));
      if (nexthop)
	DEBUGF("Next hop %s", alloca_tohex_sid(nexthop->sid));
    }

    if (!process && !forward)
      goto next;
    
    f.payload = ob_slice(b, b->position, payload_len);
    if (!f.payload){
      WHY("Payload length is longer than remaining packet size");
      break;
    }
    // mark the entire payload as having valid data
    ob_limitsize(f.payload, payload_len);
    
    // forward payloads that are for someone else or everyone
    if (forward){
      overlay_forward_payload(&f);
    }
    
    // process payloads that are for me or everyone
    if (process){
      process_incoming_frame(now, interface, &f, &context);
    }
    
  next:
    if (f.payload){
      ob_free(f.payload);
      f.payload=NULL;
    }
    b->position=next_payload;
  }
  
  send_please_explain(&context, my_subscriber, context.sender);
  
  ob_free(b);
  
  RETURN(0);
}
