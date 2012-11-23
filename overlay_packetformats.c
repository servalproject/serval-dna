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
#include "str.h"
#include "strbuf.h"
#include "overlay_buffer.h"
#include "overlay_packet.h"

struct sockaddr_in loopback;

unsigned char magic_header[]={0x00, 0x01};

int overlay_packet_init_header(struct overlay_interface *interface, struct decode_context *context, 
			       struct overlay_buffer *buff){
  if (ob_append_bytes(buff,magic_header,sizeof magic_header))
    return -1;
  return overlay_address_append_self(context, interface, buff);
}


// a frame destined for one of our local addresses, or broadcast, has arrived. Process it.
int process_incoming_frame(time_ms_t now, struct overlay_interface *interface, struct overlay_frame *f, struct decode_context *context){
  int id = (interface - overlay_interfaces);
  switch(f->type)
  {
      // route control frames
    case OF_TYPE_SELFANNOUNCE:
      if (debug&DEBUG_OVERLAYFRAMES)
	DEBUG("Processing OF_TYPE_SELFANNOUNCE");
      overlay_route_saw_selfannounce(f,now);
      break;
    case OF_TYPE_SELFANNOUNCE_ACK:
      if (debug&DEBUG_OVERLAYFRAMES)
	DEBUG("Processing OF_TYPE_SELFANNOUNCE_ACK");
      overlay_route_saw_selfannounce_ack(f,now);
      break;
    case OF_TYPE_NODEANNOUNCE:
      if (debug&DEBUG_OVERLAYFRAMES)
	DEBUG("Processing OF_TYPE_NODEANNOUNCE");
      overlay_route_saw_advertisements(id,f,context,now);
      break;
      
      // data frames
    case OF_TYPE_RHIZOME_ADVERT:
      if (debug&DEBUG_OVERLAYFRAMES)
	DEBUG("Processing OF_TYPE_RHIZOME_ADVERT");
      overlay_rhizome_saw_advertisements(id,f,now);
      break;
    case OF_TYPE_DATA:
    case OF_TYPE_DATA_VOICE:
      if (debug&DEBUG_OVERLAYFRAMES)
	DEBUG("Processing OF_TYPE_DATA");
      overlay_saw_mdp_containing_frame(f,now);
      break;
    case OF_TYPE_PLEASEEXPLAIN:
      if (debug&DEBUG_OVERLAYFRAMES)
	DEBUG("Processing OF_TYPE_PLEASEEXPLAIN");
      process_explain(f);
      break;
    default:
      return WHYF("Support for f->type=0x%x not yet implemented",f->type);
      break;
  }
  return 0;
}

// duplicate the frame and queue it
int overlay_forward_payload(struct overlay_frame *f){
  if (f->ttl<=0)
    return 0;
  
  if (debug&DEBUG_OVERLAYFRAMES)
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
    return WHY("Could not clone frame for queuing");
  
  /* Make sure voice traffic gets priority */
  if (qf->type==OF_TYPE_DATA_VOICE) {
    qf->queue=OQ_ISOCHRONOUS_VOICE;
    rhizome_saw_voice_traffic();
  }
  
  if (overlay_payload_enqueue(qf)) {
    op_free(qf);
    return WHY("failed to enqueue forwarded payload");
  }
  
  return 0;
}

int packetOkOverlay(struct overlay_interface *interface,unsigned char *packet, size_t len,
		    int recvttl, struct sockaddr *recvaddr, size_t recvaddrlen)
{
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

  struct overlay_frame f;
  struct decode_context context={
    .please_explain=NULL,
  };
  
  if (len<HEADERFIELDS_LEN)
    return WHY("Packet is too short");
  
  time_ms_t now = gettime_ms();
  struct overlay_buffer *b = ob_static(packet, len);
  ob_limitsize(b, len);
  
  if (ob_get(b)!=magic_header[0] || ob_get(b)!=magic_header[1])
    return WHY("Packet type not recognised.");
  
  bzero(&f,sizeof(struct overlay_frame));
  
  if (recvaddr->sa_family==AF_INET){
    f.recvaddr=recvaddr; 
    if (debug&DEBUG_OVERLAYFRAMES)
      DEBUG("Received overlay packet");
  } else {
    if (interface->fileP) {
      /* dummy interface, so tell to use localhost */
      loopback.sin_family = AF_INET;
      loopback.sin_port = 0;
      loopback.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      f.recvaddr=(struct sockaddr *)&loopback;
    } else 
      /* some other sort of interface, so we can't offer any help here */
      f.recvaddr=NULL;
  }

  overlay_address_parse(&context, b, NULL, &context.sender);
  
  if (context.sender && context.sender->reachable==REACHABLE_SELF){
    ob_free(b);
    return 0;
  }
  
  while(b->position < b->sizeLimit){
    context.invalid_addresses=0;
    
    int flags = ob_get(b);
    
    /* Get normal form of packet type and modifiers */
    f.type=flags&OF_TYPE_BITS;
    f.modifiers=flags&OF_MODIFIER_BITS;

    f.queue = (f.modifiers & OF_QUEUE_BITS) +1;
    
    /* Get time to live */
    f.ttl=ob_get(b);
    f.ttl--;

    /* Decode length of remainder of frame */
    int payload_len=rfs_decode(b->bytes, &b->position);

    if (payload_len <=0) {
      /* assume we fell off the end of the packet */
      break;
    }

    int next_payload = b->position + payload_len;
    
    /* Always attempt to resolve all of the addresses in a packet, or we could fail to understand an important payload 
     eg, peer sends two payloads travelling in opposite directions;
	[Next, Dest, Sender] forwarding a payload we just send, so Sender == Me
	[Next, Dest, Sender] delivering a payload to us so Next == Me
     
     But Next would be encoded as OA_CODE_PREVIOUS, so we must parse all three addresses, 
     even if Next is obviously not intended for us
     */
    
    struct subscriber *nexthop=NULL;
    bzero(f.broadcast_id.id, BROADCAST_LEN);
    
    // if the structure of the addresses looks wrong, stop immediately
    if (overlay_address_parse(&context, b, &f.broadcast_id, &nexthop)
	|| overlay_address_parse(&context, b, NULL, &f.destination)
	|| overlay_address_parse(&context, b, NULL, &f.source)){
      goto next;
    }
    
    // if we can't understand one of the addresses, skip processing the payload
    if (context.invalid_addresses)
      goto next;

    if (debug&DEBUG_OVERLAYFRAMES){
      DEBUGF("Received payload type %x, len %d", f.type, next_payload - b->position);
      DEBUGF("Payload from %s", alloca_tohex_sid(f.source->sid));
      DEBUGF("Payload to %s", (f.destination?alloca_tohex_sid(f.destination->sid):"broadcast"));
      if (!is_all_matching(f.broadcast_id.id, BROADCAST_LEN, 0))
	DEBUGF("Broadcast id %s", alloca_tohex(f.broadcast_id.id, BROADCAST_LEN));
      if (nexthop)
	DEBUGF("Next hop %s", alloca_tohex_sid(nexthop->sid));
    }

    // ignore any payload we sent
    if (f.source->reachable==REACHABLE_SELF){
      if (debug&DEBUG_OVERLAYFRAMES)
	DEBUGF("Ignoring payload from myself (%s)", alloca_tohex_sid(f.source->sid));
      goto next;
    }
    
    // skip unicast payloads that aren't for me
    if (nexthop && nexthop->reachable!=REACHABLE_SELF){
      if (debug&DEBUG_OVERLAYFRAMES)
	DEBUGF("Ignoring payload that is not meant for me (%s)", alloca_tohex_sid(nexthop->sid));
      goto next;
    }
      
    // skip broadcast payloads we've already seen
    if ((!nexthop) && overlay_broadcast_drop_check(&f.broadcast_id)){
      if (debug&DEBUG_OVERLAYFRAMES)
	DEBUGF("Ignoring duplicate broadcast (%s)", alloca_tohex(f.broadcast_id.id, BROADCAST_LEN));
      goto next;
    }
    
    f.payload = ob_slice(b, b->position, next_payload - b->position);
    if (!f.payload){
      WHY("Payload length is longer than remaining packet size");
      break;
    }
    // mark the entire payload as having valid data
    ob_limitsize(f.payload, next_payload - b->position);
    
    // forward payloads that are for someone else or everyone
    if ((!f.destination) || 
	(f.destination->reachable != REACHABLE_SELF && f.destination->reachable != REACHABLE_NONE)){
      overlay_forward_payload(&f);
    }
    
    // process payloads that are for me or everyone
    if ((!f.destination) || f.destination->reachable==REACHABLE_SELF){
      process_incoming_frame(now, interface, &f, &context);
    }
    
  next:
    if (f.payload){
      ob_free(f.payload);
      f.payload=NULL;
    }
    b->position=next_payload;
  }
  
  if (context.sender){
    struct sockaddr_in *addr=(struct sockaddr_in *)recvaddr;
    
    // always update the IP address we heard them from, even if we don't need to use it right now
    context.sender->address = *addr;
    
    // if this is a dummy announcement for a node that isn't in our routing table
    if ((context.sender->reachable == REACHABLE_NONE || context.sender->reachable == REACHABLE_UNICAST) && 
	(!context.sender->node) &&
	(interface->fileP || recvaddr->sa_family==AF_INET)){
      
      // mark this subscriber as reachable directly via unicast.
      reachable_unicast(context.sender, interface, addr->sin_addr, ntohs(addr->sin_port));
    }
  }
  
  ob_free(b);
  
  send_please_explain(&context, my_subscriber, context.sender);
  return 0;
}

int overlay_add_selfannouncement(struct decode_context *context, int interface,struct overlay_buffer *b)
{

  /* Pull the first record from the HLR database and turn it into a
     self-announcment. These are shorter than regular Subscriber Observation
     Notices (SON) because they are just single-hop announcments of presence.

     Do we really need to push the whole SID (32 bytes), or will just, say, 
     8 do so that we use a prefix of the SID which is still very hard to forge?
     
     A hearer of a self-announcement who has not previously seen the sender might
     like to get some authentication to prevent naughty people from spoofing routes.

     We can do this by having ourselves, the sender, keep track of the last few frames
     we have sent, so that we can be asked to sign them.  Actually, we won't sign them, 
     as that is too slow/energy intensive, but we could use a D-H exchange with the neighbour,
     performed once to get a shared secret that can be used to feed a stream cipher to
     produce some sort of verification.

     XXX - But this functionality really needs to move up a level to whole frame composition.
  */

  time_ms_t now = gettime_ms();

  /* XXX - BATMAN uses various TTLs, but I think that it may just be better to have all TTL=1,
   and have the onward nodes selectively choose which nodes to on-announce.  If we prioritise
   newly arrived nodes somewhat (or at least reserve some slots for them), then we can still
   get the good news travels fast property of BATMAN, but without having to flood in the formal
   sense. */
  /* Add space for Remaining Frame Size field.  This will always be a single byte
   for self-announcments as they are always <256 bytes. */
  if (overlay_packet_append_header(b, OF_TYPE_SELFANNOUNCE, 1, 1+8+1+SID_SIZE+4+4+1))
    return WHY("Could not add self-announcement header");
  
  /* Add next-hop address.  Always link-local broadcast for self-announcements */
  struct broadcast broadcast_id;
  overlay_broadcast_generate_address(&broadcast_id);
  if (overlay_broadcast_append(context, b, &broadcast_id))
    return WHY("Could not write broadcast address to self-announcement");

  /* Add final destination.  Always broadcast for self-announcments. */
  if (ob_append_byte(b, OA_CODE_PREVIOUS))
    return WHY("Could not add self-announcement header");

  /* Add our SID to the announcement as sender */
  if (overlay_address_append_self(context, &overlay_interfaces[interface], b))
    return -1;
  
  /* Sequence number range.  Based on one tick per millisecond. */
  time_ms_t last_ms = overlay_interfaces[interface].last_tick_ms;
  // If this interface has not been ticked yet (no selfannounce sent) then invent the prior sequence
  // number: one millisecond ago.
  if (last_ms == -1)
    last_ms = now - 1;
  if (ob_append_ui32(b, last_ms))
    return WHY("Could not add low sequence number to self-announcement");
  if (ob_append_ui32(b, now))
    return WHY("Could not add high sequence number to self-announcement");
  if (debug&DEBUG_OVERLAYINTERFACES)
    DEBUGF("interface #%d: last_tick_ms=%lld, now=%lld (delta=%lld)",
	interface,
	(long long)overlay_interfaces[interface].last_tick_ms,
	(long long)now,
	(long long)(now - last_ms)
      );
  overlay_interfaces[interface].last_tick_ms = now;

  /* A byte that indicates which interface we are sending over */
  if (ob_append_byte(b,interface))
    return WHY("Could not add interface number to self-announcement");

  ob_patch_rfs(b, COMPUTE_RFS_LENGTH);
  
  return 0;
}
