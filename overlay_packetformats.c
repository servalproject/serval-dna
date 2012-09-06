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
#include "strbuf.h"
#include "overlay_buffer.h"
#include "overlay_packet.h"

struct sockaddr_in loopback = {
  .sin_family=0,
  .sin_port=0,
  .sin_addr.s_addr=0x0100007f
};

// a frame destined for one of our local addresses, or broadcast, has arrived. Process it.
int process_incoming_frame(time_ms_t now, struct overlay_interface *interface, struct overlay_frame *f){
  int id = (interface - overlay_interfaces);
  switch(f->type)
  {
      // route control frames
    case OF_TYPE_SELFANNOUNCE:
      overlay_route_saw_selfannounce(f,now);
      break;
    case OF_TYPE_SELFANNOUNCE_ACK:
      overlay_route_saw_selfannounce_ack(f,now);
      break;
    case OF_TYPE_NODEANNOUNCE:
      overlay_route_saw_advertisements(id,f,now);
      break;
      
      // data frames
    case OF_TYPE_RHIZOME_ADVERT:
      overlay_rhizome_saw_advertisements(id,f,now);
      break;
    case OF_TYPE_DATA:
    case OF_TYPE_DATA_VOICE:
      overlay_saw_mdp_containing_frame(f,now);
      break;
    default:
      return WHYF("Support for f->type=0x%x not yet implemented",f->type);
      break;
  }
  return 0;
}

// duplicate the frame and queue it
int overlay_forward_payload(struct overlay_frame *f){
  f->ttl--;
  if (f->ttl<=0)
    return 0;
  
  if (debug&DEBUG_OVERLAYFRAMES)
    DEBUG("Forwarding frame");

  /* Queue frame for dispatch.
   Don't forget to put packet in the correct queue based on type.
   (e.g., mesh management, voice, video, ordinary or opportunistic).
   
   But the really important bit is to clone the frame, since the
   structure we are looking at here must be left as is and returned
   to the caller to do as they please */	  
  struct overlay_frame *qf=op_dup(f);
  if (!qf) 
    return WHY("Could not clone frame for queuing");
  
  // TODO include priority in packet header
  int qn=OQ_ORDINARY;
  /* Make sure voice traffic gets priority */
  if ((qf->type&OF_TYPE_BITS)==OF_TYPE_DATA_VOICE) {
    qn=OQ_ISOCHRONOUS_VOICE;
    rhizome_saw_voice_traffic();
  }
  
  if (overlay_payload_enqueue(qn,qf)) {
    op_free(qf);
    return WHY("failed to enqueue forwarded payload");
  }
  
  return 0;
}

int packetOkOverlay(struct overlay_interface *interface,unsigned char *packet, size_t len,
		    unsigned char *transaction_id,int recvttl,
		    struct sockaddr *recvaddr, size_t recvaddrlen, int parseP)
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
  time_ms_t now = gettime_ms();
  struct overlay_buffer *b = ob_static(packet, len);
  ob_limitsize(b, len);
  // skip magic bytes and version as they have already been parsed
  b->position=4;
  
  bzero(&f,sizeof(struct overlay_frame));
  
  if (recvaddr->sa_family==AF_INET){
    f.recvaddr=recvaddr; 
    if (debug&DEBUG_OVERLAYFRAMES)
      DEBUG("Received overlay packet");
    
  } else {
    if (interface->fileP) {
      /* dummy interface, so tell to use 0.0.0.0 */
      f.recvaddr=(struct sockaddr *)&loopback;
    } else 
      /* some other sort of interface, so we can't offer any help here */
      f.recvaddr=NULL;
  }

  overlay_address_clear();

  // TODO put sender of packet and sequence number in envelope header
  // Then we can quickly drop reflected broadcast packets
  // currently we see annoying errors as we attempt to parse each payload
  // plus with a sequence number we can detect dropped packets and nack them for retransmission
  
  /* Skip magic bytes and version */
  while(b->position < b->sizeLimit){
    int flags = ob_get(b);
    
    /* Get normal form of packet type and modifiers */
    f.type=flags&OF_TYPE_BITS;
    f.modifiers=flags&OF_MODIFIER_BITS;

    switch(f.type){
      case OF_TYPE_EXTENDED20:
	/* Eat the next two bytes */
	f.type=OF_TYPE_FLAG_E20|flags|(ob_get(b)<<4)|(ob_get(b)<<12);
	f.modifiers=0;
	break;
	  
      case OF_TYPE_EXTENDED12:
	/* Eat the next byte */
	f.type=OF_TYPE_FLAG_E12|flags|(ob_get(b)<<4);
	f.modifiers=0;
	break;
    }
    
    /* Get time to live */
    f.ttl=ob_get(b);

    /* Decode length of remainder of frame */
    int payload_len=rfs_decode(b->bytes, &b->position);

    if (payload_len <=0) {
      /* assume we fell off the end of the packet */
      break;
    }

    int payload_start=b->position;
    int next_payload = b->position + payload_len;
    
    /* Always attempt to resolve all of the addresses in a packet, or we could fail to understand an important payload 
     eg, peer sends two payloads travelling in opposite directions;
	[Next, Dest, Sender] forwarding a payload we just send, so Sender == Me
	[Next, Dest, Sender] delivering a payload to us so Next == Me
     
     But Next would be encoded as OA_CODE_PREVIOUS, so we must parse all three addresses, 
     even if Next is obviously not intended for us
     */
    
    struct subscriber *nexthop=NULL;
    
    // if we can't parse one of the addresses, skip processing the payload
    if (overlay_address_parse(b, &f.broadcast_id, &nexthop)
	|| overlay_address_parse(b, NULL, &f.destination)
	|| overlay_address_parse(b, NULL, &f.source)){
      WHYF("Parsing failed for type %x", f.type);
      dump(NULL, b->bytes + payload_start, payload_len);
      goto next;
    }
    
    if (debug&DEBUG_OVERLAYFRAMES){
      DEBUGF("Received payload type %x, len %d", f.type, next_payload - b->position);
      DEBUGF("Payload from %s", alloca_tohex_sid(f.source->sid));
      DEBUGF("Payload to %s", (f.destination?alloca_tohex_sid(f.destination->sid):alloca_tohex(f.broadcast_id.id, BROADCAST_LEN)));
      if (nexthop)
	DEBUGF("Next hop %s", alloca_tohex_sid(nexthop->sid));
    }

    if (f.type==OF_TYPE_SELFANNOUNCE){
      overlay_address_set_sender(f.source);
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
    
    // HACK, change to packet transmitter when packet format includes that.
    if (f.type!=OF_TYPE_SELFANNOUNCE && 
	f.source->reachable == REACHABLE_NONE && 
	!f.source->node &&
	!interface->fileP &&
	recvaddr->sa_family==AF_INET){
      struct sockaddr_in *addr=(struct sockaddr_in *)recvaddr;
      
      // mark this subscriber as reachable directly via unicast.
      reachable_unicast(f.source, interface, addr->sin_addr, addr->sin_port);
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
      if (debug&DEBUG_OVERLAYFRAMES)
	DEBUG("Forwarding payload");
      overlay_forward_payload(&f);
    }
    
    // process payloads that are for me or everyone
    if ((!f.destination) || f.destination->reachable==REACHABLE_SELF){
      if (debug&DEBUG_OVERLAYFRAMES)
	DEBUG("Processing payload");
      process_incoming_frame(now, interface, &f);
    }
    
  next:
    if (f.payload){
      ob_free(f.payload);
      f.payload=NULL;
    }
    b->position=next_payload;
  }
  
  ob_free(b);
  return 0;
}

int overlay_add_selfannouncement(int interface,struct overlay_buffer *b)
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

  /* Header byte */
  if (ob_append_byte(b, OF_TYPE_SELFANNOUNCE))
    return WHY("Could not add self-announcement header");

  static int ticks_per_full_address = -1;
  if (ticks_per_full_address == -1) {
    ticks_per_full_address = confValueGetInt64Range("mdp.selfannounce.ticks_per_full_address", 4LL, 1LL, 1000000LL);
    INFOF("ticks_per_full_address = %d", ticks_per_full_address);
  }
  int send_prefix = ++overlay_interfaces[interface].ticks_since_sent_full_address < ticks_per_full_address;
  if (!send_prefix)
    overlay_interfaces[interface].ticks_since_sent_full_address = 0;

  /* A TTL for this frame.
     XXX - BATMAN uses various TTLs, but I think that it may just be better to have all TTL=1,
     and have the onward nodes selectively choose which nodes to on-announce.  If we prioritise
     newly arrived nodes somewhat (or at least reserve some slots for them), then we can still
     get the good news travels fast property of BATMAN, but without having to flood in the formal
     sense. */
  if (ob_append_byte(b,1))
    return WHY("Could not add TTL to self-announcement");
  
  /* Add space for Remaining Frame Size field.  This will always be a single byte
     for self-announcments as they are always <256 bytes. */
  if (ob_append_rfs(b,1+8+1+(send_prefix?(1+7):SID_SIZE)+4+4+1))
    return WHY("Could not add RFS for self-announcement frame");

  /* Add next-hop address.  Always link-local broadcast for self-announcements */
  struct broadcast broadcast_id;
  overlay_broadcast_generate_address(&broadcast_id);
  if (overlay_broadcast_append(b, &broadcast_id))
    return WHY("Could not write broadcast address to self-announcement");

  /* Add final destination.  Always broadcast for self-announcments. */
  if (ob_append_byte(b, OA_CODE_PREVIOUS))
    return WHY("Could not add self-announcement header");

  /* Add our SID to the announcement as sender
     We can likely get away with abbreviating our own address much of the time, since these
     frames will be sent on a regular basis.  However, we can only abbreviate using a prefix,
     not any of the fancier methods.  Indeed, if we tried to use the standard abbreviation
     functions they would notice that we are attaching an address which is ourself, and send
     a uselessly short address. So instead we will use a simple scheme where we will send our
     address in full an arbitrary 1 in 4 times.
  */
  
  if (!send_prefix)
    my_subscriber->send_full=1;
  
  if (overlay_address_append(b, my_subscriber))
    return WHY("Could not append SID to self-announcement");
  
  overlay_address_set_sender(my_subscriber);
  
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
