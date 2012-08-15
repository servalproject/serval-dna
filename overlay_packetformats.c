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

struct sockaddr_in loopback = {
  .sin_family=0,
  .sin_port=0,
  .sin_addr.s_addr=0x0100007f
};

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

  int ofs;
  overlay_frame f;

  bzero(&f,sizeof(overlay_frame));
  
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

  overlay_abbreviate_unset_current_sender();

  // TODO put sender of packet and sequence number in envelope header
  // Then we can quickly drop reflected broadcast packets
  // currently we see annoying errors as we attempt to parse each payload
  // plus with a sequence number we can detect dropped packets and nack them for retransmission
  
  /* Skip magic bytes and version */
  for(ofs=4;ofs<len;)
    {
      /* Get normal form of packet type and modifiers */
      f.type=packet[ofs]&OF_TYPE_BITS;
      f.modifiers=packet[ofs]&OF_MODIFIER_BITS;

      switch(packet[ofs]&OF_TYPE_BITS)
	{
	case OF_TYPE_EXTENDED20:
	  /* Eat the next two bytes and then skip over this reserved frame type */
	  f.type=OF_TYPE_FLAG_E20|(packet[ofs]&OF_MODIFIER_BITS)|(packet[ofs+2]<<12)|(packet[ofs+1]<<4);
	  f.modifiers=0;
	  ofs+=3;
	  break;
	    
	case OF_TYPE_EXTENDED12:
	  /* Eat the next byte and then skip over this reserved frame type */
	  f.type=OF_TYPE_FLAG_E12|(packet[ofs]&OF_MODIFIER_BITS)|(packet[ofs+1]<<4);
	  f.modifiers=0;
	  ofs+=2;
	  break;
	    
	default:
	  /* No extra bytes to deal with here */
	  ofs++;
	  break;
	}
      /* Get time to live */
      f.ttl=packet[ofs++];

      /* Decode length of remainder of frame */
      f.rfs=rfs_decode(packet,&ofs);
      if (debug&DEBUG_PACKETFORMATS) DEBUGF("f.rfs=%d, ofs=%d", f.rfs, ofs);

      if (!f.rfs) {
	/* Zero length -- assume we fell off the end of the packet */
	break;
      }

      int payloadStart = ofs;
      int nextPayload = ofs+f.rfs;
      
      if (nextPayload > len){
	WHYF("Payload length %d is too long for the remaining packet buffer %d", f.rfs, len - ofs);
	break;
      }
      
      /* Always attempt to resolve all of the addresses in a packet, or we could fail to understand an important payload 
       eg, peer sends two payloads travelling in opposite directions;
          [Next, Dest, Sender] forwarding a payload we just send, so Sender == Me
          [Next, Dest, Sender] delivering a payload to us so Next == Me
       
       But Next would be encoded as OA_CODE_PREVIOUS, so we must parse all three addresses, 
       even if Next is obviously not intended for us
       */
      
      /* Now extract the next hop address */
      int alen=0;
      int nexthop_address_status=overlay_abbreviate_expand_address(packet,&ofs,f.nexthop,&alen);
      if (ofs>nextPayload){
	WARN("Next hop address didn't fit in payload");
	break;
      }
      
      alen=0;
      int destination_address_status=overlay_abbreviate_expand_address(packet,&ofs,f.destination,&alen);
      if (ofs>nextPayload){
	WARN("Destination address didn't fit in payload");
	break;
      }
      
      alen=0;
      int source_address_status=overlay_abbreviate_expand_address(packet,&ofs,f.source,&alen);
      if (ofs>nextPayload){
	WARN("Source address didn't fit in payload");
	break;
      }
      
      // TODO respond with OA_PLEASEEXPLAIN's?
      
      if (debug&DEBUG_OVERLAYFRAMES) {
	DEBUGF("Type=0x%02x", f.type);
	strbuf b = strbuf_alloca(1024);
	strbuf_sprintf(b, "Next Hop for this frame is (resolve code=%d): ", nexthop_address_status);
	if (nexthop_address_status==OA_RESOLVED)
	  strbuf_sprintf(b, "%s", alloca_tohex_sid(f.nexthop));
	else
	  strbuf_puts(b, "???");
	DEBUG(strbuf_str(b));
	strbuf_reset(b);
	strbuf_sprintf(b, "Destination for this frame is (resolve code=%d): ", destination_address_status);
	if (destination_address_status==OA_RESOLVED)
	  strbuf_sprintf(b, "%s", alloca_tohex_sid(f.destination));
	else
	  strbuf_puts(b, "???");
	DEBUG(strbuf_str(b));
	strbuf_reset(b);
	strbuf_sprintf(b, "Source for this frame is (resolve code=%d): ", source_address_status);
	if (source_address_status==OA_RESOLVED)
	  strbuf_sprintf(b, "%s", alloca_tohex_sid(f.source));
	else
	  strbuf_puts(b, "???");
	DEBUG(strbuf_str(b));
      }
      
      if (f.nexthop[0]==0 || f.destination[0]==0 || f.source[0]==0)
	break;
      
      if (nexthop_address_status!=OA_RESOLVED
	  || destination_address_status!=OA_RESOLVED
	  || source_address_status!=OA_RESOLVED){
	WARN("Unable to resolve all payload addresses");
	// we have to stop now as we can't be certain about the destination of any other payloads in this packet.
	break;
      }
	
      /* not that noteworthy, as when listening to a broadcast socket
       you hear everything you send. */
      if (overlay_address_is_local(f.source)){
	// skip the remainder of any packet that we know we sent
	// TODO add our id to the header
	if (f.type==OF_TYPE_SELFANNOUNCE)
	  break;
      }else{
	
	/* Record current sender for reference by addresses in subsequent frames in the
	 ensemble */
	if (f.type==OF_TYPE_SELFANNOUNCE)
	  overlay_abbreviate_set_current_sender(f.source);
	
	// TODO refactor all packet parsing to only allocate additional memory for the payload
	// if it needs to be queued for forwarding.
	
	f.payload = ob_static(&packet[ofs], nextPayload - ofs);
	ob_setlength(f.payload, nextPayload - ofs);
	
	/* Finally process the frame */
	overlay_frame_process(interface,&f);
	
	ob_free(f.payload);
      }
      
      /* Jump to the next payload offset */
      ofs = nextPayload;
    }
  if (0) INFOF("Finished processing overlay packet");
  
  return 0;
}

int overlay_add_selfannouncement(int interface,overlay_buffer *b)
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

  unsigned char *sid=overlay_get_my_sid();
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
  if (ob_append_byte(b,OA_CODE_BROADCAST))
    return WHY("Could not add self-announcement header");
  /* BPI for broadcast */
  {
      int i;
      for(i=0;i<8;i++)
	if (ob_append_byte(b,random()&0xff))
	  return WHYF("Could not add next-hop address byte %d", i);
  }

  /* Add final destination.  Always broadcast for self-announcments.
     As we have just referenced the broadcast address, we can encode it in a single byte */
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
  if (send_prefix) {
    if (ob_append_byte(b, OA_CODE_PREFIX7)) return WHY("Could not add address format code.");
    if (ob_append_bytes(b,sid,7)) return WHY("Could not append SID prefix to self-announcement");
  }
  else {
    if (ob_append_bytes(b,sid,SID_SIZE)) return WHY("Could not append SID to self-announcement");
  }
  /* Make note that this is the most recent address we have set */
  overlay_abbreviate_set_most_recent_address(sid);
  /* And the sender for any other addresses in this packet */
  overlay_abbreviate_set_current_sender(sid);
  
  /* Sequence number range.  Based on one tick per millisecond. */
  time_ms_t last_ms = overlay_interfaces[interface].last_tick_ms;
  // If this interface has not been ticked yet (no selfannounce sent) then invent the prior sequence
  // number: one millisecond ago.
  if (last_ms == -1)
    last_ms = now - 1;
  if (ob_append_int(b, last_ms))
    return WHY("Could not add low sequence number to self-announcement");
  if (ob_append_int(b, now))
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
