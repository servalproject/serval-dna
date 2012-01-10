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

#include "mphlr.h"


int packetOkOverlay(int interface,unsigned char *packet,int len,unsigned char *transaction_id,
		    struct sockaddr *recvaddr,int recvaddrlen,int parseP)
{
  /* 
     Overlay packets are ensembles contain one or more frames each of which 
     should be handled separately.

     There are two main types of enclosed frame.

     1. Announcement frames which contain information that helps to maintain the
     operation of the mesh.

     and

     2. Data frames that contain messages directed to nodes on the mesh.

     In both instances we allow the contained addresses to be shortened to save bandwidth,
     especially for low-bandwidth links.

     All frames have the following fields:

     Frame type (8-24bits)
     TTL (8bits)
     Remaining frame size (RFS) (see overlay_payload.c or overlay_buffer.c for explanation of format)
     Next hop (variable length due to address abbreviation)
     Destination (variable length due to address abbreviation)*
     Source (variable length due to address abbreviation)*
     Payload (length = RFS- len(frame type) - len(next hop)*

     This structure is intended to allow relaying nodes to quickly ignore frames that are
     not addressed to them as either the next hop or final destination.

     The RFS field uses additional bytes to encode the length of longer frames.  
     This provides us with a slight space saving for the common case of short frames.
     
     * Indicates fields that may be encrypted.  The source and destination addresses can
     be encrypted for paranoid traffic so that only the hops along the route know who is
     talking to whom.  This is not totally secure, but does prevent collateral eaves dropping
     of frames by 4th parties.  Paranoid communities could elect to only use nodes they trust
     to carry the frame.  And finally, the frame payload itself can be enciphered with the 
     final destination's public key, so that it is not possible even for the relaying 3rd
     parties to observe the content.  

     Naturally some information will leak simply based on the size, periodicity and other 
     characteristics of the traffic, and some 3rd parties may be malevolent, so noone should
     assume that this provides complete security.

     Paranoid mode introduces a bandwidth cost of one signature, and a potentially substantial
     energy cost of requiring every node along the delivery path to decrypt and reencrypt the
     frame.

     It would also be possible to design a super-paranoid mode where source routing is used with
     concentric shells of encryption so that each hop can only work out the next hop to send it
     to.  However, that would result in rather large frames, and require an on-demand routing
     approach which may well betray more information than the super-paranoid mode would hide.

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

  f.payload=NULL;
  f.bytes=NULL;
  f.bytecount=0;

  /* Skip magic bytes and version */
  for(ofs=4;ofs<len;)
    {
      /* Clear out the data structure ready for next frame */
      f.nexthop_address_status=OA_UNINITIALISED;
      f.destination_address_status=OA_UNINITIALISED;
      f.source_address_status=OA_UNINITIALISED;

      /* Get normal form of packet type and modifiers */
      f.type=packet[ofs]&OF_TYPE_BITS;
      f.modifiers=packet[ofs]&OF_MODIFIER_BITS;

      if (debug&DEBUG_PACKETFORMATS) fprintf(stderr,"f.type=0x%02x, f.modifiers=0x%02x, ofs=%d\n",
			   f.type,f.modifiers,ofs);

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
	case OF_TYPE_NODEANNOUNCE:
	case OF_TYPE_RESERVED_08:
	case OF_TYPE_RESERVED_09:
	case OF_TYPE_RESERVED_0a:
	case OF_TYPE_RESERVED_0b:
	case OF_TYPE_RESERVED_0c:
	case OF_TYPE_RESERVED_0d:
	case OF_TYPE_SELFANNOUNCE:
	case OF_TYPE_SELFANNOUNCE_ACK:
	case OF_TYPE_DATA:
	case OF_TYPE_DATA_VOICE:
	case OF_TYPE_RHIZOME_ADVERT:
	case OF_TYPE_PLEASEEXPLAIN:
	  /* No extra bytes to deal with here */
	  ofs++;
	  break;
	}
      /* Get time to live */
      f.ttl=packet[ofs++];

      /* Decode length of remainder of frame */
      f.rfs=rfs_decode(packet,&ofs);
      if (debug&DEBUG_PACKETFORMATS) fprintf(stderr,"f.rfs=%d, ofs=%d\n",f.rfs,ofs);

      if (!f.rfs) {
	/* Zero length -- assume we fell off the end of the packet */
	break;
      }

      /* Now extract the next hop address */
      int alen=0;
      int offset=ofs;
      f.nexthop_address_status=overlay_abbreviate_expand_address(interface,packet,&offset,f.nexthop,&alen);

      /* Now just make the rest of the frame available via the received frame structure, as the
	 frame may not be for us, so there is no point wasting time and energy if we don't have
	 to.
      */
      f.bytes=&packet[offset];
      f.bytecount=f.rfs-(offset-ofs);
      if (f.bytecount<0) {
	f.bytecount=0;
	WHY("negative residual byte count after extracting addresses from frame header");
	if (debug&DEBUG_PACKETFORMATS) fprintf(stderr,"f.rfs=%d, offset=%d, ofs=%d\n",
			     f.rfs,offset,ofs);
	return WHY("negative residual byte count after extracting addresses from frame header");
      }

      /* Finally process the frame */
      overlay_frame_process(interface,&f);
      
      /* Skip the rest of the bytes in this frame so that we can examine the next one in this
	 ensemble */
      if (debug&DEBUG_PACKETFORMATS) fprintf(stderr,"ofs=%d, f.rfs=%d, len=%d\n",ofs,f.rfs,len);
      ofs+=f.rfs;
    }

  return 0;
}

int overlay_frame_resolve_addresses(int interface,overlay_frame *f)
{
  /* Get destination and source addresses and set pointers to payload appropriately */
  int alen=0;
  int offset=0;

  overlay_abbreviate_set_most_recent_address(f->nexthop);
  f->destination_address_status=overlay_abbreviate_expand_address(interface,f->bytes,&offset,f->destination,&alen);
  alen=0;
  f->source_address_status=overlay_abbreviate_expand_address(interface,f->bytes,&offset,f->source,&alen);
  if (debug&DEBUG_OVERLAYABBREVIATIONS)
    {
      fprintf(stderr,"Wrote %d bytes into source address: \n",alen);
      int i;
      for(i=0;i<32;i++) fprintf(stderr,"%02X",f->source[i]);
      fprintf(stderr,"\n");
    }

  /* Copy payload into overlay_buffer structure */
  if (f->bytecount-offset<0) return WHY("Abbreviated ddresses run past end of packet");
  if (!f->payload) f->payload=ob_new(f->bytecount-offset); else f->payload->length=0;
  if (!f->payload) return WHY("calloc(overlay_buffer) failed.");
  if (ob_append_bytes(f->payload,&f->bytes[offset],f->bytecount-offset)) 
    return WHY("ob_append_bytes() failed.");

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

  unsigned char c;
  unsigned char *sid=overlay_get_my_sid();

  /* Header byte */
  c=OF_TYPE_SELFANNOUNCE;
  if (ob_append_bytes(b,&c,1))
    return WHY("ob_append_bytes() could not add self-announcement header");

  int send_prefix=(overlay_interfaces[interface].ticks_since_sent_full_address<4);

  /* A TTL for this frame.
     XXX - BATMAN uses various TTLs, but I think that it may just be better to have all TTL=1,
     and have the onward nodes selectively choose which nodes to on-announce.  If we prioritise
     newly arrived nodes somewhat (or at least reserve some slots for them), then we can still
     get the good news travels fast property of BATMAN, but without having to flood in the formal
     sense. */
  c=1;
  if (ob_append_bytes(b,&c,1))
    return WHY("ob_append_bytes() could not add TTL to self-announcement");
  
  /* Add space for Remaining Frame Size field.  This will always be a single byte
     for self-announcments as they are always <256 bytes. */
  c=1+8+1+(send_prefix?(1+7):SID_SIZE)+4+4+1;
  if (ob_append_bytes(b,&c,1))
    return WHY("ob_append_bytes() could not add RFS for self-announcement frame");

  /* Add next-hop address.  Always link-local broadcast for self-announcements */
  c=OA_CODE_BROADCAST;
  if (ob_append_bytes(b,&c,1))
    return WHY("ob_append_bytes() could not add self-announcement header");
  { int i; for(i=0;i<8;i++) ob_append_byte(b,random()&0xff); } /* BPI for broadcast */
  
  /* Add final destination.  Always broadcast for self-announcments.
     As we have just referenced the broadcast address, we can encode it in a single byte */
  c=OA_CODE_PREVIOUS;
  if (ob_append_bytes(b,&c,1))
    return WHY("ob_append_bytes() could not add self-announcement header");

  /* Add our SID to the announcement as sender
     We can likely get away with abbreviating our own address much of the time, since these
     frames will be sent on a regular basis.  However, we can only abbreviate using a prefix,
     not any of the fancier methods.  Indeed, if we tried to use the standard abbreviation
     functions they would notice that we are attaching an address which is ourself, and send
     a uselessly short address. So instead we will use a simple scheme where we will send our
     address in full an arbitrary 1 in 4 times.
  */
  if (overlay_interfaces[interface].ticks_since_sent_full_address>3)
    { if (ob_append_bytes(b,sid,SID_SIZE)) return WHY("Could not append SID to self-announcement"); 
      overlay_interfaces[interface].ticks_since_sent_full_address=0;
    }
  else
    {
      c=OA_CODE_PREFIX7;
      if (ob_append_bytes(b,&c,1)) return WHY("ob_append_bytes() could not add address format code.");
      if (ob_append_bytes(b,sid,7)) return WHY("Could not append SID prefix to self-announcement"); 
      overlay_interfaces[interface].ticks_since_sent_full_address++;
    }
      
  /* Sequence number range.  Based on one tick per milli-second. */
  overlay_update_sequence_number();
  if (ob_append_int(b,overlay_interfaces[interface].last_tick_ms))
    return WHY("ob_append_int() could not add low sequence number to self-announcement");
  if (ob_append_int(b,overlay_sequence_number))
    return WHY("ob_append_int() could not add high sequence number to self-announcement");
  overlay_interfaces[interface].last_tick_ms=overlay_sequence_number;
  if (debug&DEBUG_OVERLAYINTERFACES)
    fprintf(stderr,"last tick seq# = %lld\n",overlay_interfaces[interface].last_tick_ms);

  /* A byte that indicates which interface we are sending over */
  if (ob_append_byte(b,interface))
    return WHY("ob_append_int() could not add interface number to self-announcement");

  return 0;
}


