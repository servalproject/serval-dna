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
#include "overlay_buffer.h"
#include "overlay_packet.h"

static int overlay_frame_build_header(int packet_version, struct decode_context *context, 
			       struct overlay_buffer *buff, 
			       int queue, int type, int modifiers, char will_retransmit,
			       int ttl, int sequence,
			       struct broadcast *broadcast, struct subscriber *next_hop,
			       struct subscriber *destination, struct subscriber *source)
{
  if (ttl < 0 || ttl > PAYLOAD_TTL_MAX)
    return WHYF("invalid ttl=%d", ttl);

  int flags = modifiers & (PAYLOAD_FLAG_CIPHERED | PAYLOAD_FLAG_SIGNED);
  if (will_retransmit)
    flags|=PAYLOAD_FLAG_ACK_SOON;
    
  if (ttl==1 && !broadcast)
    flags |= PAYLOAD_FLAG_ONE_HOP;
  if (destination && destination==next_hop)
    flags |= PAYLOAD_FLAG_ONE_HOP;
  
  if (source == context->sender)
    flags |= PAYLOAD_FLAG_SENDER_SAME;
  
  if (!destination)
    flags |= PAYLOAD_FLAG_TO_BROADCAST;
  
  if (type!=OF_TYPE_DATA)
    flags |= PAYLOAD_FLAG_LEGACY_TYPE;
  
  ob_append_byte(buff, flags);
  
  if (!(flags & PAYLOAD_FLAG_SENDER_SAME))
    overlay_address_append(context, buff, source);
  
  if (flags & PAYLOAD_FLAG_TO_BROADCAST){
    if (!(flags & PAYLOAD_FLAG_ONE_HOP))
      overlay_broadcast_append(buff, broadcast);
  } else {
    overlay_address_append(context, buff, destination);
    if (!(flags & PAYLOAD_FLAG_ONE_HOP))
      overlay_address_append(context, buff, next_hop);
  }
  
  if (!(flags & PAYLOAD_FLAG_ONE_HOP))
    ob_append_byte(buff, ttl | ((queue&3)<<5));
  
  if (flags & PAYLOAD_FLAG_LEGACY_TYPE)
    ob_append_byte(buff, type);

  if (packet_version >= 1)
    ob_append_byte(buff, sequence);
  
  return 0;
}

int overlay_frame_append_payload(struct decode_context *context, int encapsulation,
				 struct overlay_frame *p, struct overlay_buffer *b,
				 char will_retransmit)
{
  /* Convert a payload (frame) structure into a series of bytes.
     Assumes that any encryption etc has already been done.
     Will pick a next hop if one has not been chosen.
  */

  ob_checkpoint(b);
  
  if (config.debug.packetconstruction){
    DEBUGF( "+++++\nFrame from %s to %s of type 0x%02x %s:",
	   alloca_tohex_sid_t(p->source->sid),
	   alloca_tohex_sid_t(p->destination->sid),p->type,
	   "append_payload stuffing into packet");
    if (p->payload)
      dump("payload contents", &p->payload->bytes[0],p->payload->position);
  }
  
  struct broadcast *broadcast=NULL;
  if ((!p->destination) && !is_all_matching(p->broadcast_id.id,BROADCAST_LEN,0)){
    broadcast = &p->broadcast_id;
  }
  
  if (overlay_frame_build_header(p->packet_version, context, b,
			     p->queue, p->type, p->modifiers, will_retransmit, 
			     p->ttl, p->mdp_sequence&0xFF,
			     broadcast, p->next_hop, 
			     p->destination, p->source) == -1)
    goto cleanup;
  
  if (encapsulation == ENCAP_OVERLAY)
    ob_append_ui16(b, ob_position(p->payload));

  if (ob_position(p->payload))
    ob_append_bytes(b, ob_ptr(p->payload), ob_position(p->payload));

  if (!ob_overrun(b))
    return 0;
  
cleanup:
  ob_rewind(b);
  return -1;
}

int op_free(struct overlay_frame *p)
{
  if (!p) return WHY("Asked to free NULL");
  if (p->prev&&p->prev->next==p) return WHY("p->prev->next still points here");
  if (p->next&&p->next->prev==p) return WHY("p->next->prev still points here");
  p->prev=NULL;
  p->next=NULL;
  if (p->payload) ob_free(p->payload);
  p->payload=NULL;
  free(p);
  return 0;
}

struct overlay_frame *op_dup(struct overlay_frame *in)
{
  if (!in) return NULL;

  /* clone the frame */
  struct overlay_frame *out = emalloc(sizeof(struct overlay_frame));
  if (out == NULL)
    return NULL;

  /* copy main data structure */
  bcopy(in,out,sizeof(struct overlay_frame));

  if (in->payload) {
    if ((out->payload = ob_dup(in->payload)) == NULL) {
      free(out);
      return NULL;
    }
  }
  return out;
}
