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
#include "overlay_buffer.h"
#include "overlay_packet.h"

static int op_append_type(struct overlay_buffer *headers, struct overlay_frame *p)
{
  unsigned char c[3];
  switch(p->type&OF_TYPE_FLAG_BITS)
    {
    case OF_TYPE_FLAG_NORMAL:
      c[0]=p->type|p->modifiers;
      if (debug&DEBUG_PACKETFORMATS) DEBUGF("type resolves to %02x",c[0]);
      if (ob_append_bytes(headers,c,1)) return -1;
      break;
    case OF_TYPE_FLAG_E12:
      c[0]=(p->type&OF_MODIFIER_BITS)|OF_TYPE_EXTENDED12;
      c[1]=(p->type>>4)&0xff;
      if (debug&DEBUG_PACKETFORMATS) DEBUGF("type resolves to %02x%02x",c[0],c[1]);
      if (ob_append_bytes(headers,c,2)) return -1;
      break;
    case OF_TYPE_FLAG_E20:
      c[0]=(p->type&OF_MODIFIER_BITS)|OF_TYPE_EXTENDED20;
      c[1]=(p->type>>4)&0xff;
      c[2]=(p->type>>12)&0xff;
      if (debug&DEBUG_PACKETFORMATS) DEBUGF("type resolves to %02x%02x%02x",c[0],c[1],c[2]);
      if (ob_append_bytes(headers,c,3)) return -1;
      break;
    default: 
      /* Don't know this type of frame */
      WHY("Asked for format frame with unknown TYPE_FLAG bits");
      return -1;
    }
  return 0;
}


int overlay_frame_append_payload(overlay_interface *interface, struct overlay_frame *p, struct subscriber *next_hop, struct overlay_buffer *b)
{
  /* Convert a payload (frame) structure into a series of bytes.
     Assumes that any encryption etc has already been done.
     Will pick a next hop if one has not been chosen.
  */

  struct overlay_buffer *headers;
  
  headers=ob_new();

  if (!headers) return WHY("could not allocate overlay buffer for headers");

  ob_checkpoint(b);
  
  if (debug&DEBUG_PACKETCONSTRUCTION)
    dump_payload(p,"append_payload stuffing into packet");

  /* Build header */

  /* Write fields into binary structure in correct order */

  /* Write out type field byte(s) */
  if (op_append_type(headers,p))
    goto cleanup;    

  /* Write out TTL */
  if (ob_append_byte(headers,p->ttl))
    goto cleanup;

  /* Length.  This is the fun part, because we cannot calculate how many bytes we need until
     we have abbreviated the addresses, and the length encoding we use varies according to the
     length encoded.  The simple option of running the abbreviations twice won't work because 
     we rely on context for abbreviating the addresses.  So we write it initially and then patch it
     after.
  */
  int max_len=((SID_SIZE+3)*3+headers->position+p->payload->position);
  if (debug&DEBUG_PACKETCONSTRUCTION) 
    DEBUGF("Appending RFS for max_len=%d\n",max_len);
  ob_append_rfs(headers,max_len);
  
  int addrs_start=headers->position;
  
  /* Write out addresses as abbreviated as possible */
  if (p->sendBroadcast){
    overlay_broadcast_append(headers, &p->broadcast_id);
  }else{
    overlay_address_append(headers, next_hop);
  }
  if (p->destination)
    overlay_address_append(headers,p->destination);
  else
    ob_append_byte(headers, OA_CODE_PREVIOUS);
  
  if (p->source==my_subscriber){
    overlay_address_append_self(interface, headers);
  }else{
    overlay_address_append(headers,p->source);
  }
  
  int addrs_len=headers->position-addrs_start;
  int actual_len=addrs_len+p->payload->position;
  if (debug&DEBUG_PACKETCONSTRUCTION) 
    DEBUGF("Patching RFS for actual_len=%d\n",actual_len);
  ob_patch_rfs(headers,actual_len);

  /* Write payload format plus total length of header bits */
  if (ob_makespace(b,2+headers->position+p->payload->position)) {
    /* Not enough space free in output buffer */
    if (debug&DEBUG_PACKETFORMATS)
      DEBUGF("Could not make enough space free in output buffer");
    goto cleanup;
  }
  
  /* Package up headers and payload */
  if (ob_append_bytes(b,headers->bytes,headers->position)) {
    WHY("could not append header");
    goto cleanup;
  }
  if (ob_append_bytes(b,p->payload->bytes,p->payload->position)) {
    WHY("could not append payload"); 
    goto cleanup;
  }

  ob_free(headers);
  return 0;
  
cleanup:
  ob_free(headers);
  ob_rewind(b);
  return -1;
}
  
int dump_queue(char *msg,int q)
{
  overlay_txqueue *qq=&overlay_tx[q];
  DEBUGF("Contents of TX queue #%d (%s):",q,msg);
  DEBUGF("  length=%d, maxLength=%d",qq->length,qq->maxLength);
  struct overlay_frame *f=qq->first,*l=qq->last;
  DEBUGF("  head of queue = %p, tail of queue = %p", f, l);
  struct overlay_frame *n=f;
  int count=0;
  while(n) {
    DEBUGF("    queue entry #%d : prev=%p, next=%p", count,n->prev,n->next);
    if (n==n->next) {
      WHY("      ERROR: loop in queue");
      return -1;
    }
    n=n->next;
  }
  return 0;
}

int dump_payload(struct overlay_frame *p, char *message)
{
  DEBUGF( "+++++\nFrame from %s to %s of type 0x%02x %s:",
	  alloca_tohex_sid(p->source->sid),
	  alloca_tohex_sid(p->destination->sid),p->type,
	  message?message:"");
  if (p->payload)
    dump("payload contents", &p->payload->bytes[0],p->payload->position);
  return 0;
}

int overlay_payload_enqueue(int q, struct overlay_frame *p)
{
  /* Add payload p to queue q.

     Queues get scanned from first to last, so we should append new entries
     on the end of the queue.

     Complain if there are too many frames in the queue.
  */
  
  if (!p) return WHY("Cannot queue NULL");
  
  if (p->destination){
    int r = subscriber_is_reachable(p->destination);
    if (r == REACHABLE_SELF || r == REACHABLE_NONE)
      return WHYF("Destination %s is unreachable (%d)", alloca_tohex_sid(p->destination->sid), r);
  }
      
  if (debug&DEBUG_PACKETTX)
    DEBUGF("Enqueuing packet for %s* (q[%d]length = %d)",
	   p->destination?alloca_tohex(p->destination->sid, 7): alloca_tohex(p->broadcast_id.id,BROADCAST_LEN),
	 q,overlay_tx[q].length);
  
  if (q<0||q>=OQ_MAX) 
    return WHY("Invalid queue specified");

  
  if (p->payload && p->payload->position > p->payload->sizeLimit){
    // HACK, maybe should be done in each caller
    // set the size of the payload based on the position written
    p->payload->sizeLimit=p->payload->position;
  }
  
  if (overlay_tx[q].length>=overlay_tx[q].maxLength) 
    return WHYF("Queue #%d congested (size = %d)",q,overlay_tx[q].maxLength);

  if (p->send_copies<=0)
    p->send_copies=1;
  else if(p->send_copies>5)
    return WHY("Too many copies requested");
  
  if (!p->destination){
    int i;
    int drop=1;
    
    // hook to allow for flooding via olsr
    olsr_send(p);
    
    // make sure there is an interface up that allows broadcasts
    for(i=0;i<OVERLAY_MAX_INTERFACES;i++){
      if (overlay_interfaces[i].state==INTERFACE_STATE_UP
	  && overlay_interfaces[i].send_broadcasts){
	p->broadcast_sent_via[i]=0;
	drop=0;
      }else
	p->broadcast_sent_via[i]=1;
    }
    
    // just drop it now
    if (drop)
      return -1;
    
    p->sendBroadcast=1;
  }
  
  struct overlay_frame *l=overlay_tx[q].last;
  if (l) l->next=p;
  p->prev=l;
  p->next=NULL;
  p->enqueued_at=gettime_ms();

  overlay_tx[q].last=p;
  if (!overlay_tx[q].first) overlay_tx[q].first=p;
  overlay_tx[q].length++;

  overlay_update_queue_schedule(&overlay_tx[q], p);
  
  if (0) dump_queue("after",q);

  if (q==OQ_ISOCHRONOUS_VOICE) {
    // Send a packet immediately to reduce latency
    // Also this prevents aggregation of multiple voice frames which would 
    // increase the chance of packet loss leading to missing audio
    // TODO, remove when we NACK and retry all frames
    overlay_send_packet(NULL);
  }
  
  return 0;
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
  struct overlay_frame *out=malloc(sizeof(struct overlay_frame));
  if (!out) return WHYNULL("malloc() failed");

  /* copy main data structure */
  bcopy(in,out,sizeof(struct overlay_frame));
  
  if (in->payload)
    out->payload=ob_dup(in->payload);
  return out;
}
