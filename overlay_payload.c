#include "mphlr.h"

int overlay_payload_verify(overlay_payload *p)
{
  /* Make sure that an incoming payload has a valid signature from the sender.
     This is used to prevent spoofing */

  return WHY("function not implemented");
}

int overlay_payload_package_fmt1(overlay_payload *p,overlay_buffer *b)
{
  /* Convert a payload structure into a series of bytes.
     Also select next-hop address to help payload get to its' destination */

  unsigned char nexthop[SIDDIDFIELD_LEN+1];
  int nexthoplen=0;

  overlay_buffer *headers=ob_new(256);

  if (!headers) return WHY("could not allocate overlay buffer for headers");
  if (!p) return WHY("p is NULL");
  if (!b) return WHY("b is NULL");

  /* Build header */
  int fail=0;

  if (overlay_get_nexthop(p,nexthop,&nexthoplen)) fail++;
  if (ob_append_bytes(headers,nexthop,nexthoplen)) fail++;

  /* XXX Can use shorter fields for different address types, and if we know that the next hop
     knows a short-hand for the address.
     XXX Need a prefix byte for the type of address being used.
     BETTER - We just insist that the first byte of Curve25519 addresses be >0x0f, and use
     the low numbers for special cases:
     
  */
  if (p->src[0]<0x10||p->dst[0]<0x10) {
    // Make sure that addresses do not overload the special address spaces of 0x00*-0x0f*
    fail++;
    return WHY("address begins with reserved value 0x00-0x0f");
  }
  if (ob_append_bytes(headers,(unsigned char *)p->src,SIDDIDFIELD_LEN)) fail++;
  if (ob_append_bytes(headers,(unsigned char *)p->dst,SIDDIDFIELD_LEN)) fail++;
  
  if (fail) {
    ob_free(headers);
    return WHY("failure count was non-zero");
  }

  /* Write payload format plus total length of header bits */
  if (ob_makespace(b,2+headers->length+p->payloadLength)) {
    /* Not enough space free in output buffer */
    ob_free(headers);
    return WHY("Could not make enough space free in output buffer");
  }
  
  /* Package up headers and payload */
  ob_checkpoint(b);
  if (ob_append_short(b,0x1000|(p->payloadLength+headers->length))) 
    { fail++; WHY("could not append version and length bytes"); }
  if (ob_append_bytes(b,headers->bytes,headers->length)) 
    { fail++; WHY("could not append header"); }
  if (ob_append_bytes(b,p->payload,p->payloadLength)) 
    { fail++; WHY("could not append payload"); }
  
  /* XXX SIGN &/or ENCRYPT */
  
  ob_free(headers);
  
  if (fail) { ob_rewind(b); return WHY("failure count was non-zero"); } else return 0;
}
  
overlay_payload *overlay_payload_unpackage(overlay_buffer *b) {
  /* Extract the payload at the current location in the buffer. */
    
  WHY("not implemented");
  return NULL;
}

int overlay_payload_enqueue(int q,overlay_payload *p)
{
  /* Add payload p to queue q.
  */

  return WHY("not implemented");
}

int op_free(overlay_payload *p)
{
  if (!p) return WHY("Asked to free NULL");
  if (p->prev&&p->prev->next==p) return WHY("p->prev->next still points here");
  if (p->next&&p->next->prev==p) return WHY("p->next->prev still points here");
  p->prev=NULL;
  p->next=NULL;
  if (p->payload) free(p->payload);
  p->payload=NULL;
  free(p);
  return 0;
}
