/*
  Serval Overlay Mesh Network.

  Basically we use UDP broadcast to send link-local, and then implement a BATMAN-like protocol over the top of that.
  
  Each overlay packet can contain one or more encapsulated packets each addressed using Serval DNA SIDs, with source, 
  destination and next-hop addresses.

  The use of an overlay also lets us be a bit clever about using irregular transports, such as an ISM915 modem attached via ethernet
  (which we are planning to build in coming months), by paring off the IP and UDP headers that would otherwise dominate.  Even on
  regular WiFi and ethernet we can aggregate packets in a way similar to IAX, but not just for voice frames.

  The use of long (relative to IPv4 or even IPv6) 256 bit Curve25519 addresses means that it is a really good idea to
  have neighbouring nodes exchange lists of peer aliases so that addresses can be summarised, possibly using less space than IPv4
  would have.
  
  One approach to handle address shortening is to have the periodic TTL=255 BATMAN-style hello packets include an epoch number.  
  This epoch number can be used by immediate neighbours of the originator to reference the neighbours listed in that packet by
  their ordinal position in the packet instead of by their full address.  This gets us address shortening to 1 byte in most cases 
  in return for no new packets, but the periodic hello packets will now be larger.  We might deal with this issue by having these
  hello packets reference the previous epoch for common neighbours.  Unresolved neighbour addresses could be resolved by a simple
  DNA request, which should only need to occur ocassionally, and other link-local neighbours could sniff and cache the responses
  to avoid duplicated traffic.  Indeed, during quiet times nodes could preemptively advertise address resolutions if they wished,
  or similarly advertise the full address of a few (possibly randomly selected) neighbours in each epoch.

  Byzantine Robustness is a goal, so we have to think about all sorts of malicious failure modes.

  One approach to help byzantine robustness is to have multiple signature shells for each hop for mesh topology packets.
  Thus forging a report of closeness requires forging a signature.  As such frames are forwarded, the outermost signature
  shell is removed. This is really only needed for more paranoid uses.

  We want to have different traffic classes for voice/video calls versus regular traffic, e.g., MeshMS frames.  Thus we need to have
  separate traffic queues for these items.  Aside from allowing us to prioritise isochronous data, it also allows us to expire old
  isochronous frames that are in-queue once there is no longer any point delivering them (e.g after holding them more than 200ms).
  We can also be clever about round-robin fair-sharing or even prioritising among isochronous streams.  Since we also know about the
  DNA isochronous protocols and the forward error correction and other redundancy measures we also get smart about dropping, say, 1 in 3
  frames from every call if we know that this can be safely done.  That is, when traffic is low, we maximise redundancy, and when we
  start to hit the limit of traffic, we start to throw away some of the redundancy.  This of course relies on us knowing when the
  network channel is getting too full.
  
*/

#include "mphlr.h"

int overlay_socket=-1;

int ob_unlimitsize(overlay_buffer *b);

overlay_txqueue overlay_tx[4];


int overlay_payload_verify()
{
  /* Make sure that an incoming payload has a valid signature from the sender.
     This is used to prevent spoofing */

  return WHY("function not implemented");
}


int overlay_get_nexthop(overlay_payload *p,unsigned char *hopout,int *hopaddrlen)
{
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

int overlay_payload_enqueue(int q,overlay_payload *p,int urgentP)
{
  /* Add payload p to queue q.
     If urgentP is set, then ask for the payload queue to be sent now.
  */

  return WHY("not implemented");
  if (urgentP) overlay_push_queued();
}

int overlay_push_queued()
{
  /* Try to send frames.
     The trick here is that we need to aggregate payloads based on which interface they need to go to */

  return WHY("not implemented");
}

