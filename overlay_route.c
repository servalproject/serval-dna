#include "mphlr.h"

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
  int zero=0;
  
  /* Make sure we can find our SID */
  if (!findHlr(hlr,&zero,NULL,NULL)) return WHY("Could not find first entry in HLR");

  /* Header byte */
  c=OF_SELFANNOUNCE;
  if (ob_append_bytes(b,&c,1))
    return WHY("ob_append_bytes() could not add self-announcement header");
  
  /* Add our SID to the announcement */
  if (ob_append_bytes(b,&hlr[zero+4],SID_SIZE)) return WHY("Could not append SID to self-announcement");

  /* A sequence number, so that others can keep track of their reception of our frames.
   These are per-interface */
  if (ob_append_int(b,overlay_interfaces[interface].sequence_number))
    return WHY("ob_append_int() could not add sequence number to self-announcement");

  /* A TTL for this frame?
     XXX - BATMAN uses various TTLs, but I think that it may just be better to have all TTL=1,
     and have the onward nodes selectively choose which nodes to on-announce.  If we prioritise
     newly arrived nodes somewhat (or at least reserve some slots for them), then we can still
     get the good news travels fast property of BATMAN, but without having to flood in the formal
     sense. */
  c=1;
  if (ob_append_bytes(b,&c,1))
    return WHY("ob_append_bytes() could not add TTL to self-announcement");
  
  return 0;
}

int overlay_get_nexthop(overlay_payload *p,unsigned char *nexthop,int *nexthoplen)
{
  return WHY("Not implemented");
}
