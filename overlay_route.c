#include "mphlr.h"

int overlay_add_selfannouncement(overlay_buffer *b)
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

  c=OF_SELFANNOUNCE;
  if (ob_append_bytes(b,&c,1))
    return WHY("ob_append_bytes() could not add self-announcement header");
  
  
  

  return WHY("Not implemented");
}

int overlay_get_nexthop(overlay_payload *p,unsigned char *nexthop,int *nexthoplen)
{
  return WHY("Not implemented");
}
