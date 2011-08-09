#include "mphlr.h"

int overlay_add_selfannouncement(overlay_buffer *b)
{
  /* Pull the first record from the HLR database and turn it into a
     self-announcment. These are shorter than regular Subscriber Observation
     Notices (SON) because they are just single-hop announcments of presence.

     Do we really need to push the whole SID (32 bytes), or will just, say, 
     8 do so that we use a prefix of the SID which is still very hard to forge.
     
     XXX A hearer of a self-announcement who has not previously seen the sender might
     like to get some authentication to prevent naughty people from spoofing routes.
     This should be easy enough to do, but will need some thought.
  */

  

  if (ob_append_bytes(b,OF_SELFANNOUNCE,sizeof(OF_SELFANNOUNCE)))
    return WHY("ob_append_bytes() could not add self-announcement header");
  
  

  return WHY("Not implemented");
}

int overlay_get_nexthop(overlay_payload *p,unsigned char *nexthop,int *nexthoplen)
{
  return WHY("Not implemented");
}
