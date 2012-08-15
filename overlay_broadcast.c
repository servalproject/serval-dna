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

/*
  Smart-flooding of broadcast information is also a requirement.  The long addresses help here, as we can make any address that begins
  with the first 192 bits all ones be broadcast, and use the remaining 64 bits as a "broadcast packet identifier" (BPI).  
  Nodes can remember recently seen BPIs and not forward broadcast frames that have been seen recently.  This should get us smart flooding
  of the majority of a mesh (with some node mobility issues being a factor).  We could refine this later, but it will do for now, especially
  since for things like number resolution we are happy to send repeat requests.
 */

#include "serval.h"

#define BROADCAST_LEN 8

struct broadcast{
  unsigned char id[BROADCAST_LEN];
};

#define MAX_BPIS 1024
#define BPI_MASK 0x3ff
struct broadcast bpilist[MAX_BPIS];

/* Determine if an address is broadcast */
int overlay_address_is_broadcast(unsigned char *a)
{
  int i;
  for(i=0;i<(SID_SIZE - BROADCAST_LEN);i++)
    if (a[i]!=0xff) return 0;
  return 1;
}

int overlay_broadcast_generate_address(unsigned char *a)
{
  int i;
  for(i=0;i<(SID_SIZE - BROADCAST_LEN);i++) a[i]=0xff;
  for(;i<SID_SIZE;i++) a[i]=random()&0xff;
  return 0;
}

int overlay_broadcast_drop_check(unsigned char *a)
{
  /* Don't drop frames to non-broadcast addresses */
  if (!overlay_address_is_broadcast(a)) return 0;

  /* Hash the BPI and see if we have seen it recently.
     If so, drop the frame.
     The occassional failure to supress a broadcast frame is not
     something we are going to worry about just yet.  For byzantine
     robustness it is however required. */
  int bpi_index=0;
  int i;
  for(i=0;i<BROADCAST_LEN;i++)
    {
      bpi_index=((bpi_index<<3)&0xfff8)+((bpi_index>>13)&0x7);
      bpi_index^=a[SID_SIZE - BROADCAST_LEN + i];
    }
  bpi_index&=BPI_MASK;
  
  if (memcmp(bpilist[bpi_index].id, a + SID_SIZE - BROADCAST_LEN, BROADCAST_LEN)){
    if (debug&DEBUG_BROADCASTS)
      DEBUGF("BPI %s is new", alloca_tohex(a + SID_SIZE - BROADCAST_LEN, BROADCAST_LEN));
    bcopy(a + SID_SIZE - BROADCAST_LEN, bpilist[bpi_index].id, BROADCAST_LEN);
    return 0; /* don't drop */
  }else{
    if (debug&DEBUG_BROADCASTS)
      DEBUGF("BPI %s is a duplicate", alloca_tohex(a + SID_SIZE - BROADCAST_LEN, BROADCAST_LEN));
    return 1; /* drop frame because we have seen this BPI recently */
  }
}
