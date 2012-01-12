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

#include "mphlr.h"

/* Determine if an address is broadcast */
int overlay_address_is_broadcast(unsigned char *a)
{
  int i;
  for(i=0;i<(SID_SIZE-8);i++)
    if (a[i]!=0xff) return 0;
  return 1;
}

int overlay_broadcast_generate_address(unsigned char *a)
{
  int i;
  for(i=0;i<(SID_SIZE-8);i++) a[i]=0xff;
  for(;i<SID_SIZE;i++) a[i]=random()&0xff;
  return 0;
}

#define MAX_BPIS 1024
#define BPI_MASK 0x3ff
unsigned char bpilist[MAX_BPIS][8];

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
  for(i=0;i<8;i++)
    {
      bpi_index=((bpi_index<<3)&0xfff8)+((bpi_index>>13)&0x7);
      bpi_index^=a[24+i];
    }
  bpi_index&=BPI_MASK;
  if (debug&DEBUG_BROADCASTS) 
    fprintf(stderr,"BPI %02X%02X%02X%02X%02X%02X%02X%02X resolves to hash bin %d\n",
	    a[24],a[25],a[26],a[27],a[28],a[29],a[30],a[31],bpi_index);
  
  int bpiNew=0;
  for(i=0;i<8;i++)
    {
      if (a[24+i]!=bpilist[bpi_index][i]) bpiNew=1;
      bpilist[bpi_index][i]=a[24+i];
    }

  if (bpiNew)
    {
      if (debug&DEBUG_BROADCASTS) fprintf(stderr,"  BPI is new, so don't drop frame.\n");
      return 0; /* don't drop */
    }
  else
    {
      if (debug&DEBUG_BROADCASTS) fprintf(stderr,"  BPI is already in our list, so drop the frame to prevent broadcast storms.\n");
      return 1; /* drop frame because we have seen this BPI recently */
    }
}
