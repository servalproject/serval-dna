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

int packetOk(struct overlay_interface *interface, unsigned char *packet, size_t len,
	     unsigned char *transaction_id,int ttl,
	     struct sockaddr *recvaddr, size_t recvaddrlen,int parseP)
{
  if (len<HEADERFIELDS_LEN) return WHY("Packet is too short");

  if (packet[0]==0x4F&&packet[1]==0x10) 
    {
      if (interface!=NULL)
	{
	  return packetOkOverlay(interface,packet,len,transaction_id,ttl,
				 recvaddr,recvaddrlen,parseP);
	}
      else
	/* We ignore overlay mesh packets in simple server mode, which is indicated by interface==-1 */
	return WHY("Ignoring overlay mesh packet");
    }

  return WHY("Packet type not recognised.");
}

void write_uint64(unsigned char *o,uint64_t v)
{
  int i;
  for(i=0;i<8;i++)
    { *(o++)=v&0xff; v=v>>8; }
}

void write_uint32(unsigned char *o,uint32_t v)
{
  int i;
  for(i=0;i<4;i++)
    { *(o++)=v&0xff; v=v>>8; }
}

void write_uint16(unsigned char *o,uint16_t v)
{
  int i;
  for(i=0;i<2;i++)
    { *(o++)=v&0xff; v=v>>8; }
}

