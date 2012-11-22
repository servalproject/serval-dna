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
#include "str.h"

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

int extractDid(unsigned char *packet,int *ofs,char *did)
{
  int d=0;
  int highP=1;
  int nybl;

  nybl=0;
  while(nybl!=0xf&&(*ofs<(OFS_SIDDIDFIELD+SIDDIDFIELD_LEN))&&(d<64))
    {
      if (highP) nybl=packet[*ofs]>>4; else nybl=packet[*ofs]&0xf;
      if (nybl<0xa) did[d++]='0'+nybl;
      else 
	switch(nybl) {
	case 0xa: did[d++]='*'; break;
	case 0xb: did[d++]='#'; break;
	case 0xc: did[d++]='+'; break;
	}
      if (highP) highP=0; else { (*ofs)++; highP=1; }
    }
  if (d>63) return WHY("DID too long");
  did[d]=0;

  return 0;
}

int stowDid(unsigned char *packet,int *ofs,char *did)
{
  int highP=1;
  int nybl;
  int d=0;
  int len=0;
  if (debug&DEBUG_PACKETFORMATS) printf("Packing DID \"%s\"\n",did);

  while(did[d]&&(d<DID_MAXSIZE))
    {
      switch(did[d])
	{
	case '0': case '1': case '2': case '3': case '4':
	case '5': case '6': case '7': case '8': case '9':
	  nybl=did[d]-'0'; break;
	case '*': nybl=0xa; break;
	case '#': nybl=0xb; break;
	case '+': nybl=0xc; break;
	default:
	  WHY("Illegal digits in DID number");
	  return -1;
	}
      if (highP) { packet[*ofs]=nybl<<4; highP=0; }
      else {
	packet[(*ofs)++]|=nybl; highP=1;
	len++;
      }
      d++;
    }
  if (d>=DID_MAXSIZE)
    {
      WHY("DID number too long");
      return -1;
    }
  /* Append end of number code, filling the whole byte for fast and easy comparison */
  if (highP) packet[(*ofs)++]=0xff;
  else packet[(*ofs)++]|=0x0f;
  len++;

  /* Fill remainder of field with randomness to protect any encryption */
  for(;len<SID_SIZE;len++) packet[(*ofs)++]=random()&0xff;
  
  return 0;
}

int extractSid(const unsigned char *packet, int *ofs, char *sid)
{
  (void) tohex(sid, packet + *ofs, SID_SIZE);
  *ofs += SID_SIZE;
  return 0;
}

int stowSid(unsigned char *packet, int ofs, const char *sid)
{
  if (debug & DEBUG_PACKETFORMATS)
    printf("stowing SID \"%s\"\n", sid);
  if (strcasecmp(sid,"broadcast") == 0)
    memset(packet + ofs, 0xff, SID_SIZE);
  else if (fromhex(packet + ofs, sid, SID_SIZE) != SID_SIZE || sid[SID_STRLEN] != '\0')
    return WHY("invalid SID");
  return 0;
}

int packetGetID(unsigned char *packet,int len,char *did,char *sid)
{
  int ofs=HEADERFIELDS_LEN;

  switch(packet[ofs])
    {
    case 0: /* DID */
      ofs++;
      if (extractDid(packet,&ofs,did)) return WHY("Could not decode DID");
      if (debug&DEBUG_PACKETFORMATS) DEBUGF("Decoded DID as %s", did);
      return 0;
      break;
    case 1: /* SID */
      ofs++;
      if (len<(OFS_SIDDIDFIELD+SID_SIZE)) return WHY("Packet too short");
      if (extractSid(packet,&ofs,sid)) return WHY("Could not decode SID");
      return 0;
      break;
    default: /* no idea */
      return WHY("Unknown ID key");
      break;
    }
  
  return WHY("Impossible event #1 just occurred");
}

/*
  One of the goals of our packet format is to make it very difficult to mount a known plain-text
  attack against the ciphered part of the packet.
  One defence is to make sure that no fixed fields are actually left zero.
  We accomplish this by filling "zero" fields with randomised data that meets a simple test condition.
  We have chosen to use the condition that if the modulo 256 sum of the bytes equals zero, then the packet
  is assumed to be zero/empty.
  The following two functions allow us to test this, and also to fill a field with safe "zero" data.
*/

int isFieldZeroP(unsigned char *packet,int start,int count)
{
  int mod=0;
  int i;

  for(i=start;i<start+count;i++)
    {
      mod+=packet[i];
      mod&=0xff;
    }

  if (debug&DEBUG_PACKETFORMATS) {
    if (mod) DEBUGF("Field [%d,%d) is non-zero (mod=0x%02x)",start,start+count,mod);
    else DEBUGF("Field [%d,%d) is zero",start,start+count);
  }

  if (mod) return 0; else return 1;
}

int safeZeroField(unsigned char *packet,int start,int count)
{
  int mod=0;
  int i;

  if (debug&DEBUG_PACKETFORMATS)
    DEBUGF("Known plain-text counter-measure: safe-zeroing [%d,%d)", start,start+count);
  
  for(i=start;i<(start+count-1);i++)
    {
      packet[i]=random()&0xff;
      mod+=packet[i];
      mod&=0xff;
    }
  /* set final byte so that modulo sum is zero */
  packet[i]=(0x100-mod)&0xff;
  
  return 0;
}
