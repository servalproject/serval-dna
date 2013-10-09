/* 
Serval Mesh
Copyright (C) 2010-2012 Paul Gardner-Stephen
Copyright (C) 2010-2012 Serval Project Pty Limited
Copyright (C) 2012 Serval Project Inc.

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
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include "xprintf.h"

#define MAX_SPACES 120
const char *spaces="          ""          ""          ""          "
            "          ""          ""          ""          "
  "          ""          ""          ""          ";
const char *indent(int n)
{
  return &spaces[MAX_SPACES-n];
}

int senderSet=0;
unsigned char senderAddress[32];
static void _dump(XPRINTF xpf, const unsigned char *data, size_t len, size_t ofs, const char *prefix);

#ifdef STANDALONE

int main(int argc,char **argv)
{
  int i,n;
  int len;
  unsigned char buff[8192];

  for(n=0;n<1024;n++)
    {
      int i;
      len=random()%8192;
      for(i=0;i<len;i++) buff[i]=random()&0xff;
      serval_packetvisualise_xpf(XPRINTF_STDIO(stdout), "Fuzz Test", buff, len);
    }
  return 0;
}

#endif

int serval_packetvisualise_renderaddress(XPRINTF xpf, const unsigned char *packet, size_t *ofs, int senderP)
{
  unsigned int len = packet[(*ofs)++];
  xprintf(xpf,"(0x%02x) ",len);
  switch (len){
    case 0xFF:
      xprintf(xpf,"<same as sender's address>"); 
      return 0;
    case 0xFE:
      xprintf(xpf,"<same as previous address>");
      return 0;
    case 0xFD:
      xprintf(xpf,"<you>");
      return 0;
    case 0xFC:
      xprintf(xpf,"<me>");
      return 0;
    default:
      if (len>32){
	xprintf(xpf,"<illegal address token 0x%02x>",len);
	return -1;
      }
      int i;
      for (i=0;i<len;i++)
	xprintf(xpf,"%02X",packet[(*ofs)++]);
      if (len<32) xprintf(xpf,"*");
      return 0;
  }
}

static unsigned int get_packed_uint32(const unsigned char *packet, size_t *ofs){
  unsigned int ret=0;
  int shift=0;
  int byte;
  do{
    byte = packet[(*ofs)++];
    ret |= (byte&0x7f)<<shift;
    shift+=7;
  }while(byte & 0x80);
  return ret;
}


static const char * overlay_type(unsigned int type){
  switch(type){
    case 0x20:
      return "SELF_ANNOUNCE_ACK";
    case 0x50:
      return "RHIZOME_ADVERT";
    case 0x60:
      return "PLEASE_EXPLAIN";
    default:
      return "UNKNOWN";
  }
}

static const char * port_name(uint32_t port){
  switch(port){
    case 1:
      return "KEY_MAP_REQUEST";
    case 2:
      return "LINK_STATE";
    case 4:
      return "STUN_REQUEST";
    case 5:
      return "STUN";
    case 6:
      return "PROBE";
    case 7:
      return "ECHO";
    case 8:
      return "TRACE";
    case 10:
      return "DNA_LOOKUP";
    case 12:
      return "VOMP";
    case 13:
      return "RHIZOME_REQUEST";
    case 14:
      return "RHIZOME_RESPONSE";
    case 15:
      return "DIRECTORY";
    case 16:
      return "RHIZOME_MANIFEST_REQUEST";
    case 17:
      return "RHIZOME_SYNC";
    case 0x3f:
      return "NO_REPLY";
    default:
      return "UNKNOWN";
  }
}
int isOverlayPacket(XPRINTF xpf, const unsigned char *packet, size_t *ofs, size_t len)
{
  unsigned int version = packet[(*ofs)++];
  if (version > 1)
    return 0;
  xprintf(xpf,"%sPacket version %d (0x%02x)\n",
	  indent(4),version,version);
  
  unsigned int encapsulation = packet[(*ofs)++];
    xprintf(xpf,"%sEncapsulation (0x%02x);",
	    indent(4),encapsulation);
  switch (encapsulation){
    case 1:
      xprintf(xpf, " OVERLAY\n");
      break;
    case 2:
      xprintf(xpf, " SINGLE\n");
      break;
    default:
      xprintf(xpf, " UNKNOWN\n");
      // TODO dump remainder?
      return -1;
  }

  xprintf(xpf, "%sSender; ", indent(4));
  int ret=serval_packetvisualise_renderaddress(xpf,packet,ofs,0);
  xprintf(xpf, "\n");
  if (ret)
    return ret;
  
  unsigned int packet_flags = packet[(*ofs)++];
  xprintf(xpf, "%sFlags (0x%02x);", indent(4), packet_flags);
  if (packet_flags & 1)
    xprintf(xpf, " UNICAST");
  if (packet_flags & 2)
    xprintf(xpf, " HAS_INTERFACE");
  if (packet_flags & 4)
    xprintf(xpf, " HAS_SEQUENCE");
  xprintf(xpf, "\n");
  
  if (packet_flags & 2)
    xprintf(xpf, "%sSender Interface; 0x%02x\n", indent(4), packet[(*ofs)++]);
  if (packet_flags & 4)
    xprintf(xpf, "%sSequence; 0x%02x\n", indent(4), packet[(*ofs)++]);
  
  while((*ofs)<len){
    unsigned int payload_flags = packet[(*ofs)++];
    xprintf(xpf, "%sFlags (0x%02x);", indent(6), payload_flags);
    if (payload_flags & 1)
      xprintf(xpf, " SENDER_SAME");
    if (payload_flags & 2)
      xprintf(xpf, " TO_BROADCAST");
    if (payload_flags & 4)
      xprintf(xpf, " ONE_HOP");
    if (payload_flags & 16)
      xprintf(xpf, " ENCRYPTED");
    if (payload_flags & 32)
      xprintf(xpf, " SIGNED");
    if (payload_flags & 64)
      xprintf(xpf, " ACK_SOON");
    if (payload_flags & 128)
      xprintf(xpf, " OVERLAY_TYPE");
    xprintf(xpf, "\n");
    
    if (!payload_flags & 1){
      xprintf(xpf, "%sSender; ", indent(6));
      int ret=serval_packetvisualise_renderaddress(xpf,packet,ofs,0);
      xprintf(xpf, "\n");
      if (ret)
	return ret;
    }
    
    if (payload_flags & 2){
      if (!(payload_flags & 4)){
	xprintf(xpf, "%sBroadcast ID; 0x", indent(6));
	int i;
	for (i=0;i<8;i++)
	  xprintf(xpf,"%02X",packet[(*ofs)++]);
	xprintf(xpf, "\n");
      }
    }else{
      xprintf(xpf, "%sDestination; ", indent(6));
      int ret=serval_packetvisualise_renderaddress(xpf,packet,ofs,0);
      xprintf(xpf, "\n");
      if (ret)
	return ret;
      if (!(payload_flags & 4)){
	xprintf(xpf, "%sNext Hop; ", indent(6));
	int ret=serval_packetvisualise_renderaddress(xpf,packet,ofs,0);
	xprintf(xpf, "\n");
	if (ret)
	  return ret;
      }
    }
    
    if (!(payload_flags & 4)){
      unsigned int ttl_qos = packet[(*ofs)++];
      xprintf(xpf, "%sTTL, QOS (0x%02x); %d, %d\n", indent(6), ttl_qos, ttl_qos & 0x1F, (ttl_qos >> 5) & 3);
    }
    
    int o_type=0;
    if (payload_flags & 128){
      o_type = packet[(*ofs)++];
      xprintf(xpf, "%sOverlay Type (0x%02x); %s\n", indent(6), o_type, overlay_type(o_type));
    }
    
    if (version >=1){
      xprintf(xpf, "%sMDP Sequence; 0x%02x\n", indent(6), packet[(*ofs)++]);
    }
    
    int payload_len = 0;
    if (encapsulation==1){
      payload_len=packet[(*ofs)++]<<8;
      payload_len|=packet[(*ofs)++];
      xprintf(xpf, "%sPayload length; 0x%04x\n", indent(6), payload_len);
      if (payload_len > len - *ofs)
	return -1;
    }else{
      payload_len = len - *ofs;
    }
    const unsigned char *payload_start = &packet[*ofs];
    (*ofs)+=payload_len;
    
    if (payload_flags & 16){
      xprintf(xpf, "%sPayload unreadable due to encryption\n", indent(8));
      continue;
    }
    
    if (payload_flags & 32){
      payload_len -= 64;
    }
    
    if (!(payload_flags & 128)){
      size_t payload_offset=0;
      uint32_t dest_port_raw = get_packed_uint32(payload_start, &payload_offset);
      
      int same = dest_port_raw&1;
      uint32_t dest_port = dest_port_raw >> 1;
      
      xprintf(xpf, "%sDestination Port (0x%04x); %d %s\n", indent(8), dest_port_raw, dest_port, port_name(dest_port));
      if (same){
	xprintf(xpf, "%sSource Port; SAME\n", indent(8));
      }else{
	uint32_t src_port = get_packed_uint32(payload_start, &payload_offset);
	xprintf(xpf, "%sSource Port; %d %s\n", indent(8), src_port, port_name(src_port));
      }
      payload_start += payload_offset;
      payload_len -= payload_offset;
    }
    
    xprintf(xpf, "%sPayload body;\n", indent(8));
    _dump(xpf, payload_start, payload_len, 0, indent(10));
    
    if (payload_flags & 32){
      xprintf(xpf, "%sSignature;\n", indent(8));
      _dump(xpf, payload_start+payload_len, 64, 0, indent(10));
    }
  }

  return 1;
}

int serval_packetvisualise_xpf(XPRINTF xpf, const char *message, const unsigned char *packet, size_t len)
{
  if (message)
    xprintf(xpf, "%s: ",message);
  xprintf(xpf,"Packet body of %d (0x%x) bytes:\n",(int)len,(int)len);
  _dump(xpf, packet, len, 0, "    ");
  size_t ofs=0;
  xprintf(xpf,"  Packet Structure:\n");
  if (isOverlayPacket(xpf,packet,&ofs,len))
    ;
  if (ofs<len) {
    xprintf(xpf,"  WARNING: The last %d (0x%x) bytes of the packet were not parsed.\n",(int)(len-ofs),(int)(len-ofs));
  }
  return 0;
}

static void _dump(XPRINTF xpf, const unsigned char *data, size_t len, size_t ofs, const char *prefix)
{
  int i, j;
  for (i = ofs & 0xFFFFFFF0; i < len; i += 16) {
    xprintf(xpf, "%s%04x:", prefix, i);
    for (j = 0; j < 16; ++j)
      if (i + j >= ofs && i + j < len)
	xprintf(xpf," %02x", data[i+j]);
      else
	xprintf(xpf, "   ");
    xprintf(xpf, "    ");
    for (j = 0; j < 16 && i + j < len; ++j)
      xputc(i + j < ofs ? ' ' : data[i+j] >= ' ' && data[i+j] < 0x7c ? data[i+j] : '.', xpf);
    xputc('\n', xpf);
  }
}

int serval_packetvisualise(const char *message, const unsigned char *packet, size_t len)
{
  return serval_packetvisualise_xpf(XPRINTF_STDIO(stdout),message, packet, len);
}
