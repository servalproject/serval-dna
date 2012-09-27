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
#include <stdarg.h>
#include <stdlib.h>
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
static void _dump(XPRINTF xpf, const unsigned char *data, size_t len, size_t ofs, const char *fmt, ...);

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
      serval_packetvisualise(XPRINTF_STDIO(stdout), "Fuzz Test", buff, len);
    }
  return 0;
}

#endif

int serval_packetvisualise_renderaddress(XPRINTF xpf, const unsigned char *packet, size_t *ofs, int senderP)
{

  switch(packet[*ofs]) {
  case 0x00: /* ourself */
    if (senderSet) {
      int i;
      for(i=0;i<senderSet;i++) xprintf(xpf,"%02X",senderAddress[i]);
      if (senderSet<32) xprintf(xpf,"*");
      xprintf(xpf," <same as sender's address>"); 
    } else {
      xprintf(xpf," <WARNING: self-reference to sender's address>"); 
    }
    (*ofs)++;
    break;
  case 0x01: /* by index */
    xprintf(xpf,"<address associated with index #%02x by sender>",
	    packet[(*ofs)+1]);
    (*ofs)+=2;
    break;
  case 0x03: /* previously used address */
    xprintf(xpf,"<same as previous address>");
    (*ofs)++;
    break;
  case 0x09: /* prefix 3 bytes and assign index */
  case 0x05: /* prefix 3 bytes */
    { int skip=0;
      if (packet[*ofs]&8) skip=1;
      (*ofs)++;
      xprintf(xpf,"%02X%02X%02X* <24 bit prefix",
	      packet[(*ofs)],packet[(*ofs)+1],packet[(*ofs)+2]);
      if (senderP) bcopy(&packet[*ofs],senderAddress,3); senderSet=3;
      if (skip) xprintf(xpf," assigned index 0x%02x",packet[(*ofs)+3]);
      xprintf(xpf,">");
      (*ofs)+=3+skip;
    }
    break;
  case 0x0a: /* prefix 7 bytes and assign index */
  case 0x06: /* prefix 7 bytes */
    { int skip=0;
      if (packet[*ofs]&8) skip=1;
      (*ofs)++;
      xprintf(xpf,"%02X%02X%02X%02X%02X%02X%02X* <56 bit prefix",
	      packet[(*ofs)],packet[(*ofs)+1],packet[(*ofs)+2],packet[(*ofs)+3],
	      packet[(*ofs)+4],packet[(*ofs)+5],packet[(*ofs)+6]);
      if (senderP) bcopy(&packet[*ofs],senderAddress,7); senderSet=7;
      if (skip) xprintf(xpf," assigned index 0x%02x",packet[(*ofs)+7]);
      xprintf(xpf,">");
      (*ofs)+=7+skip;
    }
    break;
  case 0x07: /* prefix 11 bytes */
    (*ofs)++;
    xprintf(xpf,"%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X* <88 bit prefix>",
	    packet[(*ofs)],packet[(*ofs)+1],packet[(*ofs)+2],packet[(*ofs)+3],
	    packet[(*ofs)+4],packet[(*ofs)+5],packet[(*ofs)+6],packet[(*ofs)+7],
	    packet[(*ofs)+8],packet[(*ofs)+9],packet[(*ofs)+10]);
    if (senderP) bcopy(&packet[*ofs],senderAddress,11); senderSet=11;
    (*ofs)+=11;
    break;
  case 0x0f: /* broadcast */
    {
      int i;
      (*ofs)++; 
      xprintf(xpf,"<broadcast BPI=");
      for(i=0;i<8;i++) xprintf(xpf,"%02X",packet[(*ofs)+i]);
      (*ofs)+=8;
      xprintf(xpf,">"); break;
    }
  case 0x0b: /* prefix 11 bytes and assign index */
  case 0x0d: /* prefix 11 bytes and assign 2-byte index */

  case 0x02: /* reserved */
  case 0x04: /* reserved */
  case 0x0c: /* reserved */
    xprintf(xpf,"<illegal address token 0x%02x>",packet[(*ofs)]);
    return -1;
    break;
  default:
  case 0x0e: /* full address and assign 2-byte index */
  case 0x08: /* full address and assign index */
    { 
      int skip=0;
      if (packet[*ofs]==0x08) { (*ofs)++; skip=1; }
      else if (packet[*ofs]==0x0e) { (*ofs)++; skip=2; }
      /* naturally presented 32 byte address */
      {
	int i;
	for(i=0;i<32;i++) xprintf(xpf,"%02x",packet[(*ofs)+i]);
	if (senderP) bcopy(&packet[*ofs],senderAddress,32); senderSet=32;
      }
      if (skip) {
	xprintf(xpf," <literal 256 bit address, assigned index 0x");
	int i;
	for(i=0;i<skip;i++) xprintf(xpf,"%02x",packet[(*ofs)+skip]);
	xprintf(xpf,">");
      } else
	xprintf(xpf," <literal 256 bit address>");
      (*ofs)+=32+skip;
    }
  }
  return 0;  
}


int isOverlayPacket(XPRINTF xpf, const unsigned char *packet, size_t *ofs, size_t len)
{
  if (packet[(*ofs)]!=0x4f) return 0;
  if (packet[(*ofs)+1]!=0x10) return 0;

  int version = (packet[(*ofs)+2]<<8)+packet[(*ofs)+3];

  xprintf(xpf,"%sServal Overlay Mesh Packet version %d (0x%04x)\n",
	  indent(4),version,version);
  if (version>0x001) {
    xprintf(xpf,"%s  WARNING: Packet version is newer than I know about.\n",indent(4));
  }
  (*ofs)+=4;

  senderSet=0;
  while((*ofs)<len)
    {
      int dumpRaw=0;
      int next_frame_ofs=-1;
      int frame_ofs=*ofs;
      int frame_flags=0;
      int frame_type=packet[(*ofs)++];
      if ((frame_type&0xf0)==0xe0) {
	frame_type=frame_type<<8;
	frame_type|=packet[(*ofs)++];
	frame_type&=0xfff;
      } else if ((frame_type&0xf0)==0xf0) {
	frame_type=frame_type<<16;
	frame_type|=packet[(*ofs)++]<<8;
	frame_type|=packet[(*ofs)++];
	frame_type&=0xfffff;
      } 
      
      frame_flags=frame_type&0xf;
      frame_type&=0xfffffff0;

      int ttl=packet[(*ofs)++];

      int rfs=packet[*ofs];
      switch(rfs) {
      case 0xfa: case 0xfb: case 0xfc: case 0xfd: case 0xfe: 
	rfs=250+256*(rfs-0xfa)+packet[++(*ofs)]; 
	break;
      case 0xff: rfs=(packet[(*ofs)+1]<<8)+packet[(*ofs)+2]; (*ofs)+=2;
      default: /* Length is natural value of field, so nothing to do */
	break;
      }
      (*ofs)++;
  
      xprintf(xpf,"%sOverlay Frame at offset 0x%x\n%stype identifier = 0x%x, modifier bits = 0x%x.\n",
	      indent(6),frame_ofs,indent(8),frame_type,frame_flags);
      xprintf(xpf,"%sTime-to-live = %d (0x%02x)\n%sframe payload bytes = %d (0x%x).\n",
	      indent(8),ttl,ttl,indent(8),rfs,rfs);
      
      /* Assuming that there is no compression or crypto, we just use the plain body 
	 of the frame. */
      const unsigned char *frame=&packet[*ofs];
      int frame_len=rfs;

      next_frame_ofs=(*ofs)+rfs;

      int cantDecodeFrame=0;
      int cantDecodeRecipient=0;
      int showSignature=0;
      xprintf(xpf,"%sframe is ",indent(8));
      switch(frame_flags&0x3) {
      case 0: xprintf(xpf,"not compressed"); break;
      case 1: xprintf(xpf,"gzip-compressed"); break;
      case 2: xprintf(xpf,"bzip2-compressed"); break;
      case 3: xprintf(xpf,"marked as compressed using illegal code 0x3"); 
	cantDecodeFrame=1;
	break;
      }
      xprintf(xpf,"\n%sframe is ",indent(8));
      switch(frame_flags&0xc) {
      case 0: xprintf(xpf,"not encrypted"); break;
      case 4: xprintf(xpf,"encrypted using recipients public key (SID)"); 
	cantDecodeFrame=1; break;
      case 8: xprintf(xpf,"signed using senders public signing key (SAS)"); 
	/* This doesn't stop us displaying the frame, as the body is still en claire.
	   It does mean that we should present the signature block, and not
	   show the signature as part of the packet body. */
	cantDecodeFrame=0; 
	showSignature=1;
	break;
      case 0xc: xprintf(xpf,"authcrypted (encrypted and authenticated) using CryptoBox (SID)"); 
	cantDecodeFrame=1; break;
      }
      xprintf(xpf,"\n");

      if (!cantDecodeRecipient) {
	/* Show next-hop, sender and  destination addresses */
	xprintf(xpf,"%sFrame    next-hop address: ",indent(8));
	if (serval_packetvisualise_renderaddress(xpf,packet,ofs,0))
	  { xprintf(xpf,"\n%sERROR: Cannot decode remainder of frame\n",indent(8));
	    dumpRaw=1;
	    goto nextframe;
	  }
	xprintf(xpf,"\n%sFrame destination address: ",indent(8));
	if (serval_packetvisualise_renderaddress(xpf,packet,ofs,0))
	  { xprintf(xpf,"\n%sERROR: Cannot decode remainder of frame\n",indent(8));
	    dumpRaw=1;
	    goto nextframe;
	  }
	xprintf(xpf,"\n%sFrame      source address: ",indent(8));
	if (serval_packetvisualise_renderaddress(xpf,packet,ofs,1))
	  { xprintf(xpf,"\n%sERROR: Cannot decode remainder of frame\n",indent(8));
	    dumpRaw=1;
	    goto nextframe;
	  }
	xprintf(xpf,"\n");
	xprintf(xpf,"%sFrame payload begins at offset 0x%x\n",indent(8),*ofs);
	frame=&packet[*ofs];
	frame_len=next_frame_ofs-(*ofs);
	if (showSignature) frame_len-=64;
	frame_ofs=0;
      } else {
	xprintf(xpf,"%sWARNING: Cannot decode frame addresses due to encryption.\n",
		indent(8));
      }

      if (cantDecodeFrame) {
	xprintf(xpf,"%sWARNING: Cannot decode compressed and/or encrypted frame.\n",indent(8));
	_dump(xpf, frame, frame_len, 0, "%s", indent(10));
      }
      else {
	/* Decrypt and/or decompress frame */

	switch(frame_type) { 
	case 0x10: /* self-announce */
	  {
	    unsigned long long time;
	    int i;
	    xprintf(xpf,"%sSelf-announcement\n",indent(8));
	    time=0; for(i=0;i<4;i++) time=(time<<8)|frame[frame_ofs++];
	    xprintf(xpf,"%sStart time: %10lldms (0x%08llx)\n",indent(10),time,time);
	    time=0; for(i=0;i<4;i++) time=(time<<8)|frame[frame_ofs++];
	    xprintf(xpf,"%sEnd time:   %10lldms (0x%08llx)\n",indent(10),time,time);
	    xprintf(xpf,"%sSender's Interface number: %d\n",indent(10),frame[frame_ofs++]);
	  }
	  break;
	case 0x20: /* self-announce ack */
	  {
	    unsigned long long time;
	    int i;
	    xprintf(xpf,"%sACK of self-announce\n",indent(8));
	    time=0; for(i=0;i<4;i++) time=(time<<8)|frame[frame_ofs++];
	    xprintf(xpf,"%sStart time: %10lldms (0x%08llx)\n",indent(10),time,time);
	    time=0; for(i=0;i<4;i++) time=(time<<8)|frame[frame_ofs++];
	    xprintf(xpf,"%sEnd time:   %10lldms (0x%08llx)\n",indent(10),time,time);
	    int iface=frame[frame_ofs++];
	    xprintf(xpf,"%sSender Interface : %d\n",indent(10),iface);	    
	  } 
	  break;
	case 0x50: /* rhizome advertisement */
	  {
	    int i,j,k;
	    int rhizome_ad_frame_type=frame[0];
	    xprintf(xpf,"%sRhizome bundle advertisement frame, version %d\n",indent(8),rhizome_ad_frame_type);
	    unsigned short int http_port = 0;
	    i=1;
	    switch (rhizome_ad_frame_type) {
	      case 3:
	      case 4:
		http_port = (frame[i] << 8) + frame[i+1];
		i += 2;
		xprintf(xpf,"%sHTTP port = %d\n", indent(8), http_port);
		break;
	    }
	    switch (rhizome_ad_frame_type) {
	      case 2:
	      case 4:
		xprintf(xpf,"%sBundle BAR(s) (i=%d, frame_len=%d):\n", indent(8),i,frame_len);
		break;
	      case 1:
	      case 3:
		/* Frame contains whole manifest(s) */
		xprintf(xpf,"%sBundle Manifest(s) (i=%d, frame_len=%d):\n", indent(8),i,frame_len);
		while(i<frame_len) {		  
		  /* Check for end of manifests */
		  if (frame[i] == 0xff) { i+=1; break; }
		  /* Check remaining bytes */
		  int manifest_len=(frame[i]<<8)+frame[i+1];
		  i+=2;
		  if (i > frame_len) {
		    xprintf(xpf,"%sERROR: Unexpected end of Frame -- skipping rest of frame.\n",indent(10));
		    break;
		  }
		  if (manifest_len>(frame_len-i)) {
		    xprintf(xpf,"%sERROR: Manifest extends for 0x%x bytes, but frame contains only 0x%x more bytes -- skipping rest of frame.\n",indent(10),manifest_len,frame_len-i);
		    _dump(xpf, frame, frame_len, 0, "%s", indent(12));
		    i=frame_len;
		    break;
		  }
		  /* find manifest self-signature block */
		  for(j=0;j<manifest_len;j++) if (frame[i+j]==0) { j++; break;}
		  xprintf(xpf,"%smanifest id @0x%x-0x%x/0x%x (len=0x%x) (from first signature block) = ",
			  indent(10),i,i+manifest_len-1,frame_len,manifest_len);
		  for(k=0;k<32;k++) xprintf(xpf,"%02X",frame[i+j+k+1+64]);
		  xprintf(xpf,"\n");
		  /* Print manifest text body */
		  int column=0;
		  xprintf(xpf,"%sManifest variables:\n",indent(12));
		  for(k=0;k<(j-1);k++) {		    
		    if (!column) { xprintf(xpf,"%s",indent(14)); column=14; }
		    switch(frame[i+k]) {
		    case '\r': /* ignore CR */
		    case '\n': /* LF */
		      column=0;
		      /* fall through */
		    default:
		      xprintf(xpf,"%c",frame[i+k]);
		    }
		  }
		  /* Print manifest signature blocks */
		  
		  xprintf(xpf,"%sManifest signature blocks\n",indent(12));
		  for(;j<manifest_len;)
		    {
		      int sigLen=frame[i+j];
		      switch(sigLen) {
		      case 0x61: /* cryptosign signature */
			xprintf(xpf,"%sNaCl CryptoSign Generated Signature\n",indent(14));
			xprintf(xpf,"%sPublic key of signatory = ",indent(16));
			for(k=0;k<32;k++) xprintf(xpf,"%02X",frame[i+j+1+64+k]);
			xprintf(xpf,"\n");
			xprintf(xpf,"%sSignature data:",indent(16));
			for(k=0;k<64;k++)
			  {
			    if (!(k&0xf)) xprintf(xpf,"\n%s",indent(18-1));
			    xprintf(xpf," %02X",frame[i+j+1+k]);
			  }
			xprintf(xpf,"\n");
			break;
		      case 0:
			sigLen=1;
		      default:
			xprintf(xpf,"%sUnknown Signature Type 0x%02x\n",indent(14),frame[i+j]);
			xprintf(xpf,"%sSignature data:",indent(16));
			for(k=0;k<(sigLen-1);k++)
			  {
			    if (!(k&0xf)) xprintf(xpf,"\n%s",indent(18-1));
			    xprintf(xpf," %02X",frame[i+j+1+k]);
			  }
			xprintf(xpf,"\n");			
			break;
		      }
		      j+=sigLen;
		    }
		  i+=manifest_len;
		}
		break;
	      default:
		xprintf(xpf,"%sWARNING: Version is newer than I understand.\n",indent(10));
		break;
	    }

	    xprintf(xpf,"%sBundle Advertisement Records (BARs):\n",indent(8));
	    for(;i<(frame_len-31);i+=32) {
	      xprintf(xpf,"%smanifest id = %02X%02X%02X%02X%02X%02X%02X%02X*\n",
		      indent(10),frame[i],frame[i+1],frame[i+2],frame[i+3],
		      frame[i+4],frame[i+5],frame[i+6],frame[i+7]);
	    
	      unsigned long long manifest_version=0;
	      for(j=0;j<7;j++) manifest_version=(manifest_version<<8)|frame[i+8+j];
	      xprintf(xpf,"%smanifest revision = %lld (0x%llx)\n",
		      indent(12),manifest_version,manifest_version);
	      xprintf(xpf,"%smanifest TTL = %d (0x%x)\n",
		      indent(12),frame[i+16],frame[i+16]);
	      unsigned long long file_size=0;
	      for(j=0;j<6;j++) file_size=(file_size<<8)+frame[i+18+j];
	      xprintf(xpf,"%sassociated file size = %lld (0x%llx) bytes\n",
		      indent(12),file_size,file_size);
	      double lat0=((frame[i+24]<<8)+frame[i+25])*180/65535-90;
	      double long0=((frame[i+26]<<8)+frame[i+27])*360/65535-180;
	      double lat1=((frame[i+28]<<8)+frame[i+29])*180/65535-90;
	      double long1=((frame[i+30]<<8)+frame[i+31])*360/65535-180;
	      xprintf(xpf,"%sgeographic extent of relevance (lat,long) = (%.f,%.f) - (%.f,%.f)\n",
		      indent(12),lat0,long0,lat1,long1);
	    }
	  }
	  break;
	case 0x70: /* node announce */
	  {
	    int i;
	    xprintf(xpf,"%sNode reachability announcment(s):\n",indent(8));
	    for(i=0;i<frame_len;i+=8)
	      xprintf(xpf,"%s  %02X%02X%02X%02X%02X%02X* best link score = %d, via %d gateways\n",
		      indent(10),
		      frame[i+0],frame[i+1],frame[i+2],frame[i+3],
		      frame[i+4],frame[i+5],
		      frame[i+6],frame[i+7]);
	  }

	  break;
	case 0x30: /* MDP frame */
	  {
	    int version=(frame[0]<<8)|(frame[1]);
	    xprintf(xpf,"%sMDP frame (version=0x%04x):\n",indent(8),version);
	    int src_port=(frame[2]<<24)|(frame[3]<<16)|(frame[4]<<8)|frame[5];
	    int dst_port=(frame[6]<<24)|(frame[7]<<16)|(frame[8]<<8)|frame[9];
	    xprintf(xpf,"%s      source port =%-6d (0x%08x)\n",
		    indent(10),src_port,src_port);
	    xprintf(xpf,"%s destination port =%-6d (0x%08x)\n",
		    indent(10),dst_port,dst_port);
	    xprintf(xpf,"%sMDP Payload:\n",indent(10));
	    _dump(xpf, frame + 10, frame_len - 10, 0, "%sframe+", indent(12));
	  }
	  break;
	case 0x40: /* voice frame */
	case 0x60: /* please explain (request for expansion of an abbreviated address) */
	default:
	  {
	    /* Reserved values */
	    xprintf(xpf,"%sWARNING: Packet contains reserved/unknown frame type 0x%02x\n", indent(8),frame_type);
	    _dump(xpf, frame, frame_len, 0, "%sframe+", indent(10));
	  }
	  break;
	}

	if (showSignature) {
	  xprintf(xpf,"%sWARNING: Signature is for display purposes, and has not been verified\n",indent(8));
	  xprintf(xpf,"%sFrame signature block (SAS signed):\n",indent(8));
	  _dump(xpf, frame + frame_len, len < 64 ? len : 64, 0, "%s" ,indent(10));
	}
      }	
      
    nextframe:
      if (next_frame_ofs<0) {
	xprintf(xpf,"%sERROR: Cannot continue decoding payload due to previous error(s)\n",indent(6));
	return 1;
      }
      if (dumpRaw)
	_dump(xpf, packet, next_frame_ofs, *ofs, "%s", indent(10));
      (*ofs)=next_frame_ofs;
      continue;
    }
      
  return 1;
}

int isDNAPacket(XPRINTF xpf, const unsigned char *packet, size_t *ofs, size_t len)
{
  return 0;
}

int serval_packetvisualise(XPRINTF xpf, const char *message, const unsigned char *packet, size_t len)
{
  if (message)
    xprintf(xpf, "%s: ",message);
  xprintf(xpf,"Packet body of %d (0x%x) bytes:\n",len,len);
  _dump(xpf, packet, len, 0, "    ");
  size_t ofs=0;
  xprintf(xpf,"  Packet Structure:\n");
  if (isOverlayPacket(xpf,packet,&ofs,len))
    ;
  else if (isDNAPacket(xpf,packet,&ofs,len))
    ;
  else {
    /* Unknown packet type. */
  }
  if (ofs<len) {
    xprintf(xpf,"  WARNING: The last %d (0x%x) bytes of the packet were not parsed.\n",len-ofs,len-ofs);
    _dump(xpf, packet, len, ofs, "    ");
  }
  return 0;
}

static void _dump(XPRINTF xpf, const unsigned char *data, size_t len, size_t ofs, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  int i, j;
  for (i = (ofs / 16) * 16; i < len; i += 16) {
    vxprintf(xpf, fmt, ap);
    xprintf(xpf, "%04x:", i);
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
  va_end(ap);
}
