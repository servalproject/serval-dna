#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SPACES 120
char *spaces="          ""          ""          ""          "
            "          ""          ""          ""          "
  "          ""          ""          ""          ";
char *indent(int n)
{
  return &spaces[MAX_SPACES-n];
}

int senderSet=0;
unsigned char senderAddress[32];

int serval_packetvisualise_renderaddress(FILE *f,unsigned char *packet,int *ofs,int senderP)
{

  switch(packet[*ofs]) {
  case 0x00: /* ourself */
    if (senderSet) {
      int i;
      for(i=0;i<senderSet;i++) fprintf(f,"%02X",senderAddress[i]);
      if (senderSet<32) fprintf(f,"*");
      fprintf(f," <same as sender's address>"); 
    } else {
      fprintf(f," <WARNING: self-reference to sender's address>"); 
    }
    (*ofs)++;
    break;
  case 0x01: /* by index */
    fprintf(f,"<address associated with index #%02x by sender>",
	    packet[(*ofs)+1]);
    (*ofs)+=2;
    break;
  case 0x03: /* previously used address */
    fprintf(f,"<same as previous address>");
    (*ofs)++;
    break;
  case 0x09: /* prefix 3 bytes and assign index */
  case 0x05: /* prefix 3 bytes */
    { int skip=0;
      if (packet[*ofs]&8) skip=1;
      (*ofs)++;
      fprintf(f,"%02X%02X%02X* <24 bit prefix",
	      packet[(*ofs)],packet[(*ofs)+1],packet[(*ofs)+2]);
      if (senderP) bcopy(&packet[*ofs],senderAddress,3); senderSet=3;
      if (skip) fprintf(f," assigned index 0x%02x",packet[(*ofs)+3]);
      fprintf(f,">");
      (*ofs)+=3+skip;
    }
    break;
  case 0x0a: /* prefix 7 bytes and assign index */
  case 0x06: /* prefix 7 bytes */
    { int skip=0;
      if (packet[*ofs]&8) skip=1;
      (*ofs)++;
      fprintf(f,"%02X%02X%02X%02X%02X%02X%02X* <56 bit prefix",
	      packet[(*ofs)],packet[(*ofs)+1],packet[(*ofs)+2],packet[(*ofs)+3],
	      packet[(*ofs)+4],packet[(*ofs)+5],packet[(*ofs)+6]);
      if (senderP) bcopy(&packet[*ofs],senderAddress,7); senderSet=7;
      if (skip) fprintf(f," assigned index 0x%02x",packet[(*ofs)+7]);
      fprintf(f,">");
      (*ofs)+=7+skip;
    }
    break;
  case 0x07: /* prefix 11 bytes */
    (*ofs)++;
    fprintf(f,"%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X* <88 bit prefix>",
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
      fprintf(f,"<broadcast BPI=");
      for(i=0;i<8;i++) fprintf(f,"%02X",packet[(*ofs)+i]);
      (*ofs)+=8;
      fprintf(f,">"); break;
    }
  case 0x0b: /* prefix 11 bytes and assign index */
  case 0x0d: /* prefix 11 bytes and assign 2-byte index */

  case 0x02: /* reserved */
  case 0x04: /* reserved */
  case 0x0c: /* reserved */
    fprintf(f,"<illegal address token 0x%02x>",packet[(*ofs)]);
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
	for(i=0;i<32;i++) fprintf(f,"%02x",packet[(*ofs)+i]);
	if (senderP) bcopy(&packet[*ofs],senderAddress,32); senderSet=32;
      }
      if (skip) {
	fprintf(f," <literal 256 bit address, assigned index 0x");
	int i;
	for(i=0;i<skip;i++) fprintf(stderr,"%02x",packet[(*ofs)+skip]);
	fprintf(f,">");
      } else
	fprintf(f," <literal 256 bit address>");
      (*ofs)+=32+skip;
    }
  }
  return 0;  
}


int isOverlayPacket(FILE *f,unsigned char *packet,int *ofs,int len)
{
  if (packet[(*ofs)]!=0x4f) return 0;
  if (packet[(*ofs)+1]!=0x10) return 0;

  int version = (packet[(*ofs)+2]<<8)+packet[(*ofs)+3];

  fprintf(f,"%sServal Overlay Mesh Packet version %d (0x%04x)\n",
	  indent(4),version,version);
  if (version>0x001) {
    fprintf(f,"%s  WARNING: Packet version is newer than I know about.\n",indent(4));
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
  
      fprintf(f,"%sOverlay Frame at offset 0x%x\n%stype identifier = 0x%x, modifier bits = 0x%x.\n",
	      indent(6),frame_ofs,indent(8),frame_type,frame_flags);
      fprintf(f,"%sTime-to-live = %d (0x%02x)\n%sframe payload bytes = %d (0x%x).\n",
	      indent(8),ttl,ttl,indent(8),rfs,rfs);
      
      /* Assuming that there is no compression or crypto, we just use the plain body 
	 of the frame. */
      unsigned char *frame=&packet[*ofs];
      int frame_len=rfs;

      next_frame_ofs=(*ofs)+rfs;

      int cantDecodeFrame=0;
      int cantDecodeRecipient=0;
      fprintf(f,"%sframe is ",indent(8));
      switch(frame_flags&0x3) {
      case 0: fprintf(f,"not compressed"); break;
      case 1: fprintf(f,"gzip-compressed"); break;
      case 2: fprintf(f,"bzip2-compressed"); break;
      case 3: fprintf(f,"marked as compressed using illegal code 0x3"); 
	cantDecodeFrame=1;
	break;
      }
      fprintf(f,"\n%sframe is ",indent(8));
      switch(frame_flags&0xc) {
      case 0: fprintf(f,"not encrypted"); break;
      case 4: fprintf(f,"encrypted using recipients public key"); 
	cantDecodeFrame=1; break;
      case 8: fprintf(f,"encrypted using recipients public key, signed using senders private key"); 
	cantDecodeFrame=1; break;
      case 0xc: fprintf(f,"encrypted using recipients public key, signed using senders private key, and addresses are also encrypted"); 
	cantDecodeFrame=1; cantDecodeRecipient=1; break;
      }
      fprintf(f,"\n");

      if (!cantDecodeRecipient) {
	/* Show next-hop, sender and  destination addresses */
	fprintf(f,"%sFrame    next-hop address: ",indent(8));
	if (serval_packetvisualise_renderaddress(f,packet,ofs,0))
	  { fprintf(f,"\n%sERROR: Cannot decode remainder of frame\n",indent(8));
	    dumpRaw=1;
	    goto nextframe;
	  }
	fprintf(f,"\n%sFrame destination address: ",indent(8));
	if (serval_packetvisualise_renderaddress(f,packet,ofs,0))
	  { fprintf(f,"\n%sERROR: Cannot decode remainder of frame\n",indent(8));
	    dumpRaw=1;
	    goto nextframe;
	  }
	fprintf(f,"\n%sFrame      source address: ",indent(8));
	if (serval_packetvisualise_renderaddress(f,packet,ofs,1))
	  { fprintf(f,"\n%sERROR: Cannot decode remainder of frame\n",indent(8));
	    dumpRaw=1;
	    goto nextframe;
	  }
	fprintf(f,"\n");
	fprintf(f,"%sFrame payload begins at offset 0x%x\n",indent(8),*ofs);
	frame=&packet[*ofs];
	frame_len=next_frame_ofs-(*ofs);
	frame_ofs=0;
      } else {
	fprintf(f,"%sWARNING: Cannot decode frame addresses due to encryption.\n",
		indent(8));
      }

      if (cantDecodeFrame) {
	fprintf(f,"%sWARNING: Cannot decode compressed and/or encrypted frame.\n",indent(8));
	int i,j;
	for(i=0;i<frame_len;i+=16) 
	  {
	    fprintf(f,"%s%04x :",indent(10),i);
	    for(j=0;j<16&&(i+j)<len;j++) fprintf(f," %02x",frame[i+j]);
	    for(;j<16;j++) fprintf(f,"   ");
	    fprintf(f,"    ");
	    for(j=0;j<16&&(i+j)<len;j++) fprintf(f,"%c",frame[i+j]>=' '
						 &&frame[i+j]<0x7c?frame[i+j]:'.');
	    fprintf(f,"\n");
	  }
      }
      else {
	/* Decrypt and/or decompress frame */

	switch(frame_type) { 
	case 0x10: /* self-announce */
	  {
	    unsigned long long time;
	    int i;
	    fprintf(f,"%sSelf-announcement\n",indent(8));
	    time=0; for(i=0;i<4;i++) time=(time<<8)|frame[frame_ofs++];
	    fprintf(f,"%sStart time: %10lldms (0x%08llx)\n",indent(10),time,time);
	    time=0; for(i=0;i<4;i++) time=(time<<8)|frame[frame_ofs++];
	    fprintf(f,"%sEnd time:   %10lldms (0x%08llx)\n",indent(10),time,time);
	    fprintf(f,"%sSender's Interface number: %d\n",indent(10),frame[frame_ofs++]);
	  }
	  break;
	case 0x20: /* self-announce ack */
	  {
	    unsigned long long time;
	    int i;
	    fprintf(f,"%sACK of self-announce\n",indent(8));
	    time=0; for(i=0;i<4;i++) time=(time<<8)|frame[frame_ofs++];
	    fprintf(f,"%sObservation time : %10lldsecs (0x%08llx)\n",indent(10),time,time);
	    while(frame_ofs<frame_len) {
	      int iface=frame[frame_ofs++];
	      int score=frame[frame_ofs++];
	      fprintf(f,"%sinterface #%d reachability score: %d (0x%02x)\n",
		      indent(12),iface,score,score);
	    }
	  } 
	  break;
	case 0x50: /* rhizome advertisement */
	  {
	    int i,j;
	    fprintf(f,"%sRhizome bundle advertisement record (BAR) announcements, version %d\n",indent(8),frame[0]);
	    if (frame[0]>1) fprintf(f,"%sWARNING: Version is newer than I understand.\n",
				    indent(10));
	    for(i=1;i<(frame_len-31);i+=32) {
	      fprintf(f,"%smanifest id = %02X%02X%02X%02X%02X%02X%02X%02X*\n",
		      indent(10),frame[i],frame[i+1],frame[i+2],frame[i+3],
		      frame[i+4],frame[i+5],frame[i+6],frame[i+7]);
	    
	      unsigned long long manifest_version=0;
	      for(j=0;j<7;j++) manifest_version=(manifest_version<<8)|frame[i+8+j];
	      fprintf(f,"%smanifest revision = %lld (0x%llx)\n",
		      indent(12),manifest_version,manifest_version);
	      fprintf(f,"%smanifest TTL = %d (0x%x)\n",
		      indent(12),frame[i+16],frame[i+16]);
	      unsigned long long file_size=0;
	      for(j=0;j<6;j++) file_size=(file_size<<8)+frame[i+18+j];
	      fprintf(f,"%sassociated file size = %lld (0x%llx) bytesov\n",
		      indent(12),file_size,file_size);
	      double lat0=((frame[i+24]<<8)+frame[i+25])*180/65535-90;
	      double long0=((frame[i+26]<<8)+frame[i+27])*360/65535-180;
	      double lat1=((frame[i+28]<<8)+frame[i+29])*180/65535-90;
	      double long1=((frame[i+30]<<8)+frame[i+31])*360/65535-180;
	      fprintf(f,"%sgeographic extent of relevance (lat,long) = (%.f,%.f) - (%.f,%.f)\n",
		      indent(12),lat0,long0,lat1,long1);
	    }
	  }
	  break;
	case 0x30: /* MDP frame */
	case 0x40: /* voice frame */
	case 0x60: /* please explain (request for expansion of an abbreviated address) */
	case 0x70: /* node announce */
	default:
	  {
	    /* Reserved values */
	    fprintf(f,"%sWARNING: Packet contains reserved/unknown frame type 0x%02x\n",
		    indent(8),frame_type);
	    int i,j;
	    for(i=0;i<frame_len;i+=16) 
	      {
		fprintf(f,"%sframe+%04x :",indent(10),i);
		for(j=0;j<16&&(i+j)<len;j++) fprintf(f," %02x",frame[i+j]);
		for(;j<16;j++) fprintf(f,"   ");
		fprintf(f,"    ");
		for(j=0;j<16&&(i+j)<len;j++) fprintf(f,"%c",frame[i+j]>=' '
						     &&frame[i+j]<0x7c?frame[i+j]:'.');
		fprintf(f,"\n");
	      }
	  }
	  break;
	}
      }	
      
    nextframe:
      if (next_frame_ofs<0) {
	fprintf(f,"%sERROR: Cannot continue decoding payload due to previous error(s)\n",indent(6));
	return 1;
      }
      if (dumpRaw) {
	int i,j;
	 for(i=0;i<next_frame_ofs;i+=16) 
	   if (i+15>=(*ofs))
	     {
	       fprintf(f,"%s%04x :",indent(10),i);
	       for(j=0;j<16&&(i+j)<next_frame_ofs;j++) if ((i+j)<(*ofs)) fprintf(f,"   "); else fprintf(f," %02x",packet[i+j]);
	       for(;j<16;j++) fprintf(f,"   ");
	       fprintf(f,"    ");
	       for(j=0;j<16&&(i+j)<next_frame_ofs;j++) if ((i+j)<(*ofs)) fprintf(f," "); else fprintf(f,"%c",packet[i+j]>=' '
											&&packet[i+j]<0x7c?packet[i+j]:'.');
	       fprintf(f,"\n");
	     }
      }
      (*ofs)=next_frame_ofs;
      continue;
    }
      
  return 1;
}

int isDNAPacket(FILE *f,unsigned char *packet,int *ofs,int len)
{
  return 0;
}


int serval_packetvisualise(FILE *f,char *message,unsigned char *packet,int len)
{
  if (message) fprintf(f,"%s:\n",message);

  int i,j;
  fprintf(f,"  Packet body of %d (0x%x) bytes:\n",len,len);
  for(i=0;i<len;i+=16) 
    {
      fprintf(f,"    %04x :",i);
      for(j=0;j<16&&(i+j)<len;j++) fprintf(f," %02x",packet[i+j]);
      for(;j<16;j++) fprintf(f,"   ");
      fprintf(f,"    ");
      for(j=0;j<16&&(i+j)<len;j++) fprintf(f,"%c",packet[i+j]>=' '
					   &&packet[i+j]<0x7c?packet[i+j]:'.');
      fprintf(f,"\n");
    }

  int ofs=0;
  fprintf(f,"  Packet Structure:\n");

  if (isOverlayPacket(f,packet,&ofs,len))
    { }
  else if (isDNAPacket(f,packet,&ofs,len))
    { }
  else {
    /* Unknown packet type. */
  }

  if (ofs<len) {
    fprintf(stderr,"  WARNING: The last %d (0x%x) bytes of the packet were not parsed.\n",len-ofs,len-ofs);
  for(i=0;i<len;i+=16) 
    if (i+15>=ofs)
    {
      fprintf(f,"    %04x :",i);
      for(j=0;j<16&&(i+j)<len;j++) if ((i+j)<ofs) fprintf(f,"   "); else fprintf(f," %02x",packet[i+j]);
      for(;j<16;j++) fprintf(f,"   ");
      fprintf(f,"    ");
      for(j=0;j<16&&(i+j)<len;j++) if ((i+j)<ofs) fprintf(f," "); else fprintf(f,"%c",packet[i+j]>=' '
					   &&packet[i+j]<0x7c?packet[i+j]:'.');
      fprintf(f,"\n");
    }
    
  }

  return 0;
}
