/*
Serval Distributed Numbering Architecture (DNA)
Copyright (C) 2012 Paul Gardner-Stephen
 
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
#include "conf.h"
#include "log.h"
#include "dataformats.h"

#define DEBUG_packet_visualise(M,P,N) logServalPacket(LOG_LEVEL_DEBUG, __WHENCE__, (M), (P), (N))

/* SLIP-style escape characters used for serial packet radio interfaces */
#define SLIP_END 0xc0
#define SLIP_ESC 0xdb
#define SLIP_0a 0x0a
#define SLIP_0d 0x0d
#define SLIP_0f 0x0f
#define SLIP_1b 0x1b

#define SLIP_ESC_END 0xdc
#define SLIP_ESC_ESC 0xdd
#define SLIP_ESC_0a 0x7a
#define SLIP_ESC_0d 0x7d
#define SLIP_ESC_0f 0x7f
#define SLIP_ESC_1b 0x6b

/* interface decoder state bits */
#define DC_VALID 1
#define DC_ESC 2

static int encode_slip(const unsigned char *src, int src_bytes, unsigned char *dst, int dst_len)
{
  int i, offset=0;
  for (i=0;i<src_bytes;i++){
    
    if (offset+3>dst_len)
      return WHY("Dest buffer full");
    
    switch(src[i]) {
      case SLIP_END:
	dst[offset++]=SLIP_ESC;
	dst[offset++]=SLIP_ESC_END;
	break;
      case SLIP_ESC:
	dst[offset++]=SLIP_ESC;
	dst[offset++]=SLIP_ESC_ESC;
	break;
      case SLIP_0a:
	dst[offset++]=SLIP_ESC;
	dst[offset++]=SLIP_ESC_0a;
	break;
      case SLIP_0d:
	dst[offset++]=SLIP_ESC;
	dst[offset++]=SLIP_ESC_0d;
	break;
      case SLIP_0f:
	dst[offset++]=SLIP_ESC;
	dst[offset++]=SLIP_ESC_0f;
	break;
      case SLIP_1b:
	dst[offset++]=SLIP_ESC;
	dst[offset++]=SLIP_ESC_1b;
	break;
      default:
	dst[offset++]=src[i];
    }
  }
  return offset;
}

int slip_encode(int format,
		const unsigned char *src, int src_bytes, unsigned char *dst, int dst_len)
{
  switch(format) {
  case SLIP_FORMAT_SLIP:
    {
      int offset=0;

      if (offset+2>dst_len)
	return WHY("Dest buffer full");
      
      dst[offset++]=SLIP_END;
      
      int ret=encode_slip(src, src_bytes, dst + offset, dst_len - offset);
      if (ret<0)
	return ret;
      offset+=ret;
      
      unsigned char crc[4];
      write_uint32(crc, Crc32_ComputeBuf( 0, src, src_bytes));
      
      ret=encode_slip(crc, 4, dst + offset, dst_len - offset);
      if (ret<0)
	return ret;
      offset+=ret;
      
      dst[offset++]=SLIP_END;
      
      return offset;
    }
  case SLIP_FORMAT_UPPER7:
    /*
      The purpose of this encoder is to work nicely with the RFD900 radios,
      including allowing the reception of RSSI information in the middle of
      packets.
      RSSI reports look like:
      L/R RSSI: 48/0  L/R noise: 62/0 pkts: 0  txe=0 rxe=0 stx=0 srx=0 ecc=0/0 temp=21 dco=0
      So we are using 0x80-0xff to hold data, and { and } to frame packets.
    */
    if (config.debug.slip)
      dump("pre-slipped packet",src,src_bytes);
    {
      if (src_bytes<1) return 0;
      if (src_bytes>0x3fff) 
	return WHYF("UPPER7 SLIP encoder packets must be <=0x3fff bytes");
      if (dst_len<(9+src_bytes+(src_bytes/7)+1))
	return WHYF("UPPER7 SLIP encoder requires 9+(8/7)*bytes to encode");
      int i,j;
      int out_len=0;

      // Start of packet marker
      dst[out_len++]='{';
      // Length of (unencoded) packet
      dst[out_len++]=0x80+((src_bytes>>7)&0x7f);
      dst[out_len++]=0x80+((src_bytes>>0)&0x7f);
      // Add 32-bit CRC
      // (putting the CRC at the front allows it to be calculated progressively
      // on the receiver side, if we decide to support that)
      uint32_t crc=Crc32_ComputeBuf( 0, src, src_bytes);
      dst[out_len++]=0x80|((crc>>25)&0x7f);
      dst[out_len++]=0x80|((crc>>(25-7))&0x7f);
      dst[out_len++]=0x80|((crc>>(25-7-7))&0x7f);
      dst[out_len++]=0x80|((crc>>(25-7-7-7))&0x7f);
      dst[out_len++]=0x80|((crc>>0)&0x7f);

      for(i=0;i<src_bytes;i+=7)
	{
	  // Create 8 bytes of output consisting of 8x7 bits

	  // Generate vector of 7 bytes to encode
	  unsigned char v[7];
	  for(j=0;j<7&&i+j<src_bytes;j++) v[j]=src[i+j];
	  for(;j<7;j++) v[j]=0;
	  if (out_len+8>dst_len) 
	    return WHYF("Ran out of space in UPPER7 SLIP encoder (used all %d bytes after encoding %d of %d bytes)",
			dst_len,i,src_bytes);
	  // We could use a nice for loop to do this, but for 8 bytes, let's
	  // just do it explicitly.
	  dst[out_len++]=0x80|                 (v[0]>>1);
	  dst[out_len++]=0x80|((v[0]&0x01)<<6)|(v[1]>>2);
	  dst[out_len++]=0x80|((v[1]&0x03)<<5)|(v[2]>>3);
	  dst[out_len++]=0x80|((v[2]&0x07)<<4)|(v[3]>>4);
	  dst[out_len++]=0x80|((v[3]&0x0f)<<3)|(v[4]>>5);
	  dst[out_len++]=0x80|((v[4]&0x1f)<<2)|(v[5]>>6);
	  dst[out_len++]=0x80|((v[5]&0x3f)<<1)|(v[6]>>7);
	  dst[out_len++]=0x80|((v[6]&0x7f)<<0);
	}

      // Mark end of packet
      dst[out_len++]='}';
      // Detect fatal miscalculations on byte counts
      if (out_len>dst_len) {
	FATALF("overran output buffer in SLIP UPPER7 encapsulation of packet (used %d of %d bytes)",out_len,dst_len);
      }
      return out_len;
    }
  default:
    return WHYF("Unsupported slip encoding #%d",format);
  }

}

time_ms_t last_rssi_time=0;
int last_radio_rssi=-999;
int last_radio_temperature=-999;
int last_radio_rxpackets=0;
int parse_rfd900_rssi(char *s)
{
  int lrssi,rrssi,lnoise,rnoise,rxpackets,temp;

  // L/R RSSI: 48/0  L/R noise: 62/0 pkts: 0  txe=0 rxe=0 stx=0 srx=0 ecc=0/0 temp=21 dco=0
  if (sscanf(s,"L/R RSSI: %d/%d  L/R noise: %d/%d pkts: %d  txe=%*d rxe=%*d stx=%*d srx=%*d ecc=%*d/%*d temp=%d dco=%*d",
	     &lrssi,&rrssi,&lnoise,&rnoise,&rxpackets, &temp)==6)
    {
      int lmargin=(lrssi-lnoise)/1.9;
      int rmargin=(rrssi-rnoise)/1.9;
      int maxmargin=lmargin; if (rmargin>maxmargin) maxmargin=rmargin;
      last_radio_rssi=maxmargin;
      last_radio_temperature=temp;
      last_radio_rxpackets=rxpackets;

      if (gettime_ms()-last_rssi_time>30000) {
	INFOF("Link budget = %+ddB, temperature=%dC",maxmargin,temp);
	last_rssi_time=gettime_ms();
      }
    }

  return 0;
}

#define UPPER7_STATE_NOTINPACKET 0
#define UPPER7_STATE_L1 1
#define UPPER7_STATE_L2 2
#define UPPER7_STATE_C1 3
#define UPPER7_STATE_C2 4
#define UPPER7_STATE_C3 5
#define UPPER7_STATE_C4 6
#define UPPER7_STATE_C5 7
#define UPPER7_STATE_D0 8
#define UPPER7_STATE_D1 9
#define UPPER7_STATE_D2 10
#define UPPER7_STATE_D3 11
#define UPPER7_STATE_D4 12
#define UPPER7_STATE_D5 13
#define UPPER7_STATE_D6 14
#define UPPER7_STATE_D7 15
int u7d_calls=0;
int upper7_decode(struct slip_decode_state *state,unsigned char byte)
{
  IN()
    u7d_calls++;
  if (config.debug.slipdecode)
    snprintf(crash_handler_clue,1024,
	     "upper7_decode() call #%d: state=%d, byte=0x%02x, rssi_len=%d, dst_offset=%d",
	     u7d_calls,state->state,byte,state->rssi_len,state->dst_offset);
  if (config.debug.slipbytestream)
    WHYF("call #%d: state=%d, byte=0x%02x, rssi_len=%d, dst_offset=%d",
	 u7d_calls,state->state,byte,state->rssi_len,state->dst_offset);

  // Parse out inline RSSI reports
  if (byte=='{') {
    state->state=UPPER7_STATE_L1; 
    state->packet_length=0;
    RETURN(0);
  } else if (byte=='}') {
    // End of packet marker -- report end of received packet to caller
    // for CRC verification etc.
    state->state=UPPER7_STATE_NOTINPACKET; RETURN(1);
  } else if (byte>=' '&&byte<=0x7f) {
    if (state->rssi_len<0) state->rssi_len=0;
    if (state->rssi_len<RSSI_TEXT_SIZE) 
      state->rssi_text[state->rssi_len++]=byte;
    RETURN(0);
  } else if (byte=='\r'||byte=='\n') {
    if (state->rssi_len>=RSSI_TEXT_SIZE) state->rssi_len=RSSI_TEXT_SIZE-1;
    if (state->rssi_len<0) state->rssi_len=0;
    state->rssi_text[state->rssi_len]=0;
    parse_rfd900_rssi(state->rssi_text);
    state->rssi_len=0;
  }

  // Non-data bytes (none currently used, but we need to catch them before
  // moving onto processing data bytes)
  if (byte<0x80) {
    RETURN(0);   
  }

  // Data bytes and packet fields
  byte&=0x7f;
  if (state->packet_length>=OVERLAY_INTERFACE_RX_BUFFER_SIZE
      ||(state->dst_offset+7)>=OVERLAY_INTERFACE_RX_BUFFER_SIZE
      ||state->dst_offset<0)
    {
      WARNF("state=%p, state->dst_offset=%d, ->packet_length=%d, ->state=%d. State reset.",
	    state,state->dst_offset,state->packet_length,state->state);
      state->state=UPPER7_STATE_NOTINPACKET;
      state->dst_offset=0;
      state->packet_length=0;
      RETURN(0);
    }
  switch(state->state) {
  case UPPER7_STATE_NOTINPACKET: RETURN(0);
  case UPPER7_STATE_L1: state->packet_length=byte<<7; state->state++; RETURN(0);
  case UPPER7_STATE_L2: state->packet_length|=byte;
    // Make sure packet length can fit in RX buffer, including that we might
    // need upto 7 bytes extra temporary space due to blocking
    if ((state->packet_length+7)<OVERLAY_INTERFACE_RX_BUFFER_SIZE) {
      state->state++; 
      state->dst_offset=0;
    } else {
      if (config.debug.packetradio) 
	DEBUGF("Ignoring jumbo packet of %d bytes",state->packet_length);
      state->state=UPPER7_STATE_NOTINPACKET;
    }
    RETURN(0);
  case UPPER7_STATE_C1: state->crc=byte<<25; state->state++; RETURN(0);
  case UPPER7_STATE_C2: state->crc|=byte<<(25-7); state->state++; RETURN(0);
  case UPPER7_STATE_C3: state->crc|=byte<<(25-7-7); state->state++; RETURN(0);
  case UPPER7_STATE_C4: state->crc|=byte<<(25-7-7-7); state->state++; RETURN(0);
  case UPPER7_STATE_C5: state->crc|=byte<<0; state->state++; RETURN(0);
  case UPPER7_STATE_D0:
    if (state->packet_length>=OVERLAY_INTERFACE_RX_BUFFER_SIZE
	||(state->dst_offset+7)>=OVERLAY_INTERFACE_RX_BUFFER_SIZE
	||state->dst_offset<0)
      {
	WARNF("state->dst_offset=%d, ->packet_length=%d, ->state=%d. State reset (again).",
	      state->dst_offset,state->packet_length,state->state);
	state->state=UPPER7_STATE_NOTINPACKET;
	state->dst_offset=0;
	state->packet_length=0;
	RETURN(0);
      }
    state->dst[state->dst_offset]=byte<<1;   
    state->state++;
    RETURN(0);
  case UPPER7_STATE_D1:
    state->dst[state->dst_offset+0]|=(byte>>6)&0x01;
    state->dst[state->dst_offset+1]=(byte<<2);
    state->state++;
    RETURN(0);
  case UPPER7_STATE_D2:
    state->dst[state->dst_offset+1]|=(byte>>5)&0x03;
    state->dst[state->dst_offset+2]=(byte<<3);
    state->state++;
    RETURN(0);
  case UPPER7_STATE_D3:
    state->dst[state->dst_offset+2]|=(byte>>4)&0x07;
    state->dst[state->dst_offset+3]=(byte<<4);
    state->state++;
    RETURN(0);
  case UPPER7_STATE_D4:
    state->dst[state->dst_offset+3]|=(byte>>3)&0x0f;
    state->dst[state->dst_offset+4]=(byte<<5);
    state->state++;
    RETURN(0);
  case UPPER7_STATE_D5:
    state->dst[state->dst_offset+4]|=(byte>>2)&0x1f;
    state->dst[state->dst_offset+5]=(byte<<6);
    state->state++;
    RETURN(0);
  case UPPER7_STATE_D6:
    state->dst[state->dst_offset+5]|=(byte>>1)&0x3f;
    state->dst[state->dst_offset+6]=(byte<<7);
    state->state++;
    RETURN(0);
  case UPPER7_STATE_D7:
    state->dst[state->dst_offset+6]|=(byte>>0)&0x7f;
    state->dst_offset+=7;
    state->state=UPPER7_STATE_D0;
    RETURN(0);
  default:
    state->state=UPPER7_STATE_NOTINPACKET;
    RETURN(0);
  }
  OUT();
}

/* state->src and state->src_size contain the freshly read bytes
   we must accumulate any partial state between calls.
*/
int slip_decode(struct slip_decode_state *state)
{
  switch(state->encapsulator) {
  case SLIP_FORMAT_SLIP:
    {
      /*
       Examine received bytes for end of packet marker.
       The challenge is that we need to make sure that the packet encapsulation
       is self-synchronising in the event that a data error occurs (including
       failure to receive an arbitrary number of bytes).
       */
      while(state->src_offset < state->src_size){
	// clear the valid bit flag if we hit the end of the destination buffer
	if (state->dst_offset>=sizeof(state->dst))
	  state->state&=~DC_VALID;
	
	if (state->state&DC_ESC){
	  // clear escape bit
	  state->state&=~DC_ESC;
	  switch(state->src[state->src_offset]) {
	    case SLIP_ESC_END: // escaped END byte
	      state->dst[state->dst_offset++]=SLIP_END;
	      break;
	    case SLIP_ESC_ESC: // escaped escape character
	      state->dst[state->dst_offset++]=SLIP_ESC;
	      break;
	    case SLIP_ESC_0a:
	      state->dst[state->dst_offset++]=SLIP_0a;
	      break;
	    case SLIP_ESC_0d:
	      state->dst[state->dst_offset++]=SLIP_0d;
	      break;
	    case SLIP_ESC_0f:
	      state->dst[state->dst_offset++]=SLIP_0f;
	      break;
	    case SLIP_ESC_1b:
	      state->dst[state->dst_offset++]=SLIP_1b;
	      break;
	    default: /* Unknown escape character. This is an error. */
	      if (config.debug.packetradio)
		WARNF("Packet radio stream contained illegal escaped byte 0x%02x -- resetting parser.",state->src[state->src_offset]);
	      state->dst_offset=0;
	      // skip everything until the next SLIP_END
	      state->state=0;
	  }
	}else{
	  // non-escape character
	  switch(state->src[state->src_offset]) {
	    case SLIP_ESC:
	      // set escape bit
	      state->state|=DC_ESC; 
	      break;
	    case SLIP_END:
	      if (state->dst_offset>4){
		
		uint32_t src_crc = read_uint32(state->dst + state->dst_offset -4);
		uint32_t crc=Crc32_ComputeBuf( 0, state->dst, state->dst_offset -4);
		
		if (src_crc != crc){
		  DEBUGF("Dropping frame due to CRC failure (%08x vs %08x)", src_crc, crc);
		  dump("frame", state->dst, state->dst_offset);
		  state->dst_offset=0;
		  state->state=0;
		  break;
		}
		// return once we've successfully parsed a valid packet that isn't empty
		state->packet_length=state->dst_offset -4;
		return 1;
	      }
	      // set the valid flag to begin parsing the next packet
	      state->state=DC_VALID;
	      break;
	    default:
	      if (state->state&DC_VALID)
		state->dst[state->dst_offset++]=state->src[state->src_offset];
	  }
	}
	state->src_offset++;
      }
      return 0;
    }
  case SLIP_FORMAT_UPPER7:
    {
      if (config.debug.slip) {
	if (state->rssi_len<0) state->rssi_len=0;
	if (state->rssi_len>=RSSI_TEXT_SIZE) state->rssi_len=RSSI_TEXT_SIZE-1;
	state->rssi_text[state->rssi_len]=0;
	DEBUGF("RX state=%d, rssi_len=%d, rssi_text='%s',src=%p, src_size=%d",
	       state->state,state->rssi_len,state->rssi_text,
	       state->src,state->src_size);
      }
     while(state->src_offset<state->src_size) {
	if (upper7_decode(state,state->src[state->src_offset++])==1) {
	  if (config.debug.slip) {
	    dump("de-slipped packet",state->dst,state->packet_length);
          }
	 
	  // Check that CRC matches
	  uint32_t crc=Crc32_ComputeBuf( 0, state->dst, state->packet_length);
	  if (crc!=state->crc) {
	    if (config.debug.packetradio||config.debug.rejecteddata)
	      DEBUGF("Rejected packet of %d bytes due to CRC mis-match (%08x vs %08x)",
		     state->packet_length,crc,state->crc);
	    if (config.debug.rejecteddata) {
	      dump("bad packet",state->dst,state->packet_length);
	    }
	  } else {
	    if (config.debug.packetradio) 
	      DEBUGF("Accepted packet of %d bytes (CRC ok)",state->packet_length);
	    return 1;
	  }
	}
      }
    }
    return 0;
  default:
    return WHYF("Unknown SLIP encapsulation format #%d",state->encapsulator);
  }
}
