#include "serval.h"
#include "conf.h"

int slip_encode(int format,
		unsigned char *src, int src_bytes, unsigned char *dst, int dst_len)
{
  switch(format) {
  case SLIP_FORMAT_SLIP:
    return WHYF("SLIP encoding not implemented",format);
    break;
  case SLIP_FORMAT_UPPER7:
    /*
      The purpose of this encoder is to work nicely with the RFD900 radios,
      including allowing the reception of RSSI information in the middle of
      packets.
      RSSI reports look like:
      L/R RSSI: 48/0  L/R noise: 62/0 pkts: 0  txe=0 rxe=0 stx=0 srx=0 ecc=0/0 temp=21 dco=0
      So we are using 0x80-0xff to hold data, and { and } to frame packets.
    */
    if (config.debug.slip) dump("pre-slipped packet",src,src_bytes);
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
      unsigned long crc=Crc32_ComputeBuf( 0, src, src_bytes);
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
    break;
  default:
    return WHYF("Unsupported slip encoding #%d",format);
  }

}

unsigned long long last_rssi_report=0;
int parse_rfd900_rssi(char *s)
{
  int lrssi,rrssi,lnoise,rnoise,temp;

  // L/R RSSI: 48/0  L/R noise: 62/0 pkts: 0  txe=0 rxe=0 stx=0 srx=0 ecc=0/0 temp=21 dco=0
  if (sscanf(s,"L/R RSSI: %d/%d  L/R noise: %d/%d pkts: %*d  txe=%*d rxe=%*d stx=%*d srx=%*d ecc=%*d/%*d temp=%d dco=%*d",
	     &lrssi,&rrssi,&lnoise,&rnoise,&temp)==5)
    {
      int lmargin=(lrssi-lnoise)/1.9;
      int rmargin=(lrssi-lnoise)/1.9;
      int maxmargin=lmargin; if (rmargin>maxmargin) maxmargin=rmargin;

      if (config.debug.packetradio||(gettime_ms()-last_rssi_report>30000)) {
	INFOF("Link budget = %ddB, temperature=%dC",maxmargin,temp);
	last_rssi_report=gettime_ms();
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
int upper7_decode(struct slip_decode_state *state,unsigned char byte)
{
  if (0&&config.debug.slip)
    DEBUGF("state=%d, byte=0x%02x",state->state,byte);

  // Parse out inline RSSI reports
  if (byte=='{') {
    state->state=UPPER7_STATE_L1; 
    state->packet_length=0;
    return 0;
  } else if (byte=='}') {
    // End of packet marker -- report end of received packet to caller
    // for CRC verification etc.
    state->state=UPPER7_STATE_NOTINPACKET; return 1;
  } else if (byte>=' '&&byte<=0x7f) {
    if (state->rssi_len<RSSI_TEXT_SIZE) 
      state->rssi_text[state->rssi_len++]=byte;
    return 0;
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
    switch (byte) {
    default:
      return 0;
    }    
  }

  // Data bytes and packet fields
  byte&=0x7f;
  switch(state->state) {
  case UPPER7_STATE_NOTINPACKET: return 0;
  case UPPER7_STATE_L1: state->packet_length=byte<<7; state->state++; return 0;
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
    return 0;
  case UPPER7_STATE_C1: state->crc=byte<<25; state->state++; return 0;
  case UPPER7_STATE_C2: state->crc|=byte<<(25-7); state->state++; return 0;
  case UPPER7_STATE_C3: state->crc|=byte<<(25-7-7); state->state++; return 0;
  case UPPER7_STATE_C4: state->crc|=byte<<(25-7-7-7); state->state++; return 0;
  case UPPER7_STATE_C5: state->crc|=byte<<0; state->state++; return 0;
  case UPPER7_STATE_D0:
    // Prevent buffer overruns
    if (state->dst_offset+7>OVERLAY_INTERFACE_RX_BUFFER_SIZE) 
      state=UPPER7_STATE_NOTINPACKET;
    state->dst[state->dst_offset]=byte<<1;   
    state->state++;
    return 0;
  case UPPER7_STATE_D1:
    state->dst[state->dst_offset+0]|=(byte>>6)&0x01;
    state->dst[state->dst_offset+1]=(byte<<2);
    state->state++;
    return 0;
  case UPPER7_STATE_D2:
    state->dst[state->dst_offset+1]|=(byte>>5)&0x03;
    state->dst[state->dst_offset+2]=(byte<<3);
    state->state++;
    return 0;
  case UPPER7_STATE_D3:
    state->dst[state->dst_offset+2]|=(byte>>4)&0x07;
    state->dst[state->dst_offset+3]=(byte<<4);
    state->state++;
    return 0;
  case UPPER7_STATE_D4:
    state->dst[state->dst_offset+3]|=(byte>>3)&0x0f;
    state->dst[state->dst_offset+4]=(byte<<5);
    state->state++;
    return 0;
  case UPPER7_STATE_D5:
    state->dst[state->dst_offset+4]|=(byte>>2)&0x1f;
    state->dst[state->dst_offset+5]=(byte<<6);
    state->state++;
    return 0;
  case UPPER7_STATE_D6:
    state->dst[state->dst_offset+5]|=(byte>>1)&0x3f;
    state->dst[state->dst_offset+6]=(byte<<7);
    state->state++;
    return 0;
  case UPPER7_STATE_D7:
    state->dst[state->dst_offset+6]|=(byte>>0)&0x7f;
    state->dst_offset+=7;
    state->state=UPPER7_STATE_D0;
    return 0;
  default:
    state->state=UPPER7_STATE_NOTINPACKET;
    return 0;
  }

}

/* state->src and state->src_size contain the freshly read bytes
   we must accumulate any partial state between calls.
*/
int slip_decode(struct slip_decode_state *state)
{
  switch(state->encapsulator) {
  case SLIP_FORMAT_SLIP:
    return WHYF("SLIP encapsulation not implemented");
  case SLIP_FORMAT_UPPER7:
    {
      if (config.debug.slip) {
	dump("RX bytes",&state->src[state->src_offset],
	     state->src_size-state->src_offset);
	if (state->rssi_len<0) state->rssi_len=0;
	if (state->rssi_len>=RSSI_TEXT_SIZE) state->rssi_len=RSSI_TEXT_SIZE-1;
	state->rssi_text[state->rssi_len]=0;
	DEBUGF("RX state=%d, rssi_len=%d, rssi_text='%s'",
	       state->state,state->rssi_len,state->rssi_text);
      }
      while(state->src_offset<state->src_size) 
	if (upper7_decode(state,state->src[state->src_offset++])==1) {
	  if (config.debug.slip)
	    dump("de-slipped packet",state->dst,state->packet_length);
	 
	  // Check that CRC matches
	  unsigned long crc=Crc32_ComputeBuf( 0, state->dst, state->packet_length);
	  if (crc!=state->crc) {
	    if (config.debug.slip)
	      DEBUGF("Rejected packet of %d bytes due to CRC mis-match (%08x vs %08x)",
		     state->packet_length,crc,state->crc);
	  } else {
	    if (config.debug.slip) 
	      DEBUGF("Accepted packet of %d bytes (CRC ok)",state->packet_length);
	    return state->packet_length;
	  }
	}
    }
    return 0;
  default:
    return WHYF("Unknown SLIP encapsulation format #%d",state->encapsulator);
  }
}
