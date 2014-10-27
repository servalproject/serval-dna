// -*- Mode: C; c-basic-offset: 2; -*-
//
// Copyright (c) 2012 Andrew Tridgell, All Rights Reserved
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
//  o Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//  o Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
// OF THE POSSIBILITY OF SUCH DAMAGE.
//

/*
Portions Copyright (C) 2013 Paul Gardner-Stephen
 
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
#include "overlay_buffer.h"
#include "overlay_interface.h"
#include "golay.h"
#include "radio_link.h"
#include "radio_link_rfd900.h"

#define RFD900_MAVLINK_MSG_ID_RADIO 166
#define RFD900_MAVLINK_MSG_ID_DATASTREAM 67

// use '3D' for 3DRadio
#define RFD900_RADIO_SOURCE_SYSTEM '3'
#define RFD900_RADIO_SOURCE_COMPONENT 'D'

/*
  we use a hand-crafted MAVLink packet based on the following
  message definition

struct mavlink_RADIO_v10 {
  uint16_t rxerrors;  // receive errors
  uint16_t fixed;     // count of error corrected packets
  uint8_t rssi;       // local signal strength
  uint8_t remrssi;    // remote signal strength
  uint8_t txbuf;      // percentage free space in transmit buffer
  uint8_t noise;      // background noise level
  uint8_t remnoise;   // remote background noise level
};

*/

#define RFD900_FEC_LENGTH 32
#define RFD900_FEC_MAX_BYTES 223
#define RFD900_RADIO_HEADER_LENGTH 6
#define RFD900_RADIO_USED_HEADER_LENGTH 4
#define RFD900_RADIO_CRC_LENGTH 2

#define RFD900_LINK_PAYLOAD_MTU (RFD900_LINK_MTU - RFD900_FEC_LENGTH - RFD900_RADIO_HEADER_LENGTH - RFD900_RADIO_CRC_LENGTH)

/*
  Each mavlink frame consists of 0xfe followed by a standard 6 byte header.
  Normally the payload plus a 2-byte CRC follows.
  We are replacing the CRC check with a Reed-Solomon code to correct as well
  as detect upto 16 bytes with errors, in return for a 32-byte overhead.

  The nature of the particular library we are using is that the overhead is
  basically fixed, but we can shorten the data section.

  Note that the mavlink headers are not protected against errors.  This is a
  limitation of the radio firmware at present. One day we will re-write the
  radio firmware so that we can send and receive raw radio frames, and get
  rid of the mavlink framing altogether, and just send R-S protected payloads.

  Not ideal, but will be fine for now.
*/

#include "fec-3.0.1/fixed.h"
void encode_rs_8(data_t *data, data_t *parity,int pad);
int decode_rs_8(data_t *data, int *eras_pos, int no_eras, int pad);

int radio_link_rfd900_free(struct overlay_interface *interface)
{
  if (interface->radio_link_state){
    free(interface->radio_link_state);
    interface->radio_link_state=NULL;
  }
  return 0;
}

int radio_link_rfd900_init(struct overlay_interface *interface)
{
  interface->radio_link_state = emalloc_zero(sizeof(struct radio_link_state));
  return 0;
}

void radio_link_rfd900_state_html(struct strbuf *b, struct overlay_interface *interface)
{
  struct radio_link_state *state = interface->radio_link_state;
  strbuf_sprintf(b, "RSSI: %ddB<br>", state->radio_rssi);
  strbuf_sprintf(b, "Remote RSSI: %ddB<br>", state->remote_rssi);
}

// write a new link layer packet to interface->txbuffer
// consuming more bytes from the next interface->tx_packet if required
static int radio_link_rfd900_encode_packet(struct radio_link_state *link_state)
{
  // if we have nothing interesting left to send, don't create a packet at all
  if (!link_state->tx_packet)
    return 0;

  int count = ob_remaining(link_state->tx_packet);
  int startP = (ob_position(link_state->tx_packet) == 0);
  int endP = 1;
  if (count > RFD900_LINK_PAYLOAD_MTU){
    count = RFD900_LINK_PAYLOAD_MTU;
    endP = 0;
  }

  link_state->txbuffer[0]=0xfe; // mavlink v1.0 magic header

  // we need to add FEC_LENGTH for FEC, but the length field doesn't include the expected headers or CRC
  int len = count + RFD900_FEC_LENGTH - RFD900_RADIO_CRC_LENGTH;
  link_state->txbuffer[1]=len; // mavlink payload length
  link_state->txbuffer[2]=(len & 0xF);
  link_state->txbuffer[3]=0;

  // add golay encoding so that decoding the actual length is more reliable
  golay_encode(&link_state->txbuffer[1]);


  link_state->txbuffer[4]=(link_state->tx_seq++) & 0x3f;
  if (startP) link_state->txbuffer[4]|=0x40;
  if (endP) link_state->txbuffer[4]|=0x80;
  link_state->txbuffer[5]=RFD900_MAVLINK_MSG_ID_DATASTREAM;

  ob_get_bytes(link_state->tx_packet, &link_state->txbuffer[6], count);

  encode_rs_8(&link_state->txbuffer[4], &link_state->txbuffer[6+count], RFD900_FEC_MAX_BYTES - (count+2));
  link_state->tx_bytes=len + RFD900_RADIO_CRC_LENGTH + RFD900_RADIO_HEADER_LENGTH;
  if (endP){
    ob_free(link_state->tx_packet);
    link_state->tx_packet=NULL;
    overlay_queue_schedule_next(gettime_ms());
  }
  return 0;
}

int radio_link_rfd900_is_busy(struct overlay_interface *interface)
{
  if (interface->radio_link_state && interface->radio_link_state->tx_packet)
    return 1;
  return 0;
}

int radio_link_rfd900_queue_packet(struct overlay_interface *interface, struct overlay_buffer *buffer)
{
  struct radio_link_state *link_state = interface->radio_link_state;

  if (link_state->tx_packet){
    ob_free(buffer);
    return WHYF("Cannot send two packets to a stream at the same time");
  }

  // prepare the buffer for reading
  ob_flip(buffer);
  link_state->tx_packet = buffer;
  radio_link_rfd900_tx(interface);

  return 0;
}

static int build_heartbeat(struct radio_link_state *link_state)
{
  int count=9;
  bzero(link_state->txbuffer, count + RFD900_RADIO_CRC_LENGTH + RFD900_RADIO_HEADER_LENGTH);

  link_state->txbuffer[0]=0xfe; // mavlink v1.0 link_state->txbuffer
  // Must be 9 to indicate heartbeat
  link_state->txbuffer[1]=count; // payload len, excluding 6 byte header and 2 byte CRC
  link_state->txbuffer[2]=(count & 0xF); // packet sequence
  link_state->txbuffer[3]=0x00; // system ID of sender (MAV_TYPE_GENERIC)
  // we're golay encoding the length to improve the probability of skipping it correctly
  golay_encode(&link_state->txbuffer[1]);
  link_state->txbuffer[4]=0xf1; // component ID of sender (MAV_COMP_ID_UART_BRIDGE)
  // Must be zero to indicate heartbeat
  link_state->txbuffer[5]=0; // message ID type of this link_state->txbuffer: DATA_STREAM

  // extra magic number to help correctly detect remote heartbeat requests
  link_state->txbuffer[14]=0x55;
  link_state->txbuffer[15]=0x05;
  golay_encode(&link_state->txbuffer[14]);
  link_state->tx_bytes = count + RFD900_RADIO_CRC_LENGTH + RFD900_RADIO_HEADER_LENGTH;
  if (config.debug.radio_link)
    DEBUGF("Produced heartbeat");

  return 0;
}

// write a new link layer packet to interface->txbuffer
// consuming more bytes from the next interface->tx_packet if required
int radio_link_rfd900_tx(struct overlay_interface *interface)
{
  struct radio_link_state *link_state = interface->radio_link_state;

  unschedule(&interface->alarm);
  interface->alarm.alarm = 0;
  time_ms_t next_tick = interface->destination->last_tx+interface->destination->tick_ms;
  time_ms_t now = gettime_ms();

  while(1){

    if (link_state->tx_bytes){
      if (link_state->next_tx_allowed > now){
	interface->alarm.alarm = link_state->next_tx_allowed;
	break;
      }

      int written=write(interface->alarm.poll.fd, &link_state->txbuffer[link_state->tx_pos], link_state->tx_bytes);
      if (written<=0){
	interface->alarm.poll.events|=POLLOUT;
	break;
      }
      link_state->remaining_space-=written;
      link_state->tx_bytes-=written;
      if (link_state->tx_bytes)
	link_state->tx_pos+=written;
      else
	link_state->tx_pos=0;
      continue;
    }

    interface->alarm.poll.events&=~POLLOUT;

    if (link_state->next_heartbeat<=now){
      build_heartbeat(link_state);
      link_state->next_heartbeat = now + 1000;
      continue;
    }

    // out of space? Don't bother to send anything interesting
    // until we hear the next heartbeat response
    if (link_state->remaining_space < RFD900_LINK_MTU + RFD900_HEARTBEAT_SIZE){
      interface->alarm.alarm = link_state->next_heartbeat;
      break;
    }

    if (link_state->remaining_space < RFD900_LINK_MTU + RFD900_HEARTBEAT_SIZE)
      link_state->next_heartbeat = now;

    if (!link_state->tx_packet){
      // finished current packet, wait for more.
      interface->alarm.alarm = next_tick;
      break;
    }

    // encode another packet fragment
    radio_link_rfd900_encode_packet(link_state);
    link_state->last_packet = now;
  }

  watch(&interface->alarm);
  if (interface->alarm.alarm<now)
    interface->alarm.alarm=now;
  if (interface->alarm.alarm){
    interface->alarm.deadline = interface->alarm.alarm+100;
    schedule(&interface->alarm);
  }

  return 0;
}

static int parse_heartbeat(struct radio_link_state *state, const unsigned char *payload)
{
  if (payload[0]==0xFE
    && payload[1]==9
    && payload[3]==RFD900_RADIO_SOURCE_SYSTEM
    && payload[4]==RFD900_RADIO_SOURCE_COMPONENT
    && payload[5]==RFD900_MAVLINK_MSG_ID_RADIO){

    // we can assume that radio status packets arrive without corruption
    state->radio_rssi=(1.0*payload[10]-payload[13])/1.9;
    state->remote_rssi=(1.0*payload[11] - payload[14])/1.9;
    int free_space = payload[12];
    int free_bytes = (free_space * 1280) / 100 - 30;
    state->remaining_space = free_bytes;
    if (free_bytes>0)
      state->next_tx_allowed = gettime_ms();
    if (free_bytes>720)
      state->next_heartbeat=gettime_ms()+1000;
    if (config.debug.packetradio)
      INFOF("Link budget = %+ddB, remote link budget = %+ddB, buffer space = %d%% (approx %d)",
	    state->radio_rssi,
	    state->remote_rssi,
	    free_space, free_bytes);
    return 1;
  }
  return 0;
}

static int radio_link_rfd900_parse(struct overlay_interface *interface, struct radio_link_state *state,
  size_t packet_length, uint8_t *payload, int *backtrack)
{
  *backtrack=0;
  if (packet_length==17){
    // if we've heard the start and end of a remote heartbeat request
    // we can skip it without checking anything else
    int errs=0;
    int tail = golay_decode(&errs, &payload[14]);
    if (tail == 0x555){
      if (config.debug.radio_link)
	DEBUGF("Decoded remote heartbeat request");
      return 1;
    }
    return 0;
  }

  size_t data_bytes = packet_length - (RFD900_RADIO_USED_HEADER_LENGTH + RFD900_FEC_LENGTH);

  int errors=decode_rs_8(&payload[4], NULL, 0, RFD900_FEC_MAX_BYTES - data_bytes);
  if (errors==-1){
    if (config.debug.radio_link)
      DEBUGF("Reed-Solomon error correction failed");
    return 0;
  }
  *backtrack=errors;
  data_bytes -= 2;
  int seq=payload[4]&0x3f;

  if (config.debug.radio_link){
    DEBUGF("Received RS protected message, len: %zd, errors: %d, seq: %d, flags:%s%s",
      data_bytes,
      errors,
      seq,
      payload[4]&0x40?" start":"",
      payload[4]&0x80?" end":"");
  }

  if (seq != ((state->seq+1)&0x3f)){
    // reject partial packet if we missed a sequence number
    if (config.debug.radio_link)
      DEBUGF("Rejecting packet, sequence jumped from %d to %d", state->seq, seq);
    state->packet_length=sizeof(state->dst)+1;
  }

  if (payload[4]&0x40){
    // start a new packet
    state->packet_length=0;
  }

  state->seq=payload[4]&0x3f;
  if (state->packet_length + data_bytes > sizeof(state->dst)){
    if (config.debug.radio_link)
      DEBUG("Fragmented packet is too long or a previous piece was missed - discarding");
    state->packet_length=sizeof(state->dst)+1;
    return 1;
  }

  bcopy(&payload[RFD900_RADIO_HEADER_LENGTH], &state->dst[state->packet_length], data_bytes);
  state->packet_length+=data_bytes;

  if (payload[4]&0x80) {
    if (config.debug.radio_link)
      DEBUGF("PDU Complete (length=%zd)",state->packet_length);

    packetOkOverlay(interface, state->dst, state->packet_length, NULL);
    state->packet_length=sizeof(state->dst)+1;
  }
  return 1;
}

static int decode_length(struct radio_link_state *state, unsigned char *p)
{
  // look for a valid golay encoded length
  int errs=0;
  int gd = golay_decode(&errs, p);
  if (gd<0 || ((gd >>8) & 0xF) != (gd&0xF))
    return -1;
  size_t length = gd&0xFF;
  length += RFD900_RADIO_HEADER_LENGTH + RFD900_RADIO_CRC_LENGTH;

  if (length!=17 && (length <= RFD900_FEC_LENGTH || length > RFD900_LINK_MTU))
    return -1;

  if (config.debug.radio_link && (errs || state->payload_length!=*p))
    DEBUGF("Decoded length %u to %zu with %d errs", *p, length, errs);

  state->payload_length=length;
  return 0;
}

// add one byte at a time from the serial link, and attempt to decode packets
int radio_link_rfd900_decode(struct overlay_interface *interface, uint8_t c)
{
  IN();
  struct radio_link_state *state=interface->radio_link_state;

  if (state->payload_start + state->payload_offset >= sizeof state->payload){
    // drop one byte if we run out of space
    if (config.debug.radio_link)
      DEBUGF("Dropped %02x, buffer full", state->payload[0]);
    bcopy(state->payload+1, state->payload, sizeof(state->payload) -1);
    state->payload_start--;
  }

  unsigned char *p = &state->payload[state->payload_start];
  p[state->payload_offset++]=c;

  while(1){
    // look for packet length headers
    p = &state->payload[state->payload_start];
    while(state->payload_length==0 && state->payload_offset>=6){
      if (p[0]==0xFE
	&& p[1]==9
	&& p[3]==RFD900_RADIO_SOURCE_SYSTEM
	&& p[4]==RFD900_RADIO_SOURCE_COMPONENT
	&& p[5]==RFD900_MAVLINK_MSG_ID_RADIO){
	//looks like a valid heartbeat response header, read the rest and process it
	state->payload_length=17;
	break;
      }

      if (decode_length(state, &p[1])==0)
	break;

      state->payload_start++;
      state->payload_offset--;
      p++;
    }

    // wait for a whole packet
    if (!state->payload_length || state->payload_offset < state->payload_length)
      RETURN(0);

    if (parse_heartbeat(state, p)){
      // cut the bytes of the heartbeat out of the buffer
      state->payload_offset -= state->payload_length;
      if (state->payload_offset){
	// shuffle bytes backwards
	bcopy(&p[state->payload_length], p, state->payload_offset);
      }
      // restart parsing for a valid header from the beginning of out buffer
      state->payload_offset+=state->payload_start;
      state->payload_start=0;
      state->payload_length=0;
      continue;
    }

    // is this a well formed packet?
    int backtrack=0;
    if (radio_link_rfd900_parse(interface, state, state->payload_length, p, &backtrack)==1){
      // Since we know we've synced with the remote party,
      // and there's nothing we can do about any earlier data
      // throw away everything before the end of this packet
      if (state->payload_start && config.debug.radio_link)
	dump("Skipped", state->payload, state->payload_start);

      // If the packet is truncated by less than 16 bytes, RS protection should be enough to recover the packet,
      // but we may need to examine the last few bytes to find the start of the next packet.
      state->payload_offset -= state->payload_length - backtrack;
      if (state->payload_offset){
	// shuffle all remaining bytes back to the start of the buffer
	bcopy(&state->payload[state->payload_start + state->payload_length - backtrack],
	  state->payload, state->payload_offset);
      }
      state->payload_start=0;
    }else{
      // ignore the first byte for now and start looking for another packet header
      // we may find a heartbeat in the middle that we need to cut out first
      state->payload_start++;
      state->payload_offset--;
    }
    state->payload_length=0;
  };
  RETURN(0);
}
