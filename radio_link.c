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
#include "golay.h"
#include "radio_link.h"
#include "network_coding.h"

#define MAVLINK_MSG_ID_RADIO 166
#define MAVLINK_MSG_ID_DATASTREAM 67

// use '3D' for 3DRadio
#define RADIO_SOURCE_SYSTEM '3'
#define RADIO_SOURCE_COMPONENT 'D'

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

#define PAYLOAD_FRAGMENT 0xFF
#define FEC_LENGTH 32
#define FEC_MAX_BYTES 223
#define RADIO_HEADER_LENGTH 6
#define RADIO_ACTUAL_HEADER_LENGTH 4
#define RADIO_CRC_LENGTH 2

#define LINK_NC_MTU (LINK_MTU - FEC_LENGTH - RADIO_ACTUAL_HEADER_LENGTH)
#define LINK_PAYLOAD_MTU (LINK_NC_MTU - NC_HEADER_LEN)

#define SERIAL_BUFFER 960

struct radio_link_state{
  struct nc *network_coding;
  
  // small buffer for parsing incoming bytes from the serial interface, 
  // looking for recoverable link layer packets
  // should be large enough to hold at least one packet from the remote end
  // plus one heartbeat packet from the local firmware
  uint8_t payload[LINK_MTU*3];
  
  // decoded length of next link layer packet
  // including all header and footer bytes
  int payload_length;
  // offset within payload that we have found a valid looking header
  int payload_start;
  // offset after payload_start for incoming bytes
  int payload_offset;
  
  // small buffer for assembling mdp payloads.
  uint8_t dst[MDP_MTU];
  // length of recovered packet
  int packet_length;
  
  // next firmware heartbeat
  time_ms_t next_heartbeat;
  
  time_ms_t last_tx_packet;
  time_ms_t last_rx_packet;
  time_ms_t last_decoded_packet;
  
  // parsed rssi
  int radio_rssi;
  int remote_rssi;
  // estimated firmware buffer space
  int32_t remaining_space;
  
  // next serial write
  uint64_t next_tx_allowed;
  // partially sent packet
  struct overlay_buffer *tx_packet;
  
  // serial write buffer
  uint8_t txbuffer[LINK_MTU];
  int tx_bytes;
  int tx_pos;
};

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

int radio_link_free(struct overlay_interface *interface)
{
  if (interface->radio_link_state){
    nc_free(interface->radio_link_state->network_coding);
    free(interface->radio_link_state);
    interface->radio_link_state=NULL;
  }
  return 0;
}

int radio_link_init(struct overlay_interface *interface)
{
  interface->radio_link_state = emalloc_zero(sizeof(struct radio_link_state));
  interface->radio_link_state->network_coding = nc_new(8, LINK_PAYLOAD_MTU);
  return 0;
}

void radio_link_state_html(struct strbuf *b, struct overlay_interface *interface)
{
  struct radio_link_state *state = interface->radio_link_state;
  strbuf_sprintf(b, "RSSI: %ddB<br>", state->radio_rssi);
  strbuf_sprintf(b, "Remote RSSI: %ddB<br>", state->remote_rssi);
  nc_state_html(b, state->network_coding);
}

static int encode_next_packet(struct radio_link_state *link_state)
{
  while (link_state->tx_packet && nc_tx_has_room(link_state->network_coding)){
    // queue one packet
    uint8_t next_packet[LINK_PAYLOAD_MTU];
    bzero(next_packet, sizeof(next_packet));
    ob_checkpoint(link_state->tx_packet);
    
    int count = ob_remaining(link_state->tx_packet);
    if (count > LINK_PAYLOAD_MTU -1){
      count = LINK_PAYLOAD_MTU -1;
      next_packet[0]=PAYLOAD_FRAGMENT;
    }else
      next_packet[0]=count;
    
    ob_get_bytes(link_state->tx_packet, &next_packet[1], count);
    if (nc_tx_enqueue_datagram(link_state->network_coding, next_packet, LINK_PAYLOAD_MTU)==0){
      if (config.debug.radio_link)
	DEBUGF("Enqueued fragment len %d of %d", count+1, ob_limit(link_state->tx_packet));
    }else{
      ob_rewind(link_state->tx_packet);
      break;
    }
    if (!ob_remaining(link_state->tx_packet)){
      ob_free(link_state->tx_packet);
      link_state->tx_packet=NULL;
      overlay_queue_schedule_next(gettime_ms());
    }
  }
  return 0;
}

int radio_link_is_busy(struct overlay_interface *interface)
{
  if (interface->radio_link_state && interface->radio_link_state->tx_packet)
    return 1;
  return 0;
}

int radio_link_queue_packet(struct overlay_interface *interface, struct overlay_buffer *buffer)
{
  struct radio_link_state *link_state = interface->radio_link_state;
  
  if (link_state->tx_packet){
    ob_free(buffer);
    return WHYF("Cannot send two packets to a stream at the same time");
  }

  // prepare the buffer for reading
  ob_flip(buffer);
  link_state->tx_packet = buffer;
  radio_link_tx(interface);
  
  return 0;
}

static int send_link_packet(struct overlay_interface *interface)
{
  struct radio_link_state *link_state = interface->radio_link_state;
  
  int data_length = nc_tx_produce_packet(link_state->network_coding, 
    &link_state->txbuffer[RADIO_ACTUAL_HEADER_LENGTH], LINK_NC_MTU);
  
  // if we have nothing interesting to send, don't create a packet at all
  if (data_length <=0)
    return 0;
  
  link_state->txbuffer[0]=0xfe; // mavlink v1.0 magic header
  
  // the current firmware assumes that the whole packet contains 6 bytes of header and 2 bytes of crc
  // that are not counted in the length.
  int whole_packet = data_length + FEC_LENGTH + RADIO_ACTUAL_HEADER_LENGTH;
  int radio_length = whole_packet - RADIO_HEADER_LENGTH - RADIO_CRC_LENGTH;
  link_state->txbuffer[1]=radio_length; // mavlink payload length
  link_state->txbuffer[2]=(radio_length & 0xF);
  link_state->txbuffer[3]=0;
  
  // add golay encoding so that decoding the actual length is more reliable
  golay_encode(&link_state->txbuffer[1]);
  
  encode_rs_8(&link_state->txbuffer[RADIO_ACTUAL_HEADER_LENGTH], 
    &link_state->txbuffer[RADIO_ACTUAL_HEADER_LENGTH + data_length], 
    FEC_MAX_BYTES - data_length);
  
  link_state->tx_bytes=whole_packet;
  if (config.debug.radio_link)
    DEBUGF("Produced packet len %d", whole_packet);
  
  return 0;
}

static int build_heartbeat(struct radio_link_state *link_state)
{
  int count=9;
  bzero(link_state->txbuffer, count + RADIO_CRC_LENGTH + RADIO_HEADER_LENGTH);
  
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
  link_state->tx_bytes = count + RADIO_CRC_LENGTH + RADIO_HEADER_LENGTH;
  if (config.debug.radio_link)
    DEBUGF("Produced heartbeat");
  
  return 0;
}

// write a new link layer packet to interface->txbuffer
// consuming more bytes from the next interface->tx_packet if required
int radio_link_tx(struct overlay_interface *interface)
{
  struct radio_link_state *link_state = interface->radio_link_state;
  
  unschedule(&interface->alarm);
  interface->alarm.alarm = 0;
  time_ms_t next_tick = interface->destination->last_tx+interface->destination->tick_ms;
  time_ms_t now = gettime_ms();
  interface->alarm.poll.events&=~POLLOUT;
  
  while(1){
    
    // encode more data if we have a packet waiting, and have space
    encode_next_packet(link_state);
    
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
      link_state->tx_bytes-=written;
      if (link_state->tx_bytes)
	link_state->tx_pos+=written;
      else
	link_state->tx_pos=0;
      continue;
    }
  
    if (link_state->next_heartbeat<=now){
      build_heartbeat(link_state);
      link_state->remaining_space -= link_state->tx_bytes;
      if (link_state->remaining_space < LINK_MTU + HEARTBEAT_SIZE)
	link_state->next_heartbeat = now + 600;
      else
	link_state->next_heartbeat = now + 5000;
      continue;
    }
    
    // out of space? Don't bother to send anything interesting 
    // until we hear the next heartbeat response
    if (link_state->remaining_space < LINK_MTU + HEARTBEAT_SIZE){
      interface->alarm.alarm = link_state->next_heartbeat;
      break;
    }
    
    int urgency = nc_tx_packet_urgency(link_state->network_coding);
    time_ms_t delay = 400;
    switch (urgency){
      case URGENCY_ASAP:
	delay=5;
	break;
      case URGENCY_ACK_SOON:
	delay=50;
	break;
      case URGENCY_SOON:
	delay=100;
	break;
    }
    
    if (link_state->last_tx_packet + delay > now){
      interface->alarm.alarm = link_state->last_tx_packet + delay;
      if (interface->alarm.alarm > next_tick && next_tick > now){
	interface->alarm.alarm = next_tick;
      }
      break;
    }
    
    send_link_packet(interface);
    link_state->remaining_space -= link_state->tx_bytes;
    link_state->last_tx_packet = now;
    
    if (link_state->remaining_space < LINK_MTU + HEARTBEAT_SIZE)
      link_state->next_heartbeat = now;
    else if(link_state->next_heartbeat > now + 600)
      link_state->next_heartbeat = now + 600;
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
    && payload[3]==RADIO_SOURCE_SYSTEM
    && payload[4]==RADIO_SOURCE_COMPONENT
    && payload[5]==MAVLINK_MSG_ID_RADIO){
    
    // we can assume that radio status packets arrive without corruption
    state->radio_rssi=(1.0*payload[10]-payload[13])/1.9;
    state->remote_rssi=(1.0*payload[11] - payload[14])/1.9;
    int free_space = payload[12];
    int free_bytes = (free_space * SERIAL_BUFFER) / 100 - 30;
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

static int radio_link_parse(struct overlay_interface *interface, struct radio_link_state *state, 
  int packet_length, unsigned char *payload, int *backtrack)
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
      state->last_rx_packet=gettime_ms();
      return 1;
    }
    return 0;
  }
  
  payload += RADIO_ACTUAL_HEADER_LENGTH;
  packet_length -= RADIO_ACTUAL_HEADER_LENGTH + FEC_LENGTH;
  
  int errors=decode_rs_8(payload, NULL, 0, FEC_MAX_BYTES - packet_length);
  if (errors==-1){
    if (config.debug.radio_link)
      DEBUGF("Reed-Solomon error correction failed");
    return 0;
  }
  *backtrack=errors;
  
  state->last_rx_packet=gettime_ms();
  int rx = nc_rx_packet(state->network_coding, payload, packet_length);
  if (config.debug.radio_link)
    DEBUGF("RX returned %d", rx);
  
  if (rx==0){
    // we received an interesting packet, can we deliver anything?
    uint8_t fragment[LINK_PAYLOAD_MTU];
    while(1){
      int len=nc_rx_next_delivered(state->network_coding, fragment, sizeof(fragment));
      if (len<=0)
	break;
      state->last_decoded_packet = gettime_ms();
      int fragment_len=fragment[0];
      if (fragment_len == PAYLOAD_FRAGMENT)
	fragment_len = len -1;
	
      // is this fragment length invalid?
      if (fragment_len > len -1)
	state->packet_length=sizeof(state->dst);
      
      // can we fit this fragment into our payload buffer?
      if (fragment_len+state->packet_length < sizeof(state->dst)){
	bcopy(&fragment[1], &state->dst[state->packet_length], fragment_len);
	state->packet_length+=fragment_len;
	
	// is this the last fragment?
	if (fragment[0] != PAYLOAD_FRAGMENT){
	  if (config.debug.radio_link)
	    DEBUGF("PDU Complete (length=%d)",state->packet_length);
	  
	  if (packetOkOverlay(interface, state->dst, state->packet_length, -1, NULL, 0)){
	    dump("Invalid packet?", state->dst, state->packet_length);
	  }
	}
      }else{
	state->packet_length=sizeof(state->dst);
      }
      
      // reset the buffer for the next packet
      if (fragment[0] != PAYLOAD_FRAGMENT)
	state->packet_length=0;
    }
  }
  
  return 1;
}

static int decode_length(struct radio_link_state *state, unsigned char *p)
{
  // look for a valid golay encoded length
  int errs=0;
  int length = golay_decode(&errs, p);
  if (length<0 || ((length >>8) & 0xF) != (length&0xF))
    return -1;
  length=length&0xFF;
  length += RADIO_HEADER_LENGTH + RADIO_CRC_LENGTH;
  
  if (length!=17 && (length <= FEC_LENGTH || length > LINK_MTU))
    return -1;
  
  if (config.debug.radio_link && (errs || state->payload_length!=*p))
    DEBUGF("Decoded length %d to %d with %d errs", *p, length, errs);
  
  state->payload_length=length;
  return 0;
}

// add one byte at a time from the serial link, and attempt to decode packets
int radio_link_decode(struct overlay_interface *interface, uint8_t *buffer, ssize_t len)
{
  IN();
  struct radio_link_state *state=interface->radio_link_state;
  int i;
  for (i=0;i<len;i++){
    uint8_t c = buffer[i];
    
    if (state->payload_start + state->payload_offset >= sizeof(state->payload)){
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
	  && p[3]==RADIO_SOURCE_SYSTEM
	  && p[4]==RADIO_SOURCE_COMPONENT
	  && p[5]==MAVLINK_MSG_ID_RADIO){
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
	break;
      
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
      if (radio_link_parse(interface, state, state->payload_length, p, &backtrack)==1){
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
  }
  RETURN(0);
}
