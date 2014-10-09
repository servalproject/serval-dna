// -*- Mode: C; c-basic-offset: 2; -*-
//
// Copyright (c) 2014 Ulf Mueller-Baumgart, All Rights Reserved
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
#include "radio_link_rfm69.h"

//main states
#define STATE_RECEIVE 0
#define STATE_SEND 1
#define STATE_WAIT_OK 2

//parser states
#define P_STATE_WAITING_FOR_START 0
#define P_STATE_START_FOUND 1
#define P_STATE_RSSI_FOUND 2
#define P_STATE_READING 3

//MDP states
#define MDP_STATE_IDLE 0
#define MDP_STATE_RX 1
#define MDP_STATE_TX 2

#define PACKET_START '{'
#define PACKET_END '}'

//MDP_MTU / RFM69_LINK_MTU = 21
#define MAX_PACKET_BLOCK_COUNT 21

#define suppress_warning(X) if(X){}

int main_state = STATE_RECEIVE;
int parser_state = P_STATE_WAITING_FOR_START;
int mdp_state = MDP_STATE_IDLE;

int radio_link_rfm69_free(struct overlay_interface *interface)
{
  if (interface->radio_link_state)
    {
      free(interface->radio_link_state);
      interface->radio_link_state = NULL;
    }
  return 0;
}

int radio_link_rfm69_init(struct overlay_interface *interface)
{
  interface->radio_link_state = emalloc_zero(sizeof(struct radio_link_state));

  return 0;
}

void radio_link_rfm69_state_html(struct strbuf *b, struct overlay_interface *interface)
{
  struct radio_link_state *state = interface->radio_link_state;
  strbuf_sprintf(b, "last packet RSSI: %ddB<br>", state->radio_rssi);
}

int radio_link_rfm69_is_busy(struct overlay_interface *interface)
{
  if (interface->radio_link_state && interface->radio_link_state->tx_packet)
    return 1;
  return 0;
}

int radio_link_rfm69_queue_packet(struct overlay_interface *interface, struct overlay_buffer *buffer)
{
  struct radio_link_state *link_state = interface->radio_link_state;

  if (link_state->tx_packet)
    {
      ob_free(buffer);
      return WHYF("Cannot send two packets to a stream at the same time");
    }

  // prepare the buffer for reading
  ob_flip(buffer);
  link_state->tx_packet = buffer;
  radio_link_rfm69_tx(interface);

  return 0;
}

void assemble_mdp_packet(struct overlay_interface *interface)
{
  struct radio_link_state *rstate = interface->radio_link_state;

  //upper four bits -> count
  //lower four bits -> seq. nr.
  //is the count and sequence number in range?
  if(((unsigned)(rstate->payload[0] >> 4)) < MAX_PACKET_BLOCK_COUNT || ((unsigned)(rstate->payload[0] >> 4)) > MAX_PACKET_BLOCK_COUNT || ((unsigned)(rstate->payload[0] & 0x0F)) > MAX_PACKET_BLOCK_COUNT)
    {
      //ERROR
      if (config.debug.radio_link)
        DEBUGF("Got a packet with a wrong count or sequence number (count: %d, sequence number: %d)", ((unsigned)(rstate->payload[0] >> 4)), ((unsigned)(rstate->payload[0] & 0x0F)));
      mdp_state = MDP_STATE_IDLE;
    }

  //inner data format: <count packets(4 bits, max. 21)><sequence number(4 bits, max. 21)><data>
  switch (mdp_state) {
    default:
      mdp_state = MDP_STATE_IDLE;
      rstate->packet_length = 0;
      break;

    case MDP_STATE_IDLE:
      mdp_state = MDP_STATE_RX;
      rstate->seq = rstate->payload[0];
      rstate->packet_length = 0;
      if (config.debug.radio_link)
        DEBUG("MDP state machine was in a crazy state. Reset.");
      break;

    case MDP_STATE_RX:
      //is the sequence number the next one (old + 1)?
      //upper four bits -> count
      //lower four bits -> seq. nr.
      if((((unsigned)(rstate->seq & 0x0F)) + 1) != ((unsigned)(rstate->payload[0] & 0x0F)))
        {
          if (config.debug.radio_link)
            DEBUGF("Got a packet with a wrong sequence number. Expected %d but got %d.", (((unsigned)(rstate->seq & 0x0F)) + 1), ((unsigned)(rstate->payload[0] & 0x0F)));
          mdp_state = MDP_STATE_IDLE;
          rstate->packet_length = 0;
        }

      //bcopy(src, dst, len);
      //first byte is the cnt#/seq#, so miss this out
      bcopy(&rstate->payload[1], &rstate->dst[rstate->packet_length], rstate->payload_length - 1);
      rstate->packet_length += rstate->payload_length - 1;
      //update the seq# (preserve the upper 4 bits, add one to the lower 4 bits, add all together)
      rstate->seq = ((unsigned)(rstate->seq & 0xF0)) | (((unsigned)(rstate->seq & 0x0F)) + 1);

      //did we received all expected packets?
      //cnt# == seq#
      if(((unsigned)(rstate->seq & 0xF0)) == ((unsigned)(rstate->seq & 0x0F)))
        {
          //hand the data over to serval
          packetOkOverlay(interface, rstate->dst, rstate->packet_length, NULL);

          //cleanup
          mdp_state = MDP_STATE_IDLE;
        }
      break;
  }
}

void parser_cleanup(struct overlay_interface *interface)
{
  struct radio_link_state *rstate = interface->radio_link_state;

  //drop the buffer (cleanup)
  parser_state = P_STATE_WAITING_FOR_START;

  rstate->payload_length = 0;
  rstate->payload_start = 0;
  rstate->payload_offset = 0;
}

void radio_link_rfm69_receive_packet(struct overlay_interface *interface, uint8_t c)
{
  IN();
  struct radio_link_state *rstate = interface->radio_link_state;

  //packet format: <start><rssi><length><data><end>
  rstate->payload[rstate->payload_offset] = c;

  switch (parser_state) {
    default:
    case P_STATE_WAITING_FOR_START:
      if(rstate->payload_offset != 0)
        {
          //ERROR!!!
          if (config.debug.radio_link)
            DEBUG("Receiver state machine was in a crazy state");

          parser_cleanup(interface);
          break;
        }

      if(rstate->payload[rstate->payload_offset] == PACKET_START)
        {
          parser_state = P_STATE_START_FOUND;
          rstate->payload_offset++;
        }
      break;
    case P_STATE_START_FOUND:
      //will read RSSI now
      parser_state = P_STATE_RSSI_FOUND;
      rstate->radio_rssi = rstate->payload[rstate->payload_offset];
      rstate->payload_offset++;
      break;
    case P_STATE_RSSI_FOUND:
      //check length
      if(rstate->payload[rstate->payload_offset] <= RFM69_LINK_MTU)
        {
          //OK!!!
          //will read length now
          parser_state = P_STATE_READING;
          rstate->payload_length = rstate->payload[rstate->payload_offset];
          rstate->payload_offset++;
        }
      else
        {
          //ERROR!!!
          if (config.debug.radio_link)
            DEBUGF("Packet length was to big. Maximum size is %d but got %d. Reset state machine.", RFM69_LINK_MTU, rstate->payload[rstate->payload_offset]);
          parser_cleanup(interface);
          break;
        }
      break;
    case P_STATE_READING:
      //will read 'length' number of bytes now

      //end sign correct --> to long?
      //packet format: <start(1 byte)><rssi(1 byte)><length(1 byte)><data(length*bytes)><end(1 byte)>
      if(rstate->payload_offset == rstate->packet_length + 3)
        {
          parser_state = P_STATE_WAITING_FOR_START;
          if(rstate->payload[rstate->payload_offset] == PACKET_END)
            {
              //valid packet received
              //TODO: hand it over to serval
              if (config.debug.radio_link)
                DEBUG("Recovered a packet from radio. Hand it over to the overlay interface.");

              //ad packet to assemble MDP packet
              assemble_mdp_packet(interface);
            }
          else
            {
              if (config.debug.radio_link)
                DEBUGF("Packet end sigh incorrect. Expected %c but got %c. Reset state machine.", PACKET_END, rstate->payload[rstate->payload_offset]);
            }


          parser_cleanup(interface);
          break;
        }
      else
        {
          rstate->payload_offset++;
        }
      break;
  }
  OUT();
}

void radio_link_rfm69_process_ok(struct overlay_interface *interface, uint8_t c)
{
  IN();
  struct radio_link_state *rstate = interface->radio_link_state;

  //OK format: "OK\r\n"
  rstate->payload[rstate->payload_offset] = c;
  rstate->payload_offset++;

  //if not in range
  if(!(rstate->payload_offset <= 3))
    {
      //ERROR!!!
      if (config.debug.radio_link)
        DEBUG("Receiver state machine was in a crazy state. Reset.");

      parser_cleanup(interface);
    }

  //we have all we need
  if(rstate->payload_offset == 3) {
      //is it "OK"?
      if(rstate->payload[rstate->payload_offset] == 'O' && rstate->payload[rstate->payload_offset] == 'K')
        {
          //got "OK"
          if (config.debug.radio_link)
            DEBUG("Got an 'OK'.");
        }
      else
        {
          //ERROR!!!
          if (config.debug.radio_link)
            DEBUG("No 'OK' received. Give up. Reset.");
        }
  }
}

int radio_link_rfm69_create_packet(struct overlay_interface *interface, uint8_t *packet, unsigned length)
{
  IN();
  struct radio_link_state *rstate = interface->radio_link_state;

  unsigned cnt;
  unsigned seq;
  if((rstate->seq >> 4) == 0)
    {
      cnt = ((unsigned)((rstate->tx_bytes + ((RFM69_LINK_MTU - 1) / 2)) / (RFM69_LINK_MTU - 1)));
      seq = 0;
    }
  else
    {
      cnt = ((unsigned)(rstate->seq >> 4));
      seq = ((unsigned)(rstate->seq & 0x0F));
    }

  if(cnt > MAX_PACKET_BLOCK_COUNT)
    {
      //ERROR!!!
      if (config.debug.radio_link)
        DEBUG("The given MDP buffer was to big.");
      return -1;
    }

  packet[0] = '{';

  //first data byte is the cnt#/seq#
  packet[1] = (((unsigned)(cnt << 4)) | ((unsigned)(seq & 0x0F)));

  bcopy(&rstate->txbuffer[rstate->tx_pos], &packet[2], length);

  packet[length] = '}';
  return 0;
  OUT();
}

void radio_link_rfm69_cleanup_buffer(struct overlay_interface *interface)
{
  IN();
  struct radio_link_state *rstate = interface->radio_link_state;

  main_state = STATE_RECEIVE;
  mdp_state = MDP_STATE_IDLE;
  ob_free(rstate->tx_packet);
  rstate->tx_packet=NULL;
  overlay_queue_schedule_next(gettime_ms());
  OUT();
}

void radio_link_rfm69_send_packet(struct overlay_interface *interface)
{
  IN();

  struct radio_link_state *rstate = interface->radio_link_state;

  int written = 0;

  //do we have to write more data than the MTU is big?
  int length;
  if(rstate->tx_bytes > RFM69_LINK_MTU)
  {
      //just write a piece as big as the MTU
      length = RFM69_LINK_MTU + 2;
  }
  else
  {
      //write the rest of the buffer
      length = rstate->tx_bytes + 2;
  }

  //create a new packet
  //format: <start><<data><end>
  //inner data format: <count packets(4 bits, max. 21)><sequence number(4 bits, max. 21)><data>
  uint8_t packet[RFM69_LINK_MTU+2];
  radio_link_rfm69_create_packet(interface, packet, length);

  written = write(interface->alarm.poll.fd, packet, length);

  if(written == length)
  {
      rstate->tx_bytes -= written;
      rstate->tx_pos += written;

      //wait for "OK"
      main_state = STATE_WAIT_OK;
  }
  else
  {
      //ERROR
      //give up sending, cleanup
      radio_link_rfm69_cleanup_buffer(interface);
      if (config.debug.radio_link)
        DEBUG("Was not able to write to the radio. Give up. Drop this MDP packet.");
  }

  //everything done?
  if(rstate->tx_bytes == 0)
  {
      radio_link_rfm69_cleanup_buffer(interface);
  }
  OUT();
}

// write a new link layer packet to interface->txbuffer
int radio_link_rfm69_tx(struct overlay_interface *interface)
{
  IN();
  switch (main_state)
    {
    case STATE_RECEIVE:
      main_state = STATE_SEND;
      mdp_state = MDP_STATE_TX;
      radio_link_rfm69_send_packet(interface);
      break;
    case STATE_SEND:
      radio_link_rfm69_send_packet(interface);
      break;
    default:
    case STATE_WAIT_OK:
//      radio_link_rfm69_cleanup_buffer(interface);
      break;
    }
  RETURN(0);
}

int radio_link_rfm69_decode(struct overlay_interface *interface, uint8_t c)
{
  IN();
  switch (main_state)
    {
    default:
    case STATE_RECEIVE:
      radio_link_rfm69_receive_packet(interface, c);
      break;
    case STATE_WAIT_OK:
      radio_link_rfm69_process_ok(interface, c);
      break;
    }
  RETURN(0);
}
