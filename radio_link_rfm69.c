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

int main_state = RFM69_STATE_IDLE;
int parser_state = RFM69_P_STATE_WAIT_FOR_START;

uint8_t modemmode;
uint8_t txpower;
float frequency;
uint8_t key[16];

int
radio_link_rfm69_free(struct overlay_interface *interface)
{
  if (interface->radio_link_state)
    {
      free(interface->radio_link_state);
      interface->radio_link_state = NULL;
    }
  return 0;
}

//void radio_link_rfm69_command_timeout(struct overlay_interface *interface)
//{
//  //we reached this point because we hit the timeout while waiting for "OK" after a command
//  WHY("Was not able to get an OK from the radio.");
//  main_state = RFM69_STATE_ERROR;
//}

//void radio_link_rfm69_command_to_radio(struct overlay_interface *interface)
//{
//  IN();
//
//  unschedule(&interface->alarm);
//  interface->alarm.alarm = 0;
//
//  struct radio_link_state *rstate = interface->radio_link_state;
//
//  int written = 0;
//
//  //try to write (more) data of the command to the radio
//  while (rstate->tx_bytes)
//    {
//      if (config.debug.radio_link)
//        DEBUGF("Try to write %d bytes to radio...", rstate->tx_bytes);
//      written = write(interface->alarm.poll.fd, &rstate->txbuffer[rstate->tx_pos], rstate->tx_bytes);
//      if (config.debug.radio_link)
//        DEBUGF("Was able to write %d bytes.", written);
//
//      //was there a problem to write all the data (command) straight to the radio?
//      //(was the OS serial buffer full?)
//      if (written <= 0)
//        {
//          //ask the scheduler to call back if there is a chance to write more data
//          //(there is a bit of space in the OS serial buffer again)
//          interface->alarm.poll.events |= POLLOUT;
//          if (config.debug.radio_link)
//            DEBUG("Tell scheduler to call back if there is a chance to write more of the command.");
//
//          //stop writing for now but set watch
//          watch(&interface->alarm);
//          RETURNVOID;
//        }
//
//      //update the count of data (packet command) we have written to the radio
//      rstate->tx_bytes -= written;
//      rstate->tx_pos += written;
//    }
//
//  //tell the scheduler to stop calling us if there space in the buffer
//  interface->alarm.poll.events &= ~POLLOUT;
//
//  //packet command is written
//
//  //cleanup
//  rstate->tx_bytes = 0;
//  rstate->tx_pos = 0;
//
//  //tell the scheduler to call us in 2 sec.
//  //if the state is still WAIT_OK we won't wait
//  //any longer and give up
//  interface->alarm.alarm = gettime_ms() + 2000;
//  schedule(&interface->alarm);
//
//  main_state = RFM69_STATE_WAIT_COMMAND_OK;
//  watch(&interface->alarm);
//  OUT();
//}

//int
//radio_link_rfm69_read_configuration(struct overlay_interface *interface)
//{
//
//}

int
radio_link_rfm69_init(struct overlay_interface *interface)
{
  interface->radio_link_state = emalloc_zero(sizeof(struct radio_link_state));
  struct radio_link_state *rstate = interface->radio_link_state;

  radio_link_rfm69_cleanup_and_idle_state(interface);

  //TODO: send AT commands to setup radio
  //TODO: read current configuration
//  sprintf(rstate->txbuffer, "ATC\n");
//  rstate->tx_pos = 0;
//  rstate->tx_bytes = 4;

  return 0;
}

void
radio_link_rfm69_state_html(struct strbuf *b,
    struct overlay_interface *interface)
{
  struct radio_link_state *state = interface->radio_link_state;
  strbuf_sprintf(b, "last packet RSSI: %ddB<br>", state->radio_rssi);
  //TODO: provide the current configuration of the radio
}

int
radio_link_rfm69_is_busy(struct overlay_interface *interface)
{
  suppress_warning(interface);
  return main_state != RFM69_STATE_IDLE;
}

int
radio_link_rfm69_queue_packet(struct overlay_interface *interface,
    struct overlay_buffer *buffer)
{
  struct radio_link_state *link_state = interface->radio_link_state;

  if (link_state->tx_packet)
    {
      ob_free(buffer);
      return WHYF("Cannot send two packets to a stream at the same time");
    }

  if (config.debug.radio_link)
    DEBUG("Got a new MDP packet. Will try to send it.");
  // prepare the buffer for reading
  ob_flip(buffer);
  link_state->tx_packet = buffer;
  main_state = RFM69_STATE_TX;
  radio_link_rfm69_callback(interface);

  return 0;
}

void
radio_link_rfm69_cleanup_and_idle_state(struct overlay_interface *interface)
{
  struct radio_link_state *rstate = interface->radio_link_state;

  //reset states
  main_state = RFM69_STATE_IDLE;
  parser_state = RFM69_P_STATE_WAIT_FOR_START;

  //drop the buffers (cleanup)
  if(rstate->tx_packet){
      ob_free(rstate->tx_packet);
  }
  rstate->tx_packet = NULL;

  rstate->tx_bytes = 0;
  rstate->tx_pos = 0;
  rstate->tx_seq = 0;

  rstate->seq = 0;
  rstate->packet_length = 0;

  rstate->payload_length = 0;
  rstate->payload_start = 0;
  rstate->payload_offset = 0;

  overlay_queue_schedule_next(gettime_ms());
}

void
radio_link_rfm69_assemble_mdp_packet(struct overlay_interface *interface)
{
  //transmit format: <start packet><packet 1><packet 2>...<packet n>
  IN();
  struct radio_link_state *rstate = interface->radio_link_state;

  if (rstate->payload_length < 1)
    {
      WHYF("Packets need to be long enough. Expected %d but got %d.",
          1, rstate->payload_length);
      radio_link_rfm69_cleanup_and_idle_state(interface);
      RETURNVOID;
    }

  //is this the start packet?
  if (rstate->packet_length == 0)
    {
      //start packet format: <count of packets>
      if (rstate->payload_length == 1)
        {
          rstate->seq = rstate->payload[0];

          if (rstate->seq > RFM69_MAX_PACKET_BLOCK_COUNT)
            {
              if (config.debug.radio_link)
                DEBUGF(
                    "Got a (start) packet with a to large packet count. The maximum allowed is %d but got %d.",
                    RFM69_MAX_PACKET_BLOCK_COUNT, rstate->seq);
              radio_link_rfm69_cleanup_and_idle_state(interface);
              RETURNVOID;
            }
        }
      else
        {
          if (config.debug.radio_link)
            DEBUGF(
                "Got a (start) packet with a wrong length. Expected %d but got %d.",
                1, rstate->payload_length);
          radio_link_rfm69_cleanup_and_idle_state(interface);
          RETURNVOID;
        }
    }

  //inner data format: <sequence number (packets remaining)><data>

  //is the sequence number correct?
  if (rstate->seq != rstate->payload[0])
    {
      //NO!
      if (config.debug.radio_link)
        DEBUGF(
            "Got a packet with a wrong sequence number. Expected %d but got %d.",
            rstate->seq, rstate->payload[4]);
      radio_link_rfm69_cleanup_and_idle_state(interface);
      RETURNVOID;
    }

  //bcopy(src, dst, len);
  //first byte is the seq#, so miss that out
  bcopy(&rstate->payload[1], &rstate->dst[rstate->packet_length],
      rstate->payload_length - 1);
  rstate->packet_length += rstate->payload_length - 1;

  //update the seq#
  rstate->seq--;

  //did we received all expected packets?
  if (rstate->seq == 0)
    {
      //hand the data over to serval
      packetOkOverlay(interface, rstate->dst, rstate->packet_length, NULL);

      //cleanup
      radio_link_rfm69_cleanup_and_idle_state(interface);
    }
  OUT();
}

void
radio_link_rfm69_receive_packet(struct overlay_interface *interface, uint8_t c)
{
  IN();
  struct radio_link_state *rstate = interface->radio_link_state;

  //transmit format: <start packet><packet 1><packet 2>...<packet n>
  //start packet format: <start><rssi><length><count of packets><end>
  //packet format: <start><rssi><length><data><end>
  //inner data format: <sequence number (packets remaining)><data>
  rstate->payload[rstate->payload_offset] = c;

  switch (parser_state)
    {
    default:
    case RFM69_P_STATE_WAIT_FOR_START:
      if (rstate->payload[rstate->payload_offset] == PACKET_START)
        {
          parser_state = RFM69_P_STATE_START_FOUND;
          rstate->payload_offset++;
        }
      break;
    case RFM69_P_STATE_START_FOUND:
      //will read RSSI now
      parser_state = RFM69_P_STATE_RSSI_FOUND;
      rstate->radio_rssi = rstate->payload[rstate->payload_offset];
      rstate->payload_offset++;
      break;
    case RFM69_P_STATE_RSSI_FOUND:
      //check length
      if (rstate->payload[rstate->payload_offset] <= RFM69_LINK_MTU)
        {
          //OK!!!
          //will read length now
          parser_state = RFM69_P_STATE_READING;
          rstate->payload_length = rstate->payload[rstate->payload_offset];
          rstate->payload_offset++;
        }
      else
        {
          //ERROR!!!
          if (config.debug.radio_link)
            DEBUGF(
                "Packet length was to big. Maximum size is %d but got %d. Reset state machine. Give up.",
                RFM69_LINK_MTU, rstate->payload[rstate->payload_offset]);
          radio_link_rfm69_cleanup_and_idle_state(interface);
          break;
        }
      break;
    case RFM69_P_STATE_READING:
      //will read 'length' number of bytes now

      //end sign correct --> to long?
      //packet format: <start(1 byte)><rssi(1 byte)><length(1 byte)><data(length*bytes)><end(1 byte)>
      if (rstate->payload_offset == rstate->payload_length + 3)
        {
          parser_state = RFM69_P_STATE_WAIT_FOR_START;
          if (rstate->payload[rstate->payload_offset] == PACKET_END)
            {
              //valid packet received
              //add packet to assemble MDP packet
              radio_link_rfm69_assemble_mdp_packet(interface);
            }
          else
            {
              if (config.debug.radio_link)
                DEBUGF(
                    "Packet end sign incorrect. Expected %c but got %c. Reset state machine.",
                    PACKET_END, rstate->payload[rstate->payload_offset]);
              radio_link_rfm69_cleanup_and_idle_state(interface);
            }

          //cleanup and prepare for next packet
          parser_state = RFM69_P_STATE_WAIT_FOR_START;

          rstate->payload_length = 0;
          rstate->payload_start = 0;
          rstate->payload_offset = 0;
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

void
radio_link_rfm69_process_ok(struct overlay_interface *interface, uint8_t c)
{
  IN();
  struct radio_link_state *rstate = interface->radio_link_state;

  rstate->payload[rstate->payload_offset] = c;

  //do we have all we need?
  //OK format: "OK\r\n"
  if (rstate->payload_offset == 3)
    {
      //is it "OK"?
      if (rstate->payload[0] == 'O' && rstate->payload[1] == 'K')
        {
          //got "OK"
          if (config.debug.radio_link)
            DEBUG("Got an 'OK'.");
        }
      else
        {
          //ERROR!!!
          if (config.debug.radio_link)
            DEBUG(
                "No 'OK' received. Give up. Reset. Hint: It is may has been arrived a packet.");
          radio_link_rfm69_cleanup_and_idle_state(interface);
          RETURNVOID;
        }
    }
  rstate->payload_offset++;

  //everything done?
  if (ob_remaining(rstate->tx_packet) == 0)
    {
      radio_link_rfm69_cleanup_and_idle_state(interface);
    }
  else
    {
      //TODO: tell the scheduler to call back the transmission method.
      interface->alarm.alarm = gettime_ms();
      schedule(&interface->alarm);
      main_state = RFM69_STATE_TX;
    }
  OUT();
}

int
radio_link_rfm69_create_next_packet(struct overlay_interface *interface)
{
  //transmit format: <start packet><packet 1><packet 2>...<packet n>
  //start packet format: <start><count of packets><end>
  //packet format: <start><data><end>
  //inner data format: <sequence number (packets remaining)><data>

  IN();
  struct radio_link_state *rstate = interface->radio_link_state;

  if (rstate->seq == 0)
    {
      //first packet
      //how many radio packets/chunks will we need to send the MDP packet?
      rstate->seq = ((unsigned) ((ob_remaining(rstate->tx_packet)
          + ((RFM69_LINK_MTU - 1) / 2)) / (RFM69_LINK_MTU - 1)));

      //return header packet
      rstate->txbuffer[0] = '{';
      //start packet format: <start><count of packets><end>
      rstate->txbuffer[1] = rstate->seq;
      rstate->txbuffer[2] = '}';

      rstate->tx_bytes = 3;
      rstate->tx_pos = 0;
      RETURN(0);
    }

  //how many radio packets/chunks will we need to send the MDP packet?
  rstate->seq = ((unsigned) ((ob_remaining(rstate->tx_packet)
      + ((RFM69_LINK_MTU - 1) / 2)) / (RFM69_LINK_MTU - 1)));

  rstate->txbuffer[0] = '{';

  //first data byte is the seq#
  rstate->txbuffer[1] = rstate->seq;

  unsigned count;
  if (ob_remaining(rstate->tx_packet) > RFM69_LINK_MTU - 1)
    {
      count = RFM69_LINK_MTU - 1;
    }
  else
    {
      count = ob_remaining(rstate->tx_packet);
    }

  ob_get_bytes(rstate->tx_packet, &rstate->txbuffer[2], count);

  rstate->txbuffer[count + 2] = '}';
  rstate->tx_bytes = count + 2;
  rstate->tx_pos = 0;

  if (config.debug.radio_link)
    DEBUG("Successfully created a packet.");
  RETURN(0);
}

void
radio_link_rfm69_send_packet(struct overlay_interface *interface)
{
  IN();

  unschedule(&interface->alarm);
  interface->alarm.alarm = 0;

  struct radio_link_state *rstate = interface->radio_link_state;

  int written = 0;

  //create a new packet command
  //transmit format: <start packet><packet 1><packet 2>...<packet n>
  //start packet command format: <start><count of packets><end>
  //packet command format: <start><data><end>
  //inner data format: <sequence number (packets remaining)><data>
  if (rstate->tx_packet && rstate->tx_bytes == 0)
    {
      radio_link_rfm69_create_next_packet(interface);
    }

  //try to write (more) data (packet command)
  while (rstate->tx_bytes)
    {
      if (config.debug.radio_link)
        DEBUGF("Try to write %d bytes to radio...", rstate->tx_bytes);
      written = write(interface->alarm.poll.fd,
          &rstate->txbuffer[rstate->tx_pos], rstate->tx_bytes);
      if (config.debug.radio_link)
        DEBUGF("Was able to write %d bytes.", written);

      //was there a problem to write all the data (packet command) straight to the radio?
      //(was the OS serial buffer full?)
      if (written <= 0)
        {
          //ask the scheduler to call back if there is a chance to write more data (packet command)
          //(there is a bit of space in the OS serial buffer again)
          interface->alarm.poll.events |= POLLOUT;
          if (config.debug.radio_link)
            DEBUG("Tell scheduler to call back if there is a chance to write more of the packet command.");

          //stop writing for now but set watch
          watch(&interface->alarm);
          RETURNVOID;
        }

      //update the count of data (packet command) we have written to the radio
      rstate->tx_bytes -= written;
      rstate->tx_pos += written;
    }

  //tell the scheduler to stop calling us if there space in the buffer
  interface->alarm.poll.events &= ~POLLOUT;

  //only if we got called to write something
  if (main_state == RFM69_STATE_TX)
    {
      //packet command is written

      //cleanup
      rstate->tx_bytes = 0;
      rstate->tx_pos = 0;

      //now wait for "OK"
      rstate->payload_length = 0;
      rstate->payload_offset = 0;
      rstate->payload_start = 0;

      //tell the scheduler to call us in 2 sec.
      //it the state is still WAIT_OK we won't wait
      //any longer and give up
      interface->alarm.alarm = gettime_ms() + 2000;
      schedule(&interface->alarm);

      main_state = RFM69_STATE_WAIT_OK;
    }

  watch(&interface->alarm);
//  schedule(&interface->alarm);
  OUT();
}

//state machine callback function
int
radio_link_rfm69_callback(struct overlay_interface *interface)
{
  IN();
  switch (main_state)
    {
    case RFM69_STATE_IDLE:
      /* no break */
    case RFM69_STATE_TX:
      radio_link_rfm69_send_packet(interface);
      break;
    case RFM69_STATE_WAIT_OK:
      //this should only happen if the a timeout occurred while waiting for "OK"
      //hint: it could mean there was a packet received while waiting for the OK
      //(so we should give up)
      radio_link_rfm69_cleanup_and_idle_state(interface);
      break;
//    case RFM69_STATE_WAIT_COMMAND_OK:
//    case RFM69_STATE_CONFIGURATION:
//      radio_link_rfm69_command_to_radio(interface);
//      break;
    default:
      WHYF("TX was called in a incorrect state.");
      break;
    }
  RETURN(0);
}

int
radio_link_rfm69_decode(struct overlay_interface *interface, uint8_t c)
{
  IN();
  struct radio_link_state *rstate = interface->radio_link_state;

  switch (main_state)
    {
    case RFM69_STATE_IDLE:
      main_state = RFM69_STATE_RX;
      parser_state = RFM69_P_STATE_WAIT_FOR_START;
      rstate->payload_length = 0;
      rstate->payload_offset = 0;
      rstate->payload_start = 0;
      /* no break */
    case RFM69_STATE_RX:
      radio_link_rfm69_receive_packet(interface, c);
      break;
    case RFM69_STATE_WAIT_OK:
      radio_link_rfm69_process_ok(interface, c);
      break;
    default:
      WHYF("RX was called in a incorrect state.");
      break;
    }
  RETURN(0);
}
