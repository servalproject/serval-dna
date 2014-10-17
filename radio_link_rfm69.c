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
#include "radio_link.h"
#include "radio_link_rfm69.h"

//main states
#define RFM69_STATE_IDLE 0
#define RFM69_STATE_RX 1
#define RFM69_STATE_TX 2
#define RFM69_STATE_SEND_COMMAND 3
#define RFM69_STATE_CONFIGURATION 4
#define RFM69_STATE_WAIT_COMMAND_OK 5
#define RFM69_STATE_WAIT_COMMAND_OK_AND_RX 6
#define RFM69_STATE_RX_THEN_SEND_COMMAND 7

#define PACKET_START '{'
#define PACKET_END '}'

//MDP_MTU / RFM69_LINK_MTU = 21
#define RFM69_MAX_PACKET_BLOCK_COUNT 21

#define suppress_warning(X) if(X){}

int main_state = RFM69_STATE_IDLE;

uint8_t modemmode;
uint8_t txpower;
float frequency;
uint8_t key[16];

#define RFM69_MAX_INPUT_LENGTH 256
uint8_t inputBuffer[RFM69_MAX_INPUT_LENGTH];
uint8_t inputPosition;

//maximal time (in ms) to wait for an OK
#define RFM69_CMD_TIMEOUT 1000

//maximal time (in ms) to wait for a transmission to be received
#define RFM69_RX_TIMEOUT 3000
#define RFM69_HEARTBEAT 500

time_ms_t radio_link_rfm69_last_cmd;
int8_t radio_link_rfm69_send_cmd_with_timeout_result;

static void radio_link_rfm69_set_callback_alarm(struct overlay_interface *interface, time_ms_t timestamp)
{
  if(!is_scheduled(&interface->alarm)) {
    //set new timeout
    interface->alarm.deadline = timestamp + 100;
    interface->alarm.alarm = timestamp;
    schedule(&interface->alarm);
  }
}

int radio_link_rfm69_free(struct overlay_interface *interface)
{
  IN();
  if (interface->radio_link_state)
  {
      free(interface->radio_link_state);
      interface->radio_link_state = NULL;
  }
  RETURN(0);
}

int radio_link_rfm69_init(struct overlay_interface *interface)
{
  IN();
  interface->radio_link_state = emalloc_zero(sizeof(struct radio_link_state));
  RETURN(0);
}

void radio_link_rfm69_state_html(struct strbuf *b, struct overlay_interface *interface)
{
  IN();
  struct radio_link_state *state = interface->radio_link_state;
  strbuf_sprintf(b, "version: %s<br>", state->version);
  strbuf_sprintf(b, "last packet RSSI: %ddB<br>", state->radio_rssi);
  //TODO: provide the current configuration of the radio
  OUT();
}

int radio_link_rfm69_is_busy(struct overlay_interface *interface)
{
  IN();
  uint8_t result;
  if(!interface->radio_link_state->version[0])
  {
      result = 1;
  }
  else if(main_state == RFM69_STATE_IDLE || main_state == RFM69_STATE_RX)
  {
      result = 0;
  }
  else if(main_state == RFM69_STATE_TX || main_state == RFM69_STATE_SEND_COMMAND || main_state == RFM69_STATE_RX_THEN_SEND_COMMAND || main_state == RFM69_STATE_WAIT_COMMAND_OK || main_state == RFM69_STATE_WAIT_COMMAND_OK_AND_RX)
  {
      result = 1;
  }
  else
  {
      result = 0;
  }

  if (config.debug.radio_link)
    DEBUGF("busy: %d", result);
  RETURN(result);
}

int radio_link_rfm69_queue_packet(struct overlay_interface *interface, struct overlay_buffer *buffer)
{
  IN();
  struct radio_link_state *link_state = interface->radio_link_state;

  if (config.debug.radio_link)
    DEBUG("A new MDP packet is tried to be queued.");

  if (!link_state->version[0])
  {
      ob_free(buffer);
      RETURN(WHYF("Cannot use the interface until the version string was received to make sure the radio is working."));
  }

  if (link_state->tx_packet)
  {
      ob_free(buffer);
      RETURN(WHYF("Cannot send two packets to a stream at the same time"));
  }

  if (config.debug.radio_link)
    DEBUG("Got a new MDP packet. Will try to send it.");

  // prepare the buffer for reading
  ob_flip(buffer);
  link_state->tx_packet = buffer;

  if(main_state == RFM69_STATE_IDLE)
    main_state = RFM69_STATE_TX;

  radio_link_rfm69_set_callback_alarm(interface, gettime_ms());
  RETURN(0);
}

void radio_link_rfm69_send_cmd_with_timeout(struct overlay_interface *interface)
{
  IN();
  struct radio_link_state *rstate = interface->radio_link_state;

  //wait for radio init (version string detected)
  if(!rstate->version[0])
  {
      if (config.debug.radio_link)
        DEBUG("NO VERSION STRING YET.");
      //no version string received, so radio is not up yet
      RETURNVOID;
  }

  //busy?
  if(main_state == RFM69_STATE_SEND_COMMAND || main_state == RFM69_STATE_RX_THEN_SEND_COMMAND || main_state == RFM69_STATE_WAIT_COMMAND_OK || main_state == RFM69_STATE_WAIT_COMMAND_OK_AND_RX)
  {
      WHY("Busy with another command.");
      RETURNVOID;
  }

  main_state = RFM69_STATE_SEND_COMMAND;
  if (config.debug.radio_link)
    DEBUG("Will send command.");

  int written = 0;

  //try to write command
  while (rstate->tx_bytes)
  {
      if (config.debug.radio_link)
        DEBUGF("Try to write %d bytes to radio...", rstate->tx_bytes);
      written = write(interface->alarm.poll.fd, &rstate->txbuffer[rstate->tx_pos], rstate->tx_bytes);
      if (config.debug.radio_link)
        DEBUGF("Was able to write %d bytes.", written);

      //was there a problem to write all the data straight to the radio?
      //(was the OS serial buffer full?)
      if (written <= 0)
      {
          //ask the scheduler to call back if there is a chance to write more data
          //(there is a bit of space in the OS serial buffer again)
          interface->alarm.poll.events |= POLLOUT;

          if (config.debug.radio_link)
            DEBUG("Tell scheduler to call back if there is a chance to write more of the command.");

          //stop writing for now but set watch
          watch(&interface->alarm);
          RETURNVOID;
      }

      //update the count of data we have written to the radio
      rstate->tx_bytes -= written;
      rstate->tx_pos += written;
  }

  //tell the scheduler to stop calling us if there space in the buffer
  interface->alarm.poll.events &= ~POLLOUT;

  //*** command is written ***

  //cleanup
  rstate->tx_bytes = 0;
  rstate->tx_pos = 0;

  //now wait for "OK"
  rstate->payload_length = 0;
  rstate->payload_offset = 0;
  rstate->payload_start = 0;

  main_state = RFM69_STATE_WAIT_COMMAND_OK;

  if (config.debug.radio_link)
    DEBUGF("Packet command was fully written to the radio. Now wait for OK %d ms.", RFM69_CMD_TIMEOUT);
  //update watch clock
  radio_link_rfm69_send_cmd_with_timeout_result = 0;
  radio_link_rfm69_last_cmd = gettime_ms();
  watch(&interface->alarm);
  RETURNVOID;
}

static void radio_link_rfm69_cleanup_tx_state_machine(struct overlay_interface *interface)
{
  IN();
  struct radio_link_state *rstate = interface->radio_link_state;

  rstate->tx_bytes = 0;
  rstate->tx_pos = 0;
  rstate->tx_seq = 0;

  if(rstate->tx_packet) {
      ob_flip(rstate->tx_packet);
  }

  OUT();
}

static void radio_link_rfm69_cleanup_rx_state_machine(struct overlay_interface *interface)
{
  IN();
  struct radio_link_state *rstate = interface->radio_link_state;

  rstate->seq = 0;
  rstate->packet_length = 0;

  rstate->payload_length = 0;
  rstate->payload_start = 0;
  rstate->payload_offset = 0;
  OUT();
}

static void radio_link_rfm69_assemble_mdp_packet(struct overlay_interface *interface)
{
  //transmit format: <start packet><packet 1><packet 2>...<packet n>
  IN();

  struct radio_link_state *rstate = interface->radio_link_state;

  if (rstate->payload_length < 1)
  {
      WHYF("Packets need to be long enough. Expected %d but got %d.", 1, rstate->payload_length);
      radio_link_rfm69_cleanup_rx_state_machine(interface);
      RETURNVOID;
  }

  //is this the start packet?
  if (strcase_startswith((const char *)&rstate->payload[2], "START", NULL))
  {
      //start a new MDP packet
      radio_link_rfm69_cleanup_rx_state_machine(interface);

      //this is the count of packets we have to expect
      rstate->seq = rstate->payload[7];

      if (rstate->seq > RFM69_MAX_PACKET_BLOCK_COUNT)
      {
          if (config.debug.radio_link)
            DEBUGF("Got a (start) packet with a to large packet count. The maximum allowed is %d but got %d.", RFM69_MAX_PACKET_BLOCK_COUNT, rstate->seq);
          radio_link_rfm69_cleanup_rx_state_machine(interface);
          RETURNVOID;
      }
      if (config.debug.radio_link)
        DEBUGF("Got a (start) packet. We expect %d packets to come.", rstate->seq);
      RETURNVOID;
  }

  //packet format: <rssi><length><data>
  //inner data format: <sequence number (packets remaining)><data>

  //update the seq#
  rstate->seq--;
  //is the sequence number correct?
  if (rstate->seq != rstate->payload[2])
  {
      //NO!
      if (config.debug.radio_link)
        DEBUGF("Got a packet with a wrong sequence number. Expected %d but got %d.", rstate->seq, rstate->payload[4]);
      radio_link_rfm69_cleanup_rx_state_machine(interface);
      RETURNVOID;
  }

  //bcopy(src, dst, len);
  //first bytes are <rssi><length><sequence number (packets remaining)>, so miss them out
  bcopy(&rstate->payload[3], &rstate->dst[rstate->packet_length], rstate->payload_length - 1);
  rstate->packet_length += rstate->payload_length - 1;

  //did we received all expected packets?
  if (rstate->seq == 0)
  {
      if (config.debug.radio_link)
        DEBUG("MDP packet complete. Hand it over to serval.");
      //hand the data over to serval
      packetOkOverlay(interface, rstate->dst, rstate->packet_length, NULL);

      if(main_state == RFM69_STATE_RX_THEN_SEND_COMMAND)
      {
          main_state = RFM69_STATE_SEND_COMMAND;
      }
      if(main_state == RFM69_STATE_WAIT_COMMAND_OK_AND_RX)
      {
          main_state = RFM69_STATE_WAIT_COMMAND_OK;
      }
      else
      {
          main_state = RFM69_STATE_IDLE;
      }

      //cleanup
      rstate->seq = 0;
      rstate->packet_length = 0;

      rstate->payload_length = 0;
      rstate->payload_start = 0;
      rstate->payload_offset = 0;
  }
  OUT();
}

static int radio_link_rfm69_create_next_packet_cmd(struct overlay_interface *interface)
{
  //transmit format: <start packet><packet 1><packet 2>...<packet n>
  //packet command format: <start><length><data><end>
  //start packet command format: <start><length><data ("START"<count of packets>)><end>
  //inner data format: <sequence number (packets remaining)><data>

  IN();
  struct radio_link_state *rstate = interface->radio_link_state;

  if (rstate->seq == 0)
  {
      //first packet
      //how many radio packets/chunks will we need to send the MDP packet?
      rstate->seq = (ob_remaining(rstate->tx_packet) / (RFM69_LINK_MTU - 1));
      if(ob_remaining(rstate->tx_packet) % RFM69_LINK_MTU)
      {
          rstate->seq++;
      }

      if (config.debug.radio_link)
        DEBUGF("We got a MDP packet with %d bytes. Our MTU is %d. So we will try to send %d packet commands to the radio (1 start packet + %d data packets).", ob_remaining(rstate->tx_packet), RFM69_LINK_MTU, rstate->seq + 1, rstate->seq);

      //return header packet
      //start packet format: <start><length><count of packets><end>
      rstate->txbuffer[0] = '{';
      rstate->txbuffer[1] = 0x06;
      rstate->txbuffer[2] = 'S';
      rstate->txbuffer[3] = 'T';
      rstate->txbuffer[4] = 'A';
      rstate->txbuffer[5] = 'R';
      rstate->txbuffer[6] = 'T';
      rstate->txbuffer[7] = rstate->seq;
      rstate->txbuffer[8] = '}';
      rstate->txbuffer[9] = '\r';

      rstate->tx_bytes = 10;
      rstate->tx_pos = 0;
      RETURN(0);
  }

  //how many radio packets/chunks will we need to send the MDP packet?
  rstate->seq--;

  unsigned count;
  if (ob_remaining(rstate->tx_packet) > RFM69_LINK_MTU - 1)
  {
      count = RFM69_LINK_MTU - 1;
  }
  else
  {
      count = ob_remaining(rstate->tx_packet);
  }

  rstate->txbuffer[0] = '{';

  //first byte is the length
  //length is # of <data> so <seq# (1)><MDP data>
  rstate->txbuffer[1] = count + 1;

  //first data byte is the seq#
  rstate->txbuffer[2] = rstate->seq;

  ob_get_bytes(rstate->tx_packet, &rstate->txbuffer[3], count);
  rstate->tx_bytes = count + 3;

  rstate->txbuffer[rstate->tx_bytes] = '}';
  rstate->tx_bytes++;
  rstate->txbuffer[rstate->tx_bytes] = '\r';
  rstate->tx_bytes++;
  rstate->tx_pos = 0;

  if (config.debug.radio_link)
    DEBUGF("Successfully created a packet with sequence number: #%d.", rstate->seq);
  RETURN(0);
}

static void radio_link_rfm69_send_packet(struct overlay_interface *interface)
{
  IN();
  struct radio_link_state *rstate = interface->radio_link_state;
  main_state = RFM69_STATE_TX;

  //last command OK?
  if(radio_link_rfm69_send_cmd_with_timeout_result == 1)
  {
      radio_link_rfm69_send_cmd_with_timeout_result = 0;
      if (config.debug.radio_link)
        DEBUG("Packet command was successful.");
  }
  else if(radio_link_rfm69_send_cmd_with_timeout_result == -1)
  {
      radio_link_rfm69_send_cmd_with_timeout_result = 0;

      //reset state machine and try to send the same packet again
      radio_link_rfm69_cleanup_tx_state_machine(interface);
//      ob_free(rstate->tx_packet);
//      rstate->tx_packet=NULL;
//      overlay_queue_schedule_next(gettime_ms());

      main_state = RFM69_STATE_IDLE;
      if (config.debug.radio_link)
        DEBUG("Last TX command was not successful (ERROR or timeout). Give up.");
      RETURNVOID;
  }

  //everything done?
  if (ob_remaining(rstate->tx_packet) == 0)
  {
      if (config.debug.radio_link)
        DEBUG("Finished to send MDP packet.");
      radio_link_rfm69_cleanup_tx_state_machine(interface);

      ob_free(rstate->tx_packet);
      rstate->tx_packet=NULL;
      overlay_queue_schedule_next(gettime_ms());

      main_state = RFM69_STATE_IDLE;
      RETURNVOID;
  }

  //create a new packet command
  //transmit format: <start packet><packet 1><packet 2>...<packet n>
  //start packet format: <start><length><count of packets><end>
  //packet format: <start><length><data><end>
  //inner data format: <sequence number (packets remaining)><data>
  if (main_state == RFM69_STATE_TX && (ob_remaining(rstate->tx_packet) > 0) && rstate->tx_bytes == 0)
  {
      radio_link_rfm69_create_next_packet_cmd(interface);
      radio_link_rfm69_send_cmd_with_timeout(interface);
  }
  OUT();
}

//state machine callback function
int radio_link_rfm69_callback(struct overlay_interface *interface)
{
  IN();
  struct radio_link_state *rstate = interface->radio_link_state;

  //set new callback timer
  radio_link_rfm69_set_callback_alarm(interface, gettime_ms() + RFM69_HEARTBEAT);

  if (config.debug.radio_link)
    DEBUGF("Radio callback was called with state ID %d", main_state);

  if (!rstate->version[0])
  {
      interface->alarm.poll.events &= ~POLLOUT;
      watch(&interface->alarm);

      if (config.debug.radio_link)
        DEBUG("Radio is not ready. No version string received yet.");
      //no version string received, so radio is not up yet

      RETURN(0);
  }

  switch (main_state)
  {
    case RFM69_STATE_IDLE:
      /* no break */
    case RFM69_STATE_TX:
      DEBUGF("tx_packet %d, remaining %d, tx_bytes %d, result %d", rstate->tx_packet ? 1:0, rstate->tx_packet ? ob_remaining(rstate->tx_packet) : 23532, rstate->tx_bytes, radio_link_rfm69_send_cmd_with_timeout_result);
      if(rstate->tx_packet)
      {
          radio_link_rfm69_send_packet(interface);
      }
      else
      {
          main_state = RFM69_STATE_IDLE;
      }
      break;
    case RFM69_STATE_RX:
      if(rstate->last_packet > gettime_ms() + RFM69_RX_TIMEOUT)
      {
          //give up on receiving
          if(main_state == RFM69_STATE_WAIT_COMMAND_OK_AND_RX)
          {
              main_state = RFM69_STATE_WAIT_COMMAND_OK;
          }
          else if(main_state == RFM69_STATE_RX_THEN_SEND_COMMAND)
          {
              main_state = RFM69_STATE_SEND_COMMAND;
          }
          else
          {
              main_state = RFM69_STATE_IDLE;
          }
          radio_link_rfm69_cleanup_rx_state_machine(interface);
          if (config.debug.radio_link)
            DEBUG("RX timed out.");
      }
      break;
    case RFM69_STATE_SEND_COMMAND:
      radio_link_rfm69_send_cmd_with_timeout(interface);
      break;
    case RFM69_STATE_WAIT_COMMAND_OK:
      if(radio_link_rfm69_last_cmd == 0 && gettime_ms() > radio_link_rfm69_last_cmd + RFM69_CMD_TIMEOUT)
      {
          radio_link_rfm69_send_cmd_with_timeout_result = -1;
      }
      break;
    default:
      break;
  }
  RETURN(0);
}

int radio_link_rfm69_decode(struct overlay_interface *interface, uint8_t c)
{
  IN();
  struct radio_link_state *rstate = interface->radio_link_state;

  //buffer full?
  if(inputPosition == RFM69_MAX_INPUT_LENGTH - 1)
  {
      if (config.debug.radio_link)
        DEBUG("Read line buffer was full. Had to drop the first byte.");

      //drop one byte
      bcopy(&inputBuffer[1], inputBuffer, RFM69_MAX_INPUT_LENGTH - 1);
  }

  inputBuffer[inputPosition] = c;
  if(inputPosition > 1 && inputBuffer[inputPosition - 1] == '\r' && inputBuffer[inputPosition] == '\n')
  {
      //is it a packet?
      if(inputBuffer[0] == PACKET_START && inputBuffer[inputPosition - 2] == PACKET_END)
      {
          //PACKET!!!
          if (config.debug.radio_link)
            DEBUG("Got an PACKET.");
          if(main_state == RFM69_STATE_WAIT_COMMAND_OK){
              main_state = RFM69_STATE_WAIT_COMMAND_OK_AND_RX;
          }
          else if(main_state == RFM69_STATE_SEND_COMMAND)
          {
              main_state = RFM69_STATE_RX_THEN_SEND_COMMAND;
          }
          else
          {
              main_state = RFM69_STATE_RX;
          }

          rstate->last_packet = gettime_ms();
          radio_link_rfm69_cleanup_tx_state_machine(interface);

          //transmit format: <start packet><packet 1><packet 2>...<packet n>
          //start packet format: <start><rssi (hex)><length (hex)><count of packets (hex)><end>\r\n
          //packet format: <start><rssi (hex)><length (hex)><data (hex)><end>\r\n
          //inner data format: <sequence number (packets remaining) (hex)><data (hex)>

          //parse hex
          fromhex(rstate->payload, (const char *)&inputBuffer[1], (inputPosition + 1 - 4) / 2 );

          //will read length now
          rstate->payload_length = rstate->payload[1];

          //TODO: check length

          //read RSSI
          rstate->radio_rssi = rstate->payload[0];

          //valid packet received
          //add packet to assemble MDP packet
          radio_link_rfm69_assemble_mdp_packet(interface);
      }
      else if (strcase_startswith((const char *)inputBuffer, "OK", NULL))
      {
          //got "OK"
          if (config.debug.radio_link)
            DEBUG("Got an 'OK'.");

          radio_link_rfm69_send_cmd_with_timeout_result = 1;
          if(main_state == RFM69_STATE_WAIT_COMMAND_OK_AND_RX){
              main_state = RFM69_STATE_RX;
          }
          else
          {
              main_state = RFM69_STATE_IDLE;
          }
      }
      else if (strcase_startswith((const char *)inputBuffer, "ERROR", NULL))
      {
          //got "ERROR"
          if (config.debug.radio_link)
            DEBUG("Got an 'ERROR'.");
          radio_link_rfm69_send_cmd_with_timeout_result = -1;
          if(main_state == RFM69_STATE_WAIT_COMMAND_OK_AND_RX){
              main_state = RFM69_STATE_RX;
          }
          else
          {
              main_state = RFM69_STATE_IDLE;
          }
      }
      else if (strcase_startswith((const char *)inputBuffer, "RFM69HW", NULL))
      {
          //got an version string
          strbuf b = strbuf_local(rstate->version, 256);
          inputBuffer[inputPosition - 1] = '\0';
          strbuf_sprintf(b, "%s", inputBuffer);

          if (config.debug.radio_link)
            DEBUGF("Got the version string '%s'", rstate->version);
          overlay_queue_schedule_next(gettime_ms());
      }
      else
      {
          //got an unexpected line
          if (config.debug.radio_link)
          {
              if(inputPosition == RFM69_MAX_INPUT_LENGTH - 1)
              {
                  inputBuffer[inputPosition - 1] = '\0';
              }
              else
              {
                  inputBuffer[RFM69_MAX_INPUT_LENGTH - 2] = '\0';
              }

              DEBUGF("Got an unexpected line '%s'", inputBuffer);
          }
      }
      inputPosition = 0;
      RETURN(0);
  }
  inputPosition++;
  RETURN(0);
}
