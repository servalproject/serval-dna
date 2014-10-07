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

#define STATE_RECEIVE 0
#define STATE_SEND 1
#define STATE_WAIT_OK 2
#define suppress_warning(X) if(X){}

int state;

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
  strbuf_sprintf(b, "RSSI: %ddB<br>", state->radio_rssi);
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
  radio_link_rfm69_callback(interface);

  return 0;
}

void radio_link_rfm69_receive_packet(struct overlay_interface *interface)
{
  suppress_warning(interface);
}

void radio_link_rfm69_process_ok(struct overlay_interface *interface)
{
  suppress_warning(interface);
}

void radio_link_rfm69_send_packet(struct overlay_interface *interface)
{
  suppress_warning(interface);
}

// write a new link layer packet to interface->txbuffer
// consuming more bytes from the next interface->tx_packet if required
int radio_link_rfm69_callback(struct overlay_interface *interface)
{
  switch (state)
    {
    default:
    case STATE_RECEIVE:
      radio_link_rfm69_receive_packet(interface);
      break;
    case STATE_WAIT_OK:
      radio_link_rfm69_process_ok(interface);
      break;
    case STATE_SEND:
      radio_link_rfm69_send_packet(interface);
      break;
    }
  return 0;
}

int radio_link_rfm69_decode(struct overlay_interface *interface, uint8_t c) {
	IN();
	suppress_warning(interface);
	suppress_warning(c);
	RETURN(0);
}
