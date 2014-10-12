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
#include "radio_link_rfm69.h"

int radio_link_free(struct overlay_interface *interface)
{
  switch (interface->radiotype)
    {
    default:
    case RADIO_TYPE_RFD900:
      return radio_link_rfd900_free(interface);
      break;
    case RADIO_TYPE_RFM69:
        return radio_link_rfm69_free(interface);
      break;
    }
  return 0;
}

int radio_link_init(struct overlay_interface *interface)
{
  switch (interface->radiotype)
    {
    default:
    case RADIO_TYPE_RFD900:
      return radio_link_rfd900_init(interface);
      break;
    case RADIO_TYPE_RFM69:
        return radio_link_rfm69_init(interface);
      break;
    }
  return 0;
}

void radio_link_state_html(struct strbuf *b, struct overlay_interface *interface)
{
  switch (interface->radiotype)
    {
    default:
    case RADIO_TYPE_RFD900:
      radio_link_rfd900_state_html(b, interface);
      break;
    case RADIO_TYPE_RFM69:
      radio_link_rfm69_state_html(b, interface);
      break;
    }
}

int radio_link_is_busy(struct overlay_interface *interface)
{
  switch (interface->radiotype)
    {
    default:
    case RADIO_TYPE_RFD900:
      return radio_link_rfd900_is_busy(interface);
      break;
    case RADIO_TYPE_RFM69:
      return radio_link_rfm69_is_busy(interface);
      break;
    }
  return 0;
}

int radio_link_queue_packet(struct overlay_interface *interface, struct overlay_buffer *buffer)
{
  switch (interface->radiotype)
    {
    default:
    case RADIO_TYPE_RFD900:
      return radio_link_rfd900_queue_packet(interface, buffer);
      break;
    case RADIO_TYPE_RFM69:
      return radio_link_rfm69_queue_packet(interface, buffer);
      break;
    }
  return 0;
}

// write a new link layer packet to interface->txbuffer
// consuming more bytes from the next interface->tx_packet if required
int radio_link_callback(struct overlay_interface *interface)
{
  switch (interface->radiotype)
    {
    default:
    case RADIO_TYPE_RFD900:
      return radio_link_rfd900_tx(interface);
      break;
    case RADIO_TYPE_RFM69:
      return radio_link_rfm69_callback(interface);
      break;
    }
  return 0;
}

// add one byte at a time from the serial link, and attempt to decode packets
int radio_link_decode(struct overlay_interface *interface, uint8_t c)
{
  IN();
  switch (interface->radiotype)
    {
    default:
    case RADIO_TYPE_RFD900:
      return radio_link_rfd900_decode(interface, c);
      break;
    case RADIO_TYPE_RFM69:
      return radio_link_rfm69_decode(interface, c);
      break;
    }
  RETURN(0);
}
