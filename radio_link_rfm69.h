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
Copyright (C) 2013 Paul Gardner-Stephen
 
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

#ifndef __SERVAL_DNA___RADIO_LINK_RFM69_H
#define __SERVAL_DNA___RADIO_LINK_RFM69_H

#define RFM69_LINK_MTU 60

//main states
#define RFM69_STATE_IDLE 0
#define RFM69_STATE_RX 1
#define RFM69_STATE_TX 2
#define RFM69_STATE_WAIT_OK 3
#define RFM69_STATE_CONFIGURATION 4
#define RFM69_STATE_WAIT_COMMAND_OK 5
#define RFM69_STATE_ERROR 6

//receive parser states
#define RFM69_P_STATE_WAIT_FOR_START 0
#define RFM69_P_STATE_START_FOUND 1
#define RFM69_P_STATE_RSSI_FOUND 2
#define RFM69_P_STATE_READING 3

#define PACKET_START '{'
#define PACKET_END '}'

//MDP_MTU / RFM69_LINK_MTU = 21
#define RFM69_MAX_PACKET_BLOCK_COUNT 21

#define suppress_warning(X) if(X){}

int radio_link_rfm69_free(struct overlay_interface *interface);
int radio_link_rfm69_init(struct overlay_interface *interface);
int radio_link_rfm69_decode(struct overlay_interface *interface, uint8_t c);
int radio_link_rfm69_callback(struct overlay_interface *interface);
void radio_link_rfm69_state_html(struct strbuf *b, struct overlay_interface *interface);
int radio_link_rfm69_is_busy(struct overlay_interface *interface);
int radio_link_rfm69_queue_packet(struct overlay_interface *interface, struct overlay_buffer *buffer);

#endif //__SERVAL_DNA___RADIO_LINK_RFM69_H
