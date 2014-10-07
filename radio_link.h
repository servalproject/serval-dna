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

#ifndef __SERVAL_DNA___RADIO_LINK_H
#define __SERVAL_DNA___RADIO_LINK_H

#define LINK_MTU 255

struct radio_link_state {
	// next seq for transmission
	int tx_seq;

	// small buffer for parsing incoming bytes from the serial interface,
	// looking for recoverable link layer packets
	// should be large enough to hold at least one packet from the remote end
	// plus one heartbeat packet from the local firmware
	uint8_t payload[LINK_MTU * 3];

	// decoded length of next link layer packet
	// including all header and footer bytes
	size_t payload_length;
	// last rx seq for reassembly
	int seq;
	// offset within payload that we have found a valid looking header
	unsigned payload_start;
	// offset after payload_start for incoming bytes
	unsigned payload_offset;

	// small buffer for assembling mdp payloads.
	uint8_t dst[MDP_MTU];
	// length of recovered packet
	size_t packet_length;

	// next firmware heartbeat
	time_ms_t next_heartbeat;

	time_ms_t last_packet;

	// parsed rssi
	int radio_rssi;
	int remote_rssi;
	// estimated firmware buffer space
	int32_t remaining_space;

	// next serial write
	time_ms_t next_tx_allowed;
	// partially sent packet
	struct overlay_buffer *tx_packet;

	// serial write buffer
	uint8_t txbuffer[LINK_MTU];
	int tx_bytes;
	int tx_pos;
};

int radio_link_free(struct overlay_interface *interface);
int radio_link_init(struct overlay_interface *interface);
int radio_link_decode(struct overlay_interface *interface, uint8_t c);
int radio_link_tx(struct overlay_interface *interface);
void radio_link_state_html(struct strbuf *b, struct overlay_interface *interface);
int radio_link_is_busy(struct overlay_interface *interface);
int radio_link_queue_packet(struct overlay_interface *interface, struct overlay_buffer *buffer);

#endif //__SERVAL_DNA___RADIO_LINK_H
