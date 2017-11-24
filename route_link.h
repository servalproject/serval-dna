/* 
Serval DNA link-state routing
Copyright (C) 2015 Serval Project Inc.

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

#ifndef __SERVAL_DNA__ROUTE_LINK_H
#define __SERVAL_DNA__ROUTE_LINK_H

#include <stdint.h> // for uint8_t

struct strbuf;
struct overlay_interface;
struct network_destination;
struct subscriber;
struct overlay_frame;
struct decode_context;
struct internal_mdp_header;

void link_neighbour_short_status_html(struct strbuf *b, const char *link_prefix);
void link_neighbour_status_html(struct strbuf *b, struct subscriber *neighbour);
int link_has_neighbours();
int link_interface_has_neighbours(struct overlay_interface *interface);
int link_destination_has_neighbours(struct network_destination *dest);
int link_stop_routing(struct subscriber *subscriber);
int link_add_destinations(struct overlay_frame *frame);
int link_state_should_forward_broadcast(struct subscriber *transmitter);
int link_state_ack_soon(struct subscriber *subscriber);
int link_received_duplicate(struct decode_context *context, int payload_seq);
int link_received_packet(struct decode_context *context, int sender_seq, uint8_t unicast);
int link_unicast_ack(struct subscriber *subscriber, struct overlay_interface *interface, struct socket_address *addr);
void link_explained(struct subscriber *subscriber);
int link_state_legacy_ack(struct overlay_frame *frame, time_ms_t now);

DECLARE_TRIGGER(nbr_change, struct subscriber *neighbour, uint8_t found, unsigned count);
DECLARE_TRIGGER(link_change, struct subscriber *subscriber, int prior_reachable);

#endif // __SERVAL_DNA__ROUTE_LINK_H
