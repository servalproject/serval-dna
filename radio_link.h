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

#define HEARTBEAT_SIZE (8+9)
#define LINK_MTU 255

int radio_link_free(struct overlay_interface *interface);
int radio_link_init(struct overlay_interface *interface);
int radio_link_decode(struct overlay_interface *interface, uint8_t c);
int radio_link_tx(struct overlay_interface *interface);
void radio_link_state_html(struct strbuf *b, struct overlay_interface *interface);
int radio_link_is_busy(struct overlay_interface *interface);
int radio_link_queue_packet(struct overlay_interface *interface, struct overlay_buffer *buffer);

#endif //__SERVAL_DNA___RADIO_LINK_H
