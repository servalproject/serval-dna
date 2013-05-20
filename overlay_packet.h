/* 
 Serval Daemon
 Copyright (C) 2012 Serval Project Inc.
 
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

#ifndef _SERVALD_OVERLAY_PACKET_H
#define _SERVALD_OVERLAY_PACKET_H

#include "overlay_address.h"
#include "serval.h"

#define FRAME_NOT_SENT -1
#define FRAME_DONT_SEND -2

struct overlay_frame {
  struct overlay_frame *prev;
  struct overlay_frame *next;
  
  unsigned int type;
  unsigned int modifiers;
  
  unsigned char ttl;
  unsigned char queue;
  char resend;
  void *send_context;
  int (*send_hook)(struct overlay_frame *, int seq, void *context);
  
  /* What sequence number have we used to send this packet on this interface.
     */
  int interface_sent_sequence[OVERLAY_MAX_INTERFACES];
  time_ms_t interface_dont_send_until[OVERLAY_MAX_INTERFACES];
  struct broadcast broadcast_id;
  
  // null if destination is broadcast
  struct subscriber *destination;
  struct subscriber *next_hop;
  
  int source_full;
  struct subscriber *source;
  
  /* IPv4 address the frame was received from, or should be sent to */
  int destination_resolved;
  struct sockaddr_in recvaddr;
  overlay_interface *interface;
  char unicast;
  time_ms_t dont_send_until;
  
  /* Actual payload */
  struct overlay_buffer *payload;
  
  time_ms_t enqueued_at;
  
};


int op_free(struct overlay_frame *p);
struct overlay_frame *op_dup(struct overlay_frame *f);

#endif
