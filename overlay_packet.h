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

struct overlay_frame {
  struct overlay_frame *prev;
  struct overlay_frame *next;
  
  unsigned int type;
  unsigned int modifiers;
  
  unsigned char ttl;
  unsigned char queue;
  // temporary hack to improve reliability before implementing per-packet nack's
  int send_copies;
  
  /* Mark which interfaces the frame has been sent on,
   so that we can ensure that broadcast frames get sent
   exactly once on each interface */
  unsigned char broadcast_sent_via[OVERLAY_MAX_INTERFACES];
  struct broadcast broadcast_id;
  
  // null if destination is broadcast
  struct subscriber *destination;
  
  struct subscriber *source;
  
  /* IPv4 node frame was received from (if applicable) */
  struct sockaddr *recvaddr;
  overlay_interface *interface;
  
  /* Actual payload */
  struct overlay_buffer *payload;
  
  time_ms_t enqueued_at;
  
};


int op_free(struct overlay_frame *p);
struct overlay_frame *op_dup(struct overlay_frame *f);

#endif
