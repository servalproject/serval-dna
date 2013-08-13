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

#define MAX_PACKET_DESTINATIONS OVERLAY_MAX_INTERFACES

struct packet_destination{
  // if we've sent this packet once, what was the envelope sequence number?
  int sent_sequence;
  time_ms_t delay_until;
  struct network_destination *destination;
};

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
  
  time_ms_t delay_until;
  struct packet_destination destinations[MAX_PACKET_DESTINATIONS];
  int destination_count;
  int transmit_count;
  
  // each payload gets a sequence number that is reused on retransmission
  int32_t mdp_sequence;
  
  // null if destination is broadcast
  struct subscriber *destination;
  struct broadcast broadcast_id;
  struct subscriber *next_hop;
  // should we force the encoding to include the entire source public key?
  int source_full;
  struct subscriber *source;
  
  /* IPv4 address the frame was received from */
  struct sockaddr_in recvaddr;
  overlay_interface *interface;
  char unicast;
  int packet_version;
  int sender_interface;
  
  /* Actual payload */
  struct overlay_buffer *payload;
  
  time_ms_t enqueued_at;
};


int op_free(struct overlay_frame *p);
struct overlay_frame *op_dup(struct overlay_frame *f);

#endif
