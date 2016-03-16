/* 
 Serval DNA MDP overlay frame
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

#ifndef __SERVAL_DNA__OVERLAY_PACKET_H
#define __SERVAL_DNA__OVERLAY_PACKET_H

#include "serval_types.h"
#include "overlay_address.h"
#include "section.h"

#define FRAME_NOT_SENT -1
#define FRAME_DONT_SEND -2

#define MAX_PACKET_DESTINATIONS OVERLAY_MAX_INTERFACES

struct packet_destination{
  // if we've sent this packet once, what was the envelope sequence number?
  int sent_sequence;
  // track when we last sent this packet. if we don't get an ack, send it again.
  time_ms_t transmit_time;
  // the actual out going stream for this packet
  struct network_destination *destination;
  // next hop in the route
  struct subscriber *next_hop;
};

struct overlay_frame {
  // packet queue pointers
  struct overlay_frame *prev;
  struct overlay_frame *next;
  
  // when did we insert into the queue?
  time_ms_t enqueued_at;
  struct __sourceloc whence;
  
  // deprecated, all future "types" should just be assigned port numbers
  unsigned int type;
  // encrypted? signed?
  unsigned int modifiers;
  
  uint8_t ttl;
  // Which QOS queue?
  uint8_t queue;
  // How many times should we retransmit?
  int8_t resend;
  
  // callback and context just before packet sending
  void *send_context;
  int (*send_hook)(struct overlay_frame *, struct network_destination *, int, void *);
  
  // when should we send it?
  time_ms_t delay_until;
  // where should we send it?
  struct packet_destination destinations[MAX_PACKET_DESTINATIONS];
  int destination_count;
  uint8_t manual_destinations;
  // how often have we sent it?
  int transmit_count;
  
  // each payload gets a sequence number that is reused on retransmission
  int32_t mdp_sequence;
  
  // packet addressing;
  // where did this packet originate?
  struct subscriber *source;
  // where is this packet destined for
  // for broadcast packets, the destination will be null and the broadcast_id will be set if ttl>1
  struct subscriber *destination;
  struct broadcast broadcast_id;
  // where is this packet going next?
  struct subscriber *next_hop;
  
  // should we force the next packet header to include our full public key?
  int source_full;
  
  // how did we receive this packet?
  struct overlay_interface *interface;
  
  // packet envelope header;
  // Was it a unicast frame
  char unicast;
  // what encoding version was used / should be used?
  int packet_version;
  // which interface did the previous hop sent it from? 
  int sender_interface;
  
  // Raw wire format of the payload, probably encrypted or signed.
  struct overlay_buffer *payload;
};

// simple representation for passing mdp packet header details
struct internal_mdp_header{
  struct subscriber *source;
  mdp_port_t source_port;
  struct subscriber *destination;
  mdp_port_t destination_port;
  int8_t resend;
  uint8_t ttl;
  uint8_t qos;
  uint8_t crypt_flags; // combination of MDP_FLAG_NO_CRYPT & MDP_FLAG_NO_SIGN flags
  struct overlay_interface *receive_interface;
  void *send_context;
  int (*send_hook)(struct overlay_frame *, struct network_destination *, int, void *);
};


int op_free(struct overlay_frame *p);
struct overlay_frame *op_dup(struct overlay_frame *f);

int reload_mdp_packet_rules(void);
void frame_remove_destination(struct overlay_frame *frame, int i);
void frame_add_destination(struct overlay_frame *frame, struct subscriber *next_hop, struct network_destination *dest);

void mdp_init_response(const struct internal_mdp_header *in, struct internal_mdp_header *out);
void overlay_mdp_encode_ports(struct overlay_buffer *plaintext, mdp_port_t dst_port, mdp_port_t src_port);
int overlay_mdp_dnalookup_reply(struct subscriber *dest, mdp_port_t dest_port, 
    struct subscriber *resolved_sid, const char *uri, const char *did, const char *name);

int _overlay_send_frame(struct __sourceloc whence, struct internal_mdp_header *header, struct overlay_buffer *payload);
#define overlay_send_frame(H, P) _overlay_send_frame(__WHENCE__, H, P)

struct internal_binding{
  mdp_port_t port;
  int (*function)(struct internal_mdp_header *header, struct overlay_buffer *payload);
};

DECLARE_SECTION(struct internal_binding, bindings);

#define DEFINE_BINDING(PORT, FUNC) \
  static int FUNC(struct internal_mdp_header *, struct overlay_buffer *);\
  static struct internal_binding BIND ## FUNC IN_SECTION(bindings) = { \
    .port = PORT, \
    .function = FUNC, \
  }

#endif //__SERVAL_DNA__OVERLAY_PACKET_H
