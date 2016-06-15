/* 
Serval DNA MDP addressing
Copyright (C) 2012-2013 Serval Project Inc.

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

#ifndef __SERVAL_DNA__OVERLAY_ADDRESS_H
#define __SERVAL_DNA__OVERLAY_ADDRESS_H

#include "constants.h"
#include "os.h" // for time_ms_t
#include "socket.h"

// not reachable
#define REACHABLE_NONE 0

// this subscriber is in our keystore
#define REACHABLE_SELF (1<<0)

// immediate neighbour broadcast packet
#define REACHABLE_BROADCAST (1<<1)

// reachable directly via unicast packet
#define REACHABLE_UNICAST (1<<2)

// packets must be routed via next_hop
#define REACHABLE_INDIRECT (1<<3)

#define REACHABLE_ASSUMED (1<<4)

#define REACHABLE_DIRECT (REACHABLE_BROADCAST|REACHABLE_UNICAST)
#define REACHABLE (REACHABLE_DIRECT|REACHABLE_INDIRECT)

#define BROADCAST_LEN 8

struct packet_rule;
struct overlay_buffer;

// This structure supports both our own routing protocol which can store calculation details in *node 
// or IP4 addresses reachable via any other kind of normal layer3 routing protocol, eg olsr
struct subscriber{
  sid_t sid;
  // minimum abbreviation length, in 4bit nibbles.
  int abbreviate_len;
  
  int max_packet_version;
  
  // link state routing information
  struct link_state *link_state;
  
  // rhizome sync state
  struct rhizome_sync *sync_state;
  struct rhizome_sync_keys *sync_keys_state;
  uint8_t sync_version;

  // result of routing calculations;
  int reachable;

  // if indirect, who is the next hop?
  struct subscriber *next_hop;
  int hop_count;
  struct subscriber *prior_hop;
  
  // if direct, or unicast, where do we send packets?
  struct network_destination *destination;
  
  time_ms_t last_stun_request;
  time_ms_t last_probe_response;
  time_ms_t last_explained;
  
  // public signing key details for remote peers
  uint8_t sas_public[SAS_SIZE];
  time_ms_t sas_last_request;
  uint8_t sas_valid:1;
  uint8_t sas_combined:1;

  // should we send the full address once?
  uint8_t send_full:1;

  // private keys for local identities
  struct keyring_identity *identity;
};

struct broadcast{
  unsigned char id[BROADCAST_LEN];
};

#define DECODE_FLAG_ENCODING_HEADER (1<<0)
#define DECODE_FLAG_INVALID_ADDRESS (1<<1)
#define DECODE_FLAG_DONT_EXPLAIN (1<<2)

struct decode_context{
  struct overlay_interface *interface;
  int sender_interface;
  int packet_version;
  int encapsulation;
  struct socket_address addr;
  uint8_t flags;
  struct overlay_frame *please_explain;
  struct subscriber *sender;
  struct subscriber *previous;
  struct subscriber *point_to_point_device;
};

struct subscriber *get_my_subscriber();
void release_my_subscriber();
extern __thread struct subscriber *directory_service;

struct subscriber *_find_subscriber(struct __sourceloc, const unsigned char *sid, int len, int create);
#define find_subscriber(sid, len, create) _find_subscriber(__WHENCE__, sid, len, create)

void enum_subscribers(struct subscriber *start, int(*callback)(struct subscriber *, void *), void *context);
int set_reachable(struct subscriber *subscriber, struct network_destination *destination, struct subscriber *next_hop, int hop_count, struct subscriber *prior_hop);
struct network_destination *load_subscriber_address(struct subscriber *subscriber);

int process_explain(struct overlay_frame *frame);
int overlay_broadcast_drop_check(struct broadcast *addr);
int overlay_broadcast_generate_address(struct broadcast *addr);

void overlay_broadcast_append(struct overlay_buffer *b, struct broadcast *broadcast);
void overlay_address_append(struct decode_context *context, struct overlay_buffer *b, struct subscriber *subscriber);

int overlay_broadcast_parse(struct overlay_buffer *b, struct broadcast *broadcast);
int overlay_address_parse(struct decode_context *context, struct overlay_buffer *b, struct subscriber **subscriber);
int send_please_explain(struct decode_context *context, struct subscriber *source, struct subscriber *destination);

void free_subscribers();

#endif //__SERVAL_DNA__OVERLAY_ADDRESS_H
