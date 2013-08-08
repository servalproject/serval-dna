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

#ifndef _SERVALD_OVERLAY_ADDRESS_H
#define _SERVALD_OVERLAY_ADDRESS_H

#include "constants.h"

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


// This structure supports both our own routing protocol which can store calculation details in *node 
// or IP4 addresses reachable via any other kind of normal layer3 routing protocol, eg olsr
struct subscriber{
  unsigned char sid[SID_SIZE];
  // minimum abbreviation length, in 4bit nibbles.
  int abbreviate_len;
  
  // should we send the full address once?
  int send_full;
  
  int max_packet_version;
  
  // overlay routing information
  struct overlay_node *node;

  // link state routing information
  struct link_state *link_state;
  
  // rhizome sync state
  struct rhizome_sync *sync_state;

  // result of routing calculations;
  int reachable;

  // if indirect, who is the next hop?
  struct subscriber *next_hop;
  
  // if direct, or unicast, where do we send packets?
  struct network_destination *destination;
  
  time_ms_t last_stun_request;
  time_ms_t last_probe_response;
  time_ms_t last_explained;
  
  // public signing key details for remote peers
  unsigned char sas_public[SAS_SIZE];
  time_ms_t sas_last_request;
  unsigned char sas_valid;
  
  // private keys for local identities
  keyring_identity *identity;
};

struct broadcast{
  unsigned char id[BROADCAST_LEN];
};

struct decode_context{
  struct overlay_interface *interface;
  int sender_interface;
  int packet_version;
  int encapsulation;
  struct sockaddr_in addr;
  union{
    // only valid while decoding
    int invalid_addresses;
    // only valid while encoding
    int encoding_header;
  };
  struct overlay_frame *please_explain;
  struct subscriber *sender;
  struct subscriber *previous;
  struct subscriber *point_to_point_device;
};

extern struct subscriber *my_subscriber;
extern struct subscriber *directory_service;

struct subscriber *find_subscriber(const unsigned char *sid, int len, int create);
void enum_subscribers(struct subscriber *start, int(*callback)(struct subscriber *, void *), void *context);
int set_reachable(struct subscriber *subscriber, struct network_destination *destination, struct subscriber *next_hop);
int load_subscriber_address(struct subscriber *subscriber);

int process_explain(struct overlay_frame *frame);
int overlay_broadcast_drop_check(struct broadcast *addr);
int overlay_broadcast_generate_address(struct broadcast *addr);

int overlay_broadcast_append(struct overlay_buffer *b, struct broadcast *broadcast);
int overlay_address_append(struct decode_context *context, struct overlay_buffer *b, struct subscriber *subscriber);

int overlay_broadcast_parse(struct overlay_buffer *b, struct broadcast *broadcast);
int overlay_address_parse(struct decode_context *context, struct overlay_buffer *b, struct subscriber **subscriber);
int send_please_explain(struct decode_context *context, struct subscriber *source, struct subscriber *destination);

#endif
