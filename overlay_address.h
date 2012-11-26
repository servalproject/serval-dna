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

// immediate neighbour
#define REACHABLE_DIRECT 1

// reachable via unicast packet
#define REACHABLE_UNICAST 2

// packets must be routed
#define REACHABLE_INDIRECT 3

// packets can probably be flooded to this peer with ttl=2
// (temporary state for new peers before path discovery has finished)
#define REACHABLE_BROADCAST 4

// this subscriber is in our keystore
#define REACHABLE_SELF 5

#define REACHABLE_DEFAULT_ROUTE 6

#define OA_CODE_SELF 0xff
#define OA_CODE_PREVIOUS 0xfe

#define BROADCAST_LEN 8


// This structure supports both our own routing protocol which can store calculation details in *node 
// or IP4 addresses reachable via any other kind of normal layer3 routing protocol, eg olsr
struct subscriber{
  unsigned char sid[SID_SIZE];
  // minimum abbreviation length, in 4bit nibbles.
  int abbreviate_len;
  
  // should we send the full address once?
  int send_full;
  
  // overlay routing information
  struct overlay_node *node;
  
  // result of routing calculations;
  int reachable;
  
  // if indirect, who is the next hop?
  struct subscriber *next_hop;
  
  // if direct, or unicast, where do we send packets?
  struct overlay_interface *interface;
  
  // if reachable==REACHABLE_UNICAST send packets to this address, else use the interface broadcast address
  struct sockaddr_in address;
  
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
  int invalid_addresses;
  struct overlay_frame *please_explain;
  struct subscriber *sender;
  struct subscriber *previous;
};

extern struct subscriber *my_subscriber;
extern struct subscriber *directory_service;

struct subscriber *find_subscriber(const unsigned char *sid, int len, int create);
void enum_subscribers(struct subscriber *start, int(*callback)(struct subscriber *, void *), void *context);
int subscriber_is_reachable(struct subscriber *subscriber);
int set_reachable(struct subscriber *subscriber, int reachable);
int reachable_unicast(struct subscriber *subscriber, overlay_interface *interface, struct in_addr addr, int port);
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
