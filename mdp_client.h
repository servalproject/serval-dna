/*
 Copyright (C) 2012 Serval Project.
 
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

#ifndef __SERVALD_MDP_CLIENT_H
#define __SERVALD_MDP_CLIENT_H

#include "serval.h"

// define 3rd party mdp API without any structure padding
#pragma pack(push, 1)

struct mdp_sockaddr {
  sid_t sid;
  mdp_port_t port;
};

#define MDP_FLAG_NO_CRYPT (1<<0)
#define MDP_FLAG_NO_SIGN (1<<1)
#define MDP_FLAG_BIND (1<<2)

#define MDP_FLAG_CLOSE (1<<3)
#define MDP_FLAG_ERROR (1<<4)

struct mdp_header {
  struct mdp_sockaddr local;
  struct mdp_sockaddr remote;
  uint8_t flags;
  uint8_t qos;
  uint8_t ttl;
};

#define BIND_PRIMARY SID_ANY
#define BIND_ALL SID_BROADCAST

#define TYPE_SID 1
#define TYPE_PIN 2
#define ACTION_LOCK 1
#define ACTION_UNLOCK 2

/* Port numbers for commands sent to the local daemon*/

#define MDP_LISTEN 0
/* lock and unlock identities from the local keyring
 * Requests start with an mdp_identity_request structure followed by a list of pins or SIDs
*/ 
#define MDP_IDENTITY 1

/* Search unlocked identities from the running daemon
 * If the request is empty, all identities will be returned
 * if the request contains a packed tag / value, identities with a matching tag will be returned
 * if the value passed in is zero length, all identities with that tag and any value will be returned
*/
#define MDP_SEARCH_IDS 2

// an identity request is sent to port MDP_IDENTITY, sid ANY
struct mdp_identity_request{
  uint8_t action;
  uint8_t type;
  // the request is followed by a list of SID's or NULL terminated entry pins for the remainder of the payload
};

#pragma pack(pop)

struct overlay_route_record{
  sid_t sid;
  char interface_name[256];
  int reachable;
  sid_t neighbour;
};

struct overlay_mdp_scan{
  struct in_addr addr;
};

/* low level V2 mdp interface */
int mdp_socket(void);
int mdp_close(int socket);
int mdp_send(int socket, const struct mdp_header *header, const uint8_t *payload, size_t len);
ssize_t mdp_recv(int socket, struct mdp_header *header, uint8_t *payload, ssize_t max_len);
int mdp_poll(int socket, time_ms_t timeout_ms);



/* Client-side MDP function */
int overlay_mdp_client_socket(void);
int overlay_mdp_client_close(int mdp_sockfd);
int overlay_mdp_client_poll(int mdp_sockfd, time_ms_t timeout_ms);
int overlay_mdp_getmyaddr(int mpd_sockfd, unsigned index, sid_t *sid);
int overlay_mdp_bind(int mdp_sockfd, const sid_t *localaddr, mdp_port_t port) ;
int overlay_mdp_recv(int mdp_sockfd, overlay_mdp_frame *mdp, mdp_port_t port, int *ttl);
int overlay_mdp_send(int mdp_sockfd, overlay_mdp_frame *mdp, int flags, int timeout_ms);
ssize_t overlay_mdp_relevant_bytes(overlay_mdp_frame *mdp);

#endif
