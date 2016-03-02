/*
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

#ifndef __SERVAL_DNA__MDP_CLIENT_H
#define __SERVAL_DNA__MDP_CLIENT_H

#include "constants.h"
#include "serval_types.h"
#include "os.h"
#include "net.h"
#include "log.h"

// define 3rd party mdp API without any structure padding
#pragma pack(push, 1)

struct mdp_sockaddr {
  sid_t sid;
  mdp_port_t port;
};

#define MDP_FLAG_NO_CRYPT (1<<0)
#define MDP_FLAG_NO_SIGN (1<<1)
#define MDP_FLAG_BIND (1<<2)
#define MDP_FLAG_REUSE (1<<5)

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

/* Port numbers for commands sent to the local daemon: remote.sid = SID_ANY
 */

/* Port zero has no function (acts as a no-op or /dev/null for packets sent to
 * it).  It exists so that side effects like binding can be performed without
 * generating any network traffic or other action.
 */
#define MDP_LISTEN 0

/* Lock and unlock identities in the local keyring.
 * Requests start with an mdp_identity_request structure followed by a list of PINs or SIDs
*/ 
#define MDP_IDENTITY 1

struct mdp_identity_request {
  uint8_t action;
#define ACTION_LOCK 1   // lock all the given SIDs or revoke the given PINs
#define ACTION_UNLOCK 2 // unlock all identities with the given PINs or the identities with the given SIDs (must have already sent the relevant unrevoked PINs)
  uint8_t type;
#define TYPE_SID 1 // this struct is followed by a list of SIDs up to end of payload
#define TYPE_PIN 2 // this struct is followed by a list of NULL terminated entry PINs up to end of payload
};

/* Search unlocked identities from the running daemon
 * If the request is empty, all identities will be returned
 * if the request contains a packed tag / value, identities with a matching tag will be returned
 * if the value passed in is zero length, all identities with that tag and any value will be returned
*/
#define MDP_SEARCH_IDS 2

/* Synchronise with the daemon's configuration.
 *
 * Once the daemon has (re)loaded all its configuration files, so that its
 * running (active) configuration is up to date, then sends a reply packet.
*/
#define MDP_SYNC_CONFIG 3

/* External interface implementation
 * 
 * Messages used for talking to a client application that implements a network 
 * interface that isn't based on simple file descriptors
 * eg android bluetooth & wifi-direct
*/
#define MDP_INTERFACE 4
#define MDP_INTERFACE_UP 0
#define MDP_INTERFACE_DOWN 1
#define MDP_INTERFACE_RECV 2

struct overlay_route_record{
  sid_t sid;
  char interface_name[256];
  int reachable;
  int hop_count;
  sid_t neighbour;
  sid_t prior_hop;
};

struct overlay_mdp_scan{
  struct in_addr addr;
};

struct overlay_mdp_data_frame {
  struct mdp_sockaddr src;
  struct mdp_sockaddr dst;
  uint16_t payload_length;
  int queue;
  int ttl;
  union{
    unsigned char payload[MDP_MTU-100];
    struct overlay_route_record route_record;
  };
};

struct overlay_mdp_error {
  unsigned int error;
  char message[128];
};

struct overlay_mdp_addrlist {
  int mode;
#define OVERLAY_MDP_ADDRLIST_MAX_SID_COUNT (~(unsigned int)0)
  unsigned int server_sid_count;
  unsigned int first_sid;
  unsigned int last_sid;
  unsigned int frame_sid_count; /* how many of the following slots are populated */
  sid_t sids[MDP_MAX_SID_REQUEST];
};


typedef struct overlay_mdp_frame {
  uint16_t packetTypeAndFlags;
  union {
    struct overlay_mdp_data_frame out;
    struct mdp_sockaddr bind;
    struct overlay_mdp_addrlist addrlist;
    struct overlay_mdp_error error;
    char raw[MDP_MTU];
  };
} overlay_mdp_frame;

#pragma pack(pop)

/* low level V2 mdp interface */
int _mdp_socket(struct __sourceloc);
int _mdp_close(struct __sourceloc, int socket);
int _mdp_send(struct __sourceloc, int socket, const struct mdp_header *header, const uint8_t *payload, size_t len);
ssize_t _mdp_recv(struct __sourceloc, int socket, struct mdp_header *header, uint8_t *payload, size_t max_len);
int _mdp_poll(struct __sourceloc, int socket, time_ms_t timeout_ms);
ssize_t mdp_poll_recv(int mdp_sock, time_ms_t deadline, struct mdp_header *rev_header, unsigned char *payload, size_t buffer_size);
int _mdp_bind(struct __sourceloc __whence, int socket, struct mdp_sockaddr *local_addr);

#define mdp_socket()      _mdp_socket(__WHENCE__)
#define mdp_close(s)      _mdp_close(__WHENCE__, (s))
#define mdp_send(s,h,p,l) _mdp_send(__WHENCE__, (s), (h), (p), (l))
#define mdp_recv(s,h,p,l) _mdp_recv(__WHENCE__, (s), (h), (p), (l))
#define mdp_poll(s,t)     _mdp_poll(__WHENCE__, (s), (t))
#define mdp_bind(s,a)     _mdp_bind(__WHENCE__, (s), (a))

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
