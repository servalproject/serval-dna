/*
 Mesh Streaming Protocol (MSP)
 Copyright (C) 2013-2014 Serval Project Inc.
 
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

#ifndef __SERVAL_DNA__MSP_CLIENT_H
#define __SERVAL_DNA__MSP_CLIENT_H

#define MSP_STATE_UNINITIALISED 0
#define MSP_STATE_LISTENING (1<<0)

#define MSP_STATE_RECEIVED_DATA (1<<1)
#define MSP_STATE_RECEIVED_PACKET (1<<2)

#define MSP_STATE_SHUTDOWN_LOCAL (1<<3)
#define MSP_STATE_SHUTDOWN_REMOTE (1<<4)

// this connection is about to be free'd, release any other resources or references to the state
#define MSP_STATE_CLOSED (1<<5)

// something has gone wrong somewhere
#define MSP_STATE_ERROR (1<<6)

// is there space for sending more data?
#define MSP_STATE_DATAOUT (1<<7)


struct msp_sock;
typedef uint16_t msp_state_t;

// allocate a new socket
struct msp_sock * msp_socket(int mdp_sock);
void msp_close(struct msp_sock *sock);
void msp_close_all(int mdp_sock);
unsigned msp_socket_count();

void msp_debug();

int msp_set_handler(struct msp_sock *sock, 
  int (*handler)(struct msp_sock *sock, msp_state_t state, const uint8_t *payload, size_t len, void *context), 
  void *context);

// the local address is only set when calling msp_listen or msp_send
int msp_set_local(struct msp_sock *sock, struct mdp_sockaddr local);
int msp_set_remote(struct msp_sock *sock, struct mdp_sockaddr remote);

int msp_listen(struct msp_sock *sock);

int msp_get_remote_adr(struct msp_sock *sock, struct mdp_sockaddr *remote);
msp_state_t msp_get_state(struct msp_sock *sock);

// bind, send data, and potentially shutdown this end of the connection
int msp_send(struct msp_sock *sock, const uint8_t *payload, size_t len);
int msp_shutdown(struct msp_sock *sock);

// receive and process an incoming packet
int msp_recv(int mdp_sock);

// next_action indicates the next time that msp_processing should be called
int msp_processing(time_ms_t *next_action);

#endif //__SERVAL_DNA__MSP_CLIENT_H
