/*
 Mesh Stream Protocol (MSP) API
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

#include "constants.h" // for MDP_MTU

#ifndef __MSP_CLIENT_INLINE
# if __GNUC__ && !__GNUC_STDC_INLINE__
#  define __MSP_CLIENT_INLINE extern inline
# else
#  define __MSP_CLIENT_INLINE inline
# endif
#endif

typedef uint16_t msp_state_t;

struct msp_sock;
struct msp_handle {
    struct msp_sock *ptr;
    unsigned salt;
};
typedef struct msp_handle MSP_SOCKET;
#define MSP_SOCKET_NULL ((MSP_SOCKET){.ptr=NULL,.salt=0})

__MSP_CLIENT_INLINE int msp_socket_is_null(MSP_SOCKET sock) {
    return sock.ptr == NULL;
}

int msp_socket_is_valid(MSP_SOCKET);

// socket lifecycle
msp_state_t msp_get_state(MSP_SOCKET sock);

int msp_socket_is_initialising(MSP_SOCKET);
int msp_socket_is_open(MSP_SOCKET);
int msp_socket_is_closed(MSP_SOCKET);

int msp_socket_is_listening(MSP_SOCKET);
int msp_socket_is_data(MSP_SOCKET);

int msp_socket_is_connected(MSP_SOCKET);

int msp_socket_is_shutdown_local(MSP_SOCKET);
int msp_socket_is_shutdown_remote(MSP_SOCKET);

unsigned msp_socket_count(void);

// allocate a new socket
MSP_SOCKET msp_socket(int mdp_sock, int flags);
// initialise a socket
void msp_set_local(MSP_SOCKET sock, const struct mdp_sockaddr *local);
void msp_connect(MSP_SOCKET sock, const struct mdp_sockaddr *remote);
int msp_listen(MSP_SOCKET sock);

// close socket(s)
int msp_shutdown(MSP_SOCKET sock);
void msp_stop(MSP_SOCKET sock);
void msp_close_all(int mdp_sock);

void msp_debug(void);

typedef size_t MSP_HANDLER(MSP_SOCKET sock, msp_state_t state, const uint8_t *payload, size_t len, void *context);
void msp_set_handler(MSP_SOCKET sock, MSP_HANDLER *handler, void *context);

int msp_get_mdp_socket(MSP_SOCKET); // returns arg passed to msp_socket() if MSP_SOCKET is valid
void msp_get_local(MSP_SOCKET sock, struct mdp_sockaddr *addr);
void msp_get_remote(MSP_SOCKET sock, struct mdp_sockaddr *addr);

// bind, send data, and potentially shutdown this end of the connection
ssize_t msp_send(MSP_SOCKET sock, const uint8_t *payload, size_t len);
// receive and process an incoming packet
int msp_recv(int mdp_sock);
// next_action indicates the next time that msp_processing should be called
int msp_processing(time_ms_t *next_action);

#endif //__SERVAL_DNA__MSP_CLIENT_H
