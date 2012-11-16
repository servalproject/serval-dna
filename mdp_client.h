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

/* Client-side MDP function */
int overlay_mdp_client_socket(void);
int overlay_mdp_client_close(int mdp_sockfd);
int overlay_mdp_client_poll(int mdp_sockfd, time_ms_t timeout_ms);
int overlay_mdp_bind(int mdp_sockfd, unsigned char *localaddr, int port);
int overlay_mdp_recv(int mdp_sockfd, overlay_mdp_frame *mdp, int port, int *ttl);
int overlay_mdp_send(int mdp_sockfd, overlay_mdp_frame *mdp,int flags,int timeout_ms);
int overlay_mdp_relevant_bytes(overlay_mdp_frame *mdp);

#endif
