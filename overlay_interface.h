/*
Serval DNA overlay network interfaces
Copyright (C) 2010 Paul Gardner-Stephen
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

#ifndef __SERVAL_DNA__OVERLAY_INTERFACE_H
#define __SERVAL_DNA__OVERLAY_INTERFACE_H

#include "socket.h"
#include "limit.h"

#define INTERFACE_STATE_DOWN 0
#define INTERFACE_STATE_UP 1
#define INTERFACE_STATE_DETECTING 2

struct overlay_interface;

// where should packets be sent to?
struct network_destination {
  int _ref_count;
  
  // which interface are we actually sending packets out of
  struct overlay_interface *interface;
  
  // The network destination address
  // this may be the interface broadcast IP address
  // but could be a unicast address
  struct socket_address address;
  
  // should outgoing packets be marked as unicast?
  char unicast;
  
  char packet_version;
  
  struct config_mdp_iftype ifconfig;
  
  // time last packet was sent
  time_ms_t last_tx;
  
  int min_rtt;
  int max_rtt;
  int resend_delay;

  // sequence number of last packet sent to this destination.
  // Used to allow NACKs that can request retransmission of recent packets.
  int sequence_number;
  int last_ack_seq;

  // rate limit for outgoing packets
  struct limit_state transfer_limit;
};

typedef struct overlay_interface {
  struct sched_ent alarm;
  
  char name[256];
  
  off_t recv_offset; /* file offset */
  
  int recv_count;
  int tx_count;
  
  struct radio_link_state *radio_link_state;

  struct config_network_interface ifconfig;
  
  char local_echo;

  struct network_destination *destination;

  struct subscriber *other_device;
  
  // the actual address of the interface.
  struct socket_address address;
  
  struct in_addr netmask;
  
  /* Use one of the INTERFACE_STATE_* constants to indicate the state of this interface. 
     If the interface stops working or disappears, it will be marked as DOWN and the socket closed.
     But if it comes back up again, we should try to reuse this structure, even if the broadcast address has changed.
   */
  int state;
} overlay_interface;

/* Maximum interface count is rather arbitrary.
 Memory consumption is O(n) with respect to this parameter, so let's not make it too big for now.
 */
extern overlay_interface overlay_interfaces[OVERLAY_MAX_INTERFACES];

struct network_destination * new_destination(struct overlay_interface *interface);
struct network_destination * create_unicast_destination(struct socket_address *addr, struct overlay_interface *interface);
struct network_destination * add_destination_ref(struct network_destination *ref);
void release_destination_ref(struct network_destination *ref);
int set_destination_ref(struct network_destination **ptr, struct network_destination *ref);

DECLARE_ALARM(overlay_interface_discover);

struct config_mdp_iftype;
int overlay_destination_configure(struct network_destination *dest, const struct config_mdp_iftype *ifconfig);

struct config_network_interface;
int overlay_interface_configure(struct overlay_interface *interface, const struct config_network_interface *ifconfig);

int
overlay_interface_init(const char *name, struct socket_address *addr, 
		       struct socket_address *netmask,
		       struct socket_address *broadcast,
		       const struct config_network_interface *ifconfig);
void overlay_interface_close(overlay_interface *interface);

int overlay_interface_register(char *name,
			   struct socket_address *addr,
			   struct socket_address *netmask,
			   struct socket_address *broadcast);
void overlay_interface_close_all();
overlay_interface * overlay_interface_get_default();
overlay_interface * overlay_interface_find(struct in_addr addr, int return_default);
overlay_interface * overlay_interface_find_name(const char *name);
overlay_interface * overlay_interface_find_name_addr(const char *name, struct socket_address *addr);
int overlay_interface_compare(overlay_interface *one, overlay_interface *two);
int overlay_broadcast_ensemble(struct network_destination *destination, struct overlay_buffer *buffer);
void interface_state_html(struct strbuf *b, struct overlay_interface *interface);
void overlay_interface_monitor_up();

#endif // __SERVAL_DNA__OVERLAY_INTERFACE_H
