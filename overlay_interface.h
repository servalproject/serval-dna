#ifndef __SERVAL_DNA__OVERLAY_INTERFACE_H
#define __SERVAL_DNA__OVERLAY_INTERFACE_H

#include "socket.h"

#define INTERFACE_STATE_FREE 0
#define INTERFACE_STATE_UP 1
#define INTERFACE_STATE_DOWN 2
#define INTERFACE_STATE_DETECTING 3


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
  
  // should we aggregate packets, or send one at a time
  char encapsulation;

  // time last packet was sent
  time_ms_t last_tx;
  
  int min_rtt;
  int max_rtt;
  int resend_delay;

  // sequence number of last packet sent to this destination.
  // Used to allow NACKs that can request retransmission of recent packets.
  int sequence_number;

  // rate limit for outgoing packets
  struct limit_state transfer_limit;

  /* Number of milli-seconds per tick for this interface, which is basically
   * related to the     the typical TX range divided by the maximum expected
   * speed of nodes in the network.  This means that short-range communications
   * has a higher bandwidth requirement than long-range communications because
   * the tick interval has to be shorter to still allow fast-convergence time
   * to allow for mobility.
   *
   * For wifi (nominal range 100m) it is usually 500ms.
   * For ~100K ISM915MHz (nominal range 1000m) it will probably be about 5000ms.
   * For ~10K ISM915MHz (nominal range ~3000m) it will probably be about 15000ms.
   *
   * These figures will be refined over time, and we will allow people to set
   * them per-interface.
   */
  unsigned tick_ms;

  // Number of milliseconds of no packets until we assume the link is dead.
  unsigned reachable_timeout_ms;
};

typedef struct overlay_interface {
  struct sched_ent alarm;
  
  char name[256];
  
  int recv_offset; /* file offset */
  
  int recv_count;
  int tx_count;
  
  struct radio_link_state *radio_link_state;

  // copy of ifconfig flags
  uint16_t drop_packets;
  char drop_broadcasts;
  char drop_unicasts;
  int port;
  int type;
  int socket_type;
  char send_broadcasts;
  char prefer_unicast;
  /* Not necessarily the real MTU, but the largest frame size we are willing to TX.
   For radio links the actual maximum and the maximum that is likely to be delivered reliably are
   potentially two quite different values. */
  int mtu;
  // can we use this interface for routes to addresses in other subnets?
  int default_route;
  // should we log more debug info on this interace? eg hex dumps of packets
  char debug;
  char local_echo;

  unsigned int uartbps; // set serial port speed (which might be different from link speed)
  int ctsrts; // enabled hardware flow control if non-zero

  struct network_destination *destination;

  // can we assume that we will only receive packets from one device?
  char point_to_point;
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

extern unsigned overlay_interface_count;

struct network_destination * new_destination(struct overlay_interface *interface, char encapsulation);
struct network_destination * create_unicast_destination(struct socket_address *addr, struct overlay_interface *interface);
struct network_destination * add_destination_ref(struct network_destination *ref);
void release_destination_ref(struct network_destination *ref);
int set_destination_ref(struct network_destination **ptr, struct network_destination *ref);


void overlay_interface_discover(struct sched_ent *alarm);
int overlay_interface_register(char *name,
			   struct socket_address *addr,
			   struct socket_address *broadcast);
overlay_interface * overlay_interface_get_default();
overlay_interface * overlay_interface_find(struct in_addr addr, int return_default);
overlay_interface * overlay_interface_find_name(const char *name);
int overlay_interface_compare(overlay_interface *one, overlay_interface *two);
int overlay_broadcast_ensemble(struct network_destination *destination, struct overlay_buffer *buffer);
void interface_state_html(struct strbuf *b, struct overlay_interface *interface);

#endif // __SERVAL_DNA__OVERLAY_INTERFACE_H
