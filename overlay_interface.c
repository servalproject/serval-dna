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

#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <assert.h>
#include <time.h>
#include <fnmatch.h>

#include "serval.h"
#include "conf.h"
#include "net.h"
#include "socket.h"
#include "overlay_interface.h"
#include "strbuf.h"
#include "strbuf_helpers.h"
#include "overlay_buffer.h"
#include "overlay_packet.h"
#include "str.h"
#include "radio_link.h"
#include "server.h"
#include "route_link.h"



// The size of the receive buffer.  This effectively sets the MRU for packet radio interfaces where
// we have to buffer packets on the receive side.
#define OVERLAY_INTERFACE_RX_BUFFER_SIZE 2048

int overlay_ready=0;
overlay_interface overlay_interfaces[OVERLAY_MAX_INTERFACES];
int overlay_last_interface_number=-1;

struct profile_total interface_poll_stats;

struct sched_ent sock_any;
struct socket_address sock_any_addr;
struct profile_total sock_any_stats;

static void overlay_interface_poll(struct sched_ent *alarm);
static int inet_up_count=0;
static void rescan_soon();

void overlay_interface_close(overlay_interface *interface)
{
  if (interface->alarm.poll.fd>=0){
    if (interface->address.addr.sa_family == AF_UNIX)
      unlink(interface->address.local.sun_path);
    if (is_watching(&interface->alarm))
      unwatch(&interface->alarm);
      
    if (interface->address.addr.sa_family == AF_INET && 
	inet_up_count>0 &&
	--inet_up_count==0 && 
	sock_any.poll.fd>0){
      
      unwatch(&sock_any);
      close(sock_any.poll.fd);
      sock_any.poll.fd=-1;
    }
    
    close(interface->alarm.poll.fd);
    interface->alarm.poll.fd=-1;
  }
  
  unschedule(&interface->alarm);
  if (interface->radio_link_state)
    radio_link_free(interface);
  interface->state=INTERFACE_STATE_DOWN;
  
  monitor_tell_formatted(MONITOR_INTERFACE, "\nINTERFACE:%s:DOWN\n", interface->name);
  INFOF("Interface %s addr %s is down", 
	interface->name, alloca_socket_address(&interface->address));
  
  link_interface_down(interface);
}

void overlay_interface_close_all()
{
  unsigned i;
  for (i=0;i<OVERLAY_MAX_INTERFACES;i++){
    if (overlay_interfaces[i].state == INTERFACE_STATE_UP)
      overlay_interface_close(&overlay_interfaces[i]);
  }
}

void overlay_interface_monitor_up()
{
  unsigned i;
  for (i=0;i<OVERLAY_MAX_INTERFACES;i++){
    if (overlay_interfaces[i].state == INTERFACE_STATE_UP)
      monitor_tell_formatted(MONITOR_INTERFACE, "\nINTERFACE:%s:UP\n", overlay_interfaces[i].name);
  }
}

void interface_state_html(struct strbuf *b, struct overlay_interface *interface)
{
  switch(interface->state){
    case INTERFACE_STATE_UP:
      strbuf_sprintf(b, "Interface %s is Up<br>", interface->name);
      break;
    default:
      strbuf_puts(b, "Interface Down");
      return;
  }
  switch(interface->ifconfig.type){
    case OVERLAY_INTERFACE_PACKETRADIO:
      strbuf_puts(b, "Type: Packet Radio<br>");
      radio_link_state_html(b, interface);
      break;
    case OVERLAY_INTERFACE_ETHERNET:
      strbuf_puts(b, "Type: Ethernet<br>");
      break;
    case OVERLAY_INTERFACE_WIFI:
      strbuf_puts(b, "Type: Wifi<br>");
      break;
    default:
    case OVERLAY_INTERFACE_UNKNOWN:
      strbuf_puts(b, "Type: Unknown<br>");
  }
  switch(interface->ifconfig.socket_type){
    case SOCK_STREAM:
      strbuf_puts(b, "Socket: Stream<br>");
      break;
    case SOCK_DGRAM:
      {
	strbuf_puts(b, "Socket: DGram<br>");
	strbuf_sprintf(b, "Address: %s<br>", alloca_socket_address(&interface->address));
	strbuf_sprintf(b, "Broadcast Address: %s<br>", alloca_socket_address(&interface->destination->address));
      }
      break;
    case SOCK_FILE:
      strbuf_puts(b, "Socket: File<br>");
      break;
    case SOCK_EXT:
      {
	strbuf_puts(b, "Socket: External<br>");
	strbuf_sprintf(b, "Client: %s<br>", alloca_socket_address(&interface->address));
      }
      break;
  }
  strbuf_sprintf(b, "TX: %d<br>", interface->tx_count);
  strbuf_sprintf(b, "RX: %d<br>", interface->recv_count);
}

// create a socket with options common to all our UDP sockets
static int
overlay_bind_socket(const struct socket_address *addr){
  int fd;
  int reuseP = 1;
  int broadcastP = 1;
  int protocol;
  
  switch(addr->addr.sa_family){
  case AF_INET:
    protocol = PF_INET;
    break;
  case AF_UNIX:
    protocol = PF_UNIX;
    break;
  default:
    return WHYF("Unsupported address %s", alloca_socket_address(addr));
  }
  
  fd = esocket(protocol, SOCK_DGRAM, 0);
  if (fd < 0)
    return -1;
  
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseP, sizeof(reuseP)) < 0) {
    WHY_perror("setsockopt(SO_REUSEADR)");
    goto error;
  }
  
  #ifdef SO_REUSEPORT
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &reuseP, sizeof(reuseP)) < 0) {
      WHY_perror("setsockopt(SO_REUSEPORT)");
      goto error;
    }
  #endif
  
  if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &broadcastP, sizeof(broadcastP)) < 0) {
    WHY_perror("setsockopt(SO_BROADCAST)");
    goto error;
  }
  
  /* Automatically close socket on calls to exec().
   This makes life easier when we restart with an exec after receiving
   a bad signal. */
  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, NULL) | 
#ifdef FD_CLOEXEC
						FD_CLOEXEC
#else
						O_CLOEXEC
#endif
	);
  
  if (socket_bind(fd, addr))
    goto error;
  
  return fd;
  
error:
  close(fd);
  return -1;
}

static int overlay_bind_interface(overlay_interface *interface){
  if (interface->alarm.poll.fd>=0)
    return 0;
    
  // We might hear about an interface coming up, after the address is assigned, 
  // but before the routing table is updated.
  // So this bind might fail, which is ok. We just need to try again.
  interface->alarm.poll.fd = overlay_bind_socket(&interface->address);
  if (interface->alarm.poll.fd<0)
    return -1;
    
  DEBUGF2(packetrx, io, "Bound to %s", alloca_socket_address(&interface->address));
  interface->alarm.poll.events=POLLIN;
  watch(&interface->alarm);
  return 0;
}

// find an interface marked for use as a default internet route
overlay_interface * overlay_interface_get_default(){
  int i;
  for (i=0;i<OVERLAY_MAX_INTERFACES;i++){
    if (overlay_interfaces[i].state==INTERFACE_STATE_UP && overlay_interfaces[i].ifconfig.default_route)
      return &overlay_interfaces[i];
  }
  return NULL;
}

// find an interface that can send a packet to this IPv4 address
overlay_interface * overlay_interface_find(struct in_addr addr, int return_default){
  int i;
  overlay_interface *ret = NULL;


  for (i=0;i<OVERLAY_MAX_INTERFACES;i++){
    if (overlay_interfaces[i].state!=INTERFACE_STATE_UP)
      continue;
    
    if (overlay_interfaces[i].address.addr.sa_family == AF_INET
      && (overlay_interfaces[i].netmask.s_addr & addr.s_addr) == (overlay_interfaces[i].netmask.s_addr & overlay_interfaces[i].address.inet.sin_addr.s_addr)){

      DEBUGF(overlayinterfaces, "Found interface #%d for in_addr=0x%08x, interface mask=0x%08x, interface addr=0x%08x\n",
	     i,
	     addr.s_addr,
	     overlay_interfaces[i].netmask.s_addr,
	     overlay_interfaces[i].address.inet.sin_addr.s_addr
	    );

      return &overlay_interfaces[i];
    } else {
      DEBUGF(overlayinterfaces, "in_addr=0x%08x is not from interface #%d (interface mask=0x%08x, interface addr=0x%08x)\n",
	     addr.s_addr,i,
	     overlay_interfaces[i].netmask.s_addr,
	     overlay_interfaces[i].address.inet.sin_addr.s_addr
	    );
    }
    
    // check if this is a default interface
    if (return_default && overlay_interfaces[i].ifconfig.default_route) {
      ret=&overlay_interfaces[i];
      DEBUGF(overlayinterfaces, "in_addr=0x%08x is being deemed to default-route interface #%d (interface mask=0x%08x, interface addr=0x%08x)\n",
	     addr.s_addr,i,
	     overlay_interfaces[i].netmask.s_addr,
	     overlay_interfaces[i].address.inet.sin_addr.s_addr
	    );
    }
  }
  
  return ret;
}

// find an interface by name
overlay_interface * overlay_interface_find_name(const char *name){
  int i;
  for (i=0;i<OVERLAY_MAX_INTERFACES;i++){
    if (overlay_interfaces[i].state!=INTERFACE_STATE_UP)
      continue;
    if (strcasecmp(name, overlay_interfaces[i].name) == 0)
      return &overlay_interfaces[i];
  }
  return NULL;
}

// find an interface by name and address
overlay_interface * overlay_interface_find_name_addr(const char *name, struct socket_address *addr){
  int i;
  for(i = 0; i < OVERLAY_MAX_INTERFACES; i++){
    if (overlay_interfaces[i].state==INTERFACE_STATE_DOWN)
      continue;
    
    if (cmp_sockaddr(addr, &overlay_interfaces[i].address)==0
      && (!name || strcasecmp(overlay_interfaces[i].name, name)==0)){
      return &overlay_interfaces[i];
    }
  }
  
  return NULL;
}

// find an interface by name and socket type
overlay_interface * overlay_interface_find_name_type(const char *name, int socket_type){
  int i;
  for(i = 0; i < OVERLAY_MAX_INTERFACES; i++){
    if (overlay_interfaces[i].state==INTERFACE_STATE_DOWN)
      continue;
    
    if (strcasecmp(overlay_interfaces[i].name, name)==0 && 
      overlay_interfaces[i].ifconfig.socket_type == socket_type)
      return &overlay_interfaces[i];
  }
  
  return NULL;
}

static int interface_type_priority(int type)
{
  switch(type){
    case OVERLAY_INTERFACE_ETHERNET:
      return 1;
    case OVERLAY_INTERFACE_WIFI:
      return 2;
    case OVERLAY_INTERFACE_PACKETRADIO:
      return 4;
  }
  return 3;
}

// Which interface is better for routing packets?
// returns -1 to indicate the first is better, 0 for equal, 1 for the second
int overlay_interface_compare(overlay_interface *one, overlay_interface *two)
{
  if (one==two)
    return 0;
  int p1 = interface_type_priority(one->ifconfig.type);
  int p2 = interface_type_priority(two->ifconfig.type);
  if (p1<p2)
    return -1;
  if (p2<p1)
    return 1;
  return 0;
}

// OSX doesn't recieve broadcast packets on sockets bound to an interface's address
// So we have to bind a socket to INADDR_ANY to receive these packets.
static void
overlay_interface_read_any(struct sched_ent *alarm)
{
  if (alarm->poll.revents & POLLIN) {
    int plen=0;
    int recvttl=1;
    unsigned char packet[16384];
    overlay_interface *interface=NULL;
    struct socket_address recvaddr;
    recvaddr.addrlen = sizeof recvaddr.store;
    
    /* Read only one UDP packet per call to share resources more fairly, and also
     enable stats to accurately count packets received */
    plen = recvwithttl(alarm->poll.fd, packet, sizeof(packet), &recvttl, &recvaddr);
    if (plen == -1) {
      WHYF_perror("recvwithttl(%d,%p,%zu,&%d,%p(%s))",
	    alarm->poll.fd, packet, sizeof packet, recvttl,
	    &recvaddr, alloca_socket_address(&recvaddr)
	  );
      unwatch(alarm);
      close(alarm->poll.fd);
      return;
    }
    
    /* Try to identify the real interface that the packet arrived on */
    interface = overlay_interface_find(recvaddr.inet.sin_addr, 0);
    
    /* Drop the packet if we don't find a match */
    if (!interface){
      DEBUGF(overlayinterfaces, "Could not find matching interface for packet received from %s", inet_ntoa(recvaddr.inet.sin_addr));
      return;
    }
    packetOkOverlay(interface, packet, plen, &recvaddr);
  }
  if (alarm->poll.revents & (POLLHUP | POLLERR)) {
    INFO("Closing broadcast socket due to error");
    unwatch(alarm);
    close(alarm->poll.fd);
    alarm->poll.fd=-1;
  }  
}

/*
bind a socket to INADDR_ANY:port

On linux you can bind to the broadcast address to receive broadcast packets per interface [or subnet],
but then you can't receive unicast packets on the same socket.

On osx, you can only receive broadcast packets if you bind to INADDR_ANY.

So the most portable way to do this is to bind to each interface's IP address for sending broadcasts 
and receiving unicasts, and bind a separate socket to INADDR_ANY just for receiving broadcast packets.

Sending packets from INADDR_ANY would probably work, but gives us less control over which interfaces are sending packets.
But there may be some platforms that need some other combination for everything to work.
*/
static int overlay_interface_init_any(int port)
{
  if (sock_any.poll.fd>0){
    // Check the port number matches
    if (sock_any_addr.inet.sin_port != htons(port))
      return WHYF("Unable to listen to broadcast packets for ports %d & %d", 
	port, ntohs(sock_any_addr.inet.sin_port));
    
    return 0;
  }
  sock_any_addr.addrlen = sizeof(sock_any_addr.inet);
  sock_any_addr.inet.sin_family = AF_INET;
  sock_any_addr.inet.sin_port = htons(port);
  sock_any_addr.inet.sin_addr.s_addr = INADDR_ANY;

  sock_any.poll.fd = overlay_bind_socket(&sock_any_addr);
  if (sock_any.poll.fd<0)
    return -1;
  
  sock_any.poll.events=POLLIN;
  sock_any.function = overlay_interface_read_any;
  
  sock_any_stats.name="overlay_interface_read_any";
  sock_any.stats=&sock_any_stats;
  watch(&sock_any);
  return 0;
}

static void calc_next_tick(struct overlay_interface *interface)
{
  time_ms_t interval = interface->destination->ifconfig.tick_ms;
  // only tick every 5s if we have no neighbours here
  if (interval < 5000 && !link_interface_has_neighbours(interface))
    interval = 5000;
  
  time_ms_t next_tick = interface->destination->last_tx+interval;
  if (!interface->destination->ifconfig.tick_ms){
    next_tick=TIME_MS_NEVER_WILL;
  }
  time_ms_t next_allowed = limit_next_allowed(&interface->destination->transfer_limit);
  if (next_tick < next_allowed)
    next_tick = next_allowed;
  
  if (interface->ifconfig.socket_type==SOCK_FILE){
    time_ms_t next_read = gettime_ms()+10;
    if (next_tick > next_read)
      next_tick = next_read;
  }else if(interface->ifconfig.socket_type==SOCK_DGRAM && interface->alarm.poll.fd<0){
    time_ms_t bind_again = gettime_ms()+50;
    if (next_tick > bind_again)
      next_tick = bind_again;
  }
  
  interface->alarm.alarm = next_tick;
  interface->alarm.deadline=interface->alarm.alarm+interface->destination->ifconfig.tick_ms/2;
}

int overlay_destination_configure(struct network_destination *dest, const struct config_mdp_iftype *ifconfig)
{
  dest->ifconfig = *ifconfig;
  // How often do we announce ourselves on this interface?
  int tick_ms=-1;
  int packet_interval=-1;
  
  // hard coded defaults:
  switch(dest->interface->ifconfig.type){
    case OVERLAY_INTERFACE_PACKETRADIO:
      tick_ms = 15000;
      packet_interval = 1000;
      break;
    case OVERLAY_INTERFACE_ETHERNET:
      tick_ms = 500;
      packet_interval = 100;
      break;
    case OVERLAY_INTERFACE_WIFI:
      tick_ms = 500;
      packet_interval = 800;
      break;
    case OVERLAY_INTERFACE_UNKNOWN:
      tick_ms = 500;
      packet_interval = 100;
      break;
  }
  
  if (dest->ifconfig.tick_ms<0)
    dest->ifconfig.tick_ms = tick_ms;
  if (dest->ifconfig.packet_interval<0)
    dest->ifconfig.packet_interval = packet_interval;
    
  if (dest->ifconfig.packet_interval<0)
    return WHYF("Invalid packet interval %d specified for destination", 
      dest->ifconfig.packet_interval);
  if (dest->ifconfig.packet_interval==0){
    INFOF("Destination is not sending any traffic!");
    dest->ifconfig.tick_ms=0;
  }else if (!dest->ifconfig.send){
    INFOF("Destination is not sending any traffic!");
    dest->ifconfig.tick_ms=0;
  }else if (dest->ifconfig.tick_ms==0)
    INFOF("Destination is running tickless");
  
  if (dest->ifconfig.tick_ms<0)
    return WHYF("No tick interval specified for destination");
    
  if (dest->ifconfig.reachable_timeout_ms<0)
    dest->ifconfig.reachable_timeout_ms = tick_ms>0 ? tick_ms * 5 : 2500;
  
    
  limit_init(&dest->transfer_limit, dest->ifconfig.packet_interval);
  
  return 0;
}

int overlay_interface_configure(struct overlay_interface *interface, const struct config_network_interface *ifconfig)
{
  // copy ifconfig values
  interface->ifconfig = *ifconfig;
  overlay_destination_configure(interface->destination, &interface->ifconfig.broadcast);
  
  if (ifconfig->socket_type==SOCK_STREAM)
    interface->ifconfig.unicast.send=0;
  
  // schedule the first tick asap
  unschedule(&interface->alarm);
  calc_next_tick(interface);
  schedule(&interface->alarm);
  
  return 0;
}

/* Returns 0 if interface is successfully added.
 * Returns 1 if interface is not added (eg, dummy file does not exist).
 * Returns -1 in case of error (misconfiguration or system error).
 */
int
overlay_interface_init(const char *name, 
		       const struct socket_address *addr, 
		       const struct socket_address *netmask,
		       const struct socket_address *broadcast,
		       const struct config_network_interface *ifconfig)
{
  int cleanup_ret = -1;

  int interface_id=-1;
  int i;
  for (i=0; i<OVERLAY_MAX_INTERFACES; i++){
    if (overlay_interfaces[i].state==INTERFACE_STATE_DOWN){
      interface_id=i;
      break;
    }
  }
  if (interface_id==-1)
    return WHY("Too many interfaces -- Increase OVERLAY_MAX_INTERFACES");

  overlay_interface *const interface = &overlay_interfaces[interface_id];
  
  bzero(interface, sizeof(overlay_interface));
  interface->state=INTERFACE_STATE_DOWN;
  
  buf_strncpy_nul(interface->name, name);
  
  interface->destination = new_destination(interface);
  
  interface->alarm.poll.fd=-1;
  interface->tx_count=0;
  interface->recv_count=0;

  if (addr)
    interface->address = *addr;
  if (broadcast)
    interface->destination->address = *broadcast;
  interface->alarm.function = overlay_interface_poll;
  interface_poll_stats.name="overlay_interface_poll";
  interface->alarm.stats=&interface_poll_stats;
  
  switch(ifconfig->socket_type){
    case SOCK_DGRAM:
      if (ifconfig->broadcast.drop || ifconfig->unicast.drop || ifconfig->drop_packets)
	FATALF("Invalid interface definition. We only support dropping packets on dummy file interfaces");
      interface->netmask = netmask->inet.sin_addr;
      interface->local_echo = 1;
      
      overlay_bind_interface(interface);
      break;
      
    case SOCK_EXT:
      interface->local_echo = 0;
      break;
      
    case SOCK_STREAM:
    case SOCK_FILE:
    {
      char read_file[1024];
      interface->local_echo = ifconfig->point_to_point?0:1;
      if (!FORMF_SERVAL_TMP_PATH(read_file, "%s/%s", config.server.interface_path, ifconfig->file))
	return -1;
      if ((interface->alarm.poll.fd = open(read_file, O_APPEND|O_RDWR)) == -1) {
	if (errno == ENOENT && ifconfig->socket_type == SOCK_FILE) {
	  cleanup_ret = 1;
	  WARNF("dummy interface not enabled: %s does not exist", alloca_str_toprint(read_file));
	} else {
	  cleanup_ret = WHYF_perror("file interface not enabled: open(%s, O_APPEND|O_RDWR)", alloca_str_toprint(read_file));
	}
	goto cleanup;
      }
      
      if (ifconfig->type==OVERLAY_INTERFACE_PACKETRADIO)
	overlay_packetradio_setup_port(interface);
      
      switch (ifconfig->socket_type) {
      case SOCK_STREAM:
	radio_link_init(interface);
	interface->alarm.poll.events=POLLIN|POLLOUT;
	watch(&interface->alarm);
	break;
	
      case SOCK_FILE:
	/* Seek to end of file as initial reading point */
	interface->recv_offset = lseek(interface->alarm.poll.fd,0,SEEK_END);
	break;
      }
    }
  }
  
  if (overlay_interface_configure(interface, ifconfig)==-1)
    return -1;
  
  interface->state=INTERFACE_STATE_UP;
  monitor_tell_formatted(MONITOR_INTERFACE, "\nINTERFACE:%s:UP\n", interface->name);
  INFOF("Interface %s addr %s, is up",interface->name, alloca_socket_address(addr));
  
  directory_registration();
  
  INFOF("Allowing a maximum of %d packets every %"PRId64"ms",
        interface->destination->transfer_limit.burst_size,
        interface->destination->transfer_limit.burst_length);

  return 0;
  
cleanup:
  if (interface->alarm.poll.fd>=0){
    unwatch(&interface->alarm);
    close(interface->alarm.poll.fd);
    interface->alarm.poll.fd=-1;
  }
  interface->state=INTERFACE_STATE_DOWN;
  return cleanup_ret;
}

static void interface_read_dgram(struct overlay_interface *interface)
{
  int plen=0;
  unsigned char packet[8096];
  
  struct socket_address recvaddr;
  recvaddr.addrlen = sizeof recvaddr.store;

  /* Read only one UDP packet per call to share resources more fairly, and also
   enable stats to accurately count packets received */
  int recvttl=1;
  plen = recvwithttl(interface->alarm.poll.fd,packet, sizeof(packet), &recvttl, &recvaddr);
  if (plen == -1) {
    WHYF_perror("recvwithttl(%d,%p,%zu,&%d,%p(%s))",
	  interface->alarm.poll.fd, packet, sizeof packet, recvttl,
	  &recvaddr, alloca_socket_address(&recvaddr)
	);
    overlay_interface_close(interface);
    return;
  }
  packetOkOverlay(interface, packet, plen, &recvaddr);
}

struct file_packet{
  struct socket_address src_addr;
  struct socket_address dst_addr;
  int pid;
  int payload_length;
  
  /* TODO ? ;
   half-power beam height (uint16)
   half-power beam width (uint16)
   range in metres, centre beam (uint32)
   latitude (uint32)
   longitude (uint32)
   X/Z direction (uint16)
   Y direction (uint16)
   speed in metres per second (uint16)
   TX frequency in Hz, uncorrected for doppler (which must be done at the receiving end to take into account
   relative motion)
   coding method (use for doppler response etc) null terminated string
   */
  
  unsigned char payload[1400];
};

static int should_drop(struct overlay_interface *interface, struct socket_address *addr){
  if (interface->ifconfig.drop_packets>=100)
    return 1;
  
  if (cmp_sockaddr(addr, &interface->address)==0){
    if (interface->ifconfig.unicast.drop)
      return 1;
  }else if (cmp_sockaddr(addr, &interface->destination->address)==0){
    if (interface->ifconfig.broadcast.drop)
      return 1;
  }else
    return 1;
  
  if (interface->ifconfig.drop_packets <= 0)
    return 0;
  if (rand()%100 >= interface->ifconfig.drop_packets)
    return 0;
  return 1;
}

static void interface_read_file(struct overlay_interface *interface)
{
  IN();
  /* Grab packets, unpackage and dispatch frames to consumers */
  struct file_packet packet;
  
  /* Read from interface file */
  off_t length = lseek(interface->alarm.poll.fd, (off_t)0, SEEK_END);
  if (interface->recv_offset > length)
    FATALF("File shrunk? It shouldn't shrink! Ever");
    
  if (interface->recv_offset<length){
    int new_packets = (length - interface->recv_offset) / sizeof packet;
    if (new_packets > 20)
      WARNF("Getting behind, there are %d unread packets (%"PRId64" vs %"PRId64")", 
	  new_packets, (int64_t)interface->recv_offset, (int64_t)length);
  
    if (lseek(interface->alarm.poll.fd,interface->recv_offset,SEEK_SET) == -1){
      WHY_perror("lseek");
      OUT();
      return;
    }
    
    ssize_t nread = read(interface->alarm.poll.fd, &packet, sizeof packet);
    if (nread == -1){
      WHY_perror("read");
      OUT();
      return;
    }
    
    if (nread == sizeof packet) {
      DEBUGF(overlayinterfaces, "Read from interface %s (filesize=%"PRId64") at offset=%"PRId64": src_addr=%s dst_addr=%s pid=%d length=%d",
	     interface->name, (int64_t)length, (int64_t)interface->recv_offset,
	     alloca_socket_address(&packet.src_addr),
	     alloca_socket_address(&packet.dst_addr),
	     packet.pid,
	     packet.payload_length
	    );
      interface->recv_offset += nread;
      if (should_drop(interface, &packet.dst_addr) || (packet.pid == getpid() && !interface->local_echo)){
	DEBUGF(overlayinterfaces, "Ignoring packet from pid=%d src_addr=%s dst_addr=%s",
	       packet.pid,
	       alloca_socket_address(&packet.src_addr),
	       alloca_socket_address(&packet.dst_addr)
	      );
      }else{
	packetOkOverlay(interface, packet.payload, packet.payload_length, &packet.src_addr);
      }
    }
  }
  
  /* if there's no input, while we want to check for more soon,
   we need to allow all other low priority alarms to fire first,
   otherwise we'll dominate the scheduler without accomplishing anything */
  time_ms_t now = gettime_ms();
  if (interface->recv_offset>=length){
    if (now + 5 < interface->alarm.alarm){
      interface->alarm.alarm = now + 5;
      interface->alarm.deadline = interface->alarm.alarm + 500;
    }
  }else{
    /* keep reading new packets as fast as possible, 
     but don't completely prevent other high priority alarms */
    if (now < interface->alarm.alarm){
      interface->alarm.alarm = now;
      interface->alarm.deadline = interface->alarm.alarm + 100;
    }
  }
  OUT();
}

static void interface_read_stream(struct overlay_interface *interface){
  IN();
  unsigned char buffer[OVERLAY_INTERFACE_RX_BUFFER_SIZE];
  ssize_t nread = read(interface->alarm.poll.fd, buffer, OVERLAY_INTERFACE_RX_BUFFER_SIZE);
  if (nread == -1){
    WHY_perror("read");
    OUT();
    return;
  }
  
  
  int i;
  for (i=0;i<nread;i++)
    radio_link_decode(interface, buffer[i]);
    
  OUT();
}

static void overlay_interface_poll(struct sched_ent *alarm)
{
  struct overlay_interface *interface = (overlay_interface *)alarm;
  time_ms_t now = gettime_ms();
    
  if (alarm->poll.revents==0){
    alarm->alarm=TIME_MS_NEVER_WILL;
    
    if (interface->state==INTERFACE_STATE_UP && !radio_link_is_busy(interface)){
      
      // if we couldn't initially bind to our dgram socket, try again now
      if (interface->ifconfig.socket_type!=SOCK_DGRAM 
          || overlay_bind_interface(interface)==0){
	
	if (interface->destination->ifconfig.tick_ms>0
	    && interface->destination->ifconfig.send
	    && now >= interface->destination->last_tx+interface->destination->ifconfig.tick_ms)
	  overlay_send_tick_packet(interface->destination);
      
      }
      calc_next_tick(interface);
    }
    
    switch(interface->ifconfig.socket_type){
      case SOCK_STREAM:
	radio_link_tx(interface);
	return;
      case SOCK_DGRAM:
      case SOCK_EXT:
	break;
      case SOCK_FILE:
	interface_read_file(interface);
        now = gettime_ms();
	break;
    }
    
    unschedule(alarm);
    if (alarm->alarm!=TIME_MS_NEVER_WILL && interface->state==INTERFACE_STATE_UP) {
      if (alarm->alarm < now) {
        alarm->alarm = now;
	alarm->deadline = alarm->alarm + interface->destination->ifconfig.tick_ms / 2;
      }
      schedule(alarm);
    }
  }
  
  if (alarm->poll.revents & POLLOUT){
    switch(interface->ifconfig.socket_type){
      case SOCK_STREAM:
	radio_link_tx(interface);
	return;
      case SOCK_EXT:
      case SOCK_DGRAM:
      case SOCK_FILE:
	//XXX error? fatal?
	break;
    }
  }
  
  if (alarm->poll.revents & POLLIN) {
    switch(interface->ifconfig.socket_type){
      case SOCK_DGRAM:
	interface_read_dgram(interface);
	break;
      case SOCK_STREAM:
	interface_read_stream(interface);
	// if we read a valid heartbeat packet, we may be able to write more bytes now.
	if (interface->state==INTERFACE_STATE_UP){
	  radio_link_tx(interface);
	  return;
	}
	break;
      case SOCK_FILE:
	interface_read_file(interface);
	break;
      case SOCK_EXT:
	break;
    }
  }
  
  if (alarm->poll.revents & (POLLHUP | POLLERR)) {
    overlay_interface_close(interface);
  }  
}

static int send_local_packet(int fd, const uint8_t *bytes, size_t len, const char *folder, const char *file)
{
  struct socket_address addr;
  
  strbuf d = strbuf_local_buf(addr.local.sun_path);
  strbuf_path_join(d, folder, file, NULL);
  if (strbuf_overrun(d))
    return WHYF("interface file name overrun: %s", alloca_str_toprint(strbuf_str(d)));
  
  struct stat st;
  if (lstat(addr.local.sun_path, &st))
    return 1;
  if (!S_ISSOCK(st.st_mode))
    return 1;
    
  addr.local.sun_family = AF_UNIX;
  addr.addrlen = sizeof(addr.local.sun_family) + strlen(addr.local.sun_path)+1;
  
  ssize_t sent = sendto(fd, bytes, len, 0, 
	    &addr.addr, addr.addrlen);
  if (sent == -1){
    if (errno != EAGAIN && errno != EWOULDBLOCK)
      return WHYF_perror("sendto(%d, %zu, %s)", fd, len, alloca_socket_address(&addr));
  }
  return 0;
}

static int send_local_broadcast(int fd, const uint8_t *bytes, size_t len, const char *folder)
{
  if (send_local_packet(fd, bytes, len, folder, "broadcast")==0)
    return 0;
    
  DIR *dir;
  struct dirent *dp;
  if ((dir = opendir(folder)) == NULL) {
    WARNF_perror("opendir(%s)", alloca_str_toprint(folder));
    return -1;
  }
  while ((dp = readdir(dir)) != NULL) {
    send_local_packet(fd, bytes, len, folder, dp->d_name);
  }
  closedir(dir);
  return 0;
}

int overlay_broadcast_ensemble(struct network_destination *destination, struct overlay_buffer *buffer)
{
  assert(destination && destination->interface);
  const unsigned char *bytes = ob_ptr(buffer);
  size_t len = ob_position(buffer);
  
  struct overlay_interface *interface = destination->interface;
  destination->last_tx = gettime_ms();
  
  if (IF_DEBUG(packettx)) {
    DEBUGF(packettx, "Sending this packet via interface %s (len=%zu)",interface->name, len);
    DEBUG_packet_visualise(NULL, bytes, len);
  }

  if (interface->state!=INTERFACE_STATE_UP){
    ob_free(buffer);
    return WHYF("Cannot send to interface %s as it is down", interface->name);
  }

  if (IF_DEBUG(overlayinterfaces) || interface->ifconfig.debug)
    _DEBUGF_TAG("overlayinterfaces", "Sending %zu byte overlay frame on %s to %s [%s]", 
		(size_t)len, interface->name, alloca_socket_address(&destination->address),
		alloca_tohex(bytes, len>64?64:len)
	       );
      
  interface->tx_count++;
  
  switch(interface->ifconfig.socket_type){
    case SOCK_STREAM:
      return radio_link_queue_packet(interface, buffer);
      
    case SOCK_FILE:
    {
      struct file_packet packet={
	.src_addr = interface->address,
	.dst_addr = destination->address,
	.pid = getpid(),
      };
      
      if (len > sizeof packet.payload) {
	WARN("Truncating long packet to fit within MTU byte limit for dummy interface");
	len = sizeof packet.payload;
      }
      packet.payload_length = len;
      bcopy(bytes, packet.payload, len);
      ob_free(buffer);
      /* This lseek() is unneccessary because the dummy file is opened in O_APPEND mode.  It's
       only purpose is to find out the offset to print in the DEBUG statement.  It is vulnerable
       to a race condition with other processes appending to the same file. */
      if (IF_DEBUG(overlayinterfaces)) {
	off_t fsize = lseek(interface->alarm.poll.fd, (off_t) 0, SEEK_END);
	if (fsize == -1) {
	  /* Don't complain if the seek fails because we are writing to a pipe or device that does
	    not support seeking. */
	  if (errno != ESPIPE)
	    return WHY_perror("lseek");
	  DEBUGF(overlayinterfaces, "Write to interface %s at offset unknown: src_addr=%s dst_addr=%s pid=%d length=%d",
		interface->name,
		alloca_socket_address(&packet.src_addr),
		alloca_socket_address(&packet.dst_addr),
		packet.pid,
		packet.payload_length
	      );
	} else
	  DEBUGF(overlayinterfaces, "Write to interface %s at offset=%"PRId64": src_addr=%s dst_addr=%s pid=%d length=%d",
		interface->name, (int64_t)fsize,
		alloca_socket_address(&packet.src_addr),
		alloca_socket_address(&packet.dst_addr),
		packet.pid,
		packet.payload_length
	      );
      }
      ssize_t nwrite = write(interface->alarm.poll.fd, &packet, sizeof(packet));
      if (nwrite == -1)
	return WHY_perror("write");
      if (nwrite != sizeof(packet))
	return WHYF("only wrote %d of %d bytes", (int)nwrite, (int)sizeof(packet));
      return 0;
    }
    case SOCK_EXT:
    {
      mdp_send_external_packet(interface, &destination->address, bytes, (size_t)len);
      ob_free(buffer);
      return 0;
    }
    case SOCK_DGRAM:
    {
      // check that we have bound the interface
      if (overlay_bind_interface(interface)==-1)
	return -1;
      
      set_nonblock(interface->alarm.poll.fd);
      if (destination->address.addr.sa_family == AF_UNIX
	&& !destination->unicast){
	// find all sockets in this folder and send to them
	send_local_broadcast(interface->alarm.poll.fd, 
		  bytes, (size_t)len, destination->address.local.sun_path);
      }else{
	ssize_t sent = sendto(interface->alarm.poll.fd, 
		  bytes, (size_t)len, 0, 
		  &destination->address.addr, destination->address.addrlen);
	if (sent == -1){
	  if (errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=ENOENT && errno!=ENOTDIR){
	    WHYF_perror("sendto(fd=%d,len=%zu,addr=%s) on interface %s",
		interface->alarm.poll.fd,
		(size_t)len,
		alloca_socket_address(&destination->address),
		interface->name
	      );
	    
	    // if we had any error while sending broadcast packets,
	    // it could be because the interface is coming down
	    // or there might be some socket error that we can't fix.
	    // So bring the interface down, and scan for network changes soon
	    if (destination == interface->destination){
	      overlay_interface_close(interface);
	      rescan_soon();
	    }
	  }
	  ob_free(buffer);
	  return -1;
	}
      }
      set_block(interface->alarm.poll.fd);
      ob_free(buffer);
      return 0;
    }
      
    default:
      ob_free(buffer);
      return WHY("Unsupported socket type");
  }
}

static const struct config_network_interface *find_interface_config(const char *name, int socket_type)
{
  // Find a matching non-dummy interface rule.
  unsigned i;
  for (i = 0; i < config.interfaces.ac; ++i) {
    const struct config_network_interface *ifconfig = &config.interfaces.av[i].value;
    if (ifconfig->socket_type==socket_type) {
      unsigned j;
      for (j = 0; j < ifconfig->match.patc; ++j){
	if (fnmatch(ifconfig->match.patv[j], name, 0) == 0)
	  return ifconfig;
      }
    }
  }
  return NULL;
}

/* Register the real interface, or update the existing interface registration. */
int
overlay_interface_register(const char *name,
			   struct socket_address *addr,
			   const struct socket_address *netmask,
			   struct socket_address *broadcast)
{
  // Find the matching non-dummy interface rule.
  const struct config_network_interface *ifconfig = find_interface_config(name, SOCK_DGRAM);
  if (!ifconfig) {
    DEBUGF(overlayinterfaces, "Interface %s does not match any rule", name);
    return 0;
  }
  if (ifconfig->exclude) {
    DEBUGF(overlayinterfaces, "Interface %s is explicitly excluded", name);
    return 0;
  }
  
  if (addr->addr.sa_family==AF_INET)
    addr->inet.sin_port = htons(ifconfig->port);
  if (broadcast->addr.sa_family==AF_INET)
    broadcast->inet.sin_port = htons(ifconfig->port);

  struct overlay_interface *interface = overlay_interface_find_name_addr(name, addr);
  // nothing to do if a matching interface is already up
  if (interface)
    return 0;
    
  /* New interface, so register it */
  if (overlay_interface_init(name, addr, netmask, broadcast, ifconfig))
    return WHYF("Could not initialise newly seen interface %s", name);

  overlay_interface_init_any(ifconfig->port);
  inet_up_count++;
  
  return 0;
}

#ifdef HAVE_LINUX_NETLINK_H

static int interface_unregister(const char *name, 
			   struct socket_address *addr
)
{
  // Find the matching non-dummy interface rule.
  const struct config_network_interface *ifconfig = find_interface_config(name, SOCK_DGRAM);
  if (!ifconfig)
    return 0;
    
  if (addr->addr.sa_family==AF_INET)
    addr->inet.sin_port = htons(ifconfig->port);
  
  struct overlay_interface *interface = overlay_interface_find_name_addr(name, addr);
  if (interface)
    overlay_interface_close(interface);
    
  return 0;
}

DEFINE_ALARM(netlink_poll);
void netlink_poll(struct sched_ent *alarm)
{
  uint8_t buff[4096];
  ssize_t len = recv(alarm->poll.fd, buff, sizeof buff, 0);
  if (len<=0)
    return;
    
  DEBUGF(overlayinterfaces, "recv(%d) len %u", alarm->poll.fd, len);
    
  struct nlmsghdr *nlh = (struct nlmsghdr *)buff;
  for (nlh = (struct nlmsghdr *)buff; (NLMSG_OK (nlh, len)) && (nlh->nlmsg_type != NLMSG_DONE); nlh = NLMSG_NEXT(nlh, len)){
    
    switch(nlh->nlmsg_type){
      case RTM_NEWADDR:
      case RTM_DELADDR:
      {
	struct ifaddrmsg *ifa = (struct ifaddrmsg *) NLMSG_DATA (nlh);
	
	// ignore loopback addresses
	if (ifa->ifa_scope == RT_SCOPE_HOST)
	  continue;
	  
	struct rtattr *rth = IFA_RTA (ifa);
	int rtl = IFA_PAYLOAD (nlh);
	
	// ifa->ifa_family;
	// ifa->ifa_prefixlen;
	const char *name=NULL;
	
	struct socket_address addr, broadcast, netmask_addr;
	bzero(&addr, sizeof(addr));
	bzero(&broadcast, sizeof(broadcast));
	bzero(&netmask_addr, sizeof(netmask_addr));
	
	addr.addr.sa_family = broadcast.addr.sa_family = netmask_addr.addr.sa_family = ifa->ifa_family;
	
	if (ifa->ifa_family == AF_INET){
	  addr.addrlen = broadcast.addrlen = netmask_addr.addrlen = sizeof(addr.inet);
	}else{
	  DEBUGF(overlayinterfaces, "Ignoring family %d", ifa->ifa_family);
	  continue;
	}
	
	for (;rtl && RTA_OK (rth, rtl); rth = RTA_NEXT (rth,rtl)){
	  void *data = RTA_DATA(rth);
	  
	  switch(rth->rta_type){
	    case IFA_LOCAL:
	      addr.inet.sin_addr.s_addr = *((uint32_t *)data);
	      break;
	    case IFA_LABEL:
	      name = RTA_DATA(rth);
	      break;
	    case IFA_BROADCAST:
	      broadcast.inet.sin_addr.s_addr = *((uint32_t *)data);
	      break;
	  }
	}
	
	if (!name){
	  WARNF_perror("Interface name not provided by IFA_LABEL");
	  continue;
	}
	
	{
	  //calculate netmask
	  unsigned prefix = ifa->ifa_prefixlen;
	  if (prefix>32) 
	    prefix=32;
	  char *c = (char *)&netmask_addr.inet.sin_addr.s_addr;
	  unsigned i;
	  for (i=0;i<(prefix/8);i++)
	    *c++ = 0xFF;
	  if (prefix %8)
	    *c = 0xFF << (8 - (prefix %8));
	}
	
	if (nlh->nlmsg_type==RTM_NEWADDR){
	  DEBUGF(overlayinterfaces, "New addr %s, %s, %s, %s", 
	    name,
	    alloca_socket_address(&addr),
	    alloca_socket_address(&broadcast),
	    alloca_socket_address(&netmask_addr)
	  );
	  overlay_interface_register(name, &addr, &netmask_addr, &broadcast);
	}else if (nlh->nlmsg_type==RTM_DELADDR){
	  DEBUGF(overlayinterfaces, "Del addr %s, %s", 
	    name,
	    alloca_socket_address(&addr)
	  );
	  interface_unregister(name, &addr);
	}
	break;
      }
    }
  }
}

static int netlink_socket()
{
  int sock = esocket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
  if (sock<0)
    return -1;
    
  struct sockaddr_nl addr;
  memset (&addr,0,sizeof(addr));
  addr.nl_family = AF_NETLINK;
  addr.nl_groups = RTMGRP_IPV4_IFADDR;
  
  if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1)
    return WHYF_perror("bind(%d,AF_NETLINK,%lu)", sock, (unsigned long)sizeof(addr));
    
  DEBUGF(overlayinterfaces, "bind(%d,AF_NETLINK,%lu)", sock, (unsigned long)sizeof(addr));
  
  return sock;
}

static int netlink_send_get()
{
  struct {
    struct nlmsghdr n;
    struct ifaddrmsg r;
  } req;
  
  memset(&req, 0, sizeof(req));
  req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;
  req.n.nlmsg_type = RTM_GETADDR;
  req.r.ifa_family = AF_INET;
  struct rtattr *rta = (struct rtattr *)(((char *)&req) + NLMSG_ALIGN(req.n.nlmsg_len));
  rta->rta_len = RTA_LENGTH(4);
  
  int fd = ALARM_STRUCT(netlink_poll).poll.fd;
  if (fd<0)
    return -1;
  if (send(fd, &req, req.n.nlmsg_len, 0)<0)
    return WHYF_perror("send(%d)", fd);
  
  DEBUG(overlayinterfaces, "Sent RTM_GETADDR");
  return 0;
}

// send a request to the kernel to get all interface addresses now
// eg on config change
static int netlink_init()
{
  struct sched_ent *alarm=&ALARM_STRUCT(netlink_poll);
  if (!is_watching(alarm)){
    alarm->poll.fd = netlink_socket();
    if (alarm->poll.fd<0)
      return -1;
    
    alarm->poll.events = POLLIN;
    watch(alarm);
  }
  
  return 0;
}

#else

// poll the OS's network interfaces
DEFINE_ALARM(overlay_interface_discover);
void overlay_interface_discover(struct sched_ent *alarm)
{
  // Register new real interfaces
  int no_route = 1;
#ifdef HAVE_IFADDRS_H
  if (no_route != 0)
    no_route = doifaddrs();
#endif
#ifdef SIOCGIFCONF
  if (no_route != 0)
    no_route = lsif();
#endif
#ifdef linux
  if (no_route != 0)
    no_route = scrapeProcNetRoute();
#endif
  if (no_route != 0) {
    FATAL("Unable to get any interface information");
  }

  alarm->alarm = gettime_ms()+5000;
  alarm->deadline = alarm->alarm + 10000;
  schedule(alarm);
}

#endif

static void file_interface_init(const struct config_network_interface *ifconfig)
{
  struct socket_address addr, netmask, broadcast;
  bzero(&addr, sizeof addr);
  bzero(&netmask, sizeof addr);
  bzero(&broadcast, sizeof broadcast);
  
  switch(ifconfig->socket_type){
  case SOCK_FILE:
    // use a fake inet address
    addr.addrlen=sizeof addr.inet;
    addr.inet.sin_family=AF_INET;
    addr.inet.sin_port=htons(ifconfig->port);
    addr.inet.sin_addr=ifconfig->dummy_address;

    netmask.addrlen=sizeof addr.inet;
    netmask.inet.sin_family=AF_INET;
    netmask.inet.sin_port=htons(ifconfig->port);
    netmask.inet.sin_addr=ifconfig->dummy_netmask;
    
    broadcast.addrlen=sizeof addr.inet;
    broadcast.inet.sin_family=AF_INET;
    broadcast.inet.sin_port=htons(ifconfig->port);
    broadcast.inet.sin_addr.s_addr=ifconfig->dummy_address.s_addr | ~ifconfig->dummy_netmask.s_addr;
    break;
    
  case SOCK_STREAM:
    break;
    
  case SOCK_DGRAM:
    {
      // use a local dgram socket
      // no abstract sockets for now
      if (!FORMF_SERVAL_RUN_PATH(addr.local.sun_path, "%s/%s", config.server.interface_path, ifconfig->file))
	return;
      
      unlink(addr.local.sun_path);
      addr.local.sun_family=AF_UNIX;
      size_t len = strlen(addr.local.sun_path);
      
      addr.addrlen=sizeof addr.local.sun_family + len + 1;
      
      broadcast = addr;
      while(len && broadcast.local.sun_path[len]!='/')
	broadcast.local.sun_path[len--]='\0';
      broadcast.addrlen = sizeof addr.local.sun_family + len + 2;
      break;
    }
    
  default:
    // ignore
    return;
  }
  
  overlay_interface_init(ifconfig->file, &addr, &netmask, &broadcast, ifconfig);
}

static void rescan_soon(){
#ifdef HAVE_LINUX_NETLINK_H
  // start listening for network changes & request current interface addresses
  if (netlink_init()<0)
    return;
  netlink_send_get();
#else
  // re-check all interfaces periodically
  time_ms_t now = gettime_ms();
  RESCHEDULE(&ALARM_STRUCT(overlay_interface_discover), now, now, now);
#endif
}

void overlay_interface_config_change()
{
  unsigned i;
  int real_interface = 0;
  
  // bring down any interface that no longer matches configuration
  for (i = 0; i < OVERLAY_MAX_INTERFACES; i++){
    if (overlay_interfaces[i].state!=INTERFACE_STATE_UP ||
      overlay_interfaces[i].ifconfig.socket_type == SOCK_EXT)
      continue;
	
    const struct config_network_interface *ifconfig = find_interface_config(
      overlay_interfaces[i].name, 
      overlay_interfaces[i].ifconfig.socket_type
    );
    
    if (!ifconfig || ifconfig->exclude){
      overlay_interface_close(&overlay_interfaces[i]);
      continue;
    }
  }
  
  // create dummy file or AF_UNIX interfaces
  for (i = 0; i < config.interfaces.ac; ++i) {
    const struct config_network_interface *ifconfig = &config.interfaces.av[i].value;
    if (ifconfig->exclude)
      continue;
    
    // ignore real interfaces, we'll deal with them later
    if (!*ifconfig->file) {
      real_interface = 1;
      continue;
    }
    
    overlay_interface *interface = overlay_interface_find_name_type(ifconfig->file, ifconfig->socket_type);
    // ignore interfaces that are already up
    if (interface)
      continue;
    
    // New file interface, so register it.
    file_interface_init(ifconfig);
  }
  
  if (real_interface)
    rescan_soon();
}

void logServalPacket(int level, struct __sourceloc __whence, const char *message, const unsigned char *packet, size_t len) {
  struct mallocbuf mb = STRUCT_MALLOCBUF_NULL;
  if (!message) message="<no message>";
  if (serval_packetvisualise_xpf(XPRINTF_MALLOCBUF(&mb), message, packet, len) == -1)
    WHY("serval_packetvisualise() failed");
  else if (mb.buffer == NULL)
    WHYF("serval_packetvisualise() output buffer missing, message=%s packet=%p len=%lu", alloca_toprint(-1, message, strlen(message)), packet, (long unsigned int)len);
  else
    logString(level, __whence, mb.buffer);
  if (mb.buffer)
    free(mb.buffer);
}
