/*
Serval Distributed Numbering Architecture (DNA)
Copyright (C) 2010 Paul Gardner-Stephen
 
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

#ifdef HAVE_IFADDRS_H
#include <ifaddrs.h>
#endif

int overlay_ready=0;
overlay_interface overlay_interfaces[OVERLAY_MAX_INTERFACES];
int overlay_last_interface_number=-1;

struct profile_total interface_poll_stats;

struct sched_ent sock_any;
struct socket_address sock_any_addr;
struct profile_total sock_any_stats;

static void overlay_interface_poll(struct sched_ent *alarm);

static void
overlay_interface_close(overlay_interface *interface){
  INFOF("Interface %s addr %s is down", 
	interface->name, alloca_socket_address(&interface->address));
  if (interface->address.addr.sa_family == AF_UNIX)
    unlink(interface->address.local.sun_path);
  link_interface_down(interface);
  unschedule(&interface->alarm);
  if (is_watching(&interface->alarm))
    unwatch(&interface->alarm);
  close(interface->alarm.poll.fd);
  if (interface->radio_link_state)
    radio_link_free(interface);
  interface->alarm.poll.fd=-1;
  interface->state=INTERFACE_STATE_DOWN;
}

void overlay_interface_close_all()
{
  unsigned i;
  for (i=0;i<OVERLAY_MAX_INTERFACES;i++){
    if (overlay_interfaces[i].state == INTERFACE_STATE_UP)
      overlay_interface_close(&overlay_interfaces[i]);
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
  switch(interface->type){
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
  switch(interface->socket_type){
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

// find an interface marked for use as a default internet route
overlay_interface * overlay_interface_get_default(){
  int i;
  for (i=0;i<OVERLAY_MAX_INTERFACES;i++){
    if (overlay_interfaces[i].state==INTERFACE_STATE_UP && overlay_interfaces[i].default_route)
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
      return &overlay_interfaces[i];
    }
    
    // check if this is a default interface
    if (return_default && overlay_interfaces[i].default_route)
      ret=&overlay_interfaces[i];
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
  int p1 = interface_type_priority(one->type);
  int p2 = interface_type_priority(two->type);
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
      if (config.debug.overlayinterfaces)
	DEBUGF("Could not find matching interface for packet received from %s", inet_ntoa(recvaddr.inet.sin_addr));
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

// bind a socket to INADDR_ANY:port
// for now, we don't have a graceful close for this interface but it should go away when the process dies
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

static int
overlay_interface_init_socket(overlay_interface *interface)
{
  /*
   On linux you can bind to the broadcast address to receive broadcast packets per interface [or subnet],
   but then you can't receive unicast packets on the same socket.
   
   On osx, you can only receive broadcast packets if you bind to INADDR_ANY.
   
   So the most portable way to do this is to bind to each interface's IP address for sending broadcasts 
   and receiving unicasts, and bind a separate socket to INADDR_ANY just for receiving broadcast packets.
   
   Sending packets from INADDR_ANY would probably work, but gives us less control over which interfaces are sending packets.
   But there may be some platforms that need some other combination for everything to work.
   */
  
  overlay_interface_init_any(interface->port);
  
  interface->alarm.poll.fd = overlay_bind_socket(&interface->address);
      
  if (interface->alarm.poll.fd<0){
    interface->state=INTERFACE_STATE_DOWN;
    return WHYF("Failed to bind interface %s", interface->name);
  }
  
  if (config.debug.packetrx || config.debug.io)
    DEBUGF("Bound to %s", alloca_socket_address(&interface->address));

  interface->alarm.poll.events=POLLIN;
  watch(&interface->alarm);
  
  return 0;
}

/* Returns 0 if interface is successfully added.
 * Returns 1 if interface is not added (eg, dummy file does not exist).
 * Returns -1 in case of error (misconfiguration or system error).
 */
static int
overlay_interface_init(const char *name, struct socket_address *addr, 
		       struct socket_address *broadcast,
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
  
  strncpy(interface->name, name, sizeof interface->name);
  
  // copy ifconfig values
  interface->drop_broadcasts = ifconfig->drop_broadcasts;
  interface->drop_unicasts = ifconfig->drop_unicasts;
  interface->drop_packets = ifconfig->drop_packets;
  interface->port = ifconfig->port;
  interface->type = ifconfig->type;
  interface->send_broadcasts = ifconfig->send_broadcasts;
  interface->prefer_unicast = ifconfig->prefer_unicast;
  interface->default_route = ifconfig->default_route;
  interface->socket_type = ifconfig->socket_type;
  interface->uartbps = ifconfig->uartbps;
  interface->ctsrts = ifconfig->ctsrts;
  set_destination_ref(&interface->destination, NULL);
  interface->destination = new_destination(interface, ifconfig->encapsulation);
  
  /* Pick a reasonable default MTU.
     This will ultimately get tuned by the bandwidth and other properties of the interface */
  interface->mtu = 1200;
  interface->point_to_point = ifconfig->point_to_point;
  
  interface->alarm.poll.fd=0;
  interface->debug = ifconfig->debug;
  interface->tx_count=0;
  interface->recv_count=0;

  // How often do we announce ourselves on this interface?
  int tick_ms=-1;
  int packet_interval=-1;
  int reachable_timeout_ms = -1;

  // hard coded defaults:
  switch (ifconfig->type) {
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
  // configurable defaults per interface
  {
    int i = config_mdp_iftypelist__get(&config.mdp.iftype, &ifconfig->type);
    if (i != -1){
      if (config.mdp.iftype.av[i].value.tick_ms>=0)
	tick_ms = config.mdp.iftype.av[i].value.tick_ms;
      if (config.mdp.iftype.av[i].value.packet_interval>=0)
	packet_interval=config.mdp.iftype.av[i].value.packet_interval;
      if (config.mdp.iftype.av[i].value.reachable_timeout_ms >= 0)
	reachable_timeout_ms = config.mdp.iftype.av[i].value.reachable_timeout_ms;
    }
  }
  // specific value for this interface
  if (ifconfig->mdp.tick_ms>=0)
    tick_ms = ifconfig->mdp.tick_ms;
  if (ifconfig->mdp.packet_interval>=0)
    packet_interval=ifconfig->mdp.packet_interval;
  if (ifconfig->mdp.reachable_timeout_ms >= 0)
    reachable_timeout_ms = ifconfig->mdp.reachable_timeout_ms;
  
  if (packet_interval<0)
    return WHYF("Invalid packet interval %d specified for interface %s", packet_interval, name);
  if (packet_interval==0){
    INFOF("Interface %s is not sending any traffic!", name);
    tick_ms=0;
  }else if (!interface->send_broadcasts){
    INFOF("Interface %s is not sending any broadcast traffic!", name);
  }else if (tick_ms==0)
    INFOF("Interface %s is running tickless", name);
  
  if (tick_ms<0)
    return WHYF("No tick interval specified for interface %s", name);

  interface->destination->tick_ms = tick_ms;
  interface->destination->reachable_timeout_ms = reachable_timeout_ms >= 0 ? reachable_timeout_ms : tick_ms > 0 ? tick_ms * 5 : 2500;
  
  limit_init(&interface->destination->transfer_limit, packet_interval);

  if (addr)
    interface->address = *addr;
  if (broadcast)
    interface->destination->address = *broadcast;
  
  interface->alarm.function = overlay_interface_poll;
  interface_poll_stats.name="overlay_interface_poll";
  interface->alarm.stats=&interface_poll_stats;
  
  if (ifconfig->socket_type == SOCK_DGRAM){
    if (ifconfig->drop_broadcasts || ifconfig->drop_unicasts || ifconfig->drop_packets)
      FATALF("Invalid interface definition. We only support dropping packets on dummy file interfaces");
    interface->local_echo = 1;
    
    if (overlay_interface_init_socket(interface))
      return WHY("overlay_interface_init_socket() failed");
  }else{
    char read_file[1024];
    interface->local_echo = interface->point_to_point?0:1;
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
  
  // schedule the first tick asap
  interface->alarm.alarm=gettime_ms();
  interface->alarm.deadline=interface->alarm.alarm;
  schedule(&interface->alarm);
  interface->state=INTERFACE_STATE_UP;
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
  if (interface->drop_packets>=100)
    return 1;
  
  if (cmp_sockaddr(addr, &interface->address)==0){
    if (interface->drop_unicasts)
      return 1;
  }else if (cmp_sockaddr(addr, &interface->destination->address)==0){
    if (interface->drop_broadcasts)
      return 1;
  }else
    return 1;
  
  if (interface->drop_packets <= 0)
    return 0;
  if (rand()%100 >= interface->drop_packets)
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
  int new_packets = (length - interface->recv_offset) / sizeof packet;
  if (new_packets > 20)
    WARNF("Getting behind, there are %d unread packets (%"PRId64" vs %"PRId64")", 
	new_packets, (int64_t)interface->recv_offset, (int64_t)length);
  
  if (interface->recv_offset<length){
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
      if (config.debug.overlayinterfaces)
	DEBUGF("Read from interface %s (filesize=%"PRId64") at offset=%"PRId64": src_addr=%s dst_addr=%s pid=%d length=%d",
	      interface->name, (int64_t)length, (int64_t)interface->recv_offset,
	      alloca_socket_address(&packet.src_addr),
	      alloca_socket_address(&packet.dst_addr),
	      packet.pid,
	      packet.payload_length
	    );
      interface->recv_offset += nread;
      if (should_drop(interface, &packet.dst_addr) || (packet.pid == getpid() && !interface->local_echo)){
	if (config.debug.packetrx)
	  DEBUGF("Ignoring packet from pid=%d src_addr=%s dst_addr=%s",
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
    if (interface->alarm.alarm == -1 || now + 5 < interface->alarm.alarm){
      interface->alarm.alarm = now + 5;
      interface->alarm.deadline = interface->alarm.alarm + 500;
    }
  }else{
    /* keep reading new packets as fast as possible, 
     but don't completely prevent other high priority alarms */
    if (interface->alarm.alarm == -1 || now < interface->alarm.alarm){
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
    alarm->alarm=-1;
    
    if (interface->state==INTERFACE_STATE_UP 
      && interface->destination->tick_ms>0
      && interface->send_broadcasts
      && !radio_link_is_busy(interface)){
      
      if (now >= interface->destination->last_tx+interface->destination->tick_ms)
        overlay_send_tick_packet(interface->destination);
	
      alarm->alarm=interface->destination->last_tx+interface->destination->tick_ms;
      alarm->deadline=alarm->alarm+interface->destination->tick_ms/2;
    }
    
    switch(interface->socket_type){
      case SOCK_STREAM:
	radio_link_tx(interface);
	return;
      case SOCK_DGRAM:
	break;
      case SOCK_FILE:
	interface_read_file(interface);
        now = gettime_ms();
	break;
    }
    
    unschedule(alarm);
    if (alarm->alarm!=-1 && interface->state==INTERFACE_STATE_UP) {
      if (alarm->alarm < now)
        alarm->alarm = now;
      schedule(alarm);
    }
  }
  
  if (alarm->poll.revents & POLLOUT){
    switch(interface->socket_type){
      case SOCK_STREAM:
	radio_link_tx(interface);
	return;
      case SOCK_DGRAM:
      case SOCK_FILE:
	//XXX error? fatal?
	break;
    }
  }
  
  if (alarm->poll.revents & POLLIN) {
    switch(interface->socket_type){
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
    }
  }
  
  if (alarm->poll.revents & (POLLHUP | POLLERR)) {
    overlay_interface_close(interface);
  }  
}

static int send_local_broadcast(int fd, const uint8_t *bytes, size_t len, struct socket_address *address)
{
  DIR *dir;
  struct dirent *dp;
  if ((dir = opendir(address->local.sun_path)) == NULL) {
    WARNF_perror("opendir(%s)", alloca_str_toprint(address->local.sun_path));
    return -1;
  }
  while ((dp = readdir(dir)) != NULL) {
    struct socket_address addr;
    
    strbuf d = strbuf_local(addr.local.sun_path, sizeof addr.local.sun_path);
    strbuf_path_join(d, address->local.sun_path, dp->d_name, NULL);
    if (strbuf_overrun(d)){
      WHYF("interface file name overrun: %s", alloca_str_toprint(strbuf_str(d)));
      continue;
    }
    
    struct stat st;
    if (lstat(addr.local.sun_path, &st)) {
      WARNF_perror("stat(%s)", alloca_str_toprint(addr.local.sun_path));
      continue;
    }
    
    if (S_ISSOCK(st.st_mode)){
      addr.local.sun_family = AF_UNIX;
      addr.addrlen = sizeof(addr.local.sun_family) + strlen(addr.local.sun_path)+1;
      
      ssize_t sent = sendto(fd, bytes, len, 0, 
		&addr.addr, addr.addrlen);
      if (sent == -1)
	WHYF_perror("sendto(%d, %zu, %s)", fd, len, alloca_socket_address(&addr));
    }
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
  
  if (config.debug.packettx){
    DEBUGF("Sending this packet via interface %s (len=%zu)",interface->name, len);
    DEBUG_packet_visualise(NULL, bytes, len);
  }

  if (interface->state!=INTERFACE_STATE_UP){
    ob_free(buffer);
    return WHYF("Cannot send to interface %s as it is down", interface->name);
  }

  if (interface->debug)
    DEBUGF("Sending on %s, len %zu: %s", interface->name, len, alloca_tohex(bytes, len>64?64:len));

  interface->tx_count++;
  
  switch(interface->socket_type){
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
      if (config.debug.overlayinterfaces) {
	off_t fsize = lseek(interface->alarm.poll.fd, (off_t) 0, SEEK_END);
	if (fsize == -1) {
	  /* Don't complain if the seek fails because we are writing to a pipe or device that does
	    not support seeking. */
	  if (errno != ESPIPE)
	    return WHY_perror("lseek");
	  DEBUGF("Write to interface %s at offset unknown: src_addr=%s dst_addr=%s pid=%d length=%d",
		interface->name,
		alloca_sockaddr(&packet.src_addr, sizeof packet.src_addr),
		alloca_sockaddr(&packet.dst_addr, sizeof packet.dst_addr),
		packet.pid,
		packet.payload_length
	      );
	} else
	  DEBUGF("Write to interface %s at offset=%"PRId64": src_addr=%s dst_addr=%s pid=%d length=%d",
		interface->name, (int64_t)fsize,
		alloca_sockaddr(&packet.src_addr, sizeof packet.src_addr),
		alloca_sockaddr(&packet.dst_addr, sizeof packet.dst_addr),
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
      
    case SOCK_DGRAM:
    {
      if (config.debug.overlayinterfaces) 
	DEBUGF("Sending %zu byte overlay frame on %s to %s", 
	  (size_t)len, interface->name, alloca_socket_address(&destination->address));
      
      set_nonblock(interface->alarm.poll.fd);
      if (destination->address.addr.sa_family == AF_UNIX
	&& !destination->unicast){
	// find all sockets in this folder and send to them
	send_local_broadcast(interface->alarm.poll.fd, 
		  bytes, (size_t)len, &destination->address);
      }else{
	ssize_t sent = sendto(interface->alarm.poll.fd, 
		  bytes, (size_t)len, 0, 
		  &destination->address.addr, destination->address.addrlen);
	if (sent == -1){
	  WHYF_perror("sendto(fd=%d,len=%zu,addr=%s) on interface %s",
	      interface->alarm.poll.fd,
	      (size_t)len,
	      alloca_socket_address(&destination->address),
	      interface->name
	    );
	  // close the interface if we had any error while sending broadcast packets,
	  // unicast packets should not bring the interface down
	  // TODO mark unicast destination as failed?
	  if (destination == interface->destination)
	    overlay_interface_close(interface);
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

/* Register the real interface, or update the existing interface registration. */
int
overlay_interface_register(char *name,
			   struct socket_address *addr,
			   struct socket_address *broadcast)
{
  // Find the matching non-dummy interface rule.
  const struct config_network_interface *ifconfig = NULL;
  unsigned i;
  for (i = 0; i < config.interfaces.ac; ++i, ifconfig = NULL) {
    ifconfig = &config.interfaces.av[i].value;
    if (ifconfig->socket_type==SOCK_DGRAM) {
      unsigned j;
      for (j = 0; j < ifconfig->match.patc; ++j){
	if (fnmatch(ifconfig->match.patv[j], name, 0) == 0)
	  break;
      }
      
      if (j < ifconfig->match.patc)
	break;
    }
  }
  if (ifconfig == NULL) {
    if (config.debug.overlayinterfaces)
      DEBUGF("Interface %s does not match any rule", name);
    return 0;
  }
  if (ifconfig->exclude) {
    if (config.debug.overlayinterfaces)
      DEBUGF("Interface %s is explicitly excluded", name);
    return 0;
  }
  
  if (addr->addr.sa_family==AF_INET)
    addr->inet.sin_port = htons(ifconfig->port);
  if (broadcast->addr.sa_family==AF_INET)
    broadcast->inet.sin_port = htons(ifconfig->port);

  if (config.debug.overlayinterfaces) {
    // note, inet_ntop doesn't seem to behave on android
    DEBUGF("%s address: %s", name, alloca_socket_address(addr));
    DEBUGF("%s broadcast address: %s", name, alloca_socket_address(broadcast));
  }

  /* Search in the exist list of interfaces */
  for(i = 0; i < OVERLAY_MAX_INTERFACES; i++){
    if (overlay_interfaces[i].state==INTERFACE_STATE_DOWN)
      continue;
    
    if (strcasecmp(overlay_interfaces[i].name, name)==0
      && cmp_sockaddr(addr, &overlay_interfaces[i].address)==0){
      
      // mark this interface as still alive
      if (overlay_interfaces[i].state==INTERFACE_STATE_DETECTING)
	overlay_interfaces[i].state=INTERFACE_STATE_UP;
	
      return 0;
    }
  }
  
  /* New interface, so register it */
  if (overlay_interface_init(name, addr, broadcast, ifconfig))
    return WHYF("Could not initialise newly seen interface %s", name);
  else if (config.debug.overlayinterfaces) 
    DEBUGF("Registered interface %s", name);

  return 0;
}
  
void overlay_interface_discover(struct sched_ent *alarm)
{
  /* Mark all UP interfaces as DETECTING, so we can tell which interfaces are new, and which are dead */
  unsigned i;
  for (i = 0; i < OVERLAY_MAX_INTERFACES; i++)
    if (overlay_interfaces[i].state==INTERFACE_STATE_UP)
      overlay_interfaces[i].state=INTERFACE_STATE_DETECTING;   

  /* Register new dummy interfaces */
  int detect_real_interfaces = 0;
  const struct config_network_interface *ifconfig = NULL;
  for (i = 0; i < config.interfaces.ac; ++i, ifconfig = NULL) {
    ifconfig = &config.interfaces.av[i].value;
    if (ifconfig->exclude)
      continue;
    if (!*ifconfig->file) {
      detect_real_interfaces = 1;
      continue;
    }
    unsigned j;
    for (j = 0; j < OVERLAY_MAX_INTERFACES; j++){
      if (overlay_interfaces[j].socket_type == ifconfig->socket_type && 
	  strcasecmp(overlay_interfaces[j].name, ifconfig->file) == 0 && 
	  overlay_interfaces[j].state==INTERFACE_STATE_DETECTING){
	overlay_interfaces[j].state=INTERFACE_STATE_UP;
	break;
      }
    }
    
    if (j >= OVERLAY_MAX_INTERFACES) {
      // New file interface, so register it.
      struct socket_address addr, broadcast;
      bzero(&addr, sizeof addr);
      bzero(&broadcast, sizeof broadcast);
      
      switch(ifconfig->socket_type){
      case SOCK_FILE:
	// use a fake inet address
	addr.addrlen=sizeof addr.inet;
	addr.inet.sin_family=AF_INET;
	addr.inet.sin_port=htons(ifconfig->port);
	addr.inet.sin_addr=ifconfig->dummy_address;
	
	broadcast.addrlen=sizeof addr.inet;
	broadcast.inet.sin_family=AF_INET;
	broadcast.inet.sin_port=htons(ifconfig->port);
	broadcast.inet.sin_addr.s_addr=ifconfig->dummy_address.s_addr | ~ifconfig->dummy_netmask.s_addr;
      // Fallthrough
      case SOCK_STREAM:
	overlay_interface_init(ifconfig->file, &addr, &broadcast, ifconfig);
	break;
      case SOCK_DGRAM:
	{
	  // use a local dgram socket
	  // no abstract sockets for now
	  if (!FORMF_SERVAL_RUN_PATH(addr.local.sun_path, "%s/%s", config.server.interface_path, ifconfig->file)) {
	    // TODO set ifconfig->exclude to prevent spam??
	    break;
	  }
	  unlink(addr.local.sun_path);
	  addr.local.sun_family=AF_UNIX;
	  size_t len = strlen(addr.local.sun_path);
	  
	  addr.addrlen=sizeof addr.local.sun_family + len + 1;
	  
	  broadcast = addr;
	  while(len && broadcast.local.sun_path[len]!='/')
	    broadcast.local.sun_path[len--]='\0';
	  broadcast.addrlen = sizeof addr.local.sun_family + len + 2;
	  
	  DEBUGF("Attempting to bind local socket w. addr %s, broadcast %s",
	    alloca_socket_address(&addr), alloca_socket_address(&broadcast));
	  overlay_interface_init(ifconfig->file, &addr, &broadcast, ifconfig);
	  break;
	}
      }
    }
  }

  // Register new real interfaces
  if (detect_real_interfaces) {
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
  }

  // Close any interfaces that have gone away.
  for(i = 0; i < OVERLAY_MAX_INTERFACES; i++)
    if (overlay_interfaces[i].state==INTERFACE_STATE_DETECTING) {
      overlay_interface_close(&overlay_interfaces[i]);
    }

  alarm->alarm = gettime_ms()+5000;
  alarm->deadline = alarm->alarm + 10000;
  schedule(alarm);
  return;
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
