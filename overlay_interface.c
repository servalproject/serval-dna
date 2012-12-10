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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <time.h>
#include <fnmatch.h>
#include "serval.h"
#include "conf.h"
#include "strbuf.h"
#include "strbuf_helpers.h"
#include "overlay_buffer.h"
#include "overlay_packet.h"
#include "str.h"

#ifdef HAVE_IFADDRS_H
#include <ifaddrs.h>
#endif

int overlay_ready=0;
int overlay_interface_count=0;
overlay_interface overlay_interfaces[OVERLAY_MAX_INTERFACES];
int overlay_last_interface_number=-1;

struct profile_total interface_poll_stats;
struct profile_total dummy_poll_stats;

struct sched_ent sock_any;
struct sockaddr_in sock_any_addr;
struct profile_total sock_any_stats;

static void overlay_interface_poll(struct sched_ent *alarm);
static void logServalPacket(int level, struct __sourceloc __whence, const char *message, const unsigned char *packet, size_t len);

#define DEBUG_packet_visualise(M,P,N) logServalPacket(LOG_LEVEL_DEBUG, __WHENCE__, (M), (P), (N))

static void
overlay_interface_close(overlay_interface *interface){
  if (interface->fileP){
    INFOF("Interface %s is down", interface->name);
  }else{
    INFOF("Interface %s addr %s is down", interface->name, inet_ntoa(interface->broadcast_address.sin_addr));
  }
  unschedule(&interface->alarm);
  unwatch(&interface->alarm);
  close(interface->alarm.poll.fd);
  interface->alarm.poll.fd=-1;
  interface->state=INTERFACE_STATE_DOWN;
}

// create a socket with options common to all our UDP sockets
static int
overlay_bind_socket(const struct sockaddr *addr, size_t addr_size, char *interface_name){
  int fd;
  int reuseP = 1;
  int broadcastP = 1;
  
  fd = socket(PF_INET,SOCK_DGRAM,0);
  if (fd < 0) {
    WHY_perror("Error creating socket");
    return -1;
  } 
  
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
  
#ifdef SO_BINDTODEVICE
  /*
   Limit incoming and outgoing packets to this interface, no matter what the routing table says.
   This should allow for a device with multiple interfaces on the same subnet.
   Don't abort if this fails, I believe it requires root, just log it.
   */
  if (interface_name && setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, interface_name, strlen(interface_name)+1) < 0) {
    WHY_perror("setsockopt(SO_BINDTODEVICE)");
  }
#endif

  if (bind(fd, addr, addr_size)) {
    WHY_perror("Bind failed");
    goto error;
  }
  
  return fd;
  
error:
  close(fd);
  return -1;
}

overlay_interface * overlay_interface_get_default(){
  int i;
  for (i=0;i<OVERLAY_MAX_INTERFACES;i++){
    if (overlay_interfaces[i].state==INTERFACE_STATE_UP && overlay_interfaces[i].default_route)
      return &overlay_interfaces[i];
  }
  return NULL;
}

overlay_interface * overlay_interface_find(struct in_addr addr, int return_default){
  int i;
  overlay_interface *ret = NULL;
  for (i=0;i<OVERLAY_MAX_INTERFACES;i++){
    if (overlay_interfaces[i].state!=INTERFACE_STATE_UP)
      continue;
    
    if ((overlay_interfaces[i].netmask.s_addr & addr.s_addr) == (overlay_interfaces[i].netmask.s_addr & overlay_interfaces[i].address.sin_addr.s_addr)){
      return &overlay_interfaces[i];
    }
    
    // check if this is a default interface
    if (return_default && overlay_interfaces[i].default_route)
      ret=&overlay_interfaces[i];
  }
  
  return ret;
}

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

// OSX doesn't recieve broadcast packets on sockets bound to an interface's address
// So we have to bind a socket to INADDR_ANY to receive these packets.
static void
overlay_interface_read_any(struct sched_ent *alarm){
  if (alarm->poll.revents & POLLIN) {
    int plen=0;
    int recvttl=1;
    unsigned char packet[16384];
    overlay_interface *interface=NULL;
    struct sockaddr src_addr;
    socklen_t addrlen = sizeof(src_addr);
    
    /* Read only one UDP packet per call to share resources more fairly, and also
     enable stats to accurately count packets received */
    plen = recvwithttl(alarm->poll.fd, packet, sizeof(packet), &recvttl, &src_addr, &addrlen);
    if (plen == -1) {
      WHY_perror("recvwithttl(c)");
      unwatch(alarm);
      close(alarm->poll.fd);
      return;
    }
    
    struct in_addr src = ((struct sockaddr_in *)&src_addr)->sin_addr;
    
    /* Try to identify the real interface that the packet arrived on */
    interface = overlay_interface_find(src, 0);
    
    /* Drop the packet if we don't find a match */
    if (!interface){
      if (debug&DEBUG_OVERLAYINTERFACES)
	DEBUGF("Could not find matching interface for packet received from %s", inet_ntoa(src));
      return;
    }
    
    /* We have a frame from this interface */
    if (debug&DEBUG_PACKETRX)
      DEBUG_packet_visualise("Read from real interface", packet,plen);
    if (debug&DEBUG_OVERLAYINTERFACES)
      DEBUGF("Received %d bytes from %s on interface %s (ANY)",plen, 
	     inet_ntoa(src),
	     interface->name);
    
    if (packetOkOverlay(interface, packet, plen, recvttl, &src_addr, addrlen)) {
      WHY("Malformed packet");
    }
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
  struct sockaddr_in addr;
  
  if (sock_any.poll.fd>0){
    // Check the port number matches
    if (sock_any_addr.sin_port != htons(port))
      return WHYF("Unable to listen to broadcast packets for ports %d & %d", port, ntohs(sock_any_addr.sin_port));
    
    return 0;
  }
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = INADDR_ANY;

  sock_any.poll.fd = overlay_bind_socket((const struct sockaddr *)&addr, sizeof(addr), NULL);
  if (sock_any.poll.fd<0)
    return -1;
  
  sock_any_addr = addr;
  
  sock_any.poll.events=POLLIN;
  sock_any.function = overlay_interface_read_any;
  
  sock_any_stats.name="overlay_interface_read_any";
  sock_any.stats=&sock_any_stats;
  watch(&sock_any);
  return 0;
}

static int
overlay_interface_init_socket(int interface_index)
{
  overlay_interface *const interface = &overlay_interfaces[interface_index];
  interface->fileP = 0;

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
  
  const struct sockaddr *addr = (const struct sockaddr *)&interface->address;
  
  interface->alarm.poll.fd = overlay_bind_socket(addr, sizeof(interface->broadcast_address), interface->name);
  if (interface->alarm.poll.fd<0){
    interface->state=INTERFACE_STATE_DOWN;
    return -1;
  }
  
  if (debug & (DEBUG_PACKETRX | DEBUG_IO)){
    char srctxt[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, (const void *)&interface->broadcast_address.sin_addr, srctxt, INET_ADDRSTRLEN))
      DEBUGF("Bound to %s:%d", srctxt, ntohs(interface->broadcast_address.sin_port));
  }

  interface->alarm.poll.events=POLLIN;
  interface->alarm.function = overlay_interface_poll;
  
  interface_poll_stats.name="overlay_interface_poll";
  interface->alarm.stats=&interface_poll_stats;
  watch(&interface->alarm);

  if (interface->tick_ms>0){
    // run the first tick asap
    interface->alarm.alarm=gettime_ms();
    interface->alarm.deadline=interface->alarm.alarm+10;
    schedule(&interface->alarm);
  }
  
  interface->state=INTERFACE_STATE_UP;
  
  INFOF("Interface %s addr %s:%d, is up",interface->name, 
	inet_ntoa(interface->address.sin_addr), ntohs(interface->address.sin_port));
  
  directory_registration();
  
  return 0;
}

static int
overlay_interface_init(const char *name, struct in_addr src_addr, struct in_addr netmask, struct in_addr broadcast,
		       const struct config_network_interface *ifconfig)
{
  /* Too many interfaces */
  if (overlay_interface_count>=OVERLAY_MAX_INTERFACES) return WHY("Too many interfaces -- Increase OVERLAY_MAX_INTERFACES");

  overlay_interface *const interface = &overlay_interfaces[overlay_interface_count];

  strncpy(interface->name, name, sizeof interface->name);
  
  /* Pick a reasonable default MTU.
     This will ultimately get tuned by the bandwidth and other properties of the interface */
  interface->mtu=1200;
  interface->state=INTERFACE_STATE_DOWN;
  interface->bits_per_second = ifconfig->speed;
  interface->port= ifconfig->port;
  interface->type= ifconfig->type;
  interface->default_route = ifconfig->default_route;
  DEBUGF("interface->default_route=%d",interface->default_route);
  interface->last_tick_ms= -1; // not ticked yet
  interface->alarm.poll.fd=0;

  // How often do we announce ourselves on this interface?
  int32_t tick_ms = ifconfig->mdp_tick_ms;
  if (tick_ms < 0) {
    int i = config_mdp_iftypelist__get(&config.mdp.iftype, &ifconfig->type);
    if (i != -1)
      tick_ms = config.mdp.iftype.av[i].value.tick_ms;
  }
  if (tick_ms < 0) {
    switch (ifconfig->type) {
    case OVERLAY_INTERFACE_PACKETRADIO:
      tick_ms = 15000;
      break;
    case OVERLAY_INTERFACE_ETHERNET:
      tick_ms = 500;
      break;
    case OVERLAY_INTERFACE_WIFI:
      tick_ms = 500;
      break;
    case OVERLAY_INTERFACE_UNKNOWN:
      tick_ms = 500;
      break;
    default:
      return WHYF("Unsupported interface type %d", ifconfig->type);
    }
  }
  assert(tick_ms >= 0);
  interface->tick_ms = tick_ms;

  // disable announcements and other broadcasts if tick_ms=0.
  if (interface->tick_ms > 0)
    interface->send_broadcasts=1;
  else{
    interface->send_broadcasts=0;
    INFOF("Interface %s is running tickless", name);
  }
  if (ifconfig->dummy[0]) {
    interface->fileP = 1;
    char dummyfile[1024];
    strbuf d = strbuf_local(dummyfile, sizeof dummyfile);
    strbuf_path_join(d, serval_instancepath(), config.server.dummy_interface_dir, ifconfig->dummy, NULL);
    if (strbuf_overrun(d))
      return WHYF("dummy interface file name overrun: %s", alloca_str_toprint(strbuf_str(d)));
    if ((interface->alarm.poll.fd = open(dummyfile,O_APPEND|O_RDWR)) < 1) {
      return WHYF("could not open dummy interface file %s for append", dummyfile);
    }

    bzero(&interface->address, sizeof(interface->address));
    interface->address.sin_family=AF_INET;
    interface->address.sin_port = htons(PORT_DNA);
    interface->address.sin_addr = ifconfig->dummy_address;
    
    interface->netmask=ifconfig->dummy_netmask;
    
    bzero(&interface->broadcast_address, sizeof(interface->address));
    interface->broadcast_address.sin_family=AF_INET;
    interface->broadcast_address.sin_port = htons(PORT_DNA);
    interface->broadcast_address.sin_addr.s_addr = interface->address.sin_addr.s_addr | ~interface->netmask.s_addr;
    interface->drop_broadcasts = ifconfig->dummy_filter_broadcasts;
    
    /* Seek to end of file as initial reading point */
    interface->recv_offset = lseek(interface->alarm.poll.fd,0,SEEK_END);
    /* XXX later add pretend location information so that we can decide which "packets" to receive
       based on closeness */    
    
    // schedule an alarm for this interface
    interface->alarm.function=overlay_dummy_poll;
    interface->alarm.alarm=gettime_ms()+10;
    interface->alarm.deadline=interface->alarm.alarm;
    dummy_poll_stats.name="overlay_dummy_poll";
    interface->alarm.stats=&dummy_poll_stats;
    schedule(&interface->alarm);
    
    interface->state=INTERFACE_STATE_UP;
    INFOF("Dummy interface %s addr %s:%d, is up",interface->name,
	  inet_ntoa(interface->address.sin_addr), ntohs(interface->address.sin_port));
    
    directory_registration();
    
  } else {
    
    interface->netmask = netmask;
    
    interface->address.sin_addr = src_addr;
    interface->address.sin_family = AF_INET;
    interface->address.sin_port = htons(interface->port);
    
    interface->broadcast_address.sin_addr = broadcast;
    interface->broadcast_address.sin_family = AF_INET;
    interface->broadcast_address.sin_port = htons(interface->port);
    
    if (overlay_interface_init_socket(overlay_interface_count))
      return WHY("overlay_interface_init_socket() failed");    
  }

  overlay_interface_count++;
  return 0;
}

static void overlay_interface_poll(struct sched_ent *alarm)
{
  struct overlay_interface *interface = (overlay_interface *)alarm;

  if (alarm->poll.revents==0){
    
    if (interface->state==INTERFACE_STATE_UP && interface->tick_ms>0){
      // tick the interface
      time_ms_t now = gettime_ms();
      int i = (interface - overlay_interfaces);
      overlay_tick_interface(i, now);
      alarm->alarm=now+interface->tick_ms;
      alarm->deadline=alarm->alarm+interface->tick_ms/2;
      schedule(alarm);
    }
    
    return;
  }
  
  if (alarm->poll.revents & POLLIN) {
    int plen=0;
    unsigned char packet[16384];

    struct sockaddr src_addr;
    socklen_t addrlen = sizeof(src_addr);

    
    /* Read only one UDP packet per call to share resources more fairly, and also
       enable stats to accurately count packets received */
    int recvttl=1;
    plen = recvwithttl(alarm->poll.fd,packet, sizeof(packet), &recvttl, &src_addr, &addrlen);
    if (plen == -1) {
      WHY_perror("recvwithttl(c)");
      overlay_interface_close(interface);
      return;
    }
    
    /* We have a frame from this interface */
    if (debug&DEBUG_PACKETRX)
      DEBUG_packet_visualise("Read from real interface", packet,plen);
    if (debug&DEBUG_OVERLAYINTERFACES) {
      struct in_addr src = ((struct sockaddr_in *)&src_addr)->sin_addr; // avoid strict-alias warning on Solaris (gcc 4.4)
      DEBUGF("Received %d bytes from %s on interface %s",plen,
	     inet_ntoa(src),
	     interface->name);
    }
    if (packetOkOverlay(interface, packet, plen, recvttl, &src_addr, addrlen)) {
      WHY("Malformed packet");
      // Do we really want to attempt to parse it again?
      //DEBUG_packet_visualise("Malformed packet", packet,plen);
    }
  }
  
  if (alarm->poll.revents & (POLLHUP | POLLERR)) {
    overlay_interface_close(interface);
  }  
}

struct dummy_packet{
  struct sockaddr_in src_addr;
  struct sockaddr_in dst_addr;
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

void overlay_dummy_poll(struct sched_ent *alarm)
{
  overlay_interface *interface = (overlay_interface *)alarm;
  /* Grab packets, unpackage and dispatch frames to consumers */
  struct dummy_packet packet;
  time_ms_t now = gettime_ms();

  /* Read from dummy interface file */
  long long length=lseek(alarm->poll.fd,0,SEEK_END);
  
  int new_packets = (length - interface->recv_offset) / sizeof packet;
  if (new_packets > 20)
    WARNF("Getting behind, there are %d unread packets", new_packets);
  
  if (interface->recv_offset >= length) {
    /* if there's no input, while we want to check for more soon,
	we need to allow all other low priority alarms to fire first,
	otherwise we'll dominate the scheduler without accomplishing anything */
    alarm->alarm = gettime_ms() + 5;
    if (interface->last_tick_ms != -1 && alarm->alarm > interface->last_tick_ms + interface->tick_ms)
      alarm->alarm = interface->last_tick_ms + interface->tick_ms;
    alarm->deadline = alarm->alarm + 10000;
  } else {
    
    if (lseek(alarm->poll.fd,interface->recv_offset,SEEK_SET) == -1){
      WHY_perror("lseek");
      return;
    }
    
    if (debug&DEBUG_OVERLAYINTERFACES)
      DEBUGF("Read interface %s (size=%lld) at offset=%d",interface->name, length, interface->recv_offset);
    
    ssize_t nread = read(alarm->poll.fd, &packet, sizeof packet);
    if (nread == -1){
      WHY_perror("read");
      return;
    }
    
    if (nread == sizeof packet) {
      interface->recv_offset += nread;
     
      if (debug&DEBUG_PACKETRX)
	DEBUG_packet_visualise("Read from dummy interface", packet.payload, packet.payload_length);
      
      if (memcmp(&packet.dst_addr, &interface->address, sizeof(packet.dst_addr))==0 ||
	  ((!interface->drop_broadcasts) &&
	  memcmp(&packet.dst_addr, &interface->broadcast_address, sizeof(packet.dst_addr))==0)){
	
	if (packetOkOverlay(interface, packet.payload, packet.payload_length, -1, 
			    (struct sockaddr*)&packet.src_addr, sizeof(packet.src_addr))) {
	  WARN("Unsupported packet from dummy interface");
	}
      }else
	DEBUGF("Ignoring packet addressed to %s:%d", inet_ntoa(packet.dst_addr.sin_addr), ntohs(packet.dst_addr.sin_port));
    }
    
    /* keep reading new packets as fast as possible, 
	but don't completely prevent other high priority alarms */
    if (interface->recv_offset >= length)
      alarm->alarm = gettime_ms() + 5;
    else
      alarm->alarm = gettime_ms();
    alarm->deadline = alarm->alarm + 100;
  }
  
  // only tick the interface if we've caught up reading all the packets
  if (interface->recv_offset >= length &&
      interface->tick_ms>0 && 
      (interface->last_tick_ms == -1 || now >= interface->last_tick_ms + interface->tick_ms)) {
    // tick the interface
    int i = (interface - overlay_interfaces);
    overlay_tick_interface(i, now);
  }
  
  schedule(alarm);

  return ;
}

int
overlay_broadcast_ensemble(int interface_number,
			   struct sockaddr_in *recipientaddr,
			   unsigned char *bytes,int len)
{
  if (debug&DEBUG_PACKETTX)
    {
      DEBUGF("Sending this packet via interface #%d",interface_number);
      DEBUG_packet_visualise(NULL,bytes,len);
    }

  overlay_interface *interface = &overlay_interfaces[interface_number];

  if (interface->state!=INTERFACE_STATE_UP){
    return WHYF("Cannot send to interface %s as it is down", interface->name);
  }

  if (interface->fileP)
    {
      
      struct dummy_packet packet={
	.src_addr = interface->address,
	.dst_addr = *recipientaddr,
	.pid = getpid(),
      };
      
      if (len > sizeof(packet.payload)){
	WARN("Truncating long packet to fit within MTU byte limit for dummy interface");
	len = sizeof(packet.payload);
      }
      packet.payload_length=len;
      bcopy(bytes, packet.payload, len);
      /* This lseek() is unneccessary because the dummy file is opened in O_APPEND mode.  It's
	 only purpose is to find out the offset to print in the DEBUG statement.  It is vulnerable
	 to a race condition with other processes appending to the same file. */
      off_t fsize = lseek(interface->alarm.poll.fd, (off_t) 0, SEEK_END);
      if (fsize == -1)
	return WHY_perror("lseek");
      if (debug&DEBUG_OVERLAYINTERFACES)
	DEBUGF("Write to interface %s at offset=%d", interface->name, fsize);
      ssize_t nwrite = write(interface->alarm.poll.fd, &packet, sizeof(packet));
      if (nwrite == -1)
	return WHY_perror("write");
      if (nwrite != sizeof(packet))
	return WHYF("only wrote %lld of %lld bytes", nwrite, sizeof(packet));
      return 0;
    }
  else
    {
      if (debug&DEBUG_OVERLAYINTERFACES) 
	DEBUGF("Sending %d byte overlay frame on %s to %s",len,interface->name,inet_ntoa(recipientaddr->sin_addr));
      if(sendto(interface->alarm.poll.fd, 
		bytes, len, 0, (struct sockaddr *)recipientaddr, sizeof(struct sockaddr_in)) != len){
	int e=errno;
	WHY_perror("sendto(c)");
	// only close the interface on some kinds of errors
	if (e==ENETDOWN || e==EINVAL)
	  overlay_interface_close(interface);
	return -1;
      }
      return 0;
    }
}

/* Register the real interface, or update the existing interface registration. */
int
overlay_interface_register(char *name,
			   struct in_addr addr,
			   struct in_addr mask)
{
  struct in_addr broadcast = {.s_addr = addr.s_addr | ~mask.s_addr};

  if (debug & DEBUG_OVERLAYINTERFACES) {
    // note, inet_ntop doesn't seem to behave on android
    DEBUGF("%s address: %s", name, inet_ntoa(addr));
    DEBUGF("%s broadcast address: %s", name, inet_ntoa(broadcast));
  }

  // Find the matching non-dummy interface rule.
  const struct config_network_interface *ifconfig = NULL;
  int i;
  for (i = 0; i < config.interfaces.ac; ++i, ifconfig = NULL) {
    ifconfig = &config.interfaces.av[i].value;
    if (!ifconfig->dummy[0]) {
      int j;
      for (j = 0; j < ifconfig->match.patc; ++j)
	if (fnmatch(ifconfig->match.patv[j], name, 0) == 0)
	  break;
    }
  }
  if (ifconfig == NULL) {
    if (debug & DEBUG_OVERLAYINTERFACES)
      DEBUGF("Interface %s does not match any rule", name);
    return 0;
  }
  if (ifconfig->exclude) {
    if (debug & DEBUG_OVERLAYINTERFACES)
      DEBUGF("Interface %s is explicitly excluded", name);
    return 0;
  }

  /* Search in the exist list of interfaces */
  int found_interface= -1;
  for(i = 0; i < overlay_interface_count; i++){
    int broadcast_match = 0;
    int name_match =0;
    
    if (overlay_interfaces[i].broadcast_address.sin_addr.s_addr == broadcast.s_addr)
      broadcast_match = 1;
    
    name_match = !strcasecmp(overlay_interfaces[i].name, name);
    
    // if we find an exact match we can stop searching
    if (name_match && broadcast_match){
      // mark this interface as still alive
      if (overlay_interfaces[i].state==INTERFACE_STATE_DETECTING)
	overlay_interfaces[i].state=INTERFACE_STATE_UP;
      
      // try to bring the interface back up again even if the address has changed
      if (overlay_interfaces[i].state==INTERFACE_STATE_DOWN){
	overlay_interfaces[i].address.sin_addr = addr;
	overlay_interface_init_socket(i);
      }
      
      // we already know about this interface, and it's up so stop looking immediately
      return 0;
    }
    
    // remember this slot to bring the interface back up again, even if the address has changed
    if (name_match && overlay_interfaces[i].state==INTERFACE_STATE_DOWN)
      found_interface=i;
  }
  
  if (found_interface>=0){
    // try to reactivate the existing interface
    overlay_interfaces[found_interface].address.sin_addr = addr;
    overlay_interfaces[found_interface].broadcast_address.sin_addr = broadcast;
    overlay_interfaces[found_interface].netmask = mask;
    return overlay_interface_init_socket(found_interface);
  }
  
  /* New interface, so register it */
  if (overlay_interface_init(name, addr, mask, broadcast, ifconfig))
    return WHYF("Could not initialise newly seen interface %s", name);
  else
    if (debug & DEBUG_OVERLAYINTERFACES) DEBUGF("Registered interface %s", name);

  return 0;
}
  
void overlay_interface_discover(struct sched_ent *alarm)
{
  /* Mark all UP interfaces as DETECTING, so we can tell which interfaces are new, and which are dead */
  int i;
  for (i = 0; i < overlay_interface_count; i++)
    if (overlay_interfaces[i].state==INTERFACE_STATE_UP)
      overlay_interfaces[i].state=INTERFACE_STATE_DETECTING;

  /* Register new dummy interfaces */
  int detect_real_interfaces = 0;
  const struct config_network_interface *ifconfig = NULL;
  for (i = 0; i < config.interfaces.ac; ++i, ifconfig = NULL) {
    ifconfig = &config.interfaces.av[i].value;
    if (!ifconfig->dummy[0]) {
      detect_real_interfaces = 1;
      continue;
    }
    for (i = 0; i < overlay_interface_count; i++)
      if (strcasecmp(overlay_interfaces[i].name, ifconfig->dummy) == 0) {
	if (overlay_interfaces[i].state==INTERFACE_STATE_DETECTING)
	  overlay_interfaces[i].state=INTERFACE_STATE_UP;
	break;
      }
    if (i >= overlay_interface_count) {
      // New dummy interface, so register it.
      struct in_addr dummyaddr = (struct in_addr){htonl(INADDR_NONE)};
      overlay_interface_init(ifconfig->dummy, dummyaddr, dummyaddr, dummyaddr, ifconfig);
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
  for(i = 0; i < overlay_interface_count; i++)
    if (overlay_interfaces[i].state==INTERFACE_STATE_DETECTING)
      overlay_interface_close(&overlay_interfaces[i]);

  alarm->alarm = gettime_ms()+5000;
  alarm->deadline = alarm->alarm + 10000;
  schedule(alarm);
  return;
}

static void
logServalPacket(int level, struct __sourceloc __whence, const char *message, const unsigned char *packet, size_t len) {
  struct mallocbuf mb = STRUCT_MALLOCBUF_NULL;
  if (serval_packetvisualise(XPRINTF_MALLOCBUF(&mb), message, packet, len) == -1)
    WHY("serval_packetvisualise() failed");
  else if (mb.buffer == NULL)
    WHYF("serval_packetvisualise() output buffer missing, message=%s packet=%p len=%lu", alloca_toprint(-1, message, strlen(message)), packet, len);
  else
    logString(level, __whence, mb.buffer);
  if (mb.buffer)
    free(mb.buffer);
}
