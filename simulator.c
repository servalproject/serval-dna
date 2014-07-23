/*
Copyright (C) 2014 Serval Project Inc.
 
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

/*
  Network simulator
*/

#include <signal.h>
#include <time.h>
#include <sys/time.h>

#include "console.h"
#include "conf.h"
#include "mem.h"
#include "socket.h"
#include "fdqueue.h"
#include "str.h"
#include "strbuf.h"
#include "strbuf_helpers.h"
#include "net.h"
#include "limit.h"

#define MTU 1600
struct peer;

/*
 * we want to support simulating common wired, wireless & UHF network topologies
 * eg layer 2 adhoc mesh, switched ethernet, AP's, openWRT's
 * With topology changes over time
 *
 * Some kind of DSL will probably be required
 *
 * Node{
 *   name "foo"
 *   type servald / switch ...
 *   Adapter{
 *     socket "path"
 *     type adhoc / ap / client / ethernet / uhf
 *     queue_length 10
 *     drop broadcast %
 *     drop unicast %
 *   }
 * }
 */

struct packet {
  struct packet *_next;
  time_ms_t recv_time;
  struct peer *destination;
  size_t len;
  uint8_t tdma_order;
  unsigned char buff[MTU];
};

struct peer {
  struct sched_ent alarm;
  struct peer *_next;
  struct network *network;
  struct socket_address addr;
  int packet_count;
  int max_packets;
  struct packet *_head, **_tail;
  uint32_t rx_count;
  uint32_t tx_count;
};

struct network {
  struct sched_ent alarm;
  char name[16];
  char path[256];
  struct limit_state limit;
  long latency;
  char drop_packets;
  char drop_broadcast;
  char drop_unicast;
  uint8_t up;
  uint8_t echo;
  uint8_t drop_broadcast_collisions; // on wifi collisions cause dropped packets
  uint32_t rx_count;
  uint32_t tx_count;
  struct peer *peer_list;
  struct network *_next;
};

struct profile_total broadcast_stats= {
  .name="sock_alarm"
};
struct profile_total unicast_stats= {
  .name="unicast_alarm"
};

struct command_state *stdin_state;

struct network *networks=NULL;
static void unicast_alarm(struct sched_ent *alarm);

void cf_on_config_change()
{
}

static void recv_packet(int fd, struct network *network, struct peer *destination)
{
  struct socket_address addr;
  struct packet *packet=emalloc_zero(sizeof(struct packet));
  if (!packet)
    return;
  network->rx_count++;
  packet->recv_time = gettime_ms();
  packet->destination = destination;
  struct iovec iov[]= {
    {
      .iov_base = (void*)&packet->buff,
      .iov_len = sizeof(packet->buff)
    }
  };
  struct msghdr hdr= {
    .msg_name=(void *)&addr.addr,
    .msg_namelen=sizeof(addr.store),
    .msg_iov=iov,
    .msg_iovlen=1,
  };
  ssize_t ret = recvmsg(fd, &hdr, 0);
  if (ret==-1) {
    free(packet);
    WHYF_perror("recvmsg(%d,...)", fd);
    return;
  }

  addr.addrlen = hdr.msg_namelen;
  packet->len = ret;
  packet->tdma_order = rand()&31;
  
  struct peer *peer = network->peer_list;
  while(peer) {
    if (cmp_sockaddr(&addr, &peer->addr)==0)
      break;
    peer=peer->_next;
  }
  if (!peer) {
    DEBUGF("New peer %s", alloca_socket_address(&addr));
    struct socket_address unicast_addr;
    unicast_addr.local.sun_family=AF_UNIX;
    strbuf d = strbuf_local(unicast_addr.local.sun_path, sizeof unicast_addr.local.sun_path);
    static unsigned peerid=0;
    strbuf_sprintf(d, "%s/peer%d", network->path, peerid++);
    if (strbuf_overrun(d)) {
      WHY("Path too long");
      free(packet);
      return;
    }

    unicast_addr.addrlen=sizeof unicast_addr.local.sun_family + strlen(unicast_addr.local.sun_path) + 1;

    peer = emalloc_zero(sizeof(struct peer));
    if (!peer) {
      free(packet);
      return;
    }
    peer->alarm.poll.fd=esocket(AF_UNIX, SOCK_DGRAM, 0);
    if (peer->alarm.poll.fd==-1) {
      free(packet);
      free(peer);
      return;
    }
    if (socket_bind(peer->alarm.poll.fd, &unicast_addr)==-1) {
      free(packet);
      free(peer);
      return;
    }
    set_nonblock(peer->alarm.poll.fd);
    peer->alarm.function=unicast_alarm;
    peer->alarm.poll.events=POLLIN;
    peer->alarm.context = peer;
    peer->network = network;
    peer->addr = addr;
    peer->_next = network->peer_list;
    peer->_tail = &peer->_head;
    peer->max_packets = 100;
    peer->alarm.stats=&unicast_stats;
    watch(&peer->alarm);
    network->peer_list = peer;
  }

  peer->tx_count++;
  
  // drop packets if the network is "down" or the peer queue is full
  if (!network->up || peer->packet_count >= peer->max_packets) {
    free(packet);
    return;
  }

  *peer->_tail = packet;
  peer->_tail = &packet->_next;
  peer->packet_count++;
  time_ms_t allowed = limit_next_allowed(&network->limit);
  if (allowed < packet->recv_time + network->latency)
    allowed = packet->recv_time + network->latency;
  if (!is_scheduled(&network->alarm) || allowed < network->alarm.alarm){
    unschedule(&network->alarm);
    network->alarm.alarm = allowed;
    network->alarm.deadline = network->alarm.alarm;
    schedule(&network->alarm);
  }
}

static void unicast_alarm(struct sched_ent *alarm)
{
  struct peer *peer = (struct peer*)alarm->context;

  if (alarm->poll.revents & POLLIN) {
    recv_packet(alarm->poll.fd, peer->network, peer);
  }
}

static int should_drop(struct network *network, struct packet *packet){
    if (network->drop_packets>=100)
      return 1;
    if (packet->destination){
      if (network->drop_unicast)
	return 1;
    }else{
      if (network->drop_broadcast)
	return 1;
    }
    if (network->drop_packets <= 0)
      return 0;
    if (rand()%100 >= network->drop_packets)
      return 0;
    return 1;
}

static void sock_alarm(struct sched_ent *alarm)
{
  struct network *network = (struct network*)alarm->context;

  if (alarm->poll.revents & POLLIN) {
    recv_packet(alarm->poll.fd, network, NULL);
  }

  if (alarm->poll.revents == 0) {
    time_ms_t allowed = limit_next_allowed(&network->limit);
    time_ms_t now = gettime_ms();
    if (allowed > now){
      alarm->deadline = alarm->alarm = allowed;
      schedule(alarm);
      return;
    }
    
    uint8_t tdma_order=127;
    unsigned tdma_count=0;
    struct packet *packet=NULL;
    struct peer *sender=NULL;
    
    // what's the best TDMA value?
    {
      struct peer *peer = network->peer_list;
      while(peer){
	struct packet *p = peer->_head;
	if (p && p->recv_time + network->latency <= now){
	  if (tdma_order > p->tdma_order){
	    tdma_order=p->tdma_order;
	    tdma_count=1;
	    packet = p;
	    sender = peer;
	  }else if(tdma_order==p->tdma_order){
	    tdma_count++;
	    packet = NULL;
	    sender = NULL;
	  }
	}
	peer = peer->_next;
      }
    }
    
    if (tdma_count!=0){
      limit_is_allowed(&network->limit);
      
      if (packet && tdma_count==1 && should_drop(network, packet)==0){
	// deliver the packet
	struct iovec iov[]= {
	  {
	    .iov_base = (void*)&packet->buff,
	    .iov_len = packet->len
	  }
	};
	struct msghdr hdr= {
	  .msg_iov=iov,
	  .msg_iovlen=1,
	};

	network->tx_count++;
	struct peer *peer = network->peer_list;
	while(peer) {
	  if ((packet->destination == peer || !packet->destination)
	      && (network->echo || peer !=sender)) {
	    hdr.msg_name=(void *)&peer->addr.addr;
	    hdr.msg_namelen=peer->addr.addrlen;
	    // failure isn't fatal...
	    if (sendmsg(sender->alarm.poll.fd, &hdr, 0)==-1)
	      WARN_perror("sendmsg()");
	    peer->rx_count++;
	  }
	  peer = peer->_next;
	}
      }
      
      if (tdma_count>1){
	// collision!
	struct peer *peer = network->peer_list;
	while(peer){
	  struct packet *p = peer->_head;
	  if (p
	  && p->recv_time + network->latency <= now 
	  && tdma_order==p->tdma_order){
	    if (!p->destination && network->drop_broadcast_collisions){
	      if (p==packet) // NOOP?
		packet = NULL;
	      peer->_head = p->_next;
	      if (!peer->_head)
		peer->_tail = &peer->_head;
	      peer->packet_count --;
	      free(p);
	    }else{
	      p->tdma_order = rand()&31;
	    }
	  }
	  peer = peer->_next;
	}
      }
      
      // free the sent packet
      if (sender && packet){
	sender->_head = packet->_next;
	if (!sender->_head)
	  sender->_tail = &sender->_head;
	sender->packet_count --;
	free(packet);
      }
    }
    
    // when is the next packet allowed?
    {
      time_ms_t next = TIME_MS_NEVER_WILL;
      struct peer *peer = network->peer_list;
      while(peer){
	struct packet *p = peer->_head;
	if (p && next > p->recv_time + network->latency){
	  next = p->recv_time + network->latency;
	}
	peer = peer->_next;
      }
      time_ms_t allowed = limit_next_allowed(&network->limit);
      if (next < allowed)
	next = allowed;
      alarm->deadline = alarm->alarm = next;
      schedule(alarm);
    }
  }
}

void signal_handler(int UNUSED(signal))
{
  command_close(stdin_state);
}

static void crash_handler(int signal)
{
  LOGF(LOG_LEVEL_FATAL, "Caught signal %s", alloca_signal_name(signal));
  dump_stack(LOG_LEVEL_FATAL);
// TODO Move logBackTrace to log utils?
//  BACKTRACE;
  // Now die of the same signal, so that our exit status reflects the cause.
  INFOF("Re-sending signal %d to self", signal);
  kill(getpid(), signal);
  // If that didn't work, then die normally.
  INFOF("exit(%d)", -signal);
  exit(-signal);
}

static struct network *find_network(const char *name)
{
  struct network *n = networks;
  while(n) {
    if (strcasecmp(name, n->name)==0)
      return n;
    n=n->_next;
  }
  WHYF("Network %s not found\n", n->name);
  return NULL;
}

static int console_create(const struct cli_parsed *parsed, struct cli_context *UNUSED(context))
{
  const char *name, *path;
  if ( cli_arg(parsed, "name", &name, NULL, NULL) == -1
       || cli_arg(parsed, "path", &path, NULL, NULL) == -1)
    return -1;

  struct socket_address addr;
  addr.local.sun_family=AF_UNIX;

  strbuf b = strbuf_local(addr.local.sun_path, sizeof addr.local.sun_path);
  strbuf_path_join(b, path, "broadcast", NULL);
  if (strbuf_overrun(b))
    return WHY("Path too long");

  addr.addrlen=sizeof addr.local.sun_family + strlen(addr.local.sun_path) + 1;
  int fd = esocket(AF_UNIX, SOCK_DGRAM, 0);
  if (fd==-1)
    return -1;
  if (socket_bind(fd, &addr)==-1) {
    close(fd);
    return -1;
  }
  set_nonblock(fd);

  struct network *n = emalloc_zero(sizeof(struct network));
  if (!n)
    return -1;

  strbuf_init(b, n->name, sizeof n->name);
  strbuf_puts(b, name);
  if (strbuf_overrun(b)) {
    socket_unlink_close(fd);
    free(n);
    return WHY("Name is too long");
  }
  strbuf_init(b, n->path, sizeof n->path);
  strbuf_puts(b, path);
  if (strbuf_overrun(b)) {
    socket_unlink_close(fd);
    free(n);
    return WHY("Path is too long");
  }

  n->_next = networks;
  networks = n;
  
  limit_init(&n->limit, 0);
  n->alarm.poll.fd = fd;
  n->alarm.function=sock_alarm;
  n->alarm.poll.events=POLLIN;
  n->alarm.stats=&broadcast_stats;
  n->alarm.context=n;
  watch(&n->alarm);

  INFOF("Created socket %s for network %s", alloca_socket_address(&addr), name);
  return 0;
}

static int console_variable(const struct cli_parsed *parsed, struct cli_context *UNUSED(context))
{
  const char *name;
  if (cli_arg(parsed, "name", &name, NULL, NULL) == -1)
    return -1;
  struct network *n = find_network(name);
  if (!n)
    return -1;
    
  unsigned i;
  for (i = 2; i+1 < parsed->argc; i+=2) {
    const char *arg = parsed->args[i];
    const char *value = parsed->args[i+1];
    
    if (strcmp(arg, "latency") == 0) {
      n->latency = atol(value);
    }else if (strcmp(arg, "echo") == 0) {
      n->echo = atoi(value) != 0;
    }else if (strcmp(arg, "rate") == 0) {
      uint32_t rate = atoi(value);
      limit_init(&n->limit, rate);
    }else if (strcmp(arg, "drop_packets") == 0){
      n->drop_packets= atol(value);
    }else if (strcmp(arg, "drop_broadcast") == 0){
      n->drop_broadcast=atol(value)!=0;
    }else if (strcmp(arg, "drop_unicast") == 0){
      n->drop_unicast=atol(value)!=0;
    }else
      return WHYF("Unknown variable %s", arg);
  }
  return 0;
}

static int console_up(const struct cli_parsed *parsed, struct cli_context *UNUSED(context))
{
  unsigned i;
  for (i = 1; i < parsed->argc; i++) {
    struct network *n = find_network(parsed->args[i]);
    if (!n)
      return -1;

    n->up = 1;
    INFOF("Network %s is now up", n->name);
    DEBUGF("Minimum latency %dms", (int)n->latency);
    DEBUGF("Will drop %d%% of packets", n->drop_packets);
    DEBUGF("Will %s broadcast packets", n->drop_broadcast?"drop":"allow");
    DEBUGF("Will %s unicast packets", n->drop_unicast?"drop":"allow");
    DEBUGF("Allowing a maximum of %d packets every %"PRId64"ms",
	  n->limit.burst_size,
	  n->limit.burst_length);
  }
  return 0;
}

static int console_down(const struct cli_parsed *parsed, struct cli_context *UNUSED(context))
{
  unsigned i;
  for (i = 1; i < parsed->argc; i++) {
    struct network *n = find_network(parsed->args[i]);
    if (!n)
      return -1;

    // free any pending packets
    struct peer *peer = n->peer_list;
    while(peer) {
      struct packet *p = peer->_head;
      while(p) {
	struct packet *f = p;
	p = p->_next;
	free(f);
      }
      peer->_head=NULL;
      peer=peer->_next;
    }

    n->up = 0;
    unschedule(&n->alarm);

    INFOF("Network %s is now down", n->name);
  }
  return 0;
}

static int console_quit(const struct cli_parsed *UNUSED(parsed), struct cli_context *UNUSED(context))
{
  command_close(stdin_state);
  return 0;
}

struct cli_schema console_commands[]= {
  {console_create,{"create","<name>","<path>",NULL},0,"Create a named network"},
  {console_variable,{"set", "<name>", "<variable>","<value>","...",NULL},0,"Set a property of the network"},
  {console_up,{"up", "<name>", "...", NULL},0,"Bring a network up"},
  {console_down,{"down","<name>","...",NULL},0,"Bring a network down"},
  {console_quit,{"quit",NULL},0,"Exit the simulator"},
  {NULL, {NULL, NULL, NULL}, 0, NULL},
};

int main()
{
  cf_init();

  /* Catch crash signals so that we can log a backtrace before expiring. */
  struct sigaction sig;
  sig.sa_handler = crash_handler;
  sigemptyset(&sig.sa_mask); // Don't block any signals during handler
  sig.sa_flags = SA_NODEFER | SA_RESETHAND; // So the signal handler can kill the process by re-sending the same signal to itself
  sigaction(SIGSEGV, &sig, NULL);
  sigaction(SIGFPE, &sig, NULL);
  sigaction(SIGILL, &sig, NULL);
  sigaction(SIGBUS, &sig, NULL);
  sigaction(SIGABRT, &sig, NULL);
  
  /* Catch SIGHUP, SIGINT so we can shutdown gracefully */
  sig.sa_handler = signal_handler;
  sigemptyset(&sig.sa_mask);
  sigaddset(&sig.sa_mask, SIGHUP);
  sigaddset(&sig.sa_mask, SIGINT);
  sig.sa_flags = 0;
  sigaction(SIGHUP, &sig, NULL);
  sigaction(SIGINT, &sig, NULL);

  stdin_state = command_register(console_commands, STDIN_FILENO);

  while(!is_command_closed(stdin_state) && fd_poll())
    ;

  INFO("Shutting down");
  command_free(stdin_state);

  {
    struct network *n = networks;
    while(n) {
      DEBUGF("Closing network %s, TX %d RX %d", n->name, n->tx_count, n->rx_count);
      unwatch(&n->alarm);
      socket_unlink_close(n->alarm.poll.fd);
      struct peer *p = n->peer_list;
      while(p) {
	DEBUGF("Closing peer proxy socket, TX %d RX %d", p->tx_count, p->rx_count);
	unwatch(&p->alarm);
	socket_unlink_close(p->alarm.poll.fd);
	struct peer *f = p;
	p=p->_next;
	free(f);
      }
      struct network *f=n;
      n=n->_next;
      free(f);
    }
  }

  return 0;
}
