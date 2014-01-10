
#include <assert.h>
#include <inttypes.h>
#include "serval.h"
#include "conf.h"
#include "mdp_client.h"
#include "msp_client.h"
#include "str.h"
#include "dataformats.h"
#include "socket.h"
#include "log.h"

#define FLAG_SHUTDOWN (1<<0)
#define FLAG_ACK (1<<1)

struct msp_packet{
  struct msp_packet *_next;
  uint16_t seq;
  uint8_t flags;
  time_ms_t added;
  time_ms_t sent;
  const uint8_t *payload;
  size_t len;
};

#define MAX_WINDOW_SIZE 4
struct msp_window{
  int packet_count;
  uint32_t base_rtt;
  uint32_t rtt;
  uint16_t next_seq; // seq of next expected TX or RX packet.
  time_ms_t last_activity;
  struct msp_packet *_head, *_tail;
};

struct msp_sock{
  struct msp_sock *_next;
  struct msp_sock *_prev;
  int mdp_sock;
  msp_state_t state;
  struct msp_window tx;
  struct msp_window rx;
  uint16_t previous_ack;
  time_ms_t next_ack;
  int (*handler)(struct msp_sock *sock, msp_state_t state, const uint8_t *payload, size_t len, void *context);
  void *context;
  struct mdp_header header;
  time_ms_t timeout;
  time_ms_t next_action;
};

struct msp_sock *root=NULL;

struct msp_sock * msp_socket(int mdp_sock)
{
  struct msp_sock *ret = emalloc_zero(sizeof(struct msp_sock));
  ret->mdp_sock = mdp_sock;
  ret->state = MSP_STATE_UNINITIALISED;
  ret->_next = root;
  // TODO set base rtt to ensure that we send the first packet a few times before giving up
  ret->tx.base_rtt = ret->tx.rtt = 0xFFFFFFFF;
  ret->tx.last_activity = TIME_NEVER_HAS;
  ret->rx.last_activity = TIME_NEVER_HAS;
  ret->next_action = TIME_NEVER_WILL;
  ret->timeout = gettime_ms() + 10000;
  ret->previous_ack = 0x7FFF;
  if (root)
    root->_prev=ret;
  root = ret;
  return ret;
}

unsigned msp_socket_count()
{
  unsigned i=0;
  struct msp_sock *p=root;
  while(p){
    i++;
    p=p->_next;
  }
  return i;
}

void msp_debug()
{
  time_ms_t now = gettime_ms();
  struct msp_sock *p=root;
  DEBUGF("Msp sockets;");
  while(p){
    DEBUGF("State %d, from %s:%d to %s:%d, next %"PRId64"ms, ack %"PRId64"ms timeout %"PRId64"ms", 
      p->state, 
      alloca_tohex_sid_t(p->header.local.sid), p->header.local.port, 
      alloca_tohex_sid_t(p->header.remote.sid), p->header.remote.port,
      (p->next_action - now),
      (p->next_ack - now),
      (p->timeout - now));
    p=p->_next;
  }
}

static void free_all_packets(struct msp_window *window)
{
  struct msp_packet *p = window->_head;
  while(p){
    struct msp_packet *free_me=p;
    p=p->_next;
    if (free_me->payload)
      free((void *)free_me->payload);
    free(free_me);
  }
}

static void free_acked_packets(struct msp_window *window, uint16_t seq)
{
  if (!window->_head)
    return;
  
  struct msp_packet *p = window->_head;
  
  uint32_t rtt=0;
  time_ms_t now = gettime_ms();

  while(p && compare_wrapped_uint16(p->seq, seq)<=0){
    if (p->sent)
      rtt = now - p->sent;
    struct msp_packet *free_me=p;
    p=p->_next;
    if (free_me->payload)
      free((void *)free_me->payload);
    free(free_me);
    window->packet_count--;
  }
  window->_head = p;
  if (rtt){
    if (rtt < 10)
      rtt=10;
    window->rtt = rtt;
    if (window->base_rtt > rtt)
      window->base_rtt = rtt;
    if (config.debug.msp)
      DEBUGF("RTT %u, base %u", rtt, window->base_rtt);
  }
  if (!p)
    window->_tail = NULL;
}

static void msp_free(struct msp_sock *sock)
{
  sock->state |= MSP_STATE_CLOSED;
  // remove from the list first
  if (sock->_prev)
    sock->_prev->_next = sock->_next;
  else
    root=sock->_next;
  if (sock->_next)
    sock->_next->_prev = sock->_prev;

  // last chance to free other resources
  if (sock->handler)
    sock->handler(sock, sock->state, NULL, 0, sock->context);
    
  free_all_packets(&sock->tx);
  free_all_packets(&sock->rx);
  
  free(sock);
}

void msp_close(struct msp_sock *sock)
{
  // TODO if never sent / received, just free it
  sock->state |= MSP_STATE_CLOSED;
}

void msp_close_all(int mdp_sock)
{
  struct msp_sock *p = root;
  while(p){
    struct msp_sock *sock=p;
    p=p->_next;
    if (sock->mdp_sock == mdp_sock)
      msp_free(sock);
  }
}

int msp_set_handler(struct msp_sock *sock, 
  int (*handler)(struct msp_sock *sock, msp_state_t state, const uint8_t *payload, size_t len, void *context), 
  void *context)
{
  sock->handler = handler;
  sock->context = context;
  return 0;
}

msp_state_t msp_get_state(struct msp_sock *sock)
{
  return sock->state;
}

int msp_set_local(struct msp_sock *sock, struct mdp_sockaddr local)
{
  assert(sock->state == MSP_STATE_UNINITIALISED);
  sock->header.local = local;
  return 0;
}

int msp_set_remote(struct msp_sock *sock, struct mdp_sockaddr remote)
{
  assert(sock->state == MSP_STATE_UNINITIALISED);
  sock->header.remote = remote;
  sock->state|=MSP_STATE_DATAOUT;
  // make sure we send a packet soon
  sock->next_ack = gettime_ms()+10;
  sock->next_action = sock->next_ack;
  return 0;
}

int msp_listen(struct msp_sock *sock)
{
  assert(sock->state == MSP_STATE_UNINITIALISED);
  assert(sock->header.local.port);
  
  sock->state |= MSP_STATE_LISTENING;
  sock->header.flags |= MDP_FLAG_BIND;
  
  if (mdp_send(sock->mdp_sock, &sock->header, NULL, 0)==-1){
    sock->state|=MSP_STATE_ERROR|MSP_STATE_CLOSED;
    return -1;
  }
  
  sock->timeout = gettime_ms()+1000;
  sock->next_action = sock->timeout;
  return 0;
}

int msp_get_remote_adr(struct msp_sock *sock, struct mdp_sockaddr *remote)
{
  *remote = sock->header.remote;
  return 0;
}

static int add_packet(struct msp_window *window, uint16_t seq, uint8_t flags, 
  const uint8_t *payload, size_t len)
{
  
  struct msp_packet **insert_pos=NULL;
  
  if (!window->_head){
    insert_pos = &window->_head;
  }else{
    if (window->_tail->seq == seq){
      // ignore duplicate packets
      return 0;
    }else if (compare_wrapped_uint16(window->_tail->seq, seq)<0){
      if (compare_wrapped_uint16(window->_head->seq, seq)>0){
	// this is ambiguous
	return WHYF("%04x is both < tail (%04x) and > head (%04x)", seq, window->_tail->seq, window->_head->seq);
      }
      insert_pos = &window->_tail->_next;
    }else{
      insert_pos = &window->_head;
      while(compare_wrapped_uint16((*insert_pos)->seq, seq)<0)
	insert_pos = &(*insert_pos)->_next;
      if ((*insert_pos)->seq == seq){
	// ignore duplicate packets
	return 0;
      }
    }
  }
  
  struct msp_packet *packet = emalloc_zero(sizeof(struct msp_packet));
  if (!packet)
    return -1;
    
  packet->_next = (*insert_pos);
  *insert_pos = packet;
  if (!packet->_next)
    window->_tail = packet;
  packet->added = gettime_ms();
  packet->seq = seq;
  packet->flags = flags;
  packet->len = len;
  
  if (payload && len){
    uint8_t *p = emalloc(len);
    if (!p){
      free(packet);
      return -1;
    }
    packet->payload = p;
    bcopy(payload, p, len);
  }
  window->packet_count++;
  return 1;
}

struct socket_address daemon_addr={.addrlen=0,};

static int msp_send_packet(struct msp_sock *sock, struct msp_packet *packet)
{
  assert(sock->header.remote.port);
  if (daemon_addr.addrlen == 0){
    if (make_local_sockaddr(&daemon_addr, "mdp.2.socket") == -1)
      return -1;
  }
  
  uint8_t msp_header[5];

  msp_header[0]=packet->flags;
  
  // only set the ack flag if we've received a sequenced packet
  if (sock->state & MSP_STATE_RECEIVED_DATA)
    msp_header[0]|=FLAG_ACK;
  
  write_uint16(&msp_header[1], sock->rx.next_seq);
  write_uint16(&msp_header[3], packet->seq);
  sock->previous_ack = sock->rx.next_seq;
  
  struct fragmented_data data={
    .fragment_count=3,
    .iov={
      {
	.iov_base = (void*)&sock->header,
	.iov_len = sizeof(struct mdp_header)
      },
      {
	.iov_base = &msp_header,
	.iov_len = sizeof(msp_header)
      },
      {
	.iov_base = (void*)packet->payload,
	.iov_len = packet->len
      }
    }
  };
  
  // allow for sending an empty payload body
  if (!(packet->payload && packet->len))
    data.fragment_count --;
  
  ssize_t r = send_message(sock->mdp_sock, &daemon_addr, &data);
  if (r==-1){
    if (errno==11)
      return 1;
    msp_close_all(sock->mdp_sock);
    return -1;
  }
  if (config.debug.msp)
    DEBUGF("Sent packet seq %02x len %zd (acked %02x)", packet->seq, packet->len, sock->rx.next_seq);
  sock->tx.last_activity = packet->sent = gettime_ms();
  sock->next_ack = packet->sent + 1500;
  return 0;
}

static int send_ack(struct msp_sock *sock)
{
  assert(sock->header.remote.port);
  if (daemon_addr.addrlen == 0){
    if (make_local_sockaddr(&daemon_addr, "mdp.2.socket") == -1)
      return -1;
  }
  
  uint8_t msp_header[3];

  msp_header[0]=0;
  // if we haven't heard a sequence number, we can't ack data
  // (but we can indicate the existence of the connection)
  if (sock->state & MSP_STATE_RECEIVED_DATA)
    msp_header[0]|=FLAG_ACK;
    
  write_uint16(&msp_header[1], sock->rx.next_seq);
  
  struct fragmented_data data={
    .fragment_count=2,
    .iov={
      {
	.iov_base = (void*)&sock->header,
	.iov_len = sizeof(struct mdp_header)
      },
      {
	.iov_base = &msp_header,
	.iov_len = sizeof(msp_header)
      }
    }
  };
  
  ssize_t r = send_message(sock->mdp_sock, &daemon_addr, &data);
  if (r==-1){
    if (errno!=11)
      msp_close_all(sock->mdp_sock);
    return -1;
  }
  if (config.debug.msp)
    DEBUGF("Sent packet (acked %02x)", sock->rx.next_seq);
  sock->previous_ack = sock->rx.next_seq;
  sock->tx.last_activity = gettime_ms();
  sock->next_ack = sock->tx.last_activity + 1500;
  return 0;
}

// add a packet to the transmit buffer
int msp_send(struct msp_sock *sock, const uint8_t *payload, size_t len)
{
  assert(sock->header.remote.port);
  assert((sock->state & MSP_STATE_SHUTDOWN_LOCAL)==0);
  
  if (sock->tx.packet_count > MAX_WINDOW_SIZE)
    return -1;
  
  if (add_packet(&sock->tx, sock->tx.next_seq, 0, payload, len)==-1)
    return -1;
  
  sock->tx.next_seq++;
  if (sock->tx.packet_count>=MAX_WINDOW_SIZE)
    sock->state&=~MSP_STATE_DATAOUT;
  // make sure we attempt to process packets from this sock soon
  // TODO calculate based on congestion window
  sock->next_action = gettime_ms();
  
  return 0;
}

int msp_shutdown(struct msp_sock *sock)
{
  assert(!(sock->state&MSP_STATE_SHUTDOWN_LOCAL));
  if (sock->tx._tail && sock->tx._tail->sent==0){
    sock->tx._tail->flags |= FLAG_SHUTDOWN;
  }else{
    if (add_packet(&sock->tx, sock->tx.next_seq, FLAG_SHUTDOWN, NULL, 0)==-1)
      return -1;
    sock->tx.next_seq++;
  }
  sock->state|=MSP_STATE_SHUTDOWN_LOCAL;
  sock->state&=~MSP_STATE_DATAOUT;
  // make sure we send a packet soon
  sock->next_action = gettime_ms();
  return 0;
}

static int process_sock(struct msp_sock *sock)
{
  time_ms_t now = gettime_ms();
  
  if (sock->timeout < now){
    WHY("MSP socket timed out");
    sock->state |= (MSP_STATE_CLOSED|MSP_STATE_ERROR);
    return -1;
  }
  
  sock->next_action = sock->timeout;
  
  if (sock->state & MSP_STATE_LISTENING)
    return 0;
  
  struct msp_packet *p;
  
  // deliver packets that have now arrived in order
  p = sock->rx._head;
  
  // TODO ... ? (sock->state & MSP_STATE_POLLIN) 
  while(p && p->seq == sock->rx.next_seq){
    struct msp_packet *packet=p;
    
    // process packet flags when we are about to deliver the last packet
    if (packet->flags & FLAG_SHUTDOWN)
      sock->state|=MSP_STATE_SHUTDOWN_REMOTE;
    
    if (sock->handler){
      int r = sock->handler(sock, sock->state, packet->payload, packet->len, sock->context);
      if (r==-1){
	sock->state |= MSP_STATE_CLOSED;
	return -1;
      }
      // keep the packet if the handler refused to accept it.
      if (r){
	sock->next_action=gettime_ms()+1;
	break;
      }
    }
    
    p=p->_next;
    sock->rx.next_seq++;
  }
  free_acked_packets(&sock->rx, sock->rx.next_seq -1);
  
  // transmit packets that can now be sent
  p = sock->tx._head;
  while(p){
    if (p->sent==0 || p->sent + 1500 < now){
      if (!sock->header.local.port){
	if (sock->header.flags & MDP_FLAG_BIND)
	  // wait until we have heard back from the daemon with our port number before sending another packet.
	  break;
	sock->header.flags |= MDP_FLAG_BIND;
      }
      int r = msp_send_packet(sock, p);
      if (r==-1)
	return -1;
      if (r)
	break;
    }
    if (sock->next_action > p->sent + 1500)
      sock->next_action = p->sent + 1500;
    p=p->_next;
  }
  
  // should we send an ack now without sending a payload?
  if (now > sock->next_ack){
    if (!sock->header.local.port){
      if (sock->header.flags & MDP_FLAG_BIND)
	// wait until we have heard back from the daemon with our port number before sending another packet.
	return 0;
      sock->header.flags |= MDP_FLAG_BIND;
    }
    int r = send_ack(sock);
    if (r==-1)
      return -1;
  }
  
  if (sock->next_action > sock->next_ack)
    sock->next_action = sock->next_ack;
  
  if (sock->state & MSP_STATE_SHUTDOWN_LOCAL
    && sock->state & MSP_STATE_SHUTDOWN_REMOTE
    && sock->tx.packet_count == 0 
    && sock->rx.packet_count == 0
    && sock->previous_ack == sock->rx.next_seq){
    sock->state |= MSP_STATE_CLOSED;
    return -1;
  }
    
  return 0;
}

int msp_processing(time_ms_t *next_action)
{
  *next_action=TIME_NEVER_WILL;
  struct msp_sock *sock = root;
  time_ms_t now = gettime_ms();
  while(sock){
    if (!(sock->state & MSP_STATE_CLOSED)
      && sock->next_action <= now){
      // this might cause the socket to be closed.
      if (process_sock(sock)==0){
	// remember the time of the next thing we need to do.
	if (sock->next_action < *next_action)
	  *next_action=sock->next_action;
      }
    }else if (sock->next_action < *next_action)
      *next_action=sock->next_action;
    if (sock->state & MSP_STATE_CLOSED){
      struct msp_sock *s = sock->_next;
      msp_free(sock);
      sock=s;
    }else{
      sock = sock->_next;
    }
  }
  return 0;
}

static int process_packet(int mdp_sock, struct mdp_header *header, const uint8_t *payload, size_t len)
{
  // any kind of error reported by the daemon, close all related msp connections
  if (header->flags & MDP_FLAG_ERROR){
    WHY("Error returned from daemon");
    msp_close_all(mdp_sock);
    return -1;
  }

  // find or create mdp_sock...
  struct msp_sock *sock=NULL;
  {
    struct msp_sock *s=root;
    struct msp_sock *listen=NULL;
    while(s){
      if (s->mdp_sock == mdp_sock ){
	
	if ((s->header.flags & MDP_FLAG_BIND) && (header->flags & MDP_FLAG_BIND)){
	  // process bind response from the daemon
	  s->header.local = header->local;
	  s->header.flags &= ~MDP_FLAG_BIND;
	  if (config.debug.msp)
	    DEBUGF("Bound to %s:%d", alloca_tohex_sid_t(header->local.sid), header->local.port);
	  s->next_action = gettime_ms();
	  if (s->state & MSP_STATE_LISTENING)
	    s->timeout = TIME_NEVER_WILL;
	  return 0;
	}
	
	if (s->state & MSP_STATE_LISTENING){
	  // remember any matching listen socket so we can create a connection on first use
	  if (s->header.local.port == header->local.port
	    && (is_sid_t_any(s->header.local.sid) 
	    || memcmp(&s->header.local.sid, &header->local.sid, SID_SIZE)==0))
	    listen=s;
	}else if (memcmp(&s->header.remote, &header->remote, sizeof header->remote)==0
	  && memcmp(&s->header.local, &header->local, sizeof header->local)==0){
	  // if the addresses match, we found it.
	  sock=s;
	  break;
	}
      }
      s = s->_next;
    }
      
    if (listen && !sock){
      // create a new socket for the incoming connection
      sock = msp_socket(listen->mdp_sock);
      sock->header = *header;
      // use the same handler initially
      sock->handler = listen->handler;
      sock->context = listen->context;
    }
    
    if (!sock){
      WARNF("Unexpected packet from %s:%d", alloca_tohex_sid_t(header->remote.sid), header->remote.port);
      // TODO reply with shutdown ack to forcefully break the connection?
      return 0;
    }
  }
  
  if (len<3)
    return WHY("Expected at least 3 bytes");
  
  sock->rx.last_activity = gettime_ms();
  sock->timeout = sock->rx.last_activity + 10000;
  
  uint8_t flags = payload[0];
  
  if (flags & FLAG_ACK){
    uint16_t ack_seq = read_uint16(&payload[1]);
    // release acknowledged packets
    free_acked_packets(&sock->tx, ack_seq);
    
    // TODO if their ack seq has not advanced, we may need to hurry up and retransmit a packet
  }
  
  if (sock->tx.packet_count < MAX_WINDOW_SIZE 
    && !(sock->state & MSP_STATE_DATAOUT)
    && !(sock->state & MSP_STATE_SHUTDOWN_LOCAL)){
    sock->state|=MSP_STATE_DATAOUT;
    if (sock->handler)
      sock->handler(sock, sock->state, NULL, 0, sock->context);
  }
  
  // make sure we attempt to process packets from this sock soon
  // TODO calculate based on congestion window
  sock->state |= MSP_STATE_RECEIVED_PACKET;
  
  sock->next_action = gettime_ms();
  
  if (len<5)
    return 0;
  
  sock->state |= MSP_STATE_RECEIVED_DATA;
  uint16_t seq = read_uint16(&payload[3]);
  
  if (add_packet(&sock->rx, seq, flags, &payload[5], len - 5)==1)
    sock->next_ack = gettime_ms();
  return 0;
}

int msp_recv(int mdp_sock)
{
  
  struct mdp_header header;
  uint8_t payload[1200];
  
  ssize_t len = mdp_recv(mdp_sock, &header, payload, sizeof(payload));
  if (len<0)
    return -1;
  
  return process_packet(mdp_sock, &header, payload, len);
}

