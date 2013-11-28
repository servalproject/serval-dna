
#include <assert.h>
#include "serval.h"
#include "mdp_client.h"
#include "msp_client.h"
#include "str.h"
#include "dataformats.h"
#include "socket.h"
#include "log.h"

#define FLAG_SHUTDOWN (1<<0)

struct msp_packet{
  struct msp_packet *_next;
  uint16_t seq;
  uint8_t flags;
  time_ms_t added;
  time_ms_t sent;
  const uint8_t *payload;
  size_t len;
};

#define MAX_WINDOW_SIZE 64
struct msp_window{
  int packet_count;
  uint32_t base_rtt;
  uint32_t rtt;
  uint16_t next_seq; // seq of next expected TX or RX packet.
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
  int (*handler)(struct msp_sock *sock, msp_state_t state, const uint8_t *payload, size_t len, void *context);
  void *context;
  struct mdp_header header;
  time_ms_t last_rx;
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
  if (root)
    root->_prev=ret;
  root = ret;
  return ret;
}

static void free_all_packets(struct msp_window *window)
{
  struct msp_packet *p = window->_head;
  while(p){
    struct msp_packet *free_me=p;
    p=p->_next;
    free((void *)free_me->payload);
    free(free_me);
  }
}

static void free_acked_packets(struct msp_window *window, uint16_t seq)
{
  struct msp_packet *p = window->_head;
  uint32_t rtt=0;
  time_ms_t now = gettime_ms();

  while(p && compare_wrapped_uint16(p->seq, seq)<=0){
    if (p->sent)
      rtt = now - p->sent;
    struct msp_packet *free_me=p;
    p=p->_next;
    free((void *)free_me->payload);
    free(free_me);
    window->packet_count--;
  }
  window->_head = p;
  if (rtt){
    window->rtt = rtt;
    if (window->base_rtt > rtt)
      window->base_rtt = rtt;
  }
  if (!p)
    window->_tail = NULL;
}

void msp_close(struct msp_sock *sock)
{
  sock->state |= MSP_STATE_CLOSED;
  
  // last chance to free other resources
  if (sock->handler)
    sock->handler(sock, sock->state, NULL, 0, sock->context);
    
  if (sock->_prev)
    sock->_prev->_next = sock->_next;
  else
    root=sock->_next;
  if (sock->_next)
    sock->_next->_prev = sock->_prev;
  
  free_all_packets(&sock->tx);
  free_all_packets(&sock->rx);
  
  free(sock);
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

void msp_set_watch(struct msp_sock *sock, msp_state_t flags)
{
  assert(flags & ~(MSP_STATE_POLLIN|MSP_STATE_POLLOUT));
  // clear any existing poll bits, and set the requested ones
  sock->state &= ~(MSP_STATE_POLLIN|MSP_STATE_POLLOUT);
  sock->state |= flags;
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
  return 0;
}

int msp_listen(struct msp_sock *sock)
{
  assert(sock->state == MSP_STATE_UNINITIALISED);
  assert(sock->header.local.port);
  
  sock->state |= MSP_STATE_LISTENING;
  sock->header.flags |= MDP_FLAG_BIND;
  mdp_send(sock->mdp_sock, &sock->header, NULL, 0);
  
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
  struct msp_packet *packet = emalloc_zero(sizeof(struct msp_packet));
  if (!packet)
    return -1;
  
  if (!window->_head){
    window->_head = window->_tail = packet;
  }else{
    if (window->_tail->seq == seq){
      // ignore duplicate packets
      free(packet);
      return 0;
    }else if (compare_wrapped_uint16(window->_tail->seq, seq)<0){
      if (compare_wrapped_uint16(window->_head->seq, seq)>0){
	// this is ambiguous
	free(packet);
	return WHYF("%04x is both < tail (%04x) and > head (%04x)", seq, window->_tail->seq, window->_head->seq);
      }
      
      window->_tail->_next = packet;
      window->_tail = packet;
    }else{
      struct msp_packet **pos = &window->_head;
      while(compare_wrapped_uint16((*pos)->seq, seq)<0){
	if ((*pos)->seq == seq){
	  // ignore duplicate packets
	  free(packet);
	  return 0;
	}
	pos = &(*pos)->_next;
      }
      (*pos)->_next = packet;
      packet->_next = (*pos);
      *pos = packet;
    }
  }
  
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
  return 0;
}

struct socket_address daemon_addr={.addrlen=0,};

static int msp_send_packet(struct msp_sock *sock, struct msp_packet *packet)
{
  if (daemon_addr.addrlen == 0){
    if (make_local_sockaddr(&daemon_addr, "mdp.2.socket") == -1)
      return -1;
  }
  
  uint8_t msp_header[5];

  msp_header[0]=packet->flags;
  write_uint16(&msp_header[1], sock->rx.next_seq);
  write_uint16(&msp_header[3], packet->seq);
  sock->previous_ack = sock->rx.next_seq;
  
  DEBUGF("Sending packet flags %d, ack %d, seq %d", packet->flags, sock->rx.next_seq, packet->seq);
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
  if (r==-1)
    return -1;
  packet->sent = gettime_ms();
  if (!sock->timeout)
    sock->timeout = packet->sent + 10000;
  return 0;
}

static int send_ack(struct msp_sock *sock)
{
  D;
  if (daemon_addr.addrlen == 0){
    if (make_local_sockaddr(&daemon_addr, "mdp.2.socket") == -1)
      return -1;
  }
  
  uint8_t msp_header[3];

  msp_header[0]=0;
  write_uint16(&msp_header[1], sock->rx.next_seq);
  sock->previous_ack = sock->rx.next_seq;
  
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
  return r<0?-1:0;
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
  
  // make sure we attempt to process packets from this sock soon
  // TODO calculate based on congestion window
  sock->next_action = gettime_ms();
  
  return 0;
}

int msp_shutdown(struct msp_sock *sock)
{
  if (sock->tx._tail && sock->tx._tail->sent==0){
    sock->tx._tail->flags |= FLAG_SHUTDOWN;
  }else{
    if (add_packet(&sock->tx, sock->tx.next_seq, FLAG_SHUTDOWN, NULL, 0)==-1)
      return -1;
    sock->tx.next_seq++;
  }
  sock->state|=MSP_STATE_SHUTDOWN_LOCAL;
  return 0;
}

static int process_sock(struct msp_sock *sock)
{
  time_ms_t now = gettime_ms();
  
  if (sock->timeout && sock->timeout < now){
    msp_close(sock);
    return -1;
  }
  
  sock->next_action = sock->timeout;
  struct msp_packet *p;
  
  // deliver packets that have now arrived in order
  p = sock->rx._head;
  if (p)
    DEBUGF("Seq %d vs %d", p->seq, sock->rx.next_seq);
  
  // TODO ... ? (sock->state & MSP_STATE_POLLIN) 
  while(p && p->seq == sock->rx.next_seq){
    struct msp_packet *packet=p;
    
    // process packet flags when we have delivered the packet
    if (packet->flags & FLAG_SHUTDOWN)
      sock->state|=MSP_STATE_SHUTDOWN_REMOTE;
    
    if (sock->handler
      && sock->handler(sock, sock->state, packet->payload, packet->len, sock->context)==-1){
      // keep the packet if the handler refused to accept it.
      break;
    }
    
    p=p->_next;
    sock->rx.next_seq++;
  }
  free_acked_packets(&sock->rx, sock->rx.next_seq -1);
  
  // transmit packets that can now be sent
  p = sock->tx._head;
  while(p){
    if (p->sent==0 || p->sent + sock->tx.rtt*2 < now){
      
      if (!(sock->state & (MSP_STATE_CONNECTING|MSP_STATE_CONNECTED))){
	sock->state |= MSP_STATE_CONNECTING;
	sock->header.flags |= MDP_FLAG_BIND;
	
      }else if (!sock->header.local.port){
	// wait until we have heard back from the daemon with our port number before sending another packet.
	break;
      }
      if (msp_send_packet(sock, p)==-1)
	return -1;
    }
    if (sock->next_action > p->sent + sock->tx.rtt*2)
      sock->next_action = p->sent + sock->tx.rtt*2;
    p=p->_next;
  }
  
  // should we send an ack now without sending a payload?
  if (sock->previous_ack != sock->rx.next_seq){
    if (send_ack(sock))
      return -1;
  }
  
  if ((sock->state & (MSP_STATE_SHUTDOWN_LOCAL|MSP_STATE_SHUTDOWN_REMOTE)) == (MSP_STATE_SHUTDOWN_LOCAL|MSP_STATE_SHUTDOWN_REMOTE)
    && sock->tx.packet_count == 0 
    && sock->rx.packet_count == 0){
    msp_close(sock);
    return -1;
  }
    
  return 0;
}

int msp_processing(time_ms_t *next_action)
{
  *next_action=0;
  struct msp_sock *sock = root;
  time_ms_t now = gettime_ms();
  while(sock){
    struct msp_sock *s=sock;
    sock = s->_next;
    
    if (s->next_action && s->next_action <= now){
      // this might cause the socket to be closed.
      if (process_sock(s)==0){
	// remember the time of the next thing we need to do.
	if (s->next_action!=0 && s->next_action < *next_action)
	  *next_action=s->next_action;
      }
    }
  }
  return 0;
}

static struct msp_sock * find_connection(int mdp_sock, struct mdp_header *header)
{
  struct msp_sock *s=root;
  struct msp_sock *listen=NULL;
  while(s){
    if (s->mdp_sock == mdp_sock ){
      if ((s->header.flags & MDP_FLAG_BIND) && (header->flags & MDP_FLAG_BIND)){
	// bind response from the daemon
	s->header.local = header->local;
	s->header.flags &= ~MDP_FLAG_BIND;
	DEBUGF("Bound to %s:%d", alloca_tohex_sid_t(header->local.sid), header->local.port);
	return NULL;
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
	return s;
      }
    }
    s = s->_next;
  }
    
  if (listen){
    // create socket for incoming connection
    s = msp_socket(listen->mdp_sock);
    s->header = *header;
    // use the same handler initially
    s->handler = listen->handler;
    s->context = listen->context;
    return s;
  }
  
  WARNF("Unexpected packet from %s:%d", alloca_tohex_sid_t(header->remote.sid), header->remote.port);
  return NULL;
}

static int process_packet(int mdp_sock, struct mdp_header *header, const uint8_t *payload, size_t len)
{
  DEBUGF("packet from %s:%d", alloca_tohex_sid_t(header->remote.sid), header->remote.port);
  // find or create mdp_sock...
  struct msp_sock *sock=find_connection(mdp_sock, header);

  if (!sock)
    return 0;
  
  if (len<3)
    return WHY("Expected at least 3 bytes");
  
  sock->state |= MSP_STATE_CONNECTED;
  sock->last_rx = gettime_ms();
  sock->timeout = sock->last_rx + 10000;
  
  uint8_t flags = payload[0];
  
  uint16_t ack_seq = read_uint16(&payload[1]);
  
  // release acknowledged packets
  free_acked_packets(&sock->tx, ack_seq);
  
  // TODO if their ack seq has not advanced, we may need to hurry up and retransmit a packet
  
  
  // make sure we attempt to process packets from this sock soon
  // TODO calculate based on congestion window
  sock->next_action = gettime_ms();
  
  if (len<5)
    return 0;
  
  uint16_t seq = read_uint16(&payload[3]);
  
  add_packet(&sock->rx, seq, flags, &payload[5], len - 5);
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

