/*
 Mesh Stream Protocol (MSP)
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
#define FLAG_FIRST (1<<2)
#define FLAG_STOP (1<<3)
#define RETRANSMIT_TIME 1500
#define HANDLER_KEEPALIVE 1000

struct msp_packet{
  struct msp_packet *_next;
  uint16_t seq;
  uint8_t flags;
  time_ms_t added;
  time_ms_t sent;
  const uint8_t *payload;
  size_t len;
  size_t offset;
};

#define MAX_WINDOW_SIZE 4
struct msp_window{
  unsigned packet_count;
  uint32_t base_rtt;
  uint32_t rtt;
  uint16_t next_seq; // seq of next expected TX or RX packet.
  time_ms_t last_activity;
  struct msp_packet *_head, *_tail;
};

struct msp_sock{
  struct msp_sock *_next;
  struct msp_sock *_prev;
  unsigned salt;
  int mdp_sock;
  msp_state_t state;
  msp_state_t last_state;
  time_ms_t last_handler;
  struct msp_window tx;
  struct msp_window rx;
  uint16_t previous_ack;
  time_ms_t next_ack;
  MSP_HANDLER *handler;
  void *context;
  struct mdp_header header;
  time_ms_t timeout;
  time_ms_t next_action;
};

#define SALT_INVALID 0xdeadbeef

int msp_socket_is_valid(MSP_SOCKET handle)
{
  // TODO Set up temporary SIGSEGV and SIGBUS handlers in case handle.ptr points to unmapped memory
  // or is misaligned, which could happen if the handle has never been initialised or free() calls
  // munmap(2) on unused areas.  That is an O(1) solution that involves a couple of system calls.
  // An alternative O(n) solution without system calls would be to scan the socket linked list to
  // see if handle.ptr is in it.  A third, O(1) solution but O(n) in memory and involving more
  // malloc() calls would be to add a new layer of pointer indirection between handles and msp_sock
  // structs, and zero the indirect pointer on free().
  // 
  // TODO also perform consistency checks on the _next and _prev pointers (requires SIGSEGV
  // and SIGBUS handler in place).
  return handle.ptr != NULL && handle.salt == handle.ptr->salt;
}

static inline struct msp_sock * handle_to_sock(const struct msp_handle *handle)
{
  assert(handle != NULL);
  assert(handle->ptr != NULL);
  assert(handle->salt == handle->ptr->salt); // could SEGV is handle has not been initialised
  return handle->ptr;
}

static inline struct msp_handle sock_to_handle(struct msp_sock *sock)
{
  return (struct msp_handle){ .ptr = sock, .salt = sock->salt };
}

static struct msp_sock *root=NULL;
static unsigned salt_counter = 0;

MSP_SOCKET msp_socket(int mdp_sock, int flags)
{
  if (flags != 0) {
    WHYF("unsupported flags = %#x", flags);
    return MSP_SOCKET_NULL;
  }
  struct msp_sock *sock = emalloc_zero(sizeof(struct msp_sock));
  if (sock == NULL)
    return MSP_SOCKET_NULL;
  if (++salt_counter == SALT_INVALID)
    ++salt_counter;
  sock->salt = salt_counter;
  sock->mdp_sock = mdp_sock;
  sock->state = MSP_STATE_UNINITIALISED;
  sock->last_state = 0xFFFF;
  sock->last_handler = TIME_MS_NEVER_HAS;
  // TODO set base rtt to ensure that we send the first packet a few times before giving up
  sock->tx.base_rtt = sock->tx.rtt = 0xFFFFFFFF;
  sock->tx.last_activity = TIME_MS_NEVER_HAS;
  sock->rx.last_activity = TIME_MS_NEVER_HAS;
  sock->next_action = TIME_MS_NEVER_WILL;
  sock->timeout = gettime_ms() + 10000;
  sock->previous_ack = 0x7FFF;
  sock->_next = root;
  if (root)
    root->_prev = sock;
  root = sock;
  return sock_to_handle(sock);
}

msp_state_t msp_get_state(MSP_SOCKET handle)
{
  return handle_to_sock(&handle)->state;
}

int msp_socket_is_initialising(MSP_SOCKET handle)
{
    return msp_socket_is_valid(handle) && msp_get_state(handle) == MSP_STATE_UNINITIALISED;
}

int msp_socket_is_open(MSP_SOCKET handle)
{
    if (!msp_socket_is_valid(handle))
        return 0;
    msp_state_t state = msp_get_state(handle);
    return (state != MSP_STATE_UNINITIALISED || handle_to_sock(&handle)->tx.packet_count != 0)
        && !(state & MSP_STATE_CLOSED);
}

int msp_socket_is_closed(MSP_SOCKET handle)
{
    return !msp_socket_is_valid(handle) || (msp_get_state(handle) & MSP_STATE_CLOSED) != 0;
}

int msp_socket_is_listening(MSP_SOCKET handle)
{
    return msp_socket_is_valid(handle) && (msp_get_state(handle) & MSP_STATE_LISTENING);
}

int msp_socket_is_data(MSP_SOCKET handle)
{
    return msp_socket_is_valid(handle)
        && ((msp_get_state(handle) & MSP_STATE_DATAOUT) || handle_to_sock(&handle)->tx.packet_count != 0);
}

int msp_socket_is_connected(MSP_SOCKET handle)
{
    return msp_socket_is_valid(handle) && (msp_get_state(handle) & MSP_STATE_RECEIVED_PACKET);
}

int msp_socket_is_shutdown_local(MSP_SOCKET handle)
{
    return msp_socket_is_valid(handle) && (msp_get_state(handle) & MSP_STATE_SHUTDOWN_LOCAL) != 0;
}

int msp_socket_is_shutdown_remote(MSP_SOCKET handle)
{
    return msp_socket_is_valid(handle) && (msp_get_state(handle) & MSP_STATE_SHUTDOWN_REMOTE) != 0;
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
  window->_head = NULL;
  window->packet_count=0;
}

static void free_acked_packets(struct msp_window *window, uint16_t seq)
{
  if (!window->_head)
    return;
  struct msp_packet *p = window->_head;
  uint32_t rtt=0xFFFFFFFF, rtt_max=0;
  time_ms_t now = gettime_ms();

  while(p && compare_wrapped_uint16(p->seq, seq)<=0){
    if (p->sent!=TIME_MS_NEVER_HAS){
      uint32_t this_rtt=now - p->sent;
      if (rtt > this_rtt)
	rtt = this_rtt;
      if (rtt_max < this_rtt)
	rtt_max = this_rtt;
    }
    struct msp_packet *free_me=p;
    p=p->_next;
    if (free_me->payload)
      free((void *)free_me->payload);
    free(free_me);
    window->packet_count--;
  }
  window->_head = p;
  if (rtt!=0xFFFFFFFF){
    if (rtt < 10)
      rtt=10;
    window->rtt = rtt;
    if (window->base_rtt > rtt)
      window->base_rtt = rtt;
    if (config.debug.msp)
      DEBUGF("ACK %x, RTT %u-%u, base %u", seq, rtt, rtt_max, window->base_rtt);
  }
  if (!p)
    window->_tail = NULL;
}

// call the handler if we need to
static size_t call_handler(struct msp_sock *sock, const uint8_t *payload, size_t len)
{
  // no handler? just consume everything
  size_t nconsumed = len;
  time_ms_t now = gettime_ms();
  if (sock->handler && (len || sock->last_state != sock->state || now - sock->last_handler > HANDLER_KEEPALIVE)) {
    // remember what we are about to call, rather than what we just called
    // we don't want to miss a state change due to re-entrancy.
    sock->last_state = sock->state;
    sock->last_handler = now;
    nconsumed = sock->handler(sock_to_handle(sock), sock->state, payload, len, sock->context);
    assert(nconsumed <= len);
  }
  return nconsumed;
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

  free_all_packets(&sock->tx);
  free_all_packets(&sock->rx);
  
  // one last chance for clients to free other resources
  call_handler(sock, NULL, 0);
  sock->salt = SALT_INVALID; // invalidate all handles that point here
  free(sock);
}

void msp_stop(MSP_SOCKET handle)
{
  struct msp_sock *sock = handle_to_sock(&handle);
  if (sock->state & MSP_STATE_STOPPED)
    return;
  
  sock->state |= MSP_STATE_STOPPED | MSP_STATE_CLOSED;
  sock->state &= ~MSP_STATE_DATAOUT;
  
  // if this a connectable socket, send a stop packet
  if (sock->header.remote.port && !(sock->state & MSP_STATE_LISTENING)){
    uint8_t response = FLAG_STOP;
    // we don't have a matching socket, reply with STOP flag to force breaking the connection
    // TODO global rate limit?
    mdp_send(sock->mdp_sock, &sock->header, &response, 1);
    if (config.debug.msp)
      DEBUGF("Sending STOP packet");
  }
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

void msp_set_handler(MSP_SOCKET handle, MSP_HANDLER *handler, void *context)
{
  struct msp_sock *sock = handle_to_sock(&handle);
  sock->handler = handler;
  sock->context = context;
}

void msp_set_local(MSP_SOCKET handle, const struct mdp_sockaddr *local)
{
  struct msp_sock *sock = handle_to_sock(&handle);
  assert(sock->state == MSP_STATE_UNINITIALISED);
  sock->header.local = *local;
}

void msp_connect(MSP_SOCKET handle, const struct mdp_sockaddr *remote)
{
  struct msp_sock *sock = handle_to_sock(&handle);
  assert(sock->state == MSP_STATE_UNINITIALISED);
  sock->header.remote = *remote;
  sock->state|=MSP_STATE_DATAOUT;
  // make sure we send a packet soon
  sock->next_ack = gettime_ms()+10;
  sock->next_action = sock->next_ack;
}

int msp_listen(MSP_SOCKET handle)
{
  struct msp_sock *sock = handle_to_sock(&handle);
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

void msp_get_local(MSP_SOCKET handle, struct mdp_sockaddr *local)
{
  *local = handle_to_sock(&handle)->header.local;
}

void msp_get_remote(MSP_SOCKET handle, struct mdp_sockaddr *remote)
{
  *remote = handle_to_sock(&handle)->header.remote;
}

static int add_packet(struct msp_window *window, uint16_t seq, uint8_t flags, const uint8_t *payload, size_t len)
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
  packet->offset = 0;
  packet->sent = TIME_MS_NEVER_HAS;
  
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
  
  uint8_t msp_header[MSP_PAYLOAD_PREAMBLE_SIZE];

  msp_header[0]=packet->flags;
  
  // only set the ack flag if we've received a sequenced packet
  if (sock->state & MSP_STATE_RECEIVED_DATA)
    msp_header[0]|=FLAG_ACK;
  // never received anything? set the connect flag
  if (!(sock->state & MSP_STATE_RECEIVED_PACKET))
    msp_header[0]|=FLAG_FIRST;
  
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
    DEBUGF("Sent packet flags %02x seq %02x len %zd (acked %02x)", msp_header[0], packet->seq, packet->len, sock->rx.next_seq);
  sock->tx.last_activity = packet->sent = gettime_ms();
  sock->next_ack = packet->sent + RETRANSMIT_TIME;
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
  
  // never received anything? set the connect flag
  if (!(sock->state & MSP_STATE_RECEIVED_PACKET))
    msp_header[0]|=FLAG_FIRST;
    
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
    DEBUGF("Sent packet flags %02x (acked %02x)", msp_header[0], sock->rx.next_seq);
  sock->previous_ack = sock->rx.next_seq;
  sock->tx.last_activity = gettime_ms();
  sock->next_ack = sock->tx.last_activity + RETRANSMIT_TIME;
  return 0;
}

// add a packet to the transmit buffer
ssize_t msp_send(MSP_SOCKET handle, const uint8_t *payload, size_t len)
{
  struct msp_sock *sock = handle_to_sock(&handle);
  assert(!(sock->state&MSP_STATE_LISTENING));
  assert(sock->header.remote.port);
  assert((sock->state & MSP_STATE_SHUTDOWN_LOCAL)==0);
  
  if ((sock->state & MSP_STATE_CLOSED) || sock->tx.packet_count > MAX_WINDOW_SIZE)
    return -1;
  if (add_packet(&sock->tx, sock->tx.next_seq, 0, payload, len)==-1)
    return -1;
  
  sock->tx.next_seq++;
  if (sock->tx.packet_count>=MAX_WINDOW_SIZE)
    sock->state&=~MSP_STATE_DATAOUT;
  // make sure we attempt to process packets from this sock soon
  // TODO calculate based on congestion window
  sock->next_action = gettime_ms();
  
  return len;
}

int msp_shutdown(MSP_SOCKET handle)
{
  struct msp_sock *sock = handle_to_sock(&handle);
  assert(!(sock->state&MSP_STATE_LISTENING));
  assert(!(sock->state&MSP_STATE_SHUTDOWN_LOCAL));
  if (sock->tx._tail && sock->tx._tail->sent==TIME_MS_NEVER_HAS){
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

// test if there is already a socket being bound
static int pending_bind(int fd)
{
  struct msp_sock *s = root;
  while(s){
    if (s->mdp_sock == fd && s->header.flags & MDP_FLAG_BIND)
      return 1;
    s=s->_next;
  }
  return 0;
}

static int process_sock(struct msp_sock *sock)
{
  time_ms_t now = gettime_ms();
  
  if (sock->timeout < now){
    sock->state |= (MSP_STATE_CLOSED|MSP_STATE_ERROR);
    return WHY("MSP socket timed out");
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
    
    assert(packet->offset <= packet->len);
    size_t nconsumed = call_handler(sock, packet->payload + packet->offset, packet->len - packet->offset);
    
    // stop calling the handler if nothing was consumed
    // TODO wait for the library to call back deliberately?
    if (nconsumed == 0 && packet->len > packet->offset)
      break;
    
    packet->offset += nconsumed;
    // keep the packet if the handler has not consumed it all, let the handler try again
    if (packet->offset < packet->len)
      continue;
    assert(packet->offset == packet->len);
    
    p=p->_next;
    sock->rx.next_seq++;
  }
  free_acked_packets(&sock->rx, sock->rx.next_seq -1);
  
  call_handler(sock, NULL, 0);
  if (sock->handler && sock->next_action > sock->last_handler + HANDLER_KEEPALIVE)
    sock->next_action = sock->last_handler + HANDLER_KEEPALIVE;
  unsigned count=0;
  p = sock->tx._head;
  while(p){
    count++;
    p=p->_next;
  }
  assert(count == sock->tx.packet_count);
  
  if (count >= MAX_WINDOW_SIZE || (sock->state & (MSP_STATE_CLOSED|MSP_STATE_SHUTDOWN_LOCAL)))
    assert(!(sock->state & MSP_STATE_DATAOUT));
  else
    assert(sock->state & MSP_STATE_DATAOUT);
    
  // transmit packets that can now be sent
  p = sock->tx._head;
  while(p){
    if (p->sent + RETRANSMIT_TIME < now){
      if (!sock->header.local.port){
	// if there's already a binding being processed, wait for it to complete
	if (pending_bind(sock->mdp_sock))
	  break;
	sock->header.flags |= MDP_FLAG_BIND;
      }
      int r = msp_send_packet(sock, p);
      if (r==-1)
	return -1;
      if (r)
	break;
    }
    if (sock->next_action > p->sent + RETRANSMIT_TIME)
      sock->next_action = p->sent + RETRANSMIT_TIME;
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
  
  // when we've delivered all local packets
  // and all our data packets have been acked, close.
  if (   (sock->state & MSP_STATE_SHUTDOWN_LOCAL)
      && (sock->state & MSP_STATE_SHUTDOWN_REMOTE)
      && sock->tx.packet_count == 0
      && sock->rx.packet_count == 0
      && sock->previous_ack == sock->rx.next_seq
  ){
    sock->state |= MSP_STATE_CLOSED;
    return -1;
  }
    
  return 0;
}

static void msp_release(struct msp_sock *sock){
  if (!sock->header.local.port)
    return;
  
  // release mdp port binding when there are no other sockets using it.
  struct msp_sock *o = root;
  while(o){
    if (o!=sock 
    && o->mdp_sock == sock->mdp_sock 
    && o->header.local.port == sock->header.local.port)
      return;
    o=o->_next;
  }
  
  struct mdp_header header;
  bzero(&header, sizeof header);
  
  header.local = sock->header.local;
  header.remote.sid = SID_ANY;
  header.remote.port = MDP_LISTEN;
  header.flags = MDP_FLAG_CLOSE;
  if (config.debug.msp)
    DEBUGF("Releasing mdp port binding %d", header.local.port);
  mdp_send(sock->mdp_sock, &header, NULL, 0);
  sock->header.local.port=0;
  sock->header.local.sid=SID_ANY;
}

int msp_processing(time_ms_t *next_action)
{
  time_ms_t next=TIME_MS_NEVER_WILL;
  struct msp_sock *sock = root;
  while(sock){
    // this might cause the socket to be closed
    // remember the time of the next thing we need to do.
    process_sock(sock);
    
    if (sock->state & MSP_STATE_CLOSED){
      struct msp_sock *s = sock->_next;
      msp_release(sock);
      msp_free(sock);
      sock=s;
    }else{
      if (sock->next_action < next)
	next=sock->next_action;
      sock = sock->_next;
    }
  }
  *next_action=next;
  return 0;
}

static int process_packet(int mdp_sock, struct mdp_header *header, const uint8_t *payload, size_t len)
{
  // any kind of error reported by the daemon, close all related msp connections on this mdp socket
  if (header->flags & MDP_FLAG_ERROR){
    WHY("Error returned from daemon!");
    return -1;
  }
  
  uint8_t flags=0;
  
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
	  if (s->state & MSP_STATE_LISTENING)
	    s->next_action = s->timeout = TIME_MS_NEVER_WILL;
	  else
	    s->next_action = gettime_ms();
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
    
    if (len<1)
      return WHY("Expected at least 1 byte");
    flags = payload[0];
    
    // ignore any stop packet if we have no matching connection
    if (!sock && flags & FLAG_STOP){
      if (config.debug.msp)
        DEBUGF("Ignoring STOP packet, no matching connection");
      return 0;
    }
    
    if (listen && (flags&FLAG_FIRST) && !sock){
      // create a new socket for incoming connections
      MSP_SOCKET handle = msp_socket(listen->mdp_sock, 0);
      sock = handle.ptr;
      if (sock) {
	sock->header = *header;
	// use the same handler initially
	sock->handler = listen->handler;
	sock->context = listen->context;
      }
    }
    
    if (!sock){
      uint8_t response = FLAG_STOP;
      // we don't have a matching socket, reply with STOP flag to force breaking the connection
      // TODO global rate limit?
      // Note that we might recieve a queued packet after sending a MDP_FLAG_CLOSE, so this might trigger an error
      mdp_send(mdp_sock, header, &response, 1);
      if (config.debug.msp)
	DEBUGF("Replying to unexpected packet with STOP packet");
      return 0;
    }
  }
  
  sock->rx.last_activity = gettime_ms();
  sock->timeout = sock->rx.last_activity + 10000;
  sock->state |= MSP_STATE_RECEIVED_PACKET;
  
  if (flags & FLAG_STOP){
    if (config.debug.msp)
      DEBUGF("Closing socket due to STOP packet");
    msp_stop(sock_to_handle(sock));
    return 0;
  }
  
  if (len<3)
    return 0;
  
  if (flags & FLAG_ACK){
    uint16_t ack_seq = read_uint16(&payload[1]);
    // release acknowledged packets
    free_acked_packets(&sock->tx, ack_seq);
    
    // TODO if their ack seq has not advanced, we may need to hurry up and retransmit a packet
  }
  
  // we might have space for more data now
  if (sock->tx.packet_count < MAX_WINDOW_SIZE 
    && !(sock->state & MSP_STATE_SHUTDOWN_LOCAL)
    && !(sock->state & MSP_STATE_CLOSED)){
    sock->state|=MSP_STATE_DATAOUT;
  }
  
  // make sure we attempt to process packets from this sock soon
  // TODO calculate based on congestion window
  sock->next_action = gettime_ms();
  
  if (len<MSP_PAYLOAD_PREAMBLE_SIZE)
    return 0;
  
  sock->state |= MSP_STATE_RECEIVED_DATA;
  uint16_t seq = read_uint16(&payload[3]);
  
  if (add_packet(&sock->rx, seq, flags, &payload[MSP_PAYLOAD_PREAMBLE_SIZE], len - MSP_PAYLOAD_PREAMBLE_SIZE)==1)
    sock->next_ack = gettime_ms();
  return 0;
}

int msp_recv(int mdp_sock)
{
  struct mdp_header header;
  uint8_t payload[1200];
  ssize_t len = mdp_recv(mdp_sock, &header, payload, sizeof(payload));
  if (len == -1)
    return -1;
  return process_packet(mdp_sock, &header, payload, len);
}
