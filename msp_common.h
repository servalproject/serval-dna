#ifndef __SERVAL_DNA__MSP_COMMON_H
#define __SERVAL_DNA__MSP_COMMON_H

#include "debug.h"

#define FLAG_SHUTDOWN (1<<0)
#define FLAG_ACK (1<<1)
#define FLAG_FIRST (1<<2)
#define FLAG_STOP (1<<3)
#define RETRANSMIT_TIME 1500
#define HANDLER_KEEPALIVE 1000

typedef uint16_t msp_state_t;

struct msp_packet{
  struct msp_packet *_next;
  uint16_t seq;
  uint8_t flags;
  time_ms_t added;
  time_ms_t sent;
  size_t len;
  size_t offset;
  uint8_t payload[];
};

#define MAX_WINDOW_SIZE 4
struct msp_window{
  unsigned packet_count;
  uint32_t base_rtt;
  uint32_t rtt;
  uint16_t next_seq; // seq of next expected TX or RX packet.
  time_ms_t last_activity;
  time_ms_t last_packet;
  struct msp_packet *_head, *_tail;
};

struct msp_stream{
  msp_state_t state;
  struct msp_window tx;
  struct msp_window rx;
  uint16_t previous_ack;
  time_ms_t next_ack;
  time_ms_t timeout;
  time_ms_t next_action;
};

static void msp_stream_init(struct msp_stream *stream)
{
  stream->state = MSP_STATE_UNINITIALISED;
  // TODO set base rtt to ensure that we send the first packet a few times before giving up
  stream->tx.base_rtt = stream->tx.rtt = 0xFFFFFFFF;
  stream->tx.last_activity = TIME_MS_NEVER_HAS;
  stream->tx.last_packet = TIME_MS_NEVER_HAS;
  stream->rx.last_activity = TIME_MS_NEVER_HAS;
  stream->rx.last_packet = TIME_MS_NEVER_HAS;
  stream->next_action = TIME_MS_NEVER_WILL;
  stream->timeout = gettime_ms() + 10000;
  stream->previous_ack = 0x7FFF;
}

static void free_all_packets(struct msp_window *window)
{
  struct msp_packet *p = window->_head;
  while(p){
    struct msp_packet *free_me=p;
    p=p->_next;
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
    DEBUGF(msp, "ACK %x, RTT %u-%u, base %u", seq, rtt, rtt_max, window->base_rtt);
  }
  if (!p)
    window->_tail = NULL;
}

static int add_packet(struct msp_window *window, uint16_t seq, uint8_t flags, const uint8_t *payload, size_t len)
{
  assert(payload || len==0);
  struct msp_packet **insert_pos=NULL;
  
  if (!window->_head){
    insert_pos = &window->_head;
  }else{
    if (window->_tail->seq == seq){
      // ignore duplicate packets
      DEBUGF(msp, "Ignore duplicate packet %02x", seq);
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
	DEBUGF(msp, "Ignore duplicate packet %02x", seq);
	return 0;
      }
    }
  }
  
  struct msp_packet *packet = emalloc_zero(sizeof(struct msp_packet) + len);
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
  
  if (len)
    bcopy(payload, packet->payload, len);
  window->packet_count++;
  DEBUGF(msp, "Add packet %02x", seq);
  return 1;
}

static size_t msp_write_ack_header(uint8_t *header, struct msp_stream *stream)
{
  header[0]=0;
  // if we haven't heard a sequence number, we can't ack data
  // (but we can indicate the existence of the connection)
  if (stream->state & MSP_STATE_RECEIVED_DATA)
    header[0]|=FLAG_ACK;
  
  // never received anything? set the connect flag
  if (!(stream->state & MSP_STATE_RECEIVED_PACKET))
    header[0]|=FLAG_FIRST;
    
  write_uint16(&header[1], stream->rx.next_seq -1);
  
  stream->previous_ack = stream->rx.next_seq -1;
  stream->tx.last_activity = gettime_ms();
  stream->next_ack = stream->tx.last_activity + RETRANSMIT_TIME;
  
  DEBUGF(msp, "Sending packet flags %02x (acked %02x)", 
    header[0], stream->rx.next_seq -1);
  return 3;
}

static size_t msp_write_preamble(uint8_t *header, struct msp_stream *stream, struct msp_packet *packet)
{
  msp_write_ack_header(header, stream);
  header[0]|=packet->flags;
  
  write_uint16(&header[3], packet->seq);
  
  DEBUGF(msp, "With packet flags %02x seq %02x len %zd", 
    header[0], packet->seq, packet->len);
  packet->sent = stream->tx.last_packet = stream->tx.last_activity;
  return MSP_PAYLOAD_PREAMBLE_SIZE;
}

static ssize_t msp_stream_send(struct msp_stream *stream, const uint8_t *payload, size_t len)
{
  assert(!(stream->state & MSP_STATE_LISTENING));
  assert((stream->state & MSP_STATE_SHUTDOWN_LOCAL)==0);
  
  if ((stream->state & MSP_STATE_CLOSED) || stream->tx.packet_count > MAX_WINDOW_SIZE)
    return -1;
  if (add_packet(&stream->tx, stream->tx.next_seq, 0, payload, len)==-1)
    return -1;
  
  stream->tx.next_seq++;
  if (stream->tx.packet_count>=MAX_WINDOW_SIZE)
    stream->state&=~MSP_STATE_DATAOUT;
  // make sure we attempt to process packets from this sock soon
  // TODO calculate based on congestion window
  stream->next_action = gettime_ms();
  
  return len;
}

static int msp_stream_shutdown(struct msp_stream *stream)
{
  assert(!(stream->state&MSP_STATE_LISTENING));
  assert(!(stream->state&MSP_STATE_SHUTDOWN_LOCAL));
  if (stream->tx._tail && stream->tx._tail->sent==TIME_MS_NEVER_HAS){
    stream->tx._tail->flags |= FLAG_SHUTDOWN;
  }else{
    if (add_packet(&stream->tx, stream->tx.next_seq, FLAG_SHUTDOWN, NULL, 0)==-1)
      return -1;
    stream->tx.next_seq++;
  }
  stream->state|=MSP_STATE_SHUTDOWN_LOCAL;
  stream->state&=~MSP_STATE_DATAOUT;
  // make sure we send a packet soon
  stream->next_action = gettime_ms();
  return 0;
}

static int msp_stream_process(struct msp_stream *stream)
{
  time_ms_t now = gettime_ms();
  if (stream->timeout < now){
    stream->state |= (MSP_STATE_CLOSED|MSP_STATE_ERROR);
    return WHY("MSP socket timed out");
  }
  
  if (stream->state & MSP_STATE_LISTENING)
    return 1;
  
  // when we've delivered all local packets
  // and all our data packets have been acked, close.
  if (   (stream->state & MSP_STATE_SHUTDOWN_LOCAL)
      && (stream->state & MSP_STATE_SHUTDOWN_REMOTE)
      && stream->tx.packet_count == 0
      && stream->rx.packet_count == 0
      && stream->previous_ack == stream->rx.next_seq -1
  )
    stream->state |= MSP_STATE_CLOSED;

  return 0;
}

// return the next in-order packet
static struct msp_packet *msp_stream_next(struct msp_stream *stream)
{
  struct msp_packet *packet = stream->rx._head;
  if (!packet || packet->seq != stream->rx.next_seq)
    return NULL;

  assert(packet->offset <= packet->len);
  
  if (packet->flags & FLAG_SHUTDOWN)
    stream->state|=MSP_STATE_SHUTDOWN_REMOTE;
  
  return packet;
}

static void msp_consume_packet(struct msp_stream *stream, struct msp_packet *packet, size_t consumed)
{
  assert(packet->seq==stream->rx.next_seq);
  packet->offset += consumed;
  if (packet->offset < packet->len)
    return;
  
  free_acked_packets(&stream->rx, stream->rx.next_seq);
  stream->rx.next_seq++;
  
  // when we've delivered all local packets
  // and all our data packets have been acked, close.
  if (   (stream->state & MSP_STATE_SHUTDOWN_LOCAL)
      && (stream->state & MSP_STATE_SHUTDOWN_REMOTE)
      && stream->tx.packet_count == 0
      && stream->rx.packet_count == 0
      && stream->previous_ack == stream->rx.next_seq -1
  )
    stream->state |= MSP_STATE_CLOSED;
}

static int msp_process_packet(struct msp_stream *stream, const uint8_t *payload, size_t len)
{
  if (len<1)
    return WHY("Expected at least 1 byte");
  
  uint8_t flags = payload[0];
  time_ms_t now = gettime_ms();
  stream->rx.last_activity = now;
  stream->timeout = stream->rx.last_activity + MSP_TIMEOUT;
  stream->state |= MSP_STATE_RECEIVED_PACKET;
  
  if (flags & FLAG_STOP){
    DEBUGF(msp, "Closing socket due to STOP packet");
    stream->state |= (MSP_STATE_CLOSED|MSP_STATE_STOPPED);
    stream->state &= ~MSP_STATE_DATAOUT;
    free_all_packets(&stream->tx);
    stream->next_action = now;
    return 0;
  }
  
  if (len<3)
    return 0;
  
  if (flags & FLAG_ACK){
    uint16_t ack_seq = read_uint16(&payload[1]);
    // release acknowledged packets
    free_acked_packets(&stream->tx, ack_seq);
    
    // TODO if their ack seq has not advanced, we may need to hurry up and retransmit a packet
  }
  
  // Do we have space for more data now?
  if (stream->tx.packet_count < MAX_WINDOW_SIZE 
    && !(stream->state & MSP_STATE_SHUTDOWN_LOCAL)
    && !(stream->state & MSP_STATE_CLOSED)){
    stream->state|=MSP_STATE_DATAOUT;
  }
  
  // make sure we attempt to process packets from this sock soon
  // TODO calculate based on congestion window
  stream->next_action = now;
  
  if (len<MSP_PAYLOAD_PREAMBLE_SIZE)
    return 0;
  
  stream->state |= MSP_STATE_RECEIVED_DATA;
  uint16_t seq = read_uint16(&payload[3]);
  stream->rx.last_packet = stream->rx.last_activity;
  if (compare_wrapped_uint16(seq, stream->rx.next_seq)>=0){
    if (add_packet(&stream->rx, seq, flags, &payload[MSP_PAYLOAD_PREAMBLE_SIZE], len - MSP_PAYLOAD_PREAMBLE_SIZE)==1)
      stream->next_ack = now;
  }
  
  return 0;
}

#endif
