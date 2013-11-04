/*
Serval DNA network coding functions
Copyright (C) 2013 Paul Gardner-Stephen

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <assert.h>
#include <inttypes.h>
#include <stdarg.h>
#include "strbuf.h"
#include "network_coding.h"
#include "dataformats.h"
#include "log.h"
#include "mem.h"

#define FLAG_NEW 1
struct nc_packet{
  uint8_t sequence;
  uint32_t combination;
  size_t len;
  uint8_t flags;
  uint8_t *payload;
};

struct nc_half {
  uint8_t last_ack;
  
  // Define the size parameters of the network coding data structures
  uint8_t window_size;    // limited to the number of bits we can fit in a uint32_t
  uint8_t window_start;   // sequence of first datagram in sending window
  uint8_t unseen; // sequence of first unseen packet
  size_t datagram_size;  // number of bytes in each fixed sized unit
  uint8_t deliver_next;   // sequence of next packet that should be delivered
  // dynamically sized array of pointers to packet buffers
  // each packet will be stored in the array based on the low order bits of the sequence number
  struct nc_packet *packets;
  // size of packet array, should be an exact 2^n in size to simplify storing sequence numbered packets
  // At the sender, this is the maximum window size
  // At the receiver, this should be 2*maximum window size to allow for older packets we can't decode yet
  uint8_t max_queue_size; 
  uint8_t queue_size;     // # of packets currently in the array
  uint8_t count_new; // number of un-sent degrees of freedom
  
  uint32_t packet_count; // total number of packets sent / received
  uint32_t uninteresting_count; // number of redundant packets received
  uint32_t ack_count; // number of received acks with no data payload
};

struct nc{
  struct nc_half tx;
  struct nc_half rx;
};

static int _nc_dump_half(struct nc_half *n);

static void _nc_free_half(struct nc_half *n)
{
  int i;
  for (i=0;i<n->max_queue_size;i++){
    if (n->packets[i].payload)
      free(n->packets[i].payload);
  }
  free(n->packets);
}

int nc_free(struct nc *n)
{
  _nc_free_half(&n->tx);
  _nc_free_half(&n->rx);
  free(n);
  return 0;
}

struct nc *nc_new(uint8_t max_window_size, uint8_t datagram_size)
{
  struct nc *n = calloc(sizeof(struct nc),1);
  if (!n)
    return NULL;
  n->tx.packets = calloc(sizeof(struct nc_packet)*max_window_size,1);
  if (!n->tx.packets){
    free(n);
    return NULL;
  }
  n->tx.max_queue_size = max_window_size;
  n->tx.window_size = 4;
  n->rx.packets = calloc(sizeof(struct nc_packet)*max_window_size*2,1);
  if (!n->rx.packets){
    free(n->tx.packets);
    free(n);
    return NULL;
  }
  n->rx.max_queue_size = max_window_size*2;
  n->tx.datagram_size = datagram_size;
  n->rx.datagram_size = datagram_size;
  return n;
}

int nc_test_dump(char *name, unsigned char *addr, int len);
int nc_test_dump_rx_queue(char *msg,struct nc *n);

int nc_tx_has_room(struct nc *n)
{
  // On the TX side the maximum number of queued packets
  // is the MINIMUM of the maximum queue size and the window
  // size.
  if (n->tx.queue_size>=n->tx.max_queue_size)
    return 0;
  return 1;
}

int nc_tx_enqueue_datagram(struct nc *n, unsigned char *d, size_t len)
{
  if (len==0 || len>n->tx.datagram_size)
    return WHYF("Invalid length %zd (%zd)", len, n->tx.datagram_size);
  if (!nc_tx_has_room(n))
    return 1;

  // Add datagram to queue
  uint8_t seq = n->tx.window_start + n->tx.queue_size;
  int index = seq & (n->tx.max_queue_size -1);
  if (n->tx.packets[index].payload)
    FATALF("Attempted to replace TX payload %d (%d) with %d without freeing it first",index,n->tx.packets[index].sequence, seq);
  n->tx.packets[index].payload = emalloc(len);
  if (!n->tx.packets[index].payload)
    return 1;
  n->tx.packets[index].sequence = seq;
  n->tx.packets[index].combination = 0x80000000;
  n->tx.packets[index].flags = FLAG_NEW;
  n->tx.count_new++;
  n->tx.packets[index].len = len;
  bcopy(d, n->tx.packets[index].payload, len);
  n->tx.queue_size++;
  return 0;
}

static int _compare_uint8(uint8_t one, uint8_t two)
{
  if (one==two)
    return 0;
  if (((one - two)&0xFF) < 0x80)
    return 1;
  return -1;
}

static int _nc_ack(struct nc_half *n, uint8_t first_unseen, uint8_t window_size)
{
  if (window_size>n->max_queue_size)
    window_size=n->max_queue_size;
  n->window_size = window_size;
  
  // ignore invalid input or no new information
  if (_compare_uint8(first_unseen, n->window_start) <= 0 ||
    _compare_uint8(first_unseen, n->window_start + n->queue_size) > 0 )
    return -1;
  
  // release any seen packets
  while(_compare_uint8(n->window_start, first_unseen) < 0){
    int index = n->window_start & (n->max_queue_size -1);
    if (n->packets[index].payload){
      free(n->packets[index].payload);
      n->packets[index].payload=NULL;
      n->queue_size--;
    }
    n->window_start++;
  }
  return 0;
}

static uint32_t _combine_masks(const struct nc_packet *src, const struct nc_packet *dst)
{
  uint8_t offset = src->sequence - dst->sequence;
  uint32_t mask = src->combination >> offset;
  if ((mask << offset) != src->combination){
//    fprintf(stderr, "Invalid mask combination (%d, %d, %d, %08x, %08x, %08x)\n", 
//      src->sequence, dst->sequence, offset, src->combination, mask, (mask << offset));
    return 0xFFFFFFFF;
  }
  return dst->combination ^ mask;
}

static void _combine_packets(const struct nc_packet *src, struct nc_packet *dst)
{
  if (dst->len < src->len)
    FATALF("Expected the destination buffer to be at least %zu", src->len);
  dst->combination = _combine_masks(src, dst);
  size_t i;
  for(i=0; i < src->len; i++)
    dst->payload[i]^=src->payload[i];
}

static int _nc_tx_combine_random_payloads(struct nc_half *n, struct nc_packet *packet){
  // TODO: Check that combination is linearly independent of recently produced
  // combinations, i.e., that it contributes information.

  // (always send the first packet in the window)
  uint32_t combination=1;
  int i;
  // give every other packet about 1/4 chance of being included
  for (i=0;i<8;i++)
    combination|=(1<<(random()&31));

  bzero(packet->payload, n->datagram_size);
  int added_new=0;
  
  for(i=0;i<n->window_size;i++) {
    int index = (n->window_start + i) & (n->max_queue_size -1);
    // assume we might have gaps in the payload list if we are a retransmitter in the network path
    if (!n->packets[index].payload)
      continue;
      
    // there's no point including more than one new packet
    // only if we have some packet loss will we need to send more combinations of packets
    if (n->packets[index].flags & FLAG_NEW){
      if (added_new)
	continue;
      _combine_packets(&n->packets[index], packet);
      added_new = 1;
      n->count_new --;
      n->packets[index].flags =0;
      continue;
    }
    
    if (combination&1)
      _combine_packets(&n->packets[index], packet);
    combination>>=1;
  }

  return 0;
}

int nc_tx_packet_urgency(struct nc *n)
{
  // new data inside the tx window size? send asap
  if (n->tx.count_new){
    int i;
    for(i=0;i<n->tx.window_size;i++) {
      int index = (n->tx.window_start + i) & (n->tx.max_queue_size -1);
      // assume we might have gaps in the payload list if we are a retransmitter in the network path
      if (!n->tx.packets[index].payload)
	continue;
      if (n->tx.packets[index].flags & FLAG_NEW)
	return URGENCY_ASAP;
    }
  }
  // ack required? send soon
  if (n->rx.unseen != n->rx.last_ack)
    return URGENCY_ASAP;
  // no new data at either end? don't care
  if (!n->tx.queue_size && !n->rx.queue_size)
    return URGENCY_IDLE;
  // send soon-ish
  return URGENCY_SOON;
}

// construct a packet and return the payload size
int nc_tx_produce_packet(struct nc *n, uint8_t *datagram, uint32_t buffer_size)
{
  // TODO: Don't waste more bytes than we need to on the bitmap and sequence number
  if (buffer_size < n->tx.datagram_size+NC_HEADER_LEN)
    return -1;
  
  uint8_t window_size = n->rx.max_queue_size - (n->rx.unseen - n->rx.deliver_next);
  if (window_size > n->rx.max_queue_size)
    window_size = n->rx.max_queue_size;
  
  datagram[0]=n->rx.unseen;
  datagram[1]=window_size;
  n->rx.last_ack = n->rx.unseen;
  size_t len=2;
  
  if (n->tx.queue_size && n->tx.window_size){
    // Produce linear combination
    struct nc_packet packet={
      .sequence = n->tx.window_start,
      .combination = 0,
      .payload = &datagram[NC_HEADER_LEN],
      .len = buffer_size - NC_HEADER_LEN,
    };
    bzero(packet.payload, packet.len);
    
    if (_nc_tx_combine_random_payloads(&n->tx, &packet))
      return -1;
    // TODO assert actual_combination? (should never be zero)
    datagram[2] = packet.sequence;
    // Write out bitmap of actual combinations involved
    write_uint32(&datagram[3], packet.combination);
    len = packet.len + NC_HEADER_LEN;
    // truncate zero bytes from the end
    while(!datagram[len-1])
      len--;
    
  }else
    n->tx.ack_count++;

  n->tx.packet_count++;
  return len;
}

void nc_state_html(struct strbuf *b, struct nc *n)
{
  strbuf_sprintf(b, "NC TX: %d (acks %d)<br>", n->tx.packet_count, n->tx.ack_count);
  strbuf_sprintf(b, "NC RX: %d (unint %d, acks %d)<br>", n->rx.packet_count, n->rx.uninteresting_count, n->rx.ack_count);
}

static int _nc_dump_half(struct nc_half *n)
{
  DEBUGF("  window start; %d", n->window_start);
  DEBUGF("  window size; %d", n->window_size);
  DEBUGF("  last_ack; %d", n->last_ack);
  DEBUGF("  unseen; %d", n->unseen);
  DEBUGF("  queue size; %d", n->queue_size);
  DEBUGF("  max queue size; %d", n->max_queue_size);
  DEBUGF("  delivered; %d", n->deliver_next);
  if (n->packet_count)
    DEBUGF("  packets; %d", n->packet_count);
  if (n->uninteresting_count)
    DEBUGF("  uninteresting; %d", n->uninteresting_count);
  if (n->ack_count)
    DEBUGF("  acks; %d", n->ack_count);
  
  int i;
  for (i=0;i<n->max_queue_size;i++){
    if (!n->packets[i].payload)
      continue;
    DEBUGF("  %02d: 0x%02x, 0x%08x",
	   i, n->packets[i].sequence, n->packets[i].combination);
    dump("packet", n->packets[i].payload, n->packets[i].len);
  }
  return 0;
}

void nc_dump(struct nc *n)
{
  DEBUGF("Network coding state");
  DEBUGF("TX");
  _nc_dump_half(&n->tx);
  DEBUGF("RX");
  _nc_dump_half(&n->rx);
}

// note, the incoming packet buffer must be allocated from the heap
// this function will take responsibility for releasing it
static int _nc_rx_combine_packet(struct nc_half *n, struct nc_packet *packet)
{
  int i;
  
  // ignore any packets with no information
  if (packet->combination == 0){
    free(packet->payload);
    return 1;
  }
    
  // First, reduce the combinations of the incoming packet based on other packets already seen
  for (i=0;i<n->max_queue_size;i++){
    if (!n->packets[i].payload || _compare_uint8(n->packets[i].sequence, packet->sequence) < 0)
      continue;
//    printf("Reducing incoming packet (%d, %08x) w. existing (%d, %08x)\n",
//      packet->sequence, packet->combination,
//      n->packets[i].sequence, n->packets[i].combination);
    uint32_t new_mask = _combine_masks(&n->packets[i], packet);
    
    // rx packet doesn't add any new information
    if (new_mask==0){
      free(packet->payload);
      return 1;
    }
    
    if (new_mask < packet->combination)
      _combine_packets(&n->packets[i], packet);
  }
  
  // the new packet must contain new information that will cause a new packet to be seen.
  int shift = __builtin_clz(packet->combination);
  packet->sequence += shift;
  packet->combination <<= shift;
  
  if (_compare_uint8(packet->sequence, n->window_start)<0){
    // um, no. I'm not storing an old packet that I've just delivered.
    // we don't reject these packets earlier, firstly because they shouldn't happen
    // secondly because we might be able to learn something based on 
    // packets that haven't been delivered yet
    free(packet->payload);
    return 1;
  }
    
  int index = packet->sequence & (n->max_queue_size -1);
  if (n->packets[index].payload){
    _nc_dump_half(n);
    FATALF("Attempted to replace RX payload %d (%d) with %d [%08x] without freeing it first",index,n->packets[index].sequence, packet->sequence, packet->combination);
  }
  
  // reduce other stored packets
  for (i=0;i<n->max_queue_size;i++){
    if (!n->packets[i].payload || _compare_uint8(n->packets[i].sequence, packet->sequence) > 0)
      continue;
//    printf("Reducing existing packet (%d, %08x) w. incoming (%d, %08x)\n",
//      n->packets[i].sequence, n->packets[i].combination,
//      packet->sequence, packet->combination);
    uint32_t new_mask = _combine_masks(packet, &n->packets[i]);
    if (new_mask < n->packets[i].combination)
      _combine_packets(packet, &n->packets[i]);
  }
  
  // add the packet to our incoming list
  n->packets[index]=*packet;
  n->queue_size++;
  
  // find the first missing seq
  uint8_t seq;
  for (seq = n->window_start; ;seq++){
    int index = seq & (n->max_queue_size -1);
    if (n->packets[index].sequence != seq || !n->packets[index].payload)
      break;
  }
  n->unseen = seq;
  
  return 0;
}

static void _nc_rx_advance_window(struct nc_half *n, uint8_t new_window_start)
{
  // advance the window start to match the sender
  // drop any payloads that have already been delivered
  while(_compare_uint8(n->window_start, new_window_start) < 0){
    if (_compare_uint8(n->window_start, n->deliver_next) < 0){
      int index = n->window_start & (n->max_queue_size -1);
      if (n->packets[index].payload){
	free(n->packets[index].payload);
	n->packets[index].payload=NULL;
	n->queue_size--;
      }
    }
    n->window_start++;
  }
}

/*
 * Parse a network coded packet,
 * returns;
 *  0 - interesting packet, the caller should immediately attempt to decode packets
 *  1 - un-interesting
 *  2 - ack only
 */
int nc_rx_packet(struct nc *n, const uint8_t *payload, size_t len)
{
  n->rx.packet_count++;
  
  if (len>=2){
    _nc_ack(&n->tx, payload[0], payload[1]);
  }
  
  if (len<NC_HEADER_LEN){
    n->rx.ack_count++;
    return 2;
  }
  
  uint8_t new_window_start = payload[2];
  
  // assume incoming packets can be padded with zero's up to n->rx.datagram_size
  struct nc_packet packet={
    .sequence = new_window_start,
    .combination = read_uint32(&payload[3]),
    .payload = emalloc_zero(n->rx.datagram_size),
    .len = n->rx.datagram_size,
  };
  bcopy(&payload[NC_HEADER_LEN], packet.payload, len - NC_HEADER_LEN);
  
  int r = _nc_rx_combine_packet(&n->rx, &packet);
  if (r==1)
    n->rx.uninteresting_count++;

  _nc_rx_advance_window(&n->rx, new_window_start);
  
  return r;
}

// After each nc_rx_packet, call this function repeatedly to retrieve all decoded payloads in order
int nc_rx_next_delivered(struct nc *n, uint8_t *payload, int buffer_size)
{
  if (buffer_size < n->rx.datagram_size)
    return -1;
    
  int index = n->rx.deliver_next & (n->rx.max_queue_size -1);
  if (!n->rx.packets[index].payload ||
    n->rx.packets[index].sequence!=n->rx.deliver_next ||
    n->rx.packets[index].combination != 0x80000000)
    return 0;
  
  bcopy(n->rx.packets[index].payload, payload, n->rx.packets[index].len);
  // drop the payload if the sender has already advanced
  if (_compare_uint8(n->rx.deliver_next, n->rx.window_start) < 0){
    free(n->rx.packets[index].payload);
    n->rx.packets[index].payload=NULL;
    n->rx.queue_size--;
  }
  n->rx.deliver_next++;
  return n->rx.packets[index].len;
}

#ifdef RUNTESTS
/* TODO: Tests that should be written.
   1. nc_new() works, and rejects bad input.
   2. nc_free() works, including on partially initialised structures.
   3. nc_tx_enqueue_datagram() works, including failing on bad input and when the
      queue is full.
   4. nc_tx_ack_dof() works, rejects bad input, and correctly releases buffers.
   5. nc_tx_random_linear_combination() works, rejects bad input, and produces valid
      linear combinations of the enqueuedumd datagrams, and never produces all zeroes.
   6. nc_rx_linear_combination() works, rejects bad input
   7. nc_rx_linear_combination() rejects when RX queue full, when combination starts
      before current window.
*/

void FAIL(const char *fmt,...){
  va_list ap;
  fprintf(stderr, "FAIL: ");
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fprintf(stderr, "\n");
  exit(-1);
}

void PASS(const char *fmt,...){
  va_list ap;
  fprintf(stderr, "PASS: ");
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fprintf(stderr, "\n");
}

void ASSERT(int test, const char *fmt,...){
  va_list ap;
  fprintf(stderr, test?"PASS: ":"FAIL: ");
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fprintf(stderr, "\n");
  if (!test)
    exit(-1);
}

int nc_test_random_datagram(uint8_t *d,int len)
{
  int i;
  for(i=0;i<len;i++)
    d[i]=random()&0xff;
  return 0;
}

int nc_test()
{
  struct nc *tx, *rx;
  tx = nc_new(16, 200);
  ASSERT(tx!=NULL, "Create nc struct for TX.");
  rx = nc_new(16, 200);
  ASSERT(rx!=NULL, "Create nc struct for RX.");

  // Prepare some random datagrams for subsequent tests
  int i;
  int sent =0;
  uint8_t datagrams[8][200];
  for (i=0;i<8;i++)
    nc_test_random_datagram(datagrams[i],200);

  // Test inserting datagrams into the queue
  
  ASSERT(!nc_tx_enqueue_datagram(tx,datagrams[0],200), "Enqueue datagram 0 for TX");
  ASSERT(tx->tx.queue_size==1, "Enqueueing datagram increases queue_size");

  int j=0;
  for(i=0;i<10;i++) {
    uint8_t outbuffer[NC_HEADER_LEN+200];
    int len=sizeof(outbuffer);
    int written = nc_tx_produce_packet(tx, outbuffer, len);
    if (written==-1)
      FAIL("Produce random linear combination of single packet for TX");
    if (i==9)
      PASS("Produce random linear combination of single packet for TX");
    uint32_t combination = read_uint32(&outbuffer[3]);
    if (!combination)
      FAIL("Should not produce empty linear combination bitmap");
    if (i==9)
      PASS("Should not produce empty linear combination bitmap");
    
    if (memcmp(&outbuffer[NC_HEADER_LEN], datagrams[0], 200)!=0)
      FAIL("Output identity datagram when only one in queue");
    if (i==9)
      PASS("Output identity datagram when only one in queue");
  }
  
  // can we combine seq & combination as expected?
  
  struct nc_packet headers[]={
    {
      .sequence = 0,
      .combination = 0xF0000000
    },
    {
      .sequence = 0,
      .combination = 0x80000000
    },
    {
      .sequence = 1,
      .combination = 0xE0000000
    },
    {
      .sequence = 2,
      .combination = 0xC0000000
    },
    {
      .sequence = 3,
      .combination = 0x80000000
    },
  };
  
  for (i=0;i<5;i++){
    for (j=i;j<5;j++){
      _combine_masks(&headers[j], &headers[i]);
      // TODO assert...
    }
  }
  
  // now can we receive this first packet?
  {
    uint8_t outbuffer[NC_HEADER_LEN+200];
    int written = nc_tx_produce_packet(tx, outbuffer, sizeof(outbuffer));
    ASSERT(written!=-1, "Produce packet");
    int r=nc_rx_packet(rx, outbuffer, written);
    ASSERT(r!=-1, "Receive packet");
    sent ++;
  }
  
  // can we decode it?
  
  {
    uint8_t outbuffer[200];
    int size = nc_rx_next_delivered(rx, outbuffer, sizeof(outbuffer));
    ASSERT(size==200, "Receive 200 bytes, got %d", size);
    ASSERT(memcmp(outbuffer, datagrams[0], 200) == 0, "Output of first packet should match incoming packet");
  }
  
  // acknowledging this first packet advances the window
  {
    uint8_t outbuffer[NC_HEADER_LEN+200];
    int written = nc_tx_produce_packet(rx, outbuffer, sizeof(outbuffer));
    ASSERT(written!=-1, "Produce ACK");
    int r=nc_rx_packet(tx, outbuffer, written);
    ASSERT(r!=-1, "Process ACK");
    ASSERT(tx->tx.window_start==1, "ACK advances window_start");
    ASSERT(tx->tx.queue_size==0, "ACK causes packet to be discarded");
  }
  
  for (i=1;i<8;i++){
    if (nc_tx_enqueue_datagram(tx,datagrams[i],200))
      FAIL("Failed to enqueue datagram %d for TX", i);
    if (tx->tx.queue_size!=i)
      FAIL("Enqueueing datagram increases queue_size");
  }
  PASS("Queued first 8 packets");
  
  int decoded=0;
  for(i=0;i<100;i++) {
    uint8_t outbuffer[NC_HEADER_LEN+200];
    int len=sizeof(outbuffer);
    int written = nc_tx_produce_packet(tx, outbuffer, len);
    if (written==-1)
      FAIL("Produce random linear combination of multiple packets for TX");
    if (i==0)
      PASS("Produce random linear combination of multiple packets for TX");
    uint32_t combination = read_uint32(&outbuffer[3]);
    if (!combination)
      FAIL("Should not produce empty linear combination bitmap");
    if (i==0)
      PASS("Should not produce empty linear combination bitmap");
      
    for(j=0;j<200;j++) {
      int k;
      uint8_t x = outbuffer[NC_HEADER_LEN+j];
      for (k=0;k<8;k++){
	if (combination&(0x80000000>>k))
	  x^=datagrams[k+1][j];
      }
      if (x)
	FAIL("Output linear combination from multiple packets in the queue");
    }
    if (i==0)
      PASS("Output linear combination from multiple packets in the queue");
      
    if (nc_rx_packet(rx, outbuffer, written)!=1)
      sent ++;

    while(1){
      uint8_t out[200];
      int size = nc_rx_next_delivered(rx, out, sizeof(out));
      if (size!=200)
	break;
      decoded++;
      if (memcmp(out, datagrams[decoded], 200) != 0)
	FAIL("Output of %d packet should match incoming packet (@%d, %02x != %02x)", decoded, j, out[j], datagrams[decoded][j]);
      if (decoded==7)
	PASS("First 8 packets delivered");
    }
  }
  
  if (decoded!=7)
    FAIL("First 8 packets should have been delivered by the first 100 test packets sent");
    
  // acknowledging first 8 packets advances the tx window
  {
    uint8_t outbuffer[NC_HEADER_LEN+200];
    int written = nc_tx_produce_packet(rx, outbuffer, sizeof(outbuffer));
    ASSERT(written!=-1, "Produce ACK");
    int r=nc_rx_packet(tx, outbuffer, written);
    ASSERT(r!=-1, "Process ACK");
    ASSERT(tx->tx.window_start==8, "ACK advances window_start");
    ASSERT(tx->tx.queue_size==0, "ACK causes packets to be discarded");
  }
  
  int histogram[64];
  int uninteresting=0;
  int dropped=0;
  bzero(histogram, sizeof(histogram));
  
  uint8_t packets[8][NC_HEADER_LEN+200];
  
  while(decoded < 10000 && sent <=1000000){
    // fill the transmit window whenever there is space
    while(tx->tx.queue_size<tx->tx.max_queue_size){
      if (nc_tx_enqueue_datagram(tx,datagrams[(tx->tx.window_start+tx->tx.queue_size+1)%7],200))
	FAIL("Failed to dispatch pre-fill datagram");
    }
    
    // generate a packet in each direction
    sent++;
    int wone = nc_tx_produce_packet(tx, packets[sent&7], NC_HEADER_LEN+200);
    int wtwo = nc_tx_produce_packet(rx, packets[(sent+4)&7], NC_HEADER_LEN+200);
    if (sent <13)
      continue;
      
    // receive a packet
    if ((random()&7))
      nc_rx_packet(tx, packets[(sent+1)&7], wtwo);
    if ((random()&7)){
      if (nc_rx_packet(rx, packets[(sent+5)&7], wone)!=1){
	int burst_len=0;
	// deliver anything that can be decoded
	while(1){
	  uint8_t out[200];
	  int size = nc_rx_next_delivered(rx, out, sizeof(out));
	  if (size!=200)
	    break;
	  decoded++;
	  burst_len++;
	}
	histogram[burst_len]++;
      }else
	uninteresting++;
    }else
      dropped++;
  }
  
  fprintf(stderr, "Received = %d\n", sent - dropped);
  fprintf(stderr, "Unint = %d\n", uninteresting);
  
  fprintf(stderr, "Delivery burst histogram;\n");
  for (i=0;i<64;i++)
    if (histogram[i])
      fprintf(stderr, "%d = %d (%d)\n", i, histogram[i], i*histogram[i]);
  ASSERT(decoded >= 10000, "Delivered %d packets after sending %d", decoded, sent);
  nc_free(tx);
  nc_free(rx);
  PASS("Release memory");
  
  return 0;
}

int main(int argc,char **argv)
{
  return nc_test();
}

#endif
