
#include "conf.h"
#include "mem.h"
#include "overlay_packet.h"
#include "overlay_address.h"
#include "overlay_buffer.h"
#include "msp_server.h"
#include "dataformats.h"

#include "msp_common.h"

struct msp_server_state{
  struct msp_server_state *_next;
  struct msp_stream stream;
  struct subscriber *local_sid;
  mdp_port_t local_port;
  struct subscriber *remote_sid;
  mdp_port_t remote_port;
};

static struct msp_server_state *msp_create(
  struct msp_server_state **root, 
  struct subscriber *remote_sid, mdp_port_t remote_port,
  struct subscriber *local_sid, mdp_port_t local_port)
{
  struct msp_server_state *state = (struct msp_server_state *)emalloc_zero(sizeof(struct msp_server_state));
  msp_stream_init(&state->stream);
  state->remote_sid = remote_sid;
  state->remote_port = remote_port;
  state->local_sid = local_sid;
  state->local_port = local_port;
  state->_next = (*root);
  (*root) = state;
  return state;
}

struct msp_server_state * msp_find_or_connect(
  struct msp_server_state **root, 
  struct subscriber *remote_sid, mdp_port_t remote_port,
  struct subscriber *local_sid, mdp_port_t local_port)
{
  struct msp_server_state *state = (*root);
  
  while(state){
    if (state->remote_sid == remote_sid && state->remote_port == remote_port)
      break;
    state = state->_next;
  }
  
  if (!state){
    state = msp_create(root, remote_sid, remote_port, local_sid, local_port);
    state->stream.state|=MSP_STATE_DATAOUT;
    // make sure we send a FIRST packet soon
    state->stream.next_action = state->stream.next_ack = gettime_ms()+10;
  }
  return state;
}

int msp_iterator_open(struct msp_server_state **root, struct msp_iterator *iterator)
{
  iterator->_next = NULL;
  iterator->_root = root;
  return 0;
}

time_ms_t msp_iterator_close(struct msp_iterator *iterator)
{
  struct msp_server_state **ptr = iterator->_root;
  time_ms_t next_action = TIME_MS_NEVER_WILL;
  while(*ptr){
    struct msp_server_state *p = (*ptr);
    if (p->stream.state & MSP_STATE_CLOSED){
      *ptr = p->_next;
      free_all_packets(&p->stream.tx);
      free_all_packets(&p->stream.rx);
      free(p);
    }else{
      if (p->stream.next_action < next_action)
	next_action = p->stream.next_action;
      ptr = &p->_next;
    }
  }
  return next_action;
}

struct msp_server_state * msp_next_closed(struct msp_iterator *iterator)
{
  struct msp_server_state *ptr = iterator->_next;
  while(1){
    if (ptr){
      ptr = ptr->_next;
    }else{
      ptr = *iterator->_root;
    }
    if (!ptr){
      iterator->_next = ptr;
      return NULL;
    }
    if (ptr->stream.state & MSP_STATE_CLOSED){
      iterator->_next = ptr;
      return ptr;
    }
  }
}

static void send_frame(struct msp_server_state *state, struct overlay_buffer *payload)
{
  struct internal_mdp_header response_header;
  bzero(&response_header, sizeof(response_header));
  
  response_header.source = state->local_sid;
  response_header.source_port = state->local_port;
  response_header.destination = state->remote_sid;
  response_header.destination_port = state->remote_port;
  
  overlay_send_frame(&response_header, payload);
  ob_free(payload);
}

static void send_packet(struct msp_server_state *state, struct msp_packet *packet)
{
  struct overlay_buffer *payload = ob_new();
  uint8_t *msp_header = ob_append_space(payload, MSP_PAYLOAD_PREAMBLE_SIZE);
  size_t len = msp_write_preamble(msp_header, &state->stream, packet);
  assert(len == MSP_PAYLOAD_PREAMBLE_SIZE);
  if (packet->len)
    ob_append_bytes(payload, packet->payload, packet->len);
  ob_flip(payload);
  send_frame(state, payload);
}

static void send_ack(struct msp_server_state *state)
{
  struct overlay_buffer *payload = ob_new();
  uint8_t *msp_header = ob_append_space(payload, 3);
  msp_write_ack_header(msp_header, &state->stream);
  ob_flip(payload);
  send_frame(state, payload);
}

struct msp_server_state * msp_process_next(struct msp_iterator *iterator)
{
  time_ms_t now = gettime_ms();
  
  struct msp_server_state *ptr = iterator->_next;
  while(1){
    if (ptr){
      struct msp_packet *packet = ptr->stream.tx._head;
      time_ms_t next_packet = TIME_MS_NEVER_WILL;
      
      ptr->stream.next_action = ptr->stream.timeout;
      while(packet){
	if (packet->sent + RETRANSMIT_TIME <= now)
	  // (re)transmit this packet
	  send_packet(ptr, packet);
	
	if (next_packet > packet->sent + RETRANSMIT_TIME)
	  next_packet = packet->sent + RETRANSMIT_TIME;
	  
	packet=packet->_next;
      }
      
      // should we send an ack now without sending a payload?
      if (now >= ptr->stream.next_ack)
	send_ack(ptr);
      
      if (ptr->stream.next_action > next_packet)
        ptr->stream.next_action = next_packet;
      if (ptr->stream.next_action > ptr->stream.next_ack)
	ptr->stream.next_action = ptr->stream.next_ack;

      ptr = ptr->_next;
    }else{
      ptr = *iterator->_root;
    }
    
    if (!ptr){
      iterator->_next = ptr;
      return NULL;
    }
    msp_stream_process(&ptr->stream);
    
    if (ptr->stream.state & MSP_STATE_DATAOUT){
      iterator->_next = ptr;
      return ptr;
    }
  }
}

int msp_send_packet(struct msp_server_state *state, const uint8_t *payload, size_t len)
{
  
  return msp_stream_send(&state->stream, payload, len);
}

int msp_shutdown_stream(struct msp_server_state *state)
{
  msp_stream_shutdown(&state->stream);
  return 0;
}

void msp_stop_stream(struct msp_server_state *state)
{
  if (state->stream.state & MSP_STATE_STOPPED)
    return;
  state->stream.state |= MSP_STATE_STOPPED | MSP_STATE_CLOSED;
  state->stream.state &= ~MSP_STATE_DATAOUT;
  free_all_packets(&state->stream.tx);

  uint8_t response = FLAG_STOP;
  struct overlay_buffer *payload = ob_static(&response, 1);
  ob_limitsize(payload, 1);
  send_frame(state, payload);
}

struct msp_server_state * msp_find_and_process(struct msp_server_state **root, const struct internal_mdp_header *header, struct overlay_buffer *payload)
{
  if (ob_remaining(payload)<1){
    WHY("Expected at least 1 byte");
    return NULL;
  }
  
  struct msp_server_state *state = (*root);
  
  while(state){
    if (state->remote_sid == header->source && state->remote_port == header->source_port)
      break;
    state = state->_next;
  }
  
  int flags = ob_peek(payload);
  if (!state && (flags & FLAG_FIRST))
    state = msp_create(root, header->source, header->source_port, header->destination, header->destination_port);
    
  if (!state){
    if (!(flags & FLAG_STOP)){
      struct internal_mdp_header response_header;
      bzero(&response_header, sizeof(response_header));
      
      mdp_init_response(header, &response_header);
      uint8_t response = FLAG_STOP;
      struct overlay_buffer * response_payload = ob_static(&response, 1);
      ob_limitsize(response_payload, 1);
      overlay_send_frame(&response_header, response_payload);
      ob_free(response_payload);
    }
    return NULL;
  }
  
  msp_process_packet(&state->stream, ob_current_ptr(payload), ob_remaining(payload));
  return state;
}

struct msp_packet *msp_recv_next(struct msp_server_state *state)
{
  return msp_stream_next(&state->stream);
}

struct overlay_buffer *msp_unpack(struct msp_server_state *UNUSED(state), struct msp_packet *packet)
{
  if (packet->offset >= packet->len)
    return NULL;
  struct overlay_buffer *payload = ob_static(packet->payload + packet->offset, packet->len - packet->offset);
  ob_limitsize(payload, packet->len - packet->offset);
  return payload;
}

void msp_consumed(struct msp_server_state *state, struct msp_packet *packet, struct overlay_buffer *payload)
{
  msp_consume_packet(&state->stream, packet, payload ? ob_position(payload) : 0);
  if (payload)
    ob_free(payload);
}

time_ms_t msp_next_action(struct msp_server_state *state)
{
  return state->stream.next_action;
}

time_ms_t msp_last_packet(struct msp_server_state *state)
{
  return state->stream.rx.last_packet > state->stream.tx.last_packet ? state->stream.rx.last_packet : state->stream.tx.last_packet;
}


struct subscriber * msp_remote_peer(struct msp_server_state *state)
{
  return state->remote_sid;
}

int msp_get_error(struct msp_server_state *state)
{
  return (state->stream.state & (MSP_STATE_ERROR|MSP_STATE_STOPPED)) ? 1 : 0;
}

int msp_can_send(struct msp_server_state *state)
{
  return (state->stream.state & MSP_STATE_DATAOUT) ? 1 : 0;
}