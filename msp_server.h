#ifndef __SERVAL_DNA__MSP_SERVER_H
#define __SERVAL_DNA__MSP_SERVER_H

typedef uint16_t msp_state_t;
struct msp_server_state;
struct msp_packet;

struct msp_iterator{
  struct msp_server_state *_next;
  struct msp_server_state **_root;
};

struct msp_server_state * msp_find_or_connect(
  struct msp_server_state **root, 
  struct subscriber *remote_sid, mdp_port_t remote_port,
  struct subscriber *local_sid, mdp_port_t local_port,
  uint8_t qos
);

struct msp_server_state * msp_find_and_process(
  struct msp_server_state **root,
  const struct internal_mdp_header *header,
  struct overlay_buffer *payload
);

struct msp_packet *msp_recv_next(struct msp_server_state *state);
struct overlay_buffer *msp_unpack(struct msp_server_state *state, struct msp_packet *packet);
void msp_consumed(struct msp_server_state *state, struct msp_packet *packet, struct overlay_buffer *payload);

time_ms_t msp_next_action(struct msp_server_state *state);
time_ms_t msp_last_packet(struct msp_server_state *state);
struct subscriber * msp_remote_peer(struct msp_server_state *state);
int msp_can_send(struct msp_server_state *state);
msp_state_t msp_get_connection_state(struct msp_server_state *state);
unsigned msp_queued_packet_count(struct msp_server_state *state);

int msp_iterator_open(struct msp_server_state **root, struct msp_iterator *iterator);
struct msp_server_state * msp_process_next(struct msp_iterator *iterator);
struct msp_server_state * msp_next_closed(struct msp_iterator *iterator);
time_ms_t msp_iterator_close(struct msp_iterator *iterator);

int msp_send_packet(struct msp_server_state *state, const uint8_t *payload, size_t len);
int msp_shutdown_stream(struct msp_server_state *state);
void msp_stop_stream(struct msp_server_state *state);

#endif