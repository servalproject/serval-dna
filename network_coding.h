#ifndef __SERVALD_NETWORK_CODING_H
#define __SERVALD_NETWORK_CODING_H

#define NC_HEADER_LEN 7

#define URGENCY_ASAP 0
#define URGENCY_SOON 1
#define URGENCY_IDLE 2

struct nc;

struct nc *nc_new(uint8_t max_window_size, uint8_t datagram_size);
int nc_free(struct nc *n);
int nc_tx_has_room(struct nc *n);
int nc_tx_enqueue_datagram(struct nc *n, unsigned char *d, size_t len);
int nc_tx_produce_packet(struct nc *n, uint8_t *datagram, uint32_t buffer_size);
int nc_rx_packet(struct nc *n, const uint8_t *payload, size_t len);
int nc_rx_next_delivered(struct nc *n, uint8_t *payload, int buffer_size);
int nc_tx_packet_urgency(struct nc *n);
void nc_dump(struct nc *n);
void nc_state_html(struct strbuf *b, struct nc *nc);

#endif