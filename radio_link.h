#ifndef __SERVALD_RADIO_LINK_H
#define __SERVALD_RADIO_LINK_H

#define HEARTBEAT_SIZE (8+9)
#define LINK_MTU 255

int radio_link_free(struct overlay_interface *interface);
int radio_link_init(struct overlay_interface *interface);
int radio_link_decode(struct overlay_interface *interface, uint8_t c);
int radio_link_tx(struct overlay_interface *interface);
void radio_link_state_html(struct strbuf *b, struct overlay_interface *interface);
int radio_link_is_busy(struct overlay_interface *interface);
int radio_link_queue_packet(struct overlay_interface *interface, struct overlay_buffer *buffer);

#endif