#ifndef __SERVALD_RADIO_LINK_H
#define __SERVALD_RADIO_LINK_H

int radio_link_free(struct overlay_interface *interface);
int radio_link_init(struct overlay_interface *interface);
int radio_link_decode(struct overlay_interface *interface, uint8_t c);
int radio_link_heartbeat(unsigned char *frame, int *outlen);
int radio_link_encode_packet(struct overlay_interface *interface);

#endif