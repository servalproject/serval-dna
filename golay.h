
#ifndef __SERVALD_GOLAY_H
#define __SERVALD_GOLAY_H

int golay_encode(uint8_t *data);
int golay_decode(int *errs, uint8_t *data);

#endif