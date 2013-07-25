
#ifndef __SERVALD_CRYPTO_H
#define __SERVALD_CRYPTO_H

#include "nacl.h"
#define SIGNATURE_BYTES crypto_sign_edwards25519sha512batch_BYTES

int crypto_verify_signature(unsigned char *sas_key, 
			    unsigned char *content, int content_len, 
			    unsigned char *signature_block, int signature_len);
int crypto_verify_message(struct subscriber *subscriber, unsigned char *message, int *message_len);
int crypto_create_signature(unsigned char *key, 
			    unsigned char *content, int content_len, 
			    unsigned char *signature, int *sig_length);
int crypto_sign_message(struct subscriber *source, unsigned char *content, int buffer_len, int *content_len);
int crypto_sign_compute_public_key(const unsigned char *skin, unsigned char *pk);

#endif
