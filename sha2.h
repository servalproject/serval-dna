#ifndef __SERVALD_SHA512_H
#define __SERVALD_SHA512_H


typedef struct crypto_hash_sha512_state {
    uint64_t      state[8];
    uint64_t      count[2];
    unsigned char buf[128];
} crypto_hash_sha512_state;
size_t crypto_hash_sha512_statebytes(void);

#ifndef crypto_hash_sha512_BYTES
#define crypto_hash_sha512_BYTES 64U
#endif

size_t crypto_hash_sha512_bytes(void);


int crypto_hash_sha512(unsigned char *out, const unsigned char *in,
                       unsigned long long inlen);


int crypto_hash_sha512_init(crypto_hash_sha512_state *state);


int crypto_hash_sha512_update(crypto_hash_sha512_state *state,
                              const unsigned char *in,
                              unsigned long long inlen);


int crypto_hash_sha512_final(crypto_hash_sha512_state *state,
                             unsigned char *out);

#endif
