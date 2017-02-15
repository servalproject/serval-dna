#ifndef __SYNC_H
#define __SYNC_H

#include "str.h" // for alloca_tohex()

/*
Synchronize two sets of keys, which are likely to contain many common values
*/

#define KEY_LEN 8
#define PREFIX_STEP_BITS 1
#define SYNC_MAX_RETRIES 1

typedef struct {
  uint8_t key[KEY_LEN];
}sync_key_t;

#define alloca_sync_key(K) alloca_tohex((K)->key, KEY_LEN)

struct sync_state;

typedef void (*peer_has) (void *context, void *peer_context, const sync_key_t *key);
typedef void (*peer_does_not_have) (void *context, void *peer_context, void *key_context, const sync_key_t *key);
typedef void (*peer_now_has) (void *context, void *peer_context, void *key_context, const sync_key_t *key);

struct sync_state* sync_alloc_state(void *context, peer_has has, peer_does_not_have has_not, peer_now_has now_has);
void sync_free_state(struct sync_state *state);

// throw away all state related to peer
void sync_free_peer_state(struct sync_state *state, void *peer_context);

// tell the sync process that we now have key, with callback context
// if the key is already present, the context will be updated
void sync_add_key(struct sync_state *state, const sync_key_t *key, void *key_context);
int sync_key_exists(const struct sync_state *state, const sync_key_t *key);
int sync_has_transmit_queued(const struct sync_state *state);

// ask for a message to be inserted into buff, returns packet length
size_t sync_build_message(struct sync_state *state, uint8_t *buff, size_t len);

// build empty message, returns packet length.
size_t sync_build_empty_message(uint8_t *buff, size_t len);

// process a message received from a peer.
int sync_recv_message(struct sync_state *state, void *peer_context, const uint8_t *buff, size_t len);

void sync_enum_differences(struct sync_state *state,
  void (*callback)(void *context, void *peer_context, const sync_key_t *key, uint8_t theirs));

#endif

