/* 
Serval DNA keyring
Copyright (C) 2013 Serval Project Inc.
Copyright (C) 2010-2012 Paul Gardner-Stephen

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

#ifndef __SERVAL_DNA__KEYRING_H
#define __SERVAL_DNA__KEYRING_H

struct cli_parsed;
#include "xprintf.h"

typedef struct keypair {
  unsigned type;
  unsigned char *private_key;
  size_t private_key_len;
  unsigned char *public_key;
  size_t public_key_len;
  uint8_t verified;
  struct keypair *next;
} keypair;

/* Contains just the list of private:public key pairs and types,
   the pin used to extract them, and the slot in the keyring file
   (so that it can be replaced/rewritten as required). */
#define PKR_SALT_BYTES 32
#define PKR_MAC_BYTES 64
typedef struct keyring_identity {
  char *PKRPin;
  struct subscriber *subscriber;
  time_ms_t challenge_expires;
  unsigned char challenge[24];
  unsigned int slot;
  struct keyring_identity *next;
  keypair *keypairs;
} keyring_identity;

typedef struct keyring_context {
  char *KeyRingPin;
  unsigned char *KeyRingSalt;
  int KeyRingSaltLen;
  struct keyring_context *next;
  keyring_identity *identities;
} keyring_context;

#define KEYRING_PAGE_SIZE 4096LL
#define KEYRING_BAM_BYTES 2048LL
#define KEYRING_BAM_BITS (KEYRING_BAM_BYTES<<3)
#define KEYRING_SLAB_SIZE (KEYRING_PAGE_SIZE*KEYRING_BAM_BITS)
typedef struct keyring_bam {
  off_t file_offset;
  unsigned char bitmap[KEYRING_BAM_BYTES];
  struct keyring_bam *next;
} keyring_bam;

typedef struct keyring_file {
  keyring_bam *bam;
  keyring_context *contexts;
  FILE *file;
  off_t file_size;
} keyring_file;

typedef struct keyring_iterator{
  keyring_file *file;
  keyring_context *context;
  keyring_identity *identity;
  keypair *keypair;
} keyring_iterator;

void keyring_iterator_start(keyring_file *k, keyring_iterator *it);
keyring_context * keyring_next_context(keyring_iterator *it);
keyring_identity * keyring_next_identity(keyring_iterator *it);
keypair * keyring_next_key(keyring_iterator *it);
keypair * keyring_next_keytype(keyring_iterator *it, unsigned keytype);
keypair *keyring_identity_keytype(keyring_identity *id, unsigned keytype);
keypair *keyring_find_did(keyring_iterator *it, const char *did);
keypair *keyring_find_sid(keyring_iterator *it, const sid_t *sidp);

void keyring_free(keyring_file *k);
int keyring_release_identity(keyring_iterator *it);

#define KEYTYPE_CRYPTOBOX 0x01 // must be lowest
#define KEYTYPE_CRYPTOSIGN 0x02
#define KEYTYPE_RHIZOME 0x03
/* DIDs aren't really keys, but the keyring is a real handy place to keep them,
   and keep them private if people so desire */
#define KEYTYPE_DID 0x04

/* Arbitrary name / value pairs */
#define KEYTYPE_PUBLIC_TAG 0x05

/* handle to keyring file for use in running instance */
extern keyring_file *keyring;

/* Public calls to keyring management */
keyring_file *keyring_open(const char *path, int writeable);
keyring_file *keyring_open_instance();
keyring_file *keyring_open_instance_cli(const struct cli_parsed *parsed);
int keyring_enter_pin(keyring_file *k, const char *pin);
int keyring_set_did(keyring_identity *id, const char *did, const char *name);
struct keypair *keyring_find_sas_private(keyring_file *k, keyring_identity *identity);
int keyring_send_sas_request(struct subscriber *subscriber);

int keyring_commit(keyring_file *k);
keyring_identity *keyring_create_identity(keyring_file *k, keyring_context *c, const char *pin);
int keyring_seed(keyring_file *k);
void keyring_identity_extract(const keyring_identity *id, const sid_t **sidp, const char **didp, const char **namep);
int keyring_load(keyring_file *k, const char *keyring_pin, unsigned entry_pinc, const char **entry_pinv, FILE *input);
int keyring_dump(keyring_file *k, XPRINTF xpf, int include_secret);

unsigned char *keyring_get_nm_bytes(const sid_t *known_sidp, const sid_t *unknown_sidp);

int keyring_mapping_request(struct internal_mdp_header *header, struct overlay_buffer *payload);
int keyring_send_unlock(struct subscriber *subscriber);
int keyring_release_subscriber(keyring_file *k, const sid_t *sid);

int keyring_set_public_tag(keyring_identity *id, const char *name, const unsigned char *value, size_t length);
keypair * keyring_find_public_tag(keyring_iterator *it, const char *name, const unsigned char **value, size_t *length);
keypair * keyring_find_public_tag_value(keyring_iterator *it, const char *name, const unsigned char *value, size_t length);
int keyring_unpack_tag(const unsigned char *packed, size_t packed_len, const char **name, const unsigned char **value, size_t *length);
int keyring_pack_tag(unsigned char *packed, size_t *packed_len, const char *name, const unsigned char *value, size_t length);

#endif // __SERVAL_DNA__KEYRING_H
