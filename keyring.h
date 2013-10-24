#ifndef __SERVALD_KEYRING_H
#define __SERVALD_KEYRING_H

typedef struct keypair {
  int type;
  unsigned char *private_key;
  size_t private_key_len;
  unsigned char *public_key;
  size_t public_key_len;
} keypair;

/* Contains just the list of private:public key pairs and types,
   the pin used to extract them, and the slot in the keyring file
   (so that it can be replaced/rewritten as required). */
#define PKR_MAX_KEYPAIRS 64
#define PKR_SALT_BYTES 32
#define PKR_MAC_BYTES 64
typedef struct keyring_identity {
  char *PKRPin;
  struct subscriber *subscriber;
  time_ms_t challenge_expires;
  unsigned char challenge[24];
  unsigned int slot;
  unsigned int keypair_count;
  keypair *keypairs[PKR_MAX_KEYPAIRS];
} keyring_identity;

/* 64K identities, can easily be increased should the need arise,
   but keep it low-ish for now so that the 64K pointers don't eat too
   much ram on a small device.  Should probably think about having
   small and large device settings for some of these things */
#define KEYRING_MAX_IDENTITIES 65536
typedef struct keyring_context {
  char *KeyRingPin;
  unsigned char *KeyRingSalt;
  int KeyRingSaltLen;
  unsigned int identity_count;
  keyring_identity *identities[KEYRING_MAX_IDENTITIES];
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

#define KEYRING_MAX_CONTEXTS 256
typedef struct keyring_file {
  int context_count;
  keyring_bam *bam;
  keyring_context *contexts[KEYRING_MAX_CONTEXTS];
  FILE *file;
  off_t file_size;
} keyring_file;

void keyring_free(keyring_file *k);
void keyring_release_identity(keyring_file *k, int cn, int id);
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
int keyring_sanitise_position(const keyring_file *k,int *cn,int *in,int *kp);
int keyring_next_keytype(const keyring_file *k, int *cn, int *in, int *kp, int keytype);
int keyring_next_identity(const keyring_file *k,int *cn,int *in,int *kp);
int keyring_identity_find_keytype(const keyring_file *k, int cn, int in, int keytype);
int keyring_find_did(const keyring_file *k,int *cn,int *in,int *kp, const char *did);
int keyring_find_sid(const keyring_file *k,int *cn,int *in,int *kp, const sid_t *sidp);
unsigned char *keyring_find_sas_private(keyring_file *k, const sid_t *sidp, unsigned char **sas_public);
int keyring_send_sas_request(struct subscriber *subscriber);

int keyring_commit(keyring_file *k);
keyring_identity *keyring_create_identity(keyring_file *k,keyring_context *c, const char *pin);
int keyring_seed(keyring_file *k);
void keyring_identity_extract(const keyring_identity *id, const sid_t **sidp, const char **didp, const char **namep);
int keyring_load(keyring_file *k, const char *keyring_pin, unsigned entry_pinc, const char **entry_pinv, FILE *input);
int keyring_dump(keyring_file *k, XPRINTF xpf, int include_secret);

unsigned char *keyring_get_nm_bytes(const sid_t *known_sidp, const sid_t *unknown_sidp);

int keyring_mapping_request(keyring_file *k, struct overlay_frame *frame, overlay_mdp_frame *req);
int keyring_send_unlock(struct subscriber *subscriber);
void keyring_release_subscriber(keyring_file *k, const sid_t *sid);

int keyring_set_public_tag(keyring_identity *id, const char *name, const unsigned char *value, size_t length);
int keyring_find_public_tag(const keyring_file *k, int *cn, int *in, int *kp, const char *name, const unsigned char **value, size_t *length);
int keyring_find_public_tag_value(const keyring_file *k, int *cn, int *in, int *kp, const char *name, const unsigned char *value, size_t length);
int keyring_unpack_tag(const unsigned char *packed, size_t packed_len, const char **name, const unsigned char **value, size_t *length);
int keyring_pack_tag(unsigned char *packed, size_t *packed_len, const char *name, const unsigned char *value, size_t length);

#endif // __SERVALD_KEYRING_H
