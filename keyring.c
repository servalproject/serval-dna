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

#include <stdio.h>
#include <assert.h>
#include "serval.h"
#include "rhizome.h"
#include "conf.h"
#include "constants.h"
#include "overlay_address.h"
#include "crypto.h"
#include "overlay_interface.h"
#include "overlay_packet.h"
#include "overlay_buffer.h"
#include "keyring.h"
#include "dataformats.h"
#include "str.h"
#include "mem.h"
#include "rotbuf.h"
#include "server.h"
#include "route_link.h"

static keyring_file *keyring_open_or_create(const char *path, int writeable);
static int keyring_initialise(keyring_file *k);
static int keyring_load(keyring_file *k, const char *pin);
static keyring_file *keyring_open_create_instance(const char *pin, int force_create);
static void keyring_free_keypair(keypair *kp);
static void keyring_free_identity(keyring_identity *id);
static int keyring_identity_mac(const keyring_identity *id, unsigned char *pkrsalt, unsigned char *mac);

struct combined_pk{
  uint8_t sign_key[crypto_sign_PUBLICKEYBYTES];
  sid_t box_key;
};

struct combined_sk{
  uint8_t sign_key[crypto_sign_SECRETKEYBYTES];
  uint8_t box_key[crypto_box_SECRETKEYBYTES];
};

static int _keyring_open(keyring_file *k, const char *path, const char *mode)
{
  DEBUGF(keyring, "opening %s in \"%s\" mode", alloca_str_toprint(path), mode);
  if (sodium_init()==-1)
    return WHY("Failed to initialise libsodium");
  k->file = fopen(path, mode);
  if (!k->file) {
    if (errno != EPERM && errno != ENOENT)
      return WHYF_perror("fopen(%s, \"%s\")", alloca_str_toprint(path), mode);
    DEBUGF(keyring, "cannot open %s in \"%s\" mode", alloca_str_toprint(path), mode);
  }
  return 0;
}

/*
 * Open keyring file and  detect its size.
 */
static keyring_file *keyring_open_or_create(const char *path, int writeable)
{
  /* Allocate structure */
  keyring_file *k = emalloc_zero(sizeof(keyring_file));
  if (!k)
    return NULL;
  /* Open keyring file read-write if we can, else use it read-only, else create it. */
  if (writeable && _keyring_open(k, path, "r+") == -1) {
    keyring_free(k);
    return NULL;
  }
  if (!k->file && _keyring_open(k, path, "r") == -1) {
    keyring_free(k);
    return NULL;
  }
  if (!k->file && writeable && _keyring_open(k, path, "w+") == -1) {
    keyring_free(k);
    return NULL;
  }
  if (!k->file) {
    WHYF_perror("cannot open or create keyring file %s", alloca_str_toprint(path));
    keyring_free(k);
    return NULL;
  }
  if (fseeko(k->file, 0, SEEK_END)) {
    WHYF_perror("fseeko(%s, 0, SEEK_END)", alloca_str_toprint(path));
    keyring_free(k);
    return NULL;
  }
  k->file_size = ftello(k->file);
  return k;
}

/*
 * Write initial content of keyring file (erasing anything already there).
 */
static int keyring_initialise(keyring_file *k)
{
  // Write 2KB of zeroes, followed by 2KB of random bytes as salt.
  if (fseeko(k->file, 0, SEEK_SET))
    return WHYF_perror("fseeko(%d, 0, SEEK_SET)", fileno(k->file));
  unsigned char buffer[KEYRING_PAGE_SIZE];
  bzero(&buffer[0], KEYRING_BAM_BYTES);
  randombytes_buf(&buffer[KEYRING_BAM_BYTES], KEYRING_PAGE_SIZE - KEYRING_BAM_BYTES);
  if (fwrite(buffer, KEYRING_PAGE_SIZE, 1, k->file) != 1) {
    WHYF_perror("fwrite(%p, %zu, 1, %d)", buffer, KEYRING_PAGE_SIZE - KEYRING_BAM_BYTES, fileno(k->file));
    return WHYF("Could not write page into keyring file");
  }
  k->file_size = KEYRING_PAGE_SIZE;
  return 0;
}

/*
 * Read the BAM and create initial context using the stored salt.
 */
static int keyring_load(keyring_file *k, const char *pin)
{
  /* Read BAMs for each slab in the file */
  keyring_bam **b=&k->bam;
  size_t offset = 0;
  while (offset < k->file_size) {
    /* Read bitmap from slab.  If offset is zero, read the salt */
    if (fseeko(k->file, (off_t)offset, SEEK_SET)) {
      WHYF_perror("fseeko(%d, %zd, SEEK_SET)", fileno(k->file), offset);
      return WHY("Could not seek to BAM in keyring file");
    }
    *b = emalloc_zero(sizeof(keyring_bam));
    if (!*b)
      return WHYF("Could not allocate keyring_bam structure");
    (*b)->file_offset = offset;
    /* Read bitmap */
    int r = fread((*b)->bitmap, KEYRING_BAM_BYTES, 1, k->file);
    if (r != 1) {
      WHYF_perror("fread(%p, %zd, 1, %d)", (*b)->bitmap, KEYRING_BAM_BYTES, fileno(k->file));
      return WHYF("Could not read BAM from keyring file");
    }
    /* Read salt if this is the first bitmap block.
       We setup a context for this self-supplied key-ring salt.
       (other keyring salts may be provided later on, resulting in
       multiple contexts being loaded) */
    if (!offset) {
      k->KeyRingPin = str_edup(pin);
      k->KeyRingSaltLen=KEYRING_PAGE_SIZE-KEYRING_BAM_BYTES;
      k->KeyRingSalt = emalloc(k->KeyRingSaltLen);
      if (!k->KeyRingSalt)
	return WHYF("Could not allocate keyring_context->salt");
      r = fread(k->KeyRingSalt, k->KeyRingSaltLen, 1, k->file);
      if (r!=1) {
	WHYF_perror("fread(%p, %d, 1, %d)", k->KeyRingSalt, k->KeyRingSaltLen, fileno(k->file));
	return WHYF("Could not read salt from keyring file");
      }
    }
    /* Skip to next slab, and find next bam pointer. */
    offset += KEYRING_PAGE_SIZE * (KEYRING_BAM_BYTES << 3);
    b = &(*b)->next;
  }
  return 0;
}

void keyring_iterator_start(keyring_file *k, keyring_iterator *it)
{
  bzero(it, sizeof(keyring_iterator));
  assert(k);
  it->file = k;
}

keyring_identity * keyring_next_identity(keyring_iterator *it)
{
  assert(it->file);
  if (!it->identity)
    it->identity=it->file->identities;
  else
    it->identity=it->identity->next;
  if (it->identity)
    it->keypair = it->identity->keypairs;
  else
    it->keypair = NULL;
  return it->identity;
}

keypair * keyring_next_key(keyring_iterator *it)
{
  if (it->keypair)
    it->keypair = it->keypair->next;
  if (!it->keypair)
    keyring_next_identity(it);
  return it->keypair;
}

keypair *keyring_next_keytype(keyring_iterator *it, unsigned keytype)
{
  keypair *kp;
  while((kp=keyring_next_key(it)) && kp->type!=keytype)
    ;
  return kp;
}

keypair *keyring_identity_keytype(const keyring_identity *id, unsigned keytype)
{
  keypair *kp=id->keypairs;
  while(kp && kp->type!=keytype)
    kp=kp->next;
  return kp;
}

keypair *keyring_find_did(keyring_iterator *it, const char *did)
{
  keypair *kp;
  while((kp=keyring_next_keytype(it, KEYTYPE_DID))){
    if ((!did[0])
	||(did[0]=='*'&&did[1]==0)
	||(!strcasecmp(did,(char *)kp->private_key))
    ) {
      return kp;
    }
  }
  return NULL;
}

const uint8_t * keyring_get_box(const keyring_identity *id)
{
  keypair *kp = id->keypairs;
  while(kp){
    if (kp->type == KEYTYPE_CRYPTOBOX)
      return kp->private_key;
    if (kp->type == KEYTYPE_CRYPTOCOMBINED){
      struct combined_sk *secret = (struct combined_sk *)kp->private_key;
      return secret->box_key;
    }
    kp = kp->next;
  }
  return NULL;
}

int keyring_find_box(keyring_iterator *it, const sid_t *sidp, const uint8_t **sk)
{
  keypair *kp;
  while((kp=keyring_next_key(it))){
    if (kp->type == KEYTYPE_CRYPTOBOX){
      if (memcmp(sidp->binary, kp->public_key, SID_SIZE) == 0){
	if (sk)
	  *sk = kp->private_key;
	return 1;
      }
    }else if(kp->type == KEYTYPE_CRYPTOCOMBINED){
      struct combined_pk *pk = (struct combined_pk *)kp->public_key;
      if (memcmp(sidp->binary, pk->box_key.binary, SID_SIZE) == 0){
	if (sk){
	  struct combined_sk *secret = (struct combined_sk *)kp->private_key;
	  *sk = secret->box_key;
	}
	return 1;
      }
    }
  }
  return 0;
}

keyring_identity *keyring_find_identity(keyring_file *k, const sid_t *sidp){
  keypair *kp;
  keyring_iterator it;
  keyring_iterator_start(k, &it);
  while((kp=keyring_next_key(&it))){
    if (kp->type == KEYTYPE_CRYPTOBOX){
      if (memcmp(sidp->binary, kp->public_key, SID_SIZE) == 0)
	return it.identity;
    }else if(kp->type == KEYTYPE_CRYPTOCOMBINED){
      struct combined_pk *pk = (struct combined_pk *)kp->public_key;
      if (memcmp(sidp->binary, pk->box_key.binary, SID_SIZE) == 0)
	return it.identity;
    }
  }
  return NULL;
}

static void add_subscriber(keyring_identity *id)
{
  id->subscriber = find_subscriber(id->box_pk->binary, SID_SIZE, 1);
  if (id->subscriber) {
    if (id->subscriber->reachable == REACHABLE_NONE){
      id->subscriber->reachable = REACHABLE_SELF;
      if (!my_subscriber)
	my_subscriber = id->subscriber;
    }
    id->subscriber->identity = id;
  }
}

static void wipestr(char *str)
{
  while (*str)
    *str++ = ' ';
}

void keyring_free(keyring_file *k)
{
  if (!k) return;

  /* Close keyring file handle */
  if (k->file) fclose(k->file);
  k->file=NULL;

  /* Free BAMs (no substructure, so easy) */
  keyring_bam *b=k->bam;
  while(b) {
    keyring_bam *last_bam=b;
    b=b->next;
    /* Clear out any private data */
    bzero(last_bam,sizeof(keyring_bam));
    /* release structure */
    free(last_bam);
  }

  /* Free dynamically allocated salt strings.
     Don't forget to overwrite any private data. */
  if (k->KeyRingPin) {
    /* Wipe pin from local memory before freeing. */
    wipestr(k->KeyRingPin);
    free(k->KeyRingPin);
    k->KeyRingPin = NULL;
  }
  if (k->KeyRingSalt) {
    bzero(k->KeyRingSalt,k->KeyRingSaltLen);
    free(k->KeyRingSalt);
    k->KeyRingSalt = NULL;
    k->KeyRingSaltLen = 0;
  }
  
  /* Wipe out any loaded identities */
  while(k->identities){
    keyring_identity *i = k->identities;
    k->identities=i->next;
    keyring_free_identity(i);
  }
  
  /* Wipe everything, just to be sure. */
  bzero(k,sizeof(keyring_file));
  free(k);
  
  return;
}

int keyring_release_identity(keyring_iterator *it)
{
  assert(it->identity);
  
  keyring_identity **i=&it->file->identities;
  while(*i){
    if ((*i)==it->identity){
      (*i) = it->identity->next;
      keyring_free_identity(it->identity);
      it->identity=(*i);
      if (it->identity)
	it->keypair = it->identity->keypairs;
      else
	it->keypair = NULL;
      return 0;
    }
    i=&(*i)->next;
  }
  return WHY("Previous identity not found");
}

int keyring_release_subscriber(keyring_file *k, const sid_t *sid)
{
  keyring_iterator it;
  keyring_iterator_start(k, &it);
  
  if (!keyring_find_sid(&it, sid))
    return WHYF("Keyring entry for %s not found", alloca_tohex_sid_t(*sid));
  if (it.identity->subscriber == my_subscriber)
    return WHYF("Cannot release my main subscriber");
  return keyring_release_identity(&it);
}

void keyring_free_identity(keyring_identity *id)
{
  if (id->PKRPin) {
    /* Wipe pin from local memory before freeing. */
    wipestr(id->PKRPin);
    free(id->PKRPin);
    id->PKRPin = NULL;
  }
  while(id->keypairs){
    keypair *kp=id->keypairs;
    id->keypairs=kp->next;
    keyring_free_keypair(kp);
  }
  if (id->challenge)
    free(id->challenge);
  if (id->subscriber)
    link_stop_routing(id->subscriber);
  bzero(id,sizeof(keyring_identity));
  free(id);
  return;
}

/*
  En/Decrypting a block requires use of the first 32 bytes of the block to provide
  salt.  The next 64 bytes constitute a message authentication code (MAC) that is
  used to verify the validity of the block.  The verification occurs in a higher
  level function, and all we need to know here is that we shouldn't decrypt the
  first 96 bytes of the block.
*/
static int keyring_munge_block(
  unsigned char *block, int len /* includes the first 96 bytes */,
  unsigned char *KeyRingSalt, int KeyRingSaltLen,
  const char *KeyRingPin, const char *PKRPin)
{
  DEBUGF(keyring, "KeyRingPin=%s PKRPin=%s", alloca_str_toprint(KeyRingPin), alloca_str_toprint(PKRPin));
  int exit_code=1;
  unsigned char hashKey[crypto_hash_sha512_BYTES];
  unsigned char hashNonce[crypto_hash_sha512_BYTES];

  unsigned char work[65536];

  if (len<96) return WHY("block too short");

  unsigned char *PKRSalt=&block[0];
  int PKRSaltLen=32;

#if crypto_box_SECRETKEYBYTES>crypto_hash_sha512_BYTES
#error crypto primitive key size too long -- hash needs to be expanded
#endif
#if crypto_box_NONCEBYTES>crypto_hash_sha512_BYTES
#error crypto primitive nonce size too long -- hash needs to be expanded
#endif

  /* Generate key and nonce hashes from the various inputs */
  unsigned ofs;
#define APPEND(buf, len) { \
    assert(ofs <= sizeof work); \
    unsigned __len = (len); \
    if (__len > sizeof work - ofs) { \
      WHY("Input too long"); \
      goto kmb_safeexit; \
    } \
    bcopy((buf), &work[ofs], __len); \
    ofs += __len; \
  }
  /* Form key as hash of various concatenated inputs.
     The ordering and repetition of the inputs is designed to make rainbow tables
     infeasible */
  ofs=0;
  APPEND(PKRSalt,PKRSaltLen);
  APPEND(PKRPin,strlen(PKRPin));
  APPEND(PKRSalt,PKRSaltLen);
  APPEND(KeyRingPin,strlen(KeyRingPin));
  crypto_hash_sha512(hashKey,work,ofs);

  /* Form the nonce as hash of various other concatenated inputs */
  ofs=0;
  APPEND(KeyRingPin,strlen(KeyRingPin));
  APPEND(KeyRingSalt,KeyRingSaltLen);
  APPEND(KeyRingPin,strlen(KeyRingPin));
  APPEND(PKRPin,strlen(PKRPin));
  crypto_hash_sha512(hashNonce,work,ofs);

  /* Now en/de-crypt the remainder of the block.
     We do this in-place for convenience, so you should not pass in a mmap()'d
     lump. */
  crypto_stream_xsalsa20_xor(&block[96],&block[96],len-96, hashNonce,hashKey);
  exit_code=0;

 kmb_safeexit:
  /* Wipe out all sensitive structures before returning */
  ofs=0;
  bzero(&work[0],65536);
  bzero(&hashKey[0],crypto_hash_sha512_BYTES);
  bzero(&hashNonce[0],crypto_hash_sha512_BYTES);
  return exit_code;
#undef APPEND
}

static const char *keytype_str(unsigned ktype, const char *unknown)
{
  switch (ktype) {
  case KEYTYPE_CRYPTOBOX: return "CRYPTOBOX";
  case KEYTYPE_CRYPTOSIGN: return "CRYPTOSIGN";
  case KEYTYPE_RHIZOME: return "RHIZOME";
  case KEYTYPE_DID: return "DID";
  case KEYTYPE_PUBLIC_TAG: return "PUBLIC_TAG";
  case KEYTYPE_CRYPTOCOMBINED: return "CRYPTOCOMBINED";
  default: return unknown;
  }
}

struct keytype {
  size_t public_key_size;
  size_t private_key_size;
  size_t packed_size;
  void (*creator)(keypair *);
  int (*packer)(const keypair *, struct rotbuf *);
  int (*unpacker)(keypair *, struct rotbuf *, size_t);
  void (*dumper)(const keypair *, XPRINTF, int);
  int (*loader)(keypair *, const char *);
};

static void create_rhizome(keypair *kp)
{
  randombytes_buf(kp->private_key, kp->private_key_len);
}

static void create_cryptocombined(keypair *kp)
{
  struct combined_pk *pk = (struct combined_pk *)kp->public_key;
  struct combined_sk *sk = (struct combined_sk *)kp->private_key;
  crypto_sign_ed25519_keypair(pk->sign_key, sk->sign_key);
  crypto_sign_ed25519_sk_to_curve25519(sk->box_key, sk->sign_key);
  crypto_scalarmult_base(pk->box_key.binary, sk->box_key);
}

static int pack_cryptocombined(const keypair *kp, struct rotbuf *rb)
{
  uint8_t seed[crypto_sign_SEEDBYTES];
  struct combined_sk *sk = (struct combined_sk *)kp->private_key;
  crypto_sign_ed25519_sk_to_seed(seed, sk->sign_key);
  rotbuf_putbuf(rb, seed, sizeof seed);
  return 0;
}

static int unpack_cryptocombined(keypair *kp, struct rotbuf *rb, size_t key_length)
{
  uint8_t seed[crypto_sign_SEEDBYTES];
  struct combined_pk *pk = (struct combined_pk *)kp->public_key;
  struct combined_sk *sk = (struct combined_sk *)kp->private_key;
  assert(key_length == sizeof seed);
  rotbuf_getbuf(rb, seed, sizeof seed);
  crypto_sign_ed25519_seed_keypair(pk->sign_key, sk->sign_key, seed);
  crypto_sign_ed25519_sk_to_curve25519(sk->box_key, sk->sign_key);
  crypto_scalarmult_base(pk->box_key.binary, sk->box_key);
  return 0;
}

static int pack_private_only(const keypair *kp, struct rotbuf *rb)
{
  rotbuf_putbuf(rb, kp->private_key, kp->private_key_len);
  return 0;
}

static int pack_public_only(const keypair *kp, struct rotbuf *rb)
{
  rotbuf_putbuf(rb, kp->public_key, kp->public_key_len);
  return 0;
}

static int pack_private_public(const keypair *kp, struct rotbuf *rb)
{
  rotbuf_putbuf(rb, kp->private_key, kp->private_key_len);
  rotbuf_putbuf(rb, kp->public_key, kp->public_key_len);
  return 0;
}

static void dump_private_public(const keypair *kp, XPRINTF xpf, int include_secret)
{
  if (kp->public_key_len)
    xprintf(xpf, " pub=%s", alloca_tohex(kp->public_key, kp->public_key_len));
  if (include_secret && kp->private_key_len)
    xprintf(xpf, " sec=%s", alloca_tohex(kp->private_key, kp->private_key_len));
}

static int _load_decode_hex(const char **hex, unsigned char **buf, size_t *len)
{
  const char *end = NULL;
  size_t hexlen = strn_fromhex(NULL, -1, *hex, &end);
  if (hexlen == 0 || end == NULL || (*end != ' ' && *end != '\0'))
    return WHY("malformed hex value");
  if (*len == 0) {
    assert(*buf == NULL);
    *len = hexlen;
    if ((*buf = emalloc_zero(*len)) == NULL)
      return -1;
  }
  else if (hexlen != *len)
    return WHYF("invalid hex value, incorrect length (expecting %zu bytes, got %zu)", *len, hexlen);
  strn_fromhex(*buf, *len, *hex, hex);
  assert(*hex == end);
  return 0;
}

static int load_private_public(keypair *kp, const char *text)
{
  assert(kp->public_key_len != 0);
  assert(kp->public_key != NULL);
  assert(kp->private_key_len != 0);
  assert(kp->private_key != NULL);
  const char *t = text;
  int got_pub = 0;
  int got_sec = 0;
  while (*t) {
    while (isspace(*t))
      ++t;
    if (str_startswith(t, "pub=", &t)) {
      if (_load_decode_hex(&t, &kp->public_key, &kp->public_key_len) == -1)
	WHY("cannot decode pub= field");
      else
	got_pub = 1;
    }
    else if (str_startswith(t, "sec=", &t)) {
      if (_load_decode_hex(&t, &kp->private_key, &kp->private_key_len) == -1)
	WHY("cannot decode sec= field");
      else
	got_sec = 1;
    }
    else if (*t)
      return WHYF("unsupported dump field: %s", t);
  }
  if (!got_sec)
    return WHY("missing sec= field");
  if (!got_pub)
    return WHY("missing pub= field");
  return 0;
}

static int load_private(keypair *kp, const char *text)
{
  assert(kp->private_key_len != 0);
  assert(kp->private_key != NULL);
  const char *t = text;
  int got_sec = 0;
  while (*t) {
    while (isspace(*t))
      ++t;
    if (str_startswith(t, "sec=", &t)) {
      if (_load_decode_hex(&t, &kp->private_key, &kp->private_key_len) == -1)
	WHY("cannot decode sec= field");
      else
	got_sec = 1;
    } else if (str_startswith(t, "pub=", &t)) {
      WARN("skipping pub= field");
      while (*t && !isspace(*t))
	++t;
    }
    else if (*t)
      return WHYF("unsupported dump field: %s", t);
  }
  if (!got_sec)
    return WHY("missing sec= field");
  return 0;
}

static int load_cryptobox(keypair *kp, const char *text)
{
  if (load_private(kp, text) == -1)
    return -1;
  crypto_scalarmult_base(kp->public_key, kp->private_key);
  return 0;
}

static int load_private_only(keypair *kp, const char *text)
{
  assert(kp->public_key_len == 0);
  assert(kp->public_key == NULL);
  return load_private(kp, text);
}

static int load_unknown(keypair *kp, const char *text)
{
  assert(kp->private_key_len == 0);
  assert(kp->private_key == NULL);
  assert(kp->public_key_len == 0);
  assert(kp->public_key == NULL);
  const char *t = text;
  while (*t) {
    while (isspace(*t))
      ++t;
    if (str_startswith(t, "pub=", &t)) {
      if (_load_decode_hex(&t, &kp->public_key, &kp->public_key_len) == -1)
	WHY("cannot decode pub= field");
    }
    else if (str_startswith(t, "sec=", &t)) {
      if (_load_decode_hex(&t, &kp->private_key, &kp->private_key_len) == -1)
	WHY("cannot decode sec= field");
    }
    else if (*t)
      return WHYF("unsupported dump field: %s", t);
  }
  return 0;
}

static int unpack_private_public(keypair *kp, struct rotbuf *rb, size_t key_length)
{
  assert(key_length == kp->private_key_len + kp->public_key_len);
  rotbuf_getbuf(rb, kp->private_key, kp->private_key_len);
  rotbuf_getbuf(rb, kp->public_key, kp->public_key_len);
  return 0;
}

static int unpack_private_only(keypair *kp, struct rotbuf *rb, size_t key_length)
{
  if (!kp->private_key){
    kp->private_key_len = key_length;
    if ((kp->private_key = emalloc(kp->private_key_len))==NULL)
      return -1;
  }else{
    assert(kp->private_key_len == key_length);
  }
  rotbuf_getbuf(rb, kp->private_key, kp->private_key_len);
  return 0;
}

static int unpack_public_only(keypair *kp, struct rotbuf *rb, size_t key_length)
{
  if (!kp->public_key){
    kp->public_key_len = key_length;
    if ((kp->public_key = emalloc(kp->public_key_len))==NULL)
      return -1;
  }else{
    assert(kp->public_key_len == key_length);
  }
  rotbuf_getbuf(rb, kp->public_key, kp->public_key_len);
  return 0;
}

static int unpack_cryptobox(keypair *kp, struct rotbuf *rb, size_t key_length)
{
  assert(key_length == kp->private_key_len);
  rotbuf_getbuf(rb, kp->private_key, kp->private_key_len);
  if (!rb->wrap)
    crypto_scalarmult_base(kp->public_key, kp->private_key);
  return 0;
}

static int pack_did_name(const keypair *kp, struct rotbuf *rb)
{
  // Ensure name is nul terminated.
  if (strnchr((const char *)kp->public_key, kp->public_key_len, '\0') == NULL)
    return WHY("missing nul terminator");
  return pack_private_public(kp, rb);
}

static int unpack_did_name(keypair *kp, struct rotbuf *rb, size_t key_length)
{
  if (unpack_private_public(kp, rb, key_length) == -1)
    return -1;
  // Fail if name is not nul terminated.
  return strnchr((const char *)kp->public_key, kp->public_key_len, '\0') == NULL ? -1 : 0;
}

static void dump_did_name(const keypair *kp, XPRINTF xpf, int UNUSED(include_secret))
{
  xprintf(xpf, " DID=%s", alloca_str_toprint_quoted((const char *)kp->private_key, "\"\""));
  xprintf(xpf, " Name=%s", alloca_str_toprint_quoted((const char *)kp->public_key, "\"\""));
}

static int load_did_name(keypair *kp, const char *text)
{
  assert(kp->public_key != NULL);
  assert(kp->private_key != NULL);
  const char *t = text;
  int got_did = 0;
  int got_name = 0;
  while (*t) {
    while (isspace(*t))
      ++t;
    if (str_startswith(t, "DID=\"", &t)) {
      if (got_did)
	return WHY("duplicate DID");
      const char *e = NULL;
      bzero(kp->private_key, kp->private_key_len);
      strn_fromprint(kp->private_key, kp->private_key_len, t, 0, '"', &e);
      if (*e != '"')
	return WHY("malformed DID quoted string");
      t = e + 1;
      got_did = 1;
    } else if (str_startswith(t, "Name=\"", &t)) {
      if (got_name)
	return WHY("duplicate Name");
      const char *e = NULL;
      bzero(kp->public_key, kp->public_key_len);
      strn_fromprint(kp->public_key, kp->public_key_len, t, 0, '"', &e);
      if (*e != '"')
	return WHY("malformed Name quoted string");
      t = e + 1;
      got_name = 1;
    }
    else if (*t)
      return WHYF("unsupported dump content: %s", t);
  }
  if (!got_did)
    return WHY("missing DID");
  if (!got_name)
    return WHY("missing Name");
  return 0;
}

/* This is where all the supported key types are declared.  In order to preserve backward
 * compatibility (reading keyring files from older versions of Serval DNA), DO NOT ERASE OR RE-USE
 * ANY KEY TYPE ENTRIES FROM THIS ARRAY.  If a key type is no longer used, it must be permanently
 * deprecated, ie, recognised and simply skipped.  The packer and unpacker functions can be changed
 * to NULL.
 */
const struct keytype keytypes[] = {
  [KEYTYPE_CRYPTOBOX] = {
      /* Only the private key is stored, and the public key (SID) is derived from the private key
       * when the keyring is read.
       */
      .private_key_size = crypto_box_SECRETKEYBYTES,
      .public_key_size = crypto_box_PUBLICKEYBYTES,
      .packed_size = crypto_box_SECRETKEYBYTES,
      .creator = NULL, // deprecated
      .packer = pack_private_only,
      .unpacker = unpack_cryptobox,
      .dumper = dump_private_public,
      .loader = load_cryptobox
    },
  [KEYTYPE_CRYPTOSIGN] = {
      /* The NaCl API does not expose any method to derive a cryptosign public key from its private
       * key, although there must be an internal NaCl function to do so.  Subverting the NaCl API to
       * invoke that function risks incompatibility with future releases of NaCl, so instead the
       * public key is stored redundantly in the keyring.
       */
      .private_key_size = crypto_sign_SECRETKEYBYTES,
      .public_key_size = crypto_sign_PUBLICKEYBYTES,
      .packed_size = crypto_sign_SECRETKEYBYTES + crypto_sign_PUBLICKEYBYTES,
      .creator = NULL, // deprecated
      .packer = pack_private_public,
      .unpacker = unpack_private_public,
      .dumper = dump_private_public,
      .loader = load_private_public
    },
  [KEYTYPE_RHIZOME] = {
      /* The Rhizome Secret (a large, unguessable number) is stored in the private key field, and
       * the public key field is not used.
       */
      .private_key_size = 32,
      .public_key_size = 0,
      .packed_size = 32,
      .creator = create_rhizome,
      .packer = pack_private_only,
      .unpacker = unpack_private_only,
      .dumper = dump_private_public,
      .loader = load_private_only
    },
  [KEYTYPE_DID] = {
      /* The DID is stored in unpacked form in the private key field, and the name in nul-terminated
       * ASCII form in the public key field.
       */
      .private_key_size = 32,
      .public_key_size = 64,
      .packed_size = 32 + 64,
      .creator = NULL, // not included in a newly created identity
      .packer = pack_did_name,
      .unpacker = unpack_did_name,
      .dumper = dump_did_name,
      .loader = load_did_name
    },
  [KEYTYPE_PUBLIC_TAG] = {
      .private_key_size = 0,
      .public_key_size = 0, // size is derived from the stored key length
      .packed_size = 0,
      .creator = NULL, // not included in a newly created identity
      .packer = pack_public_only,
      .unpacker = unpack_public_only,
      .dumper = dump_private_public,
      .loader = load_unknown
    },
  [KEYTYPE_CRYPTOCOMBINED] = {
      .private_key_size = sizeof (struct combined_sk),
      .public_key_size = sizeof (struct combined_pk),
      .packed_size = crypto_sign_SEEDBYTES,
      .creator = create_cryptocombined,
      .packer = pack_cryptocombined,
      .unpacker = unpack_cryptocombined,
      .dumper = dump_private_public,
      .loader = load_private_public
  }
  // ADD MORE KEY TYPES HERE
};

static void keyring_free_keypair(keypair *kp)
{
  if (kp->private_key) {
    bzero(kp->private_key, kp->private_key_len);
    free(kp->private_key);
  }
  if (kp->public_key) {
    bzero(kp->public_key, kp->public_key_len);
    free(kp->public_key);
  }
  bzero(kp, sizeof(keypair));
  free(kp);
}

static keypair *keyring_alloc_keypair(unsigned ktype, size_t len)
{
  assert(ktype != 0);
  keypair *kp = emalloc_zero(sizeof(keypair));
  if (!kp)
    return NULL;
  kp->type = ktype;
  if (ktype < NELS(keytypes)) {
    kp->private_key_len = keytypes[ktype].private_key_size;
    kp->public_key_len = keytypes[ktype].public_key_size;
  } else {
    kp->private_key_len = len;
    kp->public_key_len = 0;
  }
  if (   (kp->private_key_len && (kp->private_key = emalloc(kp->private_key_len)) == NULL)
      || (kp->public_key_len && (kp->public_key = emalloc(kp->public_key_len)) == NULL)
  ) {
    keyring_free_keypair(kp);
    return NULL;
  }
  return kp;
}

static int keyring_pack_identity(const keyring_identity *id, unsigned char packed[KEYRING_PAGE_SIZE])
{
  /* Convert an identity to a KEYRING_PAGE_SIZE bytes long block that consists of 32 bytes of random
   * salt, a 64 byte (512 bit) message authentication code (MAC) and the list of key pairs. */
  randombytes_buf(packed, PKR_SALT_BYTES);
  /* Calculate MAC */
  if (keyring_identity_mac(id, packed /* pkr salt */, packed + PKR_SALT_BYTES /* write mac in after salt */) == -1)
    return -1;
  /* There was a known plain-text opportunity here: byte 96 must be 0x01, and some other bytes are
   * likely deducible, e.g., the location of the trailing 0x00 byte can probably be guessed with
   * confidence.  Payload rotation will frustrate this attack.
   */
  uint16_t rotation = 0;
#ifndef NO_ROTATION
  rotation=randombytes_random();
#endif
  // The two bytes immediately following the MAC describe the rotation offset.
  packed[PKR_SALT_BYTES + PKR_MAC_BYTES] = rotation >> 8;
  packed[PKR_SALT_BYTES + PKR_MAC_BYTES + 1] = rotation & 0xff;
  /* Pack the key pairs into the rest of the slot as a rotated buffer. */
  struct rotbuf rbuf;
  rotbuf_init(&rbuf,
	    packed + PKR_SALT_BYTES + PKR_MAC_BYTES + 2,
	    KEYRING_PAGE_SIZE - (PKR_SALT_BYTES + PKR_MAC_BYTES + 2),
	    rotation);
  keypair *kp=id->keypairs;
  while(kp && !rbuf.wrap){
    unsigned ktype = kp->type;
    const char *kts = keytype_str(ktype, "unknown");
    int (*packer)(const keypair *, struct rotbuf *) = NULL;
    size_t keypair_len=0;
    const struct keytype *kt = &keytypes[ktype];
    if (ktype == 0x00)
      FATALF("ktype=0 in keypair kp=%u", kp);
    if (ktype < NELS(keytypes)) {
      packer = kt->packer;
      keypair_len = kt->packed_size;
      if (keypair_len==0){
	keypair_len = kp->private_key_len + kp->public_key_len;
      }
    } else {
      packer = pack_private_only;
      keypair_len = kp->private_key_len;
    }
    if (packer == NULL) {
      WARNF("no packer function for key type 0x%02x(%s), omitted from keyring file", ktype, kts);
    } else {
      DEBUGF(keyring, "pack key type = 0x%02x(%s)", ktype, kts);
      // First byte is the key type code.
      rotbuf_putc(&rbuf, ktype);
      // The next two bytes are the key pair length, for forward compatibility: so older software can
      // skip over key pairs with an unrecognised type.  The original four first key types do not
      // store the length, for the sake of backward compatibility with legacy keyring files.  Their
      // entry lengths are hard-coded.
      switch (ktype) {
      case KEYTYPE_CRYPTOBOX:
      case KEYTYPE_CRYPTOSIGN:
      case KEYTYPE_RHIZOME:
      case KEYTYPE_DID:
	break;
      default:
	rotbuf_putc(&rbuf, (keypair_len >> 8) & 0xff);
	rotbuf_putc(&rbuf, keypair_len & 0xff);
	break;
      }
      // The remaining bytes is the key pair in whatever format it uses.
      struct rotbuf rbstart = rbuf;
      if (packer(kp, &rbuf) != 0)
	break;
      // Ensure the correct number of bytes were written.
      unsigned packed = rotbuf_delta(&rbstart, &rbuf);
      if (packed != keypair_len) {
	WHYF("key type 0x%02x(%s) packed wrong length (packed %u, expecting %u)", ktype, kts, packed, (int)keypair_len);
	goto scram;
      }
    }
    kp=kp->next;
  }
  // Final byte is a zero key type code.
  rotbuf_putc(&rbuf, 0x00);
  if (rbuf.wrap > 1) {
    WHY("slot overrun");
    goto scram;
  }
  if (kp) {
    WHY("error filling slot");
    goto scram;
  }
  /* Randomfill the remaining part of the slot to frustrate any known-plain-text attack on the
   * keyring.
   */
  {
    unsigned char *buf;
    size_t len;
    while (rotbuf_next_chunk(&rbuf, &buf, &len))
      randombytes_buf(buf, len);
  }
  return 0;
scram:
  /* Randomfill the entire slot to erase any secret keys that may have found their way into it, to
   * avoid leaking sensitive information out through a possibly re-used memory buffer.
   */
  randombytes_buf(packed, KEYRING_PAGE_SIZE);
  return -1;
}

static int cmp_keypair(const keypair *a, const keypair *b)
{
  int c;
  if (a->type < b->type)
    return -1;
  if (a->type > b->type)
    return 1;
  if (a->public_key_len && !b->public_key_len)
    return -1;
  if (!a->public_key_len && b->public_key_len)
    return 1;
  if (a->public_key_len && b->public_key_len){
    assert(a->public_key != NULL);
    assert(b->public_key != NULL);
    size_t len = a->public_key_len;
    if (len > b->public_key_len)
      len = b->public_key_len;
    c = memcmp(a->public_key, b->public_key, len);
    if (c==0 && a->public_key_len!=b->public_key_len)
      c = a->public_key_len - b->public_key_len;
    if (c)
      return c;
  }
  if (a->private_key_len && !b->private_key_len)
    return -1;
  if (!a->private_key_len && b->private_key_len)
    return 1;
  if (a->private_key_len && b->private_key_len) {
    assert(a->private_key != NULL);
    assert(b->private_key != NULL);
    size_t len = a->private_key_len;
    if (len > b->private_key_len)
      len = b->private_key_len;
    c = memcmp(a->private_key, b->private_key, len);
    if (c==0 && a->private_key_len!=b->private_key_len)
      c = a->private_key_len - b->private_key_len;
    if (c)
      return c;
  }
  return 0;
}

/* Ensure that regardless of the order in the keyring file or loaded dump, keypairs are always
 * stored in memory in ascending order of (key type, public key, private key).
 */
static int keyring_identity_add_keypair(keyring_identity *id, keypair *kp)
{
  assert(id);
  assert(kp);
  keypair **ptr=&id->keypairs;
  int c = 1;
  while(*ptr && (c = cmp_keypair(*ptr, kp)) < 0)
    ptr = &(*ptr)->next;
  if (c == 0)
    return 0; // duplicate not inserted
  kp->next = *ptr;
  *ptr = kp;
  return 1;
}

static keyring_identity *keyring_unpack_identity(unsigned char *slot, const char *pin)
{
  /* Skip salt and MAC */
  keyring_identity *id = emalloc_zero(sizeof(keyring_identity));
  if (!id)
    return NULL;
  id->PKRPin = str_edup(pin);
  // The two bytes immediately following the MAC describe the rotation offset.
  uint16_t rotation = (slot[PKR_SALT_BYTES + PKR_MAC_BYTES] << 8) | slot[PKR_SALT_BYTES + PKR_MAC_BYTES + 1];
  /* Pack the key pairs into the rest of the slot as a rotated buffer. */
  struct rotbuf rbuf;
  rotbuf_init(&rbuf,
	    slot + PKR_SALT_BYTES + PKR_MAC_BYTES + 2,
	    KEYRING_PAGE_SIZE - (PKR_SALT_BYTES + PKR_MAC_BYTES + 2),
	    rotation);
  while (!rbuf.wrap) {
    struct rotbuf rbo = rbuf;
    unsigned char ktype = rotbuf_getc(&rbuf);
    if (rbuf.wrap || ktype == 0x00)
      break; // End of data, stop looking
    size_t keypair_len;
    // No length bytes after the original four key types, for backward compatibility.  All other key
    // types are followed by a two-byte keypair length.
    switch (ktype) {
    case KEYTYPE_CRYPTOBOX:
    case KEYTYPE_CRYPTOSIGN:
    case KEYTYPE_RHIZOME:
    case KEYTYPE_DID:
      keypair_len = keytypes[ktype].packed_size;
      break;
    default:
      keypair_len = rotbuf_getc(&rbuf) << 8;
      keypair_len |= rotbuf_getc(&rbuf);
      break;
    }
    if (keypair_len > rotbuf_remain(&rbuf)) {
      DEBUGF(keyring, "invalid keypair length %zu", keypair_len);
      keyring_free_identity(id);
      return NULL;
    }
    // Create keyring entry to hold the key pair.  Even entries of unknown type are stored,
    // so they can be dumped.
    keypair *kp = keyring_alloc_keypair(ktype, keypair_len);
    if (kp == NULL) {
      keyring_free_identity(id);
      return NULL;
    }
    struct rotbuf rbstart = rbuf;
    int (*unpacker)(keypair *, struct rotbuf *, size_t) = NULL;
    if (ktype < NELS(keytypes))
      unpacker = keytypes[ktype].unpacker;
    else
      unpacker = unpack_private_only;

    DEBUGF(keyring, "unpack key type = 0x%02x(%s) at offset %u", ktype, keytype_str(ktype, "unknown"), (int)rotbuf_position(&rbo));
    if (unpacker(kp, &rbuf, keypair_len) != 0) {
      // If there is an error, it is probably an empty slot.
      DEBUGF(keyring, "key type 0x%02x does not unpack", ktype);
      keyring_free_keypair(kp);
      keyring_free_identity(id);
      return NULL;
    }
    // Ensure that the correct number of bytes was consumed.
    size_t unpacked = rotbuf_delta(&rbstart, &rbuf);
    if (unpacked != keypair_len) {
      // If the number of bytes unpacked does not match the keypair length, it is probably an
      // empty slot.
      DEBUGF(keyring, "key type 0x%02x unpacked wrong length (unpacked %u, expecting %u)", ktype, (int)unpacked, (int)keypair_len);
      keyring_free_keypair(kp);
      keyring_free_identity(id);
      return NULL;
    }
    // Got a valid key pair!  Sort the key pairs by (key type, public key, private key) and weed
    // out duplicates.
    if (!keyring_identity_add_keypair(id, kp))
      keyring_free_keypair(kp);
  }
  // If the buffer offset overshot, we got an invalid keypair code and length combination.
  if (rbuf.wrap > 1) {
    DEBUGF(keyring, "slot overrun by %u bytes", rbuf.wrap - 1);
    keyring_free_identity(id);
    return NULL;
  }
  DEBUGF(keyring, "unpacked key pairs");
  return id;
}

static int keyring_identity_mac(const keyring_identity *id, unsigned char *pkrsalt, unsigned char *mac)
{
  unsigned char work[65536];
  unsigned ofs = 0;
#define APPEND(buf, len) { \
    assert(ofs <= sizeof work); \
    unsigned __len = (len); \
    if (__len > sizeof work - ofs) { \
      bzero(work, ofs); \
      DEBUG(keyring, "Input too long"); \
      return -1; \
    } \
    bcopy((buf), &work[ofs], __len); \
    ofs += __len; \
  }
  APPEND(&pkrsalt[0], 32);
  keypair *kp=id->keypairs;
  uint8_t found = 0;
  while(kp){
    if (kp->type == KEYTYPE_CRYPTOBOX || kp->type == KEYTYPE_CRYPTOCOMBINED){
      APPEND(kp->private_key, kp->private_key_len);
      APPEND(kp->public_key, kp->public_key_len);
      found = 1;
    }
    kp = kp->next;
  }
  if (!found){
    DEBUG(keyring,"Identity does not have a primary key");
    return -1;
  }
  APPEND(id->PKRPin, strlen(id->PKRPin));
#undef APPEND
  crypto_hash_sha512(mac, work, ofs);
  return 0;
}

static int keyring_finalise_identity(keyring_file *k, keyring_identity *id)
{
  keypair *kp = id->keypairs;
  while(kp){
    switch(kp->type){
      case KEYTYPE_CRYPTOBOX:
	id->box_pk = (const sid_t *)kp->public_key;
	id->box_sk = kp->private_key;
	break;
      case KEYTYPE_CRYPTOSIGN:
	if (!rhizome_verify_bundle_privatekey(kp->private_key,kp->public_key)){
	  /* SAS key is invalid (perhaps because it was a pre 0.90 format one),
	     so replace it */
	  WARN("SAS key is invalid -- regenerating.");
	  crypto_sign_keypair(kp->public_key, kp->private_key);
	  k->dirty = 1;
	}
	id->sign_pk = kp->public_key;
	id->sign_sk = kp->private_key;
	break;
      case KEYTYPE_CRYPTOCOMBINED:{
	struct combined_pk *pk = (struct combined_pk *)kp->public_key;
	struct combined_sk *sk = (struct combined_sk *)kp->private_key;
	id->box_pk = &pk->box_key;
	id->box_sk = sk->box_key;
	id->sign_pk = pk->sign_key;
	id->sign_sk = sk->sign_key;
	break;
      }
    }
    kp = kp->next;
  }
  return 0;
}


/* Read the slot, and try to decrypt it.  Decryption is symmetric with encryption, so the same
 * function is used for munging the slot before making use of it, whichever way we are going.  Once
 * munged, we then need to verify that the slot is valid, and if so unpack the details of the
 * identity.
 */
static int keyring_decrypt_pkr(keyring_file *k, const char *pin, int slot_number)
{
  DEBUGF(keyring, "k=%p, pin=%s slot_number=%d", k, alloca_str_toprint(pin), slot_number);
  unsigned char slot[KEYRING_PAGE_SIZE];
  keyring_identity *id=NULL;

  /* 1. Read slot. */
  if (fseeko(k->file,slot_number*KEYRING_PAGE_SIZE,SEEK_SET))
    return WHY_perror("fseeko");
  if (fread(slot, KEYRING_PAGE_SIZE, 1, k->file) != 1)
    return WHY_perror("fread");
  /* 2. Decrypt data from slot. */
  if (keyring_munge_block(slot, KEYRING_PAGE_SIZE, k->KeyRingSalt, k->KeyRingSaltLen, k->KeyRingPin, pin)) {
    WHYF("keyring_munge_block() failed, slot=%u", slot_number);
    goto kdp_safeexit;
  }
  /* 3. Unpack contents of slot into a new identity in the provided context. */
  DEBUGF(keyring, "unpack slot %u", slot_number);
  if (((id = keyring_unpack_identity(slot, pin)) == NULL))
    goto kdp_safeexit; // Not a valid slot
  id->slot = slot_number;
  /* 4. Verify that slot is self-consistent (check MAC) */
  unsigned char hash[crypto_hash_sha512_BYTES];
  if (keyring_identity_mac(id, slot, hash))
    goto kdp_safeexit;
  /* compare hash to record */
  if (memcmp(hash, &slot[PKR_SALT_BYTES], crypto_hash_sha512_BYTES)) {
    DEBUGF(keyring, "slot %u is not valid (MAC mismatch)", slot_number);
    if (IF_DEBUG(keyring)){
      dump("computed",hash,crypto_hash_sha512_BYTES);
      dump("stored",&slot[PKR_SALT_BYTES],crypto_hash_sha512_BYTES);
    }
    goto kdp_safeexit;
  }

  if (keyring_finalise_identity(k, id)!=0)
    goto kdp_safeexit;

  add_subscriber(id);

  /* All fine, so add the id into the context and return. */
  keyring_identity **i=&k->identities;
  while(*i)
    i=&(*i)->next;
  *i=id;
  return 0;

 kdp_safeexit:
  /* Clean up any potentially sensitive data before exiting */
  bzero(slot,KEYRING_PAGE_SIZE);
  bzero(hash,crypto_hash_sha512_BYTES);
  if (id)
    keyring_free_identity(id);
  return 1;
}

/* Try all valid slots with the PIN and see if we find any identities with that PIN.
   We might find more than one. */
int keyring_enter_pin(keyring_file *k, const char *pin)
{
  IN();
  DEBUGF(keyring, "k=%p, pin=%s", k, alloca_str_toprint(pin));
  if (!pin) pin="";

  // Check if PIN is already entered.
  int identitiesFound=0;
  keyring_identity *id = k->identities;
  while(id){
    if (strcmp(id->PKRPin, pin) == 0)
      identitiesFound++;
    id=id->next;
  }
  if (identitiesFound)
    RETURN(identitiesFound);
    
  unsigned slot;
  for(slot=0;slot<k->file_size/KEYRING_PAGE_SIZE;slot++) {
    /* slot zero is the BAM and salt, so skip it */
    if (slot&(KEYRING_BAM_BITS-1)) {
      /* Not a BAM slot, so examine */
      size_t file_offset = slot * KEYRING_PAGE_SIZE;

      /* See if this part of the keyring file is organised */
      keyring_bam *b=k->bam;
      while (b && (file_offset >= b->file_offset + KEYRING_SLAB_SIZE))
	b=b->next;
      if (!b) continue;

      /* Now see if slot is marked in-use.  No point checking unallocated slots,
	  especially since the cost can be upto a second of CPU time on a phone. */
      int position=slot&(KEYRING_BAM_BITS-1);
      int byte=position>>3;
      int bit=position&7;
      if (b->bitmap[byte]&(1<<bit)) {
	/* Slot is occupied, so check it.
	    We have to check it for each keyring context (ie keyring pin) */
	if (keyring_decrypt_pkr(k, pin, slot) == 0)
	  ++identitiesFound;
      }
    }
  }

  if (k->dirty)
    keyring_commit(k);
  
  RETURN(identitiesFound);
  OUT();
}

static unsigned test_slot(const keyring_file *k, unsigned slot)
{
  assert(slot < KEYRING_BAM_BITS);
  unsigned position = slot & (KEYRING_BAM_BITS - 1);
  unsigned byte = position >> 3;
  unsigned bit = position & 7;
  return (k->bam->bitmap[byte] & (1 << bit)) ? 1 : 0;
}

static void set_slot(keyring_file *k, unsigned slot, int bitvalue)
{
  assert(slot < KEYRING_BAM_BITS);
  unsigned position = slot & (KEYRING_BAM_BITS - 1);
  unsigned byte = position >> 3;
  unsigned bit = position & 7;
  if (bitvalue)
    k->bam->bitmap[byte] |= (1 << bit);
  else
    k->bam->bitmap[byte] &= ~(1 << bit);
}

/* Find free slot in keyring.  Slot 0 in any slab is the BAM and possible keyring salt, so only
 * search for space in slots 1 and above.  TODO: Extend to handle more than one slab!
 * TODO: random search to avoid predictability of used slots!
 */
static unsigned find_free_slot(const keyring_file *k)
{
  unsigned slot;
  for (slot = 1; slot < KEYRING_BAM_BITS; ++slot)
    if (!test_slot(k, slot))
      return slot;
  return 0;
}

static int keyring_commit_identity(keyring_file *k, keyring_identity *id)
{
  keyring_finalise_identity(k, id);
  // Do nothing if an identity with this sid already exists
  keyring_iterator it;
  keyring_iterator_start(k, &it);
  if (keyring_find_sid(&it, id->box_pk))
    return 0;
  set_slot(k, id->slot, 1);

  keyring_identity **i=&k->identities;
  while(*i)
    i=&(*i)->next;

  *i=id;
  add_subscriber(id);
  return 1;
}

/* Create a new identity in the specified context (which supplies the keyring pin) with the
 * specified PKR pin.  The crypto_box and crypto_sign key pairs are automatically created, and the
 * PKR is packed and written to a hithero unallocated slot which is then marked full.  Requires an
 * explicit call to keyring_commit()
*/
keyring_identity *keyring_create_identity(keyring_file *k, const char *pin)
{
  DEBUGF(keyring, "k=%p", k);
  /* Check obvious abort conditions early */
  if (!k->bam) { WHY("keyring lacks BAM (not to be confused with KAPOW)"); return NULL; }

  if (!pin) pin="";

  keyring_identity *id = emalloc_zero(sizeof(keyring_identity));
  if (!id)
    return NULL;

  /* Remember pin */
  if (!(id->PKRPin = str_edup(pin)))
    goto kci_safeexit;

  /* Find free slot in keyring. */
  id->slot = find_free_slot(k);
  if (id->slot == 0) {
    WHY("no free slots in first slab (no support for more than one slab)");
    goto kci_safeexit;
  }

  /* Allocate key pairs */
  unsigned ktype;
  for (ktype = 1; ktype < NELS(keytypes); ++ktype) {
    if (keytypes[ktype].creator) {
      keypair *kp = keyring_alloc_keypair(ktype, 0);
      if (kp == NULL)
	goto kci_safeexit;
      keytypes[ktype].creator(kp);
      keyring_identity_add_keypair(id, kp);
    }
  }
  assert(id->keypairs);

  /* Mark slot as occupied and internalise new identity. */
  if (keyring_commit_identity(k, id)!=1)
    goto kci_safeexit;

  /* Everything went fine */
  k->dirty = 1;
  return id;

 kci_safeexit:
  if (id)
    keyring_free_identity(id);
  return NULL;
}

int keyring_commit(keyring_file *k)
{
  DEBUGF(keyring, "k=%p", k);
  unsigned errorCount = 0;
  /* Write all BAMs */
  keyring_bam *b;
  for (b = k->bam; b; b = b->next) {
    if (fseeko(k->file, b->file_offset, SEEK_SET) == -1) {
      WHYF_perror("fseeko(%d, %ld, SEEK_SET)", fileno(k->file), (long)b->file_offset);
      errorCount++;
    } else if (fwrite(b->bitmap, KEYRING_BAM_BYTES, 1, k->file) != 1) {
      WHYF_perror("fwrite(%p, %ld, 1, %d)", b->bitmap, (long)KEYRING_BAM_BYTES, fileno(k->file));
      errorCount++;
    } else if (fwrite(k->KeyRingSalt, k->KeyRingSaltLen, 1, k->file)!=1) {
      WHYF_perror("fwrite(%p, %ld, 1, %d)", k->KeyRingSalt, (long)k->KeyRingSaltLen, fileno(k->file));
      errorCount++;
    }
  }
  /* For each identity in each context, write the record to disk.
     This re-salts every identity as it is re-written, and the pin
     for each identity and context is used, so changing a keypair or pin
     is as simple as updating the keyring_identity or related structure,
     and then calling this function. */
  keyring_iterator it;
  keyring_iterator_start(k, &it);
  while(keyring_next_identity(&it)){
    unsigned char pkr[KEYRING_PAGE_SIZE];
    if (keyring_pack_identity(it.identity, pkr))
      errorCount++;
    else {
      /* Now crypt and store block */
      /* Crypt */
      if (keyring_munge_block(pkr, KEYRING_PAGE_SIZE, 
	it.file->KeyRingSalt, it.file->KeyRingSaltLen, 
	it.file->KeyRingPin, it.identity->PKRPin)) {
	WHY("keyring_munge_block() failed");
	errorCount++;
      } else {
	/* Store */
	off_t file_offset = KEYRING_PAGE_SIZE * it.identity->slot;
	if (file_offset == 0) {
	  DEBUGF(keyring, "ID id=%p has slot=0", it.identity);
	} else if (fseeko(k->file, file_offset, SEEK_SET) == -1) {
	  WHYF_perror("fseeko(%d, %ld, SEEK_SET)", fileno(k->file), (long)file_offset);
	  errorCount++;
	} else if (fwrite(pkr, KEYRING_PAGE_SIZE, 1, k->file) != 1) {
	  WHYF_perror("fwrite(%p, %ld, 1, %d)", pkr, (long)KEYRING_PAGE_SIZE, fileno(k->file));
	  errorCount++;
	}
      }
    }
  }
  if (fflush(k->file) == -1) {
    WHYF_perror("fflush(%d)", fileno(k->file));
    errorCount++;
  }
  if (!errorCount)
    k->dirty=0;
  return errorCount ? WHYF("%u errors commiting keyring to disk", errorCount) : 0;
}

int keyring_set_did(keyring_identity *id, const char *did, const char *name)
{
  /* Find where to put it */
  keypair *kp = id->keypairs;
  while(kp){
    if (kp->type==KEYTYPE_DID){
      DEBUG(keyring, "Identity already contains DID");
      break;
    }
    kp=kp->next;
  }
  
  /* allocate if needed */
  if (!kp){
    if ((kp = keyring_alloc_keypair(KEYTYPE_DID, 0)) == NULL)
      return -1;
    keyring_identity_add_keypair(id, kp);
    DEBUG(keyring, "Created DID record for identity");
  }

  /* Store DID unpacked for ease of searching */
  size_t len=strlen(did);
  if (len>31)
    len=31;
  bcopy(did,&kp->private_key[0],len);
  bzero(&kp->private_key[len],32-len);
  len=strlen(name);
  if (len>63)
    len=63;
  bcopy(name,&kp->public_key[0],len);
  bzero(&kp->public_key[len],64-len);

  if (IF_DEBUG(keyring)) {
    dump("{keyring} storing did",&kp->private_key[0],32);
    dump("{keyring} storing name",&kp->public_key[0],64);
  }
  return 0;
}

int keyring_unpack_tag(const unsigned char *packed, size_t packed_len, const char **name, const unsigned char **value, size_t *length)
{
  size_t i;
  for (i=0;i<packed_len;i++){
    if (packed[i]==0){
      *name = (const char*)packed;
      if (value)
	*value = &packed[i+1];
      if (length)
	*length = packed_len - (i+1);
      return 0;
    }
  }
  return WHY("Did not find NULL values in tag");
}

int keyring_pack_tag(unsigned char *packed, size_t *packed_len, const char *name, const unsigned char *value, size_t length)
{
  size_t name_len=strlen(name)+1;
  if (packed && *packed_len <name_len+length)
    return -1;
  *packed_len=name_len+length;
  if (packed){
    bcopy(name, packed, name_len);
    bcopy(value, &packed[name_len], length);
  }
  return 0;
}

int keyring_set_public_tag(keyring_identity *id, const char *name, const unsigned char *value, size_t length)
{
  keypair *kp=id->keypairs;
  while(kp){
    const char *tag_name;
    const unsigned char *tag_value;
    size_t tag_length;
    if (kp->type==KEYTYPE_PUBLIC_TAG &&
      keyring_unpack_tag(kp->public_key, kp->public_key_len, 
	  &tag_name, &tag_value, &tag_length)==0 &&
      strcmp(tag_name, name)==0) {
      DEBUG(keyring, "Found existing public tag");
      break;
    }
    kp = kp->next;
  }
  
  /* allocate if needed */
  if (!kp){
    DEBUGF(keyring, "Creating new public tag");
    if ((kp = keyring_alloc_keypair(KEYTYPE_PUBLIC_TAG, 0)) == NULL)
      return -1;
    keyring_identity_add_keypair(id, kp);
  }
  
  if (kp->public_key)
    free(kp->public_key);
  
  if (keyring_pack_tag(NULL, &kp->public_key_len, name, value, length))
    return -1;
  kp->public_key = emalloc(kp->public_key_len);
  if (!kp->public_key)
    return -1;
  if (keyring_pack_tag(kp->public_key, &kp->public_key_len, name, value, length))
    return -1;
  
  if (IF_DEBUG(keyring))
    dump("{keyring} New tag", kp->public_key, kp->public_key_len);
  return 0;
}

keypair * keyring_find_public_tag(keyring_iterator *it, const char *name, const unsigned char **value, size_t *length)
{
  keypair *keypair;
  while((keypair=keyring_next_keytype(it,KEYTYPE_PUBLIC_TAG))){
    const char *tag_name;
    if (!keyring_unpack_tag(keypair->public_key, keypair->public_key_len, &tag_name, value, length) &&
      strcmp(name, tag_name)==0){
      return keypair;
    }
  }
  if (value)
    *value=NULL;
  return NULL;
}

keypair * keyring_find_public_tag_value(keyring_iterator *it, const char *name, const unsigned char *value, size_t length)
{
  const unsigned char *stored_value;
  size_t stored_length;
  keypair *keypair;
  while((keypair=keyring_find_public_tag(it, name, &stored_value, &stored_length))){
    if (stored_length == length && memcmp(value, stored_value, length)==0)
      return keypair;
  }
  return NULL;
}

// sign the hash of a message, adding the signature to the end of the message buffer.
int keyring_sign_message(struct keyring_identity *identity, unsigned char *content, size_t buffer_len, size_t *content_len)
{
  if (*content_len + SIGNATURE_BYTES > buffer_len)
    return WHYF("Insufficient space in message buffer to add signature. %zu, need %zu",buffer_len, *content_len + SIGNATURE_BYTES);

  unsigned char hash[crypto_hash_sha512_BYTES];
  crypto_hash_sha512(hash, content, *content_len);

  if (crypto_sign_detached(&content[*content_len], NULL, hash, crypto_hash_sha512_BYTES, identity->sign_sk))
    return WHY("Signing failed");

  *content_len += SIGNATURE_BYTES;
  return 0;
}

static int keyring_store_sas(struct internal_mdp_header *header, struct overlay_buffer *payload)
{
  if (header->source->sas_valid){
    DEBUGF(keyring, "Ignoring SID:SAS mapping for %s, already have one", alloca_tohex_sid_t(header->source->sid));
    return 0;
  }
  size_t len = ob_remaining(payload);
  
  DEBUGF(keyring, "Received SID:SAS mapping, %zd bytes", len);
  
  if (ob_remaining(payload) < SAS_SIZE + crypto_sign_BYTES)
    return WHY("Truncated key mapping announcement?");
  
  const uint8_t *sas_public = ob_get_bytes_ptr(payload, SAS_SIZE);
  const uint8_t *compactsignature = ob_get_bytes_ptr(payload, crypto_sign_BYTES);

  if (crypto_sign_verify_detached(compactsignature, header->source->sid.binary, SID_SIZE, sas_public))
    return WHY("SID:SAS mapping verification signature does not verify");
  
  /* now store it */
  bcopy(sas_public, header->source->sas_public, SAS_SIZE);
  header->source->sas_valid=1;
  header->source->sas_last_request=-1;
  
  DEBUGF(keyring, "Stored SID:SAS mapping, SID=%s to SAS=%s",
	 alloca_tohex_sid_t(header->source->sid),
	 alloca_tohex_sas(header->source->sas_public)
	);
  return 0;
}

static int keyring_respond_sas(struct internal_mdp_header *header)
{
  keyring_identity *id = header->destination->identity;

  /* It's a request, so find the SAS for the SID the request was addressed to,
     use that to sign that SID, and then return it in an authcrypted frame. */
  struct internal_mdp_header response;
  bzero(&response, sizeof response);
  mdp_init_response(header, &response);
  
  uint8_t buff[MDP_MTU];
  struct overlay_buffer *response_payload = ob_static(buff, sizeof buff);
  ob_limitsize(response_payload, sizeof buff);
  
  ob_append_byte(response_payload, KEYTYPE_CRYPTOSIGN);
  ob_append_bytes(response_payload, id->sign_pk, crypto_sign_PUBLICKEYBYTES);
  uint8_t *sig = ob_append_space(response_payload, crypto_sign_BYTES);

  if (crypto_sign_detached(sig, NULL, header->destination->sid.binary, SID_SIZE, id->sign_sk))
    return WHY("crypto_sign() failed");
    
  DEBUGF(keyring, "Sending SID:SAS mapping, %zd bytes, %s:%"PRImdp_port_t" -> %s:%"PRImdp_port_t,
	 ob_position(response_payload),
	 alloca_tohex_sid_t(header->destination->sid), header->destination_port,
	 alloca_tohex_sid_t(header->source->sid), header->source_port
        );
  
  ob_flip(response_payload);
  int ret = overlay_send_frame(&response, response_payload);
  ob_free(response_payload);
  return ret;
}

// someone else is claiming to be me on this network
// politely request that they release my identity
int keyring_send_unlock(struct subscriber *subscriber)
{
  if (!subscriber->identity)
    return WHY("Cannot unlock an identity we don't have in our keyring");
  if (subscriber->reachable==REACHABLE_SELF)
    return 0;
    
  struct internal_mdp_header header;
  bzero(&header, sizeof header);
  
  header.source = my_subscriber;
  header.destination = subscriber;
  header.source_port = MDP_PORT_KEYMAPREQUEST;
  header.destination_port = MDP_PORT_KEYMAPREQUEST;
  header.qos = OQ_MESH_MANAGEMENT;
  
  // use a fixed buffer so we know there's enough space for the signature
  uint8_t buff[MDP_MTU];
  struct overlay_buffer *response = ob_static(buff, sizeof buff);
  ob_append_byte(response, UNLOCK_REQUEST);
  
  size_t len = ob_position(response);
  if (keyring_sign_message(subscriber->identity, ob_ptr(response), sizeof(buff), &len))
    return -1;
    
  ob_append_space(response, len - ob_position(response));
  
  DEBUGF(keyring, "Sending Unlock request for sid %s", alloca_tohex_sid_t(subscriber->sid));
  ob_flip(response);
  int ret = overlay_send_frame(&header, response);
  ob_free(response);
  return ret;
}

static int keyring_send_challenge(struct subscriber *source, struct subscriber *dest)
{
  if (source == my_subscriber)
    return WHY("Cannot release my main subscriber");

  struct internal_mdp_header header;
  bzero(&header, sizeof header);
  
  header.source = source;
  header.destination = dest;
  header.source_port = MDP_PORT_KEYMAPREQUEST;
  header.destination_port = MDP_PORT_KEYMAPREQUEST;
  header.qos = OQ_MESH_MANAGEMENT;
  
  time_ms_t now = gettime_ms();

  struct keyring_challenge *challenge = source->identity->challenge;
  if (challenge && challenge->expires < now){
    free(challenge);
    challenge = NULL;
  }
  if (!challenge){
    challenge = emalloc_zero(sizeof(struct keyring_challenge));
    if (challenge){
      // give the remote party 15s to respond (should this could be based on measured link latency?)
      challenge->expires = now + 15000;
      randombytes_buf(challenge->challenge, sizeof(challenge->challenge));
    }
  }
  source->identity->challenge = challenge;
  if (!challenge)
    return -1;

  struct overlay_buffer *payload = ob_new();
  ob_append_byte(payload, UNLOCK_CHALLENGE);
  ob_append_bytes(payload, challenge->challenge, sizeof challenge->challenge);
  
  DEBUGF(keyring, "Sending Unlock challenge for sid %s", alloca_tohex_sid_t(source->sid));
    
  ob_flip(payload);
  int ret = overlay_send_frame(&header, payload);
  ob_free(payload);
  return ret;
}

static int keyring_respond_challenge(struct subscriber *subscriber, struct overlay_buffer *payload)
{
  if (!subscriber->identity)
    return WHY("Cannot unlock an identity we don't have in our keyring");
  if (subscriber->reachable==REACHABLE_SELF)
    return 0;
    
  struct internal_mdp_header header;
  bzero(&header, sizeof header);
  
  header.source = my_subscriber;
  header.destination = subscriber;
  header.source_port = MDP_PORT_KEYMAPREQUEST;
  header.destination_port = MDP_PORT_KEYMAPREQUEST;
  header.qos = OQ_MESH_MANAGEMENT;
  
  uint8_t buff[MDP_MTU];
  struct overlay_buffer *response = ob_static(buff, sizeof buff);
  ob_append_byte(response, UNLOCK_RESPONSE);
  ob_append_bytes(response, ob_current_ptr(payload), ob_remaining(payload));
  
  size_t len = ob_position(response);
  if (keyring_sign_message(subscriber->identity, ob_ptr(response), sizeof(buff), &len))
    return -1;
    
  ob_append_space(response, len - ob_position(response));
  DEBUGF(keyring, "Responding to Unlock challenge for sid %s", alloca_tohex_sid_t(subscriber->sid));
  ob_flip(response);
  int ret = overlay_send_frame(&header, response);
  ob_free(response);
  return ret;
}

static int keyring_process_challenge(keyring_file *k, struct subscriber *subscriber, struct overlay_buffer *payload)
{
  int ret=-1;
  time_ms_t now = gettime_ms();

  struct keyring_challenge *challenge = subscriber->identity->challenge;

  if (challenge){
    subscriber->identity->challenge = NULL;
    size_t len = ob_remaining(payload)+1;
    // verify that the payload was signed by our key and contains the same challenge bytes that we sent
    // TODO allow for signing the challenge bytes without sending them twice?
    if (challenge->expires >= now
      && crypto_verify_message(subscriber, ob_current_ptr(payload) -1, &len) == 0
      && len - 1 == sizeof(challenge->challenge)
      && memcmp(ob_current_ptr(payload), challenge->challenge, sizeof(challenge->challenge)) == 0){

      keyring_release_subscriber(k, &subscriber->sid);
      ret=0;
    }else{
      WHY("Challenge failed");
    }
    free(challenge);
  }
  return ret;
}

DEFINE_BINDING(MDP_PORT_KEYMAPREQUEST, keyring_mapping_request);
static int keyring_mapping_request(struct internal_mdp_header *header, struct overlay_buffer *payload)
{

  /* The authcryption of the MDP frame proves that the SAS key is owned by the
     owner of the SID, and so is absolutely compulsory. */
  if (header->crypt_flags&(MDP_NOCRYPT|MDP_NOSIGN)) 
    return WHY("mapping requests must be performed under authcryption");
    
  switch(ob_get(payload)){
    case KEYTYPE_CRYPTOSIGN:
      if (ob_remaining(payload)==0)
	return keyring_respond_sas(header);
      return keyring_store_sas(header, payload);
      break;
    case UNLOCK_REQUEST:
      {
	size_t len = ob_remaining(payload) +1;
	if (crypto_verify_message(header->destination, ob_current_ptr(payload) -1, &len))
	  return WHY("Signature check failed");
      }
      return keyring_send_challenge(header->destination, header->source);
    case UNLOCK_CHALLENGE:
      return keyring_respond_challenge(header->source, payload);
    case UNLOCK_RESPONSE:
      return keyring_process_challenge(keyring, header->destination, payload);
  }
  return WHY("Not implemented");
}

int keyring_send_sas_request(struct subscriber *subscriber){
  if (subscriber->sas_valid)
    return 0;
  
  time_ms_t now = gettime_ms();
  
  if (now < subscriber->sas_last_request + 100){
    DEBUG(keyring, "Too soon to ask for SAS mapping again");
    return 0;
  }
  
  if (!my_subscriber)
    return WHY("couldn't request SAS (I don't know who I am)");
  
  DEBUGF(keyring, "Requesting SAS mapping for SID=%s", alloca_tohex_sid_t(subscriber->sid));
  
  /* request mapping (send request auth-crypted). */
  struct internal_mdp_header header;
  bzero(&header, sizeof header);
  
  header.source = my_subscriber;
  header.destination = subscriber;
  header.source_port = MDP_PORT_KEYMAPREQUEST;
  header.destination_port = MDP_PORT_KEYMAPREQUEST;
  header.qos = OQ_MESH_MANAGEMENT;
  
  struct overlay_buffer *payload = ob_new();
  ob_append_byte(payload, KEYTYPE_CRYPTOSIGN);
  
  DEBUGF(keyring, "Sending SAS resolution request");
  subscriber->sas_last_request=now;
  ob_flip(payload);
  int ret = overlay_send_frame(&header, payload);
  ob_free(payload);
  return ret;
}

void keyring_identity_extract(const keyring_identity *id, const sid_t **sidp, const char **didp, const char **namep)
{
  keypair *kp=id->keypairs;
  while(kp){
    switch (kp->type) {
    case KEYTYPE_CRYPTOBOX:
      if (sidp)
	*sidp = (const sid_t *)kp->public_key;
      break;
    case KEYTYPE_DID:
      if (didp)
	*didp = (const char *) kp->private_key;
      if (namep)
	*namep = (const char *) kp->public_key;
      break;
    case KEYTYPE_CRYPTOCOMBINED:
      if (sidp){
	struct combined_pk *pk = (struct combined_pk *)kp->public_key;
	*sidp = &pk->box_key;
      }
      break;
    }
    kp=kp->next;
  }
}

keyring_file *keyring_create_instance()
{
  return keyring_open_create_instance("", 1);
}

keyring_file *keyring_open_instance(const char *pin)
{
  return keyring_open_create_instance(pin, 0);
}

static keyring_file *keyring_open_create_instance(const char *pin, int force_create)
{
  keyring_file *k = NULL;
  IN();
  if (create_serval_instance_dir() == -1)
    RETURN(NULL);
  // Work out the absolute path to the keyring file.
  const char *env = getenv("SERVALD_KEYRING_PATH");
  if (!env)
    env = "serval.keyring";
  char keyringFile[1024];
  if (!FORMF_SERVAL_ETC_PATH(keyringFile, "%s", env))
    RETURN(NULL);
  // Work out if the keyring file is writeable.
  const char *readonly_env = getenv("SERVALD_KEYRING_READONLY");
  bool_t readonly_b;
  int writeable = readonly_env == NULL || cf_opt_boolean(&readonly_b, readonly_env) != CFOK || !readonly_b;
  if ((k = keyring_open_or_create(keyringFile, writeable)) == NULL)
    RETURN(NULL);
  if ((force_create || k->file_size < KEYRING_PAGE_SIZE) && keyring_initialise(k) == -1) {
    keyring_free(k);
    return NULL;
  }
  if (keyring_load(k, pin) == -1) {
    keyring_free(k);
    return NULL;
  }
  RETURN(k);
  OUT();
}

keyring_file *keyring_open_instance_cli(const struct cli_parsed *parsed)
{
  IN();
  const char *kpin = NULL;
  cli_arg(parsed, "--keyring-pin", &kpin, NULL, "");
  keyring_file *k = keyring_open_instance(kpin);
  if (k == NULL)
    RETURN(NULL);
  // Always open all PIN-less entries.
  keyring_enter_pin(k, "");
  // Open all entries for which an entry PIN has been given.
  unsigned i;
  for (i = 0; i < parsed->labelc; ++i)
    if (strn_str_cmp(parsed->labelv[i].label, parsed->labelv[i].len, "--entry-pin") == 0)
      keyring_enter_pin(k, parsed->labelv[i].text);
  RETURN(k);
  OUT();
}

/* If no identities, create an initial identity with a phone number.
   This identity will not be pin protected (initially). */
int keyring_seed(keyring_file *k)
{
  /* nothing to do if there is already an identity */
  if (k->identities)
    return 0;
  keyring_identity *id=keyring_create_identity(k,"");
  if (!id)
    return WHY("Could not create new identity");
  if (keyring_commit(k))
    return WHY("Could not commit new identity to keyring file");
  return 0;
}

/*
  The CryptoBox function of NaCl involves a scalar mult operation between the
  public key of the recipient and the private key of the sender (or vice versa).
  This can take about 1 cpu second on a phone, which is rather bad.
  Fortunately, NaCl allows the caching of the result of this computation, which can
  then be fed into the process to make it much, much faster.
  Thus we need a mechanism for caching the various scalarmult results so that they
  can indeed be reused.
*/

/* XXX We need a more efficient implementation than a linear list, but it will
   do for now. */
struct nm_record {
  /* 96 bytes per record */
  sid_t known_key;
  sid_t unknown_key;
  unsigned char nm_bytes[crypto_box_BEFORENMBYTES];
};

unsigned nm_slots_used=0;
/* 512 x 96 bytes = 48KB, not too big */
#define NM_CACHE_SLOTS 512
struct nm_record nm_cache[NM_CACHE_SLOTS];

unsigned char *keyring_get_nm_bytes(const uint8_t *box_sk, const sid_t *box_pk, const sid_t *unknown_sidp)
{
  IN();
  assert(keyring != NULL);

  /* See if we have it cached already */
  unsigned i;
  for(i=0;i<nm_slots_used;i++){
    if (cmp_sid_t(&nm_cache[i].known_key, box_pk) != 0) continue;
    if (cmp_sid_t(&nm_cache[i].unknown_key, unknown_sidp) != 0) continue;
    RETURN(nm_cache[i].nm_bytes);
  }

  /* Not in the cache, so prepare to cache it (or return failure if known is not
     in fact a known key */
  /* work out where to store it */
  if (nm_slots_used<NM_CACHE_SLOTS) {
    i=nm_slots_used; nm_slots_used++; 
  } else {
    i=randombytes_uniform(NM_CACHE_SLOTS);
  }

  /* calculate and store */
  nm_cache[i].known_key = *box_pk;
  nm_cache[i].unknown_key = *unknown_sidp;
  if (crypto_box_beforenm(nm_cache[i].nm_bytes, unknown_sidp->binary, box_sk)){
    WHY("crypto_box_beforenm failed");
    RETURN(NULL);
  }
  RETURN(nm_cache[i].nm_bytes);
  OUT();
}

static int cmp_identity_ptrs(const keyring_identity *const *a, const keyring_identity *const *b)
{
  if (a==b)
    return 0;
  
  keypair *kpa=(*a)->keypairs, *kpb=(*b)->keypairs;
  int c;
  while(kpa && kpb){
    if ((c = cmp_keypair(kpa, kpb)))
      return c;
    kpa=kpa->next;
    kpb=kpb->next;
  }
  
  if (kpa)
    return 1;
  if (kpb)
    return -1;
  return 0;
}

static void keyring_dump_keypair(const keypair *kp, XPRINTF xpf, int include_secret)
{
  assert(kp->type != 0);
  assert(kp->type < NELS(keytypes));
  xprintf(xpf, "type=%u(%s) ", kp->type, keytype_str(kp->type, "unknown"));
  if (keytypes[kp->type].dumper)
    keytypes[kp->type].dumper(kp, xpf, include_secret);
  else
    dump_private_public(kp, xpf, include_secret);
}

int keyring_dump(keyring_file *k, XPRINTF xpf, int include_secret)
{
  unsigned nids = 0;
  
  keyring_iterator it;
  keyring_iterator_start(k, &it);
  while(keyring_next_identity(&it))
    ++nids;
  
  unsigned i = 0;
  const keyring_identity *idx[nids];
  
  keyring_iterator_start(k, &it);
  while(keyring_next_identity(&it)){
    assert(i < nids);
    idx[i++] = it.identity;
  }
  assert(i == nids);
  
  qsort(idx, nids, sizeof(idx[0]), (int(*)(const void *, const void *)) cmp_identity_ptrs);
  for (i = 0; i != nids; ++i) {
    keypair *kp=idx[i]->keypairs;
    while(kp){
      xprintf(xpf, "%u: ", i);
      keyring_dump_keypair(kp, xpf, include_secret);
      xprintf(xpf, "\n");
      kp=kp->next;
    }
  }
  return 0;
}

int keyring_load_from_dump(keyring_file *k, unsigned entry_pinc, const char **entry_pinv, FILE *input)
{
  clearerr(input);
  char line[1024];
  unsigned pini = 0;
  keyring_identity *id = NULL;
  unsigned last_idn = 0;
  while (fgets(line, sizeof line - 1, input) != NULL) {
    // Strip trailing \n or CRLF
    size_t linelen = strlen(line);
    if (linelen && line[linelen - 1] == '\n') {
      line[--linelen] = '\0';
      if (linelen && line[linelen - 1] == '\r')
	line[--linelen] = '\0';
    } else
      return WHY("line too long");
    unsigned idn;
    unsigned ktype;
    int i, j;
    int n = sscanf(line, "%u: type=%u (%n%*[^)]%n)", &idn, &ktype, &i, &j);
    if (n == EOF && (ferror(input) || feof(input)))
	break;
    if (n != 2)
      return WHYF("malformed input n=%u", n);
    if (ktype == 0)
      return WHY("invalid input: ktype=0");
    const char *ktypestr = &line[i];
    line[j] = '\0';
    const char *content = &line[j + 1];
    //DEBUGF(keyring, "n=%d i=%u ktypestr=%s j=%u content=%s", n, i, alloca_str_toprint(ktypestr), j, alloca_str_toprint(content));
    keypair *kp = keyring_alloc_keypair(ktype, 0);
    if (kp == NULL)
      return -1;
    int (*loader)(keypair *, const char *) = load_unknown;
    if (strcmp(ktypestr, "unknown") != 0 && ktype < NELS(keytypes))
      loader = keytypes[ktype].loader;
    if (loader(kp, content) == -1) {
      keyring_free_keypair(kp);
      return -1;
    }
    if (id == NULL || idn != last_idn) {
      last_idn = idn;
      if (id){
	if (keyring_commit_identity(k, id)!=1)
	  keyring_free_identity(id);
	else
	  k->dirty=1;
      }
      if ((id = emalloc_zero(sizeof(keyring_identity))) == NULL) {
	keyring_free_keypair(kp);
	return -1;
      }
      if ((id->PKRPin = str_edup(pini < entry_pinc ? entry_pinv[pini++] : "")) == NULL) {
	keyring_free_keypair(kp);
	keyring_free_identity(id);
	return -1;
      }
      if ((id->slot = find_free_slot(k)) == 0) {
	keyring_free_keypair(kp);
	keyring_free_identity(id);
	return WHY("no free slot");
      }
    }
    if (!keyring_identity_add_keypair(id, kp))
      keyring_free_keypair(kp);
  }
  if (id){
    if (keyring_commit_identity(k, id)!=1)
      keyring_free_identity(id);
    else
      k->dirty=1;
  }
  if (ferror(input))
    return WHYF_perror("fscanf");
  return 0;
}
