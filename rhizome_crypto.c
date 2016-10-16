/*
Serval DNA - Rhizome cryptographic operations
Copyright (C) 2014 Serval Project Inc.
Copyright (C) 2010 Paul Gardner-Stephen
 
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

#include <stdlib.h>
#include <ctype.h>
#include <assert.h>

#include "serval.h"
#include "conf.h"
#include "str.h"
#include "rhizome.h"
#include "crypto.h"
#include "keyring.h"
#include "dataformats.h"

int rhizome_manifest_createid(rhizome_manifest *m)
{
  if (crypto_sign_keypair(m->keypair.public_key.binary, m->keypair.binary))
    return WHY("Failed to create keypair for manifest ID.");
  rhizome_manifest_set_id(m, &m->keypair.public_key); // will remove any existing BK field
  m->haveSecret = NEW_BUNDLE_ID;
  return 0;
}

/* Generate a bundle id deterministically from the given seed.
 * Then either fetch it from the database or initialise a new empty manifest */
struct rhizome_bundle_result rhizome_private_bundle(rhizome_manifest *m, const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  int n = vsnprintf(NULL, 0, fmt, ap);
  va_end(ap);

  char seed[n+1];
  va_start(ap, fmt);
  vsnprintf(seed, sizeof seed, fmt, ap);
  va_end(ap);

  union {
    unsigned char hash[crypto_hash_sha512_BYTES];
    sign_private_t bsk;
  } u;

  crypto_hash_sha512(u.hash, (uint8_t *)seed, n);

  // The first 256 bits (32 bytes) of the hash will be used as the private key of the BID.

  sign_keypair_t sk;
  rhizome_bid_t bid;
  crypto_sign_seed_keypair(bid.binary, sk.binary, u.bsk.binary);

  enum rhizome_bundle_status ret = rhizome_retrieve_manifest(&bid, m);
  switch(ret){
    case RHIZOME_BUNDLE_STATUS_NEW:
      rhizome_manifest_set_id(m, &bid); // zerofills m->keypair.binary
      m->keypair = sk;
      m->haveSecret = NEW_BUNDLE_ID;
      rhizome_manifest_set_service(m, RHIZOME_SERVICE_FILE);
      rhizome_manifest_set_name(m, "");
      // always consider the content encrypted, we don't need to rely on the manifest itself.
      rhizome_manifest_set_crypt(m, PAYLOAD_ENCRYPTED);
      // setting the author would imply needing a BK, which we don't need since the private key is seeded above.
      return rhizome_fill_manifest(m, NULL);
    case RHIZOME_BUNDLE_STATUS_SAME:
      m->haveSecret = EXISTING_BUNDLE_ID;
      m->keypair = sk;
      // always consider the content encrypted, we don't need to rely on the manifest itself.
      rhizome_manifest_set_crypt(m, PAYLOAD_ENCRYPTED);
      if (strcmp(m->service, RHIZOME_SERVICE_FILE) != 0)
	return rhizome_bundle_result(RHIZOME_BUNDLE_STATUS_ERROR);
      // fallthrough
    default:
      return rhizome_bundle_result(ret);
  }
}



/* Generate a bundle id deterministically from the given bundle secret key.
 * Then initialise a new empty manifest.
 */
void rhizome_new_bundle_from_secret(rhizome_manifest *m, const rhizome_bk_t *bsk)
{
  sign_keypair_t keypair;
  crypto_sign_seed_keypair(keypair.public_key.binary, keypair.binary, bsk->binary);
  rhizome_manifest_set_id(m, &keypair.public_key); // zerofills m->keypair.binary
  m->haveSecret = NEW_BUNDLE_ID;
  m->keypair.private_key = keypair.private_key;
}

/* Given a Rhizome Secret (RS) and bundle ID (BID), XOR a bundle key 'bkin' (private or public) with
 * RS##BID. This derives the first 32-bytes of the secret key.  The BID itself as
 * public key is also the last 32-bytes of the secret key.
 *
 * @author Andrew Bettison <andrew@servalproject.org>
 * @author Paul Gardner-Stephen <paul@servalproject.org>
 */
static int rhizome_bk_xor_stream(
  const rhizome_bid_t *bidp,
  const unsigned char *rs,
  const size_t rs_len,
  const uint8_t *xor_in,
  uint8_t *xor_out,
  size_t xor_stream_byte_count)
{
  IN();
  if (rs_len<1||rs_len>65536) RETURN(WHY("rs_len invalid"));
  if (xor_stream_byte_count<1||xor_stream_byte_count>crypto_hash_sha512_BYTES)
    RETURN(WHY("xor_stream_byte_count invalid"));

  crypto_hash_sha512_state state;
  unsigned char hash[crypto_hash_sha512_BYTES];

  crypto_hash_sha512_init(&state);
  crypto_hash_sha512_update(&state, rs, rs_len);
  crypto_hash_sha512_update(&state, bidp->binary, sizeof bidp->binary);
  crypto_hash_sha512_final(&state, hash);

  unsigned i;
  for (i = 0; i != xor_stream_byte_count; ++i)
    xor_out[i] = xor_in[i] ^ hash[i];

  DEBUGF(rhizome, "   BK XOR %s with %s = %s",
    alloca_tohex(xor_in, xor_stream_byte_count),
    alloca_tohex(hash, xor_stream_byte_count),
    alloca_tohex(xor_out, xor_stream_byte_count));

  bzero(hash, sizeof hash);
  bzero(&state, sizeof state);

  OUT();
  return 0;
}

static keypair *get_secret(const keyring_identity *id)
{
  keypair *kp=keyring_identity_keytype(id, KEYTYPE_RHIZOME);
  if (!kp) {
    WARNF("Identity sid=%s has no Rhizome Secret", alloca_tohex_sid_t(*id->box_pk));
    return NULL;
  }
  assert(kp->private_key_len >= 16);
  assert(kp->private_key_len <= 1024);
  return kp;
}

static enum rhizome_bundle_authorship set_authentic(rhizome_manifest *m, const keyring_identity *id, const sid_t *sid)
{
  m->authorship = AUTHOR_AUTHENTIC;
  m->author = *sid;
  m->author_identity = id;
  if (!m->haveSecret)
    m->haveSecret = EXISTING_BUNDLE_ID;
  return m->authorship;
}

/*
 * If this identity has permission to alter the bundle, then set;
 *  - the manifest 'authorship' field to AUTHOR_AUTHENTIC
 *  - the 'author' field to the SID of the identity
 *  - the manifest 'sign_key.binary' field to the bundle secret key
 *  - the 'haveSecret' field to EXISTING_BUNDLE_ID.
 * and finally update the database with the result.
*/
static enum rhizome_bundle_authorship try_author(rhizome_manifest *m, const keyring_identity *id, const sid_t *sid){
  if (!sid)
    return AUTHOR_UNKNOWN;

  if (!id){
    id = keyring_find_identity_sid(keyring, sid);
    if (!id)
      return AUTHOR_UNKNOWN;
  }

  if (m->has_bundle_key){
    keypair *kp = get_secret(id);
    if (!kp)
      return AUTHENTICATION_ERROR;

    sign_private_t test_key;
    if (rhizome_bk_xor_stream(
	&m->keypair.public_key,
	kp->private_key, kp->private_key_len,
	m->bundle_key.binary,
	test_key.binary,
	sizeof m->bundle_key))
      return AUTHENTICATION_ERROR;

    if (m->haveSecret){
      // test that the secrets match
      if (bcmp(test_key.binary, m->keypair.private_key.binary, sizeof test_key))
	return AUTHOR_IMPOSTOR;
    }

    // check that the generated keypair is valid
    if (!crypto_isvalid_keypair(&test_key, &m->keypair.public_key))
      return AUTHOR_IMPOSTOR;

    m->keypair.private_key = test_key;
  }else{
    if (memcmp(&m->keypair.public_key, &id->sign_keypair->public_key, sizeof(sign_public_t))==0){
      m->keypair = *id->sign_keypair;
    }else{
      DEBUGF(rhizome, "   bundle has no BK field");
      // TODO if sign_key.public_key == id signing key...
      return ANONYMOUS;
    }
  }

  if (m->rowid && m->authorship == ANONYMOUS){
    // if this bundle is already in the database, update the author.
    sqlite_exec_void_loglevel(LOG_LEVEL_WARN,
	"UPDATE MANIFESTS SET author = ? WHERE rowid = ?;",
	SID_T, sid,
	INT64, m->rowid,
	END);
  }
  return set_authentic(m, id, sid);
}

/* Attempt to authenticate the authorship of the given bundle, and set the 'authorship' element
 * accordingly.
 *
 * If an author has already been set, confirm it is valid.
 *
 * If the bundle has a sender, try that identity first.
 *
 * Otherwise test each identity in the keyring to discover the author of the bundle.
 *
 * If the manifest has no BK field, then we can only test if the bundle ID is equal to the identities signing key.
 *
 * If no identity is found in the keyring that combines with the bundle key (BK) field to yield
 * the bundle's secret key, then leaves the manifest 'authorship' field as ANONYMOUS.
 */

void rhizome_authenticate_author(rhizome_manifest *m)
{
  IN();
  DEBUGF(rhizome, "authenticate author for bid=%s", m->has_id ? alloca_tohex_rhizome_bid_t(m->keypair.public_key) : "(none)");
  switch (m->authorship) {
    case ANONYMOUS:

      assert(is_sid_t_any(m->author));

      if (m->has_sender){
	sid_t test_sid;
	if (crypto_sign_to_sid(&m->keypair.public_key, &test_sid)==0){
	  if (cmp_sid_t(&test_sid, &m->sender)==0){
	    // self signed bundle, is it ours?
	    keyring_identity *id = keyring_find_identity(keyring, &m->keypair.public_key);
	    if (id){
	      set_authentic(m, id, &m->sender);
	      RETURNVOID;
	    }else{
	      m->authorship = AUTHOR_REMOTE;
	      m->author = m->sender;
	      RETURNVOID;
	    }
	  }
	}
      }
      
      // Optimisation: try 'sender' SID first, if present.
      if (m->has_sender && try_author(m, NULL, &m->sender) == AUTHOR_AUTHENTIC)
	RETURNVOID;

      keyring_iterator it;
      keyring_iterator_start(keyring, &it);
      keyring_identity *id;
      while((id = keyring_next_identity(&it))){
	// skip the sender if we've already tried it.
	if (m->has_sender && cmp_sid_t(&m->sender, id->box_pk)==0)
	  continue;
	if (try_author(m, id, id->box_pk) == AUTHOR_AUTHENTIC)
	  RETURNVOID;
      }

      RETURNVOID;

    case AUTHOR_NOT_CHECKED:
    case AUTHOR_LOCAL:
      m->authorship = try_author(m, m->author_identity, &m->author);
      RETURNVOID;
    case AUTHOR_REMOTE:
    case AUTHENTICATION_ERROR:
    case AUTHOR_UNKNOWN:
    case AUTHOR_IMPOSTOR:
    case AUTHOR_AUTHENTIC:
      // work has already been done, don't repeat it
      // TODO rescan keyring if more identities are unlocked??
      RETURNVOID;
  }
  FATALF("m->authorship = %d", (int)m->authorship);
}

/* Sets the bundle key "BK" field of a manifest.  Returns 1 if the field was set, 0 if not.
 *
 * This function must not be called unless the bundle secret is known.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int rhizome_manifest_add_bundle_key(rhizome_manifest *m)
{
  IN();
  assert(m->haveSecret);
  switch (m->authorship) {
    case ANONYMOUS: // there can be no BK field without an author
    case AUTHOR_UNKNOWN: // we already know the author is not in the keyring
    case AUTHENTICATION_ERROR: // already tried and failed to get Rhizome Secret
      break;
    case AUTHOR_NOT_CHECKED:
    case AUTHOR_LOCAL:
    case AUTHOR_AUTHENTIC:
    case AUTHOR_IMPOSTOR: {
	/* Set the BK using the provided author.  Serval Security Framework defines BK as being:
	*    BK = privateKey XOR sha512(RS##BID)
	* where BID = sign_key.public_key,
	*       RS is the rhizome secret for the specified author.
	* The nice thing about this specification is that:
	*    privateKey = BK XOR sha512(RS##BID)
	* so the same function can be used to encrypt and decrypt the BK field.
	*/

	if (!m->author_identity){
	  m->author_identity = keyring_find_identity_sid(keyring, &m->author);
	  if (!m->author_identity){
	    m->authorship = AUTHOR_UNKNOWN;
	    break;
	  }
	}

	keypair *kp = get_secret(m->author_identity);
	if (!kp){
	  m->authorship = AUTHENTICATION_ERROR;
	  break;
	}

	rhizome_bk_t bkey;
	if (rhizome_bk_xor_stream(
	    &m->keypair.public_key,
	    kp->private_key, kp->private_key_len,
	    m->keypair.private_key.binary,
	    bkey.binary,
	    sizeof bkey)){
	  m->authorship = AUTHENTICATION_ERROR;
	  break;
	}

	rhizome_manifest_set_bundle_key(m, &bkey);
	m->authorship = AUTHOR_AUTHENTIC;
	RETURN(1);
      }
      break;
    default:
      FATALF("m->authorship = %d", (int)m->authorship);
  }
  rhizome_manifest_del_bundle_key(m);
  switch (m->authorship) {
    case AUTHOR_UNKNOWN:
      INFOF("Cannot set BK because author=%s is not in keyring", alloca_tohex_sid_t(m->author));
      break;
    case AUTHENTICATION_ERROR:
      WHY("Cannot set BK due to error");
      break;
    default:
      break;
  }
  RETURN(0);
}

/* If the given bundle secret key corresponds to the bundle's ID (public key) then store it in the
 * manifest structure and mark the secret key as known.  Return 1 if the secret key was assigned,
 * 0 if not.
 *
 * This function should only be called on a manifest that already has a public key (ID) and does
 * not have a known secret key.
 * 
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int rhizome_apply_bundle_secret(rhizome_manifest *m, const rhizome_bk_t *bsk)
{
  IN();
  DEBUGF(rhizome, "manifest %p bsk=%s", m, bsk ? alloca_tohex_rhizome_bk_t(*bsk) : "NULL");
  assert(m->haveSecret == SECRET_UNKNOWN);
  assert(is_all_matching(m->keypair.private_key.binary, sizeof m->keypair.private_key.binary, 0));
  assert(m->has_id);
  assert(bsk != NULL);
  assert(!rhizome_is_bk_none(bsk));

  // no shortcut here, since bsk does not include a copy of the PK bytes
  uint8_t sk[crypto_sign_SECRETKEYBYTES];
  uint8_t pk[crypto_sign_PUBLICKEYBYTES];
  crypto_sign_seed_keypair(pk, sk, bsk->binary);

  if (bcmp(pk, m->keypair.public_key.binary, crypto_sign_PUBLICKEYBYTES) == 0){
    DEBUG(rhizome, "bundle secret verifies ok");
    bcopy(sk, m->keypair.binary, crypto_sign_SECRETKEYBYTES);
    m->haveSecret = EXISTING_BUNDLE_ID;
    RETURN(1);
  }
  RETURN(0);
  OUT();
}

typedef struct manifest_signature_block_cache {
  unsigned char manifest_hash[crypto_hash_sha512_BYTES];
  unsigned char signature_bytes[256];
  size_t signature_length;
  int signature_valid;
} manifest_signature_block_cache;

#define SIG_CACHE_SIZE 1024
manifest_signature_block_cache sig_cache[SIG_CACHE_SIZE];

static int rhizome_manifest_lookup_signature_validity(const unsigned char *hash, const unsigned char *sig, size_t sig_len)
{
  IN();
  unsigned slot=0;
  unsigned i;

  for(i=0;i<crypto_hash_sha512_BYTES;i++) {
    slot=(slot<<1)+(slot&0x80000000?1:0);
    slot+=hash[i];
  }
  for(i=0;i<sig_len;i++) {
    slot=(slot<<1)+(slot&0x80000000?1:0);
    slot+=sig[i];
  }
  slot%=SIG_CACHE_SIZE;

  if (sig_cache[slot].signature_length!=sig_len || 
      memcmp(hash, sig_cache[slot].manifest_hash, crypto_hash_sha512_BYTES) ||
      memcmp(sig, sig_cache[slot].signature_bytes, sig_len)){
    bcopy(hash, sig_cache[slot].manifest_hash, crypto_hash_sha512_BYTES);
    bcopy(sig, sig_cache[slot].signature_bytes, sig_len);
    sig_cache[slot].signature_length=sig_len;

    sig_cache[slot].signature_valid=
      crypto_sign_verify_detached(sig, hash, crypto_hash_sha512_BYTES, &sig[crypto_sign_BYTES])
      ? -1 : 0;
  }
  RETURN(sig_cache[slot].signature_valid);
  OUT();
}

int rhizome_manifest_extract_signature(rhizome_manifest *m, unsigned *ofs)
{
  IN();
  DEBUGF(rhizome_manifest, "*ofs=%u m->manifest_all_bytes=%zu", *ofs, m->manifest_all_bytes);
  assert((*ofs) < m->manifest_all_bytes);
  const unsigned char *sig = m->manifestdata + *ofs;
  uint8_t sigType = m->manifestdata[*ofs];
  uint8_t len = (sigType << 2) + 4 + 1;
  if (*ofs + len > m->manifest_all_bytes) {
    WARNF("Invalid signature at offset %u: type=%#02x gives len=%u that overruns manifest size",
	*ofs, sigType, len);
    *ofs = m->manifest_all_bytes;
    RETURN(1);
  }
  *ofs += len;
  assert (m->sig_count <= NELS(m->signatories));
  if (m->sig_count == NELS(m->signatories)) {
    WARN("Too many signature blocks in manifest");
    RETURN(2);
  }
  switch (sigType) {
    case 0x17: // crypto_sign_edwards25519sha512batch()
    {
      assert(len == 97);
      /* Reconstitute signature block */
      int r = rhizome_manifest_lookup_signature_validity(m->manifesthash.binary, sig + 1, 96);
      if (r) {
	WARN("Signature verification failed");
	RETURN(4);
      }
      m->signatureTypes[m->sig_count] = len;
      if ((m->signatories[m->sig_count] = emalloc(crypto_sign_PUBLICKEYBYTES)) == NULL)
	RETURN(-1);
      bcopy(sig + 1 + 64, m->signatories[m->sig_count], crypto_sign_PUBLICKEYBYTES);
      m->sig_count++;
      DEBUG(rhizome, "Signature verified");
      RETURN(0);
    }
  }
  WARNF("Unsupported signature at ofs=%u: type=%#02x", (unsigned)(sig - m->manifestdata), sigType);
  RETURN(3);
}

// add value to nonce, with the same result regardless of CPU endian order
// allowing for any carry value up to the size of the whole nonce
static void add_nonce(unsigned char *nonce, uint64_t value)
{
  int i=crypto_box_NONCEBYTES -1;
  while(i>=0 && value>0){
    int x = nonce[i]+(value & 0xFF);
    nonce[i]=x&0xFF;
    value = (value>>8)+(x>>8);
    i--;
  }
}

/* Encrypt a block of a stream in-place, allowing for offsets that don't align perfectly to block
 * boundaries for efficiency the caller should use a buffer size of (n*RHIZOME_CRYPT_PAGE_SIZE).
 */
int rhizome_crypt_xor_block(unsigned char *buffer, size_t buffer_size, uint64_t stream_offset, 
			    const unsigned char *key, const unsigned char *nonce)
{
  uint64_t nonce_offset = stream_offset & ~(RHIZOME_CRYPT_PAGE_SIZE -1);
  size_t offset=0;
  
  unsigned char block_nonce[crypto_box_NONCEBYTES];
  bcopy(nonce, block_nonce, sizeof(block_nonce));
  add_nonce(block_nonce, nonce_offset);
  
  if (nonce_offset < stream_offset){
    size_t padding = stream_offset & (RHIZOME_CRYPT_PAGE_SIZE -1);
    size_t size = RHIZOME_CRYPT_PAGE_SIZE - padding;
    if (size>buffer_size)
      size=buffer_size;
    
    unsigned char temp[RHIZOME_CRYPT_PAGE_SIZE];
    bcopy(buffer, temp + padding, size);
    crypto_stream_xsalsa20_xor(temp, temp, size+padding, block_nonce, key);
    bcopy(temp + padding, buffer, size);
    
    add_nonce(block_nonce, RHIZOME_CRYPT_PAGE_SIZE);
    offset+=size;
  }
  
  while(offset < buffer_size){
    size_t size = buffer_size - offset;
    if (size>RHIZOME_CRYPT_PAGE_SIZE)
      size=RHIZOME_CRYPT_PAGE_SIZE;
    
    crypto_stream_xsalsa20_xor(buffer+offset, buffer+offset, (unsigned long long) size, block_nonce, key);
    
    add_nonce(block_nonce, RHIZOME_CRYPT_PAGE_SIZE);
    offset+=size;
  }
  
  return 0;
}

/* If payload key is known, sets m->payloadKey and m->payloadNonce and returns 1.
 * Otherwise, returns 0;
 */
int rhizome_derive_payload_key(rhizome_manifest *m)
{
  assert(m->payloadEncryption == PAYLOAD_ENCRYPTED);
  unsigned char hash[crypto_hash_sha512_BYTES];

  if(m->has_recipient){
    sid_t scratch;
    const sid_t *other_pk = &m->recipient;
    const sid_t *box_pk = NULL;
    const uint8_t *box_sk = NULL;

    {
      const keyring_identity *id=NULL;
      id = keyring_find_identity_sid(keyring, &m->recipient);
      if (id){
	if (m->has_sender){
	  other_pk = &m->sender;
	}else{
	  // derive other_pk from BID
	  other_pk = &scratch;
	  if (crypto_sign_ed25519_pk_to_curve25519(scratch.binary, m->keypair.public_key.binary))
	    other_pk = NULL;
	}
      } else if (m->has_sender){
	id = keyring_find_identity_sid(keyring, &m->sender);
	// TODO error if sender != author?
      } else if (m->haveSecret){
	id = m->author_identity;
      }
      if (id){
	box_pk = id->box_pk;
	box_sk = id->box_sk;
      }
    }

    if (!box_sk || !other_pk){
      WARNF("Could not find known crypto secret for bundle");
      return 0;
    }

    unsigned char *nm_bytes=NULL;
    nm_bytes = keyring_get_nm_bytes(box_sk, box_pk, other_pk);
    DEBUGF(rhizome, "derived payload key from known=%s*, unknown=%s*",
	   alloca_tohex_sid_t_trunc(*box_pk, 7),
	   alloca_tohex_sid_t_trunc(*other_pk, 7)
    );
    assert(nm_bytes != NULL);
    crypto_hash_sha512(hash, nm_bytes, crypto_box_BEFORENMBYTES);
    
  }else{
    if (!m->haveSecret) {
      WHY("Cannot derive payload key because bundle secret is unknown");
      return 0;
    }
    DEBUGF(rhizome, "derived payload key from bundle secret bsk=%s", alloca_tohex(m->keypair.binary, sizeof m->keypair.binary));
    unsigned char raw_key[9+crypto_sign_SECRETKEYBYTES]="sasquatch";
    bcopy(m->keypair.binary, &raw_key[9], crypto_sign_SECRETKEYBYTES);
    crypto_hash_sha512(hash, raw_key, sizeof(raw_key));
  }
  bcopy(hash, m->payloadKey, RHIZOME_CRYPT_KEY_BYTES);
  DEBUGF(rhizome_manifest, "SET manifest %p payloadKey = %s", m, alloca_tohex(m->payloadKey, sizeof m->payloadKey));

  // journal bundles must always have the same nonce, regardless of version.
  // otherwise, generate nonce from version#bundle id#version;
  unsigned char raw_nonce[8 + 8 + sizeof m->keypair.public_key.binary];
  uint64_t nonce_version = m->is_journal ? 0 : m->version;
  write_uint64(&raw_nonce[0], nonce_version);
  bcopy(m->keypair.public_key.binary, &raw_nonce[8], sizeof m->keypair.public_key.binary);
  write_uint64(&raw_nonce[8 + sizeof m->keypair.public_key.binary], nonce_version);
  DEBUGF(rhizome, "derived payload nonce from bid=%s version=%"PRIu64, alloca_tohex_sid_t(m->keypair.public_key), nonce_version);
  crypto_hash_sha512(hash, raw_nonce, sizeof(raw_nonce));
  bcopy(hash, m->payloadNonce, sizeof(m->payloadNonce));
  DEBUGF(rhizome_manifest, "SET manifest %p payloadNonce = %s", m, alloca_tohex(m->payloadNonce, sizeof m->payloadNonce));

  return 1;
}
