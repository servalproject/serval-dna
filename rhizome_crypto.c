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
  if (crypto_sign_keypair(m->cryptoSignPublic.binary, m->cryptoSignSecret))
    return WHY("Failed to create keypair for manifest ID.");
  rhizome_manifest_set_id(m, &m->cryptoSignPublic); // will remove any existing BK field
  m->haveSecret = NEW_BUNDLE_ID;
  return 0;
}

/* Generate a bundle id deterministically from the given seed.
 * Then either fetch it from the database or initialise a new empty manifest */
int rhizome_get_bundle_from_seed(rhizome_manifest *m, const char *seed)
{
  union {
    unsigned char hash[crypto_hash_sha512_BYTES];
    rhizome_bk_t bsk;
  } u;
  crypto_hash_sha512(u.hash, (unsigned char *)seed, strlen(seed));
  // The first 256 bits (32 bytes) of the hash will be used as the private key of the BID.
  return rhizome_get_bundle_from_secret(m, &u.bsk);
}

/* Generate a bundle id deterministically from the given bundle secret key.
 * Then either fetch it from the database or initialise a new empty manifest
 */
int rhizome_get_bundle_from_secret(rhizome_manifest *m, const rhizome_bk_t *bsk)
{
  uint8_t sk[crypto_sign_SECRETKEYBYTES];
  rhizome_bid_t bid;
  crypto_sign_seed_keypair(bid.binary, sk, bsk->binary);
  switch (rhizome_retrieve_manifest(&bid, m)) {
    case RHIZOME_BUNDLE_STATUS_NEW: 
      rhizome_manifest_set_id(m, &bid); // zerofills m->cryptoSignSecret
      m->haveSecret = NEW_BUNDLE_ID;
      break;
    case RHIZOME_BUNDLE_STATUS_SAME:
      m->haveSecret = EXISTING_BUNDLE_ID;
      break;
    default:
      return -1;
  }
  bcopy(sk, m->cryptoSignSecret, sizeof m->cryptoSignSecret);
  return 0;
}

/* Generate a bundle id deterministically from the given bundle secret key.
 * Then initialise a new empty manifest.
 */
void rhizome_new_bundle_from_secret(rhizome_manifest *m, const rhizome_bk_t *bsk)
{
  uint8_t sk[crypto_sign_SECRETKEYBYTES];
  rhizome_bid_t bid;
  crypto_sign_seed_keypair(bid.binary, sk, bsk->binary);
  rhizome_manifest_set_id(m, &bid); // zerofills m->cryptoSignSecret
  m->haveSecret = NEW_BUNDLE_ID;
  bcopy(sk, m->cryptoSignSecret, sizeof m->cryptoSignSecret);
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
  unsigned char *xor_stream,
  size_t xor_stream_byte_count)
{
  IN();
  if (rs_len<1||rs_len>65536) RETURN(WHY("rs_len invalid"));
  if (xor_stream_byte_count<1||xor_stream_byte_count>crypto_hash_sha512_BYTES)
    RETURN(WHY("xor_stream_byte_count invalid"));

  int combined_len = rs_len + crypto_sign_PUBLICKEYBYTES;
  unsigned char buffer[combined_len];
  bcopy(&rs[0], &buffer[0], rs_len);
  bcopy(&bidp->binary[0], &buffer[rs_len], crypto_sign_PUBLICKEYBYTES);
  unsigned char hash[crypto_hash_sha512_BYTES];
  crypto_hash_sha512(hash,buffer,combined_len);
  bcopy(hash,xor_stream,xor_stream_byte_count);

  OUT();
  return 0;
}

/* CryptoSign Secret Keys in cupercop-20120525 onwards have the public key as the second half of the
 * secret key.  The public key is the BID, so this simplifies the BK<-->SECRET conversion processes.
 *
 * Returns 0 if the BK decodes correctly to the bundle secret, 1 if not.  Returns -1 if there is an
 * error.
 */
int rhizome_bk2secret(
  const rhizome_bid_t *bidp,
  const unsigned char *rs, const size_t rs_len,
  /* The BK need only be the length of the secret half of the secret key */
  const unsigned char bkin[RHIZOME_BUNDLE_KEY_BYTES],
  unsigned char secret[crypto_sign_SECRETKEYBYTES]
)
{
  IN();
  unsigned char xor_stream[RHIZOME_BUNDLE_KEY_BYTES];
  if (rhizome_bk_xor_stream(bidp, rs, rs_len, xor_stream, RHIZOME_BUNDLE_KEY_BYTES))
    RETURN(WHY("rhizome_bk_xor_stream() failed"));
  /* XOR and store secret part of secret key */
  unsigned i;
  for (i = 0; i != RHIZOME_BUNDLE_KEY_BYTES; ++i)
    secret[i] = bkin[i] ^ xor_stream[i];
  bzero(xor_stream, sizeof xor_stream);
  /* Copy BID as public-key part of secret key */
  bcopy(bidp->binary, secret + RHIZOME_BUNDLE_KEY_BYTES, sizeof bidp->binary);
  RETURN(rhizome_verify_bundle_privatekey(secret, bidp->binary) ? 0 : 1);
  OUT();
}

int rhizome_secret2bk(
  const rhizome_bid_t *bidp,
  const unsigned char *rs, const size_t rs_len,
  /* The BK need only be the length of the secret half of the secret key */
  unsigned char bkout[RHIZOME_BUNDLE_KEY_BYTES],
  const unsigned char secret[crypto_sign_SECRETKEYBYTES]
)
{
  IN();
  unsigned char xor_stream[RHIZOME_BUNDLE_KEY_BYTES];
  if (rhizome_bk_xor_stream(bidp,rs,rs_len,xor_stream,RHIZOME_BUNDLE_KEY_BYTES))
    RETURN(WHY("rhizome_bk_xor_stream() failed"));

  int i;

  /* XOR and store secret part of secret key */
  for(i = 0; i != RHIZOME_BUNDLE_KEY_BYTES; i++)
    bkout[i] = secret[i] ^ xor_stream[i];

  bzero(xor_stream, sizeof xor_stream);
  RETURN(0);
  OUT();
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

/*
 * If this identity has permission to alter the bundle, then set;
 *  - the manifest 'authorship' field to AUTHOR_AUTHENTIC
 *  - the 'author' field to the SID of the identity
 *  - the manifest 'cryptoSignSecret' field to the bundle secret key
 *  - the 'haveSecret' field to EXISTING_BUNDLE_ID.
 * and finally update the database with the result.
*/
static enum rhizome_bundle_authorship try_author(rhizome_manifest *m, const keyring_identity *id, const sid_t *sid){
  if (!sid)
    return AUTHOR_UNKNOWN;

  if (!id){
    id = keyring_find_identity(keyring, sid);
    if (!id)
      return AUTHOR_UNKNOWN;
  }

  if (m->has_bundle_key){
    keypair *kp = get_secret(id);
    if (!kp)
      return AUTHENTICATION_ERROR;
    uint8_t secret[crypto_sign_SECRETKEYBYTES];
    uint8_t *s = m->haveSecret ? secret : m->cryptoSignSecret;
    switch (rhizome_bk2secret(&m->cryptoSignPublic, kp->private_key, kp->private_key_len, m->bundle_key.binary, s)) {
      case 0:
	if (m->haveSecret && memcmp(secret, m->cryptoSignSecret, sizeof m->cryptoSignSecret) != 0)
	  FATALF("Bundle secret does not match derived secret");
	break;
      case -1:
	return AUTHENTICATION_ERROR;
      default:
	return AUTHOR_IMPOSTOR;
    }
  }else{
    if (memcmp(&m->cryptoSignPublic, id->sign_pk, crypto_sign_PUBLICKEYBYTES)==0){
      bcopy(id->sign_sk, m->cryptoSignSecret, sizeof m->cryptoSignSecret);
    }else{
      DEBUGF(rhizome, "   bundle has no BK field");
      // TODO if cryptoSignPublic == id signing key...
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

  m->authorship = AUTHOR_AUTHENTIC;
  m->author = *sid;
  m->author_identity = id;
  if (!m->haveSecret)
    m->haveSecret = EXISTING_BUNDLE_ID;
  return m->authorship;
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
  DEBUGF(rhizome, "authenticate author for bid=%s", m->has_id ? alloca_tohex_rhizome_bid_t(m->cryptoSignPublic) : "(none)");
  switch (m->authorship) {
    case ANONYMOUS:

      assert(is_sid_t_any(m->author));

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
    case AUTHENTICATION_ERROR:
    case AUTHOR_UNKNOWN:
    case AUTHOR_IMPOSTOR:
    case AUTHOR_AUTHENTIC:
      // work has already been done, don't repeat it
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
	* where BID = cryptoSignPublic,
	*       RS is the rhizome secret for the specified author.
	* The nice thing about this specification is that:
	*    privateKey = BK XOR sha512(RS##BID)
	* so the same function can be used to encrypt and decrypt the BK field.
	*/

	if (!m->author_identity){
	  m->author_identity = keyring_find_identity(keyring, &m->author);
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
	if (rhizome_secret2bk(&m->cryptoSignPublic, kp->private_key, kp->private_key_len, bkey.binary, m->cryptoSignSecret) != 0) {
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
  assert(is_all_matching(m->cryptoSignSecret, sizeof m->cryptoSignSecret, 0));
  assert(m->has_id);
  assert(bsk != NULL);
  assert(!rhizome_is_bk_none(bsk));

  // no shortcut here, since bsk does not include a copy of the PK bytes
  uint8_t sk[crypto_sign_SECRETKEYBYTES];
  uint8_t pk[crypto_sign_PUBLICKEYBYTES];
  crypto_sign_seed_keypair(pk, sk, bsk->binary);

  if (bcmp(pk, m->cryptoSignPublic.binary, crypto_sign_PUBLICKEYBYTES) == 0){
    DEBUG(rhizome, "bundle secret verifies ok");
    bcopy(sk, m->cryptoSignSecret, crypto_sign_SECRETKEYBYTES);
    m->haveSecret = EXISTING_BUNDLE_ID;
    RETURN(1);
  }
  RETURN(0);
  OUT();
}

/* Verify the validity of a given secret manifest key.  Return 1 if valid, 0 if not.
 */
int rhizome_verify_bundle_privatekey(const unsigned char *sk, const unsigned char *pkin)
{
  // first check that the public key half matches
  if (bcmp(pkin, &sk[crypto_sign_SECRETKEYBYTES - crypto_sign_PUBLICKEYBYTES], crypto_sign_PUBLICKEYBYTES)!=0)
    return 0;
  // generate a new key from the private key bytes
  uint8_t tsk[crypto_sign_SECRETKEYBYTES];
  uint8_t tpk[crypto_sign_PUBLICKEYBYTES];
  crypto_sign_seed_keypair(tpk, tsk, sk);
  // and verify the generated public key again
  return bcmp(pkin, tpk, sizeof tpk) == 0;
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
    const sid_t *box_pk;
    const uint8_t *box_sk = NULL;

    {
      const keyring_identity *id=NULL;
      id = keyring_find_identity(keyring, &m->recipient);
      if (id){
	if (m->has_sender){
	  other_pk = &m->sender;
	}else{
	  // derive other_pk from BID
	  other_pk = &scratch;
	  if (crypto_sign_ed25519_pk_to_curve25519(scratch.binary, m->cryptoSignPublic.binary))
	    other_pk = NULL;
	}
      } else if (m->has_sender){
	id = keyring_find_identity(keyring, &m->sender);
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
    DEBUGF(rhizome, "derived payload key from bundle secret bsk=%s", alloca_tohex(m->cryptoSignSecret, sizeof m->cryptoSignSecret));
    unsigned char raw_key[9+crypto_sign_SECRETKEYBYTES]="sasquatch";
    bcopy(m->cryptoSignSecret, &raw_key[9], crypto_sign_SECRETKEYBYTES);
    crypto_hash_sha512(hash, raw_key, sizeof(raw_key));
  }
  bcopy(hash, m->payloadKey, RHIZOME_CRYPT_KEY_BYTES);
  DEBUGF(rhizome_manifest, "SET manifest %p payloadKey = %s", m, alloca_tohex(m->payloadKey, sizeof m->payloadKey));

  // journal bundles must always have the same nonce, regardless of version.
  // otherwise, generate nonce from version#bundle id#version;
  unsigned char raw_nonce[8 + 8 + sizeof m->cryptoSignPublic.binary];
  uint64_t nonce_version = m->is_journal ? 0 : m->version;
  write_uint64(&raw_nonce[0], nonce_version);
  bcopy(m->cryptoSignPublic.binary, &raw_nonce[8], sizeof m->cryptoSignPublic.binary);
  write_uint64(&raw_nonce[8 + sizeof m->cryptoSignPublic.binary], nonce_version);
  DEBUGF(rhizome, "derived payload nonce from bid=%s version=%"PRIu64, alloca_tohex_sid_t(m->cryptoSignPublic), nonce_version);
  crypto_hash_sha512(hash, raw_nonce, sizeof(raw_nonce));
  bcopy(hash, m->payloadNonce, sizeof(m->payloadNonce));
  DEBUGF(rhizome_manifest, "SET manifest %p payloadNonce = %s", m, alloca_tohex(m->payloadNonce, sizeof m->payloadNonce));

  return 1;
}
