/*
Serval Distributed Numbering Architecture (DNA)
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

#include "serval.h"
#include "str.h"
#include "rhizome.h"
#include <stdlib.h>
#include <ctype.h>

/* Work out the encrypt/decrypt key for the supplied manifest.
   If the manifest is not encrypted, then return NULL.
*/
unsigned char *rhizome_bundle_shared_secret(rhizome_manifest *m)
{
  return NULL;
}

int rhizome_manifest_createid(rhizome_manifest *m)
{
  m->haveSecret=1;
  int r=crypto_sign_edwards25519sha512batch_keypair(m->cryptoSignPublic,m->cryptoSignSecret);
  if (!r) return 0;
  return WHY("Failed to create keypair for manifest ID.");
}

/* Given a Rhizome Secret (RS) and bundle ID (BID), XOR a bundle key 'bkin' (private or public) with
 * RS##BID. This derives the first 32-bytes of the secret key.  The BID itself as
 * public key is also the last 32-bytes of the secret key.
 *
 * @author Andrew Bettison <andrew@servalproject.org>
 * @author Paul Gardner-Stephen <paul@servalproject.org>
 */
int rhizome_bk_xor_stream(
  const unsigned char bid[crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES],
  const unsigned char *rs,
  const size_t rs_len,
  unsigned char *xor_stream,
  int xor_stream_byte_count)
{
  IN();
  if (rs_len<1||rs_len>65536) return WHY("rs_len invalid");
  if (xor_stream_byte_count<1||xor_stream_byte_count>crypto_hash_sha512_BYTES)
    RETURN(WHY("xor_stream_byte_count invalid"));

  int combined_len = rs_len + crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES;
  unsigned char buffer[combined_len];
  bcopy(&rs[0], &buffer[0], rs_len);
  bcopy(&bid[0], &buffer[rs_len], crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES);
  unsigned char hash[crypto_hash_sha512_BYTES];
  crypto_hash_sha512(hash,buffer,combined_len);
  bcopy(hash,xor_stream,xor_stream_byte_count);

  RETURN(0);
}

/*
  CryptoSign Secret Keys in cupercop-20120525 onwards have the public key as the
  second half of the secret key.  The public key is the BID, so this simplifies
  the BK<-->SECRET conversion processes. */
int rhizome_bk2secret(rhizome_manifest *m,
  const unsigned char bid[crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES],
  const unsigned char *rs, const size_t rs_len,
  /* The BK need only be the length of the secret half of the secret key */
  const unsigned char bkin[RHIZOME_BUNDLE_KEY_BYTES],
  unsigned char secret[crypto_sign_edwards25519sha512batch_SECRETKEYBYTES]
)
{
  IN();
  unsigned char xor_stream[RHIZOME_BUNDLE_KEY_BYTES];
  if (rhizome_bk_xor_stream(bid,rs,rs_len,xor_stream,RHIZOME_BUNDLE_KEY_BYTES))
    RETURN(WHY("rhizome_bk_xor_stream() failed"));

  int i;

  /* XOR and store secret part of secret key */
  for(i = 0; i != RHIZOME_BUNDLE_KEY_BYTES; i++)
    secret[i] = bkin[i] ^ xor_stream[i];
  /* Copy BID as public-key part of secret key */
  for(;i!=crypto_sign_edwards25519sha512batch_SECRETKEYBYTES;++i)
    secret[i]=bid[i-RHIZOME_BUNDLE_KEY_BYTES];

  bzero(xor_stream, sizeof xor_stream);
  
  RETURN(rhizome_verify_bundle_privatekey(m,secret,bid));
  
}

int rhizome_secret2bk(
  const unsigned char bid[crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES],
  const unsigned char *rs, const size_t rs_len,
  /* The BK need only be the length of the secret half of the secret key */
  unsigned char bkout[RHIZOME_BUNDLE_KEY_BYTES],
  const unsigned char secret[crypto_sign_edwards25519sha512batch_SECRETKEYBYTES]
)
{
  IN();
  unsigned char xor_stream[RHIZOME_BUNDLE_KEY_BYTES];
  if (rhizome_bk_xor_stream(bid,rs,rs_len,xor_stream,RHIZOME_BUNDLE_KEY_BYTES))
    RETURN(WHY("rhizome_bk_xor_stream() failed"));

  int i;

  /* XOR and store secret part of secret key */
  for(i = 0; i != RHIZOME_BUNDLE_KEY_BYTES; i++)
    bkout[i] = secret[i] ^ xor_stream[i];

  bzero(xor_stream, sizeof xor_stream);
  RETURN(0);
}


/* Given the SID of a bundle's author, search for an identity in the keyring and return its
 * Rhizome secret if found.
 *
 * Returns -1 if an error occurs.
 * Returns 0 if the author's rhizome secret is found; '*rs' is set to point to the secret key in the
 * keyring, and '*rs_len' is set to the key length.
 * Returns 2 if the author's identity is not in the keyring.
 * Returns 3 if the author's identity is in the keyring but has no rhizome secret.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int rhizome_find_secret(const unsigned char *authorSid, int *rs_len, const unsigned char **rs)
{
  int cn=0, in=0, kp=0;
  if (!keyring_find_sid(keyring,&cn,&in,&kp,authorSid)) {
    if (debug & DEBUG_RHIZOME)
      DEBUGF("identity sid=%s is not in keyring", alloca_tohex_sid(authorSid));
    return 2;
  }
  kp = keyring_identity_find_keytype(keyring, cn, in, KEYTYPE_RHIZOME);
  if (kp == -1) {
    if (debug & DEBUG_RHIZOME)
      DEBUGF("identity sid=%s has no Rhizome Secret", alloca_tohex_sid(authorSid));
    return 3;
  }
  int rslen = keyring->contexts[cn]->identities[in]->keypairs[kp]->private_key_len;
  if (rslen < 16 || rslen > 1024)
    return WHYF("identity sid=%s has invalid Rhizome Secret: length=%d", alloca_tohex_sid(authorSid), rslen);
  if (rs_len)
    *rs_len = rslen;
  if (rs)
    *rs = keyring->contexts[cn]->identities[in]->keypairs[kp]->private_key;
  return 0;
}

/* Given the SID of a bundle's author and the bundle ID, XOR a bundle key (private or public) with
 * RS##BID where RS is the rhizome secret of the bundle's author, and BID is the bundle's public key
 * (aka the Bundle ID).
 *
 * This will convert a manifest BK field into the bundle's private key, or vice versa.
 *
 * Returns -1 if an error occurs.
 * Returns 0 if the author's private key is located and the XOR is performed successfully.
 * Returns 2 if the author's identity is not in the keyring (this return code from
 * rhizome_find_secret()).
 * Returns 3 if the author's identity is in the keyring but has no rhizome secret (this return code
 * from rhizome_find_secret()).
 *
 * Looks up the SID in the keyring, and if it is present and has a valid-looking RS, calls
 * rhizome_bk_xor_rs() to perform the XOR.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */

/* See if the manifest has a BK entry, and if so, use it to obtain the private key for the BID.  The
 * manifest's 'author' field must contain the (binary) SID of the purported author of the bundle,
 * which is used to look up the author's rhizome secret in the keyring.
 *
 * Returns 0 if a valid private key was extracted, with the private key in the manifest
 * 'cryptoSignSecret' field and the 'haveSecret' field set to 1.
 *
 * Returns 1 if the manifest does not have a BK field.
 *
 * Returns 2 if the author is not found in the keyring (not unlocked?) -- this return code from
 * rhizome_bk_xor().
 *
 * Returns 3 if the author is found in the keyring but has no rhizome secret -- this return code
 * from rhizome_bk_xor().
 *
 * Returns 4 if the author is found in the keyring and has a rhizome secret but the private bundle
 * key formed using it does not verify.
 *
 * Returns -1 on error.
 *
 * @author Andrew Bettison <andrew@servalproject.com>

 */
int rhizome_extract_privatekey(rhizome_manifest *m)
{
  IN();
  char *bk = rhizome_manifest_get(m, "BK", NULL, 0);
  if (!bk) {
    if (debug & DEBUG_RHIZOME) DEBUG("bundle contains no BK field");
    RETURN(1);
  }
  unsigned char bkBytes[RHIZOME_BUNDLE_KEY_BYTES];
  if (fromhexstr(bkBytes, bk, RHIZOME_BUNDLE_KEY_BYTES) == -1)
    RETURN(WHYF("invalid BK field: %s", bk));

  int rs_len;
  const unsigned char *rs;
  int result = rhizome_find_secret(m->author, &rs_len, &rs);
  if (result != 0)
    return WHY("Error searching for Rhizome secret");

  result = rhizome_bk2secret(m,m->cryptoSignPublic,rs,rs_len,
			     bkBytes,m->cryptoSignSecret);

  if (result == 0) {
    m->haveSecret=1;
    RETURN(0); // bingo
  }
  memset(m->cryptoSignSecret, 0, sizeof m->cryptoSignSecret);
  m->haveSecret=0;
  if (debug & DEBUG_RHIZOME) DEBUGF("result=%d", result);
  RETURN(result);
}

/* Discover if the given manifest was created (signed) by any unlocked identity currently in the
 * keyring.
 *
 * Returns 0 if an identity is found with permission to alter the bundle, after setting the manifest
 * 'author' field to the SID of the identity and the manifest 'cryptoSignSecret' field to the bundle
 * secret key and the 'haveSecret' field to 1.
 *
 * Returns 1 if no identity in the keyring is the author of this bundle.
 *
 * Returns 4 if the manifest has no BK field.
 *
 * Returns -1 if an error occurs, eg, the manifest contains an invalid BK field.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int rhizome_find_bundle_author(rhizome_manifest *m)
{
  IN();
  char *bk = rhizome_manifest_get(m, "BK", NULL, 0);
  if (!bk) {
    if (debug & DEBUG_RHIZOME)
      DEBUGF("missing BK field");
    RETURN(4);
  }
  unsigned char bkBytes[RHIZOME_BUNDLE_KEY_BYTES];
  if (fromhexstr(bkBytes, bk, RHIZOME_BUNDLE_KEY_BYTES) == -1)
    RETURN(WHYF("invalid BK field: %s", bk));
  int cn = 0, in = 0, kp = 0;
  for (; keyring_next_identity(keyring, &cn, &in, &kp); ++kp) {
    const unsigned char *authorSid = keyring->contexts[cn]->identities[in]->keypairs[kp]->public_key;
    //if (debug & DEBUG_RHIZOME) DEBUGF("try author identity sid=%s", alloca_tohex(authorSid, SID_SIZE));
    int rkp = keyring_identity_find_keytype(keyring, cn, in, KEYTYPE_RHIZOME);
    if (rkp != -1) {
      int rs_len = keyring->contexts[cn]->identities[in]->keypairs[rkp]->private_key_len;
      if (rs_len < 16 || rs_len > 1024)
	RETURN(WHYF("invalid Rhizome Secret: length=%d", rs_len));
      const unsigned char *rs = keyring->contexts[cn]->identities[in]->keypairs[rkp]->private_key;

      if (!rhizome_bk2secret(m,m->cryptoSignPublic,rs,rs_len,
			     bkBytes,m->cryptoSignSecret)) {
	memcpy(m->author, authorSid, sizeof m->author);
	m->haveSecret=1;
	if (debug & DEBUG_RHIZOME)
	  DEBUGF("found bundle author sid=%s", alloca_tohex_sid(m->author));
	RETURN(0); // bingo
      }
    }
  }
  if (debug & DEBUG_RHIZOME)
    DEBUG("bundle author not found");
  RETURN(1);
}

/* Verify the validity of the manifest's secret key, ie, is the given manifest's 'cryptoSignSecret'
 * field actually the secret key corresponding to the public key in 'cryptoSignPublic'?
 * Return 0 if valid, 1 if not.  Return -1 if an error occurs.
 *
 * There is no NaCl API to efficiently test this.  We use a modified version of
 * crypto_sign_keypair() to accomplish this task.
 */
int rhizome_verify_bundle_privatekey(rhizome_manifest *m,
				     const unsigned char *sk,
				     const unsigned char *pkin)
{
  IN();

#include "crypto_sign_edwards25519sha512batch.h"
#include "nacl/src/crypto_sign_edwards25519sha512batch_ref/ge.h"

  unsigned char h[64];
  unsigned char pk[32];
  ge_p3 A;
  int i;

  crypto_hash_sha512(h,sk,32);
  h[0] &= 248;
  h[31] &= 63;
  h[31] |= 64;

  ge_scalarmult_base(&A,h);
  ge_p3_tobytes(pk,&A);

  for (i = 0;i < 32;++i) 
    if (pkin[i] != pk[i]) {
      if (m&&sk==m->cryptoSignSecret&&pkin==m->cryptoSignPublic)
	m->haveSecret=0;
      RETURN(-1);
    }
  if (debug & DEBUG_RHIZOME)
    DEBUGF("We have the private key for this bundle.");
  if (m&&sk==m->cryptoSignSecret&&pkin==m->cryptoSignPublic) {
    DEBUGF("Set haveSecret=1 in manifest");
    m->haveSecret=1;
  }
  RETURN(0);
}

int rhizome_sign_hash(rhizome_manifest *m,
		      rhizome_signature *out)
{
  IN();
  if (!m->haveSecret && rhizome_extract_privatekey(m))
    RETURN(WHY("Cannot find secret key to sign manifest data."));

  RETURN(rhizome_sign_hash_with_key(m,m->cryptoSignSecret,m->cryptoSignPublic,out));
}

int rhizome_sign_hash_with_key(rhizome_manifest *m,const unsigned char *sk,
			       const unsigned char *pk,rhizome_signature *out)
{
  IN();
  unsigned char signatureBuffer[crypto_sign_edwards25519sha512batch_BYTES + crypto_hash_sha512_BYTES];
  unsigned char *hash = m->manifesthash;
  unsigned long long sigLen = 0;
  int mLen = crypto_hash_sha512_BYTES;
  int r = crypto_sign_edwards25519sha512batch(signatureBuffer, &sigLen, &hash[0], mLen, sk);
  if (r)
    RETURN(WHY("crypto_sign_edwards25519sha512batch() failed."));
  /* Here we use knowledge of the internal structure of the signature block
     to remove the hash, since that is implicitly transported, thus reducing the
     actual signature size down to 64 bytes.
     We do then need to add the public key of the signatory on. */
  bcopy(signatureBuffer, &out->signature[1], 64);
  bcopy(pk, &out->signature[65], crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES);
  out->signatureLength = 65 + crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES;
  out->signature[0] = 0x17; // CryptoSign
  RETURN(0);
}

typedef struct manifest_signature_block_cache {
  unsigned char manifest_hash[crypto_hash_sha512_BYTES];
  unsigned char signature_bytes[256];
  int signature_length;
  int signature_valid;
} manifest_signature_block_cache;

#define SIG_CACHE_SIZE 1024
manifest_signature_block_cache sig_cache[SIG_CACHE_SIZE];

int rhizome_manifest_lookup_signature_validity(unsigned char *hash,unsigned char *sig,int sig_len)
{
  IN();
  unsigned int slot=0;
  int i;

  for(i=0;i<crypto_hash_sha512_BYTES;i++) {
    slot=(slot<<1)+(slot&0x80000000?1:0);
    slot+=hash[i];
  }
  for(i=0;i<sig_len;i++) {
    slot=(slot<<1)+(slot&0x80000000?1:0);
    slot+=sig[i];
  }
  slot%=SIG_CACHE_SIZE;

  int replace=0;
  if (sig_cache[slot].signature_length!=sig_len) replace=1;
  for(i=0;i<crypto_hash_sha512_BYTES;i++)
    if (hash[i]!=sig_cache[i].manifest_hash[i]) { replace=1; break; }
  for(i=0;i<sig_len;i++)
    if (sig[i]!=sig_cache[i].signature_bytes[i]) { replace=1; break; }

  if (replace) {
    for(i=0;i<crypto_hash_sha512_BYTES;i++)
      sig_cache[i].manifest_hash[i]=hash[i];
    for(i=0;i<sig_len;i++)
      sig_cache[i].signature_bytes[i]=sig[i];
    sig_cache[i].signature_length=sig_len;

    unsigned char sigBuf[256];
    unsigned char verifyBuf[256];
    unsigned char publicKey[256];

    /* Reconstitute signature by putting manifest hash between the two
       32-byte halves */
    bcopy(&sig[0],&sigBuf[0],64);
    bcopy(hash,&sigBuf[64],crypto_hash_sha512_BYTES);

    /* Get public key of signatory */
    bcopy(&sig[64],&publicKey[0],crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES);

    unsigned long long mlen=0;
    sig_cache[i].signature_valid=
      crypto_sign_edwards25519sha512batch_open(verifyBuf,&mlen,&sigBuf[0],128,
					       publicKey)
      ? -1 : 0;
  }
  RETURN(sig_cache[i].signature_valid);
}

int rhizome_manifest_extract_signature(rhizome_manifest *m,int *ofs)
{
  IN();
  if (!m)
    RETURN(WHY("NULL pointer passed in as manifest"));
  if (debug&DEBUG_RHIZOME)
    DEBUGF("m->manifest_all_bytes=%d m->manifest_bytes=%d *ofs=%d", m->manifest_all_bytes, m->manifest_bytes, *ofs);

  if ((*ofs)>=m->manifest_all_bytes) { RETURN(0); }

  int sigType=m->manifestdata[*ofs];
  int len=(sigType&0x3f)*4+4+1;

  /* Each signature type is required to have a different length to detect it.
     At present only crypto_sign_edwards25519sha512batch() signatures are
     supported. */
  int r;
  if (m->sig_count<MAX_MANIFEST_VARS)
    switch(sigType) 
      {
      case 0x17: /* crypto_sign_edwards25519sha512batch() */
	/* Reconstitute signature block */
	r=rhizome_manifest_lookup_signature_validity
	  (m->manifesthash,&m->manifestdata[(*ofs)+1],96);
#ifdef DEPRECATED
	unsigned char sigBuf[256];
	unsigned char verifyBuf[256];
	unsigned char publicKey[256];
	bcopy(&m->manifestdata[(*ofs)+1],&sigBuf[0],64);
	bcopy(&m->manifesthash[0],&sigBuf[64],crypto_hash_sha512_BYTES);
	/* Get public key of signatory */
	bcopy(&m->manifestdata[(*ofs)+1+64],&publicKey[0],crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES);
	unsigned long long mlen=0;
	int r=crypto_sign_edwards25519sha512batch_open(verifyBuf,&mlen,&sigBuf[0],128, publicKey);
#endif
	if (r) {
	  (*ofs)+=len;
	  m->errors++;
	  RETURN(WHY("Error in signature block (verification failed)."));
	} else {
	  /* Signature block passes, so add to list of signatures */
	  m->signatureTypes[m->sig_count]=len;
	  m->signatories[m->sig_count]
	    =malloc(crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES);
	  if(!m->signatories[m->sig_count]) {
	    (*ofs)+=len;
	    RETURN(WHY("malloc() failed when reading signature block"));
	  }
	  bcopy(&m->manifestdata[(*ofs)+1+64],m->signatories[m->sig_count],
		crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES);
	  m->sig_count++;
	  if (debug&DEBUG_RHIZOME) DEBUG("Signature passed.");
	}
	break;
      default:
	(*ofs)+=len;
	m->errors++;
	RETURN(WHYF("Encountered illegal or malformed signature block (unknown type=0x%02x @ offset 0x%x)",sigType,(*ofs)-len));
      }
  else
    {
      (*ofs)+=len;
      WHY("Too many signature blocks in manifest.");
      m->errors++;
    }

  (*ofs)+=len;
  RETURN(0);
}
