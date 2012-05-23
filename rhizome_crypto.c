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
#include "rhizome.h"
#include <stdlib.h>
#include <ctype.h>

int rhizome_strn_is_manifest_id(const char *id)
{
  int i;
  for (i = 0; i != crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES * 2; ++i)
    if (!isxdigit(id[i]))
      return 0;
  return 1;
}

int rhizome_str_is_manifest_id(const char *id)
{
  size_t len = strlen(id);
  return len == crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES * 2 && rhizome_strn_is_manifest_id(id);
}

int rhizome_manifest_createid(rhizome_manifest *m)
{
  m->haveSecret=1;
  int r=crypto_sign_edwards25519sha512batch_keypair(m->cryptoSignPublic,m->cryptoSignSecret);
  if (!r) return 0;
  return WHY("Failed to create keypair for manifest ID.");
}

#ifdef DEPRECATED
int rhizome_store_keypair_bytes(unsigned char *p,unsigned char *s) {
  /* XXX TODO Secrets should be encrypted using a keyring password. */
  if (sqlite_exec_int64("INSERT INTO KEYPAIRS(public,private) VALUES('%s','%s');",
			rhizome_bytes_to_hex(p,crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES),
			rhizome_bytes_to_hex(s,crypto_sign_edwards25519sha512batch_SECRETKEYBYTES))<0)
    return WHY("Failed to store key pair.");
  return 0;
}

int rhizome_find_keypair_bytes(unsigned char *p,unsigned char *s) {
  sqlite3_stmt *statement;
  char sql[1024];
  const char *cmdtail;

  snprintf(sql,1024,"SELECT private from KEYPAIRS WHERE public='%s';",
	   rhizome_bytes_to_hex(p,crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES));
  if (sqlite3_prepare_v2(rhizome_db,sql,strlen(sql)+1,&statement,&cmdtail) 
      != SQLITE_OK) {
    sqlite3_finalize(statement);    
    return WHY(sqlite3_errmsg(rhizome_db));
  }
  if ( sqlite3_step(statement) == SQLITE_ROW ) {
    if (sqlite3_column_type(statement,0)==SQLITE_TEXT) {
      const unsigned char *hex=sqlite3_column_text(statement,0);
      rhizome_hex_to_bytes((char *)hex,s,
			   crypto_sign_edwards25519sha512batch_SECRETKEYBYTES*2);
      /* XXX TODO Decrypt secret using a keyring password */
      sqlite3_finalize(statement);
      return 0;
    }
  }
  sqlite3_finalize(statement);
  return WHY("Could not find matching secret key.");
}
#endif

int rhizome_bk_xor(const char *author,
		   unsigned char bid[crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES],
		   unsigned char bkin[crypto_sign_edwards25519sha512batch_SECRETKEYBYTES],
		   unsigned char bkout[crypto_sign_edwards25519sha512batch_SECRETKEYBYTES])
{
  if (crypto_sign_edwards25519sha512batch_SECRETKEYBYTES>
      crypto_hash_sha512_BYTES)
    return WHY("BK needs to be longer than it can be");

  unsigned char authorSid[SID_SIZE];
  if (stowSid(authorSid,0,author)) return WHYF("stowSid(%s) failed", author);
  int cn=0,in=0,kp=0;
  if (!keyring_find_sid(keyring,&cn,&in,&kp,authorSid)) 
    return WHYF("keyring_find_sid() couldn't find %s.  Have you unlocked that identity?", author);
  for(kp=0;kp<keyring->contexts[cn]->identities[in]->keypair_count;kp++)
    if (keyring->contexts[cn]->identities[in]->keypairs[kp]->type==KEYTYPE_RHIZOME)
      break;
  if (kp>=keyring->contexts[cn]->identities[in]->keypair_count)
    return WHY("Identity has no Rhizome Secret");
  int rs_len=keyring->contexts[cn]->identities[in]->keypairs[kp]->private_key_len;
  unsigned char *rs=keyring->contexts[cn]->identities[in]->keypairs[kp]->private_key;
  if (rs_len<16||rs_len>1024)
    return WHYF("Rhizome Secret is too short or too long (length=%d)",rs_len);

  int combined_len=rs_len+crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES;
  unsigned char buffer[combined_len];
  bcopy(&rs[0],&buffer[0],rs_len);
  bcopy(&bid[0],&buffer[rs_len],crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES);
  unsigned char hash[crypto_hash_sha512_BYTES];
  crypto_hash_sha512(hash,buffer,combined_len);

  int len=crypto_sign_edwards25519sha512batch_SECRETKEYBYTES;
  int i;
  for(i=0;i<len;i++)
    bkout[i]=bkin[i]^hash[i];
  bzero(&buffer[0],combined_len);
  bzero(&hash[0],crypto_hash_sha512_BYTES);

  return 0;
}

/* See if the manifest has a BK entry, and if so, use it to obtain the 
   private key for the BID.  Decoding BK's relies on the provision of
   the appropriate SID.

   XXX Note that this function is not able to verify that the private key
   is correct, as there is no exposed API in NaCl for calculating the
   public key from a cryptosign private key.  We thus have to trust that
   the supplied SID is correct.

*/
int rhizome_extract_privatekey(rhizome_manifest *m,const char *authorHex)
{
  if (!authorHex) return -1; // WHY("No author SID supplied");
  char *bk = rhizome_manifest_get(m, "BK", NULL, 0);
  if (!bk) return WHY("Cannot obtain private key as manifest lacks BK field");
  
  unsigned char bkBytes[crypto_sign_edwards25519sha512batch_SECRETKEYBYTES];
  if (stowBytes(bkBytes,bk,crypto_sign_edwards25519sha512batch_SECRETKEYBYTES))
    return WHY("Failed to make packed version of BK.  Is it a valid hex string of the correct length?");

  if (rhizome_bk_xor(authorHex,
		     m->cryptoSignPublic,
		     bkBytes,
		     m->cryptoSignSecret))
    return WHY("rhizome_bk_xor() failed");

  /* Verify validity of key.
     XXX This is a pretty ugly way to do it, but NaCl offers no API to
     do this cleanly. */
  {
#ifdef HAVE_CRYPTO_SIGN_NACL_GE25519_H
#  include "crypto_sign_edwards25519sha512batch_ref/ge25519.h"
#else
#  ifdef HAVE_KLUDGE_NACL_GE25519_H
#    include "edwards25519sha512batch/ref/ge25519.h"
#  endif
#endif
#ifdef ge25519
    unsigned char *sk=m->cryptoSignSecret;
    unsigned char pk[crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES];
    sc25519 scsk;
    ge25519 gepk;
    sc25519_from32bytes(&scsk,sk);
    ge25519_scalarmult_base(&gepk, &scsk);
    ge25519_pack(pk, &gepk);
    bzero(&scsk,sizeof(scsk));
    if (memcmp(pk, m->cryptoSignPublic, crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES)) {
      if (0) {
	char hex[17];
	rhizome_bytes_to_hex_upper(m->cryptoSignPublic, hex, 8);
	WHYF("  stored public key = %s*", hex);
	rhizome_bytes_to_hex_upper(pk, hex, 8);
	WHYF("computed public key = %s*", hex);
      }
      return WHY("BID secret key decoded from BK was not valid");     
    } else
      return 0;
#else //!ge25519
    /* XXX Need to test key by signing and testing signature validity. */
    /* For the time being barf so that the caller does not think we have a validated BK
       when in fact we do not. */
    return WHY("ge25519 function not available");
#endif //!ge25519
  }
}

rhizome_signature *rhizome_sign_hash(rhizome_manifest *m,const char *author)
{
  unsigned char *hash=m->manifesthash;
  unsigned char *publicKeyBytes=m->cryptoSignPublic;
  
  if (rhizome_extract_privatekey(m,author))
    {
      WHY("Cannot find secret key to sign manifest data.");
      return NULL;
    }

  /* Signature is formed by running crypto_sign_edwards25519sha512batch() on the 
     hash of the manifest.  The signature actually contains the hash, so to save
     space we cut the hash out of the signature. */
  unsigned char signatureBuffer[crypto_sign_edwards25519sha512batch_BYTES+crypto_hash_sha512_BYTES];
  unsigned long long sigLen=0;
  int mLen=crypto_hash_sha512_BYTES;

  int r=crypto_sign_edwards25519sha512batch(signatureBuffer,&sigLen,
					    &hash[0],mLen,m->cryptoSignSecret);
  if (r) {
    WHY("crypto_sign() failed.");
    return NULL;
  }

  rhizome_signature *out=calloc(sizeof(rhizome_signature),1);

  /* Here we use knowledge of the internal structure of the signature block
     to remove the hash, since that is implicitly transported, thus reducing the
     actual signature size down to 64 bytes.
     We do then need to add the public key of the signatory on. */
  bcopy(&signatureBuffer[0],&out->signature[1],32);
  bcopy(&signatureBuffer[96],&out->signature[33],32);
  bcopy(&publicKeyBytes[0],&out->signature[65],crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES);
  out->signatureLength=65+crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES;

  out->signature[0]=out->signatureLength;

  return out;
}

int rhizome_manifest_extract_signature(rhizome_manifest *m,int *ofs)
{
  unsigned char sigBuf[256];
  unsigned char verifyBuf[256];
  unsigned char publicKey[256];
  if (!m) return WHY("NULL pointer passed in as manifest");

  if ((*ofs)>=m->manifest_bytes) return 0;

  int len=m->manifestdata[*ofs];
  if (!len) { 
    (*ofs)=m->manifest_bytes;
    m->errors++;
    return WHY("Zero byte signature blocks are not allowed, assuming signature section corrupt.");
  }

  /* Each signature type is required to have a different length to detect it.
     At present only crypto_sign_edwards25519sha512batch() signatures are
     supported. */
  if (m->sig_count<MAX_MANIFEST_VARS)
    switch(len) 
      {
      case 0x61: /* crypto_sign_edwards25519sha512batch() */
	/* Reconstitute signature block */
	bcopy(&m->manifestdata[(*ofs)+1],&sigBuf[0],32);
	bcopy(&m->manifesthash[0],&sigBuf[32],crypto_hash_sha512_BYTES);
	bcopy(&m->manifestdata[(*ofs)+1+32],&sigBuf[96],32);
	/* Get public key of signatory */
	bcopy(&m->manifestdata[(*ofs)+1+64],&publicKey[0],crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES);
	
	unsigned long long mlen=0;
	int r=crypto_sign_edwards25519sha512batch_open(verifyBuf,&mlen,&sigBuf[0],128,
						       publicKey);
	fflush(stdout); fflush(stderr);
	if (r) {
	  (*ofs)+=len;
	  m->errors++;
	  return WHY("Error in signature block (verification failed).");
	} else {
	  /* Signature block passes, so add to list of signatures */
	  m->signatureTypes[m->sig_count]=len;
	  m->signatories[m->sig_count]
	    =malloc(crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES);
	  if(!m->signatories[m->sig_count]) {
	    (*ofs)+=len;
	    return WHY("malloc() failed when reading signature block");
	  }
	  bcopy(&publicKey[0],m->signatories[m->sig_count],
		crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES);
	  m->sig_count++;
	  if (debug&DEBUG_RHIZOME) WHY("Signature passed.");
	}
	break;
      default:
	(*ofs)+=len;
	m->errors++;
	return WHY("Encountered illegal or malformed signature block");
      }
  else
    {
      (*ofs)+=len;
      WHY("Too many signature blocks in manifest.");
      m->errors++;
    }

  (*ofs)+=len;
  return 0;
}
