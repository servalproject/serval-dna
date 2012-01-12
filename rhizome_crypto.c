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

#include "mphlr.h"
#include "rhizome.h"
#include <stdlib.h>

int rhizome_manifest_createid(rhizome_manifest *m)
{
  m->haveSecret=1;
  int r=crypto_sign_edwards25519sha512batch_keypair(m->cryptoSignPublic,m->cryptoSignSecret);
  if (!r) return rhizome_store_keypair_bytes(m->cryptoSignPublic,m->cryptoSignSecret);
  return WHY("Failed to create keypair for manifest ID.");
}

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

rhizome_signature *rhizome_sign_hash(unsigned char *hash,unsigned char *publicKeyBytes)
{
  unsigned char secretKeyBytes[crypto_sign_edwards25519sha512batch_SECRETKEYBYTES];
  
  if (rhizome_find_keypair_bytes(publicKeyBytes,secretKeyBytes))
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
					    &hash[0],mLen,secretKeyBytes);
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
	  WHY("Signature passed.");
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
