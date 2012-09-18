/*
Copyright (C) 2010-2012 Paul Gardner-Stephen, Serval Project.
 
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
#include "nacl.h"
#include "overlay_address.h"

/*
  Open keyring file, read BAM and create initial context using the 
  stored salt. */
keyring_file *keyring_open(char *file)
{
  /* Allocate structure */
  keyring_file *k=calloc(sizeof(keyring_file),1);
  if (!k) {
    WHY_perror("calloc");
    return NULL;
  }
  /* Open keyring file read-write if we can, else use it read-only */
  k->file=fopen(file,"r+");
  if (!k->file) k->file=fopen(file,"r");
  if (!k->file) k->file=fopen(file,"w+");
  if (!k->file) {
    WHY_perror("fopen");
    WHYF("Could not open keyring file %s", file);
    keyring_free(k);
    return NULL;
  }
  if (fseeko(k->file,0,SEEK_END)) {
    WHY_perror("fseeko");
    WHYF("Could not seek to end of keyring file %s", file);
    keyring_free(k);
    return NULL;
  }
  k->file_size=ftello(k->file);
  if (k->file_size<KEYRING_PAGE_SIZE) {
    /* Uninitialised, so write 2KB of zeroes, 
       followed by 2KB of random bytes as salt. */
    if (fseeko(k->file,0,SEEK_SET)) {
      WHY_perror("fseeko");
      WHYF("Could not seek to start of keyring file %s", file);
      keyring_free(k);
      return NULL;
    }
    unsigned char buffer[KEYRING_PAGE_SIZE];
    bzero(&buffer[0],KEYRING_BAM_BYTES);
    if (fwrite(&buffer[0],2048,1,k->file)!=1) {
      WHY_perror("fwrite");
      WHYF("Could not write empty bitmap in fresh keyring file %s", file);
      keyring_free(k);
      return NULL;
    }
    if (urandombytes(&buffer[0],KEYRING_PAGE_SIZE-KEYRING_BAM_BYTES)) {
      WHYF("Could not get random keyring salt to put in fresh keyring file %s", file);
      keyring_free(k);
      return NULL;
    }
    if (fwrite(&buffer[0],KEYRING_PAGE_SIZE-KEYRING_BAM_BYTES,1,k->file) != 1) {
      WHY_perror("fwrite");
      WHYF("Could not write keyring salt in fresh keyring file %s", file);
      keyring_free(k);
      return NULL;
    }
    k->file_size=KEYRING_PAGE_SIZE;
  }

  /* Read BAMs for each slab in the file */
  keyring_bam **b=&k->bam;
  off_t offset=0;
  while(offset<k->file_size) {
    /* Read bitmap from slab.
       Also, if offset is zero, read the salt */
    if (fseeko(k->file,offset,SEEK_SET)) {
      WHY_perror("fseeko");
      WHYF("Could not seek to BAM in keyring file %s", file);
      keyring_free(k);
      return NULL;
    }
    *b=calloc(sizeof(keyring_bam),1);
    if (!(*b)) {
      WHY_perror("calloc");
      WHYF("Could not allocate keyring_bam structure for key ring file %s", file);
      keyring_free(k);
      return NULL;
    }
    (*b)->file_offset=offset;
    /* Read bitmap */
    int r=fread(&(*b)->bitmap[0],KEYRING_BAM_BYTES,1,k->file);
    if (r!=1) {
      WHY_perror("fread");
      WHYF("Could not read BAM from keyring file %s", file);
      keyring_free(k);
      return NULL;
    }

    /* Read salt if this is the first bitmap block.
       We setup a context for this self-supplied key-ring salt.
       (other keyring salts may be provided later on, resulting in
       multiple contexts being loaded) */
    if (!offset) {     
      k->contexts[0]=calloc(sizeof(keyring_context),1);     
      if (!k->contexts[0]) {
	WHY_perror("calloc");
	WHYF("Could not allocate keyring_context for keyring file %s", file);
	keyring_free(k);
	return NULL;
      }
      k->contexts[0]->KeyRingPin=strdup(""); /* Implied empty PIN if none provided */
      k->contexts[0]->KeyRingSaltLen=KEYRING_PAGE_SIZE-KEYRING_BAM_BYTES;
      k->contexts[0]->KeyRingSalt=malloc(k->contexts[0]->KeyRingSaltLen);
      if (!k->contexts[0]->KeyRingSalt) {
	WHY_perror("malloc");
	WHYF("Could not allocate keyring_context->salt for keyring file %s", file);
	keyring_free(k);
	return NULL;
      }
      r=fread(&k->contexts[0]->KeyRingSalt[0],k->contexts[0]->KeyRingSaltLen,1,k->file);
      if (r!=1) {
	WHY_perror("fread");
	WHYF("Could not read salt from keyring file %s", file);
	keyring_free(k);
	return NULL;
      }
      k->context_count=1;
    }

    /* Skip to next slab, and find next bam pointer. */
    offset+=KEYRING_PAGE_SIZE*(KEYRING_BAM_BYTES<<3);
    b=&(*b)->next;
  }

  return k;
}

void keyring_free(keyring_file *k)
{
  int i;
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

  /* Free contexts (including subordinate identities and dynamically allocated salt strings).
     Don't forget to overwrite any private data. */
  for(i=0;i<KEYRING_MAX_CONTEXTS;i++)
    if (k->contexts[i]) {
      keyring_free_context(k->contexts[i]);
      k->contexts[i]=NULL;
    }

  /* Wipe everything, just to be sure. */
  bzero(k,sizeof(keyring_file));

  return;
}

void keyring_free_context(keyring_context *c)
{
  int i;
  if (!c) return;

  if (c->KeyRingPin) {
    /* Wipe pin before freeing (slightly tricky since this is a variable length string */
    for(i=0;c->KeyRingPin[i];i++) c->KeyRingPin[i]=' '; i=0;
    free(c->KeyRingPin); c->KeyRingPin=NULL;
  }
  if (c->KeyRingSalt) {
    bzero(c->KeyRingSalt,c->KeyRingSaltLen);
    c->KeyRingSalt=NULL;
    c->KeyRingSaltLen=0;
  }
  
  /* Wipe out any loaded identities */
  for(i=0;i<KEYRING_MAX_IDENTITIES;i++)
    if (c->identities[i]) keyring_free_identity(c->identities[i]);  

  /* Make sure any private data is wiped out */
  bzero(c,sizeof(keyring_context));

  return;
}

void keyring_free_identity(keyring_identity *id)
{
  int i;
  if (id->PKRPin) {
    /* Wipe pin before freeing (slightly tricky since this is a variable length string */
    for(i=0;id->PKRPin[i];i++) {
      if (debug & DEBUG_KEYRING)
	DEBUGF("clearing PIN char '%c'", id->PKRPin[i]);
      id->PKRPin[i]=' ';
    }
    i=0;
    
    free(id->PKRPin); id->PKRPin=NULL;
  }

  for(i=0;i<PKR_MAX_KEYPAIRS;i++)
    if (id->keypairs[i])
      keyring_free_keypair(id->keypairs[i]);

  bzero(id,sizeof(keyring_identity));
  return;
}

void keyring_free_keypair(keypair *kp)
{
  if (kp->private_key) {
    bzero(kp->private_key,kp->private_key_len);
    free(kp->private_key);
    kp->private_key=NULL;
  }
  if (kp->public_key) {
    bzero(kp->public_key,kp->public_key_len);
    free(kp->public_key);
    kp->public_key=NULL;
  }
  
  bzero(kp,sizeof(keypair));
  return;
}

/* Create a new keyring context for the loaded keyring file.
   We don't need to load any identities etc, as that happens when we enter
   an identity pin. 
   If the pin is NULL, it is assumed to be blank.
   The pin does NOT have to be numeric, and has no practical length limitation,
   as it is used as an input into a hashing function.  But for sanity sake, let's
   limit it to 16KB.
*/
int keyring_enter_keyringpin(keyring_file *k,char *pin)
{
  if (!k) return WHY("k is null");
  if (k->context_count>=KEYRING_MAX_CONTEXTS) 
    return WHY("Too many loaded contexts already");
  if (k->context_count<1)
    return WHY("Cannot enter PIN without keyring salt being available");

  k->contexts[k->context_count]=calloc(sizeof(keyring_context),1);
  if (!k->contexts[k->context_count]) return WHY("Could not allocate new keyring context structure");
  keyring_context *c=k->contexts[k->context_count];
  /* Store pin */
  c->KeyRingPin=pin?strdup(pin):strdup("");
  /* Get salt from the zeroeth context */
  c->KeyRingSalt=malloc(k->contexts[0]->KeyRingSaltLen);
  if (!c->KeyRingSalt) {
    free(c); k->contexts[k->context_count]=NULL;
    return WHY("Could not copy keyring salt from context zero");
  }
  c->KeyRingSaltLen=k->contexts[0]->KeyRingSaltLen;
  bcopy(&k->contexts[0]->KeyRingSalt[0],&c->KeyRingSalt[0],c->KeyRingSaltLen);
  k->context_count++;
  return 0;
}

/* Enter an identity pin and search for matching records.
   This involves going through the bitmap for each slab, and
   then trying each keyring pin and identity pin with each
   record marked as allocated.
   We might find more than one matching identity, and that's okay;
   we just load them all. 
*/
int keyring_enter_identitypin(keyring_file *k,char *pin)
{
  if (!k) return WHY("k is null");

  return WHY("Not implemented");
}

/*
  En/Decrypting a block requires use of the first 32 bytes of the block to provide
  salt.  The next 64 bytes constitute a message authentication code (MAC) that is
  used to verify the validity of the block.  The verification occurs in a higher
  level function, and all we need to know here is that we shouldn't decrypt the
  first 96 bytes of the block.
*/
int keyring_munge_block(unsigned char *block,int len /* includes the first 96 bytes */,
			unsigned char *KeyRingSalt,int KeyRingSaltLen,
			const char *KeyRingPin, const char *PKRPin)
{
  int exit_code=1;
  unsigned char hashKey[crypto_hash_sha512_BYTES];
  unsigned char hashNonce[crypto_hash_sha512_BYTES];

  unsigned char work[65536];
  int ofs;

  if (len<96) return WHY("block too short");

  unsigned char *PKRSalt=&block[0];
  int PKRSaltLen=32;

#if crypto_stream_xsalsa20_KEYBYTES>crypto_hash_sha512_BYTES
#error crypto primitive key size too long -- hash needs to be expanded
#endif
#if crypto_stream_xsalsa20_NONCEBYTES>crypto_hash_sha512_BYTES
#error crypto primitive nonce size too long -- hash needs to be expanded
#endif

  /* Generate key and nonce hashes from the various inputs */
#define APPEND(b,l) if (ofs+(l)>=65536) { WHY("Input too long"); goto kmb_safeexit; } bcopy((b),&work[ofs],(l)); ofs+=(l)

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
  crypto_stream_xsalsa20_xor(&block[96],&block[96],len-96,
			     hashNonce,hashKey);
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

#define slot_byte(X) slot[((PKR_SALT_BYTES+PKR_MAC_BYTES+2)+((X)+rotation)%(KEYRING_PAGE_SIZE-(PKR_SALT_BYTES+PKR_MAC_BYTES+2)))]
int keyring_pack_identity(keyring_context *c,keyring_identity *i,
			  unsigned char packed[KEYRING_PAGE_SIZE])
{
  int ofs=0;
  int exit_code=-1;

  /* Convert an identity to a KEYRING_PAGE_SIZE bytes long block that
     consists of 32 bytes of random salt, a 64 byte (512 bit) message
     authentication code (MAC) and the list of key pairs. */
  if (urandombytes(&packed[0],PKR_SALT_BYTES)) return WHY("Could not generate salt");
  ofs+=PKR_SALT_BYTES;
  /* Calculate MAC */
  keyring_identity_mac(c,i,&packed[0] /* pkr salt */,
		       &packed[0+PKR_SALT_BYTES] /* write mac in after salt */);
  ofs+=PKR_MAC_BYTES;

  /* Leave 2 bytes for rotation (put zeroes for now) */
  int rotate_ofs=ofs;
  packed[ofs]=0; packed[ofs+1]=0;
  ofs+=2;

  /* Write keypairs */
  int kp;
  for(kp=0;kp<i->keypair_count;kp++)
    {
      if (ofs>=KEYRING_PAGE_SIZE) {
	WHY("too many or too long key pairs");
	ofs=0; goto kpi_safeexit;
      }
      packed[ofs++]=i->keypairs[kp]->type;
      switch(i->keypairs[kp]->type) {
      case KEYTYPE_RHIZOME:
      case KEYTYPE_DID:
	/* 32 chars for unpacked DID/rhizome secret, 
	   64 chars for name (for DIDs only) */
	if ((ofs
	     +i->keypairs[kp]->private_key_len
	     +i->keypairs[kp]->public_key_len
	     )>=KEYRING_PAGE_SIZE)
	  {
	    WHY("too many or too long key pairs");
	    ofs=0;
	    goto kpi_safeexit;
	  }
	bcopy(i->keypairs[kp]->private_key,&packed[ofs],
	      i->keypairs[kp]->private_key_len);
	ofs+=i->keypairs[kp]->private_key_len;
	if (i->keypairs[kp]->type==KEYTYPE_DID) {
	  bcopy(i->keypairs[kp]->public_key,&packed[ofs],
		i->keypairs[kp]->private_key_len);
	  ofs+=i->keypairs[kp]->public_key_len; 
	}
	break;
      case KEYTYPE_CRYPTOBOX:
	/* For cryptobox we only need the private key, as we compute the public
	   key from it when extracting the identity */
	if ((ofs+i->keypairs[kp]->private_key_len)>=KEYRING_PAGE_SIZE)
	  {
	    WHY("too many or too long key pairs");
	    ofs=0;
	    goto kpi_safeexit;
	  }
	bcopy(i->keypairs[kp]->private_key,&packed[ofs],
	      i->keypairs[kp]->private_key_len);
	ofs+=i->keypairs[kp]->private_key_len;
	break;
      case KEYTYPE_CRYPTOSIGN:
	/* For cryptosign keys there is no public API in NaCl to compute the
	   public key from the private key (although we could subvert the API
	   abstraction and do it anyway). But in the interests of niceness we
	   just store the public and private key pair together */
	if ((ofs
	     +i->keypairs[kp]->private_key_len
	     +i->keypairs[kp]->public_key_len)>=KEYRING_PAGE_SIZE)
	  {
	    WHY("too many or too long key pairs");
	    ofs=0;
	    goto kpi_safeexit;
	  }
	/* Write private then public */
	bcopy(i->keypairs[kp]->private_key,&packed[ofs],
	      i->keypairs[kp]->private_key_len);
	ofs+=i->keypairs[kp]->private_key_len;
	bcopy(i->keypairs[kp]->public_key,&packed[ofs],
	      i->keypairs[kp]->public_key_len);
	ofs+=i->keypairs[kp]->public_key_len;
	break;
	
      default:
	WHY("unknown key type");
	goto kpi_safeexit;
      }
    }

  if (ofs>=KEYRING_PAGE_SIZE) {
    WHY("too many or too long key pairs");
    ofs=0; goto kpi_safeexit;
  }
  packed[ofs++]=0x00; /* Terminate block */

  /* We are now all done, give or take the zeroeing of the trailing bytes. */
  exit_code=0;


 kpi_safeexit:
  /* Clear out remainder of block so that we don't leak info.
     We could have zeroed the thing to begin with, but that means extra
     memory writes that are otherwise avoidable.
     Actually, we don't want zeroes (known plain-text attack against most
     of the block's contents in the typical case), we want random data. */
  if (urandombytes(&packed[ofs],KEYRING_PAGE_SIZE-ofs))
    return WHY("urandombytes() failed to back-fill packed identity block");

  /* Rotate block by a random amount (get the randomness safely) */
  unsigned int rotation;
  if (urandombytes((unsigned char *)&rotation,sizeof(rotation)))
    return WHY("urandombytes() failed to generate random rotation");
  rotation&=0xffff;
#ifdef NO_ROTATION
  rotation=0;
#endif
  unsigned char slot[KEYRING_PAGE_SIZE];
  /* XXX There has to be a more efficient way to do this! */
  int n;
  for(n=0;n<(KEYRING_PAGE_SIZE-(PKR_SALT_BYTES+PKR_MAC_BYTES+2));n++)
    slot_byte(n)=packed[PKR_SALT_BYTES+PKR_MAC_BYTES+2+n];
  bcopy(&slot[PKR_SALT_BYTES+PKR_MAC_BYTES+2],&packed[PKR_SALT_BYTES+PKR_MAC_BYTES+2],
	KEYRING_PAGE_SIZE-(PKR_SALT_BYTES+PKR_MAC_BYTES+2));
  packed[rotate_ofs]=rotation>>8;
  packed[rotate_ofs+1]=rotation&0xff;

  return exit_code;
}

keyring_identity *keyring_unpack_identity(unsigned char *slot, const char *pin)
{
  /* Skip salt and MAC */
  int i;
  int ofs;
  keyring_identity *id=calloc(sizeof(keyring_identity),1);
  if (!id) { WHY("calloc() of identity failed"); return NULL; }
  if (!slot) { WHY("slot is null"); return NULL; }

  id->PKRPin=strdup(pin);

  /* There was a known plain-text opportunity here:
     byte 96 must be 0x01, and some other bytes are likely deducible, e.g., the
     location of the trailing 0x00 byte can probably be guessed with confidence.
     Payload rotation would help here.  So let's do that.  First two bytes is
     rotation in bytes of remainder of block.
  */

  int rotation=(slot[PKR_SALT_BYTES+PKR_MAC_BYTES]<<8)
    |slot[PKR_SALT_BYTES+PKR_MAC_BYTES+1];
  ofs=PKR_SALT_BYTES+PKR_MAC_BYTES+2;

  /* Parse block */
  for(ofs=0;ofs<(KEYRING_PAGE_SIZE-PKR_SALT_BYTES-PKR_MAC_BYTES-2);)
    {
      switch(slot_byte(ofs)) {
      case 0x00:
	/* End of data, stop looking */
	ofs=KEYRING_PAGE_SIZE;
	break;
      case KEYTYPE_RHIZOME:
      case KEYTYPE_DID:
      case KEYTYPE_CRYPTOBOX:
      case KEYTYPE_CRYPTOSIGN:
	if (id->keypair_count>=PKR_MAX_KEYPAIRS) {
	  WHY("Too many key pairs in identity");
	  keyring_free_identity(id);
	  return NULL;
	}
	keypair *kp=id->keypairs[id->keypair_count]=calloc(sizeof(keypair),1);
	if (!id->keypairs[id->keypair_count]) {
	  WHY("calloc() of key pair structure failed.");
	  keyring_free_identity(id);
	  return NULL;
	}
	kp->type=slot_byte(ofs);
	switch(kp->type) {
	case KEYTYPE_CRYPTOBOX:
	  kp->private_key_len=crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES;
	  kp->public_key_len=crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES;
	  break;
	case KEYTYPE_CRYPTOSIGN:
	  kp->private_key_len=crypto_sign_edwards25519sha512batch_SECRETKEYBYTES;
	  kp->public_key_len=crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES;
	  break;
	case KEYTYPE_RHIZOME: 
	  kp->private_key_len=32; kp->public_key_len=0;
	  break;
	case KEYTYPE_DID:
	  kp->private_key_len=32; kp->public_key_len=64;
	  break;
	}
	kp->private_key=malloc(kp->private_key_len);
	if (!kp->private_key) {
	  WHY("malloc() of private key storage failed.");
	  keyring_free_identity(id);
	  return NULL;
	}
	for(i=0;i<kp->private_key_len;i++) kp->private_key[i]=slot_byte(ofs+1+i);
	kp->public_key=malloc(kp->public_key_len);
	if (!kp->public_key) {
	  WHY("malloc() of public key storage failed.");
	  keyring_free_identity(id);
	  return NULL;
	}
	/* Hop over the private key and token that we have read */
	ofs+=1+kp->private_key_len;
	switch(kp->type) {
	case KEYTYPE_CRYPTOBOX:
	  /* Compute public key from private key.
	     
	     Public key calculation as below is taken from section 3 of:
	     http://cr.yp.to/highspeed/naclcrypto-20090310.pdf
	     
	     XXX - This can take a while on a mobile phone since it involves a
	     scalarmult operation, so searching through all slots for a pin could 
	     take a while (perhaps 1 second per pin:slot cominbation).  
	     This is both good and bad.  The other option is to store
	     the public key as well, which would make entering a pin faster, but
	     would also make trying an incorrect pin faster, thus simplifying some
	     brute-force attacks.  We need to make a decision between speed/convenience
	     and security here.
	  */
	  crypto_scalarmult_curve25519_base(kp->public_key,kp->private_key);
	  break;
	case KEYTYPE_DID:
	case KEYTYPE_CRYPTOSIGN:
	  /* While it is possible to compute the public key from the private key,
	     NaCl currently does not provide a function to do this, so we have to
	     store it, or else subvert the NaCl API, which I would rather not do.
	     So we just copy it out.  We use the same code for extracting the
	     public key for a DID (i.e, subscriber name)
	  */
	  for(i=0;i<kp->public_key_len;i++) kp->public_key[i]=slot_byte(ofs+i);
	  ofs+=kp->public_key_len;
	  break;
	case KEYTYPE_RHIZOME: 
	  /* no public key value for these, just do nothing */
	  break;
	}
	id->keypair_count++;
	break;
      default:
	/* Invalid data, so invalid record.  Free and return failure.
	   We don't complain about this, however, as it is the natural
	   effect of trying a pin on an incorrect keyring slot. */
	keyring_free_identity(id);	
	return NULL;
      }
      
    }
  return id;
}

int keyring_identity_mac(keyring_context *c,keyring_identity *id,
			 unsigned char *pkrsalt,unsigned char *mac)
{
  int ofs;
  unsigned char work[65536];
#define APPEND(b,l) if (ofs+(l)>=65536) { bzero(work,ofs); return WHY("Input too long"); } bcopy((b),&work[ofs],(l)); ofs+=(l)

  ofs=0;
  APPEND(&pkrsalt[0],32);
  APPEND(id->keypairs[0]->private_key,id->keypairs[0]->private_key_len);
  APPEND(id->keypairs[0]->public_key,id->keypairs[0]->public_key_len);
  APPEND(id->PKRPin,strlen(id->PKRPin));
  crypto_hash_sha512(mac,work,ofs);
  return 0;
}


/* Read the slot, and try to decrypt it.
   Decryption is symmetric with encryption, so the same function is used
   for munging the slot before making use of it, whichever way we are going.
   Once munged, we then need to verify that the slot is valid, and if so
   unpack the details of the identity.
*/
int keyring_decrypt_pkr(keyring_file *k,keyring_context *c,
			const char *pin,int slot_number)
{
  int exit_code=1;
  unsigned char slot[KEYRING_PAGE_SIZE];
  unsigned char hash[crypto_hash_sha512_BYTES];
  unsigned char work[65536];
  keyring_identity *id=NULL; 

  /* 1. Read slot. */
  if (fseeko(k->file,slot_number*KEYRING_PAGE_SIZE,SEEK_SET))
    return WHY_perror("fseeko");
  if (fread(&slot[0],KEYRING_PAGE_SIZE,1,k->file)!=1)
    return WHY_perror("fread");
  /* 2. Decrypt data from slot. */
  if (keyring_munge_block(slot,KEYRING_PAGE_SIZE,
			  k->contexts[0]->KeyRingSalt,
			  k->contexts[0]->KeyRingSaltLen,
			  c->KeyRingPin,pin)) {
    WHY("keyring_munge_block() failed");
    goto kdp_safeexit;
  }  

  /* 3. Unpack contents of slot into a new identity in the provided context. */  
  id=keyring_unpack_identity(slot,pin);
  if (!id) {
    // Don't complain, because this happens routinely when trying pins against slots.
    // WHY("keyring_unpack_identity() failed");
    goto kdp_safeexit;
  }
  id->slot=slot_number;

  /* 4. Verify that slot is self-consistent (check MAC) */
  if (keyring_identity_mac(k->contexts[0],id,&slot[0],hash)) {
    WHY("could not calculate MAC for identity");
    goto kdp_safeexit;
  }
  /* compare hash to record */
  if (memcmp(hash,&slot[32],crypto_hash_sha512_BYTES))
    {      
      WHY("Slot is not valid (MAC mismatch)");
      dump("computed",hash,crypto_hash_sha512_BYTES);
      dump("stored",&slot[32],crypto_hash_sha512_BYTES);
      goto kdp_safeexit;
    }
  
  // add any unlocked subscribers to our memory table, flagged as local sid's
  int i=0;
  for (i=0;i<id->keypair_count;i++){
    if (id->keypairs[i]->type == KEYTYPE_CRYPTOBOX){
      struct subscriber *subscriber = find_subscriber(id->keypairs[i]->public_key, SID_SIZE, 1);
      if (subscriber){
	set_reachable(subscriber, REACHABLE_SELF);
	if (!my_subscriber)
	  my_subscriber=subscriber;
      }
    }
  }
  
  /* Well, it's all fine, so add the id into the context and return */
  c->identities[c->identity_count++]=id;
  
  return 0;

 kdp_safeexit:
  /* Clean up any potentially sensitive data before exiting */
  bzero(slot,KEYRING_PAGE_SIZE);
  bzero(hash,crypto_hash_sha512_BYTES);
  bzero(&work[0],65536);
  if (id) keyring_free_identity(id); id=NULL;
  return exit_code;
}

/* Try all valid slots with the PIN and see if we find any identities with that PIN.
   We might find more than one. */
int keyring_enter_pin(keyring_file *k, const char *pin)
{
  IN();
  if (!k) RETURN(-1);
  if (!pin) pin="";

  int slot;
  int identitiesFound=0;

  for(slot=0;slot<k->file_size/KEYRING_PAGE_SIZE;slot++)
    {
      /* slot zero is the BAM and salt, so skip it */
      if (slot&(KEYRING_BAM_BITS-1)) {
	/* Not a BAM slot, so examine */
	off_t file_offset=slot*KEYRING_PAGE_SIZE;

	/* See if this part of the keyring file is organised */
	keyring_bam *b=k->bam;
	while (b&&(file_offset>=b->file_offset+KEYRING_SLAB_SIZE))
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
	  int c;
	  for(c=0;c<k->context_count;c++)
	    {
	      int result=keyring_decrypt_pkr(k,k->contexts[c],pin?pin:"",slot);
	      if (!result)
		identitiesFound++;
		
	    }
	}	
      }
    }
  
  /* Tell the caller how many identities we found */
  RETURN(identitiesFound);
  
}

/* Create a new identity in the specified context (which supplies the keyring pin)
   with the specified PKR pin.  
   The crypto_box and crypto_sign key pairs are automatically created, and the PKR
   is packed and written to a hithero unallocated slot which is then marked full. 
*/
keyring_identity *keyring_create_identity(keyring_file *k,keyring_context *c, const char *pin)
{
  /* Check obvious abort conditions early */
  if (!k) { WHY("keyring is NULL"); return NULL; }
  if (!k->bam) { WHY("keyring lacks BAM (not to be confused with KAPOW)"); return NULL; }
  if (!c) { WHY("keyring context is NULL"); return NULL; }
  if (c->identity_count>=KEYRING_MAX_IDENTITIES) 
    { WHY("keyring context has too many identities"); return NULL; }

  if (!pin) pin="";

  keyring_identity *id=calloc(sizeof(keyring_identity),1);
  if (!id) { WHY_perror("calloc"); return NULL; }
  
  /* Store pin */
  id->PKRPin=strdup(pin);
  if (!id->PKRPin) {
    WHY("Could not store pin");
    goto kci_safeexit;
  }

  /* Find free slot in keyring.
     Slot 0 in any slab is the BAM and possible keyring salt, so only search for
     space in slots 1 and above. */
  /* XXX Only stores to first slab! */
  keyring_bam *b=k->bam; 
  for(id->slot=1;id->slot<KEYRING_BAM_BITS;id->slot++)
    {
      int position=id->slot&(KEYRING_BAM_BITS-1);
      int byte=position>>3;
      int bit=position&7;
      if (!(b->bitmap[byte]&(1<<bit))) 
	/* found a free slot */
	break;
    }
  if (id->slot>=KEYRING_BAM_BITS) {
    WHY("no free slots in first slab (and I don't know how to store in subsequent slabs yet");
    goto kci_safeexit;
  }

  /* Allocate key pairs */

  /* crypto_box key pair */
  id->keypairs[0]=calloc(sizeof(keypair),1);
  if (!id->keypairs[0]) {
    WHY("calloc() failed preparing first key pair storage");
    goto kci_safeexit;
  }
  id->keypair_count=1;
  id->keypairs[0]->type=KEYTYPE_CRYPTOBOX;
  id->keypairs[0]->private_key_len=crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES;
  id->keypairs[0]->private_key=malloc(id->keypairs[0]->private_key_len);
  if (!id->keypairs[0]->private_key) {
    WHY("malloc() failed preparing first private key storage");
    goto kci_safeexit;
  }
  id->keypairs[0]->public_key_len=crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES;
  id->keypairs[0]->public_key=malloc(id->keypairs[0]->public_key_len);
  if (!id->keypairs[0]->public_key) {
    WHY("malloc() failed preparing first public key storage");
    goto kci_safeexit;
  }
  /* Filter out public keys that start with 0x0, as they are reserved for address
     abbreviation. */
  id->keypairs[0]->public_key[0]=0;
  while(id->keypairs[0]->public_key[0]<0x10)
    crypto_box_curve25519xsalsa20poly1305_keypair(id->keypairs[0]->public_key,
						  id->keypairs[0]->private_key);

  // add new identity to in memory table
  struct subscriber *subscriber = find_subscriber(id->keypairs[0]->public_key, SID_SIZE, 1);
  if (subscriber){
    set_reachable(subscriber, REACHABLE_SELF);
    if (!my_subscriber)
      my_subscriber=subscriber;
  }
  
  /* crypto_sign key pair */
  id->keypairs[1]=calloc(sizeof(keypair),1);
  if (!id->keypairs[1]) {
    WHY("calloc() failed preparing second key pair storage");
    goto kci_safeexit;
  }
  id->keypair_count=2;
  id->keypairs[1]->type=KEYTYPE_CRYPTOSIGN;
  id->keypairs[1]->private_key_len=crypto_sign_edwards25519sha512batch_SECRETKEYBYTES;
  id->keypairs[1]->private_key=malloc(id->keypairs[1]->private_key_len);
  if (!id->keypairs[1]->private_key) {
    WHY("malloc() failed preparing second private key storage");
    goto kci_safeexit;
  }
  id->keypairs[1]->public_key_len=crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES;
  id->keypairs[1]->public_key=malloc(id->keypairs[1]->public_key_len);
  if (!id->keypairs[1]->public_key) {
    WHY("malloc() failed preparing second public key storage");
    goto kci_safeexit;
  }

  crypto_sign_edwards25519sha512batch_keypair(id->keypairs[1]->public_key,
					      id->keypairs[1]->private_key);

  /* Rhizome Secret (for protecting Bundle Private Keys) */
  id->keypairs[2]=calloc(sizeof(keypair),1);
  if (!id->keypairs[2]) {
    WHY("calloc() failed preparing second key pair storage");
    goto kci_safeexit;
  }
  id->keypair_count=3;
  id->keypairs[2]->type=KEYTYPE_RHIZOME;
  id->keypairs[2]->private_key_len=32;
  id->keypairs[2]->private_key=malloc(id->keypairs[2]->private_key_len);
  if (!id->keypairs[2]->private_key) {
    WHY("malloc() failed preparing second private key storage");
    goto kci_safeexit;
  }
  id->keypairs[2]->public_key_len=0;
  id->keypairs[2]->public_key=NULL;
  urandombytes(id->keypairs[2]->private_key,id->keypairs[2]->private_key_len);

  /* Mark slot in use */
  int position=id->slot&(KEYRING_BAM_BITS-1);
  int byte=position>>3;
  int bit=position&7;  
  b->bitmap[byte]|=(1<<bit);

  /* Add identity to data structure */
  c->identities[c->identity_count++]=id;

  /* We require explicit calling of keyring_commit(), since that seems
     more sensible */
#ifdef NOTDEFINED
  /* Commit keyring to disk */
  if (keyring_commit(k))
    {
      /* Write to disk failed, so unlink identity and clear allocation and generally
	 clean up the mess. */
      b->bitmap[byte]&=0xff-(1<<bit);
      /* Add identity to data structure */
      c->identities[--c->identity_count]=NULL;
    }
  else
#endif

  /* Everything went fine */
  return id;

 kci_safeexit:
  if (id) keyring_free_identity(id);
  return NULL;
}

int keyring_commit(keyring_file *k)
{
  int errorCount=0;
  if (!k) return WHY("keyring was NULL");
  if (k->context_count<1) return WHY("Keyring has no contexts");

  /* Write all BAMs */
  keyring_bam *b=k->bam;
  while (b) {
    if (fseeko(k->file,b->file_offset,SEEK_SET)==0)
      {
	if (fwrite(b->bitmap,KEYRING_BAM_BYTES,1,k->file)!=1) errorCount++;
	else
	  if (fwrite(k->contexts[0]->KeyRingSalt,k->contexts[0]->KeyRingSaltLen,1,
		   k->file)!=1) errorCount++;
      }
    else errorCount++;
    b=b->next;
  }

  /* For each identity in each context, write the record to disk.
     This re-salts every identity as it is re-written, and the pin 
     for each identity and context is used, so changing a keypair or pin
     is as simple as updating the keyring_identity or related structure, 
     and then calling this function. */
  int cn,in;
  for(cn=0;cn<k->context_count;cn++)
    for(in=0;in<k->contexts[cn]->identity_count;in++)
      {
	unsigned char pkr[KEYRING_PAGE_SIZE];
	if (keyring_pack_identity(k->contexts[cn],
				  k->contexts[cn]->identities[in],
				  pkr))
	  errorCount++;
	else {
	  /* Now crypt and store block */
	  /* Crypt */
	  if (keyring_munge_block(pkr,
				  KEYRING_PAGE_SIZE,
				  k->contexts[cn]->KeyRingSalt, 
				  k->contexts[cn]->KeyRingSaltLen, 
				  k->contexts[cn]->KeyRingPin,
				  k->contexts[cn]->identities[in]->PKRPin))
	    errorCount++;
	  else {
	    /* Store */
	    off_t file_offset
	      =KEYRING_PAGE_SIZE
	      *k->contexts[cn]->identities[in]->slot;
	    if (!file_offset) {
	      if (debug * DEBUG_KEYRING)
		DEBUGF("ID %d:%d has slot=0", cn,in);
	    }
	    else if (fseeko(k->file,file_offset,SEEK_SET))
	      errorCount++;
	    else
	      if (fwrite(pkr,KEYRING_PAGE_SIZE,1,k->file)!=1)
		errorCount++;
	  }
	}
      }

  if (errorCount) WHY("One or more errors occurred while commiting keyring to disk");
  return errorCount;
}

int keyring_set_did(keyring_identity *id,char *did,char *name)
{
  if (!id) return WHY("id is null");
  if (!did) return WHY("did is null");
  if (!name) name="Mr. Smith";

  /* Find where to put it */
  int i;
  for(i=0;i<id->keypair_count;i++)
    if (id->keypairs[i]->type==KEYTYPE_DID) {
      if (debug & DEBUG_KEYRING)
	DEBUG("Identity contains DID");
      break;
    }

  if (i>=PKR_MAX_KEYPAIRS) return WHY("Too many key pairs");

  /* allocate if needed */
  if (i>=id->keypair_count) {
    id->keypairs[i]=calloc(sizeof(keypair),1);
    if (!id->keypairs[i]) return WHY_perror("calloc");
    id->keypairs[i]->type=KEYTYPE_DID;
    unsigned char *packedDid=calloc(32,1);
    if (!packedDid) return WHY_perror("calloc");
    unsigned char *packedName=calloc(64,1);
    if (!packedName) return WHY_perror("calloc");
    id->keypairs[i]->private_key=packedDid;
    id->keypairs[i]->private_key_len=32;
    id->keypairs[i]->public_key=packedName;
    id->keypairs[i]->public_key_len=64;
    id->keypair_count++;
    if (debug & DEBUG_KEYRING)
      DEBUG("Created DID record for identity");
  }
  
  /* Store DID unpacked for ease of searching */
  int len=strlen(did); if (len>31) len=31;
  bcopy(did,&id->keypairs[i]->private_key[0],len);
  bzero(&id->keypairs[i]->private_key[len],32-len);
  len=strlen(name); if (len>63) len=63;
  bcopy(name,&id->keypairs[i]->public_key[0],len);
  bzero(&id->keypairs[i]->public_key[len],64-len);
  dump("storing did",&id->keypairs[i]->private_key[0],32);
  dump("storing name",&id->keypairs[i]->public_key[0],64);
  
  return 0;
}

int keyring_find_did(const keyring_file *k,int *cn,int *in,int *kp,char *did)
{
  if (keyring_sanitise_position(k,cn,in,kp)) return 0;

  while (1) {
    /* we know we have a sane position, so see if it is interesting */
    
    if (k->contexts[*cn]->identities[*in]->keypairs[*kp]->type==KEYTYPE_DID)
      {
	/* Compare DIDs */
	if ((!did[0])
	    ||(did[0]=='*'&&did[1]==0)
	    ||(!strcasecmp(did,(char *)k->contexts[*cn]->identities[*in]
			   ->keypairs[*kp]->private_key)))
	  {
	    /* match */
	    return 1;
	  }
      }
    
    (*kp)++;
    if (keyring_sanitise_position(k,cn,in,kp)) return 0;
  }

  return 0;
}

int keyring_identity_find_keytype(const keyring_file *k, int cn, int in, int keytype)
{
  int kp;
  for (kp = 0; kp < keyring->contexts[cn]->identities[in]->keypair_count; ++kp)
    if (keyring->contexts[cn]->identities[in]->keypairs[kp]->type == keytype)
      return kp;
  return -1;
}

int keyring_next_keytype(const keyring_file *k, int *cn, int *in, int *kp, int keytype)
{
  while (!keyring_sanitise_position(k, cn, in, kp)) {
    if (k->contexts[*cn]->identities[*in]->keypairs[*kp]->type == keytype)
      return 1;
    ++*kp;
  }
  return 0;
}

int keyring_next_identity(const keyring_file *k, int *cn, int *in, int *kp)
{
  return keyring_next_keytype(k, cn, in, kp, KEYTYPE_CRYPTOBOX);
}

int keyring_sanitise_position(const keyring_file *k,int *cn,int *in,int *kp)
{
  if (!k) return 1;
  /* Sanity check passed in position */
  if ((*cn)>=keyring->context_count) return 1;
  if ((*in)>=keyring->contexts[*cn]->identity_count)
    {
      (*in)=0; (*cn)++;
      if ((*cn)>=keyring->context_count) return 1;
    }
  if ((*kp)>=keyring->contexts[*cn]->identities[*in]->keypair_count)
    {
      *kp=0; (*in)++;
      if ((*in)>=keyring->contexts[*cn]->identity_count)
	{
	  (*in)=0; (*cn)++;
	  if ((*cn)>=keyring->context_count) return 1;
	}
    }
  return 0;
}

unsigned char *keyring_find_sas_private(keyring_file *k,unsigned char *sid,
					unsigned char **sas_public)
{
  IN();
  int cn=0,in=0,kp=0;

  if (!keyring_find_sid(k,&cn,&in,&kp,sid)) {
    RETURN(WHYNULL("Could not find SID in keyring, so can't find SAS"));
  }

  for(kp=0;kp<k->contexts[cn]->identities[in]->keypair_count;kp++)
    if (k->contexts[cn]->identities[in]->keypairs[kp]->type==KEYTYPE_CRYPTOSIGN)
      {
	if (sas_public) 
	  *sas_public=
	    k->contexts[cn]->identities[in]->keypairs[kp]->public_key;
	if (debug & DEBUG_KEYRING)
	  DEBUGF("Found SAS entry for %s*", alloca_tohex(sid, 7));
	RETURN(k->contexts[cn]->identities[in]->keypairs[kp]->private_key);
      }

  RETURN(WHYNULL("Identity lacks SAS"));
}

struct sid_sas_mapping {
  unsigned char sid[SID_SIZE];
  unsigned char sas_public[SAS_SIZE];
  time_ms_t last_request_time_in_ms;
  unsigned char validP;
};

#define MAX_SID_SAS_MAPPINGS 1024
int sid_sas_mapping_count=0;
struct sid_sas_mapping sid_sas_mappings[MAX_SID_SAS_MAPPINGS];

int keyring_mapping_request(keyring_file *k, overlay_mdp_frame *req)
{
  if (!k) return WHY("keyring is null");
  if (!req) return WHY("req is null");

  /* The authcryption of the MDP frame proves that the SAS key is owned by the
     owner of the SID, and so is absolutely compulsory. */
  if (req->packetTypeAndFlags&(MDP_NOCRYPT|MDP_NOSIGN)) 
    return WHY("mapping requests must be performed under authcryption");

  if (req->out.payload_length==1) {
    /* It's a request, so find the SAS for the SID the request was addressed to,
       use that to sign that SID, and then return it in an authcrypted frame. */
    unsigned char *sas_public=NULL;
    unsigned char *sas_priv =keyring_find_sas_private(keyring,req->out.dst.sid,&sas_public);

    if ((!sas_priv)||(!sas_public)) return WHY("I don't have that SAS key");
    unsigned long long slen;
    /* type of key being verified */
    req->out.payload[0]=KEYTYPE_CRYPTOSIGN;
    /* the public key itself */
    int sigbytes=crypto_sign_edwards25519sha512batch_BYTES;
    bcopy(sas_public,&req->out.payload[1], SAS_SIZE);
    /* and a signature of the SID using the SAS key, to prove possession of
       the key.  Possession of the SID has already been established by the
       decrypting of the surrounding MDP packet.
       XXX - We could chop the SID out of the middle of the signed block here,
       just as we do for signed MDP packets to save 32 bytes.  We won't worry
       about doing this, however, as the mapping process is only once per session,
       not once per packet.  Unless I get excited enough to do it, that is.
    */
    if (crypto_sign_edwards25519sha512batch
	(&req->out.payload[1+SAS_SIZE],&slen,req->out.dst.sid,SID_SIZE,sas_priv))
      return WHY("crypto_sign() failed");
    /* chop the SID out of the signature, since it can be reinserted on reception */
    bcopy(&req->out.payload[1+SAS_SIZE+32+SID_SIZE], &req->out.payload[1+SAS_SIZE+32], sigbytes-32);
    slen-=SID_SIZE;
    /* and record the full length of this */
    req->out.payload_length = 1 + SAS_SIZE + slen;
    overlay_mdp_swap_src_dst(req);
    req->packetTypeAndFlags=MDP_TX; /* crypt and sign */
    if (debug & DEBUG_KEYRING)
      DEBUGF("Sending SID:SAS mapping, %d bytes, %s:0x%X -> %s:0x%X",
	    req->out.payload_length,
	    alloca_tohex_sid(req->out.src.sid), req->out.src.port,
	    alloca_tohex_sid(req->out.dst.sid), req->out.dst.port
	  );
    return overlay_mdp_dispatch(req,0,NULL,0);
  } else {
    /* It's probably a response. */
    if (debug & DEBUG_KEYRING)
      DEBUGF("Received SID:SAS mapping, %d bytes", req->out.payload_length);
    unsigned keytype = req->out.payload[0];

    switch (keytype) {
    case KEYTYPE_CRYPTOSIGN:
      {
	if (req->out.payload_length < 1 + SAS_SIZE)
	  return WHY("Truncated key mapping announcement?");
	unsigned char plain[req->out.payload_length];
	unsigned long long plain_len=0;
	unsigned char *sas_public=&req->out.payload[1];
	unsigned char *compactsignature = &req->out.payload[1+SAS_SIZE];
	/* reconstitute signed SID for verification */
	int siglen=SID_SIZE+crypto_sign_edwards25519sha512batch_BYTES;
	unsigned char signature[siglen];
	bcopy(&compactsignature[0],&signature[0],32);
	bcopy(&req->out.src.sid[0],&signature[32],SID_SIZE);
	bcopy(&compactsignature[32],&signature[32+SID_SIZE],32);

	int r=crypto_sign_edwards25519sha512batch_open(plain,&plain_len,
						       signature,siglen,
						       sas_public);
	if (r)
	  return WHY("SID:SAS mapping verification signature does not verify");
	/* These next two tests should never be able to fail, but let's just check anyway. */
	if (plain_len != SID_SIZE)
	  return WHY("SID:SAS mapping signed block is wrong length");
	if (memcmp(plain, req->out.src.sid, SID_SIZE) != 0)
	  return WHY("SID:SAS mapping signed block is for wrong SID");

	/* work out where to put it */
	int i;
	for (i = 0; i < sid_sas_mapping_count; ++i)
	  if (memcmp(req->out.src.sid, sid_sas_mappings[i].sid, SID_SIZE) == 0)
	    break;
	if (i >= MAX_SID_SAS_MAPPINGS)
	  i = random() % MAX_SID_SAS_MAPPINGS;
	else if (i >= sid_sas_mapping_count)
	  i = sid_sas_mapping_count++;

	/* now put it */
	bcopy(&req->out.src.sid, &sid_sas_mappings[i].sid[0], SID_SIZE);
	bcopy(sas_public, &sid_sas_mappings[i].sas_public[0], SAS_SIZE);
	if (debug & DEBUG_KEYRING)
	  DEBUGF("Stored SID:SAS mapping #%d of %d, SID=%s to SAS=%s",
	      i, sid_sas_mapping_count,
	      alloca_tohex_sid(sid_sas_mappings[i].sid),
	      alloca_tohex_sas(sid_sas_mappings[i].sas_public)
	    );
	sid_sas_mappings[i].validP=1;
	sid_sas_mappings[i].last_request_time_in_ms = -1;
	return 0;
      }
      break;
    default:
      WARNF("Ignoring SID:SAS mapping with unsupported key type %u", keytype);
      break;
    }
  }
  return WHY("Not implemented");
}

unsigned char *keyring_find_sas_public(keyring_file *k,unsigned char *sid)
{
  /* Main issue here is that we need to have the public SAS key for
     this sender.  This needs to be cached somewhere (possibly persistently,
     or not depending on a persons paranoia level, as having a SID:SAS
     mapping implies that at least machine to machine contact has occurred
     with that identity.

     See the Serval Security Framework document for a discussion of some of the
     privacy and security issues that vex a persistent store.

     For now we will just use a non-persistent cache for safety (and it happens
     to be easy to implement as well :)
  */
  IN();
  int i;
  time_ms_t now = gettime_ms();
  for(i=0;i<sid_sas_mapping_count;i++)
    {
      if (memcmp(sid,sid_sas_mappings[i].sid,SID_SIZE)) continue;
      if (sid_sas_mappings[i].validP) {
	if (debug & DEBUG_KEYRING)
	  DEBUGF("Found SAS for SID=%s", alloca_tohex_sid(sid));
	RETURN(sid_sas_mappings[i].sas_public);
      }
      /* Don't flood the network with mapping requests */
      if (sid_sas_mappings[i].last_request_time_in_ms != -1 && now < sid_sas_mappings[i].last_request_time_in_ms + 100) {
	INFO("Too soon to ask for SAS mapping again");
	RETURN(NULL);
      }
      /* we can request again, so fall out to where we do that.
         i is set to this mapping, so the request process will update this
         record. */
      break;
    }
  if (debug & DEBUG_KEYRING)
    DEBUGF("Requesting SAS mapping for SID=%s", alloca_tohex_sid(sid));

  /* allocate mapping slot or replace one at random, depending on how full things
     are */
  if (i==sid_sas_mapping_count) {
    if (i>=MAX_SID_SAS_MAPPINGS) i=random()%MAX_SID_SAS_MAPPINGS;
    else sid_sas_mapping_count++;
  }

  /* pre-populate mapping slot */
  bcopy(&sid[0], &sid_sas_mappings[i].sid[0], SID_SIZE);
  bzero(&sid_sas_mappings[i].sas_public, SAS_SIZE);
  sid_sas_mappings[i].validP=0;
  sid_sas_mappings[i].last_request_time_in_ms = now;

  if (!my_subscriber)
    RETURN(WHYNULL("couldn't request SAS (I don't know who I am)"));    
  
  // always send our sid in full, it's likely this is a new peer
  my_subscriber->send_full = 1;
  
  /* request mapping (send request auth-crypted). */
  overlay_mdp_frame mdp;
  memset(&mdp,0,sizeof(overlay_mdp_frame));
  
  mdp.packetTypeAndFlags=MDP_TX;
  bcopy(sid,mdp.out.dst.sid,SID_SIZE);
  mdp.out.dst.port=MDP_PORT_KEYMAPREQUEST;
  mdp.out.src.port=MDP_PORT_KEYMAPREQUEST;
  bcopy(my_subscriber->sid,mdp.out.src.sid,SID_SIZE);
  mdp.out.payload_length=1;
  mdp.out.payload[0]=KEYTYPE_CRYPTOSIGN;
  
  if (overlay_mdp_dispatch(&mdp, 0 /* system generated */, NULL, 0))
    RETURN(WHYNULL("Failed to send SAS resolution request"));
  if (debug & DEBUG_KEYRING)
    DEBUGF("Dispatched SAS resolution request");
  RETURN(NULL); 
}

int keyring_find_sid(const keyring_file *k, int *cn, int *in, int *kp, const unsigned char *sid)
{
  for (; !keyring_sanitise_position(k, cn, in, kp); ++*kp)
    if (k->contexts[*cn]->identities[*in]->keypairs[*kp]->type == KEYTYPE_CRYPTOBOX
      && memcmp(sid, k->contexts[*cn]->identities[*in]->keypairs[*kp]->public_key, SID_SIZE) == 0)
      return 1;
  return 0;
}

void keyring_identity_extract(const keyring_identity *id, const unsigned char **sidp, const char **didp, const char **namep)
{
  int todo = (sidp ? 1 : 0) | (didp ? 2 : 0) | (namep ? 4 : 0);
  int kpn;
  for (kpn = 0; todo && kpn < id->keypair_count; ++kpn) {
    keypair *kp = id->keypairs[kpn];
    switch (kp->type) {
    case KEYTYPE_CRYPTOBOX:
      if (sidp)
	*sidp = kp->public_key;
      todo &= ~1;
      break;
    case KEYTYPE_DID:
      if (didp)
	*didp = (const char *) kp->private_key;
      if (namep)
	*namep = (const char *) kp->public_key;
      todo &= ~6;
      break;
    }
  }
}

int keyring_enter_pins(keyring_file *k, const char *pinlist)
{
  char pin[1024];
  int i,j=0;

  for(i=0;i<=strlen(pinlist);i++)
    if (pinlist[i]==','||pinlist[i]==0)
      {
	pin[j]=0;
	keyring_enter_pin(k,pin);
	j=0;
      }
    else
      if (j<1023) pin[j++]=pinlist[i];

  return 0;
}

keyring_file *keyring_open_with_pins(const char *pinlist)
{
  keyring_file *k = NULL;
  IN();
  if (create_serval_instance_dir() == -1)
    RETURN(NULL);
  char keyringFile[1024];
  if (!FORM_SERVAL_INSTANCE_PATH(keyringFile, "serval.keyring"))
    RETURN(NULL);
  if ((k = keyring_open(keyringFile)) == NULL)
    RETURN(NULL);
  keyring_enter_pins(k,pinlist);
  RETURN(k);
}

/* If no identities, create an initial identity with a phone number.
   This identity will not be pin protected (initially). */
int keyring_seed(keyring_file *k)
{
  if (!k) return WHY("keyring is null");

  /* nothing to do if there is already an identity */
  if (k->contexts[0]->identity_count)
    return 0;

  int i;
  unsigned char did[65];
  /* Securely generate random telephone number */
  urandombytes((unsigned char *)did,10);
  /* Make DID start with 2 through 9, as 1 is special in many number spaces, 
     and 0 is commonly used for escaping to national or international dialling. */ 
  did[0]='2'+(did[0]%8);
  /* Then add 10 more digits, which is what we do in the mobile phone software */
  for(i=1;i<11;i++) did[i]='0'+(did[i]%10); did[11]=0;
  
  keyring_identity *id=keyring_create_identity(k,k->contexts[0],"");
  if (!id) return WHY("Could not create new identity");
  if (keyring_set_did(id,(char *)did,"")) return WHY("Could not set DID of new identity");
  if (keyring_commit(k)) return WHY("Could not commit new identity to keyring file");
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
  unsigned char known_key[crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES];
  unsigned char unknown_key[crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES];
  unsigned char nm_bytes[crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES];
};

int nm_slots_used=0;
/* 512 x 96 bytes = 48KB, not too big */
#define NM_CACHE_SLOTS 512
struct nm_record nm_cache[NM_CACHE_SLOTS];

unsigned char *keyring_get_nm_bytes(sockaddr_mdp *known,sockaddr_mdp *unknown)
{
  IN();
  if (!known) { RETURN(WHYNULL("known pub key is null")); }
  if (!unknown) { RETURN(WHYNULL("unknown pub key is null")); }
  if (!keyring) { RETURN(WHYNULL("keyring is null")); }

  int i;

  /* See if we have it cached already */
  for(i=0;i<nm_slots_used;i++)
    {
      if (memcmp(nm_cache[i].known_key,known->sid,
	       crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES)) continue;
      if (memcmp(nm_cache[i].unknown_key,unknown->sid,
	       crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES)) continue;
      { RETURN(nm_cache[i].nm_bytes); }
    }

  /* Not in the cache, so prepare to cache it (or return failure if known is not
     in fact a known key */
  int cn=0,in=0,kp=0;
  if (!keyring_find_sid(keyring,&cn,&in,&kp,known->sid))
    { RETURN(WHYNULL("known key is not in fact known.")); }

  /* work out where to store it */
  if (nm_slots_used<NM_CACHE_SLOTS) {
    i=nm_slots_used; nm_slots_used++; 
  } else {
    i=random()%NM_CACHE_SLOTS;
  }

  /* calculate and store */
  bcopy(known->sid,nm_cache[i].known_key,
	crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES);
  bcopy(unknown->sid,nm_cache[i].unknown_key,
	crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES);
  crypto_box_curve25519xsalsa20poly1305_beforenm(nm_cache[i].nm_bytes,
						 unknown->sid,
						 keyring
						 ->contexts[cn]
						 ->identities[in]
						 ->keypairs[kp]->private_key);
						 
  RETURN(nm_cache[i].nm_bytes);
}
