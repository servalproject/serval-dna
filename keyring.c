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

static int urandomfd = -1;

int urandombytes(unsigned char *x,unsigned long long xlen)
{
  int i;
  int t=0;

  if (urandomfd == -1) {
    for (i=0;i<4;i++) {
      urandomfd = open("/dev/urandom",O_RDONLY);
      if (urandomfd != -1) break;
      sleep(1);
    }
    if (i==4) return -1;
  }

  while (xlen > 0) {
    if (xlen < 1048576) i = xlen; else i = 1048576;

    i = read(urandomfd,x,i);
    if (i < 1) {
      sleep(1);
      t++;
      if (t>4) return -1;
      continue;
    } else t=0;

    x += i;
    xlen -= i;
  }

  return 0;
}

/*
  Open keyring file, read BAM and create initial context using the 
  stored salt. */
keyring_file *keyring_open(char *file)
{
  /* Allocate structure */
  keyring_file *k=calloc(sizeof(keyring_file),1);
  if (!k) { WHY("calloc() failed"); return NULL; }

  /* Open keyring file read-write if we can, else use it read-only */
  k->file=fopen(file,"r+");
  if (!k->file) k->file=fopen(file,"r");
  if (!k->file) {
    WHY("Could not open keyring file");
    keyring_free(k);
    return NULL;
  }
  if (fseeko(k->file,0,SEEK_END))
    {
      WHY("Could not seek to end of keyring file");
      keyring_free(k);
      return NULL;
    }
  k->file_size=ftello(k->file);

  if (k->file_size<KEYRING_PAGE_SIZE) {
    /* Uninitialised, so write 2KB of zeroes, 
       followed by 2KB of random bytes as salt. */
    if (fseeko(k->file,0,SEEK_SET)) {
      WHY("Could not seek to start of file to write header");
      keyring_free(k);
      return NULL;
    }
    unsigned char buffer[KEYRING_PAGE_SIZE];
    bzero(&buffer[0],KEYRING_BAM_BYTES);
    if (fwrite(&buffer[0],2048,1,k->file)!=1) {
      WHY("Could not write empty bitmap in fresh keyring file");
      keyring_free(k);
      return NULL;
    }
    if (urandombytes(&buffer[0],KEYRING_PAGE_SIZE-KEYRING_BAM_BYTES))
      {
	WHY("Could not get random keyring salt to put in fresh keyring file");
	keyring_free(k);
	return NULL;
      }
    if (fwrite(&buffer[0],KEYRING_PAGE_SIZE-KEYRING_BAM_BYTES,1,k->file)!=1) {
      WHY("Could not write keyring salt in fresh keyring file");
      keyring_free(k);
      return NULL;
    }
  }

  /* Read BAMs for each slab in the file */
  keyring_bam **b=&k->bam;
  off_t offset=0;
  while(offset<k->file_size) {
    /* Read bitmap from slab.
       Also, if offset is zero, read the salt */
    if (fseeko(k->file,offset,SEEK_SET))
      {
	WHY("Could not seek to BAM in keyring file");
	keyring_free(k);
	return NULL;
      }
    *b=calloc(sizeof(keyring_bam),1);
    if (!(*b))
      {
	WHY("Could not allocate keyring_bam structure for key ring file");
	keyring_free(k);
	return NULL;
      }
    (*b)->file_offset=offset;
    /* Read bitmap */
    int r=fread(&(*b)->bitmap[0],KEYRING_BAM_BYTES,1,k->file);
    if (r!=1)
      {
	WHY("Could not read BAM from keyring file");
	keyring_free(k);
	return NULL;
      }

    /* Read salt if this is the first bitmap block.
       We setup a context for this self-supplied key-ring salt.
       (other keyring salts may be provided later on, resulting in
        multiple contexts being loaded) */
    if (!offset) {     
      k->contexts[0]=calloc(sizeof(keyring_context),1);     
      if (!k->contexts[0])
	{
	  WHY("Could not allocate keyring_context for keyring file");
	  keyring_free(k);
	  return NULL;
	}
      k->contexts[0]->KeyRingPin=""; /* Implied empty PIN if none provided */
      k->contexts[0]->KeyRingSaltLen=KEYRING_PAGE_SIZE-KEYRING_BAM_BYTES;
      k->contexts[0]->KeyRingSalt=malloc(k->contexts[0]->KeyRingSaltLen);
      if (!k->contexts[0]->KeyRingSalt)
	{
	  WHY("Could not allocate keyring_context->salt for keyring file");
	  keyring_free(k);
	  return NULL;
	}

      r=fread(&k->contexts[0]->KeyRingSalt[0],k->contexts[0]->KeyRingSaltLen,1,k->file);
      if (r!=1)
	{
	  WHY("Could not read salt from keyring file");
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
    for(i=0;id->PKRPin[i];i++) id->PKRPin[i]=' '; i=0;
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
  c->KeyRingPin=pin?strdup(pin):"";
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

  WHY("Not implemented");
}

/* Read the slot, and try to decrypt it.
   Decryption is symmetric with encryption, so the same function is used
   for munging the slot before making use of it, whichever way we are going.
   Once munged, we then need to verify that the slot is valid, and if so
   unpack the details of the identity.
*/
int keyring_decrypt_pkr(keyring_file *k,keyring_context *c,int slot)
{
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
			char *KeyRingPin,char *PKRPin)
{
  int exit_code=1;
  unsigned char hashKey[crypto_hash_sha512_BYTES];
  unsigned char hashNonce[crypto_hash_sha512_BYTES];

  unsigned char work[65536];
  int ofs;

  if (len<96) return WHY("block too short");

  unsigned char *PKRSalt=&block[0];
  int PKRSaltLen=32;

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

  WHY("Not implemented");

 kmb_safeexit:
  /* Wipe out all sensitive structures before returning */
  bzero(&work[0],65536);
  bzero(&hashKey[0],crypto_hash_sha512_BYTES);
  bzero(&hashNonce[0],crypto_hash_sha512_BYTES);
  return exit_code;
}
