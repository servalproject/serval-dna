#include "serval.h"
#include "overlay_address.h"
#include "crypto.h"

// verify a signature against a public sas key.
int crypto_verify_signature(unsigned char *sas_key, 
			    unsigned char *content, unsigned long long content_len, 
			    unsigned char *signature_block, unsigned long long signature_len)
{
  IN();
  
  if (signature_len!=SIGNATURE_BYTES)
    RETURN(WHY("Invalid signature length"));
  
  /* reconstitute signed message by putting hash at end of signature */
  unsigned char reassembled[signature_len + content_len];
  bcopy(signature_block, reassembled, signature_len);
  bcopy(content, &reassembled[signature_len], content_len);
  
  /* verify signature.
   Note that crypto_sign_open requires m to be as large as signature, even
   though it will not need the whole length eventually -- it does use the 
   full length and will overwrite the end of a short buffer. */
  unsigned char message[sizeof(reassembled)+64];
  unsigned long long  mlen=0;
  int result
  =crypto_sign_edwards25519sha512batch_open(message,&mlen,
					    reassembled,sizeof(reassembled),
					    sas_key);
  
  if (result)
    RETURN(WHY("Signature verification failed"));
  RETURN(0);
}

// verify the signature at the end of a message, on return message_len will be reduced by the length of the signature.
int crypto_verify_message(struct subscriber *subscriber, unsigned char *message, int *message_len)
{
  if (!subscriber->sas_valid){
    keyring_send_sas_request(subscriber);
    return WHY("SAS key not currently on record, cannot verify");
  }
  
  *message_len -= SIGNATURE_BYTES;
  
  unsigned char hash[crypto_hash_sha512_BYTES];
  crypto_hash_sha512(hash,message,*message_len);
  
  return crypto_verify_signature(subscriber->sas_public, hash, 
				 crypto_hash_sha512_BYTES, &message[*message_len], SIGNATURE_BYTES);
}

// generate a signature for this raw content, copy the signature to the address requested.
int crypto_create_signature(unsigned char *key, 
			    unsigned char *content, unsigned long long content_len, 
			    unsigned char *signature, unsigned long long *sig_length)
{
  IN();
  
  if (*sig_length < SIGNATURE_BYTES)
    RETURN(WHY("Not enough space to store signature"));
  
  unsigned char sig[content_len + SIGNATURE_BYTES];
  /* Why does this primitive copy the whole input message? We don't want that message format, it just seems like a waste of effor to me. */
  unsigned long long length = 0;
  crypto_sign_edwards25519sha512batch(sig,&length,
				      content,content_len,
				      key);
  
  if (length != sizeof(sig))
    RETURN(WHYF("Signing seems to have failed (%d, expected %d)",length,sizeof(sig)));
  
  bcopy(sig, signature, SIGNATURE_BYTES);
  *sig_length=SIGNATURE_BYTES;
  OUT();
  return 0;
}

// sign the hash of a message, adding the signature to the end of the message buffer.
int crypto_sign_message(struct subscriber *source, unsigned char *content, int buffer_len, int *content_len)
{
  if (*content_len + SIGNATURE_BYTES > buffer_len)
    return WHYF("Insufficient space in message buffer to add signature. %d, need %d",buffer_len, *content_len + SIGNATURE_BYTES);
  
  unsigned char *key=keyring_find_sas_private(keyring, source->sid, NULL);
  if (!key)
    return WHY("Could not find signing key");
  
  unsigned char hash[crypto_hash_sha512_BYTES];
  crypto_hash_sha512(hash, content, *content_len);
  
  unsigned long long sig_length = SIGNATURE_BYTES;
  
  int ret=crypto_create_signature(key, hash, crypto_hash_sha512_BYTES, &content[*content_len], &sig_length);
  *content_len+=sig_length;
  return ret;
}
