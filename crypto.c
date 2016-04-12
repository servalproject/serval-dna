/*
Serval DNA internal cryptographic operations
Copyright 2013 Serval Project Inc.

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
#include "overlay_address.h"
#include "crypto.h"
#include "keyring.h"


// verify the signature at the end of a message, on return message_len will be reduced by the length of the signature.
int crypto_verify_message(struct subscriber *subscriber, unsigned char *message, size_t *message_len)
{
  if (!subscriber->sas_valid){
    keyring_send_sas_request(subscriber);
    return WHY("SAS key not currently on record, cannot verify");
  }
  
  if (*message_len < SIGNATURE_BYTES)
    return WHY("Message is too short to include a signature");
  
  *message_len -= SIGNATURE_BYTES;
  
  unsigned char hash[crypto_hash_sha512_BYTES];
  crypto_hash_sha512(hash,message,*message_len);
  
  if (crypto_sign_verify_detached(&message[*message_len], hash, crypto_hash_sha512_BYTES, subscriber->sas_public))
    return WHY("Signature verification failed");

  return 0;
}

// sign the hash of a message, adding the signature to the end of the message buffer.
int crypto_sign_message(struct keyring_identity *identity, unsigned char *content, size_t buffer_len, size_t *content_len)
{
  if (*content_len + SIGNATURE_BYTES > buffer_len)
    return WHYF("Insufficient space in message buffer to add signature. %zu, need %zu",buffer_len, *content_len + SIGNATURE_BYTES);
  
  struct keypair *key = keyring_find_sas_private(keyring, identity);
  if (!key)
    return WHY("Could not find signing key");
  
  unsigned char hash[crypto_hash_sha512_BYTES];
  crypto_hash_sha512(hash, content, *content_len);
  
  if (crypto_sign_detached(&content[*content_len], NULL, hash, crypto_hash_sha512_BYTES, key->private_key))
    return WHY("Signing failed");

  *content_len += SIGNATURE_BYTES;
  return 0;
}

