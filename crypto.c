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

// verify that the supplied keypair is valid (by rebuilding it)
int crypto_isvalid_keypair(const sign_private_t *private_key, const sign_public_t *public_key)
{
  sign_keypair_t test_key;
  crypto_sign_seed_keypair(test_key.public_key.binary, test_key.binary, private_key->binary);
  return bcmp(test_key.public_key.binary, public_key->binary, sizeof (sign_public_t)) == 0 ? 1 : 0;
}

int crypto_sign_to_sid(const sign_public_t *public_key, sid_t *sid)
{
  if (crypto_sign_ed25519_pk_to_curve25519(sid->binary, public_key->binary))
    return WHY("Failed to convert sign key to sid");
  return 0;
}

int crypto_ismatching_sign_sid(const sign_public_t *public_key, const sid_t *sid)
{
  sid_t test_sid;
  if (crypto_sign_to_sid(public_key, &test_sid)==0
    && cmp_sid_t(&test_sid, sid)==0)
    return 1;
  return 0;
}

// verify the signature at the end of a message, on return message_len will be reduced by the length of the signature.
int crypto_verify_message(struct subscriber *subscriber, unsigned char *message, size_t *message_len)
{
  if (!subscriber->id_valid){
    keyring_send_identity_request(subscriber);
    return WHY("SAS key not currently on record, cannot verify");
  }
  
  if (*message_len < SIGNATURE_BYTES)
    return WHY("Message is too short to include a signature");
  
  *message_len -= SIGNATURE_BYTES;
  
  unsigned char hash[crypto_hash_sha512_BYTES];
  crypto_hash_sha512(hash,message,*message_len);
  
  if (crypto_sign_verify_detached(&message[*message_len], hash, crypto_hash_sha512_BYTES, subscriber->id_public.binary))
    return WHY("Signature verification failed");

  return 0;
}


