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


