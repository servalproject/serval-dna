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

int current_sid_set=0;
unsigned char current_sid[SID_SIZE];

int packetSetMySid(char *sid)
{
  /* Set SID identity if not the first SID in the HLR */

 
  return setReason("Not implemented");
}

int packetGetPrivateKeyForSid()
{
  return setReason("Not implemented");
}

int packetClearPrivateKeys()
{
  return setReason("Not implemented");
}

int packetDecipher(unsigned char *packet,int len,int cipher)
{
  // Not encrypting for now 
  return 0;

  switch(cipher) {
  case 0: /* plain text */
  case CRYPT_PUBLIC: /*make it public, with no other requirements == plain text */
    return 0;
  case CRYPT_SIGNED:
  case CRYPT_PUBLIC|CRYPT_SIGNED:
    /* Sign but don't encrypt, i.e., crypto_sign() */
    return 0;
  case CRYPT_CIPHERED:
    /* encrypt, but don't sign.
       Down the track we will use crypto_stream(), but we need a shared secret for the conversation.
    */
    return 0;
  case CRYPT_CIPHERED|CRYPT_SIGNED:
    /* encrypt and sign, i.e., crypto_box() */
    return 0;
  default:
    return setReason("Unknown packet cipher");
  }
}

int packetEncipher(unsigned char *packet,int maxlen,int *len,int cryptoflags)
{
  // Not encrypting for now
  return 0;

  if (cryptoflags) 
    {
      return setReason("Unknown packet cipher"); 
    }
  else return 0; /* plain text */
}
