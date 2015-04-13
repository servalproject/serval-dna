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

#ifndef __SERVAL_DNA__CRYPTO_H
#define __SERVAL_DNA__CRYPTO_H

#include "nacl.h"
#define SIGNATURE_BYTES crypto_sign_edwards25519sha512batch_BYTES
struct keyring_identity;

int crypto_verify_signature(unsigned char *sas_key, 
			    unsigned char *content, int content_len, 
			    unsigned char *signature_block, int signature_len);
int crypto_verify_message(struct subscriber *subscriber, unsigned char *message, int *message_len);
int crypto_create_signature(unsigned char *key, 
			    unsigned char *content, int content_len, 
			    unsigned char *signature, int *sig_length);
int crypto_sign_message(struct keyring_identity *identity, unsigned char *content, size_t buffer_len, size_t *content_len);
void crypto_sign_compute_public_key(const unsigned char *skin, unsigned char *pk);

#endif
