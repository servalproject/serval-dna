/* 
Serval DNA foundation types
Copyright (C) 2012-2014 Serval Project Inc.

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

#ifndef __SERVAL_DNA__SERVAL_TYPES_H
#define __SERVAL_DNA__SERVAL_TYPES_H

#include <sys/types.h>
#include <stdint.h>
#include <inttypes.h>
#include <sodium.h>

/* Conveniences to assist readability
 */

typedef char bool_t;

/* Serval ID (aka Subscriber ID)
 */

#define SID_SIZE crypto_box_PUBLICKEYBYTES
#define IDENTITY_SIZE crypto_sign_PUBLICKEYBYTES

#define SID_STRLEN (SID_SIZE*2)
#define IDENTITY_STRLEN (IDENTITY_SIZE*2)

typedef struct sid_binary {
    uint8_t binary[SID_SIZE];
} sid_t;

// lib sodium crypto_sign key types;
typedef struct sign_binary {
    uint8_t binary[IDENTITY_SIZE];
} sign_public_t;

typedef struct sign_private_binary{
  uint8_t binary[crypto_sign_SEEDBYTES];
}sign_private_t;

typedef struct sign_keypair_binary{
  union{
    struct{
      sign_private_t private_key;
      sign_public_t public_key;
    };
    uint8_t binary[crypto_sign_SECRETKEYBYTES];
  };
}sign_keypair_t;


typedef struct sign_binary identity_t;


#define SID_TYPE_ANY        (0)
#define SID_TYPE_INTERNAL   (1)
#define SID_TYPE_BROADCAST  (0xFF)

#define SID_ANY         ((sid_t){{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,SID_TYPE_ANY}})
#define SID_INTERNAL    ((sid_t){{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,SID_TYPE_INTERNAL}})
#define SID_BROADCAST   ((sid_t){{0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff}})

// is the SID entirely 0xFF?
#define is_sid_t_broadcast(SID) is_all_matching((SID).binary, sizeof (*(sid_t*)0).binary, 0xFF)

// is the SID entirely 0x00?
#define is_sid_t_any(SID) is_all_matching((SID).binary, sizeof (*(sid_t*)0).binary, 0)

#define alloca_tohex_sid_t(sid)         alloca_tohex((sid).binary, SID_SIZE)
#define alloca_tohex_sid_t_trunc(sid,strlen)  tohex((char *)alloca((strlen)+1), (strlen), (sid).binary)

int cmp_sid_t(const sid_t *a, const sid_t *b);
int str_to_sid_t(sid_t *sid, const char *hex);
int strn_to_sid_t(sid_t *sid, const char *hex, size_t hexlen);
int parse_sid_t(sid_t *sid, const char *hex, ssize_t hexlen, const char **endp);
int sid_get_special_type(const sid_t *sid);

#define alloca_tohex_identity_t(identity)           alloca_tohex((identity)->binary, IDENTITY_SIZE)

int cmp_identity_t(const identity_t *a, const identity_t *b);
int str_to_identity_t(identity_t *sid, const char *hex);
int strn_to_identity_t(identity_t *sid, const char *hex, size_t hexlen);

/* MDP port number
 */

typedef uint32_t mdp_port_t;
#define PRImdp_port_t "#010" PRIx32

/* DID (phone number)
 */

#define DID_MINSIZE 5
#define DID_MAXSIZE 32

#endif // __SERVAL_DNA__SERVAL_TYPES_H
