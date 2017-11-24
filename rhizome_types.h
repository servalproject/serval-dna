/* 
Serval Rhizome foundation types and constants
Copyright (C) 2012-2015 Serval Project Inc.

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

#ifndef __SERVAL_DNA__RHIZOME_TYPES_H
#define __SERVAL_DNA__RHIZOME_TYPES_H

#include <sys/types.h>
#include <stdint.h>
#include <limits.h>
#include "serval_types.h" // for "sodium.h", sign_binary
#include "str.h"          // for alloca_tohex(), is_all_matching(), etc.

#define RHIZOME_BUNDLE_ID_BYTES         crypto_sign_PUBLICKEYBYTES
#define RHIZOME_BUNDLE_ID_STRLEN        (RHIZOME_BUNDLE_ID_BYTES * 2)
#define RHIZOME_BUNDLE_KEY_BYTES        (crypto_sign_SECRETKEYBYTES - crypto_sign_PUBLICKEYBYTES)
#define RHIZOME_BUNDLE_KEY_STRLEN       (RHIZOME_BUNDLE_KEY_BYTES * 2)
#define RHIZOME_FILEHASH_BYTES          crypto_hash_sha512_BYTES
#define RHIZOME_FILEHASH_STRLEN         (RHIZOME_FILEHASH_BYTES * 2)
#define RHIZOME_CRYPT_KEY_BYTES         crypto_box_SECRETKEYBYTES
#define RHIZOME_CRYPT_KEY_STRLEN        (RHIZOME_CRYPT_KEY_BYTES * 2)

#define RHIZOME_PASSPHRASE_MAX_STRLEN   80

#if RHIZOME_PASSPHRASE_MAX_STRLEN > RHIZOME_BUNDLE_KEY_STRLEN
# define RHIZOME_BUNDLE_SECRET_MAX_STRLEN    RHIZOME_PASSPHRASE_MAX_STRLEN
#else
# define RHIZOME_BUNDLE_SECRET_MAX_STRLEN    RHIZOME_BUNDLE_KEY_STRLEN
#endif

#define RHIZOME_BAR_BYTES               32
#define RHIZOME_BAR_PREFIX_BYTES        15
#define RHIZOME_BAR_PREFIX_OFFSET       0
#define RHIZOME_BAR_FILESIZE_OFFSET     15
#define RHIZOME_BAR_VERSION_OFFSET      16
#define RHIZOME_BAR_GEOBOX_OFFSET       23

// TODO  Rename MANIFEST_ID to BUNDLE_ID
// The following constants are deprecated, use the BUNDLE_ID forms instead
#define RHIZOME_MANIFEST_ID_BYTES       RHIZOME_BUNDLE_ID_BYTES
#define RHIZOME_MANIFEST_ID_STRLEN      RHIZOME_BUNDLE_ID_STRLEN

/* Fundamental data type: Rhizome Bundle ID
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */

typedef struct sign_binary rhizome_bid_t;

#define RHIZOME_BID_ZERO ((rhizome_bid_t){{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}})
#define RHIZOME_BID_MAX ((rhizome_bid_t){{0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff}})
#define rhizome_bid_t_is_zero(bid) is_all_matching((bid).binary, sizeof (*(rhizome_bid_t*)0).binary, 0)
#define rhizome_bid_t_is_max(bid) is_all_matching((bid).binary, sizeof (*(rhizome_bid_t*)0).binary, 0xff)
#define alloca_tohex_rhizome_bid_t(bid) alloca_tohex((bid).binary, sizeof (*(rhizome_bid_t*)0).binary)
int cmp_rhizome_bid_t(const rhizome_bid_t *a, const rhizome_bid_t *b);
int str_to_rhizome_bid_t(rhizome_bid_t *bid, const char *hex);
int strn_to_rhizome_bid_t(rhizome_bid_t *bid, const char *hex, size_t hexlen);
int parse_rhizome_bid_t(rhizome_bid_t *bid, const char *hex, ssize_t hexlen, const char **endp);

/* Fundamental data type: Rhizome File Hash
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */

typedef struct rhizome_filehash_binary {
    unsigned char binary[RHIZOME_FILEHASH_BYTES];
} rhizome_filehash_t;

#define RHIZOME_FILEHASH_NONE ((rhizome_filehash_t){{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}})
#define rhizome_filehash_t_is_zero(fh) is_all_matching((fh).binary, sizeof (*(rhizome_filehash_t*)0).binary, 0)
#define rhizome_filehash_t_is_max(fh) is_all_matching((fh).binary, sizeof (*(rhizome_filehash_t*)0).binary, 0xff)
#define alloca_tohex_rhizome_filehash_t(fh) alloca_tohex((fh).binary, sizeof (*(rhizome_filehash_t*)0).binary)
int cmp_rhizome_filehash_t(const rhizome_filehash_t *a, const rhizome_filehash_t *b);
int str_to_rhizome_filehash_t(rhizome_filehash_t *fh, const char *hex);
int strn_to_rhizome_filehash_t(rhizome_filehash_t *fh, const char *hex, size_t hexlen);

/* Fundamental data type: Rhizome Bundle Key (BK)
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */

typedef struct rhizome_bk_binary {
    unsigned char binary[RHIZOME_BUNDLE_KEY_BYTES];
} rhizome_bk_t;

#define RHIZOME_BK_NONE ((rhizome_bk_t){{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}})

int rhizome_is_bk_none(const rhizome_bk_t *bk);

#define alloca_tohex_rhizome_bk_t(bk) alloca_tohex((bk).binary, sizeof (*(rhizome_bk_t*)0).binary)
int cmp_rhizome_bk_t(const rhizome_bk_t *a, const rhizome_bk_t *b);

// The BK field can only be in hex format
int str_to_rhizome_bk_t(rhizome_bk_t *bk, const char *hex);
int strn_to_rhizome_bk_t(rhizome_bk_t *bk, const char *hex, size_t hexlen);
int parse_rhizome_bk_t(rhizome_bk_t *bk, const char *hex, ssize_t hexlen, const char **endp);

// The Bundle Secret can be given as hex or as a passphrase
int str_to_rhizome_bsk_t(rhizome_bk_t *bsk, const char *text);
int strn_to_rhizome_bsk_t(rhizome_bk_t *bsk, const char *text, size_t textlen);

/* Fundamental data type: Rhizome BAR 
 */

typedef struct rhizome_bar_binary {
    unsigned char binary[RHIZOME_BAR_BYTES];
} rhizome_bar_t;

#define rhizome_bar_prefix(X) (&(X)->binary[RHIZOME_BAR_PREFIX_OFFSET])
#define alloca_tohex_rhizome_bar_prefix(X) alloca_tohex(&(X)->binary[RHIZOME_BAR_PREFIX_OFFSET], RHIZOME_BAR_PREFIX_BYTES)
#define alloca_tohex_rhizome_bar_t(X) alloca_tohex((X)->binary, RHIZOME_BAR_BYTES)
#define rhizome_bar_log_size(X) ((unsigned char)(X)->binary[RHIZOME_BAR_FILESIZE_OFFSET])
#define rhizome_is_bar_none(X) is_all_matching((X)->binary, RHIZOME_BAR_BYTES, 0)
uint64_t rhizome_bar_version(const rhizome_bar_t *bar);
uint64_t rhizome_bar_bidprefix_ll(const rhizome_bar_t *bar);

/* Fundamental data type: Rhizome payload size
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */

#define RHIZOME_SIZE_UNSET    UINT64_MAX

/* Rhizome constants
 */


#endif // __SERVAL_DNA__RHIZOME_TYPES_H
