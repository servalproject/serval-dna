/* 
Serval Rhizome foundation types
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

#ifndef __SERVAL_DNA__RHIZOME_TYPES_H
#define __SERVAL_DNA__RHIZOME_TYPES_H

#include <sys/types.h>
#include <stdint.h>
#include <limits.h>
#include "nacl.h"
#include "sha2.h"
#include "str.h"

#ifndef __RHIZOME_TYPES_INLINE
# if __GNUC__ && !__GNUC_STDC_INLINE__
#  define __RHIZOME_TYPES_INLINE extern inline
# else
#  define __RHIZOME_TYPES_INLINE inline
# endif
#endif

#define RHIZOME_BUNDLE_ID_BYTES         crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES
#define RHIZOME_BUNDLE_ID_STRLEN        (RHIZOME_BUNDLE_ID_BYTES * 2)
#define RHIZOME_BUNDLE_KEY_BYTES        (crypto_sign_edwards25519sha512batch_SECRETKEYBYTES - crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES)
#define RHIZOME_BUNDLE_KEY_STRLEN       (RHIZOME_BUNDLE_KEY_BYTES * 2)
#define RHIZOME_FILEHASH_BYTES          SHA512_DIGEST_LENGTH
#define RHIZOME_FILEHASH_STRLEN         (RHIZOME_FILEHASH_BYTES * 2)
#define RHIZOME_CRYPT_KEY_BYTES         crypto_stream_xsalsa20_ref_KEYBYTES
#define RHIZOME_CRYPT_KEY_STRLEN        (RHIZOME_CRYPT_KEY_BYTES * 2)

// TODO  Rename MANIFEST_ID to BUNDLE_ID
// The following constants are deprecated, use the BUNDLE_ID forms instead
#define RHIZOME_MANIFEST_ID_BYTES       RHIZOME_BUNDLE_ID_BYTES
#define RHIZOME_MANIFEST_ID_STRLEN      RHIZOME_BUNDLE_ID_STRLEN

/* Fundamental data type: Rhizome Bundle ID
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */

typedef struct rhizome_bid_binary {
    unsigned char binary[RHIZOME_MANIFEST_ID_BYTES];
} rhizome_bid_t;

#define RHIZOME_BID_ZERO ((rhizome_bid_t){{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}})
#define RHIZOME_BID_MAX ((rhizome_bid_t){{0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff}})
#define rhizome_bid_t_is_zero(bid) is_all_matching((bid).binary, sizeof (*(rhizome_bid_t*)0).binary, 0)
#define rhizome_bid_t_is_max(bid) is_all_matching((bid).binary, sizeof (*(rhizome_bid_t*)0).binary, 0xff)
#define alloca_tohex_rhizome_bid_t(bid) alloca_tohex((bid).binary, sizeof (*(rhizome_bid_t*)0).binary)
int cmp_rhizome_bid_t(const rhizome_bid_t *a, const rhizome_bid_t *b);
int str_to_rhizome_bid_t(rhizome_bid_t *bid, const char *hex);
int strn_to_rhizome_bid_t(rhizome_bid_t *bid, const char *hex, const char **endp);

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
int strn_to_rhizome_filehash_t(rhizome_filehash_t *fh, const char *hex, const char **endp);

/* Fundamental data type: Rhizome Bundle Key
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */

typedef struct rhizome_bk_binary {
    unsigned char binary[RHIZOME_BUNDLE_KEY_BYTES];
} rhizome_bk_t;

#define RHIZOME_BK_NONE ((rhizome_bk_t){{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}})

__RHIZOME_TYPES_INLINE int rhizome_is_bk_none(const rhizome_bk_t *bk) {
    return is_all_matching(bk->binary, sizeof bk->binary, 0);
}

#define alloca_tohex_rhizome_bk_t(bk) alloca_tohex((bk).binary, sizeof (*(rhizome_bk_t*)0).binary)
int cmp_rhizome_bk_t(const rhizome_bk_t *a, const rhizome_bk_t *b);
int str_to_rhizome_bk_t(rhizome_bk_t *bk, const char *hex);
int strn_to_rhizome_bk_t(rhizome_bk_t *bk, const char *hex, const char **endp);

/* Fundamental data type: Rhizome payload size
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */

#define RHIZOME_SIZE_UNSET    UINT64_MAX

#endif // __SERVAL_DNA__RHIZOME_TYPES_H
