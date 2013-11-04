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

#ifndef __SERVALDNA__RHIZOME_H
#define __SERVALDNA__RHIZOME_H

#include <sqlite3.h>
#include <limits.h>
#include "sha2.h"
#include "uuid.h"
#include "str.h"
#include "strbuf.h"
#include "http_server.h"
#include "nacl.h"

#ifndef __RHIZOME_INLINE
# if __GNUC__ && !__GNUC_STDC_INLINE__
#  define __RHIZOME_INLINE extern inline
# else
#  define __RHIZOME_INLINE inline
# endif
#endif

// TODO  Rename MANIFEST_ID to BUNDLE_ID
#define RHIZOME_MANIFEST_ID_BYTES       crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES
#define RHIZOME_MANIFEST_ID_STRLEN      (RHIZOME_MANIFEST_ID_BYTES * 2)
#define RHIZOME_BUNDLE_KEY_BYTES        (crypto_sign_edwards25519sha512batch_SECRETKEYBYTES-crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES)
#define RHIZOME_BUNDLE_KEY_STRLEN       (RHIZOME_BUNDLE_KEY_BYTES  * 2)
#define RHIZOME_FILEHASH_BYTES          SHA512_DIGEST_LENGTH
#define RHIZOME_FILEHASH_STRLEN         (RHIZOME_FILEHASH_BYTES * 2)

#define RHIZOME_CRYPT_KEY_BYTES         crypto_stream_xsalsa20_ref_KEYBYTES
#define RHIZOME_CRYPT_KEY_STRLEN        (RHIZOME_CRYPT_KEY_BYTES * 2)

// assumed to always be 2^n
#define RHIZOME_CRYPT_PAGE_SIZE         4096

#define RHIZOME_HTTP_PORT 4110
#define RHIZOME_HTTP_PORT_MAX 4150

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

__RHIZOME_INLINE int rhizome_is_bk_none(const rhizome_bk_t *bk) {
    return is_all_matching(bk->binary, sizeof bk->binary, 0);
}

#define alloca_tohex_rhizome_bk_t(bk) alloca_tohex((bk).binary, sizeof (*(rhizome_bk_t*)0).binary)
int cmp_rhizome_bk_t(const rhizome_bk_t *a, const rhizome_bk_t *b);
int str_to_rhizome_bk_t(rhizome_bk_t *bk, const char *hex);


extern time_ms_t rhizome_voice_timeout;

#define RHIZOME_PRIORITY_HIGHEST RHIZOME_PRIORITY_SERVAL_CORE
#define RHIZOME_PRIORITY_SERVAL_CORE 5
#define RHIZOME_PRIORITY_SUBSCRIBED 4
#define RHIZOME_PRIORITY_SERVAL_OPTIONAL 3
#define RHIZOME_PRIORITY_DEFAULT 2
#define RHIZOME_PRIORITY_SERVAL_BULK 1
#define RHIZOME_PRIORITY_NOTINTERESTED 0

#define RHIZOME_IDLE_TIMEOUT 20000

typedef struct rhizome_signature {
  unsigned char signature[crypto_sign_edwards25519sha512batch_BYTES
			  +crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES+1];
  int signatureLength;
} rhizome_signature;

#define RHIZOME_BAR_BYTES 32
#define RHIZOME_BAR_COMPARE_BYTES 31
#define RHIZOME_BAR_PREFIX_BYTES 15
#define RHIZOME_BAR_PREFIX_OFFSET 0
#define RHIZOME_BAR_FILESIZE_OFFSET 15
#define RHIZOME_BAR_VERSION_OFFSET 16
#define RHIZOME_BAR_GEOBOX_OFFSET 23
#define RHIZOME_BAR_TTL_OFFSET 31

#define MAX_MANIFEST_VARS 256
#define MAX_MANIFEST_BYTES 8192

#define RHIZOME_SIZE_UNSET    UINT64_MAX

typedef struct rhizome_manifest
{
  int manifest_record_number;

  /* CryptoSign key pair for this manifest.  The public key is the Bundle ID
   * (aka Manifest ID).
   */
  rhizome_bid_t cryptoSignPublic;
  unsigned char cryptoSignSecret[crypto_sign_edwards25519sha512batch_SECRETKEYBYTES];

  /* Whether cryptoSignSecret is correct (ie, bundle secret is known)
   */
  enum { SECRET_UNKNOWN = 0, EXISTING_BUNDLE_ID, NEW_BUNDLE_ID } haveSecret;

  /* Version of the manifest.  Typically the number of milliseconds since 1970.
   * A value of zero (0) means it has not been set yet.
   * TODO: change this to uint64_t.
   */
  int64_t version;

  /* Payload is described by the offset of its tail (number of missing bytes
   * before the first byte in the payload), its size (number of bytes) and the
   * hash of its content.  Bundle size = tail + filesize.
   */
  uint64_t tail;
  uint64_t filesize;
  rhizome_filehash_t filehash;

  /* All the manifest fields in original order (the order affects the manifest
   * hash which was used to sign the manifest, so the signature can only be
   * checked if order is preserved).
   *
   * TODO: reduce to only unknown fields.
   *
   * TODO: store all vars and values as NUL terminated strings within
   * manifestdata[], not malloc()/free() heap, to reduce memory fragmentation
   * and allow manifest struct copying without string lifetime issues.
   */
  unsigned short var_count;
  const char *vars[MAX_MANIFEST_VARS];
  const char *values[MAX_MANIFEST_VARS];

  /* Parties who have signed this manifest (binary format, malloc(3)).
   * Recognised signature types:
   *    0x17 = crypto_sign_edwards25519sha512batch()
   */
  unsigned short sig_count;
  unsigned char *signatories[MAX_MANIFEST_VARS];
  uint8_t signatureTypes[MAX_MANIFEST_VARS];

  /* Imperfections.
   *  - Errors involve the correctness of fields that are mandatory for proper
   *    operation of the transport and storage layer.  A manifest with errors > 0
   *    must not be stored, transmitted or supplied via any API.
   *  - Warnings indicate a manifest that cannot be fully understood by this
   *    version of Rhizome (probably from a future or a very old past version
   *    of Rhizome).  During add or import (local injection), the manifest
   *    should not be imported.  During extract or export (local) a warning or
   *    error message should be logged.
   */
  unsigned short errors;
  unsigned short warnings;

  /* Set non-zero after variables have been packed and signature blocks
   * appended.  All fields below may not be valid until the manifest has been
   * finalised.
   */
  bool_t finalised;

  /* Whether the manifest contains a signature that corresponds to the manifest
   * id (ie public key).  Caches the result of 
   */
  bool_t selfSigned;

  /* If set, unlink(2) the associated file when freeing the manifest.
   */
  bool_t dataFileUnlinkOnFree;

  /* Set if the tail field is valid, ie, the bundle is a journal.
   */
  bool_t is_journal;

  /* Set if the date field is valid, ie, the manifest contains a valid "date"
   * field.
   */
  bool_t has_date;

  /* Set if the bundle_key field is valid, ie, the manifest contains a valid
   * "BK" field.
   */
  bool_t has_bundle_key;

  /* Set if the sender and recipient fields are valid, ie, the manifest
   * contains a valid "sender"/"recipient" field.
   */
  bool_t has_sender;
  bool_t has_recipient;

  /* Local authorship.  Useful for dividing bundle lists between "sent" and
   * "inbox" views.
   */
  enum rhizome_bundle_authorship { 
    ANONYMOUS = 0, // 'author' element is not valid
    AUTHOR_NOT_CHECKED, // 'author' element is valid but not checked
    AUTHENTICATION_ERROR, // author check failed, don't try again
    AUTHOR_UNKNOWN, // author is not a local identity
    AUTHOR_LOCAL, // author is in keyring (unlocked) but not verified
    AUTHOR_IMPOSTOR, // author is a local identity but fails verification
    AUTHOR_AUTHENTIC // a local identity is the verified author
  } authorship;

  /* time-to-live in hops of this manifest. */
  int ttl;

  int fileHighestPriority;

  /* Absolute path of the file associated with the manifest */
  const char *dataFileName;

  /* Whether the paylaod is encrypted or not */
  enum rhizome_manifest_crypt {
        PAYLOAD_CRYPT_UNKNOWN = 0,
        PAYLOAD_CLEAR,
        PAYLOAD_ENCRYPTED
    } payloadEncryption;
  unsigned char payloadKey[RHIZOME_CRYPT_KEY_BYTES];
  unsigned char payloadNonce[crypto_stream_xsalsa20_NONCEBYTES];

  /* From the "date" field, if present.  The number of milliseconds since 1970
   * when the bundle was last modified.
   */
  time_ms_t date;

  /* From the "service" field, which should always be present.
   */
  const char *service;

  /* From the optional "name" field.  NULL if there is no "name" field in the
   * manifest.
   */
  const char *name;

  /* Bundle Key "BK" field from the manifest.
   */
  rhizome_bk_t bundle_key;

  /* Sender and recipient fields, if present in the manifest.
   */
  sid_t sender;
  sid_t recipient;

  /* Local data, not encapsulated in the bundle.  The ROWID of the SQLite
   * MANIFESTS table row in which this manifest is stored.  Zero if the
   * manifest has not been stored yet.
   */
  uint64_t rowid;

  /* Local data, not encapsulated in the bundle.  The system time of the most
   * recent INSERT or UPDATE of the manifest into the store.  Zero if the manifest
   * has not been stored yet.
   */
  time_ms_t inserttime;

  /* Local data, not encapsulated in the bundle.  The author of the manifest.
   * A reference to a local keyring entry.  Manifests not authored locally will
   * have an ANY author (all zeros).
   */
  sid_t author;

  /* Unused.  SHOULD BE DELETED.
   */
  unsigned group_count;
  char *groups[MAX_MANIFEST_VARS];

  unsigned manifest_bytes;
  unsigned manifest_all_bytes;
  unsigned char manifestdata[MAX_MANIFEST_BYTES];
  unsigned char manifesthash[crypto_hash_sha512_BYTES];

} rhizome_manifest;

/* These setter functions (methods) are needed because the relevant attributes
 * are stored in two places: in the vars[] array and in a dedicated struct
 * element.
 *
 * TODO: refactor to remove the redundancy, possibly removing these setter
 * functions as well.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
#define rhizome_manifest_set_id(m,v)            _rhizome_manifest_set_id(__WHENCE__,(m),(v))
#define rhizome_manifest_set_version(m,v)       _rhizome_manifest_set_version(__WHENCE__,(m),(v))
#define rhizome_manifest_set_filesize(m,v)      _rhizome_manifest_set_filesize(__WHENCE__,(m),(v))
#define rhizome_manifest_set_filehash(m,v)      _rhizome_manifest_set_filehash(__WHENCE__,(m),(v))
#define rhizome_manifest_set_tail(m,v)          _rhizome_manifest_set_tail(__WHENCE__,(m),(v))
#define rhizome_manifest_set_bundle_key(m,v)    _rhizome_manifest_set_bundle_key(__WHENCE__,(m),(v))
#define rhizome_manifest_del_bundle_key(m)      _rhizome_manifest_del_bundle_key(__WHENCE__,(m))
#define rhizome_manifest_set_service(m,v)       _rhizome_manifest_set_service(__WHENCE__,(m),(v))
#define rhizome_manifest_del_service(m)         _rhizome_manifest_del_service(__WHENCE__,(m))
#define rhizome_manifest_set_name(m,v)          _rhizome_manifest_set_name(__WHENCE__,(m),(v))
#define rhizome_manifest_del_name(m)            _rhizome_manifest_del_name(__WHENCE__,(m))
#define rhizome_manifest_set_date(m,v)          _rhizome_manifest_set_date(__WHENCE__,(m),(v))
#define rhizome_manifest_del_date(m)            _rhizome_manifest_del_date(__WHENCE__,(m))
#define rhizome_manifest_set_sender(m,v)        _rhizome_manifest_set_sender(__WHENCE__,(m),(v))
#define rhizome_manifest_del_sender(m)          _rhizome_manifest_del_sender(__WHENCE__,(m))
#define rhizome_manifest_set_recipient(m,v)     _rhizome_manifest_set_recipient(__WHENCE__,(m),(v))
#define rhizome_manifest_del_recipient(m)       _rhizome_manifest_del_recipient(__WHENCE__,(m))
#define rhizome_manifest_set_crypt(m,v)         _rhizome_manifest_set_crypt(__WHENCE__,(m),(v))
#define rhizome_manifest_set_rowid(m,v)         _rhizome_manifest_set_rowid(__WHENCE__,(m),(v))
#define rhizome_manifest_set_inserttime(m,v)    _rhizome_manifest_set_inserttime(__WHENCE__,(m),(v))
#define rhizome_manifest_set_author(m,v)        _rhizome_manifest_set_author(__WHENCE__,(m),(v))
#define rhizome_manifest_del_author(m)          _rhizome_manifest_del_author(__WHENCE__,(m))

void _rhizome_manifest_set_id(struct __sourceloc, rhizome_manifest *, const rhizome_bid_t *);
void _rhizome_manifest_set_version(struct __sourceloc, rhizome_manifest *, int64_t); // TODO change to uint64_t
void _rhizome_manifest_set_filesize(struct __sourceloc, rhizome_manifest *, uint64_t);
void _rhizome_manifest_set_filehash(struct __sourceloc, rhizome_manifest *, const rhizome_filehash_t *);
void _rhizome_manifest_set_tail(struct __sourceloc, rhizome_manifest *, uint64_t);
void _rhizome_manifest_set_bundle_key(struct __sourceloc, rhizome_manifest *, const rhizome_bk_t *);
void _rhizome_manifest_del_bundle_key(struct __sourceloc, rhizome_manifest *);
void _rhizome_manifest_set_service(struct __sourceloc, rhizome_manifest *, const char *);
void _rhizome_manifest_del_service(struct __sourceloc, rhizome_manifest *);
void _rhizome_manifest_set_name(struct __sourceloc, rhizome_manifest *, const char *);
void _rhizome_manifest_del_name(struct __sourceloc, rhizome_manifest *);
void _rhizome_manifest_set_date(struct __sourceloc, rhizome_manifest *, time_ms_t);
void _rhizome_manifest_del_date(struct __sourceloc, rhizome_manifest *);
void _rhizome_manifest_set_sender(struct __sourceloc, rhizome_manifest *, const sid_t *);
void _rhizome_manifest_del_sender(struct __sourceloc, rhizome_manifest *);
void _rhizome_manifest_set_recipient(struct __sourceloc, rhizome_manifest *, const sid_t *);
void _rhizome_manifest_del_recipient(struct __sourceloc, rhizome_manifest *);
void _rhizome_manifest_set_crypt(struct __sourceloc, rhizome_manifest *, enum rhizome_manifest_crypt);
void _rhizome_manifest_set_rowid(struct __sourceloc, rhizome_manifest *, uint64_t);
void _rhizome_manifest_set_inserttime(struct __sourceloc, rhizome_manifest *, time_ms_t);
void _rhizome_manifest_set_author(struct __sourceloc, rhizome_manifest *, const sid_t *);
void _rhizome_manifest_del_author(struct __sourceloc, rhizome_manifest *);

/* Supported service identifiers.  These go in the 'service' field of every
 * manifest, and indicate which application must be used to process the bundle
 * after it is received by Rhizome.
 */
#define     RHIZOME_SERVICE_FILE    "file"
#define     RHIZOME_SERVICE_MESHMS  "MeshMS1"
#define     RHIZOME_SERVICE_MESHMS2  "MeshMS2"

extern int64_t rhizome_space;
extern uint16_t rhizome_http_server_port;

int log2ll(uint64_t x);
int rhizome_configure();
int rhizome_enabled();
int rhizome_fetch_delay_ms();

int rhizome_set_datastore_path(const char *path);

const char *rhizome_datastore_path();
int form_rhizome_datastore_path(char * buf, size_t bufsiz, const char *fmt, ...);
int create_rhizome_datastore_dir();

/* Handy statement for forming the path of a rhizome store file in a char buffer whose declaration
 * is in scope (so that sizeof(buf) will work).  Evaluates to true if the pathname fitted into
 * the provided buffer, false (0) otherwise (after logging an error).  */
#define FORM_RHIZOME_DATASTORE_PATH(buf,fmt,...) (form_rhizome_datastore_path((buf), sizeof(buf), (fmt), ##__VA_ARGS__))
#define FORM_RHIZOME_IMPORT_PATH(buf,fmt,...) (form_rhizome_import_path((buf), sizeof(buf), (fmt), ##__VA_ARGS__))

extern sqlite3 *rhizome_db;
uuid_t rhizome_db_uuid;

int rhizome_opendb();
int rhizome_close_db();
void verify_bundles();

struct rhizome_cleanup_report {
    unsigned deleted_stale_incoming_files;
    unsigned deleted_orphan_files;
    unsigned deleted_orphan_fileblobs;
};

int rhizome_cleanup(struct rhizome_cleanup_report *report);

int rhizome_manifest_createid(rhizome_manifest *m);
int rhizome_get_bundle_from_seed(rhizome_manifest *m, const char *seed);

int rhizome_strn_is_manifest_id(const char *text);
int rhizome_str_is_manifest_id(const char *text);
int rhizome_strn_is_bundle_key(const char *text);
int rhizome_str_is_bundle_key(const char *text);
int rhizome_strn_is_bundle_crypt_key(const char *text);
int rhizome_str_is_bundle_crypt_key(const char *text);
int rhizome_strn_is_file_hash(const char *text);
int rhizome_str_is_file_hash(const char *text);
int rhizome_str_is_manifest_service(const char *text);

int is_http_header_complete(const char *buf, size_t len, size_t read_since_last_call);

typedef struct sqlite_retry_state {
  unsigned int limit; // do not retry once elapsed >= limit
  unsigned int sleep; // number of milliseconds to sleep between retries
  unsigned int elapsed; // the total number of milliseconds elapsed doing retries
  time_ms_t start; // the gettime_ms() value just after the current SQL query first returned BUSY
  unsigned int busytries; // the number of times the current SQL query has returned BUSY
}
    sqlite_retry_state;

sqlite_retry_state sqlite_retry_state_init(int serverLimit, int serverSleep, int otherLimit, int otherSleep);

#define SQLITE_RETRY_STATE_DEFAULT sqlite_retry_state_init(-1,-1,-1,-1)

int rhizome_write_manifest_file(rhizome_manifest *m, const char *filename, char append);
int rhizome_manifest_selfsign(rhizome_manifest *m);
int rhizome_drop_stored_file(const rhizome_filehash_t *hashp, int maximum_priority);
int rhizome_manifest_priority(sqlite_retry_state *retry, const rhizome_bid_t *bidp);
int rhizome_read_manifest_file(rhizome_manifest *m, const char *filename, size_t bufferPAndSize);
int rhizome_hash_file(rhizome_manifest *m, const char *path, rhizome_filehash_t *hash_out, uint64_t *size_out);

void _rhizome_manifest_free(struct __sourceloc __whence, rhizome_manifest *m);
#define rhizome_manifest_free(m) _rhizome_manifest_free(__WHENCE__,m)
rhizome_manifest *_rhizome_new_manifest(struct __sourceloc __whence);
#define rhizome_new_manifest() _rhizome_new_manifest(__WHENCE__)

int rhizome_manifest_pack_variables(rhizome_manifest *m);
int rhizome_store_bundle(rhizome_manifest *m);
int rhizome_remove_file_datainvalid(sqlite_retry_state *retry, const rhizome_filehash_t *hashp);
int rhizome_store_file(rhizome_manifest *m,const unsigned char *key);
int rhizome_bundle_import_files(rhizome_manifest *m, const char *manifest_path, const char *filepath);

int rhizome_fill_manifest(rhizome_manifest *m, const char *filepath, const sid_t *authorSidp);

int rhizome_apply_bundle_secret(rhizome_manifest *, const rhizome_bk_t *);
int rhizome_manifest_add_bundle_key(rhizome_manifest *);

void rhizome_find_bundle_author_and_secret(rhizome_manifest *m);
int rhizome_lookup_author(rhizome_manifest *m);
void rhizome_authenticate_author(rhizome_manifest *m);

int rhizome_manifest_verify(rhizome_manifest *m);
int rhizome_manifest_check_sanity(rhizome_manifest *m_in);

int rhizome_manifest_finalise(rhizome_manifest *m, rhizome_manifest **mout, int deduplicate);
int rhizome_add_manifest(rhizome_manifest *m_in,int ttl);

void rhizome_bytes_to_hex_upper(unsigned const char *in, char *out, int byteCount);
int rhizome_find_privatekey(rhizome_manifest *m);
int rhizome_sign_hash(rhizome_manifest *m, rhizome_signature *out);

__RHIZOME_INLINE int sqlite_code_ok(int code)
{
  return code == SQLITE_OK || code == SQLITE_DONE;
}

__RHIZOME_INLINE int sqlite_code_busy(int code)
{
  return code == SQLITE_BUSY || code == SQLITE_LOCKED;
}

int (*sqlite_set_tracefunc(int (*newfunc)()))();
int is_debug_rhizome();
int is_debug_rhizome_ads();

enum sqlbind_type {
  END = 0xbabecafe,
  INT = 1,	      // int value
  INT_TOSTR,	      // int value
  UINT_TOSTR,	      // unsigned value
  INT64,	      // int64_t value
  INT64_TOSTR,	      // int64_t value
  UINT64_TOSTR,	      // uint64_t value
  TEXT,	              // const char *text,
  TEXT_LEN,           // const char *text, int bytes
  STATIC_TEXT,	      // const char *text,
  STATIC_TEXT_LEN,    // const char *text, int bytes
  STATIC_BLOB,	      // const void *blob, int bytes
  ZEROBLOB,	      // int bytes
  SID_T,	      // const sid_t *sidp
  RHIZOME_BID_T,      // const rhizome_bid_t *bidp
  RHIZOME_FILEHASH_T, // const rhizome_filehash_t *hashp
  TOHEX,              // const unsigned char *binary, unsigned bytes
  TEXT_TOUPPER,       // const char *text,
  TEXT_LEN_TOUPPER,   // const char *text, unsigned bytes
  UUID_T,	      // const uuid_t *uuidp
  NUL = 1 << 15,      // NUL (no arg) ; NUL|INT, ...
  INDEX = 0xfade0000, // INDEX|INT, int index, ...
  NAMED = 0xdead0000  // NAMED|INT, const char *label, ...
};

sqlite3_stmt *_sqlite_prepare(struct __sourceloc, int log_level, sqlite_retry_state *retry, const char *sqltext);
int _sqlite_bind(struct __sourceloc __whence, int log_level, sqlite_retry_state *retry, sqlite3_stmt *statement, ...);
int _sqlite_vbind(struct __sourceloc __whence, int log_level, sqlite_retry_state *retry, sqlite3_stmt *statement, va_list ap);
sqlite3_stmt *_sqlite_prepare_bind(struct __sourceloc, int log_level, sqlite_retry_state *retry, const char *sqltext, ...);
int _sqlite_retry(struct __sourceloc, sqlite_retry_state *retry, const char *action);
void _sqlite_retry_done(struct __sourceloc, sqlite_retry_state *retry, const char *action);
int _sqlite_step(struct __sourceloc, int log_level, sqlite_retry_state *retry, sqlite3_stmt *statement);
int _sqlite_exec_void(struct __sourceloc, int log_level, const char *sqltext, ...);
int _sqlite_exec_void_retry(struct __sourceloc, int log_level, sqlite_retry_state *retry, const char *sqltext, ...);
int _sqlite_exec_int64(struct __sourceloc, int64_t *result, const char *sqltext, ...);
int _sqlite_exec_int64_retry(struct __sourceloc, sqlite_retry_state *retry, int64_t *result, const char *sqltext, ...);
int _sqlite_exec_strbuf(struct __sourceloc, strbuf sb, const char *sqltext, ...);
int _sqlite_exec_strbuf_retry(struct __sourceloc, sqlite_retry_state *retry, strbuf sb, const char *sqltext, ...);
int _sqlite_vexec_strbuf_retry(struct __sourceloc, sqlite_retry_state *retry, strbuf sb, const char *sqltext, va_list ap);

// The 'arg' arguments in the following macros appear to be unnecessary, but
// they serve a very useful purpose, so don't remove them!  They ensure that
// programmers do not forget the bind args, of which there must be at least
// one, even if it is only 'END' to make no bindings at all.
#define sqlite_prepare(rs,sql)                          _sqlite_prepare(__WHENCE__, LOG_LEVEL_ERROR, (rs), (sql))
#define sqlite_prepare_loglevel(ll,rs,sql)              _sqlite_prepare(__WHENCE__, (ll), (rs), (sql))
#define sqlite_prepare_bind(rs,sql,arg,...)             _sqlite_prepare_bind(__WHENCE__, LOG_LEVEL_ERROR, (rs), (sql), arg, ##__VA_ARGS__)
#define sqlite_prepare_bind_loglevel(ll,rs,sql,arg,...) _sqlite_prepare_bind(__WHENCE__, (ll), (rs), (sql), arg, ##__VA_ARGS__)
#define sqlite_bind(rs,stmt,arg,...)                    _sqlite_bind(__WHENCE__, LOG_LEVEL_ERROR, (rs), (stmt), arg, ##__VA_ARGS__)
#define sqlite_bind_loglevel(ll,rs,stmt,arg,...)        _sqlite_bind(__WHENCE__, (ll), (rs), (stmt), arg, ##__VA_ARGS__)
#define sqlite_retry(rs,action)                         _sqlite_retry(__WHENCE__, (rs), (action))
#define sqlite_retry_done(rs,action)                    _sqlite_retry_done(__WHENCE__, (rs), (action))
#define sqlite_exec(stmt)                               _sqlite_exec(__WHENCE__, LOG_LEVEL_ERROR, NULL, (stmt))
#define sqlite_exec_retry(rs,stmt)                      _sqlite_exec(__WHENCE__, LOG_LEVEL_ERROR, (rs), (stmt))
#define sqlite_exec_retry_loglevel(ll,rs,stmt)          _sqlite_exec(__WHENCE__, (ll), (rs), (stmt))
#define sqlite_step(stmt)                               _sqlite_step(__WHENCE__, LOG_LEVEL_ERROR, NULL, (stmt))
#define sqlite_step_retry(rs,stmt)                      _sqlite_step(__WHENCE__, LOG_LEVEL_ERROR, (rs), (stmt))
#define sqlite_exec_void(sql,arg,...)                   _sqlite_exec_void(__WHENCE__, LOG_LEVEL_ERROR, (sql), arg, ##__VA_ARGS__)
#define sqlite_exec_void_loglevel(ll,sql,arg,...)       _sqlite_exec_void(__WHENCE__, (ll), (sql), arg, ##__VA_ARGS__)
#define sqlite_exec_void_retry(rs,sql,arg,...)          _sqlite_exec_void_retry(__WHENCE__, LOG_LEVEL_ERROR, (rs), (sql), arg, ##__VA_ARGS__)
#define sqlite_exec_void_retry_loglevel(ll,rs,sql,arg,...) _sqlite_exec_void_retry(__WHENCE__, (ll), (rs), (sql), arg, ##__VA_ARGS__)
#define sqlite_exec_int64(res,sql,arg,...)              _sqlite_exec_int64(__WHENCE__, (res), (sql), arg, ##__VA_ARGS__)
#define sqlite_exec_int64_retry(rs,res,sql,arg,...)     _sqlite_exec_int64_retry(__WHENCE__, (rs), (res), (sql), arg, ##__VA_ARGS__)
#define sqlite_exec_strbuf(sb,sql,arg,...)              _sqlite_exec_strbuf(__WHENCE__, (sb), (sql), arg, ##__VA_ARGS__)
#define sqlite_exec_strbuf_retry(rs,sb,sql,arg,...)     _sqlite_exec_strbuf_retry(__WHENCE__, (rs), (sb), (sql), arg, ##__VA_ARGS__)

double rhizome_manifest_get_double(rhizome_manifest *m,char *var,double default_value);
int rhizome_manifest_extract_signature(rhizome_manifest *m, unsigned *ofs);
int rhizome_update_file_priority(const char *fileid);
int rhizome_find_duplicate(const rhizome_manifest *m, rhizome_manifest **found);
int rhizome_manifest_to_bar(rhizome_manifest *m,unsigned char *bar);
int64_t rhizome_bar_version(const unsigned char *bar);
uint64_t rhizome_bar_bidprefix_ll(unsigned char *bar);
int rhizome_is_bar_interesting(unsigned char *bar);
int rhizome_is_manifest_interesting(rhizome_manifest *m);
int rhizome_retrieve_manifest(const rhizome_bid_t *bid, rhizome_manifest *m);
int rhizome_retrieve_manifest_by_prefix(const unsigned char *prefix, unsigned prefix_len, rhizome_manifest *m);
int rhizome_advertise_manifest(struct subscriber *dest, rhizome_manifest *m);
int rhizome_delete_bundle(const rhizome_bid_t *bidp);
int rhizome_delete_manifest(const rhizome_bid_t *bidp);
int rhizome_delete_payload(const rhizome_bid_t *bidp);
int rhizome_delete_file(const rhizome_filehash_t *hashp);

#define RHIZOME_DONTVERIFY 0
#define RHIZOME_VERIFY 1

int rhizome_fetching_get_fds(struct pollfd *fds,int *fdcount,int fdmax);
int monitor_announce_bundle(rhizome_manifest *m);
enum rhizome_secret_disposition {
    FOUND_RHIZOME_SECRET = 0,
    IDENTITY_NOT_FOUND,
    IDENTITY_HAS_NO_RHIZOME_SECRET,
};
enum rhizome_secret_disposition find_rhizome_secret(const sid_t *authorSidp, size_t *rs_len, const unsigned char **rs);
int rhizome_bk_xor_stream(
  const rhizome_bid_t *bidp,
  const unsigned char *rs,
  const size_t rs_len,
  unsigned char *xor_stream,
  int xor_stream_byte_count);
int rhizome_bk2secret(rhizome_manifest *m,
  const rhizome_bid_t *bidp,
  const unsigned char *rs, const size_t rs_len,
  /* The BK need only be the length of the secret half of the secret key */
  const unsigned char bkin[RHIZOME_BUNDLE_KEY_BYTES],
  unsigned char secret[crypto_sign_edwards25519sha512batch_SECRETKEYBYTES]
		      );
int rhizome_secret2bk(
  const rhizome_bid_t *bidp,
  const unsigned char *rs, const size_t rs_len,
  /* The BK need only be the length of the secret half of the secret key */
  unsigned char bkout[RHIZOME_BUNDLE_KEY_BYTES],
  const unsigned char secret[crypto_sign_edwards25519sha512batch_SECRETKEYBYTES]
);
unsigned char *rhizome_bundle_shared_secret(rhizome_manifest *m);
int rhizome_sign_hash_with_key(rhizome_manifest *m,const unsigned char *sk,
			       const unsigned char *pk,rhizome_signature *out);
int rhizome_verify_bundle_privatekey(const unsigned char *sk, const unsigned char *pk);
int rhizome_queue_ignore_manifest(unsigned char *bid_prefix, int prefix_len, int timeout);
int rhizome_ignore_manifest_check(unsigned char *bid_prefix, int prefix_len);

/* Rhizome list cursor for iterating over all or a subset of manifests in the store.
 */
struct rhizome_list_cursor {
  // Query parameters that narrow the set of listed bundles.
  const char *service;
  const char *name;
  bool_t is_sender_set;
  bool_t is_recipient_set;
  sid_t sender;
  sid_t recipient;
  // If set, then the cursor moves in ascending (chronological) order starting
  // from the first bundle with rowid > rowid_since.  If zero, then the cursor
  // moves in descending (reverse chronological) order starting from the most
  // recent bundle.
  uint64_t rowid_since;
  // Set by calling the next() function.
  rhizome_manifest *manifest;
  // Private state.
  sqlite3_stmt *_statement;
  uint64_t _rowid_current;
  uint64_t _rowid_last; // for re-opening query
};

int rhizome_list_open(sqlite_retry_state *, struct rhizome_list_cursor *);
int rhizome_list_next(sqlite_retry_state *, struct rhizome_list_cursor *);
void rhizome_list_commit(struct rhizome_list_cursor *);
void rhizome_list_release(struct rhizome_list_cursor *);

/* one manifest is required per candidate, plus a few spare.
   so MAX_RHIZOME_MANIFESTS must be > MAX_CANDIDATES. 
*/
#define MAX_RHIZOME_MANIFESTS 40
#define MAX_CANDIDATES 32

int rhizome_suggest_queue_manifest_import(rhizome_manifest *m, const struct sockaddr_in *peerip, const sid_t *peersidp);
rhizome_manifest * rhizome_fetch_search(const unsigned char *id, int prefix_length);

/* Rhizome file storage api */
struct rhizome_write_buffer
{
  struct rhizome_write_buffer *_next;
  uint64_t offset;
  size_t buffer_size;
  size_t data_size;
  unsigned char data[0];
};

struct rhizome_write
{
  rhizome_filehash_t id;
  uint64_t temp_id;
  char id_known;
  
  uint64_t tail;
  uint64_t file_offset;
  uint64_t written_offset;
  uint64_t file_length;
  struct rhizome_write_buffer *buffer_list;
  size_t buffer_size;
  
  int crypt;
  unsigned char key[RHIZOME_CRYPT_KEY_BYTES];
  unsigned char nonce[crypto_stream_xsalsa20_NONCEBYTES];
  
  SHA512_CTX sha512_context;
  int64_t blob_rowid;
  int blob_fd;
  sqlite3_blob *sql_blob;
};

struct rhizome_read_buffer{
  uint64_t offset;
  unsigned char data[RHIZOME_CRYPT_PAGE_SIZE];
  size_t len;
};

struct rhizome_read
{
  rhizome_filehash_t id;
  
  int crypt;
  unsigned char key[RHIZOME_CRYPT_KEY_BYTES];
  unsigned char nonce[crypto_stream_xsalsa20_NONCEBYTES];
  
  int64_t hash_offset;
  SHA512_CTX sha512_context;
  char invalid;
  
  int64_t blob_rowid;
  int blob_fd;
  
  uint64_t tail;
  uint64_t offset;
  uint64_t length;
};

/* Rhizome-specific HTTP request handling.
 */
typedef struct rhizome_http_request
{
  struct http_request http; // MUST BE FIRST ELEMENT

  /* Identify request from others being run.  Monotonic counter feeds it.  Only
   * used for debugging when we write post-<uuid>.log files for multi-part form
   * requests.
   */
  unsigned int uuid;

  /* For receiving a POST multipart form:
   */
  // Which part is currently being received
  enum rhizome_direct_mime_part { NONE = 0, MANIFEST, DATA } current_part;
  // Temporary file currently current part is being written to
  int part_fd;
  // Which parts have already been received
  bool_t received_manifest;
  bool_t received_data;
  // Name of data file supplied in part's Content-Disposition header, filename
  // parameter (if any)
  char data_file_name[MIME_FILENAME_MAXLEN + 1];

  union {
    /* For responses that send part or all of a payload.
    */
    struct rhizome_read read_state;

    /* For responses that list manifests.
    */
    struct {
        enum { LIST_HEADER = 0, LIST_ROWS, LIST_DONE } phase;
        uint64_t rowid_highest;
        size_t rowcount;
        time_ms_t end_time;
        struct rhizome_list_cursor cursor;
    } list;
  } u;
  
} rhizome_http_request;

int rhizome_received_content(const unsigned char *bidprefix,uint64_t version, 
			     uint64_t offset, size_t count,unsigned char *bytes,
			     int type);
int64_t rhizome_database_create_blob_for(const char *filehashhex_or_tempid,
					 int64_t fileLength,int priority);
int rhizome_server_set_response(rhizome_http_request *r, const struct http_response *h);
int rhizome_server_free_http_request(rhizome_http_request *r);
int rhizome_server_http_send_bytes(rhizome_http_request *r);
int rhizome_server_parse_http_request(rhizome_http_request *r);
int rhizome_server_simple_http_response(rhizome_http_request *r, int result, const char *response);
int rhizome_server_http_response(rhizome_http_request *r, int result, 
    const char *mime_type, const char *body, uint64_t bytes);
int rhizome_server_http_response_header(rhizome_http_request *r, int result, const char *mime_type, uint64_t bytes);
int rhizome_http_server_start(uint16_t port_low, uint16_t port_high);

int is_rhizome_enabled();
int is_rhizome_mdp_enabled();
int is_rhizome_http_enabled();
int is_rhizome_advertise_enabled();
int is_rhizome_mdp_server_running();
int is_rhizome_http_server_running();

typedef struct rhizome_direct_bundle_cursor {
  /* Where the current fill started */
  int64_t start_size_high;
  rhizome_bid_t start_bid_low;

  /* Limit of where this cursor may traverse */
  int64_t limit_size_high;
  rhizome_bid_t limit_bid_high;

  int64_t size_low;
  int64_t size_high;
  rhizome_bid_t bid_low;
  rhizome_bid_t bid_high;
  unsigned char *buffer;
  size_t buffer_size;
  size_t buffer_used;
  size_t buffer_offset_bytes;
} rhizome_direct_bundle_cursor;

rhizome_direct_bundle_cursor *rhizome_direct_bundle_iterator(size_t buffer_size);
void rhizome_direct_bundle_iterator_unlimit(rhizome_direct_bundle_cursor *r);
int rhizome_direct_bundle_iterator_pickle_range(rhizome_direct_bundle_cursor *r,
						unsigned char *pickled,
						int pickle_buffer_size);
rhizome_manifest *rhizome_direct_get_manifest(unsigned char *bid_prefix,int prefix_length);
int rhizome_direct_bundle_iterator_unpickle_range(rhizome_direct_bundle_cursor *r,
						  const unsigned char *pickled,
						  int pickle_buffer_size);
int rhizome_direct_bundle_iterator_fill(rhizome_direct_bundle_cursor *c,
					int max_bars);
void rhizome_direct_bundle_iterator_free(rhizome_direct_bundle_cursor **c);
int rhizome_direct_get_bars(const rhizome_bid_t *bid_low,
			    rhizome_bid_t *bid_high,
			    int64_t size_low, int64_t size_high,
			    const rhizome_bid_t *bid_max,
			    unsigned char *bars_out,
			    int bars_requested);
int rhizome_direct_process_post_multipart_bytes
(rhizome_http_request *r,const char *bytes,int count);

typedef struct rhizome_direct_sync_request {
  struct sched_ent alarm;
  rhizome_direct_bundle_cursor *cursor;

  int pushP;
  int pullP;

  /* Sync interval in seconds.  zero = sync only once */
  int interval;

  /* The dispatch function will be called each time a sync request can
     be sent off, i.e., one cursor->buffer full of data.
     Will differ based on underlying transport. HTTP is the initial 
     supported transport, but deLorme inReach will likely follow soon after.
  */
  void (*dispatch_function)(struct rhizome_direct_sync_request *);

  /* General purpose pointer for transport-dependent state */
  void *transport_specific_state;

  /* Statistics.
     Each sync will consist of one or more "fills" of the cursor buffer, which 
     will then be dispatched by the transport-specific dispatch function.
     Each of those dispatches may then result in zero or 
   */
  int syncs_started;
  int syncs_completed;
  int fills_sent;
  int fill_responses_processed;
  int bundles_pushed;
  int bundles_pulled;
  int bundle_transfers_in_progress;

} rhizome_direct_sync_request;

#define RHIZOME_DIRECT_MAX_SYNC_HANDLES 16
extern rhizome_direct_sync_request *rd_sync_handles[RHIZOME_DIRECT_MAX_SYNC_HANDLES];
extern int rd_sync_handle_count;

rhizome_direct_sync_request
*rhizome_direct_new_sync_request(
				 void (*transport_specific_dispatch_function)
				 (struct rhizome_direct_sync_request *),
				 size_t buffer_size, int interval, int mode, 
				 void *transport_specific_state);
int rhizome_direct_continue_sync_request(rhizome_direct_sync_request *r);
int rhizome_direct_conclude_sync_request(rhizome_direct_sync_request *r);
rhizome_direct_bundle_cursor *rhizome_direct_get_fill_response
(unsigned char *buffer,int size,int max_response_bytes);

typedef struct rhizome_direct_transport_state_http {
  int port;
  char host[1024];  
} rhizome_direct_transport_state_http;

void rhizome_direct_http_dispatch(rhizome_direct_sync_request *);

extern unsigned char favicon_bytes[];
extern int favicon_len;

int rhizome_import_from_files(const char *manifestpath,const char *filepath);

enum rhizome_start_fetch_result {
  STARTED = 0,
  SAMEBUNDLE,
  SAMEPAYLOAD,
  SUPERSEDED,
  OLDERBUNDLE,
  NEWERBUNDLE,
  IMPORTED,
  SLOTBUSY
};

enum rhizome_start_fetch_result rhizome_fetch_request_manifest_by_prefix(const struct sockaddr_in *peerip, const sid_t *sidp, const unsigned char *prefix, size_t prefix_length);
int rhizome_any_fetch_active();
int rhizome_any_fetch_queued();
int rhizome_fetch_status_html(struct strbuf *b);
int rhizome_fetch_has_queue_space(unsigned char log2_size);

struct http_response_parts {
  uint16_t code;
  char *reason;
  uint64_t range_start;
  uint64_t content_length;
  char *content_start;
};

int unpack_http_response(char *response, struct http_response_parts *parts);

/* rhizome storage methods */

int rhizome_exists(const rhizome_filehash_t *hashp);
int rhizome_open_write(struct rhizome_write *write, const rhizome_filehash_t *expectedHashp, uint64_t file_length, int priority);
int rhizome_write_buffer(struct rhizome_write *write_state, unsigned char *buffer, size_t data_size);
int rhizome_random_write(struct rhizome_write *write_state, uint64_t offset, unsigned char *buffer, size_t data_size);
int rhizome_write_open_manifest(struct rhizome_write *write, rhizome_manifest *m);
int rhizome_write_file(struct rhizome_write *write, const char *filename);
int rhizome_fail_write(struct rhizome_write *write);
int rhizome_finish_write(struct rhizome_write *write);
int rhizome_import_file(rhizome_manifest *m, const char *filepath);
int rhizome_import_buffer(rhizome_manifest *m, unsigned char *buffer, size_t length);
int rhizome_stat_file(rhizome_manifest *m, const char *filepath);
int rhizome_add_file(rhizome_manifest *m, const char *filepath);
int rhizome_derive_payload_key(rhizome_manifest *m);

int rhizome_append_journal_buffer(rhizome_manifest *m, uint64_t advance_by, unsigned char *buffer, size_t len);
int rhizome_append_journal_file(rhizome_manifest *m, uint64_t advance_by, const char *filename);
int rhizome_journal_pipe(struct rhizome_write *write, const rhizome_filehash_t *hashp, uint64_t start_offset, uint64_t length);

int rhizome_crypt_xor_block(unsigned char *buffer, size_t buffer_size, uint64_t stream_offset, 
			    const unsigned char *key, const unsigned char *nonce);
int rhizome_open_read(struct rhizome_read *read, const rhizome_filehash_t *hashp);
ssize_t rhizome_read(struct rhizome_read *read, unsigned char *buffer, size_t buffer_length);
ssize_t rhizome_read_buffered(struct rhizome_read *read, struct rhizome_read_buffer *buffer, unsigned char *data, size_t len);
int rhizome_read_close(struct rhizome_read *read);
int rhizome_open_decrypt_read(rhizome_manifest *m, struct rhizome_read *read_state);
int rhizome_extract_file(rhizome_manifest *m, const char *filepath);
int rhizome_dump_file(const rhizome_filehash_t *hashp, const char *filepath, int64_t *length);
int rhizome_read_cached(const rhizome_bid_t *bid, uint64_t version, time_ms_t timeout, 
  uint64_t fileOffset, unsigned char *buffer, size_t length);
int rhizome_cache_close();

int rhizome_database_filehash_from_id(const rhizome_bid_t *bidp, uint64_t version, rhizome_filehash_t *hashp);

int overlay_mdp_service_rhizome_sync(struct overlay_frame *frame, overlay_mdp_frame *mdp);
int rhizome_sync_announce();
int rhizome_sync_bundle_inserted(const unsigned char *bar);

#endif //__SERVALDNA__RHIZOME_H
