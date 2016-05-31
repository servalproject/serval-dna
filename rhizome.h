/*
Serval DNA Rhizome file distribution
Copyright (C) 2010-2014 Serval Project Inc.
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

#ifndef __SERVAL_DNA__RHIZOME_H
#define __SERVAL_DNA__RHIZOME_H

#include <sqlite3.h>
#include "serval_types.h"
#include "rhizome_types.h"
#include "overlay_address.h"
#include "overlay_packet.h"
#include "fdqueue.h"
#include "os.h"
#include "uuid.h"
#include "str.h"
#include "strbuf.h"
#include "trigger.h"

#ifndef __RHIZOME_INLINE
# if __GNUC__ && !__GNUC_STDC_INLINE__
#  define __RHIZOME_INLINE extern inline
# else
#  define __RHIZOME_INLINE inline
# endif
#endif

// assumed to always be 2^n
#define RHIZOME_CRYPT_PAGE_SIZE         4096

extern time_ms_t rhizome_voice_timeout;

#define RHIZOME_IDLE_TIMEOUT 20000

#define RHIZOME_BAR_COMPARE_BYTES 31
#define RHIZOME_BAR_TTL_OFFSET 31

#define MAX_MANIFEST_VARS 256
#define MAX_MANIFEST_BYTES 8192
#define MAX_MANIFEST_FIELD_LABEL_LEN 80

typedef struct rhizome_manifest
{

  /* CryptoSign key pair for this manifest.  The public key is the Bundle ID
   * (aka Manifest ID).
   */
  rhizome_bid_t cryptoSignPublic;
  unsigned char cryptoSignSecret[crypto_sign_SECRETKEYBYTES];

  /* Whether cryptoSignSecret is correct (ie, bundle secret is known)
   */
  enum { SECRET_UNKNOWN = 0, EXISTING_BUNDLE_ID, NEW_BUNDLE_ID } haveSecret;

  /* Version of the manifest.  Typically the number of milliseconds since 1970.
   * A value of zero (0) means it has not been set yet.
   */
  uint64_t version;

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

  /* Set to non-NULL if a manifest has been parsed that cannot be fully
   * understood by this version of Rhizome (probably from a future or a very
   * old past version of Rhizome).  During add (local injection), the manifest
   * should not be imported.  During extract (local decode) a warning or error
   * message should be logged.  Manifests marked as malformed are still
   * transported, imported and exported normally, as long as their signature is
   * valid.
   */
  const char *malformed;

  /* Set non-zero after variables have been packed and signature blocks
   * appended.  All fields below may not be valid until the manifest has been
   * finalised.
   */
  bool_t finalised:1;

  /* Whether the manifest contains a signature that corresponds to the manifest
   * id (ie public key).
   */
  bool_t selfSigned:1;

  /* Set if the ID field (cryptoSignPublic) contains a bundle ID.
   */
  bool_t has_id:1;

  /* Set if the filehash field contains a file hash.
   */
  bool_t has_filehash:1;

  /* Set if the tail field is valid, ie, the bundle is a journal.
   */
  bool_t is_journal:1;

  /* Set if the date field is valid, ie, the manifest contains a valid "date"
   * field.
   */
  bool_t has_date:1;

  /* Set if the bundle_key field is valid, ie, the manifest contains a valid
   * "BK" field.
   */
  bool_t has_bundle_key:1;

  /* Set if the sender and recipient fields are valid, ie, the manifest
   * contains a valid "sender"/"recipient" field.
   */
  bool_t has_sender:1;
  bool_t has_recipient:1;

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

  /* Whether the paylaod is encrypted or not */
  enum rhizome_manifest_crypt {
        PAYLOAD_CRYPT_UNKNOWN = 0,
        PAYLOAD_CLEAR,
        PAYLOAD_ENCRYPTED
    } payloadEncryption;
  unsigned char payloadKey[RHIZOME_CRYPT_KEY_BYTES];
  unsigned char payloadNonce[crypto_box_NONCEBYTES];

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
  const struct keyring_identity *author_identity;

  size_t manifest_body_bytes;
  size_t manifest_all_bytes;
  unsigned char manifestdata[MAX_MANIFEST_BYTES];
  rhizome_filehash_t manifesthash;

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
#define rhizome_manifest_del_version(m)         _rhizome_manifest_del_version(__WHENCE__,(m))
#define rhizome_manifest_set_filesize(m,v)      _rhizome_manifest_set_filesize(__WHENCE__,(m),(v))
#define rhizome_manifest_del_filesize(m)        _rhizome_manifest_del_filesize(__WHENCE__,(m))
#define rhizome_manifest_set_filehash(m,v)      _rhizome_manifest_set_filehash(__WHENCE__,(m),(v))
#define rhizome_manifest_del_filehash(m)        _rhizome_manifest_del_filehash(__WHENCE__,(m))
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
#define rhizome_manifest_set_author(m,v)        _rhizome_manifest_set_author(__WHENCE__,(m),NULL,(v))
#define rhizome_manifest_set_author_identity(m,v) _rhizome_manifest_set_author(__WHENCE__,(m),(v),NULL)
#define rhizome_manifest_del_author(m)          _rhizome_manifest_del_author(__WHENCE__,(m))

void _rhizome_manifest_set_id(struct __sourceloc, rhizome_manifest *, const rhizome_bid_t *);
void _rhizome_manifest_set_version(struct __sourceloc, rhizome_manifest *, uint64_t);
void _rhizome_manifest_del_version(struct __sourceloc, rhizome_manifest *);
void _rhizome_manifest_set_filesize(struct __sourceloc, rhizome_manifest *, uint64_t);
void _rhizome_manifest_del_filesize(struct __sourceloc, rhizome_manifest *);
void _rhizome_manifest_set_filehash(struct __sourceloc, rhizome_manifest *, const rhizome_filehash_t *);
void _rhizome_manifest_del_filehash(struct __sourceloc, rhizome_manifest *);
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
void _rhizome_manifest_set_author(struct __sourceloc, rhizome_manifest *, const struct keyring_identity *, const sid_t *);
void _rhizome_manifest_del_author(struct __sourceloc, rhizome_manifest *);

#define rhizome_manifest_overwrite(dstm,srcm)   _rhizome_manifest_overwrite(__WHENCE__,(dstm),(srcm))

int _rhizome_manifest_overwrite(struct __sourceloc, rhizome_manifest *m, const rhizome_manifest *srcm);

enum rhizome_manifest_parse_status {
    RHIZOME_MANIFEST_ERROR = -1,          // unrecoverable error while constructing manifest
    RHIZOME_MANIFEST_OK = 0,              // field parsed ok; manifest updated
    RHIZOME_MANIFEST_SYNTAX_ERROR = 1,    // field label violates syntax
    RHIZOME_MANIFEST_DUPLICATE_FIELD = 2, // field is already set in manifest
    RHIZOME_MANIFEST_INVALID = 3,         // core field value does not parse
    RHIZOME_MANIFEST_MALFORMED = 4,       // non-core field value does not parse
    RHIZOME_MANIFEST_OVERFLOW = 5,        // maximum field count exceeded
};

/* This structure represents a manifest field assignment as received by the API
 * operations "add file" or "journal append" or any other operation that takes an
 * existing manifest and modifies it to produce a new one.
 *
 * The 'label' and 'value' strings are pointer-length instead of NUL terminated,
 * to allow them to refer directly to fragments of an existing, larger text
 * without requiring the caller to allocate new strings to hold them.
 */
struct rhizome_manifest_field_assignment {
    const char *label;
    size_t labellen;
    const char *value;
    size_t valuelen;
};

int rhizome_manifest_field_label_is_valid(const char *field_label, size_t field_label_len);
int rhizome_manifest_field_value_is_valid(const char *field_value, size_t field_value_len);
enum rhizome_manifest_parse_status
    rhizome_manifest_parse_field(rhizome_manifest *m,
                                 const char *field_label, size_t field_label_len,
                                 const char *field_value, size_t field_value_len);
int rhizome_manifest_remove_field(rhizome_manifest *, const char *field_label, size_t field_label_len);

/* Supported service identifiers.  These go in the 'service' field of every
 * manifest, and indicate which application must be used to process the bundle
 * after it is received by Rhizome.
 */
#define     RHIZOME_SERVICE_FILE    "file"
#define     RHIZOME_SERVICE_MESHMS  "MeshMS1"
#define     RHIZOME_SERVICE_MESHMS2  "MeshMS2"

extern int64_t rhizome_space;

int log2ll(uint64_t x);
int rhizome_configure();
int rhizome_enabled();
int rhizome_fetch_delay_ms();

#define RHIZOME_BLOB_SUBDIR "blob"
#define RHIZOME_HASH_SUBDIR "hash"

extern __thread sqlite3 *rhizome_db;
serval_uuid_t rhizome_db_uuid;

int rhizome_opendb();
int rhizome_close_db();
void verify_bundles();

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

struct rhizome_cleanup_report {
    unsigned deleted_stale_incoming_files;
    unsigned deleted_expired_files;
    unsigned deleted_orphan_files;
    unsigned deleted_orphan_fileblobs;
    unsigned deleted_orphan_manifests;
};

int rhizome_cleanup(struct rhizome_cleanup_report *report);
int rhizome_store_cleanup(struct rhizome_cleanup_report *report);
void rhizome_vacuum_db(sqlite_retry_state *retry);
int rhizome_manifest_createid(rhizome_manifest *m);
int rhizome_get_bundle_from_seed(rhizome_manifest *m, const char *seed);
int rhizome_get_bundle_from_secret(rhizome_manifest *m, const rhizome_bk_t *bsk);
void rhizome_new_bundle_from_secret(rhizome_manifest *m, const rhizome_bk_t *bsk);

struct rhizome_manifest_summary {
  rhizome_bid_t bid;
  uint64_t version;
  size_t body_len;
};

int rhizome_manifest_inspect(const char *buf, size_t len, struct rhizome_manifest_summary *summ);

enum rhizome_bundle_status {
    RHIZOME_BUNDLE_STATUS_ERROR = -1,
    RHIZOME_BUNDLE_STATUS_NEW = 0, // bundle is newer than store
    RHIZOME_BUNDLE_STATUS_SAME = 1, // same version already in store
    RHIZOME_BUNDLE_STATUS_DUPLICATE = 2, // equivalent bundle already in store
    RHIZOME_BUNDLE_STATUS_OLD = 3, // newer version already in store
    RHIZOME_BUNDLE_STATUS_INVALID = 4, // manifest is invalid
    RHIZOME_BUNDLE_STATUS_FAKE = 5, // manifest signature not valid
    RHIZOME_BUNDLE_STATUS_INCONSISTENT = 6, // manifest filesize/filehash does not match supplied payload
    RHIZOME_BUNDLE_STATUS_NO_ROOM = 7, // doesn't fit; store may contain more important bundles
    RHIZOME_BUNDLE_STATUS_READONLY = 8, // cannot modify manifest; secret unknown
    RHIZOME_BUNDLE_STATUS_BUSY = 9, // the database is currently busy
    RHIZOME_BUNDLE_STATUS_MANIFEST_TOO_BIG = 10, // manifest + signature exceeds size limit
};

// Useful for initialising a variable then checking later that it was set to a
// valid value (typically FATAL if not).
#define INVALID_RHIZOME_BUNDLE_STATUS ((enum rhizome_bundle_status)-2)

const char *rhizome_bundle_status_message(enum rhizome_bundle_status);
const char *rhizome_bundle_status_message_nonnull(enum rhizome_bundle_status);

// Encapsulate a status enum value and an optional text message to assist with
// diagnostics.  Useful as a return value from functions that can fail in all
// sorts of ways.
struct rhizome_bundle_result {
    enum rhizome_bundle_status status;
    const char *message;
    void (*free)(void *); // call r.free(r.message) before destroying r
};

#define INVALID_RHIZOME_BUNDLE_RESULT ((struct rhizome_bundle_result){ .status = INVALID_RHIZOME_BUNDLE_STATUS, .message = NULL, .free = NULL })

// Call this before discarding a struct rhizome_bundle_result.
void rhizome_bundle_result_free(struct rhizome_bundle_result *);

// Convenience functions for constructing a struct rhizome_bundle_result and
// logging errors and debug messages in the process.
struct rhizome_bundle_result _rhizome_bundle_result(struct __sourceloc, enum rhizome_bundle_status);
struct rhizome_bundle_result _rhizome_bundle_result_static(struct __sourceloc, enum rhizome_bundle_status, const char *);
struct rhizome_bundle_result _rhizome_bundle_result_strdup(struct __sourceloc, enum rhizome_bundle_status, const char *);
struct rhizome_bundle_result _rhizome_bundle_result_sprintf(struct __sourceloc, enum rhizome_bundle_status, const char *fmt, ...);

#define rhizome_bundle_result(status)                   _rhizome_bundle_result(__WHENCE__, status)
#define rhizome_bundle_result_static(status, str)       _rhizome_bundle_result_static(__WHENCE__, status, str)
#define rhizome_bundle_result_strdup(status, str)       _rhizome_bundle_result_strdup(__WHENCE__, status, str)
#define rhizome_bundle_result_sprintf(status, fmt, ...) _rhizome_bundle_result_sprintf(__WHENCE__, status, fmt, ## __VA_ARGS__);

// Functions for extracting information from a struct rhizome_bundle_result.
const char *rhizome_bundle_result_message(struct rhizome_bundle_result); // NULL only if invalid
const char *rhizome_bundle_result_message_nonnull(struct rhizome_bundle_result);

// Function to assist logging struct rhizome_bundle_result.
#define alloca_rhizome_bundle_result(result)            strbuf_str(strbuf_append_rhizome_bundle_result(strbuf_alloca(50 + (result.message ? strlen(result.message) : 0)), result))
strbuf strbuf_append_rhizome_bundle_result(strbuf, struct rhizome_bundle_result);

enum rhizome_payload_status {
    RHIZOME_PAYLOAD_STATUS_ERROR = -1,
    RHIZOME_PAYLOAD_STATUS_EMPTY = 0, // payload is empty (zero length)
    RHIZOME_PAYLOAD_STATUS_NEW = 1, // payload is not yet in store (added)
    RHIZOME_PAYLOAD_STATUS_STORED = 2, // payload is already in store
    RHIZOME_PAYLOAD_STATUS_WRONG_SIZE = 3, // payload's size does not match manifest
    RHIZOME_PAYLOAD_STATUS_WRONG_HASH = 4, // payload's hash does not match manifest
    RHIZOME_PAYLOAD_STATUS_CRYPTO_FAIL = 5, // cannot encrypt/decrypt (payload key unknown)
    RHIZOME_PAYLOAD_STATUS_TOO_BIG = 6, // payload will never fit in our store
    RHIZOME_PAYLOAD_STATUS_EVICTED = 7, // other payloads in our store are more important
};

// Useful for initialising a variable then checking later that it was set to a
// valid value (typically FATAL if not).
#define INVALID_RHIZOME_PAYLOAD_STATUS ((enum rhizome_payload_status)-2)

const char *rhizome_payload_status_message(enum rhizome_payload_status);
const char *rhizome_payload_status_message_nonnull(enum rhizome_payload_status);

int rhizome_write_manifest_file(rhizome_manifest *m, const char *filename, char append);
int rhizome_read_manifest_from_file(rhizome_manifest *m, const char *filename);
int rhizome_manifest_validate(rhizome_manifest *m);
const char *rhizome_manifest_validate_reason(rhizome_manifest *m);
int rhizome_manifest_parse(rhizome_manifest *m);
int rhizome_manifest_verify(rhizome_manifest *m);

int rhizome_hash_file(rhizome_manifest *m, const char *path, rhizome_filehash_t *hash_out, uint64_t *size_out);

void _rhizome_manifest_free(struct __sourceloc, rhizome_manifest *m);
#define rhizome_manifest_free(m) _rhizome_manifest_free(__WHENCE__,m)
rhizome_manifest *_rhizome_new_manifest(struct __sourceloc);
#define rhizome_new_manifest() _rhizome_new_manifest(__WHENCE__)

int rhizome_store_manifest(rhizome_manifest *m);
int rhizome_store_file(rhizome_manifest *m,const unsigned char *key);

struct rhizome_bundle_result rhizome_manifest_add_file(int appending,
                                                       rhizome_manifest *m,
                                                       rhizome_manifest **mout,
                                                       const rhizome_bid_t *bid,
                                                       const rhizome_bk_t *bsk,
                                                       const sid_t *author,
                                                       const char *file_path,
                                                       unsigned nassignments,
                                                       const struct rhizome_manifest_field_assignment *assignments);
int rhizome_bundle_import_files(rhizome_manifest *m, rhizome_manifest **m_out, const char *manifest_path, const char *filepath, int zip_files);

int rhizome_manifest_set_name_from_path(rhizome_manifest *m, const char *filepath);
struct rhizome_bundle_result rhizome_fill_manifest(rhizome_manifest *m, const char *filepath);

int rhizome_apply_bundle_secret(rhizome_manifest *, const rhizome_bk_t *);
int rhizome_manifest_add_bundle_key(rhizome_manifest *);

int rhizome_lookup_author(rhizome_manifest *m);
void rhizome_authenticate_author(rhizome_manifest *m);

struct rhizome_bundle_result rhizome_manifest_finalise(rhizome_manifest *m, rhizome_manifest **m_out, int deduplicate);
enum rhizome_bundle_status rhizome_manifest_check_stored(rhizome_manifest *m, rhizome_manifest **m_out);
enum rhizome_bundle_status rhizome_add_manifest_to_store(rhizome_manifest *m_in, rhizome_manifest **m_out);

void rhizome_bytes_to_hex_upper(unsigned const char *in, char *out, int byteCount);
int rhizome_find_privatekey(rhizome_manifest *m);

__RHIZOME_INLINE int sqlite_code_ok(int code)
{
  return code == SQLITE_OK || code == SQLITE_DONE || code == SQLITE_ROW;
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
  RHIZOME_BAR_T,      // const rhizome_bar_t *barp
  RHIZOME_FILEHASH_T, // const rhizome_filehash_t *hashp
  TOHEX,              // const unsigned char *binary, unsigned bytes
  TEXT_TOUPPER,       // const char *text,
  TEXT_LEN_TOUPPER,   // const char *text, unsigned bytes
  SERVAL_UUID_T,      // const serval_uuid_t *uuidp
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
int _sqlite_exec(struct __sourceloc __whence, int log_level, sqlite_retry_state *retry, sqlite3_stmt *statement);
int _sqlite_exec_void(struct __sourceloc, int log_level, const char *sqltext, ...);
int _sqlite_exec_void_retry(struct __sourceloc, int log_level, sqlite_retry_state *retry, const char *sqltext, ...);
int _sqlite_exec_changes_retry(struct __sourceloc __whence, int log_level, sqlite_retry_state *retry, int *rowcount, int *changes, const char *sqltext, ...);
int _sqlite_exec_uint64(struct __sourceloc, uint64_t *result, const char *sqltext, ...);
int _sqlite_exec_uint64_retry(struct __sourceloc, sqlite_retry_state *retry, uint64_t *result, const char *sqltext, ...);
int _sqlite_exec_strbuf(struct __sourceloc, strbuf sb, const char *sqltext, ...);
int _sqlite_exec_strbuf_retry(struct __sourceloc, sqlite_retry_state *retry, strbuf sb, const char *sqltext, ...);
int _sqlite_vexec_strbuf_retry(struct __sourceloc, sqlite_retry_state *retry, strbuf sb, const char *sqltext, va_list ap);
int _sqlite_blob_open_retry(
  struct __sourceloc,
  int log_level,
  sqlite_retry_state *retry,
  const char *dbname,
  const char *tablename,
  const char *colname,
  sqlite3_int64 rowid,
  int flags,
  sqlite3_blob **blobp
);
int _sqlite_blob_write_retry(
  struct __sourceloc,
  int log_level,
  sqlite_retry_state *retry,
  sqlite3_blob *blob,
  const void *buf,
  int len,
  int offset
);
int _sqlite_blob_close(struct __sourceloc, int log_level, sqlite3_blob *blob);

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
#define sqlite_exec_changes_retry(rs,ROWS,CHANGES,sql,arg,...) _sqlite_exec_changes_retry(__WHENCE__, LOG_LEVEL_ERROR, (rs), (ROWS), (CHANGES), (sql), arg, ##__VA_ARGS__)
#define sqlite_exec_changes_retry_loglevel(ll,rs,ROWS,CHANGES,sql,arg,...) _sqlite_exec_changes_retry(__WHENCE__, (ll), (rs), (ROWS), (CHANGES), (sql), arg, ##__VA_ARGS__)
#define sqlite_exec_void_retry_loglevel(ll,rs,sql,arg,...) _sqlite_exec_void_retry(__WHENCE__, (ll), (rs), (sql), arg, ##__VA_ARGS__)
#define sqlite_exec_uint64(res,sql,arg,...)             _sqlite_exec_uint64(__WHENCE__, (res), (sql), arg, ##__VA_ARGS__)
#define sqlite_exec_uint64_retry(rs,res,sql,arg,...)    _sqlite_exec_uint64_retry(__WHENCE__, (rs), (res), (sql), arg, ##__VA_ARGS__)
#define sqlite_exec_strbuf(sb,sql,arg,...)              _sqlite_exec_strbuf(__WHENCE__, (sb), (sql), arg, ##__VA_ARGS__)
#define sqlite_exec_strbuf_retry(rs,sb,sql,arg,...)     _sqlite_exec_strbuf_retry(__WHENCE__, (rs), (sb), (sql), arg, ##__VA_ARGS__)
#define sqlite_blob_open_retry(rs,db,table,col,row,flags,blobp) \
                                                        _sqlite_blob_open_retry(__WHENCE__, LOG_LEVEL_ERROR, (rs), (db), (table), (col), (row), (flags), (blobp))
#define sqlite_blob_close(blob)                         _sqlite_blob_close(__WHENCE__, LOG_LEVEL_ERROR, (blob));
#define sqlite_blob_write_retry(rs,blob,buf,siz,off)    _sqlite_blob_write_retry(__WHENCE__, LOG_LEVEL_ERROR, (rs), (blob), (buf), (siz), (off))

double rhizome_manifest_get_double(rhizome_manifest *m,char *var,double default_value);
int rhizome_manifest_extract_signature(rhizome_manifest *m, unsigned *ofs);
enum rhizome_bundle_status rhizome_find_duplicate(const rhizome_manifest *m, rhizome_manifest **found);
int rhizome_manifest_to_bar(rhizome_manifest *m, rhizome_bar_t *bar);
int rhizome_is_bar_interesting(const rhizome_bar_t *bar);
int rhizome_is_manifest_interesting(rhizome_manifest *m);
enum rhizome_bundle_status rhizome_retrieve_manifest(const rhizome_bid_t *bid, rhizome_manifest *m);
enum rhizome_bundle_status rhizome_retrieve_manifest_by_prefix(const unsigned char *prefix, unsigned prefix_len, rhizome_manifest *m);
enum rhizome_bundle_status rhizome_retrieve_manifest_by_hash_prefix(const uint8_t *prefix, unsigned prefix_len, rhizome_manifest *m);
enum rhizome_bundle_status rhizome_retrieve_bar_by_hash_prefix(const uint8_t *prefix, unsigned prefix_len, rhizome_bar_t *bar);
int rhizome_advertise_manifest(struct subscriber *dest, rhizome_manifest *m);
int rhizome_mdp_send_block(struct subscriber *dest, const rhizome_bid_t *bid, uint64_t version, uint64_t fileOffset, uint32_t bitmap, uint16_t blockLength);
int rhizome_delete_bundle(const rhizome_bid_t *bidp);
int rhizome_delete_manifest(const rhizome_bid_t *bidp);
int rhizome_delete_payload(const rhizome_bid_t *bidp);
int rhizome_delete_file_id(const char *id);
int rhizome_delete_file(const rhizome_filehash_t *hashp);

#define RHIZOME_DONTVERIFY 0
#define RHIZOME_VERIFY 1

int rhizome_fetching_get_fds(struct pollfd *fds,int *fdcount,int fdmax);
int rhizome_bk2secret(
  const rhizome_bid_t *bidp,
  const unsigned char *rs, const size_t rs_len,
  /* The BK need only be the length of the secret half of the secret key */
  const unsigned char bkin[RHIZOME_BUNDLE_KEY_BYTES],
  unsigned char secret[crypto_sign_SECRETKEYBYTES]
		      );
int rhizome_secret2bk(
  const rhizome_bid_t *bidp,
  const unsigned char *rs, const size_t rs_len,
  /* The BK need only be the length of the secret half of the secret key */
  unsigned char bkout[RHIZOME_BUNDLE_KEY_BYTES],
  const unsigned char secret[crypto_sign_SECRETKEYBYTES]
);
int rhizome_verify_bundle_privatekey(const unsigned char *sk, const unsigned char *pk);
int rhizome_queue_ignore_manifest(const unsigned char *bid_prefix, int prefix_len, int timeout);
int rhizome_ignore_manifest_check(const unsigned char *bid_prefix, int prefix_len);

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
  // Private state - implementation that could change.
  sqlite_retry_state _retry;
  sqlite3_stmt *_statement;
  uint64_t _rowid_current;
  uint64_t _rowid_last; // for re-opening query
};

int rhizome_list_open(struct rhizome_list_cursor *);
int rhizome_list_next(struct rhizome_list_cursor *);
void rhizome_list_commit(struct rhizome_list_cursor *);
void rhizome_list_release(struct rhizome_list_cursor *);

#define MAX_CANDIDATES 32

int rhizome_suggest_queue_manifest_import(rhizome_manifest *m, const struct socket_address *addr, const struct subscriber *peer);
rhizome_manifest * rhizome_fetch_search(const unsigned char *id, int prefix_length);
int rhizome_fetch_bar_queued(const rhizome_bar_t *bar);

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
  uint64_t temp_id;
  uint64_t tail;
  uint64_t file_offset;
  uint64_t written_offset;
  uint64_t file_length;
  struct rhizome_write_buffer *buffer_list;
  size_t buffer_size;
  
  struct crypto_hash_sha512_state sha512_context;
  uint64_t blob_rowid;
  int blob_fd;
  sqlite3_blob *sql_blob;
  
  rhizome_filehash_t id;
  uint8_t id_known:1;
  uint8_t crypt:1;
  uint8_t journal:1;

  unsigned char key[RHIZOME_CRYPT_KEY_BYTES];
  unsigned char nonce[crypto_box_NONCEBYTES];
};

struct rhizome_read_buffer{
  uint64_t offset;
  unsigned char data[RHIZOME_CRYPT_PAGE_SIZE];
  size_t len;
};

struct rhizome_read
{
  uint64_t hash_offset;
  struct crypto_hash_sha512_state sha512_context;
  
  uint64_t blob_rowid;
  int blob_fd;
  
  uint64_t tail;
  uint64_t offset;
  uint64_t length;
  
  int8_t verified;
  uint8_t crypt;
  rhizome_filehash_t id;
  unsigned char key[RHIZOME_CRYPT_KEY_BYTES];
  unsigned char nonce[crypto_box_NONCEBYTES];
};

int rhizome_received_content(const unsigned char *bidprefix,uint64_t version, 
			     uint64_t offset, size_t count,unsigned char *bytes);

int is_rhizome_enabled();
int is_rhizome_mdp_enabled();
int is_rhizome_http_enabled();
int is_rhizome_advertise_enabled();
int is_rhizome_mdp_server_running();

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
rhizome_manifest *rhizome_direct_get_manifest(unsigned char *bid_prefix, size_t prefix_length);
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
  DONOTWANT,
  IMPORTED,
  SLOTBUSY
};

enum rhizome_start_fetch_result
rhizome_fetch_request_manifest_by_prefix(const struct socket_address *addr, 
					 const struct subscriber *peer,
					 const unsigned char *prefix, size_t prefix_length);
int rhizome_any_fetch_active();
int rhizome_any_fetch_queued();
int rhizome_fetch_status_html(struct strbuf *b);
int rhizome_fetch_has_queue_space(unsigned char log2_size);

/* Rhizome storage methods */

int rhizome_exists(const rhizome_filehash_t *hashp);
enum rhizome_payload_status rhizome_open_write(struct rhizome_write *write, const rhizome_filehash_t *expectedHashp, uint64_t file_length);
int rhizome_write_buffer(struct rhizome_write *write_state, uint8_t *buffer, size_t data_size);
int rhizome_random_write(struct rhizome_write *write_state, uint64_t offset, uint8_t *buffer, size_t data_size);
enum rhizome_payload_status rhizome_write_open_manifest(struct rhizome_write *write, rhizome_manifest *m);
enum rhizome_payload_status rhizome_write_open_journal(struct rhizome_write *write, rhizome_manifest *m, uint64_t advance_by, uint64_t append_size);
int rhizome_write_file(struct rhizome_write *write, const char *filename, off_t offset, uint64_t length);
void rhizome_fail_write(struct rhizome_write *write);
enum rhizome_payload_status rhizome_finish_write(struct rhizome_write *write);
enum rhizome_payload_status rhizome_finish_store(struct rhizome_write *write, rhizome_manifest *m, enum rhizome_payload_status status);
enum rhizome_payload_status rhizome_import_payload_from_file(rhizome_manifest *m, const char *filepath);
enum rhizome_payload_status rhizome_import_buffer(rhizome_manifest *m, uint8_t *buffer, size_t length);
enum rhizome_payload_status rhizome_stat_payload_file(rhizome_manifest *m, const char *filepath);
enum rhizome_payload_status rhizome_store_payload_file(rhizome_manifest *m, const char *filepath);
int rhizome_derive_payload_key(rhizome_manifest *m);

enum rhizome_payload_status rhizome_append_journal_buffer(rhizome_manifest *m, uint64_t advance_by, uint8_t *buffer, size_t len);
enum rhizome_payload_status rhizome_append_journal_file(rhizome_manifest *m, uint64_t advance_by, const char *filename);
enum rhizome_payload_status rhizome_journal_pipe(struct rhizome_write *write, const rhizome_filehash_t *hashp, uint64_t start_offset, uint64_t length);

int rhizome_crypt_xor_block(unsigned char *buffer, size_t buffer_size, uint64_t stream_offset, 
			    const unsigned char *key, const unsigned char *nonce);
enum rhizome_payload_status rhizome_open_read(struct rhizome_read *read, const rhizome_filehash_t *hashp);
ssize_t rhizome_read(struct rhizome_read *read, unsigned char *buffer, size_t buffer_length);
ssize_t rhizome_read_buffered(struct rhizome_read *read, struct rhizome_read_buffer *buffer, unsigned char *data, size_t len);
void rhizome_read_close(struct rhizome_read *read);
enum rhizome_payload_status rhizome_open_decrypt_read(rhizome_manifest *m, struct rhizome_read *read_state);
enum rhizome_payload_status rhizome_extract_file(rhizome_manifest *m, const char *filepath);
enum rhizome_payload_status rhizome_dump_file(const rhizome_filehash_t *hashp, const char *filepath, uint64_t *lengthp);
ssize_t rhizome_read_cached(const rhizome_bid_t *bid, uint64_t version, time_ms_t timeout, 
                            uint64_t fileOffset, unsigned char *buffer, size_t length);
int rhizome_cache_close();

int rhizome_database_filehash_from_id(const rhizome_bid_t *bidp, uint64_t version, rhizome_filehash_t *hashp);

void rhizome_sync_status();

DECLARE_ALARM(rhizome_fetch_status);

/* Rhizome triggers */

DECLARE_TRIGGER(bundle_add, rhizome_manifest*);

#endif //__SERVAL_DNA__RHIZOME_H
