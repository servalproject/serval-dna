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
#include "sha2.h"
#include "str.h"
#include "strbuf.h"
#include "nacl.h"
#include <sys/stat.h>

#ifndef __RHIZOME_INLINE
# if __GNUC__ && !__GNUC_STDC_INLINE__
#  define __RHIZOME_INLINE extern inline
# else
#  define __RHIZOME_INLINE inline
# endif
#endif

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

typedef struct rhizome_bk_binary {
    unsigned char binary[RHIZOME_BUNDLE_KEY_BYTES];
} rhizome_bk_t;

#define RHIZOME_BK_NONE ((rhizome_bk_t){{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}})

__RHIZOME_INLINE int rhizome_is_bk_none(const rhizome_bk_t *bk) {
    return is_all_matching(bk->binary, sizeof bk->binary, 0);
}

extern time_ms_t rhizome_voice_timeout;

#define RHIZOME_PRIORITY_HIGHEST RHIZOME_PRIORITY_SERVAL_CORE
#define RHIZOME_PRIORITY_SERVAL_CORE 5
#define RHIZOME_PRIORITY_SUBSCRIBED 4
#define RHIZOME_PRIORITY_SERVAL_OPTIONAL 3
#define RHIZOME_PRIORITY_DEFAULT 2
#define RHIZOME_PRIORITY_SERVAL_BULK 1
#define RHIZOME_PRIORITY_NOTINTERESTED 0

#define RHIZOME_IDLE_TIMEOUT 10000

#define EXISTING_BUNDLE_ID 1
#define NEW_BUNDLE_ID 2

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
typedef struct rhizome_manifest {
  int manifest_record_number;
  int manifest_bytes;
  int manifest_all_bytes;
  unsigned char manifestdata[MAX_MANIFEST_BYTES];
  unsigned char manifesthash[crypto_hash_sha512_BYTES];

  /* CryptoSign key pair for this manifest.
     The filename as distributed on Rhizome will be the public key
     of this pair, thus ensuring that noone can tamper with a bundle
     except the creator. */
  unsigned char cryptoSignPublic[crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES];
  unsigned char cryptoSignSecret[crypto_sign_edwards25519sha512batch_SECRETKEYBYTES];

  int var_count;
  char *vars[MAX_MANIFEST_VARS];
  char *values[MAX_MANIFEST_VARS];

  int sig_count;
  /* Parties who have signed this manifest (raw byte format) */
  unsigned char *signatories[MAX_MANIFEST_VARS];
  /*
    0x17 = crypto_sign_edwards25519sha512batch()
  */
  unsigned char signatureTypes[MAX_MANIFEST_VARS];

  int errors; /* if non-zero, then manifest should not be trusted */
  time_ms_t inserttime;
  
  /* Set non-zero after variables have been packed and
     signature blocks appended.
     All fields below may not be valid until the manifest has been finalised */
  int finalised;

  /* time-to-live in hops of this manifest. */
  int ttl;

  /* When finalised, we keep the filehash and maximum priority due to any
     group membership handy */
  long long fileLength;
  char fileHexHash[SHA512_DIGEST_STRING_LENGTH];
  int fileHighestPriority;
  /* Absolute path of the file associated with the manifest */
  char *dataFileName;
  /* If set, unlink(2) the associated file when freeing the manifest */
  int dataFileUnlinkOnFree;
  
  /* Whether the paylaod is encrypted or not */
  int payloadEncryption;
  unsigned char payloadKey[RHIZOME_CRYPT_KEY_BYTES];
  unsigned char payloadNonce[crypto_stream_xsalsa20_NONCEBYTES];

  /* Whether we have the secret for this manifest on hand */
  int haveSecret;
  /* Whether the manifest contains a signature that corresponds to the 
     manifest id (ie public key) */
  int selfSigned;

  /* Version of the manifest.  Typically the number of milliseconds since 1970. */
  long long version;
  
  int group_count;
  char *groups[MAX_MANIFEST_VARS];

  /* Author of the manifest.  A reference to a local keyring entry.  Manifests
   * not authored locally will have the ANY author (all zeros).
   */
  unsigned char author[SID_SIZE];

} rhizome_manifest;

/* Supported service identifiers.  These go in the 'service' field of every
 * manifest, and indicate which application must be used to process the bundle
 * after it is received by Rhizome.
 */
#define     RHIZOME_SERVICE_FILE    "file"
#define     RHIZOME_SERVICE_MESHMS  "MeshMS1"

extern long long rhizome_space;
extern unsigned short rhizome_http_server_port;

int rhizome_configure();
int rhizome_enabled();
int rhizome_fetch_delay_ms();

int rhizome_set_datastore_path(const char *path);

const char *rhizome_datastore_path();
int form_rhizome_datastore_path(char * buf, size_t bufsiz, const char *fmt, ...);
int create_rhizome_datastore_dir();

int form_rhizome_import_path(char * buf, size_t bufsiz, const char *fmt, ...);
int create_rhizome_import_dir();

/* Handy statement for forming the path of a rhizome store file in a char buffer whose declaration
 * is in scope (so that sizeof(buf) will work).  Evaluates to true if the pathname fitted into
 * the provided buffer, false (0) otherwise (after logging an error).  */
#define FORM_RHIZOME_DATASTORE_PATH(buf,fmt,...) (form_rhizome_datastore_path((buf), sizeof(buf), (fmt), ##__VA_ARGS__))
#define FORM_RHIZOME_IMPORT_PATH(buf,fmt,...) (form_rhizome_import_path((buf), sizeof(buf), (fmt), ##__VA_ARGS__))

extern sqlite3 *rhizome_db;

int rhizome_opendb();
int rhizome_close_db();
int rhizome_manifest_createid(rhizome_manifest *m);

int rhizome_strn_is_manifest_id(const char *text);
int rhizome_str_is_manifest_id(const char *text);
int rhizome_strn_is_bundle_key(const char *text);
int rhizome_str_is_bundle_key(const char *text);
int rhizome_strn_is_bundle_crypt_key(const char *text);
int rhizome_str_is_bundle_crypt_key(const char *text);
int rhizome_strn_is_file_hash(const char *text);
int rhizome_str_is_file_hash(const char *text);

#define alloca_tohex_bid(bid)           alloca_tohex((bid), RHIZOME_MANIFEST_ID_BYTES)

int http_header_complete(const char *buf, size_t len, size_t read_since_last_call);

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
int rhizome_drop_stored_file(const char *id,int maximum_priority);
int rhizome_manifest_priority(sqlite_retry_state *retry, const char *id);
int rhizome_read_manifest_file(rhizome_manifest *m, const char *filename, int bufferPAndSize);
int rhizome_hash_file(rhizome_manifest *m, const char *filename,char *hash_out);
char *rhizome_manifest_get(const rhizome_manifest *m, const char *var, char *out, int maxlen);
long long  rhizome_manifest_get_ll(rhizome_manifest *m, const char *var);
int rhizome_manifest_set_ll(rhizome_manifest *m,char *var,long long value);
int rhizome_manifest_set(rhizome_manifest *m, const char *var, const char *value);
int rhizome_manifest_del(rhizome_manifest *m, const char *var);
long long rhizome_file_size(char *filename);
void _rhizome_manifest_free(struct __sourceloc __whence, rhizome_manifest *m);
#define rhizome_manifest_free(m) _rhizome_manifest_free(__WHENCE__,m)
rhizome_manifest *_rhizome_new_manifest(struct __sourceloc __whence);
#define rhizome_new_manifest() _rhizome_new_manifest(__WHENCE__)
int rhizome_manifest_pack_variables(rhizome_manifest *m);
int rhizome_store_bundle(rhizome_manifest *m);
int rhizome_manifest_add_group(rhizome_manifest *m,char *groupid);
int rhizome_clean_payload(const char *fileidhex);
int rhizome_store_file(rhizome_manifest *m,const unsigned char *key);
int rhizome_bundle_import_files(rhizome_manifest *m, const char *manifest_path, const char *filepath);
int rhizome_bundle_import(rhizome_manifest *m, int ttl);
int rhizome_fill_manifest(rhizome_manifest *m, const char *filepath, const sid_t *authorSid, rhizome_bk_t *bsk);

int rhizome_manifest_verify(rhizome_manifest *m);
int rhizome_manifest_check_sanity(rhizome_manifest *m_in);
int rhizome_manifest_check_duplicate(rhizome_manifest *m_in,rhizome_manifest **m_out, int check_author);

int rhizome_manifest_bind_id(rhizome_manifest *m_in);
int rhizome_manifest_finalise(rhizome_manifest *m, rhizome_manifest **mout);
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

sqlite3_stmt *_sqlite_prepare(struct __sourceloc __whence, sqlite_retry_state *retry, const char *sqlformat, ...);
sqlite3_stmt *_sqlite_prepare_loglevel(struct __sourceloc __whence, int log_level, sqlite_retry_state *retry, strbuf stmt);
int _sqlite_retry(struct __sourceloc __whence, sqlite_retry_state *retry, const char *action);
void _sqlite_retry_done(struct __sourceloc __whence, sqlite_retry_state *retry, const char *action);
int _sqlite_step_retry(struct __sourceloc __whence, int log_level, sqlite_retry_state *retry, sqlite3_stmt *statement);
int _sqlite_exec_void(struct __sourceloc, const char *sqlformat, ...);
int _sqlite_exec_void_loglevel(struct __sourceloc, int log_level, const char *sqlformat, ...);
int _sqlite_exec_void_retry(struct __sourceloc, sqlite_retry_state *retry, const char *sqlformat, ...);
int _sqlite_exec_int64(struct __sourceloc, long long *result, const char *sqlformat,...);
int _sqlite_exec_int64_retry(struct __sourceloc, sqlite_retry_state *retry, long long *result, const char *sqlformat,...);
int _sqlite_exec_strbuf(struct __sourceloc, strbuf sb, const char *sqlformat,...);

#define sqlite_prepare(rs,fmt,...)              _sqlite_prepare(__WHENCE__, (rs), (fmt), ##__VA_ARGS__)
#define sqlite_prepare_loglevel(ll,rs,sb)       _sqlite_prepare_loglevel(__WHENCE__, (ll), (rs), (sb))
#define sqlite_retry(rs,action)                 _sqlite_retry(__WHENCE__, (rs), (action))
#define sqlite_retry_done(rs,action)            _sqlite_retry_done(__WHENCE__, (rs), (action))
#define sqlite_step(stmt)                       _sqlite_step_retry(__WHENCE__, LOG_LEVEL_ERROR, NULL, (stmt))
#define sqlite_step_retry(rs,stmt)              _sqlite_step_retry(__WHENCE__, LOG_LEVEL_ERROR, (rs), (stmt))
#define sqlite_exec_void(fmt,...)               _sqlite_exec_void(__WHENCE__, (fmt), ##__VA_ARGS__)
#define sqlite_exec_void_loglevel(ll,fmt,...)   _sqlite_exec_void_loglevel(__WHENCE__, (ll), (fmt), ##__VA_ARGS__)
#define sqlite_exec_void_retry(rs,fmt,...)      _sqlite_exec_void_retry(__WHENCE__, (rs), (fmt), ##__VA_ARGS__)
#define sqlite_exec_int64(res,fmt,...)          _sqlite_exec_int64(__WHENCE__, (res), (fmt), ##__VA_ARGS__)
#define sqlite_exec_int64_retry(rs,res,fmt,...) _sqlite_exec_int64_retry(__WHENCE__, (rs), (res), (fmt), ##__VA_ARGS__)
#define sqlite_exec_strbuf(sb,fmt,...)          _sqlite_exec_strbuf(__WHENCE__, (sb), (fmt), ##__VA_ARGS__)

double rhizome_manifest_get_double(rhizome_manifest *m,char *var,double default_value);
int rhizome_manifest_extract_signature(rhizome_manifest *m,int *ofs);
int rhizome_update_file_priority(const char *fileid);
int rhizome_find_duplicate(const rhizome_manifest *m, rhizome_manifest **found, int check_author);
int rhizome_manifest_to_bar(rhizome_manifest *m,unsigned char *bar);
long long rhizome_bar_version(unsigned char *bar);
unsigned long long rhizome_bar_bidprefix_ll(unsigned char *bar);
int rhizome_list_manifests(const char *service, const char *name, 
			   const char *sender_sid, const char *recipient_sid, 
			   int limit, int offset);
int rhizome_retrieve_manifest(const char *manifestid, rhizome_manifest *m);

#define RHIZOME_DONTVERIFY 0
#define RHIZOME_VERIFY 1

int rhizome_fetching_get_fds(struct pollfd *fds,int *fdcount,int fdmax);
int rhizome_manifest_version_cache_lookup(rhizome_manifest *m);
int rhizome_manifest_version_cache_store(rhizome_manifest *m);
int monitor_announce_bundle(rhizome_manifest *m);
int rhizome_find_secret(const unsigned char *authorSid, int *rs_len, const unsigned char **rs);
int rhizome_bk_xor_stream(
  const unsigned char bid[crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES],
  const unsigned char *rs,
  const size_t rs_len,
  unsigned char *xor_stream,
  int xor_stream_byte_count);
int rhizome_bk2secret(rhizome_manifest *m,
  const unsigned char bid[crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES],
  const unsigned char *rs, const size_t rs_len,
  /* The BK need only be the length of the secret half of the secret key */
  const unsigned char bkin[RHIZOME_BUNDLE_KEY_BYTES],
  unsigned char secret[crypto_sign_edwards25519sha512batch_SECRETKEYBYTES]
		      );
int rhizome_secret2bk(
  const unsigned char bid[crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES],
  const unsigned char *rs, const size_t rs_len,
  /* The BK need only be the length of the secret half of the secret key */
  unsigned char bkout[RHIZOME_BUNDLE_KEY_BYTES],
  const unsigned char secret[crypto_sign_edwards25519sha512batch_SECRETKEYBYTES]
		      );
unsigned char *rhizome_bundle_shared_secret(rhizome_manifest *m);
int rhizome_extract_privatekey(rhizome_manifest *m, rhizome_bk_t *bsk);
int rhizome_extract_privatekey_required(rhizome_manifest *m, rhizome_bk_t *bsk);
int rhizome_sign_hash_with_key(rhizome_manifest *m,const unsigned char *sk,
			       const unsigned char *pk,rhizome_signature *out);
int rhizome_verify_bundle_privatekey(rhizome_manifest *m, const unsigned char *sk,
				     const unsigned char *pk);
int rhizome_find_bundle_author(rhizome_manifest *m);
int rhizome_queue_ignore_manifest(rhizome_manifest *m, const struct sockaddr_in *peerip, const unsigned char peersid[SID_SIZE], int timeout);
int rhizome_ignore_manifest_check(rhizome_manifest *m, const struct sockaddr_in *peerip,const unsigned char peersid[SID_SIZE]);

/* one manifest is required per candidate, plus a few spare.
   so MAX_RHIZOME_MANIFESTS must be > MAX_CANDIDATES. 
*/
#define MAX_RHIZOME_MANIFESTS 24
#define MAX_CANDIDATES 16

int rhizome_suggest_queue_manifest_import(rhizome_manifest *m, const struct sockaddr_in *peerip,const unsigned char peersid[SID_SIZE]);

typedef struct rhizome_http_request {
  struct sched_ent alarm;
  long long initiate_time; /* time connection was initiated */
  
  struct sockaddr_in requestor;

  /* identify request from others being run.
     Monotonic counter feeds it.  Only used for debugging when we write
     post-<uuid>.log files for multi-part form requests. */
  unsigned int uuid;

  /* The HTTP request as currently received */
  int request_length;
  char request[1024];
  
  /* Nature of the request */
  int request_type;
  /* All of the below are receiving data */
#define RHIZOME_HTTP_REQUEST_RECEIVING -1
#define RHIZOME_HTTP_REQUEST_RECEIVING_MULTIPART -2
  /* All of the below are sending data */
#define RHIZOME_HTTP_REQUEST_FROMBUFFER 1
#define RHIZOME_HTTP_REQUEST_FILE 2
#define RHIZOME_HTTP_REQUEST_SUBSCRIBEDGROUPLIST 4
#define RHIZOME_HTTP_REQUEST_ALLGROUPLIST 8
#define RHIZOME_HTTP_REQUEST_BUNDLESINGROUP 16
  // manifests are small enough to send from a buffer
  // #define RHIZOME_HTTP_REQUEST_BUNDLEMANIFEST 32
  // for anything too big, we can just use a blob
#define RHIZOME_HTTP_REQUEST_BLOB 64
#define RHIZOME_HTTP_REQUEST_FAVICON 128
  
  /* Local buffer of data to be sent.
   If a RHIZOME_HTTP_REQUEST_FROMBUFFER, then the buffer is sent, and when empty
   the request is closed.
   Else emptying the buffer triggers a request to fetch more data.  Only if no
   more data is provided do we then close the request. */
  unsigned char *buffer;
  int buffer_size; // size
  int buffer_length; // number of bytes loaded into buffer
  int buffer_offset; // where we are between [0,buffer_length)
  
  /* Path of request (used by POST multipart form requests where
     the actual processing of the request does not occur while the
     request headers are still available. */
  char path[1024];
  /* Boundary string for POST multipart form requests */
  char boundary_string[1024];
  int boundary_string_length;
  /* File currently being written to while decoding POST multipart form */
  FILE *field_file;
  /* Name of data file supplied */
  char data_file_name[1024];
  /* Which fields have been seen in POST multipart form */
  int fields_seen;
  /* The seen fields bitmap above shares values with the actual Rhizome Direct
     state machine.  The state numbers (and thus bitmap values for the various
     fields) are listed here.
     
     To avoid confusion, we should not use single bit values for states that do
     not correspond directly to a particular field.
     Doesn't really matter what they are apart from not having exactly one bit set.
     In fact, the only reason to not have exactly one bit set is so that we keep as
     many bits available for field types as possible.
  */
#define RD_MIME_STATE_MANIFESTHEADERS (1<<0)
#define RD_MIME_STATE_DATAHEADERS (1<<1)
#define RD_MIME_STATE_INITIAL 0
#define RD_MIME_STATE_PARTHEADERS 0xffff0000
#define RD_MIME_STATE_BODY 0xffff0001

  /* The source specification data which are used in different ways by different 
   request types */
  char source[1024];
  long long source_index;
  long long source_count;
  int source_record_size;
  unsigned int source_flags;
  
  const char *sql_table;
  const char *sql_row;
  int64_t rowid;
  /* source_index used for offset in blob */
  long long blob_end; 
  
} rhizome_http_request;

struct http_response {
  unsigned int result_code;
  const char * content_type;
  unsigned long long content_length;
  const char * body;
};

int rhizome_received_content(unsigned char *bidprefix,uint64_t version, 
			     uint64_t offset,int count,unsigned char *bytes,
			     int type);
int64_t rhizome_database_create_blob_for(const char *hashhex,int64_t fileLength,
					 int priority);
int rhizome_server_set_response(rhizome_http_request *r, const struct http_response *h);
int rhizome_server_free_http_request(rhizome_http_request *r);
int rhizome_server_http_send_bytes(rhizome_http_request *r);
int rhizome_server_parse_http_request(rhizome_http_request *r);
int rhizome_server_simple_http_response(rhizome_http_request *r, int result, const char *response);
int rhizome_server_http_response_header(rhizome_http_request *r, int result, const char *mime_type, unsigned long long bytes);
int rhizome_server_sql_query_fill_buffer(rhizome_http_request *r, char *table, char *column);
int rhizome_http_server_start(int (*http_parse_func)(rhizome_http_request *),
			      const char *http_parse_func_description,
			      int port_low,int port_high);

int is_rhizome_enabled();
int is_rhizome_mdp_enabled();
int is_rhizome_http_enabled();
int is_rhizome_advertise_enabled();
int is_rhizome_mdp_server_running();
int is_rhizome_http_server_running();

typedef struct rhizome_direct_bundle_cursor {
  /* Where the current fill started */
  long long start_size_high;
  unsigned char start_bid_low[RHIZOME_MANIFEST_ID_BYTES];

  /* Limit of where this cursor may traverse */
  long long limit_size_high;
  unsigned char limit_bid_high[RHIZOME_MANIFEST_ID_BYTES];

  long long size_low;
  long long size_high;
  unsigned char bid_low[RHIZOME_MANIFEST_ID_BYTES];
  unsigned char bid_high[RHIZOME_MANIFEST_ID_BYTES];
  unsigned char *buffer;
  int buffer_size;
  int buffer_used;
  int buffer_offset_bytes;
} rhizome_direct_bundle_cursor;

rhizome_direct_bundle_cursor *rhizome_direct_bundle_iterator(int buffer_size);
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
int rhizome_direct_get_bars(const unsigned char bid_low[RHIZOME_MANIFEST_ID_BYTES],
			    unsigned char bid_high[RHIZOME_MANIFEST_ID_BYTES],
			    long long size_low,long long size_high,
			    const unsigned char bid_max[RHIZOME_MANIFEST_ID_BYTES],
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
				 int buffer_size,int interval, int mode, 
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

enum rhizome_start_fetch_result rhizome_fetch_request_manifest_by_prefix(const struct sockaddr_in *peerip, const unsigned char sid[SID_SIZE],const unsigned char *prefix, size_t prefix_length);
int rhizome_any_fetch_active();
int rhizome_any_fetch_queued();

struct http_response_parts {
  int code;
  char *reason;
  long long content_length;
  char *content_start;
};

int unpack_http_response(char *response, struct http_response_parts *parts);

/* Rhizome file storage api */
struct rhizome_write{
  char id[SHA512_DIGEST_STRING_LENGTH+1];
  char id_known;
  
  unsigned char *buffer;
  int buffer_size;
  int data_size;
  
  int64_t file_offset;
  int64_t file_length;
  
  int crypt;
  unsigned char key[RHIZOME_CRYPT_KEY_BYTES];
  unsigned char nonce[crypto_stream_xsalsa20_NONCEBYTES];
  
  SHA512_CTX sha512_context;
  int64_t blob_rowid;
};

struct rhizome_read{
  char id[SHA512_DIGEST_STRING_LENGTH+1];
  
  int crypt;
  unsigned char key[RHIZOME_CRYPT_KEY_BYTES];
  unsigned char nonce[crypto_stream_xsalsa20_NONCEBYTES];
  
  int hash;
  SHA512_CTX sha512_context;
  
  int64_t blob_rowid;
  
  int64_t offset;
  int64_t length;
};

int rhizome_exists(const char *fileHash);
int rhizome_open_write(struct rhizome_write *write, char *expectedFileHash, int64_t file_length, int priority);
int rhizome_flush(struct rhizome_write *write);
int rhizome_write_file(struct rhizome_write *write, const char *filename);
int rhizome_fail_write(struct rhizome_write *write);
int rhizome_finish_write(struct rhizome_write *write);
int rhizome_import_file(rhizome_manifest *m, const char *filepath);
int rhizome_stat_file(rhizome_manifest *m, const char *filepath);
int rhizome_add_file(rhizome_manifest *m, const char *filepath);
int rhizome_derive_key(rhizome_manifest *m, rhizome_bk_t *bsk);
int rhizome_crypt_xor_block(unsigned char *buffer, int buffer_size, int64_t stream_offset, 
			    const unsigned char *key, const unsigned char *nonce);
int rhizome_open_read(struct rhizome_read *read, const char *fileid, int hash);
int rhizome_read(struct rhizome_read *read, unsigned char *buffer, int buffer_length);
int rhizome_extract_file(rhizome_manifest *m, const char *filepath, rhizome_bk_t *bsk);
int rhizome_dump_file(const char *id, const char *filepath, int64_t *length);

#endif //__SERVALDNA__RHIZOME_H
