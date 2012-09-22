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

#include <sqlite3.h>
#include "sha2.h"
#include "strbuf.h"
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
#define RHIZOME_BUNDLE_KEY_BYTES        crypto_sign_edwards25519sha512batch_SECRETKEYBYTES
#define RHIZOME_BUNDLE_KEY_STRLEN       (RHIZOME_BUNDLE_KEY_BYTES  * 2)
#define RHIZOME_FILEHASH_BYTES          SHA512_DIGEST_LENGTH
#define RHIZOME_FILEHASH_STRLEN         (RHIZOME_FILEHASH_BYTES * 2)

#define RHIZOME_CRYPT_KEY_BYTES         crypto_stream_xsalsa20_ref_KEYBYTES
#define RHIZOME_CRYPT_KEY_STRLEN        (RHIZOME_CRYPT_KEY_BYTES * 2)
#define RHIZOME_CRYPT_PAGE_SIZE         4096

#define RHIZOME_HTTP_PORT 4110
#define RHIZOME_HTTP_PORT_MAX 4150

extern time_ms_t rhizome_voice_timeout;

#define RHIZOME_PRIORITY_HIGHEST RHIZOME_PRIORITY_SERVAL_CORE
#define RHIZOME_PRIORITY_SERVAL_CORE 5
#define RHIZOME_PRIORITY_SUBSCRIBED 4
#define RHIZOME_PRIORITY_SERVAL_OPTIONAL 3
#define RHIZOME_PRIORITY_DEFAULT 2
#define RHIZOME_PRIORITY_SERVAL_BULK 1
#define RHIZOME_PRIORITY_NOTINTERESTED 0

#define RHIZOME_IDLE_TIMEOUT 10000

typedef struct rhizome_signature {
  unsigned char signature[crypto_sign_edwards25519sha512batch_BYTES
			  +crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES+1];
  int signatureLength;
} rhizome_signature;

#define RHIZOME_BAR_BYTES 32

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
    0x61 = crypto_sign_edwards25519sha512batch()
  */
  unsigned char signatureTypes[MAX_MANIFEST_VARS];

  int errors; /* if non-zero, then manifest should not be trusted */

  /* Set non-zero after variables have been packed and
     signature blocks appended.
     All fields below may not be valid until the manifest has been finalised */
  int finalised;

  /* time-to-live in hops of this manifest. */
  int ttl;

  /* When finalised, we keep the filehash and maximum priority due to any
     group membership handy */
  long long fileLength;
  int fileHashedP;
  char fileHexHash[SHA512_DIGEST_STRING_LENGTH];
  int fileHighestPriority;
  /* Absolute path of the file associated with the manifest */
  char *dataFileName;
  /* Whether the paylaod is encrypted or not */
  int payloadEncryption; 

  /* Whether we have the secret for this manifest on hand */
  int haveSecret;
  /* Whether the manifest contains a signature that corresponds to the 
     manifest id (ie public key) */
  int selfSigned;

  /* Version of the manifest.  Typically the number of milliseconds since 1970. */
  long long version;
  
  int group_count;
  char *groups[MAX_MANIFEST_VARS];

} rhizome_manifest;

/* Supported service identifiers.  These go in the 'service' field of every
 * manifest, and indicate which application must be used to process the bundle
 * after it is received by Rhizome.
 */
#define     RHIZOME_SERVICE_FILE    "file"
#define     RHIZOME_SERVICE_MESHMS  "MeshMS1"

extern long long rhizome_space;
extern int rhizome_fetch_interval_ms;
extern unsigned short rhizome_http_server_port;

int rhizome_configure();

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

int http_header_complete(const char *buf, size_t len, size_t tail);
int str_startswith(char *str, const char *substring, char **afterp);
int strcase_startswith(char *str, const char *substring, char **afterp);

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

int rhizome_write_manifest_file(rhizome_manifest *m, const char *filename);
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
void _rhizome_manifest_free(struct __sourceloc where, rhizome_manifest *m);
#define rhizome_manifest_free(m) _rhizome_manifest_free(__HERE__,m)
rhizome_manifest *_rhizome_new_manifest(struct __sourceloc where);
#define rhizome_new_manifest() _rhizome_new_manifest(__HERE__)
int rhizome_manifest_pack_variables(rhizome_manifest *m);
int rhizome_store_bundle(rhizome_manifest *m);
int rhizome_manifest_add_group(rhizome_manifest *m,char *groupid);
int rhizome_clean_payload(const char *fileidhex);
int rhizome_store_file(rhizome_manifest *m,const unsigned char *key);
int rhizome_bundle_import(rhizome_manifest *m_in, rhizome_manifest **m_out, const char *bundle, int ttl);

int rhizome_manifest_verify(rhizome_manifest *m);
int rhizome_manifest_check_sanity(rhizome_manifest *m_in);
int rhizome_manifest_check_file(rhizome_manifest *m_in);
int rhizome_manifest_check_duplicate(rhizome_manifest *m_in,rhizome_manifest **m_out);

int rhizome_manifest_bind_id(rhizome_manifest *m_in, const unsigned char *authorSid);
int rhizome_manifest_bind_file(rhizome_manifest *m_in,const char *filename,int encryptP);
int rhizome_manifest_finalise(rhizome_manifest *m);
int rhizome_add_manifest(rhizome_manifest *m_in,int ttl);

void rhizome_bytes_to_hex_upper(unsigned const char *in, char *out, int byteCount);
int rhizome_find_privatekey(rhizome_manifest *m);
rhizome_signature *rhizome_sign_hash(rhizome_manifest *m, const unsigned char *authorSid);

__RHIZOME_INLINE int sqlite_code_ok(int code)
{
  return code == SQLITE_OK || code == SQLITE_DONE;
}

__RHIZOME_INLINE int sqlite_code_busy(int code)
{
  return code == SQLITE_BUSY || code == SQLITE_LOCKED;
}

sqlite3_stmt *_sqlite_prepare(struct __sourceloc, const char *sqlformat, ...);
sqlite3_stmt *_sqlite_prepare_loglevel(struct __sourceloc, int log_level, strbuf stmt);
int _sqlite_retry(struct __sourceloc where, sqlite_retry_state *retry, const char *action);
void _sqlite_retry_done(struct __sourceloc where, sqlite_retry_state *retry, const char *action);
int _sqlite_step_retry(struct __sourceloc where, int log_level, sqlite_retry_state *retry, sqlite3_stmt *statement);
int _sqlite_exec_void(struct __sourceloc, const char *sqlformat, ...);
int _sqlite_exec_void_loglevel(struct __sourceloc, int log_level, const char *sqlformat, ...);
int _sqlite_exec_void_retry(struct __sourceloc, sqlite_retry_state *retry, const char *sqlformat, ...);
int _sqlite_exec_int64(struct __sourceloc, long long *result, const char *sqlformat,...);
int _sqlite_exec_int64_retry(struct __sourceloc, sqlite_retry_state *retry, long long *result, const char *sqlformat,...);
int _sqlite_exec_strbuf(struct __sourceloc, strbuf sb, const char *sqlformat,...);

#define sqlite_prepare(fmt,...)                 _sqlite_prepare(__HERE__, (fmt), ##__VA_ARGS__)
#define sqlite_prepare_loglevel(ll,sb)          _sqlite_prepare_loglevel(__HERE__, (ll), (sb))
#define sqlite_retry(rs,action)                 _sqlite_retry(__HERE__, (rs), (action))
#define sqlite_retry_done(rs,action)            _sqlite_retry_done(__HERE__, (rs), (action))
#define sqlite_step(stmt)                       _sqlite_step_retry(__HERE__, LOG_LEVEL_ERROR, NULL, (stmt))
#define sqlite_step_retry(rs,stmt)              _sqlite_step_retry(__HERE__, LOG_LEVEL_ERROR, (rs), (stmt))
#define sqlite_exec_void(fmt,...)               _sqlite_exec_void(__HERE__, (fmt), ##__VA_ARGS__)
#define sqlite_exec_void_loglevel(ll,fmt,...)   _sqlite_exec_void_loglevel(__HERE__, (ll), (fmt), ##__VA_ARGS__)
#define sqlite_exec_void_retry(rs,fmt,...)      _sqlite_exec_void_retry(__HERE__, (rs), (fmt), ##__VA_ARGS__)
#define sqlite_exec_int64(res,fmt,...)          _sqlite_exec_int64(__HERE__, (res), (fmt), ##__VA_ARGS__)
#define sqlite_exec_int64_retry(rs,res,fmt,...) _sqlite_exec_int64_retry(__HERE__, (rs), (res), (fmt), ##__VA_ARGS__)
#define sqlite_exec_strbuf(sb,fmt,...)          _sqlite_exec_strbuf(__HERE__, (sb), (fmt), ##__VA_ARGS__)

double rhizome_manifest_get_double(rhizome_manifest *m,char *var,double default_value);
int rhizome_manifest_extract_signature(rhizome_manifest *m,int *ofs);
int rhizome_update_file_priority(const char *fileid);
int rhizome_find_duplicate(const rhizome_manifest *m, rhizome_manifest **found,
			   int checkVersionP);
int rhizome_manifest_to_bar(rhizome_manifest *m,unsigned char *bar);
long long rhizome_bar_version(unsigned char *bar);
unsigned long long rhizome_bar_bidprefix(unsigned char *bar);
int rhizome_queue_manifest_import(rhizome_manifest *m, struct sockaddr_in *peerip, int *manifest_kept);
int rhizome_list_manifests(const char *service, const char *sender_sid, const char *recipient_sid, int limit, int offset);
int rhizome_retrieve_manifest(const char *manifestid, rhizome_manifest **mp);
int rhizome_retrieve_file(const char *fileid, const char *filepath,
			  const unsigned char *key);

#define RHIZOME_DONTVERIFY 0
#define RHIZOME_VERIFY 1

int rhizome_fetching_get_fds(struct pollfd *fds,int *fdcount,int fdmax);
int rhizome_manifest_version_cache_lookup(rhizome_manifest *m);
int rhizome_manifest_version_cache_store(rhizome_manifest *m);
int monitor_announce_bundle(rhizome_manifest *m);
int rhizome_bk_xor(const unsigned char *authorSid, // binary
		   unsigned char bid[crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES],
		   unsigned char bkin[crypto_sign_edwards25519sha512batch_SECRETKEYBYTES],
		   unsigned char bkout[crypto_sign_edwards25519sha512batch_SECRETKEYBYTES]);
unsigned char *rhizome_bundle_shared_secret(rhizome_manifest *m);
int rhizome_extract_privatekey(rhizome_manifest *m, const unsigned char *authorSid);
int rhizome_verify_bundle_privatekey(rhizome_manifest *m);
int rhizome_is_self_signed(rhizome_manifest *m);
int rhizome_queue_ignore_manifest(rhizome_manifest *m,
				  struct sockaddr_in *peerip,int timeout);
int rhizome_ignore_manifest_check(rhizome_manifest *m,
				  struct sockaddr_in *peerip);

/* one manifest is required per candidate, plus a few spare.
   so MAX_RHIZOME_MANIFESTS must be > MAX_CANDIDATES. 
*/
#define MAX_RHIZOME_MANIFESTS 24
#define MAX_CANDIDATES 16

int rhizome_suggest_queue_manifest_import(rhizome_manifest *m,
					  struct sockaddr_in *peerip);

typedef struct rhizome_http_request {
  struct sched_ent alarm;
  long long initiate_time; /* time connection was initiated */
  
  /* The HTTP request as currently received */
  int request_length;
#define RHIZOME_HTTP_REQUEST_MAXLEN 1024
  char request[RHIZOME_HTTP_REQUEST_MAXLEN];
  
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
  
  sqlite3_blob *blob;
  /* source_index used for offset in blob */
  long long blob_end; 
  
} rhizome_http_request;

struct http_response {
  unsigned int result_code;
  const char * content_type;
  unsigned long long content_length;
  const char * body;
};
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
