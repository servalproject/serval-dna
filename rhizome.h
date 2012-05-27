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

#define RHIZOME_MANIFEST_ID_BYTES       crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES
#define RHIZOME_MANIFEST_ID_STRLEN      (RHIZOME_MANIFEST_ID_BYTES * 2)
#define RHIZOME_BUNDLE_KEY_BYTES        crypto_sign_edwards25519sha512batch_SECRETKEYBYTES
#define RHIZOME_BUNDLE_KEY_STRLEN       (RHIZOME_BUNDLE_KEY_BYTES  * 2)
#define RHIZOME_FILEHASH_BYTES          SHA512_DIGEST_LENGTH
#define RHIZOME_FILEHASH_STRLEN         (RHIZOME_FILEHASH_BYTES * 2)

#define RHIZOME_CRYPT_PAGE_SIZE 4096
#define RHIZOME_CRYPT_KEY_BYTES crypto_stream_xsalsa20_ref_KEYBYTES

#define RHIZOME_HTTP_PORT 4110

extern long long rhizome_voice_timeout;

typedef struct rhizome_http_request {
  int socket;
  long long last_activity; /* time of last activity in ms */
  long long initiate_time; /* time connection was initiated */

  /* The HTTP request as currently received */
  int request_length;
#define RHIZOME_HTTP_REQUEST_MAXLEN 1024
  char request[RHIZOME_HTTP_REQUEST_MAXLEN];

  /* Nature of the request */
  int request_type;
#define RHIZOME_HTTP_REQUEST_RECEIVING -1
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

  /* The source specification data which are used in different ways by different 
     request types */
  unsigned char source[1024];
  long long source_index;
  long long source_count;
  int source_record_size;
  unsigned int source_flags;

  char *blob_table;
  char *blob_column;
  unsigned long long blob_rowid;
  /* source_index used for offset in blob */
  unsigned long long blob_end; 

} rhizome_http_request;

#define RHIZOME_SERVER_MAX_LIVE_REQUESTS 32

#define RHIZOME_PRIORITY_HIGHEST RHIZOME_PRIORITY_SERVAL_CORE
#define RHIZOME_PRIORITY_SERVAL_CORE 5
#define RHIZOME_PRIORITY_SUBSCRIBED 4
#define RHIZOME_PRIORITY_SERVAL_OPTIONAL 3
#define RHIZOME_PRIORITY_DEFAULT 2
#define RHIZOME_PRIORITY_SERVAL_BULK 1
#define RHIZOME_PRIORITY_NOTINTERESTED 0

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
int rhizome_strn_is_file_hash(const char *text);
int rhizome_str_is_file_hash(const char *text);
int rhizome_write_manifest_file(rhizome_manifest *m, const char *filename);
int rhizome_manifest_selfsign(rhizome_manifest *m);
int rhizome_drop_stored_file(const char *id,int maximum_priority);
int rhizome_manifest_priority(char *id);
int rhizome_read_manifest_file(rhizome_manifest *m, const char *filename, int bufferPAndSize);
int rhizome_hash_file(rhizome_manifest *m, const char *filename,char *hash_out);
char *rhizome_manifest_get(const rhizome_manifest *m, const char *var, char *out, int maxlen);
long long  rhizome_manifest_get_ll(rhizome_manifest *m, const char *var);
int rhizome_manifest_set_ll(rhizome_manifest *m,char *var,long long value);
int rhizome_manifest_set(rhizome_manifest *m, const char *var, const char *value);
long long rhizome_file_size(char *filename);
void _rhizome_manifest_free(const char *sourcefile,const char *funcname,int line,
			    rhizome_manifest *m);
#define rhizome_manifest_free(m) _rhizome_manifest_free(__FILE__,__FUNCTION__,__LINE__,m)
rhizome_manifest *_rhizome_new_manifest(const char *file,const char *func,int line);
#define rhizome_new_manifest() _rhizome_new_manifest(__FILE__,__FUNCTION__,__LINE__)
int rhizome_manifest_pack_variables(rhizome_manifest *m);
int rhizome_store_bundle(rhizome_manifest *m);
int rhizome_manifest_add_group(rhizome_manifest *m,char *groupid);
int rhizome_clean_payload(const char *fileidhex);
int rhizome_store_file(rhizome_manifest *m,const unsigned char *key);
int rhizome_finish_sqlstatement(sqlite3_stmt *statement);
int rhizome_bundle_import(rhizome_manifest *m_in, rhizome_manifest **m_out, 
			  const char *bundle, int ttl);

int rhizome_manifest_verify(rhizome_manifest *m);
int rhizome_manifest_check_sanity(rhizome_manifest *m_in);
int rhizome_manifest_check_file(rhizome_manifest *m_in);
int rhizome_manifest_check_duplicate(rhizome_manifest *m_in,rhizome_manifest **m_out);

int rhizome_manifest_bind_id(rhizome_manifest *m_in,const char *author);
int rhizome_manifest_bind_file(rhizome_manifest *m_in,const char *filename,int encryptP);
int rhizome_manifest_finalise(rhizome_manifest *m);
int rhizome_add_manifest(rhizome_manifest *m_in,int ttl);

void rhizome_bytes_to_hex_upper(unsigned const char *in, char *out, int byteCount);
int rhizome_hex_to_bytes(const char *in,unsigned char *out,int hexChars);
int rhizome_find_privatekey(rhizome_manifest *m);
rhizome_signature *rhizome_sign_hash(rhizome_manifest *m,const char *author);
int rhizome_server_free_http_request(rhizome_http_request *r);
int rhizome_server_close_http_request(int i);
int rhizome_server_http_send_bytes(int rn,rhizome_http_request *r);
int rhizome_server_parse_http_request(int rn,rhizome_http_request *r);
int rhizome_server_simple_http_response(rhizome_http_request *r,int result, char *response);
long long sqlite_exec_void(const char *sqlformat,...);
long long sqlite_exec_int64(const char *sqlformat,...);
int sqlite_exec_strbuf(strbuf sb, const char *sqlformat,...);
int rhizome_server_http_response_header(rhizome_http_request *r,int result,
					char *mime_type,unsigned long long bytes);
int rhizome_server_sql_query_fill_buffer(int rn,rhizome_http_request *r);
double rhizome_manifest_get_double(rhizome_manifest *m,char *var,double default_value);
int chartonybl(int c);
int rhizome_manifest_extract_signature(rhizome_manifest *m,int *ofs);
int rhizome_update_file_priority(const char *fileid);
int rhizome_find_duplicate(const rhizome_manifest *m, rhizome_manifest **found,
			   int checkVersionP);
int rhizome_manifest_to_bar(rhizome_manifest *m,unsigned char *bar);
char nybltochar_upper(int n);
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
int rhizome_bk_xor(const char *author,
		   unsigned char bid[crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES],
		   unsigned char bkin[crypto_sign_edwards25519sha512batch_SECRETKEYBYTES],
		   unsigned char bkout[crypto_sign_edwards25519sha512batch_SECRETKEYBYTES]);
int rhizome_extract_privatekey(rhizome_manifest *m,const char *authorHex);
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
int rhizome_enqueue_suggestions();
