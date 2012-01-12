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

#include "sqlite-amalgamation-3070900/sqlite3.h"
#include "sha2.h"
#include <sys/stat.h>

#define RHIZOME_HTTP_PORT 4110

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
  int manifest_bytes;
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

  /* Absolute path of the file associated with the manifest */
  char *dataFileName;

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

extern long long rhizome_space;
extern char *rhizome_datastore_path;

extern sqlite3 *rhizome_db;

int rhizome_opendb();
int rhizome_manifest_createid(rhizome_manifest *m);
int rhizome_write_manifest_file(rhizome_manifest *m,char *filename);
int rhizome_manifest_sign(rhizome_manifest *m);
int rhizome_drop_stored_file(char *id,int maximum_priority);
int rhizome_manifest_priority(char *id);
rhizome_manifest *rhizome_read_manifest_file(char *filename,int bufferPAndSize,int flags);
int rhizome_hash_file(char *filename,char *hash_out);
char *rhizome_manifest_get(rhizome_manifest *m,char *var,char *value_out,int maxlen);
long long  rhizome_manifest_get_ll(rhizome_manifest *m,char *var);
int rhizome_manifest_set_ll(rhizome_manifest *m,char *var,long long value);
int rhizome_manifest_set(rhizome_manifest *m,char *var,char *value);
long long rhizome_file_size(char *filename);
void rhizome_manifest_free(rhizome_manifest *m);
int rhizome_manifest_pack_variables(rhizome_manifest *m);
int rhizome_store_bundle(rhizome_manifest *m,char *associated_filename);
int rhizome_manifest_add_group(rhizome_manifest *m,char *groupid);
int rhizome_store_file(char *file,char *hash,int priortity);
char *rhizome_safe_encode(unsigned char *in,int len);
int rhizome_finish_sqlstatement(sqlite3_stmt *statement);
int rhizome_bundle_import(char *bundle,char *groups[],int ttl,
			  int verifyP, int checkFileP, int signP);
int rhizome_manifest_finalise(rhizome_manifest *m,int signP);
char *rhizome_bytes_to_hex(unsigned char *in,int byteCount);
int rhizome_hex_to_bytes(char *in,unsigned char *out,int hexChars);
int rhizome_store_keypair_bytes(unsigned char *p,unsigned char *s);
int rhizome_find_keypair_bytes(unsigned char *p,unsigned char *s);
rhizome_signature *rhizome_sign_hash(unsigned char *hash,unsigned char *publicKeyBytes);

int rhizome_server_free_http_request(rhizome_http_request *r);
int rhizome_server_close_http_request(int i);
int rhizome_server_http_send_bytes(int rn,rhizome_http_request *r);
int rhizome_server_parse_http_request(int rn,rhizome_http_request *r);
int rhizome_server_simple_http_response(rhizome_http_request *r,int result, char *response);
long long sqlite_exec_int64(char *sqlformat,...);
int rhizome_server_http_response_header(rhizome_http_request *r,int result,
					char *mime_type,unsigned long long bytes);
int rhizome_server_sql_query_fill_buffer(int rn,rhizome_http_request *r);
double rhizome_manifest_get_double(rhizome_manifest *m,char *var,double default_value);
int chartonybl(int c);
int rhizome_manifest_extract_signature(rhizome_manifest *m,int *ofs);
long long sqlite_exec_int64(char *sqlformat,...);
int rhizome_update_file_priority(char *fileid);
int rhizome_manifest_to_bar(rhizome_manifest *m,unsigned char *bar);
char nybltochar(int n);
int rhizome_queue_manifest_import(rhizome_manifest *m,struct sockaddr_in *peerip);

#define RHIZOME_DONTVERIFY 0
#define RHIZOME_VERIFY 1
