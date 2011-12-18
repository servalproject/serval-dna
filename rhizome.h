#include "sqlite-amalgamation-3070900/sqlite3.h"
#include "sha2.h"
#include <sys/stat.h>

#define MAX_MANIFEST_VARS 256
#define MAX_MANIFEST_BYTES 8192
typedef struct rhizome_manifest {
  int manifest_bytes;
  unsigned char manifestdata[MAX_MANIFEST_BYTES];
  unsigned char manifesthash[crypto_hash_BYTES];

  /* CryptoSign key pair for this manifest.
     The filename as distributed on Rhizome will be the public key
     of this pair, thus ensuring that noone can tamper with a bundle
     except the creator. */
  unsigned char cryptoSignPublic[crypto_sign_PUBLICKEYBYTES];
  unsigned char cryptoSignSecret[crypto_sign_SECRETKEYBYTES];

  int var_count;
  char *vars[MAX_MANIFEST_VARS];
  char *values[MAX_MANIFEST_VARS];

  int sig_count;
  unsigned char *signatureBlocks[MAX_MANIFEST_VARS];
  unsigned char signatureTypes[MAX_MANIFEST_VARS];
  /* 0x01 = CryptoSign signature of manifest */
  /* 0x02 = CryptoSign signature of signatory */
  int signature_errors; /* if non-zero, then manifest should not be trusted */

  /* Set non-zero after variables have been packed and
     signature blocks appended.
     All fields below are only valid once the manifest has been finalised */
  int finalised;

  /* When finalised, we keep the filehash and maximum priority due to any
     group membership handy */
  long long fileLength;
  char fileHexHash[SHA512_DIGEST_STRING_LENGTH];
  int fileHighestPriority;

  /* Version of the manifest.  Typically the number of milliseconds since 1970. */
  long long version;
  
} rhizome_manifest;

extern long long rhizome_space;
extern char *rhizome_datastore_path;

extern sqlite3 *rhizome_db;

int rhizome_manifest_createid(rhizome_manifest *m);
int rhizome_write_manifest_file(rhizome_manifest *m,char *filename);
int rhizome_manifest_sign(rhizome_manifest *m);
int rhizome_drop_stored_file(char *id,int maximum_priority);
int rhizome_manifest_priority(char *id);
rhizome_manifest *rhizome_read_manifest_file(char *filename);
int rhizome_hash_file(char *filename,char *hash_out);
int rhizome_manifest_get(rhizome_manifest *m,char *var,char *value_out);
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
int rhizome_bundle_import(char *bundle,char *groups[],int verifyP, int checkFileP, int signP);
