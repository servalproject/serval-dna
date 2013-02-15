#include "serval.h"
#include "rhizome.h"
#include "conf.h"
#include "strlcpy.h"

#define RHIZOME_BUFFER_MAXIMUM_SIZE (1024*1024)

int rhizome_exists(const char *fileHash){
  long long gotfile = 0;
  
  if (sqlite_exec_int64(&gotfile, 
	"SELECT COUNT(*) FROM FILES, FILEBLOBS WHERE FILES.ID='%s' and FILES.datavalid=1 and FILES.ID=FILEBLOBS.ID;", 
			fileHash) != 1){
    return 0;
  }
  return gotfile;
}

int rhizome_open_write(struct rhizome_write *write, char *expectedFileHash, int64_t file_length, int priority){
  if (expectedFileHash){
    if (rhizome_exists(expectedFileHash))
      return 1;
    strlcpy(write->id, expectedFileHash, SHA512_DIGEST_STRING_LENGTH);
    write->id_known=1;
  }else{
    snprintf(write->id, sizeof(write->id), "%lld", gettime_ms());
    write->id_known=0;
  }
  
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  
  if (sqlite_exec_void_retry(&retry, "BEGIN TRANSACTION;") != SQLITE_OK)
    return WHY("Failed to begin transaction");
  
  /* INSERT INTO FILES(id as text, data blob, length integer, highestpriority integer).
   BUT, we have to do this incrementally so that we can handle blobs larger than available memory.
   This is possible using:
   int sqlite3_bind_zeroblob(sqlite3_stmt*, int, int n);
   That binds an all zeroes blob to a field.  We can then populate the data by
   opening a handle to the blob using:
   int sqlite3_blob_write(sqlite3_blob *, const void *z, int n, int iOffset);
   */

  sqlite3_stmt *statement = NULL;
  int ret=sqlite_exec_void_retry(&retry,
	"INSERT OR REPLACE INTO FILES(id,length,highestpriority,datavalid,inserttime) VALUES('%s',%lld,%d,0,%lld);",
	write->id, (long long)file_length, priority, (long long)gettime_ms());
  if (ret!=SQLITE_OK) {
    WHYF("Failed to insert into files: %s", sqlite3_errmsg(rhizome_db));
    goto insert_row_fail;
  }

  statement = sqlite_prepare(&retry,"INSERT OR REPLACE INTO FILEBLOBS(id,data) VALUES('%s',?)",write->id);
  if (!statement) {
    WHYF("Failed to insert into fileblobs: %s", sqlite3_errmsg(rhizome_db));
    goto insert_row_fail;
  }

  /* Bind appropriate sized zero-filled blob to data field */
  if (sqlite3_bind_zeroblob(statement, 1, file_length) != SQLITE_OK) {
    WHYF("sqlite3_bind_zeroblob() failed: %s: %s", sqlite3_errmsg(rhizome_db), sqlite3_sql(statement));
    goto insert_row_fail;
  }

  /* Do actual insert, and abort if it fails */
  int rowcount = 0;
  int stepcode;
  while ((stepcode = _sqlite_step_retry(__WHENCE__, LOG_LEVEL_ERROR, &retry, statement)) == SQLITE_ROW)
    ++rowcount;
  if (rowcount)
    WARNF("void query unexpectedly returned %d row%s", rowcount, rowcount == 1 ? "" : "s");

  if (!sqlite_code_ok(stepcode)){
insert_row_fail:
    WHYF("Failed to insert row for fileid=%s", write->id);
    if (statement) sqlite3_finalize(statement);
    sqlite_exec_void_retry(&retry, "ROLLBACK;");
    return -1;
  }

  sqlite3_finalize(statement);
  statement=NULL;

  /* Get rowid for inserted row, so that we can modify the blob */
  write->blob_rowid = sqlite3_last_insert_rowid(rhizome_db);
  if (config.debug.rhizome_rx)
    DEBUGF("Got rowid %lld for %s", write->blob_rowid, write->id);
  
  if (sqlite_exec_void_retry(&retry, "COMMIT;")!=SQLITE_OK){
    return WHYF("Failed to commit transaction: %s", sqlite3_errmsg(rhizome_db));
  }
  
  write->file_length = file_length;
  write->file_offset = 0;
  SHA512_Init(&write->sha512_context);
  
  write->buffer_size=write->file_length;
  
  if (write->buffer_size>RHIZOME_BUFFER_MAXIMUM_SIZE)
    write->buffer_size=RHIZOME_BUFFER_MAXIMUM_SIZE;
  
  write->buffer=malloc(write->buffer_size);
  return 0;
}

/* Write write->buffer into the database blob */
int rhizome_flush(struct rhizome_write *write){
  /* Just in case we're reading in a file that is still being written to. */
  if (write->file_offset + write->data_size > write->file_length)
    return WHY("Too much content supplied");
  
  if (write->data_size<=0)
    return WHY("No content supplied");
  
  if (write->crypt){
    if (rhizome_crypt_xor_block(write->buffer, write->data_size, write->file_offset, write->key, write->nonce))
      return -1;
  }
  
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  
  do{
    sqlite3_blob *blob=NULL;
    
    int ret = sqlite3_blob_open(rhizome_db, "main", "FILEBLOBS", "data", write->blob_rowid, 1 /* read/write */, &blob);
    if (sqlite_code_busy(ret))
      goto again;
    else if (ret!=SQLITE_OK) {
      WHYF("sqlite3_blob_open() failed: %s", 
	sqlite3_errmsg(rhizome_db));
      if (blob) sqlite3_blob_close(blob);
      return -1;
    }
    
    ret=sqlite3_blob_write(blob, write->buffer, write->data_size, 
			   write->file_offset);
    if (sqlite_code_busy(ret))
      goto again;
    else if (ret!=SQLITE_OK) {
      WHYF("sqlite3_blob_write() failed: %s", 
	   sqlite3_errmsg(rhizome_db));
      if (blob) sqlite3_blob_close(blob);
      return -1;
    }
    
    ret = sqlite3_blob_close(blob);
    blob=NULL;
    if (sqlite_code_busy(ret))
      goto again;
    else if (ret==SQLITE_OK)
      break;
    
    WHYF("sqlite3_blob_close() failed: %s", sqlite3_errmsg(rhizome_db));
    return -1;
    
  again:
    if (blob) sqlite3_blob_close(blob);
    if (sqlite_retry(&retry, "sqlite3_blob_write")==0)
      return -1;
    
  }while(1);
  
  SHA512_Update(&write->sha512_context, write->buffer, write->data_size);
  write->file_offset+=write->data_size;
  if (config.debug.rhizome)
    DEBUGF("Written %lld of %lld", write->file_offset, write->file_length);
  write->data_size=0;
  return 0;
}

/* Expects file to be at least file_length in size */
int rhizome_write_file(struct rhizome_write *write, const char *filename){
  FILE *f = fopen(filename, "r");
  if (!f)
    return WHY_perror("fopen");
  
  while(write->file_offset < write->file_length){
    
    int size=write->buffer_size - write->data_size;
    if (write->file_offset + size > write->file_length)
      size=write->file_length - write->file_offset;
    
    int r = fread(write->buffer + write->data_size, 1, size, f);
    if (r==-1){
      WHY_perror("fread");
      fclose(f);
      return -1;
    }
    write->data_size+=r;
    
    if (rhizome_flush(write)){
      fclose(f);
      return -1;
    }
  }
  
  fclose(f);
  return 0;
}

int rhizome_fail_write(struct rhizome_write *write){
  if (write->buffer)
    free(write->buffer);
  write->buffer=NULL;
  
  // don't worry too much about sql failures.
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  sqlite_exec_void_retry(&retry,
			 "DELETE FROM FILEBLOBS WHERE rowid=%lld",write->blob_rowid);
  sqlite_exec_void_retry(&retry,
			 "DELETE FROM FILES WHERE id='%s'",
			 write->id);
  return 0; 
}

int rhizome_finish_write(struct rhizome_write *write){
  if (write->data_size>0){
    if (rhizome_flush(write))
      return -1;
  }  
  if (write->buffer)
    free(write->buffer);
  write->buffer=NULL;
  
  char hash_out[SHA512_DIGEST_STRING_LENGTH+1];
  SHA512_End(&write->sha512_context, hash_out);
  
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  if (sqlite_exec_void_retry(&retry, "BEGIN TRANSACTION;") != SQLITE_OK){
    WHY("Failed to begin transaction");
    goto failure;
  }
  
  if (write->id_known){
    if (strcasecmp(write->id, hash_out)){
      WHYF("Expected hash=%s, got %s", write->id, hash_out);
      goto failure;
    }
    if (sqlite_exec_void_retry(&retry,
			       "UPDATE FILES SET inserttime=%lld, datavalid=1 WHERE id='%s'",
			       gettime_ms(), write->id)!=SQLITE_OK){
      WHYF("Failed to update files: %s", sqlite3_errmsg(rhizome_db));
      goto failure;
    }
  }else{
    str_toupper_inplace(hash_out);
    
    if (rhizome_exists(hash_out)){
      // ooops, we've already got that file, delete the new copy.
      rhizome_fail_write(write);
    }else{
      // delete any half finished records
      sqlite_exec_void_retry(&retry,"DELETE FROM FILEBLOBS WHERE id='%s';",hash_out);
      sqlite_exec_void_retry(&retry,"DELETE FROM FILES WHERE id='%s';",hash_out);
      
      if (sqlite_exec_void_retry(&retry,
				 "UPDATE FILES SET id='%s', inserttime=%lld, datavalid=1 WHERE id='%s'",
				 hash_out, gettime_ms(), write->id)!=SQLITE_OK){
	WHYF("Failed to update files: %s", sqlite3_errmsg(rhizome_db));
	goto failure;
      }
      if (sqlite_exec_void_retry(&retry,
				 "UPDATE FILEBLOBS SET id='%s' WHERE rowid=%lld",
				 hash_out, write->blob_rowid)!=SQLITE_OK){
	WHYF("Failed to update files: %s", sqlite3_errmsg(rhizome_db));
	goto failure;
      }
    }
    strlcpy(write->id, hash_out, SHA512_DIGEST_STRING_LENGTH);
  }
  if (sqlite_exec_void_retry(&retry, "COMMIT;")!=SQLITE_OK){
    WHYF("Failed to commit transaction: %s", sqlite3_errmsg(rhizome_db));
    goto failure;
  }
  return 0;
  
failure:
  sqlite_exec_void_retry(&retry, "ROLLBACK;");
  rhizome_fail_write(write);
  return -1;
}

// import a file for an existing bundle with a known file hash
int rhizome_import_file(rhizome_manifest *m, const char *filepath)
{
  if (m->fileLength<=0)
    return 0;
  
  /* Import the file first, checking the hash as we go */
  struct rhizome_write write;
  bzero(&write, sizeof(write));
  
  int ret=rhizome_open_write(&write, m->fileHexHash, m->fileLength, RHIZOME_PRIORITY_DEFAULT);
  if (ret!=0)
    return ret;
  
  // file payload is not in the store yet
  if (rhizome_write_file(&write, filepath)){
    rhizome_fail_write(&write);
    return -1;
  }
  
  if (rhizome_finish_write(&write)){
    rhizome_fail_write(&write);
    return -1;
  }
  
  return 0;
}

int rhizome_stat_file(rhizome_manifest *m, const char *filepath)
{
  long long existing = rhizome_manifest_get_ll(m, "filesize");
  
  m->fileLength = 0;
  if (filepath[0]) {
    struct stat stat;
    if (lstat(filepath,&stat))
      return WHYF("Could not stat() payload file '%s'",filepath);
    m->fileLength = stat.st_size;
  }
  
  // fail if the file is shorter than specified by the manifest
  if (existing > m->fileLength)
    return WHY("Manifest length is longer than the file");
  
  // if the file is longer than specified by the manifest, ignore the end.
  if (existing!=-1 && existing < m->fileLength)
    m->fileLength = existing;
  
  rhizome_manifest_set_ll(m, "filesize", m->fileLength);
  
  if (m->fileLength == 0){
    m->fileHexHash[0] = '\0';
    rhizome_manifest_del(m, "filehash");
  }
  return 0;
}

// import a file for a new bundle with an unknown file hash
// update the manifest with the details of the file
int rhizome_add_file(rhizome_manifest *m, const char *filepath)
{
  // Stream the file directly into the database, encrypting & hashing as we go.
  struct rhizome_write write;
  bzero(&write, sizeof(write));

  if (rhizome_open_write(&write, NULL, m->fileLength, RHIZOME_PRIORITY_DEFAULT))
    return -1;

  write.crypt=m->payloadEncryption;
  if (write.crypt){
    // if the manifest specifies encryption, make sure we can generate the payload key and encrypt the contents as we go
    if (rhizome_derive_key(m, NULL))
      return -1;
    
    if (config.debug.rhizome)
      DEBUGF("Encrypting file contents");
    
    bcopy(m->payloadKey, write.key, sizeof(write.key));
    bcopy(m->payloadNonce, write.nonce, sizeof(write.nonce));
  }
  
  if (rhizome_write_file(&write, filepath)){
    rhizome_fail_write(&write);
    return -1;
  }

  if (rhizome_finish_write(&write)){
    rhizome_fail_write(&write);
    return -1;
  }

  strlcpy(m->fileHexHash, write.id, SHA512_DIGEST_STRING_LENGTH);
  rhizome_manifest_set(m, "filehash", m->fileHexHash);
  return 0;
}

int rhizome_open_read(struct rhizome_read *read, const char *fileid, int hash){
  
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  
  strncpy(read->id, fileid, sizeof read->id);
  read->id[RHIZOME_FILEHASH_STRLEN] = '\0';
  str_toupper_inplace(read->id);
  
  sqlite3_stmt *statement = sqlite_prepare(&retry, "SELECT FILEBLOBS.rowid FROM FILEBLOBS, FILES WHERE FILEBLOBS.id = FILES.id AND FILES.id = ? AND FILES.datavalid != 0");
  if (!statement)
    return WHYF("Failed to prepare statement: %s", sqlite3_errmsg(rhizome_db));
  
  sqlite3_bind_text(statement, 1, read->id, -1, SQLITE_STATIC);
  
  int ret = sqlite_step_retry(&retry, statement);
  if (ret != SQLITE_ROW){
    WHYF("Failed to open file blob: %s", sqlite3_errmsg(rhizome_db));
    sqlite3_finalize(statement);
    return -1;
  }
  
  if (!(sqlite3_column_count(statement) == 1
	&& sqlite3_column_type(statement, 0) == SQLITE_INTEGER)) { 
    sqlite3_finalize(statement);
    return WHY("Incorrect statement column");
  }
  
  read->blob_rowid = sqlite3_column_int64(statement, 0);
  read->hash=hash;
  read->offset=0;
  read->length=-1;
  
  sqlite3_finalize(statement);
  
  if (hash)
    SHA512_Init(&read->sha512_context);
  
  return 0;
}

// returns the number of bytes read
int rhizome_read(struct rhizome_read *read, unsigned char *buffer, int buffer_length){
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  
  do{
    sqlite3_blob *blob = NULL;
    
    int ret = sqlite3_blob_open(rhizome_db, "main", "FILEBLOBS", "data", read->blob_rowid, 0 /* read only */, &blob);
    if (sqlite_code_busy(ret))
      goto again;
    else if(ret!=SQLITE_OK)
      return WHYF("sqlite3_blob_open failed: %s",sqlite3_errmsg(rhizome_db));
    
    if (read->length==-1)
      read->length=sqlite3_blob_bytes(blob);
    
    if (!buffer){
      sqlite3_blob_close(blob);
      return 0;
    }
    
    int count = read->length - read->offset;
    if (count>buffer_length)
      count=buffer_length;
    
    if (count>0){
      ret = sqlite3_blob_read(blob, buffer, count, read->offset);
      if (sqlite_code_busy(ret))
	goto again;
      else if(ret!=SQLITE_OK){
	WHYF("sqlite3_blob_read failed: %s",sqlite3_errmsg(rhizome_db));
	sqlite3_blob_close(blob);
	return -1;
      }
      
      if (read->hash){
	SHA512_Update(&read->sha512_context, buffer, count);
	
	if (read->offset + count>=read->length){
	  char hash_out[SHA512_DIGEST_STRING_LENGTH+1];
	  SHA512_End(&read->sha512_context, hash_out);
	  
	  if (strcasecmp(read->id, hash_out)){
	    sqlite3_blob_close(blob);
	    WHYF("Expected hash=%s, got %s", read->id, hash_out);
	  }
	}
      }
      
      if (read->crypt){
	if(rhizome_crypt_xor_block(buffer, count, read->offset, read->key, read->nonce)){
	  sqlite3_blob_close(blob);
	  return -1;
        }
      }
      
      read->offset+=count;
      
    }
    
    sqlite3_blob_close(blob);
    return count;
    
  again:
    if (blob) sqlite3_blob_close(blob);
    if (sqlite_retry(&retry, "sqlite3_blob_open")==0)
      return -1;
  }while (1);
}

static int write_file(struct rhizome_read *read, const char *filepath){
  int fd=-1, ret=0;
  
  if (filepath&&filepath[0]) {
    fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0775);
    if (fd == -1)
      return WHY_perror("open");
  }
  
  unsigned char buffer[RHIZOME_CRYPT_PAGE_SIZE];
  while((ret=rhizome_read(read, buffer, sizeof(buffer)))>0){
    if (fd!=-1){
      if (write(fd,buffer,ret)!=ret) {
	ret = WHY("Failed to write data to file");
	break;
      }
    }
  }
  
  if (fd!=-1){
    if (close(fd)==-1)
      ret=WHY_perror("close");
    if (ret<0){
      // TODO delete partial file
    }
  }
  
  return ret;
}

/* Extract the file related to a manifest to the file system.
 * The file will be de-crypted and verified while reading.
 * If filepath is not supplied, the file will still be checked.
 */
int rhizome_extract_file(rhizome_manifest *m, const char *filepath, rhizome_bk_t *bsk){
  struct rhizome_read read_state;
  bzero(&read_state, sizeof read_state);
  
  // for now, always hash the file
  if (rhizome_open_read(&read_state, m->fileHexHash, 1))
    return -1;
  
  read_state.crypt=m->payloadEncryption;
  if (read_state.crypt){
    // if the manifest specifies encryption, make sure we can generate the payload key and encrypt the contents as we go
    if (rhizome_derive_key(m, bsk))
      return -1;
    
    if (config.debug.rhizome)
      DEBUGF("Decrypting file contents");
    
    bcopy(m->payloadKey, read_state.key, sizeof(read_state.key));
    bcopy(m->payloadNonce, read_state.nonce, sizeof(read_state.nonce));
  }
  
  return write_file(&read_state, filepath);
}

/* dump the raw contents of a file */
int rhizome_dump_file(const char *id, const char *filepath, int64_t *length){
  struct rhizome_read read_state;
  bzero(&read_state, sizeof read_state);

  if (rhizome_open_read(&read_state, id, 1))
    return -1;
  
  if (length)
    *length = read_state.length;
  
  return write_file(&read_state, filepath);
}
