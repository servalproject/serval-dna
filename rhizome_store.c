#include "serval.h"
#include "rhizome.h"
#include "conf.h"

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
    
    /* Okay, so there are no records that match, but we should delete any half-baked record (with datavalid=0) so that the insert below doesn't fail.
     Don't worry about the return result, since it might not delete any records. */
    sqlite_exec_void("DELETE FROM FILEBLOBS WHERE id='%s';",expectedFileHash);
    sqlite_exec_void("DELETE FROM FILES WHERE id='%s';",expectedFileHash);
    strlcpy(write->id, expectedFileHash, SHA512_DIGEST_STRING_LENGTH);
    write->id_known=1;
  }else{
    snprintf(write->id, sizeof(write->id), "%lld", gettime_ms());
    write->id_known=0;
  }
  
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  
  if (sqlite_exec_void_retry(&retry, "BEGIN TRANSACTION;") == -1)
    return -1;
  
  /* INSERT INTO FILES(id as text, data blob, length integer, highestpriority integer).
   BUT, we have to do this incrementally so that we can handle blobs larger than available memory.
   This is possible using:
   int sqlite3_bind_zeroblob(sqlite3_stmt*, int, int n);
   That binds an all zeroes blob to a field.  We can then populate the data by
   opening a handle to the blob using:
   int sqlite3_blob_write(sqlite3_blob *, const void *z, int n, int iOffset);
   */
  
  int ret=sqlite_exec_void_retry(&retry,
	"INSERT OR REPLACE INTO FILES(id,length,highestpriority,datavalid,inserttime) VALUES('%s',%lld,%d,0,%lld);",
	write->id, (long long)file_length, priority, (long long)gettime_ms());
  if (ret!=SQLITE_OK) {
    WHYF("Failed to insert into files: %s",
	   sqlite3_errmsg(rhizome_db));
    goto insert_row_fail;
  }
    
  sqlite3_stmt *statement = sqlite_prepare(&retry,"INSERT OR REPLACE INTO FILEBLOBS(id,data) VALUES('%s',?)",write->id);
  if (!statement){
    WHYF("Failed to insert into fileblobs: %s",
	 sqlite3_errmsg(rhizome_db));
    goto insert_row_fail;
  }
  
  /* Bind appropriate sized zero-filled blob to data field */
  if (sqlite3_bind_zeroblob(statement, 1, file_length) != SQLITE_OK) {
    WHYF("sqlite3_bind_zeroblob() failed: %s: %s", sqlite3_errmsg(rhizome_db), sqlite3_sql(statement));
    sqlite3_finalize(statement);
    goto insert_row_fail;
  }
  
  /* Do actual insert, and abort if it fails */
  int rowcount = 0;
  int stepcode;
  while ((stepcode = _sqlite_step_retry(__WHENCE__, LOG_LEVEL_ERROR, &retry, statement)) == SQLITE_ROW)
    ++rowcount;
  
  if (rowcount)
    WARNF("void query unexpectedly returned %d row%s", rowcount, rowcount == 1 ? "" : "s");
  sqlite3_finalize(statement);
  
  if (!sqlite_code_ok(stepcode)){
  insert_row_fail:
    WHYF("Failed to insert row for fileid=%s", write->id);
    sqlite_exec_void_retry(&retry, "ROLLBACK;");
    return -1;
  }
    
  /* Get rowid for inserted row, so that we can modify the blob */
  write->blob_rowid = sqlite3_last_insert_rowid(rhizome_db);
  DEBUGF("Got rowid %lld",write->blob_rowid);
  write->file_length = file_length;
  write->file_offset = 0;
  SHA512_Init(&write->sha512_context);
  
  write->buffer_size=write->file_length;
  
  if (write->buffer_size>RHIZOME_BUFFER_MAXIMUM_SIZE)
    write->buffer_size=RHIZOME_BUFFER_MAXIMUM_SIZE;
  
  write->buffer=malloc(write->buffer_size);
  return sqlite_exec_void_retry(&retry, "COMMIT;");
}

/* Write write->buffer into the database blob */
int rhizome_flush(struct rhizome_write *write){
  /* Just in case we're reading in a file that is still being written to. */
  if (write->file_offset + write->data_size > write->file_length)
    return WHY("Too much content supplied");
  
  if (write->data_size<=0)
    return WHY("No content supplied");
  
  if (write->crypt){
    rhizome_crypt_xor_block(write->buffer, write->data_size, write->file_offset, write->key, write->nonce);
  }
  
  sqlite3_blob *blob;
  int ret = sqlite3_blob_open(rhizome_db, "main", "FILEBLOBS", "data", write->blob_rowid, 1 /* read/write */, &blob);
  if (ret!=SQLITE_OK) {
    WHYF("sqlite3_blob_open() failed: %s", 
      sqlite3_errmsg(rhizome_db));
    if (blob) sqlite3_blob_close(blob);
    return -1;
  }
  ret=sqlite3_blob_write(blob, write->buffer, write->data_size, 
			 write->file_offset);
  
  if (ret!=SQLITE_OK) {
    WHYF("sqlite3_blob_write() failed: %s", 
	 sqlite3_errmsg(rhizome_db));
    if (blob) sqlite3_blob_close(blob);
    return -1;
  }
  
  ret = sqlite3_blob_close(blob);
  if (ret!=SQLITE_OK)
    return WHYF("sqlite3_blob_close() failed: %s", sqlite3_errmsg(rhizome_db));
  blob=NULL;
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
  if (sqlite_exec_void_retry(&retry, "BEGIN TRANSACTION;") == -1)
    return -1;
  
  if (write->id_known){
    if (strcasecmp(write->id, hash_out)){
      WHYF("Expected hash=%s, got %s", write->id, hash_out);
      goto failure;
    }
    if (sqlite_exec_void_retry(&retry,
			       "UPDATE FILES SET datavalid=1 WHERE id='%s'",
			       write->id)!=SQLITE_OK){
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
				 "UPDATE FILES SET datavalid=1, id='%s' WHERE id='%s'",
				 hash_out, write->id)!=SQLITE_OK){
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
  return sqlite_exec_void_retry(&retry, "COMMIT;");
  
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
  
  if (rhizome_finish_write(&write))
    return -1;
  return 0;
}

int rhizome_stat_file(rhizome_manifest *m, const char *filepath)
{
  m->fileLength = 0;
  if (filepath[0]) {
    struct stat stat;
    if (lstat(filepath,&stat))
      return WHYF("Could not stat() payload file '%s'",filepath);
    m->fileLength = stat.st_size;
  }
  
  rhizome_manifest_set_ll(m, "filesize", m->fileLength);
  
  if (m->fileLength == 0){
    m->fileHexHash[0] = '\0';
    rhizome_manifest_del(m, "filehash");
    m->fileHashedP = 0;
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

  if (rhizome_write_file(&write, filepath)){
    rhizome_fail_write(&write);
    return -1;
  }

  if (rhizome_finish_write(&write))
    return -1;

  m->fileHashedP = 1;
  strlcpy(m->fileHexHash, write.id, SHA512_DIGEST_STRING_LENGTH);
  rhizome_manifest_set(m, "filehash", m->fileHexHash);
  return 0;
}

/*

int rhizome_open_append(struct rhizome_write *write, int64_t size, const char *expectedFileHash, const char *existingFileHash){
  
}

struct rhizome_read{
  
};

int rhizome_open_read(struct rhizome_read *read, ){
  
}

int rhizome_read(struct rhizome_read *read, unsigned char *buffer, int buffer_length){
  
}

int rhizome_seek(struct rhizome_read *read, int64_t offset){
  
}


*/