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
  
  /* INSERT INTO FILES(id as text, data blob, length integer, highestpriority integer).
   BUT, we have to do this incrementally so that we can handle blobs larger than available memory.
   This is possible using:
   int sqlite3_bind_zeroblob(sqlite3_stmt*, int, int n);
   That binds an all zeroes blob to a field.  We can then populate the data by
   opening a handle to the blob using:
   int sqlite3_blob_write(sqlite3_blob *, const void *z, int n, int iOffset);
   */
  
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  int ret=sqlite_exec_void(
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
  return 0;
}

/* Write write->buffer into the database blob */
int rhizome_flush(struct rhizome_write *write){
  /* Just in case we're reading in a file that is still being written to. */
  if (write->file_offset + write->data_size > write->file_length)
    return WHY("Too much content supplied");
  
  if (write->data_size<=0)
    return WHY("No content supplied");
  
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
  sqlite3_blob_close(blob); 
  blob=NULL;
  
  if (ret!=SQLITE_OK) {
    WHYF("sqlite3_blob_write() failed: %s", 
	 sqlite3_errmsg(rhizome_db));
    return -1;
  }
  
  SHA512_Update(&write->sha512_context, write->buffer, write->data_size);
  write->file_offset+=write->data_size;
  if (config.debug.rhizome)
    DEBUGF("Written %lld of %lld", write->file_offset, write->file_length);
  write->data_size=0;
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
      sqlite_exec_void("DELETE FROM FILEBLOBS WHERE id='%s';",hash_out);
      sqlite_exec_void("DELETE FROM FILES WHERE id='%s';",hash_out);
      
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
  
  return 0;
  
failure:
  rhizome_fail_write(write);
  return -1;
}

