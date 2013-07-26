#include "serval.h"
#include "rhizome.h"
#include "conf.h"
#include "strlcpy.h"

#define RHIZOME_BUFFER_MAXIMUM_SIZE (1024*1024)

int rhizome_exists(const char *fileHash){
  int64_t gotfile = 0;
  
  if (sqlite_exec_int64(&gotfile, 
	"SELECT COUNT(*) FROM FILES WHERE ID='%s' and datavalid=1;", 
			fileHash) != 1){
    return 0;
  }
  return gotfile;
}

int rhizome_open_write(struct rhizome_write *write, char *expectedFileHash, int64_t file_length, int priority){
  write->blob_fd=-1;
  
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
  
  if (sqlite_exec_void_retry(&retry, "BEGIN TRANSACTION;") == -1)
    return WHY("Failed to begin transaction");
  
  /* 
   we have to write incrementally so that we can handle blobs larger than available memory.
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
  if (ret==-1)
    goto insert_row_fail;
  
  char blob_path[1024];
  
  if (config.rhizome.external_blobs || file_length > 128*1024) {
    if (!FORM_RHIZOME_DATASTORE_PATH(blob_path, write->id)){
      WHY("Invalid path");
      goto insert_row_fail;
    }
    
    if (config.debug.externalblobs)
      DEBUGF("Attempting to put blob for %s in %s",
	     write->id,blob_path);
    
    write->blob_fd=open(blob_path, O_CREAT | O_TRUNC | O_WRONLY, 0664);
    if (write->blob_fd<0)
      goto insert_row_fail;
    
    if (config.debug.externalblobs)
      DEBUGF("Writing to new blob file %s (fd=%d)", blob_path, write->blob_fd);
    
  }else{
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
      DEBUGF("Got rowid %"PRId64" for %s", write->blob_rowid, write->id);
    
  }
  
  if (sqlite_exec_void_retry(&retry, "COMMIT;") == -1){
    if (write->blob_fd>=0){
      if (config.debug.externalblobs)
         DEBUGF("Cancel write to fd %d", write->blob_fd);
      close(write->blob_fd);
      write->blob_fd=-1;
      unlink(blob_path);
    }
    return -1;
  }
  
  write->file_length = file_length;
  write->file_offset = 0;
  write->written_offset = 0;
  
  SHA512_Init(&write->sha512_context);
  
  return 0;
}

/* blob_open / close will lock the database, this is bad for other processes that might attempt to 
 * use it at the same time. However, opening a blob has about O(n^2) performance. 
 * */

// encrypt and hash data, data buffers must be passed in file order.
static int prepare_data(struct rhizome_write *write_state, unsigned char *buffer, int data_size){
  if (data_size<=0)
    return WHY("No content supplied");
    
  /* Make sure we aren't being asked to write more data than we expected */
  if (write_state->file_offset + data_size > write_state->file_length)
    return WHYF("Too much content supplied, %"PRId64" + %d > %"PRId64,
		write_state->file_offset, data_size, write_state->file_length);

  if (write_state->crypt){
    if (rhizome_crypt_xor_block(
	  buffer, data_size, 
	  write_state->file_offset + write_state->tail, 
	  write_state->key, write_state->nonce))
      return -1;
  }
  
  SHA512_Update(&write_state->sha512_context, buffer, data_size);
  write_state->file_offset+=data_size;
  
  if (config.debug.rhizome)
    DEBUGF("Processed %"PRId64" of %"PRId64, write_state->file_offset, write_state->file_length);
  return 0;
}

// open database locks
static int write_get_lock(struct rhizome_write *write_state){
  if (write_state->blob_fd>=0 || write_state->sql_blob)
    return 0;
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  while(1){
    int ret = sqlite3_blob_open(rhizome_db, "main", "FILEBLOBS", "data", 
		write_state->blob_rowid, 1 /* read/write */, &write_state->sql_blob);
    if (ret==SQLITE_OK)
      return 0;
    if (!sqlite_code_busy(ret))
      return WHYF("sqlite3_blob_write() failed: %s", 
	     sqlite3_errmsg(rhizome_db));
    if (sqlite_retry(&retry, "sqlite3_blob_open")==0)
      return -1;
  }
}

// write data to disk
static int write_data(struct rhizome_write *write_state, uint64_t file_offset, unsigned char *buffer, int data_size){
  if (data_size<=0)
    return 0;
  
  if (file_offset != write_state->written_offset)
    WARNF("Writing file data out of order! [%"PRId64",%"PRId64"]", file_offset, write_state->written_offset);
    
  if (write_state->blob_fd>=0) {
    int ofs=0;
    // keep trying until all of the data is written.
    lseek(write_state->blob_fd, file_offset, SEEK_SET);
    while(ofs < data_size){
      int r=write(write_state->blob_fd, buffer + ofs, data_size - ofs);
      if (r<0)
	return WHY_perror("write");
      if (config.debug.externalblobs)
        DEBUGF("Wrote %d bytes to fd %d", r, write_state->blob_fd);
      ofs+=r;
    }
  }else{
    if (!write_state->sql_blob)
      return WHY("Must call write_get_lock() before write_data()");
    sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
    while(1){
      int ret=sqlite3_blob_write(write_state->sql_blob, buffer, data_size, file_offset);
      if (ret==SQLITE_OK)
	break;
      if (!sqlite_code_busy(ret))
	return WHYF("sqlite3_blob_write() failed: %s", 
	     sqlite3_errmsg(rhizome_db));
      if (sqlite_retry(&retry, "sqlite3_blob_write")==0)
	return -1;
    }
  }
  
  write_state->written_offset=file_offset + data_size;
  
  if (config.debug.rhizome)
    DEBUGF("Wrote %"PRId64" of %"PRId64, file_offset + data_size, write_state->file_length);
  return 0;
}

// close database locks
static int write_release_lock(struct rhizome_write *write_state){
  if (write_state->blob_fd>=0)
    return 0;
    
  if (write_state->sql_blob) 
    sqlite3_blob_close(write_state->sql_blob);
  write_state->sql_blob=NULL;
  return 0;
}

// Write data buffers in any order, the data will be cached and streamed into the database in file order. 
// Though there is an upper bound on the amount of cached data
int rhizome_random_write(struct rhizome_write *write_state, int64_t offset, unsigned char *buffer, int data_size){
  if (offset + data_size > write_state->file_length)
    data_size = write_state->file_length - offset;
  
  struct rhizome_write_buffer **ptr = &write_state->buffer_list;
  int ret=0;
  int should_write = 0;
  if (write_state->blob_fd>=0){
    should_write = 1;
  }else{
    int64_t new_size = write_state->written_offset + write_state->buffer_size + data_size;
    if (new_size>=write_state->file_length || new_size>=RHIZOME_BUFFER_MAXIMUM_SIZE)
      should_write = 1;
  }
  int64_t last_offset = write_state->written_offset;
  
  while(1){
    
    // can we process this existing data block now?
    if (*ptr && (*ptr)->offset == write_state->file_offset){
      if (prepare_data(write_state, (*ptr)->data, (*ptr)->data_size)){
	ret=-1;
	break;
      }
      continue;
    }
    
    // if existing data should be written, do so now
    if (should_write && *ptr && (*ptr)->offset == write_state->written_offset){
      struct rhizome_write_buffer *n=*ptr;
      if (write_get_lock(write_state)){
	ret=-1;
	break;
      }
      if (write_data(write_state, n->offset, n->data, n->data_size)){
	ret=-1;
	break;
      }
      write_state->buffer_size-=n->data_size;
      last_offset = n->offset + n->data_size;
      *ptr=n->_next;
      free(n);
      continue;
    }
    
    // skip over incoming data that we've already received
    if (offset < last_offset){
      int64_t delta = last_offset - offset;
      if (delta >= data_size)
	break;
      data_size -= delta;
      offset+=delta;
      buffer+=delta;
    }
    
    if (data_size<=0)
      break;
    
    // can we process the incoming data block now?
    if (data_size>0 && offset == write_state->file_offset){
      if (prepare_data(write_state, buffer, data_size)){
	ret=-1;
	break;
      }
      continue;
    }
    
    if (!*ptr || offset < (*ptr)->offset){
      // found the insert position in the list
      int64_t size = data_size;
      
      // allow for buffers to overlap, we may need to split the incoming buffer into multiple pieces.
      if (*ptr && offset+size > (*ptr)->offset)
	size = (*ptr)->offset - offset;
	
      if (should_write && offset == write_state->file_offset){
	if (write_get_lock(write_state)){
	  ret=-1;
	  break;
	}
	if (write_data(write_state, offset, buffer, size)){
	  ret=-1;
	  break;
	}
	// we need to go around the loop again to re-test if this buffer can now be written
      }else{
	// impose a limit on the total amount of cached data
	if (write_state->buffer_size + size > RHIZOME_BUFFER_MAXIMUM_SIZE)
	  size = RHIZOME_BUFFER_MAXIMUM_SIZE - write_state->buffer_size;
	if (size<=0)
	  break;
	  
	if (config.debug.rhizome)
	  DEBUGF("Caching block @%"PRId64", %"PRId64, offset, size);
	struct rhizome_write_buffer *i = emalloc(size + sizeof(struct rhizome_write_buffer));
	if (!i){
	  ret=-1;
	  break;
	}
	i->offset = offset;
	i->buffer_size = i->data_size = size;
	bcopy(buffer, i->data, size);
	i->_next = *ptr;
	write_state->buffer_size += size;
	*ptr = i;
	// if there's any overlap of this buffer and the current one, we may need to add another buffer.
	ptr = &((*ptr)->_next);
      }
      data_size -= size;
      offset+=size;
      buffer+=size;
      continue;
    }
    
    last_offset = (*ptr)->offset + (*ptr)->data_size;
    ptr = &((*ptr)->_next);
  }
  write_release_lock(write_state);
  return ret;
}

int rhizome_write_buffer(struct rhizome_write *write_state, unsigned char *buffer, int data_size){
  return rhizome_random_write(write_state, write_state->file_offset, buffer, data_size);
}

/* Expects file to be at least file_length in size, ignoring anything longer than that */
int rhizome_write_file(struct rhizome_write *write, const char *filename){
  FILE *f = fopen(filename, "r");
  if (!f)
    return WHY_perror("fopen");

  unsigned char buffer[RHIZOME_CRYPT_PAGE_SIZE];
  int ret=0;
  write_get_lock(write);
  while(write->file_offset < write->file_length){
    
    int size=sizeof(buffer);
    if (write->file_offset + size > write->file_length)
      size=write->file_length - write->file_offset;
    
    int r = fread(buffer, 1, size, f);
    if (r==-1){
      ret = WHY_perror("fread");
      goto end;
    }
    if (rhizome_write_buffer(write, buffer, r)){
      ret=-1;
      goto end;
    }
  }
end:
  write_release_lock(write);
  fclose(f);
  return ret;
}

int rhizome_store_delete(const char *id){
  char blob_path[1024];
  if (!FORM_RHIZOME_DATASTORE_PATH(blob_path, id))
    return -1;
  if (unlink(blob_path)){
    if (config.debug.externalblobs)
      DEBUG_perror("unlink");
    return -1;
  }
  return 0;
}

int rhizome_fail_write(struct rhizome_write *write){
  if (write->blob_fd>=0){
    if (config.debug.externalblobs)
      DEBUGF("Closing and removing fd %d", write->blob_fd);
    close(write->blob_fd);
    write->blob_fd=-1;
    rhizome_store_delete(write->id);
  }
  write_release_lock(write);
  while(write->buffer_list){
    struct rhizome_write_buffer *n=write->buffer_list;
    write->buffer_list=n->_next;
    free(n);
  }
  // don't worry too much about sql failures.
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  if (write->blob_rowid>=0){
    sqlite_exec_void_retry_loglevel(LOG_LEVEL_WARN, &retry,
			   "DELETE FROM FILEBLOBS WHERE rowid=%lld",write->blob_rowid);
    write->blob_rowid=-1;
  }
  sqlite_exec_void_retry_loglevel(LOG_LEVEL_WARN, &retry,
			 "DELETE FROM FILES WHERE id='%s'",
			 write->id);
  return 0;
}

int rhizome_finish_write(struct rhizome_write *write){
  if (write->buffer_list){
    if (rhizome_random_write(write, 0, NULL, 0))
      goto failure;
    if (write->buffer_list){
      WHYF("Buffer was not cleared");
      goto failure;
    }
  }
  
  if (write->file_offset < write->file_length){
    WHYF("Only processed %"PRId64" bytes, expected %"PRId64, write->file_offset, write->file_length);
  }
    
  int fd = write->blob_fd;
  if (fd>=0){
    if (config.debug.externalblobs)
      DEBUGF("Closing fd %d", fd);
    close(fd);
    write->blob_fd=-1;
  }
  write_release_lock(write);
  
  char hash_out[SHA512_DIGEST_STRING_LENGTH+1];
  SHA512_End(&write->sha512_context, hash_out);
  
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  if (sqlite_exec_void_retry(&retry, "BEGIN TRANSACTION;") == -1)
    goto failure;
  
  if (write->id_known){
    if (strcasecmp(write->id, hash_out)){
      WHYF("Expected hash=%s, got %s", write->id, hash_out);
      goto failure;
    }
    if (sqlite_exec_void_retry(&retry, "UPDATE FILES SET inserttime=%lld, datavalid=1 WHERE id='%s'",
			       gettime_ms(), write->id) == -1)
      goto failure;
  }else{
    str_toupper_inplace(hash_out);
    
    if (rhizome_exists(hash_out)){
      // ooops, we've already got that file, delete the new copy.
      rhizome_fail_write(write);
    }else{
      // delete any half finished records
      sqlite_exec_void_retry_loglevel(LOG_LEVEL_WARN, &retry,"DELETE FROM FILEBLOBS WHERE id='%s';",hash_out);
      sqlite_exec_void_retry_loglevel(LOG_LEVEL_WARN, &retry,"DELETE FROM FILES WHERE id='%s';",hash_out);
      
      if (sqlite_exec_void_retry(&retry,
				 "UPDATE FILES SET id='%s', inserttime=%lld, datavalid=1 WHERE id='%s'",
				 hash_out, gettime_ms(), write->id) == -1)
	goto failure;
      
      if (fd>=0){
	char blob_path[1024];
	char dest_path[1024];
	if (!FORM_RHIZOME_DATASTORE_PATH(blob_path, write->id)){
	  WHYF("Failed to generate file path");
	  goto failure;
	}
	if (!FORM_RHIZOME_DATASTORE_PATH(dest_path, hash_out)){
	  WHYF("Failed to generate file path");
	  goto failure;
	}
	if (link(blob_path, dest_path)){
	  WHY_perror("link");
	  goto failure;
	}
	  
	if (unlink(blob_path))
	  WHY_perror("unlink");
	
      }else{
	if (sqlite_exec_void_retry(&retry,
				   "UPDATE FILEBLOBS SET id='%s' WHERE rowid=%lld",
				   hash_out, write->blob_rowid) == -1){
	  goto failure;
	}
      }
    }
    strlcpy(write->id, hash_out, SHA512_DIGEST_STRING_LENGTH);
  }
  if (sqlite_exec_void_retry(&retry, "COMMIT;") == -1)
    goto failure;
  write->blob_rowid=-1;
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

static int rhizome_write_derive_key(rhizome_manifest *m, rhizome_bk_t *bsk, struct rhizome_write *write)
{
  if (!m->payloadEncryption)
    return 0;
  
  // if the manifest specifies encryption, make sure we can generate the payload key and encrypt the contents as we go
  if (rhizome_derive_key(m, bsk))
    return -1;

  if (config.debug.rhizome)
    DEBUGF("Encrypting payload contents for %s, %"PRId64, alloca_tohex_bid(m->cryptoSignPublic), m->version);

  write->crypt=1;
  write->tail = m->journalTail;

  bcopy(m->payloadKey, write->key, sizeof(write->key));
  bcopy(m->payloadNonce, write->nonce, sizeof(write->nonce));
  return 0;
}

int rhizome_write_open_manifest(struct rhizome_write *write, rhizome_manifest *m)
{
  if (rhizome_open_write(write, NULL, m->fileLength, RHIZOME_PRIORITY_DEFAULT))
    return -1;

  if (rhizome_write_derive_key(m, NULL, write))
    return -1;
  return 0;
}

// import a file for a new bundle with an unknown file hash
// update the manifest with the details of the file
int rhizome_add_file(rhizome_manifest *m, const char *filepath)
{
  // Stream the file directly into the database, encrypting & hashing as we go.
  struct rhizome_write write;
  bzero(&write, sizeof(write));

  if (rhizome_write_open_manifest(&write, m))
    goto failure;
  if (rhizome_write_file(&write, filepath))
    goto failure;
  if (rhizome_finish_write(&write))
    goto failure;

  strlcpy(m->fileHexHash, write.id, SHA512_DIGEST_STRING_LENGTH);
  rhizome_manifest_set(m, "filehash", m->fileHexHash);
  return 0;

failure:
  rhizome_fail_write(&write);
  return -1;
}

/* Return -1 on error, 0 if file blob found, 1 if not found.
 */
int rhizome_open_read(struct rhizome_read *read, const char *fileid, int hash)
{
  strncpy(read->id, fileid, sizeof read->id);
  read->id[RHIZOME_FILEHASH_STRLEN] = '\0';
  str_toupper_inplace(read->id);
  read->blob_rowid = -1;
  read->blob_fd = -1;
  if (sqlite_exec_int64(&read->blob_rowid, "SELECT FILEBLOBS.rowid FROM FILEBLOBS, FILES WHERE FILEBLOBS.id = FILES.id AND FILES.id = '%s' AND FILES.datavalid != 0", read->id) == -1)
    return -1;
  if (read->blob_rowid != -1) {
    read->length = -1; // discover the length on opening the db BLOB
  } else {
    // No row in FILEBLOBS, look for an external blob file.
    char blob_path[1024];
    if (!FORM_RHIZOME_DATASTORE_PATH(blob_path, read->id))
      return -1;
    read->blob_fd = open(blob_path, O_RDONLY);
    if (read->blob_fd == -1) {
      if (errno == ENOENT)
	return 1; // file not available
      return WHYF_perror("open(%s)", alloca_str_toprint(blob_path));
    }
    if ((read->length = lseek(read->blob_fd, 0, SEEK_END)) == -1)
      return WHYF_perror("lseek(%s,0,SEEK_END)", alloca_str_toprint(blob_path));
    if (config.debug.externalblobs)
      DEBUGF("Opened stored file %s as fd %d, len %"PRIx64,blob_path, read->blob_fd, read->length);
  }
  read->hash = hash;
  read->offset = 0;
  if (hash)
    SHA512_Init(&read->sha512_context);
  return 0; // file opened
}

/* Read content from the store, hashing and decrypting as we go. 
 Random access is supported, but hashing requires reads to be sequential though we don't enforce this. */
// returns the number of bytes read
int rhizome_read(struct rhizome_read *read_state, unsigned char *buffer, int buffer_length)
{
  IN();
  int bytes_read = 0;
  if (read_state->blob_fd >= 0) {
    if (lseek(read_state->blob_fd, read_state->offset, SEEK_SET) == -1)
      RETURN(WHYF_perror("lseek(%d,%ld,SEEK_SET)", read_state->blob_fd, (long)read_state->offset));
    bytes_read = read(read_state->blob_fd, buffer, buffer_length);
    if (bytes_read == -1)
      RETURN(WHYF_perror("read(%d,%p,%ld)", read_state->blob_fd, buffer, (long)buffer_length));
    if (config.debug.externalblobs)
      DEBUGF("Read %d bytes from fd %d @%"PRIx64, bytes_read, read_state->blob_fd, read_state->offset);
  } else if (read_state->blob_rowid != -1) {
    sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
    do{
      sqlite3_blob *blob = NULL;
      int ret = sqlite3_blob_open(rhizome_db, "main", "FILEBLOBS", "data", read_state->blob_rowid, 0 /* read only */, &blob);
      if (sqlite_code_busy(ret))
	goto again;
      else if(ret!=SQLITE_OK)
	RETURN(WHYF("sqlite3_blob_open failed: %s",sqlite3_errmsg(rhizome_db)));
      if (read_state->length==-1)
	read_state->length=sqlite3_blob_bytes(blob);
      bytes_read = read_state->length - read_state->offset;
      if (bytes_read>buffer_length)
	bytes_read=buffer_length;
      // allow the caller to do a dummy read, just to work out the length
      if (!buffer)
	bytes_read=0;
      if (bytes_read>0){
	ret = sqlite3_blob_read(blob, buffer, bytes_read, read_state->offset);
	if (sqlite_code_busy(ret))
	  goto again;
	else if(ret!=SQLITE_OK){
	  WHYF("sqlite3_blob_read failed: %s",sqlite3_errmsg(rhizome_db));
	  sqlite3_blob_close(blob);
	  RETURN(-1);
	}
      }
      sqlite3_blob_close(blob);
      break;
    again:
      if (blob) sqlite3_blob_close(blob);
      if (!sqlite_retry(&retry, "sqlite3_blob_open"))
	RETURN(-1);
    } while (1);
  } else
    RETURN(WHY("file not open"));
  if (read_state->hash){
    if (buffer && bytes_read>0)
      SHA512_Update(&read_state->sha512_context, buffer, bytes_read);
    if (read_state->offset + bytes_read>=read_state->length){
      char hash_out[SHA512_DIGEST_STRING_LENGTH+1];
      SHA512_End(&read_state->sha512_context, hash_out);
      if (strcasecmp(read_state->id, hash_out)){
	WHYF("Expected hash=%s, got %s", read_state->id, hash_out);
      }
      read_state->hash=0;
    }
  }
  if (read_state->crypt && buffer && bytes_read>0){
    if(rhizome_crypt_xor_block(
	buffer, bytes_read, 
	read_state->offset + read_state->tail, 
	read_state->key, read_state->nonce)){
      RETURN(-1);
    }
  }
  read_state->offset+=bytes_read;
  RETURN(bytes_read);
  OUT();
}

/* Read len bytes from read->offset into data, using *buffer to cache any reads */
int rhizome_read_buffered(struct rhizome_read *read, struct rhizome_read_buffer *buffer, unsigned char *data, int len)
{
  int bytes_copied=0;
  
  while (len>0){
    // make sure we only attempt to read data that actually exists
    if (read->length !=-1 && read->offset + len > read->length)
      len = read->length - read->offset;

    // if we can supply either the beginning or end of the data from cache, do that first.
    uint64_t ofs=read->offset - buffer->offset;
    if (ofs>=0 && ofs<=buffer->len){
      int size=len;
      if (size > buffer->len - ofs)
	size = buffer->len - ofs;
      if (size>0){
	// copy into the start of the data buffer
	bcopy(buffer->data + ofs, data, size);
	data+=size;
	len-=size;
	read->offset+=size;
	bytes_copied+=size;
	continue;
      }
    }
    
    ofs = (read->offset+len) - buffer->offset;
    if (ofs>0 && ofs<=buffer->len){
      int size=len;
      if (size > ofs)
	size = ofs;
      if (size>0){
	// copy into the end of the data buffer
	bcopy(buffer->data + ofs - size, data + len - size, size);
	len-=size;
	bytes_copied+=size;
	continue;
      }
    }
    
    // ok, so we need to read a new buffer to fulfill the request.
    // remember the requested read offset so we can put it back
    ofs = read->offset;
    buffer->offset = read->offset = ofs & ~(RHIZOME_CRYPT_PAGE_SIZE -1);
    buffer->len = rhizome_read(read, buffer->data, sizeof(buffer->data));
    read->offset = ofs;
    if (buffer->len<=0)
      return buffer->len;
  }
  return bytes_copied;
}

int rhizome_read_close(struct rhizome_read *read)
{
  if (read->blob_fd >=0){
    if (config.debug.externalblobs)
      DEBUGF("Closing store fd %d", read->blob_fd);
    close(read->blob_fd);
  }
  read->blob_fd = -1;
  return 0;
}

/* Returns -1 on error, 0 on success.
 */
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

static int read_derive_key(rhizome_manifest *m, rhizome_bk_t *bsk, struct rhizome_read *read_state){
  read_state->crypt=m->payloadEncryption;
  if (read_state->crypt){
    // if the manifest specifies encryption, make sure we can generate the payload key and encrypt
    // the contents as we go
    if (rhizome_derive_key(m, bsk)) {
      rhizome_read_close(read_state);
      return WHY("Unable to decrypt bundle, valid key not found");
    }
    if (config.debug.rhizome)
      DEBUGF("Decrypting payload contents for %s, %"PRId64, alloca_tohex_bid(m->cryptoSignPublic), m->version);
    
    read_state->tail = m->journalTail;
    bcopy(m->payloadKey, read_state->key, sizeof(read_state->key));
    bcopy(m->payloadNonce, read_state->nonce, sizeof(read_state->nonce));
  }
  return 0;
}

int rhizome_open_decrypt_read(rhizome_manifest *m, rhizome_bk_t *bsk, struct rhizome_read *read_state, int hash){
  // for now, always hash the file
  int ret = rhizome_open_read(read_state, m->fileHexHash, hash);
  if (ret == 0)
    ret = read_derive_key(m, bsk, read_state);
  return ret;
}

/* Extract the file related to a manifest to the file system.  The file will be de-crypted and
 * verified while reading.  If filepath is not supplied, the file will still be checked.
 *
 * Returns -1 on error, 0 if extracted successfully, 1 if not found.
 */
int rhizome_extract_file(rhizome_manifest *m, const char *filepath, rhizome_bk_t *bsk)
{
  struct rhizome_read read_state;
  bzero(&read_state, sizeof read_state);
  int ret = rhizome_open_decrypt_read(m, bsk, &read_state, 1);
  if (ret == 0)
    ret = write_file(&read_state, filepath);
  rhizome_read_close(&read_state);
  return ret;
}

/* dump the raw contents of a file
 *
 * Returns -1 on error, 0 if dumped successfully, 1 if not found.
 */
int rhizome_dump_file(const char *id, const char *filepath, int64_t *length)
{
  struct rhizome_read read_state;
  bzero(&read_state, sizeof read_state);

  int ret = rhizome_open_read(&read_state, id, 1);
  
  if (ret == 0) {
    ret = write_file(&read_state, filepath);
    if (length)
      *length = read_state.length;
  }
  rhizome_read_close(&read_state);
  return ret;
}

// pipe data from one payload to another
static int rhizome_pipe(struct rhizome_read *read, struct rhizome_write *write, uint64_t length)
{
  if (length > write->file_length - write->file_offset)
    return WHY("Unable to pipe that much data");

  unsigned char buffer[RHIZOME_CRYPT_PAGE_SIZE];
  while(length>0){
    int size=sizeof(buffer);
    if (size > length)
      size=length;

    int r = rhizome_read(read, buffer, size);
    if (r<0)
      return r;

    length -= r;
    
    if (rhizome_write_buffer(write, buffer, r))
      return -1;
  }

  return 0;
}

// open an existing journal bundle, advance the head pointer, duplicate the existing content and get ready to add more.
int rhizome_write_open_journal(struct rhizome_write *write, rhizome_manifest *m, rhizome_bk_t *bsk, uint64_t advance_by, uint64_t new_size)
{
  int ret = 0;

  if (advance_by > m->fileLength)
    return WHY("Cannot advance past the existing content");

  uint64_t old_length = m->fileLength;
  uint64_t copy_length = old_length - advance_by;
  
  m->fileLength = m->fileLength + new_size - advance_by;
  rhizome_manifest_set_ll(m, "filesize", m->fileLength);

  if (advance_by>0){
    m->journalTail += advance_by;
    rhizome_manifest_set_ll(m,"tail",m->journalTail);
  }

  m->version = m->fileLength;
  rhizome_manifest_set_ll(m,"version",m->version);

  ret = rhizome_open_write(write, NULL, m->fileLength, RHIZOME_PRIORITY_DEFAULT);
  if (ret)
    goto failure;

  if (copy_length>0){
    struct rhizome_read read_state;
    bzero(&read_state, sizeof read_state);
    // don't bother to decrypt the existing journal payload
    ret = rhizome_open_read(&read_state, m->fileHexHash, 1);
    if (ret)
      goto failure;

    read_state.offset = advance_by;
    ret = rhizome_pipe(&read_state, write, copy_length);
    rhizome_read_close(&read_state);
    if (ret)
      goto failure;
  }

  ret = rhizome_write_derive_key(m, bsk, write);
  if (ret)
    goto failure;
  
  return 0;

failure:
  if (ret)
    rhizome_fail_write(write);
  return ret;
}

int rhizome_append_journal_buffer(rhizome_manifest *m, rhizome_bk_t *bsk, uint64_t advance_by, unsigned char *buffer, int len)
{
  struct rhizome_write write;
  bzero(&write, sizeof write);

  int ret = rhizome_write_open_journal(&write, m, bsk, advance_by, len);
  if (ret)
    return -1;

  if (buffer && len){
    ret = rhizome_write_buffer(&write, buffer, len);
    if (ret)
      goto failure;
  }

  ret = rhizome_finish_write(&write);
  if (ret)
    goto failure;

  strlcpy(m->fileHexHash, write.id, SHA512_DIGEST_STRING_LENGTH);
  rhizome_manifest_set(m, "filehash", m->fileHexHash);
  return 0;

failure:
  if (ret)
    rhizome_fail_write(&write);
  return ret;
}

int rhizome_append_journal_file(rhizome_manifest *m, rhizome_bk_t *bsk, uint64_t advance_by, const char *filename)
{
  struct stat stat;
  if (lstat(filename,&stat))
    return WHYF("Could not stat() payload file '%s'",filename);

  struct rhizome_write write;
  bzero(&write, sizeof write);
  int ret = rhizome_write_open_journal(&write, m, bsk, advance_by, stat.st_size);
  if (ret)
    return -1;

  if (stat.st_size){
    ret = rhizome_write_file(&write, filename);
    if (ret)
      goto failure;
  }

  ret = rhizome_finish_write(&write);
  if (ret)
    goto failure;

  strlcpy(m->fileHexHash, write.id, SHA512_DIGEST_STRING_LENGTH);
  rhizome_manifest_set(m, "filehash", m->fileHexHash);

  return 0;

failure:
  if (ret)
    rhizome_fail_write(&write);
  return ret;
}

