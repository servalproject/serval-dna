#include <assert.h>
#include "serval.h"
#include "rhizome.h"
#include "conf.h"
#include "strlcpy.h"

#define RHIZOME_BUFFER_MAXIMUM_SIZE (1024*1024)

int rhizome_exists(const rhizome_filehash_t *hashp)
{
  int64_t gotfile = 0;
  if (sqlite_exec_int64(&gotfile, "SELECT COUNT(*) FROM FILES WHERE id = ? and datavalid = 1;", RHIZOME_FILEHASH_T, hashp, END) != 1)
    return 0;
  return gotfile;
}

int rhizome_open_write(struct rhizome_write *write, const rhizome_filehash_t *expectedHashp, uint64_t file_length, int priority)
{
  write->blob_fd=-1;
  
  if (expectedHashp){
    if (rhizome_exists(expectedHashp))
      return 1;
    write->id = *expectedHashp;
    write->id_known=1;
  }else{
    write->id_known=0;
  }
  time_ms_t now = gettime_ms();
  static uint64_t last_id=0;
  write->temp_id = now;
  if (write->temp_id < last_id)
    write->temp_id = last_id + 1;
  last_id = write->temp_id;
  
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  
  if (sqlite_exec_void_retry(&retry, "BEGIN TRANSACTION;", END) == -1)
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
  int ret = sqlite_exec_void_retry(
	&retry,
	"INSERT OR REPLACE INTO FILES(id,length,highestpriority,datavalid,inserttime) VALUES(?,?,?,0,?);",
	UINT64_TOSTR, write->temp_id,
	INT64, file_length,
	INT, priority,
	INT64, now,
	END
      );
  if (ret==-1)
    goto insert_row_fail;
  
  char blob_path[1024];
  
  if (config.rhizome.external_blobs || file_length > 128*1024) {
    if (!FORM_RHIZOME_DATASTORE_PATH(blob_path, "%"PRId64, write->temp_id)){
      WHY("Invalid path");
      goto insert_row_fail;
    }
    
    if (config.debug.externalblobs)
      DEBUGF("Attempting to put blob for id='%"PRId64"' in %s", write->temp_id, blob_path);
    
    write->blob_fd=open(blob_path, O_CREAT | O_TRUNC | O_WRONLY, 0664);
    if (write->blob_fd == -1)
      goto insert_row_fail;
    
    if (config.debug.externalblobs)
      DEBUGF("Writing to new blob file %s (fd=%d)", blob_path, write->blob_fd);
    
  }else{
    statement = sqlite_prepare_bind(
	&retry,
	"INSERT OR REPLACE INTO FILEBLOBS(id,data) VALUES(?,?)",
	UINT64_TOSTR, write->temp_id,
	ZEROBLOB, (int)file_length,
	END);
    if (statement == NULL)
      goto insert_row_fail;
    /* Do actual insert, and abort if it fails */
    int rowcount = 0;
    int stepcode;
    while ((stepcode = sqlite_step_retry(&retry, statement)) == SQLITE_ROW)
      ++rowcount;
    if (rowcount)
      WARNF("void query unexpectedly returned %d row%s", rowcount, rowcount == 1 ? "" : "s");
    if (!sqlite_code_ok(stepcode)){
    insert_row_fail:
      WHYF("Failed to insert row for id='%"PRId64"'", write->temp_id);
      if (statement) sqlite3_finalize(statement);
      sqlite_exec_void_retry(&retry, "ROLLBACK;", END);
      return -1;
    }
    sqlite3_finalize(statement);
    statement=NULL;
    
    /* Get rowid for inserted row, so that we can modify the blob */
    write->blob_rowid = sqlite3_last_insert_rowid(rhizome_db);
    if (config.debug.rhizome_rx)
      DEBUGF("Got rowid=%"PRId64" for id='%"PRId64"'", write->blob_rowid, write->temp_id);
    
  }
  
  if (sqlite_exec_void_retry(&retry, "COMMIT;", END) == -1){
    if (write->blob_fd != -1){
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
static int prepare_data(struct rhizome_write *write_state, unsigned char *buffer, size_t data_size)
{
  if (data_size <= 0)
    return WHY("No content supplied");
    
  /* Make sure we aren't being asked to write more data than we expected */
  if (write_state->file_offset + data_size > write_state->file_length)
    return WHYF("Too much content supplied, %"PRIu64" + %zu > %"PRIu64,
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
    DEBUGF("Processed %"PRIu64" of %"PRIu64, write_state->file_offset, write_state->file_length);
  return 0;
}

// open database locks
static int write_get_lock(struct rhizome_write *write_state){
  if (write_state->blob_fd != -1 || write_state->sql_blob)
    return 0;
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  
  // use an explicit transaction so we can delay I/O failures until COMMIT so they can be retried.
  if (sqlite_exec_void_retry(&retry, "BEGIN TRANSACTION;", END) == -1)
    return -1;
  
  while(1){
    int ret = sqlite3_blob_open(rhizome_db, "main", "FILEBLOBS", "data", 
		write_state->blob_rowid, 1 /* read/write */, &write_state->sql_blob);
    if (ret==SQLITE_OK){
      sqlite_retry_done(&retry, "sqlite3_blob_open");
      return 0;
    }
    if (!sqlite_code_busy(ret))
      return WHYF("sqlite3_blob_open() failed: %s", 
	     sqlite3_errmsg(rhizome_db));
    if (sqlite_retry(&retry, "sqlite3_blob_open")==0)
      return WHYF("Giving up");
  }
}

// write data to disk
static int write_data(struct rhizome_write *write_state, uint64_t file_offset, unsigned char *buffer, size_t data_size)
{
  if (config.debug.rhizome) {
    DEBUGF("write_state->file_length=%"PRIu64" file_offset=%"PRIu64, write_state->file_length, file_offset);
    //dump("buffer", buffer, data_size);
  }

  if (data_size<=0)
    return 0;
  
  if (file_offset != write_state->written_offset)
    WARNF("Writing file data out of order! [%"PRId64",%"PRId64"]", file_offset, write_state->written_offset);
    
  if (write_state->blob_fd != -1) {
    int ofs=0;
    // keep trying until all of the data is written.
    if (lseek64(write_state->blob_fd, (off64_t) file_offset, SEEK_SET) == -1)
      return WHYF_perror("lseek64(%d,%"PRIu64",SEEK_SET)", write_state->blob_fd, file_offset);
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
      if (ret==SQLITE_OK){
	sqlite_retry_done(&retry, "sqlite3_blob_write");
	break;
      }
      if (!sqlite_code_busy(ret))
	return WHYF("sqlite3_blob_write() failed: %s", 
	     sqlite3_errmsg(rhizome_db));
      if (sqlite_retry(&retry, "sqlite3_blob_write")==0)
	return WHY("Giving up");
    }
  }
  
  write_state->written_offset = file_offset + data_size;
  
  if (config.debug.rhizome)
    DEBUGF("Wrote %"PRIu64" of %"PRIu64, file_offset + data_size, write_state->file_length);
  return 0;
}

// close database locks
static int write_release_lock(struct rhizome_write *write_state){
  int ret=0;
  if (write_state->blob_fd != -1)
    return 0;
    
  if (write_state->sql_blob){
    ret = sqlite3_blob_close(write_state->sql_blob);
    if (ret)
      WHYF("sqlite3_blob_close() failed: %s", 
	     sqlite3_errmsg(rhizome_db));
    
    sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
    if (sqlite_exec_void_retry(&retry, "COMMIT;", END) == -1)
      ret=-1;
  }
  write_state->sql_blob=NULL;
  return ret;
}

// Write data buffers in any order, the data will be cached and streamed into the database in file order. 
// Though there is an upper bound on the amount of cached data
int rhizome_random_write(struct rhizome_write *write_state, uint64_t offset, unsigned char *buffer, size_t data_size)
{
  if (config.debug.rhizome) {
    DEBUGF("write_state->file_length=%"PRIu64" offset=%"PRIu64, write_state->file_length, offset);
    //dump("buffer", buffer, data_size);
  }
  if (offset + data_size > write_state->file_length)
    data_size = write_state->file_length - offset;
  
  struct rhizome_write_buffer **ptr = &write_state->buffer_list;
  int ret=0;
  int should_write = 0;
  // if we are writing to a file, or already have the sql blob open, write as much as we can.
  if (write_state->blob_fd != -1 || write_state->sql_blob){
    should_write = 1;
  }else{
    // cache up to RHIZOME_BUFFER_MAXIMUM_SIZE or file length before attempting to write everything in one go.
    // (Not perfect if the range overlaps)
    uint64_t new_size = write_state->written_offset + write_state->buffer_size + data_size;
    if (new_size >= write_state->file_length || new_size >= RHIZOME_BUFFER_MAXIMUM_SIZE)
      should_write = 1;
  }
  uint64_t last_offset = write_state->written_offset;
  
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
      size_t size = data_size;
      
      // allow for buffers to overlap, we may need to split the incoming buffer into multiple pieces.
      if (*ptr && offset+size > (*ptr)->offset)
	size = (*ptr)->offset - offset;
	
      if (should_write && offset == write_state->written_offset){
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
	  DEBUGF("Caching block @%"PRId64", %zu", offset, size);
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
  if (write_release_lock(write_state))
    ret=-1;
  return ret;
}

int rhizome_write_buffer(struct rhizome_write *write_state, unsigned char *buffer, size_t data_size)
{
  return rhizome_random_write(write_state, write_state->file_offset, buffer, data_size);
}

/* Expects file to be at least file_length in size, ignoring anything longer than that */
int rhizome_write_file(struct rhizome_write *write, const char *filename){
  FILE *f = fopen(filename, "r");
  if (!f)
    return WHY_perror("fopen");

  unsigned char buffer[RHIZOME_CRYPT_PAGE_SIZE];
  int ret=0;
  ret = write_get_lock(write);
  if (ret)
    goto end;
  while(write->file_offset < write->file_length) {
    size_t size = sizeof buffer;
    if (write->file_offset + size > write->file_length)
      size = write->file_length - write->file_offset;
    size_t r = fread(buffer, 1, size, f);
    if (ferror(f)){
      ret = WHY_perror("fread");
      goto end;
    }
    if (rhizome_write_buffer(write, buffer, r)){
      ret=-1;
      goto end;
    }
  }
end:
  if (write_release_lock(write))
    ret=-1;
  fclose(f);
  return ret;
}

int rhizome_fail_write(struct rhizome_write *write)
{
  if (write->blob_fd != -1){
    if (config.debug.externalblobs)
      DEBUGF("Closing and removing fd %d", write->blob_fd);
    close(write->blob_fd);
    write->blob_fd=-1;
  }
  write_release_lock(write);
  while(write->buffer_list){
    struct rhizome_write_buffer *n=write->buffer_list;
    write->buffer_list=n->_next;
    free(n);
  }
  rhizome_delete_file(&write->id);
  return 0;
}

int rhizome_finish_write(struct rhizome_write *write)
{
  if (write->blob_rowid==-1 && write->blob_fd == -1)
    return WHY("Can't finish a write that has already been closed");
  if (write->buffer_list){
    if (rhizome_random_write(write, 0, NULL, 0))
      goto failure;
    if (write->buffer_list){
      WHYF("Buffer was not cleared");
      goto failure;
    }
  }
  
  if (write->file_offset < write->file_length){
    WHYF("Only processed %"PRIu64" bytes, expected %"PRIu64, write->file_offset, write->file_length);
  }
    
  int fd = write->blob_fd;
  if (fd>=0){
    if (config.debug.externalblobs)
      DEBUGF("Closing fd %d", fd);
    close(fd);
    write->blob_fd=-1;
  }
  if (write_release_lock(write))
    goto failure;
  
  rhizome_filehash_t hash_out;
  SHA512_Final(hash_out.binary, &write->sha512_context);
  SHA512_End(&write->sha512_context, NULL);

  if (write->id_known) {
    if (cmp_rhizome_filehash_t(&write->id, &hash_out) != 0) {
      WHYF("expected filehash=%s, got %s", alloca_tohex_rhizome_filehash_t(write->id), alloca_tohex_rhizome_filehash_t(hash_out));
      goto failure;
    }
  } else {
    write->id = hash_out;
  }
  
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  rhizome_remove_file_datainvalid(&retry, &write->id);
  if (rhizome_exists(&write->id)) {
    // we've already got that payload, delete the new copy
    sqlite_exec_void_retry_loglevel(LOG_LEVEL_WARN, &retry, "DELETE FROM FILEBLOBS WHERE id = ?;", UINT64_TOSTR, write->temp_id, END);
    sqlite_exec_void_retry_loglevel(LOG_LEVEL_WARN, &retry, "DELETE FROM FILES WHERE id = ?;", UINT64_TOSTR, write->temp_id, END);
    if (config.debug.rhizome)
      DEBUGF("File id=%s already present, removed id='%"PRId64"'", alloca_tohex_rhizome_filehash_t(write->id), write->temp_id);
  } else {
    if (sqlite_exec_void_retry(&retry, "BEGIN TRANSACTION;", END) == -1)
      goto dbfailure;
    
    // delete any half finished records
    sqlite_exec_void_retry_loglevel(LOG_LEVEL_WARN, &retry, "DELETE FROM FILEBLOBS WHERE id = ?;", RHIZOME_FILEHASH_T, &write->id, END);
    sqlite_exec_void_retry_loglevel(LOG_LEVEL_WARN, &retry, "DELETE FROM FILES WHERE id = ?;", RHIZOME_FILEHASH_T, &write->id, END);
    
    if (sqlite_exec_void_retry(
	    &retry,
	    "UPDATE FILES SET id = ?, inserttime = ?, datavalid = 1 WHERE id = ?",
	    RHIZOME_FILEHASH_T, &write->id,
	    INT64, gettime_ms(),
	    UINT64_TOSTR, write->temp_id,
	    END
	  ) == -1
      )
      goto dbfailure;
    
    if (fd>=0){
      char blob_path[1024];
      char dest_path[1024];
      if (!FORM_RHIZOME_DATASTORE_PATH(blob_path, "%"PRId64, write->temp_id)){
	WHYF("Failed to generate file path");
	goto dbfailure;
      }
      if (!FORM_RHIZOME_DATASTORE_PATH(dest_path, alloca_tohex_rhizome_filehash_t(write->id))){
	WHYF("Failed to generate file path");
	goto dbfailure;
      }
      
      if (rename(blob_path, dest_path)){
	WHYF_perror("rename(%s, %s)", blob_path, dest_path);
	goto dbfailure;
      }
      
    }else{
      if (sqlite_exec_void_retry(
	    &retry,
	    "UPDATE FILEBLOBS SET id = ? WHERE rowid = ?",
	    RHIZOME_FILEHASH_T, &write->id,
	    INT64, write->blob_rowid,
	    END
	  ) == -1
	)
	  goto dbfailure;
    }
    if (sqlite_exec_void_retry(&retry, "COMMIT;", END) == -1)
      goto dbfailure;
    if (config.debug.rhizome)
      DEBUGF("Stored file %s", alloca_tohex_rhizome_filehash_t(write->id));
  }
  write->blob_rowid=-1;
  return 0;
  
dbfailure:
  sqlite_exec_void_retry(&retry, "ROLLBACK;", END);
failure:
  rhizome_fail_write(write);
  return -1;
}

// import a file for an existing bundle with a known file hash
int rhizome_import_file(rhizome_manifest *m, const char *filepath)
{
  assert(m->filesize != RHIZOME_SIZE_UNSET);
  if (m->filesize == 0)
    return 0;
  
  /* Import the file first, checking the hash as we go */
  struct rhizome_write write;
  bzero(&write, sizeof(write));
  
  int ret=rhizome_open_write(&write, &m->filehash, m->filesize, RHIZOME_PRIORITY_DEFAULT);
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

// store a whole payload from a single buffer
int rhizome_import_buffer(rhizome_manifest *m, unsigned char *buffer, size_t length)
{
  assert(m->filesize != RHIZOME_SIZE_UNSET);
  if (m->filesize == 0)
    return 0;

  if (length != m->filesize)
    return WHYF("Expected %"PRIu64" bytes, got %zu", m->filesize, length);
  
  /* Import the file first, checking the hash as we go */
  struct rhizome_write write;
  bzero(&write, sizeof(write));
  
  int ret=rhizome_open_write(&write, &m->filehash, m->filesize, RHIZOME_PRIORITY_DEFAULT);
  if (ret!=0)
    return ret;
  
  // file payload is not in the store yet
  if (rhizome_write_buffer(&write, buffer, length)){
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
  uint64_t size = 0;
  if (filepath[0]) {
    struct stat stat;
    if (lstat(filepath, &stat))
      return WHYF_perror("lstat(%s)", alloca_str_toprint(filepath));
    size = stat.st_size;
  }
  
  // Fail if the file is shorter than already specified by the manifest.
  if (m->filesize != RHIZOME_SIZE_UNSET && size < m->filesize)
    return WHY("Manifest length is longer than the file");
  
  // If the file is longer than already specified by the manifest, ignore the end of the file.
  if (m->filesize == RHIZOME_SIZE_UNSET || size > m->filesize)
    rhizome_manifest_set_filesize(m, size);
  return 0;
}

static int rhizome_write_derive_key(rhizome_manifest *m, rhizome_bk_t *bsk, struct rhizome_write *write)
{
  if (m->payloadEncryption != PAYLOAD_ENCRYPTED)
    return 0;
  
  // if the manifest specifies encryption, make sure we can generate the payload key and encrypt the contents as we go
  if (rhizome_derive_key(m, bsk))
    return -1;

  if (config.debug.rhizome)
    DEBUGF("Encrypting payload contents for %s, %"PRId64, alloca_tohex_rhizome_bid_t(m->cryptoSignPublic), m->version);

  write->crypt=1;
  if (m->is_journal && m->tail > 0)
    write->tail = m->tail;

  bcopy(m->payloadKey, write->key, sizeof(write->key));
  bcopy(m->payloadNonce, write->nonce, sizeof(write->nonce));
  return 0;
}

int rhizome_write_open_manifest(struct rhizome_write *write, rhizome_manifest *m)
{
  assert(m->filesize != RHIZOME_SIZE_UNSET);
  if (rhizome_open_write(write, NULL, m->filesize, RHIZOME_PRIORITY_DEFAULT))
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
  rhizome_manifest_set_filehash(m, &write.id);
  return 0;
failure:
  rhizome_fail_write(&write);
  return -1;
}

/* Return -1 on error, 0 if file blob found, 1 if not found.
 */
int rhizome_open_read(struct rhizome_read *read, const rhizome_filehash_t *hashp)
{
  read->id = *hashp;
  read->blob_rowid = -1;
  read->blob_fd = -1;
  if (sqlite_exec_int64(&read->blob_rowid,
      "SELECT FILEBLOBS.rowid "
      "FROM FILEBLOBS, FILES "
      "WHERE FILEBLOBS.id = FILES.id"
      " AND FILES.id = ?"
      " AND FILES.datavalid != 0", RHIZOME_FILEHASH_T, &read->id, END) == -1)
    return -1;
  if (read->blob_rowid != -1) {
    read->length = RHIZOME_SIZE_UNSET; // discover the length on opening the db BLOB
  } else {
    // No row in FILEBLOBS, look for an external blob file.
    char blob_path[1024];
    if (!FORM_RHIZOME_DATASTORE_PATH(blob_path, alloca_tohex_rhizome_filehash_t(read->id)))
      return -1;
    read->blob_fd = open(blob_path, O_RDONLY);
    if (read->blob_fd == -1) {
      if (errno == ENOENT)
	return 1; // file not available
      return WHYF_perror("open(%s)", alloca_str_toprint(blob_path));
    }
    off64_t pos = lseek64(read->blob_fd, 0, SEEK_END);
    if (pos == -1)
      return WHYF_perror("lseek64(%s,0,SEEK_END)", alloca_str_toprint(blob_path));
    read->length = pos;
    if (config.debug.externalblobs)
      DEBUGF("Opened stored file %s as fd %d, len %"PRIx64,blob_path, read->blob_fd, read->length);
  }
  read->offset = 0;
  read->hash_offset = 0;
  SHA512_Init(&read->sha512_context);
  return 0; // file opened
}

static ssize_t rhizome_read_retry(sqlite_retry_state *retry, struct rhizome_read *read_state, unsigned char *buffer, size_t bufsz)
{
  IN();
  if (read_state->blob_fd != -1) {
    if (lseek64(read_state->blob_fd, (off64_t) read_state->offset, SEEK_SET) == -1)
      RETURN(WHYF_perror("lseek64(%d,%"PRIu64",SEEK_SET)", read_state->blob_fd, read_state->offset));
    if (bufsz == 0)
      RETURN(0);
    ssize_t rd = read(read_state->blob_fd, buffer, bufsz);
    if (rd == -1)
      RETURN(WHYF_perror("read(%d,%p,%zu)", read_state->blob_fd, buffer, bufsz));
    if (config.debug.externalblobs)
      DEBUGF("Read %zu bytes from fd=%d @%"PRIx64, (size_t) rd, read_state->blob_fd, read_state->offset);
    RETURN(rd);
  }
  if (read_state->blob_rowid == -1)
    RETURN(WHY("file not open"));
  sqlite3_blob *blob = NULL;
  int ret;
  do {
    assert(blob == NULL);
    ret = sqlite3_blob_open(rhizome_db, "main", "FILEBLOBS", "data", read_state->blob_rowid, 0 /* read only */, &blob);
  } while (sqlite_code_busy(ret) && sqlite_retry(retry, "sqlite3_blob_open"));
  if (ret != SQLITE_OK) {
    assert(blob == NULL);
    RETURN(WHYF("sqlite3_blob_open() failed: %s", sqlite3_errmsg(rhizome_db)));
  }
  assert(blob != NULL);
  if (read_state->length == RHIZOME_SIZE_UNSET)
    read_state->length = sqlite3_blob_bytes(blob);
  // A NULL buffer skips the actual sqlite3_blob_read() call, which is useful just to work out
  // the length.
  size_t bytes_read = 0;
  if (buffer && bufsz && read_state->offset < read_state->length) {
    bytes_read = read_state->length - read_state->offset;
    if (bytes_read > bufsz)
      bytes_read = bufsz;
    assert(bytes_read > 0);
    do {
      ret = sqlite3_blob_read(blob, buffer, (int) bytes_read, read_state->offset);
    } while (sqlite_code_busy(ret) && sqlite_retry(retry, "sqlite3_blob_read"));
    if (ret != SQLITE_OK) {
      WHYF("sqlite3_blob_read() failed: %s", sqlite3_errmsg(rhizome_db));
      sqlite3_blob_close(blob);
      RETURN(-1);
    }
  }
  sqlite3_blob_close(blob);
  RETURN(bytes_read);
  OUT();
}

/* Read content from the store, hashing and decrypting as we go. 
 Random access is supported, but hashing requires all payload contents to be read sequentially. */
// returns the number of bytes read
ssize_t rhizome_read(struct rhizome_read *read_state, unsigned char *buffer, size_t buffer_length)
{
  IN();
  // hash check failed, just return an error
  if (read_state->invalid)
    RETURN(-1);

  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  ssize_t n = rhizome_read_retry(&retry, read_state, buffer, buffer_length);
  if (n == -1)
    RETURN(-1);
  size_t bytes_read = (size_t) n;

  // hash the payload as we go, but only if we happen to read the payload data in order
  if (read_state->hash_offset == read_state->offset && buffer && bytes_read>0){
    SHA512_Update(&read_state->sha512_context, buffer, bytes_read);
    read_state->hash_offset += bytes_read;
    // if we hash everything and the has doesn't match, we need to delete the payload
    if (read_state->hash_offset>=read_state->length){
      rhizome_filehash_t hash_out;
      SHA512_Final(hash_out.binary, &read_state->sha512_context);
      SHA512_End(&read_state->sha512_context, NULL);
      if (cmp_rhizome_filehash_t(&read_state->id, &hash_out) != 0) {
	// hash failure, mark the payload as invalid
	read_state->invalid = 1;
	RETURN(WHYF("Expected hash=%s, got %s", alloca_tohex_rhizome_filehash_t(read_state->id), alloca_tohex_rhizome_filehash_t(hash_out)));
      }
    }
  }
  
  if (read_state->crypt && buffer && bytes_read>0){
    dump("before decrypt", buffer, bytes_read);
    if(rhizome_crypt_xor_block(
	buffer, bytes_read, 
	read_state->offset + read_state->tail, 
	read_state->key, read_state->nonce)){
      RETURN(-1);
    }
  }
  read_state->offset += bytes_read;
  if (config.debug.rhizome) {
    DEBUGF("read %zu bytes, read_state->offset=%"PRIu64, bytes_read, read_state->offset);
    //dump("buffer", buffer, bytes_read);
  }
  RETURN(bytes_read);
  OUT();
}

/* Read len bytes from read->offset into data, using *buffer to cache any reads */
ssize_t rhizome_read_buffered(struct rhizome_read *read, struct rhizome_read_buffer *buffer, unsigned char *data, size_t len)
{
  size_t bytes_copied=0;
  
  while (len>0){
    DEBUGF("len=%zu read->length=%"PRIu64" read->offset=%"PRIu64" buffer->offset=%"PRIu64"", len, read->length, read->offset, buffer->offset);
    // make sure we only attempt to read data that actually exists
    if (read->length != RHIZOME_SIZE_UNSET && read->offset + len > read->length)
      len = read->length - read->offset;

    // if we can supply either the beginning or end of the data from cache, do that first.
    if (read->offset >= buffer->offset) {
      assert(read->offset - buffer->offset <= SIZE_MAX);
      size_t ofs = read->offset - buffer->offset;
      if (ofs <= buffer->len){
	size_t size = len;
	if (size > buffer->len - ofs)
	  size = buffer->len - ofs;
	if (size > 0){
	  // copy into the start of the data buffer
	  bcopy(buffer->data + ofs, data, size);
	  data+=size;
	  len-=size;
	  read->offset+=size;
	  bytes_copied+=size;
	  DEBUGF("read->offset=%"PRIu64, read->offset);
	  continue;
	}
      }
    }
    
    if (read->offset + len > buffer->offset) {
      assert(read->offset + len - buffer->offset <= SIZE_MAX);
      size_t ofs = read->offset + len - buffer->offset;
      if (ofs <= buffer->len){
	size_t size = len;
	if (size > ofs)
	  size = ofs;
	if (size>0){
	  // copy into the end of the data buffer
	  bcopy(buffer->data + ofs - size, data + len - size, size);
	  len-=size;
	  bytes_copied+=size;
	  DEBUGF("read->offset=%"PRIu64, read->offset);
	  continue;
	}
      }
    }
    
    // ok, so we need to read a new buffer to fulfill the request.
    // remember the requested read offset so we can put it back
    uint64_t ofs = read->offset;
    buffer->offset = read->offset = ofs & ~(RHIZOME_CRYPT_PAGE_SIZE -1);
    ssize_t r = rhizome_read(read, buffer->data, sizeof buffer->data);
    read->offset = ofs;
    buffer->len = 0;
    if (r == -1)
      return -1;
    buffer->len = (size_t) r;
    DEBUGF("read->offset=%"PRIu64, read->offset);
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
  if (read->invalid){
    // delete payload!
    rhizome_delete_file(&read->id);
  }
  return 0;
}

struct cache_entry{
  struct cache_entry *_left;
  struct cache_entry *_right;
  rhizome_bid_t bundle_id;
  uint64_t version;
  struct rhizome_read read_state;
  time_ms_t expires;
};
struct cache_entry *root;

static struct cache_entry ** find_entry_location(struct cache_entry **ptr, const rhizome_bid_t *bundle_id, uint64_t version)
{
  while(*ptr){
    struct cache_entry *entry = *ptr;
    int cmp = cmp_rhizome_bid_t(bundle_id, &entry->bundle_id);
    if (cmp==0){
      if (entry->version==version)
	break;
      if (version < entry->version)
	ptr = &entry->_left;
      else
	ptr = &entry->_right;
      continue;
    }
    if (cmp<0)
      ptr = &entry->_left;
    else
      ptr = &entry->_right;
  }
  return ptr;
}

static time_ms_t close_entries(struct cache_entry **entry, time_ms_t timeout)
{
  if (!*entry)
    return 0;
    
  time_ms_t ret = close_entries(&(*entry)->_left, timeout);
  time_ms_t t_right = close_entries(&(*entry)->_right, timeout);
  if (t_right!=0 && (t_right < ret || ret==0))
    ret=t_right;
    
  if ((*entry)->expires < timeout || timeout==0){
    rhizome_read_close(&(*entry)->read_state);
    // remember the two children
    struct cache_entry *left=(*entry)->_left;
    struct cache_entry *right=(*entry)->_right;
    // free this entry
    free(*entry);
    // re-add both children to the tree
    *entry=left;
    if (right){
      entry = find_entry_location(entry, &right->bundle_id, right->version);
      *entry=right;
    }
  }else{
    if ((*entry)->expires < ret || ret==0)
      ret=(*entry)->expires;
  }
  return ret;
}

// close any expired cache entries
static void rhizome_cache_alarm(struct sched_ent *alarm)
{
  alarm->alarm = close_entries(&root, gettime_ms());
  if (alarm->alarm){
    alarm->deadline = alarm->alarm + 1000;
    schedule(alarm);
  }
}

static struct profile_total cache_alarm_stats={
  .name="rhizome_cache_alarm",
};
static struct sched_ent cache_alarm={
  .function = rhizome_cache_alarm,
  .stats = &cache_alarm_stats,
};

// close all cache entries
int rhizome_cache_close()
{
  close_entries(&root, 0);
  unschedule(&cache_alarm);
  return 0;
}

static int _rhizome_cache_count(struct cache_entry *entry)
{
  if (!entry)
    return 0;
  return 1+_rhizome_cache_count(entry->_left)+_rhizome_cache_count(entry->_right);
}

int rhizome_cache_count()
{
  return _rhizome_cache_count(root);
}

// read a block of data, caching meta data for reuse
int rhizome_read_cached(const rhizome_bid_t *bidp, uint64_t version, time_ms_t timeout, uint64_t fileOffset, unsigned char *buffer, size_t length)
{
  // look for a cached entry
  struct cache_entry **ptr = find_entry_location(&root, bidp, version);
  struct cache_entry *entry = *ptr;
  
  // if we don't have one yet, create one and open it
  if (!entry){
    rhizome_filehash_t filehash;
    if (rhizome_database_filehash_from_id(bidp, version, &filehash) == -1)
      return -1;
    entry = emalloc_zero(sizeof(struct cache_entry));
    if (rhizome_open_read(&entry->read_state, &filehash)){
      free(entry);
      return WHYF("Payload %s not found", alloca_tohex_rhizome_filehash_t(filehash));
    }
    entry->bundle_id = *bidp;
    entry->version = version;
    *ptr = entry;
  }
  
  entry->read_state.offset = fileOffset;
  if (entry->read_state.length !=-1 && fileOffset >= entry->read_state.length)
    return 0;
  
  if (entry->expires < timeout){
    entry->expires = timeout;
    
    if (!cache_alarm.alarm){
      cache_alarm.alarm = timeout;
      cache_alarm.deadline = timeout + 1000;
      schedule(&cache_alarm);
    }
  }
  
  return rhizome_read(&entry->read_state, buffer, length);
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

static int read_derive_key(rhizome_manifest *m, rhizome_bk_t *bsk, struct rhizome_read *read_state)
{
  read_state->crypt = m->payloadEncryption == PAYLOAD_ENCRYPTED;
  if (read_state->crypt){
    // if the manifest specifies encryption, make sure we can generate the payload key and encrypt
    // the contents as we go
    if (rhizome_derive_key(m, bsk)) {
      rhizome_read_close(read_state);
      return WHY("Unable to decrypt bundle, valid key not found");
    }
    if (config.debug.rhizome)
      DEBUGF("Decrypting payload contents for bid=%s version=%"PRId64, alloca_tohex_rhizome_bid_t(m->cryptoSignPublic), m->version);
    if (m->is_journal && m->tail > 0)
      read_state->tail = m->tail;
    bcopy(m->payloadKey, read_state->key, sizeof(read_state->key));
    bcopy(m->payloadNonce, read_state->nonce, sizeof(read_state->nonce));
  }
  return 0;
}

int rhizome_open_decrypt_read(rhizome_manifest *m, rhizome_bk_t *bsk, struct rhizome_read *read_state)
{
  int ret = rhizome_open_read(read_state, &m->filehash);
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
  int ret = rhizome_open_decrypt_read(m, bsk, &read_state);
  if (ret == 0)
    ret = write_file(&read_state, filepath);
  rhizome_read_close(&read_state);
  return ret;
}

/* dump the raw contents of a file
 *
 * Returns -1 on error, 0 if dumped successfully, 1 if not found.
 */
int rhizome_dump_file(const rhizome_filehash_t *hashp, const char *filepath, int64_t *length)
{
  struct rhizome_read read_state;
  bzero(&read_state, sizeof read_state);

  int ret = rhizome_open_read(&read_state, hashp);
  
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
    size_t size=sizeof(buffer);
    if (size > length)
      size=length;

    ssize_t r = rhizome_read(read, buffer, size);
    if (r == -1)
      return r;

    length -= (size_t) r;
    
    if (rhizome_write_buffer(write, buffer, (size_t) r))
      return -1;
  }

  return 0;
}

int rhizome_journal_pipe(struct rhizome_write *write, const rhizome_filehash_t *hashp, uint64_t start_offset, uint64_t length)
{
  struct rhizome_read read_state;
  bzero(&read_state, sizeof read_state);
  if (rhizome_open_read(&read_state, hashp))
    return -1;
  read_state.offset = start_offset;
  int ret = rhizome_pipe(&read_state, write, length);
  rhizome_read_close(&read_state);
  return ret;
}

// open an existing journal bundle, advance the head pointer, duplicate the existing content and get ready to add more.
int rhizome_write_open_journal(struct rhizome_write *write, rhizome_manifest *m, rhizome_bk_t *bsk, uint64_t advance_by, uint64_t new_size)
{
  int ret = 0;

  assert(m->filesize != RHIZOME_SIZE_UNSET);
  assert(m->is_journal);
  if (advance_by > m->filesize)
    return WHY("Cannot advance past the existing content");

  uint64_t copy_length = m->filesize - advance_by;
  rhizome_manifest_set_filesize(m, m->filesize + new_size - advance_by);

  if (advance_by > 0)
    rhizome_manifest_set_tail(m, m->tail + advance_by);

  rhizome_manifest_set_version(m, m->filesize);

  ret = rhizome_open_write(write, NULL, m->filesize, RHIZOME_PRIORITY_DEFAULT);
  if (ret)
    goto failure;

  if (copy_length>0){
    // note that we don't need to bother decrypting the existing journal payload
    ret = rhizome_journal_pipe(write, &m->filehash, advance_by, copy_length);
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

int rhizome_append_journal_buffer(rhizome_manifest *m, rhizome_bk_t *bsk, uint64_t advance_by, unsigned char *buffer, size_t len)
{
  struct rhizome_write write;
  bzero(&write, sizeof write);

  int ret = rhizome_write_open_journal(&write, m, bsk, advance_by, (uint64_t) len);
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

  rhizome_manifest_set_filehash(m, &write.id);
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
    return WHYF_perror("stat(%s)", alloca_str_toprint(filename));

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

  rhizome_manifest_set_filehash(m, &write.id);

  return 0;

failure:
  if (ret)
    rhizome_fail_write(&write);
  return ret;
}

