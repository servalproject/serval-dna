#include "serval.h"
#include "rhizome.h"
#include "conf.h"
#include "strlcpy.h"

#define RHIZOME_BUFFER_MAXIMUM_SIZE (1024*1024)

int rhizome_exists(const char *fileHash){
  long long gotfile = 0;
  
  if (sqlite_exec_int64(&gotfile, 
	"SELECT COUNT(*) FROM FILES WHERE ID='%s' and datavalid=1;", 
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
  
  if (config.rhizome.external_blobs) {
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
      DEBUGF("Blob file created (fd=%d)", write->blob_fd);
    
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
      DEBUGF("Got rowid %lld for %s", write->blob_rowid, write->id);
    
  }
  
  if (sqlite_exec_void_retry(&retry, "COMMIT;") == -1){
    if (write->blob_fd>0){
      close(write->blob_fd);
      unlink(blob_path);
    }
    return -1;
  }
  
  write->file_length = file_length;
  write->file_offset = 0;
  
  SHA512_Init(&write->sha512_context);
  
  write->buffer_size=write->file_length;
  
  if (write->buffer_size>RHIZOME_BUFFER_MAXIMUM_SIZE)
    write->buffer_size=RHIZOME_BUFFER_MAXIMUM_SIZE;
  
  write->buffer=malloc(write->buffer_size);
  if (!write->buffer)
    return WHY("Unable to allocate write buffer");
  
  return 0;
}

/* Write write_state->buffer into the store
 Note that we don't support random writes as the contents must be hashed in order 
 But we don't enforce linear writes yet. */
int rhizome_flush(struct rhizome_write *write_state){
  IN();
  /* Make sure we aren't being asked to write more data than we expected */
  if (write_state->file_offset + write_state->data_size > write_state->file_length)
    RETURN(WHYF("Too much content supplied, %d + %d > %d", 
		write_state->file_offset, write_state->data_size, write_state->file_length));
  
  if (write_state->data_size<=0)
    RETURN(WHY("No content supplied"));
  
  if (write_state->crypt){
    if (rhizome_crypt_xor_block(write_state->buffer, write_state->data_size, 
				write_state->file_offset, write_state->key, write_state->nonce))
      RETURN(-1);
  }
  
  if (config.rhizome.external_blobs) {
    int ofs=0;
    // keep trying until all of the data is written.
    while(ofs < write_state->data_size){
      int r=write(write_state->blob_fd, write_state->buffer + ofs, write_state->data_size - ofs);
      if (r<0)
	RETURN(WHY_perror("write"));
      DEBUGF("Wrote %d bytes into external blob", r);
      ofs+=r;
    }
  }else{
    sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
    
    do{
      
      sqlite3_blob *blob=NULL;
      
      int ret = sqlite3_blob_open(rhizome_db, "main", "FILEBLOBS", "data", write_state->blob_rowid, 1 /* read/write */, &blob);
      if (sqlite_code_busy(ret))
	goto again;
      else if (ret!=SQLITE_OK) {
	WHYF("sqlite3_blob_open() failed: %s", 
	     sqlite3_errmsg(rhizome_db));
	if (blob) sqlite3_blob_close(blob);
	RETURN(-1);
      }
      
      ret=sqlite3_blob_write(blob, write_state->buffer, write_state->data_size, 
			     write_state->file_offset);
      
      if (sqlite_code_busy(ret))
	goto again;
      else if (ret!=SQLITE_OK) {
	WHYF("sqlite3_blob_write() failed: %s", 
	     sqlite3_errmsg(rhizome_db));
	if (blob) sqlite3_blob_close(blob);
	RETURN(-1);
      }
      
      ret = sqlite3_blob_close(blob);
      blob=NULL;
      if (sqlite_code_busy(ret))
	goto again;
      else if (ret==SQLITE_OK){
	break;
      }
      
      RETURN(WHYF("sqlite3_blob_close() failed: %s", sqlite3_errmsg(rhizome_db)));
      
    again:
      if (blob) sqlite3_blob_close(blob);
      if (sqlite_retry(&retry, "sqlite3_blob_write")==0)
	RETURN(1);
      
    }while(1);
  }
  
  SHA512_Update(&write_state->sha512_context, write_state->buffer, write_state->data_size);
  write_state->file_offset+=write_state->data_size;
  if (config.debug.rhizome)
    DEBUGF("Written %lld of %lld", write_state->file_offset, write_state->file_length);
  write_state->data_size=0;
  RETURN(0);
  OUT();
}

/* Expects file to be at least file_length in size, ignoring anything longer than that */
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
  if (write->buffer)
    free(write->buffer);
  write->buffer=NULL;
  
  if (write->blob_fd){
    close(write->blob_fd);
    rhizome_store_delete(write->id);
  }
  
  // don't worry too much about sql failures.
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  if (!config.rhizome.external_blobs)
    sqlite_exec_void_retry_loglevel(LOG_LEVEL_WARN, &retry,
			   "DELETE FROM FILEBLOBS WHERE rowid=%lld",write->blob_rowid);
  sqlite_exec_void_retry_loglevel(LOG_LEVEL_WARN, &retry,
			 "DELETE FROM FILES WHERE id='%s'",
			 write->id);
  return 0; 
}

int rhizome_finish_write(struct rhizome_write *write){
  if (write->data_size>0){
    if (rhizome_flush(write))
      return -1;
  }
  if (write->blob_fd)
    close(write->blob_fd);
  if (write->buffer)
    free(write->buffer);
  write->buffer=NULL;
  
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
      
      if (config.rhizome.external_blobs){
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
  if (read_state->blob_fd != -1) {
    //positionne le pointeur
     if (lseek(read_state->blob_fd, read_state->offset, SEEK_SET) == -1)
      RETURN(WHYF_perror("lseek(%d,%ld,SEEK_SET)", read_state->blob_fd, (long)read_state->offset));
    
    // read buffer-lenght char and store in buffer
    bytes_read = read(read_state->blob_fd, buffer, buffer_length);
    
    if (bytes_read == -1)
      RETURN(WHYF_perror("read(%d,%p,%ld)", read_state->blob_fd, buffer, (long)buffer_length));
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
    if(rhizome_crypt_xor_block(buffer, bytes_read, read_state->offset, read_state->key, read_state->nonce)){
      RETURN(-1);
    }
  }
  read_state->offset+=bytes_read;
  RETURN(bytes_read);
  OUT();
}

int rhizome_read_close(struct rhizome_read *read)
{
  if (read->blob_fd != -1)
    close(read->blob_fd);
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

int rhizome_open_decrypt_read(rhizome_manifest *m, rhizome_bk_t *bsk, struct rhizome_read *read_state, int hash){
  
  // for now, always hash the file
  int ret = rhizome_open_read(read_state, m->fileHexHash, hash);
  if (ret == 0) {
    read_state->crypt=m->payloadEncryption;
    if (read_state->crypt){
      // if the manifest specifies encryption, make sure we can generate the payload key and encrypt
      // the contents as we go
      if (rhizome_derive_key(m, bsk)) {
	rhizome_read_close(read_state);
	return -1;
      }
      if (config.debug.rhizome)
	DEBUGF("Decrypting file contents");
      bcopy(m->payloadKey, read_state->key, sizeof(read_state->key));
      bcopy(m->payloadNonce, read_state->nonce, sizeof(read_state->nonce));
    }
  }
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


/*int rhizome_write_messsage(const char *manifestid)
{
//if (config.debug.verbose)
 //   DEBUG_cli_parsed(parsed);
  
  const char *bskhex ;

  //const char *manifestpath, *filepath, *manifestid, *bskhex;
 
  //if (cli_arg(parsed, "manifestid", &manifestid, cli_manifestid, "") == -1 )
  //   return -1;
  //else {
//	cli_puts(manifestid);
//	cli_delim("\n");
//  }
  
  //int extract = strcasecmp(parsed->args[1], "extract")==0;
  
  // Ensure the Rhizome database exists and is open 
  if (create_serval_instance_dir() == -1)
    return -1;
  if (rhizome_opendb() == -1)
    return -1;
  
  // What does that mean ?
 // if (!(keyring = keyring_open_instance_cli(parsed)))
  //  return -1;
  
  int ret=0;
  
  //manifestid is in hex
  unsigned char manifest_id[RHIZOME_MANIFEST_ID_BYTES];
  if (fromhexstr(manifest_id, manifestid, RHIZOME_MANIFEST_ID_BYTES) == -1)
    return WHY("Invalid manifest ID");
  
  char manifestIdUpper[RHIZOME_MANIFEST_ID_STRLEN + 1];
  tohex(manifestIdUpper, manifest_id, RHIZOME_MANIFEST_ID_BYTES);

  //cli_puts("manifestid"); cli_delim(":"); cli_puts(manifestIdUpper); cli_delim("\n");
  
  // treat empty string the same as null
  if (bskhex && !*bskhex)
    bskhex=NULL;
  
  rhizome_bk_t bsk;
  if (bskhex && fromhexstr(bsk.binary, bskhex, RHIZOME_BUNDLE_KEY_BYTES) == -1)
    return WHYF("invalid bsk: \"%s\"", bskhex);

  rhizome_manifest *m = rhizome_new_manifest();
  if (m==NULL)
    return WHY("Out of manifests");
  
  ret = rhizome_retrieve_manifest(manifestIdUpper, m);
  
  if (ret==0){
    // ignore errors
    rhizome_extract_privatekey(m, NULL);
    const char *blob_service = rhizome_manifest_get(m, "service", NULL, 0);
    
    cli_puts("service");    cli_delim(":"); cli_puts(blob_service); cli_delim("\n");
    cli_puts("manifestid"); cli_delim(":"); cli_puts(manifestIdUpper); cli_delim("\n");
    cli_puts("version");    cli_delim(":"); cli_printf("%lld", m->version); cli_delim("\n");
    cli_puts("inserttime"); cli_delim(":"); cli_printf("%lld", m->inserttime); cli_delim("\n");
    if (m->haveSecret) {
      cli_puts(".author");  cli_delim(":"); cli_puts(alloca_tohex_sid(m->author)); cli_delim("\n");
    }
    cli_puts(".readonly");  cli_delim(":"); cli_printf("%d", m->haveSecret?0:1); cli_delim("\n");
    cli_puts("filesize");   cli_delim(":"); cli_printf("%lld", (long long) m->fileLength); cli_delim("\n");
    if (m->fileLength != 0) {
      cli_puts("filehash"); cli_delim(":"); cli_puts(m->fileHexHash); cli_delim("\n");
    }
  }
  
  int retfile=0;

  // From Rhizome_import_file in rhizome_store.c
  //if (m->fileLength<=0)
  //  return 0;
  
  // Import the file first, checking the hash as we go 
  struct rhizome_write write;
  bzero(&write, sizeof(write));
  
  //int ret=rhizome_open_write(&write, m->fileHexHash, m->fileLength, RHIZOME_PRIORITY_DEFAULT);
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


  
  // ret=0 if retrieve manifest is ok
  if (ret==0 && m->fileLength != 0 ){   
    // Rhizome_extract_file 
   
    // là il faut écire dans un file, utilisation de 
    struct rhizome_read read_state;
    bzero(&read_state, sizeof read_state);
    int ret = rhizome_open_decrypt_read(m, bskhex?&bsk:NULL, &read_state, 1);
  if (ret == 0)
     cli_puts("the file exist, we will read the file"); cli_delim("\n");
 
  int read_byte_version ;
  unsigned char *buffer_version;
  int buffer_length_version=100;
  buffer_version=malloc(100);
  read_byte_version=rhizome_read(&read_state, buffer_version, buffer_length_version); 
  int i=0;
  cli_puts("read_byte_version");cli_delim(":");cli_printf("%d", read_byte_version); cli_delim("\n");
  hex_dump(buffer_version, buffer_length_version);


 
    //ret = write_file(&read_state, filepath);
  rhizome_read_close(&read_state);}
  //return ret;

  /*if (ret==0 && m->fileLength != 0 && filepath && *filepath){
    if (extract){

      // Save the file, implicitly decrypting if required.
      // TODO, this may cause us to search for an author a second time if the above call to rhizome_extract_privatekey failed
      retfile = rhizome_extract_file(m, filepath, bskhex?&bsk:NULL);
    }else{
      // Save the file without attempting to decrypt
      int64_t length;
      retfile = rhizome_dump_file(m->fileHexHash, filepath, &length);
    }
  }
  
  if (ret==0 && manifestpath && *manifestpath){
    if (strcmp(manifestpath, "-") == 0) {
      // always extract a manifest to stdout, even if writing the file itself failed.
      cli_puts("manifest");
      cli_delim(":");
      cli_write(m->manifestdata, m->manifest_all_bytes);
      cli_delim("\n");
    } else {
      int append = (strcmp(manifestpath, filepath)==0)?1:0;
      // don't write out the manifest if we were asked to append it and writing the file failed.
      if ((!append) || retfile==0){
	/* If the manifest has been read in from database, the blob is there,
	 and we can lie and say we are finalised and just want to write it
	 out.  TODO: really should have a dirty/clean flag, so that write
	 works if clean but not finalised. 
	m->finalised=1;
	if (rhizome_write_manifest_file(m, manifestpath, append) == -1)
	  ret = -1;
      }
    }
  }
  if (retfile)
    ret = retfile == -1 ? -1 : 1;
  if (m)
    rhizome_manifest_free(m);
  return ret; 
  
  return ret;






} */
