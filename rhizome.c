#include "mphlr.h"
#include "rhizome.h"

long long rhizome_space=0;
char *rhizome_datastore_path=NULL;

sqlite3 *rhizome_db=NULL;

int rhizome_opendb()
{
  if (rhizome_db) return 0;
  char dbname[1024];

  if (!rhizome_datastore_path) {
    fprintf(stderr,"Cannot open rhizome database -- no path specified\n");
    exit(1);
  }
  if (strlen(rhizome_datastore_path)>1000) {
    fprintf(stderr,"Cannot open rhizome database -- data store path is too long\n");
    exit(1);
  }
  snprintf(dbname,1024,"%s/rhizome.db",rhizome_datastore_path);

  int r=sqlite3_open(dbname,&rhizome_db);
  if (r) {
    fprintf(stderr,"SQLite could not open database: %s\n",sqlite3_errmsg(rhizome_db));
    exit(1);
  }

  /* Read Rhizome configuration, and write it back out as we understand it. */
  char conf[1024];
  snprintf(conf,1024,"%s/rhizome.conf",rhizome_datastore_path);
  FILE *f=fopen(conf,"r");
  if (f) {
    char line[1024];
    line[0]=0; fgets(line,1024,f);
    while (line[0]) {
      if (sscanf(line,"space=%lld",&rhizome_space)==1) { 
	rhizome_space*=1024; /* Units are kilobytes */
      }
      line[0]=0; fgets(line,1024,f);
    }
    fclose(f);
  }
  f=fopen(conf,"w");
  if (f) {
    fprintf(f,"space=%lld\n",rhizome_space/1024LL);
    fclose(f);
  }

  /* Create tables if required */
  if (sqlite3_exec(rhizome_db,"PRAGMA auto_vacuum=2;",NULL,NULL,NULL)) {
      fprintf(stderr,"SQLite could enable incremental vacuuming: %s\n",sqlite3_errmsg(rhizome_db));
      exit(1);
  }
  if (sqlite3_exec(rhizome_db,"CREATE TABLE IF NOT EXISTS GROUPLIST(id text not null primary key, closed integer,ciphered integer);",NULL,NULL,NULL))
    {
      fprintf(stderr,"SQLite could not create GROUPLIST table: %s\n",sqlite3_errmsg(rhizome_db));
      exit(1);
    }
  if (sqlite3_exec(rhizome_db,"CREATE TABLE IF NOT EXISTS MANIFESTS(id text not null primary key, manifest blob, version integer,inserttime integer);",NULL,NULL,NULL))
    {
      fprintf(stderr,"SQLite could not create MANIFESTS table: %s\n",sqlite3_errmsg(rhizome_db));
      exit(1);
    }
  if (sqlite3_exec(rhizome_db,"CREATE TABLE IF NOT EXISTS KEYPAIRS(public text not null primary key, private text not null);",NULL,NULL,NULL))
    {
      fprintf(stderr,"SQLite could not create KEYPAIRS table: %s\n",sqlite3_errmsg(rhizome_db));
      exit(1);
    }
  if (sqlite3_exec(rhizome_db,"CREATE TABLE IF NOT EXISTS FILES(id text not null primary key, data blob, length integer, highestpriority integer, datavalid integer);",NULL,NULL,NULL))
    {
      fprintf(stderr,"SQLite could not create FILES table: %s\n",sqlite3_errmsg(rhizome_db));
      exit(1);
    }
  if (sqlite3_exec(rhizome_db,"CREATE TABLE IF NOT EXISTS FILEMANIFESTS(fileid text not null, manifestid text not null);",NULL,NULL,NULL))
    {
      fprintf(stderr,"SQLite could not create FILEMANIFESTS table: %s\n",sqlite3_errmsg(rhizome_db));
      exit(1);
    }
  if (sqlite3_exec(rhizome_db,"CREATE TABLE IF NOT EXISTS GROUPMEMBERSHIPS(manifestid text not null, groupid text not null);",NULL,NULL,NULL))
    {
      fprintf(stderr,"SQLite could not create GROUPMEMBERSHIPS table: %s\n",sqlite3_errmsg(rhizome_db));
      exit(1);
    }
  
  /* XXX Setup special groups, e.g., Serval Software and Serval Optional Data */

  return 0;
}

/* 
   Convenience wrapper for executing an SQL command that returns a single int64 value 
 */
long long sqlite_exec_int64(char *sqlformat,...)
{
  if (!rhizome_db) rhizome_opendb();

  va_list ap,ap2;
  char sqlstatement[8192];

  va_start(ap,sqlformat);
  va_copy(ap2,ap);

  vsnprintf(sqlstatement,8192,sqlformat,ap2); sqlstatement[8191]=0;

  va_end(ap);

  sqlite3_stmt *statement;
  switch (sqlite3_prepare_v2(rhizome_db,sqlstatement,-1,&statement,NULL))
    {
    case SQLITE_OK: case SQLITE_DONE: case SQLITE_ROW:
      break;
    default:
      sqlite3_finalize(statement);
      sqlite3_close(rhizome_db);
      rhizome_db=NULL;
      WHY(sqlstatement);
      WHY(sqlite3_errmsg(rhizome_db));
      return WHY("Could not prepare sql statement.");
    }
   if (sqlite3_step(statement) == SQLITE_ROW)
     {
       if (sqlite3_column_count(statement)!=1) {
	 sqlite3_finalize(statement);
	 return -1;
       }
       long long result= sqlite3_column_int(statement,0);
       sqlite3_finalize(statement);
       return result;
     }
   sqlite3_finalize(statement);
   return 0;
}

long long rhizome_database_used_bytes()
{
  long long db_page_size=sqlite_exec_int64("PRAGMA page_size;");
  long long db_page_count=sqlite_exec_int64("PRAGMA page_count;");
  long long db_free_page_count=sqlite_exec_int64("PRAGMA free_count;");
  return db_page_size*(db_page_count-db_free_page_count);
}

int rhizome_make_space(int group_priority, long long bytes)
{
  sqlite3_stmt *statement;

  /* Asked for impossibly large amount */
  if (bytes>=(rhizome_space-65536)) return -1;

  long long db_used=rhizome_database_used_bytes(); 
  
  /* If there is already enough space now, then do nothing more */
  if (db_used<=(rhizome_space-bytes-65536)) return 0;

  /* Okay, not enough space, so free up some. */
  char sql[1024];
  snprintf(sql,1024,"select id,length from files where highestpriority<%d order by descending length",group_priority);
  if(sqlite3_prepare_v2(rhizome_db,sql, -1, &statement, NULL) != SQLITE_OK )
    {
      fprintf(stderr,"SQLite error running query '%s': %s\n",sql,sqlite3_errmsg(rhizome_db));
      sqlite3_finalize(statement);
      sqlite3_close(rhizome_db);
      rhizome_db=NULL;
      exit(-1);
    }

  while ( bytes>(rhizome_space-65536-rhizome_database_used_bytes()) && sqlite3_step(statement) == SQLITE_ROW)
    {
      /* Make sure we can drop this blob, and if so drop it, and recalculate number of bytes required */
      const unsigned char *id;
      long long length;

      /* Get values */
      if (sqlite3_column_type(statement, 0)==SQLITE_TEXT) id=sqlite3_column_text(statement, 0);
      else {
	fprintf(stderr,"Incorrect type in id column of files table.\n");
	continue; }
      if (sqlite3_column_type(statement, 1)==SQLITE_INTEGER) length=sqlite3_column_int(statement, 1);
      else {
	fprintf(stderr,"Incorrect type in length column of files table.\n");
	continue; }
      
      /* Try to drop this file from storage, discarding any references that do not trump the priority of this
	 request.  The query done earlier should ensure this, but it doesn't hurt to be paranoid, and it also
	 protects against inconsistency in the database. */
      rhizome_drop_stored_file((char *)id,group_priority+1);
    }
  sqlite3_finalize(statement);

  long long equal_priority_larger_file_space_used = sqlite_exec_int64("SELECT COUNT(length) FROM FILES WHERE highestpriority=%d and length>%lld",group_priority,bytes);
  /* XXX Get rid of any equal priority files that are larger than this one */

  /* XXX Get rid of any higher priority files that are not relevant in this time or location */

  /* Couldn't make space */
  return WHY("Not implemented");
}

/* Drop the specified file from storage, and any manifests that reference it, 
   provided that none of those manifests are being retained at a higher priority
   than the maximum specified here. */
int rhizome_drop_stored_file(char *id,int maximum_priority)
{
  char sql[1024];
  sqlite3_stmt *statement;
  int cannot_drop=0;

  if (strlen(id)>70) return -1;

  snprintf(sql,1024,"select manifests.id from manifests,filemanifests where manifests.id==filemanifests.manifestid and filemanifests.fileid='%s'",
	   id);
  if(sqlite3_prepare_v2(rhizome_db,sql, -1, &statement, NULL) != SQLITE_OK )
    {
      fprintf(stderr,"SQLite error running query '%s': %s\n",sql,sqlite3_errmsg(rhizome_db));
      sqlite3_finalize(statement);
      sqlite3_close(rhizome_db);
      rhizome_db=NULL;
      return WHY("Could not drop stored file");
    }

  while ( sqlite3_step(statement) == SQLITE_ROW)
    {
      /* Find manifests for this file */
      const unsigned char *id;
      if (sqlite3_column_type(statement, 0)==SQLITE_TEXT) id=sqlite3_column_text(statement, 0);
      else {
	fprintf(stderr,"Incorrect type in id column of manifests table.\n");
	continue; }
            
      /* Check that manifest is not part of a higher priority group.
	 If so, we cannot drop the manifest or the file.
         However, we will keep iterating, as we can still drop any other manifests pointing to this file
	 that are lower priority, and thus free up a little space. */
      if (rhizome_manifest_priority((char *)id)>maximum_priority) {
	cannot_drop=1;
      } else {
	printf("removing stale filemanifests, manifests, groupmemberships\n");
	sqlite_exec_int64("delete from filemanifests where manifestid='%s';",id);
	sqlite_exec_int64("delete from manifests where manifestid='%s';",id);
	sqlite_exec_int64("delete from keypairs where public='%s';",id);
	sqlite_exec_int64("delete from groupmemberships where manifestid='%s';",id);	
      }
    }
  sqlite3_finalize(statement);

  if (!cannot_drop) {
    printf("cleaning up filemanifests, manifests\n");
    sqlite_exec_int64("delete from filemanifests where fileid='%s';",id);
    sqlite_exec_int64("delete from files where id='%s';",id);
  }
  return 0;
}

/* XXX Requires a messy join that might be slow. */
int rhizome_manifest_priority(char *id)
{
  long long result = sqlite_exec_int64("select max(grouplist.priorty) from grouplist,manifests,groupmemberships where manifests.id='%s' and grouplist.id=groupmemberships.groupid and groupmemberships.manifestid=manifests.id;",id);
  return result;
}

/* Import a bundle from the inbox folder.
   Check that the manifest prototype is valid, and if so, complete it, and sign it if required and possible.

   Note that bundles can either be an ordinary bundle, or a group description.
   Group specifications are simply manifests that have the "isagroup" variable set.
   Groups get stored in the manifests table AND a reference included in the 
   grouplist table.
   Groups are allowed to be listed as being members of other groups.
   This allows a nested, i.e., multi-level group heirarchy where sub-groups will only
   typically be discovered by joining the parent group.  Probably not a bad way to do
   things.

   The file should be included in the specified rhizome groups, if possible.
   (some groups may be closed groups that we do not have the private key for.)
*/
int rhizome_bundle_import(char *bundle,char *groups[],int verifyP, int checkFileP, int signP)
{
  char filename[1024];
  char manifestname[1024];
  char buffer[1024];
  
  snprintf(filename,1024,"%s/import/file.%s",rhizome_datastore_path,bundle); filename[1023]=0;
  snprintf(manifestname,1024,"%s/import/manifest.%s",rhizome_datastore_path,bundle); manifestname[1023]=0;

  /* Open files */
  rhizome_manifest *m=rhizome_read_manifest_file(manifestname);
  if (!m) return WHY("Could not read manifest file.");
  char hexhash[SHA512_DIGEST_STRING_LENGTH];

  /* Keep associated file name handy for later */
  m->dataFileName=strdup(filename);
  struct stat stat;
  if (lstat(filename,&stat)) {
    return WHY("Could not stat() associated file");
    m->fileLength=stat.st_size;
  }

  if (checkFileP||signP) {
    if (rhizome_hash_file(filename,hexhash))
      { rhizome_manifest_free(m); return WHY("Could not hash file."); }
    bcopy(&hexhash[0],&m->fileHexHash[0],SHA512_DIGEST_STRING_LENGTH);
    m->fileHashedP=1;
  }

  if (verifyP)
    {
      /* Make sure hashes match.
	 Make sure that no signature verification errors were spotted on loading. */
      int verifyErrors=0;
      char mhexhash[1024];
      if (checkFileP) {
	if (rhizome_manifest_get(m,"filehash",mhexhash)==0)
	  if (strcmp(hexhash,mhexhash)) verifyErrors++; }
      if (m->signature_errors) verifyErrors+=m->signature_errors;
      if (verifyErrors) {
	rhizome_manifest_free(m);
	unlink(manifestname);
	unlink(filename);
	return WHY("Errors encountered verifying bundle manifest");
      }
    }

  if (!verifyP) {
    if (rhizome_manifest_get(m,"id",buffer)!=0) {
      /* No bundle id (256 bit random string being a public key in the NaCl CryptoSign crypto system),
	 so create one, and keep the private key handy. */
      rhizome_manifest_createid(m);
    } else {
      /* An ID was specified, so look for the private key if we have it stowed away */
      if (!rhizome_find_keypair_bytes(m->cryptoSignPublic,m->cryptoSignSecret))
	m->haveSecret=1;
    }
    rhizome_manifest_set(m,"filehash",hexhash);
    if (rhizome_manifest_get(m,"version",NULL)!=0)
      /* Version not set, so set one */
      rhizome_manifest_set_ll(m,"version",overlay_time_in_ms());
    rhizome_manifest_set_ll(m,"first_byte",0);
    rhizome_manifest_set_ll(m,"last_byte",rhizome_file_size(filename));
  }
   
  /* Discard if it is older than the most recent known version */
  long long storedversion = sqlite_exec_int64("SELECT version from manifests where id='%s';",rhizome_bytes_to_hex(m->cryptoSignPublic,crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES));
  if (storedversion>rhizome_manifest_get_ll(m,"version"))
    {
      rhizome_manifest_free(m);
      return WHY("Newer version exists");
    }
					      
    
  /* Add group memberships */
					      
int i;
  if (groups) for(i=0;groups[i];i++) rhizome_manifest_add_group(m,groups[i]);

  if (rhizome_manifest_finalise(m,signP)) {
    return WHY("Failed to finalise manifest.\n");
  }

  /* Write manifest back to disk */
  if (rhizome_write_manifest_file(m,manifestname)) {
    rhizome_manifest_free(m);
    return WHY("Could not write manifest file.");
  }

  /* Okay, it is written, and can be put directly into the rhizome database now */
  int r=rhizome_store_bundle(m,filename);
  if (!r) {
    unlink(manifestname);
    unlink(filename);

    return 0;
  }

  return WHY("rhizome_store_bundle() failed.");
}

/* Update an existing Rhizome bundle */
int rhizome_bundle_push_update(char *id,long long version,unsigned char *data,int appendP)
{
  return WHY("Not implemented");
}

rhizome_manifest *rhizome_read_manifest_file(char *filename)
{
  rhizome_manifest *m = calloc(sizeof(rhizome_manifest),1);
  if (!m) return NULL;

  FILE *f=fopen(filename,"r");
  if (!f) { WHY("Could not open manifest file for reading."); 
    rhizome_manifest_free(m); return NULL; }
  m->manifest_bytes = fread(m->manifestdata,1,MAX_MANIFEST_BYTES,f);
  fclose(f);

  /* Parse out variables, signature etc */
  int ofs=0;
  while((ofs<m->manifest_bytes)&&(m->manifestdata[ofs]))
    {
      int i;
      char line[1024],var[1024],value[1024];
      while((ofs<m->manifest_bytes)&&
	    (m->manifestdata[ofs]==0x0a||
	     m->manifestdata[ofs]==0x09||
	     m->manifestdata[ofs]==0x20||
	     m->manifestdata[ofs]==0x0d)) ofs++;
      for(i=0;(i<(m->manifest_bytes-ofs))
	    &&(i<1023)
	    &&(m->manifestdata[ofs+i]!=0x00)
	    &&(m->manifestdata[ofs+i]!=0x0d)
	    &&(m->manifestdata[ofs+i]!=0x0a);i++)
	    line[i]=m->manifestdata[ofs+i];
      ofs+=i;
      line[i]=0;
      /* Ignore blank lines */
      if (line[0]==0) continue;
      if (sscanf(line,"%[^=]=%[^\n\r]",var,value)==2)
	{
	  if (rhizome_manifest_get(m,var,NULL)==0) {
	    WHY("Error in manifest file (duplicate variable -- keeping first value).");
	  }
	  if (m->var_count<MAX_MANIFEST_VARS)
	    {
	      m->vars[m->var_count]=strdup(var);
	      m->values[m->var_count]=strdup(value);
	      m->var_count++;
	    }
	}
      else
	{
	  /* Error in manifest file.
	     Silently ignore for now. */
	  WHY("Error in manifest file (badly formatted line).");
	}
    }
  /* The null byte gets included in the check sum */
  if (ofs<m->manifest_bytes) ofs++;

  /* Remember where the text ends */
  int end_of_text=ofs;

  /* Calculate hash of the text part of the file, as we need to couple this with
     each signature block to */
  unsigned char manifest_hash[crypto_hash_sha512_BYTES];
  crypto_hash_sha512(manifest_hash,m->manifestdata,end_of_text);

  /* Read signature blocks from file.
     XXX - What additional information/restrictions should the
     signatures have?  start/expiry times? geo bounding box? 
     Those elements all need to be included in the hash */
  WHY("Signature verification not implemented");

  WHY("Group membership signature reading not implemented (are we still doing it this way?)");
  
  m->manifest_bytes=end_of_text;

  WHY("Incomplete");

  return m;
}

int rhizome_hash_file(char *filename,char *hash_out)
{
  /* Gnarf! NaCl's crypto_hash() function needs the whole file passed in in one
     go.  Trouble is, we need to run Serval DNA on filesystems that lack mmap(),
     and may be very resource constrained. Thus we need a streamable SHA-512
     implementation.
  */
  FILE *f=fopen(filename,"r");
  if (!f) return WHY("Could not open file for reading to calculage SHA512 hash.");
  unsigned char buffer[8192];
  int r;

  SHA512_CTX context;
  SHA512_Init(&context);

  while(!feof(f)) {
    r=fread(buffer,1,8192,f);
    if (r>0) SHA512_Update(&context,buffer,r);
  }

  SHA512_End(&context,(char *)hash_out);
  return 0;
}

int rhizome_manifest_get(rhizome_manifest *m,char *var,char *out)
{
  int i;

  if (!m) return -1;

  for(i=0;i<m->var_count;i++)
    if (!strcmp(m->vars[i],var)) {
      if (out) strcpy(out,m->values[i]);
      return 0;
    }
  return -1;
}

long long rhizome_manifest_get_ll(rhizome_manifest *m,char *var)
{
  int i;

  if (!m) return -1;

  for(i=0;i<m->var_count;i++)
    if (!strcmp(m->vars[i],var))
      return strtoll(m->values[i],NULL,10);
  return -1;
}

int rhizome_manifest_set(rhizome_manifest *m,char *var,char *value)
{
  int i;

  if (!m) return -1;

  for(i=0;i<m->var_count;i++)
    if (!strcmp(m->vars[i],var)) {
      free(m->values[i]); 
      m->values[i]=strdup(value);
      return 0;
    }

  if (m->var_count>=MAX_MANIFEST_VARS) return -1;
  
  m->vars[m->var_count]=strdup(var);
  m->values[m->var_count]=strdup(value);
  m->var_count++;

  return 0;
}

int rhizome_manifest_set_ll(rhizome_manifest *m,char *var,long long value)
{
  char svalue[100];

  snprintf(svalue,100,"%lld",value);

  return rhizome_manifest_set(m,var,svalue);
}

long long rhizome_file_size(char *filename)
{
  FILE *f;

  /* XXX really should just use stat instead of opening the file */
  f=fopen(filename,"r");
  fseek(f,0,SEEK_END);
  long long size=ftello(f);
  fclose(f);
  return size;
}

void rhizome_manifest_free(rhizome_manifest *m)
{
  if (!m) return;

  int i;
  for(i=0;i<m->var_count;i++)
    { free(m->vars[i]); free(m->values[i]); 
      m->vars[i]=NULL; m->values[i]=NULL; }

  if (m->dataFileName) free(m->dataFileName);
  m->dataFileName=NULL;

  WHY("Doesn't free signatures yet");

  free(m);

  return;
}

/* Convert variable list to string, complaining if it ends up
   too long. 
   Signatures etc will be added later. */
int rhizome_manifest_pack_variables(rhizome_manifest *m)
{
  int i,ofs=0;

  for(i=0;i<m->var_count;i++)
    {
      if ((ofs+strlen(m->vars[i])+1+strlen(m->values[i])+1+1)>MAX_MANIFEST_BYTES)
	return WHY("Manifest variables too long in total to fit in MAX_MANIFEST_BYTES");
      snprintf((char *)&m->manifestdata[ofs],MAX_MANIFEST_BYTES-ofs,"%s=%s\n",
	       m->vars[i],m->values[i]);
      ofs+=strlen((char *)&m->manifestdata[ofs]);
    }
  m->manifest_bytes=ofs;

  return 0;
}

/* Sign this manifest using our own private CryptoSign key */
int rhizome_manifest_sign(rhizome_manifest *m)
{
  return WHY("Not implemented.");
}

int rhizome_write_manifest_file(rhizome_manifest *m,char *filename)
{
  if (!m) return WHY("Manifest is null.");
  if (!m->finalised) return WHY("Manifest must be finalised before it can be written.");
  FILE *f=fopen(filename,"w");
  int r=fwrite(m->manifestdata,m->manifest_bytes,1,f);
  fclose(f);
  if (r!=1) return WHY("Failed to fwrite() manifest file.");
  return 0;
}

int rhizome_manifest_createid(rhizome_manifest *m)
{
  m->haveSecret=1;
  return crypto_sign_edwards25519sha512batch_keypair(m->cryptoSignPublic,m->cryptoSignSecret);
}

int rhizome_store_keypair_bytes(unsigned char *p,unsigned char *s) {
  /* XXX TODO Secrets should be encrypted using a keyring password. */
  if (sqlite_exec_int64("INSERT INTO KEYPAIRS(public,private) VALUES('%s','%s');",
			rhizome_bytes_to_hex(p,crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES),
			rhizome_bytes_to_hex(s,crypto_sign_edwards25519sha512batch_SECRETKEYBYTES))<0)
    return WHY("Failed to store key pair.");
  return 0;
}

int rhizome_find_keypair_bytes(unsigned char *p,unsigned char *s) {
  sqlite3_stmt *statement;
  char sql[1024];
  const char *cmdtail;

  snprintf(sql,1024,"SELECT private from KEYPAIRS WHERE public='%s';",
	   rhizome_bytes_to_hex(p,crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES));
  if (sqlite3_prepare_v2(rhizome_db,sql,strlen(sql)+1,&statement,&cmdtail) 
      != SQLITE_OK) {
    sqlite3_finalize(statement);    
    return WHY(sqlite3_errmsg(rhizome_db));
  }
  if ( sqlite3_step(statement) == SQLITE_ROW ) {
    if (sqlite3_column_type(statement,0)==SQLITE_TEXT) {
      const unsigned char *hex=sqlite3_column_text(statement,0);
      rhizome_hex_to_bytes((char *)hex,s,
			   crypto_sign_edwards25519sha512batch_SECRETKEYBYTES);
      /* XXX TODO Decrypt secret using a keyring password */
      sqlite3_finalize(statement);
      return 0;
    }
  }
  sqlite3_finalize(statement);
  return WHY("Could not find matching secret key.");
}

/*
  Store the specified manifest into the sqlite database.
  We assume that sufficient space has been made for us.
  The manifest should be finalised, and so we don't need to
  look at the underlying manifest file, but can just write m->manifest_data
  as a blob.

  associated_filename needs to be read in and stored as a blob.  Hopefully that
  can be done in pieces so that we don't have memory exhaustion issues on small
  architectures.  However, we do know it's hash apriori from m, and so we can
  skip loading the file in if it is already stored.  mmap() apparently works on
  Linux FAT file systems, and is probably the best choice since it doesn't need
  all pages to be in RAM at the same time.

  SQLite does allow modifying of blobs once stored in the database.
  The trick is to insert the blob as all zeroes using a special function, and then
  substitute bytes in the blog progressively.

  We need to also need to create the appropriate row(s) in the MANIFESTS, FILES, 
  FILEMANIFESTS and GROUPMEMBERSHIPS tables, and possibly GROUPLIST as well.
 */
int rhizome_store_bundle(rhizome_manifest *m,char *associated_filename)
{
  char sqlcmd[1024];
  const char *cmdtail;

  if (!m->finalised) return WHY("Manifest was not finalised");

  /* Store manifest */
  snprintf(sqlcmd,1024,"INSERT INTO MANIFESTS(id,manifest,version,inserttime) VALUES('%s',?,%lld,%lld);",
	   rhizome_bytes_to_hex(m->cryptoSignPublic,crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES),
	   m->version,
	   overlay_time_in_ms());

  if (m->haveSecret) {
    if (rhizome_store_keypair_bytes(m->cryptoSignPublic,m->cryptoSignSecret))
      return WHY("Failed to store key pair.");
  } else {
    /* We don't have the secret for this manifest, so only allow updates if 
       the self-signature is valid */
    if (!m->selfSigned) {
      return WHY("Manifest is not signed, and I don't have the key.  Manifest might be forged or corrupt.");
    }
  }

  sqlite3_stmt *statement;
  if (sqlite3_prepare_v2(rhizome_db,sqlcmd,strlen(sqlcmd)+1,&statement,&cmdtail) 
      != SQLITE_OK) {
    sqlite3_finalize(statement);    
    return WHY(sqlite3_errmsg(rhizome_db));
  }

  /* Bind manifest data to data field */
  if (sqlite3_bind_blob(statement,1,m->manifestdata,m->manifest_bytes,SQLITE_TRANSIENT)!=SQLITE_OK)
    {
      sqlite3_finalize(statement);
      return WHY(sqlite3_errmsg(rhizome_db));
    }

  if (rhizome_finish_sqlstatement(statement))
    return WHY("SQLite3 failed to insert row for manifest");

  /* Create relationship between file and manifest */
  long long r=sqlite_exec_int64("INSERT INTO FILEMANIFESTS(manifestid,fileid) VALUES('%s','%s');",
				 rhizome_bytes_to_hex(m->cryptoSignPublic,crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES),
				 m->fileHexHash);
  if (r<0) {
    WHY(sqlite3_errmsg(rhizome_db));
    return WHY("SQLite3 failed to insert row in filemanifests.");
  }

  /* Create relationships to groups */
  if (rhizome_manifest_get(m,"isagroup",NULL)==0) {
    /* This manifest is a group, so add entry to group list.
       Created group is not automatically subscribed to, however. */
    int closed=rhizome_manifest_get_ll(m,"closedgroup");
    if (closed<1) closed=0;
    int ciphered=rhizome_manifest_get_ll(m,"cipheredgroup");
    if (ciphered<1) ciphered=0;
    sqlite_exec_int64("delete from grouplist where id='%s';",
		      rhizome_bytes_to_hex(m->cryptoSignPublic,crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES));
    int storedP
      =sqlite_exec_int64("insert into grouplist(id,closed,ciphered) VALUES('%s',%d,%d);",
			 rhizome_bytes_to_hex(m->cryptoSignPublic,crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES),closed,ciphered);
    if (storedP<0) return WHY("Failed to insert group manifest into grouplist table.");
  }

  {
    int g;
    int dud=0;
    for(g=0;g<m->group_count;g++)
      {
	if (sqlite_exec_int64("INSERT INTO GROUPMEMBERSHIPS(manifestid,groupid) VALUES('%s','%s');",
			   rhizome_bytes_to_hex(m->cryptoSignPublic,crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES),
			       m->groups[g])<0)
	  dud++;
      }
    if (dud>0) return WHY("Failed to create one or more group associations");
  }

  /* Store the file */
  if (m->fileLength>0) 
    if (rhizome_store_file(associated_filename,m->fileHexHash,m->fileHighestPriority)) 
      return WHY("Could not store associated file");						   

  /* Get things consistent */
  sqlite3_exec(rhizome_db,"COMMIT;",NULL,NULL,NULL);

  return 0;
}

int rhizome_finish_sqlstatement(sqlite3_stmt *statement)
{
  /* Do actual insert, and abort if it fails */
  int dud=0;
  int r;
  r=sqlite3_step(statement);
  switch(r) {
  case SQLITE_DONE: case SQLITE_ROW: case SQLITE_OK:
    break;
  default:
    WHY("sqlite3_step() failed.");
    WHY(sqlite3_errmsg(rhizome_db));
    dud++;
    sqlite3_finalize(statement);
  }

  if ((!dud)&&((r=sqlite3_finalize(statement))!=SQLITE_OK)) {
    WHY("sqlite3_finalize() failed.");
    WHY(sqlite3_errmsg(rhizome_db));
    dud++;
  }

  if (dud)  return WHY("SQLite3 could not complete statement.");
  return 0;
}

/* Like sqlite_encode_binary(), but with a fixed rotation to make comparison of
   string prefixes easier.  Also, returns string directly for convenience.
   The rotoring through four return strings is so that this function can be used
   safely inline in sprintf() type functions, which makes composition of sql statements
   easier. */
int rse_rotor=0;
char rse_out[4][129];
char *rhizome_safe_encode(unsigned char *in,int len)
{
  char *r=rse_out[rse_rotor];
  rse_rotor++;
  rse_rotor&=3;

  int i,o=0;

  for(i=0;i<len;i++)
    {
      if (o<=127)
	switch(in[i])
	  {
	  case 0x00: case 0x01: case '\'':
	    r[o++]=0x01;
	    r[o++]=in[i]^0x80;
	    break;
	  default:
	    r[o++]=in[i];
	  }
    }
  return r;
}

/* The following function just stores the file (or silently returns if it already
   exists).
   The relationships of manifests to this file are the responsibility of the
   caller. */
int rhizome_store_file(char *file,char *hash,int priority) {

  int fd=open(file,O_RDONLY);
  if (fd<0) return WHY("Could not open associated file");
  
  struct stat stat;
  if (fstat(fd,&stat)) {
    close(fd);
    return WHY("Could not stat() associated file");
  }

  unsigned char *addr =
    mmap(NULL, stat.st_size, PROT_READ, MAP_FILE|MAP_SHARED, fd, 0);
  if (addr==MAP_FAILED) {
    close(fd);
    return WHY("mmap() of associated file failed.");
  }

  /* Get hash of file if not supplied */
  char hexhash[SHA512_DIGEST_STRING_LENGTH];
  if (!hash)
    {
      /* Hash the file */
      SHA512_CTX c;
      SHA512_Init(&c);
      SHA512_Update(&c,addr,stat.st_size);
      SHA512_End(&c,hexhash);
      hash=hexhash;
    }

  /* INSERT INTO FILES(id as text, data blob, length integer, highestpriority integer).
   BUT, we have to do this incrementally so that we can handle blobs larger than available memory. 
  This is possible using: 
     int sqlite3_bind_zeroblob(sqlite3_stmt*, int, int n);
  That binds an all zeroes blob to a field.  We can then populate the data by
  opening a handle to the blob using:
     int sqlite3_blob_write(sqlite3_blob *, const void *z, int n, int iOffset);
*/
  
  char sqlcmd[1024];
  const char *cmdtail;

  /* See if the file is already stored, and if so, don't bother storing it again */
  int count=sqlite_exec_int64("SELECT COUNT(*) FROM FILES WHERE id='%s' AND datavalid<>0;",hash); 
  if (count==1) {
    /* File is already stored, so just update the highestPriority field if required. */
    long long storedPriority = sqlite_exec_int64("SELECT highestPriority FROM FILES WHERE id='%s' AND datavalid!=0",hash);
    if (storedPriority<priority)
      {
	snprintf(sqlcmd,1024,"UPDATE FILES SET highestPriority=%d WHERE id='%s';",
		 priority,hash);
	if (sqlite3_exec(rhizome_db,sqlcmd,NULL,NULL,NULL)!=SQLITE_OK) {
	  close(fd);
	  WHY(sqlite3_errmsg(rhizome_db));
	  return WHY("SQLite failed to update highestPriority field for stored file.");
	}
      }
    close(fd);
    return 0;
  } else if (count>1) {
    /* This should never happen! */
    return WHY("Duplicate records for a file in the rhizome database.  Database probably corrupt.");
  }

  /* Okay, so there are no records that match, but we should delete any half-baked record (with datavalid=0) so that the insert below doesn't fail.
   Don't worry about the return result, since it might not delete any records. */
  sqlite3_exec(rhizome_db,"DELETE FROM FILES WHERE datavalid=0;",NULL,NULL,NULL);

  snprintf(sqlcmd,1024,"INSERT INTO FILES(id,data,length,highestpriority,datavalid) VALUES('%s',?,%lld,%d,0);",
	   hash,(long long)stat.st_size,priority);
  sqlite3_stmt *statement;
  if (sqlite3_prepare_v2(rhizome_db,sqlcmd,strlen(sqlcmd)+1,&statement,&cmdtail) 
      != SQLITE_OK)
    {
      close(fd);
      sqlite3_finalize(statement);
      return WHY(sqlite3_errmsg(rhizome_db));
    }
  
  /* Bind appropriate sized zero-filled blob to data field */
  int dud=0;
  int r;
  if ((r=sqlite3_bind_zeroblob(statement,1,stat.st_size))!=SQLITE_OK)
    {
      dud++;
      WHY("sqlite3_bind_zeroblob() failed");
      WHY(sqlite3_errmsg(rhizome_db));   
    }

  /* Do actual insert, and abort if it fails */
  if (!dud)
    switch(sqlite3_step(statement)) {
    case SQLITE_OK: case SQLITE_ROW: case SQLITE_DONE:
      break;
    default:
      dud++;
      WHY("sqlite3_step() failed");
      WHY(sqlite3_errmsg(rhizome_db));   
    }

  if (sqlite3_finalize(statement)) dud++;
  if (dud) {
    close(fd);
    if (sqlite3_finalize(statement)!=SQLITE_OK)
      {
	WHY("sqlite3_finalize() failed");
	WHY(sqlite3_errmsg(rhizome_db));
      }
    return WHY("SQLite3 failed to insert row for file");
  }

  /* Get rowid for inserted row, so that we can modify the blob */
  int rowid=sqlite3_last_insert_rowid(rhizome_db);
  if (rowid<1) {
    close(fd);
    WHY(sqlite3_errmsg(rhizome_db));
    return WHY("SQLite3 failed return rowid of inserted row");
  }

  sqlite3_blob *blob;
  if (sqlite3_blob_open(rhizome_db,"main","FILES","data",rowid,
		    1 /* read/write */,
			&blob) != SQLITE_OK)
    {
      WHY(sqlite3_errmsg(rhizome_db));
      close(fd);
      sqlite3_blob_close(blob);
      return WHY("SQLite3 failed to open file blob for writing");
    }

  {
    long long i;
    for(i=0;i<stat.st_size;i+=65536)
      {
	int n=65536;
	if (i+n>stat.st_size) n=stat.st_size-i;
	if (sqlite3_blob_write(blob,&addr[i],n,i) !=SQLITE_OK) dud++;
      }
  }
  
  close(fd);
  sqlite3_blob_close(blob);

  /* Mark file as up-to-date */
  sqlite_exec_int64("UPDATE FILES SET datavalid=1 WHERE id='%s';",
	   hash);


  if (dud) {
      WHY(sqlite3_errmsg(rhizome_db));
      return WHY("SQLite3 failed write all blob data");
  }

  printf("stored file\n");
  return 0;
}


/*
  Adds a group that this bundle should be present in.  If we have the means to sign
  the bundle as a member of that group, then we create the appropriate signature block.
  The group signature blocks, like all signature blocks, will be appended to the
  manifest data during the finalisation process.
 */
int rhizome_manifest_add_group(rhizome_manifest *m,char *groupid)
{
  return WHY("Not implemented.");
}

int rhizome_manifest_dump(rhizome_manifest *m,char *msg)
{
  int i;
  fprintf(stderr,"Dumping manifest %s:\n",msg);
  for(i=0;i<m->var_count;i++)
    fprintf(stderr,"[%s]=[%s]\n",m->vars[i],m->values[i]);
  return 0;
}

int rhizome_manifest_finalise(rhizome_manifest *m,int signP)
{
  /* set fileHexHash */
  if (!m->fileHashedP) {
    if (rhizome_hash_file(m->dataFileName,m->fileHexHash))
      return WHY("rhizome_hash_file() failed during finalisation of manifest.");
    m->fileHashedP=1;
  }

  /* set fileLength */
  struct stat stat;
  if (lstat(m->dataFileName,&stat)) {
    return WHY("Could not stat() associated file");
  }
  m->fileLength=stat.st_size;
  
  /* Set file hash and size information */
  rhizome_manifest_set(m,"filehash",m->fileHexHash);
  rhizome_manifest_set_ll(m,"filesize",m->fileLength);

  /* set fileHighestPriority based on group associations.
     XXX - Should probably be set as groups are added */

  /* set version of manifest, either from version variable, or using current time */
  if (rhizome_manifest_get(m,"version",NULL))
    {
      /* No version set */
      m->version = overlay_time_in_ms();
      rhizome_manifest_set_ll(m,"version",m->version);
    }
  else
    m->version = rhizome_manifest_get_ll(m,"version");

  /* Convert to final form for signing and writing to disk */
  rhizome_manifest_pack_variables(m);

  /* Sign it */
  if (signP) rhizome_manifest_sign(m);

  /* mark manifest as finalised */
  m->finalised=1;

  return 0;
}

char nybltochar(int nybl)
{
  if (nybl<0) return '?';
  if (nybl>15) return '?';
  if (nybl<10) return '0'+nybl;
  return 'A'+nybl-10;
}

char *rhizome_bytes_to_hex(unsigned char *in,int byteCount)
{
  int i=0;

  if (byteCount>64) return "<too long>";

  rse_rotor++;
  rse_rotor&=3;

  for(i=0;i<byteCount;i++)
    {
      int d=nybltochar(in[i>>1]>>(4-4*(i&1)));
      rse_out[rse_rotor][i]=d;
    }
  rse_out[rse_rotor][i]=0;
  return rse_out[rse_rotor++];
}

int chartonybl(int c)
{
  if (c>='A'&&c<='F') return 0x0a+(c-'A');
  if (c>='a'&&c<='f') return 0x0a+(c-'a');
  if (c>='0'&&c<='9') return 0x0a+(c-'0');
  return 0;
}

int rhizome_hex_to_bytes(char *in,unsigned char *out,int hexChars)
{
  int i;

  for(i=0;i<hexChars;i++)
    {
      int byte=i>>1;
      int nybl=chartonybl(in[i]);
      out[byte]=out[byte]<<4;
      out[byte]|=nybl;
    }
  return 0;
}
