/*
Serval Rhizome file sharing
Copyright (C) 2012 The Serval Project
 
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

#include "serval.h"
#include "rhizome.h"
#include "strbuf.h"
#include <stdlib.h>

long long rhizome_space=0;
static const char *rhizome_thisdatastore_path = NULL;
static int rhizome_enabled_flag = -1; // unknown

int rhizome_enabled()
{
  if (rhizome_enabled_flag < 0)
    rhizome_enabled_flag = confValueGetBoolean("rhizome.enable", 1);
  return rhizome_enabled_flag;
}

const char *rhizome_datastore_path()
{
  if (!rhizome_thisdatastore_path)
    rhizome_set_datastore_path(NULL);
  return rhizome_thisdatastore_path;
}

int rhizome_set_datastore_path(const char *path)
{
  if (!path)
    path = confValueGet("rhizome.datastore_path", NULL);
  if (path) {
    rhizome_thisdatastore_path = strdup(path);
    if (path[0] != '/')
      WARNF("Dangerous rhizome.datastore_path setting: '%s' -- should be absolute", rhizome_thisdatastore_path);
  } else {
    rhizome_thisdatastore_path = serval_instancepath();
    WARNF("Rhizome datastore path not configured -- using instance path '%s'", rhizome_thisdatastore_path);
  }
  return 0;
}

int form_rhizome_datastore_path(char * buf, size_t bufsiz, const char *fmt, ...)
{
  va_list ap;
  strbuf b = strbuf_local(buf, bufsiz);
  strbuf_puts(b, rhizome_datastore_path());  
  if (fmt) {
    va_start(ap, fmt);
    if (*strbuf_substr(b, -1) != '/')
      strbuf_putc(b, '/');
    strbuf_vsprintf(b, fmt, ap);
    va_end(ap);
  }
  if (strbuf_overrun(b)) {
      WHY("Path buffer overrun");
      return 0;
  }
  return 1;
}

int form_rhizome_import_path(char * buf, size_t bufsiz, const char *fmt, ...)
{
  va_list ap;
  strbuf b = strbuf_local(buf, bufsiz);
  strbuf_sprintf(b, "%s/import", rhizome_datastore_path());
  if (fmt) {
    va_start(ap, fmt);
    strbuf_putc(b, '/');
    strbuf_vsprintf(b, fmt, ap);
    va_end(ap);
  }
  if (strbuf_overrun(b)) {
      WHY("Path buffer overrun");
      return 0;
  }
  return 1;
}

int create_rhizome_datastore_dir()
{
  if (debug & DEBUG_RHIZOME) DEBUGF("mkdirs(%s, 0700)", rhizome_datastore_path());
  return mkdirs(rhizome_datastore_path(), 0700);
}

int create_rhizome_import_dir()
{
  char dirname[1024];
  if (!form_rhizome_import_path(dirname, sizeof dirname, NULL))
    return -1;
  if (debug & DEBUG_RHIZOME) DEBUGF("mkdirs(%s, 0700)", dirname);
  return mkdirs(dirname, 0700);
}

sqlite3 *rhizome_db=NULL;

/* XXX Requires a messy join that might be slow. */
int rhizome_manifest_priority(char *id)
{
  long long result = sqlite_exec_int64("select max(grouplist.priorty) from grouplist,manifests,groupmemberships where manifests.id='%s' and grouplist.id=groupmemberships.groupid and groupmemberships.manifestid=manifests.id;",id);
  return result;
}

int rhizome_opendb()
{
  if (rhizome_db) return 0;

  if (create_rhizome_datastore_dir() == -1)
    return -1;
  char dbname[1024];
  if (!FORM_RHIZOME_DATASTORE_PATH(dbname, "rhizome.db"))
    return -1;

  if (sqlite3_open(dbname,&rhizome_db))
    return WHYF("SQLite could not open database: %s", sqlite3_errmsg(rhizome_db));

  /* Read Rhizome configuration */
  double rhizome_kb = atof(confValueGet("rhizome_kb", "1024"));
  rhizome_space = 1024LL * rhizome_kb;
  if (debug&DEBUG_RHIZOME) {
    DEBUGF("serval.conf:rhizome_kb=%.f", rhizome_kb);
    DEBUGF("Rhizome will use %lldB of storage for its database.", rhizome_space);
  }

  /* Create tables if required */
  if (sqlite3_exec(rhizome_db,"PRAGMA auto_vacuum=2;",NULL,NULL,NULL)) {
      WARNF("SQLite could enable incremental vacuuming: %s", sqlite3_errmsg(rhizome_db));
  }
  if (sqlite3_exec(rhizome_db,"CREATE TABLE IF NOT EXISTS GROUPLIST(id text not null primary key, closed integer,ciphered integer,priority integer);",NULL,NULL,NULL))
    {
      return WHYF("SQLite could not create GROUPLIST table: %s", sqlite3_errmsg(rhizome_db));
    }
  if (sqlite3_exec(rhizome_db,"CREATE TABLE IF NOT EXISTS MANIFESTS(id text not null primary key, manifest blob, version integer,inserttime integer, bar blob);",NULL,NULL,NULL))
    {
      return WHYF("SQLite could not create MANIFESTS table: %s", sqlite3_errmsg(rhizome_db));
    }
  if (sqlite3_exec(rhizome_db,"CREATE TABLE IF NOT EXISTS FILES(id text not null primary key, data blob, length integer, highestpriority integer, datavalid integer);",NULL,NULL,NULL))
    {
      return WHYF("SQLite could not create FILES table: %s", sqlite3_errmsg(rhizome_db));
    }
  if (sqlite3_exec(rhizome_db,"CREATE TABLE IF NOT EXISTS FILEMANIFESTS(fileid text not null, manifestid text not null);",NULL,NULL,NULL))
    {
      return WHYF("SQLite could not create FILEMANIFESTS table: %s", sqlite3_errmsg(rhizome_db));
    }
  if (sqlite3_exec(rhizome_db,"CREATE TABLE IF NOT EXISTS GROUPMEMBERSHIPS(manifestid text not null, groupid text not null);",NULL,NULL,NULL))
    {
      return WHYF("SQLite could not create GROUPMEMBERSHIPS table: %s", sqlite3_errmsg(rhizome_db));
    }
  if (sqlite3_exec(rhizome_db,"CREATE TABLE IF NOT EXISTS VERIFICATIONS(sid text not null, did text, name text, starttime integer, endtime integer, signature blob);",
		   NULL,NULL,NULL))
    {
      return WHYF("SQLite could not create VERIFICATIONS table: %s", sqlite3_errmsg(rhizome_db));
    }
  
  /* XXX Setup special groups, e.g., Serval Software and Serval Optional Data */

  return 0;
}

/* 
   Convenience wrapper for executing an SQL command that returns a no value.
   Returns -1 if an error occurs, otherwise zero.
 */
long long sqlite_exec_void(const char *sqlformat,...)
{
  if (!rhizome_db) rhizome_opendb();
  strbuf stmt = strbuf_alloca(8192);
  va_list ap;
  va_start(ap, sqlformat);
  strbuf_vsprintf(stmt, sqlformat, ap);
  va_end(ap);
  if (strbuf_overrun(stmt))
    return WHYF("Sql statement overrun: %s", strbuf_str(stmt));
  sqlite3_stmt *statement;
  switch (sqlite3_prepare_v2(rhizome_db, strbuf_str(stmt), -1, &statement, NULL)) {
    case SQLITE_OK: case SQLITE_DONE:
      break;
    default:
      WHY(strbuf_str(stmt));
      WHY(sqlite3_errmsg(rhizome_db));
      sqlite3_finalize(statement);
      sqlite3_close(rhizome_db);
      rhizome_db=NULL;
      return WHYF("Sql statement prepare: %s -- closed database", strbuf_str(stmt));
  }
  int stepcode;
  while ((stepcode = sqlite3_step(statement)) == SQLITE_ROW)
    ;
  switch (stepcode) {
    case SQLITE_OK:
    case SQLITE_DONE:
    case SQLITE_ROW:
      break;
    default:
      WHY(strbuf_str(stmt));
      WHY(sqlite3_errmsg(rhizome_db));
      sqlite3_finalize(statement);
      return WHYF("Sql statement step: %s", strbuf_str(stmt));
  }
  sqlite3_finalize(statement);
  return 0;
}

/* 
   Convenience wrapper for executing an SQL command that returns a single int64 value 
   Returns -1 if an error occurs, otherwise the value of the column in the first row.
   If there are no rows, return zero.
 */
long long sqlite_exec_int64(const char *sqlformat,...)
{
  if (!rhizome_db) rhizome_opendb();
  strbuf stmt = strbuf_alloca(8192);
  va_list ap;
  va_start(ap, sqlformat);
  strbuf_vsprintf(stmt, sqlformat, ap);
  va_end(ap);
  if (strbuf_overrun(stmt))
    return WHYF("sql statement too long: %s", strbuf_str(stmt));
  sqlite3_stmt *statement;
  switch (sqlite3_prepare_v2(rhizome_db, strbuf_str(stmt), -1, &statement, NULL)) {
    case SQLITE_OK: case SQLITE_DONE: case SQLITE_ROW:
      break;
    default:
      WHY(strbuf_str(stmt));
      WHY(sqlite3_errmsg(rhizome_db));
      sqlite3_finalize(statement);
      sqlite3_close(rhizome_db);
      rhizome_db=NULL;
      return WHYF("Could not prepare sql statement: %s -- closed database", strbuf_str(stmt));
  }
  if (sqlite3_step(statement) == SQLITE_ROW) {
    int n = sqlite3_column_count(statement);
    if (n != 1) {
      sqlite3_finalize(statement);
      return WHYF("Incorrect column count %d (should be 1): %s", n, strbuf_str(stmt));
    }
    long long result= sqlite3_column_int64(statement, 0);
    sqlite3_finalize(statement);
    return result;
  }
  sqlite3_finalize(statement);
  return WHYF("No rows found: %s", strbuf_str(stmt));
}

/* 
   Convenience wrapper for executing an SQL command that returns a single text value.
   Returns -1 if an error occurs, otherwise the number of rows that were found:
    0 means no rows, nothing is appended to the strbuf
    1 means exactly one row, and the its column is appended to the strbuf
    2 more than one row, and the first row's column is appended to the strbuf
   @author Andrew Bettison <andrew@servalproject.com>
 */
int sqlite_exec_strbuf(strbuf sb, const char *sqlformat,...)
{
  if (!rhizome_db) rhizome_opendb();
  strbuf stmt = strbuf_alloca(8192);
  va_list ap;
  va_start(ap, sqlformat);
  strbuf_vsprintf(stmt, sqlformat, ap);
  va_end(ap);
  if (strbuf_overrun(stmt))
    return WHYF("sql statement too long: %s", strbuf_str(stmt));
  sqlite3_stmt *statement;
  switch (sqlite3_prepare_v2(rhizome_db, strbuf_str(stmt), -1, &statement,NULL)) {
    case SQLITE_OK: case SQLITE_DONE: case SQLITE_ROW:
      break;
    default:
      sqlite3_finalize(statement);
      sqlite3_close(rhizome_db);
      rhizome_db=NULL;
      WHY(strbuf_str(stmt));
      WHY(sqlite3_errmsg(rhizome_db));
      return WHY("Could not prepare sql statement.");
  }
  int rows = 0;
  if (sqlite3_step(statement) == SQLITE_ROW) {
    int n = sqlite3_column_count(statement);
    if (n != 1) {
      sqlite3_finalize(statement);
      return WHYF("Incorrect column count %d (should be 1)", n);
    }
    strbuf_puts(sb, (const char *)sqlite3_column_text(statement, 0));
    sqlite3_finalize(statement);
    ++rows;
  }
  if (sqlite3_step(statement) == SQLITE_ROW)
    ++rows;
  sqlite3_finalize(statement);
  return rows;
}

long long rhizome_database_used_bytes()
{
  long long db_page_size=sqlite_exec_void("PRAGMA page_size;");
  long long db_page_count=sqlite_exec_void("PRAGMA page_count;");
  long long db_free_page_count=sqlite_exec_void("PRAGMA free_count;");
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
      WHYF("SQLite error running query '%s': %s",sql,sqlite3_errmsg(rhizome_db));
      sqlite3_finalize(statement);
      sqlite3_close(rhizome_db);
      rhizome_db=NULL;
      exit(-1);
    }

  while ( bytes>(rhizome_space-65536-rhizome_database_used_bytes()) && sqlite3_step(statement) == SQLITE_ROW)
    {
      /* Make sure we can drop this blob, and if so drop it, and recalculate number of bytes required */
      const unsigned char *id;
      //long long length;

      /* Get values */
      if (sqlite3_column_type(statement, 0)==SQLITE_TEXT) id=sqlite3_column_text(statement, 0);
      else {
	WARNF("Incorrect type in id column of files table.");
	continue; }
      if (sqlite3_column_type(statement, 1)==SQLITE_INTEGER) ;//length=sqlite3_column_int(statement, 1);
      else {
	WARNF("Incorrect type in length column of files table.");
	continue; }
      
      /* Try to drop this file from storage, discarding any references that do not trump the priority of this
	 request.  The query done earlier should ensure this, but it doesn't hurt to be paranoid, and it also
	 protects against inconsistency in the database. */
      rhizome_drop_stored_file((char *)id,group_priority+1);
    }
  sqlite3_finalize(statement);

  //long long equal_priority_larger_file_space_used = sqlite_exec_int64("SELECT COUNT(length) FROM FILES WHERE highestpriority=%d and length>%lld",group_priority,bytes);
  /* XXX Get rid of any equal priority files that are larger than this one */

  /* XXX Get rid of any higher priority files that are not relevant in this time or location */

  /* Couldn't make space */
  return WHY("Incomplete");
}

/* Drop the specified file from storage, and any manifests that reference it, 
   provided that none of those manifests are being retained at a higher priority
   than the maximum specified here. */
int rhizome_drop_stored_file(char *id,int maximum_priority)
{
  char sql[1024];
  sqlite3_stmt *statement;
  int cannot_drop=0;

  if (strlen(id)>(crypto_hash_sha512_BYTES*2+1)) {
    WHY("File ID is wrong length");
    return -1;
  }

  snprintf(sql,1024,"select manifests.id from manifests,filemanifests where manifests.id==filemanifests.manifestid and filemanifests.fileid='%s'",
	   id);
  if(sqlite3_prepare_v2(rhizome_db,sql, -1, &statement, NULL) != SQLITE_OK )
    {
      WHYF("SQLite error running query '%s': %s",sql,sqlite3_errmsg(rhizome_db));
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
	WHYF("Incorrect type in id column of manifests table.");
	continue; }
            
      /* Check that manifest is not part of a higher priority group.
	 If so, we cannot drop the manifest or the file.
         However, we will keep iterating, as we can still drop any other manifests pointing to this file
	 that are lower priority, and thus free up a little space. */
      if (rhizome_manifest_priority((char *)id)>maximum_priority) {
	WHYF("Cannot drop due to manifest %s",id);
	cannot_drop=1;
      } else {
	printf("removing stale filemanifests, manifests, groupmemberships\n");
	sqlite_exec_void("delete from filemanifests where manifestid='%s';",id);
	sqlite_exec_void("delete from manifests where manifestid='%s';",id);
	sqlite_exec_void("delete from keypairs where public='%s';",id);
	sqlite_exec_void("delete from groupmemberships where manifestid='%s';",id);	
      }
    }
  sqlite3_finalize(statement);

  if (!cannot_drop) {
    sqlite_exec_void("delete from filemanifests where fileid='%s';",id);
    sqlite_exec_void("delete from files where id='%s';",id);
  }
  return 0;
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
int rhizome_store_bundle(rhizome_manifest *m)
{
  if (!m->finalised) return WHY("Manifest was not finalised");

  char manifestid[RHIZOME_MANIFEST_ID_STRLEN + 1];
  rhizome_manifest_get(m, "id", manifestid, sizeof manifestid);
  str_toupper_inplace(manifestid);

  char filehash[RHIZOME_FILEHASH_STRLEN + 1];
  strncpy(filehash, m->fileHexHash, sizeof filehash);
  str_toupper_inplace(filehash);

  /* remove any old version of the manifest */
  if (sqlite_exec_int64("SELECT COUNT(*) FROM MANIFESTS WHERE id='%s';",manifestid)>0)
    {
      /* Manifest already exists.
	 Remove old manifest entry, and replace with new one.
	 But we do need to check if the file referenced by the old one is still needed,
	 and if it's priority is right */
      sqlite_exec_void("DELETE FROM MANIFESTS WHERE id='%s';",manifestid);
      strbuf b = strbuf_alloca(RHIZOME_FILEHASH_STRLEN + 1);
      if (sqlite_exec_strbuf(b, "SELECT fileid from filemanifests where manifestid='%s';", manifestid) == -1)
	return -1;
      if (strbuf_overrun(b))
	return WHYF("got over-long fileid from database: %s", strbuf_str(b));
      sqlite_exec_void("DELETE FROM FILEMANIFESTS WHERE manifestid='%s';",manifestid);
      /* File check must occur AFTER we drop the manifest, otherwise we think
	 that it has a reference still */
      rhizome_update_file_priority(strbuf_str(b));
    }

  /* Store manifest */
  if (debug & DEBUG_RHIZOME) DEBUGF("Writing into manifests table");
  char sqlcmd[1024];
  snprintf(sqlcmd,1024,
	   "INSERT INTO MANIFESTS(id,manifest,version,inserttime,bar) VALUES('%s',?,%lld,%lld,?);",
	   manifestid, m->version, gettime_ms());

  if (m->haveSecret) {
    /* We used to store the secret in the database, but we don't anymore, as we use 
       the BK field in the manifest. So nothing to do here. */
  } else {
    /* We don't have the secret for this manifest, so only allow updates if 
       the self-signature is valid */
    if (!m->selfSigned) {
      WHY("*** Insert into manifests failed (-2).");
      return WHY("Manifest is not signed, and I don't have the key.  Manifest might be forged or corrupt.");
    }
  }

  const char *cmdtail;
  sqlite3_stmt *statement;
  if (sqlite3_prepare_v2(rhizome_db,sqlcmd,strlen(sqlcmd)+1,&statement,&cmdtail) != SQLITE_OK) {
    WHY(sqlite3_errmsg(rhizome_db));
    sqlite3_finalize(statement);
    return WHY("Insert into manifests failed.");
  }

  /* Bind manifest data to data field */
  if (sqlite3_bind_blob(statement,1,m->manifestdata,m->manifest_bytes,SQLITE_TRANSIENT)!=SQLITE_OK)
    {
      WHY(sqlite3_errmsg(rhizome_db));
      sqlite3_finalize(statement);
      return WHY("Insert into manifests failed.");
    }

  /* Bind BAR to data field */
  unsigned char bar[RHIZOME_BAR_BYTES];
  rhizome_manifest_to_bar(m,bar);
  
  if (sqlite3_bind_blob(statement,2,bar,RHIZOME_BAR_BYTES,SQLITE_TRANSIENT)
      !=SQLITE_OK)
    {
      WHY(sqlite3_errmsg(rhizome_db));
      sqlite3_finalize(statement);
      return WHY("Insert into manifests failed.");
    }

  if (rhizome_finish_sqlstatement(statement))
    return WHY("SQLite3 failed to insert row for manifest");
  else {
    if (debug & DEBUG_RHIZOME) DEBUGF("Insert into manifests apparently worked.");
  }

  /* Create relationship between file and manifest */
  long long r=sqlite_exec_void("INSERT INTO FILEMANIFESTS(manifestid,fileid) VALUES('%s','%s');", manifestid, filehash);
  if (r<0) {
    WHY(sqlite3_errmsg(rhizome_db));
    return WHY("SQLite3 failed to insert row in filemanifests.");
  }

  /* Create relationships to groups */
  if (rhizome_manifest_get(m,"isagroup",NULL,0)!=NULL) {
    /* This manifest is a group, so add entry to group list.
       Created group is not automatically subscribed to, however. */
    int closed=rhizome_manifest_get_ll(m,"closedgroup");
    if (closed<1) closed=0;
    int ciphered=rhizome_manifest_get_ll(m,"cipheredgroup");
    if (ciphered<1) ciphered=0;
    sqlite_exec_void("delete from grouplist where id='%s';",manifestid);
    int storedP
      =sqlite_exec_void("insert into grouplist(id,closed,ciphered,priority) VALUES('%s',%d,%d,%d);",
			 manifestid,closed,ciphered,RHIZOME_PRIORITY_DEFAULT);
    if (storedP<0) return WHY("Failed to insert group manifest into grouplist table.");
  }

  {
    int g;
    int dud=0;
    for(g=0;g<m->group_count;g++)
      {
	if (sqlite_exec_void("INSERT INTO GROUPMEMBERSHIPS(manifestid,groupid) VALUES('%s','%s');",
			   manifestid, m->groups[g])<0)
	  dud++;
      }
    if (dud>0) return WHY("Failed to create one or more group associations");
  }

  /* Store the file */
  if (m->fileLength>0) 
    if (rhizome_store_file(m)) 
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

int rhizome_list_manifests(const char *service, const char *sender_sid, const char *recipient_sid, int limit, int offset)
{
  strbuf b = strbuf_alloca(1024);
  strbuf_sprintf(b, "SELECT id, manifest, version, inserttime FROM manifests ORDER BY inserttime DESC");
  if (limit)
    strbuf_sprintf(b, " LIMIT %u", limit);
  if (offset)
    strbuf_sprintf(b, " OFFSET %u", offset);
  if (strbuf_overrun(b))
    return WHYF("SQL command too long: ", strbuf_str(b));
  sqlite3_stmt *statement;
  const char *cmdtail;
  int ret = 0;
  if (sqlite3_prepare_v2(rhizome_db, strbuf_str(b), strbuf_len(b) + 1, &statement, &cmdtail) != SQLITE_OK) {
    sqlite3_finalize(statement);
    ret = WHY(sqlite3_errmsg(rhizome_db));
  } else {
    size_t rows = 0;
    cli_puts("10"); cli_delim(":"); // number of columns
    cli_puts("service"); cli_delim(":");
    cli_puts("id"); cli_delim(":");
    cli_puts("version"); cli_delim(":");
    cli_puts("date"); cli_delim(":");
    cli_puts("_inserttime"); cli_delim(":");
    cli_puts("filesize"); cli_delim(":");
    cli_puts("filehash"); cli_delim(":");
    cli_puts("name"); cli_delim(":");
    cli_puts("sender"); cli_delim(":");
    cli_puts("recipient"); cli_delim("\n");
    while (sqlite3_step(statement) == SQLITE_ROW) {
      ++rows;
      if (!(   sqlite3_column_count(statement) == 4
	    && sqlite3_column_type(statement, 0) == SQLITE_TEXT
	    && sqlite3_column_type(statement, 1) == SQLITE_BLOB
	    && sqlite3_column_type(statement, 2) == SQLITE_INTEGER
	    && sqlite3_column_type(statement, 3) == SQLITE_INTEGER
      )) { 
	ret = WHY("Incorrect statement column");
	break;
      }
      rhizome_manifest *m = rhizome_new_manifest();
      if (m == NULL) {
	ret = WHY("Out of manifests");
	break;
      }
      const char *q_manifestid = (const char *) sqlite3_column_text(statement, 0);
      const char *manifestblob = (char *) sqlite3_column_blob(statement, 1);
      size_t manifestblobsize = sqlite3_column_bytes(statement, 1); // must call after sqlite3_column_blob()
      long long q_version = sqlite3_column_int64(statement, 2);
      long long q_inserttime = sqlite3_column_int64(statement, 3);
      if (rhizome_read_manifest_file(m, manifestblob, manifestblobsize) == -1) {
	WARNF("MANIFESTS row id=%s has invalid manifest blob -- skipped", q_manifestid);
      } else {
	long long blob_version = rhizome_manifest_get_ll(m, "version");
	if (blob_version != q_version)
	  WARNF("MANIFESTS row id=%s version=%lld does not match manifest blob.version=%lld", q_manifestid, q_version, blob_version);
	int match = 1;
	const char *blob_service = rhizome_manifest_get(m, "service", NULL, 0);
	if (service[0] && !(blob_service && strcasecmp(service, blob_service) == 0))
	  match = 0;
	
	const char *blob_sender = rhizome_manifest_get(m, "sender", NULL, 0);
	const char *blob_recipient = rhizome_manifest_get(m, "recipient", NULL, 0);
	
	if (match && sender_sid[0]) {
	  if (!(blob_sender && strcasecmp(sender_sid, blob_sender) == 0))
	    match = 0;
	}
	if (match && recipient_sid[0]) {
	  if (!(blob_recipient && strcasecmp(recipient_sid, blob_recipient) == 0))
	    match = 0;
	}
	
	if (match) {
	  const char *blob_name = rhizome_manifest_get(m, "name", NULL, 0);
	  long long blob_date = rhizome_manifest_get_ll(m, "date");
	  const char *blob_filehash = rhizome_manifest_get(m, "filehash", NULL, 0);
	  long long blob_filesize = rhizome_manifest_get_ll(m, "filesize");
	  cli_puts(blob_service ? blob_service : ""); cli_delim(":");
	  cli_puts(q_manifestid); cli_delim(":");
	  cli_printf("%lld", blob_version); cli_delim(":");
	  cli_printf("%lld", blob_date); cli_delim(":");
	  cli_printf("%lld", q_inserttime); cli_delim(":");
	  cli_printf("%u", blob_filesize); cli_delim(":");
	  cli_puts(blob_filehash ? blob_filehash : ""); cli_delim(":");
	  cli_puts(blob_name ? blob_name : ""); cli_delim(":");
	  cli_puts(blob_sender ? blob_sender : ""); cli_delim(":");
	  cli_puts(blob_recipient ? blob_recipient : ""); cli_delim("\n");
	}
      }
      if (m) rhizome_manifest_free(m);
    }
  }
  sqlite3_finalize(statement);
  return ret;
}

/* The following function just stores the file (or silently returns if it already exists).
   The relationships of manifests to this file are the responsibility of the caller. */
int rhizome_store_file(rhizome_manifest *m)
{
  const char *file=m->dataFileName;
  const char *hash=m->fileHexHash;
  int priority=m->fileHighestPriority;
  if (m->payloadEncryption) 
    return WHY("Writing encrypted payloads not implemented");

  if (!m->fileHashedP)
    return WHY("Cannot store bundle file until it has been hashed");

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
      WHY(sqlite3_errmsg(rhizome_db));   
      sqlite3_finalize(statement);
      close(fd);
      return WHY("sqlite3_prepare_v2() failed");
    }
  
  /* Bind appropriate sized zero-filled blob to data field */
  int dud=0;
  int r;
  if ((r=sqlite3_bind_zeroblob(statement,1,stat.st_size))!=SQLITE_OK)
    {
      dud++;
      WHY(sqlite3_errmsg(rhizome_db));   
      WHY("sqlite3_bind_zeroblob() failed");
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
    if (sqlite3_finalize(statement)!=SQLITE_OK)
      {
	WHY(sqlite3_errmsg(rhizome_db));
	WHY("sqlite3_finalize() failed");
      }
    close(fd);
    return WHY("SQLite3 failed to insert row for file");
  }

  /* Get rowid for inserted row, so that we can modify the blob */
  int rowid=sqlite3_last_insert_rowid(rhizome_db);
  if (rowid<1) {
    WHY(sqlite3_errmsg(rhizome_db));
    close(fd);
    return WHY("SQLite3 failed return rowid of inserted row");
  }

  sqlite3_blob *blob;
  if (sqlite3_blob_open(rhizome_db,"main","FILES","data",rowid,
		    1 /* read/write */,
			&blob) != SQLITE_OK)
    {
      WHY(sqlite3_errmsg(rhizome_db));
      sqlite3_blob_close(blob);
      close(fd);
      return WHY("SQLite3 failed to open file blob for writing");
    }

#warning encrypt sections of file as we write them here
  {
    long long i;
    for(i=0;i<stat.st_size;i+=65536)
      {
	int n=65536;
	if (i+n>stat.st_size) n=stat.st_size-i;
	if (sqlite3_blob_write(blob,&addr[i],n,i) !=SQLITE_OK) dud++;
      }
  }
  
  sqlite3_blob_close(blob);
  close(fd);

  /* Mark file as up-to-date */
  sqlite_exec_void("UPDATE FILES SET datavalid=1 WHERE id='%s';", hash);

  if (dud) {
      WHY(sqlite3_errmsg(rhizome_db));
      return WHY("SQLite3 failed write all blob data");
  }

  return 0;
}


void rhizome_bytes_to_hex_upper(unsigned const char *in, char *out, int byteCount)
{
  int i=0;
  for(i = 0; i != byteCount * 2 ; ++i)
    out[i] = nybltochar_upper((in[i >> 1] >> (4 - 4 * (i & 1))) & 0xf);
  out[i] = '\0';
}

int rhizome_update_file_priority(char *fileid)
{
  /* Drop if no references */
  int referrers=sqlite_exec_int64("SELECT COUNT(*) FROM FILEMANIFESTS WHERE fileid='%s';",fileid);
  WHYF("%d references point to %s",referrers,fileid);

  if (referrers==0) {
    WHYF("About to drop file %s",fileid);
    rhizome_drop_stored_file(fileid,RHIZOME_PRIORITY_HIGHEST+1);
  } else if (referrers>0) {
    /* It has referrers, so workout the highest priority of any referrer */
        int highestPriority=sqlite_exec_int64("SELECT max(grouplist.priority) FROM MANIFESTS,FILEMANIFESTS,GROUPMEMBERSHIPS,GROUPLIST where manifests.id=filemanifests.manifestid AND groupmemberships.manifestid=manifests.id AND groupmemberships.groupid=grouplist.id AND filemanifests.fileid='%s';",fileid);
    if (highestPriority>=0)
      sqlite_exec_void("UPDATE files set highestPriority=%d WHERE id='%s';", highestPriority,fileid);
  }
  return 0;
}

/* Search the database for a manifest having the same name and payload content,
   and if the version is known, having the same version.

   @author Andrew Bettison <andrew@servalproject.com>
 */
int rhizome_find_duplicate(const rhizome_manifest *m, rhizome_manifest **found,
			   int checkVersionP)
{
  if (!m->fileHashedP)
    return WHY("Manifest payload is not hashed");
  const char *service = rhizome_manifest_get(m, "service", NULL, 0);
  const char *name = NULL;
  const char *sender = NULL;
  const char *recipient = NULL;
  if (service == NULL) {
    return WHY("Manifest has no service");
  } else if (strcasecmp(service, RHIZOME_SERVICE_FILE) == 0) {
    name = rhizome_manifest_get(m, "name", NULL, 0);
    if (!name) return WHY("Manifest has no name");
  } else if (strcasecmp(service, RHIZOME_SERVICE_MESHMS) == 0) {
    sender = rhizome_manifest_get(m, "sender", NULL, 0);
    recipient = rhizome_manifest_get(m, "recipient", NULL, 0);
    if (!sender) return WHY("Manifest has no sender");
    if (!recipient) return WHY("Manifest has no recipient");
  } else {
    return WHYF("Unsupported service '%s'", service);
  }
  char sqlcmd[1024];
  char *s = sqlcmd;
  s += snprintf(s, &sqlcmd[sizeof sqlcmd] - s,
      "SELECT manifests.id, manifests.manifest, manifests.version FROM filemanifests, manifests"
      " WHERE filemanifests.manifestid = manifests.id AND filemanifests.fileid = ?"
    );
  if (checkVersionP && s < &sqlcmd[sizeof sqlcmd])
    s += snprintf(s, sqlcmd + sizeof(sqlcmd) - s, " AND manifests.version = ?");
  if (s >= &sqlcmd[sizeof sqlcmd])
    return WHY("SQL command too long");
  int ret = 0;
  sqlite3_stmt *statement;
  const char *cmdtail;
  if (debug&DEBUG_RHIZOME) WHYF("sql query: %s",sqlcmd);
  if (sqlite3_prepare_v2(rhizome_db, sqlcmd, strlen(sqlcmd) + 1, &statement, &cmdtail) != SQLITE_OK) {
    ret = WHY(sqlite3_errmsg(rhizome_db));
  } else {
    char filehash[RHIZOME_FILEHASH_STRLEN + 1];
    strncpy(filehash, m->fileHexHash, sizeof filehash);
    str_toupper_inplace(filehash);
    if (debug & DEBUG_RHIZOME) DEBUGF("filehash=\"%s\"", filehash);
    sqlite3_bind_text(statement, 1, filehash, -1, SQLITE_STATIC);
    if (checkVersionP)
      sqlite3_bind_int64(statement, 2, m->version);
    size_t rows = 0;
    while (sqlite3_step(statement) == SQLITE_ROW) {
      ++rows;
      if (debug & DEBUG_RHIZOME) DEBUGF("Row %d", rows);
      if (!(   sqlite3_column_count(statement) == 3
	    && sqlite3_column_type(statement, 0) == SQLITE_TEXT
	    && sqlite3_column_type(statement, 1) == SQLITE_BLOB
	    && sqlite3_column_type(statement, 2) == SQLITE_INTEGER
      )) { 
	ret = WHY("Incorrect statement columns");
	break;
      }
      const char *q_manifestid = (const char *) sqlite3_column_text(statement, 0);
      size_t manifestidsize = sqlite3_column_bytes(statement, 0); // must call after sqlite3_column_text()
      if (manifestidsize != crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES * 2) {
	ret = WHYF("Malformed manifest.id from query: %s", q_manifestid);
	break;
      }
      const char *manifestblob = (char *) sqlite3_column_blob(statement, 1);
      size_t manifestblobsize = sqlite3_column_bytes(statement, 1); // must call after sqlite3_column_blob()
      long long q_version = sqlite3_column_int64(statement, 2);
      rhizome_manifest *blob_m = rhizome_new_manifest();
      if (blob_m == NULL) {
	ret = WHY("Out of manifests");
	break;
      }
      if (rhizome_read_manifest_file(blob_m, manifestblob, manifestblobsize) == -1) {
	WARNF("MANIFESTS row id=%s has invalid manifest blob -- skipped", q_manifestid);
      } else if (rhizome_manifest_verify(blob_m)) {
	WARNF("MANIFESTS row id=%s fails verification -- skipped", q_manifestid);
      } else {
	const char *blob_service = rhizome_manifest_get(blob_m, "service", NULL, 0);
	const char *blob_id = rhizome_manifest_get(blob_m, "id", NULL, 0);
	long long blob_version = rhizome_manifest_get_ll(blob_m, "version");
	const char *blob_filehash = rhizome_manifest_get(blob_m, "filehash", NULL, 0);
	long long blob_filesize = rhizome_manifest_get_ll(blob_m, "filesize");
	if (debug & DEBUG_RHIZOME)
	  DEBUGF("Consider manifest.service=%s manifest.id=%s manifest.version=%lld", blob_service, q_manifestid, blob_version);
	/* Perform consistency checks, because we're paranoid. */
	int inconsistent = 0;
	if (blob_id && strcasecmp(blob_id, q_manifestid)) {
	  WARNF("MANIFESTS row id=%s has inconsistent blob with id=%s -- skipped", q_manifestid, blob_id);
	  ++inconsistent;
	}
	if (checkVersionP && blob_version != q_version) {
	  WARNF("MANIFESTS row id=%s has inconsistent blob: manifests.version=%lld, blob.version=%lld -- skipped",
		q_manifestid, q_version, blob_version);
	  ++inconsistent;
	}
	if (!blob_filehash && strcasecmp(blob_filehash, m->fileHexHash)) {
	  WARNF("MANIFESTS row id=%s joined to FILES row id=%s has inconsistent blob: blob.filehash=%s -- skipped",
		q_manifestid, m->fileHexHash, blob_filehash);
	  ++inconsistent;
	}
	if (blob_filesize != -1 && blob_filesize != m->fileLength) {
	  WARNF("MANIFESTS row id=%s joined to FILES row id=%s has inconsistent blob: known file size %lld, blob.filesize=%lld -- skipped",
		q_manifestid, m->fileLength, blob_filesize);
	  ++inconsistent;
	}
	if (checkVersionP && q_version != m->version) {
	  WARNF("SELECT query with version=%lld returned incorrect row: manifests.version=%lld -- skipped", m->version, q_version);
	  ++inconsistent;
	}
	if (blob_service == NULL) {
	  WARNF("MANIFESTS row id=%s has blob with no 'service' -- skipped", q_manifestid, blob_id);
	  ++inconsistent;
	}
	if (!inconsistent) {
	  strbuf b = strbuf_alloca(1024);
	  if (strcasecmp(service, RHIZOME_SERVICE_FILE) == 0) {
	    const char *blob_name = rhizome_manifest_get(blob_m, "name", NULL, 0);
	    if (blob_name && !strcmp(blob_name, name)) {
	      if (debug & DEBUG_RHIZOME)
		strbuf_sprintf(b, " name=\"%s\"", blob_name);
	      ret = 1;
	    }
	  } else if (strcasecmp(service, RHIZOME_SERVICE_FILE) == 0) {
	    const char *blob_sender = rhizome_manifest_get(blob_m, "sender", NULL, 0);
	    const char *blob_recipient = rhizome_manifest_get(blob_m, "recipient", NULL, 0);
	    if (blob_sender && !strcasecmp(blob_sender, sender) && blob_recipient && !strcasecmp(blob_recipient, recipient)) {
	      if (debug & DEBUG_RHIZOME)
		strbuf_sprintf(b, " sender=%s recipient=%s", blob_sender, blob_recipient);
	      ret = 1;
	    }
	  }
	  if (ret == 1) {
	    rhizome_hex_to_bytes(q_manifestid, blob_m->cryptoSignPublic, crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES*2); 
	    memcpy(blob_m->fileHexHash, m->fileHexHash, RHIZOME_FILEHASH_STRLEN + 1);
	    blob_m->fileHashedP = 1;
	    blob_m->fileLength = m->fileLength;
	    blob_m->version = q_version;
	    *found = blob_m;
	    DEBUGF("Found duplicate payload: service=%s%s version=%llu hexhash=%s",
		    blob_service, strbuf_str(b), blob_m->version, blob_m->fileHexHash
		  );
	    break;
	  }
	}
      }
      if (blob_m) rhizome_manifest_free(blob_m);
    }
  }
  sqlite3_finalize(statement);
  return ret;
}

/* Retrieve a manifest from the database, given its manifest ID.
 *
 * Returns 1 if manifest is found (if mp != NULL then a new manifest struct is allocated, made
 * finalisable and * assigned to *mp, caller is responsible for freeing).
 * Returns 0 if manifest is not found (*mp is unchanged).
 * Returns -1 on error (*mp is unchanged).
 */
int rhizome_retrieve_manifest(const char *manifestid, rhizome_manifest **mp)
{
  char sqlcmd[1024];
  int n = snprintf(sqlcmd, sizeof(sqlcmd), "SELECT id, manifest, version, inserttime FROM manifests WHERE id = ?");
  if (n >= sizeof(sqlcmd))
    return WHY("SQL command too long");
  sqlite3_stmt *statement;
  const char *cmdtail;
  int ret = 0;
  rhizome_manifest *m = NULL;
  if (sqlite3_prepare_v2(rhizome_db, sqlcmd, strlen(sqlcmd) + 1, &statement, &cmdtail) != SQLITE_OK) {
    sqlite3_finalize(statement);
    ret = WHY(sqlite3_errmsg(rhizome_db));
  } else {
    char manifestIdUpper[RHIZOME_MANIFEST_ID_STRLEN + 1];
    strncpy(manifestIdUpper, manifestid, sizeof manifestIdUpper);
    manifestIdUpper[RHIZOME_MANIFEST_ID_STRLEN] = '\0';
    str_toupper_inplace(manifestIdUpper);
    sqlite3_bind_text(statement, 1, manifestIdUpper, -1, SQLITE_STATIC);
    while (sqlite3_step(statement) == SQLITE_ROW) {
      if (!(   sqlite3_column_count(statement) == 4
	    && sqlite3_column_type(statement, 0) == SQLITE_TEXT
	    && sqlite3_column_type(statement, 1) == SQLITE_BLOB
	    && sqlite3_column_type(statement, 2) == SQLITE_INTEGER
	    && sqlite3_column_type(statement, 3) == SQLITE_INTEGER
      )) { 
	ret = WHY("Incorrect statement column");
	break;
      }
      const char *q_manifestid = (const char *) sqlite3_column_text(statement, 0);
      const char *manifestblob = (char *) sqlite3_column_blob(statement, 1);
      size_t manifestblobsize = sqlite3_column_bytes(statement, 1); // must call after sqlite3_column_blob()
      if (mp) {
	m = rhizome_new_manifest();
	if (m == NULL) {
	  WARNF("MANIFESTS row id=%s has invalid manifest blob -- skipped", q_manifestid);
	  ret = WHY("Out of manifests");
	} else if (rhizome_read_manifest_file(m, manifestblob, manifestblobsize) == -1) {
	  WARNF("MANIFESTS row id=%s has invalid manifest blob -- skipped", q_manifestid);
	  ret = WHY("Invalid manifest blob from database");
	} else {
	  ret = 1;
	  rhizome_hex_to_bytes(manifestid, m->cryptoSignPublic, crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES*2); 
	  const char *blob_service = rhizome_manifest_get(m, "service", NULL, 0);
	  if (blob_service == NULL)
	    ret = WHY("Manifest is missing 'service' field");
	  const char *blob_filehash = rhizome_manifest_get(m, "filehash", NULL, 0);
	  if (blob_filehash == NULL)
	    ret = WHY("Manifest is missing 'filehash' field");
	  else {
	    memcpy(m->fileHexHash, blob_filehash, RHIZOME_FILEHASH_STRLEN + 1);
	    m->fileHashedP = 1;
	  }
	  long long blob_version = rhizome_manifest_get_ll(m, "version");
	  if (blob_version == -1)
	    ret = WHY("Manifest is missing 'version' field");
	  else
	    m->version = blob_version;
	  long long filesizeq = rhizome_manifest_get_ll(m, "filesize");
	  if (filesizeq == -1)
	    ret = WHY("Manifest is missing 'filesize' field");
	  else
	    m->fileLength = filesizeq;
	  if (ret == 1) {
	    cli_puts("service"); cli_delim(":");
	    cli_puts(blob_service); cli_delim("\n");
	    cli_puts("manifestid"); cli_delim(":");
	    cli_puts(q_manifestid); cli_delim("\n");
	    cli_puts("version"); cli_delim(":");
	    cli_printf("%lld", (long long) sqlite3_column_int64(statement, 2)); cli_delim("\n");
	    cli_puts("inserttime"); cli_delim(":");
	    cli_printf("%lld", (long long) sqlite3_column_int64(statement, 3)); cli_delim("\n");
	    cli_puts("filehash"); cli_delim(":");
	    cli_puts(m->fileHexHash); cli_delim("\n");
	    cli_puts("filesize"); cli_delim(":");
	    cli_printf("%lld", (long long) m->fileLength); cli_delim("\n");
	    // Could write the manifest blob to the CLI output here, but that would require the output to
	    // support byte[] fields as well as String fields.
	  }
	}
      }
      break;
    }
  }
  sqlite3_finalize(statement);
  if (mp && ret == 1)
    *mp = m;
  return ret;
}

/* Retrieve a file from the database, given its file hash.
 *
 * Returns 1 if file is found (contents are written to filepath if given).
 * Returns 0 if file is not found.
 * Returns -1 on error.
 */
int rhizome_retrieve_file(const char *fileid, const char *filepath)
{
  rhizome_update_file_priority(fileid);
  long long count=sqlite_exec_int64("SELECT COUNT(*) FROM files WHERE id = '%s' AND datavalid != 0",fileid);
  if (count<1) {
    WHY("No such file ID in the database");
    return 0; /* 0 files returned */
  } else if (count>1) {
    WARNF("There is more than one file in the database with ID=%s",fileid);
  }
  char sqlcmd[1024];
  int n = snprintf(sqlcmd, sizeof(sqlcmd), "SELECT id, data, length FROM files WHERE id = ? AND datavalid != 0");
  if (n >= sizeof(sqlcmd))
    { WHY("SQL command too long"); return 0; }
  sqlite3_stmt *statement;
  const char *cmdtail;
  int ret = 0;
  if (sqlite3_prepare_v2(rhizome_db, sqlcmd, strlen(sqlcmd) + 1, &statement, &cmdtail) != SQLITE_OK) {
    ret = WHY(sqlite3_errmsg(rhizome_db));
  } else {
    char fileIdUpper[RHIZOME_FILEHASH_STRLEN + 1];
    strncpy(fileIdUpper, fileid, sizeof fileIdUpper);
    fileIdUpper[RHIZOME_FILEHASH_STRLEN] = '\0';
    str_toupper_inplace(fileIdUpper);
    sqlite3_bind_text(statement, 1, fileIdUpper, -1, SQLITE_STATIC);
    int stepcode = sqlite3_step(statement);
    if (stepcode != SQLITE_ROW) {
      WHY("Query for file yielded no results, even though it should have");
      ret = 0; /* no files returned */
    } else if (!(   sqlite3_column_count(statement) == 3
		    && sqlite3_column_type(statement, 0) == SQLITE_TEXT
		    && sqlite3_column_type(statement, 1) == SQLITE_BLOB
		    && sqlite3_column_type(statement, 2) == SQLITE_INTEGER
		    )) { 
      WHY("Incorrect statement column");
      ret = 0; /* no files returned */
    } else {
#warning This won't work for large blobs.  It also won't allow for decryption
      const char *fileblob = (char *) sqlite3_column_blob(statement, 1);
      size_t fileblobsize = sqlite3_column_bytes(statement, 1); // must call after sqlite3_column_blob()
      long long length = sqlite3_column_int64(statement, 2);
      if (fileblobsize != length) {
	ret = 0; WHY("File length does not match blob size");
      } else {
	cli_puts("filehash"); cli_delim(":");
	cli_puts((const char *)sqlite3_column_text(statement, 0)); cli_delim("\n");
	cli_puts("filesize"); cli_delim(":");
	cli_printf("%lld", length); cli_delim("\n");
	ret = 1;
	if (filepath&&filepath[0]) {
	  int fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0775);
	  if (fd == -1) {
	    WHY_perror("open");
	    ret = WHYF("Cannot open %s for write/create", filepath);
	  } else if (write(fd, fileblob, length) != length) {
	    WHY_perror("write");
	    ret = WHYF("Error writing %lld bytes to %s ", (long long) length, filepath);
	  }
	  if (fd != -1 && close(fd) == -1) {
	    WHY_perror("close");
	    ret = 0; WHYF("Error flushing to %s ", filepath);
	  }
	}
      }
    }
  }
  sqlite3_finalize(statement);
  return ret;
}
  
