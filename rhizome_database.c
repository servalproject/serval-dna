/*
Serval Rhizome file sharing
Copyright (C) 2012 The Serval Project, Inc.

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

#define __RHIZOME_INLINE
#include <stdlib.h>
#include <time.h>
#include "serval.h"
#include "conf.h"
#include "rhizome.h"
#include "strbuf.h"
#include "strbuf_helpers.h"
#include "str.h"

int min(int a,int b)
{
  if (a<b) return a; else return b;
}

static char rhizome_thisdatastore_path[256];

const char *rhizome_datastore_path()
{
  if (!rhizome_thisdatastore_path[0])
    rhizome_set_datastore_path(NULL);
  return rhizome_thisdatastore_path;
}

int rhizome_set_datastore_path(const char *path)
{
  strbuf b = strbuf_local(rhizome_thisdatastore_path, sizeof rhizome_thisdatastore_path);
  strbuf_path_join(b, serval_instancepath(), config.rhizome.datastore_path, path, NULL);
  INFOF("Rhizome datastore path = %s", alloca_str_toprint(rhizome_thisdatastore_path));
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
  if (config.debug.rhizome) DEBUGF("mkdirs(%s, 0700)", rhizome_datastore_path());
  return emkdirs(rhizome_datastore_path(), 0700);
}

int create_rhizome_import_dir()
{
  char dirname[1024];
  if (!form_rhizome_import_path(dirname, sizeof dirname, NULL))
    return -1;
  if (config.debug.rhizome) DEBUGF("mkdirs(%s, 0700)", dirname);
  return emkdirs(dirname, 0700);
}

sqlite3 *rhizome_db=NULL;

/* XXX Requires a messy join that might be slow. */
int rhizome_manifest_priority(sqlite_retry_state *retry, const char *id)
{
  long long result = 0;
  if (sqlite_exec_int64_retry(retry, &result,
	"select max(grouplist.priorty) from grouplist,manifests,groupmemberships"
	" where manifests.id='%s'"
	"   and grouplist.id=groupmemberships.groupid"
	"   and groupmemberships.manifestid=manifests.id;",
	id
      ) == -1
  )
    return -1;
  return (int) result;
}

int is_debug_rhizome()
{
  return config.debug.rhizome;
}

int is_debug_rhizome_ads()
{
  return config.debug.rhizome_ads;
}

static int (*sqlite_trace_func)() = is_debug_rhizome;
const struct __sourceloc *sqlite_trace_whence = NULL;

static void sqlite_trace_callback(void *context, const char *rendered_sql)
{
  if (sqlite_trace_func())
    logMessage(LOG_LEVEL_DEBUG, sqlite_trace_whence ? *sqlite_trace_whence : __HERE__, "%s", rendered_sql);
}

/* This function allows code like:
 *
 *    debugflags_t oldmask = sqlite_set_debugmask(DEBUG_SOMETHING_ELSE);
 *    ...
 *    sqlite3_stmt *statement = sqlite_prepare(&retry, "select blah blah blah");
 *    while (sqlite_step_retry(&retry, statement) == SQLITE_ROW) {
 *	// do blah blah blah
 *    }
 *    ...
 *    sqlite_set_debugmask(oldmask);
 *    return result;
 *
 * so that code can choose which DEBUG_ flags control the logging of rendered SQL queries.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int (*sqlite_set_tracefunc(int (*newfunc)()))()
{
  int (*oldfunc)() = sqlite_trace_func;
  sqlite_trace_func = newfunc;
  return oldfunc;
}

void sqlite_log(void *ignored, int result, const char *msg){
  WARNF("Sqlite: %d %s", result, msg);
}

static void verify_bundles(){
  // assume that only the manifest itself can be trusted
  // fetch all manifests and reinsert them.
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  // This cursor must be ordered descending as re-inserting the manifests will give them a new higher manifest id.
  // If we didn't, we'd get stuck in an infinite loop.
  sqlite3_stmt *statement = sqlite_prepare(&retry, "SELECT ROWID, MANIFEST FROM MANIFESTS ORDER BY ROWID DESC;");
  while(sqlite_step_retry(&retry, statement)==SQLITE_ROW){
    sqlite3_int64 rowid = sqlite3_column_int64(statement, 0);
    const void *manifest = sqlite3_column_blob(statement, 1);
    int manifest_length = sqlite3_column_bytes(statement, 1);
    
    rhizome_manifest *m=rhizome_new_manifest();
    int ret=0;
    ret = rhizome_read_manifest_file(m, manifest, manifest_length);
    if (ret==0 && m->errors)
      ret=-1;
    if (ret==0)
      ret=rhizome_manifest_verify(m);
    if (ret==0){
      m->finalised=1;
      m->manifest_bytes=m->manifest_all_bytes;
      // store it again, to ensure it is valid and stored correctly with matching file content.
      ret=rhizome_store_bundle(m);
    }
    if (ret!=0){
      DEBUGF("Removing invalid manifest entry @%lld", rowid);
      //sqlite_exec_void_retry(&retry, "DELETE FROM MANIFESTS WHERE ROWID=%lld;", rowid);
    }
    rhizome_manifest_free(m);
  }
  sqlite3_finalize(statement);
}

/*
 * The MANIFESTS table 'author' column records the cryptographically verified SID of the author
 * that has write permission on the bundle, ie, possesses the Rhizome secret key that generated the
 * BID, and hence can derive the Bundle Secret from the bundle's BK field:
 * - The MANIFESTS table 'author' column is set to the author SID when a bundle is created
 *   locally bu a non-secret identity, so no verification need ever be performed for one's own
 *   bundles while they remain in the Rhizome store.
 * - When a bundle is imported, the 'author' column is set to NULL to indicate that no
 *   verification has passed yet.  This includes one's own bundles that have been purged from
 *   the local Rhizome store then recovered from a remote Rhizome node.
 * - When a manifest with NULL 'author' is examined closely, ie extracted, not merely
 *   listed, the keyring is searched for an identity that is the author.  If an author is
 *   found, the MANIFESTS table 'author' column is updated.  This allows one to regain the
 *   ability to overwrite one's own bundles that have been lost but recovered from an exterior
 *   Rhizome node.
 * - The above check automates the "own bundle recovery" mechanism at the expense of a CPU-heavy
 *   cryptographic check every time a foreign bundle is examined, but at least listing is fast.
 *   This will not scale as many identities are added to the keyring.  It will eventually have to be
 *   replaced with a means to cache positive and negative verifications in the Rhizome db for local,
 *   non-secret identities.
 *
 * -- Andrew Bettison <andrew@servalproject.com>, October 2012
 */

int rhizome_opendb()
{
  if (rhizome_db) return 0;

  IN();
  
  if (create_rhizome_datastore_dir() == -1){
    RETURN(WHY("No Directory"));
  }
  char dbpath[1024];
  if (!sqlite3_temp_directory){
    if (!FORM_RHIZOME_DATASTORE_PATH(dbpath, "")){
      RETURN(WHY("Invalid path"));
    }
    sqlite3_temp_directory = sqlite3_mprintf("%s", dbpath);
  }
  
  if (!FORM_RHIZOME_DATASTORE_PATH(dbpath, "rhizome.db")){
    RETURN(WHY("Invalid path"));
  }

  sqlite3_config(SQLITE_CONFIG_LOG,sqlite_log,NULL);
  
  if (sqlite3_open(dbpath,&rhizome_db)){
    RETURN(WHYF("SQLite could not open database %s: %s", dbpath, sqlite3_errmsg(rhizome_db)));
  }
  sqlite3_trace(rhizome_db, sqlite_trace_callback, NULL);
  int loglevel = (config.debug.rhizome) ? LOG_LEVEL_DEBUG : LOG_LEVEL_SILENT;

  /* Read Rhizome configuration */
  if (config.debug.rhizome) {
    DEBUGF("Rhizome will use %lluB of storage for its database.", (unsigned long long) config.rhizome.database_size);
  }
  
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;

  long long version;
  if (sqlite_exec_int64_retry(&retry, &version, "PRAGMA user_version;") == -1)
    RETURN(-1);
  
  if (version<1){
    /* Create tables as required */
    sqlite_exec_void_loglevel(loglevel, "PRAGMA auto_vacuum=2;");
    if (	sqlite_exec_void_retry(&retry, "CREATE TABLE IF NOT EXISTS GROUPLIST(id text not null primary key, closed integer,ciphered integer,priority integer);") == -1
      ||	sqlite_exec_void_retry(&retry, "CREATE TABLE IF NOT EXISTS MANIFESTS(id text not null primary key, version integer,inserttime integer, filesize integer, filehash text, author text, bar blob, manifest blob);") == -1
      ||	sqlite_exec_void_retry(&retry, "CREATE TABLE IF NOT EXISTS FILES(id text not null primary key, length integer, highestpriority integer, datavalid integer, inserttime integer);") == -1
      ||	sqlite_exec_void_retry(&retry, "CREATE TABLE IF NOT EXISTS FILEBLOBS(id text not null primary key, data blob);") == -1
      ||	sqlite_exec_void_retry(&retry, "DROP TABLE IF EXISTS FILEMANIFESTS;") == -1
      ||	sqlite_exec_void_retry(&retry, "CREATE TABLE IF NOT EXISTS GROUPMEMBERSHIPS(manifestid text not null, groupid text not null);") == -1
      ||	sqlite_exec_void_retry(&retry, "CREATE TABLE IF NOT EXISTS VERIFICATIONS(sid text not null, did text, name text, starttime integer, endtime integer, signature blob);") == -1
    ) {
      RETURN(WHY("Failed to create schema"));
    }

    /* Create indexes if they don't already exist */
    sqlite_exec_void_loglevel(LOG_LEVEL_WARN, "CREATE INDEX IF NOT EXISTS bundlesizeindex ON manifests (filesize);");
    sqlite_exec_void_loglevel(LOG_LEVEL_WARN, "CREATE INDEX IF NOT EXISTS IDX_MANIFESTS_HASH ON MANIFESTS(filehash);");
    
    sqlite_exec_void_loglevel(LOG_LEVEL_WARN, "PRAGMA user_version=1;");
  }
  if (version<2){
    sqlite_exec_void_loglevel(LOG_LEVEL_WARN, "ALTER TABLE MANIFESTS ADD COLUMN service text;");
    sqlite_exec_void_loglevel(LOG_LEVEL_WARN, "ALTER TABLE MANIFESTS ADD COLUMN name text;");
    sqlite_exec_void_loglevel(LOG_LEVEL_WARN, "ALTER TABLE MANIFESTS ADD COLUMN sender text collate nocase;");
    sqlite_exec_void_loglevel(LOG_LEVEL_WARN, "ALTER TABLE MANIFESTS ADD COLUMN recipient text collate nocase;");
    // if more bundle verification is required in later upgrades, move this to the end, don't run it more than once.
    verify_bundles();
    sqlite_exec_void_loglevel(LOG_LEVEL_WARN, "PRAGMA user_version=2;");
  }
  
  if (version<3){
    sqlite_exec_void_loglevel(LOG_LEVEL_WARN, "CREATE INDEX IF NOT EXISTS IDX_MANIFESTS_ID_VERSION ON MANIFESTS(id, version);");
    sqlite_exec_void_loglevel(LOG_LEVEL_WARN, "PRAGMA user_version=3;");
  }
  
  // TODO recreate tables with collate nocase on hex columns
  
  /* Future schema updates should be performed here. 
   The above schema can be assumed to exist.
   All changes should attempt to preserve any existing data */
  
  // We can't delete a file that is being transferred in another process at this very moment...
  if (config.rhizome.clean_on_open)
    rhizome_cleanup(NULL);
  RETURN(0);
  OUT();
}

int rhizome_close_db()
{
  IN();
  if (rhizome_db) {
    if (!sqlite3_get_autocommit(rhizome_db)){
      WHY("Uncommitted transaction!");
      sqlite_exec_void("ROLLBACK;");
    }
    sqlite3_stmt *stmt = NULL;
    while ((stmt = sqlite3_next_stmt(rhizome_db, stmt))) {
      const char *sql = sqlite3_sql(stmt);
      WARNF("closing Rhizome db with unfinalised statement: %s", sql ? sql : "BLOB");
    }
    int r = sqlite3_close(rhizome_db);
    if (r != SQLITE_OK)
      RETURN(WHYF("Failed to close sqlite database, %s",sqlite3_errmsg(rhizome_db)));
  }
  rhizome_db=NULL;
  RETURN(0);
  OUT();
}

/* SQL query retry logic.

   The common retry-on-busy logic is factored into this function.  This logic encapsulates the
   maximum time (timeout) that the caller may wait for a lock to be released and the sleep interval
   while waiting.  The way to use it is this:

      sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
      do ret = some_sqlite_operation(...);
        while (is_busy(ret) && sqlite_retry(&retry, "some_sqlite_operation"));
      if (is_error(ret) || is_busy(ret))
	return -1; // an error has already been logged
      sqlite_retry_done(&retry, "some_sqlite_operation");
      ...

   If the database is currently locked for updates, then some_sqlite_operation() will return a code
   indicating busy (which is distinguishable from the codes for success or any other error).
   sqlite_retry() will then log a DEBUG or INFO message, sleep for a short period and return true if
   the timeout has not been reached.  It keeps this information in the 'retry' variable, which must
   be initialised as shown.  As long as the timeout has not been reached, sqlite_retry() will keep
   sleeping and returning true.  If the timeout is reached, then sqlite_retry() will log an error
   and return false.  If the operation is successful, sqlite_retry_done() must be called to log the
   success as a DEBUG or INFO message to provide closure to the prior messages already logged by
   sqlite_retry() and to reset the 'retry' variable for re-use.

   The timeout and sleep interval depend on whether the caller is the servald server process or not.
   See the definition of the SQLITE_RETRY_STATE_DEFAULT macro for the default settings.

   A single 'retry' variable may be initialised once then used for a succession of database
   operations.  If invoked by the server process, then the timeout timer will not be reset by
   sqlite_retry() or sqlite_retry_done(), so that the timeout limit will apply to the cumulative
   latency, not just to each individual query, which could potentially add up to much greater
   latency than desired.  However, in non-server processes, each query may be allowed its own
   timeout, giving a greater chance of success at the expense of potentially greater latency.
 */

/* In the servald server process, by default we retry every 10 ms for up to 50 ms, so as to not
   introduce too much latency into server responsiveness.  In other processes (eg, Batphone MeshMS
   thread), by default we allow busy retries to go for over a second, waiting 100 ms between each
   retry.
 */
sqlite_retry_state sqlite_retry_state_init(int serverLimit, int serverSleep, int otherLimit, int otherSleep)
{
  return (sqlite_retry_state){
      .limit = serverMode ? (serverLimit < 0 ? 50 : serverLimit) : (otherLimit < 0 ? 5000 : otherLimit),
      .sleep = serverMode ? (serverSleep < 0 ? 10 : serverSleep) : (otherSleep < 0 ? 100 : otherSleep),
      .elapsed = 0,
      .start = -1,
      .busytries = 0
    };
}

int _sqlite_retry(struct __sourceloc __whence, sqlite_retry_state *retry, const char *action)
{
  time_ms_t now = gettime_ms();
  ++retry->busytries;
  if (retry->start == -1)
    retry->start = now;
  retry->elapsed = now - retry->start;
  
  INFOF("%s on try %u after %.3f seconds (limit %.3f): %s",
      sqlite3_errmsg(rhizome_db),
      retry->busytries,
      (retry->elapsed) / 1e3,
      (retry->limit) / 1e3,
      action
    );
  
  if (retry->elapsed >= retry->limit) {
    // reset ready for next query
    retry->busytries = 0;
    if (!serverMode)
      retry->start = -1;
    return 0; // tell caller to stop trying
  }
  
  if (retry->sleep)
    sleep_ms(retry->sleep);
  return 1; // tell caller to try again
}

void _sqlite_retry_done(struct __sourceloc __whence, sqlite_retry_state *retry, const char *action)
{
  if (retry->busytries) {
    time_ms_t now = gettime_ms();
    INFOF("succeeded on try %u after %.3f seconds (limit %.3f): %s",
	retry->busytries + 1,
	(now - retry->start) / 1e3,
	(retry->limit) / 1e3,
	action
      );
  }
  // reset ready for next query
  retry->busytries = 0;
  if (!serverMode)
    retry->start = -1;
}

/*
   Convenience wrapper for preparing an SQL command.
   Returns -1 if an error occurs (logged as an error), otherwise zero with the prepared
   statement in *statement.
 */
sqlite3_stmt *_sqlite_prepare(struct __sourceloc __whence, sqlite_retry_state *retry, const char *sqlformat, ...)
{
  strbuf sql = strbuf_alloca(8192);
  strbuf_va_printf(sql, sqlformat);
  return _sqlite_prepare_loglevel(__whence, LOG_LEVEL_ERROR, retry, sql);
}

sqlite3_stmt *_sqlite_prepare_loglevel(struct __sourceloc __whence, int log_level, sqlite_retry_state *retry, strbuf stmt)
{
  sqlite3_stmt *statement = NULL;
  if (strbuf_overrun(stmt)) {
    WHYF("SQL overrun: %s", strbuf_str(stmt));
    return NULL;
  }
  if (!rhizome_db && rhizome_opendb() == -1)
    return NULL;
  while (1) {
    switch (sqlite3_prepare_v2(rhizome_db, strbuf_str(stmt), -1, &statement, NULL)) {
      case SQLITE_OK:
	return statement;
      case SQLITE_BUSY:
      case SQLITE_LOCKED:
	if (retry && _sqlite_retry(__whence, retry, strbuf_str(stmt))) {
	  break; // back to sqlite3_prepare_v2()
	}
	// fall through...
      default:
	LOGF(log_level, "query invalid, %s: %s", sqlite3_errmsg(rhizome_db), strbuf_str(stmt));
	sqlite3_finalize(statement);
	return NULL;
    }
  }
}

int _sqlite_step_retry(struct __sourceloc __whence, int log_level, sqlite_retry_state *retry, sqlite3_stmt *statement)
{
  int ret = -1;
  sqlite_trace_whence = &__whence;
  while (statement) {
    int stepcode = sqlite3_step(statement);
    switch (stepcode) {
      case SQLITE_OK:
      case SQLITE_DONE:
      case SQLITE_ROW:
	if (retry)
	  _sqlite_retry_done(__whence, retry, sqlite3_sql(statement));
	ret = stepcode;
	statement = NULL;
	break;
      case SQLITE_BUSY:
      case SQLITE_LOCKED:
	if (retry && _sqlite_retry(__whence, retry, sqlite3_sql(statement))) {
	  sqlite3_reset(statement);
	  break; // back to sqlite3_step()
	}
	// fall through...
      default:
	LOGF(log_level, "query failed (%d), %s: %s", stepcode, sqlite3_errmsg(rhizome_db), sqlite3_sql(statement));
	ret = -1;
	statement = NULL;
	break;
    }
  }
  sqlite_trace_whence = NULL;
  return ret;
}

/*
 * Convenience wrapper for executing a prepared SQL statement where the row outputs are not wanted.
 * Always finalises the statement before returning.
 *
 * If an error occurs then logs it at the given level and returns -1.
 *
 * If 'retry' is non-NULL and the BUSY error occurs (indicating the database is locked, ie,
 * currently in use by another process), then resets the statement and retries while sqlite_retry()
 * returns true.  If sqlite_retry() returns false then returns -1.
 *
 * Otherwise returns the number of rows (SQLITE_ROW) results, which will be zero if the first result
 * was SQLITE_OK or SQLITE_DONE.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static int _sqlite_exec_prepared(struct __sourceloc __whence, int log_level, sqlite_retry_state *retry, sqlite3_stmt *statement)
{
  if (!statement)
    return -1;
  int rowcount = 0;
  int stepcode;
  while ((stepcode = _sqlite_step_retry(__whence, log_level, retry, statement)) == SQLITE_ROW)
    ++rowcount;
  sqlite3_finalize(statement);
  if (sqlite_trace_func())
    DEBUGF("rowcount=%d changes=%d", rowcount, sqlite3_changes(rhizome_db));
  return sqlite_code_ok(stepcode) ? rowcount : -1;
}

static int _sqlite_vexec_void(struct __sourceloc __whence, int log_level, sqlite_retry_state *retry, const char *sqlformat, va_list ap)
{
  strbuf stmt = strbuf_alloca(8192);
  strbuf_vsprintf(stmt, sqlformat, ap);
  int rowcount = _sqlite_exec_prepared(__whence, log_level, retry, _sqlite_prepare_loglevel(__whence, log_level, retry, stmt));
  if (rowcount == -1)
    return -1;
  if (rowcount)
    WARNF("void query unexpectedly returned %d row%s", rowcount, rowcount == 1 ? "" : "s");
  return sqlite3_changes(rhizome_db);
}

/* Convenience wrapper for executing an SQL command that returns no value.
 * If an error occurs then logs it at ERROR level and returns -1.  Otherwise returns the number of
 * rows changed by the command.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int _sqlite_exec_void(struct __sourceloc __whence, const char *sqlformat, ...)
{
  va_list ap;
  va_start(ap, sqlformat);
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  int ret = _sqlite_vexec_void(__whence, LOG_LEVEL_ERROR, &retry, sqlformat, ap);
  va_end(ap);
  return ret;
}

/* Same as sqlite_exec_void(), but logs any error at the given level instead of ERROR.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int _sqlite_exec_void_loglevel(struct __sourceloc __whence, int log_level, const char *sqlformat, ...)
{
  va_list ap;
  va_start(ap, sqlformat);
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  int ret = _sqlite_vexec_void(__whence, log_level, &retry, sqlformat, ap);
  va_end(ap);
  return ret;
}

/* Same as sqlite_exec_void() but if the statement cannot be executed because the database is
 * currently locked for updates, then will call sqlite_retry() on the supplied retry state variable
 * instead of its own, internal one.  If 'retry' is passed as NULL, then will not sleep and retry at
 * all in the event of a busy condition, but will log it as an error and return immediately.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int _sqlite_exec_void_retry(struct __sourceloc __whence, sqlite_retry_state *retry, const char *sqlformat, ...)
{
  va_list ap;
  va_start(ap, sqlformat);
  int ret = _sqlite_vexec_void(__whence, LOG_LEVEL_ERROR, retry, sqlformat, ap);
  va_end(ap);
  return ret;
}

/* Same as sqlite_exec_void_retry(), but logs any error at the given level instead of ERROR.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int _sqlite_exec_void_retry_loglevel(struct __sourceloc __whence, int log_level, sqlite_retry_state *retry, const char *sqlformat, ...)
{
  va_list ap;
  va_start(ap, sqlformat);
  int ret = _sqlite_vexec_void(__whence, log_level, retry, sqlformat, ap);
  va_end(ap);
  return ret;
}

static int _sqlite_vexec_int64(struct __sourceloc __whence, sqlite_retry_state *retry, long long *result, const char *sqlformat, va_list ap)
{
  strbuf stmt = strbuf_alloca(8192);
  strbuf_vsprintf(stmt, sqlformat, ap);
  sqlite3_stmt *statement = _sqlite_prepare_loglevel(__whence, LOG_LEVEL_ERROR, retry, stmt);
  if (!statement)
    return -1;
  int ret = 0;
  int rowcount = 0;
  int stepcode;
  while ((stepcode = _sqlite_step_retry(__whence, LOG_LEVEL_ERROR, retry, statement)) == SQLITE_ROW) {
    int columncount = sqlite3_column_count(statement);
    if (columncount != 1)
      ret = WHYF("incorrect column count %d (should be 1): %s", columncount, sqlite3_sql(statement));
    else if (++rowcount == 1)
      *result = sqlite3_column_int64(statement, 0);
  }
  if (rowcount > 1)
    WARNF("query unexpectedly returned %d rows, ignored all but first", rowcount);
  sqlite3_finalize(statement);
  if (!sqlite_code_ok(stepcode) || ret == -1)
    return -1;
  if (sqlite_trace_func())
    DEBUGF("rowcount=%d changes=%d", rowcount, sqlite3_changes(rhizome_db));
  return rowcount;
}

/*
 * Convenience wrapper for executing an SQL command that returns a single int64 value.
 * Logs an error and returns -1 if an error occurs.
 * If no row is found, then returns 0 and does not alter *result.
 * If exactly one row is found, the assigns its value to *result and returns 1.
 * If more than one row is found, then logs a warning, assigns the value of the first row to *result
 * and returns the number of rows.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int _sqlite_exec_int64(struct __sourceloc __whence, long long *result, const char *sqlformat,...)
{
  va_list ap;
  va_start(ap, sqlformat);
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  int ret = _sqlite_vexec_int64(__whence, &retry, result, sqlformat, ap);
  va_end(ap);
  return ret;
}

/* Same as sqlite_exec_int64() but if the statement cannot be executed because the database is
 * currently locked for updates, then will call sqlite_retry() on the supplied retry state variable
 * instead of its own, internal one.  If 'retry' is passed as NULL, then will not sleep and retry at
 * all in the event of a busy condition, but will log it as an error and return immediately.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int _sqlite_exec_int64_retry(struct __sourceloc __whence, sqlite_retry_state *retry, long long *result, const char *sqlformat,...)
{
  va_list ap;
  va_start(ap, sqlformat);
  int ret = _sqlite_vexec_int64(__whence, retry, result, sqlformat, ap);
  va_end(ap);
  return ret;
}

/* Convenience wrapper for executing an SQL command that returns a single text value.
 * Logs an error and returns -1 if an error occurs, otherwise the number of rows that were found:
 *  0 means no rows, nothing is appended to the strbuf
 *  1 means exactly one row, appends its column to the strbuf
 *  2 more than one row, logs a warning and appends the first row's column to the strbuf
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int _sqlite_exec_strbuf(struct __sourceloc __whence, strbuf sb, const char *sqlformat,...)
{
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  va_list ap;
  va_start(ap, sqlformat);
  int ret = _sqlite_vexec_strbuf_retry(__whence, &retry, sb, sqlformat, ap);
  va_end(ap);
  return ret;
}

int _sqlite_exec_strbuf_retry(struct __sourceloc __whence, sqlite_retry_state *retry, strbuf sb, const char *sqlformat, ...)
{
  va_list ap;
  va_start(ap, sqlformat);
  int ret = _sqlite_vexec_strbuf_retry(__whence, retry, sb, sqlformat, ap);
  va_end(ap);
  return ret;
}

int _sqlite_vexec_strbuf_retry(struct __sourceloc __whence, sqlite_retry_state *retry, strbuf sb, const char *sqlformat, va_list ap)
{
  strbuf stmt = strbuf_alloca(8192);
  strbuf_vsprintf(stmt, sqlformat, ap);
  sqlite3_stmt *statement = _sqlite_prepare_loglevel(__whence, LOG_LEVEL_ERROR, retry, stmt);
  if (!statement)
    return -1;
  int ret = 0;
  int rowcount = 0;
  int stepcode;
  while ((stepcode = _sqlite_step_retry(__whence, LOG_LEVEL_ERROR, retry, statement)) == SQLITE_ROW) {
    int columncount = sqlite3_column_count(statement);
    if (columncount != 1)
      ret - WHYF("incorrect column count %d (should be 1): %s", columncount, sqlite3_sql(statement));
    else if (++rowcount == 1)
      strbuf_puts(sb, (const char *)sqlite3_column_text(statement, 0));
  }
  if (rowcount > 1)
    WARNF("query unexpectedly returned %d rows, ignored all but first", rowcount);
  sqlite3_finalize(statement);
  return sqlite_code_ok(stepcode) && ret != -1 ? rowcount : -1;
}

long long rhizome_database_used_bytes()
{
  long long db_page_size;
  long long db_page_count;
  long long db_free_page_count;
  if (	sqlite_exec_int64(&db_page_size, "PRAGMA page_size;") == -1LL
    ||  sqlite_exec_int64(&db_page_count, "PRAGMA page_count;") == -1LL
    ||	sqlite_exec_int64(&db_free_page_count, "PRAGMA free_count;") == -1LL
  )
    return WHY("Cannot measure database used bytes");
  return db_page_size * (db_page_count - db_free_page_count);
}

int rhizome_database_filehash_from_id(const char *id, uint64_t version, char hash[SHA512_DIGEST_STRING_LENGTH])
{
  IN();
  
  strbuf hash_sb = strbuf_local(hash, SHA512_DIGEST_STRING_LENGTH);
  RETURN(sqlite_exec_strbuf(hash_sb, "SELECT filehash FROM MANIFESTS WHERE manifests.version=%lld AND manifests.id='%s';",
			    version,id));
  OUT();
}

static int rhizome_cleanup_external(sqlite_retry_state *retry, sqlite3_stmt *statement){
  int ret=0;
  while (sqlite_step_retry(retry, statement) == SQLITE_ROW) {
    const char *id = (const char *) sqlite3_column_text(statement, 0);
    if (rhizome_store_delete(id)==0)
      ret++;
  }
  return ret;
}

int rhizome_cleanup(struct rhizome_cleanup_report *report)
{
  IN();
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;

  // cleanup external blobs for unreferenced files
  sqlite3_stmt *statement = sqlite_prepare(&retry, "SELECT id FROM FILES WHERE inserttime < %lld AND datavalid=0;", gettime_ms() - 300000);
  int externals_removed=rhizome_cleanup_external(&retry, statement);
  sqlite3_finalize(statement);
  
  statement = sqlite_prepare(&retry, "SELECT id FROM FILES WHERE inserttime < %lld AND datavalid=1 AND NOT EXISTS( SELECT  1 FROM MANIFESTS WHERE MANIFESTS.filehash = FILES.id);", gettime_ms() - 1000);
  externals_removed+=rhizome_cleanup_external(&retry, statement);
  sqlite3_finalize(statement);
  
  // clean out unreferenced files
  int ret;
  ret = sqlite_exec_void_loglevel(LOG_LEVEL_WARN, "DELETE FROM FILES WHERE inserttime < %lld AND datavalid=0;", gettime_ms() - 300000);
  if (report)
    report->deleted_stale_incoming_files = ret;
  ret = sqlite_exec_void_loglevel(LOG_LEVEL_WARN, "DELETE FROM FILES WHERE inserttime < %lld AND datavalid=1 AND NOT EXISTS( SELECT  1 FROM MANIFESTS WHERE MANIFESTS.filehash = FILES.id);", gettime_ms() - 1000);
  if (report)
    report->deleted_orphan_files = ret;
  
  ret = sqlite_exec_void_loglevel(LOG_LEVEL_WARN, "DELETE FROM FILEBLOBS WHERE NOT EXISTS ( SELECT  1 FROM FILES WHERE FILES.id = FILEBLOBS.id );");
  if (report)
    report->deleted_orphan_fileblobs = ret + externals_removed;
   
  RETURN(0);
  OUT();
}

int rhizome_make_space(int group_priority, long long bytes)
{
  /* Asked for impossibly large amount */
  if (bytes>=(config.rhizome.database_size-65536))
    return WHYF("bytes=%lld is too large", bytes);

  long long db_used = rhizome_database_used_bytes();
  if (db_used == -1)
    return -1;
  
  rhizome_cleanup(NULL);
  
  /* If there is already enough space now, then do nothing more */
  if (db_used<=(config.rhizome.database_size-bytes-65536))
    return 0;

  /* Okay, not enough space, so free up some. */
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  sqlite3_stmt *statement = sqlite_prepare(&retry, "select id,length from files where highestpriority < %d order by descending length", group_priority);
  if (!statement)
    return -1;
  while (bytes > (config.rhizome.database_size - 65536 - rhizome_database_used_bytes())
      && sqlite_step_retry(&retry, statement) == SQLITE_ROW
  ) {
    /* Make sure we can drop this blob, and if so drop it, and recalculate number of bytes required */
    const unsigned char *id;

    /* Get values */
    if (sqlite3_column_type(statement, 0)==SQLITE_TEXT)
      id = sqlite3_column_text(statement, 0);
    else {
      WHY("Incorrect type in id column of files table");
      break;
    }
    if (sqlite3_column_type(statement, 1)==SQLITE_INTEGER)
      ; //length=sqlite3_column_int(statement, 1);
    else {
      WHY("Incorrect type in length column of files table");
      break;
    }
    /* Try to drop this file from storage, discarding any references that do not trump the priority
       of this request.  The query done earlier should ensure this, but it doesn't hurt to be
       paranoid, and it also protects against inconsistency in the database. */
    rhizome_drop_stored_file((char *)id, group_priority + 1);
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
int rhizome_drop_stored_file(const char *id,int maximum_priority)
{
  if (!rhizome_str_is_file_hash(id))
    return WHYF("invalid file hash id=%s", alloca_toprint(-1, id, strlen(id)));
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  sqlite3_stmt *statement = sqlite_prepare(&retry, "select id from manifests where filehash='%s'", id);
  if (!statement)
    return WHYF("Could not drop stored file id=%s", id);
  int can_drop = 1;
  while (sqlite_step_retry(&retry, statement) == SQLITE_ROW) {
    /* Find manifests for this file */
    if (sqlite3_column_type(statement, 0) != SQLITE_TEXT) {
      WHYF("Incorrect type in id column of manifests table");
      break;
    }
    const char *manifestId = (char *) sqlite3_column_text(statement, 0);
    /* Check that manifest is not part of a higher priority group.
	If so, we cannot drop the manifest or the file.
	However, we will keep iterating, as we can still drop any other manifests pointing to this file
	that are lower priority, and thus free up a little space. */
    int priority = rhizome_manifest_priority(&retry, manifestId);
    if (priority == -1)
      WHYF("Cannot drop fileid=%s due to error, manifestId=%s", id, manifestId);
    else if (priority > maximum_priority) {
      WHYF("Cannot drop fileid=%s due to manifest priority, manifestId=%s", id, manifestId);
      can_drop = 0;
    } else {
      if (config.debug.rhizome)
	DEBUGF("removing stale manifests, groupmemberships");
      sqlite_exec_void_retry(&retry, "delete from manifests where id='%s';", manifestId);
      sqlite_exec_void_retry(&retry, "delete from keypairs where public='%s';", manifestId);
      sqlite_exec_void_retry(&retry, "delete from groupmemberships where manifestid='%s';", manifestId);
    }
  }
  sqlite3_finalize(statement);
  if (can_drop) {
    sqlite_exec_void_retry(&retry, "delete from files where id='%s';",id);
    rhizome_store_delete(id);
    sqlite_exec_void_retry(&retry, "delete from fileblobs where id='%s';",id);
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
   and GROUPMEMBERSHIPS tables, and possibly GROUPLIST as well.
 */
int rhizome_store_bundle(rhizome_manifest *m)
{
  if (!m->finalised) return WHY("Manifest was not finalised");

  if (m->haveSecret) {
    /* We used to store the secret in the database, but we don't anymore, as we use 
     the BK field in the manifest. So nothing to do here. */
  } else {
    /* We don't have the secret for this manifest, so only allow updates if 
     the self-signature is valid */
    if (!m->selfSigned)
      return WHY("Manifest is not signed, and I don't have the key.  Manifest might be forged or corrupt.");
  }

  char manifestid[RHIZOME_MANIFEST_ID_STRLEN + 1];
  rhizome_manifest_get(m, "id", manifestid, sizeof manifestid);
  str_toupper_inplace(manifestid);

  /* Bind BAR to data field */
  unsigned char bar[RHIZOME_BAR_BYTES];
  rhizome_manifest_to_bar(m,bar);

  /* Store the file (but not if it is already in the database) */
  char filehash[RHIZOME_FILEHASH_STRLEN + 1];
  if (m->fileLength > 0) {
    strncpy(filehash, m->fileHexHash, sizeof filehash);
    str_toupper_inplace(filehash);

    if (!rhizome_exists(filehash)) {
      cli_delim("\n");cli_puts("File should already be stored by now because filehash already exist in add manifest");
      return WHY("File should already be stored by now");}
  } else {
    filehash[0] = '\0';
  }

  const char *author = is_sid_any(m->author) ? NULL : alloca_tohex_sid(m->author);
  const char *name = rhizome_manifest_get(m, "name", NULL, 0);
  const char *sender = rhizome_manifest_get(m, "sender", NULL, 0);
  const char *recipient = rhizome_manifest_get(m, "recipient", NULL, 0);
  const char *service = rhizome_manifest_get(m, "service", NULL, 0);
  
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  if (sqlite_exec_void_retry(&retry, "BEGIN TRANSACTION;") == -1)
    return WHY("Failed to begin transaction");
  
  sqlite3_stmt *stmt;
  if ((stmt = sqlite_prepare(&retry, "INSERT OR REPLACE INTO MANIFESTS(id,manifest,version,inserttime,bar,filesize,filehash,author,service,name,sender,recipient) VALUES(?,?,?,?,?,?,?,?,?,?,?,?);")) == NULL)
    goto rollback;
  if (!(   sqlite_code_ok(sqlite3_bind_text(stmt, 1, manifestid, -1, SQLITE_STATIC))
        && sqlite_code_ok(sqlite3_bind_blob(stmt, 2, m->manifestdata, m->manifest_bytes, SQLITE_STATIC))
	&& sqlite_code_ok(sqlite3_bind_int64(stmt, 3, m->version))
	&& sqlite_code_ok(sqlite3_bind_int64(stmt, 4, (long long) gettime_ms()))
	&& sqlite_code_ok(sqlite3_bind_blob(stmt, 5, bar, RHIZOME_BAR_BYTES, SQLITE_STATIC))
	&& sqlite_code_ok(sqlite3_bind_int64(stmt, 6, m->fileLength))
	&& sqlite_code_ok(sqlite3_bind_text(stmt, 7, filehash, -1, SQLITE_STATIC))
	&& sqlite_code_ok(sqlite3_bind_text(stmt, 8, author, -1, SQLITE_STATIC))
	&& sqlite_code_ok(sqlite3_bind_text(stmt, 9, service, -1, SQLITE_STATIC))
	&& sqlite_code_ok(sqlite3_bind_text(stmt, 10, name, -1, SQLITE_STATIC))
	&& sqlite_code_ok(sqlite3_bind_text(stmt, 11, sender, -1, SQLITE_STATIC))
	&& sqlite_code_ok(sqlite3_bind_text(stmt, 12, recipient, -1, SQLITE_STATIC))
  )) {
    WHYF("query failed, %s: %s", sqlite3_errmsg(rhizome_db), sqlite3_sql(stmt));
    goto rollback;
  }
  if (sqlite_step_retry(&retry, stmt) == -1)
    goto rollback;
  sqlite3_finalize(stmt);
  stmt = NULL;

  // TODO remove old payload?
  
  if (rhizome_manifest_get(m,"isagroup",NULL,0)!=NULL) {
    int closed=rhizome_manifest_get_ll(m,"closedgroup");
    if (closed<1) closed=0;
    int ciphered=rhizome_manifest_get_ll(m,"cipheredgroup");
    if (ciphered<1) ciphered=0;
    if ((stmt = sqlite_prepare(&retry, "INSERT OR REPLACE INTO GROUPLIST(id,closed,ciphered,priority) VALUES (?,?,?,?);")) == NULL)
      goto rollback;
    if (!(   sqlite_code_ok(sqlite3_bind_text(stmt, 1, manifestid, -1, SQLITE_TRANSIENT))
          && sqlite_code_ok(sqlite3_bind_int(stmt, 2, closed))
          && sqlite_code_ok(sqlite3_bind_int(stmt, 3, ciphered))
          && sqlite_code_ok(sqlite3_bind_int(stmt, 4, RHIZOME_PRIORITY_DEFAULT))
    )) {
      WHYF("query failed, %s: %s", sqlite3_errmsg(rhizome_db), sqlite3_sql(stmt));
      goto rollback;
    }
    if (sqlite_step_retry(&retry, stmt) == -1)
      goto rollback;
    sqlite3_finalize(stmt);
    stmt = NULL;
  }

  if (m->group_count > 0) {
    if ((stmt = sqlite_prepare(&retry, "INSERT OR REPLACE INTO GROUPMEMBERSHIPS(manifestid,groupid) VALUES(?, ?);")) == NULL)
      goto rollback;
    int i;
    for (i=0;i<m->group_count;i++){
      if (!(   sqlite_code_ok(sqlite3_bind_text(stmt, 1, manifestid, -1, SQLITE_TRANSIENT))
	    && sqlite_code_ok(sqlite3_bind_text(stmt, 2, m->groups[i], -1, SQLITE_TRANSIENT))
      )) {
	WHYF("query failed, %s: %s", sqlite3_errmsg(rhizome_db), sqlite3_sql(stmt));
	goto rollback;
      }
      if (sqlite_step_retry(&retry, stmt) == -1)
	goto rollback;
      sqlite3_reset(stmt);
    }
    sqlite3_finalize(stmt);
    stmt = NULL;
  }
  if (sqlite_exec_void_retry(&retry, "COMMIT;") != -1){
    // This message used in tests; do not modify or remove.
    const char *service = rhizome_manifest_get(m, "service", NULL, 0);
    INFOF("RHIZOME ADD MANIFEST service=%s bid=%s version=%lld",
	  service ? service : "NULL",
	  alloca_tohex_sid(m->cryptoSignPublic),
	  m->version
	  );
    monitor_announce_bundle(m);
    return 0;
  }
rollback:
  if (stmt)
    sqlite3_finalize(stmt);
  WHYF("Failed to store bundle bid=%s", manifestid);
  sqlite_exec_void_retry(&retry, "ROLLBACK;");
  return -1;
}

int rhizome_list_manifests(const char *service, const char *name, 
			   const char *sender_sid, const char *recipient_sid, 
			   int limit, int offset, char count_rows)
{
  IN();
  strbuf b = strbuf_alloca(1024);
  strbuf_sprintf(b, "SELECT id, manifest, version, inserttime, author, rowid FROM manifests WHERE 1=1");
  
  if (service && *service)
    strbuf_sprintf(b, " AND service = ?1");
  if (name && *name)
    strbuf_sprintf(b, " AND name like ?2");
  if (sender_sid && *sender_sid)
    strbuf_sprintf(b, " AND sender = ?3");
  if (recipient_sid && *recipient_sid)
    strbuf_sprintf(b, " AND recipient = ?4");
  
  strbuf_sprintf(b, " ORDER BY inserttime DESC");
  
  if (offset)
    strbuf_sprintf(b, " OFFSET %u", offset);
  
  if (strbuf_overrun(b))
    RETURN(WHYF("SQL command too long: ", strbuf_str(b)));
  
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  sqlite3_stmt *statement = sqlite_prepare(&retry, "%s", strbuf_str(b));
  if (!statement)
    RETURN(-1);
  
  int ret = 0;
  
  if (service && *service)
    ret = sqlite3_bind_text(statement, 1, service, -1, SQLITE_STATIC);
  if (ret==SQLITE_OK && name && *name)
    ret = sqlite3_bind_text(statement, 2, name, -1, SQLITE_STATIC);
  if (ret==SQLITE_OK && sender_sid && *sender_sid)
    ret = sqlite3_bind_text(statement, 3, sender_sid, -1, SQLITE_STATIC);
  if (ret==SQLITE_OK && recipient_sid && *recipient_sid)
    ret = sqlite3_bind_text(statement, 4, recipient_sid, -1, SQLITE_STATIC);
  
  if (ret!=SQLITE_OK){
    ret = WHYF("Failed to bind parameters: %s", sqlite3_errmsg(rhizome_db));
    goto cleanup;
  }
  
  ret=0;
  size_t rows = 0;
  
  const char *names[]={
    "_id",
    "service",
    "id",
    "version",
    "date",
    ".inserttime",
    ".author",
    ".fromhere",
    "filesize",
    "filehash",
    "sender",
    "recipient",
    "name"
  };
  cli_columns(13,names);
  
  while (sqlite_step_retry(&retry, statement) == SQLITE_ROW) {
    ++rows;
    if (limit>0 && rows>limit)
      break;
    if (!(   sqlite3_column_count(statement) == 6
	  && sqlite3_column_type(statement, 0) == SQLITE_TEXT
	  && sqlite3_column_type(statement, 1) == SQLITE_BLOB
	  && sqlite3_column_type(statement, 2) == SQLITE_INTEGER
	  && sqlite3_column_type(statement, 3) == SQLITE_INTEGER
	  && (	sqlite3_column_type(statement, 4) == SQLITE_TEXT
	     || sqlite3_column_type(statement, 4) == SQLITE_NULL
	     )
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
    const char *q_author = (const char *) sqlite3_column_text(statement, 4);
    long long rowid = sqlite3_column_int64(statement, 5);
    
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
	int from_here = 0;
	unsigned char senderSid[SID_SIZE];
	unsigned char recipientSid[SID_SIZE];
	
	if (blob_sender)
	  stowSid(senderSid, 0, blob_sender);
	if (blob_recipient)
	  stowSid(recipientSid, 0, blob_recipient);
	
	if (q_author) {
	  if (config.debug.rhizome) DEBUGF("q_author=%s", alloca_str_toprint(q_author));
	  stowSid(m->author, 0, q_author);
	  int cn = 0, in = 0, kp = 0;
	  from_here = keyring_find_sid(keyring, &cn, &in, &kp, m->author);
	}
	if (!from_here && blob_sender) {
	  if (config.debug.rhizome) DEBUGF("blob_sender=%s", alloca_str_toprint(blob_sender));
	  int cn = 0, in = 0, kp = 0;
	  from_here = keyring_find_sid(keyring, &cn, &in, &kp, senderSid);
	}
	
	cli_put_long(rowid, ":");
	cli_put_string(blob_service, ":");
	cli_put_hexvalue(m->cryptoSignPublic, RHIZOME_MANIFEST_ID_BYTES, ":");
	cli_put_long(blob_version, ":");
	cli_put_long(blob_date, ":");
	cli_put_long(q_inserttime, ":");
	cli_put_hexvalue(q_author?m->author:NULL, SID_SIZE, ":");
	cli_put_long(from_here, ":");
	cli_put_long(m->fileLength, ":");
	
	unsigned char filehash[SHA512_DIGEST_LENGTH];
	if (m->fileLength)
	  fromhex(filehash, blob_filehash, SHA512_DIGEST_LENGTH);
	
	cli_put_hexvalue(m->fileLength?filehash:NULL, SHA512_DIGEST_LENGTH, ":");
	
	cli_put_hexvalue(blob_sender?senderSid:NULL, SID_SIZE, ":");
	cli_put_hexvalue(blob_recipient?recipientSid:NULL, SID_SIZE, ":");
	cli_put_string(blob_name, "\n");
      }
    }
    if (m) rhizome_manifest_free(m);
  }
  
  if (ret==0 && count_rows){
    while (sqlite_step_retry(&retry, statement) == SQLITE_ROW)
      ++rows;
  }
  cli_row_count(rows);
  
cleanup:
  sqlite3_finalize(statement);
  RETURN(ret);
  OUT();
}

/* XXX - The following assumes only one conversation. It is possible that this 
   will not be true under various pathological situations.  Dealing with this
   is left as a future exercise.
   The offset argument can be used to return multiple results as a preliminary
   mechanism for dealing with this.
*/
int rhizome_meshms_find_conversation(const char *sender_sid_hex, 
				     const char *recipient_sid_hex, 
				     char *manifest_id_hex, int offset)
{
  IN();

  int cn=0,in=0,kp=0;
  sid_t authorSid;
  if (str_to_sid_t(&authorSid, sender_sid_hex)==-1)
    RETURN(WHYF("invalid sender_sid: '%s'", sender_sid_hex));

  if(keyring_find_sid(keyring,&cn,&in,&kp,authorSid.binary))
    {
      // We are the sender, so the BID is precisely determined
      rhizome_manifest *m=rhizome_new_manifest();
      if (m) {
	sid_t rxSid;
	if (str_to_sid_t(&rxSid, recipient_sid_hex)==-1)
	  RETURN(WHYF("invalid recipient_sid: '%s'", recipient_sid_hex)); 
	if (!rhizome_obfuscated_manifest_generate_outgoing_bid
	    (m,authorSid.binary,recipient_sid_hex))
	  {
	    tohex(manifest_id_hex,m->cryptoSignPublic,
		  crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES);
	    rhizome_manifest_free(m);
	    RETURN(0);
	  }
      }
    }

  strbuf b = strbuf_alloca(1024);
  strbuf_sprintf(b, "SELECT id FROM manifests WHERE 1=1");
  
  if (sender_sid_hex && *sender_sid_hex)
    strbuf_sprintf(b, " AND sender = ?3");
  if (recipient_sid_hex && *recipient_sid_hex)
    strbuf_sprintf(b, " AND recipient = ?4");
  
  strbuf_sprintf(b, " ORDER BY inserttime DESC");
  
  if (offset)
    strbuf_sprintf(b, " OFFSET %u", offset);
  
  if (strbuf_overrun(b))
    RETURN(WHYF("SQL command too long: ", strbuf_str(b)));
  
 //Statement is the SQL query and retry is the response from the database
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  sqlite3_stmt *statement = sqlite_prepare(&retry, "%s", strbuf_str(b));
  if (!statement)
    RETURN(-1);
  
  int ret = 0;
  
  if (ret==SQLITE_OK && sender_sid_hex && *sender_sid_hex)
    ret = sqlite3_bind_text(statement, 3, sender_sid_hex, -1, SQLITE_STATIC);
  if (ret==SQLITE_OK && recipient_sid_hex && *recipient_sid_hex)
    ret = sqlite3_bind_text(statement, 4, recipient_sid_hex, -1, SQLITE_STATIC);
  
  if (ret!=SQLITE_OK){
    ret = WHYF("Failed to bind parameters: %s", sqlite3_errmsg(rhizome_db));
    goto cleanup;
  }
  
  ret=-1;
  
  if (sqlite_step_retry(&retry, statement) == SQLITE_ROW) {
    if (!(sqlite3_column_count(statement) == 1
	  && sqlite3_column_type(statement, 0) == SQLITE_TEXT
	  )) { 
      WHY("Incorrect row structure");
      ret=-1;
      goto cleanup;
    }
    const char *q_manifestid = (const char *) sqlite3_column_text(statement, 0);
    if (q_manifestid) {
      bcopy(q_manifestid,manifest_id_hex,
	    1+min(RHIZOME_MANIFEST_ID_STRLEN,strlen(q_manifestid)));
      ret=0;
      // fall through to clean up and return
    }
  }
  // fall through to clean up and return

cleanup:
  sqlite3_finalize(statement);
  RETURN(ret);
  OUT();
} 

int rhizome_meshms_find_conversations(const char *sid, int offset, int count,
				      meshms_conversation_log_row *qsolist,
				      int qsolist_size)
{
  IN();
  strbuf b = strbuf_alloca(1024);
  strbuf_sprintf(b, "SELECT DISTINCT sender,recipient,id FROM manifests WHERE 1=1");
  strbuf_sprintf(b, " AND ( sender = ?3 or recipient = ?3)");
  strbuf_sprintf(b, " ORDER BY MIN(sender,recipient), MAX(sender,recipient)");
  
  if (offset)
    strbuf_sprintf(b, " OFFSET %u", offset);
  
  if (strbuf_overrun(b))
    RETURN(WHYF("SQL command too long: ", strbuf_str(b)));
  
 //Statement is the SQL query and retry is the response from the database
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  sqlite3_stmt *statement = sqlite_prepare(&retry, "%s", strbuf_str(b));
  if (!statement)
    RETURN(-1);
  
  int ret = 0;
  
  if (ret==SQLITE_OK && sid && *sid)
    ret = sqlite3_bind_text(statement, 3, sid, -1, SQLITE_STATIC);
  
  if (ret!=SQLITE_OK){
    ret = WHYF("Failed to bind parameters: %s", sqlite3_errmsg(rhizome_db));
    goto cleanup;
  }
  
  ret=0;
  
  int row=0;
  char last_left[SID_STRLEN+1]="";
  char last_right[SID_STRLEN+1]="";
  const char *left, *right;
  while (sqlite_step_retry(&retry, statement) == SQLITE_ROW) {
    if (!(sqlite3_column_count(statement) == 3
	  && sqlite3_column_type(statement, 0) == SQLITE_TEXT
	  && sqlite3_column_type(statement, 1) == SQLITE_TEXT
	  && sqlite3_column_type(statement, 2) == SQLITE_TEXT
	  )) { 
      WHY("Incorrect row structure");
      ret=-1;
      goto cleanup;
    }
    row++;
    if (row>count) break;
    const char *recipient_sid_hex
      = (const char *) sqlite3_column_text(statement, 1);
    const char *manifest_id_hex
      = (const char *) sqlite3_column_text(statement, 2);
    
    // Read manifest and determine real sender
    rhizome_manifest *m=rhizome_new_manifest();
    if (rhizome_retrieve_manifest(manifest_id_hex,m)) {
      // Couldn't read manifest
      WARNF("Couldn't read manifest %s",manifest_id_hex);
      continue;
    }
    if (manifest_recover_obfuscated_sender(m)) {
      WARNF("Couldn't get real sender for manifest %s",manifest_id_hex);	
    }

    meshms_conversation_log_row qso;
    unsigned char manifest_id[RHIZOME_MANIFEST_ID_BYTES];
    size_t n = fromhex(manifest_id, manifest_id_hex,RHIZOME_MANIFEST_ID_BYTES);
    sid_t recipient_sid;
    if (cf_opt_sid(&recipient_sid, recipient_sid_hex))
      continue;
    if (n<RHIZOME_MANIFEST_ID_BYTES)
      continue;

    bcopy(recipient_sid.binary,qso.recipient_sid,sizeof(qso.recipient_sid));
    bcopy(manifest_id,qso.bundle_id,sizeof(qso.bundle_id));

    int i;
    for(i=0;i<qsolist_size;i++) {
      if (!bcmp(&qso.recipient_sid,&qsolist[i].recipient_sid,
		sizeof(qso.recipient_sid)))
	// Seen this conversation already
	break;
      if (!bcmp(m->realSender,&qsolist[i].recipient_sid,
		sizeof(qso.recipient_sid)))
	// Seen this conversation already
	break;
    }
    // Don't display conversations we already know about
    if (i<qsolist_size) continue;

    char real_sender_hex[SID_SIZE*2+1];
    real_sender_hex[SID_SIZE*2]=0;
    tohex(real_sender_hex,m->realSender,SID_SIZE);   
    
    if (!strcasecmp(real_sender_hex,sid)) {
      left=real_sender_hex; right=recipient_sid_hex;
    } else {
      left=recipient_sid_hex; right=real_sender_hex;
    }
    if (strcasecmp(left,last_left)||strcasecmp(right,last_right)) {
      cli_put_string(left, ":");
      cli_put_string(right, "\n");
    }
    snprintf(last_left,SID_STRLEN+1,"%s",left);
    snprintf(last_right,SID_STRLEN+1,"%s",right);
  }

cleanup:
  sqlite3_finalize(statement);
  RETURN(ret);
  OUT();
} 

void rhizome_bytes_to_hex_upper(unsigned const char *in, char *out, int byteCount)
{
  (void) tohex(out, in, byteCount);
}

int rhizome_update_file_priority(const char *fileid)
{
  /* work out the highest priority of any referrer */
  long long highestPriority = -1;
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  if (sqlite_exec_int64_retry(&retry, &highestPriority,
	"SELECT max(grouplist.priority) FROM MANIFESTS,GROUPMEMBERSHIPS,GROUPLIST"
	" where manifests.filehash='%s'"
	"   AND groupmemberships.manifestid=manifests.id"
	"   AND groupmemberships.groupid=grouplist.id;",
	fileid) == -1)
    return -1;
  if (highestPriority >= 0 && sqlite_exec_void_retry(&retry, "UPDATE files set highestPriority=%lld WHERE id='%s';", highestPriority, fileid) == -1)
    return WHYF("cannot update priority for fileid=%s", fileid);
  return 0;
}

/* Search the database for a manifest having the same name and payload content,
   and if the version is known, having the same version.

   @author Andrew Bettison <andrew@servalproject.com>
 */
int rhizome_find_duplicate(const rhizome_manifest *m, rhizome_manifest **found, int check_author)
{
  // TODO, add service, name, sender & recipient to manifests table so we can simply query them.
  
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
  strbuf b = strbuf_local(sqlcmd, sizeof sqlcmd);
  strbuf_puts(b, "SELECT id, manifest, version, author FROM manifests WHERE ");
  if (m->fileLength != 0) {
    strbuf_puts(b, "filehash = ?");
  } else
    strbuf_puts(b, "filesize = 0");
  if (strbuf_overrun(b))
    return WHYF("SQL command too long: %s", strbuf_str(b));
  int ret = 0;
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  sqlite3_stmt *statement = sqlite_prepare(&retry, "%s", strbuf_str(b));
  if (!statement)
    return -1;
  int field = 1;
  char filehash[RHIZOME_FILEHASH_STRLEN + 1];
  if (m->fileLength != 0) {
    strncpy(filehash, m->fileHexHash, sizeof filehash);
    str_toupper_inplace(filehash);
    if (config.debug.rhizome)
      DEBUGF("filehash=\"%s\"", filehash);
    sqlite3_bind_text(statement, field++, filehash, -1, SQLITE_STATIC);
  }
  size_t rows = 0;
  while (sqlite_step_retry(&retry, statement) == SQLITE_ROW) {
    ++rows;
    if (config.debug.rhizome) DEBUGF("Row %d", rows);
    if (!(   sqlite3_column_count(statement) == 4
	  && sqlite3_column_type(statement, 0) == SQLITE_TEXT
	  && sqlite3_column_type(statement, 1) == SQLITE_BLOB
	  && sqlite3_column_type(statement, 2) == SQLITE_INTEGER
	  && (	sqlite3_column_type(statement, 3) == SQLITE_TEXT
	     || sqlite3_column_type(statement, 3) == SQLITE_NULL
	     )
    )) {
      ret = WHY("Incorrect statement columns");
      break;
    }
    const char *q_manifestid = (const char *) sqlite3_column_text(statement, 0);
    size_t manifestidsize = sqlite3_column_bytes(statement, 0); // must call after sqlite3_column_text()
    unsigned char manifest_id[RHIZOME_MANIFEST_ID_BYTES];
    if (  manifestidsize != crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES * 2
      ||  fromhexstr(manifest_id, q_manifestid, RHIZOME_MANIFEST_ID_BYTES) == -1
    ) {
      ret = WHYF("Malformed manifest.id from query: %s", q_manifestid);
      break;
    }
    const char *manifestblob = (char *) sqlite3_column_blob(statement, 1);
    size_t manifestblobsize = sqlite3_column_bytes(statement, 1); // must call after sqlite3_column_blob()
    long long q_version = sqlite3_column_int64(statement, 2);
    const char *q_author = (const char *) sqlite3_column_text(statement, 3);
    
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
      if (config.debug.rhizome)
	DEBUGF("Consider manifest.service=%s manifest.id=%s manifest.version=%lld", blob_service, q_manifestid, blob_version);
      if (q_author) {
	if (config.debug.rhizome)
	  strbuf_sprintf(b, " .author=%s", q_author);
	stowSid(blob_m->author, 0, q_author);
      }
      
      /* Perform consistency checks, because we're paranoid. */
      int inconsistent = 0;
      if (blob_id && strcasecmp(blob_id, q_manifestid)) {
	WARNF("MANIFESTS row id=%s has inconsistent blob with id=%s -- skipped", q_manifestid, blob_id);
	++inconsistent;
      }
      if (blob_version != q_version) {
	WARNF("MANIFESTS row id=%s has inconsistent blob: manifests.version=%lld, blob.version=%lld -- skipped",
	      q_manifestid, q_version, blob_version);
	++inconsistent;
      }
      if (blob_filesize != -1 && blob_filesize != m->fileLength) {
	WARNF("MANIFESTS row id=%s has inconsistent blob: known file size %lld, blob.filesize=%lld -- skipped",
	      q_manifestid, m->fileLength, blob_filesize);
	++inconsistent;
      }
      if (m->fileLength != 0) {
	if (!blob_filehash && strcasecmp(blob_filehash, m->fileHexHash)) {
	  WARNF("MANIFESTS row id=%s has inconsistent blob: manifests.filehash=%s, blob.filehash=%s -- skipped",
		q_manifestid, m->fileHexHash, blob_filehash);
	  ++inconsistent;
	}
      } else {
	if (blob_filehash) {
	  WARNF("MANIFESTS row id=%s has inconsistent blob: blob.filehash should be absent -- skipped",
		q_manifestid);
	  ++inconsistent;
	}
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
	    if (config.debug.rhizome)
	      strbuf_sprintf(b, " name=\"%s\"", blob_name);
	  }else
	    ++inconsistent;
	} else if (strcasecmp(service, RHIZOME_SERVICE_MESHMS) == 0) {
	  const char *blob_sender = rhizome_manifest_get(blob_m, "sender", NULL, 0);
	  const char *blob_recipient = rhizome_manifest_get(blob_m, "recipient", NULL, 0);
	  if (blob_sender && !strcasecmp(blob_sender, sender) && blob_recipient && !strcasecmp(blob_recipient, recipient)) {
	    if (config.debug.rhizome)
	      strbuf_sprintf(b, " sender=%s recipient=%s", blob_sender, blob_recipient);
	  }else
	    ++inconsistent;
	}
      }
      
      if ((!inconsistent) && check_author) {
	// check that we can re-author this manifest 
	if (rhizome_extract_privatekey(blob_m, NULL))
	  ++inconsistent;
      }
      
      if (!inconsistent) {
	*found = blob_m;
	if (config.debug.rhizome)
	  DEBUGF("Found duplicate payload: service=%s%s version=%llu hexhash=%s",
		blob_service, strbuf_str(b), blob_m->version, blob_m->fileHexHash, q_author ? q_author : ""
	      );
	ret = 1;
	break;
      }
    }
    if (blob_m)
      rhizome_manifest_free(blob_m);
  }
  sqlite3_finalize(statement);
  return ret;
}

/* Retrieve a manifest from the database, given its manifest ID.
 *
 * Returns 0 if manifest is found
 * Returns 1 if manifest is not found
 * Returns -1 on error
 * Caller is responsible for allocating and freeing rhizome_manifest
 */
int rhizome_retrieve_manifest(const char *manifestid, rhizome_manifest *m)
{
  int ret=0;
  
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  
  sqlite3_stmt *statement = sqlite_prepare(&retry, "SELECT manifest, version, inserttime, author FROM manifests WHERE id like ?");
  if (!statement)
    return -1;

  sqlite3_bind_text(statement, 1, manifestid, -1, SQLITE_STATIC);
  if (sqlite_step_retry(&retry, statement) == SQLITE_ROW){
    const char *manifestblob = (char *) sqlite3_column_blob(statement, 0);
    long long q_version = (long long) sqlite3_column_int64(statement, 1);
    long long q_inserttime = (long long) sqlite3_column_int64(statement, 2);
    const char *q_author = (const char *) sqlite3_column_text(statement, 3);
    size_t manifestblobsize = sqlite3_column_bytes(statement, 0); // must call after sqlite3_column_blob()
    
    if (rhizome_read_manifest_file(m, manifestblob, manifestblobsize)){
      ret=WHYF("Manifest %s exists but is invalid", manifestid);
      goto done;
    }
    
    if (q_author){
      if (stowSid(m->author, 0, q_author) == -1)
	WARNF("Manifest %s contains invalid author=%s -- ignored", manifestid, alloca_str_toprint(q_author));
    }
    
    if (m->version!=q_version)
      WARNF("Version mismatch, manifest is %lld, database is %lld", m->version, q_version);
    
    m->inserttime = q_inserttime;
  }else{
    INFOF("Manifest %s was not found", manifestid);
    ret=1;
  }
  
done:
  sqlite3_finalize(statement);
  return ret;  
}

int rhizome_delete_manifest_retry(sqlite_retry_state *retry, const char *manifestid)
{
  sqlite3_stmt *statement = sqlite_prepare(retry, "DELETE FROM manifests WHERE id = ?");
  if (!statement)
    return -1;
  sqlite3_bind_text(statement, 1, manifestid, -1, SQLITE_STATIC);
  if (_sqlite_exec_prepared(__WHENCE__, LOG_LEVEL_ERROR, retry, statement) == -1)
    return -1;
  return sqlite3_changes(rhizome_db) ? 0 : 1;
}

static int rhizome_delete_file_retry(sqlite_retry_state *retry, const char *fileid)
{
  int ret = 0;
  sqlite3_stmt *statement = sqlite_prepare(retry, "DELETE FROM files WHERE id = ?");
  if (!statement)
    ret = -1;
  else {
    sqlite3_bind_text(statement, 1, fileid, -1, SQLITE_STATIC);
    if (_sqlite_exec_prepared(__WHENCE__, LOG_LEVEL_ERROR, retry, statement) == -1)
      ret = -1;
  }
  statement = sqlite_prepare(retry, "DELETE FROM fileblobs WHERE id = ?");
  if (!statement)
    ret = -1;
  else {
    sqlite3_bind_text(statement, 1, fileid, -1, SQLITE_STATIC);
    if (_sqlite_exec_prepared(__WHENCE__, LOG_LEVEL_ERROR, retry, statement) == -1)
      ret = -1;
  }
  return ret == -1 ? -1 : sqlite3_changes(rhizome_db) ? 0 : 1;
}

int rhizome_delete_payload_retry(sqlite_retry_state *retry, const char *manifestid)
{
  strbuf fh = strbuf_alloca(RHIZOME_FILEHASH_STRLEN + 1);
  int rows = sqlite_exec_strbuf_retry(retry, fh, "SELECT filehash FROM manifests WHERE id = '%s'", manifestid);
  if (rows == -1)
    return -1;
  if (rows && rhizome_delete_file_retry(retry, strbuf_str(fh)) == -1)
    return -1;
  return 0;
}
/* Remove a manifest and its bundle from the database, given its manifest ID.
 *
 * Returns 0 if manifest is found and removed and bundle was either absent or removed
 * Returns 1 if manifest is not found
 * Returns -1 on error
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int rhizome_delete_bundle(const char *manifestid)
{
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  if (rhizome_delete_payload_retry(&retry, manifestid) == -1)
    return -1;
  if (rhizome_delete_manifest_retry(&retry, manifestid) == -1)
    return -1;
  return 0;
}

/* Remove a manifest from the database, given its manifest ID, leaving its bundle (fileblob)
 * untouched if present.
 *
 * Returns 0 if manifest is found and removed
 * Returns 1 if manifest is not found
 * Returns -1 on error
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int rhizome_delete_manifest(const char *manifestid)
{
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  return rhizome_delete_manifest_retry(&retry, manifestid);
}

/* Remove a bundle's payload (file) from the database, given its manifest ID, leaving its manifest
 * untouched if present.
 *
 * Returns 0 if manifest is found, its payload is found and removed
 * Returns 1 if manifest or payload is not found
 * Returns -1 on error
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int rhizome_delete_payload(const char *manifestid)
{
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  return rhizome_delete_payload_retry(&retry, manifestid);
}

/* Remove a file from the database, given its file hash.
 *
 * Returns 0 if file is found and removed
 * Returns 1 if file is not found
 * Returns -1 on error
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int rhizome_delete_file(const char *fileid)
{
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  return rhizome_delete_file_retry(&retry, fileid);
}

time_ms_t lookup_time=0;
time_ms_t last_bar_lookup=0;
int rhizome_is_bar_interesting(unsigned char *bar){
  IN();

  if (last_bar_lookup>(gettime_ms()-1000)) {
    /* Looking up rhizome bundles by BAR can be slow.
       If so, then ignore some percentage of BARs. */
    if (lookup_time>10) {
      // if >10ms then only check 1 in 8 BARs
      if (random()&0x7) RETURN(0);    
    }
    if (lookup_time>100) {
      // if >10ms then only check 1 in 32 (1 in 8 of 1 in 4) BARs
      if (random()&0x3) RETURN(0);   
    }
  }

  time_ms_t start_time=gettime_ms();

  int64_t version = rhizome_bar_version(bar);
  unsigned char log2_size = bar[RHIZOME_BAR_FILESIZE_OFFSET];
  int ret=1;
  char id_hex[RHIZOME_MANIFEST_ID_STRLEN];
  tohex(id_hex, &bar[RHIZOME_BAR_PREFIX_OFFSET], RHIZOME_BAR_PREFIX_BYTES);
  strcat(id_hex, "%");
  
  // are we ignoring this manifest?
  if (rhizome_ignore_manifest_check(&bar[RHIZOME_BAR_PREFIX_OFFSET], RHIZOME_BAR_PREFIX_BYTES)){
    DEBUGF("Ignoring %s", id_hex);
    RETURN(0);
  }

  // do we have free space in a fetch queue?
  if (log2_size!=0xFF && rhizome_fetch_has_queue_space(log2_size)!=1)
    RETURN(0);

  // are we already fetching this bundle [or later]?
  rhizome_manifest *m=rhizome_fetch_search(&bar[RHIZOME_BAR_PREFIX_OFFSET], RHIZOME_BAR_PREFIX_BYTES);
  if (m && m->version >= version)
    RETURN(0);
  
  // do we have this bundle [or later]?
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  sqlite3_stmt *statement = sqlite_prepare(&retry, 
    "SELECT id, version FROM manifests WHERE id like ? and version >= ?");
  
  sqlite3_bind_text(statement, 1, id_hex, -1, SQLITE_STATIC);
  sqlite3_bind_int64(statement, 2, version);
  
  if (sqlite_step_retry(&retry, statement) == SQLITE_ROW){
    if (0){
      const char *q_id = (const char *) sqlite3_column_text(statement, 0);
      long long q_version = (long long) sqlite3_column_int64(statement, 1);
      DEBUGF("Already have %s, %lld (vs %s, %lld)", q_id, q_version, id_hex, version);
    }
    ret=0;
  }  
  sqlite3_finalize(statement);

  time_ms_t end_time=gettime_ms();
  lookup_time=end_time-start_time;
  last_bar_lookup=end_time;
  if (lookup_time>50) WARNF("Looking up a BAR took %lldms",lookup_time);

  RETURN(ret);
  OUT();
}
