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
#include "rhizome.h"
#include "strbuf.h"
#include "str.h"

long long rhizome_space=0;
static const char *rhizome_thisdatastore_path = NULL;

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

debugflags_t sqlite_trace_debug = DEBUG_RHIZOME;
const struct __sourceloc *sqlite_trace_whence = NULL;

static void sqlite_trace_callback(void *context, const char *rendered_sql)
{
  if (debug & sqlite_trace_debug)
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
debugflags_t sqlite_set_debugmask(debugflags_t newmask)
{
  debugflags_t oldmask = sqlite_trace_debug;
  sqlite_trace_debug = newmask;
  return oldmask;
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
  if (!FORM_RHIZOME_DATASTORE_PATH(dbpath, "rhizome.db")){
    RETURN(WHY("Invalid path"));
  }

  if (sqlite3_open(dbpath,&rhizome_db)){
    RETURN(WHYF("SQLite could not open database %s: %s", dbpath, sqlite3_errmsg(rhizome_db)));
  }
  sqlite3_trace(rhizome_db, sqlite_trace_callback, NULL);
  int loglevel = (debug & DEBUG_RHIZOME) ? LOG_LEVEL_DEBUG : LOG_LEVEL_SILENT;

  /* Read Rhizome configuration */
  double rhizome_kb = atof(confValueGet("rhizome_kb", "1024"));
  rhizome_space = 1024LL * rhizome_kb;
  if (debug&DEBUG_RHIZOME) {
    DEBUGF("serval.conf:rhizome_kb=%.f", rhizome_kb);
    DEBUGF("Rhizome will use %lldB of storage for its database.", rhizome_space);
  }
  /* Create tables as required */
  sqlite_exec_void_loglevel(loglevel, "PRAGMA auto_vacuum=2;");
  if (	sqlite_exec_void("CREATE TABLE IF NOT EXISTS GROUPLIST(id text not null primary key, closed integer,ciphered integer,priority integer);") == -1
    ||	sqlite_exec_void("CREATE TABLE IF NOT EXISTS MANIFESTS(id text not null primary key, manifest blob, version integer,inserttime integer, bar blob, filesize integer, filehash text, author text);") == -1
    ||	sqlite_exec_void("CREATE TABLE IF NOT EXISTS FILES(id text not null primary key, data blob, length integer, highestpriority integer, datavalid integer, inserttime integer);") == -1
    ||	sqlite_exec_void("DROP TABLE IF EXISTS FILEMANIFESTS;") == -1
    ||	sqlite_exec_void("CREATE TABLE IF NOT EXISTS GROUPMEMBERSHIPS(manifestid text not null, groupid text not null);") == -1
    ||	sqlite_exec_void("CREATE TABLE IF NOT EXISTS VERIFICATIONS(sid text not null, did text, name text, starttime integer, endtime integer, signature blob);") == -1
  ) {
    RETURN(WHY("Failed to create schema"));
  }

  /* Create indexes if they don't already exist */
  sqlite_exec_void_loglevel(LOG_LEVEL_WARN, "CREATE INDEX IF NOT EXISTS bundlesizeindex ON manifests (filesize);");
  sqlite_exec_void_loglevel(LOG_LEVEL_WARN, "CREATE INDEX IF NOT EXISTS IDX_MANIFESTS_HASH ON MANIFESTS(filehash);");

  /* Clean out half-finished entries from the database */
  sqlite_exec_void_loglevel(LOG_LEVEL_WARN, "DELETE FROM MANIFESTS WHERE filehash IS NULL;");
  sqlite_exec_void_loglevel(LOG_LEVEL_WARN, "DELETE FROM FILES WHERE NOT EXISTS( SELECT  1 FROM MANIFESTS WHERE MANIFESTS.filehash = FILES.id);");
  sqlite_exec_void_loglevel(LOG_LEVEL_WARN, "DELETE FROM MANIFESTS WHERE filehash != '' AND NOT EXISTS( SELECT  1 FROM FILES WHERE MANIFESTS.filehash = FILES.id);");
  RETURN(0);
}

int rhizome_close_db()
{
  if (rhizome_db) {
    sqlite3_stmt *stmt = NULL;
    while ((stmt = sqlite3_next_stmt(rhizome_db, stmt))) {
      const char *sql = sqlite3_sql(stmt);
      WARNF("closing Rhizome db with unfinalised statement: %s", sql ? sql : "BLOB");
    }
    int r = sqlite3_close(rhizome_db);
    if (r != SQLITE_OK)
      return WHYF("Failed to close sqlite database, %s",sqlite3_errmsg(rhizome_db));
  }
  rhizome_db=NULL;
  return 0;
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
      .limit = serverMode ? (serverLimit < 0 ? 50 : serverLimit) : (otherLimit < 0 ? 1500 : otherLimit),
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
  else
    retry->elapsed += now - retry->start;
  INFOF("%s on try %u after %.3f seconds (%.3f elapsed): %s",
      sqlite3_errmsg(rhizome_db),
      retry->busytries,
      (now - retry->start) / 1e3,
      retry->elapsed / 1e3,
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
    INFOF("succeeded on try %u after %.3f seconds (%.3f elapsed): %s",
	retry->busytries + 1,
	(now - retry->start) / 1e3,
	retry->elapsed / 1e3,
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
  if (strbuf_overrun(stmt))
    return WHYFNULL("SQL overrun: %s", strbuf_str(stmt));
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
	LOGF(log_level, "query failed, %s: %s", sqlite3_errmsg(rhizome_db), sqlite3_sql(statement));
	ret = -1;
	statement = NULL;
	break;
    }
  }
  sqlite_trace_whence = NULL;
  return ret;
}

/*
   Convenience wrapper for executing a prepared SQL statement that returns no value.  If an error
   occurs then logs it at the given level and returns -1.  If 'retry' is non-NULL and the BUSY error
   occurs (indicating the database is locked, ie, currently in use by another process), then resets
   the statement and retries while sqlite_retry() returns true.  If sqlite_retry() returns false
   then returns -1.  Otherwise returns zero.  Always finalises the statement before returning.
 */
static int _sqlite_exec_void_prepared(struct __sourceloc __whence, int log_level, sqlite_retry_state *retry, sqlite3_stmt *statement)
{
  if (!statement)
    return -1;
  int rowcount = 0;
  int stepcode;
  while ((stepcode = _sqlite_step_retry(__whence, log_level, retry, statement)) == SQLITE_ROW)
    ++rowcount;
  if (rowcount)
    WARNF("void query unexpectedly returned %d row%s", rowcount, rowcount == 1 ? "" : "s");
  sqlite3_finalize(statement);
  return sqlite_code_ok(stepcode) ? 0 : -1;
}

static int _sqlite_vexec_void(struct __sourceloc __whence, int log_level, sqlite_retry_state *retry, const char *sqlformat, va_list ap)
{
  strbuf stmt = strbuf_alloca(8192);
  strbuf_vsprintf(stmt, sqlformat, ap);
  return _sqlite_exec_void_prepared(__whence, log_level, retry, _sqlite_prepare_loglevel(__whence, log_level, retry, stmt));
}

/* Convenience wrapper for executing an SQL command that returns no value.
   If an error occurs then logs it at ERROR level and returns -1.  Otherwise returns zero.
   @author Andrew Bettison <andrew@servalproject.com>
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
   @author Andrew Bettison <andrew@servalproject.com>
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
   currently locked for updates, then will call sqlite_retry() on the supplied retry state variable
   instead of its own, internal one.  If 'retry' is passed as NULL, then will not sleep and retry at
   all in the event of a busy condition, but will log it as an error and return immediately.
   @author Andrew Bettison <andrew@servalproject.com>
 */
int _sqlite_exec_void_retry(struct __sourceloc __whence, sqlite_retry_state *retry, const char *sqlformat, ...)
{
  va_list ap;
  va_start(ap, sqlformat);
  int ret = _sqlite_vexec_void(__whence, LOG_LEVEL_ERROR, retry, sqlformat, ap);
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
  return sqlite_code_ok(stepcode) && ret != -1 ? rowcount : -1;
}

/*
   Convenience wrapper for executing an SQL command that returns a single int64 value.
   Logs an error and returns -1 if an error occurs.
   If no row is found, then returns 0 and does not alter *result.
   If exactly one row is found, the assigns its value to *result and returns 1.
   If more than one row is found, then logs a warning, assigns the value of the first row to *result
   and returns the number of rows.
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
   currently locked for updates, then will call sqlite_retry() on the supplied retry state variable
   instead of its own, internal one.  If 'retry' is passed as NULL, then will not sleep and retry at
   all in the event of a busy condition, but will log it as an error and return immediately.
   @author Andrew Bettison <andrew@servalproject.com>
 */
int _sqlite_exec_int64_retry(struct __sourceloc __whence, sqlite_retry_state *retry, long long *result, const char *sqlformat,...)
{
  va_list ap;
  va_start(ap, sqlformat);
  int ret = _sqlite_vexec_int64(__whence, retry, result, sqlformat, ap);
  va_end(ap);
  return ret;
}

/*
   Convenience wrapper for executing an SQL command that returns a single text value.
   Logs an error and returns -1 if an error occurs, otherwise the number of rows that were found:
    0 means no rows, nothing is appended to the strbuf
    1 means exactly one row, appends its column to the strbuf
    2 more than one row, logs a warning and appends the first row's column to the strbuf
   @author Andrew Bettison <andrew@servalproject.com>
 */
int _sqlite_exec_strbuf(struct __sourceloc __whence, strbuf sb, const char *sqlformat,...)
{
  strbuf stmt = strbuf_alloca(8192);
  strbuf_va_printf(stmt, sqlformat);
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  sqlite3_stmt *statement = _sqlite_prepare_loglevel(__whence, LOG_LEVEL_ERROR, &retry, stmt);
  if (!statement)
    return -1;
  int ret = 0;
  int rowcount = 0;
  int stepcode;
  while ((stepcode = _sqlite_step_retry(__whence, LOG_LEVEL_ERROR, &retry, statement)) == SQLITE_ROW) {
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

int rhizome_make_space(int group_priority, long long bytes)
{
  /* Asked for impossibly large amount */
  if (bytes>=(rhizome_space-65536))
    return WHYF("bytes=%lld is too large", bytes);

  long long db_used = rhizome_database_used_bytes();
  if (db_used == -1)
    return -1;
  
  /* If there is already enough space now, then do nothing more */
  if (db_used<=(rhizome_space-bytes-65536))
    return 0;

  /* Okay, not enough space, so free up some. */
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  sqlite3_stmt *statement = sqlite_prepare(&retry, "select id,length from files where highestpriority < %d order by descending length", group_priority);
  if (!statement)
    return -1;
  while (bytes > (rhizome_space - 65536 - rhizome_database_used_bytes())
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
      if (debug & DEBUG_RHIZOME)
	DEBUGF("removing stale manifests, groupmemberships");
      sqlite_exec_void_retry(&retry, "delete from manifests where id='%s';", manifestId);
      sqlite_exec_void_retry(&retry, "delete from keypairs where public='%s';", manifestId);
      sqlite_exec_void_retry(&retry, "delete from groupmemberships where manifestid='%s';", manifestId);
    }
  }
  sqlite3_finalize(statement);
  if (can_drop)
    sqlite_exec_void_retry(&retry, "delete from files where id='%s';",id);
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
  // TODO encrypted payloads - pass encryption key here. Filehash should be of
  // encrypted data.
  // We should add the file in the same transaction, but closing the blob seems
  // to cause some issues.
  char filehash[RHIZOME_FILEHASH_STRLEN + 1];
  if (m->fileLength > 0) {
    if (!m->fileHashedP)
      return WHY("Manifest payload hash unknown");
    strncpy(filehash, m->fileHexHash, sizeof filehash);
    str_toupper_inplace(filehash);

    /* rhizome_store_file() checks if it is already in the database, so we just
       call it normally. */
    if (rhizome_store_file(m, NULL))
      return WHY("Could not store file");
  } else {
    filehash[0] = '\0';
  }

  const char *author = is_sid_any(m->author) ? NULL : alloca_tohex_sid(m->author);

  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  if (sqlite_exec_void_retry(&retry, "BEGIN TRANSACTION;") == -1)
    return -1;

  sqlite3_stmt *stmt;
  if ((stmt = sqlite_prepare(&retry, "INSERT OR REPLACE INTO MANIFESTS(id,manifest,version,inserttime,bar,filesize,filehash,author) VALUES(?,?,?,?,?,?,?,?);")) == NULL)
    goto rollback;
  if (!(   sqlite_code_ok(sqlite3_bind_text(stmt, 1, manifestid, -1, SQLITE_TRANSIENT))
        && sqlite_code_ok(sqlite3_bind_blob(stmt, 2, m->manifestdata, m->manifest_bytes, SQLITE_TRANSIENT))
	&& sqlite_code_ok(sqlite3_bind_int64(stmt, 3, m->version))
	&& sqlite_code_ok(sqlite3_bind_int64(stmt, 4, (long long) gettime_ms()))
	&& sqlite_code_ok(sqlite3_bind_blob(stmt, 5, bar, RHIZOME_BAR_BYTES, SQLITE_TRANSIENT))
	&& sqlite_code_ok(sqlite3_bind_int64(stmt, 6, m->fileLength))
	&& sqlite_code_ok(sqlite3_bind_text(stmt, 7, filehash, -1, SQLITE_TRANSIENT))
	&& sqlite_code_ok(sqlite3_bind_text(stmt, 8, author, -1, SQLITE_TRANSIENT))
  )) {
    WHYF("query failed, %s: %s", sqlite3_errmsg(rhizome_db), sqlite3_sql(stmt));
    goto rollback;
  }
  if (sqlite_step_retry(&retry, stmt) == -1)
    goto rollback;
  sqlite3_finalize(stmt);
  stmt = NULL;

  // we might need to leave the old file around for a bit
  // clean out unreferenced files first
  if ((stmt = sqlite_prepare(&retry, "DELETE FROM FILES WHERE inserttime < ? AND NOT EXISTS( SELECT  1 FROM MANIFESTS WHERE MANIFESTS.filehash = FILES.id);")) == NULL)
    goto rollback;
  if (!sqlite_code_ok(sqlite3_bind_int64(stmt, 1, (long long)(gettime_ms() - 60000)))) {
    WHYF("query failed, %s: %s", sqlite3_errmsg(rhizome_db), sqlite3_sql(stmt));
    goto rollback;
  }
  if (sqlite_step_retry(&retry, stmt) == -1)
    goto rollback;
  sqlite3_finalize(stmt);
  stmt = NULL;

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
  if (sqlite_exec_void_retry(&retry, "COMMIT;") != -1)
    return 0;
rollback:
  if (stmt)
    sqlite3_finalize(stmt);
  WHYF("Failed to store bundle bid=%s", manifestid);
  sqlite_exec_void_retry(&retry, "ROLLBACK;");
  return -1;
}

int rhizome_list_manifests(const char *service, const char *sender_sid, const char *recipient_sid, int limit, int offset)
{
  IN();
  strbuf b = strbuf_alloca(1024);
  strbuf_sprintf(b, "SELECT id, manifest, version, inserttime, author FROM manifests ORDER BY inserttime DESC");
  if (limit)
    strbuf_sprintf(b, " LIMIT %u", limit);
  if (offset)
    strbuf_sprintf(b, " OFFSET %u", offset);
  if (strbuf_overrun(b))
    RETURN(WHYF("SQL command too long: ", strbuf_str(b)));
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  sqlite3_stmt *statement = sqlite_prepare(&retry, "%s", strbuf_str(b));
  if (!statement)
    return -1;
  int ret = 0;
  size_t rows = 0;
  cli_puts("12"); cli_delim("\n"); // number of columns
  cli_puts("service"); cli_delim(":");
  cli_puts("id"); cli_delim(":");
  cli_puts("version"); cli_delim(":");
  cli_puts("date"); cli_delim(":");
  cli_puts(".inserttime"); cli_delim(":");
  cli_puts(".author"); cli_delim(":");
  cli_puts(".fromhere"); cli_delim(":");
  cli_puts("filesize"); cli_delim(":");
  cli_puts("filehash"); cli_delim(":");
  cli_puts("sender"); cli_delim(":");
  cli_puts("recipient"); cli_delim(":");
  cli_puts("name"); cli_delim("\n"); // should be last, because name may contain ':'
  while (sqlite_step_retry(&retry, statement) == SQLITE_ROW) {
    ++rows;
    if (!(   sqlite3_column_count(statement) == 5
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
	int from_here = 0;
	if (q_author) {
	  if (debug & DEBUG_RHIZOME) DEBUGF("q_author=%s", alloca_str_toprint(q_author));
	  unsigned char authorSid[SID_SIZE];
	  stowSid(authorSid, 0, q_author);
	  int cn = 0, in = 0, kp = 0;
	  from_here = keyring_find_sid(keyring, &cn, &in, &kp, authorSid);
	}
	if (!from_here && blob_sender) {
	  if (debug & DEBUG_RHIZOME) DEBUGF("blob_sender=%s", alloca_str_toprint(blob_sender));
	  unsigned char senderSid[SID_SIZE];
	  stowSid(senderSid, 0, blob_sender);
	  int cn = 0, in = 0, kp = 0;
	  from_here = keyring_find_sid(keyring, &cn, &in, &kp, senderSid);
	}
	if (debug & DEBUG_RHIZOME) DEBUGF("manifest payload size = %lld", blob_filesize);
	cli_puts(blob_service ? blob_service : ""); cli_delim(":");
	cli_puts(q_manifestid); cli_delim(":");
	cli_printf("%lld", blob_version); cli_delim(":");
	cli_printf("%lld", blob_date); cli_delim(":");
	cli_printf("%lld", q_inserttime); cli_delim(":");
	cli_puts(q_author ? q_author : ""); cli_delim(":");
	cli_printf("%d", from_here); cli_delim(":");
	cli_printf("%lld", blob_filesize); cli_delim(":");
	cli_puts(blob_filehash ? blob_filehash : ""); cli_delim(":");
	cli_puts(blob_sender ? blob_sender : ""); cli_delim(":");
	cli_puts(blob_recipient ? blob_recipient : ""); cli_delim(":");
	cli_puts(blob_name ? blob_name : ""); cli_delim("\n");
      }
    }
    if (m) rhizome_manifest_free(m);
  }
  sqlite3_finalize(statement);
  RETURN(ret);
}

/* The following function just stores the file (or silently returns if it already exists).
   The relationships of manifests to this file are the responsibility of the caller. */
int rhizome_store_file(rhizome_manifest *m,const unsigned char *key)
{
  const char *file=m->dataFileName;
  const char *hash=m->fileHexHash;
  int priority=m->fileHighestPriority;
  if (m->payloadEncryption) 
    return WHY("Writing encrypted payloads not implemented");

  if (!m->fileHashedP)
    return WHY("Cannot store bundle file until it has been hashed");

  int fd = -1;

  /* See if the file is already stored, and if so, don't bother storing it again.
     Do this check BEFORE trying to open the associated file, because if the caller
     has received a manifest and checked that it exists in the database, it may 
     (sensibly) elect not supply the file. Rhizome Direct does this. */
  long long count = 0;
  if (sqlite_exec_int64(&count, "SELECT COUNT(*) FROM FILES WHERE id='%s' AND datavalid<>0;", hash) < 1) {
    WHY("Failed to count stored files");
    goto error;
  }
  if (count >= 1) {
    /* File is already stored, so just update the highestPriority field if required. */
    long long storedPriority = -1;
    if (sqlite_exec_int64(&storedPriority, "SELECT highestPriority FROM FILES WHERE id='%s' AND datavalid!=0", hash) == -1) {
      WHY("Failed to select highest priority");
      goto error;
    }
    if (storedPriority<priority) {
      if (sqlite_exec_void("UPDATE FILES SET highestPriority=%d WHERE id='%s';", priority, hash) == -1) {
	WHY("SQLite failed to update highestPriority field for stored file.");
	goto error;
      }
    }
    return 0;
  }

  fd = open(file, O_RDONLY);
  if (fd == -1) {
    WHYF_perror("open(%s)", alloca_str_toprint(file));
    WHY("Could not open associated file");
    goto error;
  }
  
  struct stat stat;
  if (fstat(fd, &stat)) {
    WHYF_perror("fstat(%d)", fd);
    WHY("Could not stat() associated file");
    goto error;
  }
  if (stat.st_size < m->fileLength) {
    WHYF("File has shrunk by %lld bytes from %lld to %lld, not stored",
	(long long)(m->fileLength - stat.st_size), (long long) m->fileLength, (long long) stat.st_size
      );
    goto error;
  } else if (stat.st_size > m->fileLength) {
    // If the file has grown, store the original , in the hope that it will match the hash.
    WARNF("File has grown by +%lld bytes to %lld, only storing %lld",
	(long long)(stat.st_size - m->fileLength), (long long) stat.st_size, (long long) m->fileLength
      );
  }

  unsigned char *addr = mmap(NULL, m->fileLength, PROT_READ, MAP_SHARED, fd, 0);
  if (addr==MAP_FAILED) {
    WHYF_perror("mmap(NULL, %lld, PROT_READ, MAP_SHARED, %d, 0)", (long long) m->fileLength, fd);
    WHY("mmap() of associated file failed.");
    goto error;
  }

  /* Okay, so there are no records that match, but we should delete any half-baked record (with datavalid=0) so that the insert below doesn't fail.
   Don't worry about the return result, since it might not delete any records. */
  sqlite_exec_void("DELETE FROM FILES WHERE datavalid=0;");

  /* INSERT INTO FILES(id as text, data blob, length integer, highestpriority integer).
   BUT, we have to do this incrementally so that we can handle blobs larger than available memory.
  This is possible using:
     int sqlite3_bind_zeroblob(sqlite3_stmt*, int, int n);
  That binds an all zeroes blob to a field.  We can then populate the data by
  opening a handle to the blob using:
     int sqlite3_blob_write(sqlite3_blob *, const void *z, int n, int iOffset);
  */

  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  sqlite3_stmt *statement = sqlite_prepare(&retry, "INSERT OR REPLACE INTO FILES(id,data,length,highestpriority,datavalid,inserttime) VALUES('%s',?,%lld,%d,0,%lld);",
	  hash, (long long)m->fileLength, priority, (long long)gettime_ms()
	);
  if (!statement)
    goto insert_row_fail;
  /* Bind appropriate sized zero-filled blob to data field */
  if (sqlite3_bind_zeroblob(statement, 1, m->fileLength) != SQLITE_OK) {
    WHYF("sqlite3_bind_zeroblob() failed: %s: %s", sqlite3_errmsg(rhizome_db), sqlite3_sql(statement));
    sqlite3_finalize(statement);
    goto insert_row_fail;
  }
  /* Do actual insert, and abort if it fails */
  if (_sqlite_exec_void_prepared(__WHENCE__, LOG_LEVEL_ERROR, &retry, statement) == -1) {
insert_row_fail:
    WHYF("Failed to insert row for fileid=%s", hash);
    goto error;
  }

  /* Get rowid for inserted row, so that we can modify the blob */
  int64_t rowid = sqlite3_last_insert_rowid(rhizome_db);
  if (rowid<1) {
    WHYF("query failed, %s: %s", sqlite3_errmsg(rhizome_db), sqlite3_sql(statement));
    WHYF("Failed to get row ID of newly inserted row for fileid=%s", hash);
    goto error;
  }
  // We write the blob inside a transaction so that we can't get SQLITE_BUSY from
  // sqlite3_blob_close(), which cannot be retried.  Using an explicit transaction, defers BUSY
  // detection to the COMMIT, which can be retried.
  if (sqlite_exec_void_retry(&retry, "BEGIN TRANSACTION;") == -1)
    goto error;
  sqlite3_blob *blob;
  int ret;
  do ret = sqlite3_blob_open(rhizome_db, "main", "FILES", "data", rowid, 1 /* read/write */, &blob);
  while (sqlite_code_busy(ret) && sqlite_retry(&retry, "sqlite3_blob_open"));
  if (ret != SQLITE_OK) {
    WHYF("sqlite3_blob_open() failed, %s", sqlite3_errmsg(rhizome_db));
    goto rollback_blob;
  }
  sqlite_retry_done(&retry, "sqlite3_blob_open");

  /* Calculate hash of file as we go, so that we can report if
     the contents have changed during import.  This is also why we
     use the m->fileLength instead of size returned by stat, in case
     the file has been appended, e.g., if a journal is being appended to
     by a separate process.  This has already been shown to happen with
     Serval Maps, and it is also quite possible with MeshMS and other
     services. */
  char hash_out[crypto_hash_sha512_BYTES*2+1];
  {
    unsigned char nonce[crypto_stream_xsalsa20_NONCEBYTES];
    unsigned char buffer[RHIZOME_CRYPT_PAGE_SIZE];
    bzero(nonce, sizeof nonce);
    SHA512_CTX context;
    SHA512_Init(&context);
    long long i;
    for (i = 0; i < m->fileLength; i += RHIZOME_CRYPT_PAGE_SIZE) {
      int n = RHIZOME_CRYPT_PAGE_SIZE;
      if (i + n > m->fileLength)
	n = m->fileLength - i;
      const unsigned char *writeable = &addr[i];
      SHA512_Update(&context, writeable, n);
      if (key) {
	/* calculate block nonce */
	int j;
	for (j=0;j<8;j++)
	  nonce[i]=(i>>(j*8))&0xff;
	crypto_stream_xsalsa20_xor(buffer, writeable, n, nonce, key);
	writeable = buffer;
      }
      do ret = sqlite3_blob_write(blob, writeable, n, i);
	while (sqlite_code_busy(ret) && sqlite_retry(&retry, "sqlite3_blob_write"));
      if (ret != SQLITE_OK) {
	WHYF("sqlite3_blob_write() failed, %s", sqlite3_errmsg(rhizome_db));
	goto rollback_blob;
      }
      sqlite_retry_done(&retry, "sqlite3_blob_write");
    }
     SHA512_End(&context, (char *)hash_out);
     str_toupper_inplace(hash_out);
  }
  if (strcasecmp(hash_out, hash) != 0) {
    WHYF("File hash %s does not match computed hash %s -- has file been modified while being stored?",
	hash_out, hash
      );
    goto rollback_blob;
  }
  // sqlite3_blob_close() always closes the blob, regardless of return value, so it cannot be
  // retried on returning SQLITE_BUSY.
  ret = sqlite3_blob_close(blob);
  blob = NULL;
  if (!sqlite_code_ok(ret)) {
    WHYF("sqlite3_blob_close() failed, %s", sqlite3_errmsg(rhizome_db));
    goto rollback_blob;
  }

  if (sqlite_exec_void_retry(&retry, "COMMIT;") == -1)
    goto rollback;

  /* Mark file as up-to-date */
  if (sqlite_exec_void_retry(&retry, "UPDATE FILES SET datavalid=1 WHERE id='%s';", hash) != 0) {
    WHY("Failed to set datavalid");
    goto error;
  }

  close(fd);
  return 0;

rollback_blob:
  WHYF("Failed to write blob in newly inserted row for fileid=%s", hash);
  if (blob)
    sqlite3_blob_close(blob);
rollback:
  sqlite_exec_void_retry(&retry, "ROLLBACK;");
error:
  if (fd != -1)
    close(fd);
  return -1;
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
  if (highestPriority >= 0 && sqlite_exec_void_retry(&retry, "UPDATE files set highestPriority=%lld WHERE id='%s';", highestPriority, fileid) != 0)
    WHYF("cannot update priority for fileid=%s", fileid);
  return 0;
}

/* Search the database for a manifest having the same name and payload content,
   and if the version is known, having the same version.

   @author Andrew Bettison <andrew@servalproject.com>
 */
int rhizome_find_duplicate(const rhizome_manifest *m, rhizome_manifest **found, int checkVersionP)
{
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
    if (!m->fileHashedP)
      return WHY("Manifest payload is not hashed");
    strbuf_puts(b, "filehash = ?");
  } else
    strbuf_puts(b, "filesize = 0");
  if (checkVersionP)
    strbuf_puts(b, " AND version = ?");
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
    if (debug & DEBUG_RHIZOME)
      DEBUGF("filehash=\"%s\"", filehash);
    sqlite3_bind_text(statement, field++, filehash, -1, SQLITE_STATIC);
  }
  if (checkVersionP)
    sqlite3_bind_int64(statement, field++, m->version);
  size_t rows = 0;
  while (sqlite_step_retry(&retry, statement) == SQLITE_ROW) {
    ++rows;
    if (debug & DEBUG_RHIZOME) DEBUGF("Row %d", rows);
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
	} else if (strcasecmp(service, RHIZOME_SERVICE_MESHMS) == 0) {
	  const char *blob_sender = rhizome_manifest_get(blob_m, "sender", NULL, 0);
	  const char *blob_recipient = rhizome_manifest_get(blob_m, "recipient", NULL, 0);
	  if (blob_sender && !strcasecmp(blob_sender, sender) && blob_recipient && !strcasecmp(blob_recipient, recipient)) {
	    if (debug & DEBUG_RHIZOME)
	      strbuf_sprintf(b, " sender=%s recipient=%s", blob_sender, blob_recipient);
	    ret = 1;
	  }
	}
	if (ret == 1) {
	  const char *q_author = (const char *) sqlite3_column_text(statement, 3);
	  if (q_author) {
	    if (debug & DEBUG_RHIZOME)
	      strbuf_sprintf(b, " .author=%s", q_author);
	    stowSid(blob_m->author, 0, q_author);
	  }
	  memcpy(blob_m->cryptoSignPublic, manifest_id, RHIZOME_MANIFEST_ID_BYTES);
	  memcpy(blob_m->fileHexHash, m->fileHexHash, RHIZOME_FILEHASH_STRLEN + 1);
	  blob_m->fileHashedP = 1;
	  blob_m->fileLength = m->fileLength;
	  blob_m->version = q_version;
	  *found = blob_m;
	  DEBUGF("Found duplicate payload: service=%s%s version=%llu hexhash=%s",
		  blob_service, strbuf_str(b), blob_m->version, blob_m->fileHexHash, q_author ? q_author : ""
		);
	  break;
	}
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
 * Returns 1 if manifest is found (if mp != NULL then a new manifest struct is allocated, made
 * finalisable and * assigned to *mp, caller is responsible for freeing).
 * Returns 0 if manifest is not found (*mp is unchanged).
 * Returns -1 on error (*mp is unchanged).
 */
int rhizome_retrieve_manifest(const char *manifestid, rhizome_manifest **mp)
{
  unsigned char manifest_id[RHIZOME_MANIFEST_ID_BYTES];
  if (fromhexstr(manifest_id, manifestid, RHIZOME_MANIFEST_ID_BYTES) == -1)
    return WHY("Invalid manifest ID");
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  sqlite3_stmt *statement = sqlite_prepare(&retry, "SELECT id, manifest, version, inserttime, author FROM manifests WHERE id = ?");
  if (!statement)
    return -1;
  char manifestIdUpper[RHIZOME_MANIFEST_ID_STRLEN + 1];
  tohex(manifestIdUpper, manifest_id, RHIZOME_MANIFEST_ID_BYTES);
  sqlite3_bind_text(statement, 1, manifestIdUpper, -1, SQLITE_STATIC);
  int ret = 0;
  rhizome_manifest *m = NULL;
  while (sqlite_step_retry(&retry, statement) == SQLITE_ROW) {
    if (!(   sqlite3_column_count(statement) == 5
	  && sqlite3_column_type(statement, 0) == SQLITE_TEXT
	  && sqlite3_column_type(statement, 1) == SQLITE_BLOB
	  && sqlite3_column_type(statement, 2) == SQLITE_INTEGER
	  && sqlite3_column_type(statement, 3) == SQLITE_INTEGER
	  && (  sqlite3_column_type(statement, 4) == SQLITE_TEXT
	     || sqlite3_column_type(statement, 4) == SQLITE_NULL
	     )
    )) {
      ret = WHY("Incorrect statement column");
      break;
    }
    const char *q_manifestid = (const char *) sqlite3_column_text(statement, 0);
    const char *manifestblob = (char *) sqlite3_column_blob(statement, 1);
    long long q_version = (long long) sqlite3_column_int64(statement, 2);
    long long q_inserttime = (long long) sqlite3_column_int64(statement, 3);
    const char *q_author = (const char *) sqlite3_column_text(statement, 4);
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
	memcpy(m->cryptoSignPublic, manifest_id, RHIZOME_MANIFEST_ID_BYTES);
	const char *blob_service = rhizome_manifest_get(m, "service", NULL, 0);
	if (blob_service == NULL)
	  ret = WHY("Manifest is missing 'service' field");
	long long filesizeq = rhizome_manifest_get_ll(m, "filesize");
	if (filesizeq == -1)
	  ret = WHY("Manifest is missing 'filesize' field");
	else
	  m->fileLength = filesizeq;
	const char *blob_filehash = rhizome_manifest_get(m, "filehash", NULL, 0);
	if (m->fileLength != 0) {
	  if (blob_filehash == NULL)
	    ret = WHY("Manifest is missing 'filehash' field");
	  else {
	    memcpy(m->fileHexHash, blob_filehash, RHIZOME_FILEHASH_STRLEN + 1);
	    m->fileHashedP = 1;
	  }
	} else {
	  if (blob_filehash != NULL)
	    WARN("Manifest contains spurious 'filehash' field -- ignored");
	  m->fileHexHash[0] = '\0';
	  m->fileHashedP = 0;
	}
	long long blob_version = rhizome_manifest_get_ll(m, "version");
	if (blob_version == -1)
	  ret = WHY("Manifest is missing 'version' field");
	else
	  m->version = blob_version;
	int read_only = 1;
	if (q_author == NULL) {
	  // Search for the author in the keyring.
	  // TODO optimise: if manifest 'sender' is set, try that identity first.
	  int result = rhizome_find_bundle_author(m);
	  switch (result) {
	  case -1:
	    ret = WHY("Error searching keyring for bundle author");
	    break;
	  case 0:
	    read_only = 0;
	    if (sqlite_exec_void("UPDATE MANIFESTS SET author='%s' WHERE id='%s';", alloca_tohex_sid(m->author), manifestIdUpper) == -1)
	      WHY("Error updating MANIFESTS author column");
	    break;
	  }
	} else if (stowSid(m->author, 0, q_author) == -1) {
	  WARNF("MANIFESTS row id=%s contains invalid author=%s -- ignored", q_manifestid, alloca_str_toprint(q_author));
	} else {
	  // If the AUTHOR column contains a valid SID, then it means that author verification has
	  // already been done (either implicitly when the bundle was added locally, or explicitly
	  // when rhizome_find_bundle_author() was called in the case above), so we represent this
	  // bundle as writable if the author is present in the keyring and possesses a Rhizome
	  // Secret.
	  int result = rhizome_find_secret(m->author, NULL, NULL);
	  switch (result) {
	  case -1:
	    ret = WHY("Error extracting manifest private key");
	    break;
	  case 0:
	    read_only = 0;
	    break;
	  default:
	    INFOF("bundle author=%s is not in keyring -- ignored", q_author);
	    memset(m->author, 0, sizeof m->author); // do not output ".author" field
	    break;
	  }
	}
	if (ret == 1) {
	  cli_puts("service"); cli_delim(":");
	  cli_puts(blob_service); cli_delim("\n");
	  cli_puts("manifestid"); cli_delim(":");
	  cli_puts(q_manifestid); cli_delim("\n");
	  cli_puts("version"); cli_delim(":");
	  cli_printf("%lld", q_version); cli_delim("\n");
	  cli_puts("inserttime"); cli_delim(":");
	  cli_printf("%lld", q_inserttime); cli_delim("\n");
	  if (!is_sid_any(m->author)) {
	    cli_puts(".author"); cli_delim(":");
	    cli_puts(alloca_tohex_sid(m->author)); cli_delim("\n");
	  }
	  cli_puts(".readonly"); cli_delim(":");
	  cli_printf("%d", read_only); cli_delim("\n");
	  cli_puts("filesize"); cli_delim(":");
	  cli_printf("%lld", (long long) m->fileLength); cli_delim("\n");
	  if (m->fileLength != 0) {
	    cli_puts("filehash"); cli_delim(":");
	    cli_puts(m->fileHexHash); cli_delim("\n");
	  }
	  // Could write the manifest blob to the CLI output here, but that would require the output to
	  // support byte[] fields as well as String fields.
	}
      }
    }
    break;
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
int rhizome_retrieve_file(const char *fileid, const char *filepath, const unsigned char *key)
{
  if (rhizome_update_file_priority(fileid) == -1) {
    WHY("Failed to update file priority");
    return 0;
  }
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  sqlite3_stmt *statement = sqlite_prepare(&retry, "SELECT id, rowid, length FROM files WHERE id = ? AND datavalid != 0");
  if (!statement)
    return -1;
  int ret = 0;
  char fileIdUpper[RHIZOME_FILEHASH_STRLEN + 1];
  strncpy(fileIdUpper, fileid, sizeof fileIdUpper);
  fileIdUpper[RHIZOME_FILEHASH_STRLEN] = '\0';
  str_toupper_inplace(fileIdUpper);
  sqlite3_bind_text(statement, 1, fileIdUpper, -1, SQLITE_STATIC);
  int stepcode = sqlite_step_retry(&retry, statement);
  if (stepcode != SQLITE_ROW) {
    ret = 0; // no files found
  } else if (!(   sqlite3_column_count(statement) == 3
		  && sqlite3_column_type(statement, 0) == SQLITE_TEXT
		  && sqlite3_column_type(statement, 1) == SQLITE_INTEGER
		  && sqlite3_column_type(statement, 2) == SQLITE_INTEGER
  )) { 
    ret = WHY("Incorrect statement column");
  } else {
    long long length = sqlite3_column_int64(statement, 2);
    int64_t rowid = sqlite3_column_int64(statement, 1);
    sqlite3_blob *blob = NULL;
    int code;
    do code = sqlite3_blob_open(rhizome_db, "main", "FILES", "data", rowid, 0 /* read only */, &blob);
    while (sqlite_code_busy(code) && sqlite_retry(&retry, "sqlite3_blob_open"));
    if (!sqlite_code_ok(code)) {
      ret = WHY("Could not open blob for reading");
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
	} else {
	  /* read from blob and write to disk, decrypting if necessary as we go.  Each 4KB block of
	     data has a nonce which is fed with the key into crypto_stream_xsalsa20().  The nonce is
	     the file address divided by 4KB.  This approach is used as it allows us to append to
	     files easily, without having to get the XOR stream for the whole file, and without the
	     cipher on existing bytes having to change.  Both of these are important properties for
	     journal bundles, such as will be used by MeshMS.  For non-journal bundles where it is
	     important that changing the payload changes the encryption key (so that the XOR between
	     any two versions of the payload cannot be easily obtained).  We will do this by having
	     journal manifests identified, causing the key to be locked, rather than based on the
	     version number.  But anyway, we are supplied with the key here, so all we need to do is
	     do the block counting and call crypto_stream_xsalsa20().
	  */
	  long long offset;
	  unsigned char nonce[crypto_stream_xsalsa20_NONCEBYTES];
	  bzero(nonce,crypto_stream_xsalsa20_NONCEBYTES);
	  unsigned char buffer[RHIZOME_CRYPT_PAGE_SIZE];
	  for (offset = 0; offset < length; offset += RHIZOME_CRYPT_PAGE_SIZE) {
	    long long count=length-offset;
	    if (count>RHIZOME_CRYPT_PAGE_SIZE) count=RHIZOME_CRYPT_PAGE_SIZE;
	    if(sqlite3_blob_read(blob,&buffer[0],count,offset)!=SQLITE_OK) {
	      ret = 0;
	      WHYF("query failed, %s: %s", sqlite3_errmsg(rhizome_db), sqlite3_sql(statement));
	      WHYF("Error reading %lld bytes of data from blob at offset 0x%llx", count, offset);
	    }
	    if (key) {
	      /* calculate block nonce */
	      int i; for(i=0;i<8;i++) nonce[i]=(offset>>(i*8))&0xff;
	      crypto_stream_xsalsa20_xor(&buffer[0],&buffer[0],count, nonce,key);
	    }
	    if (write(fd,buffer,count)!=count) {
	      ret =0;
	      WHY("Failed to write data to file");
	    }
	  }
	  sqlite3_blob_close(blob);
	  blob = NULL;
	}
	if (fd != -1 && close(fd) == -1) {
	  WHY_perror("close");
	  WHYF("Error flushing to %s ", filepath);
	  ret = 0;
	}
      }
      if (blob)
	sqlite3_blob_close(blob);
    }
  }
  sqlite3_finalize(statement);
  return ret;
}

int rhizome_import_from_files(const char *manifestpath,const char *filepath)
{
  rhizome_manifest *m = rhizome_new_manifest();
  if (!m)
    return WHY("Out of manifests.");
  int status = -1;
  if (rhizome_read_manifest_file(m, manifestpath, 0) == -1) {
    status = WHY("could not read manifest file");
  } else if (rhizome_manifest_verify(m) == -1) {
    status = WHY("Could not verify manifest file.");
  } else {
    /* Make sure we store signatures */
    m->manifest_bytes=m->manifest_all_bytes;

    /* Add the manifest and its associated file to the Rhizome database. */
    m->dataFileName = strdup(filepath);
    if (rhizome_manifest_check_file(m))
      status = WHY("file does not belong to manifest");
    else {
      int ret = rhizome_manifest_check_duplicate(m, NULL);
      if (ret == -1)
	status = WHY("rhizome_manifest_check_duplicate() failed");
      else if (ret) {
	INFO("Duplicate found in store");
	status = 1;
      } else if (rhizome_add_manifest(m, 1) == -1) { // ttl = 1
	status = WHY("rhizome_add_manifest() failed");
      } else {
	status = 0;
      }
      if (status != -1) {
	const char *service = rhizome_manifest_get(m, "service", NULL, 0);
	if (service) {
	  cli_puts("service");
	  cli_delim(":");
	  cli_puts(service);
	  cli_delim("\n");
	}
	{
	  cli_puts("manifestid");
	  cli_delim(":");
	  cli_puts(alloca_tohex(m->cryptoSignPublic, RHIZOME_MANIFEST_ID_BYTES));
	  cli_delim("\n");
	}
	cli_puts("filesize");
	cli_delim(":");
	cli_printf("%lld", m->fileLength);
	cli_delim("\n");
	if (m->fileLength != 0) {
	  cli_puts("filehash");
	  cli_delim(":");
	  cli_puts(m->fileHexHash);
	  cli_delim("\n");
	}
	const char *name = rhizome_manifest_get(m, "name", NULL, 0);
	if (name) {
	  cli_puts("name");
	  cli_delim(":");
	  cli_puts(name);
	  cli_delim("\n");
	}
      }
    }
  }
  rhizome_manifest_free(m);
  return status;
}
