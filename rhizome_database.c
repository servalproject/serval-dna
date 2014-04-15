/*
Serval Rhizome file sharing
Copyright (C) 2012-2013 Serval Project Inc.

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
#include <ctype.h>
#include <assert.h>
#include "serval.h"
#include "conf.h"
#include "rhizome.h"
#include "strbuf.h"
#include "strbuf_helpers.h"
#include "str.h"
#include "keyring.h"

static int rhizome_delete_manifest_retry(sqlite_retry_state *retry, const rhizome_bid_t *bidp);
static int rhizome_delete_file_retry(sqlite_retry_state *retry, const rhizome_filehash_t *hashp);
static int rhizome_delete_payload_retry(sqlite_retry_state *retry, const rhizome_bid_t *bidp);

static int create_rhizome_store_dir()
{
  char rdpath[1024];
  if (!formf_rhizome_store_path(rdpath, sizeof rdpath, "%s", config.rhizome.datastore_path))
    return -1;
  INFOF("Rhizome datastore path = %s", alloca_str_toprint(rdpath));
  if (config.debug.rhizome)
    DEBUGF("mkdirs(%s, 0700)", alloca_str_toprint(rdpath));
  return emkdirs_info(rdpath, 0700);
}

sqlite3 *rhizome_db = NULL;
serval_uuid_t rhizome_db_uuid;

/* XXX Requires a messy join that might be slow. */
int rhizome_manifest_priority(sqlite_retry_state *retry, const rhizome_bid_t *bidp)
{
  uint64_t result = 0;
  if (sqlite_exec_uint64_retry(retry, &result,
	"SELECT max(grouplist.priorty) FROM GROUPLIST,MANIFESTS,GROUPMEMBERSHIPS"
	" WHERE MANIFESTS.id = ?"
	"   AND GROUPLIST.id = GROUPMEMBERSHIPS.groupid"
	"   AND GROUPMEMBERSHIPS.manifestid = MANIFESTS.id;",
	RHIZOME_BID_T, bidp,
	END
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
static int sqlite_trace_done;

/* This is called by SQLite when executing a statement using sqlite3_step().  Unfortunately, it is
 * not called on PRAGMA statements, and possibly others.  Hence the use of the profile callback (see
 * below).
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static void sqlite_trace_callback(void *UNUSED(context), const char *rendered_sql)
{
  if (sqlite_trace_func())
    logMessage(LOG_LEVEL_DEBUG, sqlite_trace_whence ? *sqlite_trace_whence : __HERE__, "%s", rendered_sql);
  ++sqlite_trace_done;
}

/* This is called by SQLite when an executed statement finishes.  We use it to log rendered SQL
 * statements when the trace callback (above) has not been called, eg, for PRAGMA statements.  This
 * requires that the 'sqlite_trace_done' static be reset to zero whenever a new prepared statement
 * is about to be stepped.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static void sqlite_profile_callback(void *context, const char *rendered_sql, sqlite_uint64 UNUSED(nanosec))
{
  if (!sqlite_trace_done)
    sqlite_trace_callback(context, rendered_sql);
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

void sqlite_log(void *UNUSED(ignored), int result, const char *msg)
{
  WARNF("Sqlite: %d %s", result, msg);
}

void verify_bundles()
{
  // assume that only the manifest itself can be trusted
  // fetch all manifests and reinsert them.
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  // This cursor must be ordered descending as re-inserting the manifests will give them a new higher manifest id.
  // If we didn't, we'd get stuck in an infinite loop.
  sqlite3_stmt *statement = sqlite_prepare(&retry, "SELECT ROWID, MANIFEST FROM MANIFESTS ORDER BY ROWID DESC;");
  while (sqlite_step_retry(&retry, statement) == SQLITE_ROW) {
    sqlite3_int64 rowid = sqlite3_column_int64(statement, 0);
    const void *blob = sqlite3_column_blob(statement, 1);
    size_t blob_length = sqlite3_column_bytes(statement, 1);
    rhizome_manifest *m = rhizome_new_manifest();
    if (m) {
      memcpy(m->manifestdata, blob, blob_length);
      m->manifest_all_bytes = blob_length;
      int ret = -1;
      if (   rhizome_manifest_parse(m) != -1
	  && rhizome_manifest_validate(m)
	  && rhizome_manifest_verify(m)
      ) {
	assert(m->finalised);
	// Store it again, to ensure that MANIFESTS columns are up to date.
	ret = rhizome_store_manifest(m);
      }
      if (ret) {
	if (config.debug.rhizome)
	  DEBUGF("Removing invalid manifest entry @%lld", rowid);
	sqlite_exec_void_retry(&retry, "DELETE FROM MANIFESTS WHERE ROWID = ?;", INT64, rowid, END);
      }
      rhizome_manifest_free(m);
    }
  }
  sqlite3_finalize(statement);
}

/*
 * The MANIFESTS table 'author' column records the cryptographically verified SID of the author that
 * has write permission on the bundle, ie, possesses the Rhizome secret key that generated the BID,
 * and hence can derive the Bundle Secret from the bundle's BK field:
 *
 * - The MANIFESTS table 'author' column is set to the author SID when a bundle is created locally
 *   by a non-secret identity, so no verification need be performed for one's own bundles while they
 *   remain in the local Rhizome store.
 *
 * - When a bundle is imported, the 'author' column is set to NULL to indicate that no verification
 *   has passed yet.  This includes one's own bundles that have been purged from the local Rhizome
 *   store then recovered from a remote Rhizome node.
 *
 * - When a manifest with NULL 'author' is examined closely, ie extracted, not merely listed, the
 *   keyring is searched for an identity that is the author.  If the identity is found and its
 *   Rhizome Secret unlocks the Bundle Key (ie, reveals a Bundle Secret that yields the Bundle's ID
 *   as its public key), the MANIFESTS table 'author' column is updated.  This allows one to regain
 *   the ability to overwrite one's own bundles that have been lost but
 *   recovered from an exterior Rhizome node.
 *
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
  if (rhizome_db) {
    assert(uuid_is_valid(&rhizome_db_uuid));
    return 0;
  }

  IN();
  
  if (create_rhizome_store_dir() == -1)
    RETURN(-1);
  char dbpath[1024];
  if (!FORMF_RHIZOME_STORE_PATH(dbpath, RHIZOME_BLOB_SUBDIR))
    RETURN(-1);
  if (emkdirs_info(dbpath, 0700) == -1)
    RETURN(-1);
  if (!sqlite3_temp_directory) {
    if (!FORMF_RHIZOME_STORE_PATH(dbpath, "sqlite3tmp"))
      RETURN(-1);
    if (emkdirs_info(dbpath, 0700) == -1)
      RETURN(-1);
    sqlite3_temp_directory = sqlite3_mprintf("%s", dbpath);
  }
  sqlite3_config(SQLITE_CONFIG_LOG,sqlite_log,NULL);
  
  if (!FORMF_RHIZOME_STORE_PATH(dbpath, "rhizome.db"))
    RETURN(-1);
  if (sqlite3_open(dbpath,&rhizome_db)){
    RETURN(WHYF("SQLite could not open database %s: %s", dbpath, sqlite3_errmsg(rhizome_db)));
  }
  sqlite3_trace(rhizome_db, sqlite_trace_callback, NULL);
  sqlite3_profile(rhizome_db, sqlite_profile_callback, NULL);
  int loglevel = (config.debug.rhizome) ? LOG_LEVEL_DEBUG : LOG_LEVEL_SILENT;

  /* Read Rhizome configuration */
  if (config.debug.rhizome)
    DEBUGF("Rhizome will use %"PRIu64"B of storage for its database.", (uint64_t) config.rhizome.database_size);
  
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;

  uint64_t version;
  if (sqlite_exec_uint64_retry(&retry, &version, "PRAGMA user_version;", END) == -1)
    RETURN(-1);
  
  if (version<1){
    /* Create tables as required */
    sqlite_exec_void_loglevel(loglevel, "PRAGMA auto_vacuum=2;", END);
    if (	sqlite_exec_void_retry(&retry, "CREATE TABLE IF NOT EXISTS GROUPLIST(id text not null primary key, closed integer,ciphered integer,priority integer);", END) == -1
      ||	sqlite_exec_void_retry(&retry, "CREATE TABLE IF NOT EXISTS MANIFESTS(id text not null primary key, version integer,inserttime integer, filesize integer, filehash text, author text, bar blob, manifest blob);", END) == -1
      ||	sqlite_exec_void_retry(&retry, "CREATE TABLE IF NOT EXISTS FILES(id text not null primary key, length integer, highestpriority integer, datavalid integer, inserttime integer);", END) == -1
      ||	sqlite_exec_void_retry(&retry, "CREATE TABLE IF NOT EXISTS FILEBLOBS(id text not null primary key, data blob);", END) == -1
      ||	sqlite_exec_void_retry(&retry, "DROP TABLE IF EXISTS FILEMANIFESTS;", END) == -1
      ||	sqlite_exec_void_retry(&retry, "CREATE TABLE IF NOT EXISTS GROUPMEMBERSHIPS(manifestid text not null, groupid text not null);", END) == -1
      ||	sqlite_exec_void_retry(&retry, "CREATE TABLE IF NOT EXISTS VERIFICATIONS(sid text not null, did text, name text, starttime integer, endtime integer, signature blob);", END) == -1
    ) {
      RETURN(WHY("Failed to create schema"));
    }
    /* Create indexes if they don't already exist */
    sqlite_exec_void_loglevel(LOG_LEVEL_WARN, "CREATE INDEX IF NOT EXISTS bundlesizeindex ON manifests (filesize);", END);
    sqlite_exec_void_loglevel(LOG_LEVEL_WARN, "CREATE INDEX IF NOT EXISTS IDX_MANIFESTS_HASH ON MANIFESTS(filehash);", END);
    sqlite_exec_void_loglevel(LOG_LEVEL_WARN, "PRAGMA user_version=1;", END);
  }
  if (version<2){
    sqlite_exec_void_loglevel(LOG_LEVEL_WARN, "ALTER TABLE MANIFESTS ADD COLUMN service text;", END);
    sqlite_exec_void_loglevel(LOG_LEVEL_WARN, "ALTER TABLE MANIFESTS ADD COLUMN name text;", END);
    sqlite_exec_void_loglevel(LOG_LEVEL_WARN, "ALTER TABLE MANIFESTS ADD COLUMN sender text collate nocase;", END);
    sqlite_exec_void_loglevel(LOG_LEVEL_WARN, "ALTER TABLE MANIFESTS ADD COLUMN recipient text collate nocase;", END);
    // if more bundle verification is required in later upgrades, move this to the end, don't run it more than once.
    verify_bundles();
    sqlite_exec_void_loglevel(LOG_LEVEL_WARN, "PRAGMA user_version=2;", END);
  }
  if (version<3){
    sqlite_exec_void_loglevel(LOG_LEVEL_WARN, "CREATE INDEX IF NOT EXISTS IDX_MANIFESTS_ID_VERSION ON MANIFESTS(id, version);", END);
    sqlite_exec_void_loglevel(LOG_LEVEL_WARN, "PRAGMA user_version=3;", END);
  }
  if (version<4){
    sqlite_exec_void_loglevel(LOG_LEVEL_WARN, "ALTER TABLE MANIFESTS ADD COLUMN tail integer;", END);
    sqlite_exec_void_loglevel(LOG_LEVEL_WARN, "PRAGMA user_version=4;", END);
  }
  if (version<5){
    sqlite_exec_void_loglevel(LOG_LEVEL_WARN, "CREATE TABLE IF NOT EXISTS IDENTITY(uuid text not null); ", END);
    sqlite_exec_void_loglevel(LOG_LEVEL_WARN, "PRAGMA user_version=5;", END);
  }

  char buf[UUID_STRLEN + 1];
  int r = sqlite_exec_strbuf_retry(&retry, strbuf_local(buf, sizeof buf), "SELECT uuid from IDENTITY LIMIT 1;", END);
  if (r == -1)
    RETURN(-1);
  if (r) {
    if (!str_to_uuid(buf, &rhizome_db_uuid, NULL)) {
      WHYF("IDENTITY table contains malformed UUID %s -- overwriting", alloca_str_toprint(buf));
      if (serval_uuid_generate_random(&rhizome_db_uuid) == -1)
	RETURN(WHY("Cannot generate new UUID for Rhizome database"));
      if (sqlite_exec_void_retry(&retry, "UPDATE IDENTITY SET uuid = ? LIMIT 1;", SERVAL_UUID_T, &rhizome_db_uuid, END) == -1)
	RETURN(WHY("Failed to update new UUID in Rhizome database"));
      if (config.debug.rhizome)
	DEBUGF("Updated Rhizome database UUID to %s", alloca_uuid_str(rhizome_db_uuid));
    }
  } else if (r == 0) {
    if (serval_uuid_generate_random(&rhizome_db_uuid) == -1)
      RETURN(WHY("Cannot generate UUID for Rhizome database"));
    if (sqlite_exec_void_retry(&retry, "INSERT INTO IDENTITY (uuid) VALUES (?);", SERVAL_UUID_T, &rhizome_db_uuid, END) == -1)
      RETURN(WHY("Failed to insert UUID into Rhizome database"));
    if (config.debug.rhizome)
      DEBUGF("Set Rhizome database UUID to %s", alloca_uuid_str(rhizome_db_uuid));
  }

  // TODO recreate tables with collate nocase on hex columns

  /* Future schema updates should be performed here. 
   The above schema can be assumed to exist.
   All changes should attempt to preserve any existing data */

  // We can't delete a file that is being transferred in another process at this very moment...
  if (config.rhizome.clean_on_open)
    rhizome_cleanup(NULL);
  INFOF("Opened Rhizome database %s, UUID=%s", dbpath, alloca_uuid_str(rhizome_db_uuid));
  RETURN(0);
  OUT();
}

int rhizome_close_db()
{
  IN();
  if (rhizome_db) {
    rhizome_cache_close();
    
    if (!sqlite3_get_autocommit(rhizome_db)){
      WHY("Uncommitted transaction!");
      sqlite_exec_void("ROLLBACK;", END);
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

/* Prepare an SQL command from a simple string.  Returns NULL if an error occurs (logged as an
 * error), otherwise returns a pointer to the prepared SQLite statement.
 *
 * IMPORTANT!  Do not form statement strings using sprintf(3) or strbuf_sprintf() or similar
 * methods, because those are susceptible to SQL injection attacks.  Instead, use bound parameters
 * and bind them using the _sqlite_bind() function below.
 *
 * IMPORTANT!  Do not add sprintf(3)-like functionality to this method.  It used to take
 * sprintf(3)-style varargs and these were deliberately removed.  It is vital to discourage bad
 * practice, and adding sprintf(3)-style args to this function would be a step in the wrong
 * direction.
 *
 * See GitHub issue #69.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
sqlite3_stmt *_sqlite_prepare(struct __sourceloc __whence, int log_level, sqlite_retry_state *retry, const char *sqltext)
{
  IN();
  sqlite3_stmt *statement = NULL;
  if (!rhizome_db && rhizome_opendb() == -1)
    RETURN(NULL);
  while (1) {
    switch (sqlite3_prepare_v2(rhizome_db, sqltext, -1, &statement, NULL)) {
      case SQLITE_OK:
	sqlite_trace_done = 0;
	RETURN(statement);
      case SQLITE_BUSY:
      case SQLITE_LOCKED:
	if (retry && _sqlite_retry(__whence, retry, sqltext)) {
	  break; // back to sqlite3_prepare_v2()
	}
	// fall through...
      default:
	LOGF(log_level, "query invalid, %s: %s", sqlite3_errmsg(rhizome_db), sqltext);
	sqlite3_finalize(statement);
	RETURN(NULL);
    }
  }
}

/* Bind some parameters to a prepared SQL statement.  Returns -1 if an error occurs (logged as an
 * error), otherwise zero with the prepared statement in *statement.
 *
 * Developed as part of GitHub issue #69.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int _sqlite_vbind(struct __sourceloc __whence, int log_level, sqlite_retry_state *retry, sqlite3_stmt *statement, va_list ap)
{
  const int index_limit = sqlite3_limit(rhizome_db, SQLITE_LIMIT_VARIABLE_NUMBER, -1);
  unsigned argnum = 0;
  int index_counter = 0;
  enum sqlbind_type typ;
  while ((typ = va_arg(ap, int)) != END) {
    ++argnum;
    int index;
    const char *name = NULL;
    strbuf ext = NULL;
    if ((typ & 0xffff0000) == INDEX) {
      typ &= 0xffff;
      index = va_arg(ap, int);
      ++argnum;
      if (index < 1 || index > index_limit) {
	LOGF(log_level, "at bind arg %u, illegal index=%d: %s", argnum, index, sqlite3_sql(statement));
	return -1;
      }
      if (config.debug.rhizome)
	strbuf_sprintf((ext = strbuf_alloca(35)), "|INDEX(%d)", index);
    } else if ((typ & 0xffff0000) == NAMED) {
      typ &= 0xffff;
      name = va_arg(ap, const char *);
      ++argnum;
      index = sqlite3_bind_parameter_index(statement, name);
      if (index == 0) {
	LOGF(log_level, "at bind arg %u, no parameter named %s in query: %s", argnum, alloca_str_toprint(name), sqlite3_sql(statement));
	return -1;
      }
      if (config.debug.rhizome) {
	ext = strbuf_alloca(30 + toprint_str_len(name, "\"\""));
	strbuf_puts(ext, "|NAMED(");
	strbuf_toprint_quoted(ext, "\"\"", name);
	strbuf_puts(ext, ")");
      }
    } else if ((typ & 0xffff0000) == 0) {
      index = ++index_counter;
      if (config.debug.rhizome)
	ext = strbuf_alloca(10);
    } else {
      FATALF("at bind arg %u, unsupported bind code typ=0x%08x: %s", argnum, typ, sqlite3_sql(statement));
      return -1;
    }
#define BIND_DEBUG(TYP,FUNC,ARGFMT,...) \
	if (config.debug.rhizome_sql_bind) \
	  DEBUGF("%s%s %s(%d," ARGFMT ") %s", #TYP, strbuf_str(ext), #FUNC, index, ##__VA_ARGS__, sqlite3_sql(statement))
#define BIND_RETRY(FUNC, ...) \
	do { \
	  switch (FUNC(statement, index, ##__VA_ARGS__)) { \
	    case SQLITE_OK: \
	      break; \
	    case SQLITE_BUSY: \
	    case SQLITE_LOCKED: \
	      if (retry && _sqlite_retry(__whence, retry, #FUNC "()")) \
		continue; \
	    default: \
	      LOGF(log_level, #FUNC "(%d) failed, %s: %s", index, sqlite3_errmsg(rhizome_db), sqlite3_sql(statement)); \
	      sqlite3_finalize(statement); \
	      return -1; \
	  } \
	  break; \
	} while (1)
#define BIND_NULL(TYP) \
	if (typ & NUL) { \
	  BIND_DEBUG(TYP, sqlite3_bind_null, ""); \
	  BIND_RETRY(sqlite3_bind_null); \
	} else { \
	  LOGF(log_level, "at bind arg %u, %s%s parameter is NULL: %s", argnum, #TYP, strbuf_str(ext), sqlite3_sql(statement)); \
	  sqlite3_finalize(statement); \
	  return -1; \
	}
    switch (typ) {
      case NUL:
	BIND_DEBUG(NUL, sqlite3_bind_null, "");
	BIND_RETRY(sqlite3_bind_null);
	break;
      default:
	if ((typ & NUL) && config.debug.rhizome)
	  strbuf_puts(ext, "|NUL");
	switch (typ & ~NUL) {
	  case INT: {
	      int value = va_arg(ap, int);
	      ++argnum;
	      BIND_DEBUG(INT, sqlite3_bind_int, "%d", value);
	      BIND_RETRY(sqlite3_bind_int, value);
	    }
	    break;
	  case INT_TOSTR: {
	      int value = va_arg(ap, int);
	      ++argnum;
	      char str[25];
	      sprintf(str, "%d", value);
	      BIND_DEBUG(INT_TOSTR, sqlite3_bind_text, "%s,-1,SQLITE_TRANSIENT", alloca_str_toprint(str));
	      BIND_RETRY(sqlite3_bind_text, str, -1, SQLITE_TRANSIENT);
	    }
	    break;
	  case UINT_TOSTR: {
	      unsigned value = va_arg(ap, unsigned);
	      ++argnum;
	      char str[25];
	      sprintf(str, "%u", value);
	      BIND_DEBUG(UINT_TOSTR, sqlite3_bind_text, "%s,-1,SQLITE_TRANSIENT", alloca_str_toprint(str));
	      BIND_RETRY(sqlite3_bind_text, str, -1, SQLITE_TRANSIENT);
	    }
	    break;
	  case INT64: {
	      sqlite3_int64 value = va_arg(ap, int64_t);
	      BIND_DEBUG(INT64, sqlite3_bind_int64, "%"PRId64, (int64_t)value);
	      BIND_RETRY(sqlite3_bind_int64, value);
	    }
	    break;
	  case INT64_TOSTR: {
	      int64_t value = va_arg(ap, int64_t);
	      ++argnum;
	      char str[35];
	      sprintf(str, "%"PRId64, value);
	      BIND_DEBUG(INT64_TOSTR, sqlite3_bind_text, "%s,-1,SQLITE_TRANSIENT", alloca_str_toprint(str));
	      BIND_RETRY(sqlite3_bind_text, str, -1, SQLITE_TRANSIENT);
	    }
	    break;
	  case UINT64_TOSTR: {
	      uint64_t value = va_arg(ap, uint64_t);
	      ++argnum;
	      char str[35];
	      sprintf(str, "%"PRIu64, value);
	      BIND_DEBUG(UINT64_TOSTR, sqlite3_bind_text, "%s,-1,SQLITE_TRANSIENT", alloca_str_toprint(str));
	      BIND_RETRY(sqlite3_bind_text, str, -1, SQLITE_TRANSIENT);
	    }
	    break;
	  case TEXT: {
	      const char *text = va_arg(ap, const char *);
	      ++argnum;
	      if (text == NULL) {
		BIND_NULL(TEXT);
	      } else {
		BIND_DEBUG(TEXT, sqlite3_bind_text, "%s,-1,SQLITE_TRANSIENT", alloca_str_toprint(text));
		BIND_RETRY(sqlite3_bind_text, text, -1, SQLITE_TRANSIENT);
	      }
	    }
	    break;
	  case TEXT_LEN: {
	      const char *text = va_arg(ap, const char *);
	      int bytes = va_arg(ap, int);
	      argnum += 2;
	      if (text == NULL) {
		BIND_NULL(TEXT_LEN);
	      } else {
		BIND_DEBUG(TEXT_LEN, sqlite3_bind_text, "%s,%d,SQLITE_TRANSIENT", alloca_str_toprint(text), bytes);
		BIND_RETRY(sqlite3_bind_text, text, bytes, SQLITE_TRANSIENT);
	      }
	    }
	    break;
	  case STATIC_TEXT: {
	      const char *text = va_arg(ap, const char *);
	      ++argnum;
	      if (text == NULL) {
		BIND_NULL(STATIC_TEXT);
	      } else {
		BIND_DEBUG(STATIC_TEXT, sqlite3_bind_text, "%s,-1,SQLITE_STATIC", alloca_str_toprint(text));
		BIND_RETRY(sqlite3_bind_text, text, -1, SQLITE_STATIC);
	      }
	    }
	    break;
	  case STATIC_TEXT_LEN: {
	      const char *text = va_arg(ap, const char *);
	      int bytes = va_arg(ap, int);
	      argnum += 2;
	      if (text == NULL) {
		BIND_NULL(STATIC_TEXT_LEN);
	      } else {
		BIND_DEBUG(STATIC_TEXT_LEN, sqlite3_bind_text, "%s,%d,SQLITE_STATIC", alloca_str_toprint(text), bytes);
		BIND_RETRY(sqlite3_bind_text, text, bytes, SQLITE_STATIC);
	      }
	    }
	    break;
	  case STATIC_BLOB: {
	      const void *blob = va_arg(ap, const void *);
	      int bytes = va_arg(ap, int);
	      argnum += 2;
	      if (blob == NULL) {
		BIND_NULL(STATIC_BLOB);
	      } else {
		BIND_DEBUG(STATIC_BLOB, sqlite3_bind_blob, "%s,%d,SQLITE_STATIC", alloca_toprint(20, blob, bytes), bytes);
		BIND_RETRY(sqlite3_bind_blob, blob, bytes, SQLITE_STATIC);
	      }
	    };
	    break;
	  case ZEROBLOB: {
	      int bytes = va_arg(ap, int);
	      ++argnum;
	      BIND_DEBUG(ZEROBLOB, sqlite3_bind_zeroblob, "%d,SQLITE_STATIC", bytes);
	      BIND_RETRY(sqlite3_bind_zeroblob, bytes);
	    };
	    break;
	  case SID_T: {
	      const sid_t *sidp = va_arg(ap, const sid_t *);
	      ++argnum;
	      if (sidp == NULL) {
		BIND_NULL(SID_T);
	      } else {
		const char *sid_hex = alloca_tohex_sid_t(*sidp);
		BIND_DEBUG(SID_T, sqlite3_bind_text, "%s,%u,SQLITE_TRANSIENT", sid_hex, SID_STRLEN);
		BIND_RETRY(sqlite3_bind_text, sid_hex, SID_STRLEN, SQLITE_TRANSIENT);
	      }
	    }
	    break;
	  case RHIZOME_BID_T: {
	      const rhizome_bid_t *bidp = va_arg(ap, const rhizome_bid_t *);
	      ++argnum;
	      if (bidp == NULL) {
		BIND_NULL(RHIZOME_BID_T);
	      } else {
		const char *bid_hex = alloca_tohex_rhizome_bid_t(*bidp);
		BIND_DEBUG(RHIZOME_BID_T, sqlite3_bind_text, "%s,%u,SQLITE_TRANSIENT", bid_hex, RHIZOME_MANIFEST_ID_STRLEN);
		BIND_RETRY(sqlite3_bind_text, bid_hex, RHIZOME_MANIFEST_ID_STRLEN, SQLITE_TRANSIENT);
	      }
	    }
	    break;
	  case RHIZOME_FILEHASH_T: {
	      const rhizome_filehash_t *hashp = va_arg(ap, const rhizome_filehash_t *);
	      ++argnum;
	      if (hashp == NULL) {
		BIND_NULL(RHIZOME_FILEHASH_T);
	      } else {
		char hash_hex[RHIZOME_FILEHASH_STRLEN + 1];
		tohex(hash_hex, RHIZOME_FILEHASH_STRLEN, hashp->binary);
		BIND_DEBUG(RHIZOME_FILEHASH_T, sqlite3_bind_text, "%s,%u,SQLITE_TRANSIENT", hash_hex, RHIZOME_FILEHASH_STRLEN);
		BIND_RETRY(sqlite3_bind_text, hash_hex, RHIZOME_FILEHASH_STRLEN, SQLITE_TRANSIENT);
	      }
	    }
	    break;
	  case TOHEX: {
	      const unsigned char *binary = va_arg(ap, const unsigned char *);
	      unsigned bytes = va_arg(ap, unsigned);
	      argnum += 2;
	      if (binary == NULL) {
		BIND_NULL(TOHEX);
	      } else {
		const char *hex = alloca_tohex(binary, bytes);
		BIND_DEBUG(TOHEX, sqlite3_bind_text, "%s,%u,SQLITE_TRANSIENT", hex, bytes * 2);
		BIND_RETRY(sqlite3_bind_text, hex, bytes * 2, SQLITE_TRANSIENT);
	      }
	    }
	    break;
	  case TEXT_TOUPPER: {
	      const char *text = va_arg(ap, const char *);
	      ++argnum;
	      if (text == NULL) {
		BIND_NULL(TEXT_TOUPPER);
	      } else {
		unsigned bytes = strlen(text);
		char upper[bytes + 1];
		str_toupper_inplace(strcpy(upper, text));
		BIND_DEBUG(TEXT_TOUPPER, sqlite3_bind_text, "%s,%u,SQLITE_TRANSIENT", alloca_toprint(-1, upper, bytes), bytes);
		BIND_RETRY(sqlite3_bind_text, upper, bytes, SQLITE_TRANSIENT);
	      }
	    }
	    break;
	  case TEXT_LEN_TOUPPER: {
	      const char *text = va_arg(ap, const char *);
	      unsigned bytes = va_arg(ap, unsigned);
	      argnum += 2;
	      if (text == NULL) {
		BIND_NULL(TEXT);
	      } else {
		char upper[bytes];
		unsigned i;
		for (i = 0; i != bytes; ++i)
		  upper[i] = toupper(text[i]);
		BIND_DEBUG(TEXT_LEN_TOUPPER, sqlite3_bind_text, "%s,%u,SQLITE_TRANSIENT", alloca_toprint(-1, upper, bytes), bytes);
		BIND_RETRY(sqlite3_bind_text, upper, bytes, SQLITE_TRANSIENT);
	      }
	    }
	    break;
	  case SERVAL_UUID_T: {
	      const serval_uuid_t *uuidp = va_arg(ap, const serval_uuid_t *);
	      ++argnum;
	      if (uuidp == NULL) {
		BIND_NULL(SERVAL_UUID_T);
	      } else {
		char uuid_str[UUID_STRLEN + 1];
		uuid_to_str(uuidp, uuid_str);
		BIND_DEBUG(SERVAL_UUID_T, sqlite3_bind_text, "%s,%u,SQLITE_TRANSIENT", uuid_str, UUID_STRLEN);
		BIND_RETRY(sqlite3_bind_text, uuid_str, UUID_STRLEN, SQLITE_TRANSIENT);
	      }
	    }
	    break;
#undef BIND_RETRY
	  default:
	    FATALF("at bind arg %u, unsupported bind code typ=0x%08x: %s", argnum, typ, sqlite3_sql(statement));
	}
	break;
    }
  }
  return 0;
}

int _sqlite_bind(struct __sourceloc __whence, int log_level, sqlite_retry_state *retry, sqlite3_stmt *statement, ...)
{
  va_list ap;
  va_start(ap, statement);
  int ret = _sqlite_vbind(__whence, log_level, retry, statement, ap);
  va_end(ap);
  return ret;
}

/* Prepare an SQL statement and bind some parameters.  Returns a pointer to the SQLite statement if
 * successful or NULL if an error occurs (which is logged at the given log level).
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
sqlite3_stmt *_sqlite_prepare_bind(struct __sourceloc __whence, int log_level, sqlite_retry_state *retry, const char *sqltext, ...)
{
  sqlite3_stmt *statement = _sqlite_prepare(__whence, log_level, retry, sqltext);
  if (statement != NULL) {
    va_list ap;
    va_start(ap, sqltext);
    int ret = _sqlite_vbind(__whence, log_level, retry, statement, ap);
    va_end(ap);
    if (ret == -1) {
      sqlite3_finalize(statement);
      statement = NULL;
    }
  }
  return statement;
}

int _sqlite_step(struct __sourceloc __whence, int log_level, sqlite_retry_state *retry, sqlite3_stmt *statement)
{
  IN();
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
  OUT();
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
static int _sqlite_exec(struct __sourceloc __whence, int log_level, sqlite_retry_state *retry, sqlite3_stmt *statement)
{
  if (!statement)
    return -1;
  int rowcount = 0;
  int stepcode;
  while ((stepcode = _sqlite_step(__whence, log_level, retry, statement)) == SQLITE_ROW)
    ++rowcount;
  sqlite3_finalize(statement);
  if (sqlite_trace_func())
    DEBUGF("rowcount=%d changes=%d", rowcount, sqlite3_changes(rhizome_db));
  return sqlite_code_ok(stepcode) ? rowcount : -1;
}

/* Execute an SQL command that returns no value.  If an error occurs then logs it at ERROR level and
 * returns -1.  Otherwise returns the number of rows changed by the command.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static int _sqlite_vexec_void(struct __sourceloc __whence, int log_level, sqlite_retry_state *retry, const char *sqltext, va_list ap)
{
  sqlite3_stmt *statement = _sqlite_prepare(__whence, log_level, retry, sqltext);
  if (!statement)
    return -1;
  if (_sqlite_vbind(__whence, log_level, retry, statement, ap) == -1)
    return -1;
  int rowcount = _sqlite_exec(__whence, log_level, retry, statement);
  if (rowcount == -1)
    return -1;
  if (rowcount)
    WARNF("void query unexpectedly returned %d row%s", rowcount, rowcount == 1 ? "" : "s");
  return sqlite3_changes(rhizome_db);
}

/* Convenience wrapper for executing an SQL command that returns no value.  If an error occurs then
 * logs it at ERROR level and returns -1.  Otherwise returns the number of rows changed by the
 * command.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int _sqlite_exec_void(struct __sourceloc __whence, int log_level, const char *sqltext, ...)
{
  va_list ap;
  va_start(ap, sqltext);
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  int ret = _sqlite_vexec_void(__whence, log_level, &retry, sqltext, ap);
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
int _sqlite_exec_void_retry(struct __sourceloc __whence, int log_level, sqlite_retry_state *retry, const char *sqltext, ...)
{
  va_list ap;
  va_start(ap, sqltext);
  int ret = _sqlite_vexec_void(__whence, log_level, retry, sqltext, ap);
  va_end(ap);
  return ret;
}

static int _sqlite_vexec_uint64(struct __sourceloc __whence, sqlite_retry_state *retry, uint64_t *result, const char *sqltext, va_list ap)
{
  sqlite3_stmt *statement = _sqlite_prepare(__whence, LOG_LEVEL_ERROR, retry, sqltext);
  if (!statement)
    return -1;
  if (_sqlite_vbind(__whence, LOG_LEVEL_ERROR, retry, statement, ap) == -1)
    return -1;
  int ret = 0;
  int rowcount = 0;
  int stepcode;
  while ((stepcode = _sqlite_step(__whence, LOG_LEVEL_ERROR, retry, statement)) == SQLITE_ROW) {
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
    DEBUGF("rowcount=%d changes=%d result=%"PRIu64, rowcount, sqlite3_changes(rhizome_db), *result);
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
int _sqlite_exec_uint64(struct __sourceloc __whence, uint64_t *result, const char *sqlformat,...)
{
  va_list ap;
  va_start(ap, sqlformat);
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  int ret = _sqlite_vexec_uint64(__whence, &retry, result, sqlformat, ap);
  va_end(ap);
  return ret;
}

/* Same as sqlite_exec_uint64() but if the statement cannot be executed because the database is
 * currently locked for updates, then will call sqlite_retry() on the supplied retry state variable
 * instead of its own, internal one.  If 'retry' is passed as NULL, then will not sleep and retry at
 * all in the event of a busy condition, but will log it as an error and return immediately.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int _sqlite_exec_uint64_retry(struct __sourceloc __whence, sqlite_retry_state *retry, uint64_t *result, const char *sqlformat,...)
{
  va_list ap;
  va_start(ap, sqlformat);
  int ret = _sqlite_vexec_uint64(__whence, retry, result, sqlformat, ap);
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

int _sqlite_vexec_strbuf_retry(struct __sourceloc __whence, sqlite_retry_state *retry, strbuf sb, const char *sqltext, va_list ap)
{
  sqlite3_stmt *statement = _sqlite_prepare(__whence, LOG_LEVEL_ERROR, retry, sqltext);
  if (!statement)
    return -1;
  if (_sqlite_vbind(__whence, LOG_LEVEL_ERROR, retry, statement, ap) == -1)
    return -1;
  int ret = 0;
  int rowcount = 0;
  int stepcode;
  while ((stepcode = _sqlite_step(__whence, LOG_LEVEL_ERROR, retry, statement)) == SQLITE_ROW) {
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

int _sqlite_blob_open_retry(
  struct __sourceloc __whence,
  int log_level,
  sqlite_retry_state *retry,
  const char *dbname,
  const char *tablename,
  const char *colname,
  sqlite3_int64 rowid,
  int flags,
  sqlite3_blob **blobp
)
{
  IN();
  while (1) {
    int code = sqlite3_blob_open(rhizome_db, dbname, tablename, colname, rowid, flags, blobp);
    switch (code) {
      case SQLITE_OK:
	if (retry)
	  _sqlite_retry_done(__whence, retry, "sqlite3_blob_open()");
	RETURN(code);
      case SQLITE_DONE:
      case SQLITE_ROW:
	LOGF(log_level, "sqlite3_blob_open() returned unexpected code (%d)", code);
	RETURN(-1);
      case SQLITE_BUSY:
      case SQLITE_LOCKED:
	if (retry && _sqlite_retry(__whence, retry, "sqlite3_blob_open()"))
	  break; // back to sqlite3_blob_open()
	// fall through...
      default:
	LOGF(log_level, "sqlite3_blob_open() failed (%d), %s", code, sqlite3_errmsg(rhizome_db));
	RETURN(-1);
    }
  }
  FATAL("not reached");
  OUT();
}

int _sqlite_blob_write_retry(
  struct __sourceloc __whence,
  int log_level,
  sqlite_retry_state *retry,
  sqlite3_blob *blob,
  const void *buf,
  int len,
  int offset
)
{
  IN();
  while (1) {
    int code = sqlite3_blob_write(blob, buf, len, offset);
    switch (code) {
      case SQLITE_OK:
	if (retry)
	  _sqlite_retry_done(__whence, retry, "sqlite3_blob_write()");
	RETURN(code);
      case SQLITE_DONE:
      case SQLITE_ROW:
	LOGF(log_level, "sqlite3_blob_write() returned unexpected code (%d)", code);
	RETURN(-1);
      case SQLITE_BUSY:
      case SQLITE_LOCKED:
	if (retry && _sqlite_retry(__whence, retry, "sqlite3_blob_write()"))
	  break; // back to sqlite3_blob_open()
	// fall through...
      default:
	LOGF(log_level, "sqlite3_blob_write() failed (%d), %s", code, sqlite3_errmsg(rhizome_db));
	RETURN(-1);
    }
  }
  FATAL("not reached");
  OUT();
}

int _sqlite_blob_close(struct __sourceloc __whence, int log_level, sqlite3_blob *blob)
{
  int code = sqlite3_blob_close(blob);
  if (code != SQLITE_OK)
    LOGF(log_level, "sqlite3_blob_close() failed: %s", sqlite3_errmsg(rhizome_db));
  return 0;
}

static uint64_t rhizome_database_used_bytes()
{
  uint64_t db_page_size;
  uint64_t db_page_count;
  uint64_t db_free_page_count;
  if (	sqlite_exec_uint64(&db_page_size, "PRAGMA page_size;", END) == -1LL
    ||  sqlite_exec_uint64(&db_page_count, "PRAGMA page_count;", END) == -1LL
    ||	sqlite_exec_uint64(&db_free_page_count, "PRAGMA free_count;", END) == -1LL
  ) {
    WHY("Cannot measure database used bytes");
    return UINT64_MAX;
  }
  return db_page_size * (db_page_count - db_free_page_count);
}

int rhizome_database_filehash_from_id(const rhizome_bid_t *bidp, uint64_t version, rhizome_filehash_t *hashp)
{
  IN();
  strbuf hash_sb = strbuf_alloca(RHIZOME_FILEHASH_STRLEN + 1);
  if (	 sqlite_exec_strbuf(hash_sb, "SELECT filehash FROM MANIFESTS WHERE version = ? AND id = ?;",
			    INT64, version, RHIZOME_BID_T, bidp, END) == -1)
    RETURN(-1);
  if (strbuf_overrun(hash_sb) || str_to_rhizome_filehash_t(hashp, strbuf_str(hash_sb)) == -1)
    RETURN(WHYF("malformed file hash for bid=%s version=%"PRIu64, alloca_tohex_rhizome_bid_t(*bidp), version));
  RETURN(0);
  OUT();
}

static int rhizome_delete_external(const char *id)
{
  // attempt to remove any external blob
  char blob_path[1024];
  if (!FORMF_RHIZOME_STORE_PATH(blob_path, "%s/%s", RHIZOME_BLOB_SUBDIR, id))
    return -1;
  if (unlink(blob_path) == -1) {
    if (errno != ENOENT)
      return WHYF_perror("unlink(%s)", alloca_str_toprint(blob_path));
    return 1;
  }
  if (config.debug.rhizome_store)
    DEBUGF("Deleted blob file %s", blob_path);
  return 0;
}

static int rhizome_delete_orphan_fileblobs_retry(sqlite_retry_state *retry)
{
  return sqlite_exec_void_retry_loglevel(LOG_LEVEL_WARN, retry,
      "DELETE FROM FILEBLOBS WHERE NOT EXISTS( SELECT 1 FROM FILES WHERE FILES.id = FILEBLOBS.id );",
      END);
}

int rhizome_remove_file_datainvalid(sqlite_retry_state *retry, const rhizome_filehash_t *hashp)
{
  int ret = 0;
  if (sqlite_exec_void_retry_loglevel(LOG_LEVEL_WARN, retry,
	  "DELETE FROM FILES WHERE id = ? and datavalid = 0;",
	  RHIZOME_FILEHASH_T, hashp, END
	) == -1
  )
    ret = -1;
  if (sqlite_exec_void_retry_loglevel(LOG_LEVEL_WARN, retry,
	  "DELETE FROM FILEBLOBS WHERE id = ? AND NOT EXISTS( SELECT 1 FROM FILES WHERE FILES.id = FILEBLOBS.id );",
	  RHIZOME_FILEHASH_T, hashp, END
	) == -1
  )
    ret = -1;
  return ret;
}

int rhizome_cleanup(struct rhizome_cleanup_report *report)
{
  IN();
  if (config.debug.rhizome && report == NULL)
    report = alloca(sizeof *report);
  if (report)
    bzero(report, sizeof *report);
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;

  /* For testing, it helps to speed up the cleanup process. */
  const char *orphan_payload_persist_ms = getenv("SERVALD_ORPHAN_PAYLOAD_PERSIST_MS");
  const char *invalid_payload_persist_ms = getenv("SERVALD_INVALID_PAYLOAD_PERSIST_MS");
  time_ms_t now = gettime_ms();
  time_ms_t insert_horizon_no_manifest = now - (orphan_payload_persist_ms ? atoi(orphan_payload_persist_ms) : 1000); // 1 second ago
  time_ms_t insert_horizon_not_valid = now - (invalid_payload_persist_ms ? atoi(invalid_payload_persist_ms) : 300000); // 5 minutes ago

  // Remove external payload files for stale, incomplete payloads.
  unsigned candidates = 0;
  sqlite3_stmt *statement = sqlite_prepare_bind(&retry,
      "SELECT id FROM FILES WHERE inserttime < ? AND datavalid = 0;",
      INT64, insert_horizon_not_valid, END);
  while (sqlite_step_retry(&retry, statement) == SQLITE_ROW) {
    candidates++;
    const char *id = (const char *) sqlite3_column_text(statement, 0);
    if (rhizome_delete_external(id) == 0 && report)
      ++report->deleted_stale_incoming_files;
  }
  sqlite3_finalize(statement);

  // Remove external payload files for old, unreferenced payloads.
  statement = sqlite_prepare_bind(&retry,
      "SELECT id FROM FILES WHERE inserttime < ? AND datavalid = 1 AND NOT EXISTS( SELECT 1 FROM MANIFESTS WHERE MANIFESTS.filehash = FILES.id);",
      INT64, insert_horizon_no_manifest, END);
  while (sqlite_step_retry(&retry, statement) == SQLITE_ROW) {
    candidates++;
    const char *id = (const char *) sqlite3_column_text(statement, 0);
    if (rhizome_delete_external(id) == 0 && report)
      ++report->deleted_orphan_files;
  }
  sqlite3_finalize(statement);

  // TODO Iterate through all files in RHIZOME_BLOB_SUBDIR and delete any which are no longer
  // referenced or are stale.  This could take a long time, so for scalability should be done
  // in an incremental background task.  See GitHub issue #50.
 
  // Remove payload records that are stale and incomplete or old and unreferenced.
  int ret;
  if (candidates) {
    ret = sqlite_exec_void_retry_loglevel(LOG_LEVEL_WARN, &retry,
	"DELETE FROM FILES WHERE inserttime < ? AND datavalid = 0;",
	INT64, insert_horizon_not_valid, END);
    if (report && ret > 0)
      report->deleted_stale_incoming_files += ret;
    ret = sqlite_exec_void_retry_loglevel(LOG_LEVEL_WARN, &retry,
	"DELETE FROM FILES WHERE inserttime < ? AND datavalid=1 AND NOT EXISTS( SELECT 1 FROM MANIFESTS WHERE MANIFESTS.filehash = FILES.id);",
	INT64, insert_horizon_no_manifest, END);
    if (report && ret > 0)
      report->deleted_orphan_files += ret;
  }

  // Remove payload blobs that are no longer referenced.
  if ((ret = rhizome_delete_orphan_fileblobs_retry(&retry)) > 0 && report)
    report->deleted_orphan_fileblobs += ret;

  if (config.debug.rhizome && report)
    DEBUGF("report deleted_stale_incoming_files=%u deleted_orphan_files=%u deleted_orphan_fileblobs=%u",
	report->deleted_stale_incoming_files,
	report->deleted_orphan_files,
	report->deleted_orphan_fileblobs
      );
  RETURN(0);
  OUT();
}

int rhizome_make_space(int group_priority, uint64_t bytes)
{
  /* Asked for impossibly large amount */
  const size_t margin = 65536;
  const uint64_t limit = config.rhizome.database_size > margin ? config.rhizome.database_size - margin : 1;
  if (bytes >= limit)
    return WHYF("bytes=%"PRIu64" is too large", bytes);

  uint64_t db_used = rhizome_database_used_bytes();
  if (db_used == UINT64_MAX)
    return -1;
  
  rhizome_cleanup(NULL);
  
  /* If there is already enough space now, then do nothing more */
  if (db_used + bytes <= limit)
    return 0;

  /* Okay, not enough space, so free up some. */
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  sqlite3_stmt *statement = sqlite_prepare_bind(&retry,
      "SELECT id,length FROM FILES WHERE highestpriority < ? ORDER BY DESCENDING LENGTH",
      INT, group_priority, END);
  if (!statement)
    return -1;
  while (db_used + bytes > limit && sqlite_step_retry(&retry, statement) == SQLITE_ROW) {
    /* Make sure we can drop this blob, and if so drop it, and recalculate number of bytes required */
    const char *id;
    /* Get values */
    if (sqlite3_column_type(statement, 0)==SQLITE_TEXT)
      id = (const char *) sqlite3_column_text(statement, 0);
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
    rhizome_filehash_t hash;
    if (str_to_rhizome_filehash_t(&hash, id) == -1)
      WHYF("invalid field FILES.id=%s -- ignored", alloca_str_toprint(id));
    else {
      /* Try to drop this file from storage, discarding any references that do not trump the
       * priority of this request.  The query done earlier should ensure this, but it doesn't hurt
       * to be paranoid, and it also protects against inconsistency in the database.
       */
      rhizome_drop_stored_file(&hash, group_priority + 1);
      if ((db_used = rhizome_database_used_bytes()) == UINT64_MAX)
	break;
    }
  }
  sqlite3_finalize(statement);

  //int64_t equal_priority_larger_file_space_used = sqlite_exec_int64("SELECT COUNT(length) FROM
  //FILES WHERE highestpriority = ? and length > ?", INT, group_priority, INT64, bytes, END);
  /* XXX Get rid of any equal priority files that are larger than this one */

  /* XXX Get rid of any higher priority files that are not relevant in this time or location */

  /* Couldn't make space */
  return WHY("Incomplete");
}

/* Drop the specified file from storage, and any manifests that reference it, provided that none of
 * those manifests are being retained at a higher priority than the maximum specified here.
 */
int rhizome_drop_stored_file(const rhizome_filehash_t *hashp, int maximum_priority)
{
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  sqlite3_stmt *statement = sqlite_prepare_bind(&retry, "SELECT id FROM MANIFESTS WHERE filehash = ?", RHIZOME_FILEHASH_T, hashp, END);
  if (!statement)
    return WHYF("Could not drop stored file id=%s", alloca_tohex_rhizome_filehash_t(*hashp));
  int can_drop = 1;
  while (sqlite_step_retry(&retry, statement) == SQLITE_ROW) {
    /* Find manifests for this file */
    if (sqlite3_column_type(statement, 0) != SQLITE_TEXT) {
      WHYF("Incorrect type in id column of manifests table");
      break;
    }
    const char *q_id = (char *) sqlite3_column_text(statement, 0);
    rhizome_bid_t bid;
    if (str_to_rhizome_bid_t(&bid, q_id) == -1) {
      WARNF("malformed column value MANIFESTS.id = %s -- skipped", alloca_str_toprint(q_id));
      continue;
    }
    /* Check that manifest is not part of a higher priority group.
	If so, we cannot drop the manifest or the file.
	However, we will keep iterating, as we can still drop any other manifests pointing to this file
	that are lower priority, and thus free up a little space. */
    int priority = rhizome_manifest_priority(&retry, &bid);
    if (priority == -1)
      WHYF("Cannot drop fileid=%s due to error, bid=%s", alloca_tohex_rhizome_filehash_t(*hashp), alloca_tohex_rhizome_bid_t(bid));
    else if (priority > maximum_priority) {
      WHYF("Cannot drop fileid=%s due to manifest priority, bid=%s", alloca_tohex_rhizome_filehash_t(*hashp), alloca_tohex_rhizome_bid_t(bid));
      can_drop = 0;
    } else {
      if (config.debug.rhizome)
	DEBUGF("removing stale manifests, groupmemberships");
      sqlite_exec_void_retry(&retry, "DELETE FROM MANIFESTS WHERE id = ?;", RHIZOME_BID_T, &bid, END);
      sqlite_exec_void_retry(&retry, "DELETE FROM KEYPAIRS WHERE public = ?;", RHIZOME_BID_T, &bid, END);
      sqlite_exec_void_retry(&retry, "DELETE FROM GROUPMEMBERSHIPS WHERE manifestid = ?;", RHIZOME_BID_T, &bid, END);
    }
  }
  sqlite3_finalize(statement);
  if (can_drop)
    rhizome_delete_file_retry(&retry, hashp);
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
int rhizome_store_manifest(rhizome_manifest *m)
{
  assert(m->finalised);

  // If we don't have the secret for this manifest, only store it if its self-signature is valid
  if (!m->haveSecret && !m->selfSigned)
    return WHY("Manifest is not signed, and I don't have the key.  Manifest might be forged or corrupt.");

  /* Bind BAR to data field */
  unsigned char bar[RHIZOME_BAR_BYTES];
  rhizome_manifest_to_bar(m,bar);

  /* Store the file (but not if it is already in the database) */
  assert(m->filesize != RHIZOME_SIZE_UNSET);
  if (m->filesize > 0 && !rhizome_exists(&m->filehash))
    return WHY("File should already be stored by now");

  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  if (sqlite_exec_void_retry(&retry, "BEGIN TRANSACTION;", END) == -1)
    return WHY("Failed to begin transaction");

  time_ms_t now = gettime_ms();

  // The INSERT OR REPLACE statement will delete a row with the same ID (primary key) if it exists,
  // so a new autoincremented ROWID will be allocated whether or not the manifest with this ID is
  // already in the table.  Other code depends on this property: that ROWID is monotonically
  // increasing with time and unique.
  sqlite3_stmt *stmt;
  if ((stmt = sqlite_prepare_bind(&retry,
	"INSERT OR REPLACE INTO MANIFESTS("
	  "id,"
	  "manifest,"
	  "version,"
	  "inserttime,"
	  "bar,"
	  "filesize,"
	  "filehash,"
	  "author,"
	  "service,"
	  "name,"
	  "sender,"
	  "recipient,"
	  "tail"
	") VALUES("
	  "?,?,?,?,?,?,?,?,?,?,?,?,?"
	");",
	RHIZOME_BID_T, &m->cryptoSignPublic,
	STATIC_BLOB, m->manifestdata, m->manifest_all_bytes,
	INT64, m->version,
	INT64, (int64_t) now,
	STATIC_BLOB, bar, RHIZOME_BAR_BYTES,
	INT64, m->filesize,
	RHIZOME_FILEHASH_T|NUL, m->filesize > 0 ? &m->filehash : NULL,
	// Only store the author if it is known to be authentic.
	SID_T|NUL, m->authorship == AUTHOR_AUTHENTIC ? &m->author : NULL,
	STATIC_TEXT, m->service,
	STATIC_TEXT|NUL, m->name,
	SID_T|NUL, m->has_sender ? &m->sender : NULL,
	SID_T|NUL, m->has_recipient ? &m->recipient : NULL,
	INT64, m->tail,
	END
      )
  ) == NULL)
    goto rollback;
  if (sqlite_step_retry(&retry, stmt) == -1)
    goto rollback;
  sqlite3_finalize(stmt);
  stmt = NULL;
  rhizome_manifest_set_rowid(m, sqlite3_last_insert_rowid(rhizome_db));
  rhizome_manifest_set_inserttime(m, now);

//  if (serverMode)
//    rhizome_sync_bundle_inserted(bar);

  // TODO remove old payload?
  
#if 0
  if (rhizome_manifest_get(m,"isagroup",NULL,0)!=NULL) {
    int closed=rhizome_manifest_get_ll(m,"closedgroup");
    if (closed<1) closed=0;
    int ciphered=rhizome_manifest_get_ll(m,"cipheredgroup");
    if (ciphered<1) ciphered=0;
    if ((stmt = sqlite_prepare_bind(&retry,
	    "INSERT OR REPLACE INTO GROUPLIST(id,closed,ciphered,priority) VALUES (?,?,?,?);",
	    RHIZOME_BID_T, &m->cryptoSignPublic,
	    INT, closed,
	    INT, ciphered,
	    INT, RHIZOME_PRIORITY_DEFAULT,
	    END
	  )
      ) == NULL
    )
      goto rollback;
    if (sqlite_step_retry(&retry, stmt) == -1)
      goto rollback;
    sqlite3_finalize(stmt);
    stmt = NULL;
  }
#endif

#if 0
  if (m->group_count > 0) {
    if ((stmt = sqlite_prepare(&retry, "INSERT OR REPLACE INTO GROUPMEMBERSHIPS (manifestid, groupid) VALUES (?, ?);")) == NULL)
      goto rollback;
    unsigned i;
    for (i=0;i<m->group_count;i++){
      if (sqlite_bind(&retry, stmt, RHIZOME_BID_T, &m->cryptoSignPublic, TEXT, m->groups[i]) == -1)
	goto rollback;
      if (sqlite_step_retry(&retry, stmt) == -1)
	goto rollback;
      sqlite3_reset(stmt);
    }
    sqlite3_finalize(stmt);
    stmt = NULL;
  }
#endif

  if (sqlite_exec_void_retry(&retry, "COMMIT;", END) != -1){
    // This message used in tests; do not modify or remove.
    INFOF("RHIZOME ADD MANIFEST service=%s bid=%s version=%"PRIu64,
	  m->service ? m->service : "NULL",
	  alloca_tohex_rhizome_bid_t(m->cryptoSignPublic),
	  m->version
	);
    monitor_announce_bundle(m);
    if (serverMode)
      rhizome_sync_announce();
    return 0;
  }
rollback:
  if (stmt)
    sqlite3_finalize(stmt);
  WHYF("Failed to store bundle bid=%s", alloca_tohex_rhizome_bid_t(m->cryptoSignPublic));
  sqlite_exec_void_retry(&retry, "ROLLBACK;", END);
  return -1;
}

/* The cursor struct must be zerofilled and the query parameters optionally filled in prior to
 * calling this function.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int rhizome_list_open(struct rhizome_list_cursor *c)
{
  if (config.debug.rhizome)
    DEBUGF("c=%p c->service=%s c->name=%s c->sender=%s c->recipient=%s c->rowid_since=%"PRIu64" c->_rowid_last=%"PRIu64,
	c,
	alloca_str_toprint(c->service),
	alloca_str_toprint(c->name),
	c->is_sender_set ? alloca_tohex_sid_t(c->sender) : "UNSET",
	c->is_recipient_set ? alloca_tohex_sid_t(c->recipient) : "UNSET",
	c->rowid_since,
	c->_rowid_last
      );
  IN();
  strbuf b = strbuf_alloca(1024);
  strbuf_sprintf(b, "SELECT id, manifest, version, inserttime, author, rowid FROM manifests WHERE 1=1");
  if (c->service)
    strbuf_puts(b, " AND service = @service");
  if (c->name)
    strbuf_puts(b, " AND name like @name");
  if (c->is_sender_set)
    strbuf_puts(b, " AND sender = @sender");
  if (c->is_recipient_set)
    strbuf_puts(b, " AND recipient = @recipient");
  if (c->rowid_since) {
    strbuf_puts(b, " AND rowid > @last ORDER BY rowid ASC"); // oldest first
    if (c->_rowid_last < c->rowid_since)
      c->_rowid_last = c->rowid_since;
  } else {
    if (c->_rowid_last)
      strbuf_puts(b, " AND rowid < @last");
    strbuf_puts(b, " ORDER BY rowid DESC"); // most recent first
  }
  if (strbuf_overrun(b))
    RETURN(WHYF("SQL command too long: %s", strbuf_str(b)));
  c->_retry = SQLITE_RETRY_STATE_DEFAULT;
  c->_statement = sqlite_prepare(&c->_retry, strbuf_str(b));
  if (c->_statement == NULL)
    RETURN(-1);
  if (c->service && sqlite_bind(&c->_retry, c->_statement, NAMED|STATIC_TEXT, "@service", c->service, END) == -1)
    goto failure;
  if (c->name && sqlite_bind(&c->_retry, c->_statement, NAMED|STATIC_TEXT, "@name", c->name, END) == -1)
    goto failure;
  if (c->is_sender_set && sqlite_bind(&c->_retry, c->_statement, NAMED|SID_T, "@sender", &c->sender, END) == -1)
    goto failure;
  if (c->is_recipient_set && sqlite_bind(&c->_retry, c->_statement, NAMED|SID_T, "@recipient", &c->recipient, END) == -1)
    goto failure;
  if (c->_rowid_last && sqlite_bind(&c->_retry, c->_statement, NAMED|INT64, "@last", c->_rowid_last, END) == -1)
    goto failure;
  c->manifest = NULL;
  c->_rowid_current = 0;
  RETURN(0);
  OUT();
failure:
  sqlite3_finalize(c->_statement);
  c->_statement = NULL;
  RETURN(-1);
  OUT();
}

/* Guaranteed to return manifests with monotonically descending rowid.  The first manifest will have
 * the greatest rowid.
 *
 * Returns 1 if a new manifest has been fetched from the list, in which case the cursor 'manifest'
 * field points to the fetched manifest.  Returns 0 if there are no more manifests in the list.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int rhizome_list_next(struct rhizome_list_cursor *c)
{
  if (config.debug.rhizome)
    DEBUGF("c=%p c->service=%s c->name=%s c->sender=%s c->recipient=%s c->rowid_since=%"PRIu64" c->_rowid_last=%"PRIu64,
	c,
	alloca_str_toprint(c->service),
	alloca_str_toprint(c->name),
	c->is_sender_set ? alloca_tohex_sid_t(c->sender) : "UNSET",
	c->is_recipient_set ? alloca_tohex_sid_t(c->recipient) : "UNSET",
	c->rowid_since,
	c->_rowid_last
      );
  IN();
  if (c->_statement == NULL && rhizome_list_open(c) == -1)
    RETURN(-1);
  while (1) {
    if (c->manifest) {
      rhizome_manifest_free(c->manifest);
      c->_rowid_current = 0;
      c->manifest = NULL;
    }
    if (sqlite_step_retry(&c->_retry, c->_statement) != SQLITE_ROW)
      break;
    assert(sqlite3_column_count(c->_statement) == 6);
    assert(sqlite3_column_type(c->_statement, 0) == SQLITE_TEXT);
    assert(sqlite3_column_type(c->_statement, 1) == SQLITE_BLOB);
    assert(sqlite3_column_type(c->_statement, 2) == SQLITE_INTEGER);
    assert(sqlite3_column_type(c->_statement, 3) == SQLITE_INTEGER);
    assert(sqlite3_column_type(c->_statement, 4) == SQLITE_TEXT || sqlite3_column_type(c->_statement, 4) == SQLITE_NULL);
    assert(sqlite3_column_type(c->_statement, 5) == SQLITE_INTEGER);
    uint64_t q_rowid = sqlite3_column_int64(c->_statement, 5);
    if (c->_rowid_current && (c->rowid_since ? q_rowid >= c->_rowid_current : q_rowid <= c->_rowid_current)) {
      WHYF("Query returned rowid=%"PRIu64" out of order (last was %"PRIu64") -- skipped", q_rowid, c->_rowid_current);
      continue;
    }
    c->_rowid_current = q_rowid;
    if (q_rowid <= c->rowid_since) {
      WHYF("Query returned rowid=%"PRIu64" <= rowid_since=%"PRIu64" -- skipped", q_rowid, c->rowid_since);
      continue;
    }
    const char *q_manifestid = (const char *) sqlite3_column_text(c->_statement, 0);
    const char *manifestblob = (char *) sqlite3_column_blob(c->_statement, 1);
    size_t manifestblobsize = sqlite3_column_bytes(c->_statement, 1); // must call after sqlite3_column_blob()
    uint64_t q_version = sqlite3_column_int64(c->_statement, 2);
    int64_t q_inserttime = sqlite3_column_int64(c->_statement, 3);
    const char *q_author = (const char *) sqlite3_column_text(c->_statement, 4);
    sid_t *author = NULL;
    if (q_author) {
      author = alloca(sizeof *author);
      if (str_to_sid_t(author, q_author) == -1) {
	WHYF("MANIFESTS row id=%s has invalid author column %s -- skipped", q_manifestid, alloca_str_toprint(q_author));
	continue;
      }
    }
    rhizome_manifest *m = c->manifest = rhizome_new_manifest();
    if (m == NULL)
      RETURN(-1);
    memcpy(m->manifestdata, manifestblob, manifestblobsize);
    m->manifest_all_bytes = manifestblobsize;
    if (   rhizome_manifest_parse(m) == -1
	|| !rhizome_manifest_validate(m)
    ) {
      WHYF("MANIFESTS row id=%s has invalid manifest blob -- skipped", q_manifestid);
      continue;
    }
    if (m->version != q_version) {
      WHYF("MANIFESTS row id=%s version=%"PRIu64" does not match manifest blob version=%"PRIu64" -- skipped",
	  q_manifestid, q_version, m->version);
      continue;
    }
    if (author)
      rhizome_manifest_set_author(m, author);
    rhizome_manifest_set_rowid(m, q_rowid);
    rhizome_manifest_set_inserttime(m, q_inserttime);
    if (c->service && !(m->service && strcasecmp(c->service, m->service) == 0))
      continue;
    if (c->is_sender_set && !(m->has_sender && cmp_sid_t(&c->sender, &m->sender) == 0))
      continue;
    if (c->is_recipient_set && !(m->has_recipient && cmp_sid_t(&c->recipient, &m->recipient) == 0))
      continue;
    assert(c->_rowid_current != 0);
    // Don't do rhizome_verify_author(m); too CPU expensive for a listing.  Save that for when
    // the bundle is extracted or exported.
    RETURN(1);
  }
  assert(c->_rowid_current == 0);
  RETURN(0);
  OUT();
}

void rhizome_list_commit(struct rhizome_list_cursor *c)
{
  if (config.debug.rhizome)
    DEBUGF("c=%p c->rowid_since=%"PRIu64" c->_rowid_current=%"PRIu64" c->_rowid_last=%"PRIu64,
	c, c->rowid_since, c->_rowid_current, c->_rowid_last);
  assert(c->_rowid_current != 0);
  if (c->_rowid_last == 0 || (c->rowid_since ? c->_rowid_current > c->_rowid_last : c->_rowid_current < c->_rowid_last))
    c->_rowid_last = c->_rowid_current;
}

void rhizome_list_release(struct rhizome_list_cursor *c)
{
  if (config.debug.rhizome)
    DEBUGF("c=%p", c);
  if (c->manifest) {
    rhizome_manifest_free(c->manifest);
    c->_rowid_current = 0;
    c->manifest = NULL;
  }
  if (c->_statement) {
    sqlite3_finalize(c->_statement);
    c->_statement = NULL;
  }
}

void rhizome_bytes_to_hex_upper(unsigned const char *in, char *out, int byteCount)
{
  (void) tohex(out, byteCount * 2, in);
}

int rhizome_update_file_priority(const char *fileid)
{
  /* work out the highest priority of any referrer */
  uint64_t highestPriority = 0;
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  if (sqlite_exec_uint64_retry(&retry, &highestPriority,
	"SELECT max(grouplist.priority) FROM MANIFESTS, GROUPMEMBERSHIPS, GROUPLIST"
	" WHERE MANIFESTS.filehash = ?"
	"   AND GROUPMEMBERSHIPS.manifestid = MANIFESTS.id"
	"   AND GROUPMEMBERSHIPS.groupid = GROUPLIST.id;",
	TEXT_TOUPPER, fileid, END
      ) == -1
  )
    return -1;
  if (sqlite_exec_void_retry(&retry,
	"UPDATE files SET highestPriority = ? WHERE id = ?;",
	INT64, highestPriority, TEXT_TOUPPER, fileid, END
      ) == -1
  )
    return WHYF("cannot update priority for fileid=%s", fileid);
  return 0;
}

/* Search the database for a manifest having the same name and payload content, and if the version
 * is known, having the same version.  Returns RHIZOME_BUNDLE_STATUS_DUPLICATE if a duplicate is found
 * (setting *found to point to the duplicate's manifest), returns RHIZOME_BUNDLE_STATUS_NEW if no
 * duplicate is found (leaving *found unchanged).  Returns -1 on error (leaving *found undefined).
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
enum rhizome_bundle_status rhizome_find_duplicate(const rhizome_manifest *m, rhizome_manifest **found)
{
  if (m->service == NULL)
    return WHY("Manifest has no service");
  char sqlcmd[1024];
  strbuf b = strbuf_local(sqlcmd, sizeof sqlcmd);
  strbuf_puts(b, "SELECT id, manifest, author FROM manifests WHERE filesize = ? AND service = ?");
  assert(m->filesize != RHIZOME_SIZE_UNSET);
  if (m->filesize > 0)
    strbuf_puts(b, " AND filehash = ?");
  if (m->name)
    strbuf_puts(b, " AND name = ?");
  if (m->has_sender)
    strbuf_puts(b, " AND sender = ?");
  if (m->has_recipient)
    strbuf_puts(b, " AND recipient = ?");
  if (strbuf_overrun(b))
    return WHYF("SQL command too long: %s", strbuf_str(b));
  int ret = RHIZOME_BUNDLE_STATUS_NEW;
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  sqlite3_stmt *statement = sqlite_prepare_bind(&retry, strbuf_str(b), INT64, m->filesize, STATIC_TEXT, m->service, END);
  if (!statement)
    return -1;
  int field = 2;
  if (m->filesize > 0)
    sqlite_bind(&retry, statement, INDEX|RHIZOME_FILEHASH_T, ++field, &m->filehash, END);
  if (m->name)
    sqlite_bind(&retry, statement, INDEX|STATIC_TEXT, ++field, m->name, END);
  if (m->has_sender)
    sqlite_bind(&retry, statement, INDEX|SID_T, ++field, &m->sender, END);
  if (m->has_recipient)
    sqlite_bind(&retry, statement, INDEX|SID_T, ++field, &m->recipient, END);

  int rows = 0;
  while (sqlite_step_retry(&retry, statement) == SQLITE_ROW) {
    ++rows;
    if (config.debug.rhizome)
      DEBUGF("Row %d", rows);
    rhizome_manifest *blob_m = rhizome_new_manifest();
    if (blob_m == NULL) {
      ret = WHY("Out of manifests");
      break;
    }
    const unsigned char *q_manifestid = sqlite3_column_text(statement, 0);
    const char *manifestblob = (char *) sqlite3_column_blob(statement, 1);
    size_t manifestblobsize = sqlite3_column_bytes(statement, 1); // must call after sqlite3_column_blob()
    memcpy(blob_m->manifestdata, manifestblob, manifestblobsize);
    blob_m->manifest_all_bytes = manifestblobsize;
    if (   rhizome_manifest_parse(blob_m) == -1
	|| !rhizome_manifest_validate(blob_m)
       ) {
      WARNF("MANIFESTS row id=%s has invalid manifest blob -- skipped", q_manifestid);
      goto next;
    }
    if (!rhizome_manifest_verify(blob_m)) {
      WARNF("MANIFESTS row id=%s fails verification -- skipped", q_manifestid);
      goto next;
    }
    const char *q_author = (const char *) sqlite3_column_text(statement, 2);
    if (q_author) {
      sid_t author;
      if (str_to_sid_t(&author, q_author) == -1)
	WARNF("MANIFESTS row id=%s has invalid author=%s -- ignored", q_manifestid, alloca_str_toprint(q_author));
      else
	rhizome_manifest_set_author(blob_m, &author);
    }
    // check that we can re-author this manifest
    rhizome_authenticate_author(blob_m);
    if (m->authorship != AUTHOR_AUTHENTIC)
      goto next;
    *found = blob_m;
    if (config.debug.rhizome)
      DEBUGF("Found duplicate payload, %s", q_manifestid);
    ret = RHIZOME_BUNDLE_STATUS_DUPLICATE;
    break;
next:
    if (blob_m)
      rhizome_manifest_free(blob_m);
  }
  sqlite3_finalize(statement);
  return ret;
}

static int unpack_manifest_row(rhizome_manifest *m, sqlite3_stmt *statement)
{
  const char *q_id = (const char *) sqlite3_column_text(statement, 0);
  const char *q_blob = (char *) sqlite3_column_blob(statement, 1);
  uint64_t q_version = sqlite3_column_int64(statement, 2);
  int64_t q_inserttime = sqlite3_column_int64(statement, 3);
  const char *q_author = (const char *) sqlite3_column_text(statement, 4);
  size_t q_blobsize = sqlite3_column_bytes(statement, 1); // must call after sqlite3_column_blob()
  uint64_t q_rowid = sqlite3_column_int64(statement, 5);
  memcpy(m->manifestdata, q_blob, q_blobsize);
  m->manifest_all_bytes = q_blobsize;
  if (rhizome_manifest_parse(m) == -1 || !rhizome_manifest_validate(m))
    return WHYF("Manifest bid=%s in database but invalid", q_id);
  if (q_author) {
    sid_t author;
    if (str_to_sid_t(&author, q_author) == -1)
      WARNF("MANIFESTS row id=%s has invalid author=%s -- ignored", q_id, alloca_str_toprint(q_author));
    else
      rhizome_manifest_set_author(m, &author);
  }
  if (m->version != q_version)
    WARNF("Version mismatch, manifest is %"PRIu64", database is %"PRIu64, m->version, q_version);
  rhizome_manifest_set_rowid(m, q_rowid);
  rhizome_manifest_set_inserttime(m, q_inserttime);
  return 0;
}

/* Retrieve a manifest from the database, given its Bundle ID.
 *
 * Returns 0 if manifest is found
 * Returns 1 if manifest is not found
 * Returns -1 on error
 * Caller is responsible for allocating and freeing rhizome_manifest
 */
int rhizome_retrieve_manifest(const rhizome_bid_t *bidp, rhizome_manifest *m)
{
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  sqlite3_stmt *statement = sqlite_prepare_bind(&retry,
      "SELECT id, manifest, version, inserttime, author, rowid FROM manifests WHERE id = ?",
      RHIZOME_BID_T, bidp,
      END);
  if (!statement)
    return -1;
  int ret = 1;
  if (sqlite_step_retry(&retry, statement) == SQLITE_ROW)
    ret = unpack_manifest_row(m, statement);
  else
    INFOF("Manifest id=%s not found", alloca_tohex_rhizome_bid_t(*bidp));
  sqlite3_finalize(statement);
  return ret;
}

/* Retrieve any manifest from the database whose Bundle ID starts with the given prefix.
 *
 * Returns 0 if a manifest is found
 * Returns 1 if no manifest is found
 * Returns -1 on error
 * Caller is responsible for allocating and freeing rhizome_manifest
 */
int rhizome_retrieve_manifest_by_prefix(const unsigned char *prefix, unsigned prefix_len, rhizome_manifest *m)
{
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  const unsigned prefix_strlen = prefix_len * 2;
  char like[prefix_strlen + 2];
  tohex(like, prefix_strlen, prefix);
  like[prefix_strlen] = '%';
  like[prefix_strlen + 1] = '\0';
  sqlite3_stmt *statement = sqlite_prepare_bind(&retry,
      "SELECT id, manifest, version, inserttime, author, rowid FROM manifests WHERE id like ?",
      TEXT, like,
      END);
  if (!statement)
    return -1;
  int ret = 1;
  if (sqlite_step_retry(&retry, statement) == SQLITE_ROW)
    ret = unpack_manifest_row(m, statement);
  else
    INFOF("Manifest with id prefix=`%s` not found", like);
  sqlite3_finalize(statement);
  return ret;
}

static int rhizome_delete_manifest_retry(sqlite_retry_state *retry, const rhizome_bid_t *bidp)
{
  sqlite3_stmt *statement = sqlite_prepare_bind(retry,
      "DELETE FROM manifests WHERE id = ?",
      RHIZOME_BID_T, bidp,
      END);
  if (!statement)
    return -1;
  if (_sqlite_exec(__WHENCE__, LOG_LEVEL_ERROR, retry, statement) == -1)
    return -1;
  return sqlite3_changes(rhizome_db) ? 0 : 1;
}

static int rhizome_delete_file_retry(sqlite_retry_state *retry, const rhizome_filehash_t *hashp)
{
  int ret = 0;
  rhizome_delete_external(alloca_tohex_rhizome_filehash_t(*hashp));
  sqlite3_stmt *statement = sqlite_prepare_bind(retry, "DELETE FROM files WHERE id = ?", RHIZOME_FILEHASH_T, hashp, END);
  if (!statement || sqlite_exec_retry(retry, statement) == -1)
    ret = -1;
  statement = sqlite_prepare_bind(retry, "DELETE FROM fileblobs WHERE id = ?", RHIZOME_FILEHASH_T, hashp, END);
  if (!statement || sqlite_exec_retry(retry, statement) == -1)
    ret = -1;
  return ret == -1 ? -1 : sqlite3_changes(rhizome_db) ? 0 : 1;
}

static int rhizome_delete_payload_retry(sqlite_retry_state *retry, const rhizome_bid_t *bidp)
{
  strbuf fh = strbuf_alloca(RHIZOME_FILEHASH_STRLEN + 1);
  int rows = sqlite_exec_strbuf_retry(retry, fh, "SELECT filehash FROM manifests WHERE id = ?", RHIZOME_BID_T, bidp, END);
  if (rows == -1)
    return -1;
  rhizome_filehash_t hash;
  if (str_to_rhizome_filehash_t(&hash, strbuf_str(fh)) == -1)
    return WHYF("invalid field FILES.id=%s", strbuf_str(fh));
  if (rows && rhizome_delete_file_retry(retry, &hash) == -1)
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
int rhizome_delete_bundle(const rhizome_bid_t *bidp)
{
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  if (rhizome_delete_payload_retry(&retry, bidp) == -1)
    return -1;
  if (rhizome_delete_manifest_retry(&retry, bidp) == -1)
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
int rhizome_delete_manifest(const rhizome_bid_t *bidp)
{
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  return rhizome_delete_manifest_retry(&retry, bidp);
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
int rhizome_delete_payload(const rhizome_bid_t *bidp)
{
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  return rhizome_delete_payload_retry(&retry, bidp);
}

/* Remove a file from the database, given its file hash.
 *
 * Returns 0 if file is found and removed
 * Returns 1 if file is not found
 * Returns -1 on error
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int rhizome_delete_file(const rhizome_filehash_t *hashp)
{
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  return rhizome_delete_file_retry(&retry, hashp);
}

static int is_interesting(const char *id_hex, uint64_t version)
{
  IN();
  int ret=1;

  // do we have this bundle [or later]?
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  sqlite3_stmt *statement = sqlite_prepare_bind(&retry,
    "SELECT filehash FROM MANIFESTS WHERE id LIKE ? AND version >= ?",
    TEXT_TOUPPER, id_hex,
    INT64, version,
    END);
  if (!statement)
    RETURN(-1);
  if (sqlite_step_retry(&retry, statement) == SQLITE_ROW){
    const char *q_filehash = (const char *) sqlite3_column_text(statement, 0);
    ret=0;
    if (q_filehash && *q_filehash) {
      rhizome_filehash_t hash;
      if (str_to_rhizome_filehash_t(&hash, q_filehash) == -1) {
	WARNF("invalid field MANIFESTS.filehash=%s -- ignored", alloca_str_toprint(q_filehash));
	ret = 1;
      } else if (!rhizome_exists(&hash))
	ret = 1;
    }
  }
  sqlite3_finalize(statement);
  RETURN(ret);
  OUT();
}

int rhizome_is_bar_interesting(const unsigned char *bar)
{
  uint64_t version = rhizome_bar_version(bar);
  char id_hex[RHIZOME_BAR_PREFIX_BYTES *2 + 2];
  tohex(id_hex, RHIZOME_BAR_PREFIX_BYTES * 2, &bar[RHIZOME_BAR_PREFIX_OFFSET]);
  strcat(id_hex, "%");
  return is_interesting(id_hex, version);
}

int rhizome_is_manifest_interesting(rhizome_manifest *m)
{
  return is_interesting(alloca_tohex_rhizome_bid_t(m->cryptoSignPublic), m->version);
}
