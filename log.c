/*
Serval DNA logging.
Copyright 2013 Serval Project Inc.

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

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <time.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <libgen.h>
#include <dirent.h>
#include <assert.h>

#include "log.h"
#include "net.h"
#include "os.h"
#include "conf.h"
#include "str.h"
#include "strbuf.h"
#include "strbuf_helpers.h"
#include "xprintf.h"

int serverMode = 0;
const struct __sourceloc __whence = __NOWHERE__;

#define NO_FILE ((FILE *)1)

/* The _log_state structure records the persistent state associated with a single log output
 * destination.  The state is only persistent for the lifetime of the process (eg, while the daemon
 * is running), and is not stored anywhere else.  It is initially zerofilled.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
struct _log_state {
  /* Whether the software version has been logged in the current file yet.  */
  bool_t version_logged;
  /* The time stamp of the last logged message, used to detect when the date advances so that
  * the date can be logged.  */
  struct tm last_tm;
  /* Whether the current configuration has been logged in the current file yet.  */
  bool_t config_logged;
};

/* The _log_iterator structure is a transient structure that is used to iterate over all the
 * supported log output destinations.  Generally, one of these is created (as an auto variable)
 * every time a log message is generated, and destroyed immediately after the message has been sent
 * to all the log outputs.
 *
 * The log iterator is controlled using various _log_iterator_xxx() functions.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
typedef struct _log_iterator {
  const struct config_log_format *config;
  struct _log_state *state;
  struct timeval tv;
  struct tm tm;
  XPRINTF xpf;
  time_t file_start_time;
} _log_iterator;

/* Static variables for sending log output to a file.
 *
 * The _log_file_strbuf is used to accumulate log messages before the log file is open and ready for
 * writing.
 */
const char *_log_file_path;
char _log_file_path_buf[400];
static FILE *_log_file = NULL;
static void _open_log_file(_log_iterator *);
static void _rotate_log_file(_log_iterator *it);
static void _flush_log_file();
struct _log_state state_file;
struct config_log_format config_file;
time_t _log_file_start_time;
static char _log_file_buf[8192];
static struct strbuf _log_file_strbuf = STRUCT_STRBUF_EMPTY;

#ifdef ANDROID
/* Static variables for sending log output to the Android log.
 *
 * The _android_strbuf is used to accumulate a single log line before printing to Android's logging
 * API.
 */
#include <android/log.h>
struct _log_state state_android;
static char _log_android_buf[1024];
static struct strbuf _android_strbuf;
#endif // ANDROID

/* Static variables for sending log output to standard error.
 */
static FILE *logfile_stderr = NULL;
struct _log_state state_stderr;
static void _open_log_stderr();
static void _flush_log_stderr();

/* Primitive operations for _log_iterator structures.
 */

static void _log_iterator_start(_log_iterator *it)
{
  memset(it, 0, sizeof *it);
  gettimeofday(&it->tv, NULL);
  localtime_r(&it->tv.tv_sec, &it->tm);
}

static void _log_iterator_rewind(_log_iterator *it)
{
  it->config = NULL;
  it->state = NULL;
}

static void _log_iterator_advance_to_file(_log_iterator *it)
{
  cf_dfl_config_log_format(&config_file);
  cf_cpy_config_log_format(&config_file, &config.log.file);
  it->config = &config_file;
  it->state = &state_file;
}

#ifdef ANDROID
static void _log_iterator_advance_to_android(_log_iterator *it)
{
  it->config = &config.log.android;
  it->state = &state_android;
}
#endif // ANDROID

static void _log_iterator_advance_to_stderr(_log_iterator *it)
{
  it->config = &config.log.console;
  it->state = &state_stderr;
}

static int _log_iterator_advance(_log_iterator *it)
{
  if (it->config == NULL) {
    _log_iterator_advance_to_file(it);
    return 1;
  }
  if (it->config == &config_file) {
#ifdef ANDROID
    _log_iterator_advance_to_android(it);
    return 1;
  }
  if (it->config == &config.log.android) {
#endif // ANDROID
    _log_iterator_advance_to_stderr(it);
    return 1;
  }
  return 0;
}

static int _log_enabled(_log_iterator *it)
{
  if (it->config == &config_file) {
    _open_log_file(it); // puts initial INFO message(s) at head of log file
    if (_log_file == NO_FILE)
      return 0;
  }
  else if (it->config == &config.log.console) {
    _open_log_stderr();
    if (logfile_stderr == NULL || logfile_stderr == NO_FILE)
      return 0;
  }
  return 1;
}

static void _log_prefix_level(_log_iterator *it, int level)
{
  const char *levelstr = "UNKWN:";
  switch (level) {
    case LOG_LEVEL_FATAL: levelstr = "FATAL:"; break;
    case LOG_LEVEL_ERROR: levelstr = "ERROR:"; break;
    case LOG_LEVEL_WARN:  levelstr = "WARN:"; break;
    case LOG_LEVEL_HINT:  levelstr = "HINT:"; break;
    case LOG_LEVEL_INFO:  levelstr = "INFO:"; break;
    case LOG_LEVEL_DEBUG: levelstr = "DEBUG:"; break;
  }
  xprintf(it->xpf, "%-6.6s", levelstr);
}

static void _log_prefix(_log_iterator *it, int level)
{
  if (it->config == &config_file) {
    if (strbuf_is_empty(&_log_file_strbuf))
      strbuf_init(&_log_file_strbuf, _log_file_buf, sizeof _log_file_buf);
    else if (strbuf_len(&_log_file_strbuf))
      strbuf_putc(&_log_file_strbuf, '\n');
    it->xpf = XPRINTF_STRBUF(&_log_file_strbuf);
    _log_prefix_level(it, level);
  }
#ifdef ANDROID
  else if (it->config == &config.log.android) {
    strbuf_init(&_android_strbuf, _log_android_buf, sizeof _log_android_buf);
    it->xpf = XPRINTF_STRBUF(&_android_strbuf);
  }
#endif // ANDROID
  else if (it->config == &config.log.console) {
    it->xpf = XPRINTF_STDIO(logfile_stderr);
    _log_prefix_level(it, level);
  }
  else
    abort();
  if (it->config->show_pid)
    xprintf(it->xpf, "[%5u] ", getpid());
  if (it->config->show_time) {
    if (it->tv.tv_sec == 0) {
      xputs("NOTIME______ ", it->xpf);
    } else {
      char buf[50];
      if (strftime(buf, sizeof buf, "%T", &it->tm) == 0)
	xputs("EMPTYTIME___ ", it->xpf);
      else
	xprintf(it->xpf, "%s.%03u ", buf, it->tv.tv_usec / 1000);
    }
  }
}

static const char *_trimbuildpath(const char *path)
{
  /* Remove common path prefix */
  int lastsep = 0;
  int i;
  for (i = 0; __FILE__[i] && path[i]; ++i) {
    if (i && path[i - 1] == '/')
      lastsep = i;
    if (__FILE__[i] != path[i])
      break;
  }
  return &path[lastsep];
}

static void _log_prefix_whence(_log_iterator *it, struct __sourceloc whence)
{
  if (whence.file && whence.file[0]) {
    xprintf(it->xpf, "%s", _trimbuildpath(whence.file));
    if (whence.line)
      xprintf(it->xpf, ":%u", whence.line);
    if (whence.function)
      xprintf(it->xpf, ":%s()", whence.function);
    xputs("  ", it->xpf);
  } else if (whence.function && whence.function[0]) {
    xprintf(it->xpf, "%s()  ", whence.function);
  }
}

static void _log_end_line(_log_iterator *it, int level)
{
#ifdef ANDROID
  if (it->config == &config.log.android) {
    int alevel = ANDROID_LOG_UNKNOWN;
    switch (level) {
      case LOG_LEVEL_FATAL: alevel = ANDROID_LOG_FATAL; break;
      case LOG_LEVEL_ERROR: alevel = ANDROID_LOG_ERROR; break;
      case LOG_LEVEL_WARN:  alevel = ANDROID_LOG_WARN; break;
      case LOG_LEVEL_HINT:
      case LOG_LEVEL_INFO:  alevel = ANDROID_LOG_INFO; break;
      case LOG_LEVEL_DEBUG: alevel = ANDROID_LOG_DEBUG; break;
      default: abort();
    }
    __android_log_print(alevel, "servald", "%s", _log_android_buf);
  }
  else
#endif // ANDROID
  if (it->config == &config.log.console) {
    fputc('\n', logfile_stderr);
  }
}

static void _log_flush(_log_iterator *it)
{
  if (it->config == &config_file) {
    _flush_log_file();
  }
  else if (it->config == &config.log.console) {
    _flush_log_stderr();
  }
}

static void _log_vprintf_nl(_log_iterator *it, int level, const char *fmt, va_list ap)
{
  _log_prefix(it, level);
  vxprintf(it->xpf, fmt, ap);
  _log_end_line(it, level);
}

static void _log_printf_nl(_log_iterator *it, int level, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  _log_vprintf_nl(it, level, fmt, ap);
  va_end(ap);
}

static void _log_current_datetime(_log_iterator *it, int level)
{
  char buf[50];
  if (strftime(buf, sizeof buf, "%F %T %z", &it->tm)) {
    _log_printf_nl(it, level, "Local date/time: %s", buf);
    it->state->last_tm = it->tm;
  }
}

static void _log_software_version(_log_iterator *it, int level)
{
  _log_printf_nl(it, level, "Serval DNA version: %s", version_servald);
  it->state->version_logged = 1;
}

static int _log_current_config(_log_iterator *it, int level)
{
  if (!cf_limbo) {
    struct cf_om_node *root = NULL;
    int ret = cf_fmt_config_main(&root, &config);
    if (ret == CFERROR) {
      _log_printf_nl(it, level, "Cannot dump current configuration: cf_fmt_config_main() returned CFERROR");
    } else {
      _log_printf_nl(it, level, "Current configuration:");
      struct cf_om_iterator oit;
      int empty = 1;
      for (cf_om_iter_start(&oit, root); oit.node; cf_om_iter_next(&oit)) {
	if (oit.node->text && oit.node->line_number) {
	  empty = 0;
	  _log_printf_nl(it, level, "   %s=%s", oit.node->fullkey, oit.node->text);
	}
      }
      if (empty)
	_log_printf_nl(it, level, "   (empty)");
    }
    cf_om_free_node(&root);
    it->state->config_logged = 1;
  }
  return 1;
}

static void _log_update(_log_iterator *it)
{
  if ( it->tm.tm_mday != it->state->last_tm.tm_mday
    || it->tm.tm_mon != it->state->last_tm.tm_mon
    || it->tm.tm_year != it->state->last_tm.tm_year
  )
    _log_current_datetime(it, LOG_LEVEL_INFO);
  if (!it->state->version_logged)
    _log_software_version(it, LOG_LEVEL_INFO);
  if (it->config->dump_config && !it->state->config_logged)
    _log_current_config(it, LOG_LEVEL_INFO);
}

static int _log_iterator_next(_log_iterator *it, int level)
{
  assert(level >= LOG_LEVEL_SILENT);
  assert(level <= LOG_LEVEL_FATAL);
  _log_end_line(it, level);
  _log_flush(it);
  while (_log_iterator_advance(it)) {
    if (level >= it->config->level && _log_enabled(it)) {
      _log_update(it);
      _log_prefix(it, level);
      return 1;
    }
  }
  return 0;
}

static void _log_iterator_vprintf_nl(_log_iterator *it, int level, struct __sourceloc whence, const char *fmt, va_list ap)
{
  _log_iterator_rewind(it);
  while (_log_iterator_next(it, level)) {
    _log_prefix_whence(it, whence);
    va_list ap1;
    va_copy(ap1, ap);
    vxprintf(it->xpf, fmt, ap1);
    va_end(ap1);
  }
}

static void _log_iterator_printf_nl(_log_iterator *it, int level, struct __sourceloc whence, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  _log_iterator_vprintf_nl(it, level, whence, fmt, ap);
  va_end(ap);
}

static void _logs_vprintf_nl(int level, struct __sourceloc whence, const char *fmt, va_list ap)
{
  _log_iterator it;
  _log_iterator_start(&it);
  _log_iterator_vprintf_nl(&it, level, whence, fmt, ap);
}

static void _logs_printf_nl(int level, struct __sourceloc whence, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  _logs_vprintf_nl(level, whence, fmt, ap);
  va_end(ap);
}

const char *log_file_directory_path()
{
  return config.log.file.directory_path;
}

static void _compute_file_start_time(_log_iterator *it)
{
  if (it->file_start_time == 0) {
    assert(!cf_limbo);
    assert(it->tv.tv_sec != 0);
    it->file_start_time = it->tv.tv_sec;
    if (config.log.file.duration)
      it->file_start_time -= it->file_start_time % config.log.file.duration;
  }
}

static void _open_log_file(_log_iterator *it)
{
  assert(it->state == &state_file);
  if (_log_file != NO_FILE) {
    if (_log_file_path == NULL)
      _log_file_path = getenv("SERVALD_LOG_FILE");
    if (_log_file_path == NULL && !cf_limbo) {
      strbuf sbfile = strbuf_local(_log_file_path_buf, sizeof _log_file_path_buf);
      strbuf_path_join(sbfile, serval_instancepath(), log_file_directory_path(), NULL);
      _compute_file_start_time(it);
      if (config.log.file.path[0]) {
	strbuf_path_join(sbfile, config.log.file.path, NULL);
      } else {
	struct tm tm;
	(void)localtime_r(&it->file_start_time, &tm);
	strbuf_append_strftime(sbfile, "/serval-%Y%m%d%H%M%S.log", &tm);
      }
      if (strbuf_overrun(sbfile)) {
	_log_file = NO_FILE;
	_logs_printf_nl(LOG_LEVEL_ERROR, __HERE__, "Cannot form log file name - buffer overrun");
      } else {
	_log_file_start_time = it->file_start_time;
	_log_file_path = strbuf_str(sbfile);
      }
    }
    if (!_log_file) {
      if (_log_file_path == NULL) {
	if (cf_limbo)
	  return;
	_log_file = NO_FILE;
	_logs_printf_nl(serverMode ? LOG_LEVEL_WARN : LOG_LEVEL_INFO, __NOWHERE__, "No log file configured");
      } else {
	// Create the new log file.
	size_t dirsiz = strlen(_log_file_path) + 1;
	char _dir[dirsiz];
	strcpy(_dir, _log_file_path);
	const char *dir = dirname(_dir); // modifies _dir[]
	if (mkdirs(dir, 0700) != -1 && (_log_file = fopen(_log_file_path, "a"))) {
	  setlinebuf(_log_file);
	  memset(it->state, 0, sizeof *it->state);
	  // The first line in every log file must be the starting time stamp.  (After that, it is up
	  // to _log_update() to insert other mandatory messages in any suitable order.)
	  _log_current_datetime(it, LOG_LEVEL_INFO);
	  _logs_printf_nl(LOG_LEVEL_INFO, __NOWHERE__, "Logging to %s (fd %d)", _log_file_path, fileno(_log_file));
	  // Update the log symlink to point to the latest log file.
	  strbuf sbsymlink = strbuf_alloca(400);
	  strbuf_path_join(sbsymlink, serval_instancepath(), "serval.log", NULL);
	  if (strbuf_overrun(sbsymlink))
	    _logs_printf_nl(LOG_LEVEL_ERROR, __HERE__, "Cannot form log symlink name - buffer overrun");
	  else {
	    const char *f = _log_file_path;
	    const char *s = strbuf_str(sbsymlink);
	    const char *relpath = f;
	    for (; *f && *f == *s; ++f, ++s)
	      if (*f == '/')
		relpath = f;
	    while (*relpath == '/')
	      ++relpath;
	    while (*s == '/')
	      ++s;
	    if (strchr(s, '/'))
	      relpath = _log_file_path;
	    unlink(strbuf_str(sbsymlink));
	    if (symlink(relpath, strbuf_str(sbsymlink)) == -1)
	      _logs_printf_nl(LOG_LEVEL_ERROR, __HERE__, "Cannot symlink %s to %s - %s [errno=%d]", strbuf_str(sbsymlink), relpath, strerror(errno), errno);
	  }
	  // Expire old log files.
	  size_t pathsiz = strlen(_log_file_path) + 1;
	  char path[pathsiz];
	  while (1) {
	    strcpy(path, _log_file_path);
	    const char *base = basename(path); // modifies path[]
	    DIR *d = opendir(dir);
	    if (!d) {
	      _logs_printf_nl(LOG_LEVEL_ERROR, __HERE__, "Cannot expire log files: opendir(%s) - %s [errno=%d]", dir, strerror(errno), errno);
	      break;
	    }
	    struct dirent oldest;
	    memset(&oldest, 0, sizeof oldest);
	    unsigned count = 0;
	    while (1) {
	      struct dirent ent;
	      struct dirent *ep;
	      int err = readdir_r(d, &ent, &ep);
	      if (err) {
		_logs_printf_nl(LOG_LEVEL_ERROR, __HERE__, "Cannot expire log files: r_readdir(%s) - %s [errno=%d]", dir, strerror(err), err);
		break;
	      }
	      if (!ep)
		break;
	      const char *e;
	      if (   str_startswith(ent.d_name, "serval-", &e)
		  && isdigit(e[0]) && isdigit(e[1]) && isdigit(e[2]) && isdigit(e[3]) // YYYY
		  && isdigit(e[4]) && isdigit(e[5]) // MM
		  && isdigit(e[6]) && isdigit(e[7]) // DD
		  && isdigit(e[8]) && isdigit(e[9]) // HH
		  && isdigit(e[10]) && isdigit(e[11]) // MM
		  && isdigit(e[12]) && isdigit(e[13]) // SS
		  && strcmp(&e[14], ".log") == 0
	      ) {
		++count;
		if ( strcmp(ent.d_name, base) != 0
		  && (!oldest.d_name[0] || strcmp(ent.d_name, oldest.d_name) < 0)
		)
		  oldest = ent;
	      }
	    }
	    closedir(d);
	    if (count <= config.log.file.rotate || !oldest.d_name[0])
	      break;
	    strbuf b = strbuf_local(path, pathsiz);
	    strbuf_path_join(b, dir, oldest.d_name, NULL);
	    assert(!strbuf_overrun(b));
	    _logs_printf_nl(LOG_LEVEL_INFO, __NOWHERE__, "Unlink %s", path);
	    unlink(path);
	  }
	} else {
	  _log_file = NO_FILE;
	  _logs_printf_nl(LOG_LEVEL_WARN, __HERE__, "Cannot create/append %s - %s [errno=%d]", _log_file_path, strerror(errno), errno);
	}
      }
    }
  }
}

static void _rotate_log_file(_log_iterator *it)
{
  if (_log_file != NO_FILE && _log_file_path == _log_file_path_buf) {
    assert(!cf_limbo);
    if (!config.log.file.path[0] && config.log.file.duration) {
      _compute_file_start_time(it);
      if (it->file_start_time != _log_file_start_time) {
	// Close the current log file, which will cause _open_log_file() to open the next one.
	if (_log_file)
	  fclose(_log_file);
	_log_file = NULL;
	_log_file_path = NULL;
      }
    }
  }
}

static void _flush_log_file()
{
  if (_log_file && _log_file != NO_FILE) {
    fprintf(_log_file, "%s%s%s",
	strbuf_len(&_log_file_strbuf) ? strbuf_str(&_log_file_strbuf) : "",
	strbuf_len(&_log_file_strbuf) ? "\n" : "",
	strbuf_overrun(&_log_file_strbuf) ? "LOG OVERRUN\n" : ""
      );
    strbuf_reset(&_log_file_strbuf);
  }
}

void close_log_file()
{
  if (_log_file && _log_file != NO_FILE)
    fclose(_log_file);
  _log_file = NULL;
}

static void _open_log_stderr()
{
  if (!logfile_stderr) {
    logfile_stderr = stderr;
    setlinebuf(logfile_stderr);
  }
}

static void _flush_log_stderr()
{
  if (logfile_stderr && logfile_stderr != NO_FILE)
    fflush(logfile_stderr);
}

void disable_log_stderr()
{
  if (logfile_stderr && logfile_stderr != NO_FILE) {
    fflush(logfile_stderr);
    logfile_stderr = NO_FILE;
  }
}

void logFlush()
{
  _log_iterator it;
  _log_iterator_start(&it);
  while (_log_iterator_advance(&it))
    _log_flush(&it);
}

void logArgv(int level, struct __sourceloc whence, const char *label, int argc, const char *const *argv)
{
  if (level != LOG_LEVEL_SILENT) {
    struct strbuf b;
    strbuf_init(&b, NULL, 0);
    strbuf_append_argv(&b, argc, argv);
    size_t len = strbuf_count(&b);
    strbuf_init(&b, alloca(len + 1), len + 1);
    strbuf_append_argv(&b, argc, argv);
    _log_iterator it;
    _log_iterator_start(&it);
    _rotate_log_file(&it);
    while (_log_iterator_next(&it, level)) {
      _log_prefix_whence(&it, whence);
      if (label) {
	xputs(label, it.xpf);
	xputc(' ', it.xpf);
      }
      xputs(strbuf_str(&b), it.xpf);
    }
  }
}

void logString(int level, struct __sourceloc whence, const char *str)
{
  if (level != LOG_LEVEL_SILENT) {
    _log_iterator it;
    _log_iterator_start(&it);
    _rotate_log_file(&it);
    const char *s = str;
    const char *p;
    for (p = str; *p; ++p) {
      if (*p == '\n') {
	_log_iterator_rewind(&it);
	while (_log_iterator_next(&it, level)) {
	  _log_prefix_whence(&it, whence);
	  xprintf(it.xpf, "%.*s", p - s, s);
	}
	s = p + 1;
      }
    }
    if (p > s) {
      _log_iterator_rewind(&it);
      while (_log_iterator_next(&it, level)) {
	_log_prefix_whence(&it, whence);
	xprintf(it.xpf, "%.*s", p - s, s);
      }
    }
  }
}

void logMessage(int level, struct __sourceloc whence, const char *fmt, ...)
{
  if (level != LOG_LEVEL_SILENT) {
    va_list ap;
    va_start(ap, fmt);
    vlogMessage(level, whence, fmt, ap);
    va_end(ap);
  }
}

void vlogMessage(int level, struct __sourceloc whence, const char *fmt, va_list ap)
{
  if (level != LOG_LEVEL_SILENT) {
    _log_iterator it;
    _log_iterator_start(&it);
    _rotate_log_file(&it);
    while (_log_iterator_next(&it, level)) {
      _log_prefix_whence(&it, whence);
      va_list ap1;
      va_copy(ap1, ap);
      vxprintf(it.xpf, fmt, ap1);
      va_end(ap1);
    }
  }
}

void logConfigChanged()
{
  _log_iterator it;
  _log_iterator_start(&it);
  while (_log_iterator_advance(&it))
    it.state->config_logged = 0;
  logFlush();
}

int logDump(int level, struct __sourceloc whence, char *name, const unsigned char *addr, size_t len)
{
  if (level != LOG_LEVEL_SILENT) {
    char buf[100];
    size_t i;
    if (name)
      logMessage(level, whence, "Dump of %s", name);
    for(i = 0; i < len; i += 16) {
      strbuf b = strbuf_local(buf, sizeof buf);
      strbuf_sprintf(b, "  %04x :", i);
      int j;
      for (j = 0; j < 16 && i + j < len; j++)
	strbuf_sprintf(b, " %02x", addr[i + j]);
      for (; j < 16; j++)
	strbuf_puts(b, "   ");
      strbuf_puts(b, "    ");
      for (j = 0; j < 16 && i + j < len; j++)
	strbuf_sprintf(b, "%c", addr[i+j] >= ' ' && addr[i+j] < 0x7f ? addr[i+j] : '.');
      logMessage(level, whence, "%s", strbuf_str(b));
    }
  }
  return 0;
}

ssize_t get_self_executable_path(char *buf, size_t len)
{
#if defined(linux)
  return read_symlink("/proc/self/exe", buf, len);
#elif defined (__sun__)
  return read_symlink("/proc/self/path/a.out", buf, len);
#elif defined (__APPLE__)
  uint32_t bufsize = len;
  return _NSGetExecutablePath(buf, &bufsize) == -1 && len ? -1 : bufsize;
#else
#error Unable to find executable path
#endif
}

int log_backtrace(struct __sourceloc whence)
{
#ifndef NO_BACKTRACE
  _log_iterator it;
  _log_iterator_start(&it);
  _rotate_log_file(&it);
  char execpath[MAXPATHLEN];
  if (get_self_executable_path(execpath, sizeof execpath) == -1)
    return WHY("cannot log backtrace: own executable path unknown");
  char tempfile[MAXPATHLEN];
  if (!FORM_SERVAL_INSTANCE_PATH(tempfile, "servalgdb.XXXXXX"))
    return -1;
  int tmpfd = mkstemp(tempfile);
  if (tmpfd == -1)
    return WHYF_perror("mkstemp(%s)", alloca_str_toprint(tempfile));
  if (write_str(tmpfd, "backtrace\n") == -1) {
    close(tmpfd);
    unlink(tempfile);
    return -1;
  }
  if (close(tmpfd) == -1) {
    WHY_perror("close");
    unlink(tempfile);
    return -1;
  }
  char pidstr[12];
  snprintf(pidstr, sizeof pidstr, "%jd", (intmax_t)getpid());
  int stdout_fds[2];
  if (pipe(stdout_fds) == -1)
    return WHY_perror("pipe");
  pid_t child_pid;
  switch (child_pid = fork()) {
  case -1: // error
    WHY_perror("fork");
    close(stdout_fds[0]);
    close(stdout_fds[1]);
    return WHY("cannot log backtrace: fork failed");
  case 0: // child
    if (dup2(stdout_fds[1], 1) == -1 || dup2(stdout_fds[1], 2) == -1) {
      perror("dup2");
      _exit(-1);
    }
    close(0);
    if (open("/dev/null", O_RDONLY) != 0) {
      perror("open(\"/dev/null\")");
      _exit(-2);
    }
    close(stdout_fds[0]);
    /* XXX: Need the cast on Solaris because it defins NULL as 0L and gcc doesn't
     * see it as a sentinal */
    execlp("gdb", "gdb", "-n", "-batch", "-x", tempfile, execpath, pidstr, (void*)NULL);
    perror("execlp(\"gdb\")");
    do { _exit(-3); } while (1);
    break;
  }
  // parent
  close(stdout_fds[1]);
  _log_iterator_printf_nl(&it, LOG_LEVEL_DEBUG, whence, "GDB BACKTRACE");
  char buf[1024];
  char *const bufe = buf + sizeof buf;
  char *linep = buf;
  char *readp = buf;
  ssize_t nr;
  while ((nr = read(stdout_fds[0], readp, bufe - readp)) > 0) {
    char *p = readp;
    readp = readp + nr;
    for (; p < readp; ++p)
      if (*p == '\n' || *p == '\0') {
	*p = '\0';
	_log_iterator_printf_nl(&it, LOG_LEVEL_DEBUG, __NOWHERE__, "%s", linep);
	linep = p + 1;
      }
    if (readp >= bufe && linep == buf) {
      // Line does not fit into buffer.
      char t = bufe[-1];
      bufe[-1] = '\0';
      _log_iterator_printf_nl(&it, LOG_LEVEL_DEBUG, __NOWHERE__, "%s", buf);
      buf[0] = t;
      readp = buf + 1;
    } else if (readp + 120 >= bufe && linep != buf) {
      // Buffer low on space.
      if (linep < readp)
	memmove(buf, linep, readp - linep);
      readp -= linep - buf;
      linep = buf;
    }
    // Invariant: readp < bufe
  }
  if (nr == -1)
    WHY_perror("read");
  if (readp > linep) {
    *readp = '\0';
    _log_iterator_printf_nl(&it, LOG_LEVEL_DEBUG, __NOWHERE__, "%s", linep);
  }
  close(stdout_fds[0]);
  int status = 0;
  if (waitpid(child_pid, &status, 0) == -1)
    WHY_perror("waitpid");
  strbuf b = strbuf_local(buf, sizeof buf);
  strbuf_append_exit_status(b, status);
  _log_iterator_printf_nl(&it, LOG_LEVEL_DEBUG, __NOWHERE__, "gdb %s", buf);
  unlink(tempfile);
#endif
  return 0;
}

const char *log_level_as_string(int level)
{
  switch (level) {
    case LOG_LEVEL_SILENT: return "silent";
    case LOG_LEVEL_DEBUG:  return "debug";
    case LOG_LEVEL_INFO:   return "info";
    case LOG_LEVEL_HINT:   return "hint";
    case LOG_LEVEL_WARN:   return "warn";
    case LOG_LEVEL_ERROR:  return "error";
    case LOG_LEVEL_FATAL:  return "fatal";
    case LOG_LEVEL_NONE:   return "none";
  }
  return NULL;
}

int string_to_log_level(const char *text)
{
  if (strcasecmp(text, "none") == 0)   return LOG_LEVEL_NONE;
  if (strcasecmp(text, "fatal") == 0)  return LOG_LEVEL_FATAL;
  if (strcasecmp(text, "error") == 0)  return LOG_LEVEL_ERROR;
  if (strcasecmp(text, "warn") == 0)   return LOG_LEVEL_WARN;
  if (strcasecmp(text, "hint") == 0)   return LOG_LEVEL_HINT;
  if (strcasecmp(text, "info") == 0)   return LOG_LEVEL_INFO;
  if (strcasecmp(text, "debug") == 0)  return LOG_LEVEL_DEBUG;
  if (strcasecmp(text, "silent") == 0) return LOG_LEVEL_SILENT;
  return LOG_LEVEL_INVALID;
}
