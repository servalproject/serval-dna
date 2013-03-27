/* 
Serval logging.
Copyright (C) 2012 Serval Project Inc.

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

static FILE *logfile_file = NULL;
static FILE *logfile_stderr = NULL;
#define NO_FILE ((FILE *)1)

/* The file logbuf is used to accumulate log messages before the log file is open and ready for
 * writing.
 */
static char _log_buf[8192];
static struct strbuf logbuf = STRUCT_STRBUF_EMPTY;

#ifdef ANDROID

#include <android/log.h>

/* The Android logbuf is used to accumulate a single log line before printing to Android's
 * logging API.
 */
static char _log_buf_android[1024];
static struct strbuf logbuf_android;

#endif // ANDROID

static void _open_log_file()
{
  if (!logfile_file) {
    const char *logpath = getenv("SERVALD_LOG_FILE");
    if (!logpath) {
      if (cf_limbo)
	return;
      logpath = config.log.file_path;
    }
    if (!logpath || !logpath[0]) {
      logfile_file = NO_FILE;
      if (serverMode)
	logMessage(LOG_LEVEL_INFO, __NOWHERE__, "No logfile_file configured");
    } else {
      char path[1024];
      if (!FORM_SERVAL_INSTANCE_PATH(path, logpath)) {
	logfile_file = NO_FILE;
	logMessage(LOG_LEVEL_WARN, __NOWHERE__, "Logfile path overrun");
      } else if ((logfile_file = fopen(path, "a"))) {
	setlinebuf(logfile_file);
	if (serverMode)
	  logMessage(LOG_LEVEL_INFO, __NOWHERE__, "Logging to %s (fd %d)", path, fileno(logfile_file));
      } else {
	logfile_file = NO_FILE;
	WARNF_perror("fopen(%s)", path);
	logMessage(LOG_LEVEL_WARN, __NOWHERE__, "Cannot append to %s", path);
      }
    }
  }
}

static void _flush_log_file()
{
  if (logfile_file && logfile_file != NO_FILE) {
    fprintf(logfile_file, "%s%s%s",
	strbuf_len(&logbuf) ? strbuf_str(&logbuf) : "",
	strbuf_len(&logbuf) ? "\n" : "",
	strbuf_overrun(&logbuf) ? "LOG OVERRUN\n" : ""
      );
    strbuf_reset(&logbuf);
  }
}

void close_log_file()
{
  if (logfile_file && logfile_file != NO_FILE)
    fclose(logfile_file);
  logfile_file = NULL;
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

struct _log_state {

  /* This structure is initially zerofilled. */

  /* Whether the software version has been logged in the current file yet.
  */
  bool_t version_logged;

  /* The time stamp of the last logged message, used to detect when the date advances so that
  * the date can be logged.
  */
  struct tm last_tm;

};

struct _log_state state_file;
#ifdef ANDROID
struct _log_state state_android;
#endif
struct _log_state state_stderr;

typedef struct _log_iterator {
  int level;
  struct __sourceloc whence;
  struct timeval tv;
  struct tm tm;
  XPRINTF xpf;
  int _file;
#ifdef ANDROID
  int _android;
#endif
  int _stderr;
} _log_iterator;

static void _log_iterator_start(_log_iterator *it, int level, struct __sourceloc whence)
{
  assert(level <= LOG_LEVEL_FATAL);
  memset(it, 0, sizeof *it);
  it->level = level;
  it->whence = whence;
  gettimeofday(&it->tv, NULL);
  localtime_r(&it->tv.tv_sec, &it->tm);
}

static void _log_level_prefix(_log_iterator *it, int level)
{
  const char *levelstr = "UNKWN:";
  switch (level) {
    case LOG_LEVEL_FATAL: levelstr = "FATAL:"; break;
    case LOG_LEVEL_ERROR: levelstr = "ERROR:"; break;
    case LOG_LEVEL_WARN:  levelstr = "WARN:"; break;
    case LOG_LEVEL_INFO:  levelstr = "INFO:"; break;
    case LOG_LEVEL_DEBUG: levelstr = "DEBUG:"; break;
  }
  xprintf(it->xpf, "%-6.6s", levelstr);
}

static int _log_prefix(const struct config_log_format *cfg, _log_iterator *it, int level)
{
  if (cfg == &config.log.file) {
    _open_log_file(); // puts initial INFO message at start of log file
    if (logfile_file == NO_FILE)
      return 0;
    if (strbuf_is_empty(&logbuf))
      strbuf_init(&logbuf, _log_buf, sizeof _log_buf);
    else if (strbuf_len(&logbuf))
      strbuf_putc(&logbuf, '\n');
    it->xpf = XPRINTF_STRBUF(&logbuf);
    _log_level_prefix(it, level);
  }
#ifdef ANDROID
  else if (cfg == &config.log.android) {
    strbuf_init(&logbuf_android, _log_buf_android, sizeof _log_buf_android);
    it->xpf = XPRINTF_STRBUF(&logbuf_android);
  }
#endif // ANDROID
  else if (cfg == &config.log.stderr) {
    _open_log_stderr();
    if (logfile_stderr == NULL || logfile_stderr == NO_FILE)
      return 0;
    it->xpf = XPRINTF_STDIO(logfile_stderr);
    _log_level_prefix(it, level);
  }
  else
    abort();
  if (cfg->show_pid)
    xprintf(it->xpf, "[%5u] ", getpid());
  if (cfg->show_time) {
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
  return 1;
}

static void _log_finish(const struct config_log_format *cfg, _log_iterator *it, int level)
{
  if (cfg == &config.log.file) {
    _flush_log_file();
  }
#ifdef ANDROID
  else if (cfg == &config.log.android) {
    int alevel = ANDROID_LOG_UNKNOWN;
    switch (it->level) {
      case LOG_LEVEL_FATAL: alevel = ANDROID_LOG_FATAL; break;
      case LOG_LEVEL_ERROR: alevel = ANDROID_LOG_ERROR; break;
      case LOG_LEVEL_INFO:  alevel = ANDROID_LOG_INFO; break;
      case LOG_LEVEL_WARN:  alevel = ANDROID_LOG_WARN; break;
      case LOG_LEVEL_DEBUG: alevel = ANDROID_LOG_DEBUG; break;
      case LOG_LEVEL_SILENT: return;
      default: abort();
    }
    __android_log_print(alevel, "servald", "%s", strbuf_str(_log_buf_android));
  }
#endif // ANDROID
  else if (cfg == &config.log.stderr) {
    fputc('\n', logfile_stderr);
    _flush_log_stderr();
  }
  else
    abort();
}

static int _log_prepare(const struct config_log_format *cfg, struct _log_state *state, _log_iterator *it)
{
  if (it->level < cfg->level)
    return 0;
  if ( it->tm.tm_mday != state->last_tm.tm_mday
    || it->tm.tm_mon != state->last_tm.tm_mon
    || it->tm.tm_year != state->last_tm.tm_year
  ) {
    char buf[50];
    if (strftime(buf, sizeof buf, "%F %T %z", &it->tm)) {
      if (!_log_prefix(cfg, it, LOG_LEVEL_INFO))
	return 0;
      xputs("Local date/time: ", it->xpf);
      xputs(buf, it->xpf);
      state->last_tm = it->tm;
      _log_finish(cfg, it, LOG_LEVEL_INFO);
    }
  }
  if (!state->version_logged) {
    if (!_log_prefix(cfg, it, LOG_LEVEL_INFO))
      return 0;
    xprintf(it->xpf, "Serval DNA version: %s", version_servald);
    state->version_logged = 1;
    _log_finish(cfg, it, LOG_LEVEL_INFO);
  }
  if (!_log_prefix(cfg, it, it->level))
    return 0;
  if (it->whence.file) {
    xprintf(it->xpf, "%s", _trimbuildpath(it->whence.file));
    if (it->whence.line)
      xprintf(it->xpf, ":%u", it->whence.line);
    if (it->whence.function)
      xprintf(it->xpf, ":%s()", it->whence.function);
    xputs("  ", it->xpf);
  } else if (it->whence.function) {
    xprintf(it->xpf, "%s()  ", it->whence.function);
  }
  return 1;
}

static int _log_iterator_next(_log_iterator *it)
{
  if (it->_file == 0) {
    if (_log_prepare(&config.log.file, &state_file, it)) {
      it->_file = 1;
      return 1;
    }
  }
  else if (it->_file == 1) {
    _log_finish(&config.log.file, it, it->level);
  }
  it->_file = 2;
#ifdef ANDROID
  if (it->_android == 0) {
    if (_log_prepare(&config.log.android, &state_android, it)) {
      it->_android = 1;
      return 1;
    }
  }
  else if (it->_android == 1) {
    _log_finish(&config.log.android, it, it->level);
  }
  it->_android = 2;
#endif // ANDROID
  if (it->_stderr == 0) {
    if (_log_prepare(&config.log.stderr, &state_stderr, it)) {
      it->_stderr = 1;
      return 1;
    }
  }
  else if (it->_stderr == 1) {
    _log_finish(&config.log.stderr, it, it->level);
  }
  it->_stderr = 2;
  return 0;
}

void logFlush()
{
  _flush_log_file();
  _flush_log_stderr();
}

void logArgv(int level, struct __sourceloc whence, const char *label, int argc, const char *const *argv)
{
  struct strbuf b;
  strbuf_init(&b, NULL, 0);
  strbuf_append_argv(&b, argc, argv);
  size_t len = strbuf_count(&b);
  strbuf_init(&b, alloca(len + 1), len + 1);
  strbuf_append_argv(&b, argc, argv);
  _log_iterator it;
  _log_iterator_start(&it, level, whence);
  while (_log_iterator_next(&it)) {
    if (label) {
      xputs(label, it.xpf);
      xputc(' ', it.xpf);
    }
    xputs(strbuf_str(&b), it.xpf);
  }
}

void logString(int level, struct __sourceloc whence, const char *str)
{
  _log_iterator it;
  const char *s = str;
  const char *p;
  for (p = str; *p; ++p) {
    if (*p == '\n') {
      _log_iterator_start(&it, level, whence);
      while (_log_iterator_next(&it))
	xprintf(it.xpf, "%.*s", p - s, s);
      s = p + 1;
    }
  }
  if (p > s) {
    _log_iterator_start(&it, level, whence);
    while (_log_iterator_next(&it))
      xprintf(it.xpf, "%.*s", p - s, s);
  }
}

void logMessage(int level, struct __sourceloc whence, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  vlogMessage(level, whence, fmt, ap);
  va_end(ap);
}

void vlogMessage(int level, struct __sourceloc whence, const char *fmt, va_list ap)
{
  _log_iterator it;
  _log_iterator_start(&it, level, whence);
  while (_log_iterator_next(&it))
    vxprintf(it.xpf, fmt, ap);
}

void logCurrentConfig()
{
  struct cf_om_node *root = NULL;
  int ret = cf_fmt_config_main(&root, &config);
  if (ret == CFERROR) {
    cf_om_free_node(&root);
    WHY("cannot log current config");
  } else {
    struct cf_om_iterator it;
    logMessage(LOG_LEVEL_INFO, __NOWHERE__, "Current configuration:");
    for (cf_om_iter_start(&it, root); it.node; cf_om_iter_next(&it)) {
      if (it.node->text && it.node->line_number)
	logMessage(LOG_LEVEL_INFO, __NOWHERE__, "   %s=%s", it.node->fullkey, it.node->text);
    }
  }
}

int logDump(int level, struct __sourceloc whence, char *name, const unsigned char *addr, size_t len)
{
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
  _open_log_file();
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
  logMessage(LOG_LEVEL_DEBUG, whence, "GDB BACKTRACE");
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
	logMessage(LOG_LEVEL_DEBUG, __NOWHERE__, "%s", linep);
	linep = p + 1;
      }
    if (readp >= bufe && linep == buf) {
      // Line does not fit into buffer.
      char t = bufe[-1];
      bufe[-1] = '\0';
      logMessage(LOG_LEVEL_DEBUG, __NOWHERE__, "%s", buf);
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
    logMessage(LOG_LEVEL_DEBUG, __NOWHERE__, "%s", linep);
  }
  close(stdout_fds[0]);
  int status = 0;
  if (waitpid(child_pid, &status, 0) == -1)
    WHY_perror("waitpid");
  strbuf b = strbuf_local(buf, sizeof buf);
  strbuf_append_exit_status(b, status);
  logMessage(LOG_LEVEL_DEBUG, __NOWHERE__, "gdb %s", buf);
  unlink(tempfile);
#endif
  return 0;
}
