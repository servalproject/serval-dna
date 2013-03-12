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

const struct __sourceloc __whence = __NOWHERE__;

static FILE *logfile = NULL;

/* The logbuf is used to accumulate log messages before the log file is open and ready for
 * writing.
 */
static char _log_buf[8192];
static struct strbuf logbuf = STRUCT_STRBUF_EMPTY;

/* Whether the software version has been logged in the current file yet.
 */
bool_t version_logged = 0;

struct tm last_tm;
/* The time stamp of the last logged message, used to detect when the date advances so that
 * the date can be logged.
 */
struct tm last_tm;

#ifdef ANDROID
#include <android/log.h>
#endif

void set_logging(FILE *f)
{
  logfile = f;
  if (f == stdout)
    INFO("Logging to stdout");
  else if (f == stderr)
    INFO("Logging to stderr");
  else if (f != NULL)
    INFOF("Logging to stream with fd=%d", fileno(f));
}

static FILE *_open_logging()
{
#ifdef ANDROID
  return NULL;
#endif
  if (!logfile) {
    const char *logpath = getenv("SERVALD_LOG_FILE");
    if (!logpath) {
      if (cf_limbo)
	return NULL;
      logpath = config.log.file;
    }
    if (!logpath || !logpath[0]) {
      logfile = stderr;
      if (serverMode)
	logMessage(LOG_LEVEL_INFO, __NOWHERE__, "No logfile configured -- logging to stderr");
    } else {
      char path[1024];
      if (!FORM_SERVAL_INSTANCE_PATH(path, logpath)) {
	logfile = stderr;
	logMessage(LOG_LEVEL_WARN, __NOWHERE__, "Logfile path overrun -- logging to stderr");
      } else if ((logfile = fopen(path, "a"))) {
	setlinebuf(logfile);
	if (serverMode)
	  logMessage(LOG_LEVEL_INFO, __NOWHERE__, "Logging to %s (fd %d)", path, fileno(logfile));
      } else {
	logfile = stderr;
	WARNF_perror("fopen(%s)", path);
	logMessage(LOG_LEVEL_WARN, __NOWHERE__, "Cannot append to %s -- falling back to stderr", path);
      }
    }
  }
  return logfile;
}

FILE *open_logging()
{
  return _open_logging();
}

void close_logging()
{
  if (logfile) {
    fclose(logfile);
    logfile = NULL;
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

static int _log_prepare(int level, struct __sourceloc whence)
{
  if (level == LOG_LEVEL_SILENT)
    return 0;
  struct timeval tv;
  tv.tv_sec = 0;
  if (config.log.show_time)
    gettimeofday(&tv, NULL);
  if (!version_logged)
    logVersion();
  _open_logging(); // Put initial INFO message at start of log file
  // No calls outside log.c from this point on.
  while (1) {
    if (strbuf_is_empty(&logbuf))
      strbuf_init(&logbuf, _log_buf, sizeof _log_buf);
    else if (strbuf_len(&logbuf))
      strbuf_putc(&logbuf, '\n');
#ifndef ANDROID
    const char *levelstr = "UNKWN:";
    switch (level) {
      case LOG_LEVEL_FATAL: levelstr = "FATAL:"; break;
      case LOG_LEVEL_ERROR: levelstr = "ERROR:"; break;
      case LOG_LEVEL_INFO:  levelstr = "INFO:"; break;
      case LOG_LEVEL_WARN:  levelstr = "WARN:"; break;
      case LOG_LEVEL_DEBUG: levelstr = "DEBUG:"; break;
    }
    strbuf_sprintf(&logbuf, "%-6.6s", levelstr);
#endif
    if (config.log.show_pid)
      strbuf_sprintf(&logbuf, " [%5u]", getpid());
    if (config.log.show_time) {
      if (tv.tv_sec == 0) {
	strbuf_puts(&logbuf, " NOTIME______");
      } else {
	struct tm tm;
	localtime_r(&tv.tv_sec, &tm);
	char buf[50];
	if (strftime(buf, sizeof buf, "%T", &tm) == 0)
	  strbuf_puts(&logbuf, " EMPTYTIME___");
	else
	  strbuf_sprintf(&logbuf, " %s.%03u", buf, tv.tv_usec / 1000);
	if (tm.tm_mday != last_tm.tm_mday || tm.tm_mon != last_tm.tm_mon || tm.tm_year != last_tm.tm_year) {
	  if (strftime(buf, sizeof buf, "%F %T %z", &tm))
	    strbuf_puts(&logbuf, " Local date/time: ");
	    strbuf_puts(&logbuf, buf);
	    last_tm = tm;
	    continue;
	}
	last_tm = tm;
      }
    }
    break;
  }
  if (whence.file) {
    strbuf_sprintf(&logbuf, " %s", _trimbuildpath(whence.file));
    if (whence.line)
      strbuf_sprintf(&logbuf, ":%u", whence.line);
    if (whence.function)
      strbuf_sprintf(&logbuf, ":%s()", whence.function);
    strbuf_putc(&logbuf, ' ');
  } else if (whence.function) {
    strbuf_sprintf(&logbuf, " %s() ", whence.function);
  }
  strbuf_putc(&logbuf, ' ');
  return 1;
}

/* Internal logging implementation.
 *
 * This function is called after every single log message is appended to logbuf, and is given the
 * level of the message.  This function must reset the given strbuf after its contents have been
 * sent to the log, otherwise log messages will be repeated.  If this function never resets the
 * strbuf, then it may eventually overrun.
 *
 * This function is also called to flush the given logbuf, by giving a log level of SILENT.  That
 * indicates that no new message has been appended since the last time this function was called.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static void _log_internal(int level, struct strbuf *buf)
{
#ifdef ANDROID
  int alevel = ANDROID_LOG_UNKNOWN;
  switch (level) {
    case LOG_LEVEL_FATAL: alevel = ANDROID_LOG_FATAL; break;
    case LOG_LEVEL_ERROR: alevel = ANDROID_LOG_ERROR; break;
    case LOG_LEVEL_INFO:  alevel = ANDROID_LOG_INFO; break;
    case LOG_LEVEL_WARN:  alevel = ANDROID_LOG_WARN; break;
    case LOG_LEVEL_DEBUG: alevel = ANDROID_LOG_DEBUG; break;
    case LOG_LEVEL_SILENT: return;
    default: abort();
  }
  __android_log_print(alevel, "servald", "%s", strbuf_str(buf));
  strbuf_reset(buf);
#else
  FILE *logf = _open_logging();
  if (logf) {
    fprintf(logf, "%s%s%s",
	strbuf_len(buf) ? strbuf_str(buf) : "",
	strbuf_len(buf) ? "\n" : "",
	strbuf_overrun(buf) ? "LOG OVERRUN\n" : ""
      );
    strbuf_reset(buf);
  }
#endif
}

void (*_log_implementation)(int level, struct strbuf *buf) = _log_internal;

static void _log_finish(int level)
{
  if (_log_implementation)
    _log_implementation(level, &logbuf);
}

void set_log_implementation(void (*log_function)(int level, struct strbuf *buf))
{
  _log_implementation=log_function;
}

void logFlush()
{
  if (_log_implementation)
    _log_implementation(LOG_LEVEL_SILENT, &logbuf);
}

void logArgv(int level, struct __sourceloc whence, const char *label, int argc, const char *const *argv)
{
  if (_log_prepare(level, whence)) {
    if (label) {
      strbuf_puts(&logbuf, label);
      strbuf_putc(&logbuf, ' ');
    }
    strbuf_append_argv(&logbuf, argc, argv);
    _log_finish(level);
  }
}

void logString(int level, struct __sourceloc whence, const char *str)
{
  const char *s = str;
  const char *p;
  for (p = str; *p; ++p) {
    if (*p == '\n') {
      if (_log_prepare(level, whence)) {
	strbuf_ncat(&logbuf, s, p - s);
	_log_finish(level);
      }
      s = p + 1;
    }
  }
  if (p > s && _log_prepare(level, whence)) {
    strbuf_ncat(&logbuf, s, p - s);
    _log_finish(level);
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
  if (_log_prepare(level, whence)) {
    strbuf_vsprintf(&logbuf, fmt, ap);
    _log_finish(level);
  }
}

void logVersion()
{
  version_logged = 1;
  logMessage(LOG_LEVEL_INFO, __NOWHERE__, "Serval DNA version: %s", version_servald);
}

void logDebugFlags()
{
  struct cf_om_node *debug_root = NULL;
  cf_fmt_config_debug(&debug_root, &config.debug);
  strbuf b = strbuf_alloca(1024);
  struct cf_om_iterator it;
  for (cf_om_iter_start(&it, debug_root); it.node; cf_om_iter_next(&it))
    if (it.node->text) {
      bool_t val = 0;
      if (cf_opt_boolean(&val, it.node->text) != CFOK || val) {
	if (strbuf_len(b))
	  strbuf_puts(b, ", ");
	strbuf_puts(b, it.node->fullkey);
	if (!val) {
	  strbuf_putc(b, '=');
	  strbuf_puts(b, it.node->text);
	}
      }
    }
  if (strbuf_len(b))
    logMessage(LOG_LEVEL_INFO, __NOWHERE__, "Debug options: %s", strbuf_str(b));
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
  open_logging();
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
