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
#include "conf.h"
#include "str.h"
#include "strbuf.h"
#include "strbuf_helpers.h"

const struct __sourceloc __whence = __NOWHERE__;

debugflags_t debug = 0;

static FILE *logfile = NULL;
static int flag_show_pid = -1;
static int flag_show_time = -1;

/* The logbuf is used to accumulate log messages before the log file is open and ready for
   writing.
 */
static char _log_buf[8192];
static struct strbuf logbuf = STRUCT_STRBUF_EMPTY;

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
      if (confBusy())
	return NULL;
      logpath = confValueGet("log.file", NULL);
    }
    if (!logpath) {
      logfile = stderr; //fopen("/tmp/foo", "a");
      INFO("No logfile configured -- logging to stderr");
    } else if ((logfile = fopen(logpath, "a"))) {
      setlinebuf(logfile);
      INFOF("Logging to %s (fd %d)", logpath, fileno(logfile));
    } else {
      logfile = stderr; //fopen("/tmp/bar", "a");
      WARNF_perror("fopen(%s)", logpath);
      WARNF("Cannot append to %s -- falling back to stderr", logpath);
    }
  }
  return logfile;
}

FILE *open_logging()
{
  return _open_logging();
}

static int show_pid()
{
  if (flag_show_pid < 0 && !confBusy())
    flag_show_pid = confValueGetBoolean("log.show_pid", 0);
  return flag_show_pid;
}

static int show_time()
{
  if (flag_show_time < 0 && !confBusy())
    flag_show_time = confValueGetBoolean("log.show_time", 0);
  return flag_show_time;
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
  int showtime = show_time();
  if (showtime)
    gettimeofday(&tv, NULL);
  int showpid = show_pid();
  _open_logging(); // Put initial INFO message at start of log file
  // No calls outside log.c from this point on.
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
  strbuf_sprintf(&logbuf, "%-6.6s ", levelstr);
#endif
  if (showpid)
    strbuf_sprintf(&logbuf, "[%5u] ", getpid());
  if (showtime) {
    if (tv.tv_sec == 0) {
      strbuf_puts(&logbuf, "NOTIME______ ");
    } else {
      struct tm tm;
      char buf[20];
      if (strftime(buf, sizeof buf, "%T", localtime_r(&tv.tv_sec, &tm)) == 0)
	strbuf_puts(&logbuf, "EMPTYTIME___ ");
      else
	strbuf_sprintf(&logbuf, "%s.%03u ", buf, tv.tv_usec / 1000);
    }
  }
  if (whence.file) {
    strbuf_sprintf(&logbuf, "%s", _trimbuildpath(whence.file));
    if (whence.line)
      strbuf_sprintf(&logbuf, ":%u", whence.line);
    if (whence.function)
      strbuf_sprintf(&logbuf, ":%s()", whence.function);
    strbuf_putc(&logbuf, ' ');
  } else if (whence.function) {
    strbuf_sprintf(&logbuf, "%s() ", whence.function);
  }
  strbuf_putc(&logbuf, ' ');
  return 1;
}

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
  }
  __android_log_print(alevel, "servald", "%s", strbuf_str(buf));
  strbuf_reset(buf);
#else
  FILE *logf = _open_logging();
  if (logf) {
    fprintf(logf, "%s\n%s", strbuf_str(buf), strbuf_overrun(buf) ? "LOG OVERRUN\n" : "");
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

debugflags_t debugFlagMask(const char *flagname)
{
  if	  (!strcasecmp(flagname,"all"))			return DEBUG_ALL;
  else if (!strcasecmp(flagname,"interfaces"))		return DEBUG_OVERLAYINTERFACES;
  else if (!strcasecmp(flagname,"rx"))			return DEBUG_PACKETRX;
  else if (!strcasecmp(flagname,"tx"))			return DEBUG_PACKETTX;
  else if (!strcasecmp(flagname,"verbose"))		return DEBUG_VERBOSE;
  else if (!strcasecmp(flagname,"verbio"))		return DEBUG_VERBOSE_IO;
  else if (!strcasecmp(flagname,"peers"))		return DEBUG_PEERS;
  else if (!strcasecmp(flagname,"dnaresponses"))	return DEBUG_DNARESPONSES;
  else if (!strcasecmp(flagname,"dnahelper"))		return DEBUG_DNAHELPER;
  else if (!strcasecmp(flagname,"vomp"))		return DEBUG_VOMP;
  else if (!strcasecmp(flagname,"packetformats"))	return DEBUG_PACKETFORMATS;
  else if (!strcasecmp(flagname,"packetconstruction"))	return DEBUG_PACKETCONSTRUCTION;
  else if (!strcasecmp(flagname,"gateway"))		return DEBUG_GATEWAY;
  else if (!strcasecmp(flagname,"keyring"))		return DEBUG_KEYRING;
  else if (!strcasecmp(flagname,"sockio"))		return DEBUG_IO;
  else if (!strcasecmp(flagname,"frames"))		return DEBUG_OVERLAYFRAMES;
  else if (!strcasecmp(flagname,"abbreviations"))	return DEBUG_OVERLAYABBREVIATIONS;
  else if (!strcasecmp(flagname,"routing"))		return DEBUG_OVERLAYROUTING;
  else if (!strcasecmp(flagname,"security"))		return DEBUG_SECURITY;
  else if (!strcasecmp(flagname,"rhizome"))	        return DEBUG_RHIZOME;
  else if (!strcasecmp(flagname,"rhizometx"))		return DEBUG_RHIZOME_TX;
  else if (!strcasecmp(flagname,"rhizomerx"))		return DEBUG_RHIZOME_RX;
  else if (!strcasecmp(flagname,"rhizomeads"))		return DEBUG_RHIZOME_ADS;
  else if (!strcasecmp(flagname,"monitorroutes"))	return DEBUG_OVERLAYROUTEMONITOR;
  else if (!strcasecmp(flagname,"queues"))		return DEBUG_QUEUES;
  else if (!strcasecmp(flagname,"broadcasts"))		return DEBUG_BROADCASTS;
  else if (!strcasecmp(flagname,"manifests"))		return DEBUG_MANIFESTS;
  else if (!strcasecmp(flagname,"mdprequests"))		return DEBUG_MDPREQUESTS;
  else if (!strcasecmp(flagname,"timing"))		return DEBUG_TIMING;
  return 0;
}

/* Read the symbolic link into the supplied buffer and add a terminating nul.  Return -1 if the
 * buffer is too short to hold the link content and the nul.  If readlink(2) returns an error, then
 * logs it and returns -1.  Otherwise, returns the number of bytes read, including the terminating
 * nul, ie, returns what readlink(2) returns plus one.  If the 'len' argument is given as zero, then
 * returns the number of bytes that would be read, by calling lstat(2) instead of readlink(2), plus
 * one for the terminating nul.  Beware of the following race condition: a symbolic link may be
 * altered between calling the lstat(2) and readlink(2), so the following apparently overflow-proof
 * code may still fail from a buffer overflow in the second call to read_symlink():
 *
 *    char *readlink_malloc(const char *path) {
 *	ssize_t len = read_symlink(path, NULL, 0);
 *	if (len == -1)
 *	  return NULL;
 *	char *buf = malloc(len);
 *	if (buf == NULL)
 *	  return NULL;
 *	if (read_symlink(path, buf, len) == -1) {
 *	  free(buf);
 *	  return NULL;
 *	}
 *	return buf;
 *    }
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
ssize_t read_symlink(const char *path, char *buf, size_t len)
{
  if (len == 0) {
    struct stat stat;
    if (lstat(path, &stat) == -1)
      return WHYF_perror("lstat(%s)", path);
    return stat.st_size;
  }
  ssize_t nr = readlink(path, buf, len);
  if (nr == -1)
    return WHYF_perror("readlink(%s)", path);
  if (nr >= len)
    return WHYF("buffer overrun from readlink(%s, len=%lu)", path, (unsigned long) len);
  buf[nr] = '\0';
  return nr;
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
  return 0;
}
