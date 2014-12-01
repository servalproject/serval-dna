/*
Serval DNA logging utility functions
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

#include <libgen.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/param.h>
#include "log.h"
#include "strbuf.h"
#include "strbuf_helpers.h"
#include "instance.h"
#include "str.h"
#include "net.h"

int logDump(int level, struct __sourceloc whence, char *name, const unsigned char *addr, size_t len)
{
  if (level != LOG_LEVEL_SILENT) {
    char buf[100];
    size_t i;
    if (name)
      logMessage(level, whence, "Dump of %s", name);
    for(i = 0; i < len; i += 16) {
      strbuf b = strbuf_local(buf, sizeof buf);
      strbuf_sprintf(b, "  %04zx :", i);
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

void logArgv(int level, struct __sourceloc whence, const char *label, int argc, const char *const *argv)
{
  if (level != LOG_LEVEL_SILENT) {
    struct strbuf b;
    strbuf_init(&b, NULL, 0);
    strbuf_append_argv(&b, argc, argv);
    size_t len = strbuf_count(&b);
    strbuf_init(&b, alloca(len + 1), len + 1);
    strbuf_append_argv(&b, argc, argv);
    if (label)
      logMessage(level, whence, "%s %s", label, strbuf_str(&b));
    else
      logMessage(level, whence, "%s", strbuf_str(&b));
  }
}

void logString(int level, struct __sourceloc whence, const char *str)
{
  if (level != LOG_LEVEL_SILENT) {
    const char *s = str;
    const char *p;
    for (p = str; *p; ++p) {
      if (*p == '\n') {
	logMessage(level, whence, "%.*s", (int)(p - s), s);
	s = p + 1;
      }
    }
    if (p > s)
      logMessage(level, whence, "%.*s", (int)(p - s), s);
  }
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

int logBacktrace(int level, struct __sourceloc whence)
{
#ifndef NO_BACKTRACE
  char execpath[MAXPATHLEN];
  if (get_self_executable_path(execpath, sizeof execpath) == -1)
    return WHY("cannot log backtrace: own executable path unknown");
  char tempfile[MAXPATHLEN];
  if (!FORMF_SERVAL_TMP_PATH(tempfile, "servalgdb.XXXXXX"))
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
    // Need the (void*) cast on Solaris because it defines NULL as 0L and gcc doesn't accept it as a
    // sentinal
    execlp("gdb", "gdb", "-n", "-batch", "-x", tempfile, execpath, pidstr, (void*)NULL);
    perror("execlp(\"gdb\")");
    do { _exit(-3); } while (1);
    break;
  }
  // parent
  close(stdout_fds[1]);
  logMessage(level, whence, "GDB BACKTRACE");
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
	logMessage(level, __NOWHERE__, "GDB %s", linep);
	linep = p + 1;
      }
    if (readp >= bufe && linep == buf) {
      // Line does not fit into buffer.
      char t = bufe[-1];
      bufe[-1] = '\0';
      logMessage(level, __NOWHERE__, "GDB %s", buf);
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
    logMessage(level, __NOWHERE__, "GDB %s", linep);
  }
  close(stdout_fds[0]);
  int status = 0;
  if (waitpid(child_pid, &status, 0) == -1)
    WHY_perror("waitpid");
  strbuf b = strbuf_local(buf, sizeof buf);
  strbuf_append_exit_status(b, status);
  logMessage(level, __NOWHERE__, "gdb %s", buf);
  unlink(tempfile);
#endif
  return 0;
}
