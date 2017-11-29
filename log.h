/*
Serval DNA logging
Copyright (C) 2016 Flinders University
Copyright (C) 2012-2015 Serval Project Inc.
 
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

#ifndef __SERVAL_DNA__LOG_H
#define __SERVAL_DNA__LOG_H

#include <sys/types.h> // for size_t
#include <stdio.h> // for NULL
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include "whence.h"

#ifndef __SERVAL_LOG_INLINE
# if __GNUC__ && !__GNUC_STDC_INLINE__
#  define __SERVAL_LOG_INLINE extern inline
# else
#  define __SERVAL_LOG_INLINE inline
# endif
#endif

// Logging levels.
#define LOG_LEVEL_INVALID   (-1)
#define LOG_LEVEL_SILENT    (0)
#define LOG_LEVEL_DEBUG     (1)
#define LOG_LEVEL_INFO      (2)
#define LOG_LEVEL_HINT      (3)
#define LOG_LEVEL_WARN      (4)
#define LOG_LEVEL_ERROR     (5)
#define LOG_LEVEL_FATAL     (6)
#define LOG_LEVEL_NONE      (127)
const char *log_level_as_string(int level);
int string_to_log_level(const char *text);

// Logging primitives:

// Log a message via all available log outputs.
void serval_vlogf(int level, struct __sourceloc whence, const char *fmt, va_list ap);

// Flush all log outputs.
void serval_log_flush();

// Close all log outputs without flushing; they will be re-opened on the next
// vLogMessage().  This is mainly used in forked child processes, to ensure
// that the child process does not share open file descriptors with the parent
// process.
void serval_log_close();

// If possible, capture all output written to the given file descriptor in a
// persistent log format, such as a file or an operating system log.  Any
// output that produces a persistent log and is able to redirect the file
// descriptor into that log will do so.  If any output is already writing to
// the file descriptor (eg, the console output, which writes to fd 2) then that
// output will cease writing to that file descriptor.  Returns true if the file
// descriptor has been redirected successfully.
bool_t serval_log_capture_fd(int fd);

// Logging context string -- if non-empty, then is prefixed to all log messages
// inside square brackets.
struct strbuf;
extern struct strbuf log_context;

// The log level to use for the message that no log file output is configured.
extern int serval_log_level_NoLogFileConfigured;

// The following logging utilities are implemented entirely in terms of the
// above primitives.

__SERVAL_LOG_INLINE void serval_logf(int level, struct __sourceloc whence, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  serval_vlogf(level, whence, fmt, ap);
  va_end(ap);
}

__SERVAL_LOG_INLINE int serval_logf_and_return(int retval, struct __sourceloc whence, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  serval_vlogf(LOG_LEVEL_ERROR, whence, fmt, ap);
  va_end(ap);
  return retval;
}

int serval_log_backtrace(int level, struct __sourceloc whence);
void serval_log_argv(int level, struct __sourceloc whence, const char *label, int argc, const char *const *argv);
int serval_log_hexdump(int level, struct __sourceloc whence, char *name, const unsigned char *addr, size_t len);
void serval_log_multiline(int level, struct __sourceloc whence, const char *str);

// Convenient logging macros.

#define LOGF(L,F,...)           serval_logf(L, __WHENCE__, F, ##__VA_ARGS__)
#define LOGF_perror(L,F,...)    serval_logf(L, __WHENCE__, F ": %s [errno=%d]", ##__VA_ARGS__, strerror(errno), errno)
#define LOG_perror(L,X)         LOGF_perror(L, "%s", (X))

#define NOWHENCE(LOGSTMT)       do { const struct __sourceloc __whence = __NOWHENCE__; LOGSTMT; } while (0)

#define BACKTRACE               serval_log_backtrace(LOG_LEVEL_FATAL, __WHENCE__)

#define FATALF(F,...)           do { LOGF(LOG_LEVEL_FATAL, F, ##__VA_ARGS__); abort(); exit(-1); } while (1)
#define FATAL(X)                FATALF("%s", (X))
#define FATALF_perror(F,...)    FATALF(F ": %s [errno=%d]", ##__VA_ARGS__, strerror(errno), errno)
#define FATAL_perror(X)         FATALF_perror("%s", (X))

#define WHYF(F,...)             serval_logf_and_return(-1, __WHENCE__, F, ##__VA_ARGS__)
#define WHY(X)                  WHYF("%s", (X))
#define WHYF_perror(F,...)      WHYF(F ": %s [errno=%d]", ##__VA_ARGS__, strerror(errno), errno)
#define WHY_perror(X)           WHYF_perror("%s", (X))
#define WHY_argv(X,ARGC,ARGV)   serval_log_argv(LOG_LEVEL_ERROR, __WHENCE__, (X), (ARGC), (ARGV))
#define WHY_dump(X,ADDR,LEN)    serval_log_hexdump(LOG_LEVEL_ERROR, __WHENCE__, (X), (const unsigned char *)(ADDR), (size_t)(LEN))

#define WARNF(F,...)            LOGF(LOG_LEVEL_WARN, F, ##__VA_ARGS__)
#define WARN(X)                 WARNF("%s", (X))
#define WARNF_perror(F,...)     LOGF_perror(LOG_LEVEL_WARN, F, ##__VA_ARGS__)
#define WARN_perror(X)          WARNF_perror("%s", (X))
#define WARN_dump(X,ADDR,LEN)   serval_log_hexdump(LOG_LEVEL_WARN, __WHENCE__, (X), (const unsigned char *)(ADDR), (size_t)(LEN))

#define HINTF(F,...)            LOGF(LOG_LEVEL_HINT, F, ##__VA_ARGS__)
#define HINT(X)                 HINTF("%s", (X))
#define HINT_argv(X,ARGC,ARGV)  serval_log_argv(LOG_LEVEL_HINT, __WHENCE__, (X), (ARGC), (ARGV))
#define HINT_dump(X,ADDR,LEN)   serval_log_hexdump(LOG_LEVEL_HINT, __WHENCE__, (X), (const unsigned char *)(ADDR), (size_t)(LEN))

#define INFOF(F,...)            LOGF(LOG_LEVEL_INFO, F, ##__VA_ARGS__)
#define INFO(X)                 INFOF("%s", (X))

// These macros are useful for implementing other macros that conditionally log
// at DEBUG level; DEBUG() and DEBUGF() in "debug.h" are the prime example.

#define _DEBUGF(F,...)           LOGF(LOG_LEVEL_DEBUG, F, ##__VA_ARGS__)
#define _DEBUG(X)                _DEBUGF("%s", (X))
#define _DEBUGF_perror(F,...)    LOGF_perror(LOG_LEVEL_DEBUG, F, ##__VA_ARGS__)
#define _DEBUG_perror(X)         _DEBUGF_perror("%s", (X))
#define _DEBUG_argv(X,ARGC,ARGV) serval_log_argv(LOG_LEVEL_DEBUG, __WHENCE__, (X), (ARGC), (ARGV))
#define _DEBUG_dump(X,ADDR,LEN)  serval_log_hexdump(LOG_LEVEL_DEBUG, __WHENCE__, (X), (const unsigned char *)(ADDR), (size_t)(LEN))

#define _DEBUGF_TAG(TAG,F,...)            _DEBUGF("{%s} " F, (TAG), ##__VA_ARGS__)
#define _DEBUGF_TAG_perror(TAG,F,...)     _DEBUGF_perror("{%s} " F, (TAG), ##__VA_ARGS__)
#define _DEBUG_TAG_argv(TAG,X,ARGC,ARGV)  _DEBUG_argv("{" TAG "} " X, (ARGC), (ARGV))
#define _DEBUG_TAG_dump(TAG,X,ADDR,LEN)   _DEBUG_dump("{" TAG "} " X, (ADDR), (LEN))

#endif // __SERVAL_DNA__LOG_H
