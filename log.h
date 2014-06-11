/*
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

// Log output control.
extern int logLevel_NoLogFileConfigured;
void close_log_file();
void disable_log_stderr();
void logFlush();
void logConfigChanged();

// Logging primitives.
void vlogMessage(int level, struct __sourceloc whence, const char *fmt, va_list);
int logBacktrace(int level, struct __sourceloc whence);

__SERVAL_LOG_INLINE void logMessage(int level, struct __sourceloc whence, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  vlogMessage(level, whence, fmt, ap);
  va_end(ap);
}

// Useful logging primitive macros.
#define LOGF(L,F,...)       logMessage(L, __WHENCE__, F, ##__VA_ARGS__)
#define LOGF_perror(L,F,...) logMessage_perror(L, __WHENCE__, F, ##__VA_ARGS__)
#define LOG_perror(L,X)     LOGF_perror(L, "%s", (X))

#define logMessage_perror(L,whence,F,...) (logMessage(L, whence, F ": %s [errno=%d]", ##__VA_ARGS__, strerror(errno), errno))

#define NOWHENCE(LOGSTMT)   do { const struct __sourceloc __whence = __NOWHENCE__; LOGSTMT; } while (0)

#define FATALF(F,...)       do { LOGF(LOG_LEVEL_FATAL, F, ##__VA_ARGS__); abort(); exit(-1); } while (1)
#define FATAL(X)            FATALF("%s", (X))
#define FATALF_perror(F,...) FATALF(F ": %s [errno=%d]", ##__VA_ARGS__, strerror(errno), errno)
#define FATAL_perror(X)     FATALF_perror("%s", (X))

#define WHYF(F,...)         (LOGF(LOG_LEVEL_ERROR, F, ##__VA_ARGS__), -1)
#define WHY(X)              WHYF("%s", (X))
#define WHYFNULL(F,...)     (LOGF(LOG_LEVEL_ERROR, F, ##__VA_ARGS__), NULL)
#define WHYNULL(X)          (WHYFNULL("%s", (X)))
#define WHYF_perror(F,...)  (LOGF_perror(LOG_LEVEL_ERROR, F, ##__VA_ARGS__), -1)
#define WHY_perror(X)       WHYF_perror("%s", (X))
#define WHY_argv(X,ARGC,ARGV) logArgv(LOG_LEVEL_ERROR, __WHENCE__, (X), (ARGC), (ARGV))

#define WARNF(F,...)        LOGF(LOG_LEVEL_WARN, F, ##__VA_ARGS__)
#define WARN(X)             WARNF("%s", (X))
#define WARNF_perror(F,...) LOGF_perror(LOG_LEVEL_WARN, F, ##__VA_ARGS__)
#define WARN_perror(X)      WARNF_perror("%s", (X))

#define HINTF(F,...)        LOGF(LOG_LEVEL_HINT, F, ##__VA_ARGS__)
#define HINT(X)             HINTF("%s", (X))
#define HINT_argv(X,ARGC,ARGV) logArgv(LOG_LEVEL_HINT, __WHENCE__, (X), (ARGC), (ARGV))

#define INFOF(F,...)        LOGF(LOG_LEVEL_INFO, F, ##__VA_ARGS__)
#define INFO(X)             INFOF("%s", (X))

#define DEBUGF(F,...)       LOGF(LOG_LEVEL_DEBUG, F, ##__VA_ARGS__)
#define DEBUG(X)            DEBUGF("%s", (X))
#define DEBUGF_perror(F,...) LOGF_perror(LOG_LEVEL_DEBUG, F, ##__VA_ARGS__)
#define DEBUG_perror(X)     DEBUGF_perror("%s", (X))
#define D                   (DEBUG("D"), 1)
#define T                   (config.debug.trace ? DEBUG("T") : 1)
#define DEBUG_argv(X,ARGC,ARGV) logArgv(LOG_LEVEL_DEBUG, __WHENCE__, (X), (ARGC), (ARGV))

#define dump(X,A,N)         logDump(LOG_LEVEL_DEBUG, __WHENCE__, (X), (const unsigned char *)(A), (size_t)(N))

#define BACKTRACE           logBacktrace(LOG_LEVEL_FATAL, __WHENCE__)

// Utility functions, defined in terms of above primitives.
void logArgv(int level, struct __sourceloc whence, const char *label, int argc, const char *const *argv);
int logDump(int level, struct __sourceloc whence, char *name, const unsigned char *addr, size_t len);
void logString(int level, struct __sourceloc whence, const char *str);

#endif // __SERVAL_DNA__LOG_H
