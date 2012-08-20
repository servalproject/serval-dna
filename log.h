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

#ifndef __SERVALD_LOG_H
#define __SERVALD_LOG_H

#include <stdio.h>
#include <stdarg.h>
#include "strbuf_helpers.h"

extern unsigned int debug;

#define DEBUG_ALL                   (~0)
#define DEBUG_PACKETRX              (1 << 0)
#define DEBUG_OVERLAYINTERFACES     (1 << 1)
#define DEBUG_VERBOSE               (1 << 2)
#define DEBUG_VERBOSE_IO            (1 << 3)
#define DEBUG_PEERS                 (1 << 4)
#define DEBUG_DNARESPONSES          (1 << 5)
#define DEBUG_DNAHELPER             (1 << 6)
#define DEBUG_VOMP                  (1 << 7)
#define DEBUG_RHIZOME_RX            (1 << 8)
#define DEBUG_PACKETFORMATS         (1 << 9)
#define DEBUG_GATEWAY               (1 << 10)
#define DEBUG_KEYRING               (1 << 11)
#define DEBUG_IO                    (1 << 12)
#define DEBUG_OVERLAYFRAMES         (1 << 13)
#define DEBUG_OVERLAYABBREVIATIONS  (1 << 14)
#define DEBUG_OVERLAYROUTING        (1 << 15)
#define DEBUG_SECURITY              (1 << 16)
#define DEBUG_RHIZOME               (1 << 17)
#define DEBUG_OVERLAYROUTEMONITOR   (1 << 18)
#define DEBUG_QUEUES                (1 << 19)
#define DEBUG_BROADCASTS            (1 << 20)
#define DEBUG_RHIZOME_TX            (1 << 21)
#define DEBUG_PACKETTX              (1 << 22)
#define DEBUG_PACKETCONSTRUCTION    (1 << 23)
#define DEBUG_MANIFESTS             (1 << 24)
#define DEBUG_MDPREQUESTS           (1 << 25)
#define DEBUG_TIMING                (1 << 26)

#define LOG_LEVEL_SILENT    (-1)
#define LOG_LEVEL_DEBUG     (0)
#define LOG_LEVEL_INFO      (1)
#define LOG_LEVEL_WARN      (2)
#define LOG_LEVEL_ERROR     (3)
#define LOG_LEVEL_FATAL     (4)

struct strbuf;

void set_logging(FILE *f);
FILE *open_logging();
void close_logging();
void logArgv(int level, const char *file, unsigned int line, const char *function, const char *label, int argc, const char *const *argv);
void logString(int level, const char *file, unsigned int line, const char *function, const char *str); 
void logMessage(int level, const char *file, unsigned int line, const char *function, const char *fmt, ...);
void vlogMessage(int level, const char *file, unsigned int line, const char *function, const char *fmt, va_list);
unsigned int debugFlagMask(const char *flagname);
int logDump(int level, const char *file, unsigned int line, const char *function, char *name, unsigned char *addr, size_t len);
char *toprint(char *dstStr, ssize_t dstBufSiz, const char *srcBuf, size_t srcBytes);
size_t toprint_strlen(const char *srcBuf, size_t srcBytes);
ssize_t get_self_executable_path(char *buf, size_t len);
int log_backtrace(const char *file, unsigned int line, const char *function);
void set_log_implementation(void (*log_function)(int level, struct strbuf *buf));

#define alloca_toprint(dstlen,buf,len)  toprint((char *)alloca((dstlen) == -1 ? toprint_strlen((buf),(len)) + 1 : (dstlen)), (dstlen), (buf), (len))

#define LOGF(L,F,...)       (logMessage(L, __FILE__, __LINE__, __FUNCTION__, F, ##__VA_ARGS__))
#define LOGF_perror(L,F,...) logMessage_perror(L, __FILE__, __LINE__, __FUNCTION__, F, ##__VA_ARGS__)
#define LOG_perror(L,X)     LOGF_perror(L, "%s", (X))

#define logMessage_perror(L,file,line,func,F,...) \
                            (logMessage(L, file, line, func, F ": %s [errno=%d]", ##__VA_ARGS__, strerror(errno), errno))

#define FATALF(F,...)       do { LOGF(LOG_LEVEL_FATAL, F, ##__VA_ARGS__); exit(-1); } while (1)
#define FATAL(X)            FATALF("%s", (X))
#define FATAL_perror(X)     FATALF("%s: %s [errno=%d]", (X), strerror(errno), errno)

#define WHYF(F,...)         (LOGF(LOG_LEVEL_ERROR, F, ##__VA_ARGS__), -1)
#define WHY(X)              WHYF("%s", (X))
#define WHYFNULL(F,...)     (LOGF(LOG_LEVEL_ERROR, F, ##__VA_ARGS__), NULL)
#define WHYNULL(X)          (WHYFNULL("%s", (X)))
#define WHYF_perror(F,...)  WHYF(F ": %s [errno=%d]", ##__VA_ARGS__, strerror(errno), errno)
#define WHY_perror(X)       WHYF("%s: %s [errno=%d]", (X), strerror(errno), errno)

#define WARNF(F,...)        LOGF(LOG_LEVEL_WARN, F, ##__VA_ARGS__)
#define WARN(X)             WARNF("%s", (X))
#define WARN_perror(X)      WARNF("%s: %s [errno=%d]", (X), strerror(errno), errno)
#define WHY_argv(X,ARGC,ARGV) logArgv(LOG_LEVEL_ERROR, __FILE__, __LINE__, __FUNCTION__, (X), (ARGC), (ARGV))

#define INFOF(F,...)        LOGF(LOG_LEVEL_INFO, F, ##__VA_ARGS__)
#define INFO(X)             INFOF("%s", (X))

#define DEBUGF(F,...)       LOGF(LOG_LEVEL_DEBUG, F, ##__VA_ARGS__)
#define DEBUG(X)            DEBUGF("%s", (X))
#define DEBUGF_perror(F,...) DEBUGF(F ": %s [errno=%d]", ##__VA_ARGS__, strerror(errno), errno)
#define DEBUG_perror(X)     DEBUGF("%s: %s [errno=%d]", (X), strerror(errno), errno)
#define D DEBUG("D")
#define DEBUG_argv(X,ARGC,ARGV) logArgv(LOG_LEVEL_DEBUG, __FILE__, __LINE__, __FUNCTION__, (X), (ARGC), (ARGV))

#define dump(X,A,N)         logDump(LOG_LEVEL_DEBUG, __FILE__, __LINE__, __FUNCTION__, (X), (A), (N))

#define BACKTRACE           log_backtrace(__FILE__, __LINE__, __FUNCTION__)

#endif // __SERVALD_LOG_H
