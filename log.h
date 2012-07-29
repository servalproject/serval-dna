/*
Copyright (C) 2010-2012 Paul Gardner-Stephen, Serval Project.
 
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

#include <stdio.h>
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include "constants.h"


extern unsigned int debug;
void set_logging(FILE *f);
FILE *open_logging();
void close_logging();
void logMessage(int level, const char *file, unsigned int line, const char *function, const char *fmt, ...);
void vlogMessage(int level, const char *file, unsigned int line, const char *function, const char *fmt, va_list);
unsigned int debugFlagMask(const char *flagname);
char *catv(const char *data, char *buf, size_t len);
int dump(char *name, unsigned char *addr, size_t len);
char *toprint(char *dstStr, ssize_t dstChars, const char *srcBuf, size_t srcBytes);
void logArgv(int level, const char *file, unsigned int line, const char *function, const char *label, int argc, const char *const *argv);
size_t toprint_strlen(ssize_t dstStrLen, const char *srcBuf, size_t srcBytes);
ssize_t get_self_executable_path(char *buf, size_t len);
int log_backtrace(const char *file, unsigned int line, const char *function);


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
#define WHYNULL(X)          (LOGF(LOG_LEVEL_ERROR, "%s", X), NULL)
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

#define BACKTRACE           log_backtrace(__FILE__, __LINE__, __FUNCTION__)

struct response {
  int code;
  unsigned char sid[SID_SIZE];
  struct in_addr sender;
  int recvttl;
  unsigned char *response;
  int response_len;
  int var_id;
  int var_instance;
  int value_len;
  int value_offset;
  int value_bytes;
  struct response *next,*prev;

  /* who sent it? */
  unsigned short peer_id;
  /* have we checked it to see if it allows us to stop requesting? */
  unsigned char checked;
};

struct response_set {
  struct response *responses;
  struct response *last_response;
  int response_count;

  /* Bit mask of peers who have replied */
  unsigned char *reply_bitmask;
};
