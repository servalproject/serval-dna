/* 
Serval Distributed Numbering Architecture (DNA)
Copyright (C) 2010 Paul Gardner-Stephen 

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

#include "serval.h"
#include "strbuf.h"
#include <ctype.h>
#include <sys/time.h>
#include <time.h>

unsigned int debug = 0;
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

FILE *open_logging()
{
  if (!logfile) {
    const char *logpath = getenv("SERVALD_LOG_FILE");
    if (!logpath) {
      // If the configuration is locked (eg, it called WHY() or DEBUG() while initialising, which
      // led back to here) then return NULL to indicate the message cannot be logged.
      if (confLocked())
	return NULL;
      logpath = confValueGet("log.file", NULL);
    }
    if (!logpath) {
      logfile = stderr;
      INFO("No logfile configured -- logging to stderr");
    } else if ((logfile = fopen(logpath, "a"))) {
      setlinebuf(logfile);
      INFOF("Logging to %s (fd %d)", logpath, fileno(logfile));
    } else {
      logfile = stderr;
      WARN_perror("fopen");
      WARNF("Cannot append to %s -- falling back to stderr", logpath);
    }
  }
  return logfile;
}

static int show_pid()
{
  if (flag_show_pid < 0 && !confLocked())
    flag_show_pid = confValueGetBoolean("log.show_pid", 0);
  return flag_show_pid;
}

static int show_time()
{
  if (flag_show_time < 0 && !confLocked())
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

void logMessage(int level, const char *file, unsigned int line, const char *function, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  vlogMessage(level, file, line, function, fmt, ap);
  va_end(ap);
}

void vlogMessage(int level, const char *file, unsigned int line, const char *function, const char *fmt, va_list ap)
{
  if (level != LOG_LEVEL_SILENT) {
    if (strbuf_is_empty(&logbuf))
      strbuf_init(&logbuf, _log_buf, sizeof _log_buf);
#ifndef ANDROID
    const char *levelstr = "UNKWN:";
    switch (level) {
      case LOG_LEVEL_FATAL: levelstr = "FATAL:"; break;
      case LOG_LEVEL_ERROR: levelstr = "ERROR:"; break;
      case LOG_LEVEL_INFO:  levelstr = "INFO:"; break;
      case LOG_LEVEL_WARN:  levelstr = "WARN:"; break;
      case LOG_LEVEL_DEBUG: levelstr = "DEBUG:"; break;
    }
    strbuf_sprintf(&logbuf, "%-6s ", levelstr);
#endif
    if (show_pid())
      strbuf_sprintf(&logbuf, "[%5u] ", getpid());
    if (show_time()) {
      struct timeval tv;
      if (gettimeofday(&tv, NULL) == -1) {
	strbuf_puts(&logbuf, "NOTIME______");
      } else {
	struct tm tm;
	char buf[20];
	if (strftime(buf, sizeof buf, "%T", localtime_r(&tv.tv_sec, &tm)) == 0)
	  strbuf_puts(&logbuf, "EMPTYTIME___");
	else
	  strbuf_sprintf(&logbuf, "%s.%03u ", buf, tv.tv_usec / 1000);
      }
    }
    strbuf_sprintf(&logbuf, "%s:%u:%s()  ", file ? trimbuildpath(file) : "NULL", line, function ? function : "NULL");
    strbuf_vsprintf(&logbuf, fmt, ap);
    strbuf_puts(&logbuf, "\n");
#ifdef ANDROID
    int alevel = ANDROID_LOG_UNKNOWN;
    switch (level) {
      case LOG_LEVEL_FATAL: alevel = ANDROID_LOG_FATAL; break;
      case LOG_LEVEL_ERROR: alevel = ANDROID_LOG_ERROR; break;
      case LOG_LEVEL_INFO:  alevel = ANDROID_LOG_INFO; break;
      case LOG_LEVEL_WARN:  alevel = ANDROID_LOG_WARN; break;
      case LOG_LEVEL_DEBUG: alevel = ANDROID_LOG_DEBUG; break;
    }
    __android_log_print(alevel, "servald", "%s", strbuf_str(&logbuf));
    strbuf_reset(&logbuf);
#else
    FILE *logf = open_logging();
    if (logf) {
      fputs(strbuf_str(&logbuf), logf);
      if (strbuf_overrun(&logbuf))
	fputs("OVERRUN\n", logf);
      strbuf_reset(&logbuf);
    }
#endif
  }
}

const char *trimbuildpath(const char *path)
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

int dump(char *name, unsigned char *addr, size_t len)
{
  char buf[100];
  size_t i;
  DEBUGF("Dump of %s", name);
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
    DEBUG(strbuf_str(b));
  }
  return 0;
}

char *catv(const char *data, char *buf, size_t len)
{
  strbuf b = strbuf_local(buf, len);
  for (; *data && !strbuf_overrun(b); ++data) {
    if (*data == '\n') strbuf_puts(b, "\\n");
    else if (*data == '\r')   strbuf_puts(b, "\\r");
    else if (*data == '\t')   strbuf_puts(b, "\\t");
    else if (*data == '\\')   strbuf_puts(b, "\\\\");
    else if (isprint(*data))  strbuf_putc(b, *data);
    else		      strbuf_sprintf(b, "\\x%02x", *data);
  }
  return buf;
}

int dumpResponses(struct response_set *responses)
{
  struct response *r;
  if (!responses) {
    DEBUG("Response set is NULL");
    return 0;
  }
  DEBUGF("Response set claims to contain %d entries.", responses->response_count);
  r = responses->responses;
  while(r) {
    DEBUGF("  response code 0x%02x", r->code);
    if (r->next && r->next->prev != r)
      DEBUG("    !! response chain is broken");
    r = r->next;
  }
  return 0;
}

unsigned int debugFlagMask(const char *flagname) {
  if	  (!strcasecmp(flagname,"all"))			return DEBUG_ALL;
  else if (!strcasecmp(flagname,"interfaces"))		return DEBUG_OVERLAYINTERFACES;
  else if (!strcasecmp(flagname,"rx"))			return DEBUG_PACKETRX;
  else if (!strcasecmp(flagname,"tx"))			return DEBUG_PACKETTX;
  else if (!strcasecmp(flagname,"verbose"))		return DEBUG_VERBOSE;
  else if (!strcasecmp(flagname,"verbio"))		return DEBUG_VERBOSE_IO;
  else if (!strcasecmp(flagname,"peers"))		return DEBUG_PEERS;
  else if (!strcasecmp(flagname,"dnaresponses"))	return DEBUG_DNARESPONSES;
  else if (!strcasecmp(flagname,"dnarequests"))		return DEBUG_DNAREQUESTS;
  else if (!strcasecmp(flagname,"simulation"))		return DEBUG_SIMULATION;
  else if (!strcasecmp(flagname,"dnavars"))		return DEBUG_DNAVARS;
  else if (!strcasecmp(flagname,"packetformats"))	return DEBUG_PACKETFORMATS;
  else if (!strcasecmp(flagname,"packetconstruction"))	return DEBUG_PACKETCONSTRUCTION;
  else if (!strcasecmp(flagname,"gateway"))		return DEBUG_GATEWAY;
  else if (!strcasecmp(flagname,"hlr"))			return DEBUG_HLR;
  else if (!strcasecmp(flagname,"sockio"))		return DEBUG_IO;
  else if (!strcasecmp(flagname,"frames"))		return DEBUG_OVERLAYFRAMES;
  else if (!strcasecmp(flagname,"abbreviations"))	return DEBUG_OVERLAYABBREVIATIONS;
  else if (!strcasecmp(flagname,"routing"))		return DEBUG_OVERLAYROUTING;
  else if (!strcasecmp(flagname,"security"))		return DEBUG_SECURITY;
  else if (!strcasecmp(flagname,"rhizome"))	        return DEBUG_RHIZOME;
  else if (!strcasecmp(flagname,"rhizomesync"))		return DEBUG_RHIZOMESYNC;
  else if (!strcasecmp(flagname,"monitorroutes"))	return DEBUG_OVERLAYROUTEMONITOR;
  else if (!strcasecmp(flagname,"queues"))		return DEBUG_QUEUES;
  else if (!strcasecmp(flagname,"broadcasts"))		return DEBUG_BROADCASTS;
  else if (!strcasecmp(flagname,"manifests"))		return DEBUG_MANIFESTS;
  else if (!strcasecmp(flagname,"mdprequests"))		return DEBUG_MDPREQUESTS;
  return 0;
}

/* Format a buffer of data as a printable representation, eg: "Abc\x0b\n\0", for display
   in log messages.
   @author Andrew Bettison <andrew@servalproject.com>
 */
char *toprint(char *dstStr, size_t dstChars, const unsigned char *srcBuf, size_t srcBytes)
{
  strbuf b = strbuf_local(dstStr, dstChars);
  strbuf_putc(b, '"');
  for (; srcBytes && !strbuf_overrun(b); ++srcBuf, --srcBytes) {
    if (*srcBuf == '\0')
      strbuf_puts(b, "\\0");
    else if (*srcBuf == '\n')
      strbuf_puts(b, "\\n");
    else if (*srcBuf == '\r')
      strbuf_puts(b, "\\r");
    else if (*srcBuf == '\t')
      strbuf_puts(b, "\\t");
    else if (isprint(*srcBuf))
      strbuf_putc(b, *srcBuf);
    else
      strbuf_sprintf(b, "\\x%02x", *srcBuf);
  }
  strbuf_putc(b, '"');
  if (strbuf_overrun(b)) {
    strbuf_trunc(b, -4);
    strbuf_puts(b, "\"...");
  }
  return dstStr;
}
