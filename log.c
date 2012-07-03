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

unsigned int debug = 0;
static FILE *logfile = NULL;

#ifdef ANDROID
#include <android/log.h> 
#endif

FILE *open_logging()
{
  if (!logfile) {
    const char *logpath = getenv("SERVALD_LOG_FILE");
    if (!logpath)
      logpath = confValueGet("logfile", NULL);
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
    strbuf b = strbuf_alloca(8192);
    strbuf_sprintf(b, "%s:%u:%s()  ", file ? trimbuildpath(file) : "NULL", line, function ? function : "NULL");
    strbuf_vsprintf(b, fmt, ap);
#ifdef ANDROID
    int alevel = ANDROID_LOG_UNKNOWN;
    switch (level) {
      case LOG_LEVEL_FATAL: alevel = ANDROID_LOG_FATAL; break;
      case LOG_LEVEL_ERROR: alevel = ANDROID_LOG_ERROR; break;
      case LOG_LEVEL_INFO:  alevel = ANDROID_LOG_INFO; break;
      case LOG_LEVEL_WARN:  alevel = ANDROID_LOG_WARN; break;
      case LOG_LEVEL_DEBUG: alevel = ANDROID_LOG_DEBUG; break;
    }
    __android_log_print(alevel, "servald", "%s", strbuf_str(b));
#endif
    const char *levelstr = "UNKNOWN";
    switch (level) {
      case LOG_LEVEL_FATAL: levelstr = "FATAL"; break;
      case LOG_LEVEL_ERROR: levelstr = "ERROR"; break;
      case LOG_LEVEL_INFO:  levelstr = "INFO"; break;
      case LOG_LEVEL_WARN:  levelstr = "WARN"; break;
      case LOG_LEVEL_DEBUG: levelstr = "DEBUG"; break;
    }
    if (logfile || open_logging())
      fprintf(logfile, "%s: [%d] %s\n", levelstr, getpid(), strbuf_str(b));
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
  else if (!strcasecmp(flagname,"filesync"))		return DEBUG_RHIZOMESYNC;
  else if (!strcasecmp(flagname,"monitorroutes"))	return DEBUG_OVERLAYROUTEMONITOR;
  else if (!strcasecmp(flagname,"queues"))		return DEBUG_QUEUES;
  else if (!strcasecmp(flagname,"broadcasts"))		return DEBUG_BROADCASTS;
  else if (!strcasecmp(flagname,"manifests"))		return DEBUG_MANIFESTS;
  WARNF("Unsupported debug flag '%s'", flagname);
  return 0;
}

