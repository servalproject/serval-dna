/*
Serval logging to standard error
Copyright 2014 Serval Project Inc.

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
#include <time.h>
#include <sys/time.h>
#include "log.h"

/* An implementation of the Serval logging API that writes directly to standard error
 * using stdio buffered output.
 */

int serverMode=0;

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

void vlogMessage(int level, struct __sourceloc whence, const char *fmt, va_list ap)
{
  const char *levelstr = "UNKWN:";
  switch (level) {
  case LOG_LEVEL_FATAL:
    levelstr = "FATAL:";
    break;
  case LOG_LEVEL_ERROR:
    levelstr = "ERROR:";
    break;
  case LOG_LEVEL_INFO:
    levelstr = "INFO:";
    break;
  case LOG_LEVEL_WARN:
    levelstr = "WARN:";
    break;
  case LOG_LEVEL_DEBUG:
    levelstr = "DEBUG:";
    break;
  }
  
  struct timeval tv;
  struct tm tm;
  gettimeofday(&tv, NULL);
  localtime_r(&tv.tv_sec, &tm);
  char buf[50];
  strftime(buf, sizeof buf, "%T", &tm);
  fprintf(stderr, "%s.%03u ", buf, (unsigned int)tv.tv_usec / 1000);
  
  fprintf(stderr, "%s ", levelstr);
  if (whence.file) {
    fprintf(stderr, "%s", _trimbuildpath(whence.file));
    if (whence.line)
      fprintf(stderr, ":%u", whence.line);
    if (whence.function)
      fprintf(stderr, ":%s()", whence.function);
    fputc(' ', stderr);
  } else if (whence.function) {
    fprintf(stderr, "%s() ", whence.function);
  }
  vfprintf(stderr, fmt, ap);
  fputc('\n', stderr);
}

void logFlush()
{
  fflush(stderr);
}

void logConfigChanged()
{
}
