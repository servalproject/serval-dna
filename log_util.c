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

#include "log.h"
#include "strbuf.h"
#include "strbuf_helpers.h"

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
