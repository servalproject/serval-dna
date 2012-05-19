/*
Serval string buffer primitives
Copyright (C) 2012 The Serval Project
 
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

#include "strbuf.h"

void strbuf_init(strbuf *sb, char *buffer, size_t size)
{
  sb->start = sb->current = buffer;
  sb->end = sb->start + size - 1;
  if (sb->start && sb->end >= sb->start) {
    *sb->start = '\0';
    *sb->end = '\0';
  }
}

strbuf *strbuf_ncat(strbuf *sb, const char *text, size_t len)
{
  if (sb->start && sb->current < sb->end) {
    size_t n = sb->end - sb->current;
    strncpy(sb->current, text, len < n ? len : n);
  }
  sb->current += len;
  return sb;
}

int strbuf_sprintf(strbuf *sb, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  int n = strbuf_vsprintf(sb, fmt, ap);
  va_end(ap);
  return n;
}

int strbuf_vsprintf(strbuf *sb, const char *fmt, va_list ap) 
{
  va_list ap2;
  va_copy(ap2, ap);
  int n;
  if (sb->start && sb->current < sb->end) {
    n = vsnprintf(sb->start, sb->end - sb->current, fmt, ap2);
  } else {
    char tmp[1];
    n = vsnprintf(tmp, sizeof tmp, fmt, ap2);
  }
  if (n != -1)
    sb->current += n;
  va_end(ap2);
  return n;
}

char *strbuf_substr(const strbuf *sb, int offset)
{
  char *s;
  if (offset < 0) {
    s = sb->end + offset;
    if (s < sb->start)
      s = sb->start;
  } else {
    s = sb->start + offset;
    if (s > sb->end)
      s = sb->end;
  }
  return s;
}
