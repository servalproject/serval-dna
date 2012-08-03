/*
Serval string buffer primitives
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

#define __STRBUF_INLINE
#include "strbuf.h"

static inline size_t min(size_t a, size_t b) {
  return a < b ? a : b;
}

strbuf strbuf_init(strbuf sb, char *buffer, size_t size)
{
  sb->start = buffer;
  sb->end = sb->start + size - 1;
  return strbuf_reset(sb);
}

strbuf strbuf_reset(strbuf sb)
{
  sb->current = sb->start;
  if (sb->start && sb->end >= sb->start) {
    *sb->start = '\0';
    *sb->end = '\0'; // should never get overwritten
  }
  return sb;
}

strbuf strbuf_ncat(strbuf sb, const char *text, size_t len)
{
  if (sb->start && sb->current < sb->end) {
    register size_t n = min(sb->end - sb->current, len);
    char *c;
    for (c = sb->current; n && (*c = *text); --n, ++c, ++text)
      ;
    *c = '\0';
  }
  sb->current += len;
  return sb;
}

strbuf strbuf_puts(strbuf sb, const char *text)
{
  if (sb->start && sb->current < sb->end) {
    register size_t n = sb->end - sb->current;
    while (n-- && (*sb->current = *text)) {
      ++sb->current;
      ++text;
    }
  }
  while (*text) {
    ++sb->current;
    ++text;
  }
  return sb;
}

strbuf strbuf_tohex(strbuf sb, const unsigned char *data, size_t len)
{
  static char hexdigit[16] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
  char *p = sb->current;
  sb->current += len * 2;
  if (sb->start) {
    char *e = sb->current < sb->end ? sb->current : sb->end;
    // The following loop could overwrite the '\0' at *sp->end.
    for (; p < e; ++data) {
      *p++ = hexdigit[*data >> 4];
      *p++ = hexdigit[*data & 0xf];
    }
    // This will restore the '\0' at *sp->end if it was overwritten.
    *e = '\0';
  }
  return sb;
}

strbuf strbuf_putc(strbuf sb, char ch)
{
  if (sb->start && sb->current < sb->end) {
    *sb->current++ = ch;
    *sb->current = '\0';
  } else
    ++sb->current;
  return sb;
}

int strbuf_sprintf(strbuf sb, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  int n = strbuf_vsprintf(sb, fmt, ap);
  va_end(ap);
  return n;
}

int strbuf_vsprintf(strbuf sb, const char *fmt, va_list ap)
{
  int n;
  if (sb->start && sb->current < sb->end) {
    n = vsnprintf(sb->current, sb->end - sb->current + 1, fmt, ap);
    *sb->end = '\0';
  } else {
    char tmp[1];
    n = vsnprintf(tmp, sizeof tmp, fmt, ap);
  }
  if (n != -1)
    sb->current += n;
  return n;
}

char *strbuf_substr(const_strbuf sb, int offset)
{
  char *s;
  if (offset < 0) {
    s = (sb->current < sb->end ? sb->current : sb->end) + offset;
    if (s < sb->start)
      s = sb->start;
  } else {
    s = sb->start + offset;
    if (s > sb->end)
      s = sb->end;
  }
  return s;
}

strbuf strbuf_trunc(strbuf sb, int offset)
{
  if (offset < 0) {
    char *e = sb->current < sb->end ? sb->current : sb->end;
    sb->current = offset <= sb->start - e ? sb->start : e + offset;
  } else {
    char *s = sb->start + offset;
    if (s < sb->current)
      sb->current = s;
  }
  if (sb->start && sb->current < sb->end)
    *sb->current = '\0';
  return sb;
}
