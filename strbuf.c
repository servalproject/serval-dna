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
#include "str.h"

static inline size_t min(size_t a, size_t b) {
  return a < b ? a : b;
}

strbuf strbuf_init(strbuf sb, char *buffer, ssize_t size)
{
  sb->start = buffer;
  sb->end = size >= 0 ? sb->start + size - 1 : NULL;
  return strbuf_reset(sb);
}

strbuf strbuf_reset(strbuf sb)
{
  sb->current = sb->start;
  if (sb->start)
    *sb->start = '\0';
  return sb;
}

strbuf strbuf_ncat(strbuf sb, const char *text, size_t len)
{
  if (sb->start && (!sb->end || (sb->current < sb->end))) {
    register size_t n = sb->end ? min(sb->end - sb->current, len) : len;
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
  if (sb->start) {
    if (!sb->end) {
      while ((*sb->current = *text)) {
	++sb->current;
	++text;
      }
    } else if (sb->current < sb->end) {
      register size_t n = sb->end - sb->current;
      while (n-- && (*sb->current = *text)) {
	++sb->current;
	++text;
      }
      *sb->current = '\0';
    }
  }
  while (*text++)
    ++sb->current;
  return sb;
}

strbuf strbuf_tohex(strbuf sb, size_t strlen, const unsigned char *data)
{
  char *p = sb->current;
  sb->current += strlen;
  if (sb->start) {
    char *e = sb->end && sb->current > sb->end ? sb->end : sb->current;
    // The following loop could overwrite the '\0' at *sp->end.
    size_t i;
    for (i = 0; i < strlen && p < e; ++i)
      *p++ = (i & 1) ? hexdigit_upper[*data++ & 0xf] : hexdigit_upper[*data >> 4];
    // This will restore the '\0' at *sp->end if it was overwritten.
    *e = '\0';
  }
  return sb;
}

strbuf strbuf_putc(strbuf sb, char ch)
{
  if (sb->start && (!sb->end || sb->current < sb->end)) {
    sb->current[0] = ch;
    sb->current[1] = '\0';
  }
  ++sb->current;
  return sb;
}

strbuf strbuf_sprintf(strbuf sb, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  strbuf_vsprintf(sb, fmt, ap);
  va_end(ap);
  return sb;
}

strbuf strbuf_vsprintf(strbuf sb, const char *fmt, va_list ap)
{
  int n;
  if (sb->start && !sb->end) {
    n = vsprintf(sb->current, fmt, ap);
  } else if (sb->start && sb->current < sb->end) {
    int space = sb->end - sb->current + 1;
    n = vsnprintf(sb->current, space, fmt, ap);
    if (n >= space)
      *sb->end = '\0';
  } else {
    char tmp[1];
    n = vsnprintf(tmp, sizeof tmp, fmt, ap);
  }
  if (n != -1)
    sb->current += n;
  return sb;
}

char *strbuf_substr(const_strbuf sb, int offset)
{
  char *s;
  if (!sb->start)
    s = NULL;
  else if (offset < 0) {
    s = strbuf_end(sb) + offset;
    if (s < sb->start)
      s = sb->start;
  } else {
    s = sb->start + offset;
    if (sb->end && s > sb->end)
      s = sb->end;
  }
  return s;
}

strbuf strbuf_trunc(strbuf sb, int offset)
{
  if (offset < 0) {
    char *e = strbuf_end(sb);
    sb->current = offset <= sb->start - e ? sb->start : e + offset;
  } else {
    char *s = sb->start + offset;
    if (s < sb->current)
      sb->current = s;
  }
  if (sb->start && (!sb->end || sb->current < sb->end))
    *sb->current = '\0';
  return sb;
}
