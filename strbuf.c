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

#define __STRBUF_INLINE
#include "strbuf.h"

static inline size_t min(size_t a, size_t b) {
  return a < b ? a : b;
}

strbuf strbuf_init(strbuf sb, char *buffer, size_t size)
{
  sb->start = sb->current = buffer;
  sb->end = sb->start + size - 1;
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
    while (n-- && (*sb->current = *text++))
      ++sb->current;
  }
  return sb;
}

strbuf strbuf_puts(strbuf sb, const char *text)
{
  if (sb->start && sb->current < sb->end) {
    register size_t n = sb->end - sb->current;
    while (n-- && (*sb->current = *text++))
      ++sb->current;
  }
  return sb;
}

strbuf strbuf_putc(strbuf sb, char ch)
{
  if (sb->start && sb->current < sb->end) {
    *sb->current++ = ch;
    *sb->current = '\0';
  }
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
