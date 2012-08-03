/*
Serval extensible printf.
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

#include <stdio.h>
#include <stdlib.h>
#include "xprintf.h"

void xprintf(XPRINTF xfp, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  vxprintf(xfp, fmt, ap);
  va_end(ap);
}

void vxprintf(XPRINTF xfp, const char *fmt, va_list ap)
{
  (*xfp.func)(xfp.context, fmt, ap);
}

void xputs(const char *str, XPRINTF xpf)
{
  xprintf(xpf, "%s", str);
}

void xputc(char c, XPRINTF xpf)
{
  xprintf(xpf, "%c", c);
}

void _cx_vprintf_stdio(void *context, const char *fmt, va_list ap)
{
  vfprintf((FILE *)context, fmt, ap);
}

static void grow_mallocbuf(struct mallocbuf *mb, size_t extra)
{
  size_t newsize = mb->size + extra;
  // Round up to nearest multiple of 1024.
  newsize = newsize + 1024 - ((newsize - 1) % 1024 + 1);
  char *newbuf = realloc(mb->buffer, newsize);
  if (newbuf) {
    mb->current += newbuf - mb->buffer;
    mb->size = newsize;
    mb->buffer = newbuf;
  }
}

void _cx_vprintf_mallocbuf(void *context, const char *fmt, va_list ap)
{
  struct mallocbuf *mb = (struct mallocbuf *) context;
  if (mb->buffer == NULL)
    grow_mallocbuf(mb, 1024);
  if (mb->current) {
    if (mb->current + 1 >= mb->buffer + mb->size)
      grow_mallocbuf(mb, 1024);
    int n = vsnprintf(mb->current, mb->buffer + mb->size - mb->current, fmt, ap);
    char *newcurrent = mb->current + n;
    char *end = mb->buffer + mb->size;
    if (newcurrent < end)
      mb->current = newcurrent;
    else {
      grow_mallocbuf(mb, newcurrent - end + 1);
      n = vsnprintf(mb->current, mb->buffer + mb->size - mb->current, fmt, ap);
      char *newcurrent = mb->current + n;
      char *end = mb->buffer + mb->size;
      if (newcurrent < end)
	mb->current = newcurrent;
      else {
	mb->current = mb->buffer + mb->size - 1;
	*mb->current = '\0';
      }
    }
  }
}
