/*
Copyright (C) 2014 Serval Project Inc.
 
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

#include "whence.h"
#include "strbuf.h"
#include "strbuf_helpers.h"

const struct __sourceloc __whence = __NOWHERE__;

char *sourceloc_tostr(char *dstStr, ssize_t dstBufSiz, struct __sourceloc loc)
{
  strbuf b = strbuf_local(dstStr, dstBufSiz);
  strbuf_append_sourceloc(b, loc);
  return dstStr;
}

size_t sourceloc_tostr_len(struct __sourceloc loc)
{
  return strbuf_count(strbuf_append_sourceloc(strbuf_local(NULL, 0), loc));
}

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

void xprint_sourceloc(XPRINTF xpf, struct __sourceloc loc)
{
  int flag = 0;
  if (loc.file && loc.file[0]) {
    xprintf(xpf, "%s", _trimbuildpath(loc.file));
    ++flag;
  }
  if (loc.line) {
    if (flag)
      xputc(':', xpf);
    xprintf(xpf, "%u", loc.line);
    ++flag;
  }
  if (loc.function && loc.function[0]) {
    if (flag)
      xputc(':', xpf);
    xprintf(xpf, "%s", loc.function);
    if (loc.function[strlen(loc.function) - 1] != ')')
      xputs("()", xpf);
    ++flag;
  }
}
