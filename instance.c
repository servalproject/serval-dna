/*
Serval DNA instance directory path
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

#include <stdlib.h>
#include "serval.h"
#include "str.h"
#include "os.h"
#include "strbuf.h"
#include "strbuf_helpers.h"

static char *thisinstancepath = NULL;

const char *serval_instancepath()
{
  if (thisinstancepath)
    return thisinstancepath;
  const char *instancepath = getenv("SERVALINSTANCE_PATH");
  if (!instancepath)
    instancepath = DEFAULT_INSTANCE_PATH;
  return instancepath;
}

int formf_serval_instance_path(struct __sourceloc __whence, char *buf, size_t bufsiz, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  int ret = vformf_serval_instance_path(__whence, buf, bufsiz, fmt, ap);
  va_end(ap);
  return ret;
}

int vformf_serval_instance_path(struct __sourceloc __whence, char *buf, size_t bufsiz, const char *fmt, va_list ap)
{
  strbuf b = strbuf_local(buf, bufsiz);
  strbuf_va_vprintf(b, fmt, ap);
  if (!strbuf_overrun(b) && strbuf_len(b) && buf[0] != '/') {
    strbuf_reset(b);
    strbuf_puts(b, serval_instancepath());
    strbuf_putc(b, '/');
    strbuf_va_vprintf(b, fmt, ap);
  }
  if (!strbuf_overrun(b))
    return 1;
  WHYF("instance path overflow (strlen %lu, sizeof buffer %lu): %s",
      (unsigned long)strbuf_count(b),
      (unsigned long)bufsiz,
      alloca_str_toprint(buf));
  return 0;
}

int create_serval_instance_dir() {
  return emkdirs(serval_instancepath(), 0700);
}
