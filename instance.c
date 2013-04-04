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

void serval_setinstancepath(const char *instancepath)
{
  if (thisinstancepath == NULL)
    free(thisinstancepath);
  thisinstancepath = strdup(instancepath);
}

int form_serval_instance_path(char *buf, size_t bufsiz, const char *path)
{
  strbuf b = strbuf_local(buf, bufsiz);
  strbuf_path_join(b, serval_instancepath(), path, NULL);
  if (!strbuf_overrun(b))
    return 1;
  WHYF("Cannot form pathname \"%s/%s\" -- buffer too small (%lu bytes)", serval_instancepath(), path, (unsigned long)bufsiz);
  return 0;
}

int create_serval_instance_dir() {
  return emkdirs(serval_instancepath(), 0700);
}
