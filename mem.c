/* 
Serval DNA memory management
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

#include <string.h>
#include "mem.h"

void *_emalloc(struct __sourceloc __whence, size_t len)
{
  char *new = malloc(len + 1);
  if (!new) {
    WHYF_perror("malloc(%lu)", (long)len);
    return NULL;
  }
  return new;
}

char *_strn_edup(struct __sourceloc __whence, const char *str, size_t len)
{
  char *new = _emalloc(__whence, len + 1);
  if (new) {
    strncpy(new, str, len);
    new[len] = '\0';
  }
  return new;
}

char *_str_edup(struct __sourceloc __whence, const char *str)
{
  return _strn_edup(__whence, str, strlen(str));
}
