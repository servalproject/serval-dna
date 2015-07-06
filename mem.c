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

void *_emalloc(struct __sourceloc __whence, size_t bytes)
{
  char *new = malloc(bytes);
  if (!new) {
    WHYF_perror("malloc(%lu)", (long)bytes);
    return NULL;
  }
  return new;
}

void *_erealloc(struct __sourceloc __whence, void *ptr, size_t bytes)
{
  char *new = realloc(ptr, bytes);
  if (!new) {
    WHYF_perror("realloc(%p, %lu)", ptr, (unsigned long)bytes);
    return NULL;
  }
  return new;
}

void *_emalloc_zero(struct __sourceloc __whence, size_t bytes)
{
  char *new = _emalloc(__whence, bytes);
  if (new)
    memset(new, 0, bytes);
  return new;
}

char *_strn_edup(struct __sourceloc __whence, const char *str, size_t len)
{
  char *new = _emalloc(__whence, len + 1);
  if (new)
    strncpy(new, str, len)[len] = '\0';
  return new;
}

char *_str_edup(struct __sourceloc __whence, const char *str)
{
  return _strn_edup(__whence, str, strlen(str));
}

#undef malloc
#undef calloc
#undef free
#undef realloc

#define SDM_GUARD_AFTER 16384

void *_serval_debug_malloc(unsigned int bytes, struct __sourceloc __whence)
{
  void *r=malloc(bytes+SDM_GUARD_AFTER);
  _DEBUGF("malloc(%d) -> %p", bytes, r); 
  return r;
}

void *_serval_debug_calloc(unsigned int bytes, unsigned int count, struct __sourceloc __whence)
{
  void *r=calloc((bytes*count)+SDM_GUARD_AFTER,1);
  _DEBUGF("calloc(%d,%d) -> %p", bytes, count, r); 
  return r;
}

void _serval_debug_free(void *p, struct __sourceloc __whence)
{
  free(p);
  _DEBUGF("free(%p)", p); 
}
