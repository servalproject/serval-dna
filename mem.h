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

#ifndef __SERVAL_DNA__MEM_H
#define __SERVAL_DNA__MEM_H

#include <sys/types.h>
#include "log.h"

// #define MALLOC_PARANOIA

#ifdef MALLOC_PARANOIA
#define malloc(X) _serval_debug_malloc(X,__WHENCE__)
#define calloc(X,Y) _serval_debug_calloc(X,Y,__WHENCE__)
#define free(X) _serval_debug_free(X,__WHENCE__)
void *_serval_debug_malloc(unsigned int bytes, struct __sourceloc whence);
void *_serval_debug_calloc(unsigned int bytes, unsigned int count, struct __sourceloc whence);
void _serval_debug_free(void *p, struct __sourceloc whence);
#endif

/* Equivalent to malloc(3), but logs an error before returning NULL.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
void *_emalloc(struct __sourceloc, size_t bytes);

/* Equivalent to realloc(3), but logs an error before returning NULL.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
void *_erealloc(struct __sourceloc __whence, void *ptr, size_t bytes);

/* Equivalent to malloc(3) followed by memset(3) to zerofill, but logs an error
 * before returning NULL.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
void *_emalloc_zero(struct __sourceloc, size_t bytes);

/* Equivalent to strdup(3)/strndup(3), but logs an error before returning NULL.
 *
 * Why aren't these in str.h?  Because str.c must not depend on log.h/log.c!  str.c is used in link
 * contexts where log.c is not present.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
char *_str_edup(struct __sourceloc, const char *str);
char *_strn_edup(struct __sourceloc, const char *str, size_t len);

#define emalloc(bytes)       _emalloc(__HERE__, (bytes))
#define erealloc(ptr, bytes) _erealloc(__HERE__, (ptr), (bytes))
#define emalloc_zero(bytes)  _emalloc_zero(__HERE__, (bytes))
#define str_edup(str)        _str_edup(__HERE__, (str))
#define strn_edup(str, len)  _strn_edup(__HERE__, (str), (len))

#endif // __SERVAL_DNA__MEM_H
