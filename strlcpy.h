/*
  Copyright (C) 2012,2015 Serval Project Inc.

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


#ifndef __STRLCPY_H__
#define __STRLCPY_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// Do not use strlcpy() in Serval DNA source code, use strncpy_nul() or
// buf_strncpy_nul() from "str.h" instead.  This strlcpy() is provided only
// because it is needed by sqlite3.c.

#ifdef HAVE_STRLCPY
#  include <string.h>
#else
#  include <stdlib.h>  // for size_t
size_t strlcpy(char *dst, const char *src, size_t sz);
#endif

#endif
