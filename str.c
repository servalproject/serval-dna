/*
 Serval string primitives
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
#include <string.h>
#include <ctype.h>
#include "str.h"
#include "log.h"

int str_startswith(char *str, const char *substring, char **afterp)
{
  while (*substring && *substring == *str)
    ++substring, ++str;
  if (*substring)
    return 0;
  if (afterp)
    *afterp = str;
  return 1;
}

int strcase_startswith(char *str, const char *substring, char **afterp)
{
  while (*substring && *str && toupper(*substring) == toupper(*str))
    ++substring, ++str;
  if (*substring)
    return 0;
  if (afterp)
    *afterp = str;
  return 1;
}

/* Like strstr() but doesn't depend on null termination */
const char *str_str(const char *s1,const char *s2,int s1len)
{
  int s2len=strlen(s2);
  for(;*s1&&(s1len--);s1++)
    if (!strncmp(s1,s2,s2len)) return s1;
  return NULL;
}
