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

#include <stdlib.h>
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

int parse_argv(char *cmdline, char delim, char **argv, int max_argv)
{
  int argc=0;
  if (*cmdline && argc<max_argv){
    argv[argc++]=cmdline;
  }
  // TODO quoted argument handling?
  while(*cmdline){
    if (*cmdline==delim){
      *cmdline=0;
      if (cmdline[1] && argc<max_argv)
	argv[argc++]=cmdline+1;
    }
    cmdline++;
  }
  return argc;
}

/* Like strstr() but doesn't depend on null termination */
char *str_str(char *haystack, const char *needle, int haystack_len)
{
  size_t needle_len = strlen(needle);
  if (needle_len == 0)
    return haystack;
  if (haystack_len >= needle_len) {
    for (; *haystack && haystack_len >= needle_len; ++haystack, --haystack_len)
      if (strncmp(haystack, needle, needle_len) == 0)
	return haystack;
  }
  return NULL;
}

int str_to_ll_scaled(const char *str, int base, long long *result, char **afterp)
{
  if (!(isdigit(*str) || *str == '-' || *str == '+'))
    return 0;
  char *end;
  long long value = strtoll(str, &end, base);
  if (end == str)
    return 0;
  switch (*end) {
    case '\0': break;
    case 'k': value *= 1000LL; ++end; break;
    case 'K': value *= 1024LL; ++end; break;
    case 'm': value *= 1000LL * 1000LL; ++end; break;
    case 'M': value *= 1024LL * 1024LL; ++end; break;
    case 'g': value *= 1000LL * 1000LL * 1000LL; ++end; break;
    case 'G': value *= 1024LL * 1024LL * 1024LL; ++end; break;
    default: return 0;
  }
  if (afterp)
    *afterp = end;
  else if (*end)
    return 0;
  *result = value;
  return 1;
}
