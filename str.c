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

#define __STR_INLINE
#include "str.h"
#include "strbuf_helpers.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

char hexdigit[16] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

char *tohex(char *dstHex, const unsigned char *srcBinary, size_t bytes)
{
  char *p;
  for (p = dstHex; bytes--; ++srcBinary) {
    *p++ = hexdigit[*srcBinary >> 4];
    *p++ = hexdigit[*srcBinary & 0xf];
  }
  *p = '\0';
  return dstHex;
}

/* Convert nbinary*2 ASCII hex characters [0-9A-Fa-f] to nbinary bytes of data.  Can be used to
   perform the conversion in-place, eg, fromhex(buf, (char*)buf, n);  Returns -1 if a non-hex-digit
   character is encountered, otherwise returns the number of binary bytes produced (= nbinary).
   @author Andrew Bettison <andrew@servalproject.com>
 */
size_t fromhex(unsigned char *dstBinary, const char *srcHex, size_t nbinary)
{
  size_t count = 0;
  while (count != nbinary) {
    unsigned char high = hexvalue(*srcHex++);
    if (high & 0xf0) return -1;
    unsigned char low = hexvalue(*srcHex++);
    if (low & 0xf0) return -1;
    dstBinary[count++] = (high << 4) + low;
  }
  return count;
}

/* Convert nbinary*2 ASCII hex characters [0-9A-Fa-f] followed by a nul '\0' character to nbinary bytes of data.  Can be used to
   perform the conversion in-place, eg, fromhex(buf, (char*)buf, n);  Returns -1 if a non-hex-digit
   character is encountered or the character immediately following the last hex digit is not a nul,
   otherwise returns zero.
   @author Andrew Bettison <andrew@servalproject.com>
 */
int fromhexstr(unsigned char *dstBinary, const char *srcHex, size_t nbinary)
{
  return (fromhex(dstBinary, srcHex, nbinary) == nbinary && srcHex[nbinary * 2] == '\0') ? 0 : -1;
}

/* Does this whole buffer contain the same value? */
int is_all_matching(const unsigned char *ptr, size_t len, unsigned char value)
{
  while (len--)
    if (*ptr++ != value)
      return 0;
  return 1;
}

char *str_toupper_inplace(char *str)
{
  register char *s;
  for (s = str; *s; ++s)
    *s = toupper(*s);
  return str;
}

int str_startswith(const char *str, const char *substring, const char **afterp)
{
  while (*substring && *substring == *str)
    ++substring, ++str;
  if (*substring)
    return 0;
  if (afterp)
    *afterp = str;
  return 1;
}

int strn_startswith(const char *str, size_t len, const char *substring, const char **afterp)
{
  while (len && *substring && *substring == *str)
    --len, ++substring, ++str;
  if (*substring)
    return 0;
  if (afterp)
    *afterp = str;
  return 1;
}

int strcase_startswith(const char *str, const char *substring, const char **afterp)
{
  while (*substring && *str && toupper(*substring) == toupper(*str))
    ++substring, ++str;
  if (*substring)
    return 0;
  if (afterp)
    *afterp = str;
  return 1;
}

int strncase_startswith(const char *str, size_t len, const char *substring, const char **afterp)
{
  while (len && *substring && toupper(*substring) == toupper(*str))
    --len, ++substring, ++str;
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

int str_to_ll_scaled(const char *str, int base, long long *result, const char **afterp)
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

/* Format a buffer of data as a printable representation, eg: "Abc\x0b\n\0", for display
   in log messages.
   @author Andrew Bettison <andrew@servalproject.com>
 */
char *toprint(char *dstStr, ssize_t dstBufSiz, const char *srcBuf, size_t srcBytes, const char quotes[2])
{
  strbuf b = strbuf_local(dstStr, dstBufSiz);
  strbuf_toprint_quoted_len(b, quotes, srcBuf, srcBytes);
  return dstStr;
}

/* Compute the length of the string produced by toprint().  If dstStrLen == -1 then returns the
   exact number of characters in the printable representation (excluding the terminating nul),
   otherwise returns dstStrLen.
   @author Andrew Bettison <andrew@servalproject.com>
 */
size_t toprint_len(const char *srcBuf, size_t srcBytes, const char quotes[2])
{
  return strbuf_count(strbuf_toprint_quoted_len(strbuf_local(NULL, 0), quotes, srcBuf, srcBytes));
}

/* Format a null-terminated string as a printable representation, eg: "Abc\x0b\n", for display
   in log messages.
   @author Andrew Bettison <andrew@servalproject.com>
 */
char *toprint_str(char *dstStr, ssize_t dstBufSiz, const char *srcStr, const char quotes[2])
{
  strbuf b = strbuf_local(dstStr, dstBufSiz);
  strbuf_toprint_quoted(b, quotes, srcStr);
  return dstStr;
}

/* Compute the length of the string produced by toprint_str().  If dstStrLen == -1 then returns the
   exact number of characters in the printable representation (excluding the terminating nul),
   otherwise returns dstStrLen.
   @author Andrew Bettison <andrew@servalproject.com>
 */
size_t toprint_str_len(const char *srcStr, const char quotes[2])
{
  return strbuf_count(strbuf_toprint_quoted(strbuf_local(NULL, 0), quotes, srcStr));
}

size_t str_fromprint(unsigned char *dst, const char *src)
{
  unsigned char *const odst = dst;
  while (*src) {
    switch (*src) {
    case '\\':
      ++src;
      switch (*src) {
      case '\0': *dst++ = '\\'; break;
      case '0': *dst++ = '\0'; ++src; break;
      case 'n': *dst++ = '\n'; ++src; break;
      case 'r': *dst++ = '\r'; ++src; break;
      case 't': *dst++ = '\t'; ++src; break;
      case 'x':
	if (isxdigit(src[1]) && isxdigit(src[2])) {
	  ++src;
	  fromhex(dst++, src, 1);
	  src += 2;
	  break;
	}
	// fall through
      default:
	*dst++ = *src++;
	break;
      }
      break;
    default:
      *dst++ = *src++;
      break;
    }
  }
  return dst - odst;
}
