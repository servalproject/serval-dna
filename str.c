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
#include "constants.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <limits.h>

const char hexdigit[16] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

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

const char *strnchr(const char *s, size_t n, char c)
{
  for (; n; --n, ++s) {
    if (*s == c)
      return s;
    if (!*s)
      break;
  }
  return NULL;
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

int strn_str_cmp(const char *str1, size_t len1, const char *str2)
{
  int r = strncmp(str1, str2, len1);
  if (r)
    return r;
  size_t len2 = strlen(str2);
  return len1 < len2 ? -1 : len1 > len2 ? 1 : 0;
}

int strn_str_casecmp(const char *str1, size_t len1, const char *str2)
{
  int r = strncasecmp(str1, str2, len1);
  if (r)
    return r;
  size_t len2 = strlen(str2);
  return len1 < len2 ? -1 : len1 > len2 ? 1 : 0;
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

static struct scale_factor {
  char symbol;
  uint64_t factor;
}
  scale_factors[] = {
      { 'G', 1024LL * 1024LL * 1024LL },
      { 'g', 1000LL * 1000LL * 1000LL },
      { 'M', 1024LL * 1024LL },
      { 'm', 1000LL * 1000LL },
      { 'K', 1024LL },
      { 'k', 1000LL }
  };

uint64_t scale_factor(const char *str, const char **afterp)
{
  uint64_t factor = 1;
  int i;
  for (i = 0; i != NELS(scale_factors); ++i)
    if (scale_factors[i].symbol == str[0]) {
      ++str;
      factor = scale_factors[i].factor;
      break;
    }
  if (afterp)
    *afterp = str;
  else if (*str)
    factor = 0;
  return factor;
}

int str_to_int64_scaled(const char *str, int base, int64_t *result, const char **afterp)
{
  if (isspace(*str))
    return 0;
  const char *end = str;
  long long value = strtoll(str, (char**)&end, base);
  if (end == str)
    return 0;
  value *= scale_factor(end, &end);
  if (afterp)
    *afterp = end;
  else if (*end)
    return 0;
  *result = value;
  return 1;
}

int str_to_uint64_scaled(const char *str, int base, uint64_t *result, const char **afterp)
{
  if (isspace(*str))
    return 0;
  const char *end = str;
  unsigned long long value = strtoull(str, (char**)&end, base);
  if (end == str)
    return 0;
  value *= scale_factor(end, &end);
  if (afterp)
    *afterp = end;
  else if (*end)
    return 0;
  *result = value;
  return 1;
}

int uint64_scaled_to_str(char *str, size_t len, uint64_t value)
{
  char symbol = '\0';
  int i;
  for (i = 0; i != NELS(scale_factors); ++i)
    if (value % scale_factors[i].factor == 0) {
      value /= scale_factors[i].factor;
      symbol = scale_factors[i].symbol;
      break;
    }
  strbuf b = strbuf_local(str, len);
  strbuf_sprintf(b, "%llu", (unsigned long long) value);
  if (symbol)
    strbuf_putc(b, symbol);
  return strbuf_overrun(b) ? 0 : 1;
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

/* Format a null-terminated string as a printable representation, eg: `Abc\x0b\n`, for display
   in log messages.  If the given string pointer is NULL, return the string "NULL" without quotes.
   @author Andrew Bettison <andrew@servalproject.com>
 */
char *toprint_str(char *dstStr, ssize_t dstBufSiz, const char *srcStr, const char quotes[2])
{
  strbuf b = strbuf_local(dstStr, dstBufSiz);
  if (srcStr)
    strbuf_toprint_quoted(b, quotes, srcStr);
  else
    strbuf_puts(b, "NULL");
  return dstStr;
}

/* Compute the length of the string produced by toprint_str(), excluding the terminating nul.
   @author Andrew Bettison <andrew@servalproject.com>
 */
size_t toprint_str_len(const char *srcStr, const char quotes[2])
{
  return srcStr ? strbuf_count(strbuf_toprint_quoted(strbuf_local(NULL, 0), quotes, srcStr)) : 4;
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

/* Return true if the string resembles a URI.
 * Based on RFC-3986 generic syntax, assuming nothing about the hierarchical part.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int str_is_uri(const char *uri)
{
  const char *p;
  size_t len;
  if (!str_uri_scheme(uri, &p, &len))
    return 0;
  const char *const q = (p += len + 1);
  for (; *p && (is_uri_char_unreserved(*p) || is_uri_char_reserved(*p)) && *p != '?' && *p != '#'; ++p)
    ;
  if (p == q)
    return 0;
  if (*p == '?')
    for (++p; *p && (is_uri_char_unreserved(*p) || is_uri_char_reserved(*p)) && *p != '?' && *p != '#'; ++p)
      ;
  if (*p == '#')
    for (++p; *p && (is_uri_char_unreserved(*p) || is_uri_char_reserved(*p)) && *p != '?' && *p != '#'; ++p)
      ;
  return !*p;
}

int str_uri_scheme(const char *uri, const char **partp, size_t *lenp)
{
  const char *p = uri;
  // Scheme is ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
  if (!isalpha(*p++))
    return 0;
  while (is_uri_char_scheme(*p))
    ++p;
  // Scheme is followed by colon ":".
  if (*p != ':')
    return 0;
  if (partp)
    *partp = uri;
  if (lenp)
    *lenp = p - uri;
  return 1;
}

int str_uri_hierarchical(const char *uri, const char **partp, size_t *lenp)
{
  const char *p = uri;
  while (*p && *p != ':')
    ++p;
  if (*p != ':')
    return 0;
  const char *const q = ++p;
  while (*p && (is_uri_char_unreserved(*p) || is_uri_char_reserved(*p)) && *p != '?' && *p != '#')
    ++p;
  if (p == q)
    return 0;
  if (partp)
    *partp = q;
  if (lenp)
    *lenp = p - q;
  return 1;
}

int str_uri_query(const char *uri, const char **partp, size_t *lenp)
{
  const char *p = uri;
  while (*p && *p != '?')
    ++p;
  if (*p != '?')
    return 0;
  const char *const q = ++p;
  while (*p && (is_uri_char_unreserved(*p) || is_uri_char_reserved(*p)) && *p != '#')
    ++p;
  if (p == q || (*p && *p != '#'))
    return 0;
  if (partp)
    *partp = q;
  if (lenp)
    *lenp = p - q;
  return 1;
}

int str_uri_fragment(const char *uri, const char **partp, size_t *lenp)
{
  const char *p = uri;
  while (*p && *p != '#')
    ++p;
  if (*p != '#')
    return 0;
  const char *const q = ++p;
  while (*p && (is_uri_char_unreserved(*p) || is_uri_char_reserved(*p)))
    ++p;
  if (p == q || *p)
    return 0;
  if (partp)
    *partp = q;
  if (lenp)
    *lenp = p - q;
  return 1;
}

int str_uri_hierarchical_authority(const char *hier, const char **partp, size_t *lenp)
{
  if (hier[0] != '/' || hier[1] != '/')
    return 0;
  const char *const q = hier + 2;
  const char *p = q;
  while (*p && (is_uri_char_unreserved(*p) || is_uri_char_reserved(*p)) && *p != '/' && *p != '?' && *p != '#')
    ++p;
  if (p == q || (*p && *p != '/' && *p != '?' && *p != '#'))
    return 0;
  if (partp)
    *partp = q;
  if (lenp)
    *lenp = p - q;
  return 1;
}

int str_uri_hierarchical_path(const char *hier, const char **partp, size_t *lenp)
{
  if (hier[0] != '/' || hier[1] != '/')
    return 0;
  const char *p = hier + 2;
  while (*p && *p != '/' && *p != '?' && *p != '#')
    ++p;
  if (!*p)
    return 0;
  const char *const q = ++p;
  while (*p && (is_uri_char_unreserved(*p) || is_uri_char_reserved(*p)) && *p != '/' && *p != '?' && *p != '#')
    ++p;
  if (p == q || (*p && *p != '/' && *p != '?' && *p != '#'))
    return 0;
  if (partp)
    *partp = q;
  if (lenp)
    *lenp = p - q;
  return 1;
}

int str_uri_authority_username(const char *auth, const char **partp, size_t *lenp)
{
  const char *p;
  for (p = auth; *p && *p != '@' && *p != '/' && *p != '?' && *p != '#'; ++p)
      ;
  if (*p != '@')
    return 0;
  for (p = auth; *p && *p != ':' && *p != '@'; ++p)
    ;
  if (*p != ':')
    return 0;
  if (partp)
    *partp = auth;
  if (lenp)
    *lenp = p - auth;
  return 1;
}

int str_uri_authority_password(const char *auth, const char **partp, size_t *lenp)
{
  const char *p;
  for (p = auth; *p && *p != '@' && *p != '/' && *p != '?' && *p != '#'; ++p)
      ;
  if (*p != '@')
    return 0;
  for (p = auth; *p && *p != ':' && *p != '@'; ++p)
    ;
  if (*p != ':')
    return 0;
  const char *const q = ++p;
  for (; *p && *p != '@'; ++p)
    ;
  assert(*p == '@');
  if (partp)
    *partp = q;
  if (lenp)
    *lenp = p - q;
  return 1;
}

int str_uri_authority_hostname(const char *auth, const char **partp, size_t *lenp)
{
  const char *p;
  const char *q = auth;
  for (p = auth; *p && *p != '/' && *p != '?' && *p != '#'; ++p)
      if (*p == '@')
	q = p + 1;
  const char *r = p;
  while (r > q && isdigit(*--r))
    ;
  if (r < p - 1 && *r == ':')
    p = r;
  if (partp)
    *partp = q;
  if (lenp)
    *lenp = p - q;
  return 1;
}

int str_uri_authority_port(const char *auth, unsigned short *portp)
{
  const char *p;
  const char *q = auth;
  for (p = auth; *p && *p != '/' && *p != '?' && *p != '#'; ++p)
      if (*p == '@')
	q = p + 1;
  const char *r = p;
  while (r > q && isdigit(*--r))
    ;
  if (r < p - 1 && *r == ':') {
    for (++r; *r == '0'; ++r)
      ;
    int n;
    if (p - r <= 5 && (n = atoi(r)) <= USHRT_MAX) {
      *portp = n;
      return 1;
    }
  }
  return 0;
}
