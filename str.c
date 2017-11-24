/*
 Serval string primitives
 Copyright (C) 2012-2015 Serval Project Inc.
 Copyright (C) 2016 Flinders University
 
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

#define __SERVAL_DNA__STR_INLINE
#include "str.h"
#include "strbuf_helpers.h"
#include "sodium.h"

#include <stdio.h>   // for NULL
#include <string.h>  // for strlen(), strncmp() etc.
#include <ctype.h>
#include <assert.h>
#include <limits.h>  // for UINT8_MAX

const char hexdigit_upper[16] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
const char hexdigit_lower[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

char *tohex(char *dstHex, size_t dstStrLen, const unsigned char *srcBinary)
{
  char *p;
  size_t i;
  for (p = dstHex, i = 0; i < dstStrLen; ++i)
    *p++ = (i & 1) ? hexdigit_upper[*srcBinary++ & 0xf] : hexdigit_upper[*srcBinary >> 4];
  *p = '\0';
  return dstHex;
}

size_t fromhex(unsigned char *dstBinary, const char *srcHex, size_t nbinary)
{
  if (strn_fromhex(dstBinary, nbinary, srcHex, NULL) == nbinary)
    return nbinary;
  return -1;
}

int fromhexstr(unsigned char *dstBinary, size_t nbinary, const char *srcHex)
{
  const char *p;
  if (strn_fromhex(dstBinary, nbinary, srcHex, &p) == nbinary && *p == '\0')
    return 0;
  return -1;
}

int fromhexstrn(unsigned char *dstBinary, size_t nbinary, const char *srcHex, size_t nHex, const char **afterHex)
{
  if (nbinary *2 == nHex && strn_fromhex(dstBinary, nbinary, srcHex, afterHex) == nbinary)
    return 0;
  return -1;
}

size_t strn_fromhex(unsigned char *dstBinary, ssize_t dstsiz, const char *srcHex, const char **afterHex)
{
  unsigned char *dstorig = dstBinary;
  unsigned char *dstend = dstBinary + dstsiz;
  while (dstsiz == -1 || dstBinary < dstend) {
    int high = hexvalue(srcHex[0]);
    if (high == -1)
      break;
    int low = hexvalue(srcHex[1]);
    if (low == -1)
      break;
    if (dstorig != NULL)
      *dstBinary = (high << 4) + low;
    ++dstBinary;
    srcHex += 2;
  }
  if (afterHex)
    *afterHex = srcHex;
  return dstBinary - dstorig;
}

#define _B64 _SERVAL_CTYPE_0_BASE64
#define _B64U _SERVAL_CTYPE_0_BASE64URL

uint8_t _serval_ctype_0[UINT8_MAX] = {
  ['A'] = _B64 | _B64U | 0,
  ['B'] = _B64 | _B64U | 1,
  ['C'] = _B64 | _B64U | 2,
  ['D'] = _B64 | _B64U | 3,
  ['E'] = _B64 | _B64U | 4,
  ['F'] = _B64 | _B64U | 5,
  ['G'] = _B64 | _B64U | 6,
  ['H'] = _B64 | _B64U | 7,
  ['I'] = _B64 | _B64U | 8,
  ['J'] = _B64 | _B64U | 9,
  ['K'] = _B64 | _B64U | 10,
  ['L'] = _B64 | _B64U | 11,
  ['M'] = _B64 | _B64U | 12,
  ['N'] = _B64 | _B64U | 13,
  ['O'] = _B64 | _B64U | 14,
  ['P'] = _B64 | _B64U | 15,
  ['Q'] = _B64 | _B64U | 16,
  ['R'] = _B64 | _B64U | 17,
  ['S'] = _B64 | _B64U | 18,
  ['T'] = _B64 | _B64U | 19,
  ['U'] = _B64 | _B64U | 20,
  ['V'] = _B64 | _B64U | 21,
  ['W'] = _B64 | _B64U | 22,
  ['X'] = _B64 | _B64U | 23,
  ['Y'] = _B64 | _B64U | 24,
  ['Z'] = _B64 | _B64U | 25,
  ['a'] = _B64 | _B64U | 26,
  ['b'] = _B64 | _B64U | 27,
  ['c'] = _B64 | _B64U | 28,
  ['d'] = _B64 | _B64U | 29,
  ['e'] = _B64 | _B64U | 30,
  ['f'] = _B64 | _B64U | 31,
  ['g'] = _B64 | _B64U | 32,
  ['h'] = _B64 | _B64U | 33,
  ['i'] = _B64 | _B64U | 34,
  ['j'] = _B64 | _B64U | 35,
  ['k'] = _B64 | _B64U | 36,
  ['l'] = _B64 | _B64U | 37,
  ['m'] = _B64 | _B64U | 38,
  ['n'] = _B64 | _B64U | 39,
  ['o'] = _B64 | _B64U | 40,
  ['p'] = _B64 | _B64U | 41,
  ['q'] = _B64 | _B64U | 42,
  ['r'] = _B64 | _B64U | 43,
  ['s'] = _B64 | _B64U | 44,
  ['t'] = _B64 | _B64U | 45,
  ['u'] = _B64 | _B64U | 46,
  ['v'] = _B64 | _B64U | 47,
  ['w'] = _B64 | _B64U | 48,
  ['x'] = _B64 | _B64U | 49,
  ['y'] = _B64 | _B64U | 50,
  ['z'] = _B64 | _B64U | 51,
  ['0'] = _B64 | _B64U | 52,
  ['1'] = _B64 | _B64U | 53,
  ['2'] = _B64 | _B64U | 54,
  ['3'] = _B64 | _B64U | 55,
  ['4'] = _B64 | _B64U | 56,
  ['5'] = _B64 | _B64U | 57,
  ['6'] = _B64 | _B64U | 58,
  ['7'] = _B64 | _B64U | 59,
  ['8'] = _B64 | _B64U | 60,
  ['9'] = _B64 | _B64U | 61,
  ['+'] = _B64 | 62,
  ['/'] = _B64 | 63,
  ['-'] = _B64U | 62,
  ['_'] = _B64U | 63,
};

#define _SEP		_SERVAL_CTYPE_1_HTTP_SEPARATOR 
#define _URI_SCHEME	_SERVAL_CTYPE_1_URI_SCHEME
#define _URI_UNRES	_SERVAL_CTYPE_1_URI_UNRESERVED
#define _URI_RES	_SERVAL_CTYPE_1_URI_RESERVED

uint8_t _serval_ctype_1[UINT8_MAX] = {
  ['A'] = _URI_SCHEME | _URI_UNRES | 0xA,
  ['B'] = _URI_SCHEME | _URI_UNRES | 0xB,
  ['C'] = _URI_SCHEME | _URI_UNRES | 0xC,
  ['D'] = _URI_SCHEME | _URI_UNRES | 0xD,
  ['E'] = _URI_SCHEME | _URI_UNRES | 0xE,
  ['F'] = _URI_SCHEME | _URI_UNRES | 0xF,
  ['G'] = _URI_SCHEME | _URI_UNRES,
  ['H'] = _URI_SCHEME | _URI_UNRES,
  ['I'] = _URI_SCHEME | _URI_UNRES,
  ['J'] = _URI_SCHEME | _URI_UNRES,
  ['K'] = _URI_SCHEME | _URI_UNRES,
  ['L'] = _URI_SCHEME | _URI_UNRES,
  ['M'] = _URI_SCHEME | _URI_UNRES,
  ['N'] = _URI_SCHEME | _URI_UNRES,
  ['O'] = _URI_SCHEME | _URI_UNRES,
  ['P'] = _URI_SCHEME | _URI_UNRES,
  ['Q'] = _URI_SCHEME | _URI_UNRES,
  ['R'] = _URI_SCHEME | _URI_UNRES,
  ['S'] = _URI_SCHEME | _URI_UNRES,
  ['T'] = _URI_SCHEME | _URI_UNRES,
  ['U'] = _URI_SCHEME | _URI_UNRES,
  ['V'] = _URI_SCHEME | _URI_UNRES,
  ['W'] = _URI_SCHEME | _URI_UNRES,
  ['X'] = _URI_SCHEME | _URI_UNRES,
  ['Y'] = _URI_SCHEME | _URI_UNRES,
  ['Z'] = _URI_SCHEME | _URI_UNRES,
  ['a'] = _URI_SCHEME | _URI_UNRES | 0xa,
  ['b'] = _URI_SCHEME | _URI_UNRES | 0xb,
  ['c'] = _URI_SCHEME | _URI_UNRES | 0xc,
  ['d'] = _URI_SCHEME | _URI_UNRES | 0xd,
  ['e'] = _URI_SCHEME | _URI_UNRES | 0xe,
  ['f'] = _URI_SCHEME | _URI_UNRES | 0xf,
  ['g'] = _URI_SCHEME | _URI_UNRES,
  ['h'] = _URI_SCHEME | _URI_UNRES,
  ['i'] = _URI_SCHEME | _URI_UNRES,
  ['j'] = _URI_SCHEME | _URI_UNRES,
  ['k'] = _URI_SCHEME | _URI_UNRES,
  ['l'] = _URI_SCHEME | _URI_UNRES,
  ['m'] = _URI_SCHEME | _URI_UNRES,
  ['n'] = _URI_SCHEME | _URI_UNRES,
  ['o'] = _URI_SCHEME | _URI_UNRES,
  ['p'] = _URI_SCHEME | _URI_UNRES,
  ['q'] = _URI_SCHEME | _URI_UNRES,
  ['r'] = _URI_SCHEME | _URI_UNRES,
  ['s'] = _URI_SCHEME | _URI_UNRES,
  ['t'] = _URI_SCHEME | _URI_UNRES,
  ['u'] = _URI_SCHEME | _URI_UNRES,
  ['v'] = _URI_SCHEME | _URI_UNRES,
  ['w'] = _URI_SCHEME | _URI_UNRES,
  ['x'] = _URI_SCHEME | _URI_UNRES,
  ['y'] = _URI_SCHEME | _URI_UNRES,
  ['z'] = _URI_SCHEME | _URI_UNRES,
  ['0'] = _URI_SCHEME | _URI_UNRES | 0,
  ['1'] = _URI_SCHEME | _URI_UNRES | 1,
  ['2'] = _URI_SCHEME | _URI_UNRES | 2,
  ['3'] = _URI_SCHEME | _URI_UNRES | 3,
  ['4'] = _URI_SCHEME | _URI_UNRES | 4,
  ['5'] = _URI_SCHEME | _URI_UNRES | 5,
  ['6'] = _URI_SCHEME | _URI_UNRES | 6,
  ['7'] = _URI_SCHEME | _URI_UNRES | 7,
  ['8'] = _URI_SCHEME | _URI_UNRES | 8,
  ['9'] = _URI_SCHEME | _URI_UNRES | 9,
  ['\t'] = _SEP,
  [' '] = _SEP,
  ['_'] = _URI_UNRES,
  ['='] = _SEP | _URI_RES,
  ['<'] = _SEP,
  ['>'] = _SEP,
  [';'] = _SEP | _URI_RES,
  [':'] = _SEP | _URI_RES,
  ['\\'] = _SEP,
  ['\''] = _URI_RES,
  ['"'] = _SEP,
  ['/'] = _SEP | _URI_RES,
  ['['] = _SEP | _URI_RES,
  [']'] = _SEP | _URI_RES,
  ['{'] = _SEP,
  ['}'] = _SEP,
  ['('] = _SEP | _URI_RES,
  [')'] = _SEP | _URI_RES,
  [','] = _SEP | _URI_RES,
  ['.'] = _URI_SCHEME | _URI_UNRES,
  ['?'] = _SEP | _URI_RES,
  ['!'] = _URI_RES,
  ['+'] = _URI_SCHEME | _URI_RES,
  ['-'] = _URI_SCHEME | _URI_UNRES,
  ['*'] = _URI_RES,
  ['$'] = _URI_RES,
  ['&'] = _URI_RES,
  ['#'] = _URI_RES,
  ['@'] = _SEP | _URI_RES,
  ['~'] = _URI_UNRES,
};

#define _BND _SERVAL_CTYPE_2_MULTIPART_BOUNDARY

uint8_t _serval_ctype_2[UINT8_MAX] = {
  ['A'] = _BND,
  ['B'] = _BND,
  ['C'] = _BND,
  ['D'] = _BND,
  ['E'] = _BND,
  ['F'] = _BND,
  ['G'] = _BND,
  ['H'] = _BND,
  ['I'] = _BND,
  ['J'] = _BND,
  ['K'] = _BND,
  ['L'] = _BND,
  ['M'] = _BND,
  ['N'] = _BND,
  ['O'] = _BND,
  ['P'] = _BND,
  ['Q'] = _BND,
  ['R'] = _BND,
  ['S'] = _BND,
  ['T'] = _BND,
  ['U'] = _BND,
  ['V'] = _BND,
  ['W'] = _BND,
  ['X'] = _BND,
  ['Y'] = _BND,
  ['Z'] = _BND,
  ['a'] = _BND,
  ['b'] = _BND,
  ['c'] = _BND,
  ['d'] = _BND,
  ['e'] = _BND,
  ['f'] = _BND,
  ['g'] = _BND,
  ['h'] = _BND,
  ['i'] = _BND,
  ['j'] = _BND,
  ['k'] = _BND,
  ['l'] = _BND,
  ['m'] = _BND,
  ['n'] = _BND,
  ['o'] = _BND,
  ['p'] = _BND,
  ['q'] = _BND,
  ['r'] = _BND,
  ['s'] = _BND,
  ['t'] = _BND,
  ['u'] = _BND,
  ['v'] = _BND,
  ['w'] = _BND,
  ['x'] = _BND,
  ['y'] = _BND,
  ['z'] = _BND,
  ['0'] = _BND,
  ['1'] = _BND,
  ['2'] = _BND,
  ['3'] = _BND,
  ['4'] = _BND,
  ['5'] = _BND,
  ['6'] = _BND,
  ['7'] = _BND,
  ['8'] = _BND,
  ['9'] = _BND,
  ['+'] = _BND,
  ['/'] = _BND,
  ['='] = _BND,
  ['-'] = _BND,
  ['.'] = _BND,
  [':'] = _BND,
  ['_'] = _BND,
  ['('] = _BND,
  [')'] = _BND,
  [','] = _BND,
  ['?'] = _BND,
  [' '] = _BND,
};

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

char *str_tolower_inplace(char *str)
{
  register char *s;
  for (s = str; *s; ++s)
    *s = tolower(*s);
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

int strn_startswith(const char *str, ssize_t len, const char *substring, const char **afterp)
{
  // if len == -1 then str must be nul terminated
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

int str_endswith(const char *str, const char *substring, const char **startp) {
  size_t len = strlen(str);
  size_t sublen = strlen(substring);
  if (len < sublen || strcmp(&str[len - sublen], substring) != 0)
    return 0;
  if (startp)
    *startp = &str[len - sublen];
  return 1;
}

int strcase_endswith(const char *str, const char *substring, const char **startp) {
  size_t len = strlen(str);
  size_t sublen = strlen(substring);
  if (len < sublen || strcasecmp(&str[len - sublen], substring) != 0)
    return 0;
  if (startp)
    *startp = &str[len - sublen];
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
char *str_str(char *haystack, const char *needle, size_t haystack_len)
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

/* Compute the length of the string produced by sprintf(fmt, ...).
   @author Andrew Bettison <andrew@servalproject.com>
 */
size_t sprintf_len(const char *fmt, ...)
{
  strbuf b = strbuf_local(NULL, 0);
  va_list ap;
  va_start(ap, fmt);
  strbuf_vsprintf(b, fmt, ap);
  va_end(ap);
  return strbuf_count(b);
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

/* Compute the length of the string produced by toprint().
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

size_t strn_fromprint(char *dst, size_t dstsiz, const char *src, size_t srclen, char endquote, const char **afterp)
{
  char *const odst = dst;
  char *const edst = dst + dstsiz;
  const char *const esrc = srclen ? src + srclen : NULL;
  while ((src < esrc || !esrc) && *src && *src != endquote && dst < edst) {
    switch (*src) {
    case '\\':
      ++src;
      unsigned char d;
      switch (*src) {
      case '\0': d = '\\'; break;
      case '0': d = '\0'; ++src; break;
      case 'n': d = '\n'; ++src; break;
      case 'r': d = '\r'; ++src; break;
      case 't': d = '\t'; ++src; break;
      case 'x':
	if (isxdigit(src[1]) && isxdigit(src[2])) {
	  ++src;
	  fromhex(&d, src, 1);
	  src += 2;
	  break;
	}
	// fall through
      default:
	d = *src++;
	break;
      }
      *dst++ = d;
      break;
    default:
      *dst++ = *src++;
      break;
    }
  }
  if (afterp)
    *afterp = src;
  return dst - odst;
}

void str_digest_passphrase(unsigned char *dstBinary, size_t dstsiz, const char *passphrase)
{
  strn_digest_passphrase(dstBinary, dstsiz, passphrase, strlen(passphrase));
}

void strn_digest_passphrase(unsigned char *dstBinary, size_t dstsiz, const char *passphrase, size_t passlen)
{
  assert(dstsiz <= SERVAL_PASSPHRASE_DIGEST_MAX_BINARY);
  crypto_hash_sha512_state context;
  static const char salt1[] = "Sago pudding";
  static const char salt2[] = "Rhubarb pie";
  crypto_hash_sha512_init(&context);
  crypto_hash_sha512_update(&context, (unsigned char *)salt1, sizeof salt1 - 1);
  crypto_hash_sha512_update(&context, (unsigned char *)passphrase, passlen);
  crypto_hash_sha512_update(&context, (unsigned char *)salt2, sizeof salt2 - 1);
  unsigned char hash[crypto_hash_sha512_BYTES];
  crypto_hash_sha512_final(&context, hash);
  bcopy(hash, dstBinary, dstsiz);
}
