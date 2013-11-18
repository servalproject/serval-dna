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
#include <sys/uio.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <limits.h>
#include <errno.h>

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

int fromhexstr(unsigned char *dstBinary, const char *srcHex, size_t nbinary)
{
  const char *p;
  if (strn_fromhex(dstBinary, nbinary, srcHex, &p) == nbinary && *p == '\0')
    return 0;
  return -1;
}

size_t strn_fromhex(unsigned char *dstBinary, ssize_t dstlen, const char *srcHex, const char **afterHex)
{
  unsigned char *dstorig = dstBinary;
  unsigned char *dstend = dstBinary + dstlen;
  while (dstlen == -1 || dstBinary < dstend) {
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

const char base64_symbols[64] = {
  'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
  'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f',
  'g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v',
  'w','x','y','z','0','1','2','3','4','5','6','7','8','9','+','/'
};

size_t base64_encodev(char *dstBase64, const struct iovec *const iov, int const iovcnt)
{
  char *dst = dstBase64;
  unsigned place = 0;
  unsigned char buf = 0;
  int iovc = 0;
  for (iovc = 0; iovc != iovcnt; ++iovc) {
    unsigned char *src = iov[iovc].iov_base;
    size_t cnt = iov[iovc].iov_len;
    for (; cnt; --cnt, ++src) {
      switch (place) {
	case 0:
	  *dst++ = base64_symbols[*src >> 2];
	  buf = (*src << 4) & 0x3f;
	  place = 1;
	  break;
	case 1:
	  *dst++ = base64_symbols[(*src >> 4) | buf];
	  buf = (*src << 2) & 0x3f;
	  place = 2;
	  break;
	case 2:
	  *dst++ = base64_symbols[(*src >> 6) | buf];
	  *dst++ = base64_symbols[*src & 0x3f];
	  place = 0;
	  break;
      }
    }
  }
  if (place)
    *dst++ = base64_symbols[buf];
  switch (place) {
    case 2:
      *dst++ = '=';
    case 1:
      *dst++ = '=';
  }
  return dst - dstBase64;
}

size_t base64_encode(char *const dstBase64, const unsigned char *src, size_t srclen)
{
  struct iovec iov;
  iov.iov_base = (void *) src;
  iov.iov_len = srclen;
  return base64_encodev(dstBase64, &iov, 1);
}

char *to_base64_str(char *const dstBase64, const unsigned char *srcBinary, size_t srcBytes)
{
  dstBase64[base64_encode(dstBase64, srcBinary, srcBytes)] = '\0';
  return dstBase64;
}

size_t base64_decode(unsigned char *dstBinary, size_t dstsiz, const char *const srcBase64, size_t srclen,
                     const char **afterp, int flags, int (*skip_pred)(char))
{
  uint8_t buf = 0;
  size_t digits = 0;
  unsigned pads = 0;
  size_t bytes = 0;
  const char *const srcend = srcBase64 + srclen;
  const char *src = srcBase64;
  const char *first_pad = NULL;
  for (; srclen == 0 || (src < srcend); ++src) {
    int isdigit = is_base64_digit(*src);
    int ispad = is_base64_pad(*src);
    if (!isdigit && !ispad && skip_pred && skip_pred(*src))
      continue;
    assert(pads <= 2);
    if (pads == 2)
      break;
    int place = digits & 3;
    if (pads == 1) {
      if (place == 3)
	break;
      assert(place == 2);
      if (ispad) {
	++pads;
	continue; // consume trailing space before ending
      }
      // If only one pad character was present but there should be two, then don't consume the first
      // one.
      assert(first_pad != NULL);
      src = first_pad;
      break;
    }
    assert(pads == 0);
    if (ispad && place >= 2) {
      first_pad = src;
      ++pads;
      continue;
    }
    if (!isdigit)
      break;
    ++digits;
    if (dstBinary && bytes < dstsiz) {
      uint8_t d = base64_digit(*src);
      switch (place) {
	case 0:
	  buf = d << 2;
	  break;
	case 1:
	  dstBinary[bytes++] = buf | (d >> 4);
	  buf = d << 4;
	  break;
	case 2:
	  dstBinary[bytes++] = buf | (d >> 2);
	  buf = d << 6;
	  break;
	case 3:
	  dstBinary[bytes++] = buf | d;
	  break;
      }
    } else if (flags & B64_CONSUME_ALL) {
      switch (place) {
	case 1: case 2: case 3: ++bytes;
      }
    } else
      break;
  }
  if (afterp)
    *afterp = src;
  else if (*src)
    return 0;
  return bytes;
}

#define _B64 _SERVAL_CTYPE_0_BASE64
#define _BND _SERVAL_CTYPE_0_MULTIPART_BOUNDARY

uint8_t _serval_ctype_0[UINT8_MAX] = {
  ['A'] = _BND | _B64 | 0,
  ['B'] = _BND | _B64 | 1,
  ['C'] = _BND | _B64 | 2,
  ['D'] = _BND | _B64 | 3,
  ['E'] = _BND | _B64 | 4,
  ['F'] = _BND | _B64 | 5,
  ['G'] = _BND | _B64 | 6,
  ['H'] = _BND | _B64 | 7,
  ['I'] = _BND | _B64 | 8,
  ['J'] = _BND | _B64 | 9,
  ['K'] = _BND | _B64 | 10,
  ['L'] = _BND | _B64 | 11,
  ['M'] = _BND | _B64 | 12,
  ['N'] = _BND | _B64 | 13,
  ['O'] = _BND | _B64 | 14,
  ['P'] = _BND | _B64 | 15,
  ['Q'] = _BND | _B64 | 16,
  ['R'] = _BND | _B64 | 17,
  ['S'] = _BND | _B64 | 18,
  ['T'] = _BND | _B64 | 19,
  ['U'] = _BND | _B64 | 20,
  ['V'] = _BND | _B64 | 21,
  ['W'] = _BND | _B64 | 22,
  ['X'] = _BND | _B64 | 23,
  ['Y'] = _BND | _B64 | 24,
  ['Z'] = _BND | _B64 | 25,
  ['a'] = _BND | _B64 | 26,
  ['b'] = _BND | _B64 | 27,
  ['c'] = _BND | _B64 | 28,
  ['d'] = _BND | _B64 | 29,
  ['e'] = _BND | _B64 | 30,
  ['f'] = _BND | _B64 | 31,
  ['g'] = _BND | _B64 | 32,
  ['h'] = _BND | _B64 | 33,
  ['i'] = _BND | _B64 | 34,
  ['j'] = _BND | _B64 | 35,
  ['k'] = _BND | _B64 | 36,
  ['l'] = _BND | _B64 | 37,
  ['m'] = _BND | _B64 | 38,
  ['n'] = _BND | _B64 | 39,
  ['o'] = _BND | _B64 | 40,
  ['p'] = _BND | _B64 | 41,
  ['q'] = _BND | _B64 | 42,
  ['r'] = _BND | _B64 | 43,
  ['s'] = _BND | _B64 | 44,
  ['t'] = _BND | _B64 | 45,
  ['u'] = _BND | _B64 | 46,
  ['v'] = _BND | _B64 | 47,
  ['w'] = _BND | _B64 | 48,
  ['x'] = _BND | _B64 | 49,
  ['y'] = _BND | _B64 | 50,
  ['z'] = _BND | _B64 | 51,
  ['0'] = _BND | _B64 | 52,
  ['1'] = _BND | _B64 | 53,
  ['2'] = _BND | _B64 | 54,
  ['3'] = _BND | _B64 | 55,
  ['4'] = _BND | _B64 | 56,
  ['5'] = _BND | _B64 | 57,
  ['6'] = _BND | _B64 | 58,
  ['7'] = _BND | _B64 | 59,
  ['8'] = _BND | _B64 | 60,
  ['9'] = _BND | _B64 | 61,
  ['+'] = _BND | _B64 | 62,
  ['/'] = _BND | _B64 | 63,
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

int str_to_int(const char *str, int base, int *result, const char **afterp)
{
  if (isspace(*str))
    return 0;
  const char *end = str;
  errno = 0;
  long value = strtol(str, (char**)&end, base);
  if (afterp)
    *afterp = end;
  if (errno == ERANGE || end == str || value > INT_MAX || value < INT_MIN || isdigit(*end) || (!afterp && *end))
    return 0;
  if (result)
    *result = value;
  return 1;
}

int str_to_uint(const char *str, int base, unsigned *result, const char **afterp)
{
  if (isspace(*str))
    return 0;
  const char *end = str;
  errno = 0;
  unsigned long value = strtoul(str, (char**)&end, base);
  if (afterp)
    *afterp = end;
  if (errno == ERANGE || end == str || value > UINT_MAX || isdigit(*end) || (!afterp && *end))
    return 0;
  if (result)
    *result = value;
  return 1;
}

int str_to_int64(const char *str, int base, int64_t *result, const char **afterp)
{
  if (isspace(*str))
    return 0;
  const char *end = str;
  errno = 0;
  long long value = strtoll(str, (char**)&end, base);
  if (afterp)
    *afterp = end;
  if (errno == ERANGE || end == str || isdigit(*end) || (!afterp && *end))
    return 0;
  if (result)
    *result = value;
  return 1;
}

int str_to_uint64(const char *str, int base, uint64_t *result, const char **afterp)
{
  if (isspace(*str))
    return 0;
  const char *end = str;
  errno = 0;
  unsigned long long value = strtoull(str, (char**)&end, base);
  if (afterp)
    *afterp = end;
  if (errno == ERANGE || end == str || isdigit(*end) || (!afterp && *end))
    return 0;
  if (result)
    *result = value;
  return 1;
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
  int64_t value;
  const char *end = str;
  if (!str_to_int64(str, base, &value, &end)) {
    if (afterp)
      *afterp = end;
    return 0;
  }
  value *= scale_factor(end, &end);
  if (afterp)
    *afterp = end;
  else if (*end)
    return 0;
  if (result)
    *result = value;
  return 1;
}

int str_to_uint64_scaled(const char *str, int base, uint64_t *result, const char **afterp)
{
  uint64_t value;
  const char *end = str;
  if (!str_to_uint64(str, base, &value, &end)) {
    if (afterp)
      *afterp = end;
    return 0;
  }
  value *= scale_factor(end, &end);
  if (afterp)
    *afterp = end;
  else if (*end)
    return 0;
  if (result)
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

int str_to_uint64_interval_ms(const char *str, int64_t *result, const char **afterp)
{
  const unsigned precision = 1000;
  if (isspace(*str))
    return 0;
  const char *end = str;
  unsigned long long value = strtoull(str, (char**)&end, 10) * precision;
  if (end == str) {
    if (afterp)
      *afterp = end;
    return 0;
  }
  if (end[0] == '.' && isdigit(end[1])) {
    ++end;
    unsigned factor;
    for (factor = precision / 10; isdigit(*end) && factor; factor /= 10)
      value += (*end++ - '0') * factor;
  }
  if (afterp)
    *afterp = end;
  else if (*end)
    return 0;
  if (result)
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

size_t strn_fromprint(unsigned char *dst, size_t dstsiz, const char *src, size_t srclen, char endquote, const char **afterp)
{
  unsigned char *const odst = dst;
  unsigned char *const edst = dst + dstsiz;
  const char *const esrc = srclen ? src + srclen : NULL;
  while (src < esrc && *src && *src != endquote && dst < edst) {
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

int str_uri_authority_port(const char *auth, uint16_t *portp)
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
    unsigned int n;
    if (p - r <= 5 && (n = atoi(r)) <= USHRT_MAX) {
      *portp = n;
      return 1;
    }
  }
  return 0;
}
