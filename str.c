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

#define __SERVAL_DNA__STR_INLINE
#include "str.h"
#include "strbuf_helpers.h"
#include "constants.h"
#include "sha2.h"

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

static size_t _uri_encodev(int www_form, char *const dstUrienc, ssize_t dstsiz, struct iovec ** iovp, int *iovcntp)
{
  char * dst = dstUrienc;
  char * const dstend = dstUrienc + dstsiz;
  while (*iovcntp && (dstsiz == -1 || dst < dstend)) {
    if ((*iovp)->iov_len == 0) {
      --*iovcntp;
      ++*iovp;
    } else {
      unsigned char c = *(unsigned char *)(*iovp)->iov_base;
      if (www_form && c == ' ') {
	if (dstUrienc)
	  *dst = '+';
	++dst;
      } else if (is_uri_char_unreserved(c)) {
	if (dstUrienc)
	  *dst = c;
	++dst;
      } else if (dst + 3 <= dstend) {
	if (dstUrienc) {
	  dst[0] = '%';
	  dst[1] = hexdigit_upper[c & 0xf];
	  dst[2] = hexdigit_upper[c >> 4];
	}
	dst += 3;
      } else {
	break;
      }
      ++(*iovp)->iov_base;
      --(*iovp)->iov_len;
    }
  }
  return dst - dstUrienc;
}

static size_t _uri_encode(int www_form, char *const dstUrienc, ssize_t dstsiz, const char *src, size_t srclen, const char **afterp)
{
  struct iovec _iov;
  _iov.iov_base = (void *) src;
  _iov.iov_len = srclen;
  struct iovec *iov = &_iov;
  int ioc = 1;
  size_t encoded = _uri_encodev(www_form, dstUrienc, dstsiz, &iov, &ioc);
  if (afterp)
    *afterp = _iov.iov_base;
  return encoded;
}

size_t uri_encode(char *const dstUrienc, ssize_t dstsiz, const char *src, size_t srclen, const char **afterp)
{
  return _uri_encode(0, dstUrienc, dstsiz, src, srclen, afterp);
}

size_t www_form_uri_encode(char *const dstUrienc, ssize_t dstsiz, const char *src, size_t srclen, const char **afterp)
{
  return _uri_encode(1, dstUrienc, dstsiz, src, srclen, afterp);
}

size_t uri_encodev(char *const dstUrienc, ssize_t dstsiz, struct iovec ** iovp, int *iovcntp)
{
  return _uri_encodev(0, dstUrienc, dstsiz, iovp, iovcntp);
}

size_t www_form_uri_encodev(char *const dstUrienc, ssize_t dstsiz, struct iovec ** iovp, int *iovcntp)
{
  return _uri_encodev(1, dstUrienc, dstsiz, iovp, iovcntp);
}

static size_t _uri_decode(int www_form, char *const dstOrig, ssize_t dstsiz, const char *srcUrienc, size_t srclen, const char **afterp)
{
  char *dst = dstOrig;
  char *const dstend = dst + dstsiz;
  while (srclen && (dstsiz == -1 || dst < dstend)) {
    if (www_form && *srcUrienc == '+') {
      if (dstOrig)
	*dst = ' ';
      ++srcUrienc;
      --srclen;
    } else if (srclen >= 3 && srcUrienc[0] == '%' && isxdigit(srcUrienc[1]) && isxdigit(srcUrienc[2])) {
      if (dstOrig)
	*dst = (hexvalue(srcUrienc[1]) << 4) + hexvalue(srcUrienc[2]);
      srcUrienc += 3;
      srclen -= 3;
    } else {
      if (dstOrig)
	*dst = *srcUrienc;
      ++srcUrienc;
      --srclen;
    }
    ++dst;
  }
  if (afterp)
    *afterp = srcUrienc;
  return dst - dstOrig;
}

size_t uri_decode(char *const dst, ssize_t dstsiz, const char *srcUrienc, size_t srclen, const char **afterp)
{
  return _uri_decode(0, dst, dstsiz, srcUrienc, srclen, afterp);
}

size_t www_form_uri_decode(char *const dst, ssize_t dstsiz, const char *srcUrienc, size_t srclen, const char **afterp)
{
  return _uri_decode(1, dst, dstsiz, srcUrienc, srclen, afterp);
}

const char base64_symbols[65] = {
  'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
  'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f',
  'g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v',
  'w','x','y','z','0','1','2','3','4','5','6','7','8','9','+','/',
  '='
};

const char base64url_symbols[65] = {
  'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
  'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f',
  'g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v',
  'w','x','y','z','0','1','2','3','4','5','6','7','8','9','-','_',
  '='
};

static size_t _base64_encodev(const char symbols[], char *dstBase64, const struct iovec *const iov, int const iovcnt)
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
	  *dst++ = symbols[*src >> 2];
	  buf = (*src << 4) & 0x3f;
	  place = 1;
	  break;
	case 1:
	  *dst++ = symbols[(*src >> 4) | buf];
	  buf = (*src << 2) & 0x3f;
	  place = 2;
	  break;
	case 2:
	  *dst++ = symbols[(*src >> 6) | buf];
	  *dst++ = symbols[*src & 0x3f];
	  place = 0;
	  break;
      }
    }
  }
  if (place)
    *dst++ = symbols[buf];
  switch (place) {
    case 1:
      *dst++ = symbols[64];
    case 2:
      *dst++ = symbols[64];
  }
  return dst - dstBase64;
}

size_t base64_encodev(char *dstBase64, const struct iovec *const iov, int const iovcnt)
{
  return _base64_encodev(base64_symbols, dstBase64, iov, iovcnt);
}

size_t base64url_encodev(char *dstBase64, const struct iovec *const iov, int const iovcnt)
{
  return _base64_encodev(base64url_symbols, dstBase64, iov, iovcnt);
}

size_t base64_encode(char *const dstBase64, const unsigned char *src, size_t srclen)
{
  struct iovec iov;
  iov.iov_base = (void *) src;
  iov.iov_len = srclen;
  return _base64_encodev(base64_symbols, dstBase64, &iov, 1);
}

size_t base64url_encode(char *const dstBase64, const unsigned char *src, size_t srclen)
{
  struct iovec iov;
  iov.iov_base = (void *) src;
  iov.iov_len = srclen;
  return _base64_encodev(base64url_symbols, dstBase64, &iov, 1);
}

char *to_base64_str(char *const dstBase64, const unsigned char *srcBinary, size_t srcBytes)
{
  dstBase64[base64_encode(dstBase64, srcBinary, srcBytes)] = '\0';
  return dstBase64;
}

char *to_base64url_str(char *const dstBase64, const unsigned char *srcBinary, size_t srcBytes)
{
  dstBase64[base64url_encode(dstBase64, srcBinary, srcBytes)] = '\0';
  return dstBase64;
}

static size_t _base64_decode(unsigned char *dstBinary, size_t dstsiz, const char *const srcBase64, size_t srclen,
                     const char **afterp, int flags, int (*skip_pred)(int),
		     int (*isdigit_pred)(int), int (*ispad_pred)(int), uint8_t (*todigit)(char)
		  )
{
  uint8_t buf = 0;
  size_t digits = 0;
  unsigned pads = 0;
  size_t bytes = 0;
  const char *const srcend = srcBase64 + srclen;
  const char *src = srcBase64;
  const char *first_pad = NULL;
  for (; srclen == 0 || (src < srcend); ++src) {
    int isdigit = isdigit_pred(*src);
    int ispad = ispad_pred(*src);
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
      uint8_t d = todigit(*src);
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

size_t base64_decode(unsigned char *dstBinary, size_t dstsiz, const char *const srcBase64, size_t srclen,
                     const char **afterp, int flags, int (*skip_pred)(int))
{
  return _base64_decode(dstBinary, dstsiz, srcBase64, srclen, afterp, flags, skip_pred, is_base64_digit, is_base64_pad, base64_digit);
}


size_t base64url_decode(unsigned char *dstBinary, size_t dstsiz, const char *const srcBase64, size_t srclen,
                        const char **afterp, int flags, int (*skip_pred)(int))
{
  return _base64_decode(dstBinary, dstsiz, srcBase64, srclen, afterp, flags, skip_pred, is_base64url_digit, is_base64url_pad, base64url_digit);
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

int str_is_uint64_decimal(const char *str)
{
  return str_to_uint64(str, 10, NULL, NULL);
}

int str_to_int32(const char *str, unsigned base, int32_t *result, const char **afterp)
{
  if (isspace(*str))
    return 0;
  const char *end = str;
  errno = 0;
  long value = strtol(str, (char**)&end, base);
  if (afterp)
    *afterp = end;
  if (errno == ERANGE || end == str || value > INT32_MAX || value < INT32_MIN || isdigit(*end) || (!afterp && *end))
    return 0;
  if (result)
    *result = value;
  return 1;
}

int str_to_uint32(const char *str, unsigned base, uint32_t *result, const char **afterp)
{
  return strn_to_uint32(str, 0, base, result, afterp);
}

int strn_to_uint32(const char *str, size_t strlen, unsigned base, uint32_t *result, const char **afterp)
{
  assert(base > 0);
  assert(base <= 16);
  uint32_t value = 0;
  uint32_t newvalue = 0;
  const char *const end = str + strlen;
  const char *s;
  for (s = str; strlen ? s < end : *s; ++s) {
    int digit = hexvalue(*s);
    if (digit < 0 || (unsigned)digit >= base)
      break;
    newvalue = value * base + digit;
    if (newvalue < value) // overflow
      break;
    value = newvalue;
  }
  if (afterp)
    *afterp = s;
  if (s == str || value > UINT32_MAX || value != newvalue || (!afterp && (strlen ? s != end : *s)))
    return 0;
  if (result)
    *result = value;
  return 1;
}

int str_to_int64(const char *str, unsigned base, int64_t *result, const char **afterp)
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

int str_to_uint64(const char *str, unsigned base, uint64_t *result, const char **afterp)
{
  return strn_to_uint64(str, 0, base, result, afterp);
}

int strn_to_uint64(const char *str, size_t strlen, unsigned base, uint64_t *result, const char **afterp)
{
  assert(base > 0);
  assert(base <= 16);
  uint64_t value = 0;
  uint64_t newvalue = 0;
  const char *const end = str + strlen;
  const char *s;
  for (s = str; strlen ? s < end : *s; ++s) {
    int digit = hexvalue(*s);
    if (digit < 0 || (unsigned)digit >= base)
      break;
    newvalue = value * base + digit;
    if (newvalue < value) // overflow
      break;
    value = newvalue;
  }
  if (afterp)
    *afterp = s;
  if (s == str || value > UINT64_MAX || value != newvalue || (!afterp && (strlen ? s != end : *s)))
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

int str_to_int64_scaled(const char *str, unsigned base, int64_t *result, const char **afterp)
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

int str_to_uint32_scaled(const char *str, unsigned base, uint32_t *result, const char **afterp)
{
  uint32_t value;
  const char *end = str;
  if (!str_to_uint32(str, base, &value, &end)) {
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

int uint32_scaled_to_str(char *str, size_t len, uint32_t value)
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
  strbuf_sprintf(b, "%lu", (unsigned long) value);
  if (symbol)
    strbuf_putc(b, symbol);
  return strbuf_overrun(b) ? 0 : 1;
}

int str_to_uint64_scaled(const char *str, unsigned base, uint64_t *result, const char **afterp)
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

size_t strn_fromprint(unsigned char *dst, size_t dstsiz, const char *src, size_t srclen, char endquote, const char **afterp)
{
  unsigned char *const odst = dst;
  unsigned char *const edst = dst + dstsiz;
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
  return strn_digest_passphrase(dstBinary, dstsiz, passphrase, strlen(passphrase));
}

void strn_digest_passphrase(unsigned char *dstBinary, size_t dstsiz, const char *passphrase, size_t passlen)
{
  assert(dstsiz <= SERVAL_PASSPHRASE_DIGEST_MAX_BINARY);
  SHA512_CTX context;
  static const char salt1[] = "Sago pudding";
  static const char salt2[] = "Rhubarb pie";
  SHA512_Init(&context);
  SHA512_Update(&context, (unsigned char *)salt1, sizeof salt1 - 1);
  SHA512_Update(&context, (unsigned char *)passphrase, passlen);
  SHA512_Update(&context, (unsigned char *)salt2, sizeof salt2 - 1);
  SHA512_Final_Len(dstBinary, dstsiz, &context);
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
