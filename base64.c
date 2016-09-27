/*
 Serval Base64 primitives
 Copyright (C) 2013 Serval Project Inc.
 
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

#include "base64.h"
#include "str.h"     // for Serval ctype
#include <stdint.h>  // for uint8_t
#include <stdio.h>   // for NULL
#include <sys/uio.h> // for iovec
#include <assert.h>

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
