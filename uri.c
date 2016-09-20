/*
 Serval URI primitives
 Copyright (C) 2012-2016 Serval Project Inc.
 
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

#include "uri.h"
#include "str.h"
#include <ctype.h>
#include <stdlib.h>  // for atoi()
#include <sys/uio.h> // for iovec
#include <limits.h>  // for USHRT_MAX
#include <assert.h>

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

int str_is_uri_scheme(const char *scheme)
{
  if (!isalpha(*scheme++))
    return 0;
  while (is_uri_char_scheme(*scheme))
    ++scheme;
  return *scheme == '\0';
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
