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

#ifndef __SERVAL_DNA__URI_H__
#define __SERVAL_DNA__URI_H__

#include <stdint.h>    // for uint16_t
#include <sys/types.h> // for size_t

/* -------------------- URI encoding and decoding -------------------- */

/* Encode up to 'srclen' bytes of byte data (or up to first nul if 'srclen' == -1) at 'src' into at
 * most 'dstsiz' bytes of URI-encoded (or www-form-urlencoded) representation at 'dstUrienc'.  If
 * 'dstsiz' is -1 or 'dstUrienc' is NULL, does not write any encoded bytes, but still counts them.
 * If 'afterp' is not NULL, then sets *afterp to point to the source byte immediately following the
 * last character encoded.  A "%xx" sequence will never be partially encoded; if all the "%xx" does
 * not fit within the destination buffer, then none of it is produced.
 *
 * Returns the total number of encoded bytes written at 'dstUrienc'.
 *
 * Can be used to count encoded bytes without actually encoding, eg:
 *
 *    uri_encode(NULL, -1, buf, buflen, NULL);
 *
 * The uri_encodev() and www_form_uri_encodev() functions are a multi-buffer gather variants,
 * analagous to readv(2) and writev(2).  Modifies the supplied *iovp, *iovcntp parameters and the
 * iovec structures at (*iovp)[...] to represent the remaining source bytes not encoded.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
size_t uri_encode(char *const dstUrienc, ssize_t dstsiz, const char *src, size_t srclen, const char **afterp);
size_t www_form_uri_encode(char *const dstUrienc, ssize_t dstsiz, const char *src, size_t srclen, const char **afterp);

struct iovec;
size_t uri_encodev(char *const dstUrienc, ssize_t dstsiz, struct iovec **iovp, int *iovcntp); // modifies *iovp, (*iovp)[...] and *iovcntp
size_t www_form_uri_encodev(char *const dstUrienc, ssize_t dstsiz, struct iovec **iovp, int *iovcntp); // modifies *iovp, (*iovp)[...] and *iovcntp

/* Decode up to 'srclen' bytes of URI-encoded (or www-form-urlencoded) data at 'srcUrienc' into at
 * most 'dstsiz' bytes at 'dst'.  If 'dstsiz' is -1 or 'dst' is NULL, then does not write any
 * decoded bytes, but still counts them.  If 'afterp' is not NULL, then sets *afterp to point to the
 * source byte immediately following the last byte decoded.
 *
 * Returns the total number of decoded bytes written at 'dst'.
 *
 * Can be used to decode in-place, eg:
 *
 *    uri_decode((char *)buf, n, (const unsigned char *)buf, n, NULL);
 *
 * Can be used to count decoded bytes without actually decoding, eg:
 *
 *    uri_decode(NULL, -1, buf, buflen, NULL);
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
size_t uri_decode(char *const dst, ssize_t dstsiz, const char *srcUrienc, size_t srclen, const char **afterp);
size_t www_form_uri_decode(char *const dst, ssize_t dstsiz, const char *srcUrienc, size_t srclen, const char **afterp);

/* -------------------- URI parsing -------------------- */

/* Return true if the string resembles a nul-terminated URI.
 * Based on RFC-3986 generic syntax, assuming nothing about the hierarchical part.
 *
 * uri :=           scheme ":" hierarchical [ "?" query ] [ "#" fragment ]
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int str_is_uri(const char *uri);

/* Return true if the string resembles a URI scheme without the terminating colon.
 * Based on RFC-3986 generic syntax.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int str_is_uri_scheme(const char *scheme);

/* Pick apart a URI into its basic parts.
 *
 * uri :=           scheme ":" hierarchical [ "?" query ] [ "#" fragment ]
 *
 * Based on RFC-3986 generic syntax, assuming nothing about the hierarchical
 * part.  If the respective part is found, sets (*partp) to point to the start
 * of the part within the supplied 'uri' string, sets (*lenp) to the length of
 * the part substring and returns 1.  Otherwise returns 0.  These functions
 * do not reliably validate that the string in 'uri' is a valid URI; that must
 * be done by calling str_is_uri().
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int str_uri_scheme(const char *uri, const char **partp, size_t *lenp);
int str_uri_hierarchical(const char *uri, const char **partp, size_t *lenp);
int str_uri_query(const char *uri, const char **partp, size_t *lenp);
int str_uri_fragment(const char *uri, const char **partp, size_t *lenp);

/* Pick apart a URI hierarchical part into its basic parts.
 *
 * hierarchical :=  "//" authority [ "/" path ]
 *
 * If the respective part is found, sets (*partp) to point to the start of the
 * part within the supplied 'uri' string, sets (*lenp) to the length of the
 * part substring and returns 1.  Otherwise returns 0.
 *
 * These functions may be called directly on the part returned by
 * str_uri_hierarchical(), even though it is not nul-terminated, because they
 * treat "?" and "#" as equally valid terminators.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int str_uri_hierarchical_authority(const char *hier, const char **partp, size_t *lenp);
int str_uri_hierarchical_path(const char *hier, const char **partp, size_t *lenp);

/* Pick apart a URI authority into its basic parts.
 *
 * authority :=     [ username ":" password "@" ] hostname [ ":" port ]
 *
 * If the respective part is found, sets (*partp) to point to the start of the
 * part within the supplied 'uri' string, sets (*lenp) to the length of the
 * part substring and returns 1.  Otherwise returns 0.
 *
 * These functions may be called directly on the part returned by
 * str_uri_hierarchical_authority(), even though it is not nul-terminated,
 * because they treat "/", "?" and "#" as equally valid terminators.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int str_uri_authority_username(const char *auth, const char **partp, size_t *lenp);
int str_uri_authority_password(const char *auth, const char **partp, size_t *lenp);
int str_uri_authority_hostname(const char *auth, const char **partp, size_t *lenp);
int str_uri_authority_port(const char *auth, uint16_t *portp);

#endif // __SERVAL_DNA__URI_H__
