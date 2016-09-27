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

#ifndef __SERVAL_DNA__BASE64_H__
#define __SERVAL_DNA__BASE64_H__

#include <sys/types.h> // for size_t
#include <alloca.h>

/* Return the number of bytes required to represent 'binaryBytes' bytes of binary data encoded
 * into Base64 form.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
#define BASE64_ENCODED_LEN(binaryBytes) (((size_t)(binaryBytes) + 2) / 3 * 4)

/* Array of encoding symbols.  Entry [64] is the pad character (usually '=').
 */
extern const char base64_symbols[65];
extern const char base64url_symbols[65];

/* Encode 'srcBytes' bytes of binary data at 'srcBinary' into Base64 representation at 'dstBase64'
 * (or Base64-URL representation at 'dstBase64url'), which must point to at least
 * 'BASE64_ENCODED_LEN(srcBytes)' bytes.  The encoding is terminated by a "=" or "==" pad to bring
 * the total number of encoded bytes up to a multiple of 4.
 *
 * Returns the total number of encoded bytes writtent at 'dstBase64'.
 *
 * The base64_encodev() is a multi-buffer gather variant, analagous to readv(2) and writev(2).
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
size_t base64_encode(char *dstBase64, const unsigned char *srcBinary, size_t srcBytes);
size_t base64url_encode(char *dstBase64url, const unsigned char *srcBinary, size_t srcBytes);
struct iovec;
size_t base64_encode(char *dstBase64, const unsigned char *srcBinary, size_t srcBytes);
size_t base64url_encodev(char *dstBase64url, const struct iovec *iov, int iovcnt);

/* The same as base64_encode() but appends a terminating NUL character to the encoded string,
 * so 'dstBase64' must point to at least 'BASE64_ENCODED_LEN(srcBytes) + 1' bytes.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
char *to_base64_str(char *dstBase64, const unsigned char *srcBinary, size_t srcBytes);
char *to_base64url_str(char *dstBase64url, const unsigned char *srcBinary, size_t srcBytes);

#define alloca_base64(buf,len)  to_base64_str(alloca(BASE64_ENCODED_LEN(len) + 1), (buf), (len))
#define alloca_base64url(buf,len)  to_base64url_str(alloca(BASE64_ENCODED_LEN(len) + 1), (buf), (len))

/* Decode the string at 'srcBase64' as ASCII Base64 or Base64-URL (as per RFC-4648), writing up to
 * 'dstsiz' decoded binary bytes at 'dstBinary'.  Returns the number of decoded binary bytes
 * produced.  If 'dstsiz' is zero or 'dstBinary' is NULL, no binary bytes are produced and returns
 * zero.
 *
 * If the 'afterp' pointer is not NULL, then sets *afterp to point to the first character in
 * 'srcBase64' where decoding stopped for whatever reason.
 *
 * If 'srclen' is 0, then the string at 'stcBase64' is assumed to be NUL-terminated, and decoding
 * runs until the first non-Base64-digit is encountered.  If 'srclen' is nonzero, then decoding will
 * cease at the first non-Base64-digit or when 'srclen' bytes at 'srcBase64' have been decoded,
 * whichever comes first.
 *
 * If 'skip_pred' is not NULL, then all leading, internal and trailing characters C which are not a
 * valid Base64 digit or pad '=' will be skipped if skip_pred(C) returns true.  Otherwise, decoding
 * ends at C.
 *
 * If the B64_CONSUME_ALL flag is set, then once the 'dstsiz' limit is reached (or if 'dstBinary' is
 * NULL), the Base64 decoding process continues without actually writing decoded bytes, but instead
 * counts them and advances through the 'srcBase64' buffer as usual.  The return value is then the
 * number of binary bytes that would be decoded were all available Base64 decoded from 'srcBase64',
 * and *afterp points to the first character beyond the end of the decoded source characters.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
size_t base64_decode(unsigned char *dstBinary, size_t dstsiz, const char *const srcBase64, size_t srclen,
                     const char **afterp, int flags, int (*skip_pred)(int));
size_t base64url_decode(unsigned char *dstBinary, size_t dstsiz, const char *const srcBase64url, size_t srclen,
                        const char **afterp, int flags, int (*skip_pred)(int));

#define B64_CONSUME_ALL (1 << 0)

#endif // __SERVAL_DNA__BASE64_H__
