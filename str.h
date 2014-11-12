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

#ifndef __SERVAL_DNA__STR_H__
#define __SERVAL_DNA__STR_H__

#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <ctype.h>
#include <alloca.h>

#ifndef __SERVAL_DNA__STR_INLINE
# if __GNUC__ && !__GNUC_STDC_INLINE__
#  define __SERVAL_DNA__STR_INLINE extern inline
# else
#  define __SERVAL_DNA__STR_INLINE inline
# endif
#endif

/* -------------------- Useful functions and macros -------------------- */

#define alloca_strdup(str)  strcpy(alloca(strlen(str) + 1), (str))

int is_all_matching(const unsigned char *ptr, size_t len, unsigned char value);

char *str_toupper_inplace(char *s);
char *str_tolower_inplace(char *s);

/* -------------------- Hexadecimal strings -------------------- */

extern const char hexdigit_upper[16];
extern const char hexdigit_lower[16];

/* Return true iff 'len' bytes starting at 'text' are hex digits, upper or lower case.
 * Does not check the following byte.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
__SERVAL_DNA__STR_INLINE int is_xsubstring(const char *text, int len)
{
  while (len--)
    if (!isxdigit(*text++))
      return 0;
  return 1;
}

/* Return true iff the nul-terminated string 'text' has length 'len' and consists only of hex
 * digits, upper or lower case.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
__SERVAL_DNA__STR_INLINE int is_xstring(const char *text, int len)
{
  while (len--)
    if (!isxdigit(*text++))
      return 0;
  return *text == '\0';
}

/* Converts a given binary blob to uppercase ASCII hexadecimal with a NUL terminator on the end.
 * 'dstHex' must point to a buffer of at least 'dstStrLen' + 1 bytes.
 */
char *tohex(char *dstHex, size_t dstStrlen, const unsigned char *srcBinary);
#define alloca_tohex(buf,bytes)  tohex((char *)alloca((bytes)*2+1), (bytes) * 2, (buf))

/* Convert nbinary*2 ASCII hex characters [0-9A-Fa-f] to nbinary bytes of data.  Can be used to
 * perform the conversion in-place, eg, fromhex(buf, (char*)buf, n);  Returns -1 if a non-hex-digit
 * character is encountered, otherwise returns the number of binary bytes produced (= nbinary).
 * Does not insist that the last hex digit is followed by a NUL or any particular character.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
size_t fromhex(unsigned char *dstBinary, const char *srcHex, size_t nbinary);

/* Convert nbinary*2 ASCII hex characters [0-9A-Fa-f] followed by a NUL '\0' character to nbinary
 * bytes of data.  Can be used to perform the conversion in-place, eg, fromhex(buf, (char*)buf, n);
 * Returns -1 if a non-hex-digit character is encountered or the character immediately following the
 * last hex digit is not a NUL, otherwise returns zero.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int fromhexstr(unsigned char *dstBinary, const char *srcHex, size_t nbinary);

/* Decode pairs of ASCII hex characters [0-9A-Fa-f] into binary data with an optional upper limit on
 * the number of binary bytes produced (destination buffer size).  Returns the number of binary
 * bytes decoded.  If 'afterHex' is not NULL, then sets *afterHex to point to the source character
 * immediately following the last hex digit consumed.
 *
 * Can be used to perform a conversion in-place, eg:
 *
 *    strn_fromhex((unsigned char *)buf, n, (const char *)buf, NULL);
 *
 * Can also be used to count hex digits without converting, eg:
 *
 *    strn_fromhex(NULL, -1, buf, NULL);
 *
 * The fromhex() and fromhexstr() functions are both implemented using strn_fromhex().
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
size_t strn_fromhex(unsigned char *dstBinary, ssize_t dstlen, const char *src, const char **afterp);

/* -------------------- Base64 encoding and decoding -------------------- */

/* Return the number of bytes required to represent 'binaryBytes' bytes of binary data encoded
 * into Base64 form.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
#define BASE64_ENCODED_LEN(binaryBytes) (((size_t)(binaryBytes) + 2) / 3 * 4)

/* Array of encoding symbols.  Entry [64] is the pad character (usually '=').
 */
const char base64_symbols[65];
const char base64url_symbols[65];

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
                     const char **afterp, int flags, int (*skip_pred)(char));
size_t base64url_decode(unsigned char *dstBinary, size_t dstsiz, const char *const srcBase64url, size_t srclen,
                        const char **afterp, int flags, int (*skip_pred)(char));

#define B64_CONSUME_ALL (1 << 0)

/* -------------------- Character classes -------------------- */

#define _SERVAL_CTYPE_0_BASE64_MASK 0x3f
#define _SERVAL_CTYPE_0_BASE64 (1 << 6)
#define _SERVAL_CTYPE_0_BASE64URL (1 << 7)

#define _SERVAL_CTYPE_1_HEX_MASK 0xf
#define _SERVAL_CTYPE_1_HTTP_SEPARATOR (1 << 4)
#define _SERVAL_CTYPE_1_URI_SCHEME (1 << 5)
#define _SERVAL_CTYPE_1_URI_UNRESERVED (1 << 6)
#define _SERVAL_CTYPE_1_URI_RESERVED (1 << 7)

#define _SERVAL_CTYPE_2_MULTIPART_BOUNDARY (1 << 0)

extern uint8_t _serval_ctype_0[UINT8_MAX];
extern uint8_t _serval_ctype_1[UINT8_MAX];
extern uint8_t _serval_ctype_2[UINT8_MAX];

__SERVAL_DNA__STR_INLINE int is_http_char(char c) {
  return isascii(c);
}

__SERVAL_DNA__STR_INLINE int is_http_ctl(char c) {
  return iscntrl(c);
}

__SERVAL_DNA__STR_INLINE int is_base64_digit(char c) {
  return (_serval_ctype_0[(unsigned char) c] & _SERVAL_CTYPE_0_BASE64) != 0;
}

__SERVAL_DNA__STR_INLINE int is_base64url_digit(char c) {
  return (_serval_ctype_0[(unsigned char) c] & _SERVAL_CTYPE_0_BASE64URL) != 0;
}

__SERVAL_DNA__STR_INLINE int is_base64_pad(char c) {
  return c == '=';
}

__SERVAL_DNA__STR_INLINE int is_base64url_pad(char c) {
  return c == '=';
}

__SERVAL_DNA__STR_INLINE uint8_t base64_digit(char c) {
  return _serval_ctype_0[(unsigned char) c] & _SERVAL_CTYPE_0_BASE64_MASK;
}

__SERVAL_DNA__STR_INLINE uint8_t base64url_digit(char c) {
  return _serval_ctype_0[(unsigned char) c] & _SERVAL_CTYPE_0_BASE64_MASK;
}

__SERVAL_DNA__STR_INLINE int is_multipart_boundary(char c) {
  return (_serval_ctype_2[(unsigned char) c] & _SERVAL_CTYPE_2_MULTIPART_BOUNDARY) != 0;
}

__SERVAL_DNA__STR_INLINE int is_valid_multipart_boundary_string(const char *s)
{
  if (s[0] == '\0')
    return 0;
  for (; *s; ++s)
    if (!is_multipart_boundary(*s))
      return 0;
  return s[-1] != ' ';
}

__SERVAL_DNA__STR_INLINE int is_http_separator(char c) {
  return (_serval_ctype_1[(unsigned char) c] & _SERVAL_CTYPE_1_HTTP_SEPARATOR) != 0;
}

__SERVAL_DNA__STR_INLINE int is_http_token(char c) {
  return is_http_char(c) && !is_http_ctl(c) && !is_http_separator(c);
}

/* Convert the given ASCII hex digit character into its radix value, eg, '0' ->
 * 0, 'b' -> 11.  If the argument is not an ASCII hex digit, returns -1.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
__SERVAL_DNA__STR_INLINE int hexvalue(char c) {
  return isxdigit(c) ? _serval_ctype_1[(unsigned char) c] & _SERVAL_CTYPE_1_HEX_MASK : -1;
}

/* -------------------- Printable string representation -------------------- */

char *toprint(char *dstStr, ssize_t dstBufSiz, const char *srcBuf, size_t srcBytes, const char quotes[2]);
char *toprint_str(char *dstStr, ssize_t dstBufSiz, const char *srcStr, const char quotes[2]);
size_t toprint_len(const char *srcBuf, size_t srcBytes, const char quotes[2]);
size_t toprint_str_len(const char *srcStr, const char quotes[2]);
size_t strn_fromprint(unsigned char *dst, size_t dstsiz, const char *src, size_t srclen, char endquote, const char **afterp);

#define alloca_toprint_quoted(dstlen,buf,len,quotes)  toprint((char *)alloca((dstlen) == -1 ? toprint_len((const char *)(buf),(len), (quotes)) + 1 : (size_t)(dstlen)), (size_t)(dstlen), (const char *)(buf), (len), (quotes))
#define alloca_toprint(dstlen,buf,len)  alloca_toprint_quoted(dstlen,buf,len,"``")

#define alloca_str_toprint_quoted(str, quotes)  toprint_str((char *)alloca(toprint_str_len((str), (quotes)) + 1), -1, (str), (quotes))
#define alloca_str_toprint(str)  alloca_str_toprint_quoted(str, "``")

/* -------------------- Useful string primitives -------------------- */

/* Like strchr(3), but only looks for 'c' in the first 'n' characters of 's', stopping at the first
 * nul char in 's'.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
const char *strnchr(const char *s, size_t n, char c);

/* Like strchr(3) and strrchr(3), but returns the index into the string instead of a pointer, or -1
 * if the character is not found.  The '_dfl' variants take a third argument that gives the default
 * value to return if the character is not found.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */

__SERVAL_DNA__STR_INLINE ssize_t str_index_dfl(const char *s, char c, ssize_t dfl)
{
  const char *r = strchr(s, c);
  return r ? r - s : dfl;
}

__SERVAL_DNA__STR_INLINE ssize_t str_rindex_dfl(const char *s, char c, ssize_t dfl)
{
  const char *r = strrchr(s, c);
  return r ? r - s : dfl;
}

__SERVAL_DNA__STR_INLINE ssize_t str_index(const char *s, char c)
{
  return str_index_dfl(s, c, -1);
}

__SERVAL_DNA__STR_INLINE ssize_t str_rindex(const char *s, char c)
{
  return str_rindex_dfl(s, c, -1);
}

/* Check if a given nul-terminated string 'str' starts with a given nul-terminated sub-string.  If
 * so, return 1 and, if afterp is not NULL, set *afterp to point to the character in 'str'
 * immediately following the substring.  Otherwise return 0.
 *
 * This function is used to parse HTTP headers and responses, which are typically not
 * nul-terminated, but are held in a buffer which has an associated length.  To avoid this function
 * running past the end of the buffer, the caller must ensure that the buffer contains a sub-string
 * that is not part of the sub-string being sought, eg, "\r\n\r\n" as detected by
 * is_http_header_complete().  This guarantees that this function will return nonzero before running
 * past the end of the buffer.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int str_startswith(const char *str, const char *substring, const char **afterp);

/* Check if a given string 'str' of a given length 'len' starts with a given nul-terminated
 * sub-string.  If so, return 1 and, if afterp is not NULL, set *afterp to point to the character
 * immediately following the substring.  Otherwise return 0.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int strn_startswith(const char *str, size_t len, const char *substring, const char **afterp);

/* Case-insensitive form of str_startswith().
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int strcase_startswith(const char *str, const char *substring, const char **afterp);

/* Case-insensitive form of strn_startswith().
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int strncase_startswith(const char *str, size_t len, const char *substring, const char **afterp);

/* Compare the given string 'str1' of a given length 'len1' with a given nul-terminated string
 * 'str2'.  Equivalent to { str1[len1] = '\0'; return strcmp(str1, str2); } except without modifying
 * str1[].
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int strn_str_cmp(const char *str1, size_t len1, const char *str2);

/* Compare case-insenstivively the given string 'str1' of a given length 'len1' with a given
 * nul-terminated string 'str2'.  Equivalent to { str1[len1] = '\0'; return strcasecmp(str1, str2);
 * } except without modifying str1[].
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int strn_str_casecmp(const char *str1, size_t len1, const char *str2);

/* like strstr(3), but doesn't depend on null termination.
 *
 * @author Paul Gardner-Stephen <paul@servalproject.org>
 * @author Andrew Bettison <andrew@servalproject.com>
 */
char *str_str(char *haystack, const char *needle, size_t haystack_len);

/* -------------------- Numeric strings -------------------- */

/* Returns 1 if the given nul-terminated string parses successfully as an unsigned 64-bit integer.
 * Returns 0 if not.  This is simply a shortcut for str_to_uint32(str, 10, NULL, NULL), which is
 * convenient for when a pointer to a predicate function is needed.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int str_is_uint64_decimal(const char *str);

/* Parse a NUL-terminated string as an integer in ASCII radix notation in the given 'base' (eg,
 * base=10 means decimal).
 *
 * Returns 1 if a valid integer is parsed, storing the value in *result (unless result is NULL) and
 * storing a pointer to the immediately succeeding character in *afterp.  If afterp is NULL then
 * returns 0 unless the immediately succeeding character is a NUL '\0'.  If no integer is parsed or
 * if the integer overflows (too many digits), then returns 0, leaving *result unchanged and setting
 * setting *afterp to point to the character where parsing failed.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int str_to_int32(const char *str, unsigned base, int32_t *result, const char **afterp);
int str_to_uint32(const char *str, unsigned base, uint32_t *result, const char **afterp);
int str_to_int64(const char *str, unsigned base, int64_t *result, const char **afterp);
int str_to_uint64(const char *str, unsigned base, uint64_t *result, const char **afterp);

/* Parse a length-bound string as an integer in ASCII radix notation in the given 'base' (eg,
 * base=10 means decimal).
 *
 * Returns 1 if a valid integer is parsed, storing the value in *result (unless result is NULL) and
 * storing a pointer to the immediately succeeding character in *afterp.  If afterp is NULL then
 * returns 0 unless all 'strlen' characters of the string were consumed.  If no integer is parsed or
 * if the integer overflows (too many digits), then returns 0, leaving *result unchanged and setting
 * setting *afterp to point to the character where parsing failed.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int strn_to_uint32(const char *str, size_t strlen, unsigned base, uint32_t *result, const char **afterp);
int strn_to_uint64(const char *str, size_t strlen, unsigned base, uint64_t *result, const char **afterp);

/* Parse a string as an integer in ASCII radix notation in the given 'base' (eg, base=10 means
 * decimal) and scale the result by a factor given by an optional suffix "scaling" character in the
 * set {kKmMgG}: 'k' = 1e3, 'K' = 1<<10, 'm' = 1e6, 'M' = 1<<20, 'g' = 1e9, 'G' = * 1<<30.
 *
 * Return 1 if a valid scaled integer was parsed, storing the value in *result (unless result is
 * NULL) and storing a pointer to the immediately succeeding character in *afterp (unless afterp is
 * NULL, in which case returns 1 only if the immediately succeeding character is a nul '\0').
 * Returns 0 otherwise, leaving *result and *afterp unchanged.
 *
 * NOTE: an argument base > 16 will cause any trailing 'g' or 'G' character to be parsed as part of
 * the integer, not as a scale suffix.  Ditto for base > 20 and 'k' 'K', and base > 22 and 'm' 'M'.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int str_to_int32_scaled(const char *str, unsigned base, int32_t *result, const char **afterp);
int str_to_uint32_scaled(const char *str, unsigned base, uint32_t *result, const char **afterp);
int str_to_int64_scaled(const char *str, unsigned base, int64_t *result, const char **afterp);
int str_to_uint64_scaled(const char *str, unsigned base, uint64_t *result, const char **afterp);
uint64_t scale_factor(const char *str, const char **afterp);

/* Format a string as a decimal integer in ASCII radix notation with a scale suffix character in the
 * set {kKmMgG}: 'k' = 1e3, 'K' = 1<<10, 'm' = 1e6, 'M' = 1<<20, 'g' = 1e9, 'G' = * 1<<30 if the
 * value is an exact multiple.
 *
 * Return 1 if the supplied string buffer was large enough to hold the formatted result plus a
 * terminating nul character, 0 otherwise.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int uint32_scaled_to_str(char *str, size_t len, uint32_t value);
int uint64_scaled_to_str(char *str, size_t len, uint64_t value);

/* Parse a string as a time interval (seconds) in millisecond resolution.  Return the number of
 * milliseconds.  Valid strings are all unsigned ASCII decimal numbers with up to three digits after
 * the decimal point.
 *
 * Return 1 if a valid interval was parsed, storing the number of milliseconds in *result (unless
 * result is NULL) and storing a pointer to the immediately succeeding character in *afterp (unless
 * afterp is NULL, in which case returns 1 only if the immediately succeeding character is a nul
 * '\0').  Returns 0 otherwise, leaving *result and *afterp unchanged.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int str_to_uint64_interval_ms(const char *str, int64_t *result, const char **afterp);

/* -------------------- URI strings -------------------- */

/* Return true if the string resembles a nul-terminated URI.
 * Based on RFC-3986 generic syntax, assuming nothing about the hierarchical part.
 *
 * uri :=           scheme ":" hierarchical [ "?" query ] [ "#" fragment ]
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int str_is_uri(const char *uri);

__SERVAL_DNA__STR_INLINE int is_uri_char_scheme(char c) {
  return (_serval_ctype_1[(unsigned char) c] & _SERVAL_CTYPE_1_URI_SCHEME) != 0;
}

__SERVAL_DNA__STR_INLINE int is_uri_char_unreserved(char c) {
  return (_serval_ctype_1[(unsigned char) c] & _SERVAL_CTYPE_1_URI_UNRESERVED) != 0;
}

__SERVAL_DNA__STR_INLINE int is_uri_char_reserved(char c) {
  return (_serval_ctype_1[(unsigned char) c] & _SERVAL_CTYPE_1_URI_RESERVED) != 0;
}

/* Return true if the string resembles a URI scheme without the terminating colon.
 * Based on RFC-3986 generic syntax.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
__SERVAL_DNA__STR_INLINE int str_is_uri_scheme(const char *scheme)
{
  if (!isalpha(*scheme++))
    return 0;
  while (is_uri_char_scheme(*scheme))
    ++scheme;
  return *scheme == '\0';
}

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

/* -------------------- Command-line strings -------------------- */

int parse_argv(char *cmdline, char delim, char **argv, int max_argv);

#endif // __SERVAL_DNA__STR_H__
