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

#ifndef __SERVAL_DNA_STR_H__
#define __SERVAL_DNA_STR_H__

#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <ctype.h>
#include <alloca.h>

#ifndef __SERVAL_DNA_STR_INLINE
# if __GNUC__ && !__GNUC_STDC_INLINE__
#  define __SERVAL_DNA_STR_INLINE extern inline
# else
#  define __SERVAL_DNA_STR_INLINE inline
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
__SERVAL_DNA_STR_INLINE int is_xsubstring(const char *text, int len)
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
__SERVAL_DNA_STR_INLINE int is_xstring(const char *text, int len)
{
  while (len--)
    if (!isxdigit(*text++))
      return 0;
  return *text == '\0';
}

/* Converts a given binary blob to uppercase ASCII hexadecimal.
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

/* -------------------- Character classes -------------------- */

#define _SERVAL_CTYPE_0_BASE64_MASK 0x3f
#define _SERVAL_CTYPE_0_BASE64 (1 << 6)
#define _SERVAL_CTYPE_0_MULTIPART_BOUNDARY (1 << 7)

#define _SERVAL_CTYPE_1_HEX_MASK 0xf
#define _SERVAL_CTYPE_1_HTTP_SEPARATOR (1 << 4)
#define _SERVAL_CTYPE_1_URI_SCHEME (1 << 5)
#define _SERVAL_CTYPE_1_URI_UNRESERVED (1 << 6)
#define _SERVAL_CTYPE_1_URI_RESERVED (1 << 7)

extern uint8_t _serval_ctype_0[UINT8_MAX];
extern uint8_t _serval_ctype_1[UINT8_MAX];

__SERVAL_DNA_STR_INLINE int is_http_char(char c) {
  return isascii(c);
}

__SERVAL_DNA_STR_INLINE int is_http_ctl(char c) {
  return iscntrl(c);
}

__SERVAL_DNA_STR_INLINE int is_base64_digit(char c) {
  return (_serval_ctype_0[(unsigned char) c] & _SERVAL_CTYPE_0_BASE64) != 0;
}

__SERVAL_DNA_STR_INLINE int is_base64_pad(char c) {
  return c == '=';
}

__SERVAL_DNA_STR_INLINE uint8_t base64_digit(char c) {
  return _serval_ctype_0[(unsigned char) c] & _SERVAL_CTYPE_0_BASE64_MASK;
}

__SERVAL_DNA_STR_INLINE int is_multipart_boundary(char c) {
  return (_serval_ctype_0[(unsigned char) c] & _SERVAL_CTYPE_0_MULTIPART_BOUNDARY) != 0;
}

__SERVAL_DNA_STR_INLINE int is_valid_multipart_boundary_string(const char *s)
{
  if (s[0] == '\0')
    return 0;
  for (; *s; ++s)
    if (!is_multipart_boundary(*s))
      return 0;
  return s[-1] != ' ';
}

__SERVAL_DNA_STR_INLINE int is_http_separator(char c) {
  return (_serval_ctype_1[(unsigned char) c] & _SERVAL_CTYPE_1_HTTP_SEPARATOR) != 0;
}

__SERVAL_DNA_STR_INLINE int is_http_token(char c) {
  return is_http_char(c) && !is_http_ctl(c) && !is_http_separator(c);
}

/* Convert the given ASCII hex digit character into its radix value, eg, '0' ->
 * 0, 'b' -> 11.  If the argument is not an ASCII hex digit, returns -1.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
__SERVAL_DNA_STR_INLINE int hexvalue(char c) {
  return isxdigit(c) ? _serval_ctype_1[(unsigned char) c] & _SERVAL_CTYPE_1_HEX_MASK : -1;
}

/* -------------------- Printable string representation -------------------- */

char *toprint(char *dstStr, ssize_t dstBufSiz, const char *srcBuf, size_t srcBytes, const char quotes[2]);
char *toprint_str(char *dstStr, ssize_t dstBufSiz, const char *srcStr, const char quotes[2]);
size_t toprint_len(const char *srcBuf, size_t srcBytes, const char quotes[2]);
size_t toprint_str_len(const char *srcStr, const char quotes[2]);
size_t strn_fromprint(unsigned char *dst, size_t dstsiz, const char *src, size_t srclen, char endquote, const char **afterp);

#define alloca_toprint_quoted(dstlen,buf,len,quotes)  toprint((char *)alloca((dstlen) == -1 ? toprint_len((const char *)(buf),(len), (quotes)) + 1 : (dstlen)), (dstlen), (const char *)(buf), (len), (quotes))
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

__SERVAL_DNA_STR_INLINE ssize_t str_index_dfl(const char *s, char c, ssize_t dfl)
{
  const char *r = strchr(s, c);
  return r ? r - s : dfl;
}

__SERVAL_DNA_STR_INLINE ssize_t str_rindex_dfl(const char *s, char c, ssize_t dfl)
{
  const char *r = strrchr(s, c);
  return r ? r - s : dfl;
}

__SERVAL_DNA_STR_INLINE ssize_t str_index(const char *s, char c)
{
  return str_index_dfl(s, c, -1);
}

__SERVAL_DNA_STR_INLINE ssize_t str_rindex(const char *s, char c)
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
char *str_str(char *haystack, const char *needle, int haystack_len);

/* Parse a string as an integer in ASCII radix notation in the given 'base' (eg, base=10 means
 * decimal).
 *
 * Returns 1 if a valid integer is parsed, storing the value in *result (unless result is NULL) and
 * storing a pointer to the immediately succeeding character in *afterp.  If afterp is NULL then
 * returns 0 unless the immediately succeeding character is a NUL '\0'.  If no integer is parsed or
 * if the integer overflows (too many digits), then returns 0, leaving *result unchanged and setting
 * setting *afterp to point to the character where parsing failed.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int str_to_int(const char *str, int base, int *result, const char **afterp);
int str_to_uint(const char *str, int base, unsigned *result, const char **afterp);
int str_to_int64(const char *str, int base, int64_t *result, const char **afterp);
int str_to_uint64(const char *str, int base, uint64_t *result, const char **afterp);

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
int str_to_int64_scaled(const char *str, int base, int64_t *result, const char **afterp);
int str_to_uint64_scaled(const char *str, int base, uint64_t *result, const char **afterp);
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

/* Return true if the string resembles a nul-terminated URI.
 * Based on RFC-3986 generic syntax, assuming nothing about the hierarchical part.
 *
 * uri :=           scheme ":" hierarchical [ "?" query ] [ "#" fragment ]
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int str_is_uri(const char *uri);

__SERVAL_DNA_STR_INLINE int is_uri_char_scheme(char c) {
  return (_serval_ctype_1[(unsigned char) c] & _SERVAL_CTYPE_1_URI_SCHEME) != 0;
}

__SERVAL_DNA_STR_INLINE int is_uri_char_unreserved(char c) {
  return (_serval_ctype_1[(unsigned char) c] & _SERVAL_CTYPE_1_URI_UNRESERVED) != 0;
}

__SERVAL_DNA_STR_INLINE int is_uri_char_reserved(char c) {
  return (_serval_ctype_1[(unsigned char) c] & _SERVAL_CTYPE_1_URI_RESERVED) != 0;
}

/* Return true if the string resembles a URI scheme without the terminating colon.
 * Based on RFC-3986 generic syntax.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
__SERVAL_DNA_STR_INLINE int str_is_uri_scheme(const char *scheme)
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


int parse_argv(char *cmdline, char delim, char **argv, int max_argv);

#endif // __SERVAL_DNA_STR_H__
