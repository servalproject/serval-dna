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

#ifndef __SERVAL_DNA__STR_H__
#define __SERVAL_DNA__STR_H__

#include <string.h>    // for strcpy(), strlen() etc.
#include <stdint.h>    // for uint8_t
#include <sys/types.h> // for size_t
#include <ctype.h>     // for isascii(), isxdigit() etc.
#include <alloca.h>

#ifndef __SERVAL_DNA__STR_INLINE
# if __GNUC__ && !__GNUC_STDC_INLINE__
#  define __SERVAL_DNA__STR_INLINE extern inline
# else
#  define __SERVAL_DNA__STR_INLINE inline
# endif
#endif

/* -------------------- Useful functions and macros -------------------- */

#define alloca_strdup(str)       strcpy(alloca(strlen(str) + 1), (str))
#define alloca_strndup(str,len)  strncpy_nul(alloca((len) + 1), (str), (len) + 1)
#define buf_strncpy_nul(buf,str) strncpy_nul((buf), (str), sizeof(buf))

/* Like strncpy(3) but ensures the string is nul terminated.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
__SERVAL_DNA__STR_INLINE char *strncpy_nul(char *dst, const char *src, size_t n)
{
  strncpy(dst, src, n - 1)[n - 1] = '\0';
  return dst;
}

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
int fromhexstr(unsigned char *dstBinary, size_t nbinary, const char *srcHex);
int fromhexstrn(unsigned char *dstBinary, size_t nbinary, const char *srcHex, size_t nHex, const char **afterHex);

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
size_t strn_fromhex(unsigned char *dstBinary, ssize_t dstsiz, const char *src, const char **afterp);

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

__SERVAL_DNA__STR_INLINE int is_http_char(int c) {
  return isascii(c);
}

__SERVAL_DNA__STR_INLINE int is_http_ctl(int c) {
  return iscntrl(c);
}

__SERVAL_DNA__STR_INLINE int is_base64_digit(int c) {
  return (_serval_ctype_0[(uint8_t) c] & _SERVAL_CTYPE_0_BASE64) != 0;
}

__SERVAL_DNA__STR_INLINE int is_base64url_digit(int c) {
  return (_serval_ctype_0[(uint8_t) c] & _SERVAL_CTYPE_0_BASE64URL) != 0;
}

__SERVAL_DNA__STR_INLINE int is_base64_pad(int c) {
  return c == '=';
}

__SERVAL_DNA__STR_INLINE int is_base64url_pad(int c) {
  return c == '=';
}

__SERVAL_DNA__STR_INLINE uint8_t base64_digit(char c) {
  return _serval_ctype_0[(uint8_t) c] & _SERVAL_CTYPE_0_BASE64_MASK;
}

__SERVAL_DNA__STR_INLINE uint8_t base64url_digit(char c) {
  return _serval_ctype_0[(uint8_t) c] & _SERVAL_CTYPE_0_BASE64_MASK;
}

__SERVAL_DNA__STR_INLINE int is_multipart_boundary(int c) {
  return (_serval_ctype_2[(uint8_t) c] & _SERVAL_CTYPE_2_MULTIPART_BOUNDARY) != 0;
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

__SERVAL_DNA__STR_INLINE int is_http_separator(int c) {
  return (_serval_ctype_1[(uint8_t) c] & _SERVAL_CTYPE_1_HTTP_SEPARATOR) != 0;
}

__SERVAL_DNA__STR_INLINE int is_http_token(int c) {
  return is_http_char(c) && !is_http_ctl(c) && !is_http_separator(c);
}

__SERVAL_DNA__STR_INLINE int is_uri_char_scheme(int c) {
  return (_serval_ctype_1[(uint8_t) c] & _SERVAL_CTYPE_1_URI_SCHEME) != 0;
}

__SERVAL_DNA__STR_INLINE int is_uri_char_unreserved(int c) {
  return (_serval_ctype_1[(uint8_t) c] & _SERVAL_CTYPE_1_URI_UNRESERVED) != 0;
}

__SERVAL_DNA__STR_INLINE int is_uri_char_reserved(int c) {
  return (_serval_ctype_1[(uint8_t) c] & _SERVAL_CTYPE_1_URI_RESERVED) != 0;
}

/* Convert the given ASCII hex digit character into its radix value, eg, '0' ->
 * 0, 'b' -> 11.  If the argument is not an ASCII hex digit, returns -1.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
__SERVAL_DNA__STR_INLINE int hexvalue(int c) {
  return isxdigit(c) ? _serval_ctype_1[(uint8_t) c] & _SERVAL_CTYPE_1_HEX_MASK : -1;
}

/* -------------------- In-line string formatting -------------------- */

size_t sprintf_len(const char *fmt, ...);
#define alloca_sprintf(dstsiz, fmt,...) strbuf_str(strbuf_sprintf(strbuf_alloca((dstsiz) == -1 ? sprintf_len((fmt), ##__VA_ARGS__) + 1 : (size_t)(dstsiz)), (fmt), ##__VA_ARGS__))

/* -------------------- Printable string representation -------------------- */

char *toprint(char *dstStr, ssize_t dstBufSiz, const char *srcBuf, size_t srcBytes, const char quotes[2]);
char *toprint_str(char *dstStr, ssize_t dstBufSiz, const char *srcStr, const char quotes[2]);
size_t toprint_len(const char *srcBuf, size_t srcBytes, const char quotes[2]);
size_t toprint_str_len(const char *srcStr, const char quotes[2]);
size_t strn_fromprint(char *dst, size_t dstsiz, const char *src, size_t srclen, char endquote, const char **afterp);

#define alloca_toprint_quoted(dstsiz,buf,len,quotes)  toprint((char *)alloca((dstsiz) == -1 ? toprint_len((const char *)(buf),(len), (quotes)) + 1 : (size_t)(dstsiz)), (ssize_t)(dstsiz), (const char *)(buf), (len), (quotes))
#define alloca_toprint(dstsiz,buf,len)  alloca_toprint_quoted(dstsiz,buf,len,"``")

#define alloca_str_toprint_quoted(str, quotes)  toprint_str((char *)alloca(toprint_str_len((str), (quotes)) + 1), -1, (str), (quotes))
#define alloca_str_toprint(str)  alloca_str_toprint_quoted(str, "``")

/* -------------------- Pass phrases -------------------- */

#define SERVAL_PASSPHRASE_DIGEST_MAX_BINARY 64

/* Digest a pass phrase into binary data of at most
 * SERVAL_PASSPHRASE_DIGEST_MAX_BINARY bytes using a strong one-way function.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
void str_digest_passphrase(unsigned char *dstBinary, size_t dstsiz, const char *passphrase);
void strn_digest_passphrase(unsigned char *dstBinary, size_t dstsiz, const char *passphrase, size_t passlen);

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
 * If len == -1 then is equivalent to str_startswith().
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int strn_startswith(const char *str, ssize_t len, const char *substring, const char **afterp);

/* Case-insensitive form of str_startswith().
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int strcase_startswith(const char *str, const char *substring, const char **afterp);

/* Case-insensitive form of strn_startswith().
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int strncase_startswith(const char *str, size_t len, const char *substring, const char **afterp);

/* Check if a given nul-terminated string 'str' ends with a given nul-terminated sub-string.  If
 * so, return 1 and, if startp is not NULL, set *startp to point to the first character of the
 * found substring.  Otherwise return 0.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int str_endswith(const char *str, const char *substring, const char **startp);

/* Case-insensitive form of str_endswith().
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int strcase_endswith(const char *str, const char *substring, const char **startp);

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

/* -------------------- Command-line strings -------------------- */

int parse_argv(char *cmdline, char delim, char **argv, int max_argv);

#endif // __SERVAL_DNA__STR_H__
