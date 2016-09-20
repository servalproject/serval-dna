/*
 Serval numerical string primitives
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

#ifndef __SERVAL_DNA__NUMERIC_STR_H__
#define __SERVAL_DNA__NUMERIC_STR_H__

#include "strbuf.h"
#include <sys/types.h> // for size_t
#include <stdint.h>

#ifndef __SERVAL_DNA__NUMERIC_STR_INLINE
# if __GNUC__ && !__GNUC_STDC_INLINE__
#  define __SERVAL_DNA__NUMERIC_STR_INLINE extern inline
# else
#  define __SERVAL_DNA__NUMERIC_STR_INLINE inline
# endif
#endif

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
int str_to_uint16(const char *str, unsigned base, uint16_t *result, const char **afterp);
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
int strn_to_uint16(const char *str, size_t strlen, unsigned base, uint16_t *result, const char **afterp);
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

/* Append an integer value to a strbuf in ASCII decimal format, optionally scaled with a scale
 * suffix character in the set {kKmMgGtTpP}: 'k' = 1e3, 'K' = 1<<10, 'm' = 1e6, 'M' = 1<<20, 'g' =
 * 1e9, 'G' = * 1<<30, etc.  This format is lossless because the value is only scaled if it is an
 * exact multiple of the scaling factor.
 *
 * Eg, 1000 -> "1k"
 *     1001 -> "1001"
 *     1024 -> "1K"
 *     1025 -> "1025"
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
strbuf strbuf_append_uint32_scaled(strbuf sb, uint32_t value);
strbuf strbuf_append_uint64_scaled(strbuf sb, uint64_t value);

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

#endif // __SERVAL_DNA__NUMERIC_STR_H__
