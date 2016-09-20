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

#define __SERVAL_DNA__NUMERIC_STR_INLINE
#include "numeric_str.h"
#include "str.h"
#include "strbuf.h"
#include <stdlib.h>
#include <errno.h>

int str_to_uint16(const char *str, unsigned base, uint16_t *result, const char **afterp)
{
  return strn_to_uint16(str, 0, base, result, afterp);
}

int strn_to_uint16(const char *str, size_t strlen, unsigned base, uint16_t *result, const char **afterp)
{
  assert(base > 0);
  assert(base <= 16);
  uint16_t value = 0;
  uint16_t newvalue = 0;
  const char *const end = str + strlen;
  const char *s;
  for (s = str; strlen ? s < end : *s; ++s) {
    int digit = hexvalue(*s);
    if (digit < 0 || (unsigned)digit >= base)
      break;
    newvalue = value * base + digit;
    if (newvalue / base != value) // overflow
      break;
    value = newvalue;
  }
  if (afterp)
    *afterp = s;
  if (s == str || value != newvalue || (!afterp && (strlen ? s != end : *s)))
    return 0;
  if (result)
    *result = value;
  return 1;
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

int str_is_uint64_decimal(const char *str)
{
  return str_to_uint64(str, 10, NULL, NULL);
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
      { 'P', 1024LL * 1024LL * 1024LL * 1024LL * 1024LL },
      { 'p', 1000LL * 1000LL * 1000LL * 1000LL * 1000LL },
      { 'T', 1024LL * 1024LL * 1024LL * 1024LL },
      { 't', 1000LL * 1000LL * 1000LL * 1000LL },
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

