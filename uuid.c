/*
Serval DNA Universally Unique Identifier support
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

#define __SERVALDNA_UUID_H_INLINE
#include "uuid.h"
#include "os.h"
#include "str.h"

#include <assert.h>
#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif

enum uuid_version uuid_get_version(const uuid_t *uuid)
{
  assert(uuid_is_valid(uuid));
  switch (ntohs(uuid->u.record.time_hi_and_version) & 0xf000) {
    case 0x1000: return UUID_VERSION_TIME_BASED;
    case 0x2000: return UUID_VERSION_DCE_SECURITY;
    case 0x3000: return UUID_VERSION_NAME_MD5;
    case 0x4000: return UUID_VERSION_RANDOM;
    case 0x5000: return UUID_VERSION_NAME_SHA1;
  }
  return UUID_VERSION_UNSUPPORTED;
}

void uuid_set_version(uuid_t *uuid, enum uuid_version version)
{
  uint16_t version_bits;
  switch (version) {
    case UUID_VERSION_TIME_BASED:   version_bits = 0x1000; break;
    case UUID_VERSION_DCE_SECURITY: version_bits = 0x2000; break;
    case UUID_VERSION_NAME_MD5:	    version_bits = 0x3000; break;
    case UUID_VERSION_RANDOM:	    version_bits = 0x4000; break;
    case UUID_VERSION_NAME_SHA1:    version_bits = 0x5000; break;
    default: abort();
  }
  assert(uuid_is_valid(uuid));
  uuid->u.record.time_hi_and_version = htons((ntohs(uuid->u.record.time_hi_and_version) & 0xfff) | version_bits);
}

int uuid_generate_random(uuid_t *uuid)
{
  if (urandombytes(uuid->u.binary, sizeof uuid->u.binary) == -1)
    return -1;
  // The following discards 6 random bits.
  uuid->u.record.clock_seq_hi_and_reserved &= 0x3f;
  uuid->u.record.clock_seq_hi_and_reserved |= 0x80;
  uuid_set_version(uuid, UUID_VERSION_RANDOM);
  return 0;
}

char *uuid_to_str(const uuid_t *uuid, char *const dst)
{
  char *p = dst;
  assert(uuid_is_valid(uuid));
  unsigned i;
  for (i = 0; i != sizeof uuid->u.binary; ++i) {
    switch (i) {
      case 4: case 6: case 8: case 10:
	*p++ = '-';
      default:
	*p++ = hexdigit_lower[uuid->u.binary[i] >> 4];
	*p++ = hexdigit_lower[uuid->u.binary[i] & 0xf];
    }
  }
  *p = '\0';
  assert(p == dst + UUID_STRLEN);
  return dst;
}

int str_to_uuid(const char *const str, uuid_t *uuid, const char **afterp)
{
  const char *end = str;
  int ret = 0;
  if (	 strn_fromhex(uuid->u.binary, 4, end, &end) == 4
      && *end == '-'
      && strn_fromhex(uuid->u.binary + 4, 2, end + 1, &end) == 2
      && *end == '-'
      && strn_fromhex(uuid->u.binary + 6, 2, end + 1, &end) == 2
      && *end == '-'
      && strn_fromhex(uuid->u.binary + 8, 2, end + 1, &end) == 2
      && *end == '-'
      && strn_fromhex(uuid->u.binary + 10, 6, end + 1, &end) == 6
  ) {
    assert(end == str + UUID_STRLEN);
    ret = uuid_is_valid(uuid);
  }
  if (afterp)
    *afterp = end;
  if (ret == 0 || (!afterp && *end))
    return 0;
  return 1;
}
