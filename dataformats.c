/*
Serval DNA data interchange formats
Copyright (C) 2010-2013 Serval Project Inc.

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

#include <ctype.h>
#include "serval.h"
#include "rhizome.h"
#include "str.h"
#include "dataformats.h"

int cmp_sid_t(const sid_t *a, const sid_t *b)
{
  return memcmp(a, b, sizeof a->binary);
}

int str_to_sid_t(sid_t *sidp, const char *hex)
{
  const char *end;
  return strn_to_sid_t(sidp, hex, SIZE_MAX, &end) != -1 && *end == '\0' ? 0 : -1;
}

int strn_to_sid_t(sid_t *sidp, const char *hex, size_t hexlen, const char **endp)
{
  if (strn_startswith(hex, hexlen, "broadcast", endp)) {
    if (sidp)
      *sidp = SID_BROADCAST;
    return 0;
  }
  sid_t tmp;
  if (hexlen < sizeof tmp.binary * 2)
    return -1;
  int n = fromhex(tmp.binary, hex, sizeof tmp.binary);
  if (n != sizeof tmp.binary)
    return -1;
  if (sidp)
    *sidp = tmp;
  if (endp)
    *endp = hex + sizeof tmp.binary * 2;
  return 0;
}

int str_is_subscriber_id(const char *sid)
{
  size_t len = 0;
  return strn_is_subscriber_id(sid, &len) && sid[len] == '\0';
}

int strn_is_subscriber_id(const char *sid, size_t *lenp)
{
  if (strncasecmp(sid, "broadcast", 9) == 0) {
    if (lenp)
      *lenp = 9;
    return 1;
  }
  if (is_xsubstring(sid, SID_STRLEN)) {
    if (lenp)
      *lenp = SID_STRLEN;
    return 1;
  }
  return 0;
}

int cmp_rhizome_bid_t(const rhizome_bid_t *a, const rhizome_bid_t *b)
{
  return memcmp(a, b, sizeof a->binary);
}

int str_to_rhizome_bid_t(rhizome_bid_t *bid, const char *hex)
{
  return bid ? fromhexstr(bid->binary, hex, sizeof bid->binary) : is_xstring(hex, RHIZOME_BUNDLE_ID_STRLEN) ? 0 : -1;
}

int strn_to_rhizome_bid_t(rhizome_bid_t *bid, const char *hex, const char **endp)
{
  rhizome_bid_t tmp;
  int n = fromhex(tmp.binary, hex, sizeof tmp.binary);
  if (n != sizeof tmp.binary)
    return -1;
  if (bid)
    *bid = tmp;
  if (endp)
    *endp = hex + sizeof tmp.binary * 2;
  return 0;
}

int cmp_rhizome_filehash_t(const rhizome_filehash_t *a, const rhizome_filehash_t *b)
{
  return memcmp(a, b, sizeof a->binary);
}

int str_to_rhizome_filehash_t(rhizome_filehash_t *hashp, const char *hex)
{
  return hashp ? fromhexstr(hashp->binary, hex, sizeof hashp->binary) : is_xstring(hex, RHIZOME_FILEHASH_STRLEN) ? 0 : -1;
}

int strn_to_rhizome_filehash_t(rhizome_filehash_t *hashp, const char *hex, const char **endp)
{
  rhizome_filehash_t tmp;
  int n = fromhex(tmp.binary, hex, sizeof tmp.binary);
  if (n != sizeof tmp.binary)
    return -1;
  if (hashp)
    *hashp = tmp;
  if (endp)
    *endp = hex + sizeof tmp.binary * 2;
  return 0;
}

int str_to_rhizome_bk_t(rhizome_bk_t *bkp, const char *hex)
{
  return bkp ? fromhexstr(bkp->binary, hex, sizeof bkp->binary) : is_xstring(hex, RHIZOME_BUNDLE_KEY_STRLEN) ? 0 : -1;
}

int strn_to_rhizome_bk_t(rhizome_bk_t *bkp, const char *hex, const char **endp)
{
  rhizome_bk_t tmp;
  int n = fromhex(tmp.binary, hex, sizeof tmp.binary);
  if (n != sizeof tmp.binary)
    return -1;
  if (bkp)
    *bkp = tmp;
  if (endp)
    *endp = hex + sizeof tmp.binary * 2;
  return 0;
}

int rhizome_strn_is_bundle_crypt_key(const char *key)
{
  return is_xsubstring(key, RHIZOME_CRYPT_KEY_STRLEN);
}

int rhizome_str_is_bundle_crypt_key(const char *key)
{
  return is_xstring(key, RHIZOME_CRYPT_KEY_STRLEN);
}

int rhizome_str_is_manifest_service(const char *text)
{
  if (text[0] == '\0')
    return 0;
  while (*text && (isalnum(*text) || *text == '_' || *text == '.'))
    ++text;
  return *text == '\0';
}

/* A name cannot contain a LF because that is the Rhizome text manifest field terminator.  For the
 * time being, CR is not allowed either, because the Rhizome field terminator includes an optional
 * CR.  See rhizome_manifest_parse().
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int rhizome_str_is_manifest_name(const char *text)
{
  while (*text && *text != '\n' && *text != '\r')
    ++text;
  return *text == '\0';
}

int str_is_did(const char *did)
{
  size_t len = 0;
  return strn_is_did(did, &len) && did[len] == '\0';
}

int is_didchar(char c)
{
  return isdigit(c) || c == '*' || c == '#' || c == '+';
}

int strn_is_did(const char *did, size_t *lenp)
{
  int i;
  for (i = 0; i < DID_MAXSIZE && is_didchar(did[i]); ++i)
    ;
  if (i < DID_MINSIZE)
    return 0;
  if (lenp)
    *lenp = i;
  return 1;
}

void write_uint64(unsigned char *o,uint64_t v)
{
  int i;
  for(i=0;i<8;i++)
  { *(o++)=v&0xff; v=v>>8; }
}

void write_uint32(unsigned char *o,uint32_t v)
{
  int i;
  for(i=0;i<4;i++)
  { *(o++)=v&0xff; v=v>>8; }
}

void write_uint16(unsigned char *o,uint16_t v)
{
  int i;
  for(i=0;i<2;i++)
  { *(o++)=v&0xff; v=v>>8; }
}

uint64_t read_uint64(const unsigned char *o)
{
  int i;
  uint64_t v=0;
  for(i=0;i<8;i++) v=(v<<8)|o[8-1-i];
  return v;
}

uint32_t read_uint32(const unsigned char *o)
{
  int i;
  uint32_t v=0;
  for(i=0;i<4;i++) v=(v<<8)|o[4-1-i];
  return v;
}

uint16_t read_uint16(const unsigned char *o)
{
  int i;
  uint16_t v=0;
  for(i=0;i<2;i++) v=(v<<8)|o[2-1-i];
  return v;
}

int compare_wrapped_uint8(uint8_t one, uint8_t two)
{
  return (int8_t)(one - two);
}

int compare_wrapped_uint16(uint16_t one, uint16_t two)
{
  return (int16_t)(one - two);
}
