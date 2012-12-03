/*
Serval Distributed Numbering Architecture (DNA)
Copyright (C) 2010 Paul Gardner-Stephen

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

#include "serval.h"
#include "rhizome.h"
#include "str.h"
#include <ctype.h>

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

int rhizome_strn_is_manifest_id(const char *id)
{
  return is_xsubstring(id, RHIZOME_MANIFEST_ID_STRLEN);
}

int rhizome_str_is_manifest_id(const char *id)
{
  return is_xstring(id, RHIZOME_MANIFEST_ID_STRLEN);
}

int rhizome_strn_is_bundle_key(const char *key)
{
  return is_xsubstring(key, RHIZOME_BUNDLE_KEY_STRLEN);
}

int rhizome_str_is_bundle_key(const char *key)
{
  return is_xstring(key, RHIZOME_BUNDLE_KEY_STRLEN);
}

int rhizome_strn_is_bundle_crypt_key(const char *key)
{
  return is_xsubstring(key, RHIZOME_CRYPT_KEY_STRLEN);
}

int rhizome_str_is_bundle_crypt_key(const char *key)
{
  return is_xstring(key, RHIZOME_CRYPT_KEY_STRLEN);
}

int rhizome_strn_is_file_hash(const char *hash)
{
  return is_xsubstring(hash, RHIZOME_FILEHASH_STRLEN);
}

int rhizome_str_is_file_hash(const char *hash)
{
  return is_xstring(hash, RHIZOME_FILEHASH_STRLEN);
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

int extractDid(unsigned char *packet,int *ofs,char *did)
{
  int d=0;
  int highP=1;
  int nybl;

  nybl=0;
  while(nybl!=0xf&&(d<64))
    {
      if (highP) nybl=packet[*ofs]>>4; else nybl=packet[*ofs]&0xf;
      if (nybl<0xa) did[d++]='0'+nybl;
      else 
	switch(nybl) {
	case 0xa: did[d++]='*'; break;
	case 0xb: did[d++]='#'; break;
	case 0xc: did[d++]='+'; break;
	}
      if (highP) highP=0; else { (*ofs)++; highP=1; }
    }
  if (d>63) return WHY("DID too long");
  did[d]=0;

  return 0;
}

int stowDid(unsigned char *packet,int *ofs,char *did)
{
  int highP=1;
  int nybl;
  int d=0;
  int len=0;
  if (debug&DEBUG_PACKETFORMATS) printf("Packing DID \"%s\"\n",did);

  while(did[d]&&(d<DID_MAXSIZE))
    {
      switch(did[d])
	{
	case '0': case '1': case '2': case '3': case '4':
	case '5': case '6': case '7': case '8': case '9':
	  nybl=did[d]-'0'; break;
	case '*': nybl=0xa; break;
	case '#': nybl=0xb; break;
	case '+': nybl=0xc; break;
	default:
	  WHY("Illegal digits in DID number");
	  return -1;
	}
      if (highP) { packet[*ofs]=nybl<<4; highP=0; }
      else {
	packet[(*ofs)++]|=nybl; highP=1;
	len++;
      }
      d++;
    }
  if (d>=DID_MAXSIZE)
    {
      WHY("DID number too long");
      return -1;
    }
  /* Append end of number code, filling the whole byte for fast and easy comparison */
  if (highP) packet[(*ofs)++]=0xff;
  else packet[(*ofs)++]|=0x0f;
  len++;

  /* Fill remainder of field with randomness to protect any encryption */
  for(;len<SID_SIZE;len++) packet[(*ofs)++]=random()&0xff;
  
  return 0;
}

int extractSid(const unsigned char *packet, int *ofs, char *sid)
{
  (void) tohex(sid, packet + *ofs, SID_SIZE);
  *ofs += SID_SIZE;
  return 0;
}

int stowSid(unsigned char *packet, int ofs, const char *sid)
{
  if (debug & DEBUG_PACKETFORMATS)
    printf("stowing SID \"%s\"\n", sid);
  if (strcasecmp(sid,"broadcast") == 0)
    memset(packet + ofs, 0xff, SID_SIZE);
  else if (fromhex(packet + ofs, sid, SID_SIZE) != SID_SIZE || sid[SID_STRLEN] != '\0')
    return WHY("invalid SID");
  return 0;
}

int is_uri_char_scheme(char c)
{
  return isalpha(c) || isdigit(c) || c == '+' || c == '-' || c == '.';
}

int is_uri_char_unreserved(char c)
{
  return isalpha(c) || isdigit(c) || c == '-' || c == '.' || c == '_' || c == '~';
}

int is_uri_char_reserved(char c)
{
  switch (c) {
    case ':': case '/': case '?': case '#': case '[': case ']': case '@':
    case '!': case '$': case '&': case '\'': case '(': case ')':
    case '*': case '+': case ',': case ';': case '=':
      return 1;
  }
  return 0;
}

/* Return true if the string resembles a URI.
   Based on RFC-3986 generic syntax, assuming nothing about the hierarchical part.
   @author Andrew Bettison <andrew@servalproject.com>
 */
int str_is_uri(const char *uri)
{
  const char *p = uri;
  // Scheme is ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
  if (!isalpha(*p++))
    return 0;
  while (is_uri_char_scheme(*p))
    ++p;
  // Scheme is followed by colon ":".
  if (*p++ != ':')
    return 0;
  // Hierarchical part must contain only valid characters.
  const char *q = p;
  while (is_uri_char_unreserved(*p) || is_uri_char_reserved(*p))
    ++p;
  return p != q && *p == '\0';
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

uint64_t read_uint64(unsigned char *o)
{
  int i;
  uint64_t v=0;
  for(i=0;i<8;i++) v=(v<<8)|o[8-1-i];
  return v;
}

uint32_t read_uint32(unsigned char *o)
{
  int i;
  uint32_t v=0;
  for(i=0;i<4;i++) v=(v<<8)|o[4-1-i];
  return v;
}

uint16_t read_uint16(unsigned char *o)
{
  int i;
  uint16_t v=0;
  for(i=0;i<2;i++) v=(v<<8)|o[2-1-i];
  return v;
}
