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
#include <ctype.h>

char hexdigit[16] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

static inline int _is_xsubstring(const char *text, int len)
{
  while (len--)
    if (!isxdigit(*text++))
      return 0;
  return 1;
}

static inline int _is_xstring(const char *text, int len)
{
  while (len--)
    if (!isxdigit(*text++))
      return 0;
  return *text == '\0';
}

/* Return true iff 'len' bytes starting at 'text' are hex digits, upper or lower case.
   Does not check the following byte.
   @author Andrew Bettison <andrew@servalproject.com>
 */
int is_xsubstring(const char *text, int len)
{
  return _is_xsubstring(text, len);
}

/* Return true iff the nul-terminated string 'text' has length 'len' and consists only of hex
   digits, upper or lower case.
   @author Andrew Bettison <andrew@servalproject.com>
 */
int is_xstring(const char *text, int len)
{
  return _is_xstring(text, len);
}

char *tohex(char *dstHex, const unsigned char *srcBinary, size_t bytes)
{
  char *p;
  for (p = dstHex; bytes--; ++srcBinary) {
    *p++ = hexdigit[*srcBinary >> 4];
    *p++ = hexdigit[*srcBinary & 0xf];
  }
  *p = '\0';
  return dstHex;
}

size_t fromhex(unsigned char *dstBinary, const char *srcHex, size_t bytes)
{
  size_t count = 0;
  while (count != bytes) {
    unsigned char high = hexvalue(*srcHex++);
    if (high & 0xf0) return -1;
    unsigned char low = hexvalue(*srcHex++);
    if (low & 0xf0) return -1;
    dstBinary[count++] = (high << 4) + low;
  }
  return count;
}

int fromhexstr(unsigned char *dstBinary, const char *srcHex, size_t bytes)
{
  return (fromhex(dstBinary, srcHex, bytes) == bytes && srcHex[bytes * 2] == '\0') ? 0 : -1;
}

int rhizome_strn_is_manifest_id(const char *id)
{
  return _is_xsubstring(id, RHIZOME_MANIFEST_ID_STRLEN);
}

int rhizome_str_is_manifest_id(const char *id)
{
  return _is_xstring(id, RHIZOME_MANIFEST_ID_STRLEN);
}

int rhizome_strn_is_bundle_key(const char *key)
{
  return _is_xsubstring(key, RHIZOME_BUNDLE_KEY_STRLEN);
}

int rhizome_str_is_bundle_key(const char *key)
{
  return _is_xstring(key, RHIZOME_BUNDLE_KEY_STRLEN);
}

int rhizome_strn_is_bundle_crypt_key(const char *key)
{
  return _is_xsubstring(key, RHIZOME_CRYPT_KEY_STRLEN);
}

int rhizome_str_is_bundle_crypt_key(const char *key)
{
  return _is_xstring(key, RHIZOME_CRYPT_KEY_STRLEN);
}

int rhizome_strn_is_file_hash(const char *hash)
{
  return _is_xsubstring(hash, RHIZOME_FILEHASH_STRLEN);
}

int rhizome_str_is_file_hash(const char *hash)
{
  return _is_xstring(hash, RHIZOME_FILEHASH_STRLEN);
}

int extractDid(unsigned char *packet,int *ofs,char *did)
{
  int d=0;
  int highP=1;
  int nybl;

  nybl=0;
  while(nybl!=0xf&&(*ofs<(OFS_SIDDIDFIELD+SIDDIDFIELD_LEN))&&(d<64))
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

int validateSid(const char *sid)
{
  if (!sid) {
    WHY("invalid SID == NULL");
    return 0;
  }
  if (strcasecmp(sid, "broadcast") == 0)
    return 1;
  const char *s = sid;
  const char *e = sid + SID_STRLEN;
  while (s != e && isxdigit(*s))
    ++s;
  if (s != e) {
    if (*s)
      WHYF("invalid SID, contains non-hex character 0x%02x at offset %d", *s, s - sid);
    else
      WHYF("invalid SID, too short (strlen %d)", s - sid);
    return 0;
  }
  if (*s) {
    WHYF("invalid SID, too long");
    return 0;
  }
  return 1;
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

char *str_toupper_inplace(char *str)
{
  register char *s;
  for (s = str; *s; ++s)
    *s = toupper(*s);
  return str;
}

int hexvalue(char c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

int packetGetID(unsigned char *packet,int len,char *did,char *sid)
{
  int ofs=HEADERFIELDS_LEN;

  switch(packet[ofs])
    {
    case 0: /* DID */
      ofs++;
      if (extractDid(packet,&ofs,did)) return WHY("Could not decode DID");
      if (debug&DEBUG_PACKETFORMATS) fprintf(stderr,"Decoded DID as %s\n",did);
      return 0;
      break;
    case 1: /* SID */
      ofs++;
      if (len<(OFS_SIDDIDFIELD+SID_SIZE)) return WHY("Packet too short");
      if (extractSid(packet,&ofs,sid)) return WHY("Could not decode SID");
      return 0;
      break;
    default: /* no idea */
      return WHY("Unknown ID key");
      break;
    }
  
  return WHY("Impossible event #1 just occurred");
}

/*
  One of the goals of our packet format is to make it very difficult to mount a known plain-text
  attack against the ciphered part of the packet.
  One defence is to make sure that no fixed fields are actually left zero.
  We accomplish this by filling "zero" fields with randomised data that meets a simple test condition.
  We have chosen to use the condition that if the modulo 256 sum of the bytes equals zero, then the packet
  is assumed to be zero/empty.
  The following two functions allow us to test this, and also to fill a field with safe "zero" data.
*/

int isFieldZeroP(unsigned char *packet,int start,int count)
{
  int mod=0;
  int i;

  for(i=start;i<start+count;i++)
    {
      mod+=packet[i];
      mod&=0xff;
    }

  if (debug&DEBUG_PACKETFORMATS) {
    if (mod) fprintf(stderr,"Field [%d,%d) is non-zero (mod=0x%02x)\n",start,start+count,mod);
    else fprintf(stderr,"Field [%d,%d) is zero\n",start,start+count);
  }

  if (mod) return 0; else return 1;
}

int safeZeroField(unsigned char *packet,int start,int count)
{
  int mod=0;
  int i;

  if (debug&DEBUG_PACKETFORMATS)
    fprintf(stderr,"Known plain-text counter-measure: safe-zeroing [%d,%d)\n",
	    start,start+count);
  
  for(i=start;i<(start+count-1);i++)
    {
      packet[i]=random()&0xff;
      mod+=packet[i];
      mod&=0xff;
    }
  /* set final byte so that modulo sum is zero */
  packet[i]=(0x100-mod)&0xff;
  
  return 0;
}

