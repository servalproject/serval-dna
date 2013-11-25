/* 
Serval DNA configuration
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

#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <stdarg.h>
#include <assert.h>
#include <arpa/inet.h>

#include "log.h"
#include "str.h"
#include "strbuf.h"
#include "strbuf_helpers.h"
#include "conf.h"
#include "dataformats.h"

int cf_opt_boolean(bool_t *booleanp, const char *text)
{
  if (!strcasecmp(text, "true") || !strcasecmp(text, "yes") || !strcasecmp(text, "on") || !strcasecmp(text, "1")) {
    *booleanp = 1;
    return CFOK;
  }
  else if (!strcasecmp(text, "false") || !strcasecmp(text, "no") || !strcasecmp(text, "off") || !strcasecmp(text, "0")) {
    *booleanp = 0;
    return CFOK;
  }
  return CFINVALID;
}

int cf_fmt_boolean(const char **textp, const bool_t *booleanp)
{
  if (*booleanp == 1) {
    *textp = str_edup("true");
    return CFOK;
  }
  else if (*booleanp == 0) {
    *textp = str_edup("false");
    return CFOK;
  }
  return CFINVALID;
}

int cf_cmp_boolean(const bool_t *a, const bool_t *b)
{
  return !*a && *b ? -1 : *a && !*b ? 1 : 0;
}

int cf_opt_absolute_path(char *str, size_t len, const char *text)
{
  if (text[0] != '/')
    return CFINVALID;
  if (strlen(text) >= len)
    return CFSTRINGOVERFLOW;
  strncpy(str, text, len);
  assert(str[len - 1] == '\0');
  return CFOK;
}

int cf_fmt_absolute_path(const char **textp, const char *str)
{
  if (str[0] != '/')
    return CFINVALID;
  *textp = str_edup(str);
  return CFOK;
}

int cf_cmp_absolute_path(const char *a, const char *b)
{
  return strcmp(a, b);
}

int cf_opt_protocol(char *str, size_t len, const char *text)
{
  if (!str_is_uri_scheme(text))
    return CFINVALID;
  if (strlen(text) >= len)
    return CFSTRINGOVERFLOW;
  strncpy(str, text, len);
  assert(str[len - 1] == '\0');
  return CFOK;
}

int cf_fmt_protocol(const char **textp, const char *str)
{
  if (!str_is_uri_scheme(str))
    return CFINVALID;
  *textp = str_edup(str);
  return CFOK;
}

int cf_cmp_protocol(const char *a, const char *b)
{
  return strcmp(a, b);
}

int cf_opt_rhizome_peer(struct config_rhizome_peer *rpeer, const struct cf_om_node *node)
{
  if (!node->text)
    return cf_opt_config_rhizome_peer(rpeer, node);
  if (node->nodc) {
    cf_warn_incompatible_children(node);
    return CFINCOMPATIBLE;
  }
  return cf_opt_rhizome_peer_from_uri(rpeer, node->text);
}

int cf_fmt_rhizome_peer(struct cf_om_node **parentp, const struct config_rhizome_peer *rpeer)
{
  return cf_fmt_config_rhizome_peer(parentp, rpeer);
}

int cf_cmp_rhizome_peer(const struct config_rhizome_peer *a, const struct config_rhizome_peer *b)
{
  return cf_cmp_config_rhizome_peer(a, b);
}

int cf_opt_rhizome_peer_from_uri(struct config_rhizome_peer *rpeer, const char *text)
{
  const char *protocol;
  size_t protolen;
  const char *auth;
  if (str_is_uri(text)) {
    const char *hier;
    if (!(   str_uri_scheme(text, &protocol, &protolen)
	  && str_uri_hierarchical(text, &hier, NULL)
	  && str_uri_hierarchical_authority(hier, &auth, NULL))
    )
      return CFINVALID;
  } else {
    auth = text;
    protocol = "http";
    protolen = strlen(protocol);
  }
  const char *host;
  size_t hostlen;
  uint16_t port = RHIZOME_HTTP_PORT;
  if (!str_uri_authority_hostname(auth, &host, &hostlen))
    return CFINVALID;
  str_uri_authority_port(auth, &port);
  if (protolen >= sizeof rpeer->protocol)
    return CFSTRINGOVERFLOW;
  if (hostlen >= sizeof rpeer->host)
    return CFSTRINGOVERFLOW;
  strncpy(rpeer->protocol, protocol, protolen)[protolen] = '\0';
  strncpy(rpeer->host, host, hostlen)[hostlen] = '\0';
  rpeer->port = port;
  return CFOK;
}

int cf_opt_str(char *str, size_t len, const char *text)
{
  if (strlen(text) >= len)
    return CFSTRINGOVERFLOW;
  strncpy(str, text, len);
  assert(str[len - 1] == '\0');
  return CFOK;
}

int cf_fmt_str(const char **textp, const char *str)
{
  *textp = str_edup(str);
  return CFOK;
}

int cf_cmp_str(const char *a, const char *b)
{
  return strcmp(a, b);
}

int cf_opt_str_nonempty(char *str, size_t len, const char *text)
{
  if (!text[0])
    return CFINVALID;
  return cf_opt_str(str, len, text);
}

int cf_fmt_str_nonempty(const char **textp, const char *str)
{
  if (!str[0])
    return CFINVALID;
  *textp = str_edup(str);
  return CFOK;
}

int cf_cmp_str_nonempty(const char *a, const char *b)
{
  return strcmp(a, b);
}

int cf_opt_int(int *intp, const char *text)
{
  const char *end = text;
  long value = strtol(text, (char**)&end, 10);
  if (end == text || *end)
    return CFINVALID;
  *intp = value;
  return CFOK;
}

int cf_fmt_int(const char **textp, const int *intp)
{
  char buf[22];
  sprintf(buf, "%d", *intp);
  *textp = str_edup(buf);
  return CFOK;
}

int cf_cmp_int(const int *a, const int *b)
{
  return *a < *b ? -1 : *a > *b ? 1 : 0;
}

int cf_opt_uint(unsigned int *uintp, const char *text)
{
  const char *end = text;
  unsigned long value = strtoul(text, (char**)&end, 10);
  if (end == text || *end)
    return CFINVALID;
  *uintp = value;
  return CFOK;
}

int cf_fmt_uint(const char **textp, const unsigned int *uintp)
{
  char buf[22];
  sprintf(buf, "%u", *uintp);
  *textp = str_edup(buf);
  return CFOK;
}

int cf_cmp_uint(const unsigned int *a, const unsigned int *b)
{
  return *a < *b ? -1 : *a > *b ? 1 : 0;
}

int cf_opt_int32_nonneg(int32_t *intp, const char *text)
{
  const char *end = text;
  long value = strtol(text, (char**)&end, 10);
  if (end == text || *end || value < 0 || value > 0x7fffffffL)
    return CFINVALID;
  *intp = value;
  return CFOK;
}

int cf_opt_int32_rs232baudrate(int32_t *intp, const char *text)
{
  const char *end = text;
  long value = strtol(text, (char**)&end, 10);
  if (end == text || *end || value < 0 || value > 0x7fffffffL)
    return CFINVALID;
  switch(value) {
  case 50: case 75: case 110: case 134: case 150: case 200: case 300:
  case 600: case 1200: case 1800: case 2400: case 4800: case 7200:
  case 9600: case 14400: case 28800: case 38400: case 57600: case 115200:
  case 230400:
    *intp = value;
    return CFOK;
    break;
  default:
    return CFINVALID;
  }
}

int cf_fmt_int32_rs232baudrate(const char **textp, const int32_t *intp)
{
  char buf[12];
  sprintf(buf, "%d", *intp);
  *textp = str_edup(buf);
  return CFOK;
}

int cf_cmp_int32_rs232baudrate(const int32_t *a, const int32_t *b)
{
  return *a < *b ? -1 : *a > *b ? 1 : 0;
}


static int cf_fmt_int32(const char **textp, const int32_t *intp)
{
  char buf[12];
  sprintf(buf, "%d", *intp);
  *textp = str_edup(buf);
  return CFOK;
}

int cf_cmp_int32(const int32_t *a, const int32_t *b)
{
  return *a < *b ? -1 : *a > *b ? 1 : 0;
}

static int cf_fmt_uint32(const char **textp, const uint32_t *uintp)
{
  char buf[12];
  sprintf(buf, "%u", *uintp);
  *textp = str_edup(buf);
  return CFOK;
}

int cf_cmp_uint32(const uint32_t *a, const uint32_t *b)
{
  return *a < *b ? -1 : *a > *b ? 1 : 0;
}

int cf_fmt_int32_nonneg(const char **textp, const int32_t *intp)
{
  if (*intp < 0)
    return CFINVALID;
  return cf_fmt_int32(textp, intp);
}

int cf_cmp_int32_nonneg(const int32_t *a, const int32_t *b)
{
  return cf_cmp_int32(a, b);
}

int cf_opt_uint32_nonzero(uint32_t *intp, const char *text)
{
  const char *end = text;
  unsigned long value = strtoul(text, (char**)&end, 10);
  if (end == text || *end || value < 1 || value > 0xffffffffL)
    return CFINVALID;
  *intp = value;
  return CFOK;
}

int cf_fmt_uint32_nonzero(const char **textp, const uint32_t *uintp)
{
  if (*uintp == 0)
    return CFINVALID;
  return cf_fmt_uint32(textp, uintp);
}

int cf_cmp_uint32_nonzero(const uint32_t *a, const uint32_t *b)
{
  return cf_cmp_uint32(a, b);
}

int cf_opt_uint32_time_interval(uint32_t *intp, const char *text)
{
  const char *t = text;
  uint32_t seconds = 0;
  while (*t) {
    const char *p = t;
    while (isdigit(*p))
      ++p;
    if (*p == '.' && (p != t || isdigit(p[1])))
      for (++p; isdigit(*p); ++p)
	;
    if (p == t)
      return CFINVALID;
    const char *end = t;
    double d = strtod(t, (char**)&end);
    if (end != p)
      return CFINVALID;
    switch (*p) {
      case 's': case 'S': ++p; break;
      case 'm': case 'M': d *= 60; ++p; break;
      case 'h': case 'H': d *= 60 * 60; ++p; break;
      case 'd': case 'D': d *= 60 * 60 * 24; ++p; break;
      case 'w': case 'W': d *= 60 * 60 * 24 * 7; ++p; break;
      case '\0': break;
      default: return CFINVALID;
    }
    if (d != floor(d))
      return CFINVALID;
    seconds += d;
    t = p;
  }
  *intp = seconds;
  return CFOK;
}

int cf_fmt_uint32_time_interval(const char **textp, const uint32_t *uintp)
{
  strbuf b = strbuf_alloca(60);
  uint32_t seconds = *uintp;
  if (seconds >= 7 * 24 * 60 * 60) {
    unsigned weeks = seconds / (7 * 24 * 60 * 60);
    seconds = seconds - weeks * (7 * 24 * 60 * 60);
    strbuf_sprintf(b, "%uw", weeks);
  }
  if (seconds >= 24 * 60 * 60) {
    unsigned days = seconds / (24 * 60 * 60);
    seconds = seconds - days * (24 * 60 * 60);
    strbuf_sprintf(b, "%ud", days);
  }
  if (seconds >= 60 * 60) {
    unsigned hours = seconds / (60 * 60);
    seconds = seconds - hours * (60 * 60);
    strbuf_sprintf(b, "%uh", hours);
  }
  if (seconds >= 60) {
    unsigned minutes = seconds / 60;
    seconds = seconds - minutes * 60;
    strbuf_sprintf(b, "%um", minutes);
  }
  if (seconds)
    strbuf_sprintf(b, "%us", seconds);
  if (strbuf_overrun(b))
    return CFINVALID;
  *textp = str_edup(strbuf_str(b));
  return CFOK;
}

int cf_cmp_uint32_time_interval(const uint32_t *a, const uint32_t *b)
{
  return cf_cmp_uint32(a, b);
}

int cf_opt_uint64_scaled(uint64_t *intp, const char *text)
{
  uint64_t result;
  const char *end;
  if (!str_to_uint64_scaled(text, 10, &result, &end) || *end)
    return CFINVALID;
  *intp = result;
  return CFOK;
}

int cf_fmt_uint64_scaled(const char **textp, const uint64_t *uintp)
{
  char buf[25];
  int n = uint64_scaled_to_str(buf, sizeof buf, *uintp);
  assert(n != 0);
  *textp = str_edup(buf);
  return CFOK;
}

int cf_cmp_uint64_scaled(const uint64_t *a, const uint64_t *b)
{
  return *a < *b ? -1 : *a > *b ? 1 : 0;
}

int cf_opt_ushort(unsigned short *ushortp, const char *text)
{
  const char *end = text;
  unsigned long value = strtoul(text, (char**)&end, 10);
  if (end == text || *end || value > 0xffffL)
    return CFINVALID;
  *ushortp = value;
  return CFOK;
}

int cf_fmt_ushort(const char **textp, const unsigned short *ushortp)
{
  char buf[12];
  sprintf(buf, "%u", (unsigned int) *ushortp);
  *textp = str_edup(buf);
  return CFOK;
}

int cf_cmp_ushort(const unsigned short *a, const unsigned short *b)
{
  return *a < *b ? -1 : *a > *b ? 1 : 0;
}

int cf_opt_ushort_nonzero(unsigned short *ushortp, const char *text)
{
  unsigned short value;
  if (cf_opt_ushort(&value, text) != CFOK || value == 0)
    return CFINVALID;
  *ushortp = value;
  return CFOK;
}

int cf_fmt_ushort_nonzero(const char **textp, const unsigned short *ushortp)
{
  if (*ushortp == 0)
    return CFINVALID;
  return cf_fmt_ushort(textp, ushortp);
}

int cf_cmp_short(const short *a, const short *b)
{
  return *a < *b ? -1 : *a > *b ? 1 : 0;
}

int cf_cmp_ushort_nonzero(const unsigned short *a, const unsigned short *b)
{
  return cf_cmp_ushort(a, b);
}

int vld_argv(const struct cf_om_node *parent, struct config_argv *array, int result)
{
  unsigned short last_key = 0;
  int i;
  if (array->ac) {
    unsigned short last_key = array->av[0].key;
    for (i = 1; i < array->ac; ++i) {
      unsigned short key = array->av[i].key;
      if (last_key > key) {
	cf_warn_node(parent, NULL, "array is not sorted");
	return CFERROR;
      }
      last_key = key;
    }
  }
  for (i = 0; i < array->ac; ++i) {
    unsigned short key = array->av[i].key;
    assert(key >= 1);
    assert(key >= last_key);
    if (last_key == key) {
      char labelkey[12];
      sprintf(labelkey, "%u", last_key);
      cf_warn_duplicate_node(parent, labelkey);
      result |= CFDUPLICATE;
    }
    while (++last_key < key && last_key <= sizeof(array->av)) {
      char labelkey[12];
      sprintf(labelkey, "%u", last_key);
      cf_warn_missing_node(parent, labelkey);
      result |= CFINCOMPLETE;
    }
    last_key = key;
  }
  return result;
}

int cf_opt_in_addr(struct in_addr *addrp, const char *text)
{
  struct in_addr addr;
  if (!inet_aton(text, &addr))
    return CFINVALID;
  *addrp = addr;
  return CFOK;
}

int cf_fmt_in_addr(const char **textp, const struct in_addr *addrp)
{
  *textp = str_edup(inet_ntoa(*addrp));
  return CFOK;
}

int cf_cmp_in_addr(const struct in_addr *a, const struct in_addr *b)
{
  return memcmp(a, b, sizeof(struct in_addr));
}

int cf_opt_uint16(uint16_t *uintp, const char *text)
{
  uint16_t ui = 0;
  const char *p;
  for (p = text; isdigit(*p); ++p) {
      uint16_t oui = ui;
      ui = ui * 10 + *p - '0';
      if (ui / 10 != oui)
	break;
  }
  if (*p)
    return CFINVALID;
  *uintp = ui;
  return CFOK;
}

int cf_fmt_uint16(const char **textp, const uint16_t *uintp)
{
  char buf[12];
  sprintf(buf, "%u", (unsigned int) *uintp);
  *textp = str_edup(buf);
  return CFOK;
}

int cf_cmp_uint16(const uint16_t *a, const uint16_t *b)
{
  return *a < *b ? -1 : *a > *b ? 1 : 0;
}

int cf_opt_uint16_nonzero(uint16_t *uintp, const char *text)
{
  uint16_t ui;
  if (cf_opt_uint16(&ui, text) != CFOK || ui == 0)
    return CFINVALID;
  *uintp = ui;
  return CFOK;
}

int cf_fmt_uint16_nonzero(const char **textp, const uint16_t *uintp)
{
  if (*uintp == 0)
    return CFINVALID;
  return cf_fmt_uint16(textp, uintp);
}

int cf_cmp_uint16_nonzero(const uint16_t *a, const uint16_t *b)
{
  return cf_cmp_uint16(a, b);
}

int cf_opt_sid(sid_t *sidp, const char *text)
{
  if (strcasecmp(text, "broadcast")==0){
    *sidp = SID_BROADCAST;
    return CFOK;
  }
  if (!str_is_subscriber_id(text))
    return CFINVALID;
  int r = str_to_sid_t(sidp, text);
  assert(r != -1);
  return CFOK;
}

int cf_fmt_sid(const char **textp, const sid_t *sidp)
{
  *textp = str_edup(alloca_tohex_sid_t(*sidp));
  return CFOK;
}

int cf_cmp_sid(const sid_t *a, const sid_t *b)
{
  return memcmp(a->binary, b->binary, sizeof a->binary);
}

int cf_opt_rhizome_bk(rhizome_bk_t *bkp, const char *text)
{
  if (!rhizome_str_is_bundle_key(text))
    return CFINVALID;
  size_t n = fromhex(bkp->binary, text, RHIZOME_BUNDLE_KEY_BYTES);
  assert(n == RHIZOME_BUNDLE_KEY_BYTES);
  return CFOK;
}

int cf_fmt_rhizome_bk(const char **textp, const rhizome_bk_t *bkp)
{
  *textp = str_edup(alloca_tohex_rhizome_bk_t(*bkp));
  return CFOK;
}

int cf_cmp_rhizome_bk(const rhizome_bk_t *a, const rhizome_bk_t *b)
{
  return memcmp(a, b, sizeof a->binary);
}

int cf_opt_interface_type(short *typep, const char *text)
{
  if (strcasecmp(text, "ethernet") == 0) {
    *typep = OVERLAY_INTERFACE_ETHERNET;
    return CFOK;
  }
  if (strcasecmp(text, "wifi") == 0) {
    *typep = OVERLAY_INTERFACE_WIFI;
    return CFOK;
  }
  if (strcasecmp(text, "catear") == 0) {
    *typep = OVERLAY_INTERFACE_PACKETRADIO;
    return CFOK;
  }
  if (strcasecmp(text, "other") == 0) {
    *typep = OVERLAY_INTERFACE_UNKNOWN;
    return CFOK;
  }
  return CFINVALID;
}

int cf_fmt_interface_type(const char **textp, const short *typep)
{
  const char *t = NULL;
  switch (*typep) {
    case OVERLAY_INTERFACE_ETHERNET:	t = "ethernet"; break;
    case OVERLAY_INTERFACE_WIFI:	t = "wifi"; break;
    case OVERLAY_INTERFACE_PACKETRADIO: t = "catear"; break;
    case OVERLAY_INTERFACE_UNKNOWN:	t = "other"; break;
  }
  if (!t)
    return CFINVALID;
  *textp = str_edup(t);
  return CFOK;
}

int cf_cmp_interface_type(const short *a, const short *b)
{
  return *a < *b ? -1 : *a > *b ? 1 : 0;
}

int cf_opt_socket_type(short *typep, const char *text)
{
  if (strcasecmp(text, "dgram") == 0) {
    *typep = SOCK_DGRAM;
    return CFOK;
  }
  if (strcasecmp(text, "stream") == 0) {
    *typep = SOCK_STREAM;
    return CFOK;
  }
  if (strcasecmp(text, "file") == 0) {
    *typep = SOCK_FILE;
    return CFOK;
  }
  return CFINVALID;
}

int cf_fmt_socket_type(const char **textp, const short *typep)
{
  const char *t = NULL;
  switch (*typep) {
    case SOCK_DGRAM:  t = "dgram"; break;
    case SOCK_STREAM: t = "stream"; break;
    case SOCK_FILE:   t = "file"; break;
  }
  if (!t)
    return CFINVALID;
  *textp = str_edup(t);
  return CFOK;
}

int cf_cmp_socket_type(const short *a, const short *b)
{
  return cf_cmp_short(a, b);
}

int cf_opt_encapsulation(short *encapp, const char *text)
{
  if (strcasecmp(text, "overlay") == 0) {
    *encapp = ENCAP_OVERLAY;
    return CFOK;
  }
  if (strcasecmp(text, "single") == 0) {
    *encapp = ENCAP_SINGLE;
    return CFOK;
  }
  return CFINVALID;
}

int cf_fmt_encapsulation(const char **textp, const short *encapp)
{
  const char *t = NULL;
  switch (*encapp) {
    case ENCAP_OVERLAY: t = "overlay"; break;
    case ENCAP_SINGLE:  t = "single"; break;
  }
  if (!t)
    return CFINVALID;
  *textp = str_edup(t);
  return CFOK;
}

int cf_cmp_encapsulation(const short *a, const short *b)
{
  return cf_cmp_short(a, b);
}

int cf_opt_pattern_list(struct pattern_list *listp, const char *text)
{
  struct pattern_list list;
  memset(&list, 0, sizeof list);
  const char *word = NULL;
  const char *p;
  for (p = text; ; ++p) {
    if (!*p || isspace(*p) || *p == ',') {
      if (word) {
	size_t len = p - word;
	if (list.patc >= NELS(list.patv) || len >= sizeof(list.patv[list.patc]))
	  return CFARRAYOVERFLOW;
	strncpy(list.patv[list.patc++], word, len)[len] = '\0';
	word = NULL;
      }
      if (!*p)
	break;
    } else if (!word)
      word = p;
  }
  assert(word == NULL);
  if (list.patc == 0)
    return CFEMPTY;
  *listp = list;
  return CFOK;
}

int cf_fmt_pattern_list(const char **textp, const struct pattern_list *listp)
{
  if (listp->patc == 0)
    return CFEMPTY;
  char buf[sizeof listp->patv];
  char *bufp = buf;
  unsigned i;
  for (i = 0; i < listp->patc; ++i) {
    if (bufp != buf)
      *bufp++ = ',';
    const char *patvp = listp->patv[i];
    const char *npatvp = listp->patv[i + 1];
    while (bufp < &buf[sizeof buf - 1] && patvp < npatvp && (*bufp = *patvp))
      ++bufp, ++patvp;
    if (patvp >= npatvp)
      return CFINVALID;
    assert(bufp < &buf[sizeof buf - 1]);
  }
  *bufp = '\0';
  *textp = str_edup(buf);
  return CFOK;
}

int cf_cmp_pattern_list(const struct pattern_list *a, const struct pattern_list *b)
{
  unsigned i;
  for (i = 0; i < a->patc && i < b->patc; ++i) {
    int c = strcmp(a->patv[i], b->patv[i]);
    if (c)
      return c;
  }
  return (a->patc < b->patc) ? -1 : (a->patc > b->patc) ? 1 : 0;
}

/* Config parse function.  Implements the original form of the 'interfaces' config option.  Parses a
 * single text string of the form:
 *
 *   ( "+" | "-" ) [ interfacename ] [ "=" type ] [ ":" port [ ":" speed ] ]
 *
 * where:
 *
 *   "+" means include the interface
 *   "-" means exclude the interface
 *
 *   The original implementation applied include/exclude matching in the order that the list was
 *   given, but the new implementation applies all exclusions before apply inclusions.  This should
 *   not be a problem, as there were no known uses that depended on testing an inclusion before an
 *   exclusion.
 *
 *   An empty 'interfacename' matches all interfaces.  So a "+" by itself includes all interfaces,
 *   and a '-' by itself excludes all interfaces.  These two rules are applied after all other
 *   interface inclusions/exclusions are tested, otherwise "-" would overrule all other interfaces.
 *
 *   The optional 'type' tells DNA how to handle the interface in terms of bandwidth:distance
 *   relationship for calculating tick times etc.
 *
 *   The optional 'port' is the port number to bind all interfaces, instead of the default.
 *
 *   The optional 'speed' is the nominal bits/second bandwidth of the interface, instead of the
 *   default.  It is expressed as a positive integer with an optional scaling suffix, eg, "150k",
 *   "1K", "900M".
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static int cf_opt_network_interface_legacy(struct config_network_interface *nifp, const char *text)
{
  //DEBUGF("%s text=%s", __FUNCTION__, alloca_str_toprint(text));
  struct config_network_interface nif;
  (&nif);
  cf_dfl_config_network_interface(&nif);
  if (text[0] != '+' && text[0] != '-')
    return CFINVALID; // "Sign must be + or -"
  nif.exclude = (text[0] == '-');
  const char *const endtext = text + strlen(text);
  const char *name = text + 1;
  const char *p = strpbrk(name, "=:");
  if (!p)
    p = endtext;
  size_t len = p - name;
  if (name[0] == '>') {
    if (len - 1 >= sizeof(nif.file))
      return CFSTRINGOVERFLOW;
    strncpy(nif.file, &name[1], len - 1)[len - 1] = '\0';
    nif.match.patc = 0;
    nif.socket_type = SOCK_FILE;
  } else {
    int addstar = strnchr(name, len, '*') == NULL ? 1 : 0;
    if (len + addstar >= sizeof(nif.match.patv[0]))
      return CFSTRINGOVERFLOW;
    strncpy(nif.match.patv[0], name, len)[len + addstar] = '\0';
    if (addstar)
      nif.match.patv[0][len] = '*';
    nif.match.patc = 1;
    nif.socket_type = SOCK_DGRAM;
  }
  if (*p == '=') {
    const char *const type = p + 1;
    p = strchr(type, ':');
    if (!p)
      p = endtext;
    len = p - type;
    if (len) {
      char buf[len + 1];
      strncpy(buf, type, len)[len] = '\0';
      int result = cf_opt_interface_type(&nif.type, buf);
      switch (result) {
      case CFERROR: return CFERROR;
      case CFOK: break;
      default: return result; // "Invalid interface type"
      }
    }
  }
  if (*p == ':') {
    const char *const port = p + 1;
    p = strchr(port, ':');
    if (!p)
      p = endtext;
    len = p - port;
    if (len) {
      char buf[len + 1];
      strncpy(buf, port, len)[len] = '\0';
      int result = cf_opt_uint16_nonzero(&nif.port, buf);
      switch (result) {
      case CFERROR: return CFERROR;
      case CFOK: break;
      default: return result; // "Invalid interface port number"
      }
    }
  }
  if (*p == ':') {
    p = endtext;
  }
  if (*p)
    return CFINVALID; // "Extra junk at end of interface specification"
  *nifp = nif;
  return CFOK;
}

int cf_opt_network_interface(struct config_network_interface *nifp, const struct cf_om_node *node)
{
  if (!node->text)
    return cf_opt_config_network_interface(nifp, node);
  if (node->nodc) {
    cf_warn_incompatible_children(node);
    return CFINCOMPATIBLE;
  }
  return cf_opt_network_interface_legacy(nifp, node->text);
}

int cf_fmt_network_interface(struct cf_om_node **parentp, const struct config_network_interface *nifp)
{
  return cf_fmt_config_network_interface(parentp, nifp);
}

int cf_cmp_network_interface(const struct config_network_interface *a, const struct config_network_interface *b)
{
  return cf_cmp_config_network_interface(a, b);
}

int vld_network_interface(const struct cf_om_node *parent, struct config_network_interface *nifp, int result)
{
  if (nifp->match.patc != 0 && nifp->file[0]) {
    int nodei_match = cf_om_get_child(parent, "match", NULL);
    int nodei_file = cf_om_get_child(parent, "file", NULL);
    assert(nodei_match != -1);
    assert(nodei_file != -1);
    cf_warn_incompatible(parent->nodv[nodei_match], parent->nodv[nodei_file]);
    return result | CFSUB(CFINCOMPATIBLE);
  }
  if (nifp->socket_type == SOCK_UNSPECIFIED) {
    if (nifp->match.patc != 0)
      nifp->socket_type = SOCK_DGRAM;
    else if (nifp->file[0])
      nifp->socket_type = SOCK_FILE;
    else {
      cf_warn_missing_node(parent, "match");
      return result | CFINCOMPLETE;
    }
  } else {
    if (nifp->socket_type == SOCK_DGRAM && nifp->file[0]){
      int nodei_socket_type = cf_om_get_child(parent, "socket_type", NULL);
      int nodei_file = cf_om_get_child(parent, "file", NULL);
      assert(nodei_socket_type != -1);
      assert(nodei_file != -1);
      cf_warn_incompatible(parent->nodv[nodei_socket_type], parent->nodv[nodei_file]);
      return result | CFSUB(CFINCOMPATIBLE);
    }
    if (nifp->socket_type != SOCK_DGRAM && !nifp->file[0]){
      cf_warn_missing_node(parent, "file");
      return result | CFSUB(CFINCOMPATIBLE);
    }
  }
  return result;
}

/* Config parse function.  Implements the original form of the 'interfaces' config option.  Parses a
 * comma-separated list of interface rules (see cf_opt_network_interface_legacy() for the format of
 * each rule), then parses the regular config array-of-struct style interface option settings so
 * that both forms are supported.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int cf_opt_interface_list(struct config_interface_list *listp, const struct cf_om_node *node)
{
  if (!node->text)
    return cf_opt_config_interface_list(listp, node);
  if (node->nodc) {
    cf_warn_incompatible_children(node);
    return CFINCOMPATIBLE;
  }
  const char *p;
  const char *arg = NULL;
  unsigned n = listp->ac;
  int result = CFOK;
  for (p = node->text; n < NELS(listp->av); ++p) {
    if (*p == '\0' || *p == ',' || isspace(*p)) {
      if (arg) {
	int len = p - arg;
	if (len > 80) {
	  result |= CFSTRINGOVERFLOW;
	  goto bye;
	}
	char buf[len + 1];
	strncpy(buf, arg, len)[len] = '\0';
	int ret = cf_opt_network_interface_legacy(&listp->av[n].value, buf);
	switch (ret) {
	case CFERROR: return CFERROR;
	case CFOK:
	  listp->av[n].key = n;
	  ++n;
	  break;
	default: {
	    strbuf b = strbuf_alloca(180);
	    strbuf_cf_flag_reason(b, ret);
	    cf_warn_node(node, NULL, "invalid interface rule %s -- %s", alloca_str_toprint(buf), strbuf_str(b)); \
	    result |= CFSUB(ret);
	    break;
	  }
	}
	arg = NULL;
      }
      if (!*p)
	break;
    } else if (!arg)
      arg = p;
  }
  if (*p) {
    result |= CFARRAYOVERFLOW;
    goto bye;
  }
  assert(n <= NELS(listp->av));
  listp->ac = n;
bye:
  if (listp->ac == 0)
    result |= CFEMPTY;
  return result;
}

int cf_fmt_interface_list(struct cf_om_node **parentp, const struct config_interface_list *listp)
{
  return cf_fmt_config_interface_list(parentp, listp);
}

int cf_cmp_interface_list(const struct config_interface_list *a, const struct config_interface_list *b)
{
  return cf_cmp_config_interface_list(a, b);
}

int cf_opt_log_level(int *levelp, const char *text)
{
  int level = string_to_log_level(text);
  if (level == LOG_LEVEL_INVALID)
    return CFINVALID;
  *levelp = level;
  return CFOK;
}

int cf_fmt_log_level(const char **textp, const int *levelp)
{
  const char *t = log_level_as_string(*levelp);
  if (!t)
    return CFINVALID;
  *textp = str_edup(t);
  return CFOK;
}

int cf_cmp_log_level(const int *a, const int *b)
{
  return cf_cmp_int(a, b);
}
