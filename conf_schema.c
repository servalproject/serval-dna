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
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <stdarg.h>
#include <assert.h>
#include <arpa/inet.h>

#include "log.h"
#include "str.h"
#include "strbuf.h"
#include "strbuf_helpers.h"
#include "config.h"

int cf_opt_boolean(int *booleanp, const char *text)
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

int cf_opt_debugflags(debugflags_t *flagsp, const struct cf_om_node *node)
{
  //DEBUGF("%s", __FUNCTION__);
  //cf_dump_node(node, 1);
  debugflags_t setmask = 0;
  debugflags_t clearmask = 0;
  int setall = 0;
  int clearall = 0;
  int result = CFEMPTY;
  int i;
  for (i = 0; i < node->nodc; ++i) {
    const struct cf_om_node *child = node->nodv[i];
    cf_warn_unsupported_children(child);
    debugflags_t mask = debugFlagMask(child->key);
    int flag = -1;
    if (!mask)
      cf_warn_unsupported_node(child);
    else if (child->text) {
      int ret = cf_opt_boolean(&flag, child->text);
      switch (ret) {
      case CFERROR: return CFERROR;
      case CFOK:
	result &= ~CFEMPTY;
	if (mask == ~0) {
	  if (flag)
	    setall = 1;
	  else
	    clearall = 1;
	} else {
	  if (flag)
	    setmask |= mask;
	  else
	    clearmask |= mask;
	}
	break;
      default:
	cf_warn_node_value(child, ret);
	result |= ret;
	break;
      }
    }
  }
  if (setall)
    *flagsp = ~0;
  else if (clearall)
    *flagsp = 0;
  *flagsp &= ~clearmask;
  *flagsp |= setmask;
  return result;
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

int cf_opt_rhizome_peer(struct config_rhizomepeer *rpeer, const struct cf_om_node *node)
{
  if (!node->text)
    return cf_opt_config_rhizomepeer(rpeer, node);
  cf_warn_spurious_children(node);
  const char *protocol;
  size_t protolen;
  const char *auth;
  if (str_is_uri(node->text)) {
    const char *hier;
    if (!(   str_uri_scheme(node->text, &protocol, &protolen)
	  && str_uri_hierarchical(node->text, &hier, NULL)
	  && str_uri_hierarchical_authority(hier, &auth, NULL))
    )
      return CFINVALID;
  } else {
    auth = node->text;
    protocol = "http";
    protolen = strlen(protocol);
  }
  const char *host;
  size_t hostlen;
  unsigned short port = 4110;
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

int cf_opt_str_nonempty(char *str, size_t len, const char *text)
{
  if (!text[0])
    return CFINVALID;
  return cf_opt_str(str, len, text);
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

int cf_opt_uint32_nonzero(uint32_t *intp, const char *text)
{
  const char *end = text;
  long value = strtoul(text, (char**)&end, 10);
  if (end == text || *end || value < 1 || value > 0xffffffffL)
    return CFINVALID;
  *intp = value;
  return CFOK;
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

int cf_opt_ushort_nonzero(unsigned short *ushortp, const char *text)
{
  uint32_t ui;
  if (cf_opt_uint32_nonzero(&ui, text) != CFOK || ui > 0xffff)
    return CFINVALID;
  *ushortp = ui;
  return CFOK;
}

int cmp_short(const short *a, const short *b)
{
  return *a < *b ? -1 : *a > *b ? 1 : 0;
}

int cmp_ushort(const unsigned short *a, const unsigned short *b)
{
  return *a < *b ? -1 : *a > *b ? 1 : 0;
}

int cmp_sid(const sid_t *a, const sid_t *b)
{
  return memcmp(a->binary, b->binary, sizeof a->binary);
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

int cf_opt_port(unsigned short *portp, const char *text)
{
  unsigned short port = 0;
  const char *p;
  for (p = text; isdigit(*p); ++p) {
      unsigned oport = port;
      port = port * 10 + *p - '0';
      if (port / 10 != oport)
	break;
  }
  if (*p || port == 0)
    return CFINVALID;
  *portp = port;
  return CFOK;
}

int cf_opt_sid(sid_t *sidp, const char *text)
{
  sid_t sid;
  if (!str_is_subscriber_id(text))
    return CFINVALID;
  size_t n = fromhex(sidp->binary, text, SID_SIZE);
  assert(n == SID_SIZE);
  return CFOK;
}

int cf_opt_rhizome_bk(rhizome_bk_t *bkp, const char *text)
{
  rhizome_bk_t sid;
  if (!rhizome_str_is_bundle_key(text))
    return CFINVALID;
  size_t n = fromhex(bkp->binary, text, RHIZOME_BUNDLE_KEY_BYTES);
  assert(n == RHIZOME_BUNDLE_KEY_BYTES);
  return CFOK;
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
  *listp = list;
  return CFOK;
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
int cf_opt_network_interface(struct config_network_interface *nifp, const char *text)
{
  //DEBUGF("%s text=%s", __FUNCTION__, alloca_str_toprint(text));
  struct config_network_interface nif;
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
  int star = (len == 0 || (name[0] != '>' && name[len - 1] != '*')) ? 1 : 0;
  if (len + star >= sizeof(nif.match.patv[0]))
    return CFSTRINGOVERFLOW;
  strncpy(nif.match.patv[0], name, len)[len + star] = '\0';
  if (star)
    nif.match.patv[0][len] = '*';
  nif.match.patc = 1;
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
      int result = cf_opt_port(&nif.port, buf);
      switch (result) {
      case CFERROR: return CFERROR;
      case CFOK: break;
      default: return result; // "Invalid interface port number"
      }
    }
  }
  if (*p == ':') {
    const char *const speed = p + 1;
    p = endtext;
    len = p - speed;
    if (len) {
      char buf[len + 1];
      strncpy(buf, speed, len)[len] = '\0';
      int result = cf_opt_uint64_scaled(&nif.speed, buf);
      switch (result) {
      case CFERROR: return CFERROR;
      case CFOK: break;
      default: return result; // "Invalid interface speed"
      }
      if (nif.speed < 1)
	return CFINVALID; // "Interfaces must be capable of at least 1 bit per second"
    }
  }
  if (*p)
    return CFINVALID; // "Extra junk at end of interface specification"
  *nifp = nif;
  return CFOK;
}

/* Config parse function.  Implements the original form of the 'interfaces' config option.  Parses a
 * comma-separated list of interface rules (see cf_opt_network_interface() for the format of each
 * rule), then parses the regular config array-of-struct style interface option settings so that
 * both forms are supported.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int cf_opt_interface_list(struct config_interface_list *listp, const struct cf_om_node *node)
{
  int result = cf_opt_config_interface_list(listp, node);
  if (result == CFERROR)
    return CFERROR;
  if (node->text) {
    const char *p;
    const char *arg = NULL;
    unsigned n = listp->ac;
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
	  int ret = cf_opt_network_interface(&listp->av[n].value, buf);
	  switch (ret) {
	  case CFERROR: return CFERROR;
	  case CFOK:
	    len = snprintf(listp->av[n].key, sizeof listp->av[n].key - 1, "%u", n);
	    listp->av[n].key[len] = '\0';
	    ++n;
	    break;
	  default:
	    cf_warn_node(node, NULL, "invalid interface rule %s", alloca_str_toprint(buf)); \
	    result |= CFSUB(ret);
	    break;
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
  }
bye:
  if (listp->ac == 0)
    result |= CFEMPTY;
  else
    result &= ~CFEMPTY;
  return result;
}
