#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>

#include "str.h"
#include "strbuf_helpers.h"

#define NELS(a) (sizeof (a) / sizeof *(a))
#define DEBUGF(F,...) fprintf(stderr, "DEBUG: " F "\n", ##__VA_ARGS__)
#define WARNF(F,...) fprintf(stderr, "WARN:  " F "\n", ##__VA_ARGS__)
#define WHYF(F,...) fprintf(stderr, "ERROR: " F "\n", ##__VA_ARGS__)
#define WHYF_perror(F,...) fprintf(stderr, "ERROR: " F ": %s [errno=%d]\n", ##__VA_ARGS__, strerror(errno), errno)
#define alloca_str(s) ((s) ? alloca_str_toprint(s) : "NULL")

#include "config.h"

struct config_node {
    const char *source; // = parse_config() 'source' arg
    unsigned int line_number;
    const char *fullkey; // malloc()
    const char *key; // points inside fullkey, do not free()
    const char *text; // malloc()
    size_t nodc;
    struct config_node *nodv[10]; // malloc()
};

const char *find_keyend(const char *const key, const char *const fullkeyend)
{
  const char *s = key;
  if (s < fullkeyend && (isalpha(*s) || *s == '_'))
    ++s;
  while (s < fullkeyend && (isalnum(*s) || *s == '_'))
    ++s;
  if (s == key || (s < fullkeyend && *s != '.'))
    return NULL;
  return s;
}

void *emalloc(size_t len)
{
  char *new = malloc(len + 1);
  if (!new) {
    WHYF_perror("malloc(%lu)", (long)len);
    return NULL;
  }
  return new;
}

char *strn_emalloc(const char *str, size_t len)
{
  char *new = emalloc(len + 1);
  if (new) {
    strncpy(new, str, len);
    new[len] = '\0';
  }
  return new;
}

char *str_emalloc(const char *str)
{
  return strn_emalloc(str, strlen(str));
}

int make_child(struct config_node **const parentp, const char *const fullkey, const char *const key, const char *const keyend)
{
  size_t keylen = keyend - key;
  //DEBUGF("%s key=%s", __FUNCTION__, alloca_toprint(-1, key, keylen));
  int i = 0;
  struct config_node *child;
  if ((*parentp)->nodc) {
    // Binary search for matching child.
    int m = 0;
    int n = (*parentp)->nodc - 1;
    int c;
    do {
      i = (m + n) / 2;
      child = (*parentp)->nodv[i];
      c = strncmp(key, child->key, keylen);
      if (c == 0 && child->key[keylen])
	c = -1;
      //DEBUGF("   m=%d n=%d i=%d child->key=%s c=%d", m, n, i, alloca_str(child->key), c);
      if (c == 0) {
	//DEBUGF("   found i=%d", i);
	return i;
      }
      if (c > 0)
	m = ++i;
      else
	n = i - 1;
    } while (m <= n);
  }
  // At this point, i is the index where a new child should be inserted.
  assert(i >= 0);
  assert(i <= (*parentp)->nodc);
  child = emalloc(sizeof *child);
  if (child == NULL)
    return -1;
  memset(child, 0, sizeof *child);
  ++(*parentp)->nodc;
  if ((*parentp)->nodc > NELS((*parentp)->nodv))
    *parentp = realloc(*parentp, sizeof(**parentp) + sizeof((*parentp)->nodv[0]) * ((*parentp)->nodc - NELS((*parentp)->nodv)));
  int j;
  for (j = (*parentp)->nodc - 1; j > i; --j)
    (*parentp)->nodv[j] = (*parentp)->nodv[j-1];
  (*parentp)->nodv[i] = child;
  if (!(child->fullkey = strn_emalloc(fullkey, keyend - fullkey))) {
    free(child);
    return -1;
  }
  child->key = child->fullkey + (key - fullkey);
  //DEBUGF("   insert i=%d", i);
  return i;
}

void free_config_node(struct config_node *node)
{
  while (node->nodc)
    free_config_node(node->nodv[--node->nodc]);
  if (node->fullkey) {
    free((char *)node->fullkey);
    node->fullkey = node->key = NULL;
  }
  if (node->text) {
    free((char *)node->text);
    node->text = NULL;
  }
  free(node);
}

struct config_node *parse_config(const char *source, const char *buf, size_t len)
{
  struct config_node *root = emalloc(sizeof(struct config_node));
  if (root == NULL)
    return NULL;
  memset(root, 0, sizeof *root);
  const char *end = buf + len;
  const char *line = buf;
  const char *nextline;
  unsigned lineno = 1;
  for (lineno = 1; line < end; line = nextline, ++lineno) {
    const char *lend = line;
    while (lend < end && *lend != '\n')
      ++lend;
    nextline = lend + 1;
    if (lend > line && lend[-1] == '\r')
      --lend;
    //DEBUGF("lineno=%u %s", lineno, alloca_toprint(-1, line, lend - line));
    const char *p;
    for (p = line; p < lend && isspace(*p); ++p)
      ;
    if (p == lend)
      continue; // skip empty and blank lines
    for (p = line; p < lend && *p != '='; ++p)
      ;
    if (p == line || p == lend) {
      WARNF("%s:%u: malformed configuration line -- ignored", source, lineno);
      continue;
    }
    struct config_node **nodep = &root;
    const char *fullkey = line;
    const char *fullkeyend = p;
    const char *key = fullkey;
    const char *keyend = NULL;
    int nodi = -1;
    while (key <= fullkeyend && (keyend = find_keyend(key, fullkeyend)) && (nodi = make_child(nodep, fullkey, key, keyend)) != -1) {
      key = keyend + 1;
      nodep = &(*nodep)->nodv[nodi];
    }
    if (keyend == NULL) {
      WARNF("%s:%u: malformed configuration option %s -- ignored",
	  source, lineno, alloca_toprint(-1, fullkey, fullkeyend - fullkey)
	);
      continue;
    }
    if (nodi == -1)
      goto error; // out of memory
    struct config_node *node = *nodep;
    if (node->text) {
      WARNF("%s:%u: duplicate configuration option %s -- ignored (original is at %s:%u)",
	  source, lineno, alloca_toprint(-1, fullkey, fullkeyend - fullkey),
	  node->source, node->line_number
	);
      continue;
    }
    ++p;
    if (!(node->text = strn_emalloc(p, lend - p)))
      break; // out of memory
    node->source = source;
    node->line_number = lineno;
  }
  return root;
error:
  free_config_node(root);
  return NULL;
}

void dump_config_node(const struct config_node *node, int indent)
{
  if (node == NULL)
    DEBUGF("%*sNULL", indent * 3, "");
  else {
    DEBUGF("%*s%s:%u fullkey=%s key=%s text=%s", indent * 3, "",
	node->source ? node->source : "NULL",
	node->line_number,
	alloca_str(node->fullkey),
	alloca_str(node->key),
	alloca_str(node->text)
      );
    int i;
    for (i = 0; i < node->nodc; ++i)
      dump_config_node(node->nodv[i], indent + 1);
  }
}

int get_child(const struct config_node *parent, const char *key)
{
  int i;
  for (i = 0; i < parent->nodc; ++i)
    if (strcmp(parent->nodv[i]->key, key) == 0)
      return i;
  return -1;
}

void missing_node(const struct config_node *parent, const char *key)
{
  WARNF("missing configuration option `%s.%s`", parent->fullkey, key);
}

void invalid_text(const struct config_node *node, const char *reason)
{
  WARNF("%s:%u: ignoring configuration option %s with invalid value %s%s%s",
      node->source, node->line_number,
      alloca_str(node->fullkey),
      alloca_str(node->text),
      reason && reason[0] ? " -- " : "", reason ? reason : ""
    );
}

void ignore_node(const struct config_node *node, const char *msg)
{
  if (node->source && node->line_number)
    WARNF("%s:%u: ignoring configuration option %s%s%s",
	node->source, node->line_number, alloca_str(node->fullkey),
	msg && msg[0] ? " -- " : "", msg ? msg : ""
      );
  else
    WARNF("ignoring configuration option %s%s%s",
	alloca_str(node->fullkey),
	msg && msg[0] ? " -- " : "", msg ? msg : ""
      );
}

void ignore_tree(const struct config_node *node, const char *msg);

void ignore_children(const struct config_node *parent, const char *msg)
{
  int i;
  for (i = 0; i < parent->nodc; ++i)
    ignore_tree(parent->nodv[i], msg);
}

void ignore_tree(const struct config_node *node, const char *msg)
{
  if (node->text)
    ignore_node(node, msg);
  ignore_children(node, msg);
}

void unsupported_node(const struct config_node *node)
{
  ignore_node(node, "not supported");
}

void list_overflow(const struct config_node *node)
{
  ignore_children(node, "list overflow");
}

void list_omit_element(const struct config_node *node)
{
  ignore_node(node, "omitted from list");
}

void spurious_children(const struct config_node *parent)
{
  ignore_children(parent, "spurious");
}

void unsupported_children(const struct config_node *parent)
{
  ignore_children(parent, "not supported");
}

void unsupported_tree(const struct config_node *node)
{
  ignore_tree(node, "not supported");
}

/* Return values for parsing functions */
#define CFERROR     (-1)
#define CFOK        0
#define CFOVERFLOW  1
#define CFMISSING   2
#define CFINVALID   3

// Generate parser function prototypes.
#define SECTION(__sect) \
    int opt_config_##__sect(struct config_##__sect *, const struct config_node *);
#define ATOM(__type, __name, __default, __parser, __flags, __comment) \
    int __parser(__type *, const struct config_node *);
#define STRING(__size, __name, __default, __parser, __flags, __comment) \
    int __parser(char *, size_t, const struct config_node *);
#define SUB(__sect, __name, __flags) \
    int opt_config_##__sect(struct config_##__sect *, const struct config_node *node);
#define SUBP(__sect, __name, __parser, __flags) \
    int __parser(struct config_##__sect *, const struct config_node *node);
#define SECTION_END
#define LIST(__sect, __type, __size, __parser, __comment) \
    int opt_config_##__sect(struct config_##__sect *, const struct config_node *); \
    int __parser(__type *, const struct config_node *);
#include "config_schema.h"
#undef SECTION
#undef ATOM
#undef STRING
#undef SUB
#undef SUBP
#undef SECTION_END
#undef LIST

int opt_boolean(int *booleanp, const struct config_node *node);
int opt_absolute_path(char *str, size_t len, const struct config_node *node);
int opt_debugflags(debugflags_t *flagsp, const struct config_node *node);
int opt_rhizome_peer(struct config_rhizomepeer *, const struct config_node *node);
int opt_str_nonempty(char *str, size_t len, const struct config_node *node);
int opt_port(unsigned short *portp, const struct config_node *node);
int opt_uint64_scaled(uint64_t *intp, const struct config_node *node);
int opt_sid(sid_t *sidp, const struct config_node *node);
int opt_interface_type(short *typep, const struct config_node *node);
int opt_pattern_list(struct pattern_list *listp, const struct config_node *node);
int opt_interface_list(struct config_interface_list *listp, const struct config_node *node);

int opt_boolean(int *booleanp, const struct config_node *node)
{
  unsupported_children(node);
  if (!node->text)
    return CFMISSING;
  if (!strcasecmp(node->text, "true") || !strcasecmp(node->text, "yes") || !strcasecmp(node->text, "on") || !strcasecmp(node->text, "1")) {
    *booleanp = 1;
    return CFOK;
  }
  else if (!strcasecmp(node->text, "false") || !strcasecmp(node->text, "no") || !strcasecmp(node->text, "off") || !strcasecmp(node->text, "0")) {
    *booleanp = 0;
    return CFOK;
  }
  invalid_text(node, "expecting true|yes|on|1|false|no|off|0");
  return CFINVALID;
}

int opt_absolute_path(char *str, size_t len, const struct config_node *node)
{
  //DEBUGF("%s", __FUNCTION__);
  //dump_config_node(node, 1);
  unsupported_children(node);
  if (!node->text)
    return CFMISSING;
  if (node->text[0] != '/') {
    invalid_text(node, "must start with '/'");
    return CFINVALID;
  }
  if (strlen(node->text) >= len) {
    invalid_text(node, "string overflow");
    return CFOVERFLOW;
  }
  strncpy(str, node->text, len);
  assert(str[len - 1] == '\0');
  return CFOK;
}

debugflags_t debugFlagMask(const char *flagname)
{
  if	  (!strcasecmp(flagname,"all"))			return ~0;
  else if (!strcasecmp(flagname,"interfaces"))		return 1 << 0;
  else if (!strcasecmp(flagname,"rx"))			return 1 << 1;
  else if (!strcasecmp(flagname,"tx"))			return 1 << 2;
  else if (!strcasecmp(flagname,"verbose"))		return 1 << 3;
  else if (!strcasecmp(flagname,"verbio"))		return 1 << 4;
  else if (!strcasecmp(flagname,"peers"))		return 1 << 5;
  else if (!strcasecmp(flagname,"dnaresponses"))	return 1 << 6;
  else if (!strcasecmp(flagname,"dnahelper"))		return 1 << 7;
  else if (!strcasecmp(flagname,"vomp"))		return 1 << 8;
  else if (!strcasecmp(flagname,"packetformats"))	return 1 << 9;
  else if (!strcasecmp(flagname,"packetconstruction"))	return 1 << 10;
  else if (!strcasecmp(flagname,"gateway"))		return 1 << 11;
  else if (!strcasecmp(flagname,"keyring"))		return 1 << 12;
  else if (!strcasecmp(flagname,"sockio"))		return 1 << 13;
  else if (!strcasecmp(flagname,"frames"))		return 1 << 14;
  else if (!strcasecmp(flagname,"abbreviations"))	return 1 << 15;
  else if (!strcasecmp(flagname,"routing"))		return 1 << 16;
  else if (!strcasecmp(flagname,"security"))		return 1 << 17;
  else if (!strcasecmp(flagname,"rhizome"))	        return 1 << 18;
  else if (!strcasecmp(flagname,"rhizometx"))		return 1 << 19;
  else if (!strcasecmp(flagname,"rhizomerx"))		return 1 << 20;
  else if (!strcasecmp(flagname,"rhizomeads"))		return 1 << 21;
  else if (!strcasecmp(flagname,"monitorroutes"))	return 1 << 22;
  else if (!strcasecmp(flagname,"queues"))		return 1 << 23;
  else if (!strcasecmp(flagname,"broadcasts"))		return 1 << 24;
  else if (!strcasecmp(flagname,"manifests"))		return 1 << 25;
  else if (!strcasecmp(flagname,"mdprequests"))		return 1 << 26;
  else if (!strcasecmp(flagname,"timing"))		return 1 << 27;
  return 0;
}

int opt_debugflags(debugflags_t *flagsp, const struct config_node *node)
{
  //DEBUGF("%s", __FUNCTION__);
  //dump_config_node(node, 1);
  if (node->text)
    unsupported_tree(node);
  debugflags_t setmask = 0;
  debugflags_t clearmask = 0;
  int setall = 0;
  int clearall = 0;
  int i;
  for (i = 0; i < node->nodc; ++i) {
    const struct config_node *child = node->nodv[i];
    debugflags_t mask = debugFlagMask(child->key);
    int flag = -1;
    if (!mask)
      unsupported_tree(child);
    else if (opt_boolean(&flag, child) != -1) {
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
    }
  }
  if (setall)
    *flagsp = ~0;
  else if (clearall)
    *flagsp = 0;
  *flagsp &= ~clearmask;
  *flagsp |= setmask;
  return CFOK;
}

int opt_protocol(char *str, size_t len, const struct config_node *node)
{
  //DEBUGF("%s", __FUNCTION__);
  //dump_config_node(node, 1);
  unsupported_children(node);
  if (!node->text)
    return CFMISSING;
  if (!str_is_uri_scheme(node->text)) {
    invalid_text(node, "contains invalid character");
    return CFINVALID;
  }
  if (strlen(node->text) >= len) {
    invalid_text(node, "string overflow");
    return CFOVERFLOW;
  }
  strncpy(str, node->text, len);
  assert(str[len - 1] == '\0');
  return CFOK;
}

int opt_rhizome_peer(struct config_rhizomepeer *rpeer, const struct config_node *node)
{
  if (!node->text) {
    dfl_config_rhizomepeer(rpeer);
    return opt_config_rhizomepeer(rpeer, node);
  }
  spurious_children(node);
  const char *protocol;
  size_t protolen;
  const char *auth;
  if (str_is_uri(node->text)) {
    const char *hier;
    if (!(   str_uri_scheme(node->text, &protocol, &protolen)
	  && str_uri_hierarchical(node->text, &hier, NULL)
	  && str_uri_hierarchical_authority(hier, &auth, NULL))
    )
      goto invalid;
  } else {
    auth = node->text;
    protocol = "http";
    protolen = strlen(protocol);
  }
  const char *host;
  size_t hostlen;
  unsigned short port = 4110;
  if (!str_uri_authority_hostname(auth, &host, &hostlen))
    goto invalid;
  str_uri_authority_port(auth, &port);
  if (protolen >= sizeof rpeer->protocol) {
    invalid_text(node, "protocol string overflow");
    return CFOVERFLOW;
  }
  if (hostlen >= sizeof rpeer->host) {
    invalid_text(node, "hostname string overflow");
    return CFOVERFLOW;
  }
  strncpy(rpeer->protocol, protocol, protolen)[protolen] = '\0';
  strncpy(rpeer->host, host, hostlen)[hostlen] = '\0';
  rpeer->port = port;
  return CFOK;
invalid:
  invalid_text(node, "malformed URL");
  return CFINVALID;
}

int opt_str_nonempty(char *str, size_t len, const struct config_node *node)
{
  //DEBUGF("%s", __FUNCTION__);
  //dump_config_node(node, 1);
  unsupported_children(node);
  if (!node->text)
    return CFMISSING;
  if (!node->text[0]) {
    invalid_text(node, "empty string");
    return CFINVALID;
  }
  if (strlen(node->text) >= len) {
    invalid_text(node, "string overflow");
    return CFOVERFLOW;
  }
  strncpy(str, node->text, len);
  assert(str[len - 1] == '\0');
  return CFOK;
}

int opt_uint64_scaled(uint64_t *intp, const struct config_node *node)
{
  //DEBUGF("%s", __FUNCTION__);
  //dump_config_node(node, 1);
  unsupported_children(node);
  if (!node->text)
    return CFMISSING;
  uint64_t result;
  const char *end;
  if (!str_to_uint64_scaled(node->text, 10, &result, &end)) {
    invalid_text(node, "invalid scaled unsigned integer");
    return CFINVALID;
  }
  *intp = result;
  return CFOK;
}

int opt_port(unsigned short *portp, const struct config_node *node)
{
  //DEBUGF("%s", __FUNCTION__);
  //dump_config_node(node, 1);
  unsupported_children(node);
  if (!node->text)
    return CFMISSING;
  unsigned short port = 0;
  const char *p;
  for (p = node->text; isdigit(*p); ++p) {
      unsigned oport = port;
      port = port * 10 + *p - '0';
      if (port / 10 != oport)
	break;
  }
  if (*p || port == 0) {
    invalid_text(node, "invalid port number");
    return CFINVALID;
  }
  *portp = port;
  return CFOK;
}

int opt_sid(sid_t *sidp, const struct config_node *node)
{
  //DEBUGF("%s", __FUNCTION__);
  //dump_config_node(node, 1);
  unsupported_children(node);
  if (!node->text)
    return CFMISSING;
  sid_t sid;
  if (!str_is_subscriber_id(node->text)) {
    invalid_text(node, "invalid subscriber ID");
    return CFINVALID;
  }
  size_t n = fromhex(sidp->binary, node->text, SID_SIZE);
  assert(n == SID_SIZE);
  return CFOK;
}

int opt_interface_type(short *typep, const struct config_node *node)
{
  //DEBUGF("%s", __FUNCTION__);
  //dump_config_node(node, 1);
  unsupported_children(node);
  if (!node->text)
    return CFMISSING;
  if (strcasecmp(node->text, "ethernet") == 0) {
    *typep = OVERLAY_INTERFACE_ETHERNET;
    return CFOK;
  }
  if (strcasecmp(node->text, "wifi") == 0) {
    *typep = OVERLAY_INTERFACE_WIFI;
    return CFOK;
  }
  if (strcasecmp(node->text, "catear") == 0) {
    *typep = OVERLAY_INTERFACE_PACKETRADIO;
    return CFOK;
  }
  if (strcasecmp(node->text, "other") == 0) {
    *typep = OVERLAY_INTERFACE_UNKNOWN;
    return CFOK;
  }
  invalid_text(node, "invalid network interface type");
  return CFINVALID;
}

int opt_pattern_list(struct pattern_list *listp, const struct config_node *node)
{
  //DEBUGF("%s", __FUNCTION__);
  //dump_config_node(node, 1);
  unsupported_children(node);
  if (!node->text)
    return CFMISSING;
  struct pattern_list list;
  memset(&list, 0, sizeof list);
  const char *word = NULL;
  const char *p;
  for (p = node->text; ; ++p) {
    if (!*p || isspace(*p) || *p == ',') {
      if (word) {
	size_t len = p - word;
	if (list.patc >= NELS(list.patv) || len >= sizeof(list.patv[list.patc])) {
	  invalid_text(node, "string overflow");
	  return CFOVERFLOW;
	}
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

int opt_interface_list(struct config_interface_list *listp, const struct config_node *node)
{
  if (!node->text) {
    dfl_config_interface_list(listp);
    return opt_config_interface_list(listp, node);
  }
  spurious_children(node);
  invalid_text(node, "NOT IMPLEMENTED");
  return CFINVALID;
}

void missing_node(const struct config_node *parent, const char *key);
void unsupported_node(const struct config_node *node);
void unsupported_tree(const struct config_node *node);
void list_overflow(const struct config_node *node);
void list_omit_element(const struct config_node *node);

// Schema item flags.
#define __MANDATORY     1

// Schema flag symbols, to be used in the '__flags' macro arguments.
#define MANDATORY   |__MANDATORY

// Generate default functions, dfl_config_SECTION()
#define SECTION(__sect) \
    int dfl_config_##__sect(struct config_##__sect *s) {
#define ATOM(__type, __name, __default, __parser, __flags, __comment) \
        s->__name = (__default);
#define STRING(__size, __name, __default, __parser, __flags, __comment) \
        strncpy(s->__name, (__default), (__size))[(__size)] = '\0';
#define SUB(__sect, __name, __flags) \
        dfl_config_##__sect(&s->__name);
#define SUBP(__sect, __name, __parser, __flags) \
        dfl_config_##__sect(&s->__name);
#define SECTION_END \
        return 0; \
    }
#define LIST(__sect, __type, __size, __parser, __comment) \
    int dfl_config_##__sect(struct config_##__sect *s) { \
        s->listc = 0; \
        return 0; \
    }
#include "config_schema.h"
#undef SECTION
#undef ATOM
#undef STRING
#undef SUB
#undef SUBP
#undef SECTION_END
#undef LIST

// Generate parsing functions, opt_config_SECTION()
#define SECTION(__sect) \
    int opt_config_##__sect(struct config_##__sect *s, const struct config_node *node) { \
        if (node->text) unsupported_node(node); \
        int result = CFOK; \
        char used[node->nodc]; \
        memset(used, 0, node->nodc);
#define __ITEM(__name, __flags, __parseexpr) \
        { \
            int i = get_child(node, #__name); \
            if (i != -1) { \
                used[i] = 1; \
                const struct config_node *child = node->nodv[i]; \
                int ret = (__parseexpr); \
                switch (ret) { \
                case CFERROR: return CFERROR; \
                case CFMISSING: i = -1; break; \
                default: if (result < ret) result = ret; break; \
                } \
            } \
            if (i == -1 && ((0 __flags) & __MANDATORY)) { \
                missing_node(node, #__name); \
                if (result < CFMISSING) result = CFMISSING; \
            } \
        }
#define ATOM(__type, __name, __default, __parser, __flags, __comment) \
        __ITEM(__name, __flags, __parser(&s->__name, child))
#define STRING(__size, __name, __default, __parser, __flags, __comment) \
        __ITEM(__name, __flags, __parser(s->__name, (__size) + 1, child))
#define SUB(__sect, __name, __flags) \
        __ITEM(__name, __flags, opt_config_##__sect(&s->__name, child))
#define SUBP(__sect, __name, __parser, __flags) \
        __ITEM(__name, __flags, __parser(&s->__name, child))
#define SECTION_END \
        { \
            int i; \
            for (i = 0; i < node->nodc; ++i) \
                if (!used[i]) \
                    unsupported_tree(node->nodv[i]); \
        } \
        return result; \
    }
#define LIST(__sect, __type, __size, __parser, __comment) \
    int opt_config_##__sect(struct config_##__sect *s, const struct config_node *node) { \
        if (node->text) unsupported_node(node); \
        int result = CFOK; \
	int i; \
	for (i = 0; i < node->nodc && s->listc < NELS(s->listv); ++i) { \
	    const struct config_node *elt = node->nodv[i]; \
	    int ret = __parser(&s->listv[s->listc].value, elt); \
	    switch (ret) { \
	    case CFERROR: return CFERROR; \
	    case CFOK: \
		strncpy(s->listv[s->listc].label, elt->key, sizeof s->listv[s->listc].label - 1)\
		    [sizeof s->listv[s->listc].label - 1] = '\0'; \
		++s->listc; \
		break; \
	    default: \
		list_omit_element(elt); \
		break; \
	    } \
	} \
	for (; i < node->nodc; ++i) { \
	    if (result < CFOVERFLOW) result = CFOVERFLOW; \
	    list_overflow(node->nodv[i]); \
	} \
        return result; \
    }
#include "config_schema.h"
#undef SECTION
#undef ATOM
#undef STRING
#undef SUB
#undef SUBP
#undef SECTION_END
#undef LIST
int main(int argc, char **argv)
{
  int i;
  for (i = 1; i < argc; ++i) {
    int fd = open(argv[i], O_RDONLY);
    if (fd == -1) {
      perror("open");
      exit(1);
    }
    struct stat st;
    fstat(fd, &st);
    char *buf = malloc(st.st_size);
    if (!buf) {
      perror("malloc");
      exit(1);
    }
    if (read(fd, buf, st.st_size) != st.st_size) {
      perror("read");
      exit(1);
    }
    struct config_node *root = parse_config(argv[i], buf, st.st_size);
    close(fd);
    //dump_config_node(root, 0);
    struct config_main config;
    memset(&config, 0, sizeof config);
    dfl_config_main(&config);
    opt_config_main(&config, root);
    free_config_node(root);
    free(buf);
    DEBUGF("config.log.file = %s", alloca_str(config.log.file));
    DEBUGF("config.log.show_pid = %d", config.log.show_pid);
    DEBUGF("config.log.show_time = %d", config.log.show_time);
    DEBUGF("config.debug = %llx", (unsigned long long) config.debug);
    DEBUGF("config.directory.service = %s", alloca_tohex(config.directory.service.binary, SID_SIZE));
    int j;
    for (j = 0; j < config.rhizome.direct.peer.listc; ++j) {
      DEBUGF("config.rhizome.direct.peer.%s", config.rhizome.direct.peer.listv[j].label);
      DEBUGF("   .protocol = %s", alloca_str(config.rhizome.direct.peer.listv[j].value.protocol));
      DEBUGF("   .host = %s", alloca_str(config.rhizome.direct.peer.listv[j].value.host));
      DEBUGF("   .port = %u", config.rhizome.direct.peer.listv[j].value.port);
    }
  }
  exit(0);
}
