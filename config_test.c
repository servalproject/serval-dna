#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <assert.h>

#include "str.h"
#include "strbuf.h"
#include "strbuf_helpers.h"

#define NELS(a) (sizeof (a) / sizeof *(a))
#define _DEBUGF(F,...) fprintf(stderr, "DEBUG: " F "\n", ##__VA_ARGS__)
#define _WARNF(F,...) fprintf(stderr, "WARN:  " F "\n", ##__VA_ARGS__)
#define _WHYF(F,...) fprintf(stderr, "ERROR: " F "\n", ##__VA_ARGS__)
#define _WHYF_perror(F,...) fprintf(stderr, "ERROR: " F ": %s [errno=%d]\n", ##__VA_ARGS__, strerror(errno), errno)
#define DEBUGF(F,...) _DEBUGF("%s:%u  " F, __FILE__, __LINE__, ##__VA_ARGS__)
#define WARNF(F,...) _WARNF("%s:%u  " F, __FILE__, __LINE__, ##__VA_ARGS__)
#define WHYF(F,...) _WHYF("%s:%u  " F, __FILE__, __LINE__, ##__VA_ARGS__)
#define WHYF_perror(F,...) _WHYF_perror("%s:%u  " F, __FILE__, __LINE__, ##__VA_ARGS__)
#define alloca_str(s) ((s) ? alloca_str_toprint(s) : "NULL")

#include "config.h"

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

int make_child(struct cf_om_node **const parentp, const char *const fullkey, const char *const key, const char *const keyend)
{
  size_t keylen = keyend - key;
  //DEBUGF("%s key=%s", __FUNCTION__, alloca_toprint(-1, key, keylen));
  int i = 0;
  struct cf_om_node *child;
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

void free_config_node(struct cf_om_node *node)
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

struct cf_om_node *parse_config(const char *source, const char *buf, size_t len)
{
  struct cf_om_node *root = emalloc(sizeof(struct cf_om_node));
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
    if (line[0] == '#')
      continue; // skip comment lines
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
    struct cf_om_node **nodep = &root;
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
    struct cf_om_node *node = *nodep;
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

void dump_config_node(const struct cf_om_node *node, int indent)
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

int get_child(const struct cf_om_node *parent, const char *key)
{
  int i;
  for (i = 0; i < parent->nodc; ++i)
    if (strcmp(parent->nodv[i]->key, key) == 0)
      return i;
  return -1;
}

void warn_nodev(const char *file, unsigned line, const struct cf_om_node *node, const char *key, const char *fmt, va_list ap)
{
  strbuf b = strbuf_alloca(1024);
  if (node) {
    if (node->source && node->line_number)
      strbuf_sprintf(b, "%s:%u: ", node->source, node->line_number);
    strbuf_puts(b, "configuration option \"");
    strbuf_puts(b, node->fullkey);
    if (key && key[0]) {
      strbuf_putc(b, '.');
      strbuf_puts(b, key);
    }
    strbuf_puts(b, "\" ");
  }
  strbuf_vsprintf(b, fmt, ap);
  _WARNF("%s:%u  %s", file, line, strbuf_str(b));
}

void warn_childrenv(const char *file, unsigned line, const struct cf_om_node *parent, const char *fmt, va_list ap)
{
  int i;
  for (i = 0; i < parent->nodc; ++i) {
    warn_nodev(file, line, parent->nodv[i], NULL, fmt, ap);
    warn_childrenv(file, line, parent->nodv[i], fmt, ap);
  }
}

void warn_node(const char *file, unsigned line, const struct cf_om_node *node, const char *key, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  warn_nodev(file, line, node, key, fmt, ap);
  va_end(ap);
}

void warn_children(const char *file, unsigned line, const struct cf_om_node *node, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  warn_childrenv(file, line, node, fmt, ap);
  va_end(ap);
}

void warn_missing_node(const struct cf_om_node *parent, const char *key)
{
  warn_node(__FILE__, __LINE__, parent, key, "is missing");
}

strbuf strbuf_cf_flags(strbuf sb, int flags)
{
  if (flags == CFERROR)
    return strbuf_puts(sb, "CFERROR");
  size_t n = strbuf_len(sb);
  static struct { int flag; const char *name; } flagdefs[] = {
      { CFEMPTY, "CFEMPTY" },
      { CFSTRINGOVERFLOW, "CFSTRINGOVERFLOW" },
      { CFARRAYOVERFLOW, "CFARRAYOVERFLOW" },
      { CFINCOMPLETE, "CFINCOMPLETE" },
      { CFINVALID, "CFINVALID" },
      { CFUNSUPPORTED, "CFUNSUPPORTED" },
    };
  int i;
  for (i = 0; i < NELS(flagdefs); ++i) {
    if (flags & flagdefs[i].flag) {
      if (strbuf_len(sb) != n)
	strbuf_putc(sb, ' ');
      strbuf_puts(sb, flagdefs[i].name);
      flags &= ~flagdefs[i].flag;
    }
  }
  for (i = 0; i < NELS(flagdefs); ++i) {
    if (flags & CFSUB(flagdefs[i].flag)) {
      if (strbuf_len(sb) != n)
	strbuf_putc(sb, ' ');
      strbuf_puts(sb, "CFSUB(");
      strbuf_puts(sb, flagdefs[i].name);
      strbuf_putc(sb, ')');
      flags &= ~CFSUB(flagdefs[i].flag);
    }
  }
  if (flags) {
    if (strbuf_len(sb) != n)
      strbuf_putc(sb, ' ');
    strbuf_sprintf(sb, "%#x", flags);
  }
  if (strbuf_len(sb) == n)
    strbuf_puts(sb, "CFOK");
  return sb;
}

strbuf strbuf_cf_flag_reason(strbuf sb, int flags)
{
  if (flags == CFERROR)
    return strbuf_puts(sb, "unrecoverable error");
  size_t n = strbuf_len(sb);
  static struct { int flag; const char *reason; } flagdefs[] = {
      { CFEMPTY, "empty" },
      { CFSTRINGOVERFLOW, "string overflow" },
      { CFARRAYOVERFLOW, "array overflow" },
      { CFINCOMPLETE, "incomplete" },
      { CFINVALID, "invalid" },
      { CFUNSUPPORTED, "not supported" },
      { CFSUB(CFEMPTY), "contains empty element" },
      { CFSUB(CFSTRINGOVERFLOW), "contains string overflow" },
      { CFSUB(CFARRAYOVERFLOW), "contains array overflow" },
      { CFSUB(CFINCOMPLETE), "contains incomplete element" },
      { CFSUB(CFINVALID), "contains invalid element" },
      { CFSUB(CFUNSUPPORTED), "contains unsupported element" },
    };
  int i;
  for (i = 0; i < NELS(flagdefs); ++i) {
    if (flags & flagdefs[i].flag) {
      if (strbuf_len(sb) != n)
	strbuf_puts(sb, ", ");
      strbuf_puts(sb, flagdefs[i].reason);
      flags &= ~flagdefs[i].flag;
    }
  }
  if (strbuf_len(sb) == n)
    strbuf_puts(sb, "no reason");
  return sb;
}

void warn_node_value(const struct cf_om_node *node, int reason)
{
  strbuf b = strbuf_alloca(180);
  strbuf_cf_flag_reason(b, reason);
  warn_node(__FILE__, __LINE__, node, NULL, "value %s %s", alloca_str(node->text), strbuf_str(b));
}

void warn_no_array(const struct cf_om_node *node, int reason)
{
  strbuf b = strbuf_alloca(180);
  strbuf_cf_flag_reason(b, reason);
  warn_node(__FILE__, __LINE__, node, NULL, "array discarded -- %s", strbuf_str(b));
}

void warn_unsupported_node(const struct cf_om_node *node)
{
  warn_node(__FILE__, __LINE__, node, NULL, "not supported");
}

void warn_unsupported_children(const struct cf_om_node *parent)
{
  int i;
  for (i = 0; i < parent->nodc; ++i) {
    if (parent->nodv[i]->text)
      warn_unsupported_node(parent->nodv[i]);
    warn_unsupported_children(parent->nodv[i]);
  }
}

void warn_list_overflow(const struct cf_om_node *node)
{
  warn_node(__FILE__, __LINE__, node, NULL, "list overflow");
  warn_children(__FILE__, __LINE__, node, "list overflow");
}

void warn_spurious_children(const struct cf_om_node *parent)
{
  warn_children(__FILE__, __LINE__, parent, "spurious");
}

void warn_array_label(const struct cf_om_node *node, int reason)
{
  strbuf b = strbuf_alloca(180);
  strbuf_cf_flag_reason(b, reason);
  warn_node(__FILE__, __LINE__, node, NULL, "array label %s -- %s", alloca_str(node->key), strbuf_str(b));
}

void warn_array_value(const struct cf_om_node *node, int reason)
{
  strbuf b = strbuf_alloca(180);
  strbuf_cf_flag_reason(b, reason);
  if (node->text)
    warn_node(__FILE__, __LINE__, node, NULL, "array value %s -- %s", alloca_str(node->text), strbuf_str(b));
  else
    warn_node(__FILE__, __LINE__, node, NULL, "array element -- %s", strbuf_str(b));
}

int opt_boolean(int *booleanp, const char *text);
int opt_absolute_path(char *str, size_t len, const char *text);
int opt_debugflags(debugflags_t *flagsp, const struct cf_om_node *node);
int opt_rhizome_peer(struct config_rhizomepeer *, const struct cf_om_node *node);
int opt_str(char *str, size_t len, const char *text);
int opt_str_nonempty(char *str, size_t len, const char *text);
int opt_int(int *intp, const char *text);
int opt_uint64_scaled(uint64_t *intp, const char *text);
int opt_protocol(char *str, size_t len, const char *text);
int opt_port(unsigned short *portp, const char *text);
int opt_sid(sid_t *sidp, const char *text);
int opt_interface_type(short *typep, const char *text);
int opt_pattern_list(struct pattern_list *listp, const char *text);
int opt_interface_list(struct config_interface_list *listp, const struct cf_om_node *node);

int opt_boolean(int *booleanp, const char *text)
{
  if (!strcasecmp(text, "true") || !strcasecmp(text, "yes") || !strcasecmp(text, "on") || !strcasecmp(text, "1")) {
    *booleanp = 1;
    return CFOK;
  }
  else if (!strcasecmp(text, "false") || !strcasecmp(text, "no") || !strcasecmp(text, "off") || !strcasecmp(text, "0")) {
    *booleanp = 0;
    return CFOK;
  }
  //invalid_text(node, "expecting true|yes|on|1|false|no|off|0");
  return CFINVALID;
}

int opt_absolute_path(char *str, size_t len, const char *text)
{
  if (text[0] != '/') {
    //invalid_text(node, "must start with '/'");
    return CFINVALID;
  }
  if (strlen(text) >= len) {
    //invalid_text(node, "string overflow");
    return CFSTRINGOVERFLOW;
  }
  strncpy(str, text, len);
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

int opt_debugflags(debugflags_t *flagsp, const struct cf_om_node *node)
{
  //DEBUGF("%s", __FUNCTION__);
  //dump_config_node(node, 1);
  debugflags_t setmask = 0;
  debugflags_t clearmask = 0;
  int setall = 0;
  int clearall = 0;
  int result = CFEMPTY;
  int i;
  for (i = 0; i < node->nodc; ++i) {
    const struct cf_om_node *child = node->nodv[i];
    warn_unsupported_children(child);
    debugflags_t mask = debugFlagMask(child->key);
    int flag = -1;
    if (!mask)
      warn_unsupported_node(child);
    else if (child->text) {
      int ret = opt_boolean(&flag, child->text);
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
	warn_node_value(child, ret);
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

int opt_protocol(char *str, size_t len, const char *text)
{
  if (!str_is_uri_scheme(text)) {
    //invalid_text(node, "contains invalid character");
    return CFINVALID;
  }
  if (strlen(text) >= len) {
    //invalid_text(node, "string overflow");
    return CFSTRINGOVERFLOW;
  }
  strncpy(str, text, len);
  assert(str[len - 1] == '\0');
  return CFOK;
}

int opt_rhizome_peer(struct config_rhizomepeer *rpeer, const struct cf_om_node *node)
{
  if (!node->text)
    return opt_config_rhizomepeer(rpeer, node);
  warn_spurious_children(node);
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
    //invalid_text(node, "protocol string overflow");
    return CFSTRINGOVERFLOW;
  }
  if (hostlen >= sizeof rpeer->host) {
    //invalid_text(node, "hostname string overflow");
    return CFSTRINGOVERFLOW;
  }
  strncpy(rpeer->protocol, protocol, protolen)[protolen] = '\0';
  strncpy(rpeer->host, host, hostlen)[hostlen] = '\0';
  rpeer->port = port;
  return CFOK;
invalid:
  //invalid_text(node, "malformed URL");
  return CFINVALID;
}

int opt_str(char *str, size_t len, const char *text)
{
  if (strlen(text) >= len)
    return CFSTRINGOVERFLOW;
  strncpy(str, text, len);
  assert(str[len - 1] == '\0');
  return CFOK;
}

int opt_str_nonempty(char *str, size_t len, const char *text)
{
  if (!text[0]) {
    //invalid_text(node, "empty string");
    return CFINVALID;
  }
  return opt_str(str, len, text);
}

int opt_int(int *intp, const char *text)
{
  const char *end = text;
  long value = strtol(text, (char**)&end, 10);
  if (end == text || *end)
    return CFINVALID;
  *intp = value;
  return CFOK;
}

int opt_uint64_scaled(uint64_t *intp, const char *text)
{
  uint64_t result;
  const char *end;
  if (!str_to_uint64_scaled(text, 10, &result, &end) || *end) {
    //invalid_text(node, "invalid scaled unsigned integer");
    return CFINVALID;
  }
  *intp = result;
  return CFOK;
}

int opt_argv_label(char *str, size_t len, const char *text)
{
  const char *s = text;
  if (isdigit(*s) && *s != '0') {
    ++s;
    while (isdigit(*s))
      ++s;
  }
  if (s == text || *s)
    return CFINVALID;
  if (s - text >= len)
    return CFSTRINGOVERFLOW;
  strncpy(str, text, len - 1)[len - 1] = '\0';
  return CFOK;
}

int cmp_argv(const struct config_argv__element *a, const struct config_argv__element *b)
{
  int ai = atoi(a->label);
  int bi = atoi(b->label);
  return ai < bi ? -1 : ai > bi ? 1 : 0;
}

int vld_argv(const struct cf_om_node *parent, struct config_argv *array, int result)
{
  qsort(array->av, array->ac, sizeof array->av[0], (int (*)(const void *, const void *)) cmp_argv);
  int last_label = -1;
  int i;
  for (i = 0; i < array->ac; ++i) {
    int label = atoi(array->av[i].label);
    assert(label >= 1);
    while (last_label != -1 && ++last_label < label && last_label <= sizeof(array->av)) {
      char labelkey[12];
      sprintf(labelkey, "%u", last_label);
      warn_missing_node(parent, labelkey);
      result |= CFINCOMPLETE;
    }
    last_label = label;
  }
  return result;
}

int opt_port(unsigned short *portp, const char *text)
{
  unsigned short port = 0;
  const char *p;
  for (p = text; isdigit(*p); ++p) {
      unsigned oport = port;
      port = port * 10 + *p - '0';
      if (port / 10 != oport)
	break;
  }
  if (*p || port == 0) {
    //invalid_text(node, "invalid port number");
    return CFINVALID;
  }
  *portp = port;
  return CFOK;
}

int opt_sid(sid_t *sidp, const char *text)
{
  sid_t sid;
  if (!str_is_subscriber_id(text)) {
    //invalid_text(node, "invalid subscriber ID");
    return CFINVALID;
  }
  size_t n = fromhex(sidp->binary, text, SID_SIZE);
  assert(n == SID_SIZE);
  return CFOK;
}

int opt_interface_type(short *typep, const char *text)
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
  //invalid_text(node, "invalid network interface type");
  return CFINVALID;
}

int opt_pattern_list(struct pattern_list *listp, const char *text)
{
  struct pattern_list list;
  memset(&list, 0, sizeof list);
  const char *word = NULL;
  const char *p;
  for (p = text; ; ++p) {
    if (!*p || isspace(*p) || *p == ',') {
      if (word) {
	size_t len = p - word;
	if (list.patc >= NELS(list.patv) || len >= sizeof(list.patv[list.patc])) {
	  //invalid_text(node, "string overflow");
	  return CFARRAYOVERFLOW;
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
int opt_network_interface(struct config_network_interface *nifp, const char *text)
{
  //DEBUGF("%s text=%s", __FUNCTION__, alloca_str(text));
  struct config_network_interface nif;
  dfl_config_network_interface(&nif);
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
      int result = opt_interface_type(&nif.type, buf);
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
      int result = opt_port(&nif.port, buf);
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
      int result = opt_uint64_scaled(&nif.speed, buf);
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
 * comma-separated list of interface rules (see opt_network_interface() for the format of each
 * rule), then parses the regular config array-of-struct style interface option settings so that
 * both forms are supported.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int opt_interface_list(struct config_interface_list *listp, const struct cf_om_node *node)
{
  int result = opt_config_interface_list(listp, node);
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
	  int ret = opt_network_interface(&listp->av[n].value, buf);
	  switch (ret) {
	  case CFERROR: return CFERROR;
	  case CFOK:
	    len = snprintf(listp->av[n].label, sizeof listp->av[n].label - 1, "%u", n);
	    listp->av[n].label[len] = '\0';
	    ++n;
	    break;
	  default:
	    warn_node(__FILE__, __LINE__, node, NULL, "invalid interface rule %s", alloca_str(buf)); \
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

// Schema item flags.
#define __MANDATORY     (1<<0)
#define __TEXT		(1<<1)
#define __CHILDREN	(1<<2)

// Schema flag symbols, to be used in the '__flags' macro arguments.
#define MANDATORY	|__MANDATORY
#define USES_TEXT	|__TEXT
#define USES_CHILDREN	|__CHILDREN

// Generate parsing functions, opt_config_SECTION()
#define STRUCT(__name, __validator...) \
    int opt_config_##__name(struct config_##__name *strct, const struct cf_om_node *node) { \
      int (*validator)(const struct cf_om_node *, struct config_##__name *, int) = (NULL, ##__validator); \
      int result = CFEMPTY; \
      char used[node->nodc]; \
      memset(used, 0, node->nodc * sizeof used[0]);
#define __ITEM(__element, __flags, __parseexpr) \
      { \
	int i = get_child(node, #__element); \
	const struct cf_om_node *child = (i != -1) ? node->nodv[i] : NULL; \
	int ret = CFEMPTY; \
	if (child) { \
	  used[i] |= (__flags); \
	  ret = (__parseexpr); \
	  if (ret == CFERROR) \
	    return CFERROR; \
	} \
	result |= ret & CF__SUBFLAGS; \
	ret &= CF__FLAGS; \
	if (!(ret & CFEMPTY)) \
	  result &= ~CFEMPTY; \
	else if ((__flags) & __MANDATORY) { \
	  warn_missing_node(node, #__element); \
	  result |= CFINCOMPLETE; \
	} \
	if (ret & ~CFEMPTY) { \
	  assert(child != NULL); \
	  if (child->text) \
	    warn_node_value(child, ret); \
	  result |= CFSUB(ret); \
	} \
      }
#define NODE(__type, __element, __default, __parser, __flags, __comment) \
        __ITEM(__element, 0 __flags, __parser(&strct->__element, child))
#define ATOM(__type, __element, __default, __parser, __flags, __comment) \
        __ITEM(__element, ((0 __flags)|__TEXT)&~__CHILDREN, child->text ? __parser(&strct->__element, child->text) : CFEMPTY)
#define STRING(__size, __element, __default, __parser, __flags, __comment) \
        __ITEM(__element, ((0 __flags)|__TEXT)&~__CHILDREN, child->text ? __parser(strct->__element, (__size) + 1, child->text) : CFEMPTY)
#define SUB_STRUCT(__name, __element, __flags) \
        __ITEM(__element, (0 __flags)|__CHILDREN, opt_config_##__name(&strct->__element, child))
#define NODE_STRUCT(__name, __element, __parser, __flags) \
        __ITEM(__element, (0 __flags)|__TEXT|__CHILDREN, __parser(&strct->__element, child))
#define END_STRUCT \
      { \
	int i; \
	for (i = 0; i < node->nodc; ++i) { \
	  if (node->nodv[i]->text && !(used[i] & __TEXT)) { \
	    warn_unsupported_node(node->nodv[i]); \
	    result |= CFSUB(CFUNSUPPORTED); \
	  } \
	  if (node->nodv[i]->nodc && !(used[i] & __CHILDREN)) { \
	    warn_unsupported_children(node->nodv[i]); \
	    result |= CFSUB(CFUNSUPPORTED); \
	  } \
	} \
      } \
      if (validator) \
	result = (*validator)(node, strct, result); \
      return result; \
    }

#define __ARRAY(__name, __lblparser, __parseexpr, __validator...) \
    int opt_config_##__name(struct config_##__name *array, const struct cf_om_node *node) { \
      int (*validator)(const struct cf_om_node *, struct config_##__name *, int) = (NULL, ##__validator); \
      int result = CFOK; \
      int i, n; \
      for (n = 0, i = 0; i < node->nodc && n < NELS(array->av); ++i) { \
	const struct cf_om_node *child = node->nodv[i]; \
	int ret = __lblparser(array->av[n].label, sizeof array->av[n].label, child->key); \
	if (ret == CFERROR) \
	  return CFERROR; \
	result |= ret & CF__SUBFLAGS; \
	ret &= CF__FLAGS; \
	result |= CFSUB(ret); \
	if (ret != CFOK) \
	  warn_array_label(child, ret); \
	else { \
	  ret = (__parseexpr); \
	  if (ret == CFERROR) \
	    return CFERROR; \
	  result |= ret & CF__SUBFLAGS; \
	  ret &= CF__FLAGS; \
	  result |= CFSUB(ret); \
	  if (ret == CFOK) \
	    ++n; \
	  else \
	    warn_array_value(child, ret); \
	} \
      } \
      if (i < node->nodc) { \
	assert(n == NELS(array->av)); \
	result |= CFARRAYOVERFLOW; \
	for (; i < node->nodc; ++i) \
	  warn_list_overflow(node->nodv[i]); \
      } \
      array->ac = n; \
      if (validator) \
	result = (*validator)(node, array, result); \
      if (result & ~CFEMPTY) { \
	warn_no_array(node, result); \
	array->ac = 0; \
      } \
      if (array->ac == 0) \
	result |= CFEMPTY; \
      return result; \
    }
#define ARRAY_ATOM(__name, __size, __lbllen, __type, __lblparser, __eltparser, __validator...) \
    __ARRAY(__name, __lblparser, child->text ? __eltparser(&array->av[n].value, child->text) : CFEMPTY, ##__validator)
#define ARRAY_STRING(__name, __size, __lbllen, __strsize, __lblparser, __eltparser, __validator...) \
    __ARRAY(__name, __lblparser, child->text ? __eltparser(array->av[n].value, sizeof array->av[n].value, child->text) : CFEMPTY, ##__validator)
#define ARRAY_NODE(__name, __size, __lbllen, __type, __lblparser, __eltparser, __validator...) \
    __ARRAY(__name, __lblparser, __eltparser(&array->av[n].value, child), ##__validator)
#define ARRAY_STRUCT(__name, __size, __lbllen, __structname, __lblparser, __validator...) \
    __ARRAY(__name, __lblparser, opt_config_##__structname(&array->av[n].value, child), ##__validator)

#include "config_schema.h"

#undef STRUCT
#undef NODE
#undef ATOM
#undef STRING
#undef SUB_STRUCT
#undef NODE_STRUCT
#undef END_STRUCT
#undef __ARRAY

#undef ARRAY_ATOM
#undef ARRAY_STRING
#undef ARRAY_NODE
#undef ARRAY_STRUCT

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
    struct cf_om_node *root = parse_config(argv[i], buf, st.st_size);
    close(fd);
    //dump_config_node(root, 0);
    struct config_main config;
    memset(&config, 0, sizeof config);
    dfl_config_main(&config);
    int result = opt_config_main(&config, root);
    free_config_node(root);
    free(buf);
    DEBUGF("result = %s", strbuf_str(strbuf_cf_flags(strbuf_alloca(128), result)));
    DEBUGF("config.log.file = %s", alloca_str(config.log.file));
    DEBUGF("config.log.show_pid = %d", config.log.show_pid);
    DEBUGF("config.log.show_time = %d", config.log.show_time);
    DEBUGF("config.server.chdir = %s", alloca_str(config.server.chdir));
    DEBUGF("config.debug = %llx", (unsigned long long) config.debug);
    DEBUGF("config.directory.service = %s", alloca_tohex(config.directory.service.binary, SID_SIZE));
    int j;
    for (j = 0; j < config.dna.helper.argv.ac; ++j) {
      DEBUGF("config.dna.helper.argv.%s=%s", config.dna.helper.argv.av[j].label, config.dna.helper.argv.av[j].value);
    }
    for (j = 0; j < config.rhizome.direct.peer.ac; ++j) {
      DEBUGF("config.rhizome.direct.peer.%s", config.rhizome.direct.peer.av[j].label);
      DEBUGF("   .protocol = %s", alloca_str(config.rhizome.direct.peer.av[j].value.protocol));
      DEBUGF("   .host = %s", alloca_str(config.rhizome.direct.peer.av[j].value.host));
      DEBUGF("   .port = %u", config.rhizome.direct.peer.av[j].value.port);
    }
    for (j = 0; j < config.interfaces.ac; ++j) {
      DEBUGF("config.interfaces.%s", config.interfaces.av[j].label);
      DEBUGF("   .exclude = %d", config.interfaces.av[j].value.exclude);
      DEBUGF("   .match = [");
      int k;
      for (k = 0; k < config.interfaces.av[j].value.match.patc; ++k)
	DEBUGF("             %s", alloca_str(config.interfaces.av[j].value.match.patv[k]));
      DEBUGF("            ]");
      DEBUGF("   .type = %d", config.interfaces.av[j].value.type);
      DEBUGF("   .port = %u", config.interfaces.av[j].value.port);
      DEBUGF("   .speed = %llu", (unsigned long long) config.interfaces.av[j].value.speed);
    }
  }
  exit(0);
}
