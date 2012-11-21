#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>

#include "str.h"
#include "strbuf_helpers.h"
#include "config.h"

#define NELS(a) (sizeof (a) / sizeof *(a))
#define DEBUGF(F,...) fprintf(stderr, "DEBUG: " F "\n", ##__VA_ARGS__)
#define WARNF(F,...) fprintf(stderr, "WARN:  " F "\n", ##__VA_ARGS__)
#define WHYF(F,...) fprintf(stderr, "ERROR: " F "\n", ##__VA_ARGS__)
#define WHYF_perror(F,...) fprintf(stderr, "ERROR: " F ": %s [errno=%d]\n", ##__VA_ARGS__, strerror(errno), errno)

struct config_main config;
struct config_main default_config;

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
      //DEBUGF("   m=%d n=%d i=%d child->key=%s c=%d", m, n, i, alloca_str_toprint(child->key), c);
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
  memset(child, sizeof *child, 0);
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
  memset(root, sizeof *root, 0);
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
    for (++p; p < lend && isspace(*p); ++p)
      ;
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
	node->fullkey ? alloca_str_toprint(node->fullkey) : "NULL",
	node->key ? alloca_str_toprint(node->key) : "NULL",
	node->text ? alloca_str_toprint(node->text) : "NULL"
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

void invalid_text(const struct config_node *node, const char *reason)
{
  WARNF("%s:%u: ignoring configuration option %s with invalid value %s%s%s",
      node->source, node->line_number,
      alloca_str_toprint(node->fullkey),
      alloca_str_toprint(node->text),
      reason && reason[0] ? " -- " : "", reason ? reason : ""
    );
}

void ignore_node(const struct config_node *node, const char *msg)
{
  WARNF("%s:%u: ignoring configuration option %s%s%s",
      node->source, node->line_number, alloca_str_toprint(node->fullkey),
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

int opt_boolean(int *booleanp, const struct config_node *node)
{
  unsupported_children(node);
  if (!node->text)
    return 1;
  if (!strcasecmp(node->text, "true") || !strcasecmp(node->text, "yes") || !strcasecmp(node->text, "on") || !strcasecmp(node->text, "1")) {
    *booleanp = 1;
    return 0;
  }
  else if (!strcasecmp(node->text, "false") || !strcasecmp(node->text, "no") || !strcasecmp(node->text, "off") || !strcasecmp(node->text, "0")) {
    *booleanp = 0;
    return 0;
  }
  invalid_text(node, "expecting true|yes|on|1|false|no|off|0");
  return 1;
}

int opt_absolute_path(const char **pathp, const struct config_node *node)
{
  //DEBUGF("%s", __FUNCTION__);
  //dump_config_node(node, 1);
  unsupported_children(node);
  if (!node->text)
    return 1;
  if (node->text[0] != '/') {
    invalid_text(node, "must start with '/'");
    return 1;
  }
  if (*pathp)
    free((char *) *pathp); // TODO: this should be unnecessary
  if ((*pathp = str_emalloc(node->text)) == NULL)
    return -1;
  return 0;
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
  return 0;
}

int opt_protocol(const char **protocolp, const struct config_node *node)
{
}

int opt_rhizome_peer(struct config_rhizomepeer *rpeer, const struct config_node *node)
{
  if (!node->text)
    return opt_config_rhizomepeer(rpeer, node);
  spurious_children(node);
  const char *protocol;
  size_t protolen;
  const char *auth;
  if (str_is_uri(node->text)) {
    const char *hier;
    if (!(   str_uri_scheme(node->text, &protocol, &protolen)
	  && str_uri_hierarchical(node->text, &hier, NULL)
	  && str_uri_hierarchical_authority(hier, &auth, NULL))
    ) {
      invalid_text(node, "malformed URL");
      return -1;
    }
  } else {
    auth = node->text;
    protocol = "http";
    protolen = strlen(protocol);
  }
  const char *host;
  size_t hostlen;
  unsigned short port = 0;
  if (!str_uri_authority_hostname(auth, &host, &hostlen))
    return -1;
  str_uri_authority_port(auth, &port);
  if (!(rpeer->protocol = strn_emalloc(protocol, protolen)))
    return -1;
  if (!(rpeer->host = str_emalloc(host))) {
    free((char *) rpeer->protocol);
    return -1;
  }
  rpeer->port = port;
  return 0;
}

int opt_host(const char **hostp, const struct config_node *node)
{
  //DEBUGF("%s", __FUNCTION__);
  //dump_config_node(node, 1);
  unsupported_children(node);
  if (!node->text)
    return 1;
  if (!node->text[0]) {
    invalid_text(node, "empty host name");
    return 1;
  }
  if (*hostp)
    free((char *) *hostp); // TODO: this should be unnecessary
  if ((*hostp = str_emalloc(node->text)) == NULL)
    return -1;
  return 0;
}

int opt_port(unsigned short *portp, const struct config_node *node)
{
  //DEBUGF("%s", __FUNCTION__);
  //dump_config_node(node, 1);
  unsupported_children(node);
  if (!node->text)
    return 1;
  unsigned short port = 0;
  const char *p;
  for (p = node->text; isdigit(*p); ++p) {
      unsigned oport = port;
      port = port * 10 + *p - '0';
      if (port / 10 != oport)
	break;
  }
  if (*p) {
    invalid_text(node, "invalid port number");
    return 1;
  }
  *portp = port;
  return 1;
}

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
    dfl_config_main(&config);
    opt_config_main(&config, root);
    free_config_node(root);
    free(buf);
    DEBUGF("config.log.file = %s", config.log.file ? alloca_str_toprint(config.log.file) : "NULL");
    DEBUGF("config.log.show_pid = %d", config.log.show_pid);
    DEBUGF("config.log.show_time = %d", config.log.show_time);
    DEBUGF("config.debug = %llx", (unsigned long long) config.debug);
    int j;
    for (j = 0; j < config.rhizome.direct.peer.listc; ++j) {
      DEBUGF("config.rhizome.direct.peer.%s", config.rhizome.direct.peer.listv[j].label);
      DEBUGF("   .protocol = %s", alloca_str_toprint(config.rhizome.direct.peer.listv[j].value.protocol));
      DEBUGF("   .host = %s", alloca_str_toprint(config.rhizome.direct.peer.listv[j].value.host));
      DEBUGF("   .port = %u", config.rhizome.direct.peer.listv[j].value.port);
    }
  }
  exit(0);
}
