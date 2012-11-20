#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

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

const char *find_keyend(const char *const fullkey, const char *const fullkeyend)
{
  const char *s;
  for (s = fullkey; s < fullkeyend && (isalnum(*s) || *s == '_'); ++s)
    ;
  if (s == fullkey || (s < fullkeyend && *s != '.'))
    return NULL;
  return s;
}

char *strn_malloc(const char *str, size_t len)
{
  char *new = malloc(len + 1);
  if (!new) {
    WHYF_perror("malloc(%lu)", (long)len + 1);
    return NULL;
  }
  strncpy(new, str, len);
  new[len] = '\0';
  return new;
}

char *str_malloc(const char *str)
{
  return strn_malloc(str, strlen(str));
}

int make_child(struct config_node **const parentp, const char *const key, size_t keylen)
{
  // TODO: search using binary chop and insert in key lexical order.
  int i;
  struct config_node *child;
  for (i = 0; i < (*parentp)->nodc; ++i) {
    child = (*parentp)->nodv[i];
    if (strncmp(child->key, key, keylen) == 0 && child->key[keylen] == '\0')
      return i;
  }
  child = (struct config_node *) calloc(1, sizeof *child);
  if (child == NULL) {
    WHYF_perror("calloc(1, %u)", sizeof(struct config_node));
    return -1;
  }
  i = (*parentp)->nodc++;
  if ((*parentp)->nodc > NELS((*parentp)->nodv))
    *parentp = realloc(*parentp, sizeof(**parentp) + sizeof((*parentp)->nodv[0]) * ((*parentp)->nodc - NELS((*parentp)->nodv)));
  (*parentp)->nodv[i] = child;
  return i;
}

struct config_node *parse_config(const char *source, const char *buf, size_t len)
{
  struct config_node *root = calloc(1, sizeof(struct config_node));
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
    struct config_node **parentp = &root;
    const char *fullkey = line;
    const char *fullkeyend = p;
    const char *key = fullkey;
    const char *keyend = NULL;
    int nodi;
    struct config_node *node = NULL;
    while (key < fullkeyend && (keyend = find_keyend(key, fullkeyend)) && (nodi = make_child(parentp, key, keyend - key)) != -1) {
      node = (*parentp)->nodv[nodi];
      if (node->text) {
	WARNF("%s:%u: duplicate configuration option %s -- ignored (original is at %s:%u)",
	    source, lineno, alloca_toprint(-1, fullkey, fullkeyend - fullkey),
	    node->source, node->line_number
	  );
	break;
      }
      if (node->line_number == 0) {
	node->source = source;
	node->line_number = lineno;
      }
      if (!node->fullkey) {
	if (!(node->fullkey = strn_malloc(fullkey, keyend - fullkey)))
	  break; // out of memory
	node->key = node->fullkey + (key - fullkey);
      }
      node->text = NULL;
      key = keyend + 1;
      parentp = &(*parentp)->nodv[nodi];
    }
    if (keyend == NULL) {
      WARNF("%s:%u: malformed configuration option %s -- ignored",
	  source, lineno, alloca_toprint(-1, fullkey, fullkeyend - fullkey)
	);
      break;
    }
    if (nodi == -1)
      break; // out of memory
    for (++p; p < lend && isspace(*p); ++p)
      ;
    if (!(node->text = strn_malloc(p, lend - p)))
      break; // out of memory
  }
  return root;
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

void invalid_text(const struct config_node *node)
{
  WARNF("%s:%u: invalid configuration option %s=%s -- ignored",
      node->source, node->line_number,
      alloca_str_toprint(node->fullkey),
      alloca_str_toprint(node->text)
    );
}

void unsupported_node(const struct config_node *node)
{
  WARNF("%s:%u: unsupported configuration option %s -- ignored",
      node->source, node->line_number, alloca_str_toprint(node->fullkey)
    );
}

void unsupported_children(const struct config_node *parent)
{
  int i;
  for (i = 0; i < parent->nodc; ++i)
    unsupported_tree(parent->nodv[i]);
}

void unsupported_tree(const struct config_node *node)
{
  if (node->text)
    unsupported_node(node);
  unsupported_children(node);
}

void unused_config_node(const struct config_node *node)
{
  if (node->text)
    unsupported_node(node);
  int i;
  for (i = 0; i < node->nodc; ++i)
    unused_config_node(node->nodv[i]);
}

int opt_boolean(int *booleanp, const struct config_node *node)
{
  unsupported_children(node);
  if (node->text) {
    if (!strcasecmp(node->text, "true") || !strcasecmp(node->text, "yes") || !strcasecmp(node->text, "on") || !strcasecmp(node->text, "1"))
      return (*booleanp = 1);
    else if (!strcasecmp(node->text, "false") || !strcasecmp(node->text, "no") || !strcasecmp(node->text, "off") || !strcasecmp(node->text, "0"))
      return (*booleanp = 0);
    else
      invalid_text(node);
  }
  return -1;
}

int opt_absolute_path(const char **pathp, const struct config_node *node)
{
  DEBUGF("%s", __FUNCTION__);
  dump_config_node(node, 1);
  unsupported_children(node);
  if (node->text) {
    if (node->text[0] != '/')
      invalid_text(node);
    else {
      if (*pathp)
	free((char *) *pathp);
      if ((*pathp = str_malloc(node->text)))
	return 0;
    }
  }
  return -1;
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

void opt_debugflags(debugflags_t *flagsp, const struct config_node *node)
{
  DEBUGF("%s", __FUNCTION__);
  dump_config_node(node, 1);
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
  }
  exit(0);
}
