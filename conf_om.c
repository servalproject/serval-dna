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
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <assert.h>

#include "str.h"
#include "strbuf.h"
#include "strbuf_helpers.h"

#define _DEBUGF(F,...) fprintf(stderr, "DEBUG: " F "\n", ##__VA_ARGS__)
#define _WARNF(F,...) fprintf(stderr, "WARN:  " F "\n", ##__VA_ARGS__)
#define _WHYF(F,...) fprintf(stderr, "ERROR: " F "\n", ##__VA_ARGS__)
#define _WHYF_perror(F,...) fprintf(stderr, "ERROR: " F ": %s [errno=%d]\n", ##__VA_ARGS__, strerror(errno), errno)
#define DEBUGF(F,...) _DEBUGF("%s:%u  " F, __FILE__, __LINE__, ##__VA_ARGS__)
#define WARNF(F,...) _WARNF("%s:%u  " F, __FILE__, __LINE__, ##__VA_ARGS__)
#define WHYF(F,...) _WHYF("%s:%u  " F, __FILE__, __LINE__, ##__VA_ARGS__)
#define WHYF_perror(F,...) _WHYF_perror("%s:%u  " F, __FILE__, __LINE__, ##__VA_ARGS__)

#include "config.h"

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

static const char *cf_find_keyend(const char *const key, const char *const fullkeyend)
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

static int cf_om_make_child(struct cf_om_node **const parentp, const char *const fullkey, const char *const key, const char *const keyend)
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

int cf_get_child(const struct cf_om_node *parent, const char *key)
{
  // TODO: use binary search, since child nodes are already sorted by key
  int i;
  for (i = 0; i < parent->nodc; ++i)
    if (strcmp(parent->nodv[i]->key, key) == 0)
      return i;
  return -1;
}

void cf_free_node(struct cf_om_node *node)
{
  while (node->nodc)
    cf_free_node(node->nodv[--node->nodc]);
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

struct cf_om_node *cf_parse_to_om(const char *source, const char *buf, size_t len)
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
    while (key <= fullkeyend && (keyend = cf_find_keyend(key, fullkeyend)) && (nodi = cf_om_make_child(nodep, fullkey, key, keyend)) != -1) {
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
  cf_free_node(root);
  return NULL;
}

void cf_dump_node(const struct cf_om_node *node, int indent)
{
  if (node == NULL)
    DEBUGF("%*sNULL", indent * 3, "");
  else {
    DEBUGF("%*s%s:%u fullkey=%s key=%s text=%s", indent * 3, "",
	node->source ? node->source : "NULL",
	node->line_number,
	alloca_str_toprint(node->fullkey),
	alloca_str_toprint(node->key),
	alloca_str_toprint(node->text)
      );
    int i;
    for (i = 0; i < node->nodc; ++i)
      cf_dump_node(node->nodv[i], indent + 1);
  }
}

void cf_warn_nodev(const char *file, unsigned line, const struct cf_om_node *node, const char *key, const char *fmt, va_list ap)
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

void cf_warn_childrenv(const char *file, unsigned line, const struct cf_om_node *parent, const char *fmt, va_list ap)
{
  int i;
  for (i = 0; i < parent->nodc; ++i) {
    cf_warn_nodev(file, line, parent->nodv[i], NULL, fmt, ap);
    cf_warn_childrenv(file, line, parent->nodv[i], fmt, ap);
  }
}

void cf_warn_node(const char *file, unsigned line, const struct cf_om_node *node, const char *key, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  cf_warn_nodev(file, line, node, key, fmt, ap);
  va_end(ap);
}

void cf_warn_children(const char *file, unsigned line, const struct cf_om_node *node, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  cf_warn_childrenv(file, line, node, fmt, ap);
  va_end(ap);
}

void cf_warn_duplicate_node(const struct cf_om_node *parent, const char *key)
{
  cf_warn_node(__FILE__, __LINE__, parent, key, "is duplicate");
}

void cf_warn_missing_node(const struct cf_om_node *parent, const char *key)
{
  cf_warn_node(__FILE__, __LINE__, parent, key, "is missing");
}

void cf_warn_spurious_children(const struct cf_om_node *parent)
{
  cf_warn_children(__FILE__, __LINE__, parent, "spurious");
}

void cf_warn_unsupported_node(const struct cf_om_node *node)
{
  cf_warn_node(__FILE__, __LINE__, node, NULL, "not supported");
}

void cf_warn_unsupported_children(const struct cf_om_node *parent)
{
  int i;
  for (i = 0; i < parent->nodc; ++i) {
    if (parent->nodv[i]->text)
      cf_warn_unsupported_node(parent->nodv[i]);
    cf_warn_unsupported_children(parent->nodv[i]);
  }
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

void cf_warn_node_value(const struct cf_om_node *node, int reason)
{
  strbuf b = strbuf_alloca(180);
  strbuf_cf_flag_reason(b, reason);
  cf_warn_node(__FILE__, __LINE__, node, NULL, "value %s %s", alloca_str_toprint(node->text), strbuf_str(b));
}

void cf_warn_no_array(const struct cf_om_node *node, int reason)
{
  strbuf b = strbuf_alloca(180);
  strbuf_cf_flag_reason(b, reason);
  cf_warn_node(__FILE__, __LINE__, node, NULL, "array discarded -- %s", strbuf_str(b));
}

void cf_warn_array_key(const struct cf_om_node *node, int reason)
{
  strbuf b = strbuf_alloca(180);
  strbuf_cf_flag_reason(b, reason);
  cf_warn_node(__FILE__, __LINE__, node, NULL, "array label %s -- %s", alloca_str_toprint(node->key), strbuf_str(b));
}

void cf_warn_array_value(const struct cf_om_node *node, int reason)
{
  strbuf b = strbuf_alloca(180);
  strbuf_cf_flag_reason(b, reason);
  if (node->text)
    cf_warn_node(__FILE__, __LINE__, node, NULL, "array value %s -- %s", alloca_str_toprint(node->text), strbuf_str(b));
  else
    cf_warn_node(__FILE__, __LINE__, node, NULL, "array element -- %s", strbuf_str(b));
}

void cf_warn_list_overflow(const struct cf_om_node *node)
{
  cf_warn_node(__FILE__, __LINE__, node, NULL, "list overflow");
  cf_warn_children(__FILE__, __LINE__, node, "list overflow");
}
