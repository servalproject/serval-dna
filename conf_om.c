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

#include "mem.h"
#include "str.h"
#include "strbuf.h"
#include "log.h"
#include "conf.h"

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

static const char *cf_find_keypattern_end(const char *const key, const char *const fullkeyend)
{
  const char *s = cf_find_keyend(key, fullkeyend);
  if (s == NULL) {
    s = key;
    if (s < fullkeyend && *s == '*')
      ++s;
    if (s + 1 == fullkeyend && *s == '*')
      ++s;
    if (s == key || (s < fullkeyend && *s != '.'))
      return NULL;
  }
  return s;
}

/* This predicate function defines the constraints on configuration option names.
 *
 *    OPTION_NAME  ::= ( KEY "." )* LASTKEY
 *    KEY	   ::= ( ALPHA | "_") ( ALPHANUM | "_" )*
 *    LASTKEY	   ::= KEY
 *    ALPHA	   ::= "A" .. "Z" | "a" .. "z"
 *    ALPHANUM	   ::= ALPHA | "0" .. "9"
 *
 * Valid examples:
 *	foo
 *	foo.bar
 *	foo.bar.chow
 *	_word
 *	word1
 *	word_1
 * Invalid:
 *      foo.
 *	.foo
 *	1foo
 *	foo.bar.
 *	12
 *	1.2.3
 *	foo bar
 *  @author Andrew Bettison <andrew@servalproject.com>
 */
int is_configvarname(const char *text)
{
  const char *const textend = text + strlen(text);
  const char *key = text;
  const char *keyend = NULL;
  while (key <= textend && (keyend = cf_find_keyend(key, textend)) != NULL)
    key = keyend + 1;
  return keyend != NULL;
}

/* This predicate function defines the constraints on configuration option patterns.
 * Similar to is_configvarname().
 *
 *    OPTION_PATTERN	::= ( KEY_PATTERN "." )* LASTKEY_PATTERN
 *    KEY_PATTERN	::= "*" | KEY
 *    LASTKEY_PATTERN	::= "**" | KEY_PATTERN
 *
 *  @author Andrew Bettison <andrew@servalproject.com>
 */
int is_configvarpattern(const char *text)
{
  const char *const textend = text + strlen(text);
  const char *key = text;
  const char *keyend = NULL;
  while (key <= textend && (keyend = cf_find_keypattern_end(key, textend)) != NULL)
    key = keyend + 1;
  return keyend != NULL;
}

static int cf_om_make_child(struct cf_om_node **const parentp, const char *const fullkey, const char *const key, const char *const keyend)
{
  // Allocate parent node if it is not present.
  if (!*parentp && (*parentp = emalloc_zero(sizeof **parentp)) == NULL)
    return -1;
  size_t keylen = keyend - key;
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
  if ((child = emalloc_zero(sizeof *child)) == NULL)
    return -1;
  if (!(child->fullkey = strn_edup(fullkey, keyend - fullkey))) {
    free(child);
    return -1;
  }
  child->key = child->fullkey + (key - fullkey);
  ++(*parentp)->nodc;
  if ((*parentp)->nodc > NELS((*parentp)->nodv))
    *parentp = realloc(*parentp, sizeof(**parentp) + sizeof((*parentp)->nodv[0]) * ((*parentp)->nodc - NELS((*parentp)->nodv)));
  int j;
  for (j = (*parentp)->nodc - 1; j > i; --j)
    (*parentp)->nodv[j] = (*parentp)->nodv[j-1];
  (*parentp)->nodv[i] = child;
  //DEBUGF("   insert i=%d", i);
  return i;
}

int cf_om_add_child(struct cf_om_node **const parentp, const char *const key)
{
  size_t parent_fullkey_len = (parentp && *parentp && (*parentp)->fullkey) ? strlen((*parentp)->fullkey) : 0;
  size_t fullkey_len = parent_fullkey_len + 1 + strlen(key);
  char fullkey[fullkey_len + 1];
  char *pkey = fullkey;
  if (parent_fullkey_len) {
    strcpy(fullkey, (*parentp)->fullkey);
    pkey = fullkey + parent_fullkey_len;
    *pkey++ = '.';
  }
  strcpy(pkey, key);
  return cf_om_make_child(parentp, fullkey, pkey, fullkey + fullkey_len);
}

int cf_om_get_child(const struct cf_om_node *parent, const char *key, const char *keyend)
{
  if (keyend == NULL)
    keyend = key + strlen(key);
  // TODO: use binary search, since child nodes are already sorted by key
  int i;
  for (i = 0; i < parent->nodc; ++i)
    if (memcmp(parent->nodv[i]->key, key, keyend - key) == 0 && parent->nodv[i]->key[keyend - key] == '\0')
      return i;
  return -1;
}

void cf_om_remove_child(struct cf_om_node **parentp, unsigned n)
{
  if (n < (*parentp)->nodc) {
    cf_om_free_node(&(*parentp)->nodv[n]);
    --(*parentp)->nodc;
    for (; n < (*parentp)->nodc; ++n)
      (*parentp)->nodv[n] = (*parentp)->nodv[n+1];
  }
}

int cf_om_parse(const char *source, const char *buf, size_t len, struct cf_om_node **rootp)
{
  const char *end = buf + len;
  const char *line = buf;
  const char *nextline;
  unsigned lineno = 1;
  int result = CFEMPTY;
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
      WARNF("%s:%u: malformed configuration line", source, lineno);
      result |= CFINVALID;
      continue;
    }
    struct cf_om_node **nodep = rootp;
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
      WARNF("%s:%u: malformed configuration option %s",
	  source, lineno, alloca_toprint(-1, fullkey, fullkeyend - fullkey)
	);
      result |= CFINVALID;
      continue;
    }
    if (nodi == -1)
      return CFERROR; // out of memory
    struct cf_om_node *node = *nodep;
    if (node->text) {
      WARNF("%s:%u: duplicate configuration option %s (original is at %s:%u)",
	  source, lineno, alloca_toprint(-1, fullkey, fullkeyend - fullkey),
	  node->source, node->line_number
	);
      result |= CFDUPLICATE;
      continue;
    }
    ++p;
    if (!(node->text = strn_edup(p, lend - p)))
      return CFERROR; // out of memory
    node->source = source;
    node->line_number = lineno;
    result &= ~CFEMPTY;
  }
  return result;
}

void cf_om_free_node(struct cf_om_node **nodep)
{
  if (*nodep) {
    //DEBUGF("%s text=%s nodc=%d", (*nodep)->fullkey, alloca_str_toprint((*nodep)->text), (*nodep)->nodc);
    while ((*nodep)->nodc)
      cf_om_free_node(&(*nodep)->nodv[--(*nodep)->nodc]);
    if ((*nodep)->fullkey) {
      free((char *)(*nodep)->fullkey);
      (*nodep)->fullkey = (*nodep)->key = NULL;
    }
    if ((*nodep)->text) {
      free((char *)(*nodep)->text);
      (*nodep)->text = NULL;
    }
    free(*nodep);
    *nodep = NULL;
  }
}

void cf_om_dump_node(const struct cf_om_node *node, int indent)
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
      cf_om_dump_node(node->nodv[i], indent + 1);
  }
}

int cf_om_match(const char *pattern, const struct cf_om_node *node)
{
  if (node == NULL) {
    //DEBUGF("pattern='%s' node=NULL", pattern);
    return 0;
  }
  if (node->fullkey == NULL) {
    //DEBUGF("pattern='%s' node->fullkey=NULL", pattern);
    return 0;
  }
  /*
  DEBUGF("pattern='%s' node->fullkey=%s node->nodc=%d node->text=%s",
      pattern,
      alloca_str_toprint(node->fullkey),
      node->nodc,
      alloca_str_toprint(node->text)
    );
  */
  if (!pattern[0])
    return -1;
  const char *const pattern_end = pattern + strlen(pattern);
  const char *pat = pattern;
  const char *key = node->fullkey;
  const char *const fullkeyend = node->fullkey + strlen(node->fullkey);
  const char *keyend = NULL;
  const char *patend = pat;
  //DEBUGF("   pat=%s key=%s", alloca_str_toprint(pat), alloca_str_toprint(key));
  while (pat < pattern_end && key <= fullkeyend && (keyend = cf_find_keyend(key, fullkeyend)) && (patend = cf_find_keypattern_end(pat, pattern_end))) {
    if (pat[0] == '*') {
      if (pat[1] == '*')
	return 1;
      pat = patend;
      key = keyend;
    } else {
      while (pat < patend && key < fullkeyend && *pat == *key)
	++pat, ++key;
      if (pat != patend || key != keyend)
	return 0;
    }
    if (*pat)
      ++pat;
    if (*key)
      ++key;
    //DEBUGF("   pat=%s key=%s", alloca_str_toprint(pat), alloca_str_toprint(key));
  }
  //DEBUGF("   patend=%s keyend=%s", alloca_str_toprint(patend), alloca_str_toprint(keyend));
  return patend == NULL ? -1 : keyend && keyend == fullkeyend && pat == pattern_end;
}

const char *cf_om_get(const struct cf_om_node *node, const char *fullkey)
{
  if (node == NULL)
    return NULL;
  const char *fullkeyend = fullkey + strlen(fullkey);
  const char *key = fullkey;
  const char *keyend = NULL;
  int nodi = -1;
  while (key <= fullkeyend && (keyend = cf_find_keyend(key, fullkeyend)) && (nodi = cf_om_get_child(node, key, keyend)) != -1) {
    key = keyend + 1;
    node = node->nodv[nodi];
  }
  if (keyend == NULL) {
    WARNF("malformed configuration option %s", alloca_toprint(-1, fullkey, fullkeyend - fullkey));
    return NULL;
  }
  if (nodi == -1)
    return NULL;
  return node->text;
}

int cf_om_set(struct cf_om_node **nodep, const char *fullkey, const char *text)
{
  const char *fullkeyend = fullkey + strlen(fullkey);
  const char *key = fullkey;
  const char *keyend = NULL;
  int nodi = -1;
  while (key <= fullkeyend && (keyend = cf_find_keyend(key, fullkeyend)) && (nodi = cf_om_make_child(nodep, fullkey, key, keyend)) != -1) {
    key = keyend + 1;
    nodep = &(*nodep)->nodv[nodi];
  }
  if (keyend == NULL) {
    WARNF("malformed configuration option %s", alloca_toprint(-1, fullkey, fullkeyend - fullkey));
    return CFINVALID;
  }
  if (nodi == -1)
    return CFERROR; // out of memory
  struct cf_om_node *node = *nodep;
  free((char *)node->text);
  if (text == NULL)
    node->text = NULL;
  else if (!(node->text = str_edup(text)))
    return CFERROR; // out of memory
  return CFOK;
}

void cf_om_iter_start(struct cf_om_iterator *it, const struct cf_om_node *root)
{
  it->sp = 0;
  it->stack[0].node = it->node = root;
  it->stack[0].index = 0;
}

#if 0
static void cf_om_iter_dump(struct cf_om_iterator *it)
{
  strbuf b = strbuf_alloca(1024);
  strbuf_sprintf(b, "node=%p sp=%d", it->node, it->sp);
  int i;
  for (i = 0; i <= it->sp; ++i)
    strbuf_sprintf(b, " %p[%d]", it->stack[i].node, it->stack[i].index);
  DEBUG(strbuf_str(b));
}
#endif

int cf_om_iter_next(struct cf_om_iterator *it)
{
  //cf_om_iter_dump(it);
  if (!it->node)
    return 0;
  while (1) {
    const struct cf_om_node *parent = it->stack[it->sp].node;
    int i = it->stack[it->sp].index++;
    if (i < parent->nodc) {
      it->node = parent->nodv[i];
      if (it->node == NULL)
	return WHY("null node");
      if (it->sp >= NELS(it->stack))
	return WHY("stack overflow");
      ++it->sp;
      it->stack[it->sp].node = it->node;
      it->stack[it->sp].index = 0;
      return 0;
    } else if (it->sp) {
      --it->sp;
    } else {
      it->node = NULL;
      return 0;
    }
  }
}

void _cf_warn_nodev(struct __sourceloc __whence, const struct cf_om_node *node, const char *key, const char *fmt, va_list ap)
{
  strbuf b = strbuf_alloca(1024);
  if (node) {
    if (node->source && node->line_number)
      strbuf_sprintf(b, "%s:%u: ", node->source, node->line_number);
    strbuf_puts(b, "configuration option \"");
    if (node->fullkey && node->fullkey[0])
      strbuf_puts(b, node->fullkey);
    if (key && key[0]) {
      if (node->fullkey && node->fullkey[0])
	strbuf_putc(b, '.');
      strbuf_puts(b, key);
    }
    strbuf_puts(b, "\" ");
  }
  strbuf_vsprintf(b, fmt, ap);
  WARN(strbuf_str(b));
}

void _cf_warn_childrenv(struct __sourceloc __whence, const struct cf_om_node *parent, const char *fmt, va_list ap)
{
  int i;
  for (i = 0; i < parent->nodc; ++i) {
    _cf_warn_nodev(__whence, parent->nodv[i], NULL, fmt, ap);
    _cf_warn_childrenv(__whence, parent->nodv[i], fmt, ap);
  }
}

void _cf_warn_node(struct __sourceloc __whence, const struct cf_om_node *node, const char *key, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  _cf_warn_nodev(__whence, node, key, fmt, ap);
  va_end(ap);
}

void _cf_warn_children(struct __sourceloc __whence, const struct cf_om_node *node, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  _cf_warn_childrenv(__whence, node, fmt, ap);
  va_end(ap);
}

void _cf_warn_duplicate_node(struct __sourceloc __whence, const struct cf_om_node *parent, const char *key)
{
  _cf_warn_node(__whence, parent, key, "is duplicate");
}

void _cf_warn_missing_node(struct __sourceloc __whence, const struct cf_om_node *parent, const char *key)
{
  _cf_warn_node(__whence, parent, key, "is missing");
}

void _cf_warn_incompatible(struct __sourceloc __whence, const struct cf_om_node *node, const struct cf_om_node *orig)
{
  assert(node != orig);
  strbuf b = strbuf_alloca(180);
  if (orig) {
    strbuf_sprintf(b, "\"%s\"", orig->fullkey);
    if (orig->source && orig->line_number)
      strbuf_sprintf(b, " at %s:%u", orig->source, orig->line_number);
  } else {
    strbuf_puts(b, "other option(s)");
  }
  _cf_warn_node(__whence, node, NULL, "is incompatible with %s", strbuf_str(b));
}

void _cf_warn_incompatible_children(struct __sourceloc __whence, const struct cf_om_node *parent)
{
  struct cf_om_iterator it;
  for (cf_om_iter_start(&it, parent); it.node; cf_om_iter_next(&it))
    if (it.node != parent && it.node->text)
      _cf_warn_incompatible(__whence, parent, it.node);
}

void _cf_warn_unsupported_node(struct __sourceloc __whence, const struct cf_om_node *node)
{
  _cf_warn_node(__whence, node, NULL, "not supported");
}

void _cf_warn_unsupported_children(struct __sourceloc __whence, const struct cf_om_node *parent)
{
  int i;
  for (i = 0; i < parent->nodc; ++i) {
    if (parent->nodv[i]->text)
      _cf_warn_unsupported_node(__whence, parent->nodv[i]);
    _cf_warn_unsupported_children(__whence, parent->nodv[i]);
  }
}

strbuf strbuf_cf_flags(strbuf sb, int flags)
{
  if (flags == CFERROR)
    return strbuf_puts(sb, "CFERROR");
  size_t n = strbuf_len(sb);
  static struct { int flag; const char *name; } flagdefs[] = {
      { CFEMPTY, "CFEMPTY" },
      { CFDUPLICATE, "CFDUPLICATE" },
      { CFSTRINGOVERFLOW, "CFSTRINGOVERFLOW" },
      { CFARRAYOVERFLOW, "CFARRAYOVERFLOW" },
      { CFINCOMPLETE, "CFINCOMPLETE" },
      { CFINCOMPATIBLE, "CFINCOMPATIBLE" },
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
      { CFDUPLICATE, "duplicate element" },
      { CFSTRINGOVERFLOW, "string overflow" },
      { CFARRAYOVERFLOW, "array overflow" },
      { CFINCOMPLETE, "incomplete" },
      { CFINCOMPATIBLE, "incompatible" },
      { CFINVALID, "invalid" },
      { CFUNSUPPORTED, "not supported" },
      { CFSUB(CFEMPTY), "contains empty element" },
      { CFSUB(CFDUPLICATE), "contains element with duplicate" },
      { CFSUB(CFSTRINGOVERFLOW), "contains string overflow" },
      { CFSUB(CFARRAYOVERFLOW), "contains array overflow" },
      { CFSUB(CFINCOMPLETE), "contains incomplete element" },
      { CFSUB(CFINCOMPATIBLE), "contains incompatible element" },
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

void _cf_warn_node_value(struct __sourceloc __whence, const struct cf_om_node *node, int reason)
{
  strbuf b = strbuf_alloca(180);
  strbuf_cf_flag_reason(b, reason);
  _cf_warn_node(__whence, node, NULL, "value %s %s", alloca_str_toprint(node->text), strbuf_str(b));
}

void _cf_warn_no_array(struct __sourceloc __whence, const struct cf_om_node *node, int reason)
{
  strbuf b = strbuf_alloca(180);
  strbuf_cf_flag_reason(b, reason);
  _cf_warn_node(__whence, node, NULL, "array discarded -- %s", strbuf_str(b));
}

void _cf_warn_array_key(struct __sourceloc __whence, const struct cf_om_node *node, int reason)
{
  strbuf b = strbuf_alloca(180);
  strbuf_cf_flag_reason(b, reason);
  _cf_warn_node(__whence, node, NULL, "array key %s -- %s", alloca_str_toprint(node->key), strbuf_str(b));
}

void _cf_warn_array_value(struct __sourceloc __whence, const struct cf_om_node *node, int reason)
{
  strbuf b = strbuf_alloca(180);
  strbuf_cf_flag_reason(b, reason);
  if (node->text)
    _cf_warn_node(__whence, node, NULL, "array value %s -- %s", alloca_str_toprint(node->text), strbuf_str(b));
  else
    _cf_warn_node(__whence, node, NULL, "array element -- %s", strbuf_str(b));
}

void _cf_warn_list_overflow(struct __sourceloc __whence, const struct cf_om_node *node)
{
  _cf_warn_node(__whence, node, NULL, "list overflow");
  _cf_warn_children(__whence, node, "list overflow");
}
