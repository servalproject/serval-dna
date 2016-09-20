/*
 MDP packet filtering
 Copyright (C) 2013-2014 Serval Project Inc.
 
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

#include <inttypes.h> // for PRIx64 on Android
#include "serval.h" // for serverMode
#include "serval_types.h"
#include "instance.h"
#include "overlay_address.h"
#include "overlay_packet.h"
#include "constants.h"
#include "conf.h"
#include "mem.h"
#include "numeric_str.h"
#include "server.h"

//#define DEBUG_MDP_FILTER_PARSING 1

#define PACKET_RULES_FILE_MAX_SIZE  (32 * 1024)

struct mdp_portrange {
  mdp_port_t port_first;
  mdp_port_t port_last;
};

struct packet_rule {
  struct packet_rule *next;
  struct subscriber *local_subscriber;
  struct subscriber *remote_subscriber;
  struct mdp_portrange local_ports;
  struct mdp_portrange remote_ports;
  uint8_t flags;
};

#define RULE_DROP	  (1<<0)
#define RULE_INBOUND	  (1<<1)
#define RULE_OUTBOUND	  (1<<2)
#define RULE_LOCAL_PORT	  (1<<3)
#define RULE_REMOTE_PORT  (1<<4)

#define alloca_packet_rule(r) strbuf_str(strbuf_append_packet_rule(strbuf_alloca(180), (r)))

static strbuf strbuf_append_mdp_portrange(strbuf sb, const struct mdp_portrange *range)
{
  strbuf_sprintf(sb, ":%"PRImdp_port_t, range->port_first);
  if (range->port_last != range->port_first)
    strbuf_sprintf(sb, "-%"PRImdp_port_t, range->port_last);
  return sb;
}

static strbuf strbuf_append_packet_rule(strbuf sb, const struct packet_rule *rule)
{
  strbuf_puts(sb, rule->flags & RULE_DROP ? "drop " : "allow ");
  if (rule->flags & (RULE_INBOUND | RULE_OUTBOUND)) {
    if (rule->local_subscriber)
      strbuf_puts(sb, alloca_tohex_sid_t(rule->local_subscriber->sid));
    else
      strbuf_putc(sb, '*');
    if (rule->flags & RULE_LOCAL_PORT)
      strbuf_append_mdp_portrange(sb, &rule->local_ports);
    strbuf_putc(sb, ' ');
    if (rule->flags & RULE_INBOUND)
      strbuf_putc(sb, '<');
    if (rule->flags & RULE_OUTBOUND)
      strbuf_putc(sb, '>');
    if (rule->remote_subscriber)
      strbuf_puts(sb, alloca_tohex_sid_t(rule->remote_subscriber->sid));
    else
      strbuf_putc(sb, '*');
    if (rule->flags & RULE_REMOTE_PORT)
      strbuf_append_mdp_portrange(sb, &rule->remote_ports);
  } else
    strbuf_puts(sb, "all");
  return sb;
}

static struct packet_rule *packet_rules = NULL;
static struct file_meta packet_rules_meta = FILE_META_UNKNOWN;

int allow_inbound_packet(const struct internal_mdp_header *header)
{
  const struct packet_rule *rule;
  for (rule = packet_rules; rule; rule = rule->next)
    if (   (   (rule->flags & RULE_INBOUND)
	    && (rule->remote_subscriber == NULL || header->source == rule->remote_subscriber)
	    && (!(rule->flags & RULE_REMOTE_PORT) || (header->source_port >= rule->remote_ports.port_first && header->source_port <= rule->remote_ports.port_last))
	    && (rule->local_subscriber == NULL || header->destination == rule->local_subscriber)
	    && (!(rule->flags & RULE_LOCAL_PORT) || (header->destination_port >= rule->local_ports.port_first && header->destination_port <= rule->local_ports.port_last))
	   )
	|| (rule->flags & (RULE_INBOUND | RULE_OUTBOUND)) == 0
    ) {
      if (rule->flags & RULE_DROP)
	DEBUGF(mdp_filter, "DROP inbound packet source=%s:%"PRImdp_port_t" destination=%s:%"PRImdp_port_t,
	       header->source ? alloca_tohex_sid_t(header->source->sid) : "null",
	       header->source_port,
	       header->destination ? alloca_tohex_sid_t(header->destination->sid) : "null",
	       header->destination_port
	      );
      return rule->flags & RULE_DROP ? 0 : 1;
    }
  return 1; // allow by default
}

int allow_outbound_packet(const struct internal_mdp_header *header)
{
  const struct packet_rule *rule;
  for (rule = packet_rules; rule; rule = rule->next)
    if (   (   (rule->flags & RULE_OUTBOUND)
	    && (rule->remote_subscriber == NULL || header->destination == rule->remote_subscriber)
	    && (!(rule->flags & RULE_REMOTE_PORT) || (header->destination_port >= rule->remote_ports.port_first && header->destination_port <= rule->remote_ports.port_last))
	    && (rule->local_subscriber == NULL || header->source == rule->local_subscriber)
	    && (!(rule->flags & RULE_LOCAL_PORT) || (header->source_port >= rule->local_ports.port_first && header->source_port <= rule->local_ports.port_last))
	   )
	|| (rule->flags & (RULE_INBOUND | RULE_OUTBOUND)) == 0
    ) {
      if (rule->flags & RULE_DROP)
	DEBUGF(mdp_filter, "DROP outbound packet source=%s:%"PRImdp_port_t" destination=%s:%"PRImdp_port_t,
	       header->source ? alloca_tohex_sid_t(header->source->sid) : "null",
	       header->source_port,
	       header->destination ? alloca_tohex_sid_t(header->destination->sid) : "null",
	       header->destination_port
	      );
      return rule->flags & RULE_DROP ? 0 : 1;
    }
  return 1; // allow by default
}

static void free_rule_list(struct packet_rule *rule)
{
  while(rule){
    struct packet_rule *t = rule;
    rule = rule->next;
    free(t);
  }
}

/* Primitives for reading a file input stream with dependable back and ahead buffering so that a
 * parser can make use of primitives that operate on memory buffers instead of FILE*.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */

typedef struct cursor {
  FILE *stream;
  char buffer[1024]; // for pinning and pre-load
  char *end;
  const char *current;
  const char *pin;
  size_t pins;
} *Cursor;

typedef const struct cursor *ConstCursor;

typedef size_t Pin;

#ifndef EOF
#define EOF (-1)
#endif

#ifdef DEBUG_MDP_FILTER_PARSING

#define alloca_cursor_state(c) strbuf_str(strbuf_append_cursor_state(strbuf_alloca(80), c))

static strbuf strbuf_append_cursor_state(strbuf sb, ConstCursor c)
{
  strbuf_sprintf(sb, "{ .current=%u .end=%u .pins=%u", c->current - c->buffer, c->end - c->buffer, c->pins);
  if (c->pin)
    strbuf_sprintf(sb, " .pin=%u", c->pin - c->buffer);
  strbuf_puts(sb, " ");
  strbuf_toprint_quoted_len(sb, "``", c->current, c->end - c->current);
  strbuf_puts(sb, " }");
  return sb;
}

#endif // DEBUG_MDP_FILTER_PARSING

static void init_cursor(Cursor c, FILE *stream)
{
  c->stream = stream;
  c->current = c->end = c->buffer;
  c->pin = NULL;
  c->pins = 0;
}

static inline size_t available(ConstCursor c)
{
  assert(c->current >= c->buffer);
  assert(c->current <= c->end);
  return c->end - c->current;
}

#define preload(c,n) _preload(__WHENCE__,(c),(n))
static inline size_t _preload(struct __sourceloc __whence, Cursor c, size_t n)
{
#ifdef DEBUG_MDP_FILTER_PARSING
  DEBUGF(mdp_filter, "preload(cursor=%s, n=%zu)", alloca_cursor_state(c), n);
#endif
  assert(c->current >= c->buffer);
  assert(c->current <= c->end);
  size_t available = c->end - c->current;
  while (available < n && !feof(c->stream)) {
    size_t space = (c->buffer + sizeof c->buffer) - c->end;
    size_t stale = c->current - c->buffer;
    if (c->pin) {
      assert(c->pin >= c->buffer);
      assert(c->pin <= c->current);
      stale = c->pin - c->buffer;
    }
    size_t ahead = (available + space >= n) ? n - available : (stale == 0) ? space : 0;
    if (ahead) {
      c->end += fread(c->end, 1, ahead, c->stream);
      available = c->end - c->current;
    } else if (stale) {
      assert(c->end >= c->buffer + stale);
      size_t fresh = c->end - c->buffer - stale;
      memmove(c->buffer, c->buffer + stale, fresh);
      if (c->pin) {
	assert(c->pin == c->buffer + stale);
	c->pin = c->buffer;
	c->current -= stale;
      } else {
	assert(c->current == c->buffer + stale);
	c->current = c->buffer;
      }
      c->end -= stale;
    } else {
      WHYF("cannot pre-load %zu bytes, buffer too small", n);
      break;
    }
  }
  return available;
}

#define eof(c) _eof(__WHENCE__,(c))
static inline size_t _eof(struct __sourceloc __whence, Cursor c)
{
  preload(c, 1);
  assert(c->current >= c->buffer);
  assert(c->current <= c->end);
  return c->current == c->end && feof(c->stream);
}

#define peek(c) _peek(__WHENCE__,(c))
static inline char _peek(struct __sourceloc __whence, Cursor c)
{
  if (eof(c))
    return EOF;
  assert(c->current < c->end);
  return *c->current;
}

static inline const char *preloaded(ConstCursor c)
{
  assert(c->current >= c->buffer);
  assert(c->current < c->end);
  return c->current;
}

#define skip(c,t) _skip(__WHENCE__,(c),(t))
static inline char _skip(struct __sourceloc __whence, Cursor c, const char *text)
{
#ifdef DEBUG_MDP_FILTER_PARSING
  DEBUGF(mdp_filter, "skip(cursor=%s, text=%s)", alloca_cursor_state(c), alloca_str_toprint(text));
#endif
  size_t textlen = strlen(text);
  preload(c, textlen);
  if (textlen <= available(c) && str_startswith(c->current, text, &c->current))
    return 1;
  return 0;
}

#define next(c) _next(__WHENCE__,(c))
static inline void _next(struct __sourceloc UNUSED(__whence), Cursor c)
{
#ifdef DEBUG_MDP_FILTER_PARSING
  DEBUGF(mdp_filter, "next(cursor=%s)", alloca_cursor_state(c));
#endif
  assert(c->current >= c->buffer);
  assert(c->current < c->end);
  ++c->current;
}

#define advance_to(c,p) _advance_to(__WHENCE__,(c),(p))
static inline void _advance_to(struct __sourceloc UNUSED(__whence), Cursor c, const char *pos)
{
#ifdef DEBUG_MDP_FILTER_PARSING
  DEBUGF(mdp_filter, "advance_to(cursor=%s, pos=%d)", alloca_cursor_state(c), (int)(pos - c->buffer));
#endif
  assert(pos >= c->current);
  assert(pos <= c->end);
  c->current = pos;
}

#define pin(c) _pin(__WHENCE__,(c))
static inline Pin _pin(struct __sourceloc UNUSED(__whence), Cursor c)
{
#ifdef DEBUG_MDP_FILTER_PARSING
  DEBUGF(mdp_filter, "pin(cursor=%s)", alloca_cursor_state(c));
#endif
  assert(c->current >= c->buffer);
  assert(c->current < c->end);
  if (c->pin)
    assert(c->pin <= c->current);
  else
    c->pin = c->current;
  ++c->pins;
  return c->current - c->pin;
}

#define retreat(c,t) _retreat(__WHENCE__,(c),(t))
static inline void _retreat(struct __sourceloc UNUSED(__whence), Cursor c, Pin p)
{
#ifdef DEBUG_MDP_FILTER_PARSING
  DEBUGF(mdp_filter, "retreat(cursor=%s, p=%zu)", alloca_cursor_state(c), p);
#endif
  assert(c->current >= c->buffer);
  assert(c->current <= c->end);
  assert(c->pins > 0);
  assert(c->pin != NULL);
  assert(c->pin >= c->buffer);
  assert(c->pin <= c->current);
  assert(c->pin + p >= c->buffer);
  assert(c->pin + p <= c->current);
  c->current = c->pin + p;
  if (--c->pins == 0)
    c->pin = NULL;
}

#define unpin(c,t) _unpin(__WHENCE__,(c),(t))
static inline void _unpin(struct __sourceloc UNUSED(__whence), Cursor c, Pin p)
{
#ifdef DEBUG_MDP_FILTER_PARSING
  DEBUGF(mdp_filter, "unpin(cursor=%s, p=%zu)", alloca_cursor_state(c), p);
#endif
  assert(c->current >= c->buffer);
  assert(c->current <= c->end);
  assert(c->pins > 0);
  assert(c->pin != NULL);
  assert(c->pin >= c->buffer);
  assert(c->pin <= c->current);
  assert(c->pin + p >= c->buffer);
  assert(c->pin + p <= c->current);
  if (--c->pins == 0)
    c->pin = NULL;
}

/*
 * rules := optspace [ rule optspace ( sep optspace rule optspace ){0..} ]
 * sep := "\n" | ";"
 * rule := verb space which
 * verb := "allow" | "drop"
 * which := "all" | pattern
 * pattern := [ endpoint optspace ] direction optspace endpoint
 * direction := ">" | "<" | "<>"
 * endpoint := sidany [ optspace ":" optspace portrange ]
 * sidany := "*" | sidhex | "broadcast"
 * sidhex := hexdigit {64}
 * portrange := port optspace [ "-" optspace port ]
 * port := hexport | decport
 * hexport := "0x" hexdigit {1..8}
 * decport := decdigit {1..10}
 * decdigit := "0".."9"
 * hexdigit := decdigit | "A".."F" | "a".."f"
 * optspace := " " {0..}
 * space := " " {1..}
 */

static int _space(Cursor c)
{
  int ret = 0;
  while (peek(c) == ' ') {
    next(c);
    ret = 1;
  }
  return ret;
}

static int _optspace(Cursor c)
{
  _space(c);
  return 1;
}

static int _sep(Cursor c)
{
  if (peek(c) == '\n' || peek(c) == ';') {
    next(c);
    return 1;
  }
  return 0;
}

static int _port(Cursor c, mdp_port_t *portp)
{
  const char *end;
  int r;
  if (skip(c, "0x")) {
    preload(c, 8);
    r = strn_to_uint32(preloaded(c), available(c), 16, portp, &end);
  } else {
    preload(c, 10);
    r = strn_to_uint32(preloaded(c), available(c), 10, portp, &end);
  }
  if (r) {
    advance_to(c, end);
    return 1;
  }
  return 0;
}

static int _portrange(Cursor c, struct mdp_portrange *range)
{
  if (!_port(c, &range->port_first))
    return 0;
  _optspace(c);
  if (peek(c) == '-') {
    next(c);
    _optspace(c);
    if (!_port(c, &range->port_last))
      return 0;
  } else
    range->port_last = range->port_first;
  return 1;
}

static int _endpoint(Cursor c, uint8_t *flagsp, uint8_t port_flag, struct subscriber **subscr, struct mdp_portrange *portrangep)
{
  const char *end;
  sid_t sid;
  preload(c, SID_STRLEN);
  if (skip(c, "*")) {
    *subscr = NULL;
  } else if (parse_sid_t(&sid, preloaded(c), available(c), &end) == 0) {
    if ((*subscr = find_subscriber(sid.binary, sizeof sid.binary, 1)) == NULL)
      return 0;
    advance_to(c, end);
  } else
    return 0;
  _optspace(c);
  if (peek(c) == ':') {
    next(c);
    _optspace(c);
    if (!_portrange(c, portrangep))
      return 0;
    *flagsp |= port_flag;
  }
  return 1;
}

static int _direction(Cursor c, uint8_t *flagsp)
{
  *flagsp &= ~(RULE_INBOUND | RULE_OUTBOUND);
  if (skip(c, "<"))
    *flagsp |= RULE_INBOUND;
  if (skip(c, ">"))
    *flagsp |= RULE_OUTBOUND;
  return *flagsp & (RULE_INBOUND | RULE_OUTBOUND) ? 1 : 0;
}

static int _pattern(Cursor c, struct packet_rule *rule)
{
  Pin p = pin(c);
  if (_endpoint(c, &rule->flags, RULE_LOCAL_PORT, &rule->local_subscriber, &rule->local_ports)) {
    unpin(c, p);
    _optspace(c);
  } else
    retreat(c, p);
  return _direction(c, &rule->flags)
      && _optspace(c)
      && _endpoint(c, &rule->flags, RULE_REMOTE_PORT, &rule->remote_subscriber, &rule->remote_ports);
}

static int _which(Cursor c, struct packet_rule *rule)
{
  return skip(c, "all") || _pattern(c, rule);
}

static int _verb(Cursor c, struct packet_rule *rule)
{
  if (skip(c, "allow"))
    return 1;
  if (skip(c, "drop")) {
    rule->flags |= RULE_DROP;
    return 1;
  }
  return 0;
}

static int _rule(Cursor c, struct packet_rule **rulep)
{
  assert(*rulep == NULL);
  if ((*rulep = emalloc_zero(sizeof(struct packet_rule))) == NULL)
    return -1;
  if (_verb(c, *rulep) && _optspace(c) && _which(c, *rulep))
    return 1;
  free(*rulep);
  *rulep = NULL;
  return 0;
}

static int _rules(Cursor c, struct packet_rule **listp)
{
  assert(*listp == NULL);
  _optspace(c);
  int r;
  if ((r = _rule(c, listp)) == -1)
    return -1;
  _optspace(c);
  if (r) {
    assert(*listp != NULL);
    listp = &(*listp)->next;
    assert(*listp == NULL);
    while (!eof(c) && _sep(c) && !eof(c)) {
      _optspace(c);
      if ((r = _rule(c, listp)) == -1)
	return -1;
      _optspace(c);
      if (!r)
	break;
      assert(*listp != NULL);
      listp = &(*listp)->next;
      assert(*listp == NULL);
    }
  }
  return eof(c);
}

/* Parse the given text as a list of MDP filter rules and return the pointer to the head of the list
 * if successful.  List elements are allocated using malloc(3).  The 'source' and 'destination'
 * subscriber structs are allocated using find_subscriber() for each SID parsed in the rules.  Does
 * not alter the rules currently in force -- use set_mdp_packet_rules() for that.
 *
 * Returns 0 if parsing succeeds, assigning the head of the list of parsed rules to *rulep.  Returns
 * 1 if parsing fails because of malformed text (*rulep is unchanged).  Returns -1 if parsing fails
 * due to system failure (i/o error or out of memory).
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static int parse_mdp_packet_rules(FILE *fp, struct packet_rule **rulep)
{
  struct packet_rule *rules = NULL;
  struct cursor cursor;
  init_cursor(&cursor, fp);
  int r;
  if ((r = _rules(&cursor, &rules)) == 1) {
    *rulep = rules;
    return 0;
  }
  if (r == -1)
    WHY("failure parsing packet filter rules");
  else if (available(&cursor))
    WHYF("malformed packet filter rule at %s", alloca_toprint(30, preloaded(&cursor), available(&cursor)));
  else
    WHYF("malformed packet filter rule at EOF");
  free_rule_list(rules);
  return 1;
}

/* Clear the current packet filter rules, leaving no rules in force.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static void clear_mdp_packet_rules()
{
  free_rule_list(packet_rules);
  packet_rules = NULL;
  DEBUG(mdp_filter, "cleared packet filter rules");
}

/* Replace the current packet filter rules with the given new list of rules.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static void set_mdp_packet_rules(struct packet_rule *rules)
{
  clear_mdp_packet_rules();
  packet_rules = rules;
  if (IF_DEBUG(mdp_filter) && packet_rules) {
    DEBUG(mdp_filter, "set new packet filter rules:");
    const struct packet_rule *rule;
    for (rule = packet_rules; rule; rule = rule->next)
      DEBUGF(mdp_filter, "   %s", alloca_packet_rule(rule));
  }
}

/* Load the packet filter rules from the configured file if the file has changed since last load.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int reload_mdp_packet_rules()
{
  if (!config.mdp.filter_rules_path[0]) {
    if (packet_rules_meta.mtime.tv_sec != -1 && serverMode)
      INFOF("no packet rules file configured");
    clear_mdp_packet_rules();
    packet_rules_meta = FILE_META_UNKNOWN;
    return 0;
  }
  char rules_path[1024];
  if (!FORMF_SERVAL_ETC_PATH(rules_path, "%s", config.mdp.filter_rules_path))
    return -1;
  DEBUGF(mdp_filter, "        file path=%s", alloca_str_toprint(rules_path));
  struct file_meta meta;
  if (get_file_meta(rules_path, &meta) == -1)
    return -1;
  DEBUGF(mdp_filter, "        file meta=%s", alloca_file_meta(&meta));
  DEBUGF(mdp_filter, "packet_rules_meta=%s", alloca_file_meta(&packet_rules_meta));
  if (cmp_file_meta(&meta, &packet_rules_meta) == 0)
    return 0; // no change since last load
  if (packet_rules_meta.mtime.tv_sec != -1 && serverMode)
    INFOF("packet rules file %s -- detected new version", rules_path);
  int ret = 1;
  if (meta.mtime.tv_sec == -1) {
    WARNF("packet rules file %s does not exist -- allowing all packets", rules_path);
    clear_mdp_packet_rules();
  } else if (meta.size > PACKET_RULES_FILE_MAX_SIZE) {
    WHYF("packet rules file %s is too big (%ju bytes exceeds limit %d) -- not loaded", rules_path, (uintmax_t)meta.size, PACKET_RULES_FILE_MAX_SIZE);
    return -1;
  } else if (meta.size <= 0) {
    WARNF("packet rules file %s is zero size -- allowing all packets", rules_path);
    clear_mdp_packet_rules();
  } else {
    FILE *fp = fopen(rules_path, "r");
    if (fp == NULL) {
      WHYF_perror("fopen(%s,\"r\")", alloca_str_toprint(rules_path));
      return WHY("packet rules file not loaded");
    }
    struct packet_rule *new_rules = NULL;
    int r = parse_mdp_packet_rules(fp, &new_rules);
    fclose(fp);
    if (r == 0)
      set_mdp_packet_rules(new_rules);
    else
      ret = -1;
  }
  packet_rules_meta = meta;
  return ret;
}
