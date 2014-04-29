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

#include "serval.h"
#include "overlay_address.h"
#include "overlay_packet.h"
#include "constants.h"
#include "conf.h"
#include "mem.h"
#include "str.h"

//#define DEBUG_MDP_FILTER_PARSING 1

#define PACKET_RULES_FILE_MAX_SIZE  (32 * 1024)

struct packet_rule {
  struct subscriber *source;
  struct subscriber *destination;
  mdp_port_t src_start;
  mdp_port_t src_end;
  mdp_port_t dst_start;
  mdp_port_t dst_end;
  uint8_t flags;
  struct packet_rule *next;
};

#define alloca_packet_rule(r) strbuf_str(strbuf_append_packet_rule(strbuf_alloca(180), (r)))

static strbuf strbuf_append_packet_rule(strbuf sb, const struct packet_rule *rule)
{
  strbuf_puts(sb, rule->flags & RULE_DROP ? "drop " : "allow ");
  size_t pos = strbuf_count(sb);
  if (rule->flags & (RULE_SOURCE | RULE_SRC_PORT))
    strbuf_putc(sb, '<');
  if (rule->flags & RULE_SOURCE)
    strbuf_puts(sb, alloca_tohex_sid_t(rule->source->sid));
  else if (rule->flags & RULE_SRC_PORT)
    strbuf_putc(sb, '*');
  if (rule->flags & RULE_SRC_PORT) {
    strbuf_sprintf(sb, ":%"PRImdp_port_t, rule->src_start);
    if (rule->src_end != rule->src_start)
      strbuf_sprintf(sb, "-%"PRImdp_port_t, rule->src_end);
  }
  if (pos != strbuf_count(sb))
    strbuf_putc(sb, ' ');
  if (rule->flags & (RULE_DESTINATION | RULE_DST_PORT))
    strbuf_putc(sb, '>');
  if (rule->flags & RULE_DESTINATION)
    strbuf_puts(sb, alloca_tohex_sid_t(rule->destination->sid));
  else if (rule->flags & RULE_DST_PORT)
    strbuf_putc(sb, '*');
  if (rule->flags & RULE_DST_PORT) {
    strbuf_sprintf(sb, ":%"PRImdp_port_t, rule->dst_start);
    if (rule->dst_end != rule->dst_start)
      strbuf_sprintf(sb, "-%"PRImdp_port_t, rule->dst_end);
  }
  if (pos == strbuf_count(sb))
    strbuf_puts(sb, "all");
  return sb;
}

static struct packet_rule *packet_rules = NULL;
static struct file_meta packet_rules_meta = FILE_META_UNKNOWN;

static int match_rule(const struct internal_mdp_header *header, const struct packet_rule *rule)
{
#if 0
  if (config.debug.mdp_filter)
    DEBUGF("test packet %s:%"PRImdp_port_t"->%s:%"PRImdp_port_t" on rule: %s",
	header->source ? alloca_tohex_sid_t(header->source->sid) : "null",
	header->source_port,
	header->destination ? alloca_tohex_sid_t(header->destination->sid) : "null",
	header->destination_port,
	alloca_packet_rule(rule)
      );
#endif
  if ((rule->flags & RULE_SOURCE) && header->source != rule->source)
    return 0;
  if ((rule->flags & RULE_DESTINATION) && header->destination != rule->destination)
    return 0;
  if ((rule->flags & RULE_SRC_PORT) && 
      (header->source_port < rule->src_start||header->source_port > rule->src_end))
    return 0;
  if ((rule->flags & RULE_DST_PORT) && 
      (header->destination_port < rule->dst_start||header->destination_port > rule->dst_end))
    return 0;
#if 0
  if (config.debug.mdp_filter)
    DEBUGF("packet matches rule: %s", alloca_packet_rule(rule));
#endif
  return 1;
}

int filter_packet(const struct internal_mdp_header *header)
{
  const struct packet_rule *rule;
  for (rule = packet_rules; rule; rule = rule->next)
    if (match_rule(header, rule)) {
      if ((rule->flags & RULE_DROP) && config.debug.mdp_filter)
	DEBUGF("DROP packet source=%s:%"PRImdp_port_t" destination=%s:%"PRImdp_port_t,
	    header->source ? alloca_tohex_sid_t(header->source->sid) : "null",
	    header->source_port,
	    header->destination ? alloca_tohex_sid_t(header->destination->sid) : "null",
	    header->destination_port
	  );
      return rule->flags & RULE_DROP;
    }
  return RULE_ALLOW;
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
  if (config.debug.mdp_filter)
    DEBUGF("preload(cursor=%s, n=%zu)", alloca_cursor_state(c), n);
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
  assert(c->current >= c->buffer);
  assert(c->current <= c->end);
  if (c->end == c->current)
    preload(c, 1);
  return c->current == c->end && feof(c->stream);
}

static inline char peek(ConstCursor c)
{
  assert(c->current >= c->buffer);
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
  if (config.debug.mdp_filter)
    DEBUGF("skip(cursor=%s, text=%s)", alloca_cursor_state(c), alloca_str_toprint(text));
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
  if (config.debug.mdp_filter)
    DEBUGF("next(cursor=%s)", alloca_cursor_state(c));
#endif
  assert(c->current >= c->buffer);
  assert(c->current < c->end);
  ++c->current;
}

#define advance_to(c,p) _advance_to(__WHENCE__,(c),(p))
static inline void _advance_to(struct __sourceloc UNUSED(__whence), Cursor c, const char *pos)
{
#ifdef DEBUG_MDP_FILTER_PARSING
  if (config.debug.mdp_filter)
    DEBUGF("advance_to(cursor=%s, pos=%d)", alloca_cursor_state(c), (int)(pos - c->buffer));
#endif
  assert(pos >= c->current);
  assert(pos <= c->end);
  c->current = pos;
}

#define pin(c) _pin(__WHENCE__,(c))
static inline Pin _pin(struct __sourceloc UNUSED(__whence), Cursor c)
{
#ifdef DEBUG_MDP_FILTER_PARSING
  if (config.debug.mdp_filter)
    DEBUGF("pin(cursor=%s)", alloca_cursor_state(c));
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
  if (config.debug.mdp_filter)
    DEBUGF("retreat(cursor=%s, p=%zu)", alloca_cursor_state(c), p);
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
  if (config.debug.mdp_filter)
    DEBUGF("unpin(cursor=%s, p=%zu)", alloca_cursor_state(c), p);
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
 * rule := verb space pattern
 * verb := "allow" | "drop"
 * pattern := "all" | srcpat optspace [ dstpat ] | dstpat optspace [ srcpat ]
 * srcpat := "<" optspace endpoint
 * dstpat := ">" optspace endpoint
 * endpoint := [ sid ] [ optspace ":" optspace portrange ]
 * sid := "*" | sidhex | "broadcast"
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
  if (eof(c) || peek(c) != ' ')
    return 0;
  while (!eof(c) && peek(c) == ' ')
    next(c);
  return 1;
}

static int _optspace(Cursor c)
{
  _space(c);
  return 1;
}

static int _sep(Cursor c)
{
  if (!eof(c) && (peek(c) == '\n' || peek(c) == ';')) {
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

static int _portrange(Cursor c, mdp_port_t *port_start, mdp_port_t *port_end)
{
  if (!_port(c, port_start))
    return 0;
  Pin p = pin(c);
  _optspace(c);
  if (!eof(c) && peek(c) == '-') {
    next(c);
    _optspace(c);
    if (!_port(c, port_end)) {
      retreat(c, p);
      return 0;
    }
  } else
    *port_end = *port_start;
  unpin(c, p);
  return 1;
}

static int _endpoint(Cursor c, uint8_t *flagsp, uint8_t sid_flag, uint8_t port_flag, struct subscriber **subscr, mdp_port_t *port_start, mdp_port_t *port_end)
{
  const char *end;
  sid_t sid;
  preload(c, SID_STRLEN);
  if (skip(c, "*")) {
    *subscr = NULL;
  } else if (strn_to_sid_t(&sid, preloaded(c), available(c), &end) == 0) {
    if ((*subscr = find_subscriber(sid.binary, sizeof sid.binary, 1)) == NULL)
      return 0;
    *flagsp |= sid_flag;
    advance_to(c, end);
  } else
    return 0;
  _optspace(c);
  if (!eof(c) && peek(c) == ':') {
    next(c);
    _optspace(c);
    if (!_portrange(c, port_start, port_end))
      return 0;
    *flagsp |= port_flag;
  }
  return 1;
}

static int _srcpat(Cursor c, struct packet_rule *rule)
{
  if (eof(c) || peek(c) != '<')
    return 0;
  next(c);
  _optspace(c);
  return _endpoint(c, &rule->flags, RULE_SOURCE, RULE_SRC_PORT, &rule->source, &rule->src_start, &rule->src_end);
}

static int _dstpat(Cursor c, struct packet_rule *rule)
{
  if (eof(c) || peek(c) != '>')
    return 0;
  next(c);
  _optspace(c);
  return _endpoint(c, &rule->flags, RULE_DESTINATION, RULE_DST_PORT, &rule->destination, &rule->dst_start, &rule->dst_end);
}

static int _pattern(Cursor c, struct packet_rule *rule)
{
  if (eof(c))
    return 0;
  if (skip(c, "all"))
    return 1;
  if (peek(c) == '<')
    return _srcpat(c, rule) && _optspace(c) && (peek(c) == '>' ? _dstpat(c, rule) : 1);
  if (peek(c) == '>')
    return _dstpat(c, rule) && _optspace(c) && (peek(c) == '<' ? _srcpat(c, rule) : 1);
  return 0;
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
  if (_verb(c, *rulep) && _optspace(c) && _pattern(c, *rulep))
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
 * Returns NULL if the parsing fails because of either a malformed text or system failure (out of
 * memory).
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static struct packet_rule *parse_mdp_packet_rules(FILE *fp)
{
  struct packet_rule *rules = NULL;
  struct cursor cursor;
  init_cursor(&cursor, fp);
  int r;
  if ((r = _rules(&cursor, &rules)) == 1)
    return rules;
  if (r == -1)
    WHY("failure parsing packet filter rules");
  else if (available(&cursor))
    WHYF("malformed packet filter rule at %s", alloca_toprint(30, preloaded(&cursor), available(&cursor)));
  else
    WHYF("malformed packet filter rule at EOF");
  free_rule_list(rules);
  return NULL;
}

/* Clear the current packet filter rules, leaving no rules in force.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static void clear_mdp_packet_rules()
{
  free_rule_list(packet_rules);
  packet_rules = NULL;
  if (config.debug.mdp_filter)
    DEBUG("cleared packet filter rules");
}

/* Replace the current packet filter rules with the given new list of rules.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static void set_mdp_packet_rules(struct packet_rule *rules)
{
  clear_mdp_packet_rules();
  packet_rules = rules;
  if (config.debug.mdp_filter && packet_rules) {
    DEBUG("set new packet filter rules:");
    const struct packet_rule *rule;
    for (rule = packet_rules; rule; rule = rule->next)
      DEBUGF("   %s", alloca_packet_rule(rule));
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
  if (config.debug.mdp_filter)
    DEBUGF("        file path=%s", alloca_str_toprint(rules_path));
  struct file_meta meta;
  if (get_file_meta(rules_path, &meta) == -1)
    return -1;
  if (config.debug.mdp_filter) {
    DEBUGF("        file meta=%s", alloca_file_meta(&meta));
    DEBUGF("packet_rules_meta=%s", alloca_file_meta(&packet_rules_meta));
  }
  if (cmp_file_meta(&meta, &packet_rules_meta) == 0)
    return 0; // no change since last load
  if (packet_rules_meta.mtime.tv_sec != -1 && serverMode)
    INFOF("packet rules file %s -- detected new version", rules_path);
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
    struct packet_rule *new_rules = parse_mdp_packet_rules(fp);
    fclose(fp);
    set_mdp_packet_rules(new_rules);
  }
  packet_rules_meta = meta;
  return 1;
}
