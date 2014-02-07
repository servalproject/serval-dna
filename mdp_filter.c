
#include "serval.h"
#include "overlay_address.h"
#include "overlay_packet.h"
#include "constants.h"
#include "conf.h"

#define RULE_ALLOW 0
#define RULE_DROP (1<<0)
#define RULE_SOURCE (1<<1)
#define RULE_DESTINATION (1<<2)
#define RULE_SRC_PORT (1<<3)
#define RULE_DST_PORT (1<<4)

struct packet_rule{
  struct subscriber *source;
  struct subscriber *destination;
  mdp_port_t src_start;
  mdp_port_t src_end;
  mdp_port_t dst_start;
  mdp_port_t dst_end;
  uint8_t flags;
  struct packet_rule *next;
};
struct packet_rule *global_rules = NULL;

static int match_rule(struct internal_mdp_header *header, struct packet_rule *rule)
{
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
  if (config.debug.mdprequests)
    DEBUGF("Packet matches %s rule, flags:%s%s%s%s", 
      rule->flags & RULE_DROP ? "DROP" : "ALLOW",
      rule->flags & RULE_SOURCE ? " SOURCE" : "",
      rule->flags & RULE_DESTINATION ? " DESTINATION" : "",
      rule->flags & RULE_SRC_PORT? " SOURCE_PORT" : "",
      rule->flags & RULE_DST_PORT ? " DESTINATION_PORT" : "");
  return 1;
}

int allow_incoming_packet(struct internal_mdp_header *header)
{
  struct packet_rule *rule = header->source->source_rules;
  while(rule){
    if (match_rule(header, rule))
      return rule->flags & RULE_DROP;
    rule = rule->next;
  }
  rule = global_rules;
  while(rule){
    if (match_rule(header, rule))
      return rule->flags & RULE_DROP;
    rule = rule->next;
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

static int drop_rule(struct subscriber *subscriber, void *UNUSED(context))
{
  free_rule_list(subscriber->source_rules);
  subscriber->source_rules=NULL;
  return 0;
}

void load_mdp_packet_rules(const char *UNUSED(filename))
{
  // drop all existing rules
  free_rule_list(global_rules);
  global_rules=NULL;
  enum_subscribers(NULL, drop_rule, NULL);
  
  // TODO parse config [file]?
  
  /* 
   * Rule format?
   * one line per rule, name value pairs for parameters?
   * eg;
   * 
   * DROP,source=FF...,destination_port=00[-99]
   * DROP,destination=broadcast
   * ALLOW
   * 
   * */
}

