#include "serval.h"
#include "overlay_address.h"
#include "overlay_buffer.h"
#include "overlay_packet.h"
#include "str.h"
#include "conf.h"

/*
Link state routing;

- each node sends a packet on a heartbeat
- on recieving a packet, update a link cost calculation (initially up/down only)
- when the cost changes, update a version field
- every heartbeat interval, send link cost details
  - send link cost for every neighbour, they need to know we can still hear them.
- after parsing incoming link details, if anything has changed, mark routes as dirty

*/

#define INCLUDE_ANYWAY (500)
#define LINK_EXPIRY (5000)
#define LINK_NEIGHBOUR_INTERVAL (1000)
#define LINK_INTERVAL (5000)
#define MAX_LINK_STATES 512

#define FLAG_HAS_INTERFACE (1<<0)
#define FLAG_NO_PATH (1<<1)
#define FLAG_BROADCAST (1<<2)
#define FLAG_UNICAST (1<<3)

struct link{
  struct link *_left;
  struct link *_right;

  struct subscriber *transmitter;
  struct link *parent;
  struct overlay_interface *interface;
  struct subscriber *receiver;

  // neighbour path version when path scores were last updated
  char path_version;

  // link quality stats;
  char link_version;

  // calculated path score;
  int hop_count;

  // loop prevention;
  char calculating;
};

struct neighbour_link{
  struct neighbour_link *_next;

  // which of their interfaces are these stats for?
  int neighbour_interface;
  // which interface did we hear it on?
  struct overlay_interface *interface;

  // very simple time based link up/down detection;
  // when will we consider the link broken?
  time_ms_t neighbour_unicast_receive_timeout;
  time_ms_t neighbour_broadcast_receive_timeout;
};

struct neighbour{
  struct neighbour *_next;

  struct subscriber *subscriber;

  // whenever we hear about a link change, update the version to mark all link path scores as dirty
  char path_version;

  // when do we assume the link is dead because they stopped hearing us or vice versa?
  time_ms_t neighbour_link_timeout;

  // next link update
  time_ms_t next_neighbour_update;

  // un-balanced tree of known link states
  struct link *root;

  // list of incoming link stats
  struct neighbour_link *links, *best_link;

  // whenever we pick a different link or the stats change in a way everyone needs to know ASAP, update the version
  char version;
};

// one struct per subscriber, where we track all routing information, allocated on first use
struct link_state{
  // what is the current best hop count? (via subscriber->next_hop)
  struct subscriber *next_hop;
  struct subscriber *transmitter;
  int hop_count;
  int route_version;
  char calculating;

  // when do we need to send a new link state message.
  time_ms_t next_update;
};

static void link_send(struct sched_ent *alarm);

static struct profile_total link_send_stats={
  .name="link_send",
};
static struct sched_ent link_send_alarm={
  .function = link_send,
  .stats = &link_send_stats,
};

struct neighbour *neighbours=NULL;
int route_version=0;

static struct link_state *get_link_state(struct subscriber *subscriber)
{
  if (!subscriber->link_state){
    subscriber->link_state = emalloc_zero(sizeof(struct link_state));
    subscriber->link_state->route_version = route_version -1;
  }
  return subscriber->link_state;
}

static struct neighbour *get_neighbour(struct subscriber *subscriber, char create)
{
  struct neighbour *n = neighbours;
  while(n){
    if (n->subscriber==subscriber)
      return n;
    n = n->_next;
  }
  if (create){
    n = emalloc_zero(sizeof(struct neighbour));
    n->subscriber = subscriber;
    n->_next = neighbours;
    neighbours = n;
    if (config.debug.linkstate)
      DEBUGF("LINK STATE; new neighbour %s", alloca_tohex_sid(n->subscriber->sid));
  }
  return n;
}

static void free_links(struct link *link)
{
  if (!link)
    return;
  free_links(link->_left);
  link->_left=NULL;
  free_links(link->_right);
  link->_right=NULL;
  free(link);
}

static struct link *find_link(struct neighbour *neighbour, struct subscriber *receiver, char create)
{
  struct link **link_ptr=&neighbour->root, *link=neighbour->root;
  while(1){
    if (link==NULL){
      if (create){
        link = *link_ptr = emalloc_zero(sizeof(struct link));
        link->receiver = receiver;
        link->path_version = neighbour->path_version -1;
      }
      break;
    }
    if (receiver == link->receiver)
      break;
    if (memcmp(receiver->sid, link->receiver->sid, SID_SIZE)<0){
      link_ptr = &link->_left;
    }else{
      link_ptr = &link->_right;
    }
    link = *link_ptr;
  }
  return link;
}

static struct link *get_parent(struct neighbour *neighbour, struct link *link)
{
  // root of the routing table.
  if (link->receiver == neighbour->subscriber || link->transmitter == NULL)
    return NULL;

  if (!link->parent)
    link->parent = find_link(neighbour, link->transmitter, 0);

  return link->parent;
}

static void update_path_score(struct neighbour *neighbour, struct link *link){
  if (link->path_version == neighbour->path_version)
    return;
  if (link->calculating)
    return;

  link->calculating = 1;
  int hop_count = -1;

  if (link->transmitter == my_subscriber){
    if (link->receiver==neighbour->subscriber)
      hop_count = 1;
  }else{
    struct link *parent = get_parent(neighbour, link);
    if (parent && (!parent->calculating)){
      update_path_score(neighbour, parent);
      // TODO more interesting path cost metrics...
      if (parent->hop_count>0)
        hop_count = parent->hop_count+1;
    }
  }

  if (config.debug.verbose && config.debug.linkstate && hop_count != link->hop_count)
    DEBUGF("LINK STATE; path score to %s via %s version %d = %d",
	alloca_tohex_sid(link->receiver->sid),
	alloca_tohex_sid(neighbour->subscriber->sid),
	neighbour->path_version,
	hop_count);

  link->hop_count = hop_count;
  link->path_version = neighbour->path_version;
  link->calculating = 0;
}

static int find_best_link(struct subscriber *subscriber)
{
  if (subscriber->reachable==REACHABLE_SELF)
    return 0;

  struct link_state *state = get_link_state(subscriber);
  if (state->route_version == route_version)
    return 0;

  if (state->calculating)
    return -1;
  state->calculating = 1;

  struct neighbour *neighbour = neighbours;
  struct overlay_interface *interface = NULL;
  int best_hop_count = 99;
  struct subscriber *next_hop = NULL, *transmitter=NULL;
  time_ms_t now = gettime_ms();

  while (neighbour){
    if (neighbour->neighbour_link_timeout < now)
      goto next;

    struct link *link = find_link(neighbour, subscriber, 0);
    if (!(link && link->transmitter))
      goto next;

    if (link->transmitter != my_subscriber){
      struct link_state *parent_state = get_link_state(link->transmitter);
      find_best_link(link->transmitter);
      if (parent_state->next_hop != neighbour->subscriber)
	goto next;
    }

    update_path_score(neighbour, link);
    if (link->hop_count>0 && link->hop_count < best_hop_count){
      next_hop = neighbour->subscriber;
      best_hop_count = link->hop_count;
      transmitter = link->transmitter;
      interface = link->interface;
    }

next:
    neighbour = neighbour->_next;
  }

  int changed =0;
  if (state->next_hop != next_hop || state->transmitter != transmitter)
    changed = 1;
  if (next_hop == subscriber && (interface != subscriber->interface))
    changed = 1;

  if (changed){
    if (config.debug.linkstate){
      if (next_hop == subscriber){
	DEBUGF("LINK STATE; neighbour %s is reachable on interface %s",
	  alloca_tohex_sid(subscriber->sid), 
	  interface->name);
      } else {
        DEBUGF("LINK STATE; next hop for %s is now %d hops, %s via %s", 
	  alloca_tohex_sid(subscriber->sid), 
	  best_hop_count,
	  next_hop?alloca_tohex_sid(next_hop->sid):"UNREACHABLE", 
	  transmitter?alloca_tohex_sid(transmitter->sid):"NONE");
      }
    }
    state->next_update = now;
  }

  state->next_hop = next_hop;
  state->transmitter = transmitter;
  state->hop_count = best_hop_count;
  state->route_version = route_version;
  state->calculating = 0;

  int reachable = subscriber->reachable;
  if (next_hop == NULL){
    if (!(subscriber->reachable & REACHABLE_ASSUMED))
      reachable = REACHABLE_NONE;
  } else if (next_hop == subscriber){
    reachable = REACHABLE_BROADCAST | (subscriber->reachable & REACHABLE_UNICAST);
    subscriber->interface = interface;
  } else {
    reachable = REACHABLE_INDIRECT;
  }
  subscriber->next_hop = next_hop;
  set_reachable(subscriber, reachable);

  return 0;
}

static int append_link_state(struct overlay_buffer *payload, char flags, struct subscriber *transmitter, struct subscriber *receiver, int interface, int version){
  if (interface!=-1)
    flags|=FLAG_HAS_INTERFACE;
  if (!transmitter)
    flags|=FLAG_NO_PATH;

  int length_pos = ob_position(payload);
  if (ob_append_byte(payload, 0))
    return -1;

  if (ob_append_byte(payload, flags))
    return -1;

  if (overlay_address_append(NULL, payload, receiver))
    return -1;

  if (ob_append_byte(payload, version))
    return -1;

  if (transmitter)
    if (overlay_address_append(NULL, payload, transmitter))
      return -1;

  if (interface!=-1)
    if (ob_append_byte(payload, interface))
      return -1;

  // TODO insert future fields here


  // patch the record length
  int end_pos = ob_position(payload);
  if (ob_set(payload, length_pos, end_pos - length_pos))
    return -1;

  ob_checkpoint(payload);
  return 0;
}

static int append_link(struct subscriber *subscriber, void *context)
{
  if (subscriber == my_subscriber)
    return 0;

  struct overlay_buffer *payload = context;
  struct link_state *state = get_link_state(subscriber);

  time_ms_t now = gettime_ms();

  find_best_link(subscriber);

  if (state->next_update - INCLUDE_ANYWAY <= now){
    if (subscriber->reachable==REACHABLE_SELF){
      // Other entries in our keyring are always one hop away from us.
      if (append_link_state(payload, 0, my_subscriber, subscriber, -1, 0)){
        link_send_alarm.alarm = now;
        return 1;
      }
    } else {

      if (append_link_state(payload, 0, state->transmitter, subscriber, -1, 0)){
        link_send_alarm.alarm = now;
        return 1;
      }
    }
    state->next_update = now + LINK_INTERVAL;
  }

  if (state->next_update < link_send_alarm.alarm)
    link_send_alarm.alarm = state->next_update;

  return 0;
}

static void free_neighbour(struct neighbour **neighbour_ptr){
  struct neighbour *n = *neighbour_ptr;
  if (config.debug.linkstate && config.debug.verbose)
    DEBUGF("LINK STATE; all links from neighbour %s have died", alloca_tohex_sid(n->subscriber->sid));

  struct neighbour_link *link = n->links;
  while(link){
    struct neighbour_link *l=link;
    link = l->_next;
    free(l);
  }

  free_links(n->root);
  n->root=NULL;
  *neighbour_ptr = n->_next;
  free(n);
  route_version++;
}

static void clean_neighbours(time_ms_t now)
{
  struct neighbour **n_ptr = &neighbours;
  while (*n_ptr){
    struct neighbour *n = *n_ptr;
    struct neighbour_link **list = &n->links;
    while(*list){
      struct neighbour_link *link = *list;
      if (link->interface->state!=INTERFACE_STATE_UP ||
	  (link->neighbour_unicast_receive_timeout < now && link->neighbour_broadcast_receive_timeout < now)){
        if (config.debug.linkstate && config.debug.verbose)
          DEBUGF("LINK STATE; link expired from neighbour %s on interface %s", 
            alloca_tohex_sid(n->subscriber->sid),
            link->interface->name);
        *list=link->_next;
        free(link);
      }else{
        list = &link->_next;
      }
    }
    if (!n->links){
      free_neighbour(n_ptr);
    }else{
      n_ptr = &n->_next;
    }
  }
}

static int link_send_neighbours(struct overlay_buffer *payload)
{
  time_ms_t now = gettime_ms();
  clean_neighbours(now);
  struct neighbour *n = neighbours;

  while (n){
    // TODO compare other link stats to find the best...
    struct neighbour_link *best_link=n->links;
    if (best_link){
      struct neighbour_link *link=best_link->_next;
      while(link){
        if (link->interface != best_link->interface &&
	  overlay_interface_compare(best_link->interface, link->interface))
	  best_link = link;
        link = link->_next;
      }
    }

    if (n->best_link != best_link){
      n->best_link = best_link;
      n->version ++;
      n->next_neighbour_update = now;
      if (config.debug.linkstate && config.debug.verbose)
        DEBUGF("LINK STATE; best link from neighbour %s is now on interface %s", 
          alloca_tohex_sid(n->subscriber->sid),
          best_link?best_link->interface->name:"NONE");
    }

    char flags=0;
    if (best_link->neighbour_unicast_receive_timeout >= now)
      flags|=FLAG_UNICAST;
    if (best_link->neighbour_broadcast_receive_timeout >= now)
      flags|=FLAG_BROADCAST;

    if (n->next_neighbour_update - INCLUDE_ANYWAY <= now){
      if (append_link_state(payload, flags, n->subscriber, my_subscriber, best_link->neighbour_interface, n->version)){
        link_send_alarm.alarm = now;
	return 1;
      }
      n->next_neighbour_update = now + best_link->interface->tick_ms;
    }

    if (n->next_neighbour_update < link_send_alarm.alarm)
      link_send_alarm.alarm = n->next_neighbour_update;

    n = n->_next;
  }
  return 0;
}

// send link details
static void link_send(struct sched_ent *alarm)
{
  alarm->alarm=gettime_ms() + LINK_INTERVAL;

  struct overlay_frame *frame=emalloc_zero(sizeof(struct overlay_frame));
  frame->type=OF_TYPE_DATA;
  frame->source=my_subscriber;
  frame->ttl=1;
  frame->queue=OQ_MESH_MANAGEMENT;
  frame->payload = ob_new();
  ob_limitsize(frame->payload, 400);

  overlay_mdp_encode_ports(frame->payload, MDP_PORT_LINKSTATE, MDP_PORT_LINKSTATE);
  ob_checkpoint(frame->payload);
  int pos = ob_position(frame->payload);

  if (link_send_neighbours(frame->payload)==0){
    enum_subscribers(NULL, append_link, frame->payload);
  }

  ob_rewind(frame->payload);

  if (ob_position(frame->payload) == pos)
    op_free(frame);
  else if (overlay_payload_enqueue(frame))
    op_free(frame);

  schedule(alarm);
}

static void update_alarm(time_ms_t limit){
  if (link_send_alarm.alarm>limit || link_send_alarm.alarm==0){
    unschedule(&link_send_alarm);
    link_send_alarm.alarm=limit;
    schedule(&link_send_alarm);
  }
}

struct neighbour_link * get_neighbour_link(struct neighbour *neighbour, struct overlay_interface *interface, int sender_interface)
{
  struct neighbour_link *link = neighbour->links;
  while(link){
    if (link->interface == interface && link->neighbour_interface == sender_interface)
      return link;
    link=link->_next;
  }
  link = emalloc_zero(sizeof(struct neighbour_link));
  link->interface = interface;
  link->neighbour_interface = sender_interface;
  link->_next = neighbour->links;
  if (config.debug.linkstate && config.debug.verbose)
    DEBUGF("LINK STATE; new possible link from neighbour %s on interface %s/%d", 
      alloca_tohex_sid(neighbour->subscriber->sid),
      interface->name,
      sender_interface);
  neighbour->links = link;
  return link;
}

// track stats for receiving packets from this neighbour
int link_received_packet(struct subscriber *subscriber, struct overlay_interface *interface, int sender_interface, int sender_seq, int unicast)
{
  // TODO better handling of unicast routes
  if (unicast)
    return 0;

  struct neighbour *neighbour = get_neighbour(subscriber, 1);
  struct neighbour_link *link=get_neighbour_link(neighbour, interface, sender_interface);
  time_ms_t now = gettime_ms();

  // for now we'll use a simple time based link up/down flag
  // force an update when we start hearing a new neighbour link
  if (unicast){
    if (link->neighbour_unicast_receive_timeout < now){
      neighbour->next_neighbour_update = now;
      neighbour->version++;
      update_alarm(now);
    }
    link->neighbour_unicast_receive_timeout = now + LINK_EXPIRY;
  }else{
    if (link->neighbour_broadcast_receive_timeout < now){
      neighbour->next_neighbour_update = now;
      neighbour->version++;
      update_alarm(now);
    }
    link->neighbour_broadcast_receive_timeout = now + (interface->tick_ms * 3);
  }
  return 0;
}

// parse incoming link details
int link_receive(overlay_mdp_frame *mdp)
{
  struct overlay_buffer *payload = ob_static(mdp->out.payload, mdp->out.payload_length);
  ob_limitsize(payload, mdp->out.payload_length);

  struct subscriber *sender = find_subscriber(mdp->out.src.sid, SID_SIZE, 0);
  struct neighbour *neighbour = get_neighbour(sender, 1);

  struct decode_context context;
  bzero(&context, sizeof(context));
  time_ms_t now = gettime_ms();
  char changed = 0;

  while(ob_remaining(payload)>0){
    context.invalid_addresses=0;

    struct subscriber *receiver=NULL, *transmitter=NULL;
    struct overlay_interface *interface = NULL;
    int start_pos = ob_position(payload);
    int length = ob_get(payload);
    if (length <=0)
      break;

    int flags = ob_get(payload);
    if (flags<0)
      break;
    if (overlay_address_parse(&context, payload, &receiver))
      break;
    int version = ob_get(payload);
    if (version < 0)
      break;
    if (!(flags & FLAG_NO_PATH)){
      if (overlay_address_parse(&context, payload, &transmitter))
        break;
    }
    int interface_id = -1;
    if (flags & FLAG_HAS_INTERFACE){
      interface_id = ob_get(payload);
      if (interface_id < 0)
        break;
      if (interface_id >= OVERLAY_MAX_INTERFACES)
	continue;
    }

    // jump to the position of the next record, even if there's more data we don't understand
    payload->position = start_pos + length;

    if (context.invalid_addresses)
      continue;

    // ignore any links that our neighbour is using to route through us.
    if (receiver == my_subscriber)
      continue;

    if (receiver == sender){
      // who can our neighbour hear?

      // TODO build a map of everyone in our 2 hop neighbourhood to control broadcast flooding?

      if (transmitter == my_subscriber && interface_id != -1){
        // they can hear us? we can route through them!
	interface = &overlay_interfaces[interface_id];
	if (interface->state != INTERFACE_STATE_UP)
	  continue;

	if (neighbour->neighbour_link_timeout < now)
	  changed = 1;

	neighbour->neighbour_link_timeout = now + LINK_INTERVAL;
      }else
        continue;
    }else if(transmitter == my_subscriber)
      transmitter = NULL;

    struct link *link = find_link(neighbour, receiver, transmitter?1:0);
    if (link && (link->transmitter != transmitter || link->link_version != version)){
      changed = 1;
      link->transmitter = transmitter;
      link->link_version = version;
      link->interface = interface;
      // TODO other link attributes...
    }
  }

  send_please_explain(&context, my_subscriber, sender);

  if (changed){
    route_version++;
    neighbour->path_version ++;
    if (link_send_alarm.alarm>now || link_send_alarm.alarm==0){
      unschedule(&link_send_alarm);
      link_send_alarm.alarm=now;
      schedule(&link_send_alarm);
    }
  }

  return 0;
}

// if a neighbour asks for a subscriber explaination, make sure we repeat relevant link information immediately.
void link_explained(struct subscriber *subscriber)
{
  time_ms_t now = gettime_ms();
  struct link_state *state = get_link_state(subscriber);
  state->next_update = now;
  update_alarm(now);
}

void link_interface_down(struct overlay_interface *interface)
{
  clean_neighbours(gettime_ms());
}
