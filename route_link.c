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

struct neighbour{
  struct neighbour *_next;

  struct subscriber *subscriber;

  // whenever we hear about a link change, update the version to mark all link path scores as dirty
  char path_version;

  // when do we assume the link is dead because they can't hear us?
  time_ms_t neighbour_link_timeout;
  // which of our interfaces did they hear us from?
  int our_interface;

  // which of their interfaces have we heard them sending from?
  int neighbour_interface;
  char neighbour_version;

  // when will we consider the link broken?
  time_ms_t neighbour_unicast_receive_timeout;
  time_ms_t neighbour_broadcast_receive_timeout;

  // next link update
  time_ms_t next_neighbour_update;

  // un-balanced tree of known link states
  struct link *root;
};

// one struct per subscriber, where we track all routing information, allocated on first use
struct link_state{
  // what is the current best hop count? (via subscriber->next_hop)
  struct subscriber *next_hop;
  struct subscriber *transmitter;
  int hop_count;

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

struct neighbour *neighbours;


static struct link_state *get_link_state(struct subscriber *subscriber)
{
  if (!subscriber->link_state)
    subscriber->link_state = emalloc_zero(sizeof(struct link_state));
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

static struct link *find_link(struct neighbour *neighbour, struct subscriber *receiver)
{
  struct link **link_ptr=&neighbour->root, *link=neighbour->root;
  while(1){
    if (link==NULL){
      link = *link_ptr = emalloc_zero(sizeof(struct link));
      link->receiver = receiver;
      link->path_version = neighbour->path_version -1;
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
    link->parent = find_link(neighbour, link->transmitter);

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

  link->hop_count = hop_count;
  link->path_version = neighbour->path_version;
  link->calculating = 0;
}

static int find_best_link(struct subscriber *subscriber, struct neighbour **best_neighbour, struct link **best_link)
{
  struct link_state *state = get_link_state(subscriber);
  struct neighbour *neighbour = neighbours;
  int best_hop_count = 99;
  struct subscriber *next_hop = NULL, *transmitter=NULL;
  time_ms_t now = gettime_ms();

  while (neighbour){
    struct link *link = find_link(neighbour, subscriber);
    if (neighbour->neighbour_link_timeout >= now){
      update_path_score(neighbour, link);
      if (link->hop_count>0 && link->hop_count < best_hop_count){
        next_hop = neighbour->subscriber;
        best_hop_count = link->hop_count;
	transmitter = link->transmitter;
	if (best_link)
	  *best_link = link;
	if (best_neighbour)
	  *best_neighbour = neighbour;
      }
    }
    neighbour = neighbour->_next;
  }

  if (state->next_hop != next_hop || state->transmitter != transmitter){
    if (config.debug.linkstate)
      DEBUGF("LINK STATE; next hop for %s is now %s", alloca_tohex_sid(subscriber->sid), next_hop?alloca_tohex_sid(next_hop->sid):"UNREACHABLE");
    state->next_update = now;
  }

  state->next_hop = next_hop;
  state->transmitter = transmitter;
  state->hop_count = best_hop_count;

  return 0;
}

static int append_link_state(struct overlay_buffer *payload, char flags, struct subscriber *transmitter, struct subscriber *receiver, int interface, int version){
  if (interface!=-1)
    flags|=FLAG_HAS_INTERFACE;
  if (!transmitter)
    flags|=FLAG_NO_PATH;

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

  struct link *link = NULL;
  find_best_link(subscriber, NULL, &link);

  if (state->next_update - INCLUDE_ANYWAY <= now){
    if (subscriber->reachable==REACHABLE_SELF){
      // Other entries in our keyring are always one hop away from us.
      if (append_link_state(payload, 0, my_subscriber, subscriber, -1, 0)){
        link_send_alarm.alarm = now;
        return 1;
      }
    } else {

      if (append_link_state(payload, 0, link?link->transmitter:NULL, subscriber, -1, 0)){
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

static int link_send_neighbours(struct overlay_buffer *payload){
  struct neighbour **n_ptr = &neighbours;
  time_ms_t now = gettime_ms();

  while (*n_ptr){
    struct neighbour *n = *n_ptr;
    if (n->neighbour_unicast_receive_timeout <now && n->neighbour_broadcast_receive_timeout < now){
      // If we haven't heard any packets from this neighbour, free the struct as we go.
      if (config.debug.linkstate)
        DEBUGF("LINK STATE; neighbour connection timed out %s", alloca_tohex_sid(n->subscriber->sid));
      free_links(n->root);
      n->root=NULL;
      *n_ptr = n->_next;
      free(n);
    }else{
      char flags=0;
      if (n->neighbour_unicast_receive_timeout >= now)
        flags|=FLAG_UNICAST;
      if (n->neighbour_broadcast_receive_timeout >= now)
        flags|=FLAG_BROADCAST;

      if (n->next_neighbour_update - INCLUDE_ANYWAY <= now){
        if (append_link_state(payload, flags, n->subscriber, my_subscriber, n->neighbour_interface, n->neighbour_version)){
          link_send_alarm.alarm = now;
	  return 1;
        }
        n->next_neighbour_update = now + LINK_NEIGHBOUR_INTERVAL;
      }
      if (n->next_neighbour_update < link_send_alarm.alarm)
        link_send_alarm.alarm = n->next_neighbour_update;

      n_ptr = &(n->_next);
    }
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

  if (link_send_neighbours(frame->payload)==0)
    enum_subscribers(NULL, append_link, frame->payload);

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

// track stats for receiving packets from this neighbour
int link_received_packet(struct subscriber *subscriber, int sender_interface, int sender_seq, int unicast)
{
  struct neighbour *n = get_neighbour(subscriber, 1);
  time_ms_t now = gettime_ms();

  // force an update when we start hearing a new neighbour link
  if (unicast){
    if (n->neighbour_unicast_receive_timeout < now){
      n->next_neighbour_update = now;
      n->neighbour_version++;
      update_alarm(now);
    }
    n->neighbour_unicast_receive_timeout = now + LINK_EXPIRY;
  }else{
    if (n->neighbour_broadcast_receive_timeout < now){
      n->next_neighbour_update = now;
      n->neighbour_version++;
      update_alarm(now);
    }
    n->neighbour_broadcast_receive_timeout = now + LINK_EXPIRY;
  }
  // TODO track each sender interface independently?
  n->neighbour_interface = sender_interface;
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
    int interface = -1;
    if (flags & FLAG_HAS_INTERFACE){
      interface = ob_get(payload);
      if (interface < 0)
        break;
    }

    if (context.invalid_addresses)
      continue;

    // ignore any links that our neighbour is using to route through us.
    if (receiver == my_subscriber)
      continue;
    if (receiver == sender){
      // who can our neighbour hear?

      // TODO build a map of everyone in our 2 hop neighbourhood to control broadcast flooding?

      if (transmitter == my_subscriber){
        // they can hear us? we can route through them!

	if (neighbour->neighbour_link_timeout < now){
	  if (config.debug.linkstate)
	    DEBUGF("LINK STATE; neighbour is now routable - %s", alloca_tohex_sid(receiver->sid));
	  changed = 1;
	}
	neighbour->neighbour_link_timeout = now + LINK_INTERVAL;
      }else
        continue;
    }

    struct link *link = find_link(neighbour, receiver);
    if (link->transmitter != transmitter || link->link_version != version){
      changed = 1;
      link->transmitter = transmitter;
      link->link_version = version;
      // TODO other link attributes...
    }
  }

  send_please_explain(&context, my_subscriber, sender);

  if (changed){
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

