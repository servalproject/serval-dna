#include "serval.h"
#include "overlay_address.h"
#include "overlay_buffer.h"
#include "overlay_packet.h"
#include "str.h"
#include "conf.h"
#include <assert.h>

/*
Link state routing;

- each node sends a packet on a heartbeat
- on recieving a packet, update a link cost calculation (initially up/down only)
- when the cost changes, update a version field
- every heartbeat interval, send link cost details
  - send link cost for every neighbour, they need to know we can still hear them.
- after parsing incoming link details, if anything has changed, mark routes as dirty

*/

#define INCLUDE_ANYWAY (200)
#define MAX_LINK_STATES 512

#define FLAG_HAS_INTERFACE (1<<0)
#define FLAG_NO_PATH (1<<1)
#define FLAG_BROADCAST (1<<2)
#define FLAG_UNICAST (1<<3)
#define FLAG_HAS_ACK (1<<4)
#define FLAG_HAS_DROP_RATE (1<<5)

#define ACK_WINDOW (16)

struct link{
  struct link *_left;
  struct link *_right;

  struct subscriber *transmitter;
  struct link *parent;
  struct network_destination *destination;
  struct subscriber *receiver;

  // What's the last ack we've heard so we don't process nacks twice.
  int last_ack_seq;

  // neighbour path version when path scores were last updated
  char path_version;

  // link quality stats;
  char link_version;
  char drop_rate;

  // calculated path score;
  int hop_count;
  int path_drop_rate;

  // loop prevention;
  char calculating;
};

// statistics of incoming half of network links
struct link_in{
  struct link_in *_next;

  // which of our interfaces did we hear it on?
  overlay_interface *interface;
  
  // which of their interfaces did they send it from?
  int neighbour_interface;

  // very simple time based link up/down detection;
  // when will we consider the link broken?
  time_ms_t link_timeout;

  // unicast or broadcast?
  char unicast;
  
  int ack_sequence;
  uint64_t ack_mask;
  int ack_counter;
};

struct link_out{
  struct link_out *_next;
  time_ms_t timeout;
  struct network_destination *destination;
};

struct neighbour{
  struct neighbour *_next;

  struct subscriber *subscriber;

  // whenever we hear about a link change, update the version to mark all link path scores as dirty
  char path_version;

  // when do we assume the link is dead because they stopped hearing us or vice versa?
  time_ms_t link_in_timeout;

  // if a neighbour is telling the world that they are using us as a next hop, we need to send acks & nacks with high priority
  // otherwise we don't care too much about packet loss.
  char using_us;

  // is this neighbour still sending selfacks?
  char legacy_protocol;
  
  // when a neighbour is using us as a next hop *and* they are using us to send packets to one of our neighbours, 
  // we must forward their broadcasts
  time_ms_t routing_through_us;

  // which of their mdp packets have we already heard and can be dropped as duplicates?
  int mdp_ack_sequence;
  uint64_t mdp_ack_mask;

  // next link update
  time_ms_t next_neighbour_update;
  time_ms_t last_update;
  int last_update_seq;
  time_ms_t rtt;

  // un-balanced tree of known link states
  struct link *root;

  // list of incoming link stats
  struct link_in *links, *best_link;
  
  // list of outgoing links
  struct link_out *out_links;
};

// one struct per subscriber, where we track all routing information, allocated on first use
struct link_state{
  // what is the current best hop count? (via subscriber->next_hop)
  struct subscriber *next_hop;
  struct subscriber *transmitter;
  int hop_count;
  int route_version;
  // if a neighbour is free'd this link will point to invalid memory.
  // don't use this pointer directly, call find_best_link instead
  struct link *link;
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

struct network_destination * new_destination(struct overlay_interface *interface, char encapsulation){
  assert(interface);
  struct network_destination *ret = emalloc_zero(sizeof(struct network_destination));
  if (ret){
    ret->_ref_count=1;
    ret->encapsulation = encapsulation;
    ret->interface = interface;
//    DEBUGF("Create ref %p, %d - %s", ret, ret->_ref_count, ret->interface->name);
  }
  return ret;
}

struct network_destination * create_unicast_destination(struct sockaddr_in addr, struct overlay_interface *interface){
  if (!interface)
    interface = overlay_interface_find(addr.sin_addr, 1);
  if (!interface){
    WHY("I don't know which interface to use");
    return NULL;
  }
  if (interface->state!=INTERFACE_STATE_UP){
    WHY("The interface is down.");
    return NULL;
  }
  if (addr.sin_addr.s_addr==0 || addr.sin_port==0){
//    WHY("Invalid unicast address");
    return NULL;
  }
  
  struct network_destination *ret = new_destination(interface, ENCAP_OVERLAY);
  if (ret){
    ret->address = addr;
    ret->unicast = 1;
    ret->tick_ms = interface->destination->tick_ms;
    ret->sequence_number = -1;
  }
  return ret;
}

struct network_destination * add_destination_ref(struct network_destination *ref){
  ref->_ref_count++;
//  DEBUGF("Add ref %p, %d - %s", ref, ref->_ref_count, ref->interface->name);
  return ref;
}

void release_destination_ref(struct network_destination *ref){
  if (ref->_ref_count<=1){
//    DEBUGF("Free ref %p, %d - %s", ref, ref->_ref_count, ref->interface->name);
    free(ref);
  }else{
    ref->_ref_count--;
//    DEBUGF("Drop ref %p, %d - %s", ref, ref->_ref_count, ref->interface->name);
  }
}

int set_destination_ref(struct network_destination **ptr, struct network_destination *ref){
  if (ref==*ptr)
    return 0;
  if (ref)
    add_destination_ref(ref);
  if (*ptr)
    release_destination_ref(*ptr);
  *ptr = ref;
  return 1;
}

static int NumberOfSetBits(uint32_t i)
{
    i = i - ((i >> 1) & 0x55555555);
    i = (i & 0x33333333) + ((i >> 2) & 0x33333333);
    return (((i + (i >> 4)) & 0x0F0F0F0F) * 0x01010101) >> 24;
}

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
    n->last_update_seq = -1;
    n->mdp_ack_sequence = -1;
    // TODO measure min/max rtt
    n->rtt = 120;
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
  if (link->destination)
    release_destination_ref(link->destination);
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
	link->last_ack_seq = -1;
	link->link_version = -1;
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
  int drop_rate = 0;

  if (link->transmitter == my_subscriber){
    if (link->receiver==neighbour->subscriber){
      hop_count = 1;
    }
  }else{
    struct link *parent = get_parent(neighbour, link);
    if (parent && (!parent->calculating)){
      update_path_score(neighbour, parent);
      // TODO more interesting path cost metrics...
      if (parent->hop_count>0){
        hop_count = parent->hop_count+1;
        drop_rate = parent->path_drop_rate;
      }
    }
  }

  // ignore occasional dropped packets due to collisions
  if (link->drop_rate>2)
    drop_rate += link->drop_rate;

  if (config.debug.verbose && config.debug.linkstate && hop_count != link->hop_count)
    DEBUGF("LINK STATE; path score to %s via %s version %d = %d",
	alloca_tohex_sid(link->receiver->sid),
	alloca_tohex_sid(neighbour->subscriber->sid),
	neighbour->path_version,
	hop_count);

  link->hop_count = hop_count;
  link->path_version = neighbour->path_version;
  link->path_drop_rate = drop_rate;
  link->calculating = 0;
}

// pick the best path to this network destination
static struct link * find_best_link(struct subscriber *subscriber)
{
  IN();
  if (subscriber->reachable==REACHABLE_SELF)
    RETURN(NULL);

  struct link_state *state = get_link_state(subscriber);
  if (state->route_version == route_version)
    RETURN(state->link);

  if (state->calculating)
    RETURN(NULL);
  state->calculating = 1;

  struct neighbour *neighbour = neighbours;
  struct network_destination *destination = NULL;
  int best_hop_count = 99;
  int best_drop_rate = 99;
  struct link *best_link = NULL;
  struct subscriber *next_hop = NULL, *transmitter=NULL;
  time_ms_t now = gettime_ms();

  while (neighbour){
    if (neighbour->link_in_timeout < now)
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

    if (link->hop_count>0){
      if (link->path_drop_rate < best_drop_rate ||
         (link->path_drop_rate == best_drop_rate && link->hop_count < best_hop_count)){
        next_hop = neighbour->subscriber;
        best_hop_count = link->hop_count;
	best_drop_rate = link->path_drop_rate;
        transmitter = link->transmitter;
        destination = link->destination;
        best_link = link;
      }
    }

next:
    neighbour = neighbour->_next;
  }

  int changed =0;
  if (state->transmitter != transmitter || state->link != best_link)
    changed = 1;

  state->next_hop = next_hop;
  state->transmitter = transmitter;
  state->hop_count = best_hop_count;
  state->route_version = route_version;
  state->calculating = 0;
  state->link = best_link;
  
  if (next_hop == subscriber)
    next_hop = NULL;
  if (set_reachable(subscriber, destination, next_hop))
    changed = 1;
  
  if (changed){
    monitor_announce_link(best_hop_count, transmitter, subscriber);
    state->next_update = now+5;
  }

  RETURN(best_link);
}

static int monitor_announce(struct subscriber *subscriber, void *context){
  if (subscriber->reachable & REACHABLE){
    struct link_state *state = get_link_state(subscriber);
    monitor_announce_link(state->hop_count, state->transmitter, subscriber);
  }
  return 0;
}

int link_state_announce_links(){
  enum_subscribers(NULL, monitor_announce, NULL);
  return 0;
}

static int append_link_state(struct overlay_buffer *payload, char flags, 
                             struct subscriber *transmitter, struct subscriber *receiver, 
                             int interface, int version, int ack_sequence, uint32_t ack_mask, 
                             int drop_rate)
{
  if (interface!=-1)
    flags|=FLAG_HAS_INTERFACE;
  if (!transmitter)
    flags|=FLAG_NO_PATH;
  if (ack_sequence!=-1)
    flags|=FLAG_HAS_ACK;
  if (drop_rate!=-1)
    flags|=FLAG_HAS_DROP_RATE;

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

  if (ack_sequence!=-1){
    if (ob_append_byte(payload, ack_sequence))
      return -1;
    if (ob_append_ui32(payload, ack_mask))
      return -1;
  }

  if (drop_rate!=-1)
    if (ob_append_byte(payload, drop_rate))
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

  if (subscriber->reachable==REACHABLE_SELF){
    if (state->next_update - INCLUDE_ANYWAY <= now){
      // Other entries in our keyring are always one hop away from us.
      if (append_link_state(payload, 0, my_subscriber, subscriber, -1, 1, -1, 0, 0)){
        link_send_alarm.alarm = now+5;
        return 1;
      }
      // include information about this link every 5s
      state->next_update = now + 5000;
    }
  } else {
    struct link *best_link = find_best_link(subscriber);

    if (state->next_update - INCLUDE_ANYWAY <= now){
      if (append_link_state(payload, 0, state->transmitter, subscriber, -1, 
	  best_link?best_link->link_version:-1, -1, 0, best_link?best_link->drop_rate:32)){
        link_send_alarm.alarm = now+5;
        return 1;
      }
      // include information about this link every 5s
      state->next_update = now + 5000;
    }
  }

  if (state->next_update < link_send_alarm.alarm)
    link_send_alarm.alarm = state->next_update;

  return 0;
}

static void free_neighbour(struct neighbour **neighbour_ptr){
  struct neighbour *n = *neighbour_ptr;
  if (config.debug.linkstate && config.debug.verbose)
    DEBUGF("LINK STATE; all links from neighbour %s have died", alloca_tohex_sid(n->subscriber->sid));

  struct link_in *link = n->links;
  while(link){
    struct link_in *l=link;
    link = l->_next;
    free(l);
  }

  struct link_out *out = n->out_links;
  while (out){
    struct link_out *l=out;
    out = l->_next;
    release_destination_ref(out->destination);
    free(l);
  }
  
  free_links(n->root);
  n->root=NULL;
  *neighbour_ptr = n->_next;
  free(n);
}

static void clean_neighbours(time_ms_t now)
{
  struct neighbour **n_ptr = &neighbours;
  while (*n_ptr){
    struct neighbour *n = *n_ptr;
    
    struct link_in **list = &n->links;
    while(*list){
      struct link_in *link = *list;
      if (link->interface->state!=INTERFACE_STATE_UP || link->link_timeout < now){
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
    
    struct link_out **out = &n->out_links;
    while(*out){
      struct link_out *link = *out;
      if (link->destination->interface->state!=INTERFACE_STATE_UP || link->timeout < now){
	*out = link->_next;
	release_destination_ref(link->destination);
	free(link);
      }else{
	out = &link->_next;
      }
    }
    
    // when all links to a neighbour that we are routing through expire, force a routing calculation update
    struct link_state *state = get_link_state(n->subscriber);
    if (state->next_hop == n->subscriber && 
	(n->link_in_timeout < now || !n->links || !n->out_links) && 
	state->route_version == route_version)
      route_version++;
      
    if (!n->links || !n->out_links){
      free_neighbour(n_ptr);
    }else{
      n_ptr = &n->_next;
    }
  }
}

static int send_legacy_self_announce_ack(struct neighbour *neighbour, struct link_in *link, time_ms_t now){
  struct overlay_frame *frame=emalloc_zero(sizeof(struct overlay_frame));
  frame->type = OF_TYPE_SELFANNOUNCE_ACK;
  frame->ttl = 6;
  frame->destination = neighbour->subscriber;
  frame->source = my_subscriber;
  frame->payload = ob_new();
  ob_append_ui32(frame->payload, neighbour->last_update);
  ob_append_ui32(frame->payload, now);
  ob_append_byte(frame->payload, link->neighbour_interface);
  frame->queue=OQ_MESH_MANAGEMENT;
  if (overlay_payload_enqueue(frame)){
    op_free(frame);
    return -1;
  }
  return 0;
}

static int neighbour_find_best_link(struct neighbour *n)
{
  // TODO compare other link stats to find the best...
  struct link_in *best_link=n->links;
  if (best_link){
    struct link_in *link=best_link->_next;
    while(link){
      // find the link with the best interface
      switch(overlay_interface_compare(best_link->interface, link->interface)){
	case -1:
	  break;
	case 0:
	  if (link->unicast < best_link->unicast)
	    break;
	  // fall through
	case 1:
	  best_link = link;
      }
      link = link->_next;
    }
  }

  if (n->best_link != best_link){
    n->best_link = best_link;
    n->next_neighbour_update = gettime_ms()+5;
    if (config.debug.linkstate && config.debug.verbose){
      if (best_link){
	DEBUGF("LINK STATE; best link from neighbour %s is %s on interface %s", 
	  alloca_tohex_sid(n->subscriber->sid),
	  best_link->unicast?"unicast":"broadcast",
	  best_link->interface->name);
      }else{
	DEBUGF("LINK STATE; no best link from neighbour %s", 
	  alloca_tohex_sid(n->subscriber->sid));
      }
    }
  }

  return 0;
}

static int neighbour_link_sent(struct overlay_frame *frame, int sequence, void *context)
{
  struct subscriber *subscriber = context;
  struct neighbour *neighbour = get_neighbour(subscriber, 0);
  if (!neighbour)
    return 0;
  neighbour->last_update_seq = sequence;
  if (config.debug.linkstate && config.debug.verbose)
    DEBUGF("LINK STATE; ack sent to neighbour %s in seq %d", alloca_tohex_sid(subscriber->sid), sequence);
  return 0;
}

static int send_neighbour_link(struct neighbour *n)
{
  IN();
  if (!n->best_link)
    RETURN(-1);
  time_ms_t now = gettime_ms();
  
  if (n->legacy_protocol){
    // send a self announce ack instead.
    send_legacy_self_announce_ack(n, n->best_link, now);
    n->last_update = now;
  } else {
    struct overlay_frame *frame=emalloc_zero(sizeof(struct overlay_frame));
    frame->type=OF_TYPE_DATA;
    frame->source=my_subscriber;
    frame->ttl=1;
    frame->queue=OQ_MESH_MANAGEMENT;
    frame->payload = ob_new();
    frame->send_hook = neighbour_link_sent;
    frame->send_context = n->subscriber;
    frame->resend=-1;

    if (n->subscriber->reachable & REACHABLE_INDIRECT){
      frame->destination = n->subscriber;
      if (config.debug.linkstate && config.debug.verbose)
	DEBUGF("Sending link state ack indirectly");
    }else if (n->subscriber->reachable & REACHABLE){
      // we don't wont to address the next hop to this neighbour as that will force another reply ack
      // but we still want them to receive it.
      frame->destinations[frame->destination_count++].destination = add_destination_ref(n->subscriber->destination);
    }else{
      // no routing decision yet? send this packet to all probable destinations.
      if (config.debug.linkstate && config.debug.verbose)
	DEBUGF("Sending link state ack to all possibilities");
      struct link_out *out = n->out_links;
      while(out){
	frame->destinations[frame->destination_count++].destination = add_destination_ref(out->destination);
	out = out->_next;
      }
    }
    
    ob_limitsize(frame->payload, 400);
    overlay_mdp_encode_ports(frame->payload, MDP_PORT_LINKSTATE, MDP_PORT_LINKSTATE);

    char flags=0;
    if (n->best_link->unicast)
      flags|=FLAG_UNICAST;
    else
      flags|=FLAG_BROADCAST;

    if (config.debug.linkstate && config.debug.verbose)
      DEBUGF("LINK STATE; Sending ack to %s for seq %d", alloca_tohex_sid(n->subscriber->sid), n->best_link->ack_sequence);

    append_link_state(frame->payload, flags, n->subscriber, my_subscriber, n->best_link->neighbour_interface, 1,
	              n->best_link->ack_sequence, n->best_link->ack_mask, -1);
    if (overlay_payload_enqueue(frame))
      op_free(frame);

    n->best_link->ack_counter = ACK_WINDOW;
    n->last_update = now;
  }
  n->next_neighbour_update = n->last_update + n->best_link->interface->destination->tick_ms;
  if (config.debug.linkstate && config.debug.verbose)
    DEBUGF("Next update for %s in %lldms", alloca_tohex_sid(n->subscriber->sid), n->next_neighbour_update - gettime_ms());
  OUT();
  return 0;
}

static int link_send_neighbours()
{
  time_ms_t now = gettime_ms();
  clean_neighbours(now);
  struct neighbour *n = neighbours;

  while (n){
    neighbour_find_best_link(n);

    if (n->next_neighbour_update - INCLUDE_ANYWAY <= now){
      send_neighbour_link(n);
    }

    if (n->next_neighbour_update < link_send_alarm.alarm)
      link_send_alarm.alarm = n->next_neighbour_update;

    struct link_out *out = n->out_links;
    while(out){
      if (out->destination->tick_ms>0 && out->destination->unicast){
	if (out->destination->last_tx + out->destination->tick_ms < now)
	  overlay_send_tick_packet(out->destination);
	if (out->destination->last_tx + out->destination->tick_ms < link_send_alarm.alarm)
	  link_send_alarm.alarm = out->destination->last_tx + out->destination->tick_ms;
      }
      out=out->_next;
    }
    
    n = n->_next;
  }
  return 0;
}

// send link details
static void link_send(struct sched_ent *alarm)
{
  time_ms_t now = gettime_ms();

  alarm->alarm=now + 60000;

  // TODO use a separate alarm
  link_send_neighbours();

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

  enum_subscribers(NULL, append_link, frame->payload);

  ob_rewind(frame->payload);

  if (ob_position(frame->payload) == pos)
    op_free(frame);
  else if (overlay_payload_enqueue(frame))
    op_free(frame);

  if (neighbours){
    alarm->deadline = alarm->alarm;
    schedule(alarm);
  }else
    alarm->alarm=0;
}

static void update_alarm(time_ms_t limit){
  if (link_send_alarm.alarm>limit || link_send_alarm.alarm==0){
    unschedule(&link_send_alarm);
    link_send_alarm.alarm = limit;
    link_send_alarm.deadline = limit+10;
    schedule(&link_send_alarm);
  }
}

struct link_in * get_neighbour_link(struct neighbour *neighbour, struct overlay_interface *interface, int sender_interface, char unicast)
{
  struct link_in *link = neighbour->links;
  if (unicast){
    if (interface->prefer_unicast)
      unicast=1;
    else
      unicast=-1;
  }
  while(link){
    if (link->interface == interface 
      && link->neighbour_interface == sender_interface 
      && link->unicast == unicast)
      return link;
    link=link->_next;
  }
  link = emalloc_zero(sizeof(struct link_in));
  link->interface = interface;
  link->unicast = unicast;
  link->neighbour_interface = sender_interface;
  link->ack_sequence = -1;
  link->ack_mask = 0;
  link->_next = neighbour->links;
  if (config.debug.linkstate && config.debug.verbose)
    DEBUGF("LINK STATE; new possible %s link from neighbour %s on interface %s/%d", 
      unicast?"unicast":"broadcast",
      alloca_tohex_sid(neighbour->subscriber->sid),
      interface->name,
      sender_interface);
  neighbour->links = link;
  return link;
}

int link_add_destinations(struct overlay_frame *frame)
{
  if (frame->destination){
    frame->next_hop = frame->destination;
    
    // if the destination is unreachable, but we have a reachable directory service
    // forward it through the directory service
    if (frame->next_hop->reachable==REACHABLE_NONE
      && directory_service 
      && frame->next_hop!=directory_service
      && directory_service->reachable&REACHABLE)
      frame->next_hop = directory_service;
    
    if (frame->next_hop->reachable==REACHABLE_NONE){
      // if the destination is a neighbour, add all probable destinations
      struct neighbour *n = get_neighbour(frame->destination, 0);
      if (n){
	struct link_out *out = n->out_links;
	while(out){
	  frame->destinations[frame->destination_count++].destination = add_destination_ref(out->destination);
	  out = out->_next;
	}
      }
    }
    
    if ((frame->next_hop->reachable&REACHABLE)==REACHABLE_INDIRECT)
      frame->next_hop = frame->next_hop->next_hop;
    
    if (frame->next_hop->reachable&REACHABLE_DIRECT){
      if (frame->destination_count < MAX_PACKET_DESTINATIONS)
	frame->destinations[frame->destination_count++].destination=add_destination_ref(frame->next_hop->destination);
    }    
  }else{
    char added_interface[OVERLAY_MAX_INTERFACES];
    bzero(added_interface, sizeof(added_interface));
    
    struct neighbour *neighbour = neighbours;
    for(;neighbour;neighbour = neighbour->_next){
      if (neighbour->subscriber->reachable&REACHABLE_DIRECT){
	struct network_destination *dest = neighbour->subscriber->destination;
	// TODO set packet version per destination
	if (frame->packet_version > neighbour->subscriber->max_packet_version)
	  frame->packet_version = neighbour->subscriber->max_packet_version;
	
	if (!dest->unicast){
	  // make sure we only add broadcast interfaces once
	  int id = dest->interface - overlay_interfaces;
	  if (added_interface[id]){
	    continue;
	  }
	}
	
	if (frame->destination_count < MAX_PACKET_DESTINATIONS)
	  frame->destinations[frame->destination_count++].destination=add_destination_ref(dest);
      }
    }
  }
  return 0;
}

// do we need to forward any broadcast packets transmitted by this neighbour?
int link_state_should_forward_broadcast(struct subscriber *transmitter)
{
  struct neighbour *neighbour = get_neighbour(transmitter, 0);
  if (!neighbour)
    return 1;
  time_ms_t now = gettime_ms();
  // it's only safe to drop broadcasts if we know we are in this neighbours routing table,
  // and we know we are not vital to reach someone else.
  // if we aren't in their routing table as an immediate neighbour, we may be hearing this broadcast packet over an otherwise unreliable link.
  // since we're going to process it now and assume that any future copies are duplicates, its better to be safe and forward it.
  if (neighbour->using_us && neighbour->routing_through_us < now)
    return 0;
  return 1;
}

// when we receive a packet from a neighbour with ourselves as the next hop, make sure we send an ack soon(ish)
int link_state_ack_soon(struct subscriber *subscriber){
  IN();
  struct neighbour *neighbour = get_neighbour(subscriber, 0);
  if (!neighbour)
    RETURN(0);

  time_ms_t now = gettime_ms();
  if (neighbour->using_us && neighbour->next_neighbour_update > now + 80){
    neighbour->next_neighbour_update = now + 80;
  }
  update_alarm(neighbour->next_neighbour_update);
  OUT();
  return 0;
}

// our neighbour is sending a duplicate frame, did we see the original?
int link_received_duplicate(struct subscriber *subscriber, struct overlay_interface *interface, int sender_interface, int payload_seq, int unicast)
{
  struct neighbour *neighbour = get_neighbour(subscriber, 0);
  if (!neighbour)
    return 0;

  if (neighbour->mdp_ack_sequence != -1){
    if (neighbour->mdp_ack_sequence == payload_seq){
      return 1;
    }

    int offset = (neighbour->mdp_ack_sequence - 1 - payload_seq)&0xFF;
    if (offset < 64){
      if (neighbour->mdp_ack_mask & (1<<offset)){
	return 1;
      }
      neighbour->mdp_ack_mask |= (1<<offset);
    }else{
      int offset = (payload_seq - neighbour->mdp_ack_sequence - 1)&0xFF;
      neighbour->mdp_ack_mask = (neighbour->mdp_ack_mask << 1) | 1;
      neighbour->mdp_ack_mask = neighbour->mdp_ack_mask << offset;
      neighbour->mdp_ack_sequence = payload_seq;
    }
  }else
    neighbour->mdp_ack_sequence = payload_seq;
  return 0;
}

// remote peer has confirmed hearing a recent unicast packet
int link_unicast_ack(struct subscriber *subscriber, struct overlay_interface *interface, struct sockaddr_in addr)
{
  // TODO find / create network destination, keep it alive
  return 0;
}

static struct link_out *create_out_link(struct neighbour *neighbour, overlay_interface *interface, struct sockaddr_in addr, char unicast){
  struct link_out *ret=emalloc_zero(sizeof(struct link_out));
  if (ret){
    ret->_next=neighbour->out_links;
    neighbour->out_links=ret;
    if (unicast)
      ret->destination = create_unicast_destination(addr, interface);
    else
      ret->destination = add_destination_ref(interface->destination);
    ret->timeout = gettime_ms()+ret->destination->tick_ms*2;
    update_alarm(gettime_ms()+5);
  }
  return ret;
}

static struct link_out *find_out_link(struct neighbour *neighbour, overlay_interface *interface, char unicast){
  struct link_out *ret = neighbour->out_links;
  while(ret){
    if (ret->destination->interface==interface 
	&& ret->destination->unicast==unicast)
      return ret;
    ret=ret->_next;
  }
  return NULL;
}

// track stats for receiving packets from this neighbour
int link_received_packet(struct decode_context *context, int sender_seq, char unicast)
{
  if (!context->sender)
    return 0;
  
  struct neighbour *neighbour = get_neighbour(context->sender, 1);
  // get stats about incoming packets
  struct link_in *link=get_neighbour_link(neighbour, context->interface, context->sender_interface, unicast);
  time_ms_t now = gettime_ms();

  if (!neighbour->out_links){
    // if this packet arrived in an IPv4 packet, assume we need to send them unicast packets
    if (context->addr.sin_family==AF_INET && context->addr.sin_port!=0 && context->addr.sin_addr.s_addr!=0){
      if (config.debug.linkstate && config.debug.verbose)
	DEBUGF("Assuming reachable via unicast");
      create_out_link(neighbour, context->interface, context->addr, 1);
    }
    // if this packet arrived from the same IPv4 subnet, or a different type of network, assume they can hear our broadcasts
    if (context->addr.sin_family!=AF_INET || 
	(context->addr.sin_addr.s_addr & context->interface->netmask.s_addr) 
	== (context->interface->address.sin_addr.s_addr& context->interface->netmask.s_addr)){
      if (config.debug.linkstate && config.debug.verbose)
	DEBUGF("Assuming reachable via broadcast");
      create_out_link(neighbour, context->interface, context->addr, 0);
    }
  }

  link->ack_counter --;

  // for now we'll use a simple time based link up/down flag + dropped packet count
  if (sender_seq >=0){
    if (link->ack_sequence != -1){
      int offset = (link->ack_sequence - 1 - sender_seq)&0xFF;
      if (offset < 64){
        if (config.debug.verbose && config.debug.linkstate)
          DEBUGF("LINK STATE; late seq %d from %s on %s", 
	    sender_seq, alloca_tohex_sid(context->sender->sid), context->interface->name);
	link->ack_mask |= (1<<offset);
      }else{
        link->ack_mask = (link->ack_mask << 1) | 1;
        while(1){
          link->ack_sequence = (link->ack_sequence+1)&0xFF;
	  if (link->ack_sequence == sender_seq)
	    break;
	  // missed a packet? send a link state soon
          if (config.debug.verbose && config.debug.linkstate)
            DEBUGF("LINK STATE; missed seq %d from %s on %s", 
	      link->ack_sequence, alloca_tohex_sid(context->sender->sid), context->interface->name);
	  link->ack_mask = link->ack_mask << 1;
	  link->ack_counter --;

	  // if we need to nack promptly
	  if (neighbour->using_us && link==neighbour->best_link){
	    neighbour->next_neighbour_update = now + 10;

	    if (link->ack_counter <=0){
	      neighbour_find_best_link(neighbour);
              send_neighbour_link(neighbour);
	    }
	  }
        }
      }
    }else
      link->ack_sequence = sender_seq;
  }

  // force an update when we start hearing a new neighbour link
  if (link->link_timeout < now){
    if (neighbour->next_neighbour_update > now + 10);
      neighbour->next_neighbour_update = now + 10;
  }
  link->link_timeout = now + (context->interface->destination->tick_ms *5);

  // force an update soon when we need to promptly ack packets
  if (neighbour->using_us > now && link == neighbour->best_link && link->ack_counter <=0){
    neighbour_find_best_link(neighbour);
    send_neighbour_link(neighbour);
  }

  update_alarm(neighbour->next_neighbour_update);
  return 0;
}

// parse incoming link details
int link_receive(struct overlay_frame *frame, overlay_mdp_frame *mdp)
{
  IN();
  struct overlay_buffer *payload = ob_static(mdp->out.payload, mdp->out.payload_length);
  ob_limitsize(payload, mdp->out.payload_length);

  struct subscriber *sender = find_subscriber(mdp->out.src.sid, SID_SIZE, 0);
  struct neighbour *neighbour = get_neighbour(sender, 1);

  struct decode_context context;
  bzero(&context, sizeof(context));
  context.interface = frame->interface;
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

    int ack_seq = -1;
    uint32_t ack_mask = 0;
    int drop_rate = 0;

    if (flags & FLAG_HAS_ACK){
      ack_seq = ob_get(payload);
      ack_mask = ob_get_ui32(payload);

      drop_rate = 15 - NumberOfSetBits((ack_mask & 0x7FFF));
      // we can deal with low packet loss, and with fast packet transmission rates we're going to see lots of broadcast collisions.
      // we only want to force a link update when packet loss due to interference is high. Otherwise ignore it.
      if (drop_rate <=3)
	drop_rate = 0;
    }

    if (flags & FLAG_HAS_DROP_RATE){
      drop_rate = ob_get(payload);
      if (drop_rate <0)
	break;
    }

    // jump to the position of the next record, even if there's more data we don't understand
    payload->position = start_pos + length;

    if (context.invalid_addresses)
      continue;

    if (config.debug.verbose && config.debug.linkstate)
      DEBUGF("LINK STATE; record - %d, %s, %s, %d, %d, %x, %d",
	flags,
	receiver?alloca_tohex_sid(receiver->sid):"NULL",
	transmitter?alloca_tohex_sid(transmitter->sid):"NULL",
	interface_id,
	ack_seq,
	ack_mask,
	drop_rate);

    if (receiver == my_subscriber){
      // track if our neighbour is using us as an immediate neighbour, if they are we need to ack / nack promptly
      neighbour->using_us = (transmitter==sender?1:0);

      // for routing, we can completely ignore any links that our neighbour is using to route to us.
      // we can always send packets to ourself :)
      continue;
    }

    struct network_destination *destination=NULL;
    
    if (receiver == sender){
      // ignore other incoming links to our neighbour
      if (transmitter!=my_subscriber || interface_id==-1)
        continue;

      interface = &overlay_interfaces[interface_id];
      // ignore any links claiming to be from an interface we aren't using
      if (interface->state != INTERFACE_STATE_UP)
	continue;

      struct link_out *out = find_out_link(neighbour, interface, flags&FLAG_UNICAST?1:0);
      if (!out)
	continue;
      // start sending sequence numbers when our neighbour has acked a packet
      if (out->destination->sequence_number<0)
	out->destination->sequence_number=0;
      out->timeout=now + out->destination->tick_ms * 5;
      destination = out->destination;
      
    }else if(transmitter == my_subscriber){
      // if our neighbour starts using us to reach this receiver, we have to treat the link in our routing table as if it just died.
      transmitter = NULL;
      if (receiver->reachable != REACHABLE_SELF){
        // also we should forward this neighbours broadcast packets to ensure they reach this receiver.
        // since we won't remember this link for routing purposes, we'll just use a simple timer.
        neighbour->routing_through_us = now + 2500;
      }
    }

    struct link *link = find_link(neighbour, receiver, transmitter?1:0);
    if (!link)
      continue;

    if (transmitter == my_subscriber && receiver == sender && interface_id != -1 && destination){
      // they can hear us? we can route through them!
      
      version = link->link_version;
      
      // which network destination can they hear us from?
	
      if (set_destination_ref(&link->destination, destination)){
	changed = 1;
	version++;
      }

      if (neighbour->link_in_timeout < now || version<0){
	changed = 1;
	version++;
      }
      neighbour->link_in_timeout = now + interface->destination->tick_ms * 5;
      
      if (drop_rate != link->drop_rate || transmitter != link->transmitter)
	version++;

      // process acks / nacks
      if (ack_seq!=-1){
	// TODO unicast
        overlay_queue_ack(sender, interface->destination, ack_mask, ack_seq);

        // did they miss our last ack?
        if (neighbour->last_update_seq!=-1){
	  int seq_delta = (ack_seq - neighbour->last_update_seq)&0xFF;
	  if (seq_delta <= 32 && (seq_delta==0 || ack_mask&(1<<(seq_delta-1)))){
	    neighbour->last_update_seq = -1;
	  }else if(seq_delta < 128){
	    // send another ack asap
	    if (config.debug.linkstate && config.debug.verbose)
	      DEBUGF("LINK STATE; neighbour %s missed ack %d, queue another", alloca_tohex_sid(sender->sid), neighbour->last_update_seq);
	    neighbour->next_neighbour_update=now+5;
	    update_alarm(neighbour->next_neighbour_update);
	  }
        }
      }

      link->last_ack_seq = ack_seq;
    }else{
      set_destination_ref(&link->destination, NULL);
    }

    if (link->transmitter != transmitter || link->link_version != version){
      changed = 1;
      link->transmitter = transmitter;
      link->link_version = version & 0xFF;
      link->drop_rate = drop_rate;
      // TODO other link attributes...
    }
  }

  send_please_explain(&context, my_subscriber, sender);

  if (changed){
    route_version++;
    neighbour->path_version ++;
    if (link_send_alarm.alarm>now+5 || link_send_alarm.alarm==0){
      unschedule(&link_send_alarm);
      link_send_alarm.alarm=now+5;
      // read all incoming packets first
      link_send_alarm.deadline=now+15;
      schedule(&link_send_alarm);
    }
  }
  OUT();
  return 0;
}

// if a neighbour asks for a subscriber explaination, make sure we repeat relevant link information immediately.
void link_explained(struct subscriber *subscriber)
{
  time_ms_t now = gettime_ms();
  struct link_state *state = get_link_state(subscriber);
  state->next_update = now+5;
  update_alarm(now+5);
}

void link_interface_down(struct overlay_interface *interface)
{
  clean_neighbours(gettime_ms());
}

/* if an ancient node on the network uses their old protocol to tell us that they can hear us;
  - send the same format back at them
  - treat the link as up.
  - but we aren't going to use this link in either routing protocol
*/
int link_state_legacy_ack(struct overlay_frame *frame, time_ms_t now)
{
  if (frame->payload->sizeLimit<9) 
    return WHY("selfannounce ack packet too short");

  ob_get_ui32(frame->payload);
  ob_get_ui32(frame->payload);
  int iface=ob_get(frame->payload);
  overlay_interface *interface = &overlay_interfaces[iface];

  // record that we have a possible link to this neighbour
  struct neighbour *neighbour = get_neighbour(frame->source, 1);
  struct link *link = find_link(neighbour, frame->source, 1);
  int changed = 0;

  if (!neighbour->legacy_protocol){
    changed = 1;
    if (config.debug.linkstate)
      DEBUGF("LINK STATE; new legacy neighbour %s", alloca_tohex_sid(frame->source->sid));
  }
  if (neighbour->link_in_timeout < now)
    changed = 1;
  if (link->transmitter != my_subscriber)
    changed = 1;

  link->transmitter = my_subscriber;
  link->link_version = 1;
  link->destination = interface->destination;

  // give this link a high cost, we aren't going to route through it anyway...
  link->drop_rate = 32;

  // track the incoming link so we remember to send broadcasts
  struct link_in *nl = get_neighbour_link(neighbour, frame->interface, iface, 0);
  nl->link_timeout = now + (link->destination->tick_ms *5);

  neighbour->legacy_protocol = 1;
  neighbour->link_in_timeout = now + link->destination->tick_ms * 5;

  if (changed){
    route_version++;
    neighbour->path_version ++;
    if (link_send_alarm.alarm>now+5 || link_send_alarm.alarm==0){
      unschedule(&link_send_alarm);
      link_send_alarm.alarm=now+5;
      // read all incoming packets first
      link_send_alarm.deadline=now+15;
      schedule(&link_send_alarm);
    }
  }

  return 0;
}

