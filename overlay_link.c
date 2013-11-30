#include <assert.h>
#include "serval.h"
#include "conf.h"
#include "str.h"
#include "overlay_address.h"
#include "overlay_buffer.h"
#include "overlay_packet.h"
#include "keyring.h"

#define MIN_BURST_LENGTH 5000

struct probe_contents{
  struct sockaddr_in addr;
  unsigned char interface;
};

static void update_limit_state(struct limit_state *state, time_ms_t now){
  if (state->next_interval > now || state->burst_size==0){
    return;
  }
  
  if (state->next_interval + state->burst_length>now)
    state->next_interval+=state->burst_length;
  else
    state->next_interval=now + state->burst_length;
  
  state->sent = 0;
}

/* When should we next allow this thing to occur? */
time_ms_t limit_next_allowed(struct limit_state *state){
  time_ms_t now = gettime_ms();
  if (!state->burst_length)
    return now;
  update_limit_state(state, now);
  
  if (state->sent < state->burst_size)
    return now;
  return state->next_interval;
}

/* Can we do this now? if so, track it */
int limit_is_allowed(struct limit_state *state){
  time_ms_t now = gettime_ms();
  if (!state->burst_length)
    return 0;
  update_limit_state(state, now);
  if (state->sent >= state->burst_size){
    return -1;
  }
  state->sent ++;
  return 0;
}

/* Initialise burst size and length based on the number we can do in one MIN_BURST */
int limit_init(struct limit_state *state, int rate_micro_seconds){
  if (rate_micro_seconds==0){
    state->burst_size=0;
    state->burst_length=1;
  }else{
    state->burst_size = (MIN_BURST_LENGTH / rate_micro_seconds)+1;
    state->burst_length = (state->burst_size * rate_micro_seconds) / 1000.0;
  }
  return 0;
}

int set_reachable(struct subscriber *subscriber, 
  struct network_destination *destination, struct subscriber *next_hop){
  
  int reachable = REACHABLE_NONE;
  if (destination)
    reachable = destination->unicast?REACHABLE_UNICAST:REACHABLE_BROADCAST;
  else if(next_hop)
    reachable = REACHABLE_INDIRECT;
  
  if (subscriber->reachable==reachable 
    && subscriber->next_hop==next_hop 
    && subscriber->destination == destination)
    return 0;
  
  int old_value = subscriber->reachable;
  subscriber->reachable = reachable;
  set_destination_ref(&subscriber->destination, destination);
  subscriber->next_hop = next_hop;
  
  // These log messages are for use in tests.  Changing them may break test scripts.
  if (config.debug.overlayrouting || config.debug.linkstate) {
    switch (reachable) {
      case REACHABLE_NONE:
	DEBUGF("NOT REACHABLE sid=%s", alloca_tohex_sid_t(subscriber->sid));
	break;
      case REACHABLE_INDIRECT:
	DEBUGF("REACHABLE INDIRECTLY sid=%s, via %s", 
	  alloca_tohex_sid_t(subscriber->sid), alloca_tohex_sid_t(next_hop->sid));
	break;
      case REACHABLE_UNICAST:
	DEBUGF("REACHABLE VIA UNICAST sid=%s, on %s ", alloca_tohex_sid_t(subscriber->sid), destination->interface->name);
	break;
      case REACHABLE_BROADCAST:
	DEBUGF("REACHABLE VIA BROADCAST sid=%s, on %s ", alloca_tohex_sid_t(subscriber->sid), destination->interface->name);
	break;
    }
  }
  
  /* Pre-emptively send a sas request */
  if (!subscriber->sas_valid && reachable&REACHABLE)
    keyring_send_sas_request(subscriber);
  
  // Hacky layering violation... send our identity to a directory service
  if (subscriber==directory_service)
    directory_registration();
  
  if ((old_value & REACHABLE) && (!(reachable & REACHABLE)))
    monitor_announce_unreachable_peer(&subscriber->sid);
  if ((!(old_value & REACHABLE)) && (reachable & REACHABLE))
    monitor_announce_peer(&subscriber->sid);
  
  return 1;
}

int resolve_name(const char *name, struct in_addr *addr){
  // TODO this can block, move to worker thread.
  IN();
  int ret=0;
  struct addrinfo hint={
    .ai_family=AF_INET,
  };
  struct addrinfo *addresses=NULL;
  if (getaddrinfo(name, NULL, &hint, &addresses))
    RETURN(WHYF("Failed to resolve %s",name));
  
  if (addresses->ai_addr->sa_family==AF_INET){
    *addr = ((struct sockaddr_in *)addresses->ai_addr)->sin_addr;
    if (config.debug.overlayrouting)
      DEBUGF("Resolved %s into %s", name, inet_ntoa(*addr));
    
  }else
    ret=WHY("Ignoring non IPv4 address");
  
  freeaddrinfo(addresses);
  RETURN(ret);
  OUT();
}

// load a unicast address from configuration
int load_subscriber_address(struct subscriber *subscriber)
{
  if (!subscriber || subscriber->reachable&REACHABLE)
    return 0;
  int i = config_host_list__get(&config.hosts, &subscriber->sid);
  // No unicast configuration? just return.
  if (i == -1)
    return 1;
  const struct config_host *hostc = &config.hosts.av[i].value;
  overlay_interface *interface = NULL;
  if (*hostc->interface){
    interface = overlay_interface_find_name(hostc->interface);
    if (!interface)
      return WHY("Can't fund configured interface");
  }
  struct sockaddr_in addr;
  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr = hostc->address;
  addr.sin_port = htons(hostc->port);
  if (addr.sin_addr.s_addr==INADDR_NONE){
    if (interface || overlay_interface_get_default()){
      if (resolve_name(hostc->host, &addr.sin_addr))
	return -1;
    }else{
      // interface isnt up yet
      return 1;
    }
  }
  if (config.debug.overlayrouting)
    DEBUGF("Loaded address %s:%d for %s", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), alloca_tohex_sid_t(subscriber->sid));
  struct network_destination *destination = create_unicast_destination(addr, interface);
  if (!destination)
    return -1;
  int ret=overlay_send_probe(subscriber, destination, OQ_MESH_MANAGEMENT);
  release_destination_ref(destination);
  return ret;
}

/* Collection of unicast echo responses to detect working links */
int
overlay_mdp_service_probe(struct overlay_frame *frame, overlay_mdp_frame *mdp)
{
  IN();
  if (mdp->out.src.port!=MDP_PORT_ECHO || mdp->out.payload_length != sizeof(struct probe_contents)){
    WARN("Probe packets should be returned from remote echo port");
    RETURN(-1);
  }
  
  if (frame->source->reachable == REACHABLE_SELF)
    RETURN(0);
  
  struct probe_contents probe;
  bcopy(&mdp->out.payload, &probe, sizeof(struct probe_contents));
  if (probe.addr.sin_family!=AF_INET)
    RETURN(WHY("Unsupported address family"));
  
  RETURN(link_unicast_ack(frame->source, &overlay_interfaces[probe.interface], probe.addr));
  OUT();
}

int overlay_send_probe(struct subscriber *peer, struct network_destination *destination, int queue){
  // never send unicast probes over a stream interface
  if (destination->interface->socket_type==SOCK_STREAM)
    return 0;
  
  time_ms_t now = gettime_ms();
  // though unicast probes don't typically use the same network destination, 
  // we should still try to throttle when we can
  if (destination->last_tx + destination->tick_ms > now)
    return -1;
  
  struct overlay_frame *frame=malloc(sizeof(struct overlay_frame));
  bzero(frame,sizeof(struct overlay_frame));
  frame->type=OF_TYPE_DATA;
  frame->source = my_subscriber;
  frame->next_hop = frame->destination = peer;
  frame->ttl=1;
  frame->queue=queue;
  frame->destinations[frame->destination_count++].destination=add_destination_ref(destination);
  if ((frame->payload = ob_new()) == NULL) {
    op_free(frame);
    return -1;
  }
  frame->source_full = 1;
  // TODO call mdp payload encryption / signing without calling overlay_mdp_dispatch...
  
  overlay_mdp_encode_ports(frame->payload, MDP_PORT_ECHO, MDP_PORT_PROBE);
  // not worried about byte order here as we are the only node that should be parsing the contents.
  unsigned char *dst=ob_append_space(frame->payload, sizeof(struct probe_contents));
  if (!dst){
    op_free(frame);
    return -1;
  }
  struct probe_contents probe;
  probe.addr=destination->address;
  // get interface number
  probe.interface = destination->interface - overlay_interfaces;
  bcopy(&probe, dst, sizeof(struct probe_contents));
  if (overlay_payload_enqueue(frame)){
    op_free(frame);
    return -1;
  }
  if (config.debug.overlayrouting)
    DEBUGF("Queued probe packet on interface %s to %s:%d for %s", 
	 destination->interface->name, 
	 inet_ntoa(destination->address.sin_addr), ntohs(destination->address.sin_port), 
	 peer?alloca_tohex_sid_t(peer->sid):"ANY");
  return 0;
}

// append the address of a unicast link into a packet buffer
static void overlay_append_unicast_address(struct subscriber *subscriber, struct overlay_buffer *buff)
{
  if (   subscriber->destination 
      && subscriber->destination->unicast
      && subscriber->destination->address.sin_family==AF_INET
  ) {
    overlay_address_append(NULL, buff, subscriber);
    ob_append_ui32(buff, subscriber->destination->address.sin_addr.s_addr);
    ob_append_ui16(buff, subscriber->destination->address.sin_port);
    if (config.debug.overlayrouting)
      DEBUGF("Added STUN info for %s", alloca_tohex_sid_t(subscriber->sid));
  }else{
    if (config.debug.overlayrouting)
      DEBUGF("Unable to give address of %s, %d", alloca_tohex_sid_t(subscriber->sid),subscriber->reachable);
  }
}

int overlay_mdp_service_stun_req(overlay_mdp_frame *mdp)
{
  if (config.debug.overlayrouting)
    DEBUGF("Processing STUN request from %s", alloca_tohex_sid_t(mdp->out.src.sid));

  struct overlay_buffer *payload = ob_static(mdp->out.payload, mdp->out.payload_length);
  ob_limitsize(payload, mdp->out.payload_length);
  
  overlay_mdp_frame reply;
  bzero(&reply, sizeof(reply));
  reply.packetTypeAndFlags=MDP_TX;
  
  reply.out.dst.sid = mdp->out.src.sid;
  reply.out.src.sid = mdp->out.dst.sid;
  reply.out.src.port=MDP_PORT_STUNREQ;
  reply.out.dst.port=MDP_PORT_STUN;
  reply.out.queue=OQ_MESH_MANAGEMENT;
  
  struct overlay_buffer *replypayload = ob_static(reply.out.payload, sizeof(reply.out.payload));
  
  ob_checkpoint(replypayload);
  while (ob_remaining(payload) > 0) {
    struct subscriber *subscriber=NULL;
    if (overlay_address_parse(NULL, payload, &subscriber))
      break;
    if (!subscriber){
      if (config.debug.overlayrouting)
	DEBUGF("Unknown subscriber");
      continue;
    }
    overlay_append_unicast_address(subscriber, replypayload);
    if (ob_overrun(payload))
      break;
    ob_checkpoint(replypayload);
  }
  ob_rewind(replypayload);
  reply.out.payload_length=ob_position(replypayload);
  
  if (reply.out.payload_length){
    if (config.debug.overlayrouting)
      DEBUGF("Sending reply");
    overlay_mdp_dispatch(&reply, NULL);
  }
  ob_free(replypayload);
  ob_free(payload);
  return 0;
}

int overlay_mdp_service_stun(overlay_mdp_frame *mdp)
{
  struct overlay_buffer *buff = ob_static(mdp->out.payload, mdp->out.payload_length);
  ob_limitsize(buff, mdp->out.payload_length);

  if (config.debug.overlayrouting)
    DEBUGF("Processing STUN info from %s", alloca_tohex_sid_t(mdp->out.src.sid));

  while(ob_remaining(buff)>0){
    struct subscriber *subscriber=NULL;
    struct sockaddr_in addr;
    
    // TODO explain addresses, link expiry time, resolve differences between addresses...
    
    if (overlay_address_parse(NULL, buff, &subscriber)){
      break;
    }
    
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ob_get_ui32(buff);
    addr.sin_port = ob_get_ui16(buff);
    
    if (!subscriber || (subscriber->reachable!=REACHABLE_NONE))
      continue;
    
    struct network_destination *destination = create_unicast_destination(addr, NULL);
    if (destination){
      overlay_send_probe(subscriber, destination, OQ_MESH_MANAGEMENT);
      release_destination_ref(destination);
    }
  }
  
  ob_free(buff);
  return 0;
}

int overlay_send_stun_request(struct subscriber *server, struct subscriber *request){
  if ((!server) || (!request))
    return -1;
  if (!(server->reachable&REACHABLE))
    return -1;
  // don't bother with a stun request if the peer is already reachable directly
  if (request->reachable&REACHABLE_DIRECT)
    return -1;
  
  time_ms_t now = gettime_ms();
  if (request->last_stun_request +1000 > now)
    return -1;
  
  request->last_stun_request=now;
  
  overlay_mdp_frame mdp;
  bzero(&mdp, sizeof(mdp));
  mdp.packetTypeAndFlags=MDP_TX;
  
  mdp.out.src.sid = my_subscriber->sid;
  mdp.out.dst.sid = server->sid;
  mdp.out.src.port=MDP_PORT_STUN;
  mdp.out.dst.port=MDP_PORT_STUNREQ;
  mdp.out.queue=OQ_MESH_MANAGEMENT;
  
  struct overlay_buffer *payload = ob_static(mdp.out.payload, sizeof(mdp.out.payload));
  overlay_address_append(NULL, payload, request);
  if (!ob_overrun(payload)) {
    mdp.out.payload_length=ob_position(payload);
    if (config.debug.overlayrouting)
      DEBUGF("Sending STUN request to %s", alloca_tohex_sid_t(server->sid));
    overlay_mdp_dispatch(&mdp, NULL);
  }
  ob_free(payload);
  return 0;
}
