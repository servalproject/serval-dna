#include "serval.h"
#include "conf.h"
#include "str.h"
#include "overlay_address.h"
#include "overlay_buffer.h"
#include "overlay_packet.h"

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
  update_limit_state(state, now);
  
  if (state->sent < state->burst_size)
    return now;
  return state->next_interval;
}

/* Can we do this now? if so, track it */
int limit_is_allowed(struct limit_state *state){
  time_ms_t now = gettime_ms();
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
  }else{
    state->burst_size = (MIN_BURST_LENGTH / rate_micro_seconds)+1;
    state->burst_length = (state->burst_size * rate_micro_seconds) / 1000.0;
  }
  return 0;
}

// quick test to make sure the specified route is valid.
int subscriber_is_reachable(struct subscriber *subscriber){
  if (!subscriber)
    return REACHABLE_NONE;
  
  int ret = subscriber->reachable;
  
  if (ret==REACHABLE_INDIRECT){
    if (!subscriber->next_hop)
      ret = REACHABLE_NONE;
    
    // avoid infinite recursion...
    else if (!(subscriber->next_hop->reachable & REACHABLE_DIRECT))
      ret = REACHABLE_NONE;
    else{
      int r = subscriber_is_reachable(subscriber->next_hop);
      if (r&REACHABLE_ASSUMED)
	ret = REACHABLE_NONE;
      else if (!(r & REACHABLE_DIRECT))
	ret = REACHABLE_NONE;
    }
  }
  
  if (ret & REACHABLE_DIRECT){
    // make sure the interface is still up
    if (!subscriber->interface)
      ret=REACHABLE_NONE;
    else if (subscriber->interface->state!=INTERFACE_STATE_UP)
      ret=REACHABLE_NONE;
  }
  
  return ret;
}

int set_reachable(struct subscriber *subscriber, int reachable){
  if (subscriber->reachable==reachable)
    return 0;
  int old_value = subscriber->reachable;
  subscriber->reachable=reachable;
  
  // These log messages are for use in tests.  Changing them may break test scripts.
  if (config.debug.overlayrouting) {
    switch (reachable) {
      case REACHABLE_NONE:
	DEBUGF("NOT REACHABLE sid=%s", alloca_tohex_sid(subscriber->sid));
	break;
      case REACHABLE_SELF:
	break;
      case REACHABLE_INDIRECT:
	DEBUGF("REACHABLE INDIRECTLY sid=%s", alloca_tohex_sid(subscriber->sid));
	DEBUGF("(via %s, %d)",subscriber->next_hop?alloca_tohex_sid(subscriber->next_hop->sid):"NOONE!"
	       ,subscriber->next_hop?subscriber->next_hop->reachable:0);
	break;
      case REACHABLE_UNICAST:
	DEBUGF("REACHABLE VIA UNICAST sid=%s", alloca_tohex_sid(subscriber->sid));
	break;
      case REACHABLE_BROADCAST:
	DEBUGF("REACHABLE VIA BROADCAST sid=%s", alloca_tohex_sid(subscriber->sid));
	break;
      case REACHABLE_UNICAST|REACHABLE_ASSUMED:
	DEBUGF("ASSUMED REACHABLE VIA UNICAST sid=%s", alloca_tohex_sid(subscriber->sid));
	break;
      case REACHABLE_BROADCAST|REACHABLE_ASSUMED:
	DEBUGF("ASSUMED REACHABLE VIA BROADCAST sid=%s", alloca_tohex_sid(subscriber->sid));
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
    monitor_announce_unreachable_peer(subscriber->sid);
  if ((!(old_value & REACHABLE)) && (reachable & REACHABLE))
    monitor_announce_peer(subscriber->sid);
  
  return 0;
}

// mark the subscriber as reachable via reply unicast packet
int reachable_unicast(struct subscriber *subscriber, overlay_interface *interface, struct in_addr addr, int port){
  if (subscriber->reachable&REACHABLE)
    return -1;
  
  if (subscriber->node)
    return -1;
  
  subscriber->interface = interface;
  subscriber->address.sin_family = AF_INET;
  subscriber->address.sin_addr = addr;
  subscriber->address.sin_port = htons(port);
  set_reachable(subscriber, REACHABLE_UNICAST);
  
  return 0;
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
    DEBUGF("Resolved %s into %s", name, inet_ntoa(*addr));
    
  }else
    ret=-1;
  
  freeaddrinfo(addresses);
  RETURN(ret);
}

// load a unicast address from configuration
int load_subscriber_address(struct subscriber *subscriber)
{
  if (subscriber_is_reachable(subscriber)&REACHABLE)
    return 0;
  int i = config_host_list__get(&config.hosts, (const sid_t*)subscriber->sid);
  // No unicast configuration? just return.
  if (i == -1)
    return 1;
  const struct config_host *hostc = &config.hosts.av[i].value;
  overlay_interface *interface = NULL;
  if (*hostc->interface){
    interface = overlay_interface_find_name(hostc->interface);
    if (!interface)
      return -1;
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
  DEBUGF("Loaded address %s:%d for %s", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), alloca_tohex_sid(subscriber->sid));
  return overlay_send_probe(subscriber, addr, interface, OQ_MESH_MANAGEMENT);
}

/* Collection of unicast echo responses to detect working links */
int
overlay_mdp_service_probe(overlay_mdp_frame *mdp)
{
  IN();
  if (mdp->out.src.port!=MDP_PORT_ECHO || mdp->out.payload_length != sizeof(struct probe_contents)){
    WARN("Probe packets should be returned from remote echo port");
    RETURN(-1);
  }
  
  struct subscriber *peer = find_subscriber(mdp->out.src.sid, SID_SIZE, 0);
  struct probe_contents probe;
  bcopy(&mdp->out.payload, &probe, sizeof(struct probe_contents));
  if (probe.addr.sin_family!=AF_INET)
    RETURN(WHY("Unsupported address family"));
  
  if (peer->reachable == REACHABLE_NONE || peer->reachable == REACHABLE_INDIRECT || (peer->reachable & REACHABLE_ASSUMED)){
    peer->interface = &overlay_interfaces[probe.interface];
    peer->address.sin_family = AF_INET;
    peer->address.sin_addr = probe.addr.sin_addr;
    peer->address.sin_port = probe.addr.sin_port;
    set_reachable(peer, REACHABLE_UNICAST);
  }
  RETURN(0);
}

int overlay_send_probe(struct subscriber *peer, struct sockaddr_in addr, overlay_interface *interface, int queue){
  if (interface==NULL)
    interface = overlay_interface_find(addr.sin_addr, 1);
  
  if (!interface)
    return WHY("I don't know which interface to use");
  
  time_ms_t now = gettime_ms();
  
  if (peer && peer->last_probe+1000>now)
    return -1;
  
  struct overlay_frame *frame=malloc(sizeof(struct overlay_frame));
  bzero(frame,sizeof(struct overlay_frame));
  frame->type=OF_TYPE_DATA;
  frame->source = my_subscriber;
  frame->next_hop = frame->destination = peer;
  frame->ttl=1;
  frame->queue=queue;
  frame->destination_resolved=1;
  frame->recvaddr=addr;
  frame->unicast=1;
  frame->interface=interface;
  frame->payload = ob_new();
  frame->source_full = 1;
  // TODO call mdp payload encryption / signing without calling overlay_mdp_dispatch...
  
  if (peer)
    peer->last_probe=gettime_ms();
  
  if (overlay_mdp_encode_ports(frame->payload, MDP_PORT_ECHO, MDP_PORT_PROBE)){
    op_free(frame);
    return -1;
  }
  // not worried about byte order here as we are the only node that should be parsing the contents.
  unsigned char *dst=ob_append_space(frame->payload, sizeof(struct probe_contents));
  if (!dst){
    op_free(frame);
    return -1;
  }
  struct probe_contents probe;
  probe.addr=addr;
  // get interface number
  probe.interface = interface - overlay_interfaces;
  bcopy(&probe, dst, sizeof(struct probe_contents));
  if (overlay_payload_enqueue(frame)){
    op_free(frame);
    return -1;
  }
  DEBUGF("Queued probe packet on interface %s to %s:%d for %s", 
	 interface->name, inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), peer?alloca_tohex_sid(peer->sid):"ANY");
  return 0;
}

// append the address of a unicast link into a packet buffer
static int overlay_append_unicast_address(struct subscriber *subscriber, struct overlay_buffer *buff)
{
  if (subscriber->reachable & REACHABLE_ASSUMED || !(subscriber->reachable & REACHABLE_UNICAST)){
    DEBUGF("Unable to give address of %s, %d", alloca_tohex_sid(subscriber->sid),subscriber->reachable);
    return 0;
  }
  
  if (overlay_address_append(NULL, buff, subscriber))
    return -1;
  if (ob_append_ui32(buff, subscriber->address.sin_addr.s_addr))
    return -1;
  if (ob_append_ui16(buff, subscriber->address.sin_port))
    return -1;
  ob_checkpoint(buff);
  DEBUGF("Added STUN info for %s", alloca_tohex_sid(subscriber->sid));
  return 0;
}

// append the address of all neighbour unicast links into a packet buffer
/*
 static int overlay_append_local_unicasts(struct subscriber *subscriber, void *context)
 {
 struct overlay_buffer *buff = context;
 if ((!subscriber->interface) ||
 (!(subscriber->reachable & REACHABLE_UNICAST)) ||
 (subscriber->reachable & REACHABLE_ASSUMED))
 return 0;
 if ((subscriber->address.sin_addr.s_addr & subscriber->interface->netmask.s_addr) !=
 (subscriber->interface->address.sin_addr.s_addr & subscriber->interface->netmask.s_addr))
 return 0;
 return overlay_append_unicast_address(subscriber, buff);
 }
 */

int overlay_mdp_service_stun_req(overlay_mdp_frame *mdp)
{
  DEBUGF("Processing STUN request from %s", alloca_tohex_sid(mdp->out.src.sid));
  
  struct overlay_buffer *payload = ob_static(mdp->out.payload, mdp->out.payload_length);
  ob_limitsize(payload, mdp->out.payload_length);
  
  overlay_mdp_frame reply;
  bzero(&reply, sizeof(reply));
  reply.packetTypeAndFlags=MDP_TX;
  
  bcopy(mdp->out.src.sid, reply.out.dst.sid, SID_SIZE);
  bcopy(mdp->out.dst.sid, reply.out.src.sid, SID_SIZE);
  reply.out.src.port=MDP_PORT_STUNREQ;
  reply.out.dst.port=MDP_PORT_STUN;
  reply.out.queue=OQ_MESH_MANAGEMENT;
  
  struct overlay_buffer *replypayload = ob_static(reply.out.payload, sizeof(reply.out.payload));
  
  ob_checkpoint(replypayload);
  while(ob_remaining(payload)>0){
    struct subscriber *subscriber=NULL;
    
    if (overlay_address_parse(NULL, payload, &subscriber))
      break;
    
    if (!subscriber){
      DEBUGF("Unknown subscriber");
      continue;
    }
    
    if (overlay_append_unicast_address(subscriber, replypayload))
      break;
  }
  
  ob_rewind(replypayload);
  reply.out.payload_length=ob_position(replypayload);
  
  if (reply.out.payload_length){
    DEBUGF("Sending reply");
    overlay_mdp_dispatch(&reply,0 /* system generated */,
			 NULL,0);
  }
  ob_free(replypayload);
  ob_free(payload);
  return 0;
}

int overlay_mdp_service_stun(overlay_mdp_frame *mdp)
{
  struct overlay_buffer *buff = ob_static(mdp->out.payload, mdp->out.payload_length);
  ob_limitsize(buff, mdp->out.payload_length);
  
  DEBUGF("Processing STUN info from %s", alloca_tohex_sid(mdp->out.src.sid));
  
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
    
    overlay_send_probe(subscriber, addr, NULL, OQ_MESH_MANAGEMENT);
  }
  
  ob_free(buff);
  return 0;
}

int overlay_send_stun_request(struct subscriber *server, struct subscriber *request){
  if ((!server) || (!request))
    return -1;
  if (!(subscriber_is_reachable(server)&REACHABLE))
    return -1;
  // don't bother with a stun request if the peer is already reachable directly
  // TODO link timeouts
  if (subscriber_is_reachable(request)&REACHABLE_DIRECT)
    return -1;
  
  time_ms_t now = gettime_ms();
  if (request->last_stun_request +1000 > now)
    return -1;
  
  request->last_stun_request=now;
  
  overlay_mdp_frame mdp;
  bzero(&mdp, sizeof(mdp));
  mdp.packetTypeAndFlags=MDP_TX;
  
  bcopy(my_subscriber->sid, mdp.out.src.sid, SID_SIZE);
  bcopy(server->sid, mdp.out.dst.sid, SID_SIZE);
  mdp.out.src.port=MDP_PORT_STUN;
  mdp.out.dst.port=MDP_PORT_STUNREQ;
  mdp.out.queue=OQ_MESH_MANAGEMENT;
  
  struct overlay_buffer *payload = ob_static(mdp.out.payload, sizeof(mdp.out.payload));
  overlay_address_append(NULL, payload, request);
  mdp.out.payload_length=ob_position(payload);
  DEBUGF("Sending STUN request to %s", alloca_tohex_sid(server->sid));
  overlay_mdp_dispatch(&mdp,0 /* system generated */,
		       NULL,0);
  ob_free(payload);
  return 0;
}
