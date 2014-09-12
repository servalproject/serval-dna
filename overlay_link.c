/*
Serval DNA MDP overlay network link tracking
Copyright (C) 2012-2013 Serval Project Inc.
Copyright (C) 2010-2012 Paul Gardner-Stephen
 
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
#include "conf.h"
#include "str.h"
#include "overlay_address.h"
#include "overlay_buffer.h"
#include "overlay_interface.h"
#include "overlay_packet.h"
#include "keyring.h"
#include "strbuf_helpers.h"

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
  struct socket_address addr;
  bzero(&addr, sizeof(addr));
  addr.addrlen = sizeof(addr.inet);
  addr.inet.sin_family = AF_INET;
  addr.inet.sin_addr = hostc->address;
  addr.inet.sin_port = htons(hostc->port);
  if (addr.inet.sin_addr.s_addr==INADDR_NONE){
    if (interface || overlay_interface_get_default()){
      if (resolve_name(hostc->host, &addr.inet.sin_addr))
	return -1;
    }else{
      // interface isnt up yet
      return 1;
    }
  }
  if (config.debug.overlayrouting)
    DEBUGF("Loaded address %s for %s", alloca_socket_address(&addr), alloca_tohex_sid_t(subscriber->sid));
  struct network_destination *destination = create_unicast_destination(&addr, interface);
  if (!destination)
    return -1;
  int ret=overlay_send_probe(subscriber, destination, OQ_MESH_MANAGEMENT);
  release_destination_ref(destination);
  return ret;
}

/* Collection of unicast echo responses to detect working links */
int
overlay_mdp_service_probe(struct internal_mdp_header *header, struct overlay_buffer *payload)
{
  IN();
  if (header->source_port!=MDP_PORT_ECHO){
    WARN("Probe packets should be returned from remote echo port");
    RETURN(-1);
  }
  
  if (header->source->reachable == REACHABLE_SELF)
    RETURN(0);
  
  uint8_t interface = ob_get(payload);
  struct socket_address addr;
  addr.addrlen = ob_remaining(payload);
  
  if (addr.addrlen > sizeof(addr.store))
    RETURN(-1);
  
  ob_get_bytes(payload, (unsigned char*)&addr.addr, addr.addrlen);
  
  RETURN(link_unicast_ack(header->source, &overlay_interfaces[interface], &addr));
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
  
  // TODO enhance overlay_send_frame to support pre-supplied network destinations
  
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
  
  overlay_mdp_encode_ports(frame->payload, MDP_PORT_ECHO, MDP_PORT_PROBE);
  
  ob_append_byte(frame->payload, destination->interface - overlay_interfaces);
  ob_append_bytes(frame->payload, (uint8_t*)&destination->address.addr, destination->address.addrlen);
  
  if (overlay_payload_enqueue(frame)){
    op_free(frame);
    return -1;
  }
  if (config.debug.overlayrouting)
    DEBUGF("Queued probe packet on interface %s to %s for %s", 
	 destination->interface->name, 
	 alloca_socket_address(&destination->address), 
	 peer?alloca_tohex_sid_t(peer->sid):"ANY");
  return 0;
}

// append the address of a unicast link into a packet buffer
static void overlay_append_unicast_address(struct subscriber *subscriber, struct overlay_buffer *buff)
{
  if (   subscriber->destination 
      && subscriber->destination->unicast
      && subscriber->destination->address.addr.sa_family==AF_INET
  ) {
    overlay_address_append(NULL, buff, subscriber);
    ob_append_ui32(buff, subscriber->destination->address.inet.sin_addr.s_addr);
    ob_append_ui16(buff, subscriber->destination->address.inet.sin_port);
    if (config.debug.overlayrouting)
      DEBUGF("Added STUN info for %s", alloca_tohex_sid_t(subscriber->sid));
  }else{
    if (config.debug.overlayrouting)
      DEBUGF("Unable to give address of %s, %d", alloca_tohex_sid_t(subscriber->sid),subscriber->reachable);
  }
}

int overlay_mdp_service_stun_req(struct internal_mdp_header *header, struct overlay_buffer *payload)
{
  if (config.debug.overlayrouting)
    DEBUGF("Processing STUN request from %s", alloca_tohex_sid_t(header->source->sid));

  struct internal_mdp_header reply;
  bzero(&reply, sizeof reply);
  
  mdp_init_response(header, &reply);
  reply.qos = OQ_MESH_MANAGEMENT;
  
  struct overlay_buffer *replypayload = ob_new();
  ob_limitsize(replypayload, MDP_MTU);
  
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
  
  if (ob_position(replypayload)){
    if (config.debug.overlayrouting)
      DEBUGF("Sending reply");
    ob_flip(replypayload);
    overlay_send_frame(&reply, replypayload);
  }
  ob_free(replypayload);
  return 0;
}

int overlay_mdp_service_stun(struct internal_mdp_header *header, struct overlay_buffer *payload)
{
  if (config.debug.overlayrouting)
    DEBUGF("Processing STUN info from %s", alloca_tohex_sid_t(header->source->sid));

  while(ob_remaining(payload)>0){
    struct subscriber *subscriber=NULL;
    
    // TODO explain addresses, link expiry time, resolve differences between addresses...
    
    if (overlay_address_parse(NULL, payload, &subscriber)){
      break;
    }
    struct socket_address addr;
    addr.addrlen = sizeof(addr.inet);
    addr.inet.sin_family = AF_INET;
    addr.inet.sin_addr.s_addr = ob_get_ui32(payload);
    addr.inet.sin_port = ob_get_ui16(payload);
    
    if (!subscriber || (subscriber->reachable&REACHABLE_DIRECT))
      continue;
    
    struct network_destination *destination = create_unicast_destination(&addr, NULL);
    if (destination){
      overlay_send_probe(subscriber, destination, OQ_MESH_MANAGEMENT);
      release_destination_ref(destination);
    }
  }
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
  
  struct internal_mdp_header header;
  bzero(&header, sizeof header);
  header.source = my_subscriber;
  header.destination = server;
  
  header.source_port = MDP_PORT_STUN;
  header.destination_port = MDP_PORT_STUNREQ;
  header.qos = OQ_MESH_MANAGEMENT;
  
  struct overlay_buffer *payload = ob_new();
  ob_limitsize(payload, MDP_MTU);
  
  overlay_address_append(NULL, payload, request);
  if (!ob_overrun(payload)) {
    if (config.debug.overlayrouting)
      DEBUGF("Sending STUN request to %s", alloca_tohex_sid_t(server->sid));
      
    ob_flip(payload);
    overlay_send_frame(&header, payload);
  }
  ob_free(payload);
  return 0;
}
