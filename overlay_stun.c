/*
Serval DNA MDP overlay network link tracking
Copyright (C) 2016 Flinders University
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
#include "route_link.h"
#include "overlay_interface.h"
#include "overlay_buffer.h"
#include "debug.h"

DEFINE_BINDING(MDP_PORT_STUN, overlay_mdp_service_stun);
static int overlay_mdp_service_stun(struct internal_mdp_header *header, struct overlay_buffer *payload)
{
  DEBUGF(overlayrouting, "Processing STUN info from %s", alloca_tohex_sid_t(header->source->sid));

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
    
    // only trust stun responses from our directory service or about the packet sender.
    if (directory_service == header->source || subscriber == header->source){
      overlay_interface *interface = overlay_interface_find(addr.inet.sin_addr, 1);
      if (!interface){
	WARNF("Can't find interface for %s", alloca_socket_address(&addr));
	return 0;
      }
      struct network_destination *destination = create_unicast_destination(&addr, interface);
      if (destination){
	overlay_send_probe(subscriber, destination, OQ_MESH_MANAGEMENT);
	release_destination_ref(destination);
      }
    }
  }
  return 0;
}
