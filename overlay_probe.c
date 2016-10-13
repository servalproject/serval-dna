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
#include "fdqueue.h"

/* Collection of unicast echo responses to detect working links */
DEFINE_BINDING(MDP_PORT_PROBE, overlay_mdp_service_probe);
static int overlay_mdp_service_probe(struct internal_mdp_header *header, struct overlay_buffer *payload)
{
  IN();
  if (header->source_port!=MDP_PORT_ECHO){
    WARN("Probe packets should be returned from remote echo port");
    RETURN(-1);
  }
  DEBUGF(overlayrouting, "Received probe response from %s", alloca_tohex_sid_t(header->source->sid));
  
  if (header->source->reachable == REACHABLE_SELF)
    RETURN(0);
  
  uint8_t interface = ob_get(payload);
  struct socket_address addr;
  addr.addrlen = ob_remaining(payload);
  
  if (addr.addrlen > sizeof(addr.store))
    RETURN(WHY("Badly formatted probe packet"));
  
  ob_get_bytes(payload, (unsigned char*)&addr.addr, addr.addrlen);
  
  RETURN(link_unicast_ack(header->source, &overlay_interfaces[interface], &addr));
  OUT();
}
