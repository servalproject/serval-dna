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
    DEBUGF(overlayrouting, "Added STUN info for %s", alloca_tohex_sid_t(subscriber->sid));
  }else{
    DEBUGF(overlayrouting, "Unable to give address of %s, %d", alloca_tohex_sid_t(subscriber->sid),subscriber->reachable);
  }
}

DEFINE_BINDING(MDP_PORT_STUNREQ, overlay_mdp_service_stun_req);
static int overlay_mdp_service_stun_req(struct internal_mdp_header *header, struct overlay_buffer *payload)
{
  DEBUGF(overlayrouting, "Processing STUN request from %s", alloca_tohex_sid_t(header->source->sid));

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
      DEBUGF(overlayrouting, "Unknown subscriber");
      continue;
    }
    overlay_append_unicast_address(subscriber, replypayload);
    if (ob_overrun(payload))
      break;
    ob_checkpoint(replypayload);
  }
  ob_rewind(replypayload);
  
  if (ob_position(replypayload)){
    DEBUGF(overlayrouting, "Sending reply");
    ob_flip(replypayload);
    overlay_send_frame(&reply, replypayload);
  }
  ob_free(replypayload);
  return 0;
}
