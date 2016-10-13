/*
Serval DNA MDP echo service
Copyright (C) 2016 Flinders University
Copyright (C) 2012-2015 Serval Project Inc.
Copyright (C) 2012 Paul Gardner-Stephen
 
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

#include "mdp_client.h"
#include "overlay_packet.h"
#include "fdqueue.h"

DEFINE_BINDING(MDP_PORT_ECHO, overlay_mdp_service_echo);
static int overlay_mdp_service_echo(struct internal_mdp_header *header, struct overlay_buffer *payload)
{
  IN();
  
  if (header->source_port == MDP_PORT_ECHO)
    RETURN(WHY("Prevented infinite echo loop"));
    
  struct internal_mdp_header response_header;
  bzero(&response_header, sizeof response_header);
  
  mdp_init_response(header, &response_header);
  // keep all defaults
  
  RETURN(overlay_send_frame(&response_header, payload));
  OUT();
}
