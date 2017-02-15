/*
Serval DNA daemon features
Copyright (C) 2016 Flinders University

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

#include "feature.h"

void servald_features()
{
  USE_FEATURE(cli_version);
  USE_FEATURE(cli_echo);
  USE_FEATURE(cli_log);
  USE_FEATURE(cli_config);
  USE_FEATURE(cli_server);
  USE_FEATURE(cli_keyring);
  USE_FEATURE(cli_network);
  USE_FEATURE(cli_rhizome);
  USE_FEATURE(cli_meshms);
  USE_FEATURE(cli_meshmb);
  USE_FEATURE(cli_monitor);
  USE_FEATURE(cli_msp_proxy);
  USE_FEATURE(cli_rhizome_direct);

  USE_FEATURE(mdp_binding_MDP_PORT_ECHO);
  USE_FEATURE(mdp_binding_MDP_PORT_TRACE);
  USE_FEATURE(mdp_binding_MDP_PORT_KEYMAPREQUEST);
  USE_FEATURE(mdp_binding_MDP_PORT_DNALOOKUP);
  USE_FEATURE(mdp_binding_MDP_PORT_PROBE);
  USE_FEATURE(mdp_binding_MDP_PORT_STUN);
  USE_FEATURE(mdp_binding_MDP_PORT_STUNREQ);
  USE_FEATURE(mdp_binding_MDP_PORT_LINKSTATE);
  USE_FEATURE(mdp_binding_MDP_PORT_VOMP);
  USE_FEATURE(mdp_binding_MDP_PORT_RHIZOME_SYNC_BARS);
  USE_FEATURE(mdp_binding_MDP_PORT_RHIZOME_SYNC_KEYS);
  USE_FEATURE(mdp_binding_MDP_PORT_RHIZOME_REQUEST);
  USE_FEATURE(mdp_binding_MDP_PORT_RHIZOME_RESPONSE);
  USE_FEATURE(mdp_binding_MDP_PORT_RHIZOME_MANIFEST_REQUEST);

  USE_FEATURE(http_server);
  USE_FEATURE(http_rhizome);
  USE_FEATURE(http_rhizome_direct);
  USE_FEATURE(http_rest_keyring);
  USE_FEATURE(http_rest_rhizome);
  USE_FEATURE(http_rest_meshms);
  USE_FEATURE(http_rest_meshmb);
}
