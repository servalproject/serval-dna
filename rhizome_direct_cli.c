/*
Serval DNA Rhizome Direct
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

#include "feature.h"
#include "commandline.h"
#include "rhizome.h"
#include "mem.h"
#include "conf.h"
#include "debug.h"
#include "str.h"

DEFINE_FEATURE(cli_rhizome_direct);

/*
  Initiate a synchronisation episode.
*/
static int rhizome_direct_start_sync_request(rhizome_direct_sync_request *r)
{
  assert(r);
  assert(r->syncs_started==r->syncs_completed);

  r->syncs_started++;

  return rhizome_direct_continue_sync_request(r);  
}

static int rhizome_sync_with_peers(int mode, int peer_count, const struct config_rhizome_peer *const *peers)
{
  /* Get iterator capable of 64KB buffering.
     In future we should parse the sync URL and base the buffer size on the
     transport and allowable traffic volumes. */
  rhizome_direct_transport_state_http *state = emalloc_zero(sizeof(rhizome_direct_transport_state_http));
  /* XXX This code runs each sync in series, when we can probably do them in
     parallel.  But we can't really do them in parallel until we make the
     synchronisation process fully asynchronous, which probably won't happen
     for a while yet.
     Also, we don't currently parse the URI protocol field fully. */
  int peer_number;
  for (peer_number = 0; peer_number < peer_count; ++peer_number) {
    const struct config_rhizome_peer *peer = peers[peer_number];
    if (strcasecmp(peer->protocol, "http") != 0)
      return WHYF("Unsupported Rhizome Direct protocol %s", alloca_str_toprint(peer->protocol));
    strbuf h = strbuf_local(state->host, sizeof state->host);
    strbuf_puts(h, peer->host);
    if (strbuf_overrun(h))
      return WHYF("Rhizome Direct host name too long: %s", alloca_str_toprint(peer->host));
    state->port = peer->port;
    DEBUGF(rhizome_direct, "Rhizome direct peer is %s://%s:%d", peer->protocol, state->host, state->port);
    rhizome_direct_sync_request *s = rhizome_direct_new_sync_request(rhizome_direct_http_dispatch, 65536, 0, mode, state);
    rhizome_direct_start_sync_request(s);
    if (rd_sync_handle_count > 0)
      while (fd_poll() && rd_sync_handle_count > 0)
	;
  }
  return 0;
}

DEFINE_CMD(app_rhizome_direct_sync, 0,
  "Synchronise with the specified Rhizome Direct server.",
  "rhizome","direct","push|pull|sync","[<url>]");
static int app_rhizome_direct_sync(const struct cli_parsed *parsed, struct cli_context *UNUSED(context))
{
  DEBUG_cli_parsed(verbose, parsed);
  /* Attempt to connect with a remote Rhizome Direct instance,
     and negotiate which BARs to synchronise. */
  const char *modeName = (parsed->argc >= 3 ? parsed->args[2] : "sync");
  int mode=3; /* two-way sync */
  if (!strcasecmp(modeName,"push")) mode=1; /* push only */
  if (!strcasecmp(modeName,"pull")) mode=2; /* pull only */
  DEBUGF(rhizome_direct, "sync direction = %d",mode);
  rhizome_opendb();
  if (parsed->args[3]) {
    struct config_rhizome_peer peer;
    const struct config_rhizome_peer *peers[1] = { &peer };
    int result = cf_opt_rhizome_peer_from_uri(&peer, parsed->args[3]);
    if (result == CFOK)
      return rhizome_sync_with_peers(mode, 1, peers);
    else {
      strbuf b = strbuf_alloca(128);
      strbuf_cf_flag_reason(b, result);
      return WHYF("Invalid peer URI %s -- %s", alloca_str_toprint(parsed->args[3]), strbuf_str(b));
    }
  } else if (config.rhizome.direct.peer.ac == 0) {
    DEBUG(rhizome_direct, "No rhizome direct peers were configured or supplied");
    return -1;
  } else {
    const struct config_rhizome_peer *peers[config.rhizome.direct.peer.ac];
    unsigned i;
    for (i = 0; i < config.rhizome.direct.peer.ac; ++i)
      peers[i] = &config.rhizome.direct.peer.av[i].value;
    return rhizome_sync_with_peers(mode, config.rhizome.direct.peer.ac, peers);
  }
}
