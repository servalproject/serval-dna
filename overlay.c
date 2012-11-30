/*
Serval Distributed Numbering Architecture (DNA)
Copyright (C) 2010 Paul Gardner-Stephen
 
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

/*
  Serval Overlay Mesh Network.

  Basically we use UDP broadcast to send link-local, and then implement a BATMAN-like protocol over the top of that.
  
  Each overlay packet can contain one or more encapsulated packets each addressed using Serval DNA SIDs, with source, 
  destination and next-hop addresses.

  The use of an overlay also lets us be a bit clever about using irregular transports, such as an ISM915 modem attached via ethernet
  (which we are planning to build in coming months), by paring off the IP and UDP headers that would otherwise dominate.  Even on
  regular WiFi and ethernet we can aggregate packets in a way similar to IAX, but not just for voice frames.

  The use of long (relative to IPv4 or even IPv6) 256 bit Curve25519 addresses means that it is a really good idea to
  have neighbouring nodes exchange lists of peer aliases so that addresses can be summarised, possibly using less space than IPv4
  would have.
  
  One approach to handle address shortening is to have the periodic TTL=255 BATMAN-style hello packets include an epoch number.  
  This epoch number can be used by immediate neighbours of the originator to reference the neighbours listed in that packet by
  their ordinal position in the packet instead of by their full address.  This gets us address shortening to 1 byte in most cases 
  in return for no new packets, but the periodic hello packets will now be larger.  We might deal with this issue by having these
  hello packets reference the previous epoch for common neighbours.  Unresolved neighbour addresses could be resolved by a simple
  DNA request, which should only need to occur ocassionally, and other link-local neighbours could sniff and cache the responses
  to avoid duplicated traffic.  Indeed, during quiet times nodes could preemptively advertise address resolutions if they wished,
  or similarly advertise the full address of a few (possibly randomly selected) neighbours in each epoch.

  Byzantine Robustness is a goal, so we have to think about all sorts of malicious failure modes.

  One approach to help byzantine robustness is to have multiple signature shells for each hop for mesh topology packets.
  Thus forging a report of closeness requires forging a signature.  As such frames are forwarded, the outermost signature
  shell is removed. This is really only needed for more paranoid uses.

  We want to have different traffic classes for voice/video calls versus regular traffic, e.g., MeshMS frames.  Thus we need to have
  separate traffic queues for these items.  Aside from allowing us to prioritise isochronous data, it also allows us to expire old
  isochronous frames that are in-queue once there is no longer any point delivering them (e.g after holding them more than 200ms).
  We can also be clever about round-robin fair-sharing or even prioritising among isochronous streams.  Since we also know about the
  DNA isochronous protocols and the forward error correction and other redundancy measures we also get smart about dropping, say, 1 in 3
  frames from every call if we know that this can be safely done.  That is, when traffic is low, we maximise redundancy, and when we
  start to hit the limit of traffic, we start to throw away some of the redundancy.  This of course relies on us knowing when the
  network channel is getting too full.

  Smart-flooding of broadcast information is also a requirement.  The long addresses help here, as we can make any address that begins
  with the first 192 bits all ones be broadcast, and use the remaining 64 bits as a "broadcast packet identifier" (BPI).  
  Nodes can remember recently seen BPIs and not forward broadcast frames that have been seen recently.  This should get us smart flooding
  of the majority of a mesh (with some node mobility issues being a factor).  We could refine this later, but it will do for now, especially
  since for things like number resolution we are happy to send repeat requests.

  This file currently seems to exist solely to contain this introduction, which is fine with me. Functions land in here until their
  proper place becomes apparent.
  
*/

#include "serval.h"
#include "rhizome.h"
#include "strbuf.h"

int overlayMode=0;

keyring_file *keyring=NULL;

int overlayServerMode()
{
  /* In overlay mode we need to listen to all of our sockets, and also to
     send periodic traffic. This means we need to */
  INFO("Running in overlay mode.");

  /* Get keyring available for use.
     Required for MDP, and very soon as a complete replacement for the
     HLR for DNA lookups, even in non-overlay mode. */
  keyring=keyring_open_with_pins("");
  if (!keyring) {
    return WHY("Could not open serval keyring file.");
  }
  /* put initial identity in if we don't have any visible */
  keyring_seed(keyring);

  overlay_queue_init();
  
  /* Get the set of socket file descriptors we need to monitor.
     Note that end-of-file will trigger select(), so we cannot run select() if we 
     have any dummy interfaces running. So we do an ugly hack of just waiting no more than
     5ms between checks if we have a dummy interface running.  This is a reasonable simulation
     of wifi latency anyway, so we'll live with it.  Larger values will affect voice transport,
     and smaller values would affect CPU and energy use, and make the simulation less realistic. */

  time_ms_t now = gettime_ms();
  
#define SCHEDULE(X, Y, D) { \
static struct profile_total _stats_##X={.name="" #X "",}; \
static struct sched_ent _sched_##X={\
  .stats = &_stats_##X, \
  .function=X,\
}; \
_sched_##X.alarm=(now+Y);\
_sched_##X.deadline=(now+Y+D);\
schedule(&_sched_##X); }
  
  /* Periodically check for server shut down */
  SCHEDULE(server_shutdown_check, 0, 100);
  
  /* Setup up MDP & monitor interface unix domain sockets */
  overlay_mdp_setup_sockets();
  monitor_setup_sockets();
  
  olsr_init_socket();

  /* Get rhizome server started BEFORE populating fd list so that
     the server's listen socket is in the list for poll() */
  if (is_rhizome_enabled()) rhizome_opendb();

  /* Rhizome http server needs to know which callback to attach
	 to client sockets, so provide it here, along with the name to
	 appear in time accounting statistics. */
  if (is_rhizome_http_enabled())
    rhizome_http_server_start(rhizome_server_parse_http_request,
			      "rhizome_server_parse_http_request",
			      RHIZOME_HTTP_PORT,RHIZOME_HTTP_PORT_MAX);    

  // start the dna helper if configured
  dna_helper_start();
  
  // preload directory service information
  directory_service_init();
  
  /* Periodically check for new interfaces */
  SCHEDULE(overlay_interface_discover, 1, 100);

  /* Periodically update route table. */
  SCHEDULE(overlay_route_tick, 100, 100);

  /* Show CPU usage stats periodically */
  if (debug&DEBUG_TIMING){
    SCHEDULE(fd_periodicstats, 3000, 500);
  }

#undef SCHEDULE
  
  while(1) {
    /* Check for activitiy and respond to it */
    fd_poll();
  }

  return 0;
}
