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
#include "conf.h"
#include "rhizome.h"
#include "httpd.h"
#include "strbuf.h"
#include "keyring.h"
#include "overlay_interface.h"
#include "server.h"

int overlayMode=0;

keyring_file *keyring=NULL;

/* The caller must set up the keyring before calling this function, and the keyring must contain at
 * least one identity, otherwise MDP and routing will not work.
 */
int overlayServerMode()
{
  IN();

  /* Setup up client API sockets before writing our PID file
     We want clients to be able to connect to our sockets as soon 
     as servald start has returned. But we don't want servald start
     to take very long. 
     Try to perform only minimal CPU or IO processing here.
  */
  overlay_mdp_setup_sockets();
  monitor_setup_sockets();
  // start the HTTP server if enabled
  httpd_server_start(HTTPD_PORT, HTTPD_PORT_MAX);    
 
  /* record PID file so that servald start can return */
  if (server_write_pid())
    RETURN(-1);
  
  overlay_queue_init();
  
  if (is_rhizome_enabled()){
    rhizome_opendb();
    if (config.rhizome.clean_on_start && !config.rhizome.clean_on_open)
      rhizome_cleanup(NULL);
  }

  time_ms_t now = gettime_ms();
  
  /* Periodically check for server shut down */
  RESCHEDULE_ALARM(server_shutdown_check, now, 100);
  
  /* Periodically reload configuration */
  RESCHEDULE_ALARM(server_config_reload, now+config.server.config_reload_interval_ms, 100);
  
  overlay_mdp_bind_internal_services();
  
  olsr_init_socket();

  /* Calculate (and possibly show) CPU usage stats periodically */
  RESCHEDULE_ALARM(fd_periodicstats, now+3000, 500);

  cf_on_config_change();
  
  // log message used by tests to wait for the server to start
  INFO("Server initialised, entering main loop");
  /* Check for activitiy and respond to it */
  while(fd_poll() && (serverMode==1));
  
  serverCleanUp();
  RETURN(0);
  OUT();
}
