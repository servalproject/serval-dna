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

/* @PGS/20120615 */
int last_valid=0;
int last_line;
const char *last_file;
const char *last_func;
long long last_time;

/* @PGS/20120615 */
void TIMING_PAUSE()
{
  last_valid=0;
}

/* @PGS/20120615 */
void _TIMING_CHECK(const char *file,const char *func,int line)
{
  long long now=overlay_gettime_ms();
  if (last_valid) {
    if (now-last_time>5) {
      // More than 5ms spent in a given task, complain
      char msg[1024];
      snprintf(msg,1024,"Spent %lldms between %s:%d in %s() and here",
	       now-last_time,last_file,last_line,last_func);
      logMessage(LOG_LEVEL_WARN,file,line,func,"%s",msg);
    }
  }

  last_valid=1;
  last_file=file;
  last_func=func;
  last_line=line;
  last_time=now;
}


int overlayMode=0;

overlay_txqueue overlay_tx[OQ_MAX];

keyring_file *keyring=NULL;

int overlayServerMode()
{
  /* In overlay mode we need to listen to all of our sockets, and also to
     send periodic traffic. This means we need to */
  fprintf(stderr,"Running in overlay mode.\n");
  
  /* Get keyring available for use.
     Required for MDP, and very soon as a complete replacement for the
     HLR for DNA lookups, even in non-overlay mode. */
  keyring=keyring_open_with_pins("");
  if (!keyring) {
    return WHY("Could not open serval keyring file.");
  }
  /* put initial identity in if we don't have any visible */
  keyring_seed(keyring);

  /* Set default congestion levels for queues */
  int i;
  for(i=0;i<OQ_MAX;i++) {
    overlay_tx[i].maxLength=100;
    overlay_tx[i].latencyTarget=5000; /* Keep packets in queue for 5 seconds by default */
  }
  /* But expire voice/video call packets much sooner, as they just aren't any use if late */
  overlay_tx[OQ_ISOCHRONOUS_VOICE].latencyTarget=500;
  overlay_tx[OQ_ISOCHRONOUS_VIDEO].latencyTarget=500;

  /* Get the set of socket file descriptors we need to monitor.
     Note that end-of-file will trigger select(), so we cannot run select() if we 
     have any dummy interfaces running. So we do an ugly hack of just waiting no more than
     5ms between checks if we have a dummy interface running.  This is a reasonable simulation
     of wifi latency anyway, so we'll live with it.  Larger values will affect voice transport,
     and smaller values would affect CPU and energy use, and make the simulation less realistic. */

  /* Create structures to use 1MB of RAM for testing */
  overlay_route_init(1);

  /* Setup up MDP unix domain sockets */
  overlay_mdp_setup_sockets();

  /* Get rhizome server started BEFORE populating fd list so that
     the server's listen socket is in the list for poll() */
  if (rhizome_enabled()) rhizome_server_start();
  /* Pick next rhizome files to grab every few seconds
     from the priority list continuously being built from observed
     bundle announcements */
  fd_setalarm(rhizome_enqueue_suggestions,3000,3000);

  /* Periodically check for new interfaces */
  fd_setalarm(overlay_interface_discover,1,5000);

  /* Periodically check for server shut down */
  fd_setalarm(server_shutdown_check,1,1000);

  /* Periodically update route table.
     (Alarm interval is dynamically updated by overlay_route_tick()
      based on load/route table size etc) */
  fd_setalarm(overlay_route_tick,1000,1000);

  while(1) {

    /* Check for activitiy and respond to it */
    fd_list();
    fd_poll();

    /* Work out how long we can wait before we need to tick */
    memabuseCheck();

    vomp_tick();

    overlay_check_ticks();
  }

  return 0;
}

int overlay_frame_process(int interface,overlay_frame *f)
{
  if (!f) return WHY("f==NULL");

  long long now=overlay_gettime_ms();

  if (f->source_address_status==OA_RESOLVED&&overlay_address_is_local(f->source))
      return WHY("Dropping frame claiming to come from myself.");

  if (debug&DEBUG_OVERLAYFRAMES) fprintf(stderr,">>> Received frame (type=%02x, bytes=%d)\n",f->type,f->payload?f->payload->length:-1);

  /* First order of business is whether the nexthop address has been resolved.
     If not, we need to think about asking for it to be resolved.
     The trouble is that we do not want to trigger a Hanson Event (a storm of
     please explains/resolution requests). Yet, we do not want to delay 
     communications unnecessarily.  

     The simple solution for now is to queue the address for resolution request
     in our next tick.  If we see another resolution request for the same
     address in the mean time, then we can cancel our request */
  switch (f->nexthop_address_status)
    {
    case OA_UNINITIALISED:
      /* Um? Right. */
      return WHY("frame passed with ununitialised nexthop address");
      break;
    case OA_RESOLVED:
      /* Great, we have the address, so we can get on with things */
      break;
    case OA_PLEASEEXPLAIN:
      return -1; //  WHY("Address cannot be resolved -- aborting packet processing.");
      /* XXX Should send a please explain to get this address resolved. */
      break;
    case OA_UNSUPPORTED:
    default:
      /* If we don't support the address format, we should probably tell
	 the sender. Again, we queue this up, and cancel it if someone else
	 tells them in the meantime to avoid an Opposition Event (like a Hanson
	 Event, but repeatedly berating any node that holds a different policy
	 to itself. */
      WHY("Packet with unsupported address format");
      overlay_interface_repeat_abbreviation_policy[interface]=1;
      return -1;
      break;
    }

  /* Okay, nexthop is valid, so let's see if it is us */
  int forMe=0,i;
  int ultimatelyForMe=0;
  int broadcast=0;
  int nhbroadcast=overlay_address_is_broadcast(f->nexthop);
  int duplicateBroadcast=0;

  if (nhbroadcast) {
    if (overlay_broadcast_drop_check(f->nexthop)) duplicateBroadcast=1;
    
    forMe=1; }
  if (overlay_address_is_local(f->nexthop)) forMe=1;

  if (forMe) {
    /* It's for us, so resolve the addresses */
    if (overlay_frame_resolve_addresses(interface,f))
      return WHY("Failed to resolve destination and sender addresses in frame");
    broadcast=overlay_address_is_broadcast(f->destination);    
    if (debug&DEBUG_OVERLAYFRAMES) {
      fprintf(stderr,"Destination for this frame is (resolve code=%d): ",f->destination_address_status);
      if (f->destination_address_status==OA_RESOLVED) for(i=0;i<SID_SIZE;i++) fprintf(stderr,"%02x",f->destination[i]); else fprintf(stderr,"???");
      fprintf(stderr,"\n");
      fprintf(stderr,"Source for this frame is (resolve code=%d): ",f->source_address_status);
      if (f->source_address_status==OA_RESOLVED) for(i=0;i<SID_SIZE;i++) fprintf(stderr,"%02x",f->source[i]); else fprintf(stderr,"???");
      fprintf(stderr,"\n");
    }

    if (f->source_address_status!=OA_RESOLVED) {
      if (debug&DEBUG_OVERLAYFRAMES) WHY("Source address could not be resolved, so dropping frame.");
      return -1;
    }
    if (overlay_address_is_local(f->source))
      {
	/* not that noteworthy, as when listening to a broadcast socket
	   you hear everything you send. */
	if (debug&DEBUG_OVERLAYROUTING) 
	  WHY("Dropping frame claiming to come from myself.");
	return -1;
      }

    if (f->destination_address_status==OA_RESOLVED) {
      if (overlay_address_is_broadcast(f->destination))	
	{ ultimatelyForMe=1; broadcast=1; }
      if (overlay_address_is_local(f->destination)) ultimatelyForMe=1;
    } else {
      if (debug&DEBUG_OVERLAYFRAMES) WHY("Destination address could not be resolved, so dropping frame.");
      return WHY("could not resolve destination address");
    }
  }

  if (debug&DEBUG_OVERLAYFRAMES) {
    fprintf(stderr,"This frame does%s have me listed as next hop.\n",forMe?"":" not");
    fprintf(stderr,"This frame is%s for me.\n",ultimatelyForMe?"":" not");
    fprintf(stderr,"This frame is%s%s broadcast.\n",
	    broadcast?"":" not",duplicateBroadcast?" a duplicate":"");
  }

  if (duplicateBroadcast) {
    if (0) WHY("Packet is duplicate broadcast");
    return 0;
  }

  /* Not for us? Then just ignore it */
  if (!forMe) {
    return 0;
  }

  /* Is this a frame we have to forward on? */
  if (((!ultimatelyForMe)||broadcast)&&(f->ttl>1))
    {
      /* Yes, it is. */
      int len=0;      

      if (broadcast&&(!duplicateBroadcast)&&
	  ((f->type==OF_TYPE_SELFANNOUNCE)
	   ||(f->type==OF_TYPE_RHIZOME_ADVERT)
	   ))
	{
	  // Don't forward broadcast self-announcement packets as that is O(n^2) with
	  // traffic.  We have other means to propagating the mesh topology information.
	  // Similarly, rhizome advertisement traffic is always link local, so don't 
	  // forward that either.
	  if (debug&DEBUG_BROADCASTS)
	    if (duplicateBroadcast)
	      fprintf(stderr,"Dropping broadcast frame (BPI seen before)\n");
	} else {
	if (debug&DEBUG_OVERLAYFRAMES) fprintf(stderr,"\nForwarding frame.\n");
	int dontForward=0;
	if (!broadcast) {
	  if (overlay_get_nexthop(f->destination,f->nexthop,&len,
				  &f->nexthop_interface))
	    WHY("Could not find next hop for host - dropping frame");
	  dontForward=1;
	}
	f->ttl--;

	if (0)
	  printf("considering forwarding frame to %s (forme=%d, bcast=%d, dup=%d)\n",
		 overlay_render_sid(f->destination),ultimatelyForMe,broadcast,
		 duplicateBroadcast);

	if (overlay_address_is_broadcast(f->destination))
	  {
	    /* if nexthop and destination address are the same, and nexthop was shown
	       not to be a duplicate, then we don't need to test the destination
	       address for being a duplicate broadcast. */
	    int sameAsNextHop=1,i;
	    for(i=0;i<SID_SIZE;i++) 
	      if (f->nexthop[i]!=f->destination[i])
		{ sameAsNextHop=0; break; }

	    if ((!sameAsNextHop)&&overlay_broadcast_drop_check(f->destination))
	      duplicateBroadcast=1;
	    if (duplicateBroadcast)
	      { 
		printf("reject src is %s\n",overlay_render_sid(f->source));
		printf("reject nexthop is %s\n",overlay_render_sid(f->nexthop));
		printf("reject destination is %s\n",
		       overlay_render_sid(f->destination));		
		return WHY("Not forwarding or reading duplicate broadcast");
	      }
	  }

	if (!dontForward) {
	  /* Queue frame for dispatch.
	     Don't forget to put packet in the correct queue based on type.
	     (e.g., mesh management, voice, video, ordinary or opportunistic).

	     But the really important bit is to clone the frame, since the
	     structure we are looking at here must be left as is and returned
	     to the caller to do as they please */	  
	  overlay_frame *qf=op_dup(f);
	  if (!qf) WHY("Could not clone frame for queuing");
	  else {
	    int qn=OQ_ORDINARY;
	    /* Make sure voice traffic gets priority */
	    if ((qf->type&OF_TYPE_BITS)==OF_TYPE_DATA_VOICE) {
	      qn=OQ_ISOCHRONOUS_VOICE;
	      rhizome_saw_voice_traffic();
	    }
	    if (0) WHY("queuing frame for forwarding");
	    if (overlay_payload_enqueue(qn,qf,0)) {
	      WHY("failed to enqueue forwarded payload");
	      op_free(qf);
	    }
	  }
	}

	/* If the frame was a broadcast frame, then we need to hang around
	   so that we can process it, since we are one of the recipients.
	   Otherwise, return triumphant. */
	if (!broadcast) return 0;
      }
    }

  switch(f->type)
    {
    case OF_TYPE_SELFANNOUNCE:
      overlay_route_saw_selfannounce(interface,f,now);
      break;
    case OF_TYPE_SELFANNOUNCE_ACK:
      overlay_route_saw_selfannounce_ack(interface,f,now);
      break;
    case OF_TYPE_NODEANNOUNCE:
      overlay_route_saw_advertisements(interface,f,now);
      break;
    case OF_TYPE_RHIZOME_ADVERT:
      overlay_rhizome_saw_advertisements(interface,f,now);
      break;
    case OF_TYPE_DATA:
    case OF_TYPE_DATA_VOICE:
      if (0) {
	WHY("saw mdp containing frame");
	printf("  src = %s\n",overlay_render_sid(f->source));
	printf("  nxt = %s\n",overlay_render_sid(f->nexthop));
	printf("  dst = %s\n",overlay_render_sid(f->destination));
	fflush(stdout);
	dump("payload",&f->payload->bytes[0],f->payload->length);
	fflush(stdout);
      }
      overlay_saw_mdp_containing_frame(interface,f,now);
      break;
    default:
      fprintf(stderr,"Unsupported f->type=0x%x\n",f->type);
      return WHY("Support for that f->type not yet implemented");
      break;
    }

  return 0;
}

