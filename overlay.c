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

  This file currently seems to exist solely to contain this introduction, which is fine with me. Functions land in here until their
  proper place becomes apparent.
  
*/

#include "mphlr.h"

int overlayMode=0;

overlay_txqueue overlay_tx[OQ_MAX];

int overlayServerMode()
{
  /* In overlay mode we need to listen to all of our sockets, and also to
     send periodic traffic. This means we need to */
  fprintf(stderr,"Running in overlay mode.\n");
  
  /* Get the set of socket file descriptors we need to monitor.
     Note that end-of-file will trigger select(), so we cannot run select() if we 
     have any dummy interfaces running. So we do an ugly hack of just waiting no more than
     5ms between checks if we have a dummy interface running.  This is a reasonable simulation
     of wifi latency anyway, so we'll live with it.  Larger values will affect voice transport,
     and smaller values would affect CPU and energy use, and make the simulation less realistic. */
  int i;
  fd_set read_fds;
  int maxfd=-1;  

  /* Create structures to use 1MB of RAM for testing */
  overlay_route_init(1);

  /* Add all local SIDs to our cache */
  int ofs=0;
  while(findHlr(hlr,&ofs,NULL,NULL)) {
    overlay_abbreviate_cache_address(&hlr[ofs+4]);
    if (nextHlr(hlr,&ofs)) break;
  }

  while(1) {
    /* Work out how long we can wait before we need to tick */
    long long ms=overlay_time_until_next_tick();
    struct timeval waittime;
    
    int filesPresent=0;
    FD_ZERO(&read_fds);      
    for(i=0;i<overlay_interface_count;i++)
      {
	if (!overlay_interfaces[i].fileP)
	  {
	    if (overlay_interfaces[i].fd>maxfd) maxfd=overlay_interfaces[i].fd;
	    FD_SET(overlay_interfaces[i].fd,&read_fds);
	  }
	else { filesPresent=1; if (ms>5) ms=5; }
      }
    
    waittime.tv_usec=(ms%1000)*1000;
    waittime.tv_sec=ms/1000;

    if (debug&4) fprintf(stderr,"Waiting via select() for up to %lldms\n",ms);
    int r=select(maxfd+1,&read_fds,NULL,NULL,&waittime);
    if (r<0) {
      /* select had a problem */
      if (debug&4) perror("select()");
      WHY("select() complained.");
    } else if (r>0) {
      /* We have data, so try to receive it */
      if (debug&4) fprintf(stderr,"select() reports packets waiting\n");
      overlay_rx_messages();
    } else {
      /* No data before tick occurred, so do nothing.
	 Well, for now let's just check anyway. */
      if (debug&4) fprintf(stderr,"select() timeout.\n");
      overlay_rx_messages();
    }
    /* Check if we need to trigger any ticks on any interfaces */
    overlay_check_ticks();
  }

  return 0;
}

int overlay_frame_process(int interface,overlay_frame *f)
{
  if (!f) return WHY("f==NULL");

  long long now=overlay_gettime_ms();

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
      break;
    case OA_UNSUPPORTED:
    default:
      /* If we don't support the address format, we should probably tell
	 the sender. Again, we queue this up, and cancel it if someone else
	 tells them in the meantime to avoid an Opposition Event (like a Hanson
	 Event, but repeatedly berating any node that holds a different policy
	 to itself. */
      overlay_interface_repeat_abbreviation_policy[interface]=1;
      return -1;
      break;
    }

  /* Okay, nexthop is valid, so let's see if it is us */
  int forMe=0,i;
  int ultimatelyForMe=0;
  int broadcast=0;
  fprintf(stderr,"Nexthop for this frame is: ");
  for(i=0;i<SID_SIZE;i++) fprintf(stderr,"%02x",f->nexthop[i]);
  fprintf(stderr,"\n");

  for(i=0;i<SID_SIZE;i++) if (f->nexthop[i]!=0xff) break;
  if (i==SID_SIZE) forMe=1;
  for(i=0;i<SID_SIZE;i++) if (f->nexthop[i]!=hlr[4+i]) break;
  if (i==SID_SIZE) forMe=1;

  if (forMe) {
    /* It's for us, so resolve the addresses */
    if (overlay_frame_resolve_addresses(interface,f))
      return WHY("Failed to resolve destination and sender addresses in frame");
    if (debug&4) {
      fprintf(stderr,"Destination for this frame is (resolve code=%d): ",f->destination_address_status);
      if (f->destination_address_status==OA_RESOLVED) for(i=0;i<SID_SIZE;i++) fprintf(stderr,"%02x",f->destination[i]); else fprintf(stderr,"???");
      fprintf(stderr,"\n");
      fprintf(stderr,"Source for this frame is (resolve code=%d): ",f->source_address_status);
      if (f->source_address_status==OA_RESOLVED) for(i=0;i<SID_SIZE;i++) fprintf(stderr,"%02x",f->source[i]); else fprintf(stderr,"???");
      fprintf(stderr,"\n");
    }

    if (f->destination_address_status==OA_RESOLVED) {
      for(i=0;i<SID_SIZE;i++) if (f->destination[i]!=0xff) break;
      if (i==SID_SIZE) { ultimatelyForMe=1; broadcast=1; }
      for(i=0;i<SID_SIZE;i++) if (f->destination[i]!=hlr[4+i]) break;
      if (i==SID_SIZE) ultimatelyForMe=1;
    }
  }
  
  fprintf(stderr,"This frame does%s have me listed as next hop.\n",forMe?"":" not");
  fprintf(stderr,"This frame is%s for me.\n",ultimatelyForMe?"":" not");

  /* Not for us? Then just ignore it */
  if (!forMe) return 0;

  /* Is this a frame we have to forward on? */
  if (((!ultimatelyForMe)||broadcast)&&(f->ttl>1))
    {
      /* Yes, it is. */
      int len=0;

      if (broadcast&&(f->type==OF_TYPE_SELFANNOUNCE)) {
	// Don't forward broadcast self-announcement packets as that is O(n^2) with
	// traffic.  We have other means to propagating the mesh topology information.
      } else {
	if (overlay_get_nexthop(f->destination,f->nexthop,&len))
	  return WHY("Could not find next hop for host - dropping frame");
	f->ttl--;
	
	/* Queue frame for dispatch.
	   Don't forget to put packet in the correct queue based on type.
	   (e.g., mesh management, voice, video, ordinary or opportunistic). */		
	WHY("forwarding of frames not implemented");
	
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
    default:
      return WHY("Support for that f->type not yet implemented");
      break;
    }

  return 0;
}
