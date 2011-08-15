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

overlay_txqueue overlay_tx[4];

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

int overlay_frame_process(overlay_frame *f)
{
  return WHY("Not implemented");
}
