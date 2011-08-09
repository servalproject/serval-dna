#include "mphlr.h"

#ifdef HAVE_IFADDRS_H
#include <ifaddrs.h>
#endif

int overlay_ready=0;
int overlay_interface_count=0;
overlay_interface overlay_interfaces[OVERLAY_MAX_INTERFACES];

int overlay_interface_type(char *s)
{
  if (!strcasecmp(s,"ethernet")) return OVERLAY_INTERFACE_ETHERNET;
  if (!strcasecmp(s,"wifi")) return OVERLAY_INTERFACE_WIFI;
  if (!strcasecmp(s,"other")) return OVERLAY_INTERFACE_UNKNOWN;
  if (!strcasecmp(s,"catear")) return OVERLAY_INTERFACE_PACKETRADIO;
  return WHY("Invalid interface type -- consider using 'wifi','ethernet' or 'other'");
}

int overlay_interface_arg(char *arg)
{
  /* Parse an interface argument, of the form:

     address[:speed[:type[:port]]]
  */
  
  char address[80];
  char speed[80]="2m";
  char typestring[80]="wifi";
  int port=PORT_DNA;
  int type=OVERLAY_INTERFACE_UNKNOWN;
  int n=0;

  /* Too long */
  if (strlen(arg)>79) return WHY("interface specification was >79 characters");

  if (sscanf(arg,"%[^:]%n:%[^:]%n:%[^:]%n:%d%n",
	     address,&n,speed,&n,typestring,&n,&port,&n)>=1)
    {
      int speed_in_bits=parse_quantity(speed);
      if (speed_in_bits<=1) {
	fprintf(stderr,"speed='%s'\n",speed);
	return WHY("Interfaces must be capable of at least 1 bit per second");
      }
      if (n<strlen(arg)) return WHY("Extra stuff at end of interface specification");

      type=overlay_interface_type(typestring);
      if (type<0) return WHY("Invalid interface type in specification");

      /* Okay, register the interface */
      in_addr_t src_addr=inet_addr(address);
      if (overlay_init_interface(src_addr,speed_in_bits,port,type))
	return WHY("Could not initialise interface");

    }
  else return WHY("Bad interface specification");
  return 0;
}

int overlay_interface_args(char *arg)
{
  /* Parse series of comma-separated interface definitions from a single argument
   */
  int i=0;
  char interface[80];
  int len=0;

  for(i=0;arg[i];i++)
    {
      if (arg[i]==',') {
	interface[len]=0;
	if (overlay_interface_arg(interface)) return WHY("Could not add interface");
	len=0;
      } else {
	if (len<79) {
	  interface[len++]=arg[i];
	  interface[len]=0;
	} else 
	  return WHY("Interface definition is too long (each must be <80 characters)");
      }
    }
  if (len) if (overlay_interface_arg(interface)) return WHY("Could not add final interface");
  return 0;     
}

int overlay_init_interface(in_addr_t src_addr,int speed_in_bits,int port,int type)
{
  struct sockaddr_in bind_addr;

  /* Too many interfaces */
  if (overlay_interface_count>=OVERLAY_MAX_INTERFACES) return WHY("Too many interfaces -- Increase OVERLAY_MAX_INTERFACES");

#define I(X) overlay_interfaces[overlay_interface_count].X

  I(socket)=socket(PF_INET,SOCK_DGRAM,0);
  if (I(socket)<0) {
    return WHY("Could not create UDP socket for interface");
  }

  bind_addr.sin_family = AF_INET;
  bind_addr.sin_port = htons( port<0?PORT_DNA:port );
  /* XXX Is this right? Are we really setting the local side address?
     I was in a plane when at the time, so couldn't Google it.
  */
  fprintf(stderr,"src_addr=%08x\n",(unsigned int)src_addr);
  bind_addr.sin_addr.s_addr = htonl( src_addr );
  if(bind(I(socket),(struct sockaddr *)&bind_addr,sizeof(bind_addr))) {
    perror("bind()");
    return WHY("MP HLR server could not bind to requested UDP port (bind() failed)");
  }

  /* Pick a reasonable default MTU.
     This will ultimately get tuned by the bandwidth and other properties of the interface */
  I(mtu)=1200;

  I(bits_per_second)=speed_in_bits;
  I(port)=bind_addr.sin_port;
  I(type)=type;
  I(tick_ms)=500;
  switch(type) {
  case OVERLAY_INTERFACE_PACKETRADIO: I(tick_ms)=15000; break;
  case OVERLAY_INTERFACE_ETHERNET: I(tick_ms)=500; break;
  case OVERLAY_INTERFACE_WIFI: I(tick_ms)=500; break;
  }

  overlay_interface_count++;
#undef I(X)
  return 0;
}

int overlay_rx_messages()
{
  int i;

  /* Grab packets, unpackage and dispatch frames to consumers */
  /* XXX Okay, so how are we managing out-of-process consumers?
     They need some way to register their interest in listening to a port.
  */
  for(i=0;i<overlay_interface_count;i++)
    {
    }

  return WHY("Not implemented");
}

int overlay_tx_messages()
{
  /* Check out the various queues, and add payloads to a new frame and send it out. */
  /* XXX We may want to throttle the maximum packets/sec or KB/sec */

  /* How are we going to pick and choose things from the various priority queues?
     We could simply pick the top item from each queue in round-robin until the 
     frame is filled. That would be a start.  We could certainly get more intelligent
     and stuff lots of little frames from a high priority queue in if that makes sense, 
     especially if they look like getting delayed a bit.  Perhaps we just reserve the first
     n bytes for the first queue, the first n+k bytes for the first two queues and so on?
  */

  /* XXX Go through queue and separate into per-interface queues? */
  
  return 0;
}

int overlay_broadcast_ensemble(int interface_number,unsigned char *bytes,int len)
{
  struct sockaddr_in s;

  memset(&s, '\0', sizeof(struct sockaddr_in));
  s = overlay_interfaces[interface_number].broadcast_address;
  s.sin_family = AF_INET;
  s.sin_port = htons( overlay_interfaces[interface_number].port );

  if(sendto(overlay_interfaces[interface_number].socket, bytes, len, 0, (struct sockaddr *)&s, sizeof(struct sockaddr_in)) < 0)
    /* Failed to send */
    return WHY("sendto() failed");
  else
    /* Sent okay */
    return 0;
}

int overlay_interface_discover()
{
#ifdef HAVE_IFADDRS_H
  struct ifaddrs *ifaddr,*ifa;
  int family;
  
  if (getifaddrs(&ifaddr) == -1)  {
    perror("getifaddr()");
    return WHY("getifaddrs() failed");
  }

  for (ifa=ifaddr;ifa!=NULL;ifa=ifa->ifa_next) {
    family=ifa->ifa_addr->sa_family;
    switch(family) {
    case AF_INET: 
      {
	unsigned char *name=(unsigned char *)ifa->ifa_name;
	unsigned int local=(((struct sockaddr_in *)(ifa->ifa_addr))->sin_addr.s_addr);
	unsigned int netmask=(((struct sockaddr_in *)(ifa->ifa_netmask))->sin_addr.s_addr);
	unsigned int broadcast=local|~netmask;
	printf("%s: %08x %08x %08x\n",name,local,netmask,broadcast);
	/* XXX now register the interface, or update the existing interface registration */
	break;
      }
    }
  }
#endif
  return 0;
}

int overlay_tick_interface(int i, long long now)
{
  int frame_pax=0;
#define MAX_FRAME_PAX 1024
  overlay_payload *pax[MAX_FRAME_PAX];

  if (overlay_interfaces[i].bits_per_second<1) {
    /* An interface with no speed budget is for listening only, so doesn't get ticked */
    return 0;
  }
    
  fprintf(stderr,"Ticking interface #%d\n",i);

  /* Get a buffer ready, and limit it's size appropriately.
     XXX size limit should be reduced from MTU.
     XXX we should also take account of the volume of data likely to be in the TX buffer. */  
  overlay_buffer *e=ob_new(overlay_interfaces[i].mtu);
  if (!e) return WHY("ob_new() failed");
  ob_limitsize(e,overlay_interfaces[i].mtu);

  /* 0. Setup Serval Mesh frame header. We do not use an explicit length field for these, as the various
     component payloads are all self-authenticating, or at least that is the theory. */
  unsigned char bytes[]={/* Magic */ 'O',0x10,
			 /* Version */ 0x00,0x01};
  if (ob_append_bytes(e,bytes,4)) return WHY("ob_append_bytes() refused to append magic bytes.");

  /* 1. Send announcement about ourselves, including one SID that we host if we host more than one SID
     (the first SID we host becomes our own identity, saving a little bit of data here).
  */
  overlay_add_selfannouncement(i,e);
  
  /* 2. Add any queued high-priority isochronous data (i.e. voice) to the frame. */
  overlay_payload **p=&overlay_tx[OVERLAY_ISOCHRONOUS_VOICE].first;
  while(p)
    {
      /* Throw away any stale frames */
      overlay_payload *pp=*p;

      if (!pp) break;

      if (now>((*p)->enqueued_at+200)) {
	/* Stale, so remove from queue */
	*p=pp->next;
	pp->next->prev=*p;
	op_free(p);
      }
      else
	{
	  /* XXX Filter for those which should be sent via this interface.
	     To do that we need to know the nexthop, and the best route to the next hop. */
	  
	  /* We keep trying to queue frames in case they will fit, as not all frames are of equal size.
	     This means that lower bit-rate codecs will get higher priority, which is probably not all
	     bad.  The only hard limit is the maximum number of payloads we allow in a frame, which is
	     set so high as to be irrelevant, even on loopback or gigabit ethernet interface */
	  if (frame_pax>=MAX_FRAME_PAX) break;
	  if (!overlay_payload_package_fmt1(*p,e))
	    {
	      /* Add payload to list of payloads we are sending with this frame so that we can dequeue them
		 if we send them. */
	      pax[frame_pax++]=*p;
	    }
	  p=&(*p)->next;
	}
    }

  /* 3. Add some mesh reachability reports (unlike BATMAN we announce reachability to peers progressively).
        Give priority to newly observed nodes so that good news travels quickly to help roaming.
	XXX - Don't forget about PONGing reachability reports to allow use of monodirectional links.
  */

  /* 4. XXX Add lower-priority queued data */

  /* 5. XXX Fill the packet up to a suitable size with anything that seems a good idea */
     
  /* Now send the frame.  This takes the form of a special DNA packet with a different
     service code, which we setup earlier. */
  fprintf(stderr,"Sending %d bytes\n",e->length);
  if (!overlay_broadcast_ensemble(i,e->bytes,e->length))
    {
      fprintf(stderr,"Successfully transmitted tick frame on interface #%d\n",i);
      /* De-queue the passengers who were aboard. */
      int j;
      overlay_payload **p=&overlay_tx[OVERLAY_ISOCHRONOUS_VOICE].first;
      for(j=0;j<frame_pax;j++)
	{
	  /* Skip any frames that didn't get queued */
	  while ((*p)&&(*p!=pax[j])) p=&(*p)->next;
	  /* Now get rid of this frame once we have found it */
	  if (*p) {
	    *p=pax[j]->next;
	    if (pax[j]->next) pax[j]->next->prev=pax[j]->prev;
	    if (op_free(pax[j])) WHY("op_free() failed");
	  }
	}
      return 0;
    }
  else WHY("overlay_broadcast_ensemble() failed");
}

int overlay_check_ticks()
{
  /* Check if any interface(s) are due for a tick */
  int i;
  struct timeval nowtv;
  long long now;

  if (gettimeofday(&nowtv,NULL))
    return WHY("gettimeofday() failed");
  
  /* Get current time in milliseconds */
  now=nowtv.tv_sec*1000;
  now=now+nowtv.tv_usec/1000;

  /* Now check if the next tick time for the interfaces is no later than that time.
     If so, trigger a tick on the interface. */
  for(i=0;i<overlay_interface_count;i++)
    {
      if (now>=overlay_interfaces[i].last_tick_ms+overlay_interfaces[i].tick_ms)
	{
	  /* This interface is due for a tick */
	  overlay_tick_interface(i,now);
	  overlay_interfaces[i].last_tick_ms=now;
	}
    }

  return 0;
}

long long overlay_time_until_next_tick()
{
  /* By default only tick once per day */
  long long nexttick=86400*1000;
  long long now;
  struct timeval tv;

  gettimeofday(&tv,NULL);
  now=tv.tv_sec*1000+tv.tv_usec/1000;

  int i;
  for(i=0;i<overlay_interface_count;i++)
    {
      long long thistick=(overlay_interfaces[i].last_tick_ms+overlay_interfaces[i].tick_ms)-now;
      if (thistick<0) thistick=0;
      if (thistick<nexttick) nexttick=thistick;
    }

  return nexttick;
}
