#include "mphlr.h"

#ifdef HAVE_IFADDRS_H
#include <ifaddrs.h>
#endif

int overlay_ready=0;
int overlay_interface_count=0;
overlay_interface overlay_interfaces[OVERLAY_MAX_INTERFACES];

struct interface_rules {
  char *namespec;
  unsigned long long speed_in_bits;
  int port;
  char type;
  char excludeP;
  struct interface_rules *next;
};

struct interface_rules *interface_filter=NULL;

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

     <+|->[interfacename][=type]

     +interface tells DNA to sit on that interface
     -interface tells DNA to not sit on that interface
     +/- without an interface tells DNA to sit on all interfaces.

     The first match rules, so -en0+ tells DNA to use all interfaces, excepting en0

     The optional =type specifier tells DNA how to handle the interface in terms of
     bandwidth:distance relationship for calculating tick times etc.

     The special type =custom allows full specification:
     
     XXX - Settle the custom specification now that we have changed the interface
     management.
  */

  char sign[80]="+";
  char interface_name[80]="";
  char speed[80]="1m";
  char typestring[80]="wifi";
  int port=PORT_DNA;
  int type=OVERLAY_INTERFACE_UNKNOWN;
  int n=0;

  /* Too long */
  if (strlen(arg)>79) return WHY("interface specification was >79 characters");

  struct interface_rules *r=calloc(sizeof(struct interface_rules),1);
  if (!r) return WHY("calloc(struct interface rules),1) failed");


  if (sscanf(arg,"%[+-]%n%[^=+-]%n=%[^:]%n:%d%n:%[^:]%n",
	     sign,&n,interface_name,&n,typestring,&n,&port,&n,speed,&n)>=1)
    {
      if (n<strlen(arg)) { free(r); return WHY("Extra junk at end of interface specification"); }

      if (strlen(sign)>1) { free(r); return WHY("Sign must be + or -"); }
      switch(sign[0])
	{
	case '+': break;
	case '-': r->excludeP=1; break;
	default: 
	  free(r);
	  return WHY("Invalid interface list item: Must begin with + or -");
	}

      long long speed_in_bits=parse_quantity(speed);
      if (speed_in_bits<=1) {
	free(r);
	return WHY("Interfaces must be capable of at least 1 bit per second");
      }
      if (n<strlen(arg)) return WHY("Extra stuff at end of interface specification");

      type=overlay_interface_type(typestring);
      if (type<0) { free(r); return WHY("Invalid interface type in specification"); }

      /* Okay, register the interface preference */
      r->namespec=strdup(interface_name);
      r->speed_in_bits=speed_in_bits;
      r->port=port;
      r->type=type;
      
      r->next=interface_filter;
      interface_filter=r;

      return 0;
    }
  else { free(r); return WHY("Bad interface specification"); }
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

int overlay_interface_init_socket(int interface,struct sockaddr_in src_addr,struct sockaddr_in broadcast,
				  struct sockaddr_in netmask)
{
#define I(X) overlay_interfaces[interface].X
  I(local_address)=src_addr;
  I(broadcast_address)=broadcast;
  I(netmask)=netmask;

  I(socket)=socket(PF_INET,SOCK_DGRAM,0);
  if (I(socket)<0) {
    return WHY("Could not create UDP socket for interface");
  }

  src_addr.sin_family = AF_INET;
  src_addr.sin_port = htons( I(port) );
  /* XXX Is this right? Are we really setting the local side address?
     I was in a plane when at the time, so couldn't Google it.
  */
  fprintf(stderr,"src_addr=%08x\n",(unsigned int)src_addr.sin_addr.s_addr);
  if(bind(I(socket),(struct sockaddr *)&src_addr,sizeof(src_addr))) {
    perror("bind()");
    return WHY("MP HLR server could not bind to requested UDP port (bind() failed)");
  }
  fprintf(stderr,"Bound to port 0x%04x\n",src_addr.sin_port);

  int broadcastP=1;
  if(setsockopt(I(socket), SOL_SOCKET, SO_BROADCAST, &broadcastP, sizeof(broadcastP)) < 0) {
    perror("setsockopt");
    return WHY("setsockopt() failed");
  }
 
  return 0;
#undef I(X)
}

int overlay_interface_init(char *name,struct sockaddr_in src_addr,struct sockaddr_in broadcast,
			   struct sockaddr_in netmask,int speed_in_bits,int port,int type)
{
  /* Too many interfaces */
  if (overlay_interface_count>=OVERLAY_MAX_INTERFACES) return WHY("Too many interfaces -- Increase OVERLAY_MAX_INTERFACES");

#define I(X) overlay_interfaces[overlay_interface_count].X

  strcpy(I(name),name);

  /* Pick a reasonable default MTU.
     This will ultimately get tuned by the bandwidth and other properties of the interface */
  I(mtu)=1200;

  I(observed)=1;
  I(bits_per_second)=speed_in_bits;
  I(port)=port;
  I(type)=type;
  I(tick_ms)=500;
  I(last_tick_ms)=0;
  I(fd)=0;
  switch(type) {
  case OVERLAY_INTERFACE_PACKETRADIO: I(tick_ms)=15000; break;
  case OVERLAY_INTERFACE_ETHERNET: I(tick_ms)=500; break;
  case OVERLAY_INTERFACE_WIFI: I(tick_ms)=500; break;
  }

  if (name[0]=='>') {
    I(fd) = open(&name[1],O_APPEND|O_NONBLOCK|O_RDWR);
    if (I(fd)<1)
      return WHY("could not open dummy interface file for append");
    /* Seek to end of file as initial reading point */
    I(socket)=lseek(I(fd),0,SEEK_END); /* socket gets reused to hold file offset */
    /* XXX later add pretend location information so that we can decide which "packets" to receive
       based on closeness */    
  } else {
    if (overlay_interface_init_socket(overlay_interface_count,src_addr,broadcast,netmask))
      return WHY("overlay_interface_init_socket() failed");    
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
  unsigned char packet[16384];
  int plen=0;
  int c[OVERLAY_MAX_INTERFACES];
  int count=0;
  
  /* Look at all interfaces */
  for(i=0;i<overlay_interface_count;i++) { c[i]=(overlay_interfaces[i].observed>0); count+=c[i]; }

  /* Grab packets from interfaces in round-robin fashion until all have been grabbed,
     or until we have spent too long (maybe 10ms?) */
  while(count>0)
    for(i=0;i<overlay_interface_count;i++)
      {
	struct sockaddr src_addr;
	unsigned int addrlen=sizeof(src_addr);
	unsigned char transaction_id[8];

	if (overlay_interfaces[i].fd) {
	  /* Read from dummy interface file */
	  lseek(overlay_interfaces[i].fd,overlay_interfaces[i].socket,SEEK_SET);
	  if (read(overlay_interfaces[i].fd,packet,overlay_interfaces[i].mtu)==overlay_interfaces[i].mtu)
	    {
	      overlay_interfaces[i].socket+=overlay_interfaces[i].mtu;
	      plen=overlay_interfaces[i].mtu;
	      bzero(&transaction_id[0],8);
	      bzero(&src_addr,sizeof(src_addr));
	      if (!packetOk(packet,plen,transaction_id,&src_addr,addrlen,1)) WHY("Malformed packet from dummy interface");
	    }
	  else { c[i]=0; count--; }
	} else {
	  /* Read from UDP socket */
	  plen=recvfrom(overlay_interfaces[i].socket,packet,sizeof(packet),MSG_DONTWAIT,
			&src_addr,&addrlen);
	  if (plen<0) { c[i]=0; count--; } else {
	    /* We have a frame from this interface */
	    fprintf(stderr,"Received %d bytes on interface #%d\n",plen,i);
	    
	    bzero(&transaction_id[0],8);
	    if (!packetOk(packet,plen,transaction_id,&src_addr,addrlen,1)) WHY("Malformed packet");	  
	  }
	}
      }

  return 0;
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
  
  return WHY("not implemented");
}

int overlay_broadcast_ensemble(int interface_number,unsigned char *bytes,int len)
{
  struct sockaddr_in s;

  memset(&s, '\0', sizeof(struct sockaddr_in));
  s = overlay_interfaces[interface_number].broadcast_address;
  s.sin_family = AF_INET;
  fprintf(stderr,"Port=%d\n",overlay_interfaces[interface_number].port);
  s.sin_port = htons( overlay_interfaces[interface_number].port );

  if (overlay_interfaces[interface_number].fd)
    {
      if (write(overlay_interfaces[interface_number].fd,bytes,overlay_interfaces[interface_number].mtu)
	  !=overlay_interfaces[interface_number].mtu)
	{
	  perror("write()");
	  return WHY("write() failed");
	}
      else
	return 0;
    }
  else
    {
      if(sendto(overlay_interfaces[interface_number].socket, bytes, len, 0, (struct sockaddr *)&s, sizeof(struct sockaddr_in)) < 0)
	{
	  /* Failed to send */
	  perror("sendto");
	  return WHY("sendto() failed");
	}
      else
	/* Sent okay */
	return 0;
    }
}

int overlay_interface_discover()
{
#ifdef HAVE_IFADDRS_H
  struct ifaddrs *ifaddr,*ifa;
  int family,i;
  
  if (getifaddrs(&ifaddr) == -1)  {
    perror("getifaddr()");
    return WHY("getifaddrs() failed");
  }

  /* Mark all interfaces as not observed, so that we know if we need to cull any */
  for(i=0;i<overlay_interface_count;i++) overlay_interfaces[i].observed--;

  /* Check through for any virtual dummy interfaces */
  struct interface_rules *r=interface_filter;
  while(r) {
    if (r->namespec[0]=='>') {
      for(i=0;i<overlay_interface_count;i++) if (!strcasecmp(overlay_interfaces[i].name,r->namespec)) break;
      if (i<overlay_interface_count)
	/* We already know about this interface, so just update it */
	overlay_interfaces[i].observed=1;
      else {
	/* New interface, so register it */
	struct sockaddr_in dummyaddr;
	if (overlay_interface_init(r->namespec,dummyaddr,dummyaddr,dummyaddr,
				   1000000,PORT_DNA,OVERLAY_INTERFACE_WIFI))
	  WHY("Could not initialise newly seen interface");
	else
	  fprintf(stderr,"Registered interface %s\n",r->namespec);
      }	          
    }
    r=r->next;
  }

  /* Check through actual network interfaces */
  for (ifa=ifaddr;ifa!=NULL;ifa=ifa->ifa_next) {
    family=ifa->ifa_addr->sa_family;
    switch(family) {
    case AF_INET: 
      {
	unsigned char *name=(unsigned char *)ifa->ifa_name;
	struct sockaddr_in local=*(struct sockaddr_in *)ifa->ifa_addr;
	struct sockaddr_in netmask=*(struct sockaddr_in *)ifa->ifa_netmask;
	unsigned int broadcast_bits=local.sin_addr.s_addr|~netmask.sin_addr.s_addr;
	struct sockaddr_in broadcast=local;
	broadcast.sin_addr.s_addr=broadcast_bits;
	printf("%s: %08x %08x %08x\n",name,local.sin_addr.s_addr,netmask.sin_addr.s_addr,broadcast.sin_addr.s_addr);
	/* Now register the interface, or update the existing interface registration */
	struct interface_rules *r=interface_filter,*me=NULL;
	while(r) {
	  if (!strcasecmp((char *)name,r->namespec)) me=r;
	  if (!r->namespec[0]) me=r;
	  r=r->next;
	}
	if (me&&(!me->excludeP)) {
	  fprintf(stderr,"Interface %s is interesting.\n",name);
	  /* We should register or update this interface. */
	  int i;
	  for(i=0;i<overlay_interface_count;i++) if (!strcasecmp(overlay_interfaces[i].name,(char *)name)) break;
	  if (i<overlay_interface_count) {
	    /* We already know about this interface, so just update it */
	    if ((overlay_interfaces[i].local_address.sin_addr.s_addr==local.sin_addr.s_addr)&&
		(overlay_interfaces[i].broadcast_address.sin_addr.s_addr==broadcast.sin_addr.s_addr)&&
		(overlay_interfaces[i].netmask.sin_addr.s_addr==netmask.sin_addr.s_addr))
	      {
		/* Mark it as being seen */
		overlay_interfaces[i].observed=1;
		continue;
	      }
	    else
	      {
		/* Interface has changed */
		close(overlay_interfaces[i].socket);
		if (overlay_interface_init_socket(i,local,broadcast,netmask))
		  WHY("Could not reinitialise changed interface");
	      }
	  }
	  else {
	    /* New interface, so register it */
	    if (overlay_interface_init((char *)name,local,broadcast,netmask,
				       me->speed_in_bits,me->port,me->type))
	      WHY("Could not initialise newly seen interface");
	    else
	      fprintf(stderr,"Registered interface %s\n",name);
	  }	    
	}
	break;
      }
    }
  }
#endif
  freeifaddrs(ifaddr);

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
  overlay_interfaces[i].sequence_number++;
  
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
	op_free(*p);
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
      fprintf(stderr,"Successfully transmitted tick frame #%d on interface #%d\n",
	      overlay_interfaces[i].sequence_number,i);
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
  else return WHY("overlay_broadcast_ensemble() failed");

}

int overlay_check_ticks()
{
  /* Check if any interface(s) are due for a tick */
  int i;
  struct timeval nowtv;
  long long now;

  /* Check for changes to interfaces */
  overlay_interface_discover();
  
  if (gettimeofday(&nowtv,NULL))
    return WHY("gettimeofday() failed");

  /* Get current time in milliseconds */
  now=nowtv.tv_sec*1000LL;
  now=now+nowtv.tv_usec/1000;

  /* Now check if the next tick time for the interfaces is no later than that time.
     If so, trigger a tick on the interface. */
  fprintf(stderr,"Examining %d interfaces.\n",overlay_interface_count);
  for(i=0;i<overlay_interface_count;i++)
    {
      /* Only tick live interfaces */
      if (overlay_interfaces[i].observed>0)
	{
	  fprintf(stderr,"Interface %s ticks every %dms, last at %lld.\n",overlay_interfaces[i].name,
		  overlay_interfaces[i].tick_ms,overlay_interfaces[i].last_tick_ms);
	  if (now>=overlay_interfaces[i].last_tick_ms+overlay_interfaces[i].tick_ms)
	    {
	      /* This interface is due for a tick */
	      overlay_tick_interface(i,now);
	      overlay_interfaces[i].last_tick_ms=now;
	    }
	}
      else
	fprintf(stderr,"Interface %s is awol.\n",overlay_interfaces[i].name);
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
  now=tv.tv_sec*1000LL+tv.tv_usec/1000;

  int i;
  fprintf(stderr,"Tick-check on %d interfaces at %lldms\n",overlay_interface_count,now);
  for(i=0;i<overlay_interface_count;i++)
    if (overlay_interfaces[i].observed>0)
    {
	  fprintf(stderr,"Interface %s ticks every %dms, last at %lld.\n",overlay_interfaces[i].name,
		  overlay_interfaces[i].tick_ms,overlay_interfaces[i].last_tick_ms);

      long long thistick=(overlay_interfaces[i].last_tick_ms+overlay_interfaces[i].tick_ms)-now;
      if (thistick<0) thistick=0;
      if (thistick<nexttick) nexttick=thistick;
    }

  return nexttick;
}
