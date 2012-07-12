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

#include <assert.h>
#include <time.h>
#include "serval.h"
#include "strbuf.h"

#ifdef HAVE_IFADDRS_H
#include <ifaddrs.h>
#endif

int overlay_ready=0;
int overlay_interface_count=0;
overlay_interface overlay_interfaces[OVERLAY_MAX_INTERFACES];
int overlay_last_interface_number=-1;

struct interface_rules {
  char *namespec;
  unsigned long long speed_in_bits;
  int port;
  char type;
  char excludeP;
  struct interface_rules *next;
};

struct interface_rules *interface_filter=NULL;

struct profile_total interface_poll_stats;
struct profile_total dummy_poll_stats;

struct outgoing_packet{
  overlay_interface *interface;
  int i;
  overlay_buffer *buffer;
};

struct sched_ent next_packet;
struct profile_total send_packet;

int overlay_tick_interface(int i, long long now);

unsigned char magic_header[]={/* Magic */ 'O',0x10,
  /* Version */ 0x00,0x01};


/* Return milliseconds since server started.  First call will always return zero.
   Must use long long, not time_t, as time_t can be 32bits, which is too small for
   milli-seconds since 1970. */
long long overlay_sequence_start_time = 0;
long long overlay_gettime_ms()
{
  long long now;
  if (!overlay_sequence_start_time) {
    overlay_sequence_start_time = gettime_ms();
    now = 0;
  } else
    now= gettime_ms()-overlay_sequence_start_time;

  return now;
}

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


  if (sscanf(arg,"%[+-]%n%[^=:,]%n=%[^:]%n:%d%n:%[^:]%n",
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

int overlay_interface_args(const char *arg)
{
  /* Parse series of comma-separated interface definitions from a single argument
   */
  int i=0;
  char interface[80];
  int len=0;

  for(i=0;arg[i];i++)
    {
      if (arg[i]==','||arg[i]=='\n') {
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

int
overlay_interface_init_socket(int interface, struct sockaddr_in src_addr, struct sockaddr_in broadcast) {
  char			srctxt[INET_ADDRSTRLEN];

#define I(X) overlay_interfaces[interface].X
  I(broadcast_address) = broadcast;
  I(fileP) = 0;

  I(alarm.poll.fd) = socket(PF_INET,SOCK_DGRAM,0);
  
  if (I(alarm.poll.fd) < 0) {
      WHY_perror("socket");
      WHYF("Could not create UDP socket for interface: %s",strerror(errno));
      goto error;
  } else 
    INFOF("interface #%d fd=%d",interface, I(alarm.poll.fd));

  int reuseP = 1;
  if (setsockopt(I(alarm.poll.fd), SOL_SOCKET, SO_REUSEADDR, &reuseP, sizeof(reuseP)) < 0) {
      WHY_perror("setsockopt(SO_REUSEADR)");
      goto error;
    }
#ifdef SO_REUSEPORT
  if (setsockopt(I(alarm.poll.fd), SOL_SOCKET, SO_REUSEPORT, &reuseP, sizeof(reuseP)) < 0) {
      WHY_perror("setsockopt(SO_REUSEPORT)");
      goto error;
    }
#endif
  int broadcastP = 1;
  if (setsockopt(I(alarm.poll.fd), SOL_SOCKET, SO_BROADCAST, &broadcastP, sizeof(broadcastP)) < 0) {
    WHY_perror("setsockopt");
    goto error;
  }

  /* Automatically close socket on calls to exec().
     This makes life easier when we restart with an exec after receiving
     a bad signal. */
  fcntl(I(alarm.poll.fd), F_SETFL, fcntl(I(alarm.poll.fd), F_GETFL, NULL) | O_CLOEXEC);

  /*  @PGS/20120615
      Use the broadcast address, so that we can reliably receive broadcast 
      traffic on all platforms. BUT on OSX we really need a non-broadcast socket
      to send from, because you cannot send from a broadcast socket on OSX it seems.
  */
  broadcast.sin_family = AF_INET;
  broadcast.sin_port = htons(I(port));
  if (bind(I(alarm.poll.fd), (struct sockaddr *)&broadcast, sizeof(broadcast))) {
    WHY_perror("bind");
    WHY("MP HLR server could not bind to requested UDP port (bind() failed)");
    goto error;
  }
  assert(inet_ntop(AF_INET, (const void *)&broadcast.sin_addr, srctxt, INET_ADDRSTRLEN) != NULL);
  if (debug & (DEBUG_PACKETRX | DEBUG_IO)) DEBUGF("Bound to %s:%d", srctxt, ntohs(broadcast.sin_port));

  I(alarm.poll.events)=POLLIN;
  I(alarm.function) = overlay_interface_poll;
  
  interface_poll_stats.name="overlay_interface_poll";
  I(alarm.stats)=&interface_poll_stats;
  watch(&I(alarm));

  // run the first tick asap
  I(alarm.alarm)=overlay_gettime_ms();
  I(alarm.deadline)=I(alarm.alarm)+10;
  schedule(&I(alarm));
  
  return 0;

  error:
  close(I(alarm.poll.fd));
  I(alarm.poll.fd)=-1;
  return -1;
#undef I
}

int overlay_interface_init(char *name,struct sockaddr_in src_addr,struct sockaddr_in broadcast,
			   int speed_in_bits,int port,int type)
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
  I(last_tick_ms)=0;
  I(alarm.poll.fd)=0;
  switch (type) {
  case OVERLAY_INTERFACE_PACKETRADIO:
    I(tick_ms) = confValueGetInt64Range("mdp.packetradio.tick_ms", 15000LL, 1LL, 3600000LL);
    break;
  case OVERLAY_INTERFACE_ETHERNET:
    I(tick_ms) = confValueGetInt64Range("mdp.ethernet.tick_ms", 500LL, 1LL, 3600000LL);
    break;
  case OVERLAY_INTERFACE_WIFI:
    I(tick_ms) = confValueGetInt64Range("mdp.wifi.tick_ms", 500LL, 1LL, 3600000LL);
    break;
  case OVERLAY_INTERFACE_UNKNOWN:
    I(tick_ms) = confValueGetInt64Range("mdp.unknown.tick_ms", 500LL, 1LL, 3600000LL);
    break;
  default:
    return WHYF("Unsupported interface type %d", type);
  }

  if (name[0]=='>') {
    I(fileP)=1;
    char dummyfile[1024];
    if (name[1]=='/') {
      /* Absolute path */
      snprintf(dummyfile,1024,"%s",&name[1]);
    } else
      /* Relative to instance path */
      if (!FORM_SERVAL_INSTANCE_PATH(dummyfile, &name[1]))
	return WHY("could not form dummy interfance name");
    
    if ((I(alarm.poll.fd) = open(dummyfile,O_APPEND|O_RDWR)) < 1) {
      return WHY("could not open dummy interface file for append");
    }

    /* Seek to end of file as initial reading point */
    I(offset)=lseek(I(alarm.poll.fd),0,SEEK_END); /* socket gets reused to hold file offset */
    /* XXX later add pretend location information so that we can decide which "packets" to receive
       based on closeness */    
    
    // schedule an alarm for this interface
    I(alarm.function)=overlay_dummy_poll;
    I(alarm.alarm)=overlay_gettime_ms()+10;
    I(alarm.deadline)=I(alarm.alarm);
    dummy_poll_stats.name="overlay_dummy_poll";
    I(alarm.stats)=&dummy_poll_stats;
    schedule(&I(alarm));
  } else {
    if (overlay_interface_init_socket(overlay_interface_count,src_addr,broadcast))
      return WHY("overlay_interface_init_socket() failed");    
  }

  overlay_interface_count++;
#undef I
  return 0;
}

void overlay_interface_poll(struct sched_ent *alarm)
{
  struct overlay_interface *interface = (overlay_interface *)alarm;
  int plen=0;
  unsigned char packet[16384];

  struct sockaddr src_addr;
  socklen_t addrlen = sizeof(src_addr);

  if (alarm->poll.revents==0){
    // tick the interface
    unsigned long long now = overlay_gettime_ms();
    int i = (interface - overlay_interfaces);
    overlay_tick_interface(i, now);
    alarm->alarm=now+interface->tick_ms;
    alarm->deadline=alarm->alarm+interface->tick_ms/2;
    schedule(alarm);
    return;
  }
  
  /* Read only one UDP packet per call to share resources more fairly, and also
     enable stats to accurately count packets received */
  int recvttl=1;
  plen = recvwithttl(alarm->poll.fd,packet, sizeof(packet), &recvttl, &src_addr, &addrlen);
  if (plen != -1) {
    /* We have a frame from this interface */
    if (debug&DEBUG_PACKETRX)
      serval_packetvisualise(open_logging(),"Read from real interface", packet,plen);
    if (debug&DEBUG_OVERLAYINTERFACES) DEBUGF("Received %d bytes on interface %s",plen,interface->name);
    if (packetOk(interface,packet,plen,NULL,recvttl,&src_addr,addrlen,1)) {
      WHY("Malformed packet");
      serval_packetvisualise(open_logging(), "Malformed packet", packet,plen);
    }
  }
}

void overlay_dummy_poll(struct sched_ent *alarm)
{
  overlay_interface *interface = (overlay_interface *)alarm;
  /* Grab packets, unpackage and dispatch frames to consumers */
  /* XXX Okay, so how are we managing out-of-process consumers?
     They need some way to register their interest in listening to a port.
  */
  unsigned char packet[16384];
  int plen=0;
  struct sockaddr src_addr;
  size_t addrlen = sizeof(src_addr);
  unsigned char transaction_id[8];
  unsigned long long now = overlay_gettime_ms();

  if (interface->last_tick_ms + interface->tick_ms <= now){
    // tick the interface
    int i = (interface - overlay_interfaces);
    overlay_tick_interface(i, now);
  }
  
  /* Read from dummy interface file */
  long long length=lseek(alarm->poll.fd,0,SEEK_END);
  if (interface->offset>=length)
    {
      /* if there's no input, while we want to check for more soon,
	 we need to allow all other low priority alarms to fire first,
	 otherwise we'll dominate the scheduler without accomplishing anything */
      
      alarm->alarm = overlay_gettime_ms()+20;
      alarm->deadline = alarm->alarm + 10000;
      
      if (alarm->alarm > interface->last_tick_ms + interface->tick_ms)
	alarm->alarm = interface->last_tick_ms + interface->tick_ms;
      if (debug&DEBUG_OVERLAYINTERFACES)
	DEBUGF("At end of input on dummy interface %s", interface->name);
    }
  else
    {
      lseek(alarm->poll.fd,interface->offset,SEEK_SET);
      if (debug&DEBUG_OVERLAYINTERFACES)
	DEBUGF("Read interface %s (size=%lld) at offset=%d",interface->name, length, interface->offset);
      ssize_t nread = read(alarm->poll.fd,&packet[0],2048);
      if (nread == -1)
	WHY_perror("read");
      else {
	interface->offset += nread;
	if (nread == 2048) {
	  plen = packet[110]+(packet[111]<<8);
	  if (plen > nread - 128)
	    plen = -1;
	  if (debug&DEBUG_PACKETRX)
	    serval_packetvisualise(open_logging(), "Read from dummy interface", &packet[128], plen);
	  bzero(&transaction_id[0],8);
	  bzero(&src_addr,sizeof(src_addr));
	  if (plen >= 4) {
	    if (packet[0] == 0x01 && packet[1] == 0 && packet[2] == 0 && packet[3] == 0) {
	      if (packetOk(interface,&packet[128],plen,transaction_id, -1 /* fake TTL */, &src_addr,addrlen,1) == -1)
		WARN("Unsupported packet from dummy interface");
	    } else {
	      WARNF("Unsupported packet version from dummy interface: %02x %02x %02x %02x", packet[0], packet[1], packet[2], packet[3]);
	    }
	  } else {
	    WARNF("Invalid packet from dummy interface: plen=%lld", (long long) plen);
	  }
	}
	else
	  WARNF("Read %lld bytes from dummy interface", nread);
      }
      
      /* keep reading new packets as fast as possible, 
	 but don't prevent other high priority alarms */
      alarm->alarm = overlay_gettime_ms();
      alarm->deadline = alarm->alarm + 200;
      
    }
  
  schedule(alarm);

  return ;
}

int overlay_broadcast_ensemble(int interface_number,
			       struct sockaddr_in *recipientaddr /* NULL == broadcast */,
			       unsigned char *bytes,int len)
{
  struct sockaddr_in s;

  if (debug&DEBUG_PACKETTX)
    {
      DEBUGF("Sending this packet via interface #%d",interface_number);
      serval_packetvisualise(open_logging(),NULL,bytes,len);
    }

  overlay_interface *interface = &overlay_interfaces[interface_number];

  memset(&s, '\0', sizeof(struct sockaddr_in));
  if (recipientaddr) {
    bcopy(recipientaddr,&s,sizeof(struct sockaddr_in));
  }
  else {
    s = interface->broadcast_address;
    s.sin_family = AF_INET;
    if (debug&DEBUG_PACKETTX) DEBUGF("Port=%d",interface->port);
    s.sin_port = htons(interface->port);
  }

  if (interface->fileP)
    {
      char buf[2048];
      bzero(&buf[0],128);
      /* Version information */
      buf[0]=1; buf[1]=0; 
      buf[2]=0; buf[3]=0;
      /* PID of creator */
      buf[4]=getpid()&0xff; buf[5]=getpid()>>8;

      /* TODO make a structure for all this stuff */
      /* bytes 4-5  = half-power beam height (uint16) */
      /* bytes 6-7  = half-power beam width (uint16) */
      /* bytes 8-11 = range in metres, centre beam (uint32) */
      /* bytes 16-47 = sender */
      /* bytes 48-79 = next hop */
      /* bytes 80-83 = latitude (uint32) */
      /* bytes 84-87 = longitude (uint32) */
      /* bytes 88-89 = X/Z direction (uint16) */
      /* bytes 90-91 = Y direction (uint16) */
      /* bytes 92-93 = speed in metres per second (uint16) */
      /* bytes 94-97 = TX frequency in Hz, uncorrected for doppler (which must be done at the receiving end to take into account
         relative motion) */
      /* bytes 98-109 = coding method (use for doppler response etc) null terminated string */
      /* bytes 110-111 = length of packet body in bytes */
      /* bytes 112-127 reserved for future use */

      if (len>2048-128) {
	WARN("Truncating long packet to fit within 1920 byte limit for dummy interface");
	len=2048-128;
      }

      /* Record length of packet */
      buf[110]=len&0xff;
      buf[111]=(len>>8)&0xff;

      bzero(&buf[128+len],2048-(128+len));
      bcopy(bytes,&buf[128],len);
      /* This lseek() is unneccessary because the dummy file is opened in O_APPEND mode.  It's
	 only purpose is to find out the offset to print in the DEBUG statement.  It is vulnerable
	 to a race condition with other processes appending to the same file. */
      off_t fsize = lseek(interface->alarm.poll.fd, (off_t) 0, SEEK_END);
      if (fsize == -1)
	return WHY_perror("lseek");
      interface->offset = fsize;
      if (debug&DEBUG_OVERLAYINTERFACES)
	DEBUGF("Write to interface %s at offset=%d", interface->name, interface->offset);
      ssize_t nwrite = write(interface->alarm.poll.fd, buf, 2048);
      if (nwrite == -1)
	return WHY_perror("write");
      interface->offset += nwrite;
      if (nwrite != 2048)
	return WHYF("only wrote %lld of %lld bytes", nwrite, 2048);
      return 0;
    }
  else
    {
      if(sendto(interface->alarm.poll.fd, 
		bytes, len, 0, (struct sockaddr *)&s, sizeof(struct sockaddr_in)) != len)
	  return WHY_perror("sendto(c)");
      return 0;
    }
}

/* This function is called to return old non-overlay requests back out the
   interface they came in. */
int overlay_sendto(struct sockaddr_in *recipientaddr,unsigned char *bytes,int len)
{
  if (debug&DEBUG_PACKETTX) DEBUGF("Sending %d bytes",len);
  if (overlay_broadcast_ensemble(overlay_last_interface_number,recipientaddr,bytes,len) == -1) 
    return -1;
  return len;
}

/* Register the interface, or update the existing interface registration */
int
overlay_interface_register(char *name,
			   struct sockaddr_in local,
			   struct sockaddr_in broadcast) {
  struct interface_rules	*r, *me;
  int				i;

  /* See if the interface is listed in the filter */
  me = NULL;
  r = interface_filter;
  while(r) {
    if (!strcasecmp(name, r->namespec))
      me = r;

    r = r->next;
  }

  if (me == NULL || me->excludeP) {
    if (debug & DEBUG_OVERLAYINTERFACES)
      DEBUGF("Interface %s is not interesting.",name);
    return 0;
  }

  /* Search in the exist list of interfaces */
  for(i = 0; i < overlay_interface_count; i++)
    if (!strcasecmp(overlay_interfaces[i].name, name))
      break;
  
  if (i < overlay_interface_count) {
    /* We already know about this interface, so just update it. */

    /* Check if the broadcast address is the same
       TODO: This only applies on Linux because only there can you bind to the bcast addr
       DOC 20120608
    */
    if ((overlay_interfaces[i].broadcast_address.sin_addr.s_addr & 0xffffffff)
	== (broadcast.sin_addr.s_addr & 0xffffffff)) {
      /* Same address, mark it as being seen */
      overlay_interfaces[i].observed = 1;
      return 0;
    } else {
      if (0) {
	/* Interface has changed.
	   TODO: We should register each address we understand in a list and check them.
	   DOC 20120608 */
	INFOF("Interface changed %08llx.%08llx vs %08llx.%08llx",
	      /* overlay_interfaces[i].local_address.sin_addr.s_addr */0,
	      overlay_interfaces[i].broadcast_address.sin_addr.s_addr,
	      local.sin_addr.s_addr,
	      broadcast.sin_addr.s_addr);
	unwatch(&overlay_interfaces[i].alarm);
	close(overlay_interfaces[i].alarm.poll.fd);
	overlay_interfaces[i].alarm.poll.fd = -1;
	if (overlay_interface_init_socket(i, local, broadcast))
	  INFOF("Could not reinitialise changed interface %s", name);
      }
    }
  } else {
    /* New interface, so register it */
    if (overlay_interface_init(name,local, broadcast, me->speed_in_bits, me->port, me->type))
      WHYF("Could not initialise newly seen interface %s", name);
    else
      if (debug & DEBUG_OVERLAYINTERFACES) DEBUGF("Registered interface %s", name);
  }

  return 0;
}
  
void overlay_interface_discover(struct sched_ent *alarm){
  int				no_route, i;
  struct interface_rules	*r;
  struct sockaddr_in		dummyaddr;
   
  /* Mark all interfaces as not observed, so that we know if we need to cull any */
  for(i = 0; i < overlay_interface_count; i++)
    overlay_interfaces[i].observed = 0;

  /* Check through for any virtual dummy interfaces */
  for (r = interface_filter; r != NULL; r = r->next) {
    if (r->namespec[0] != '>')
      continue;
    
    for(i = 0; i < overlay_interface_count; i++)
      if (!strcasecmp(overlay_interfaces[i].name,r->namespec))
	break;

    if (i < overlay_interface_count)
      /* We already know about this interface, so just update it */
      overlay_interfaces[i].observed = 1;
    else {
      /* New interface, so register it */      
      if (overlay_interface_init(r->namespec,dummyaddr,dummyaddr,
				 1000000,PORT_DNA,OVERLAY_INTERFACE_WIFI)) {
	if (debug & DEBUG_OVERLAYINTERFACES) DEBUGF("Could not initialise newly seen interface %s", r->namespec);
      }
      else
	if (debug & DEBUG_OVERLAYINTERFACES) DEBUGF("Registered interface %s",r->namespec);
    }
  }

  /* Look for real interfaces */
  no_route = 1;
  
#ifdef HAVE_IFADDRS_H
  if (no_route != 0)
    no_route = doifaddrs();
#endif

#ifdef SIOCGIFCONF
  if (no_route != 0)
    no_route = lsif();
#endif

#ifdef linux
  if (no_route != 0)
    no_route = scrapeProcNetRoute();
#endif

  if (no_route != 0) {
    FATAL("Unable to get any interface information");
  }
  
  alarm->alarm = overlay_gettime_ms()+5000;
  alarm->deadline = alarm->alarm + 10000;
  schedule(alarm);
  return;
}

/* remove and free a payload from the queue */
overlay_frame *overlay_queue_remove(overlay_txqueue *queue, overlay_frame *frame){
  overlay_frame *prev = frame->prev;
  overlay_frame *next = frame->next;
  if (prev)
    prev->next = next;
  else if(frame == queue->first)
    queue->first = next;
    
  if (next)
    next->prev = prev;
  else if(frame == queue->last)
    queue->last = prev;
  
  queue->length--;
  
  op_free(frame);
  
  return next;
}

int overlay_queue_dump(overlay_txqueue *q)
{
  strbuf b = strbuf_alloca(8192);
  struct overlay_frame *f;
  strbuf_sprintf(b,"overlay_txqueue @ 0x%p\n",q);
  strbuf_sprintf(b,"  length=%d\n",q->length);
  strbuf_sprintf(b,"  maxLenght=%d\n",q->maxLength);
  strbuf_sprintf(b,"  latencyTarget=%d milli-seconds\n",q->latencyTarget);
  strbuf_sprintf(b,"  first=%p\n",q->first);
  f=q->first;
  while(f) {
    strbuf_sprintf(b,"    %p: ->next=%p, ->prev=%p\n",
	    f,f->next,f->prev);
    if (f==f->next) {
      strbuf_sprintf(b,"        LOOP!\n"); break;
    }
    f=f->next;
  }
  strbuf_sprintf(b,"  last=%p\n",q->last);
  f=q->last;
  while(f) {
    strbuf_sprintf(b,"    %p: ->next=%p, ->prev=%p\n",
	    f,f->next,f->prev);
    if (f==f->prev) {
      strbuf_sprintf(b,"        LOOP!\n"); break;
    }
    f=f->prev;
  }
  DEBUG(strbuf_str(b));
  return 0;
}

int overlay_resolve_next_hop(overlay_frame *frame){
  if (frame->nexthop_address_status==OA_RESOLVED)
    return 0;
  
  if (frame->isBroadcast)
    bcopy(&frame->destination,&frame->nexthop,SID_SIZE);
  else if (overlay_get_nexthop((unsigned char *)frame->destination,frame->nexthop,&frame->nexthop_interface)){
    // TODO new code?
    frame->nexthop_address_status=OA_UNSUPPORTED;
    return -1;
  }
  
  frame->nexthop_address_status=OA_RESOLVED;
  return 0;
}

void overlay_init_packet(struct outgoing_packet *packet, int interface){
  packet->i = interface;
  packet->interface = &overlay_interfaces[packet->i];
  packet->buffer=ob_new(packet->interface->mtu);
  ob_limitsize(packet->buffer, packet->interface->mtu);
  ob_append_bytes(packet->buffer,magic_header,4);
}

// update the alarm time and return 1 if changed
int overlay_calc_queue_time(overlay_txqueue *queue, overlay_frame *frame){
  int ret=0;
  long long int send_time;
  
  if (frame->nexthop_address_status==OA_UNINITIALISED)
    overlay_resolve_next_hop(frame);
  if (frame->nexthop_address_status!=OA_RESOLVED)
    return 0;
  
  // when is the next packet from this queue due?
  send_time=queue->first->enqueued_at + queue->transmit_delay;
  if (next_packet.alarm==0 || send_time < next_packet.alarm){
    next_packet.alarm=send_time;
    ret = 1;
  }
  
  // how long can we wait if the server is busy?
  send_time += queue->grace_period;
  if (next_packet.deadline==0 || send_time < next_packet.deadline){
    next_packet.deadline=send_time;
    ret = 1;
  }
  if (!next_packet.function){
    next_packet.function=overlay_send_packet;
    send_packet.name="overlay_send_packet";
    next_packet.stats=&send_packet;
  }
  return ret;
}

void overlay_stuff_packet(struct outgoing_packet *packet, overlay_txqueue *queue, long long now){
  overlay_frame *frame = queue->first;
  
  // TODO stop when the packet is nearly full?
  
  while(frame){
    int drop =0;
    frame->isBroadcast = overlay_address_is_broadcast(frame->destination);
    
    if (frame->enqueued_at + queue->latencyTarget < now)
      drop=1;
    else if(frame->isBroadcast)
      drop=overlay_broadcast_drop_check(frame->destination);
    
    if (drop){
      DEBUG("Dropping frame due to expiry timeout");
      frame = overlay_queue_remove(queue, frame);
      continue;
    }
    
    if (overlay_resolve_next_hop(frame))
      goto skip;
    
    if (!packet->buffer){
      // use the interface of the first payload we find
      if (frame->isBroadcast){
	// find an interface that we haven't broadcast on yet
	int i;
	for(i=0;i<OVERLAY_MAX_INTERFACES;i++)
	{
	  if (overlay_interfaces[i].observed>0)
	    if (!frame->broadcast_sent_via[i]){
	      overlay_init_packet(packet, i);
	      break;
	    }
	}
	
	if (!packet->buffer){
	  // oh dear, why is this broadcast still in the queue?
	  frame = overlay_queue_remove(queue, frame);
	  continue;
	}
      }else{
	overlay_init_packet(packet, frame->nexthop_interface);
      }
      
    }else{
      // make sure this payload can be sent via this interface
      if (frame->isBroadcast){
	if (frame->broadcast_sent_via[packet->i]){
	  goto skip;
	}
      }else if(packet->i != frame->nexthop_interface){
	goto skip;
      }
    }
    
    if (overlay_frame_package_fmt1(frame, packet->buffer))
      // payload was not queued
      goto skip;
    
    // mark the payload as sent
    int keep_payload = 0;
    
    if (frame->isBroadcast){
      int i;
      frame->broadcast_sent_via[packet->i]=1;
      
      // check if there is still a broadcast to be sent      
      for(i=0;i<OVERLAY_MAX_INTERFACES;i++)
      {
	if (overlay_interfaces[i].observed>0)
	  if (!frame->broadcast_sent_via[i]){
	    keep_payload=1;
	    break;
	  }
      }
    }
    
    if (!keep_payload){
      frame = overlay_queue_remove(queue, frame);
      continue;
    }
    
  skip:
    // if we can't send the payload now, check when we should try
    overlay_calc_queue_time(queue, frame);
    frame = frame->next;
  }
}

// fill a packet from our outgoing queues and send it
int overlay_fill_send_packet(struct outgoing_packet *packet, long long now){
  int i;
  IN();
  // while we're looking at queues, work out when to schedule another packet
  unschedule(&next_packet);
  next_packet.alarm=0;
  next_packet.deadline=0;
  
  for (i=0;i<OQ_MAX;i++){
    overlay_txqueue *queue=&overlay_tx[i];
    
    overlay_stuff_packet(packet, queue, now);
  }
  
  if (next_packet.alarm)
    schedule(&next_packet);
  
  if(packet->buffer){
    // send the packet
    if (packet->buffer->length>=HEADERFIELDS_LEN){
      if (debug&DEBUG_PACKETCONSTRUCTION)
	dump("assembled packet",&packet->buffer->bytes[0],packet->buffer->length);
      
      if (debug&DEBUG_OVERLAYINTERFACES) 
	DEBUGF("Sending %d byte packet",packet->buffer->length);
      
      overlay_broadcast_ensemble(packet->i,NULL,packet->buffer->bytes,packet->buffer->length);
    }
    ob_free(packet->buffer);
    RETURN(1);
  }
  RETURN(0);
}

// when the queue timer elapses, send a packet
void overlay_send_packet(struct sched_ent *alarm){
  struct outgoing_packet packet;
  bzero(&packet, sizeof(struct outgoing_packet));
  
  overlay_fill_send_packet(&packet, overlay_gettime_ms());
}

// update time for next alarm and reschedule
void overlay_update_queue_schedule(overlay_txqueue *queue, overlay_frame *frame){
  if (overlay_calc_queue_time(queue, frame)){
    unschedule(&next_packet);
    DEBUGF("Scheduled next packet in %dms", next_packet.alarm - overlay_gettime_ms());
    schedule(&next_packet);
  }
}

int overlay_tick_interface(int i, long long now)
{
  struct outgoing_packet packet;
  IN();

  if (overlay_interfaces[i].bits_per_second<1) {
    /* An interface with no speed budget is for listening only, so doesn't get ticked */
    RETURN(0);
  }

  // initialise the packet buffer
  bzero(&packet, sizeof(struct outgoing_packet));
  overlay_init_packet(&packet, i);
  
  if (debug&DEBUG_OVERLAYINTERFACES) DEBUGF("Ticking interface #%d",i);

  /* 1. Send announcement about ourselves, including one SID that we host if we host more than one SID
     (the first SID we host becomes our own identity, saving a little bit of data here).
  */
  overlay_add_selfannouncement(i,packet.buffer);
  
  /* Add advertisements for ROUTES */
  overlay_route_add_advertisements(packet.buffer);
  
  if (rhizome_enabled() && rhizome_http_server_running())
    overlay_rhizome_add_advertisements(i,packet.buffer);
  
  /* Stuff more payloads from queues and send it */
  overlay_fill_send_packet(&packet, now);
  RETURN(0);
}

long long parse_quantity(char *q)
{
  int m;
  char units[80];

  if (strlen(q)>=80) return WHY("quantity string >=80 characters");

  if (sscanf(q,"%d%s",&m,units)==2)
    {
      if (units[1]) return WHY("Units should be single character");
      switch(units[0])
	{
	case 'k': return m*1000LL;
	case 'K': return m*1024LL;
	case 'm': return m*1000LL*1000LL;
	case 'M': return m*1024LL*1024LL;
	case 'g': return m*1000LL*1000LL*1000LL;
	case 'G': return m*1024LL*1024LL*1024LL;
	default:
	  return WHY("Illegal unit: should be k,K,m,M,g, or G.");
	}
    }
  if (sscanf(q,"%d",&m)==1)
    {
      return m;
    }
  else
    {
      return WHY("Could not parse quantity");
    }
}
