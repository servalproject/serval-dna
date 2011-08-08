#include "mphlr.h"

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

  I(bits_per_second)=speed_in_bits;
  I(port)=bind_addr.sin_port;
  I(type)=type;

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
  
  return 0;
}

int overlay_broadcast_ensemble(int interface_number,char *bytes,int len)
{
  struct sockaddr_in s;

  memset(&s, '\0', sizeof(struct sockaddr_in));
  s.sin_family = AF_INET;
  s.sin_port = htons( PORT_OVERLAY );
  s.sin_addr.s_addr = htonl( INADDR_BROADCAST );

  if(sendto(overlay_interfaces[interface_number].socket, bytes, len, 0, (struct sockaddr *)&s, sizeof(struct sockaddr_in)) < 0)
    /* Failed to send */
    return WHY("sendto() failed");
  else
    /* Sent okay */
    return 0;
}
