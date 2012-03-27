/*
Copyright (C) 2010-2012 Paul Gardner-Stephen, Serval Project.
 
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

#include "serval.h"
#include <sys/stat.h>

int mdp_abstract_socket=-1;
int mdp_named_socket=-1;
int overlay_mdp_setup_sockets()
{
  struct sockaddr_un name;
  int len;
  
  name.sun_family = AF_UNIX;
  
#ifndef HAVE_LINUX_IF_H
  /* Abstrack name space (i.e., non-file represented) unix domain sockets are a
     linux-only thing. */
  mdp_abstract_socket = -1;
#else
  if (mdp_abstract_socket==-1) {
    /* Abstract name space unix sockets is a special Linux thing, which is
       convenient for us because Android is Linux, but does not have a shared
       writable path that is on a UFS partition, so we cannot use traditional
       named unix domain sockets. So the abstract name space gives us a solution. */
    name.sun_path[0]=0;
    /* XXX The 100 should be replaced with the actual maximum allowed.
       Apparently POSIX requires it to be at least 100, but I would still feel
       more comfortable with using the appropriate constant. */
    snprintf(&name.sun_path[1],100,"org.servalproject.mesh.overlay.mdp");
    len = 1+strlen(&name.sun_path[1]) + sizeof(name.sun_family);
    
    mdp_abstract_socket = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (mdp_abstract_socket>-1) {
      int dud=0;
      int r=bind(mdp_abstract_socket, (struct sockaddr *)&name, len);
      if (r) { dud=1; r=0; WHY("bind() of abstract name space socket failed (not an error on non-linux systems"); }
      if (dud) {
	close(mdp_abstract_socket);
	mdp_abstract_socket=-1;
	WHY("Could not open abstract name-space socket (only a problem on Linux).");
      }
    }
  }
#endif
  if (mdp_named_socket==-1) {
    char *instancepath=serval_instancepath();
    if (strlen(instancepath)>85) return WHY("Instance path too long to allow construction of named unix domain socket.");
    snprintf(&name.sun_path[0],100,"%s/mdp.socket",instancepath);
    unlink(&name.sun_path[0]);
    len = 0+strlen(&name.sun_path[0]) + sizeof(name.sun_family)+1;
    mdp_named_socket = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (mdp_named_socket>-1) {
      int dud=0;
      int r=bind(mdp_named_socket, (struct sockaddr *)&name, len);
      if (r) { dud=1; r=0; WHY("bind() of named unix domain socket failed"); }
      if (dud) {
	close(mdp_named_socket);
	mdp_named_socket=-1;
	WHY("Could not open named unix domain socket.");
      }
    }
  }

  return 0;
  
}

int overlay_mdp_get_fds(struct pollfd *fds,int *fdcount,int fdmax)
{
  /* Make sure sockets are open */
  overlay_mdp_setup_sockets();

  if ((*fdcount)>=fdmax) return -1;
  if (mdp_abstract_socket>-1)
    {
      if (debug&DEBUG_IO) {
	fprintf(stderr,"MDP abstract name space socket is poll() slot #%d (fd %d)\n",
		*fdcount,mdp_abstract_socket);
      }
      fds[*fdcount].fd=mdp_abstract_socket;
      fds[*fdcount].events=POLLIN;
      (*fdcount)++;
    }
  if ((*fdcount)>=fdmax) return -1;
  if (mdp_named_socket>-1)
    {
      if (debug&DEBUG_IO) {
	fprintf(stderr,"MDP named unix domain socket is poll() slot #%d (fd %d)\n",
		*fdcount,mdp_named_socket);
      }
      fds[*fdcount].fd=mdp_named_socket;
      fds[*fdcount].events=POLLIN;
      (*fdcount)++;
    }


  return 0;
}

#define MDP_MAX_BINDINGS 100
#define MDP_MAX_SOCKET_NAME_LEN 110
int mdp_bindings_initialised=0;
sockaddr_mdp mdp_bindings[MDP_MAX_BINDINGS];
char mdp_bindings_sockets[MDP_MAX_BINDINGS][MDP_MAX_SOCKET_NAME_LEN];
int mdp_bindings_socket_name_lengths[MDP_MAX_BINDINGS];

int overlay_mdp_reply_error(int sock,
			    struct sockaddr_un *recvaddr,int recvaddrlen,
			    int error_number,char *message)
{
  overlay_mdp_frame mdpreply;

  mdpreply.packetTypeAndFlags=MDP_ERROR;
  mdpreply.error.error=error_number;
  if (error_number==0||message)
    snprintf(&mdpreply.error.message[0],128,"%s",message?message:"Success");
  else
    snprintf(&mdpreply.error.message[0],128,"Error code #%d",error_number);
  mdpreply.error.message[127]=0;

  return overlay_mdp_reply(sock,recvaddr,recvaddrlen,&mdpreply);
}

int overlay_mdp_reply(int sock,struct sockaddr_un *recvaddr,int recvaddrlen,
			  overlay_mdp_frame *mdpreply)
{
  int replylen;

  replylen=overlay_mdp_relevant_bytes(mdpreply);
  if (replylen<0) return WHY("Invalid MDP frame (could not compute length)");

  errno=0;
  int r=sendto(sock,(char *)mdpreply,replylen,0,
	       (struct sockaddr *)recvaddr,recvaddrlen);
  if (r<0) { 
    perror("sendto"); 
    WHY("sendto() failed when sending MDP reply"); 
    printf("sock=%d, r=%d\n",sock,r);
    return -1;
  }
  return 0;  
}

int overlay_mdp_reply_ok(int sock,
			 struct sockaddr_un *recvaddr,int recvaddrlen,
			 char *message)
{
  return overlay_mdp_reply_error(sock,recvaddr,recvaddrlen,0,message);
}

int overlay_mdp_process_bind_request(int sock,overlay_mdp_frame *mdp,
				     struct sockaddr_un *recvaddr,int recvaddrlen)
{
  int i;
  if (!mdp_bindings_initialised) {
    /* Mark all slots as unused */
    for(i=0;i<MDP_MAX_BINDINGS;i++) mdp_bindings[i].port=0;
    mdp_bindings_initialised=1;
  }

  WHY("Doesn't authenticate source address on multi-SID installations like an OpenBTS:mesh gateway)");
  
  /* Make sure source address is either all zeros (listen on all), or a valid
     local address */
  for(i=0;i<SID_SIZE;i++) if (mdp->bind.sid[i]) break;
  if (i<SID_SIZE) {
    /* Not all zeroes, so make sure it is a valid SID */
    int j,ok=0;
    for(j=0;j<overlay_local_identity_count;j++)
      {
	fprintf(stderr,"Comparing %s against local addr ",
		overlay_render_sid(mdp->bind.sid));
	fprintf(stderr,"%s\n",
		overlay_render_sid(overlay_local_identities[j]));
	for(i=0;i<SID_SIZE;i++)
	  if (mdp->bind.sid[i]!=overlay_local_identities[j][i]) break;
	if (i==SID_SIZE) { ok=1; break; }
      }
    if (!ok) {
      /* Source address is invalid */
      return overlay_mdp_reply_error(sock,recvaddr,recvaddrlen,7,
				     "Bind address is not valid (must be a local MDP address, or all zeroes).");
    }
  }

  /* See if binding already exists */
  int found=-1;
  int free=-1;
  for(i=0;i<MDP_MAX_BINDINGS;i++) {
    /* Look for duplicate bindings */
    if (mdp_bindings[i].port==mdp->bind.port_number)
      if (!memcmp(mdp_bindings[i].sid,mdp->bind.sid,SID_SIZE))
	{ found=i; break; }
    /* Look for free slots in case we need one */
    if ((free==-1)&&(mdp_bindings[i].port==0)) free=i;
  }
 
  /* Binding was found.  See if it is us, if so, then all is well,
     else we check flags to see if we should override the existing binding. */
  if (found>-1) {
    if (mdp_bindings_socket_name_lengths[found]==recvaddrlen)
      if (!memcmp(mdp_bindings_sockets[found],recvaddr->sun_path,recvaddrlen))
	{
	  fprintf(stderr,"Identical binding exists");
	  WHY("Need to return binding information to client");
	  return overlay_mdp_reply_ok(sock,recvaddr,recvaddrlen,"Port bound (actually, it was already bound to you)");
	}
    /* Okay, so there is an existing binding.  Either replace it (if requested) or
       return an error */
    if (!(mdp->packetTypeAndFlags&MDP_FORCE))
      {
	fprintf(stderr,"Port already in use.\n");
	return overlay_mdp_reply_error(sock,recvaddr,recvaddrlen,3,
				       "Port already in use");
      }
    else {
      /* Cause existing binding to be replaced.
	 XXX - We should notify the existing binding holder that their binding
	 has been snaffled. */
      WHY("Warn socket holder about port-snatch");
      free=found;
    }
  }

  /* Okay, so no binding exists.  Make one, and return success.
     If we have too many bindings, we should return an error.
     XXX - We don't find out when the socket responsible for a binding has died,
     so stale bindings can hang around.  We really need a solution to this, e.g., 
     probing the sockets periodically (by sending an MDP NOOP frame perhaps?) and
     destroying any socket that reports an error.
  */
  if (free==-1) {
    /* XXX Should we probe for stale bindings here and now, since this is when
       we want the spare slots ? */
    WHY("Should probe existing bindings to see if any can be freed");
    fprintf(stderr,"No free port binding slots.  Close other connections and try again?");
    return overlay_mdp_reply_error(sock,recvaddr,recvaddrlen,4,"All binding slots in use. Close old connections and try again, or increase MDP_MAX_BINDINGS.");
  }

  /* Okay, record binding and report success */
  mdp_bindings[free].port=mdp->bind.port_number;
  memcpy(&mdp_bindings[free].sid[0],&mdp->bind.sid[0],SID_SIZE);
  mdp_bindings_socket_name_lengths[free]=recvaddrlen-2;
  memcpy(&mdp_bindings_sockets[free][0],&recvaddr->sun_path[0],
	 mdp_bindings_socket_name_lengths[free]);
  return overlay_mdp_reply_ok(sock,recvaddr,recvaddrlen,"Port bound");
}

int overlay_saw_mdp_containing_frame(int interface,overlay_frame *f,long long now)
{
  /* Take frame source and destination and use them to populate mdp->in->{src,dst}
     SIDs.
     XXX - I think we put the SIDs into the MDP frame at present, which is
     redundant, as they are included in the lower-level overlay frame structure.
     Take ports from mdp frame itself.
     Take payload from mdp frame itself.
  */
  return WHY("Not implemented");
}

int overlay_saw_mdp_frame(int interface, overlay_mdp_frame *mdp,long long now)
{
  printf("mdp frame type=0x%x\n",mdp->packetTypeAndFlags);

  switch(mdp->packetTypeAndFlags&MDP_TYPE_MASK) {
  case MDP_TX: 
    /* Regular MDP frame addressed to us.  Look for matching port binding,
       and if available, push to client.  Else do nothing, or if we feel nice
       send back a connection refused type message? Silence is probably the
       more prudent path. */    
    break;
  default:
    return WHY("We should only see MDP_TX frames here");
  }

  return WHY("Not implemented");
}

int overlay_mdp_sanitytest_sourceaddr(sockaddr_mdp *src,
				      struct sockaddr_un *recvaddr,
				      int recvaddrlen)
{
  if (overlay_address_is_broadcast(src->sid))
    {
      /* This is rather naughty if it happens, since broadcasting a
	 response can lead to all manner of nasty things.
	 Picture a packet with broadcast as the source address, sent
	 to, say, the MDP echo port on another node, and with a source
	 port also of the echo port.  Said echo will get multiplied many,
	 many, many times over before the TTL finally reaches zero.
	 So we just say no to any packet with a broadcast source address. 
	 (Of course we have other layers of protection against such 
	 shenanigens, such as using BPIs to smart-flood broadcasts, but
	 security comes through depth.)
      */
      return WHY("Packet had broadcast address as source address");
    }
  
  /* Now make sure that source address is in the list of bound addresses,
     and that the recvaddr matches. */
  int i;
  for(i=0;i<MDP_MAX_BINDINGS;i++)
    {
      if (!memcmp(src,&mdp_bindings[i],sizeof(sockaddr_mdp)))
	{
	  /* Binding matches, now make sure the sockets match */
	  if (mdp_bindings_socket_name_lengths[i]==(recvaddrlen-sizeof(short)))
	      if (!memcmp(mdp_bindings_sockets[i],recvaddr->sun_path,
			  recvaddrlen-sizeof(short)))
	      {
		/* Everything matches, so this unix socket and MDP address 
		   combination is valid */
		return 0;
	      }
	}
    }

  return WHY("No such socket binding:unix domain socket tuple exists -- someone might be trying to spoof someone else's connection");
}

int overlay_mdp_poll()
{
  unsigned char buffer[16384];
  int ttl;
  unsigned char recvaddrbuffer[1024];
  struct sockaddr *recvaddr=(struct sockaddr *)&recvaddrbuffer[0];
  socklen_t recvaddrlen=sizeof(recvaddrbuffer);
  struct sockaddr_un *recvaddr_un=NULL;

  if (mdp_named_socket>-1) {
    ttl=-1;
    bzero((void *)recvaddrbuffer,sizeof(recvaddrbuffer));
    fcntl(mdp_named_socket, F_SETFL, 
	  fcntl(mdp_named_socket, F_GETFL, NULL)|O_NONBLOCK); 
    int len = recvwithttl(mdp_named_socket,buffer,sizeof(buffer),&ttl,
			  recvaddr,&recvaddrlen);
    recvaddr_un=(struct sockaddr_un *)recvaddr;

    if (len>0) {
      /* Look at overlay_mdp_frame we have received */
      overlay_mdp_frame *mdp=(overlay_mdp_frame *)&buffer[0];      

      switch(mdp->packetTypeAndFlags&MDP_TYPE_MASK) {
      case MDP_GETADDRS:
	{
	  overlay_mdp_frame mdpreply;
	  
	  /* Work out which SIDs to get ... */
	  int sid_num=mdp->addrlist.first_sid;
	  int max_sid=mdp->addrlist.last_sid;
	  int max_sids=mdp->addrlist.frame_sid_count;
	  /* ... and constrain list for sanity */
	  if (sid_num<0) sid_num=0;
	  if (sid_num>overlay_local_identity_count) max_sids=0;
	  if (max_sids>MDP_MAX_SID_REQUEST) max_sids=MDP_MAX_SID_REQUEST;
	  if (max_sids>(overlay_local_identity_count-sid_num))
	    max_sids=overlay_local_identity_count-sid_num;
	  if (max_sid>(overlay_local_identity_count-sid_num))
	    max_sid=overlay_local_identity_count-sid_num;	
	  if (max_sids<0) max_sids=0;
	  
	  /* Prepare reply packet */
	  mdpreply.packetTypeAndFlags=MDP_ADDRLIST;
	  mdpreply.addrlist.server_sid_count=overlay_local_identity_count;
	  mdpreply.addrlist.first_sid=sid_num;
	  mdpreply.addrlist.last_sid=max_sid;
	  mdpreply.addrlist.frame_sid_count=max_sids;
	  
	  /* Populate with SIDs */
	  int i;
	  for(i=0;i<max_sids;i++)
	    bcopy(overlay_local_identities[sid_num+i],
		  mdpreply.addrlist.sids[i],SID_SIZE);
	  
	  /* Send back to caller */
	  return overlay_mdp_reply(mdp_named_socket,
				   (struct sockaddr_un *)recvaddr,recvaddrlen,
				   &mdpreply);
	}
	break;
      case MDP_TX: /* Send payload */
	/* Construct MDP packet frame from overlay_mdp_frame structure
	   (need to add return address from bindings list, and copy
	   payload etc). */
	{
	  /* Work out if destination is broadcast or not */
	  int broadcast=1;

	  if (overlay_mdp_sanitytest_sourceaddr(&mdp->out.src,
					    (struct sockaddr_un *)recvaddr,
					    recvaddrlen))
	    return overlay_mdp_reply_error
	      (mdp_named_socket,
	       (struct sockaddr_un *)recvaddr,
	       recvaddrlen,8,
	       "Source address is invalid (you must bind to a source address before"
	       " you can send packets");

	  if (!overlay_address_is_broadcast(mdp->out.dst.sid)) broadcast=0;

	  if (overlay_address_is_local(mdp->out.dst.sid)||broadcast)
	    {
	      /* Packet is addressed such that we should process it. */
	      overlay_saw_mdp_frame(-1 /* not received on a network interface */,
				    mdp,overlay_gettime_ms());

	      if (!broadcast) {
		/* Is local, and is not broadcast, so shouldn't get sent out
		   on the wire. */
		WHY("non-broadcast packet delivered locally");
		return 0;
	      }
	    }

	  /* broadcast packets cannot be encrypted, so complain if MDP_NOCRYPT
	     flag is not set. Also, MDP_NOSIGN must also be applied, until
	     NaCl cryptobox keys can be used for signing. */	
	  if (broadcast) {
	    if ((mdp->packetTypeAndFlags&(MDP_NOCRYPT|MDP_NOSIGN))
		!=(MDP_NOCRYPT|MDP_NOSIGN))
	      return overlay_mdp_reply_error(mdp_named_socket,
					     recvaddr_un,recvaddrlen,5,
					     "Broadcast packets cannot be encrypted "
					     "or signed (signing will be possible in"
					     " a future version).");
	  }
	  
	  /* Prepare the overlay frame for dispatch */
	  struct overlay_frame *frame;
	  frame=calloc(sizeof(overlay_frame),1);
	  if (!frame) return WHY("calloc() failed to allocate overlay frame");
	  frame->type=OF_TYPE_DATA;
	  frame->prev=NULL;
	  frame->next=NULL;

	  /* Work out the disposition of the frame.  For now we are only worried
	     about the crypto matters, and not compression that may be applied
	     before encryption (since applying it after is useless as ciphered
	     text should have maximum entropy). */
	  switch(mdp->packetTypeAndFlags&(MDP_NOCRYPT|MDP_NOSIGN)) {
	  case 0: /* crypted and signed (using CryptBox authcryption primitive) */
	    frame->modifiers=OF_CRYPTO_SIGNED|OF_CRYPTO_CIPHERED; 
	    op_free(frame);
	    return WHY("ciphered+signed MDP frames not implemented");
	    break;
	  case MDP_NOSIGN: 
	    /* ciphered, but not signed.
	       This means we don't use CryptoBox, but rather a more compact means
	       of representing the ciphered stream segment.
	    */
	    frame->modifiers=OF_CRYPTO_CIPHERED; 
	    op_free(frame);
	    return WHY("ciphered MDP packets not implemented");
	    break;
	  case MDP_NOCRYPT: 
	    /* clear text, but signed (need to think about how to implement this
	       while NaCl cannot sign using CryptoBox keys. We could use a 
	       CryptoSign key, and allow queries as to the authenticity of said key
	       via authcrypted channel between the parties. */
	    frame->modifiers=OF_CRYPTO_SIGNED; 
	    op_free(frame);
	    return WHY("signed MDP packets not implemented");
	    break;
	  case MDP_NOSIGN|MDP_NOCRYPT: /* clear text and no signature */
	    frame->modifiers=0; 
	    /* Copy payload body in */
	    frame->payload=ob_new(1 /* frame type (MDP) */
				  +1 /* MDP version */
				  +4 /* dst port */
				  +4 /* src port */
				  +mdp->out.payload_length);
	    /* MDP version 1 */
	    ob_append_byte(frame->payload,0x01);
	    ob_append_byte(frame->payload,0x01);
	    /* Destination port */
	    ob_append_int(frame->payload,mdp->out.dst.port);
	    /* XXX we should probably pull the source port from the bindings
	       On that note, when a binding is granted, we should probably
	       provide a token that can be used to lookup the binding and
	       indicate which binding the packet is for? */
	    ob_append_int(frame->payload,0);
	    ob_append_bytes(frame->payload,mdp->out.payload,mdp->out.payload_length);
	    break;
	  }
	  frame->ttl=64; /* normal TTL (XXX allow setting this would be a good idea) */	  
	  /* set source to ourselves 
	     XXX should eventually honour binding, which should allow choosing which
	     local identity.  This will be required for openbts integration/SIP:MSIP
	     gateways etc. */
	  overlay_frame_set_me_as_source(frame);

	  /* Set destination address */
	  if (broadcast)
	    overlay_frame_set_broadcast_as_destination(frame);
	  else{
	    bcopy(&mdp->out.dst.sid[0],frame->destination,SID_SIZE);
	    frame->destination_address_status=OA_RESOLVED;
	  }	
	  
	  if (overlay_payload_enqueue(OQ_ORDINARY,frame))
	    {
	      if (frame) op_free(frame);
	      return WHY("Error enqueuing frame");
	    }
	  else {
	    WHY("queued frame");
	    return 0;
	  }
	}
	break;
      case MDP_BIND: /* Bind to port */
	return overlay_mdp_process_bind_request(mdp_named_socket,mdp,
						recvaddr_un,recvaddrlen);
	break;
      default:
	/* Client is not allowed to send any other frame type */
	WHY("Illegal frame type.");
	mdp->packetTypeAndFlags=MDP_ERROR;
	mdp->error.error=2;
	snprintf(mdp->error.message,128,"Illegal request type.  Clients may use only MDP_TX or MDP_BIND.");
	int len=4+4+strlen(mdp->error.message)+1;
	errno=0;
	/* We ignore the result of the following, because it is just sending an
	   error message back to the client.  If this fails, where would we report
	   the error to? My point exactly. */
	sendto(mdp_named_socket,mdp,len,0,(struct sockaddr *)recvaddr,recvaddrlen);
      }
    }

    fcntl(mdp_named_socket, F_SETFL, 
	  fcntl(mdp_named_socket, F_GETFL, NULL)&(~O_NONBLOCK)); 
  }

  if (!(random()&0xff)) WHY("Not implemented");
  return -1;
}

int overlay_mdp_relevant_bytes(overlay_mdp_frame *mdp) 
{
  int len=4;
  switch(mdp->packetTypeAndFlags&MDP_TYPE_MASK)
    {
    case MDP_ADDRLIST: len=4
	+sizeof(mdp->addrlist.frame_sid_count)
	+sizeof(mdp->addrlist.first_sid)
	+sizeof(mdp->addrlist.last_sid)
	+sizeof(mdp->addrlist.server_sid_count)
	+mdp->addrlist.frame_sid_count*SID_SIZE;
      break;
    case MDP_GETADDRS: len=4
	+sizeof(mdp->addrlist.frame_sid_count)
	+sizeof(mdp->addrlist.first_sid)
	+sizeof(mdp->addrlist.last_sid)
	+sizeof(mdp->addrlist.server_sid_count);
      break;
    case MDP_TX: 
      len=4+sizeof(mdp->out)
	-sizeof(mdp->out.payload)
	+mdp->out.payload_length; 
      break;
    case MDP_RX: 
      len=4+sizeof(mdp->in)
	-sizeof(mdp->in.payload)
	+mdp->in.payload_length; break;
    case MDP_BIND: len=4+sizeof(mdp->bind); break;
    case MDP_ERROR: 
      /* This formulation is used so that we don't copy any bytes after the
	 end of the string, to avoid information leaks */
      len=4+4+strlen(mdp->error.message)+1; break;
    default:
      fprintf(stderr,"mdp frame type=0x%x\n",mdp->packetTypeAndFlags);
      return WHY("Illegal MDP frame type.");
    }
  return len;
}

int mdp_client_socket=-1;
int overlay_mdp_dispatch(overlay_mdp_frame *mdp,int flags,int timeout_ms)
{
  int len=4;
 
  if (mdp_client_socket==-1) overlay_mdp_client_init();

  /* Minimise frame length to save work and prevent accidental disclosure of
     memory contents. */
  len=overlay_mdp_relevant_bytes(mdp);
  if (len<0) return WHY("MDP frame invalid (could not compute length)");

  /* Construct name of socket to send to. */
  char mdp_socket_name[101];
  mdp_socket_name[100]=0;
  snprintf(mdp_socket_name,100,"%s/mdp.socket",serval_instancepath());
  if (mdp_socket_name[100]) {    
    return WHY("instance path is too long (unix domain named sockets have a short maximum path length)");
  }
  struct sockaddr_un name;
  name.sun_family = AF_UNIX;
  strcpy(name.sun_path, mdp_socket_name); 

  int result=sendto(mdp_client_socket, mdp, len, 0,
		    (struct sockaddr *)&name, sizeof(struct sockaddr_un));
  if (result<0) {
    mdp->packetTypeAndFlags=MDP_ERROR;
    mdp->error.error=1;
    snprintf(mdp->error.message,128,"Error sending frame to MDP server.");
    /* Clear socket so that we have the chance of reconnecting */
    overlay_mdp_client_done();
    return -1;
  } else {
    if (!(flags&MDP_AWAITREPLY)) {       
      return 0;
    }
  }

  /* Wait for a reply until timeout */
  struct pollfd fds[1];
  int fdcount=1;
  fds[0].fd=mdp_client_socket; fds[0].events=POLLIN;
  result = poll(fds,fdcount,timeout_ms);
  if (result==0) {
    /* Timeout */
    mdp->packetTypeAndFlags=MDP_ERROR;
    mdp->error.error=1;
    snprintf(mdp->error.message,128,"Timeout waiting for reply to MDP packet (packet was successfully sent).");    
    return -1;
  }

  int ttl=-1;
  if (!overlay_mdp_recv(mdp,&ttl)) {
    /* If all is well, examine result and return error code provided */
    WHY("Got a reply from server");
    if ((mdp->packetTypeAndFlags&MDP_TYPE_MASK)==MDP_ERROR)
	return mdp->error.error;
    else
      /* Something other than an error has been returned */
      return 0;
  } else {
    /* poll() said that there was data, but there isn't.
       So we will abort. */
    return WHY("poll() aborted");
  }
}

int overlay_mdp_client_init()
{
  char mdp_temporary_socket[1024];
  mdp_temporary_socket[0]=0;
  if (mdp_client_socket==-1) {
    /* Open socket to MDP server (thus connection is always local) */
    WHY("Use of abstract name space socket for Linux not implemented");
    
    mdp_client_socket = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (mdp_client_socket < 0) {
      perror("socket");
      return WHY("Could not open socket to MDP server");
    }

    /* We must bind to a temporary file name */
    snprintf(mdp_temporary_socket,1024,"%s/mdp-client.socket",serval_instancepath());
    unlink(mdp_temporary_socket);    
    struct sockaddr_un name;
    name.sun_family = AF_UNIX;
    snprintf(&name.sun_path[0],100,"%s",mdp_temporary_socket);
    int len = 1+strlen(&name.sun_path[0]) + sizeof(name.sun_family)+1;
    int r=bind(mdp_client_socket, (struct sockaddr *)&name, len);
    if (r) {
      WHY("Could not bind MDP client socket to file name");
      perror("bind");
      return -1;
    }
  }
  
  return 0;
}

int overlay_mdp_client_done()
{
  char mdp_temporary_socket[1024];
  snprintf(mdp_temporary_socket,1024,"%s/mdp-client.socket",serval_instancepath());
  unlink(mdp_temporary_socket);
  if (mdp_client_socket!=-1) close(mdp_client_socket);
  mdp_client_socket=-1;
  return 0;
}

int overlay_mdp_client_poll(long long timeout_ms)
{
  if (timeout_ms<0) timeout_ms=0;
  struct pollfd fds[1];
  int fdcount=1;
  fds[0].fd=mdp_client_socket; fds[0].events=POLLIN;

  return poll(fds,fdcount,timeout_ms);
}

int overlay_mdp_recv(overlay_mdp_frame *mdp,int *ttl) 
{
  char mdp_socket_name[101];
  mdp_socket_name[100]=0;
  snprintf(mdp_socket_name,100,"%s/mdp.socket",serval_instancepath());

  /* Check if reply available */
  fcntl(mdp_client_socket, F_SETFL, 
	fcntl(mdp_client_socket, F_GETFL, NULL)|O_NONBLOCK); 
  unsigned char recvaddrbuffer[1024];
  struct sockaddr *recvaddr=(struct sockaddr *)recvaddrbuffer;
  unsigned int recvaddrlen=sizeof(recvaddrbuffer);
  struct sockaddr_un *recvaddr_un;
  mdp->packetTypeAndFlags=0;
  int len = recvwithttl(mdp_client_socket,(unsigned char *)mdp,
		    sizeof(overlay_mdp_frame),ttl,recvaddr,&recvaddrlen);
  recvaddr_un=(struct sockaddr_un *)recvaddr;
  if (len>0) {
    /* Make sure recvaddr matches who we sent it to */
    if (strncmp(mdp_socket_name, recvaddr_un->sun_path, sizeof(recvaddr_un->sun_path))) {
      /* Okay, reply was PROBABLY not from the server, but on OSX if the path
	 has a symlink in it, it is resolved in the reply path, but might not
	 be in the request path (mdp_socket_name), thus we need to stat() and
	 compare inode numbers etc */
      struct stat sb1,sb2;
      if (stat(mdp_socket_name,&sb1)) return WHY("stat(mdp_socket_name) failed, so could not verify that reply came from MDP server");
      if (stat(recvaddr_un->sun_path,&sb2)) return WHY("stat(ra->sun_path) failed, so could not verify that reply came from MDP server");
      if ((sb1.st_ino!=sb2.st_ino)||(sb1.st_dev!=sb2.st_dev))
	return WHY("Reply did not come from server");
    }
    /* Valid packet received */
    return 0;
  } else 
    /* no packet received */
    return -1;

}
