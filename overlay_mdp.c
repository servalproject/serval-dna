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

int overlay_saw_mdp_frame(int interface,overlay_frame *f,long long now)
{
  return WHY("Not implemented");
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

    if (len>0) {
      dump("packet from unix domain socket",
	   buffer,len);
      dump("recvaddr",recvaddrbuffer,recvaddrlen);
      /* Look at overlay_mdp_frame we have received */
      overlay_mdp_frame *mdp=(overlay_mdp_frame *)&buffer[0];
      switch(mdp->packetTypeAndFlags) {
      case MDP_TX: /* Send payload */
	break;
      case MDP_BIND: /* Bind to port */
	WHY("MDP_BIND request");
	break;
      default:
	/* Client is not allowed to send any other frame type */
	WHY("Illegal frame type.");
	mdp->packetTypeAndFlags=MDP_ERROR;
	mdp->error.error=2;
	snprintf(mdp->error.message,128,"Illegal request type.  Clients may use only MDP_TX or MDP_BIND.");
	int len=4+4+strlen(mdp->error.message)+1;
	errno=0;
	int e=sendto(mdp_named_socket,mdp,len,0,(struct sockaddr *)recvaddr,recvaddrlen);
	
	perror("sendto");
      }
    }

    recvaddr_un=(struct sockaddr_un *)recvaddr;
    fcntl(mdp_named_socket, F_SETFL, 
	  fcntl(mdp_named_socket, F_GETFL, NULL)&(~O_NONBLOCK)); 
  }

  if (!(random()&0xff)) WHY("Not implemented");
  return -1;
}

int mdp_client_socket=-1;
int overlay_mdp_dispatch(overlay_mdp_frame *mdp,int flags,int timeout_ms)
{
  int len=4;
  char mdp_temporary_socket[1024];
  mdp_temporary_socket[0]=0;
 
  /* Minimise frame length to save work and prevent accidental disclosure of
     memory contents. */
  switch(mdp->packetTypeAndFlags)
    {
    case MDP_TX: len=4+sizeof(mdp->out)+mdp->out.payload_length; break;
    case MDP_RX: len=4+sizeof(mdp->in)+mdp->out.payload_length; break;
    case MDP_BIND: len=4+4; break;
    case MDP_ERROR: len=4+4+strlen(mdp->error.message)+1; break;
    default:
      return WHY("Illegal MDP frame type.");
    }

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

  /* Construct name of socket to send to. */
  char mdp_socket_name[101];
  mdp_socket_name[100]=0;
  snprintf(mdp_socket_name,100,"%s/mdp.socket",serval_instancepath());
  if (mdp_socket_name[100]) {
    if (mdp_temporary_socket[0]) unlink(mdp_temporary_socket);
    return WHY("instance path is too long (unix domain named sockets have a short maximum path length)");
  }
  struct sockaddr_un name;
  name.sun_family = AF_UNIX;
  strcpy(name.sun_path, mdp_socket_name); 

  /* XXX Sends whole mdp structure, regardless of how much or little is used. */
  int result=sendto(mdp_client_socket, mdp, len, 0,
		    (struct sockaddr *)&name, sizeof(struct sockaddr_un));
  if (result<0) {
    mdp->packetTypeAndFlags=MDP_ERROR;
    mdp->error.error=1;
    snprintf(mdp->error.message,128,"Error sending frame to MDP server.");
    /* Clear socket so that we have the chance of reconnecting */
    mdp_client_socket=-1;
    if (mdp_temporary_socket[0]) unlink(mdp_temporary_socket);
    return -1;
  } else {
    WHY("packet sent");
    if (mdp_temporary_socket[0]) unlink(mdp_temporary_socket);
    if (!(flags&MDP_AWAITREPLY)) return 0;
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
    if (mdp_temporary_socket[0]) unlink(mdp_temporary_socket);
    return -1;
  }

  /* Check if reply available */
  
  if (mdp_temporary_socket[0]) unlink(mdp_temporary_socket);
  return WHY("Not implemented");
}
