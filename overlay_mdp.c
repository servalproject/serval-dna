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
  return WHY("Not implemented");
}
