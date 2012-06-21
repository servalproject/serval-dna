/* 
Serval Distributed Numbering Architecture (DNA)
Copyright (C) 2012 Paul Gardner-Stephen 

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

/*
  The challenge with making an interface for calling an external program to 
  resolve a DID into a URI is that it really should be asynchronous, so that
  servald can't pause due to delays in looking up DIDs by helper applications.
  
  This can be partially mitigated by having a cache, so that at least for repeated
  requests the helper doesn't need to be called each time.  This is very important
  because the DNA protocol relies on pre-emptive retries to ensure reception of
  a request over a lossy network.

  The second part of the solution is to create an asynchronous queue for requests,
  by passing them via file descriptor to a single persistent instance of the DNA
  helper application, and polling the output of that application for results, and
  then passing them out to their destinations.  This ensures that the process is
  asynchronous and non-blocking, regardless of how much time the helper application
  requires.  Then the helper will just be another file descriptor to poll in the
  main loop.
 */

int dna_helper_stdin=-1;
int dna_helper_stdout=-1;

int dna_helper_start(const char *command)
{
  int stdin_fds[2];
  int stdout_fds[2];

  if (pipe(stdin_fds)) return -1;
  if (pipe(stdout_fds)) {
    close(stdin_fds[0]); close(stdin_fds[1]); 
    return -1;
  }

  int pid=-1;
  if ((pid=fork())!=0) {
    /* Child, should exec() to become helper after installing file descriptors. */
    if (dup2(stdin_fds[1],0)) exit(-1); /* replace stdin */
    if (dup2(stdout_fds[0],1)) exit(-1); /* replace stdout */
    if (dup2(stdout_fds[0],2)) exit(-1); /* replace stderr */
    execl(command,command,NULL);
    /* execl() should never return, since it replaces this process with a new
       one. Thus something bad must have happened. */      
    exit(-1);
  } else {
    if (pid==-1) {
      /* fork failed */
      close(stdin_fds[0]); close(stdin_fds[1]); 
      close(stdout_fds[0]); close(stdout_fds[1]); 
      return -1;
    } else {
      /* Parent, should put file descriptors into place for use */
      dna_helper_stdin=stdin_fds[0];
      dna_helper_stdout=stdout_fds[1];
      return 0;
    }
  }

  return -1;
}

int dna_helper_enqueue(char *did, unsigned char *requestorSid)
{
  /* Check if we have a helper configured. If not, then set
     dna_helper_stdin to magic value of -2 so that we don't waste time
     in future looking up the dna helper configuration value. */
  if (dna_helper_stdin==-2) return -1;
  if (dna_helper_stdin==-1) {
      const char *dna_helper = confValueGet("dna.helper",NULL);
    if (!dna_helper||!dna_helper[0]) {
      dna_helper_stdin=-2; 
      return -1;
    }

    /* Okay, so we have a helper configured.
       Run it */
    dna_helper_start(dna_helper);
    if (dna_helper_stdin<0) 
      return -1;
  }

  /* Write request to dna helper.
     Request takes form:  DID<space>SID-of-Requestor\n 
     By passing the requestor's SID to the helper, we don't need to maintain
     any state, as all we have to do is wait for responses from the helper,
     which will include the requestor's SID.
  */
  signal(SIGPIPE,sigPipeHandler);
  sigPipeFlag=0;
  write(dna_helper_stdin,did,strlen(did));
  write(dna_helper_stdin," ",1);
  write(dna_helper_stdin,overlay_render_sid(requestorSid),SID_SIZE*2);
  write(dna_helper_stdin,"\n",1);
  if (sigPipeFlag) {
    /* Assume broken pipe due to dead helper.
       Next request will cause it to be restarted.
       (Losing the current request is not a big problem, because
       DNA preemptively retries, anyway.
       XXX In fact, we should probably have a limit to the number of restarts
       in quick succession so that we don't waste lots of time with a buggy or
       suicidal helper.
    */
    close(dna_helper_stdin);
    close(dna_helper_stdout);
    dna_helper_stdin=-1;
    dna_helper_stdout=-1;
    return -1;
  }

  return 0;
}

int dna_return_resolution(overlay_mdp_frame *mdp, unsigned char *fromSid,
			  const char *did,const char *name,const char *uri)
{
  /* copy SID out into source address of frame */	      
  bcopy(fromSid,&mdp->out.src.sid[0],SID_SIZE);
  
  /* and build reply as did\nname\nURI<NUL> */
  snprintf((char *)&mdp->out.payload[0],512,"%s\n%s\n%s",
	   did,name,uri);
  mdp->out.payload_length=strlen((char *)mdp->out.payload)+1;

  /* Dispatch response */
  mdp->packetTypeAndFlags&=MDP_FLAG_MASK;
  mdp->packetTypeAndFlags|=MDP_TX;
  overlay_mdp_dispatch(mdp,0 /* system generated */,
		       NULL,0);

  return 0;
}
