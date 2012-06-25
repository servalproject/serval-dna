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

static int dna_helper_stdin = -1;
static int dna_helper_stdout = -1;

int
parseDnaReply(unsigned char *bytes, int count, char *did, char *name, char *uri) {
  bzero(did, SID_SIZE);
  bzero(name,64);
  bzero(uri,512);
  int i,l;

  l=0;
  for(i=0;i<511&&i<count&&bytes[i]!=0x0a;i++)
    did[l++]=bytes[i];
  did[l]=0;
  if (i>=count||i>=511) return WHY("DNA response does not contain name field");
  l=0; i++;
  for(;i<511&&i<count&&bytes[i]!=0x0a;i++)
    name[l++]=bytes[i];
  name[l]=0;
  if (i>=count||i>=511) return WHY("DNA response does not contain URI field");
  l=0; i++;
  for(;i<511&&i<count&&bytes[i]!=0;i++)
    uri[l++]=bytes[i];
  uri[l]=0;
  /* DEBUGF("did='%s', name='%s', uri='%s'",did,name,uri); */

  return 0;
}

static int
dna_helper_start(const char *command, const char *arg) {
  int	stdin_fds[2], stdout_fds[2];
  pid_t	pid;
  
  if (pipe(stdin_fds))
    return WHY_perror("pipe");

  if (pipe(stdout_fds)) {
    close(stdin_fds[0]);
    close(stdin_fds[1]); 
    return WHY_perror("pipe");
  }

  if ((pid = fork()) != 0) {
    /* Child, should exec() to become helper after installing file descriptors. */
    if (dup2(stdin_fds[1], 0)) /* replace stdin */
      exit(-1);
    if (dup2(stdout_fds[0], 1)) /* replace stdout */
      exit(-1);
    if (dup2(stdout_fds[0], 2)) /* replace stderr */
      exit(-1);
    execl(command, command, arg, NULL);
    abort(); /* Can't get here */
  } else {
    if (pid == -1) {
      /* fork failed */
      WHY_perror("fork");
      close(stdin_fds[0]);
      close(stdin_fds[1]); 
      close(stdout_fds[0]);
      close(stdout_fds[1]); 
      return -1;
    } else {
      /* Parent, should put file descriptors into place for use */
      dna_helper_stdin = stdin_fds[0];
      dna_helper_stdout = stdout_fds[1];
      return 0;
    }
  }
  return -1;
}

int
dna_helper_enqueue(char *did, unsigned char *requestorSid) {
  const char	*dna_helper, *dna_helper_arg;
  char		buffer[1024];
  
  if (dna_helper_stdin == -2)
    return -1;

  if (dna_helper_stdin == -1) {
      dna_helper = confValueGet("dna.helper", NULL);
    if (!dna_helper || !dna_helper[0]) {
      /* Check if we have a helper configured. If not, then set
	 dna_helper_stdin to magic value of -2 so that we don't waste time
	 in future looking up the dna helper configuration value. */
      dna_helper_stdin = -2; 
      return -1;
    }
    
    /* Look for optional argument */
    dna_helper_arg = confValueGet("dna.helperarg", NULL);

    /* Okay, so we have a helper configured.
       Run it */
    if (dna_helper_start(dna_helper, dna_helper_arg) < 0)
      /* Something broke, bail out */
      return -1;
  }

  /* Write request to dna helper.
     Request takes form:  SID-of-Requestor|DID|\n
     By passing the requestor's SID to the helper, we don't need to maintain
     any state, as all we have to do is wait for responses from the helper,
     which will include the requestor's SID.
  */
  bzero(buffer, sizeof(buffer));
  if (snprintf(buffer, sizeof(buffer) - 1, "%s|%s|\n", overlay_render_sid(requestorSid), did) > 
      sizeof(buffer) - 1)
    return WHY("Command to helper is too long");
    
  sigPipeFlag = 0;
  WRITE_STR(dna_helper_stdin, buffer);

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
    dna_helper_stdin = -1;
    dna_helper_stdout = -1;
    return -1;
  }

  return 0;
}

int dna_return_resolution(overlay_mdp_frame *mdp, unsigned char *fromSid,
			  const char *did,const char *name, const char *uri) {
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
