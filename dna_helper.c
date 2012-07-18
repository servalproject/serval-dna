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

#include <sys/types.h>
#include <sys/wait.h>
#include "serval.h"
#include "strbuf.h"
#include "strbuf_helpers.h"

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

static pid_t dna_helper_pid = -1;
static int dna_helper_stdin = -1;
static int dna_helper_stdout = -1;

int
parseDnaReply(const unsigned char *bytes, int count, 
	      char *sidhex, char *did, char *name, char *uri)
{
  /* Replies look like: TOKEN|URI|DID|NAME| */
  const unsigned char *b = bytes;
  const unsigned char *e = bytes + count;
  char *p, *q;
  for (p = sidhex, q = sidhex + SID_STRLEN; b != e && *b != '|' && p != q; ++p, ++b)
    *p = *b;
  *p = '\0';
  if (b == e || *b++ != '|')
    return -1;
  for (p = uri, q = uri + 511; b != e && *b != '|' && p != q; ++p, ++b)
    *p = *b;
  *p = '\0';
  if (b == e || *b++ != '|')
    return -1;
  for (p = did, q = did + DID_MAXSIZE; b != e && *b != '|' && p != q; ++p, ++b)
    *p = *b;
  *p = '\0';
  if (b == e || *b++ != '|')
    return -1;
  for (p = name, q = name + 63; b != e && *b != '|' && p != q; ++p, ++b)
    *p = *b;
  *p = '\0';
  if (b == e || *b != '|')
    return -1;
  return 0;
}

static struct sched_ent dna_helper_sched;

void dna_helper_monitor(struct sched_ent *alarm);

static int
dna_helper_start(const char *command, const char *arg)
{
  int stdin_fds[2], stdout_fds[2];
  if (pipe(stdin_fds))
    return WHY_perror("pipe");
  if (pipe(stdout_fds)) {
    close(stdin_fds[0]);
    close(stdin_fds[1]); 
    return WHY_perror("pipe");
  }
  switch (dna_helper_pid = fork()) {
  case 0:
    /* Child, should exec() to become helper after installing file descriptors. */
    if (dup2(stdin_fds[1], 0)) /* replace stdin */
      exit(-1);
    if (dup2(stdout_fds[0], 1)) /* replace stdout */
      exit(-1);
    if (dup2(stdout_fds[0], 2)) /* replace stderr */
      exit(-1);
    execl(command, command, arg, NULL);
    WHYF_perror("execl(%s, %s, %s, NULL)", command, command, arg ? arg : "NULL");
    abort(); /* Can't get here */
    break;
  case -1:
    /* fork failed */
    WHY_perror("fork");
    close(stdin_fds[0]);
    close(stdin_fds[1]); 
    close(stdout_fds[0]);
    close(stdout_fds[1]); 
    return -1;
  default:
    /* Parent, should put file descriptors into place for use */
    INFOF("Started DNA helper, pid=%u: %s %s", dna_helper_pid, command, arg ? arg : "");
    dna_helper_stdin = stdin_fds[0];
    dna_helper_stdout = stdout_fds[1];
    dna_helper_sched.function = dna_helper_monitor;
    dna_helper_sched.context = NULL;
    dna_helper_sched.poll.fd = dna_helper_stdout;
    dna_helper_sched.poll.events = POLLIN;
    dna_helper_sched.alarm = overlay_gettime_ms() + 1000;
    dna_helper_sched.stats = NULL;
    watch(&dna_helper_sched);
    schedule(&dna_helper_sched);
    return 0;
  }
  return -1;
}

static int
dna_helper_harvest()
{
  D;
  if (dna_helper_pid > 0) {
    int status;
    pid_t pid = waitpid(dna_helper_pid, &status, WNOHANG);
    if (pid == dna_helper_pid) {
      strbuf b = strbuf_alloca(80);
      INFOF("DNA helper pid=%u %s", pid, strbuf_str(strbuf_append_exit_status(b, status)));
      unschedule(&dna_helper_sched);
      unwatch(&dna_helper_sched);
      dna_helper_pid = -1;
      return 1;
    } else if (pid == -1) {
      return WHYF_perror("waitpid(%d, WNOHANG)", dna_helper_pid);
    } else if (pid) {
      return WHYF("waitpid(%d, WNOHANG) returned %d", dna_helper_pid, pid);
    }
  }
  return 0;
}

void dna_helper_monitor(struct sched_ent *alarm)
{
  if (alarm != &dna_helper_sched) {
    WHY("Alarm not for me");
    return;
  }
  if (dna_helper_sched.poll.revents & POLLIN) {
    unsigned char buffer[1024];
    if (read_nonblock(dna_helper_sched.poll.fd, buffer, sizeof buffer) != -1) {
      DEBUGF("Got DNA helper reply %s", alloca_toprint(160, buffer, sizeof buffer));
    }
  }
  if (dna_helper_harvest() <= 0) {
    dna_helper_sched.alarm = overlay_gettime_ms() + 1000;
    schedule(alarm);
  }
}

int
dna_helper_enqueue(char *did, unsigned char *requestorSid)
{
  if (dna_helper_pid == 0)
    return -1;
  if (dna_helper_pid == -1) {
    const char *dna_helper_executable = confValueGet("dna.helper.executable", NULL);
    const char *dna_helper_arg1 = confValueGet("dna.helper.argv.1", NULL);
    if (!dna_helper_executable || !dna_helper_executable[0]) {
      /* Check if we have a helper configured. If not, then set
	 dna_helper_pid to magic value of 0 so that we don't waste time
	 in future looking up the dna helper configuration value. */
      INFO("No DNA helper configured");
      dna_helper_pid = 0; 
      return -1;
    }
    if (dna_helper_start(dna_helper_executable, dna_helper_arg1) < 0) {
      /* Something broke, bail out */
      DEBUG("Failed to start dna helper");
      return -1;
    }
  }
  /* Write request to dna helper.
     Request takes form:  SID-of-Requestor|DID|\n
     By passing the requestor's SID to the helper, we don't need to maintain
     any state, as all we have to do is wait for responses from the helper,
     which will include the requestor's SID.
  */
  char buffer[1024];
  strbuf b = strbuf_local(buffer, sizeof buffer);
  strbuf_sprintf(b, "%s|%s|\n", alloca_tohex_sid(requestorSid), did);
  if (strbuf_overrun(b))
    return WHY("DNA helper buffer overrun");
  sigPipeFlag = 0;
  write_all(dna_helper_stdin, strbuf_str(b), strbuf_len(b));
  if (sigPipeFlag) {
    /* Assume broken pipe due to dead helper.
       Next request will cause it to be restarted.
       (Losing the current request is not a big problem, because
       DNA preemptively retries, anyway.
       XXX In fact, we should probably have a limit to the number of restarts
       in quick succession so that we don't waste lots of time with a buggy or
       suicidal helper.
    */
    WARN("Got SIGPIPE from DNA helper");
    close(dna_helper_stdin);
    close(dna_helper_stdout);
    dna_helper_stdin = -1;
    dna_helper_stdout = -1;
    dna_helper_harvest();
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
