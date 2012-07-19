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
#include <signal.h>
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

static pid_t dna_helper_pid = -1;
static int dna_helper_stdin = -1;
static int dna_helper_stdout = -1;
static int dna_helper_stderr = -1;
static int dna_helper_started = 0;

static struct sched_ent sched_requests = STRUCT_SCHED_ENT_UNUSED;
static struct sched_ent sched_replies = STRUCT_SCHED_ENT_UNUSED;
static struct sched_ent sched_harvester = STRUCT_SCHED_ENT_UNUSED;
static struct sched_ent sched_errors = STRUCT_SCHED_ENT_UNUSED;
static struct sched_ent schedrestart = STRUCT_SCHED_ENT_UNUSED;

static char request_buffer[1024];
static size_t request_length = 0;

void monitor_requests(struct sched_ent *alarm);
void monitor_replies(struct sched_ent *alarm);
void monitor_errors(struct sched_ent *alarm);
void harvester(struct sched_ent *alarm);

static void
dna_helper_close_pipes()
{
  if (debug & DEBUG_DNAHELPER)
    DEBUG("Closing DNA helper pipes");
  if (sched_requests.poll.fd != -1) {
    unwatch(&sched_requests);
    sched_requests.poll.fd = -1;
  }
  if (dna_helper_stdin != -1) {
    close(dna_helper_stdin);
    dna_helper_stdin = -1;
  }
  if (sched_replies.poll.fd != -1) {
    unwatch(&sched_replies);
    sched_replies.poll.fd = -1;
  }
  if (dna_helper_stdout != -1) {
    close(dna_helper_stdout);
    dna_helper_stdout = -1;
  }
  if (sched_errors.poll.fd != -1) {
    unwatch(&sched_errors);
    sched_errors.poll.fd = -1;
  }
  if (dna_helper_stderr != -1) {
    close(dna_helper_stderr);
    dna_helper_stderr = -1;
  }
}

static int
dna_helper_start(const char *command, const char *arg)
{
  dna_helper_close_pipes();
  int stdin_fds[2], stdout_fds[2], stderr_fds[2];
  if (pipe(stdin_fds) == -1)
    return WHY_perror("pipe");
  if (pipe(stdout_fds) == -1) {
    WHY_perror("pipe");
    close(stdin_fds[0]);
    close(stdin_fds[1]);
    return -1;
  }
  if (pipe(stderr_fds) == -1) {
    WHY_perror("pipe");
    close(stdin_fds[0]);
    close(stdin_fds[1]);
    close(stdout_fds[0]);
    close(stdout_fds[1]);
    return -1;
  }
  switch (dna_helper_pid = fork()) {
  case 0:
    /* Child, should exec() to become helper after installing file descriptors. */
    set_logging(stderr);
    signal(SIGTERM, SIG_DFL);
    close(stdin_fds[1]);
    close(stdout_fds[0]);
    close(stderr_fds[0]);
    if (dup2(stderr_fds[1], 2) == -1 || dup2(stdout_fds[1], 1) == -1 || dup2(stdin_fds[0], 0) == -1) {
      LOG_perror(LOG_LEVEL_FATAL, "dup2");
      fflush(stderr);
      _exit(-1);
    }
    execl(command, command, arg, NULL);
    LOGF_perror(LOG_LEVEL_FATAL, "execl(%s, %s, %s, NULL)", command, command, arg ? arg : "NULL");
    fflush(stderr);
    do { _exit(-1); } while (1);
    break;
  case -1:
    /* fork failed */
    WHY_perror("fork");
    close(stdin_fds[0]);
    close(stdin_fds[1]);
    close(stdout_fds[0]);
    close(stdout_fds[1]);
    close(stderr_fds[0]);
    close(stderr_fds[1]);
    return -1;
  default:
    /* Parent, should put file descriptors into place for use */
    close(stdin_fds[0]);
    close(stdout_fds[1]);
    close(stderr_fds[1]);
    dna_helper_started = 0;
    dna_helper_stdin = stdin_fds[1];
    dna_helper_stdout = stdout_fds[0];
    dna_helper_stderr = stderr_fds[0];
    INFOF("STARTED DNA HELPER pid=%u stdin=%d stdout=%d stderr=%d executable=%s arg=%s",
	dna_helper_pid,
	dna_helper_stdin,
	dna_helper_stdout,
	dna_helper_stderr,
	command,
	arg ? arg : "NULL"
      );
    sched_requests.function = monitor_requests;
    sched_requests.context = NULL;
    sched_requests.poll.fd = dna_helper_stdin;
    sched_requests.poll.events = POLLOUT;
    sched_requests.stats = NULL;
    sched_replies.function = monitor_replies;
    sched_replies.context = NULL;
    sched_replies.poll.fd = dna_helper_stdout;
    sched_replies.poll.events = POLLIN;
    sched_replies.stats = NULL;
    sched_errors.function = monitor_errors;
    sched_errors.context = NULL;
    sched_errors.poll.fd = dna_helper_stderr;
    sched_errors.poll.events = POLLIN;
    sched_errors.stats = NULL;
    sched_harvester.function = harvester;
    sched_harvester.stats = NULL;
    sched_harvester.alarm = overlay_gettime_ms() + 1000;
    watch(&sched_replies);
    watch(&sched_errors);
    schedule(&sched_harvester);
    return 0;
  }
  return -1;
}

static int
dna_helper_stop()
{
  if (dna_helper_pid > 0) {
    if (debug & DEBUG_DNAHELPER)
      DEBUGF("Sending SIGTERM to DNA helper pid=%d", dna_helper_pid);
    if (kill(dna_helper_pid, SIGTERM) == -1)
      WHYF_perror("kill(%d, SIGTERM)", dna_helper_pid);
    // The process is wait()ed for in dna_helper_monitor() so that we do not block here.
    return 1;
  }
  return 0;
}

static int
dna_helper_harvest(int blocking)
{
  if (dna_helper_pid > 0) {
    if (blocking && (debug & DEBUG_DNAHELPER))
      DEBUGF("Waiting for DNA helper pid=%d to die", dna_helper_pid);
    int status;
    pid_t pid = waitpid(dna_helper_pid, &status, blocking ? 0 : WNOHANG);
    if (pid == dna_helper_pid) {
      strbuf b = strbuf_alloca(80);
      INFOF("DNA helper pid=%u %s", pid, strbuf_str(strbuf_append_exit_status(b, status)));
      unschedule(&sched_harvester);
      dna_helper_pid = -1;
      return 1;
    } else if (pid == -1) {
      return WHYF_perror("waitpid(%d, %s)", dna_helper_pid, blocking ? "0" : "WNOHANG");
    } else if (pid) {
      return WHYF("waitpid(%d, %s) returned %d", dna_helper_pid, blocking ? "0" : "WNOHANG", pid);
    }
  }
  return 0;
}

int dna_helper_shutdown()
{
  if (debug & DEBUG_DNAHELPER)
    DEBUG("Shutting down DNA helper");
  dna_helper_close_pipes();
  switch (dna_helper_stop()) {
  case -1:
    return -1;
  case 0:
    return 0;
  default:
    return dna_helper_harvest(1);
  }
}

void dna_helper_restart(struct sched_ent *alarm)
{
  if (debug & DEBUG_DNAHELPER)
    DEBUG("Re-enable DNA helper restart");
  if (dna_helper_pid == 0)
    dna_helper_pid = -1;
}

void monitor_requests(struct sched_ent *alarm)
{
  if (debug & DEBUG_DNAHELPER) {
    DEBUGF("sched_requests.poll.revents=%s",
	strbuf_str(strbuf_append_poll_events(strbuf_alloca(40), sched_requests.poll.revents))
      );
  }
  if (sched_requests.poll.revents & (POLLHUP | POLLERR)) {
    WARN("DNA helper stdin closed -- stopping DNA helper");
    close(dna_helper_stdin);
    dna_helper_stdin = -1;
    unwatch(&sched_requests);
    sched_requests.poll.fd = -1;
    dna_helper_stop();
  }
  else if (sched_requests.poll.revents & POLLOUT) {
    unwatch(&sched_requests);
    sched_requests.poll.fd = -1;
    if (request_length) {
      sigPipeFlag = 0;
      if (write_all(dna_helper_stdin, request_buffer, request_length) == request_length) {
	// Request sent successfully.  Start watching for reply.
	request_length = 0;
      } else if (sigPipeFlag) {
	/* Broken pipe is probably due to a dead helper, but make sure the helper is dead, just to be
	   sure.  It will be harvested at the next harvester() timeout, and restarted on the first
	   request that arrives after a suitable pause has elapsed.  Losing the current request is not
	   a big problem, because DNA preemptively retries.
	*/
	WARN("Got SIGPIPE from DNA helper -- stopping DNA helper");
	dna_helper_stop();
      }
    }
  }
}

void monitor_replies(struct sched_ent *alarm)
{
  if (debug & DEBUG_DNAHELPER) {
    DEBUGF("sched_replies.poll.revents=%s",
	strbuf_str(strbuf_append_poll_events(strbuf_alloca(40), sched_replies.poll.revents))
      );
  }
  if (sched_replies.poll.revents & POLLIN) {
    if (dna_helper_started) {
      unsigned char buffer[1024];
      ssize_t nread = read_nonblock(sched_replies.poll.fd, buffer, sizeof buffer);
      if (nread > 0) {
	if (debug & DEBUG_DNAHELPER)
	  DEBUGF("DNA helper reply %s", alloca_toprint(-1, buffer, nread));
	// TODO parse and send DNA reply
      }
    } else {
      unsigned char buffer[8];
      ssize_t nread = read_nonblock(sched_replies.poll.fd, buffer, sizeof buffer);
      if (nread > 0) {
	if (nread == sizeof buffer && strncmp((const char *)buffer, "STARTED\n", sizeof buffer) == 0)
	  dna_helper_started = 1;
	else {
	  WHYF("Unexpected DNA helper ACK %s", alloca_toprint(-1, buffer, nread));
	  dna_helper_stop();
	}
      }
    }
  }
  if (sched_replies.poll.revents & (POLLHUP | POLLERR)) {
    close(dna_helper_stdout);
    dna_helper_stdout = -1;
    unwatch(&sched_replies);
    sched_replies.poll.fd = -1;
  }
}

void monitor_errors(struct sched_ent *alarm)
{
  if (debug & DEBUG_DNAHELPER) {
    DEBUGF("sched_errors.poll.revents=%s",
	strbuf_str(strbuf_append_poll_events(strbuf_alloca(40), sched_errors.poll.revents))
      );
  }
  if (sched_errors.poll.revents & POLLIN) {
    unsigned char buffer[1024];
    ssize_t nread = read_nonblock(sched_errors.poll.fd, buffer, sizeof buffer);
    if (nread > 0 && (debug & DEBUG_DNAHELPER))
      DEBUGF("DNA helper stderr %s", alloca_toprint(-1, buffer, nread));
  }
  if (sched_errors.poll.revents & (POLLHUP | POLLERR)) {
    close(dna_helper_stdout);
    dna_helper_stdout = -1;
    unwatch(&sched_errors);
    sched_errors.poll.fd = -1;
  }
}

void harvester(struct sched_ent *alarm)
{
  // While the helper process appears to still be running, keep calling this function.
  // Otherwise, wait a while before re-starting the helper.
  if (dna_helper_harvest(0) <= 0) {
    sched_harvester.alarm = overlay_gettime_ms() + 1000;
    schedule(&sched_harvester);
  } else {
    const int delay_ms = 2000;
    if (debug & DEBUG_DNAHELPER)
      DEBUGF("DNA helper has died, pausing %d ms before restart", delay_ms);
    dna_helper_pid = 0;
    schedrestart.function = dna_helper_restart;
    schedrestart.alarm = overlay_gettime_ms() + delay_ms;
    schedule(&schedrestart);
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
      WHY("Failed to start DNA helper");
      return -1;
    }
  }
  /* Write request to dna helper.
     Request takes form:  SID-of-Requestor|DID|\n
     By passing the requestor's SID to the helper, we don't need to maintain
     any state, as all we have to do is wait for responses from the helper,
     which will include the requestor's SID.
  */
  if (request_length) {
    WARN("DNA helper request already pending -- dropping new request");
  } else {
    strbuf b = strbuf_local(request_buffer, sizeof request_buffer);
    strbuf_sprintf(b, "%s|%s|\n", alloca_tohex_sid(requestorSid), did);
    if (strbuf_overrun(b))
      return WHY("DNA helper request buffer overrun -- request not sent");
    else {
      request_length = strbuf_len(b);
      watch(&sched_requests);
    }
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
