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
#include <sys/stat.h>
#include <signal.h>
#include "serval.h"
#include "conf.h"
#include "str.h"
#include "strbuf.h"
#include "strbuf_helpers.h"
#include "overlay_address.h"
#include "dataformats.h"

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
parseDnaReply(const char *buf, size_t len, char *token, char *did, char *name, char *uri, const char **bufp)
{
  /* Replies look like: TOKEN|URI|DID|NAME| where TOKEN is usually a hex SID */
  const char *b = buf;
  const char *e = buf + len;
  char *p, *q;
  for (p = token, q = token + SID_STRLEN; b != e && *b != '|' && p != q; ++p, ++b)
    *p = *b;
  *p = '\0';
  if (b == e || *b++ != '|')
    return 0;
  for (p = uri, q = uri + 511; b != e && *b != '|' && p != q; ++p, ++b)
    *p = *b;
  *p = '\0';
  if (b == e || *b++ != '|')
    return 0;
  for (p = did, q = did + DID_MAXSIZE; b != e && *b != '|' && p != q; ++p, ++b)
    *p = *b;
  *p = '\0';
  if (b == e || *b++ != '|')
    return 0;
  for (p = name, q = name + 63; b != e && *b != '|' && p != q; ++p, ++b)
    *p = *b;
  *p = '\0';
  if (b == e || *b++ != '|')
    return 0;
  if (bufp)
    *bufp = b;
  return 1;
}

static pid_t dna_helper_pid = -1;
static int dna_helper_stdin = -1;
static int dna_helper_stdout = -1;
static int dna_helper_stderr = -1;
static int dna_helper_started = 0;

#define DECLARE_SCHED_ENT(FUNCTION, VARIABLE) \
static void FUNCTION(struct sched_ent *alarm); \
static struct profile_total VARIABLE##_timing={.name="" #FUNCTION "",}; \
static struct sched_ent VARIABLE = {.function = FUNCTION, .stats = & VARIABLE##_timing, .poll.fd = -1, };

DECLARE_SCHED_ENT(monitor_requests, sched_requests);
DECLARE_SCHED_ENT(monitor_replies,  sched_replies);
DECLARE_SCHED_ENT(monitor_errors,   sched_errors);
DECLARE_SCHED_ENT(harvester,        sched_harvester);
DECLARE_SCHED_ENT(restart_delayer,  sched_restart);
DECLARE_SCHED_ENT(reply_timeout,    sched_timeout);

// This buffer must hold "SID|DID|\n\0"
static char request_buffer[SID_STRLEN + DID_MAXSIZE + 4];
static char *request_bufptr = NULL;
static char *request_bufend = NULL;
static overlay_mdp_data_frame request_mdp_data;
static char request_did[DID_MAXSIZE + 1];

static int awaiting_reply = 0;
static int discarding_until_nl = 0;
static char reply_buffer[2048];
static char *reply_bufend = NULL;

static void
dna_helper_close_pipes()
{
  if (dna_helper_stdin != -1) {
    if (config.debug.dnahelper)
      DEBUGF("DNAHELPER closing stdin pipe fd=%d", dna_helper_stdin);
    close(dna_helper_stdin);
    dna_helper_stdin = -1;
  }
  if (sched_requests.poll.fd != -1) {
    unwatch(&sched_requests);
    sched_requests.poll.fd = -1;
  }
  if (dna_helper_stdout != -1) {
    if (config.debug.dnahelper)
      DEBUGF("DNAHELPER closing stdout pipe fd=%d", dna_helper_stdout);
    close(dna_helper_stdout);
    dna_helper_stdout = -1;
  }
  if (sched_replies.poll.fd != -1) {
    unwatch(&sched_replies);
    sched_replies.poll.fd = -1;
  }
  if (dna_helper_stderr != -1) {
    if (config.debug.dnahelper)
      DEBUGF("DNAHELPER closing stderr pipe fd=%d", dna_helper_stderr);
    close(dna_helper_stderr);
    dna_helper_stderr = -1;
  }
  if (sched_errors.poll.fd != -1) {
    unwatch(&sched_errors);
    sched_errors.poll.fd = -1;
  }
}

int
dna_helper_start()
{
  if (!config.dna.helper.executable[0]) {
    /* Check if we have a helper configured. If not, then set
     dna_helper_pid to magic value of 0 so that we don't waste time
     in future looking up the dna helper configuration value. */
    INFO("DNAHELPER none configured");
    dna_helper_pid = 0;
    return 0;
  }
  
  if (!my_subscriber)
    return WHY("Unable to lookup my SID");
  
  const char *mysid = alloca_tohex_sid_t(my_subscriber->sid);
  
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
  // Construct argv[] for execv() and log messages.
  const char *argv[config.dna.helper.argv.ac + 2];
  argv[0] = config.dna.helper.executable;
  int i;
  for (i = 0; i < config.dna.helper.argv.ac; ++i)
    argv[i + 1] = config.dna.helper.argv.av[i].value;
  argv[i + 1] = NULL;
  strbuf argv_sb = strbuf_append_argv(strbuf_alloca(1024), config.dna.helper.argv.ac + 1, argv);
  switch (dna_helper_pid = fork()) {
  case 0:
    /* Child, should exec() to become helper after installing file descriptors. */
    close_log_file();
    setenv("MYSID", mysid, 1);
    signal(SIGTERM, SIG_DFL);
    close(stdin_fds[1]);
    close(stdout_fds[0]);
    close(stderr_fds[0]);
    if (dup2(stderr_fds[1], 2) == -1 || dup2(stdout_fds[1], 1) == -1 || dup2(stdin_fds[0], 0) == -1) {
      LOG_perror(LOG_LEVEL_FATAL, "dup2");
      _exit(-1);
    }
    {
      execv(config.dna.helper.executable, (char **)argv);
      LOGF_perror(LOG_LEVEL_FATAL, "execv(%s, [%s])",
	  alloca_str_toprint(config.dna.helper.executable),
	  strbuf_str(argv_sb)
	);
    }
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
    INFOF("STARTED DNA HELPER pid=%u stdin=%d stdout=%d stderr=%d executable=%s argv=[%s]",
	dna_helper_pid,
	dna_helper_stdin,
	dna_helper_stdout,
	dna_helper_stderr,
	alloca_str_toprint(config.dna.helper.executable),
	strbuf_str(argv_sb)
      );

    sched_replies.poll.fd = dna_helper_stdout;
    sched_replies.poll.events = POLLIN;
    sched_errors.poll.fd = dna_helper_stderr;
    sched_errors.poll.events = POLLIN;
    sched_requests.poll.fd = -1;
    sched_requests.poll.events = POLLOUT;
    sched_harvester.alarm = gettime_ms() + 1000;
    sched_harvester.deadline = sched_harvester.alarm + 1000;
    reply_bufend = reply_buffer;
    discarding_until_nl = 0;
    awaiting_reply = 0;
    watch(&sched_replies);
    watch(&sched_errors);
    schedule(&sched_harvester);
    return 0;
  }
  return -1;
}

static int
dna_helper_kill()
{
  if (awaiting_reply) {
    unschedule(&sched_timeout);
    awaiting_reply = 0;
  }
  if (dna_helper_pid > 0) {
    if (config.debug.dnahelper)
      DEBUGF("DNAHELPER sending SIGTERM to pid=%d", dna_helper_pid);
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
    if (blocking && (config.debug.dnahelper))
      DEBUGF("DNAHELPER waiting for pid=%d to die", dna_helper_pid);
    int status;
    pid_t pid = waitpid(dna_helper_pid, &status, blocking ? 0 : WNOHANG);
    if (pid == dna_helper_pid) {
      strbuf b = strbuf_alloca(80);
      INFOF("DNAHELPER process pid=%u %s", pid, strbuf_str(strbuf_append_exit_status(b, status)));
      unschedule(&sched_harvester);
      dna_helper_pid = -1;
      if (awaiting_reply) {
	unschedule(&sched_timeout);
	awaiting_reply = 0;
      }
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
  if (config.debug.dnahelper)
    DEBUG("DNAHELPER shutting down");
  dna_helper_close_pipes();
  switch (dna_helper_kill()) {
  case -1:
    return -1;
  case 0:
    return 0;
  default:
    return dna_helper_harvest(1);
  }
}

static void monitor_requests(struct sched_ent *alarm)
{
  if (config.debug.dnahelper) {
    DEBUGF("sched_requests.poll.fd=%d .revents=%s",
	sched_requests.poll.fd,
	strbuf_str(strbuf_append_poll_events(strbuf_alloca(40), sched_requests.poll.revents))
      );
  }
  // On Linux, poll(2) returns ERR when the remote reader dies.  On Mac OS X, poll(2) returns NVAL,
  // which is documented to mean the file descriptor is not open, but testing revealed that in this
  // case it is still open.  See issue #5.
  if (sched_requests.poll.revents & (POLLHUP | POLLERR | POLLNVAL)) {
    if (config.debug.dnahelper)
      DEBUGF("DNAHELPER closing stdin fd=%d", dna_helper_stdin);
    close(dna_helper_stdin);
    dna_helper_stdin = -1;
    unwatch(&sched_requests);
    sched_requests.poll.fd = -1;
    dna_helper_kill();
  }
  else if (sched_requests.poll.revents & POLLOUT) {
    if (request_bufptr) {
      if (request_bufptr < request_bufend) {
	size_t remaining = request_bufend - request_bufptr;
	sigPipeFlag = 0;
	ssize_t written = write_nonblock(dna_helper_stdin, request_bufptr, remaining);
	if (sigPipeFlag) {
	  /* Broken pipe is probably due to a dead helper, but make sure the helper is dead, just to be
	    sure.  It will be harvested at the next harvester() timeout, and restarted on the first
	    request that arrives after a suitable pause has elapsed.  Losing the current request is not
	    a big problem, because DNA preemptively retries.
	  */
	  INFO("DNAHELPER got SIGPIPE on write -- stopping process");
	  dna_helper_kill();
	} else if (written > 0) {
	  if (config.debug.dnahelper)
	    DEBUGF("DNAHELPER wrote request %s", alloca_toprint(-1, request_bufptr, written));
	  request_bufptr += written;
	}
      }
      if (request_bufptr >= request_bufend) {
	// Request sent successfully.  Start watching for reply.
	request_bufptr = request_bufend = NULL;
	awaiting_reply = 1;
	sched_timeout.alarm = gettime_ms() + 1500;
	sched_timeout.deadline = sched_timeout.alarm + 3000;
	schedule(&sched_timeout);
      }
    }
    // If no request to send, stop monitoring the helper's stdin pipe.
    if (!request_bufptr) {
      unwatch(&sched_requests);
      sched_requests.poll.fd = -1;
    }
  }
}

static char *srv_strnstr(char *haystack, size_t haystack_len, const char *needle)
{
  size_t needle_len = strlen(needle);
  for (; haystack_len >= needle_len; ++haystack, --haystack_len) {
    if (strncmp(haystack, needle, needle_len) == 0)
      return haystack;
  }
  return NULL;
}

void handle_reply_line(const char *bufp, size_t len)
{
  if (!dna_helper_started) {
    if (len == 8 && strncmp(bufp, "STARTED\n", 8) == 0) {
      if (config.debug.dnahelper)
	DEBUGF("DNAHELPER got STARTED ACK");
      dna_helper_started = 1;
      // Start sending request if there is one pending.
      if (request_bufptr) {
	sched_requests.poll.fd = dna_helper_stdin;
	watch(&sched_requests);
      }
    } else {
      WHYF("DNAHELPER malformed start ACK %s", alloca_toprint(-1, bufp, len));
      dna_helper_kill();
    }
  } else if (awaiting_reply) {
    if (len == 5 && strncmp(bufp, "DONE\n", 5) == 0) {
      if (config.debug.dnahelper)
	DEBUG("DNAHELPER reply DONE");
      unschedule(&sched_timeout);
      awaiting_reply = 0;
    } else {
      char sidhex[SID_STRLEN + 1];
      char did[DID_MAXSIZE + 1];
      char name[64];
      char uri[512];
      const char *replyend = NULL;
      if (!parseDnaReply(bufp, len, sidhex, did, name, uri, &replyend))
	WHYF("DNAHELPER reply %s invalid -- ignored", alloca_toprint(-1, bufp, len));
      else if (uri[0] == '\0')
	WHYF("DNAHELPER reply %s contains empty URI -- ignored", alloca_toprint(-1, bufp, len));
      else if (!str_is_uri(uri))
	WHYF("DNAHELPER reply %s contains invalid URI -- ignored", alloca_toprint(-1, bufp, len));
      else if (sidhex[0] == '\0')
	WHYF("DNAHELPER reply %s contains empty token -- ignored", alloca_toprint(-1, bufp, len));
      else if (!str_is_subscriber_id(sidhex))
	WHYF("DNAHELPER reply %s contains invalid token -- ignored", alloca_toprint(-1, bufp, len));
      else if (strncmp(sidhex, request_buffer, SID_STRLEN) != 0)
	WHYF("DNAHELPER reply %s contains mismatched token -- ignored", alloca_toprint(-1, bufp, len));
      else if (did[0] == '\0')
	WHYF("DNAHELPER reply %s contains empty DID -- ignored", alloca_toprint(-1, bufp, len));
      else if (!str_is_did(did))
	WHYF("DNAHELPER reply %s contains invalid DID -- ignored", alloca_toprint(-1, bufp, len));
      else if (strcmp(did, request_did) != 0)
	WHYF("DNAHELPER reply %s contains mismatched DID -- ignored", alloca_toprint(-1, bufp, len));
      else if (*replyend != '\n')
	WHYF("DNAHELPER reply %s contains spurious trailing chars -- ignored", alloca_toprint(-1, bufp, len));
      else {
	if (config.debug.dnahelper)
	  DEBUGF("DNAHELPER reply %s", alloca_toprint(-1, bufp, len));
	overlay_mdp_dnalookup_reply(&request_mdp_data.src, &my_subscriber->sid, uri, did, name);
      }
    }
  } else {
    WARNF("DNAHELPER spurious output %s -- ignored", alloca_toprint(-1, bufp, len));
  }
}

static void monitor_replies(struct sched_ent *alarm)
{
  if (config.debug.dnahelper) {
    DEBUGF("sched_replies.poll.fd=%d .revents=%s",
	sched_replies.poll.fd,
	strbuf_str(strbuf_append_poll_events(strbuf_alloca(40), sched_replies.poll.revents))
      );
  }
  if (sched_replies.poll.revents & POLLIN) {
    size_t remaining = reply_buffer + sizeof reply_buffer - reply_bufend;
    ssize_t nread = read_nonblock(sched_replies.poll.fd, reply_bufend, remaining);
    if (nread > 0) {
      char *bufp = reply_buffer;
      char *readp = reply_bufend;
      reply_bufend += nread;
      char *nl;
      while (nread > 0 && (nl = srv_strnstr(readp, nread, "\n"))) {
	size_t len = nl - bufp + 1;
	if (discarding_until_nl) {
	  if (config.debug.dnahelper)
	    DEBUGF("Discarding %s", alloca_toprint(-1, bufp, len));
	  discarding_until_nl = 0;
	} else {
	  handle_reply_line(bufp, len);
	}
	readp = bufp = nl + 1;
	nread = reply_bufend - readp;
      }
      if (bufp != reply_buffer) {
	size_t len = reply_bufend - bufp;
	memmove(reply_buffer, bufp, len);
	reply_bufend = reply_buffer + len;
      } else if (reply_bufend >= reply_buffer + sizeof reply_buffer) {
	WHY("DNAHELPER reply buffer overrun");
	if (config.debug.dnahelper)
	  DEBUGF("Discarding %s", alloca_toprint(-1, reply_buffer, sizeof reply_buffer));
	reply_bufend = reply_buffer;
	discarding_until_nl = 1;
      }
    }
  }
  if (sched_replies.poll.revents & (POLLHUP | POLLERR | POLLNVAL)) {
    if (config.debug.dnahelper)
      DEBUGF("DNAHELPER closing stdout fd=%d", dna_helper_stdout);
    close(dna_helper_stdout);
    dna_helper_stdout = -1;
    unwatch(&sched_replies);
    sched_replies.poll.fd = -1;
    dna_helper_kill();
  }
}

static void monitor_errors(struct sched_ent *alarm)
{
  if (config.debug.dnahelper) {
    DEBUGF("sched_errors.poll.fd=%d .revents=%s",
	sched_errors.poll.fd,
	strbuf_str(strbuf_append_poll_events(strbuf_alloca(40), sched_errors.poll.revents))
      );
  }
  if (sched_errors.poll.revents & POLLIN) {
    char buffer[1024];
    ssize_t nread = read_nonblock(sched_errors.poll.fd, buffer, sizeof buffer);
    if (nread > 0)
      WHYF("DNAHELPER stderr %s", alloca_toprint(-1, buffer, nread));
  }
  if (sched_errors.poll.revents & (POLLHUP | POLLERR | POLLNVAL)) {
    if (config.debug.dnahelper)
      DEBUGF("DNAHELPER closing stderr fd=%d", dna_helper_stderr);
    close(dna_helper_stderr);
    dna_helper_stderr = -1;
    unwatch(&sched_errors);
    sched_errors.poll.fd = -1;
  }
}

static void harvester(struct sched_ent *alarm)
{
  // While the helper process appears to still be running, keep calling this function.
  // Otherwise, wait a while before re-starting the helper.
  if (dna_helper_harvest(0) <= 0) {
    sched_harvester.alarm = gettime_ms() + 1000;
    sched_harvester.deadline = sched_harvester.alarm + 1000;
    schedule(&sched_harvester);
  } else {
    const int delay_ms = 500;
    if (config.debug.dnahelper)
      DEBUGF("DNAHELPER process died, pausing %d ms before restart", delay_ms);
    dna_helper_pid = 0; // Will be set to -1 after delay
    sched_restart.function = restart_delayer;
    sched_restart.alarm = gettime_ms() + delay_ms;
    sched_restart.deadline = sched_restart.alarm + 500;
    schedule(&sched_restart);
  }
}

static void restart_delayer(struct sched_ent *alarm)
{
  if (dna_helper_pid == 0) {
    if (config.debug.dnahelper)
      DEBUG("DNAHELPER re-enable restart");
    dna_helper_pid = -1;
  }
}

static void reply_timeout(struct sched_ent *alarm)
{
  if (awaiting_reply) {
    WHY("DNAHELPER reply timeout");
    dna_helper_kill();
  }
}

int
dna_helper_enqueue(overlay_mdp_frame *mdp, const char *did, const sid_t *requestorSidp)
{
  if (config.debug.dnahelper)
    DEBUGF("DNAHELPER request did=%s sid=%s", did, alloca_tohex_sid_t(*requestorSidp));
  if (dna_helper_pid == 0)
    return 0;
  // Only try to restart a DNA helper process if the previous one is well and truly gone.
  if (dna_helper_pid == -1 && dna_helper_stdin == -1 && dna_helper_stdout == -1 && dna_helper_stderr == -1) {
    if (dna_helper_start() == -1) {
      /* Something broke, bail out */
      return WHY("DNAHELPER start failed");
    }
  }
  /* Write request to dna helper.
     Request takes form:  SID-of-Requestor|DID|\n
     By passing the requestor's SID to the helper, we don't need to maintain
     any state, as all we have to do is wait for responses from the helper,
     which will include the requestor's SID.
  */
  if (dna_helper_stdin == -1)
    return 0;
  if (request_bufptr && request_bufptr != request_buffer) {
    WARNF("DNAHELPER currently sending request %s -- dropping new request", request_buffer);
    return 0;
  }
  if (awaiting_reply) {
    WARN("DNAHELPER currently awaiting reply -- dropping new request");
    return 0;
  }
  char buffer[sizeof request_buffer];
  strbuf b = strbuf_local(request_bufptr == request_buffer ? buffer : request_buffer, sizeof buffer);
  strbuf_tohex(b, SID_STRLEN, requestorSidp->binary);
  strbuf_putc(b, '|');
  strbuf_puts(b, did);
  strbuf_putc(b, '|');
  strbuf_putc(b, '\n');
  if (strbuf_overrun(b)) {
    WHYF("DNAHELPER request buffer overrun: %s -- request not sent", strbuf_str(b));
    request_bufptr = request_bufend = NULL;
  } else {
    if (strbuf_str(b) != request_buffer) {
      if (strcmp(strbuf_str(b), request_buffer) != 0)
	WARNF("DNAHELPER overwriting unsent request %s", request_buffer);
      strcpy(request_buffer, strbuf_str(b));
    }
    request_bufptr = request_buffer;
    request_bufend = request_buffer + strbuf_len(b);
    request_mdp_data = mdp->out;
    strncpy(request_did, did, sizeof request_did);
    request_did[sizeof request_did - 1] = '\0';
  }
  if (dna_helper_started) {
    sched_requests.poll.fd = dna_helper_stdin;
    watch(&sched_requests);
  }
  return 1;
}
