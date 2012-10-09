/*
Serval Distributed Numbering Architecture (DNA)
Copyright (C) 2010-2012 Paul Gardner-Stephen

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

#include <sys/time.h>
#include <sys/wait.h>
#include <math.h>
#include <string.h>
#include <ctype.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <time.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#ifdef HAVE_JNI_H
#include <jni.h>
#endif
#include "serval.h"
#include "rhizome.h"
#include "strbuf.h"
#include "mdp_client.h"
#include "cli.h"

extern struct command_line_option command_line_options[];

int commandline_usage(int argc, const char *const *argv, struct command_line_option *o, void *context){
  printf("Serval Mesh version <version>.\n");
  return cli_usage(command_line_options);
}

/* Data structures for accumulating output of a single JNI call.
*/

#ifdef HAVE_JNI_H

#define OUTV_BUFFER_ALLOCSIZE	(8192)

JNIEnv *jni_env = NULL;
int jni_exception = 0;

jobject outv_list = NULL;
jmethodID listAddMethodId = NULL;

char *outv_buffer = NULL;
char *outv_current = NULL;
char *outv_limit = NULL;

static int outv_growbuf(size_t needed)
{
  size_t newsize = (outv_limit - outv_current < needed) ? (outv_limit - outv_buffer) + needed : 0;
  if (newsize) {
    // Round up to nearest multiple of OUTV_BUFFER_ALLOCSIZE.
    newsize = newsize + OUTV_BUFFER_ALLOCSIZE - ((newsize - 1) % OUTV_BUFFER_ALLOCSIZE + 1);
    size_t length = outv_current - outv_buffer;
    outv_buffer = realloc(outv_buffer, newsize);
    if (outv_buffer == NULL)
      return WHYF("Out of memory allocating %lu bytes", (unsigned long) newsize);
    outv_current = outv_buffer + length;
    outv_limit = outv_buffer + newsize;
  }
  return 0;
}

static int outv_end_field()
{
  outv_growbuf(1);
  *outv_current++ = '\0';
  jstring str = (jstring)(*jni_env)->NewStringUTF(jni_env, outv_buffer);
  outv_current = outv_buffer;
  if (str == NULL) {
    jni_exception = 1;
    return WHY("Exception thrown from NewStringUTF()");
  }
  (*jni_env)->CallBooleanMethod(jni_env, outv_list, listAddMethodId, str);
  if ((*jni_env)->ExceptionOccurred(jni_env)) {
    jni_exception = 1;
    return WHY("Exception thrown from CallBooleanMethod()");
  }
  (*jni_env)->DeleteLocalRef(jni_env, str);
  return 0;
}

/* JNI entry point to command line.  See org.servalproject.servald.ServalD class for the Java side.
   JNI method descriptor: "(Ljava/util/List;[Ljava/lang/String;)I"
*/
JNIEXPORT jint JNICALL Java_org_servalproject_servald_ServalD_rawCommand(JNIEnv *env, jobject this, jobject outv, jobjectArray args)
{
  jclass stringClass = NULL;
  jclass listClass = NULL;
  unsigned char status = 0; // to match what the shell gets: 0..255
  // Enforce non re-entrancy.
  if (jni_env) {
    jclass exceptionClass = NULL;
    if ((exceptionClass = (*env)->FindClass(env, "java/lang/IllegalStateException")) == NULL)
      return -1; // exception
    (*env)->ThrowNew(env, exceptionClass, "re-entrancy not supported");
    return -1;
  }
  // Get some handles to some classes and methods that we use later on.
  if ((stringClass = (*env)->FindClass(env, "java/lang/String")) == NULL)
    return -1; // exception
  if ((listClass = (*env)->FindClass(env, "java/util/List")) == NULL)
    return -1; // exception
  if ((listAddMethodId = (*env)->GetMethodID(env, listClass, "add", "(Ljava/lang/Object;)Z")) == NULL)
    return -1; // exception
  // Construct argv, argc from this method's arguments.
  jsize len = (*env)->GetArrayLength(env, args);
  const char **argv = malloc(sizeof(char*) * (len + 1));
  if (argv == NULL) {
    jclass exceptionClass = NULL;
    if ((exceptionClass = (*env)->FindClass(env, "java/lang/OutOfMemoryError")) == NULL)
      return -1; // exception
    (*env)->ThrowNew(env, exceptionClass, "malloc returned NULL");
    return -1;
  }
  jsize i;
  for (i = 0; i <= len; ++i)
    argv[i] = NULL;
  int argc = len;
  // From now on, in case of an exception we have to free some resources before
  // returning.
  jni_exception = 0;
  for (i = 0; !jni_exception && i != len; ++i) {
    const jstring arg = (jstring)(*env)->GetObjectArrayElement(env, args, i);
    if (arg == NULL)
      jni_exception = 1;
    else {
      const char *str = (*env)->GetStringUTFChars(env, arg, NULL);
      if (str == NULL)
	jni_exception = 1;
      else
	argv[i] = str;
    }
  }
  if (!jni_exception) {
    // Set up the output buffer.
    outv_list = outv;
    outv_current = outv_buffer;
    // Execute the command.
    jni_env = env;
    status = parseCommandLine(NULL, argc, argv);
    jni_env = NULL;
  }
  // Release argv Java string buffers.
  for (i = 0; i != len; ++i) {
    if (argv[i]) {
      const jstring arg = (jstring)(*env)->GetObjectArrayElement(env, args, i);
      (*env)->ReleaseStringUTFChars(env, arg, argv[i]);
    }
  }
  free(argv);
  // Deal with Java exceptions: NewStringUTF out of memory in outv_end_field().
  if (jni_exception || (outv_current != outv_buffer && outv_end_field() == -1))
    return -1;
  return (jint) status;
}

#endif /* HAVE_JNI_H */

/* The argc and argv arguments must be passed verbatim from main(argc, argv), so argv[0] is path to
   executable.
*/
int parseCommandLine(const char *argv0, int argc, const char *const *args)
{
  fd_clearstats();
  IN();
  confSetDebugFlags();
  
  int result = cli_execute(argv0, argc, args, command_line_options, NULL);
  /* clean up after ourselves */
  overlay_mdp_client_done();
  OUT();
  
  if (debug&DEBUG_TIMING)
    fd_showstats();
  return result;
}

/* Write a single character to output.  If in a JNI call, then this appends the character to the
   current output field.  Returns the character written cast to an unsigned char then to int, or EOF
   on error.
 */
int cli_putchar(char c)
{
#ifdef HAVE_JNI_H
    if (jni_env) {
      if (outv_current == outv_limit && outv_growbuf(1) == -1)
	return EOF;
      *outv_current++ = c;
      return (unsigned char) c;
    }
    else
#endif
      return putchar(c);
}

/* Write a null-terminated string to output.  If in a JNI call, then this appends the string to the
   current output field.  The terminating null is not included.  Returns a non-negative integer on
   success, EOF on error.
 */
int cli_puts(const char *str)
{
#ifdef HAVE_JNI_H
    if (jni_env) {
      size_t len = strlen(str);
      size_t avail = outv_limit - outv_current;
      if (avail < len) {
	strncpy(outv_current, str, avail);
	outv_current = outv_limit;
	if (outv_growbuf(len) == -1)
	  return EOF;
	len -= avail;
	str += avail;
      }
      strncpy(outv_current, str, len);
      outv_current += len;
      return 0;
    }
    else
#endif
      return fputs(str, stdout);
}

/* Write a formatted string to output.  If in a JNI call, then this appends the string to the
   current output field, excluding the terminating null.  Returns the number of bytes
   written/appended, or -1 on error.
 */
int cli_printf(const char *fmt, ...)
{
  int ret = 0;
  va_list ap;
#ifdef HAVE_JNI_H
  if (jni_env) {
    size_t avail = outv_limit - outv_current;
    va_start(ap, fmt);
    int count = vsnprintf(outv_current, avail, fmt, ap);
    va_end(ap);
    if (count >= avail) {
      if (outv_growbuf(count) == -1)
	return -1;
      va_start(ap, fmt);
      vsprintf(outv_current, fmt, ap);
      va_end(ap);
    }
    outv_current += count;
    ret = count;
  } else
#endif
  {
    va_start(ap, fmt);
    ret = vfprintf(stdout, fmt, ap);
    va_end(ap);
  }
  return ret;
}

/* Delimit the current output field.  This closes the current field, so that the next cli_ output
   function will start appending to a new field.  Returns 0 on success, -1 on error.  If not in a
   JNI call, then this simply writes a newline to standard output (or the value of the
   SERVALD_OUTPUT_DELIMITER env var if set).
 */
int cli_delim(const char *opt)
{
#ifdef HAVE_JNI_H
  if (jni_env)
    return outv_end_field();
#endif
  const char *delim = getenv("SERVALD_OUTPUT_DELIMITER");
  if (delim == NULL)
    delim = opt ? opt : "\n";
  fputs(delim, stdout);
  return 0;
}

/* Flush the output fields if they are being written to standard output.
 */
void cli_flush()
{
#ifdef HAVE_JNI_H
  if (jni_env)
    return;
#endif
  fflush(stdout);
}

int app_echo(int argc, const char *const *argv, struct command_line_option *o, void *context)
{
  if (debug & DEBUG_VERBOSE) DEBUG_argv("command", argc, argv);
  int i;
  for (i = 1; i < argc; ++i) {
    if (debug & DEBUG_VERBOSE)
      DEBUGF("echo:argv[%d]=%s", i, argv[i]);
    cli_puts(argv[i]);
    cli_delim(NULL);
  }
  return 0;
}

void lookup_send_request(unsigned char *srcsid, int srcport, unsigned char *dstsid, const char *did){
  int i;
  overlay_mdp_frame mdp;
  bzero(&mdp,sizeof(mdp));
  
  
  /* set source address to a local address, and pick a random port */
  mdp.out.src.port=srcport;
  bcopy(srcsid,mdp.out.src.sid,SID_SIZE);
  
  /* Send to destination address and DNA lookup port */
  
  if (dstsid){
    /* Send an encrypted unicast packet */
    mdp.packetTypeAndFlags=MDP_TX;
    bcopy(dstsid, mdp.out.dst.sid, SID_SIZE);
  }else{
    /* Send a broadcast packet, flooding across the local mesh network */
    mdp.packetTypeAndFlags=MDP_TX|MDP_NOCRYPT;
    for(i=0;i<SID_SIZE;i++) 
      mdp.out.dst.sid[i]=0xff;
  }  
  mdp.out.dst.port=MDP_PORT_DNALOOKUP;
  
  /* put DID into packet */
  bcopy(did,&mdp.out.payload[0],strlen(did)+1);
  mdp.out.payload_length=strlen(did)+1;
  
  overlay_mdp_send(&mdp,0,0);
  
  /* Also send an encrypted unicast request to a configured directory service */
  if (!dstsid){
    const char *directory_service = confValueGet("directory.service", NULL);
    if (directory_service){
      if (stowSid(mdp.out.dst.sid, 0, directory_service)==-1){
	WHYF("Invalid directory server SID %s", directory_service);
      }else{
	mdp.packetTypeAndFlags=MDP_TX;
	overlay_mdp_send(&mdp,0,0);
      }
    }
  }
}

int app_dna_lookup(int argc, const char *const *argv, struct command_line_option *o, void *context)
{
  if (debug & DEBUG_VERBOSE) DEBUG_argv("command", argc, argv);
  
  /* Create the instance directory if it does not yet exist */
  if (create_serval_instance_dir() == -1)
    return -1;

  int uri_count=0;
#define MAXREPLIES 256
#define MAXURILEN 256
  char uris[MAXREPLIES][MAXURILEN];

  const char *did, *delay;
  if (cli_arg(argc, argv, o, "did", &did, cli_lookup_did, "*") == -1)
    return -1;
  if (cli_arg(argc, argv, o, "timeout", &delay, NULL, "3000") == -1)
    return -1;
  
  int idelay=atoi(delay);
  int one_reply=0;
  
  // Ugly hack, if timeout is negative, stop after first reply
  if (idelay<0){
    one_reply=1;
    idelay=-idelay;
  }
  
  /* Bind to MDP socket and await confirmation */
  unsigned char srcsid[SID_SIZE];
  int port=32768+(random()&32767);
  if (overlay_mdp_getmyaddr(0,srcsid)) return WHY("Could not get local address");
  if (overlay_mdp_bind(srcsid,port)) return WHY("Could not bind to MDP socket");

  /* use MDP to send the lookup request to MDP_PORT_DNALOOKUP, and wait for
     replies. */

  /* Now repeatedly send resolution request and collect results until we reach
     timeout. */
  time_ms_t timeout = gettime_ms() + idelay;
  time_ms_t last_tx = 0;
  time_ms_t now;
  int interval=125;
  
  while (timeout > (now = gettime_ms()))
    {
      if ((last_tx+interval)<now)
	{

	  lookup_send_request(srcsid, port, NULL, did);

	  last_tx=now;
	  interval+=interval>>1;
	}
      time_ms_t short_timeout=125;
      while(short_timeout>0) {
	if (overlay_mdp_client_poll(short_timeout))
	  {
	    overlay_mdp_frame rx;
	    int ttl;
	    if (overlay_mdp_recv(&rx, port, &ttl)==0)
	      {
		if (rx.packetTypeAndFlags==MDP_ERROR)
		  {
		    WHYF("       Error message: %s", rx.error.message);
		  }
		else if ((rx.packetTypeAndFlags&MDP_TYPE_MASK)==MDP_TX) {
		  /* Extract DID, Name, URI from response. */
		  if (strlen((char *)rx.in.payload)<512) {
		    char sidhex[SID_STRLEN + 1];
		    char did[DID_MAXSIZE + 1];
		    char name[64];
		    char uri[512];
		    if ( !parseDnaReply((char *)rx.in.payload, rx.in.payload_length, sidhex, did, name, uri, NULL)
		      || !str_is_subscriber_id(sidhex)
		      || !str_is_did(did)
		      || !str_is_uri(uri)
		    ) {
		      WHYF("Received malformed DNA reply: %s", alloca_toprint(160, (const char *)rx.in.payload, rx.in.payload_length));
		    } else {
		      /* Have we seen this response before? */
		      int i;
		      for(i=0;i<uri_count;i++)
			if (!strcmp(uri,uris[i])) break;
		      if (i==uri_count) {
			/* Not previously seen, so report it */
			cli_puts(uri); cli_delim(":");
			cli_puts(did); cli_delim(":");
			cli_puts(name); cli_delim("\n");
			
			if (one_reply){
			  timeout=now;
			  short_timeout=0;
			}
			
			/* Remember that we have seen it */
			if (uri_count<MAXREPLIES&&strlen(uri)<MAXURILEN) {
			  strcpy(uris[uri_count++],uri);
			}
		      }
		    }
		  }
		}
		else WHYF("packettype=0x%x",rx.packetTypeAndFlags);
		if (servalShutdown) break;
	      }
	  }
	if (servalShutdown) break;
	short_timeout=125-(gettime_ms()-now);
      }
      if (servalShutdown) break;
    }

  overlay_mdp_client_done();
  return 0;
}

int app_server_start(int argc, const char *const *argv, struct command_line_option *o, void *context)
{
  if (debug & DEBUG_VERBOSE) DEBUG_argv("command", argc, argv);
  /* Process optional arguments */
  int pid=-1;
  int cpid=-1;
#if 0
  // It would have been nice if whoever disabled this code had left a comment as to why they didn't
  // simply delete it altogether.  In any event, this logic is largely redundant because the Android
  // Batphone app automatically calls "servald stop" then "servald start" (via JNI) whenever its
  // monitor interface socket is broken.
  // -- Andrew Bettison <andrew@servalproject.com>
  int status=server_probe(&pid);
  switch(status) {
  case SERVER_NOTRESPONDING: 
    /* server is not responding, and we have been asked to start,
       so try to kill it?
    */
    WHYF("Serval process already running (pid=%d), but no responding.", pid);
    if (pid>-1) {
      kill(pid,SIGHUP); sleep(1);
      status=server_probe(&pid);
      if (status!=SERVER_NOTRUNNING) {
	WHY("Tried to stop stuck servald process, but attempt failed.");
	return -1;
      }
      WHY("Killed stuck servald process, so will try to start");
      pid=-1;
    }
    break;
  case SERVER_NOTRUNNING:
    /* all is well */
    break;
  case SERVER_RUNNING:
    /* instance running */
    break;
  default:
    /* no idea what is going on, so try to start anyway */
    break;
  }
#endif
  const char *execpath, *instancepath;
  char *tmp;
  int foregroundP = (argc >= 2 && !strcasecmp(argv[1], "foreground"));
  if (cli_arg(argc, argv, o, "instance path", &instancepath, cli_absolute_path, NULL) == -1
   || cli_arg(argc, argv, o, "exec path", &execpath, cli_absolute_path, NULL) == -1)
    return -1;
  if (instancepath != NULL)
    serval_setinstancepath(instancepath);
  if (execpath == NULL) {
#ifdef HAVE_JNI_H
    if (jni_env)
      return WHY("Must supply <exec path> argument when invoked via JNI");
#endif
    if ((tmp = malloc(PATH_MAX)) == NULL)
	return WHY("Out of memory");
  if (get_self_executable_path(tmp, PATH_MAX) == -1)
    return WHY("unable to determine own executable name");
  execpath = tmp;
  }
  /* Create the instance directory if it does not yet exist */
  if (create_serval_instance_dir() == -1)
    return -1;
  /* Now that we know our instance path, we can ask for the default set of
     network interfaces that we will take interest in. */
  const char *interfaces = confValueGet("interfaces", "");
  if (!interfaces[0])
    WHY("No network interfaces configured (empty 'interfaces' config setting)");
  overlay_interface_args(interfaces);
  if (pid == -1)
    pid = server_pid();
  if (pid < 0)
    return -1;
  int ret = -1;
  // If the pidfile identifies this process, it probably means we are re-spawning after a SEGV, so
  // go ahead and do the fork/exec.
  if (pid > 0 && pid != getpid()) {
    INFOF("Server already running (pid=%d)", pid);
    ret = 10;
  } else {
    if (foregroundP)
      INFOF("Foreground server process %s", execpath ? execpath : "without exec");
    else
      INFOF("Starting background server %s", execpath ? execpath : "without exec");
    /* Start the Serval process.  All server settings will be read by the server process from the
       instance directory when it starts up.  */
    if (server_remove_stopfile() == -1)
      return -1;
    if (rhizome_enabled() && rhizome_opendb() == -1)
      return -1;
    overlayMode = 1;
    if (foregroundP)
      return server(NULL);
    const char *dir = getenv("SERVALD_SERVER_CHDIR");
    if (!dir)
      dir = confValueGet("server.chdir", "/");
    switch (cpid = fork()) {
      case -1:
	/* Main process.  Fork failed.  There is no child process. */
	return WHY_perror("fork");
      case 0: {
	/* Child process.  Fork then exit, to disconnect daemon from parent process, so that
	   when daemon exits it does not live on as a zombie. N.B. Do not return from within this
	   process; that will unroll the JNI call stack and cause havoc.  Use _exit().  */
	switch (fork()) {
	  case -1:
	    exit(WHY_perror("fork"));
	  case 0: {
	    /* Grandchild process.  Close logfile (so that it gets re-opened again on demand, with
	       our own file pointer), disconnect from current directory, disconnect standard I/O
	       streams, and start a new process session so that if we are being started by an adb
	       shell session, then we don't receive a SIGHUP when the adb shell process ends.  */
	    close_logging();
	    int fd;
	    if ((fd = open("/dev/null", O_RDWR, 0)) == -1)
	      _exit(WHY_perror("open"));
	    if (setsid() == -1)
	      _exit(WHY_perror("setsid"));
	    (void)chdir(dir);
	    (void)dup2(fd, 0);
	    (void)dup2(fd, 1);
	    (void)dup2(fd, 2);
	    if (fd > 2)
	      (void)close(fd);
	    /* The execpath option is provided so that a JNI call to "start" can be made which
	       creates a new server daemon process with the correct argv[0].  Otherwise, the servald
	       process appears as a process with argv[0] = "org.servalproject". */
	    if (execpath) {
	    /* Need the cast on Solaris because it defines NULL as 0L and gcc doesn't see it as a
	       sentinal. */
	      execl(execpath, execpath, "start", "foreground", (void *)NULL);
	      _exit(-1);
	    }
	    _exit(server(NULL));
	    // NOT REACHED
	  }
	}
	_exit(0); // Main process is waitpid()-ing for this.
      }
    }
    /* Main process.  Wait for the child process to fork the grandchild and exit. */
    waitpid(cpid, NULL, 0);
    /* Allow a few seconds for the grandchild process to report for duty. */
    time_ms_t timeout = gettime_ms() + 5000;
    do {
      sleep_ms(200); // 5 Hz
    } while ((pid = server_pid()) == 0 && gettime_ms() < timeout);
    if (pid == -1)
      return -1;
    if (pid == 0)
      return WHY("Server process did not start");
    ret = 0;
  }
  cli_puts("instancepath");
  cli_delim(":");
  cli_puts(serval_instancepath());
  cli_delim("\n");
  cli_puts("pid");
  cli_delim(":");
  cli_printf("%d", pid);
  cli_delim("\n");
  cli_flush();
  /* Sleep before returning if env var is set.  This is used in testing, to simulate the situation
     on Android phones where the "start" command is invoked via the JNI interface and the calling
     process does not die.
   */
  const char *post_sleep = getenv("SERVALD_START_POST_SLEEP");
  if (post_sleep) {
    time_ms_t milliseconds = atof(post_sleep) * 1000;
    if (milliseconds > 0) {
      INFOF("Sleeping for %lld milliseconds", (long long) milliseconds);
      sleep_ms(milliseconds);
    }
  }
  return ret;
}

int app_server_stop(int argc, const char *const *argv, struct command_line_option *o, void *context)
{
  if (debug & DEBUG_VERBOSE) DEBUG_argv("command", argc, argv);
  int			pid, tries, running;
  const char		*instancepath;
  time_ms_t		timeout;
  if (cli_arg(argc, argv, o, "instance path", &instancepath, cli_absolute_path, NULL) == -1)
    return WHY("Unable to determine instance path");
  if (instancepath != NULL)
    serval_setinstancepath(instancepath);
  instancepath = serval_instancepath();
  cli_puts("instancepath");
  cli_delim(":");
  cli_puts(instancepath);
  cli_delim("\n");
  pid = server_pid();
  /* Not running, nothing to stop */
  if (pid <= 0)
    return 1;
  INFOF("Stopping server (pid=%d)", pid);
  /* Set the stop file and signal the process */
  cli_puts("pid");
  cli_delim(":");
  cli_printf("%d", pid);
  cli_delim("\n");
  tries = 0;
  running = pid;
  while (running == pid) {
    if (tries >= 5)
      return WHYF(
	  "Servald pid=%d for instance '%s' did not stop after %d SIGHUP signals",
	  pid, instancepath, tries
	);
    ++tries;
    /* Create the stopfile, which causes the server process's signal handler to exit
       instead of restarting. */
    server_create_stopfile();
    if (kill(pid, SIGHUP) == -1) {
      // ESRCH means process is gone, possibly we are racing with another stop, or servald just
      // died voluntarily.
      if (errno == ESRCH) {
	serverCleanUp();
	break;
      }
      WHY_perror("kill");
      return WHYF("Error sending SIGHUP to Servald pid=%d for instance '%s'", pid, instancepath);
    }
    /* Allow a few seconds for the process to die. */
    timeout = gettime_ms() + 2000;
    do
      sleep_ms(200); // 5 Hz
    while ((running = server_pid()) == pid && gettime_ms() < timeout);
  }
  server_remove_stopfile();
  cli_puts("tries");
  cli_delim(":");
  cli_printf("%d", tries);
  cli_delim("\n");
  return 0;
}

int app_server_status(int argc, const char *const *argv, struct command_line_option *o, void *context)
{
  if (debug & DEBUG_VERBOSE) DEBUG_argv("command", argc, argv);
  int	pid;
  const char *instancepath;
  if (cli_arg(argc, argv, o, "instance path", &instancepath, cli_absolute_path, NULL) == -1)
    return WHY("Unable to determine instance path");
  if (instancepath != NULL)
    serval_setinstancepath(instancepath);
  pid = server_pid();
  cli_puts("instancepath");
  cli_delim(":");
  cli_puts(serval_instancepath());
  cli_delim("\n");
  cli_puts("status");
  cli_delim(":");
  cli_printf("%s", pid > 0 ? "running" : "stopped");
  cli_delim("\n");
  if (pid > 0) {
    cli_puts("pid");
    cli_delim(":");
    cli_printf("%d", pid);
    cli_delim("\n");
  }
  return pid > 0 ? 0 : 1;
}

int app_mdp_ping(int argc, const char *const *argv, struct command_line_option *o, void *context)
{
  if (debug & DEBUG_VERBOSE) DEBUG_argv("command", argc, argv);
  const char *sid, *count;
  if (cli_arg(argc, argv, o, "SID|broadcast", &sid, str_is_subscriber_id, "broadcast") == -1)
    return -1;
  if (cli_arg(argc, argv, o, "count", &count, NULL, "0") == -1)
    return -1;
  
  // assume we wont hear any responses
  int ret=-1;
  int icount=atoi(count);

  overlay_mdp_frame mdp;
  bzero(&mdp, sizeof(overlay_mdp_frame));
  /* Bind to MDP socket and await confirmation */
  unsigned char srcsid[SID_SIZE];
  int port=32768+(random()&32767);
  if (overlay_mdp_getmyaddr(0,srcsid)) return WHY("Could not get local address");
  if (overlay_mdp_bind(srcsid,port)) return WHY("Could not bind to MDP socket");

  /* First sequence number in the echo frames */
  unsigned int firstSeq=random();
  unsigned int sequence_number=firstSeq;

  /* Get SID that we want to ping.
     XXX - allow lookup of SID prefixes and telephone numbers
     (that would require MDP lookup of phone numbers, which doesn't yet occur) */
  int i;
  int broadcast=0;
  unsigned char ping_sid[SID_SIZE];
  if (strcasecmp(sid,"broadcast")) {
    stowSid(ping_sid,0,sid);
  } else {
    for(i=0;i<SID_SIZE;i++) ping_sid[i]=0xff;
    broadcast=1;
  }

  /* XXX Eventually we should try to resolve SID to phone number and vice versa */
  printf("MDP PING %s (%s): 12 data bytes\n", alloca_tohex_sid(ping_sid), alloca_tohex_sid(ping_sid));

  time_ms_t rx_mintime=-1;
  time_ms_t rx_maxtime=-1;
  time_ms_t rx_ms=0;
  time_ms_t rx_times[1024];
  long long rx_count=0,tx_count=0;

  if (broadcast) 
    WHY("WARNING: broadcast ping packets will not be encryped.");
  while(icount==0 || tx_count<icount) {
    /* Now send the ping packets */
    mdp.packetTypeAndFlags=MDP_TX;
    if (broadcast) mdp.packetTypeAndFlags|=MDP_NOCRYPT;
    mdp.out.src.port=port;
    bcopy(srcsid,mdp.out.src.sid,SID_SIZE);
    bcopy(ping_sid,&mdp.out.dst.sid[0],SID_SIZE);
    mdp.out.queue=OQ_MESH_MANAGEMENT;
    /* Set port to well known echo port (from /etc/services) */
    mdp.out.dst.port=7;
    mdp.out.payload_length=4+8;
    int *seq=(int *)&mdp.out.payload;
    *seq=sequence_number;
    long long *txtime=(long long *)&mdp.out.payload[4];
    *txtime=gettime_ms();
    
    int res=overlay_mdp_send(&mdp,0,0);
    if (res) {
      WHYF("ERROR: Could not dispatch PING frame #%d (error %d)", sequence_number - firstSeq, res);
      if (mdp.packetTypeAndFlags==MDP_ERROR)
	WHYF("       Error message: %s", mdp.error.message);
    } else tx_count++;

    /* Now look for replies until one second has passed, and print any replies
       with appropriate information as required */
    time_ms_t now = gettime_ms();
    time_ms_t timeout = now + 1000;

    while(now<timeout) {
      time_ms_t timeout_ms = timeout - gettime_ms();
      int result = overlay_mdp_client_poll(timeout_ms);

      if (result>0) {
	int ttl=-1;
	if (overlay_mdp_recv(&mdp, port, &ttl)==0) {
	  switch(mdp.packetTypeAndFlags&MDP_TYPE_MASK) {
	  case MDP_ERROR:
	    WHYF("mdpping: overlay_mdp_recv: %s (code %d)", mdp.error.message, mdp.error.error);
	    break;
	  case MDP_TX:
	    {
	      int *rxseq=(int *)&mdp.in.payload;
	      long long *txtime=(long long *)&mdp.in.payload[4];
	      time_ms_t delay = gettime_ms() - *txtime;
	      printf("%s: seq=%d time=%lld ms%s%s\n",
		     alloca_tohex_sid(mdp.in.src.sid),(*rxseq)-firstSeq+1,delay,
		     mdp.packetTypeAndFlags&MDP_NOCRYPT?"":" ENCRYPTED",
		     mdp.packetTypeAndFlags&MDP_NOSIGN?"":" SIGNED");
	      // TODO Put duplicate pong detection here so that stats work properly.
	      rx_count++;
	      ret=0;
	      rx_ms+=delay;
	      if (rx_mintime>delay||rx_mintime==-1) rx_mintime=delay;
	      if (delay>rx_maxtime) rx_maxtime=delay;
	      rx_times[rx_count%1024]=delay;
	    }
	    break;
	  default:
	    WHYF("mdpping: overlay_mdp_recv: Unexpected MDP frame type 0x%x", mdp.packetTypeAndFlags);
	    break;
	  }
	}
      }
      now=gettime_ms();
      if (servalShutdown)
	break;
    }
    sequence_number++;
    timeout=now+1000;
  }

  {
    float rx_stddev=0;
    float rx_mean=rx_ms*1.0/rx_count;
    int samples=rx_count;
    if (samples>1024) samples=1024;
    int i;
    for(i=0;i<samples;i++)
      rx_stddev+=(rx_mean-rx_times[i])*(rx_mean-rx_times[i]);
    rx_stddev/=samples;
    rx_stddev=sqrtf(rx_stddev);

    /* XXX Report final statistics before going */
    printf("--- %s ping statistics ---\n", alloca_tohex_sid(ping_sid));
    printf("%lld packets transmitted, %lld packets received, %3.1f%% packet loss\n",
	   tx_count,rx_count,tx_count?(tx_count-rx_count)*100.0/tx_count:0);
    printf("round-trip min/avg/max/stddev%s = %lld/%.3f/%lld/%.3f ms\n",
	   (samples<rx_count)?" (stddev calculated from last 1024 samples)":"",
	   rx_mintime,rx_mean,rx_maxtime,rx_stddev);
  }
  overlay_mdp_client_done();
  return ret;
}

int app_config_set(int argc, const char *const *argv, struct command_line_option *o, void *context)
{
  if (debug & DEBUG_VERBOSE) DEBUG_argv("command", argc, argv);
  const char *var, *val;
  if (	cli_arg(argc, argv, o, "variable", &var, is_configvarname, NULL)
     || cli_arg(argc, argv, o, "value", &val, NULL, ""))
    return -1;
  if (create_serval_instance_dir() == -1)
    return -1;
  return confValueSet(var, val) == -1 ? -1 : confWrite();
}

int app_config_del(int argc, const char *const *argv, struct command_line_option *o, void *context)
{
  if (debug & DEBUG_VERBOSE) DEBUG_argv("command", argc, argv);
  const char *var;
  if (cli_arg(argc, argv, o, "variable", &var, is_configvarname, NULL))
    return -1;
  if (create_serval_instance_dir() == -1)
    return -1;
  return confValueSet(var, NULL) == -1 ? -1 : confWrite();
}

int app_config_get(int argc, const char *const *argv, struct command_line_option *o, void *context)
{
  if (debug & DEBUG_VERBOSE) DEBUG_argv("command", argc, argv);
  const char *var;
  if (cli_arg(argc, argv, o, "variable", &var, is_configvarname, NULL) == -1)
    return -1;
  if (create_serval_instance_dir() == -1)
    return -1;
  if (var) {
    const char *value = confValueGet(var, NULL);
    if (value) {
      cli_puts(var);
      cli_delim("=");
      cli_puts(value);
      cli_delim("\n");
    }
  } else {
    int n = confVarCount();
    if (n == -1)
      return -1;
    unsigned int i;
    for (i = 0; i != n; ++i) {
      cli_puts(confVar(i));
      cli_delim("=");
      cli_puts(confValue(i));
      cli_delim("\n");
    }
  }
  return 0;
}

int app_rhizome_hash_file(int argc, const char *const *argv, struct command_line_option *o, void *context)
{
  if (debug & DEBUG_VERBOSE) DEBUG_argv("command", argc, argv);
  /* compute hash of file. We do this without a manifest, so it will necessarily
     return the hash of the file unencrypted. */
  const char *filepath;
  cli_arg(argc, argv, o, "filepath", &filepath, NULL, "");
  char hexhash[RHIZOME_FILEHASH_STRLEN + 1];
  if (rhizome_hash_file(NULL,filepath, hexhash))
    return -1;
  cli_puts(hexhash);
  cli_delim("\n");
  return 0;
}

int app_rhizome_add_file(int argc, const char *const *argv, struct command_line_option *o, void *context)
{
  if (debug & DEBUG_VERBOSE) DEBUG_argv("command", argc, argv);
  const char *filepath, *manifestpath, *authorSidHex, *pin, *bskhex;
  cli_arg(argc, argv, o, "filepath", &filepath, NULL, "");
  if (cli_arg(argc, argv, o, "author_sid", &authorSidHex, cli_optional_sid, "") == -1)
    return -1;
  cli_arg(argc, argv, o, "pin", &pin, NULL, "");
  cli_arg(argc, argv, o, "manifestpath", &manifestpath, NULL, "");
  if (cli_arg(argc, argv, o, "bsk", &bskhex, cli_optional_bundle_key, "") == -1)
    return -1;
  unsigned char authorSid[SID_SIZE];
  if (authorSidHex[0] && fromhexstr(authorSid, authorSidHex, SID_SIZE) == -1)
    return WHYF("invalid author_sid: %s", authorSidHex);
  unsigned char bsk[RHIZOME_BUNDLE_KEY_BYTES];
  if (bskhex[0] && fromhexstr(bsk, bskhex, RHIZOME_BUNDLE_KEY_BYTES) == -1)
    return WHYF("invalid bsk: %s", bskhex);
  if (create_serval_instance_dir() == -1)
    return -1;
  if (!(keyring = keyring_open_with_pins((char *)pin)))
    return -1;
  if (rhizome_opendb() == -1)
    return -1;
  /* Create a new manifest that will represent the file.  If a manifest file was supplied, then read
   * it, otherwise create a blank manifest. */
  rhizome_manifest *m = rhizome_new_manifest();
  if (!m)
    return WHY("Manifest struct could not be allocated -- not added to rhizome");
  if (manifestpath[0] && access(manifestpath, R_OK) == 0) {
    if (debug & DEBUG_RHIZOME) DEBUGF("reading manifest from %s", manifestpath);
    /* Don't verify the manifest, because it will fail if it is incomplete.
       This is okay, because we fill in any missing bits and sanity check before
       trying to write it out. */
    if (rhizome_read_manifest_file(m, manifestpath, 0) == -1) {
      rhizome_manifest_free(m);
      return WHY("Manifest file could not be loaded -- not added to rhizome");
    }
  } else {
    if (debug & DEBUG_RHIZOME) DEBUGF("manifest file %s does not exist -- creating new manifest", manifestpath);
  }
  /* Fill in a few missing manifest fields, to make it easier to use when adding new files:
      - the default service is FILE
      - use the current time for "date"
      - if service is file, then use the payload file's basename for "name"
  */
  const char *service = rhizome_manifest_get(m, "service", NULL, 0);
  if (service == NULL) {
    rhizome_manifest_set(m, "service", (service = RHIZOME_SERVICE_FILE));
    if (debug & DEBUG_RHIZOME) DEBUGF("missing 'service', set default service=%s", service);
  } else {
    if (debug & DEBUG_RHIZOME) DEBUGF("manifest contains service=%s", service);
  }
  if (rhizome_manifest_get(m, "date", NULL, 0) == NULL) {
    rhizome_manifest_set_ll(m, "date", (long long) gettime_ms());
    if (debug & DEBUG_RHIZOME) DEBUGF("missing 'date', set default date=%s", rhizome_manifest_get(m, "date", NULL, 0));
  }
  if (strcasecmp(RHIZOME_SERVICE_FILE, service) == 0) {
    const char *name = rhizome_manifest_get(m, "name", NULL, 0);
    if (name == NULL) {
      name = strrchr(filepath, '/');
      name = name ? name + 1 : filepath;
      rhizome_manifest_set(m, "name", name);
      if (debug & DEBUG_RHIZOME) DEBUGF("missing 'name', set default name=\"%s\"", name);
    } else {
      if (debug & DEBUG_RHIZOME) DEBUGF("manifest contains name=\"%s\"", name);
    }
  }
  /* If the author was not specified on the command-line, then the manifest's "sender"
      field is used, if present. */
  const char *sender = NULL;
  if (!authorSidHex[0] && (sender = rhizome_manifest_get(m, "sender", NULL, 0)) != NULL) {
    if (fromhexstr(authorSid, sender, SID_SIZE) == -1)
      return WHYF("invalid sender: %s", sender);
    authorSidHex = sender;
  }
  /* Bind an ID to the manifest, and also bind the file.  Then finalise the manifest.
     But if the manifest already contains an ID, don't override it. */
  if (rhizome_manifest_get(m, "id", NULL, 0) == NULL) {
    if (rhizome_manifest_bind_id(m, authorSidHex[0] ? authorSid : NULL)) {
      rhizome_manifest_free(m);
      m = NULL;
      return WHY("Could not bind manifest to an ID");
    }
  } else if (bskhex[0]) {
    /* Modifying an existing bundle.  If the caller provides the bundle secret key, then ensure that
       it corresponds to the bundle's public key (its bundle ID), otherwise the caller cannot modify
       the bundle. */
    memcpy(m->cryptoSignSecret, bsk, RHIZOME_BUNDLE_KEY_BYTES);
    if (rhizome_verify_bundle_privatekey(m) == -1) {
      rhizome_manifest_free(m);
      m = NULL;
      return WHY("Incorrect BID secret key.");
    }
  } else if (!authorSidHex[0]) {
    /* In order to modify an existing bundle, the author must be known. */
    rhizome_manifest_free(m);
    m = NULL;
    return WHY("Author SID not specified");
  } else if (rhizome_extract_privatekey(m, authorSid) == -1) {
    /* Only the original author can modify an existing bundle. */
    rhizome_manifest_free(m);
    m = NULL;
    return WHY("Could not extract BID secret key. Does the manifest have a BK?");
  }
  int encryptP = 0; // TODO Determine here whether payload is to be encrypted.
  if (rhizome_manifest_bind_file(m, filepath, encryptP)) {
    rhizome_manifest_free(m);
    return WHYF("Could not bind manifest to file '%s'",filepath);
  }
  /* Add the manifest and its associated file to the Rhizome database, 
     generating an "id" in the process.
     PGS @20121003 - Hang on, didn't we create the ID above? Presumably the
     following does NOT in fact generate a bundle ID. 
  */
  rhizome_manifest *mout = NULL;
  if (debug & DEBUG_RHIZOME) DEBUGF("rhizome_add_manifest(author='%s')", authorSidHex);

  int ret=0;
  if (rhizome_manifest_check_duplicate(m,&mout)==2)
    {
      /* duplicate found -- verify it so that we can write it out later */
      rhizome_manifest_verify(mout);
      ret=2;
    } else {
    /* not duplicate, so finalise and add to database */
    if (rhizome_manifest_finalise(m)) {
      rhizome_manifest_free(m);
      return WHY("Could not finalise manifest");
    }
    if (rhizome_add_manifest(m,255 /* TTL */)) {
      rhizome_manifest_free(m);
      return WHY("Manifest not added to Rhizome database");
    }
  }

  /* If successfully added, overwrite the manifest file so that the Java component that is
     invoking this command can read it to obtain feedback on the result. */
  rhizome_manifest *mwritten=mout?mout:m;
  if (manifestpath[0] 
      && rhizome_write_manifest_file(mwritten, manifestpath) == -1)
    ret = WHY("Could not overwrite manifest file.");
  service = rhizome_manifest_get(mwritten, "service", NULL, 0);
  if (service) {
    cli_puts("service");
    cli_delim(":");
    cli_puts(service);
    cli_delim("\n");
  }
  {
    char bid[RHIZOME_MANIFEST_ID_STRLEN + 1];
    rhizome_bytes_to_hex_upper(mwritten->cryptoSignPublic, bid, RHIZOME_MANIFEST_ID_BYTES);
    cli_puts("manifestid");
    cli_delim(":");
    cli_puts(bid);
    cli_delim("\n");
  }
  {
    char secret[RHIZOME_BUNDLE_KEY_STRLEN + 1];
    rhizome_bytes_to_hex_upper(mwritten->cryptoSignSecret, secret, RHIZOME_BUNDLE_KEY_BYTES);
    cli_puts("secret");
    cli_delim(":");
    cli_puts(secret);
    cli_delim("\n");
  }
  cli_puts("filesize");
  cli_delim(":");
  cli_printf("%lld", mwritten->fileLength);
  cli_delim("\n");
  if (mwritten->fileLength != 0) {
    cli_puts("filehash");
    cli_delim(":");
    cli_puts(mwritten->fileHexHash);
    cli_delim("\n");
  }
  const char *name = rhizome_manifest_get(mwritten, "name", NULL, 0);
  if (name) {
    cli_puts("name");
    cli_delim(":");
    cli_puts(name);
    cli_delim("\n");
  }
  rhizome_manifest_free(m);
  if (mout != m)
    rhizome_manifest_free(mout);
  return ret;
}

int app_rhizome_import_bundle(int argc, const char *const *argv, struct command_line_option *o, void *context)
{
  if (debug & DEBUG_VERBOSE) DEBUG_argv("command", argc, argv);
  const char *filepath, *manifestpath;
  cli_arg(argc, argv, o, "filepath", &filepath, NULL, "");
  cli_arg(argc, argv, o, "manifestpath", &manifestpath, NULL, "");
  if (rhizome_opendb() == -1)
    return -1;
  int status=rhizome_import_from_files(manifestpath,filepath);
  return status;
}

int app_rhizome_extract_manifest(int argc, const char *const *argv, struct command_line_option *o, void *context)
{
  if (debug & DEBUG_VERBOSE) DEBUG_argv("command", argc, argv);
  const char *manifestid, *manifestpath;
  if (cli_arg(argc, argv, o, "manifestid", &manifestid, cli_manifestid, NULL)
   || cli_arg(argc, argv, o, "manifestpath", &manifestpath, NULL, NULL) == -1)
    return -1;
  /* Ensure the Rhizome database exists and is open */
  if (create_serval_instance_dir() == -1)
    return -1;
  if (rhizome_opendb() == -1)
    return -1;
  /* Extract the manifest from the database */
  rhizome_manifest *m = NULL;
  int ret = rhizome_retrieve_manifest(manifestid, &m);
  switch (ret) {
    case 0: ret = 1; break;
    case 1: ret = 0;
      if (manifestpath) {
	/* If the manifest has been read in from database, the blob is there,
	   and we can lie and say we are finalised and just want to write it
	   out.  XXX really should have a dirty/clean flag, so that write
	   works is clean but not finalised. */
	m->finalised=1;
	if (rhizome_write_manifest_file(m, manifestpath) == -1)
	  ret = -1;
      }
      break;
    case -1: break;
    default: ret = WHYF("Unsupported return value %d", ret); break;
  }
  if (m)
    rhizome_manifest_free(m);
  return ret;
}

int app_rhizome_extract_file(int argc, const char *const *argv, struct command_line_option *o, void *context)
{
  if (debug & DEBUG_VERBOSE) DEBUG_argv("command", argc, argv);
  const char *fileid, *filepath, *keyhex;
  if (cli_arg(argc, argv, o, "fileid", &fileid, cli_fileid, NULL)
   || cli_arg(argc, argv, o, "filepath", &filepath, NULL, "") == -1)
    return -1;
  cli_arg(argc, argv, o, "key", &keyhex, cli_optional_bundle_crypt_key, "");
  unsigned char key[RHIZOME_CRYPT_KEY_STRLEN + 1];
  if (keyhex[0] && fromhexstr(key, keyhex, RHIZOME_CRYPT_KEY_BYTES) == -1)
    return -1;
  /* Ensure the Rhizome database exists and is open */
  if (create_serval_instance_dir() == -1)
    return -1;
  if (rhizome_opendb() == -1)
    return -1;
  /* Extract the file from the database.
     We don't provide a decryption key here, because we don't know it.
     (We probably should allow the user to provide one).
  */
  int ret = rhizome_retrieve_file(fileid, filepath, keyhex[0] ? key : NULL);
  switch (ret) {
    case 0: ret = 1; break;
    case 1: ret = 0; break;
    case -1: break;
    default: ret = WHYF("Unsupported return value %d", ret); break;
  }
  return ret;
}

int app_rhizome_list(int argc, const char *const *argv, struct command_line_option *o, void *context)
{
  if (debug & DEBUG_VERBOSE) DEBUG_argv("command", argc, argv);
  const char *pin, *service, *sender_sid, *recipient_sid, *offset, *limit;
  cli_arg(argc, argv, o, "pin,pin...", &pin, NULL, "");
  cli_arg(argc, argv, o, "service", &service, NULL, "");
  cli_arg(argc, argv, o, "sender_sid", &sender_sid, cli_optional_sid, "");
  cli_arg(argc, argv, o, "recipient_sid", &recipient_sid, cli_optional_sid, "");
  cli_arg(argc, argv, o, "offset", &offset, cli_uint, "0");
  cli_arg(argc, argv, o, "limit", &limit, cli_uint, "0");
  /* Create the instance directory if it does not yet exist */
  if (create_serval_instance_dir() == -1)
    return -1;
  if (!(keyring = keyring_open_with_pins(pin)))
    return -1;
  if (rhizome_opendb() == -1)
    return -1;
  return rhizome_list_manifests(service, sender_sid, recipient_sid, atoi(offset), atoi(limit));
}

int app_keyring_create(int argc, const char *const *argv, struct command_line_option *o, void *context)
{
  if (debug & DEBUG_VERBOSE) DEBUG_argv("command", argc, argv);
  const char *pin;
  cli_arg(argc, argv, o, "pin,pin...", &pin, NULL, "");
  if (!keyring_open_with_pins(pin))
    return -1;
  return 0;
}

int app_keyring_list(int argc, const char *const *argv, struct command_line_option *o, void *context)
{
  if (debug & DEBUG_VERBOSE) DEBUG_argv("command", argc, argv);
  const char *pin;
  cli_arg(argc, argv, o, "pin,pin...", &pin, NULL, "");
  keyring_file *k = keyring_open_with_pins(pin);
  if (!k)
    return -1;
  int cn, in;
  for (cn = 0; cn < k->context_count; ++cn)
    for (in = 0; in < k->contexts[cn]->identity_count; ++in) {
      const unsigned char *sid = NULL;
      const char *did = NULL;
      const char *name = NULL;
      keyring_identity_extract(k->contexts[cn]->identities[in], &sid, &did, &name);
      if (sid || did) {	 
	  if (sid) cli_printf("%s", alloca_tohex_sid(sid));
	  cli_delim(":");
	  if (did) cli_puts(did);
	  cli_delim(":");
	  if (name) cli_puts(name);
	  cli_delim("\n");
      }
    }
  return 0;
 }

int app_keyring_add(int argc, const char *const *argv, struct command_line_option *o, void *context)
{
  if (debug & DEBUG_VERBOSE) DEBUG_argv("command", argc, argv);
  const char *pin;
  cli_arg(argc, argv, o, "pin", &pin, NULL, "");
  keyring_file *k = keyring_open_with_pins("");
  if (!k)
    return -1;
  const keyring_identity *id = keyring_create_identity(k, k->contexts[0], pin);
  if (id == NULL) {
    keyring_free(k);
    return WHY("Could not create new identity");
  }
  const unsigned char *sid = NULL;
  const char *did = "";
  const char *name = "";
  keyring_identity_extract(id, &sid, &did, &name);
  if (!sid) {
    keyring_free(k);
    return WHY("New identity has no SID");
  }
  if (keyring_commit(k) == -1) {
    keyring_free(k);
    return WHY("Could not write new identity");
  }
  cli_puts("sid");
  cli_delim(":");
  cli_printf("%s", alloca_tohex_sid(sid));
  cli_delim("\n");
  if (did) {
    cli_puts("did");
    cli_delim(":");
    cli_puts(did);
    cli_delim("\n");
  }
  if (name) {
    cli_puts("name");
    cli_delim(":");
    cli_puts(name);
    cli_delim("\n");
  }
  keyring_free(k);
  return 0;
}

int app_keyring_set_did(int argc, const char *const *argv, struct command_line_option *o, void *context)
{
  if (debug & DEBUG_VERBOSE) DEBUG_argv("command", argc, argv);
  const char *sid, *did, *pin, *name;
  cli_arg(argc, argv, o, "sid", &sid, str_is_subscriber_id, "");
  cli_arg(argc, argv, o, "did", &did, cli_optional_did, "");
  cli_arg(argc, argv, o, "name", &name, NULL, "");
  cli_arg(argc, argv, o, "pin", &pin, NULL, "");

  if (strlen(name)>63) return WHY("Name too long (31 char max)");

  if (!(keyring = keyring_open_with_pins(pin)))
    return -1;

  unsigned char packedSid[SID_SIZE];
  stowSid(packedSid,0,(char *)sid);

  int cn=0,in=0,kp=0;
  int r=keyring_find_sid(keyring,&cn,&in,&kp,packedSid);
  if (!r) return WHY("No matching SID");
  if (keyring_set_did(keyring->contexts[cn]->identities[in],
		      (char *)did,(char *)name))
    return WHY("Could not set DID");
  if (keyring_commit(keyring))
    return WHY("Could not write updated keyring record");

  return 0;
}

int app_id_self(int argc, const char *const *argv, struct command_line_option *o, void *context)
{
  if (debug & DEBUG_VERBOSE) DEBUG_argv("command", argc, argv);
  /* List my own identities */
  overlay_mdp_frame a;
  bzero(&a, sizeof(overlay_mdp_frame));
  int result;
  int count=0;

  a.packetTypeAndFlags=MDP_GETADDRS;
  if (!strcasecmp(argv[1],"self"))
    a.addrlist.mode = MDP_ADDRLIST_MODE_SELF; /* get own identities */
  else if (!strcasecmp(argv[1],"allpeers"))
    a.addrlist.mode = MDP_ADDRLIST_MODE_ALL_PEERS; /* get all known peers */
  else if (!strcasecmp(argv[1],"peers"))
    a.addrlist.mode = MDP_ADDRLIST_MODE_ROUTABLE_PEERS; /* get routable (reachable) peers */
  else
    return WHYF("unsupported arg '%s'", argv[1]);
  a.addrlist.first_sid=0;

  do{
    result=overlay_mdp_send(&a,MDP_AWAITREPLY,5000);
    if (result) {
      if (a.packetTypeAndFlags==MDP_ERROR)
	{
	  WHYF("  MDP Server error #%d: '%s'",
	       a.error.error,a.error.message);
	}
      else
	WHYF("Could not get list of local MDP addresses");
      return WHY("Failed to get local address list");
    }
    if ((a.packetTypeAndFlags&MDP_TYPE_MASK)!=MDP_ADDRLIST)
      return WHY("MDP Server returned something other than an address list");
    int i;
    for(i=0;i<a.addrlist.frame_sid_count;i++) {
      count++;
      cli_printf("%s", alloca_tohex_sid(a.addrlist.sids[i])); cli_delim("\n");
    }
    /* get ready to ask for next block of SIDs */
    a.packetTypeAndFlags=MDP_GETADDRS;
    a.addrlist.first_sid=a.addrlist.last_sid+1;
  }while(a.addrlist.frame_sid_count==MDP_MAX_SID_REQUEST);

  return 0;
}

int app_count_peers(int argc, const char *const *argv, struct command_line_option *o, void *context){
  overlay_mdp_frame a;
  bzero(&a, sizeof(overlay_mdp_frame));
  a.packetTypeAndFlags=MDP_GETADDRS;
  a.addrlist.mode = MDP_ADDRLIST_MODE_ROUTABLE_PEERS;
  a.addrlist.first_sid=0x7fffffff;
  if (overlay_mdp_send(&a,MDP_AWAITREPLY,5000)){
    if (a.packetTypeAndFlags==MDP_ERROR)
      return WHYF("  MDP Server error #%d: '%s'",a.error.error,a.error.message);
    return WHYF("Failed to send request");
  }
  cli_printf("%d",a.addrlist.server_sid_count);
  cli_delim("\n");
  return 0;
}

int app_test_rfs(int argc, const char *const *argv, struct command_line_option *o, void *context)
{
  if (debug & DEBUG_VERBOSE) DEBUG_argv("command", argc, argv);
  printf("Testing that RFS coder works properly.\n");
  int i;
  for(i=0;i<65536;i++) {
    unsigned char bytes[8];
    rfs_encode(i, &bytes[0]);
    int zero=0;
    int r=rfs_decode(&bytes[0],&zero);
    if (i != r)
      printf("RFS encoding of %d decodes to %d: %s\n", i, r, alloca_tohex(bytes, sizeof bytes));
  }
  return 0;
}

int app_crypt_test(int argc, const char *const *argv, struct command_line_option *o, void *context)
{
  if (debug & DEBUG_VERBOSE) DEBUG_argv("command", argc, argv);
  unsigned char nonce[crypto_box_curve25519xsalsa20poly1305_NONCEBYTES];
  unsigned char k[crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES];

  unsigned char plain_block[65536];

  urandombytes(nonce,sizeof(nonce));
  urandombytes(k,sizeof(k));

  int len,i;

  for(len=16;len<=65536;len*=2) {
    time_ms_t start = gettime_ms();
    for (i=0;i<1000;i++) {
      bzero(&plain_block[0],crypto_box_curve25519xsalsa20poly1305_ZEROBYTES);
      crypto_box_curve25519xsalsa20poly1305_afternm
	(plain_block,plain_block,len,nonce,k);
    }
    time_ms_t end = gettime_ms();
    printf("%d bytes - 100 tests took %lldms - mean time = %.2fms\n",
	   len, (long long) end - start, (end - start) * 1.0 / i);
  }
  return 0;
}

int app_node_info(int argc, const char *const *argv, struct command_line_option *o, void *context)
{
  if (debug & DEBUG_VERBOSE) DEBUG_argv("command", argc, argv);
  const char *sid;
  cli_arg(argc, argv, o, "sid", &sid, NULL, "");

  overlay_mdp_frame mdp;
  bzero(&mdp,sizeof(mdp));
  int resolveDid=0;

  mdp.packetTypeAndFlags=MDP_NODEINFO;
  if (argc>3) resolveDid=1;
  mdp.nodeinfo.resolve_did=1; // Request resolution of DID and Name by local server if it can.

  /* get SID or SID prefix 
     XXX - Doesn't correctly handle odd-lengthed SID prefixes (ignores last digit).
     The matching code in overlay_route.c also has a similar problem with the last
     digit of an odd-length prefix being ignored. */
  int i;
  mdp.nodeinfo.sid_prefix_length=0;
  for(i = 0; (i != SID_SIZE)&&sid[i<<1]&&sid[(i<<1)+1]; i++) {
    mdp.nodeinfo.sid[mdp.nodeinfo.sid_prefix_length] = hexvalue(sid[i<<1]) << 4;
    mdp.nodeinfo.sid[mdp.nodeinfo.sid_prefix_length++] |= hexvalue(sid[(i<<1)+1]);
  }
  mdp.nodeinfo.sid_prefix_length*=2;

  int result=overlay_mdp_send(&mdp,MDP_AWAITREPLY,5000);
  if (result) {
    if (mdp.packetTypeAndFlags==MDP_ERROR)
      {
	overlay_mdp_client_done();
	return WHYF("  MDP Server error #%d: '%s'",mdp.error.error,mdp.error.message);
      }
    else {
      overlay_mdp_client_done();
      return WHYF("Could not get information about node.");
    }
  }

  if (resolveDid&&(!mdp.nodeinfo.resolve_did)) {
    /* Asked for DID resolution, but did not get it, so do a DNA lookup
       here.  We do this on the client side, so that we don't block the 
       single-threaded server. */
    overlay_mdp_frame mdp_reply;
    int port=32768+(random()&0xffff);
    
    unsigned char srcsid[SID_SIZE];
    if (overlay_mdp_getmyaddr(0,srcsid)) port=0;
    if (overlay_mdp_bind(srcsid,port)) port=0;

    if (port) {    
      time_ms_t now = gettime_ms();
      time_ms_t timeout = now + 3000;
      time_ms_t next_send = now;
      
      while(now < timeout){
	now=gettime_ms();
	
	if (now >= next_send){
	  /* Send a unicast packet to this node, asking for any did */
	  lookup_send_request(srcsid, port, mdp.nodeinfo.sid, "");
	  next_send+=125;
	  continue;
	}
	
	time_ms_t timeout_ms = (next_send>timeout?timeout:next_send) - now;
	if (overlay_mdp_client_poll(timeout_ms)<=0)
	  continue;
	
	int ttl=-1;
	if (overlay_mdp_recv(&mdp_reply, port, &ttl))
	  continue;
	
	if ((mdp_reply.packetTypeAndFlags&MDP_TYPE_MASK)==MDP_ERROR){
	  // TODO log error?
	  continue;
	}
	
	if (mdp_reply.packetTypeAndFlags!=MDP_TX) {
	  WHYF("MDP returned an unexpected message (type=0x%x)",
	       mdp_reply.packetTypeAndFlags);
	  
	  if (mdp_reply.packetTypeAndFlags==MDP_ERROR) 
	    WHYF("MDP message is return/error: %d:%s",
		 mdp_reply.error.error,mdp_reply.error.message);
	  continue;
	}
	
	// we might receive a late response from an ealier request, ignore it
	if (memcmp(mdp_reply.in.src.sid, mdp.nodeinfo.sid, SID_SIZE)){
	  WHYF("Unexpected result from SID %s", alloca_tohex_sid(mdp_reply.in.src.sid));
	  continue;
	}
	
	{
	  char sidhex[SID_STRLEN + 1];
	  char did[DID_MAXSIZE + 1];
	  char name[64];
	  char uri[512];
	  if ( !parseDnaReply((char *)mdp_reply.in.payload, mdp_reply.in.payload_length, sidhex, did, name, uri, NULL)
	    || !str_is_subscriber_id(sidhex)
	    || !str_is_did(did)
	    || !str_is_uri(uri)
	  ) {
	    WHYF("Received malformed DNA reply: %s", 
		 alloca_toprint(160, (const char *)mdp_reply.in.payload, mdp_reply.in.payload_length));
	  } else {
	    /* Got a good DNA reply, copy it into place and stop polling */
	    bcopy(did,mdp.nodeinfo.did,32);
	    bcopy(name,mdp.nodeinfo.name,64);
	    mdp.nodeinfo.resolve_did=1;
	    break;
	  }
	}
      }
    }
  }

  cli_printf("record"); cli_delim(":");
  // TODO remove these two unused output fields
  cli_printf("%d",1); cli_delim(":");
  cli_printf("%d",1); cli_delim(":");
  cli_printf("%s",mdp.nodeinfo.foundP?"found":"noresult"); cli_delim(":");
  cli_printf("%s", alloca_tohex_sid(mdp.nodeinfo.sid)); cli_delim(":");
  cli_printf("%s",mdp.nodeinfo.resolve_did?mdp.nodeinfo.did:"did-not-resolved"); 
  cli_delim(":");
  cli_printf("%s",mdp.nodeinfo.localP?"self":"peer"); cli_delim(":");
  cli_printf("%s",mdp.nodeinfo.neighbourP?"direct":"indirect"); 
  cli_delim(":");
  cli_printf("%d",mdp.nodeinfo.score); cli_delim(":");
  cli_printf("%d",mdp.nodeinfo.interface_number); cli_delim(":");
  cli_printf("%s",mdp.nodeinfo.resolve_did?mdp.nodeinfo.name:"name-not-resolved");
  cli_delim("\n");

  return 0;
}

/* NULL marks ends of command structure.
   "<anystring>" marks an arg that can take any value.
   "[<anystring>]" marks an optional arg that can take any value.
   All args following the first optional arg are optional, whether marked or not.
   Only exactly matching prototypes will be used.
   Together with the description, this makes it easy for us to auto-generate the
   list of valid command line formats for display to the user if they try an
   invalid one.  It also means we can do away with getopt() etc.

   The CLIFLAG_STANDALONE means that they cannot be used with a running servald
   instance, but act as an instance.  In other words, don't call these from the
   serval frontend, e.g, Java application on Android.  There are various reasons,
   such as some will try to fork() and exec() (bad for a Java thread to do), while
   others manipulate files that the running instance may be using.

   Keep this list alphabetically sorted for user convenience.
*/
struct command_line_option command_line_options[]={
  {app_dna_lookup,{"dna","lookup","<did>","[<timeout>]",NULL},0,
   "Lookup the SIP/MDP address of the supplied telephone number (DID)."},
  {commandline_usage,{"help",NULL},0,
   "Display command usage."},
  {app_echo,{"echo","...",NULL},CLIFLAG_STANDALONE,
   "Output the supplied string."},
  {app_server_start,{"start",NULL},CLIFLAG_STANDALONE,
   "Start Serval Mesh node process with instance path taken from SERVALINSTANCE_PATH environment variable."},
  {app_server_start,{"start","in","<instance path>",NULL},CLIFLAG_STANDALONE,
   "Start Serval Mesh node process with given instance path."},
  {app_server_start,{"start","exec","<exec path>",NULL},CLIFLAG_STANDALONE,
   "Start Serval Mesh node process with instance path taken from SERVALINSTANCE_PATH environment variable."},
  {app_server_start,{"start","exec","<exec path>","in","<instance path>",NULL},CLIFLAG_STANDALONE,
   "Start Serval Mesh node process with given instance path."},
  {app_server_start,{"start","foreground",NULL},CLIFLAG_STANDALONE,
   "Start Serval Mesh node process without detatching from foreground."},
  {app_server_start,{"start","foreground","in","<instance path>",NULL},CLIFLAG_STANDALONE,
   "Start Serval Mesh node process with given instance path, without detatching from foreground."},
  {app_server_stop,{"stop",NULL},0,
   "Stop a running Serval Mesh node process with instance path taken from SERVALINSTANCE_PATH environment variable."},
  {app_server_stop,{"stop","in","<instance path>",NULL},0,
   "Stop a running Serval Mesh node process with given instance path."},
  {app_server_status,{"status",NULL},0,
   "Display information about any running Serval Mesh node."},
  {app_mdp_ping,{"mdp","ping","<SID|broadcast>","[<count>]",NULL},CLIFLAG_STANDALONE,
   "Attempts to ping specified node via Mesh Datagram Protocol (MDP)."},
  {app_config_set,{"config","set","<variable>","<value>",NULL},CLIFLAG_STANDALONE,
   "Set specified configuration variable."},
  {app_config_del,{"config","del","<variable>",NULL},CLIFLAG_STANDALONE,
   "Set specified configuration variable."},
  {app_config_get,{"config","get","[<variable>]",NULL},CLIFLAG_STANDALONE,
   "Get specified configuration variable."},
  {app_vomp_console,{"console",NULL},0,
    "Test phone call life-cycle from the console"},
  {app_rhizome_hash_file,{"rhizome","hash","file","<filepath>",NULL},CLIFLAG_STANDALONE,
   "Compute the Rhizome hash of a file"},
  {app_rhizome_add_file,{"rhizome","add","file","<author_sid>","<pin>","<filepath>","[<manifestpath>]","[<bsk>]",NULL},CLIFLAG_STANDALONE,
   "Add a file to Rhizome and optionally write its manifest to the given path"},
  {app_rhizome_import_bundle,{"rhizome","import","bundle","<filepath>","<manifestpath>",NULL},CLIFLAG_STANDALONE,
   "Import a payload/manifest pair into Rhizome"},
  {app_rhizome_list,{"rhizome","list","<pin,pin...>","[<service>]","[<sender_sid>]","[<recipient_sid>]","[<offset>]","[<limit>]",NULL},CLIFLAG_STANDALONE,
   "List all manifests and files in Rhizome"},
  {app_rhizome_extract_manifest,{"rhizome","extract","manifest","<manifestid>","[<manifestpath>]",NULL},CLIFLAG_STANDALONE,
   "Extract a manifest from Rhizome and write it to the given path"},
  {app_rhizome_extract_file,{"rhizome","extract","file","<fileid>","[<filepath>]","[<key>]",NULL},CLIFLAG_STANDALONE,
   "Extract a file from Rhizome and write it to the given path"},
  {app_rhizome_direct_sync,{"rhizome","direct","sync","[peer url]",NULL},
   CLIFLAG_STANDALONE,
   "Synchronise with the specified Rhizome Direct server. Return when done."},
  {app_rhizome_direct_sync,{"rhizome","direct","push","[peer url]",NULL},
   CLIFLAG_STANDALONE,
   "Deliver all new content to the specified Rhizome Direct server. Return when done."},
  {app_rhizome_direct_sync,{"rhizome","direct","pull","[peer url]",NULL},
   CLIFLAG_STANDALONE,
   "Fetch all new content from the specified Rhizome Direct server. Return when done."},
  {app_keyring_create,{"keyring","create",NULL},0,
   "Create a new keyring file."},
  {app_keyring_list,{"keyring","list","[<pin,pin...>]",NULL},CLIFLAG_STANDALONE,
   "List identites in specified key ring that can be accessed using the specified PINs"},
  {app_keyring_add,{"keyring","add","[<pin>]",NULL},CLIFLAG_STANDALONE,
   "Create a new identity in the keyring protected by the provided PIN"},
  {app_keyring_set_did,{"set","did","<sid>","<did>","<name>","[<pin>]",NULL},CLIFLAG_STANDALONE,
   "Set the DID for the specified SID.  Optionally supply PIN to unlock the SID record in the keyring."},
  {app_id_self,{"id","self",NULL},0,
   "Return my own identity(s) as URIs"},
  {app_id_self,{"id","peers",NULL},0,
   "Return identity of known routable peers as URIs"},
  {app_id_self,{"id","allpeers",NULL},0,
   "Return identity of all known peers as URIs"},
  {app_node_info,{"node","info","<sid>","[getdid]",NULL},0,
   "Return information about SID, and optionally ask for DID resolution via network"},
  {app_count_peers,{"peer","count",NULL},0,
    "Return a count of routable peers on the network"},
  {app_test_rfs,{"test","rfs",NULL},0,
   "Test RFS field calculation"},
  {app_monitor_cli,{"monitor",NULL},0,
   "Interactive servald monitor interface."},
  {app_crypt_test,{"crypt","test",NULL},0,
   "Run cryptography speed test"},
#ifdef HAVE_VOIPTEST
  {app_pa_phone,{"phone",NULL},0,
   "Run phone test application"},
#endif
  {NULL,{NULL}}
};
