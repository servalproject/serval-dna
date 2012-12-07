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
#include "conf.h"
#include "rhizome.h"
#include "strbuf.h"
#include "str.h"
#include "mdp_client.h"
#include "cli.h"
#include "overlay_address.h"

extern struct command_line_option command_line_options[];

int commandline_usage(int argc, const char *const *argv, const struct command_line_option *o, void *context){
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
  size_t length = outv_current - outv_buffer;
  outv_current = outv_buffer;
  jbyteArray arr = (*jni_env)->NewByteArray(jni_env, length);
  if (arr == NULL) {
    jni_exception = 1;
    return WHY("Exception thrown from NewByteArray()");
  }
  (*jni_env)->SetByteArrayRegion(jni_env, arr, 0, length, (jbyte*)outv_buffer);
  if ((*jni_env)->ExceptionOccurred(jni_env)) {
    jni_exception = 1;
    return WHY("Exception thrown from SetByteArrayRegion()");
  }
  (*jni_env)->CallBooleanMethod(jni_env, outv_list, listAddMethodId, arr);
  if ((*jni_env)->ExceptionOccurred(jni_env)) {
    jni_exception = 1;
    return WHY("Exception thrown from CallBooleanMethod()");
  }
  (*jni_env)->DeleteLocalRef(jni_env, arr);
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
  
  int result = cli_parse(argc, args, command_line_options);
  if (result != -1) {
    const struct command_line_option *option = &command_line_options[result];
    if (option->flags & CLIFLAG_PERMISSIVE_CONFIG)
      cf_reload_permissive();
    else
      cf_reload();
    result = cli_invoke(option, argc, args, NULL);
  } else {
    cf_reload();
  }

  /* clean up after ourselves */
  overlay_mdp_client_done();
  rhizome_close_db();
  OUT();
  
  if (config.debug.timing)
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

/* Write a buffer of data to output.  If in a JNI call, then this appends the data to the
   current output field, including any embedded nul characters.  Returns a non-negative integer on
   success, EOF on error.
 */
int cli_write(const unsigned char *buf, size_t len)
{
#ifdef HAVE_JNI_H
    if (jni_env) {
      size_t avail = outv_limit - outv_current;
      if (avail < len) {
	memcpy(outv_current, buf, avail);
	outv_current = outv_limit;
	if (outv_growbuf(len) == -1)
	  return EOF;
	len -= avail;
	buf += avail;
      }
      memcpy(outv_current, buf, len);
      outv_current += len;
      return 0;
    }
    else
#endif
      return fwrite(buf, len, 1, stdout);
}

/* Write a null-terminated string to output.  If in a JNI call, then this appends the string to the
   current output field.  The terminating null is not included.  Returns a non-negative integer on
   success, EOF on error.
 */
int cli_puts(const char *str)
{
#ifdef HAVE_JNI_H
    if (jni_env)
      return cli_write((const unsigned char *) str, strlen(str));
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

int app_echo(int argc, const char *const *argv, const struct command_line_option *o, void *context)
{
  if (config.debug.verbose) DEBUG_argv("command", argc, argv);
  int i = 1;
  int escapes = 0;
  if (i < argc && strcmp(argv[i], "-e") == 0) {
    escapes = 1;
    ++i;
  }
  for (; i < argc; ++i) {
    if (config.debug.verbose)
      DEBUGF("echo:argv[%d]=\"%s\"", i, argv[i]);
    if (escapes) {
      unsigned char buf[strlen(argv[i])];
      size_t len = str_fromprint(buf, argv[i]);
      cli_write(buf, len);
    } else
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
    if (!is_sid_any(config.directory.service.binary)) {
      memcpy(mdp.out.dst.sid, config.directory.service.binary, SID_SIZE);
      mdp.packetTypeAndFlags=MDP_TX;
      overlay_mdp_send(&mdp,0,0);
    }
  }
}

int app_dna_lookup(int argc, const char *const *argv, const struct command_line_option *o, void *context)
{
  if (config.debug.verbose) DEBUG_argv("command", argc, argv);
  
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

int app_server_start(int argc, const char *const *argv, const struct command_line_option *o, void *context)
{
  if (config.debug.verbose) DEBUG_argv("command", argc, argv);
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
  if (config.interfaces.ac == 0)
    WARN("No network interfaces configured (empty 'interfaces' config option)");
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
    overlayMode = 1;
    if (foregroundP)
      return server(NULL);
    const char *dir = getenv("SERVALD_SERVER_CHDIR");
    if (!dir)
      dir = config.server.chdir;
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
	    
	    //TODO close config
	    
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

int app_server_stop(int argc, const char *const *argv, const struct command_line_option *o, void *context)
{
  if (config.debug.verbose) DEBUG_argv("command", argc, argv);
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

int app_server_status(int argc, const char *const *argv, const struct command_line_option *o, void *context)
{
  if (config.debug.verbose) DEBUG_argv("command", argc, argv);
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

int app_mdp_ping(int argc, const char *const *argv, const struct command_line_option *o, void *context)
{
  if (config.debug.verbose) DEBUG_argv("command", argc, argv);
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
    bcopy(ping_sid,mdp.out.dst.sid,SID_SIZE);
    mdp.out.queue=OQ_MESH_MANAGEMENT;
    /* Set port to well known echo port */
    mdp.out.dst.port=MDP_PORT_ECHO;
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
	      int hop_count = 64 - mdp.in.ttl;
	      time_ms_t delay = gettime_ms() - *txtime;
	      printf("%s: seq=%d time=%lldms hops=%d %s%s\n",
		     alloca_tohex_sid(mdp.in.src.sid),
		     (*rxseq)-firstSeq+1,
		     delay,
		     hop_count,
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

int app_config_schema(int argc, const char *const *argv, const struct command_line_option *o, void *context)
{
  if (config.debug.verbose) DEBUG_argv("command", argc, argv);
  if (create_serval_instance_dir() == -1)
    return -1;
  struct cf_om_node *root = NULL;
  if (cf_sch_config_main(&root) == -1)
    return -1;
  struct cf_om_iterator it;
  for (cf_om_iter_start(&it, root); it.node; cf_om_iter_next(&it))
    if (it.node->text || it.node->nodc == 0) {
      cli_puts(it.node->fullkey);
      cli_delim("=");
      if (it.node->text)
	cli_puts(it.node->text);
      cli_delim("\n");
    }
  return 0;
}

int app_config_set(int argc, const char *const *argv, const struct command_line_option *o, void *context)
{
  if (config.debug.verbose) DEBUG_argv("command", argc, argv);
  if (create_serval_instance_dir() == -1)
    return -1;
  // <kludge>
  // This fixes a subtle bug in when upgrading the Batphone app: the servald.conf file does
  // not get upgraded.  The bug goes like this:
  //  1. new Batphone APK is installed, but prior servald.conf is not overwritten because it
  //     comes in serval.zip;
  //  2. new Batphone is started, which calls JNI "stop" command, which reads the old servald.conf
  //     into memory buffer;
  //  3. new Batphone unpacks serval.zip, overwriting servald.conf with new version;
  //  4. new Batphone calls JNI "config set rhizome.enable 1", which sets the "rhizome.enable"
  //     config option in the existing memory buffer and overwrites servald.conf;
  // Bingo, the old version of servald.conf is what remains.  This kludge intervenes in step 4, by
  // reading the new servald.conf into the memory buffer before applying the "rhizome.enable" set
  // value and overwriting.
  if (cf_om_reload() == -1)
    return -1;
  // </kludge>
  const char *var[argc - 1];
  const char *val[argc - 1];
  int nvar = 0;
  int i;
  for (i = 1; i < argc; ++i) {
    int iv;
    if (strcmp(argv[i], "set") == 0) {
      if (i + 2 > argc)
	return WHYF("malformed command at argv[%d]: 'set' not followed by two arguments", i);
      var[nvar] = argv[iv = ++i];
      val[nvar] = argv[++i];
    } else if (strcmp(argv[i], "del") == 0) {
      if (i + 1 > argc)
	return WHYF("malformed command at argv[%d]: 'del' not followed by one argument", i);
      var[nvar] = argv[iv = ++i];
      val[nvar] = NULL;
    } else
      return WHYF("malformed command at argv[%d]: unsupported action '%s'", i, argv[i]);
    if (!is_configvarname(var[nvar]))
      return WHYF("malformed command at argv[%d]: '%s' is not a valid config option name", iv, var[nvar]);
    ++nvar;
  }
  for (i = 0; i < nvar; ++i)
    if (cf_om_set(&cf_om_root, var[i], val[i]) == -1)
      return -1;
  if (cf_om_save() == -1)
    return -1;
  if (cf_reload() == -1) // logs an error if the new config is bad
    return 2;
  return 0;
}

int app_config_get(int argc, const char *const *argv, const struct command_line_option *o, void *context)
{
  if (config.debug.verbose) DEBUG_argv("command", argc, argv);
  const char *var;
  if (cli_arg(argc, argv, o, "variable", &var, is_configvarpattern, NULL) == -1)
    return -1;
  if (create_serval_instance_dir() == -1)
    return -1;
  if (cf_om_reload() == -1)
    return -1;
  if (var && is_configvarname(var)) {
    const char *value = cf_om_get(cf_om_root, var);
    if (value) {
      cli_puts(var);
      cli_delim("=");
      cli_puts(value);
      cli_delim("\n");
    }
  } else {
    struct cf_om_iterator it;
    for (cf_om_iter_start(&it, cf_om_root); it.node; cf_om_iter_next(&it)) {
      if (var && cf_om_match(var, it.node) <= 0)
	continue;
      if (it.node->text) {
	cli_puts(it.node->fullkey);
	cli_delim("=");
	cli_puts(it.node->text);
	cli_delim("\n");
      }
    }
  }
  return 0;
}

int app_rhizome_hash_file(int argc, const char *const *argv, const struct command_line_option *o, void *context)
{
  if (config.debug.verbose) DEBUG_argv("command", argc, argv);
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

int app_rhizome_add_file(int argc, const char *const *argv, const struct command_line_option *o, void *context)
{
  if (config.debug.verbose) DEBUG_argv("command", argc, argv);
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
    if (config.debug.rhizome) DEBUGF("reading manifest from %s", manifestpath);
    /* Don't verify the manifest, because it will fail if it is incomplete.
       This is okay, because we fill in any missing bits and sanity check before
       trying to write it out. */
    if (rhizome_read_manifest_file(m, manifestpath, 0) == -1) {
      rhizome_manifest_free(m);
      return WHY("Manifest file could not be loaded -- not added to rhizome");
    }
  } else {
    if (config.debug.rhizome) DEBUGF("manifest file %s does not exist -- creating new manifest", manifestpath);
  }
  /* Fill in a few missing manifest fields, to make it easier to use when adding new files:
      - the default service is FILE
      - use the current time for "date"
      - if service is file, then use the payload file's basename for "name"
  */
  const char *service = rhizome_manifest_get(m, "service", NULL, 0);
  if (service == NULL) {
    rhizome_manifest_set(m, "service", (service = RHIZOME_SERVICE_FILE));
    if (config.debug.rhizome) DEBUGF("missing 'service', set default service=%s", service);
  } else {
    if (config.debug.rhizome) DEBUGF("manifest contains service=%s", service);
  }
  if (rhizome_manifest_get(m, "date", NULL, 0) == NULL) {
    rhizome_manifest_set_ll(m, "date", (long long) gettime_ms());
    if (config.debug.rhizome) DEBUGF("missing 'date', set default date=%s", rhizome_manifest_get(m, "date", NULL, 0));
  }
  if (strcasecmp(RHIZOME_SERVICE_FILE, service) == 0) {
    const char *name = rhizome_manifest_get(m, "name", NULL, 0);
    if (name == NULL) {
      name = strrchr(filepath, '/');
      name = name ? name + 1 : filepath;
      rhizome_manifest_set(m, "name", name);
      if (config.debug.rhizome) DEBUGF("missing 'name', set default name=\"%s\"", name);
    } else {
      if (config.debug.rhizome) DEBUGF("manifest contains name=\"%s\"", name);
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
  if (authorSidHex[0]) {
    if (config.debug.rhizome) DEBUGF("author=%s", authorSidHex);
    memcpy(m->author, authorSid, SID_SIZE);
  }
  const char *id = rhizome_manifest_get(m, "id", NULL, 0);
  if (id == NULL) {
    if (config.debug.rhizome) DEBUG("creating new bundle");
    if (rhizome_manifest_bind_id(m) == -1) {
      rhizome_manifest_free(m);
      return WHY("Could not bind manifest to an ID");
    }
  } else {
    if (config.debug.rhizome) DEBUGF("modifying existing bundle bid=%s", id);
    // Modifying an existing bundle.  If an author SID is supplied, we must ensure that it is valid,
    // ie, that identity has permission to alter the bundle.  If no author SID is supplied but a BSK
    // is supplied, then use that to alter the bundle.  Otherwise, search the keyring for an
    // identity with permission to alter the bundle.
    if (!is_sid_any(m->author)) {
      // Check that the given author has permission to alter the bundle, and extract the secret
      // bundle key if so.
      int result = rhizome_extract_privatekey(m);
      switch (result) {
      case -1:
	rhizome_manifest_free(m);
	return WHY("error in rhizome_extract_privatekey()");
      case 0:
	break;
      case 1:
	if (bskhex[0])
	  break;
	rhizome_manifest_free(m);
	return WHY("Manifest does not have BK field");
      case 2:
	rhizome_manifest_free(m);
	return WHY("Author unknown");
      case 3:
	rhizome_manifest_free(m);
	return WHY("Author does not have a Rhizome Secret");
      case 4:
	rhizome_manifest_free(m);
	return WHY("Author does not have permission to modify manifest");
      default:
	rhizome_manifest_free(m);
	return WHYF("Unknown result from rhizome_extract_privatekey(): %d", result);
      }
    }
    if (bskhex[0]) {
      if (config.debug.rhizome) DEBUGF("bskhex=%s", bskhex);
      if (m->haveSecret) {
	// If a bundle secret key was supplied that does not match the secret key derived from the
	// author, then warn but carry on using the author's.
	if (memcmp(bsk, m->cryptoSignSecret, RHIZOME_BUNDLE_KEY_BYTES) != 0)
	  WARNF("Supplied bundle secret key is invalid -- ignoring");
      } else {
	// The caller provided the bundle secret key, so ensure that it corresponds to the bundle's
	// public key (its bundle ID), otherwise it won't work.
	memcpy(m->cryptoSignSecret, bsk, RHIZOME_BUNDLE_KEY_BYTES);
	if (rhizome_verify_bundle_privatekey(m,m->cryptoSignSecret,
					     m->cryptoSignPublic) == -1) {
	  rhizome_manifest_free(m);
	  return WHY("Incorrect BID secret key.");
	}
      }
    }
    // If we still don't know the bundle secret or the author, then search for an author.
    if (!m->haveSecret && is_sid_any(m->author)) {
      if (config.debug.rhizome) DEBUG("bundle author not specified, searching keyring");
      int result = rhizome_find_bundle_author(m);
      if (result != 0) {
	rhizome_manifest_free(m);
	switch (result) {
	case -1:
	  return WHY("error in rhizome_find_bundle_author()");
	case 4:
	  return WHY("Manifest does not have BK field");
	case 1:
	  return WHY("No author found");
	default:
	  return WHYF("Unknown result from rhizome_find_bundle_author(): %d", result);
	}
      }
    }
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
  int ret=0;
  rhizome_manifest *mout = NULL;
  if (rhizome_manifest_check_duplicate(m, &mout) == 2) {
    /* duplicate found -- verify it so that we can write it out later */
    rhizome_manifest_verify(mout);
    ret=2;
  } else {
    /* not duplicate, so finalise and add to database */
    if (rhizome_manifest_finalise(m)) {
      rhizome_manifest_free(m);
      return WHY("Could not finalise manifest");
    }
    if (rhizome_add_manifest(m, 255 /* TTL */)) {
      rhizome_manifest_free(m);
      return WHY("Manifest not added to Rhizome database");
    }
  }

  /* If successfully added, overwrite the manifest file so that the Java component that is
     invoking this command can read it to obtain feedback on the result. */
  rhizome_manifest *mwritten = mout ? mout : m;
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

int app_rhizome_import_bundle(int argc, const char *const *argv, const struct command_line_option *o, void *context)
{
  if (config.debug.verbose) DEBUG_argv("command", argc, argv);
  const char *filepath, *manifestpath;
  cli_arg(argc, argv, o, "filepath", &filepath, NULL, "");
  cli_arg(argc, argv, o, "manifestpath", &manifestpath, NULL, "");
  if (rhizome_opendb() == -1)
    return -1;
  int status=rhizome_import_from_files(manifestpath,filepath);
  return status;
}

int app_rhizome_extract_manifest(int argc, const char *const *argv, const struct command_line_option *o, void *context)
{
  if (config.debug.verbose) DEBUG_argv("command", argc, argv);
  const char *pins, *manifestid, *manifestpath;
  cli_arg(argc, argv, o, "pin,pin...", &pins, NULL, "");
  if (cli_arg(argc, argv, o, "manifestid", &manifestid, cli_manifestid, NULL)
   || cli_arg(argc, argv, o, "manifestpath", &manifestpath, NULL, NULL) == -1)
    return -1;
  /* Ensure the Rhizome database exists and is open */
  if (create_serval_instance_dir() == -1)
    return -1;
  if (!(keyring = keyring_open_with_pins(pins)))
    return -1;
  if (rhizome_opendb() == -1)
    return -1;
  /* Extract the manifest from the database */
  rhizome_manifest *m = NULL;
  int ret = rhizome_retrieve_manifest(manifestid, &m);
  switch (ret) {
    case 0: ret = 1; break;
    case 1: ret = 0;
      if (manifestpath && strcmp(manifestpath, "-") == 0) {
	cli_puts("manifest");
	cli_delim(":");
	cli_write(m->manifestdata, m->manifest_all_bytes);
	cli_delim("\n");
      } else if (manifestpath) {
	/* If the manifest has been read in from database, the blob is there,
	   and we can lie and say we are finalised and just want to write it
	   out.  TODO: really should have a dirty/clean flag, so that write
	   works if clean but not finalised. */
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

int app_rhizome_extract_file(int argc, const char *const *argv, const struct command_line_option *o, void *context)
{
  if (config.debug.verbose) DEBUG_argv("command", argc, argv);
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

int app_rhizome_list(int argc, const char *const *argv, const struct command_line_option *o, void *context)
{
  if (config.debug.verbose) DEBUG_argv("command", argc, argv);
  const char *pins, *service, *sender_sid, *recipient_sid, *offset, *limit;
  cli_arg(argc, argv, o, "pin,pin...", &pins, NULL, "");
  cli_arg(argc, argv, o, "service", &service, NULL, "");
  cli_arg(argc, argv, o, "sender_sid", &sender_sid, cli_optional_sid, "");
  cli_arg(argc, argv, o, "recipient_sid", &recipient_sid, cli_optional_sid, "");
  cli_arg(argc, argv, o, "offset", &offset, cli_uint, "0");
  cli_arg(argc, argv, o, "limit", &limit, cli_uint, "0");
  /* Create the instance directory if it does not yet exist */
  if (create_serval_instance_dir() == -1)
    return -1;
  if (!(keyring = keyring_open_with_pins(pins)))
    return -1;
  if (rhizome_opendb() == -1)
    return -1;
  return rhizome_list_manifests(service, sender_sid, recipient_sid, atoi(offset), atoi(limit));
}

int app_keyring_create(int argc, const char *const *argv, const struct command_line_option *o, void *context)
{
  if (config.debug.verbose) DEBUG_argv("command", argc, argv);
  const char *pin;
  cli_arg(argc, argv, o, "pin,pin...", &pin, NULL, "");
  if (!keyring_open_with_pins(pin))
    return -1;
  return 0;
}

int app_keyring_list(int argc, const char *const *argv, const struct command_line_option *o, void *context)
{
  if (config.debug.verbose) DEBUG_argv("command", argc, argv);
  const char *pins;
  cli_arg(argc, argv, o, "pin,pin...", &pins, NULL, "");
  keyring_file *k = keyring_open_with_pins(pins);
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

int app_keyring_add(int argc, const char *const *argv, const struct command_line_option *o, void *context)
{
  if (config.debug.verbose) DEBUG_argv("command", argc, argv);
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

int app_keyring_set_did(int argc, const char *const *argv, const struct command_line_option *o, void *context)
{
  if (config.debug.verbose) DEBUG_argv("command", argc, argv);
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

int app_id_self(int argc, const char *const *argv, const struct command_line_option *o, void *context)
{
  if (config.debug.verbose) DEBUG_argv("command", argc, argv);
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

int app_count_peers(int argc, const char *const *argv, const struct command_line_option *o, void *context)
{
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

int app_crypt_test(int argc, const char *const *argv, const struct command_line_option *o, void *context)
{
  if (config.debug.verbose) DEBUG_argv("command", argc, argv);
  unsigned char nonce[crypto_box_curve25519xsalsa20poly1305_NONCEBYTES];
  unsigned char k[crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES];

  unsigned char plain_block[65536];

  urandombytes(nonce,sizeof(nonce));
  urandombytes(k,sizeof(k));

  int len,i;

  printf("Benchmarking CryptoBox Auth-Cryption:\n");
  int count=1024;
  for(len=16;len<=16384;len*=2) {
    time_ms_t start = gettime_ms();
    for (i=0;i<count;i++) {
      bzero(&plain_block[0],crypto_box_curve25519xsalsa20poly1305_ZEROBYTES);
      crypto_box_curve25519xsalsa20poly1305_afternm
	(plain_block,plain_block,len,nonce,k);
    }
    time_ms_t end = gettime_ms();
    double each=(end - start) * 1.0 / i;
    printf("%d bytes - %d tests took %lldms - mean time = %.2fms\n",
	   len, i, (long long) end - start, each);
    /* Auto-reduce number of repeats so that it doesn't take too long on the phone */
    if (each>1.00) count/=2;
  }


  printf("Benchmarking CryptoSign signature verification:\n");
  {

    unsigned char sign_pk[crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES];
    unsigned char sign_sk[crypto_sign_edwards25519sha512batch_SECRETKEYBYTES];
    if (crypto_sign_edwards25519sha512batch_keypair(sign_pk,sign_sk))
      { fprintf(stderr,"crypto_sign_curve25519xsalsa20poly1305_keypair() failed.\n");
	exit(-1); }

    unsigned char plainTextIn[1024];
    unsigned char cipherText[1024];
    unsigned char plainTextOut[1024];
    unsigned long long cipherLen=0;
    unsigned long long plainLenOut;
    bzero(plainTextIn,1024);
    bzero(cipherText,1024);
    snprintf((char *)&plainTextIn[0],1024,"%s","No casaba melons allowed in the lab.");
    int plainLenIn=64;

    time_ms_t start = gettime_ms();
    for(i=0;i<10;i++) {
    int r=crypto_sign_edwards25519sha512batch(cipherText,&cipherLen,
					      plainTextIn,plainLenIn,
					      sign_sk);
    if (r) { fprintf(stderr,"crypto_sign_edwards25519sha512batch() failed.\n");
      exit(-1); }
    }

    time_ms_t end=gettime_ms();
    printf("mean signature generation time = %.2fms\n",
	   (end-start)*1.0/i);
    start = gettime_ms();

    for(i=0;i<10;i++) {
      bzero(&plainTextOut,1024); plainLenOut=0;
      int r=crypto_sign_edwards25519sha512batch_open(plainTextOut,&plainLenOut,
						 &cipherText[0],cipherLen,
						 sign_pk);
      if (r) { 
	fprintf(stderr,"crypto_sign_edwards25519sha512batch_open() failed (r=%d, i=%d).\n",
		r,i);
	exit(-1);
      }
    }
    end = gettime_ms();
    printf("mean signature verification time = %.2fms\n",
	   (end-start)*1.0/i);
  }

  /* We can't do public signing with a crypto_box key, but we should be able to
     do shared-secret generation using crypto_sign keys. */
  {
    printf("Testing supercop-20120525 Ed25519 CryptoSign implementation:\n");

    unsigned char sign1_pk[crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES];
    unsigned char sign1_sk[crypto_sign_edwards25519sha512batch_SECRETKEYBYTES];
    if (crypto_sign_edwards25519sha512batch_keypair(sign1_pk,sign1_sk))
      { fprintf(stderr,"crypto_sign_edwards25519sha512batch_keypair() failed.\n");
	exit(-1); }

    /* Try calculating public key from secret key */
    unsigned char pk[crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES];

    /* New Ed25519 implementation has public key as 2nd half of private key. */
    bcopy(&sign1_sk[32],pk,32);

    if (memcmp(pk, sign1_pk, crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES)) {
      fprintf(stderr,"Could not calculate public key from private key.\n");
      dump("calculated",&pk,sizeof(pk));
      dump("original",&sign1_pk,sizeof(sign1_pk));
      //      exit(-1);
    } else printf("Can calculate public key from private key.\n");

    /* Now use a pre-tested keypair and make sure that we can sign and verify with
       it, and that the signatures are as expected. */
    
    unsigned char key[64]={
      0xf6,0x70,0x6b,0x8a,0x4e,0x1e,0x4b,0x01,
      0x11,0x56,0x85,0xac,0x63,0x46,0x67,0x5f,
      0xc1,0x44,0xcf,0xdf,0x98,0x5c,0x2b,0x8b,
      0x18,0xff,0x70,0x9c,0x12,0x71,0x48,0xb9,

      0x32,0x2a,0x88,0xba,0x9c,0xdd,0xed,0x35,
      0x8f,0x01,0x18,0xf7,0x60,0x1b,0xfb,0x80,
      0xaf,0xce,0x74,0xe0,0x85,0x39,0xac,0x13,
      0x15,0xf6,0x79,0xaa,0x68,0xef,0x5d,0xc6};

    unsigned char plainTextIn[1024];
    unsigned char plainTextOut[1024];
    unsigned char cipherText[1024];
    unsigned long long cipherLen=0;
    unsigned long long plainLenOut;
    bzero(plainTextIn,1024);
    bzero(cipherText,1024);
    snprintf((char *)&plainTextIn[0],1024,"%s","No casaba melons allowed in the lab.");
    int plainLenIn=64;

    int r=crypto_sign_edwards25519sha512batch(cipherText,&cipherLen,
					  plainTextIn,plainLenIn,
					  key);
    if (r) { fprintf(stderr,"crypto_sign_edwards25519sha512batch() failed.\n");
      exit(-1); }
  
    dump("signature",cipherText,cipherLen);
   
    unsigned char casabamelons[128]={
      0xa4,0xea,0xd0,0x7f,0x11,0x65,0x28,0x3f,0x90,0x45,0x87,0xbf,0xe5,0xb9,0x15,0x2a,0x9a,0x2d,0x99,0x35,0x0d,0x0e,0x7b,0xb0,0xcd,0x15,0x2e,0xe8,0xeb,0xb3,0xc2,0xb1,0x13,0x8e,0xe3,0x82,0x55,0x6c,0x6e,0x34,0x44,0xe4,0xbc,0xa3,0xd5,0xe0,0x7a,0x6a,0x67,0x61,0xda,0x79,0x67,0xb6,0x1c,0x2e,0x48,0xc7,0x28,0x5b,0xd8,0xd0,0x54,0x0c,0x4e,0x6f,0x20,0x63,0x61,0x73,0x61,0x62,0x61,0x20,0x6d,0x65,0x6c,0x6f,0x6e,0x73,0x20,0x61,0x6c,0x6c,0x6f,0x77,0x65,0x64,0x20,0x69,0x6e,0x20,0x74,0x68,0x65,0x20,0x6c,0x61,0x62,0x2e,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
    };
    
    if (cipherLen!=128||memcmp(casabamelons, cipherText, 128)) {
      fprintf(stderr,"Computed signature for stored key+message does not match expected value.\n");
      dump("expected signature",casabamelons,sizeof(casabamelons));
      //      exit(-1);
    }
  
    bzero(&plainTextOut,1024); plainLenOut=0;
    r=crypto_sign_edwards25519sha512batch_open(plainTextOut,&plainLenOut,
					       &casabamelons[0],128,
					       /* the public key, which is the 2nd
						  half of the secret key. */
					       &key[32]);
    if (r) {
      fprintf(stderr,"Cannot open rearranged ref/ version of signature.\n");      
    } else 
      printf("Signature open fine.\n");

  }
  
  return 0;
}

int app_node_info(int argc, const char *const *argv, const struct command_line_option *o, void *context)
{
  if (config.debug.verbose) DEBUG_argv("command", argc, argv);
  const char *sid;
  cli_arg(argc, argv, o, "sid", &sid, NULL, "");

  overlay_mdp_frame mdp;
  bzero(&mdp,sizeof(mdp));

  mdp.packetTypeAndFlags=MDP_NODEINFO;
  
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

  cli_printf("record"); cli_delim(":");
  cli_printf("%s",mdp.nodeinfo.foundP?"found":"noresult"); cli_delim(":");
  cli_printf("%s", alloca_tohex_sid(mdp.nodeinfo.sid)); cli_delim(":");
  cli_printf("%s",mdp.nodeinfo.localP?"self":"peer"); cli_delim(":");
  cli_printf("%s",mdp.nodeinfo.neighbourP?"direct":"indirect"); cli_delim(":");
  cli_printf("%d",mdp.nodeinfo.score); cli_delim(":");
  cli_printf("%d",mdp.nodeinfo.interface_number); cli_delim("\n");

  return 0;
}

int app_route_print(int argc, const char *const *argv, const struct command_line_option *o, void *context)
{
  overlay_mdp_frame mdp;
  bzero(&mdp,sizeof(mdp));
  
  mdp.packetTypeAndFlags=MDP_ROUTING_TABLE;
  overlay_mdp_send(&mdp,0,0);
  while(overlay_mdp_client_poll(200)){
    overlay_mdp_frame rx;
    int ttl;
    if (overlay_mdp_recv(&rx, 0, &ttl))
      continue;
    
    int ofs=0;
    while(ofs + sizeof(struct overlay_route_record) <= rx.out.payload_length){
      struct overlay_route_record *p=(struct overlay_route_record *)&rx.out.payload[ofs];
      ofs+=sizeof(struct overlay_route_record);
      
      cli_printf(alloca_tohex_sid(p->sid));
      cli_delim(":");
      
      if (p->reachable==REACHABLE_NONE)
	cli_printf("NONE");
      if (p->reachable & REACHABLE_SELF)
	cli_printf("SELF ");
      if (p->reachable & REACHABLE_ASSUMED)
	cli_printf("ASSUMED ");
      if (p->reachable & REACHABLE_BROADCAST)
	cli_printf("BROADCAST ");
      if (p->reachable & REACHABLE_UNICAST)
	cli_printf("UNICAST ");
      if (p->reachable & REACHABLE_INDIRECT)
	cli_printf("INDIRECT ");
      
      cli_delim(":");
      cli_printf(alloca_tohex_sid(p->neighbour));
      cli_delim("\n");
    }
  }
  return 0;
}

int app_reverse_lookup(int argc, const char *const *argv, const struct command_line_option *o, void *context)
{
  const char *sid, *delay;
  
  if (cli_arg(argc, argv, o, "sid", &sid, str_is_subscriber_id, "") == -1)
    return -1;
  if (cli_arg(argc, argv, o, "timeout", &delay, NULL, "3000") == -1)
    return -1;
  
  
  int port=32768+(random()&0xffff);
  
  unsigned char srcsid[SID_SIZE];
  unsigned char dstsid[SID_SIZE];
  
  stowSid(dstsid,0,(char *)sid);
  
  if (overlay_mdp_getmyaddr(0,srcsid))
    return WHY("Unable to get my address");
  if (overlay_mdp_bind(srcsid,port))
    return WHY("Unable to bind port");

  time_ms_t now = gettime_ms();
  time_ms_t timeout = now + atoi(delay);
  time_ms_t next_send = now;
  overlay_mdp_frame mdp_reply;
  
  while(now < timeout){
    now=gettime_ms();
    
    if (now >= next_send){
      /* Send a unicast packet to this node, asking for any did */
      lookup_send_request(srcsid, port, dstsid, "");
      next_send+=125;
      continue;
    }
    
    time_ms_t poll_timeout = (next_send>timeout?timeout:next_send) - now;
    if (overlay_mdp_client_poll(poll_timeout)<=0)
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
    
    // we might receive a late response from an ealier request on the same socket, ignore it
    if (memcmp(mdp_reply.in.src.sid, dstsid, SID_SIZE)){
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
	continue;
      }
      
      /* Got a good DNA reply, copy it into place and stop polling */
      cli_puts("did");
      cli_delim(":");
      cli_puts(did);
      cli_delim("\n");
      cli_puts("name");
      cli_delim(":");
      cli_puts(name);
      cli_delim("\n");
      break;
    }
  }
  return 0;
}

int app_network_scan(int argc, const char *const *argv, const struct command_line_option *o, void *context)
{
  overlay_mdp_frame mdp;
  bzero(&mdp,sizeof(mdp));
  
  mdp.packetTypeAndFlags=MDP_SCAN;
  
  struct overlay_mdp_scan *scan = (struct overlay_mdp_scan *)&mdp.raw;
  const char *address;
  if (cli_arg(argc, argv, o, "address", &address, NULL, NULL) == -1)
    return -1;
  
  if (address){
    DEBUGF("Parsing arg %s", address);
    if (!inet_aton(address, &scan->addr))
      return WHY("Unable to parse the address");
  }else
    DEBUGF("Scanning local networks");
  
  overlay_mdp_send(&mdp,MDP_AWAITREPLY,5000);
  if (mdp.packetTypeAndFlags!=MDP_ERROR)
    return -1;
  cli_puts(mdp.error.message);
  cli_delim("\n");
  return mdp.error.error;
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
  {app_server_stop,{"stop",NULL},CLIFLAG_PERMISSIVE_CONFIG,
   "Stop a running Serval Mesh node process with instance path taken from SERVALINSTANCE_PATH environment variable."},
  {app_server_stop,{"stop","in","<instance path>",NULL},CLIFLAG_PERMISSIVE_CONFIG,
   "Stop a running Serval Mesh node process with given instance path."},
  {app_server_status,{"status",NULL},0,
   "Display information about any running Serval Mesh node."},
  {app_mdp_ping,{"mdp","ping","<SID|broadcast>","[<count>]",NULL},CLIFLAG_STANDALONE,
   "Attempts to ping specified node via Mesh Datagram Protocol (MDP)."},
  {app_config_schema,{"config","schema",NULL},CLIFLAG_STANDALONE|CLIFLAG_PERMISSIVE_CONFIG,
   "Dump configuration schema."},
  {app_config_set,{"config","set","<variable>","<value>","...",NULL},CLIFLAG_STANDALONE|CLIFLAG_PERMISSIVE_CONFIG,
   "Set and del specified configuration variables."},
  {app_config_set,{"config","del","<variable>","...",NULL},CLIFLAG_STANDALONE|CLIFLAG_PERMISSIVE_CONFIG,
   "Del and set specified configuration variables."},
  {app_config_get,{"config","get","[<variable>]",NULL},CLIFLAG_STANDALONE|CLIFLAG_PERMISSIVE_CONFIG,
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
  {app_rhizome_extract_manifest,{"rhizome","extract","manifest","<manifestid>","[<manifestpath>]","[<pin,pin...>]",NULL},CLIFLAG_STANDALONE,
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
  {app_rhizome_direct_async,{"rhizome","direct","async","[<message bytes>]","[<max messages>]","[<token>]",NULL},
   CLIFLAG_STANDALONE,
   "Prepare a batch of messages that communicate new content added to a rhizome store in a bandwidth efficient manner."},
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
  {app_route_print, {"route","print",NULL},0,
  "Print the routing table"},
  {app_network_scan, {"scan","[<address>]",NULL},0,
    "Scan the network for serval peers. If no argument is supplied, all local addresses will be scanned."},
  {app_node_info,{"node","info","<sid>",NULL},0,
   "Return routing information about a SID"},
  {app_count_peers,{"peer","count",NULL},0,
    "Return a count of routable peers on the network"},
  {app_reverse_lookup, {"reverse", "lookup", "<sid>", "[<timeout>]", NULL}, 0,
    "Lookup the phone number and name of a given subscriber"},
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
