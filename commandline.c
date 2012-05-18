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

#define _GNU_SOURCE // For asprintf()
#include <sys/time.h>
#include <sys/wait.h>
#include <math.h>
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <time.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#ifdef HAVE_JNI_H
#include <jni.h>
#endif
#include "serval.h"
#include "rhizome.h"

int cli_usage() {
  fprintf(stderr,"\nServal Mesh version <version>.\n");
  fprintf(stderr,"Usage:\n");
  int i,j;
  for(i=0;command_line_options[i].function;i++)
    {
      for(j=0;command_line_options[i].words[j];j++)
	fprintf(stderr," %s",command_line_options[i].words[j]);
      fprintf(stderr,"\n   %s\n",command_line_options[i].description);
    }
  return -1;
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
    status = parseCommandLine(argc, argv);
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

static void complainCommandLine(const char *prefix, int argc, const char *const *argv)
{
  char buf[1024];
  char *b = buf;
  int i;
  char *e = buf + sizeof(buf) - 4;
  for (i = 0; b < e && i != argc; ++i) {
      if (i) *b++ = ' ';
      const char *a = argv[i];
      if (b < e) *b++ = '\'';
      for (; *a && b < e; ++a) {
	  if (*a == '\'') {
	    if (b < e) *b++ = '\'';
	    if (b < e) *b++ = '\\';
	    if (b < e) *b++ = '\'';
	    if (b < e) *b++ = '\'';
	  } else {
	    if (b < e) *b++ = *a;
	  }
      }
      if (b < e) *b++ = '\'';
  }
  if (b < e)
      *b = '\0';
  else
      strcpy(e, "...");
  setReason("%s%s", prefix, buf);
}

/* args[] excludes command name (unless hardlinks are used to use first words 
   of command sequences as alternate names of the command. */
int parseCommandLine(int argc, const char *const *args)
{
  int i;
  int ambiguous=0;
  int cli_call=-1;
  for(i=0;command_line_options[i].function;i++)
    {
      int j;
      const char *word = NULL;
      int optional = 0;
      int mandatory = 0;
      for (j = 0; (word = command_line_options[i].words[j]); ++j) {
	int wordlen = strlen(word);
	if (optional < 0) {
	  WHYF("Internal error: command_line_options[%d].word[%d]=\"%s\" not allowed after \"...\"", i, j, word);
	  break;
	}
	else if (!(  (wordlen > 2 && word[0] == '<' && word[wordlen-1] == '>')
		  || (wordlen > 4 && word[0] == '[' && word[1] == '<' && word[wordlen-2] == '>' && word[wordlen-1] == ']')
		  || (wordlen > 0)
	)) {
	  WHYF("Internal error: command_line_options[%d].word[%d]=\"%s\" is malformed", i, j, word);
	  break;
	} else if (word[0] == '<') {
	  ++mandatory;
	  if (optional) {
	    WHYF("Internal error: command_line_options[%d].word[%d]=\"%s\" should be optional", i, j, word);
	    break;
	  }
	} else if (word[0] == '[') {
	  ++optional;
	} else if (wordlen == 3 && word[0] == '.' && word[1] == '.' && word[2] == '.') {
	  optional = -1;
	} else {
	  ++mandatory;
	  if (j < argc && strcasecmp(word, args[j])) // literal words don't match
	    break;
	}
      }
      if (!word && argc >= mandatory && (optional < 0 || argc <= mandatory + optional)) {
	/* A match!  We got through the command definition with no internal errors and all literal
	   args matched and we have a proper number of args.  If we have multiple matches, then note
	   that the call is ambiguous. */
	if (cli_call>=0) ambiguous++;
	if (ambiguous==1) {
	  setReason("Ambiguous command line call:");
	  complainCommandLine("   ", argc, args);
	  setReason("Matches the following known command line calls:");
	  complainCommandLine("   ", argc, command_line_options[cli_call].words);
	}
	if (ambiguous) {
	  complainCommandLine("   ", argc, command_line_options[i].words);
	}
	cli_call=i;
      }
    }

  /* Don't process ambiguous calls */
  if (ambiguous) return -1;
  /* Complain if we found no matching calls */
  if (cli_call<0) {
    setReason("Unknown command line call:");
    complainCommandLine("   ", argc, args);
    return cli_usage();
  }

  /* Otherwise, make call */
  confSetDebugFlags();
  int result=command_line_options[cli_call].function(argc, args, &command_line_options[cli_call]);
  /* clean up after ourselves */
  overlay_mdp_client_done();
  return result;
}

int cli_arg(int argc, const char *const *argv, command_line_option *o, char *argname, const char **dst, int (*validator)(const char *arg), char *defaultvalue)
{
  int arglen = strlen(argname);
  int i;
  const char *word;
  for(i = 0; (word = o->words[i]); ++i) {
    int wordlen = strlen(word);
    /* No need to check that the "<...>" and "[<...>]" are all intact in the command_line_option,
       because that was already checked in parseCommandLine(). */
    if (i < argc
      &&(  (wordlen == arglen + 2 && word[0] == '<' && !strncasecmp(&word[1], argname, arglen))
        || (wordlen == arglen + 4 && word[0] == '[' && !strncasecmp(&word[2], argname, arglen)))
    ) {
      const char *value = argv[i];
      if (validator && !(*validator)(value))
	return setReason("Invalid argument %d '%s': \"%s\"", i + 1, argname, value);
      *dst = value;
      return 0;
    }
  }
  /* No matching valid argument was found, so return default value.  It might seem that this should
     never happen, but it can because more than one version of a command line option may exist, one
     with a given argument and another without, and allowing a default value means we can have a
     single function handle both in a fairly simple manner. */
  *dst = defaultvalue;
  return 1;
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
  va_list ap,ap2;
  va_start(ap,fmt);
  va_copy(ap2,ap);
#ifdef HAVE_JNI_H
  if (jni_env) {
    size_t avail = outv_limit - outv_current;
    int count = vsnprintf(outv_current, avail, fmt, ap2);
    if (count >= avail) {
      if (outv_growbuf(count) == -1)
	return -1;
      vsprintf(outv_current, fmt, ap2);
    }
    outv_current += count;
    ret = count;
  } else
#endif
    ret = vfprintf(stdout, fmt, ap2);
  va_end(ap);
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
  if (jni_env) {
    return outv_end_field();
  } else
#endif
  {
    const char *delim = getenv("SERVALD_OUTPUT_DELIMITER");
    if (delim == NULL)
      delim = opt ? opt : "\n";
    fputs(delim, stdout);
  }
  return 0;
}

int app_echo(int argc, const char *const *argv, struct command_line_option *o)
{
  int i;
  for (i = 1; i < argc; ++i) {
    if (debug & DEBUG_VERBOSE)
      DEBUGF("echo:argv[%d]=%s", i, argv[i]);
    cli_puts(argv[i]);
    cli_delim(NULL);
  }
  return 0;
}

int app_dna_lookup(int argc, const char *const *argv, struct command_line_option *o)
{
  int i;
  /* Create the instance directory if it does not yet exist */
  if (create_serval_instance_dir() == -1)
    return -1;

  int sid_count=0;
  unsigned char sids[128][SID_SIZE];

  const char *did;
  if (cli_arg(argc, argv, o, "did", &did, NULL, "*") == -1)
    return -1;

  /* Bind to MDP socket and await confirmation */
  unsigned char srcsid[SID_SIZE];
  int port=32768+(random()&32767);
  if (overlay_mdp_getmyaddr(0,srcsid)) return WHY("Could not get local address");
  if (overlay_mdp_bind(srcsid,port)) return WHY("Could not bind to MDP socket");

  /* use MDP to send the lookup request to MDP_PORT_DNALOOKUP, and wait for
     replies. */
  overlay_mdp_frame mdp;
  bzero(&mdp,sizeof(mdp));

  /* Now repeatedly send resolution request and collect results until we reach
     timeout. */
  unsigned long long timeout=overlay_gettime_ms()+3000;
  unsigned long long last_tx=0;
  
  while(timeout>overlay_gettime_ms())
    {
      unsigned long long now=overlay_gettime_ms();
      if ((last_tx+125)<now)
	{ 
	  mdp.packetTypeAndFlags=MDP_TX|MDP_NOCRYPT;
	  
	  /* set source address to a local address, and pick a random port */
	  mdp.out.src.port=port;
	  bcopy(&srcsid[0],&mdp.out.src.sid[0],SID_SIZE);
	  
	  /* Send to broadcast address and DNA lookup port */
	  for(i=0;i<SID_SIZE;i++) mdp.out.dst.sid[i]=0xff;
	  mdp.out.dst.port=MDP_PORT_DNALOOKUP;
	  
	  /* put DID into packet */
	  bcopy(did,&mdp.out.payload[0],strlen(did)+1);
	  mdp.out.payload_length=strlen(did)+1;

	  overlay_mdp_send(&mdp,0,0);
	  last_tx=now;
	}
      long long short_timeout=125;
      while(short_timeout>0) {
	if (overlay_mdp_client_poll(short_timeout))
	  {
	    overlay_mdp_frame rx;
	    int ttl;
	    while (overlay_mdp_recv(&rx,&ttl)==0)
	      {
		if (rx.packetTypeAndFlags==MDP_ERROR)
		  {
		    WHYF("       Error message: %s", mdp.error.message);
		  }
		else if ((rx.packetTypeAndFlags&MDP_TYPE_MASK)==MDP_TX) {
		  /* Display match unless it is a duplicate.
		     XXX - For wildcard searches, each sid will only show up once. */
		  int i;
		  for(i=0;i<sid_count;i++)
		    if (!memcmp(&rx.in.src.sid[0],&sids[i][0],SID_SIZE))
		      break;		  
		  if (i==sid_count) {
		    cli_puts(overlay_render_sid(&rx.in.src.sid[0])); cli_delim(":");
		    cli_puts((char *)&rx.in.payload[0]); cli_delim(":");
		    cli_puts((char *)&rx.in.payload[32]); cli_delim("\n");
		    if (sid_count<128) {
		      bcopy(&rx.in.src.sid[0],&sids[i][0],SID_SIZE);
		      sid_count++;
		    }
		  }
		}
		else WHYF("packettype=0x%x",rx.packetTypeAndFlags);
		if (servalShutdown) break;
	      }
	  }
	if (servalShutdown) break;
	short_timeout=125-(overlay_gettime_ms()-now);
      }
      if (servalShutdown) break;
    }

  overlay_mdp_client_done();
  return 0;
}

int confValueRotor=0;
char confValue[4][128];
const char *confValueGet(const char *var, const char *defaultValue)
{
  if (!var) return defaultValue;
  int varLen=strlen(var);

  char filename[1024];
  if (!FORM_SERVAL_INSTANCE_PATH(filename, "serval.conf")) {
    WARNF("Using default value of %s: %s", var, defaultValue);
    return defaultValue;
  }
  FILE *f = fopen(filename,"r");
  if (!f) {
    WARNF("Cannot open serval.conf, using default value of %s: %s", var, defaultValue);
    return defaultValue;
  }

  char line[1024];
  line[0]=0; fgets(line,1024,f);
  while(line[0]) {
    if (!strncasecmp(line,var,varLen)) {
      if (line[varLen]=='=') {
	fclose(f);
	if (strlen(&line[varLen+1])>127) return defaultValue;
	/* The rotor is used to pick which of four buffers to return in.
	   This allows the use of up to four calls to confValueGet() in
	   a single string formatting exercise, without unexpected side
	   effect. */
	confValueRotor++; confValueRotor&=3;
	strcpy(&confValue[confValueRotor][0],&line[varLen+1]);
	return &confValue[confValueRotor][0];
      }
    }
    line[0]=0; fgets(line,1024,f);
  }
  fclose(f);
  return defaultValue;
}

int confValueGetBoolean(const char *var, int defaultValue)
{
  const char *value = confValueGet(var, NULL);
  if (!value)
    return defaultValue;
  int flag = confParseBoolean(value, var);
  if (flag >= 0)
    return flag;
  WARNF("Config option %s: using default value %s", var, defaultValue ? "true" : "false");
  return defaultValue;
}

void confSetDebugFlags()
{
  char filename[1024];
  if (FORM_SERVAL_INSTANCE_PATH(filename, "serval.conf")) {
    FILE *f = fopen(filename, "r");
    if (!f) {
      WARN("Cannot open serval.conf");
    } else {
      long long setmask = 0;
      long long clearmask = 0;
      int setall = 0;
      int clearall = 0;
      char line[1024];
      line[0] = '\0';
      fgets(line, sizeof line, f);
      while (line[0]) {
	if (!strncasecmp(line, "debug.", 6)) {
	  char *flagname = line + 6;
	  char *p = flagname;
	  while (*p && *p != '=')
	    ++p;
	  int flag;
	  if (*p) {
	    *p = '\0';
	    char *q = p + 1;
	    while (*q && *q != '\n')
	      ++q;
	    *q = '\0';
	    if ((flag = confParseBoolean(p + 1, flagname)) != -1) {
	      long long mask = debugFlagMask(flagname);
	      if (mask == -1)
		if (flag) setall = 1; else clearall = 1;
	      else
		if (flag) setmask |= mask; else clearmask |= mask;
	    }
	  }
	}
	line[0] = '\0';
	fgets(line, sizeof line, f);
      }
      fclose(f);
      if (setall) debug = -1; else if (clearall) debug = 0;
      debug &= ~clearmask;
      debug |= setmask;
    }
  }
}

int confParseBoolean(const char *text, const char *option_name)
{
  if (!strcasecmp(text, "on") || !strcasecmp(text, "yes") || !strcasecmp(text, "true") || !strcmp(text, "1"))
    return 1;
  if (!strcasecmp(text, "off") || !strcasecmp(text, "no") || !strcasecmp(text, "false") || !strcmp(text, "0"))
    return 0;
  WARNF("Config option %s: invalid boolean value '%s'", option_name, text);
  return -1;
}

int cli_absolute_path(const char *arg)
{
  return arg[0] == '/' && arg[1] != '\0';
}

int app_server_start(int argc, const char *const *argv, struct command_line_option *o)
{
  /* Process optional arguments */
  const char *execpath;
  int foregroundP = (argc >= 2 && !strcasecmp(argv[1], "foreground"));
  if (cli_arg(argc, argv, o, "instance path", &thisinstancepath, cli_absolute_path, NULL) == -1
   || cli_arg(argc, argv, o, "exec path", &execpath, cli_absolute_path, NULL) == -1)
    return -1;
  /* Create the instance directory if it does not yet exist */
  if (create_serval_instance_dir() == -1)
    return -1;
  /* Now that we know our instance path, we can ask for the default set of
     network interfaces that we will take interest in. */
  const char *interfaces = confValueGet("interfaces", "");
  if (!interfaces[0])
    WHY("No network interfaces configured (empty 'interfaces' config setting)");
  overlay_interface_args(interfaces);
  int pid = server_pid();
  if (pid < 0)
    return -1;
  int ret = 1;
  if (pid > 0) {
    WHYF("Serval process already running (pid=%d)", pid);
  } else {
    /* Start the Serval process.  All server settings will be read by the server process from the
       instance directory when it starts up.  */
    if (server_remove_stopfile() == -1)
      return -1;
    rhizome_opendb();
    overlayMode = 1;
    if (foregroundP)
      return server(NULL);
    int cpid;
    switch ((cpid = fork())) {
      case -1:
	return WHY_perror("fork");
      case 0: {
	/* Child process.  Fork then exit, to disconnect daemon from parent process, so that
	   when daemon exits it does not live on as a zombie. N.B. Do not return from within this
	   process; that will unroll the JNI call stack and cause havoc.  Use exit().  */
	switch (fork()) {
	  case -1:
	    exit(WHY_perror("fork"));
	  case 0: {
	    /* Grandchild process.  Disconnect from current directory, disconnect standard i/o
	       streams, and start a new process group so that if we are being started by an adb
	       shell session, then we don't receive a SIGHUP when the adb shell process ends.  */
	    chdir("/");
	    close(0);
	    open("/dev/null", O_RDONLY);
	    close(1);
	    open("/dev/null", O_WRONLY);
	    close(2);
	    open("/dev/null", O_WRONLY);
	    setpgrp();
	    /* The execpath option is provided so that a JNI call to "start" can be made which
	       creates a new server daemon process with the correct argv[0].  Otherwise, the servald
	       process appears as a process with argv[0] = "org.servalproject". */
	    if (execpath) {
	      execl(execpath, execpath, "start", "foreground", NULL);
	      exit(-1);
	    }
	    exit(server(NULL));
	  }
	}
	exit(0); // Parent is waitpid()-ing for this.
      }
    }
    /* Parent process.  Wait for the child process to fork the grandchild then die. */
    waitpid(cpid, NULL, 0);
    /* Allow a few seconds for the grandchild process to report for duty. */
    long long timeout = gettime_ms() + 5000;
    do {
      struct timespec delay;
      delay.tv_sec = 0;
      delay.tv_nsec = 200000000; // 200 ms = 5 Hz
      nanosleep(&delay, NULL);
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
  return ret;
}

int app_server_stop(int argc, const char *const *argv, struct command_line_option *o)
{
  if (cli_arg(argc, argv, o, "instance path", &thisinstancepath, cli_absolute_path, NULL) == -1)
    return -1;
  const char *instancepath = serval_instancepath();
  cli_puts("instancepath");
  cli_delim(":");
  cli_puts(instancepath);
  cli_delim("\n");
  int pid = server_pid();
  // If there is no pidfile, then there is no server process to stop.
  if (pid <= 0)
    return 1;
  // Otherwise, we have a server process to stop, so get to work.
  cli_puts("pid");
  cli_delim(":");
  cli_printf("%d", pid);
  cli_delim("\n");
  int tries = 0;
  int running = pid;
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
    long long timeout = gettime_ms() + 2000;
    do {
      struct timespec delay;
      delay.tv_sec = 0;
      delay.tv_nsec = 200000000; // 200 ms = 5 Hz
      nanosleep(&delay, NULL);
    } while ((running = server_pid()) == pid && gettime_ms() < timeout);
  }
  server_remove_stopfile();
  cli_puts("tries");
  cli_delim(":");
  cli_printf("%d", tries);
  cli_delim("\n");
  return 0;
}

int app_server_status(int argc, const char *const *argv, struct command_line_option *o)
{
  if (cli_arg(argc, argv, o, "instance path", &thisinstancepath, cli_absolute_path, NULL) == -1)
    return -1;
  int pid = server_pid();
  if (pid < 0)
    return -1;
  cli_puts("instancepath");
  cli_delim(":");
  cli_puts(serval_instancepath());
  cli_delim("\n");
  if (pid) {
    cli_puts("pid");
    cli_delim(":");
    cli_printf("%d", pid);
    cli_delim("\n");
  }
  return pid > 0 ? 0 : 1;
}

int app_mdp_ping(int argc, const char *const *argv, struct command_line_option *o)
{
  const char *sid;
  if (cli_arg(argc, argv, o, "SID|broadcast", &sid, validateSid, "broadcast") == -1)
    return -1;

  overlay_mdp_frame mdp;
  
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
  printf("MDP PING %s (%s): 12 data bytes\n",
	 overlay_render_sid(ping_sid),
	 overlay_render_sid(ping_sid));

  long long rx_mintime=-1;
  long long rx_maxtime=-1;
  long long rx_count=0,tx_count=0;
  long long rx_ms=0;
  long long rx_times[1024];

  if (broadcast) 
    WHY("WARNING: broadcast ping packets will not be encryped.");
  while(1) {
    /* Now send the ping packets */
    mdp.packetTypeAndFlags=MDP_TX;
    if (broadcast) mdp.packetTypeAndFlags|=MDP_NOCRYPT;
    mdp.out.src.port=port;
    bcopy(srcsid,mdp.out.src.sid,SID_SIZE);
    bcopy(ping_sid,&mdp.out.dst.sid[0],SID_SIZE);
    /* Set port to well known echo port (from /etc/services) */
    mdp.out.dst.port=7;
    mdp.out.payload_length=4+8;
    int *seq=(int *)&mdp.out.payload;
    *seq=sequence_number;
    long long *txtime=(long long *)&mdp.out.payload[4];
    *txtime=overlay_gettime_ms();
    
    int res=overlay_mdp_send(&mdp,0,0);
    if (res) {
      WHYF("ERROR: Could not dispatch PING frame #%d (error %d)", sequence_number - firstSeq, res);
      if (mdp.packetTypeAndFlags==MDP_ERROR)
	WHYF("       Error message: %s", mdp.error.message);
    } else tx_count++;

    /* Now look for replies until one second has passed, and print any replies
       with appropriate information as required */
    long long now=overlay_gettime_ms();
    long long timeout=now+1000;

    while(now<timeout) {
      long long timeout_ms=timeout-overlay_gettime_ms();
      int result = overlay_mdp_client_poll(timeout_ms);

      if (result>0) {
	int ttl=-1;
	while (overlay_mdp_recv(&mdp,&ttl)==0) {
	  switch(mdp.packetTypeAndFlags&MDP_TYPE_MASK) {
	  case MDP_ERROR:
	    WHYF("mdpping: overlay_mdp_recv: %s (code %d)", mdp.error.message, mdp.error.error);
	    break;
	  case MDP_TX:
	    {
	      int *rxseq=(int *)&mdp.in.payload;
	      long long *txtime=(long long *)&mdp.in.payload[4];
	      long long delay=overlay_gettime_ms()-*txtime;
	      printf("%s: seq=%d time=%lld ms%s%s\n",
		     overlay_render_sid(mdp.in.src.sid),(*rxseq)-firstSeq+1,delay,
		     mdp.packetTypeAndFlags&MDP_NOCRYPT?"":" ENCRYPTED",
		     mdp.packetTypeAndFlags&MDP_NOSIGN?"":" SIGNED");
	     #warning put duplicate pong detection here so that stats work properly
	      rx_count++;
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
      now=overlay_gettime_ms();
      if (servalShutdown) {

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
	fprintf(stderr,"--- %s ping statistics ---\n",overlay_render_sid(ping_sid));
	fprintf(stderr,"%lld packets transmitted, %lld packets received, %3.1f%% packet loss\n",
		tx_count,rx_count,tx_count?(tx_count-rx_count)*100.0/tx_count:0);
	fprintf(stderr,"round-trip min/avg/max/stddev%s = %lld/%.3f/%lld/%.3f ms\n",
		(samples<rx_count)?" (stddev calculated from last 1024 samples)":"",
		rx_mintime,rx_mean,rx_maxtime,rx_stddev);

	overlay_mdp_client_done();
	return 0;
      }
    }
    sequence_number++;
    timeout=now+1000;
  }

  overlay_mdp_client_done();
  return 0;
}

static int set_variable(const char *var, const char *val)
{
  char conffile[1024];
  FILE *in;
  if (!FORM_SERVAL_INSTANCE_PATH(conffile, "serval.conf") ||
      !((in = fopen(conffile, "r")) || (in = fopen(conffile, "w")))
    ) {
    if (var)
      return WHY("could not read configuration file.");
    return -1;
  }

  char tempfile[1024];
  FILE *out;
  if (!FORM_SERVAL_INSTANCE_PATH(tempfile, "serval.conf.temp") ||
      !(out = fopen(tempfile, "w"))
    ) {
    fclose(in);
    return WHY("could not write temporary file.");
  }

  /* Read and write lines of config file, replacing the variable in question
     if required.  If the variable didn't already exist, then write it out at
     the end. */
  char line[1024];
  int found=0;
  int varlen=strlen(var);
  line[0]=0; fgets(line,1024,in);
  while(line[0]) {
    if (!strncasecmp(var, line, varlen) && line[varlen] == '=') {
      if (!found && val)
	fprintf(out, "%s=%s\n", var, val);
      found = 1;
    } else
      fprintf(out,"%s",line);
    line[0]=0; fgets(line,1024,in);
  }
  if (!found && val)
    fprintf(out, "%s=%s\n", var, val);
  fclose(in); fclose(out);

  if (rename(tempfile,conffile)) {
    return WHYF("Failed to rename \"%s\" to \"%s\".", tempfile, conffile);
  }

  return 0;
}

int cli_configvarname(const char *arg)
{
  if (arg[0] == '\0')
    return 0;
  if (!(isalnum(arg[0]) || arg[0] == '_'))
    return 0;
  const char *s = arg + 1;
  for (; *s; ++s)
    if (!(isalnum(*s) || *s == '_' || (*s == '.' && s[-1] != '.')))
      return 0;
  return s[-1] != '.';
}

int app_config_set(int argc, const char *const *argv, struct command_line_option *o)
{
  const char *var, *val;
  if (	cli_arg(argc, argv, o, "variable", &var, cli_configvarname, NULL)
     || cli_arg(argc, argv, o, "value", &val, NULL, ""))
    return -1;
  if (create_serval_instance_dir() == -1)
    return -1;
  return set_variable(var, val);
}

int app_config_del(int argc, const char *const *argv, struct command_line_option *o)
{
  const char *var;
  if (cli_arg(argc, argv, o, "variable", &var, cli_configvarname, NULL))
    return -1;
  if (create_serval_instance_dir() == -1)
    return -1;
  return set_variable(var, NULL);
}

int app_config_get(int argc, const char *const *argv, struct command_line_option *o)
{
  const char *var;
  if (cli_arg(argc, argv, o, "variable", &var, cli_configvarname, NULL) == -1)
    return -1;
  if (create_serval_instance_dir() == -1)
    return -1;
  char conffile[1024];
  FILE *in;
  if (!FORM_SERVAL_INSTANCE_PATH(conffile, "serval.conf") ||
      !((in = fopen(conffile, "r")) || (in = fopen(conffile, "w")))
    ) {
    return WHY("could not read configuration file.");
  }
  /* Read lines of config file. */
  char line[1024];
  int varlen = var ? strlen(var) : 0;
  line[0]=0; fgets(line,1024,in);
  while(line[0]) {
    if (varlen == 0) {
      fputs(line, stdout);
    }
    else if (!strncasecmp(var, line, varlen) && line[varlen] == '=') {
      fputs(line, stdout);
      break;
    }
    line[0]=0;
    fgets(line,1024,in);
  }
  fclose(in);
  return 0;
}

int cli_optional_sid(const char *arg)
{
  return !arg[0] || validateSid(arg);
}

int app_rhizome_add_file(int argc, const char *const *argv, struct command_line_option *o)
{
  const char *filepath, *manifestpath, *authorSid, *pin;
  cli_arg(argc, argv, o, "filepath", &filepath, NULL, "");
  cli_arg(argc, argv, o, "author_sid", &authorSid, cli_optional_sid, "");
  cli_arg(argc, argv, o, "pin", &pin, NULL, "");
  cli_arg(argc, argv, o, "manifestpath", &manifestpath, NULL, "");

  keyring=keyring_open_with_pins(pin);
  if (!keyring) { WHY("keyring add: Failed to create/open keyring file");
    return -1; }


  /* Ensure the Rhizome database exists and is open */
  if (create_serval_instance_dir() == -1)
    return -1;
  rhizome_opendb();
  /* Create a new manifest that will represent the file.  If a manifest file was supplied, then read
   * it, otherwise create a blank manifest. */
  rhizome_manifest *m = NULL;
  int manifest_file_supplied = 0;
  if (manifestpath[0] && access(manifestpath, R_OK) == 0) {    
    m = rhizome_read_manifest_file(manifestpath, 0, 0); // no verify
    if (!m)
      return WHY("Manifest file could not be loaded -- not added to rhizome");
    manifest_file_supplied = 1;
  } else {
    m = rhizome_new_manifest();
    if (!m)
      return WHY("Manifest struct could not be allocated -- not added to rhizome");
  }
  /* Fill in a few missing manifest fields, to make it easier to use when adding new files:
      - the default service is "file"
      - the current time for "date"
      - if service is "file", then the payload file's basename for "name"
  */
  const char *service = rhizome_manifest_get(m, "service", NULL, 0);
  if (service == NULL) {
    rhizome_manifest_set(m, "service", (service = "file"));
  }
  if (rhizome_manifest_get(m, "date", NULL, 0) == NULL) {
    rhizome_manifest_set_ll(m, "date", gettime_ms());
  }
  if (strcasecmp("file", service) == 0) {
    if (rhizome_manifest_get(m, "name", NULL, 0) == NULL) {
      const char *name = strrchr(filepath, '/');
      name = name ? name + 1 : filepath;
      rhizome_manifest_set(m, "name", name);
    }
  }
  /* Add the manifest and its associated file to the Rhizome database, generating an "id" in the
   * process */
  rhizome_manifest *mout = NULL;
  if (debug & DEBUG_RHIZOME) DEBUGF("rhizome_add_manifest(author='%s')", authorSid);
  int ret = rhizome_add_manifest(
		m, &mout, filepath,
		NULL, // no groups - XXX should allow them
		255, // ttl - XXX should read from somewhere
		manifest_file_supplied, // int verifyP
		1, // int checkFileP
		1, // int signP
		authorSid[0] ? authorSid : NULL // SID of author as hex, so that they can modify the bundle later
    );
  if (ret == -1)
    return WHY("Manifest not added to Rhizome database");
  if (!(ret == 0 || ret == 2))
    return WHYF("Unexpected return value ret=%d", ret);
  /* If successfully added, overwrite the manifest file so that the Java component that is
     invoking this command can read it to obtain feedback on the result. */
  if (manifestpath[0] && rhizome_write_manifest_file(mout, manifestpath) == -1)
    ret = WHY("Could not overwrite manifest file.");
  service = rhizome_manifest_get(mout, "service", NULL, 0);
  if (service) {
    cli_puts("service"); cli_delim(":");
    cli_puts(service); cli_delim("\n");
  }
  cli_puts("manifestid"); cli_delim(":");
  cli_puts(rhizome_bytes_to_hex(mout->cryptoSignPublic, crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES)); cli_delim("\n");
  cli_puts("filehash"); cli_delim(":");
  cli_puts(mout->fileHexHash); cli_delim("\n");
  cli_puts("filesize"); cli_delim(":");
  cli_printf("%lld", mout->fileLength); cli_delim("\n");
  const char *name = rhizome_manifest_get(mout, "name", NULL, 0);
  if (name) {
    cli_puts("name"); cli_delim(":");
    cli_puts(name); cli_delim("\n");
  }
  rhizome_manifest_free(m);
  if (mout != m)
    rhizome_manifest_free(mout);
  return ret;
}

int cli_manifestid(const char *arg)
{
  return rhizome_str_is_manifest_id(arg);
}

int app_rhizome_extract_manifest(int argc, const char *const *argv, struct command_line_option *o)
{
  const char *manifestid, *manifestpath;
  if (cli_arg(argc, argv, o, "manifestid", &manifestid, cli_manifestid, NULL)
   || cli_arg(argc, argv, o, "manifestpath", &manifestpath, NULL, "") == -1)
    return -1;
  /* Ensure the Rhizome database exists and is open */
  if (create_serval_instance_dir() == -1)
    return -1;
  rhizome_opendb();
  /* Extract the manifest from the database */
  rhizome_manifest *m = NULL;
  int ret = rhizome_retrieve_manifest(manifestid, &m);
  switch (ret) {
    case 0: ret = 1; break;
    case 1: ret = 0;
      if (manifestpath[0]) {
	/* If the manifest has been read in from database, the blob is there,
	   and we can lie and say we are finalised and just want to write it
	   out.  XXX really should have a dirty/clean flag, so that write
	   works is clean but not finalised. */
	m->finalised=1;
	if (rhizome_write_manifest_file(m, manifestpath) == -1)
	  ret = WHY("Could not overwrite manifest file.");
      }
      break;
    case -1: break;
    default: ret = WHYF("Unsupported return value %d", ret); break;
  }
  if (m)
    rhizome_manifest_free(m);
  return ret;
}

int cli_fileid(const char *arg)
{
  return rhizome_str_is_file_hash(arg);
}

int app_rhizome_extract_file(int argc, const char *const *argv, struct command_line_option *o)
{
  const char *fileid, *filepath;
  if (cli_arg(argc, argv, o, "fileid", &fileid, cli_fileid, NULL)
   || cli_arg(argc, argv, o, "filepath", &filepath, NULL, "") == -1)
    return -1;
  /* Ensure the Rhizome database exists and is open */
  if (create_serval_instance_dir() == -1)
    return -1;
  rhizome_opendb();
  /* Extract the file from the database */
  int ret = rhizome_retrieve_file(fileid, filepath);
  switch (ret) {
    case 0: ret = 1; break;
    case 1: ret = 0; break;
    case -1: break;
    default: ret = WHYF("Unsupported return value %d", ret); break;
  }
  return ret;
}

int cli_uint(const char *arg)
{
  register const char *s = arg;
  while (isdigit(*s++))
    ;
  return s != arg && *s == '\0';
}

int app_rhizome_list(int argc, const char *const *argv, struct command_line_option *o)
{
  const char *service, *sender_sid, *recipient_sid, *offset, *limit;
  cli_arg(argc, argv, o, "service", &service, NULL, "");
  cli_arg(argc, argv, o, "sender_sid", &sender_sid, cli_optional_sid, "");
  cli_arg(argc, argv, o, "recipient_sid", &recipient_sid, cli_optional_sid, "");
  cli_arg(argc, argv, o, "offset", &offset, cli_uint, "0");
  cli_arg(argc, argv, o, "limit", &limit, cli_uint, "0");
  /* Create the instance directory if it does not yet exist */
  if (create_serval_instance_dir() == -1)
    return -1;
  rhizome_opendb();
  return rhizome_list_manifests(service, sender_sid, recipient_sid, atoi(offset), atoi(limit));
}

int app_keyring_create(int argc, const char *const *argv, struct command_line_option *o)
{
  const char *pin;
  cli_arg(argc, argv, o, "pin,pin ...", &pin, NULL, "");
  keyring_file *k=keyring_open_with_pins(pin);
  if (!k) WHY("keyring create: Failed to create/open keyring file");
  return 0;
}

int app_keyring_list(int argc, const char *const *argv, struct command_line_option *o)
{
  const char *pin;
  cli_arg(argc, argv, o, "pin,pin ...", &pin, NULL, "");
  keyring_file *k=keyring_open_with_pins(pin);

  int cn=0;
  int in=0;

  for(cn=0;cn<k->context_count;cn++)
    for(in=0;in<k->contexts[cn]->identity_count;in++)
      {
	int kpn;
	keypair *kp;
	unsigned char *sid=NULL,*did=NULL;
	for(kpn=0;kpn<k->contexts[cn]->identities[in]->keypair_count;kpn++)
	  {
	    kp=k->contexts[cn]->identities[in]->keypairs[kpn];
	    if (kp->type==KEYTYPE_CRYPTOBOX) sid=kp->public_key;
	    if (kp->type==KEYTYPE_DID) did=kp->private_key;
	  }
	if (sid||did) {
	    int i;
	    if (sid) for(i=0;i<SID_SIZE;i++) cli_printf("%02x",sid[i]);
	    cli_delim(":");
	    if (did) cli_puts((char*)did);
	    cli_delim("\n");
	}
      }
  return 0;
 }

int app_keyring_add(int argc, const char *const *argv, struct command_line_option *o)
{
  const char *pin;
  cli_arg(argc, argv, o, "pin", &pin, NULL, "");

  keyring_file *k=keyring_open_with_pins("");
  if (!k) { WHY("keyring add: Failed to create/open keyring file");
    return -1; }
  
  if (keyring_create_identity(k,k->contexts[0],(char *)pin)==NULL)
    return setReason("Could not create new identity (keyring_create_identity() failed)");
  if (keyring_commit(k))
    return setReason("Could not write new identity (keyring_commit() failed)");
  keyring_free(k);
  return 0;
}

int app_keyring_set_did(int argc, const char *const *argv, struct command_line_option *o)
{
  const char *sid, *did, *pin, *name;
  cli_arg(argc, argv, o, "sid", &sid, NULL, "");
  cli_arg(argc, argv, o, "did", &did, NULL, "");
  cli_arg(argc, argv, o, "name", &name, NULL, "");
  cli_arg(argc, argv, o, "pin", &pin, NULL, "");

  if (strlen(did)>31) return WHY("DID too long (31 digits max)");
  if (strlen(name)>63) return WHY("Name too long (31 char max)");

  keyring=keyring_open_with_pins((char *)pin);
  if (!keyring) return WHY("Could not open keyring file");

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

int app_id_self(int argc, const char *const *argv, struct command_line_option *o)
{
  /* List my own identities */
  overlay_mdp_frame a;
  int result;
  int count=0;

  a.packetTypeAndFlags=MDP_GETADDRS;
  if (!strcasecmp(argv[1],"self"))
    a.addrlist.selfP=1; /* get own identities, not those of peers */
  else
    a.addrlist.selfP=0; /* get peer list */
  a.addrlist.first_sid=-1;
  a.addrlist.last_sid=0x7fffffff;
  a.addrlist.frame_sid_count=MDP_MAX_SID_REQUEST;

  while(a.addrlist.frame_sid_count==MDP_MAX_SID_REQUEST) {
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
      cli_printf("%s",overlay_render_sid(a.addrlist.sids[i])); cli_delim("\n");
    }
    /* get ready to ask for next block of SIDs */
    a.packetTypeAndFlags=MDP_GETADDRS;
    a.addrlist.first_sid=a.addrlist.last_sid+1;
  }
  return 0;
}

int app_test_rfs(int argc, const char *const *argv, struct command_line_option *o)
{
  unsigned char bytes[8];
  int i;
  
  fprintf(stderr,"Testing that RFS coder works properly.\n");
  for(i=0;i<65536;i++)
    {
      rfs_encode(i,&bytes[0]);
      int zero=0;
      int r=rfs_decode(&bytes[0],&zero);
      if (i!=r) {
	fprintf(stderr,"RFS encoding of %d decodes to %d: ",i,r);
	int j;
	for(j=0;j<zero;j++) fprintf(stderr," %02x",bytes[j]);
	fprintf(stderr,"\n");
      }
    }
  return 0;
}

int app_node_info(int argc, const char *const *argv, struct command_line_option *o)
{
  const char *sid;
  cli_arg(argc, argv, o, "sid", &sid, NULL, "");

  overlay_mdp_frame mdp;
  bzero(&mdp,sizeof(mdp));
  int resolveDid=0;

  mdp.packetTypeAndFlags=MDP_NODEINFO;
  if (argc>3) resolveDid=1;
  mdp.nodeinfo.resolve_did=0; // so we know that we don't have a result yet.

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
    overlay_mdp_frame m2;
    bzero(&m2,sizeof(m2));
    int port=32768+(random()&0xffff);
    unsigned char srcsid[SID_SIZE];
    if (overlay_mdp_getmyaddr(0,srcsid)) port=0;
    if (overlay_mdp_bind(srcsid,port)) port=0;

    if (port) {    
      int i;
      for(i=0;i<(3000/125);i++) {
	m2.packetTypeAndFlags=MDP_TX;
	m2.out.src.port=port;
	bcopy(&srcsid[0],&m2.out.src.sid[0],SID_SIZE);
	bcopy(&mdp.nodeinfo.sid[0],&m2.out.dst.sid[0],SID_SIZE);
	m2.out.dst.port=MDP_PORT_DNALOOKUP;
	/* search for any DID */
	m2.out.payload[0]=0;
	m2.out.payload_length=1;

	if (!overlay_mdp_send(&m2,MDP_AWAITREPLY,125))
	  {	    
	    int bytes=m2.in.payload_length;
	    if (m2.packetTypeAndFlags!=MDP_TX) {
	      WHYF("MDP returned an unexpected message (type=0x%x)",
		   m2.packetTypeAndFlags);
	      if (m2.packetTypeAndFlags==MDP_ERROR) 
		WHYF("MDP message is return/error: %d:%s",
		     m2.error.error,m2.error.message);
	    }
	    if ((bytes+1)<sizeof(mdp.nodeinfo.did)+sizeof(mdp.nodeinfo.name))
	      {
		bcopy(&m2.in.payload[0],&mdp.nodeinfo.did[0],32);
		bcopy(&m2.in.payload[32],&mdp.nodeinfo.name[0],64);
		mdp.nodeinfo.did[bytes]=0;
		mdp.nodeinfo.resolve_did=1;
	      }
	    break;
	  } else {
	  if (0) {
	    WHY("Poll for DNA number resolution failed");
	    if (m2.packetTypeAndFlags==MDP_ERROR) 
	      WHYF("error.error=%d, error.message=%s",m2.error.error,m2.error.message);
	  }
	}
      }
    }
  }

  cli_printf("record"); cli_delim(":");
  cli_printf("%d",mdp.nodeinfo.index); cli_delim(":");
  cli_printf("%d",mdp.nodeinfo.count); cli_delim(":");
  cli_printf("%s",mdp.nodeinfo.foundP?"found":"noresult"); cli_delim(":");
  cli_printf("%s",overlay_render_sid(mdp.nodeinfo.sid)); cli_delim(":");
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
command_line_option command_line_options[]={
  {app_dna_lookup,{"dna","lookup","<did>",NULL},0,
   "Lookup the SIP/MDP address of the supplied telephone number (DID)."},
  {cli_usage,{"help",NULL},0,
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
  {app_mdp_ping,{"mdp","ping","<SID|broadcast>",NULL},CLIFLAG_STANDALONE,
   "Attempts to ping specified node via Mesh Datagram Protocol (MDP)."},
  {app_config_set,{"config","set","<variable>","<value>",NULL},CLIFLAG_STANDALONE,
   "Set specified configuration variable."},
  {app_config_del,{"config","del","<variable>",NULL},CLIFLAG_STANDALONE,
   "Set specified configuration variable."},
  {app_config_get,{"config","get","[<variable>]",NULL},CLIFLAG_STANDALONE,
   "Get specified configuration variable."},
  {app_rhizome_add_file,{"rhizome","add","file","<author_sid>","<pin>","<filepath>","[<manifestpath>]",NULL},CLIFLAG_STANDALONE,
   "Add a file to Rhizome and optionally write its manifest to the given path"},
  {app_rhizome_list,{"rhizome","list","[<service>]","[<sender_sid>]","[<recipient_sid>]","[<offset>]","[<limit>]",NULL},CLIFLAG_STANDALONE,
   "List all manifests and files in Rhizome"},
  {app_rhizome_extract_manifest,{"rhizome","extract","manifest","<manifestid>","[<manifestpath>]",NULL},CLIFLAG_STANDALONE,
   "Extract a manifest from Rhizome and write it to the given path"},
  {app_rhizome_extract_file,{"rhizome","extract","file","<fileid>","[<filepath>]",NULL},CLIFLAG_STANDALONE,
   "Extract a file from Rhizome and write it to the given path"},
  {app_keyring_create,{"keyring","create",NULL},0,
   "Create a new keyring file."},
  {app_keyring_list,{"keyring","list","[<pin,pin ...>]",NULL},CLIFLAG_STANDALONE,
   "List identites in specified key ring that can be accessed using the specified PINs"},
  {app_keyring_add,{"keyring","add","[<pin>]",NULL},CLIFLAG_STANDALONE,
   "Create a new identity in the keyring protected by the provided PIN"},
  {app_keyring_set_did,{"set","did","<sid>","<did>","<name>","[<pin>]",NULL},CLIFLAG_STANDALONE,
   "Set the DID for the specified SID.  Optionally supply PIN to unlock the SID record in the keyring."},
  {app_vomp_status,{"vomp","status",NULL},0,
   "Display status of any VoMP calls"},
  {app_vomp_monitor,{"vomp","monitor",NULL},0,
   "Monitor state and audio-flow of VoMP calls"},
  {app_vomp_pickup,{"vomp","pickup","<call>",NULL},0,
   "Accept specified call (use vomp status to get list of calls)"},
  {app_vomp_hangup,{"vomp","hangup","<call>",NULL},0,
   "End specified call (use vomp status to get list of calls)"},
  {app_vomp_dtmf,{"vomp","dtmf","<call>","<digits>",NULL},0,
   "Send DTMF digits over specified call"},
  {app_vomp_dial,{"vomp","dial","<sid>","<did>","[<callerid>]",NULL},0,
   "Attempt to dial the specified sid and did."},
  {app_id_self,{"id","self",NULL},0,
   "Return my own identity(s) as SIDs"},
  {app_id_self,{"id","peers",NULL},0,
   "Return identity of known peers as SIDs"},
  {app_node_info,{"node","info","<sid>","[getdid]",NULL},0,
   "Return information about SID, and optionally ask for DID resolution via network"},
  {app_test_rfs,{"test","rfs",NULL},0,
   "Test RFS field calculation"},
  {app_monitor_cli,{"monitor","[<sid>]",NULL},0,
   "Interactive servald monitor interface.  Specify SID to auto-dial that peer and insert dummy audio data"},
#ifdef HAVE_VOIPTEST
  {app_pa_phone,{"phone",NULL},0,
   "Run phone test application"},
#endif
  {NULL,{NULL}}
};
