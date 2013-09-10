/*
Serval DNA command-line functions
Copyright (C) 2010-2013 Serval Project, Inc.

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
#include <assert.h>
#include "serval.h"
#include "conf.h"
#include "rhizome.h"
#include "strbuf.h"
#include "strbuf_helpers.h"
#include "str.h"
#include "mdp_client.h"
#include "cli.h"
#include "overlay_address.h"
#include "overlay_buffer.h"

extern struct cli_schema command_line_options[];

int commandline_usage(const struct cli_parsed *parsed, struct cli_context *context)
{
  printf("Serval DNA version %s\nUsage:\n", version_servald);
  return cli_usage_parsed(parsed, XPRINTF_STDIO(stdout));
}

/* Data structures for accumulating output of a single JNI call.
*/

#ifdef HAVE_JNI_H

#define OUTV_BUFFER_ALLOCSIZE	(8192)

jclass IJniResults = NULL;
jmethodID startResultSet, setColumnName, putString, putBlob, putLong, putDouble, totalRowCount;

static int outv_growbuf(struct cli_context *context, size_t needed)
{
  size_t newsize = (context->outv_limit - context->outv_current < needed) ? (context->outv_limit - context->outv_buffer) + needed : 0;
  if (newsize) {
    // Round up to nearest multiple of OUTV_BUFFER_ALLOCSIZE.
    newsize = newsize + OUTV_BUFFER_ALLOCSIZE - ((newsize - 1) % OUTV_BUFFER_ALLOCSIZE + 1);
    size_t length = context->outv_current - context->outv_buffer;
    context->outv_buffer = realloc(context->outv_buffer, newsize);
    if (context->outv_buffer == NULL)
      return WHYF("Out of memory allocating %lu bytes", (unsigned long) newsize);
    context->outv_current = context->outv_buffer + length;
    context->outv_limit = context->outv_buffer + newsize;
  }
  return 0;
}

static int put_blob(struct cli_context *context, jbyte *value, jsize length){
  jbyteArray arr = NULL;
  if (value && length>0){
    arr = (*context->jni_env)->NewByteArray(context->jni_env, length);
    if (arr == NULL || (*context->jni_env)->ExceptionOccurred(context->jni_env)) {
      context->jni_exception = 1;
      return WHY("Exception thrown from NewByteArray()");
    }
    (*context->jni_env)->SetByteArrayRegion(context->jni_env, arr, 0, length, value);
    if ((*context->jni_env)->ExceptionOccurred(context->jni_env)) {
      context->jni_exception = 1;
      return WHYF("Exception thrown from SetByteArrayRegion()");
    }
  }
  (*context->jni_env)->CallVoidMethod(context->jni_env, context->jniResults, putBlob, arr);
  if ((*context->jni_env)->ExceptionOccurred(context->jni_env)) {
    context->jni_exception = 1;
    return WHY("Exception thrown from CallVoidMethod()");
  }
  if (arr)
    (*context->jni_env)->DeleteLocalRef(context->jni_env, arr);
  return 0;
}

static int outv_end_field(struct cli_context *context)
{
  jsize length = context->outv_current - context->outv_buffer;
  context->outv_current = context->outv_buffer;
  return put_blob(context, (jbyte *)context->outv_buffer, length);
}

int Throw(JNIEnv *env, const char *class, const char *msg)
{
  jclass exceptionClass = NULL;
  if ((exceptionClass = (*env)->FindClass(env, class)) == NULL)
    return -1; // exception
  (*env)->ThrowNew(env, exceptionClass, msg);
  return -1;
}

/* JNI entry point to command line.  See org.servalproject.servald.ServalD class for the Java side.
   JNI method descriptor: "(Ljava/util/List;[Ljava/lang/String;)I"
*/
JNIEXPORT jint JNICALL Java_org_servalproject_servald_ServalD_rawCommand(JNIEnv *env, jobject this, jobject outv, jobjectArray args)
{
  struct cli_context context;
  bzero(&context, sizeof(context));

  // find jni results methods
  if (!IJniResults){
    IJniResults = (*env)->FindClass(env, "org/servalproject/servald/IJniResults");
    if (IJniResults==NULL)
      return Throw(env, "java/lang/IllegalStateException", "Unable to locate class org.servalproject.servald.IJniResults");
    startResultSet = (*env)->GetMethodID(env, IJniResults, "startResultSet", "(I)V");
    if (startResultSet==NULL)
      return Throw(env, "java/lang/IllegalStateException", "Unable to locate method startResultSet");
    setColumnName = (*env)->GetMethodID(env, IJniResults, "setColumnName", "(ILjava/lang/String;)V");
    if (setColumnName==NULL)
      return Throw(env, "java/lang/IllegalStateException", "Unable to locate method setColumnName");
    putString = (*env)->GetMethodID(env, IJniResults, "putString", "(Ljava/lang/String;)V");
    if (putString==NULL)
      return Throw(env, "java/lang/IllegalStateException", "Unable to locate method putString");
    putBlob = (*env)->GetMethodID(env, IJniResults, "putBlob", "([B)V");
    if (putBlob==NULL)
      return Throw(env, "java/lang/IllegalStateException", "Unable to locate method putBlob");
    putLong = (*env)->GetMethodID(env, IJniResults, "putLong", "(J)V");
    if (putLong==NULL)
      return Throw(env, "java/lang/IllegalStateException", "Unable to locate method putLong");
    putDouble = (*env)->GetMethodID(env, IJniResults, "putDouble", "(D)V");
    if (putDouble==NULL)
      return Throw(env, "java/lang/IllegalStateException", "Unable to locate method putDouble");
    totalRowCount = (*env)->GetMethodID(env, IJniResults, "totalRowCount", "(I)V");
    if (totalRowCount==NULL)
      return Throw(env, "java/lang/IllegalStateException", "Unable to locate method totalRowCount");
  }

  unsigned char status = 0; // to match what the shell gets: 0..255

  // Construct argv, argc from this method's arguments.
  jsize len = (*env)->GetArrayLength(env, args);
  const char **argv = alloca(sizeof(char*) * (len + 1));
  if (argv == NULL)
    return Throw(env, "java/lang/OutOfMemoryError", "alloca() returned NULL");
  jsize i;
  for (i = 0; i <= len; ++i)
    argv[i] = NULL;
  int argc = len;
  // From now on, in case of an exception we have to free some resources before
  // returning.
  for (i = 0; !context.jni_exception && i < len; ++i) {
    const jstring arg = (jstring)(*env)->GetObjectArrayElement(env, args, i);
    if ((*env)->ExceptionOccurred(env))
      context.jni_exception = 1;
    else if (arg == NULL) {
      Throw(env, "java/lang/NullPointerException", "null element in argv");
      context.jni_exception = 1;
    }
    else {
      const char *str = (*env)->GetStringUTFChars(env, arg, NULL);
      if (str == NULL)
	context.jni_exception = 1;
      else
	argv[i] = str;
    }
  }
  if (!context.jni_exception) {
    // Set up the output buffer.
    context.jniResults = outv;
    context.outv_current = context.outv_buffer;
    // Execute the command.
    context.jni_env = env;
    status = parseCommandLine(&context, NULL, argc, argv);
  }

  // free any temporary output buffer
  if (context.outv_buffer)
    free(context.outv_buffer);

  // Release argv Java string buffers.
  for (i = 0; i < len; ++i) {
    if (argv[i]) {
      const jstring arg = (jstring)(*env)->GetObjectArrayElement(env, args, i);
      (*env)->ReleaseStringUTFChars(env, arg, argv[i]);
    }
  }

  // Deal with Java exceptions: NewStringUTF out of memory in outv_end_field().
  if (context.jni_exception || (context.outv_current != context.outv_buffer && outv_end_field(&context) == -1))
    return -1;

  return (jint) status;
}

#endif /* HAVE_JNI_H */

/* The argc and argv arguments must be passed verbatim from main(argc, argv), so argv[0] is path to
   executable.
*/
int parseCommandLine(struct cli_context *context, const char *argv0, int argc, const char *const *args)
{
  fd_clearstats();
  IN();
  
  struct cli_parsed parsed;
  int result = cli_parse(argc, args, command_line_options, &parsed);
  switch (result) {
  case 0:
    // Do not run the command if the configuration does not load ok.
    if (((parsed.commands[parsed.cmdi].flags & CLIFLAG_PERMISSIVE_CONFIG) ? cf_reload_permissive() : cf_reload()) != -1)
      result = cli_invoke(&parsed, context);
    else {
      strbuf b = strbuf_alloca(160);
      strbuf_append_argv(b, argc, args);
      result = WHYF("configuration defective, not running command: %s", strbuf_str(b));
    }
    break;
  case 1:
  case 2:
    // Load configuration so that log messages can get out.
    cf_reload_permissive();
    NOWHENCE(HINTF("Run \"%s help\" for more information.", argv0 ? argv0 : "servald"));
    break;
  default:
    // Load configuration so that log error messages can get out.
    cf_reload_permissive();
    break;
  }

  /* clean up after ourselves */
  overlay_mdp_client_done();
  rhizome_close_db();
  OUT();
  
  if (config.debug.timing)
    fd_showstats();
  return result;
}

/* Write a buffer of data to output.  If in a JNI call, then this appends the data to the
   current output field, including any embedded nul characters.  Returns a non-negative integer on
   success, EOF on error.
 */
int cli_write(struct cli_context *context, const unsigned char *buf, size_t len)
{
#ifdef HAVE_JNI_H
  if (context && context->jni_env) {
    size_t avail = context->outv_limit - context->outv_current;
    if (avail < len) {
      memcpy(context->outv_current, buf, avail);
      context->outv_current = context->outv_limit;
      if (outv_growbuf(context, len) == -1)
	return EOF;
      len -= avail;
      buf += avail;
    }
    memcpy(context->outv_current, buf, len);
    context->outv_current += len;
    return 0;
  }
#endif
  return fwrite(buf, len, 1, stdout);
}

/* Write a null-terminated string to output.  If in a JNI call, then this appends the string to the
   current output field.  The terminating null is not included.  Returns a non-negative integer on
   success, EOF on error.
 */
int cli_puts(struct cli_context *context, const char *str)
{
#ifdef HAVE_JNI_H
    if (context && context->jni_env)
      return cli_write(context, (const unsigned char *) str, strlen(str));
    else
#endif
      return fputs(str, stdout);
}

/* Write a formatted string to output.  If in a JNI call, then this appends the string to the
   current output field, excluding the terminating null.  Returns the number of bytes
   written/appended, or -1 on error.
 */
int cli_printf(struct cli_context *context, const char *fmt, ...)
{
  int ret = 0;
  va_list ap;
#ifdef HAVE_JNI_H
  if (context && context->jni_env) {
    size_t avail = context->outv_limit - context->outv_current;
    va_start(ap, fmt);
    int count = vsnprintf(context->outv_current, avail, fmt, ap);
    va_end(ap);
    if (count >= avail) {
      if (outv_growbuf(context, count) == -1)
	return -1;
      va_start(ap, fmt);
      vsprintf(context->outv_current, fmt, ap);
      va_end(ap);
    }
    context->outv_current += count;
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

void cli_columns(struct cli_context *context, int columns, const char *names[]){
#ifdef HAVE_JNI_H
  if (context && context->jni_env) {
    (*context->jni_env)->CallVoidMethod(context->jni_env, context->jniResults, startResultSet, columns);
    if ((*context->jni_env)->ExceptionOccurred(context->jni_env)) {
      context->jni_exception = 1;
      WHY("Exception thrown from CallVoidMethod()");
      return;
    }
    int i;
    for (i=0;i<columns;i++){
      jstring str = (jstring)(*context->jni_env)->NewStringUTF(context->jni_env, names[i]);
      if (str == NULL) {
	context->jni_exception = 1;
	WHY("Exception thrown from NewStringUTF()");
	return;
      }
      (*context->jni_env)->CallVoidMethod(context->jni_env, context->jniResults, setColumnName, i, str);
      (*context->jni_env)->DeleteLocalRef(context->jni_env, str);
    }
    return;
  }
#endif
  cli_printf(context, "%d",columns);
  cli_delim(context, "\n");
  int i;
  for (i=0;i<columns;i++){
    cli_puts(context, names[i]);
    if (i+1==columns)
      cli_delim(context, "\n");
    else
      cli_delim(context, ":");
  }
}

void cli_field_name(struct cli_context *context, const char *name, const char *delim){
#ifdef HAVE_JNI_H
  if (context && context->jni_env) {
    jstring str = (jstring)(*context->jni_env)->NewStringUTF(context->jni_env, name);
    if (str == NULL) {
      context->jni_exception = 1;
      WHY("Exception thrown from NewStringUTF()");
      return;
    }
    (*context->jni_env)->CallVoidMethod(context->jni_env, context->jniResults, setColumnName, -1, str);
    (*context->jni_env)->DeleteLocalRef(context->jni_env, str);
    return;
  }
#endif
  cli_puts(context, name);
  cli_delim(context, delim);
}

void cli_put_long(struct cli_context *context, int64_t value, const char *delim){
#ifdef HAVE_JNI_H
  if (context && context->jni_env) {
    (*context->jni_env)->CallVoidMethod(context->jni_env, context->jniResults, putLong, value);
    return;
  }
#endif
  cli_printf(context, "%" PRId64, value);
  cli_delim(context, delim);
}

void cli_put_string(struct cli_context *context, const char *value, const char *delim){
#ifdef HAVE_JNI_H
  if (context && context->jni_env) {
    jstring str = NULL;
    if (value){
      str = (jstring)(*context->jni_env)->NewStringUTF(context->jni_env, value);
      if (str == NULL) {
	context->jni_exception = 1;
	WHY("Exception thrown from NewStringUTF()");
	return;
      }
    }
    (*context->jni_env)->CallVoidMethod(context->jni_env, context->jniResults, putString, str);
    (*context->jni_env)->DeleteLocalRef(context->jni_env, str);
    return;
  }
#endif
  if (value)
    cli_puts(context, value);
  cli_delim(context, delim);
}

void cli_put_hexvalue(struct cli_context *context, const unsigned char *value, int length, const char *delim){
#ifdef HAVE_JNI_H
  if (context && context->jni_env) {
    put_blob(context, (jbyte*)value, length);
    return;
  }
#endif
  if (value)
    cli_puts(context, alloca_tohex(value, length));
  cli_delim(context, delim);
}

void cli_row_count(struct cli_context *context, int rows){
#ifdef HAVE_JNI_H
  if (context && context->jni_env) {
    (*context->jni_env)->CallVoidMethod(context->jni_env, context->jniResults, totalRowCount, rows);
    if ((*context->jni_env)->ExceptionOccurred(context->jni_env)) {
      context->jni_exception = 1;
      WHY("Exception thrown from CallVoidMethod()");
      return;
    }
  }
#endif
}

/* Delimit the current output field.  This closes the current field, so that the next cli_ output
   function will start appending to a new field.  Returns 0 on success, -1 on error.  If not in a
   JNI call, then this simply writes a newline to standard output (or the value of the
   SERVALD_OUTPUT_DELIMITER env var if set).
 */
int cli_delim(struct cli_context *context, const char *opt)
{
#ifdef HAVE_JNI_H
  if (context && context->jni_env)
    return outv_end_field(context);
#endif
  const char *delim = getenv("SERVALD_OUTPUT_DELIMITER");
  if (delim == NULL)
    delim = opt ? opt : "\n";
  fputs(delim, stdout);
  return 0;
}

/* Flush the output fields if they are being written to standard output.
 */
void cli_flush(struct cli_context *context)
{
#ifdef HAVE_JNI_H
  if (context && context->jni_env)
    return;
#endif
  fflush(stdout);
}

int app_echo(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  int escapes = !cli_arg(parsed, "-e", NULL, NULL, NULL);
  int i;
  for (i = parsed->varargi; i < parsed->argc; ++i) {
    const char *arg = parsed->args[i];
    if (config.debug.verbose)
      DEBUGF("echo:argv[%d]=\"%s\"", i, arg);
    if (escapes) {
      unsigned char buf[strlen(arg)];
      size_t len = strn_fromprint(buf, sizeof buf, arg, '\0', NULL);
      cli_write(context, buf, len);
    } else
      cli_puts(context, arg);
    cli_delim(context, NULL);
  }
  return 0;
}

int app_log(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  assert(parsed->argc == 3);
  const char *lvl = parsed->args[1];
  const char *msg = parsed->args[2];
  int level = string_to_log_level(lvl);
  if (level == LOG_LEVEL_INVALID)
    return WHYF("invalid log level: %s", lvl);
  logMessage(level, __NOWHERE__, "%s", msg);
  return 0;
}

void lookup_send_request(const sid_t *srcsid, int srcport, const sid_t *dstsid, const char *did)
{
  int i;
  overlay_mdp_frame mdp;
  bzero(&mdp,sizeof(mdp));
  
  
  /* set source address to a local address, and pick a random port */
  mdp.out.src.port=srcport;
  bcopy(srcsid->binary, mdp.out.src.sid, SID_SIZE);
  
  /* Send to destination address and DNA lookup port */
  
  if (dstsid) {
    /* Send an encrypted unicast packet */
    mdp.packetTypeAndFlags=MDP_TX;
    bcopy(dstsid->binary, mdp.out.dst.sid, SID_SIZE);
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

int app_dna_lookup(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  
  /* Create the instance directory if it does not yet exist */
  if (create_serval_instance_dir() == -1)
    return -1;

  int uri_count=0;
#define MAXREPLIES 256
#define MAXURILEN 256
  char uris[MAXREPLIES][MAXURILEN];

  const char *did, *delay;
  if (cli_arg(parsed, "did", &did, cli_lookup_did, "*") == -1)
    return -1;
  if (cli_arg(parsed, "timeout", &delay, NULL, "3000") == -1)
    return -1;
  
  int idelay=atoi(delay);
  int one_reply=0;
  
  // Ugly hack, if timeout is negative, stop after first reply
  if (idelay<0){
    one_reply=1;
    idelay=-idelay;
  }
  
  /* Bind to MDP socket and await confirmation */
  sid_t srcsid;
  int port=32768+(random()&32767);
  if (overlay_mdp_getmyaddr(0, &srcsid)) return WHY("Could not get local address");
  if (overlay_mdp_bind(&srcsid, port)) return WHY("Could not bind to MDP socket");

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

	  lookup_send_request(&srcsid, port, NULL, did);

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
			cli_put_string(context, uri, ":");
			cli_put_string(context, did, ":");
			cli_put_string(context, name, "\n");
			
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

int app_server_start(const struct cli_parsed *parsed, struct cli_context *context)
{
  IN();
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
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
      kill(pid,SIGHUP); 
      sleep_ms(1000);
      status=server_probe(&pid);
      if (status!=SERVER_NOTRUNNING) {
	WHY("Tried to stop stuck servald process, but attempt failed.");
	RETURN(-1);
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
  const char *execpath;
  if (cli_arg(parsed, "exec", &execpath, cli_absolute_path, NULL) == -1)
    RETURN(-1);
  int foregroundP = cli_arg(parsed, "foreground", NULL, NULL, NULL) == 0;
#ifdef HAVE_JNI_H
  if (context && context->jni_env && execpath == NULL)
    RETURN(WHY("Must supply \"exec <path>\" arguments when invoked via JNI"));
#endif
  /* Create the instance directory if it does not yet exist */
  if (create_serval_instance_dir() == -1)
    RETURN(-1);
  /* Now that we know our instance path, we can ask for the default set of
     network interfaces that we will take interest in. */
  if (config.interfaces.ac == 0)
    NOWHENCE(WARN("No network interfaces configured (empty 'interfaces' config option)"));
  if (pid == -1)
    pid = server_pid();
  if (pid < 0)
    RETURN(-1);
  int ret = -1;
  // If the pidfile identifies this process, it probably means we are re-spawning after a SEGV, so
  // go ahead and do the fork/exec.
  if (pid > 0 && pid != getpid()) {
    WARNF("Server already running (pid=%d)", pid);
    ret = 10;
  } else {
    if (foregroundP)
      INFOF("Foreground server process %s", execpath ? execpath : "without exec");
    else
      INFOF("Starting background server %s", execpath ? execpath : "without exec");
    /* Start the Serval process.  All server settings will be read by the server process from the
       instance directory when it starts up.  */
    if (server_remove_stopfile() == -1)
      RETURN(-1);
    overlayMode = 1;
    if (foregroundP)
      RETURN(server(parsed));
    const char *dir = getenv("SERVALD_SERVER_CHDIR");
    if (!dir)
      dir = config.server.chdir;
    switch (cpid = fork()) {
      case -1:
	/* Main process.  Fork failed.  There is no child process. */
	RETURN(WHY_perror("fork"));
      case 0: {
	/* Child process.  Fork then exit, to disconnect daemon from parent process, so that
	   when daemon exits it does not live on as a zombie. N.B. Do not return from within this
	   process; that will unroll the JNI call stack and cause havoc.  Use _exit().  */
	switch (fork()) {
	  case -1:
	    exit(WHY_perror("fork"));
	  case 0: {
	    /* Grandchild process.  Close logfile (so that it gets re-opened again on demand, with
	       our own file pointer), disable logging to stderr (about to get closed), disconnect
	       from current directory, disconnect standard I/O streams, and start a new process
	       session so that if we are being started by an adb shell session on an Android device,
	       then we don't receive a SIGHUP when the adb shell process ends.  */
	    close_log_file();
	    disable_log_stderr();
	    int fd;
	    if ((fd = open("/dev/null", O_RDWR, 0)) == -1)
	      _exit(WHY_perror("open(\"/dev/null\")"));
	    if (setsid() == -1)
	      _exit(WHY_perror("setsid"));
	    if (chdir(dir) == -1)
	      _exit(WHYF_perror("chdir(%s)", alloca_str_toprint(dir)));
	    if (dup2(fd, 0) == -1)
	      _exit(WHYF_perror("dup2(%d,0)", fd));
	    if (dup2(fd, 1) == -1)
	      _exit(WHYF_perror("dup2(%d,1)", fd));
	    if (dup2(fd, 2) == -1)
	      _exit(WHYF_perror("dup2(%d,2)", fd));
	    if (fd > 2)
	      (void)close(fd);
	    /* The execpath option is provided so that a JNI call to "start" can be made which
	       creates a new server daemon process with the correct argv[0].  Otherwise, the servald
	       process appears as a process with argv[0] = "org.servalproject". */
	    if (execpath) {
	    /* Need the cast on Solaris because it defines NULL as 0L and gcc doesn't see it as a
	       sentinal. */
	      execl(execpath, execpath, "start", "foreground", (void *)NULL);
	      WHYF_perror("execl(%s,\"start\",\"foreground\")", alloca_str_toprint(execpath));
	      _exit(-1);
	    }
	    _exit(server(parsed));
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
      RETURN(-1);
    if (pid == 0)
      RETURN(WHY("Server process did not start"));
    ret = 0;
  }
  cli_field_name(context, "instancepath", ":");
  cli_put_string(context, serval_instancepath(), "\n");
  cli_field_name(context, "pid", ":");
  cli_put_long(context, pid, "\n");
  cli_flush(context);
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
  RETURN(ret);
  OUT();
}

int app_server_stop(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  int			pid, tries, running;
  time_ms_t		timeout;
  const char *instancepath = serval_instancepath();
  cli_field_name(context, "instancepath", ":");
  cli_put_string(context, instancepath, "\n");
  pid = server_pid();
  /* Not running, nothing to stop */
  if (pid <= 0)
    return 1;
  INFOF("Stopping server (pid=%d)", pid);
  /* Set the stop file and signal the process */
  cli_field_name(context, "pid", ":");
  cli_put_long(context, pid, "\n");
  tries = 0;
  running = pid;
  while (running == pid) {
    if (tries >= 5) {
      WHYF("Servald pid=%d for instance '%s' did not stop after %d SIGHUP signals",
	   pid, instancepath, tries);
      return 253;
    }
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
      WHYF("Error sending SIGHUP to Servald pid=%d for instance '%s'", pid, instancepath);
      return 252;
    }
    /* Allow a few seconds for the process to die. */
    timeout = gettime_ms() + 2000;
    do
      sleep_ms(200); // 5 Hz
    while ((running = server_pid()) == pid && gettime_ms() < timeout);
  }
  server_remove_stopfile();
  cli_field_name(context, "tries", ":");
  cli_put_long(context, tries, "\n");
  return 0;
}

int app_server_status(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  int pid = server_pid();
  cli_field_name(context, "instancepath", ":");
  cli_put_string(context, serval_instancepath(), "\n");
  cli_field_name(context, "status", ":");
  cli_put_string(context, pid > 0 ? "running" : "stopped", "\n");
  if (pid > 0) {
    cli_field_name(context, "pid", ":");
    cli_put_long(context, pid, "\n");
  }
  return pid > 0 ? 0 : 1;
}

int app_mdp_ping(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  const char *sidhex, *count, *opt_timeout, *opt_interval;
  if (   cli_arg(parsed, "--timeout", &opt_timeout, cli_interval_ms, "1") == -1
      || cli_arg(parsed, "--interval", &opt_interval, cli_interval_ms, "1") == -1
      || cli_arg(parsed, "SID", &sidhex, str_is_subscriber_id, "broadcast") == -1
      || cli_arg(parsed, "count", &count, cli_uint, "0") == -1)
    return -1;
  
  // assume we wont hear any responses
  int ret=1;
  int icount=atoi(count);
  int64_t timeout_ms = 1000;
  str_to_uint64_interval_ms(opt_timeout, &timeout_ms, NULL);
  if (timeout_ms == 0)
    timeout_ms = 60 * 60000; // 1 hour...
  int64_t interval_ms = 1000;
  str_to_uint64_interval_ms(opt_interval, &interval_ms, NULL);

  overlay_mdp_frame mdp;
  bzero(&mdp, sizeof(overlay_mdp_frame));
  /* Bind to MDP socket and await confirmation */
  sid_t srcsid;
  int port=32768+(random()&32767);
  if (overlay_mdp_getmyaddr(0, &srcsid)) return WHY("Could not get local address");
  if (overlay_mdp_bind(&srcsid, port)) return WHY("Could not bind to MDP socket");

  /* First sequence number in the echo frames */
  unsigned int firstSeq=random();
  unsigned int sequence_number=firstSeq;

  /* Get SID that we want to ping.
     TODO - allow lookup of SID prefixes and telephone numbers
     (that would require MDP lookup of phone numbers, which doesn't yet occur) */
  sid_t ping_sid;
  if (str_to_sid_t(&ping_sid, sidhex) == -1)
    return WHY("str_to_sid_t() failed");
  int broadcast = is_sid_broadcast(ping_sid.binary);

  /* TODO Eventually we should try to resolve SID to phone number and vice versa */
  cli_printf(context, "MDP PING %s (%s): 12 data bytes", alloca_tohex_sid_t(ping_sid), alloca_tohex_sid_t(ping_sid));
  cli_delim(context, "\n");
  cli_flush(context);

  time_ms_t rx_mintime=-1;
  time_ms_t rx_maxtime=-1;
  time_ms_t rx_ms=0;
  time_ms_t rx_times[1024];
  int rx_count=0,tx_count=0;

  if (broadcast)
    WARN("broadcast ping packets will not be encrypted");
  for (; icount==0 || tx_count<icount; ++sequence_number) {
    /* Now send the ping packets */
    mdp.packetTypeAndFlags=MDP_TX;
    if (broadcast) mdp.packetTypeAndFlags|=MDP_NOCRYPT;
    mdp.out.src.port=port;
    bcopy(srcsid.binary, mdp.out.src.sid, SID_SIZE);
    bcopy(ping_sid.binary, mdp.out.dst.sid, SID_SIZE);
    mdp.out.queue=OQ_MESH_MANAGEMENT;
    /* Set port to well known echo port */
    mdp.out.dst.port=MDP_PORT_ECHO;
    mdp.out.payload_length=4+8;
    int *seq=(int *)&mdp.out.payload;
    *seq=sequence_number;
    write_uint64(&mdp.out.payload[4], gettime_ms());
    
    int res=overlay_mdp_send(&mdp,0,0);
    if (res) {
      WHYF("could not dispatch PING frame #%d (error %d)%s%s",
	  sequence_number - firstSeq,
	  res,
	  mdp.packetTypeAndFlags == MDP_ERROR ? ": " : "",
	  mdp.packetTypeAndFlags == MDP_ERROR ? mdp.error.message : ""
	);
    } else
      tx_count++;

    /* Now look for replies until one second has passed, and print any replies
       with appropriate information as required */
    time_ms_t now = gettime_ms();
    time_ms_t finish = now + (tx_count < icount?interval_ms:timeout_ms);
    for (; !servalShutdown && now < finish; now = gettime_ms()) {
      time_ms_t poll_timeout_ms = finish - gettime_ms();
      int result = overlay_mdp_client_poll(poll_timeout_ms);

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
	      time_ms_t txtime = read_uint64(&mdp.in.payload[4]);
	      int hop_count = 64 - mdp.in.ttl;
	      time_ms_t delay = gettime_ms() - txtime;
	      cli_printf(context, "%s: seq=%d time=%lldms hops=%d %s%s",
		     alloca_tohex_sid(mdp.in.src.sid),
		     (*rxseq)-firstSeq+1,
		     (long long)delay,
		     hop_count,
		     mdp.packetTypeAndFlags&MDP_NOCRYPT?"":" ENCRYPTED",
		     mdp.packetTypeAndFlags&MDP_NOSIGN?"":" SIGNED");
	      cli_delim(context, "\n");
	      cli_flush(context);
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
    }
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
    cli_printf(context, "--- %s ping statistics ---\n", alloca_tohex_sid_t(ping_sid));
    cli_printf(context, "%d packets transmitted, %d packets received, %3.1f%% packet loss\n",
	   tx_count,rx_count,tx_count?(tx_count-rx_count)*100.0/tx_count:0);
    cli_printf(context, "round-trip min/avg/max/stddev%s = %lld/%.3f/%lld/%.3f ms\n",
	   (samples<rx_count)?" (stddev calculated from last 1024 samples)":"",
	   rx_mintime,rx_mean,rx_maxtime,rx_stddev);
    cli_delim(context, NULL);
    cli_flush(context);
  }
  overlay_mdp_client_done();
  return ret;
}

int app_trace(const struct cli_parsed *parsed, struct cli_context *context){
  
  const char *sidhex;
  if (cli_arg(parsed, "SID", &sidhex, str_is_subscriber_id, NULL) == -1)
    return -1;
  
  sid_t srcsid;
  sid_t dstsid;
  if (str_to_sid_t(&dstsid, sidhex) == -1)
    return WHY("str_to_sid_t() failed");
  
  overlay_mdp_frame mdp;
  bzero(&mdp, sizeof(mdp));
  
  int port=32768+(random()&32767);
  if (overlay_mdp_getmyaddr(0, &srcsid)) return WHY("Could not get local address");
  if (overlay_mdp_bind(&srcsid, port)) return WHY("Could not bind to MDP socket");
  
  bcopy(srcsid.binary, mdp.out.src.sid, SID_SIZE);
  bcopy(srcsid.binary, mdp.out.dst.sid, SID_SIZE);
  mdp.out.src.port=port;
  mdp.out.dst.port=MDP_PORT_TRACE;
  mdp.packetTypeAndFlags=MDP_TX;
  struct overlay_buffer *b = ob_static(mdp.out.payload, sizeof(mdp.out.payload));
  
  ob_append_byte(b, SID_SIZE);
  ob_append_bytes(b, srcsid.binary, SID_SIZE);
  
  ob_append_byte(b, SID_SIZE);
  ob_append_bytes(b, dstsid.binary, SID_SIZE);
  
  mdp.out.payload_length = ob_position(b);
  cli_printf(context, "Tracing the network path from %s to %s", 
	 alloca_tohex_sid(srcsid.binary), alloca_tohex_sid(dstsid.binary));
  cli_delim(context, "\n");
  cli_flush(context);

  int ret=overlay_mdp_send(&mdp,MDP_AWAITREPLY,5000);
  ob_free(b);
  if (ret)
    DEBUGF("overlay_mdp_send returned %d", ret);
  else{
    int offset=0;
    {
      // skip the first two sid's
      int len = mdp.out.payload[offset++];
      offset+=len;
      len = mdp.out.payload[offset++];
      offset+=len;
    }
    int i=0;
    while(offset<mdp.out.payload_length){
      int len = mdp.out.payload[offset++];
      cli_put_long(context, i, ":");
      cli_put_string(context, alloca_tohex(&mdp.out.payload[offset], len), "\n");
      offset+=len;
      i++;
    }
  }
  overlay_mdp_client_done();
  return ret;
}

int app_config_schema(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  struct cf_om_node *root = NULL;
  if (cf_sch_config_main(&root) == -1) {
    cf_om_free_node(&root);
    return -1;
  }
  struct cf_om_iterator it;
  for (cf_om_iter_start(&it, root); it.node; cf_om_iter_next(&it))
    if (it.node->text || it.node->nodc == 0) {
      cli_put_string(context, it.node->fullkey,"=");
      cli_put_string(context, it.node->text, "\n");
    }
  cf_om_free_node(&root);
  return 0;
}

int app_config_dump(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  int full = 0 == cli_arg(parsed, "--full", NULL, NULL, NULL);
  if (create_serval_instance_dir() == -1)
    return -1;
  struct cf_om_node *root = NULL;
  int ret = cf_fmt_config_main(&root, &config);
  if (ret == CFERROR) {
    cf_om_free_node(&root);
    return -1;
  }
  struct cf_om_iterator it;
  for (cf_om_iter_start(&it, root); it.node; cf_om_iter_next(&it)) {
    if (it.node->text && (full || it.node->line_number)) {
      cli_put_string(context, it.node->fullkey, "=");
      cli_put_string(context, it.node->text, "\n");
    }
  }
  cf_om_free_node(&root);
  return ret == CFOK ? 0 : 1;
}

int app_config_set(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
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
  const char *var[parsed->argc - 1];
  const char *val[parsed->argc - 1];
  int nvar = 0;
  int i;
  for (i = 1; i < parsed->argc; ++i) {
    const char *arg = parsed->args[i];
    int iv;
    if (strcmp(arg, "set") == 0) {
      if (i + 2 > parsed->argc)
	return WHYF("malformed command at args[%d]: 'set' not followed by two arguments", i);
      var[nvar] = parsed->args[iv = ++i];
      val[nvar] = parsed->args[++i];
    } else if (strcmp(arg, "del") == 0) {
      if (i + 1 > parsed->argc)
	return WHYF("malformed command at args[%d]: 'del' not followed by one argument", i);
      var[nvar] = parsed->args[iv = ++i];
      val[nvar] = NULL;
    } else
      return WHYF("malformed command at args[%d]: unsupported action '%s'", i, arg);
    if (!is_configvarname(var[nvar]))
      return WHYF("malformed command at args[%d]: '%s' is not a valid config option name", iv, var[nvar]);
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

int app_config_get(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  const char *var;
  if (cli_arg(parsed, "variable", &var, is_configvarpattern, NULL) == -1)
    return -1;
  if (create_serval_instance_dir() == -1)
    return -1;
  if (cf_om_reload() == -1)
    return -1;
  if (var && is_configvarname(var)) {
    const char *value = cf_om_get(cf_om_root, var);
    if (value) {
      cli_field_name(context, var, "=");
      cli_put_string(context, value, "\n");
    }
  } else {
    struct cf_om_iterator it;
    for (cf_om_iter_start(&it, cf_om_root); it.node; cf_om_iter_next(&it)) {
      if (var && cf_om_match(var, it.node) <= 0)
	continue;
      if (it.node->text) {
	cli_field_name(context, it.node->fullkey, "=");
	cli_put_string(context, it.node->text, "\n");
      }
    }
  }
  return 0;
}

int app_rhizome_hash_file(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  /* compute hash of file. We do this without a manifest, so it will necessarily
     return the hash of the file unencrypted. */
  const char *filepath;
  cli_arg(parsed, "filepath", &filepath, NULL, "");
  char hexhash[RHIZOME_FILEHASH_STRLEN + 1];
  if (rhizome_hash_file(NULL,filepath, hexhash))
    return -1;
  cli_put_string(context, hexhash, "\n");
  return 0;
}

int app_rhizome_add_file(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  const char *filepath, *manifestpath, *manifestid, *authorSidHex, *bskhex;

  cli_arg(parsed, "filepath", &filepath, NULL, "");
  if (cli_arg(parsed, "author_sid", &authorSidHex, cli_optional_sid, "") == -1)
    return -1;
  cli_arg(parsed, "manifestpath", &manifestpath, NULL, "");
  cli_arg(parsed, "manifestid", &manifestid, NULL, "");
  if (cli_arg(parsed, "bsk", &bskhex, cli_optional_bundle_key, NULL) == -1)
    return -1;

  sid_t authorSid;
  if (authorSidHex[0] && str_to_sid_t(&authorSid, authorSidHex) == -1)
    return WHYF("invalid author_sid: %s", authorSidHex);
  rhizome_bk_t bsk;
  
  // treat empty string the same as null
  if (bskhex && !*bskhex)
    bskhex=NULL;
  
  if (bskhex && fromhexstr(bsk.binary, bskhex, RHIZOME_BUNDLE_KEY_BYTES) == -1)
    return WHYF("invalid bsk: \"%s\"", bskhex);
  
  int journal = strcasecmp(parsed->args[1], "journal")==0;

  if (create_serval_instance_dir() == -1)
    return -1;
  if (!(keyring = keyring_open_instance_cli(parsed)))
    return -1;
  if (rhizome_opendb() == -1)
    return -1;
  
  /* Create a new manifest that will represent the file.  If a manifest file was supplied, then read
   * it, otherwise create a blank manifest. */
  rhizome_manifest *m = rhizome_new_manifest();
  if (!m)
    return WHY("Manifest struct could not be allocated -- not added to rhizome");
  
  if (manifestpath && *manifestpath && access(manifestpath, R_OK) == 0) {
    if (config.debug.rhizome)
      DEBUGF("reading manifest from %s", manifestpath);
    /* Don't verify the manifest, because it will fail if it is incomplete.
       This is okay, because we fill in any missing bits and sanity check before
       trying to write it out. */
    if (rhizome_read_manifest_file(m, manifestpath, 0) == -1) {
      rhizome_manifest_free(m);
      return WHY("Manifest file could not be loaded -- not added to rhizome");
    }
  } else if(manifestid && *manifestid) {
    if (config.debug.rhizome)
      DEBUGF("Reading manifest from database");
    if (rhizome_retrieve_manifest(manifestid, m)){
      rhizome_manifest_free(m);
      return WHY("Existing manifest could not be loaded -- not added to rhizome");
    }
  } else {
    if (config.debug.rhizome)
      DEBUGF("Creating new manifest");
    if (journal){
      m->journalTail = 0;
      rhizome_manifest_set_ll(m,"tail",m->journalTail);
    }
  }

  if (journal && m->journalTail==-1)
    return WHY("Existing manifest is not a journal");

  if ((!journal) && m->journalTail>=0)
    return WHY("Existing manifest is a journal");

  if (rhizome_fill_manifest(m, filepath, *authorSidHex?&authorSid:NULL, bskhex?&bsk:NULL)){
    rhizome_manifest_free(m);
    return -1;
  }

  if (journal){
    if (rhizome_append_journal_file(m, bskhex?&bsk:NULL, 0, filepath)){
      rhizome_manifest_free(m);
      return -1;
    }
  }else{
    if (rhizome_stat_file(m, filepath)){
      rhizome_manifest_free(m);
      return -1;
    }
  
    if (m->fileLength){
      if (rhizome_add_file(m, filepath)){
        rhizome_manifest_free(m);
        return -1;
      }
    }
  }
  
  rhizome_manifest *mout = NULL;
  int ret=rhizome_manifest_finalise(m,&mout);
  if (ret<0){
    rhizome_manifest_free(m);
    return -1;
  }
  
  if (manifestpath && *manifestpath
      && rhizome_write_manifest_file(mout, manifestpath, 0) == -1)
    ret = WHY("Could not overwrite manifest file.");
  const char *service = rhizome_manifest_get(mout, "service", NULL, 0);
  if (service) {
    cli_field_name(context, "service", ":");
    cli_put_string(context, service, "\n");
  }
  {
    char bid[RHIZOME_MANIFEST_ID_STRLEN + 1];
    rhizome_bytes_to_hex_upper(mout->cryptoSignPublic, bid, RHIZOME_MANIFEST_ID_BYTES);
    cli_field_name(context, "manifestid", ":");
    cli_put_string(context, bid, "\n");
  }
  {
    char secret[RHIZOME_BUNDLE_KEY_STRLEN + 1];
    rhizome_bytes_to_hex_upper(mout->cryptoSignSecret, secret, RHIZOME_BUNDLE_KEY_BYTES);
    cli_field_name(context, "secret", ":");
    cli_put_string(context, secret, "\n");
  }
  cli_field_name(context, "version", ":");
  cli_put_long(context, m->version, "\n");
  cli_field_name(context, "filesize", ":");
  cli_put_long(context, mout->fileLength, "\n");
  if (mout->fileLength != 0) {
    cli_field_name(context, "filehash", ":");
    cli_put_string(context, mout->fileHexHash, "\n");
  }
  const char *name = rhizome_manifest_get(mout, "name", NULL, 0);
  if (name) {
    cli_field_name(context, "name", ":");
    cli_put_string(context, name, "\n");
  }
  if (mout != m)
    rhizome_manifest_free(mout);
  rhizome_manifest_free(m);
  return ret;
}

int app_slip_test(const struct cli_parsed *parsed, struct cli_context *context)
{
  const char *seed = NULL;
  const char *iterations = NULL;
  const char *duration = NULL;
  if (   cli_arg(parsed, "--seed", &seed, cli_uint, NULL) == -1
      || cli_arg(parsed, "--duration", &duration, cli_uint, NULL) == -1
      || cli_arg(parsed, "--iterations", &iterations, cli_uint, NULL) == -1)
    return -1;
  if (seed)
    srandom(atoi(seed));
  int maxcount = iterations ? atoi(iterations) : duration ? 0 : 1000;
  time_ms_t start = duration ? gettime_ms() : 0;
  time_ms_t end = duration ? start + atoi(duration) * (time_ms_t) 1000 : 0;
  int count;
  for (count = 0; maxcount == 0 || count < maxcount; ++count) {    
    if (end && gettime_ms() >= end)
      break;
    unsigned char bufin[8192];
    unsigned char bufout[8192];
    int len=1+random()%1500;
    int i;
    for(i=0;i<len;i++) bufin[i]=random()&0xff;
    struct slip_decode_state state;
    bzero(&state,sizeof state);
    int outlen=slip_encode(SLIP_FORMAT_UPPER7,bufin,len,bufout,8192);
    for(i=0;i<outlen;i++) upper7_decode(&state,bufout[i]);
    uint32_t crc=Crc32_ComputeBuf( 0, state.dst, state.packet_length);
    if (crc!=state.crc) {
      WHYF("CRC error (%08x vs %08x)",crc,state.crc);
      dump("input",bufin,len);
      dump("encoded",bufout,outlen);
      dump("decoded",state.dst,state.packet_length);
      return 1;
    } else { 
      if (!(count%1000))
	cli_printf(context, "."); cli_flush(context); 
    }   
  }
  cli_printf(context, "Test passed.\n");
  return 0;
}

int app_rhizome_import_bundle(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  const char *filepath, *manifestpath;
  cli_arg(parsed, "filepath", &filepath, NULL, "");
  cli_arg(parsed, "manifestpath", &manifestpath, NULL, "");
  if (rhizome_opendb() == -1)
    return -1;
  
  rhizome_manifest *m = rhizome_new_manifest();
  if (!m)
    return WHY("Out of manifests.");
  
  int status=rhizome_bundle_import_files(m, manifestpath, filepath);
  if (status<0)
    goto cleanup;
  
  // TODO generalise the way we dump manifest details from add, import & export
  // so callers can also generalise their parsing
  
  const char *service = rhizome_manifest_get(m, "service", NULL, 0);
  if (service) {
    cli_field_name(context, "service", ":");
    cli_put_string(context, service, "\n");
  }
  {
    cli_field_name(context, "manifestid", ":");
    cli_put_string(context, alloca_tohex(m->cryptoSignPublic, RHIZOME_MANIFEST_ID_BYTES), "\n");
  }
  cli_field_name(context, "version", ":");
  cli_put_long(context, m->version, "\n");
  cli_field_name(context, "filesize", ":");
  cli_put_long(context, m->fileLength, "\n");
  if (m->fileLength != 0) {
    cli_field_name(context, "filehash", ":");
    cli_put_string(context, m->fileHexHash, "\n");
  }
  const char *name = rhizome_manifest_get(m, "name", NULL, 0);
  if (name) {
    cli_field_name(context, "name", ":");
    cli_put_string(context, name, "\n");
  }
  
cleanup:
  rhizome_manifest_free(m);
  return status;
}

int app_rhizome_append_manifest(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  const char *manifestpath, *filepath;
  if ( cli_arg(parsed, "manifestpath", &manifestpath, NULL, "") == -1
    || cli_arg(parsed, "filepath", &filepath, NULL, "") == -1)
    return -1;
  
  rhizome_manifest *m = rhizome_new_manifest();
  if (!m)
    return WHY("Out of manifests.");
  
  int ret=0;
  if (rhizome_read_manifest_file(m, manifestpath, 0))
    ret=-1;
  // TODO why doesn't read manifest file set finalised???
  m->finalised=1;
  
  if (ret==0 && rhizome_write_manifest_file(m, filepath, 1) == -1)
    ret = -1;
  
  if (m)
    rhizome_manifest_free(m);
  return ret;
}

int app_rhizome_delete(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  const char *manifestid, *fileid;
  if (cli_arg(parsed, "manifestid", &manifestid, cli_manifestid, NULL) == -1)
    return -1;
  if (cli_arg(parsed, "fileid", &fileid, cli_fileid, NULL) == -1)
    return -1;
  /* Ensure the Rhizome database exists and is open */
  if (create_serval_instance_dir() == -1)
    return -1;
  if (rhizome_opendb() == -1)
    return -1;
  if (!(keyring = keyring_open_instance_cli(parsed)))
    return -1;
  int ret=0;
  if (cli_arg(parsed, "file", NULL, NULL, NULL) == 0) {
    if (!fileid)
      return WHY("missing <fileid> argument");
    unsigned char filehash[RHIZOME_FILEHASH_BYTES];
    if (fromhexstr(filehash, fileid, RHIZOME_FILEHASH_BYTES) == -1)
      return WHY("Invalid file ID");
    char fileIDUpper[RHIZOME_FILEHASH_STRLEN + 1];
    tohex(fileIDUpper, filehash, RHIZOME_FILEHASH_BYTES);
    ret = rhizome_delete_file(fileIDUpper);
  } else {
    if (!manifestid)
      return WHY("missing <manifestid> argument");
    unsigned char manifest_id[RHIZOME_MANIFEST_ID_BYTES];
    if (fromhexstr(manifest_id, manifestid, RHIZOME_MANIFEST_ID_BYTES) == -1)
      return WHY("Invalid manifest ID");
    char manifestIdUpper[RHIZOME_MANIFEST_ID_STRLEN + 1];
    tohex(manifestIdUpper, manifest_id, RHIZOME_MANIFEST_ID_BYTES);
    if (cli_arg(parsed, "bundle", NULL, NULL, NULL) == 0)
      ret = rhizome_delete_bundle(manifestIdUpper);
    else if (cli_arg(parsed, "manifest", NULL, NULL, NULL) == 0)
      ret = rhizome_delete_manifest(manifestIdUpper);
    else if (cli_arg(parsed, "payload", NULL, NULL, NULL) == 0)
      ret = rhizome_delete_payload(manifestIdUpper);
    else
      return WHY("unrecognised command");
  }
  return ret;
}

int app_rhizome_clean(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  int verify = cli_arg(parsed, "verify", NULL, NULL, NULL) == 0;
  if (verify)
    verify_bundles();
  struct rhizome_cleanup_report report;
  if (rhizome_cleanup(&report) == -1)
    return -1;
  cli_field_name(context, "deleted_stale_incoming_files", ":");
  cli_put_long(context, report.deleted_stale_incoming_files, "\n");
  cli_field_name(context, "deleted_orphan_files", ":");
  cli_put_long(context, report.deleted_orphan_files, "\n");
  cli_field_name(context, "deleted_orphan_fileblobs", ":");
  cli_put_long(context, report.deleted_orphan_fileblobs, "\n");
  return 0;
}

int app_rhizome_extract(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  const char *manifestpath, *filepath, *manifestid, *bskhex;
  if (   cli_arg(parsed, "manifestid", &manifestid, cli_manifestid, "") == -1
      || cli_arg(parsed, "manifestpath", &manifestpath, NULL, "") == -1
      || cli_arg(parsed, "filepath", &filepath, NULL, "") == -1
      || cli_arg(parsed, "bsk", &bskhex, cli_optional_bundle_key, NULL) == -1)
    return -1;
  
  int extract = strcasecmp(parsed->args[1], "extract")==0;
  
  /* Ensure the Rhizome database exists and is open */
  if (create_serval_instance_dir() == -1)
    return -1;
  if (rhizome_opendb() == -1)
    return -1;
  
  if (!(keyring = keyring_open_instance_cli(parsed)))
    return -1;
  
  int ret=0;
  
  unsigned char manifest_id[RHIZOME_MANIFEST_ID_BYTES];
  if (fromhexstr(manifest_id, manifestid, RHIZOME_MANIFEST_ID_BYTES) == -1)
    return WHY("Invalid manifest ID");
  
  char manifestIdUpper[RHIZOME_MANIFEST_ID_STRLEN + 1];
  tohex(manifestIdUpper, manifest_id, RHIZOME_MANIFEST_ID_BYTES);
  
  // treat empty string the same as null
  if (bskhex && !*bskhex)
    bskhex=NULL;
  
  rhizome_bk_t bsk;
  if (bskhex && fromhexstr(bsk.binary, bskhex, RHIZOME_BUNDLE_KEY_BYTES) == -1)
    return WHYF("invalid bsk: \"%s\"", bskhex);

  rhizome_manifest *m = rhizome_new_manifest();
  if (m==NULL)
    return WHY("Out of manifests");
  
  ret = rhizome_retrieve_manifest(manifestIdUpper, m);
  
  if (ret==0){
    // ignore errors
    rhizome_extract_privatekey(m, NULL);
    const char *blob_service = rhizome_manifest_get(m, "service", NULL, 0);
    
    cli_field_name(context, "service", ":");    cli_put_string(context, blob_service, "\n");
    cli_field_name(context, "manifestid", ":"); cli_put_string(context, manifestIdUpper, "\n");
    cli_field_name(context, "version", ":");    cli_put_long(context, m->version, "\n");
    cli_field_name(context, "inserttime", ":"); cli_put_long(context, m->inserttime, "\n");
    if (m->haveSecret) {
      cli_field_name(context, ".author", ":");  cli_put_string(context, alloca_tohex_sid(m->author), "\n");
    }
    cli_field_name(context, ".readonly", ":");  cli_put_long(context, m->haveSecret?0:1, "\n");
    cli_field_name(context, "filesize", ":");   cli_put_long(context, m->fileLength, "\n");
    if (m->fileLength != 0) {
      cli_field_name(context, "filehash", ":"); cli_put_string(context, m->fileHexHash, "\n");
    }
  }
  
  int retfile=0;
  
  if (ret==0 && m->fileLength != 0 && filepath && *filepath){
    if (extract){
      // Save the file, implicitly decrypting if required.
      // TODO, this may cause us to search for an author a second time if the above call to rhizome_extract_privatekey failed
      retfile = rhizome_extract_file(m, filepath, bskhex?&bsk:NULL);
    }else{
      // Save the file without attempting to decrypt
      int64_t length;
      retfile = rhizome_dump_file(m->fileHexHash, filepath, &length);
    }
  }
  
  if (ret==0 && manifestpath && *manifestpath){
    if (strcmp(manifestpath, "-") == 0) {
      // always extract a manifest to stdout, even if writing the file itself failed.
      cli_field_name(context, "manifest", ":");
      cli_write(context, m->manifestdata, m->manifest_all_bytes);
      cli_delim(context, "\n");
    } else {
      int append = (strcmp(manifestpath, filepath)==0)?1:0;
      // don't write out the manifest if we were asked to append it and writing the file failed.
      if ((!append) || retfile==0){
	/* If the manifest has been read in from database, the blob is there,
	 and we can lie and say we are finalised and just want to write it
	 out.  TODO: really should have a dirty/clean flag, so that write
	 works if clean but not finalised. */
	m->finalised=1;
	if (rhizome_write_manifest_file(m, manifestpath, append) == -1)
	  ret = -1;
      }
    }
  }
  if (retfile)
    ret = retfile == -1 ? -1 : 1;
  if (m)
    rhizome_manifest_free(m);
  return ret;
}

int app_rhizome_export_file(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  const char *fileid, *filepath;
  if (   cli_arg(parsed, "filepath", &filepath, NULL, "") == -1
      || cli_arg(parsed, "fileid", &fileid, cli_fileid, NULL) == -1)
    return -1;
  if (create_serval_instance_dir() == -1)
    return -1;
  if (rhizome_opendb() == -1)
    return -1;
  if (!rhizome_exists(fileid))
    return 1;
  int64_t length;
  int ret = rhizome_dump_file(fileid, filepath, &length);
  if (ret)
    return ret == -1 ? -1 : 1;
  cli_field_name(context, "filehash", ":");
  cli_put_string(context, fileid, "\n");
  cli_field_name(context, "filesize", ":");
  cli_put_long(context, length, "\n");
  return 0;
}

int app_rhizome_list(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  const char *service, *name, *sender_sid, *recipient_sid, *offset, *limit;
  cli_arg(parsed, "service", &service, NULL, "");
  cli_arg(parsed, "name", &name, NULL, "");
  cli_arg(parsed, "sender_sid", &sender_sid, cli_optional_sid, "");
  cli_arg(parsed, "recipient_sid", &recipient_sid, cli_optional_sid, "");
  cli_arg(parsed, "offset", &offset, cli_uint, "0");
  cli_arg(parsed, "limit", &limit, cli_uint, "0");
  /* Create the instance directory if it does not yet exist */
  if (create_serval_instance_dir() == -1)
    return -1;
  if (!(keyring = keyring_open_instance_cli(parsed)))
    return -1;
  if (rhizome_opendb() == -1)
    return -1;
  return rhizome_list_manifests(context, service, name, sender_sid, recipient_sid, atoi(offset), atoi(limit), 0);
}

int app_keyring_create(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  keyring_file *k = keyring_open_instance();
  if (!k)
    return -1;
  keyring_free(k);
  return 0;
}

int app_keyring_dump(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  const char *path;
  if (cli_arg(parsed, "file", &path, cli_path_regular, NULL) == -1)
    return -1;
  int include_secret = 0 == cli_arg(parsed, "--secret", NULL, NULL, NULL);
  keyring_file *k = keyring_open_instance_cli(parsed);
  if (!k)
    return -1;
  FILE *fp = path ? fopen(path, "w") : stdout;
  if (fp == NULL) {
    WHYF_perror("fopen(%s, \"w\")", alloca_str_toprint(path));
    keyring_free(k);
    return -1;
  }
  int ret = keyring_dump(k, XPRINTF_STDIO(fp), include_secret);
  if (fp != stdout && fclose(fp) == EOF) {
    WHYF_perror("fclose(%s)", alloca_str_toprint(path));
    keyring_free(k);
    return -1;
  }
  keyring_free(k);
  return ret;
}

int app_keyring_load(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  const char *path;
  if (cli_arg(parsed, "file", &path, cli_path_regular, NULL) == -1)
    return -1;
  const char *kpin;
  if (cli_arg(parsed, "keyring-pin", &kpin, NULL, "") == -1)
    return -1;
  unsigned pinc = 0;
  unsigned i;
  for (i = 0; i < parsed->labelc; ++i)
    if (strn_str_cmp(parsed->labelv[i].label, parsed->labelv[i].len, "entry-pin") == 0)
      ++pinc;
  const char *pinv[pinc];
  unsigned pc = 0;
  for (i = 0; i < parsed->labelc; ++i)
    if (strn_str_cmp(parsed->labelv[i].label, parsed->labelv[i].len, "entry-pin") == 0) {
      assert(pc < pinc);
      pinv[pc++] = parsed->labelv[i].text;
    }
  keyring_file *k = keyring_open_instance_cli(parsed);
  if (!k)
    return -1;
  FILE *fp = path && strcmp(path, "-") != 0 ? fopen(path, "r") : stdin;
  if (fp == NULL) {
    WHYF_perror("fopen(%s, \"r\")", alloca_str_toprint(path));
    keyring_free(k);
    return -1;
  }
  if (keyring_load(k, kpin, pinc, pinv, fp) == -1) {
    keyring_free(k);
    return -1;
  }
  if (keyring_commit(k) == -1) {
    keyring_free(k);
    return WHY("Could not write new identity");
  }
  keyring_free(k);
  return 0;
}

int app_keyring_list(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  keyring_file *k = keyring_open_instance_cli(parsed);
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
	cli_put_string(context, alloca_tohex_sid(sid), ":");
	cli_put_string(context, did, ":");
	cli_put_string(context, name, "\n");
      }
    }
  keyring_free(k);
  return 0;
 }

int app_keyring_add(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  const char *pin;
  cli_arg(parsed, "pin", &pin, NULL, "");
  keyring_file *k = keyring_open_instance_cli(parsed);
  if (!k)
    return -1;
  keyring_enter_pin(k, pin);
  const keyring_identity *id = keyring_create_identity(k, k->contexts[k->context_count - 1], pin);
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
  cli_field_name(context, "sid", ":");
  cli_put_string(context, alloca_tohex_sid(sid), "\n");
  if (did) {
    cli_field_name(context, "did", ":");
    cli_put_string(context, did, "\n");
  }
  if (name) {
    cli_field_name(context, "name", ":");
    cli_put_string(context, name, "\n");
  }
  keyring_free(k);
  return 0;
}

int app_keyring_set_did(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  const char *sidhex, *did, *name;
  cli_arg(parsed, "sid", &sidhex, str_is_subscriber_id, "");
  cli_arg(parsed, "did", &did, cli_optional_did, "");
  cli_arg(parsed, "name", &name, NULL, "");

  if (strlen(name)>63) return WHY("Name too long (31 char max)");

  if (!(keyring = keyring_open_instance_cli(parsed)))
    return -1;

  sid_t sid;
  if (str_to_sid_t(&sid, sidhex) == -1)
    return WHY("str_to_sid_t() failed");

  int cn=0,in=0,kp=0;
  int r=keyring_find_sid(keyring, &cn, &in, &kp, sid.binary);
  if (!r) return WHY("No matching SID");
  if (keyring_set_did(keyring->contexts[cn]->identities[in], did, name))
    return WHY("Could not set DID");
  if (keyring_commit(keyring))
    return WHY("Could not write updated keyring record");

  cli_field_name(context, "sid", ":");
  cli_put_string(context, alloca_tohex_sid(sid.binary), "\n");
  if (did) {
    cli_field_name(context, "did", ":");
    cli_put_string(context, did, "\n");
  }
  if (name) {
    cli_field_name(context, "name", ":");
    cli_put_string(context, name, "\n");
  }
  keyring_free(keyring);
  return 0;
}

int app_id_self(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  /* List my own identities */
  overlay_mdp_frame a;
  bzero(&a, sizeof(overlay_mdp_frame));
  int result;
  int count=0;

  a.packetTypeAndFlags=MDP_GETADDRS;
  const char *arg = parsed->labelc ? parsed->labelv[0].text : "";
  if (!strcasecmp(arg,"self"))
    a.addrlist.mode = MDP_ADDRLIST_MODE_SELF; /* get own identities */
  else if (!strcasecmp(arg,"allpeers"))
    a.addrlist.mode = MDP_ADDRLIST_MODE_ALL_PEERS; /* get all known peers */
  else if (!strcasecmp(arg,"peers"))
    a.addrlist.mode = MDP_ADDRLIST_MODE_ROUTABLE_PEERS; /* get routable (reachable) peers */
  else
    return WHYF("unsupported arg '%s'", arg);
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
      cli_printf(context, "%s", alloca_tohex_sid(a.addrlist.sids[i])); cli_delim(context, "\n");
    }
    /* get ready to ask for next block of SIDs */
    a.packetTypeAndFlags=MDP_GETADDRS;
    a.addrlist.first_sid=a.addrlist.last_sid+1;
  }while(a.addrlist.frame_sid_count==MDP_MAX_SID_REQUEST);

  return 0;
}

int app_count_peers(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  overlay_mdp_frame a;
  bzero(&a, sizeof(overlay_mdp_frame));
  a.packetTypeAndFlags=MDP_GETADDRS;
  a.addrlist.mode = MDP_ADDRLIST_MODE_ROUTABLE_PEERS;
  a.addrlist.first_sid = OVERLAY_MDP_ADDRLIST_MAX_SID_COUNT;
  if (overlay_mdp_send(&a,MDP_AWAITREPLY,5000)){
    if (a.packetTypeAndFlags==MDP_ERROR)
      return WHYF("  MDP Server error #%d: '%s'",a.error.error,a.error.message);
    return WHYF("Failed to send request");
  }
  cli_put_long(context, a.addrlist.server_sid_count, "\n");
  return 0;
}

int app_byteorder_test(const struct cli_parsed *parsed, struct cli_context *context)
{
  uint64_t in=0x1234;
  uint64_t out;

  unsigned char bytes[8];

  write_uint64(&bytes[0],in);
  out=read_uint64(&bytes[0]);
  if (in!=out)
    cli_printf(context,"Byte order mangled (0x%016"PRIx64" should have been %016"PRIx64")\n",
	       out,in);
  else cli_printf(context,"Byte order preserved.\n");
  return -1;
}

int app_crypt_test(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  unsigned char nonce[crypto_box_curve25519xsalsa20poly1305_NONCEBYTES];
  unsigned char k[crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES];

  unsigned char plain_block[65536];

  urandombytes(nonce,sizeof(nonce));
  urandombytes(k,sizeof(k));

  int len,i;

  cli_printf(context, "Benchmarking CryptoBox Auth-Cryption:\n");
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
    cli_printf(context, "%d bytes - %d tests took %lldms - mean time = %.2fms\n",
	   len, i, (long long) end - start, each);
    /* Auto-reduce number of repeats so that it doesn't take too long on the phone */
    if (each>1.00) count/=2;
  }


  cli_printf(context, "Benchmarking CryptoSign signature verification:\n");
  {

    unsigned char sign_pk[crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES];
    unsigned char sign_sk[crypto_sign_edwards25519sha512batch_SECRETKEYBYTES];
    if (crypto_sign_edwards25519sha512batch_keypair(sign_pk,sign_sk))
      return WHY("crypto_sign_curve25519xsalsa20poly1305_keypair() failed.\n");

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
      if (r)
        return WHY("crypto_sign_edwards25519sha512batch() failed.\n");
    }

    time_ms_t end=gettime_ms();
    cli_printf(context, "mean signature generation time = %.2fms\n",
  	   (end-start)*1.0/i);
    start = gettime_ms();

    for(i=0;i<10;i++) {
      bzero(&plainTextOut,1024); plainLenOut=0;
      int r=crypto_sign_edwards25519sha512batch_open(plainTextOut,&plainLenOut,
						 &cipherText[0],cipherLen,
						 sign_pk);
      if (r)
	return WHYF("crypto_sign_edwards25519sha512batch_open() failed (r=%d, i=%d).\n",
		r,i);
    }
    end = gettime_ms();
    cli_printf(context, "mean signature verification time = %.2fms\n",
	   (end-start)*1.0/i);
  }

  /* We can't do public signing with a crypto_box key, but we should be able to
     do shared-secret generation using crypto_sign keys. */
  {
    cli_printf(context, "Testing supercop-20120525 Ed25519 CryptoSign implementation:\n");

    unsigned char sign1_pk[crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES];
    unsigned char sign1_sk[crypto_sign_edwards25519sha512batch_SECRETKEYBYTES];
    if (crypto_sign_edwards25519sha512batch_keypair(sign1_pk,sign1_sk))
      return WHY("crypto_sign_edwards25519sha512batch_keypair() failed.\n");

    /* Try calculating public key from secret key */
    unsigned char pk[crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES];

    /* New Ed25519 implementation has public key as 2nd half of private key. */
    bcopy(&sign1_sk[32],pk,32);

    if (memcmp(pk, sign1_pk, crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES)) {
      WHY("Could not calculate public key from private key.\n");
      dump("calculated",&pk,sizeof(pk));
      dump("original",&sign1_pk,sizeof(sign1_pk));
    } else
      cli_printf(context, "Can calculate public key from private key.\n");

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
    if (r)
      return WHY("crypto_sign_edwards25519sha512batch() failed.\n");
  
    dump("signature",cipherText,cipherLen);
   
    unsigned char casabamelons[128]={
      0xa4,0xea,0xd0,0x7f,0x11,0x65,0x28,0x3f,0x90,0x45,0x87,0xbf,0xe5,0xb9,0x15,0x2a,0x9a,0x2d,0x99,0x35,0x0d,0x0e,0x7b,0xb0,0xcd,0x15,0x2e,0xe8,0xeb,0xb3,0xc2,0xb1,0x13,0x8e,0xe3,0x82,0x55,0x6c,0x6e,0x34,0x44,0xe4,0xbc,0xa3,0xd5,0xe0,0x7a,0x6a,0x67,0x61,0xda,0x79,0x67,0xb6,0x1c,0x2e,0x48,0xc7,0x28,0x5b,0xd8,0xd0,0x54,0x0c,0x4e,0x6f,0x20,0x63,0x61,0x73,0x61,0x62,0x61,0x20,0x6d,0x65,0x6c,0x6f,0x6e,0x73,0x20,0x61,0x6c,0x6c,0x6f,0x77,0x65,0x64,0x20,0x69,0x6e,0x20,0x74,0x68,0x65,0x20,0x6c,0x61,0x62,0x2e,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
    };
    
    if (cipherLen!=128||memcmp(casabamelons, cipherText, 128)) {
      WHY("Computed signature for stored key+message does not match expected value.\n");
      dump("expected signature",casabamelons,sizeof(casabamelons));
    }
  
    bzero(&plainTextOut,1024); plainLenOut=0;
    r=crypto_sign_edwards25519sha512batch_open(plainTextOut,&plainLenOut,
					       &casabamelons[0],128,
					       /* the public key, which is the 2nd
						  half of the secret key. */
					       &key[32]);
    if (r)
      WHY("Cannot open rearranged ref/ version of signature.\n");
    else
      cli_printf(context, "Signature open fine.\n");

  }
  
  return 0;
}

int app_route_print(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  overlay_mdp_frame mdp;
  bzero(&mdp,sizeof(mdp));
  
  mdp.packetTypeAndFlags=MDP_ROUTING_TABLE;
  overlay_mdp_send(&mdp,0,0);
  
  const char *names[]={
    "Subscriber id",
    "Routing flags",
    "Interface",
    "Next hop"
  };
  cli_columns(context, 4, names);
  
  while(overlay_mdp_client_poll(200)){
    overlay_mdp_frame rx;
    int ttl;
    if (overlay_mdp_recv(&rx, 0, &ttl))
      continue;
    
    int ofs=0;
    while(ofs + sizeof(struct overlay_route_record) <= rx.out.payload_length){
      struct overlay_route_record *p=(struct overlay_route_record *)&rx.out.payload[ofs];
      ofs+=sizeof(struct overlay_route_record);
      
      if (p->reachable==REACHABLE_NONE)
	continue;

      cli_put_string(context, alloca_tohex_sid(p->sid), ":");
      char flags[32];
      strbuf b = strbuf_local(flags, sizeof flags);
      
      switch (p->reachable){
	case REACHABLE_SELF:
	  strbuf_puts(b, "SELF");
	  break;
	case REACHABLE_BROADCAST:
	  strbuf_puts(b, "BROADCAST");
	  break;
	case REACHABLE_UNICAST:
	  strbuf_puts(b, "UNICAST");
	  break;
	case REACHABLE_INDIRECT:
	  strbuf_puts(b, "INDIRECT");
	  break;
	default:
	  strbuf_sprintf(b, "%d", p->reachable);
      }
      cli_put_string(context, strbuf_str(b), ":");
      cli_put_string(context, p->interface_name, ":");
      cli_put_string(context, alloca_tohex_sid(p->neighbour), "\n");
    }
  }
  return 0;
}

int app_reverse_lookup(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  const char *sidhex, *delay;
  if (cli_arg(parsed, "sid", &sidhex, str_is_subscriber_id, "") == -1)
    return -1;
  if (cli_arg(parsed, "timeout", &delay, NULL, "3000") == -1)
    return -1;

  int port=32768+(random()&0xffff);

  sid_t srcsid;
  sid_t dstsid;

  if (str_to_sid_t(&dstsid, sidhex) == -1)
    return WHY("str_to_sid_t() failed");

  if (overlay_mdp_getmyaddr(0, &srcsid))
    return WHY("Unable to get my address");
  if (overlay_mdp_bind(&srcsid, port))
    return WHY("Unable to bind port");

  time_ms_t now = gettime_ms();
  time_ms_t timeout = now + atoi(delay);
  time_ms_t next_send = now;
  overlay_mdp_frame mdp_reply;
  
  while (now < timeout){
    now=gettime_ms();
    
    if (now >= next_send){
      /* Send a unicast packet to this node, asking for any did */
      lookup_send_request(&srcsid, port, &dstsid, "");
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
    if (memcmp(mdp_reply.in.src.sid, dstsid.binary, sizeof dstsid.binary)){
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
      cli_field_name(context, "sid", ":");
      cli_put_string(context, sidhex, ":");
      cli_field_name(context, "did", ":");
      cli_put_string(context, did, "\n");
      cli_field_name(context, "name", ":");
      cli_put_string(context, name, "\n");
      return 0;
    }
  }
  return 1;
}

int app_network_scan(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  overlay_mdp_frame mdp;
  bzero(&mdp,sizeof(mdp));
  
  mdp.packetTypeAndFlags=MDP_SCAN;
  
  struct overlay_mdp_scan *scan = (struct overlay_mdp_scan *)&mdp.raw;
  const char *address;
  if (cli_arg(parsed, "address", &address, NULL, NULL) == -1)
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
  cli_put_string(context, mdp.error.message, "\n");
  return mdp.error.error;
}

/* See cli_parse() for details of command specification syntax.
*/
#define KEYRING_PIN_OPTION	  ,"[--keyring-pin=<pin>]"
#define KEYRING_ENTRY_PIN_OPTION  ,"[--entry-pin=<pin>]"
#define KEYRING_PIN_OPTIONS	  KEYRING_PIN_OPTION KEYRING_ENTRY_PIN_OPTION "..."
struct cli_schema command_line_options[]={
  {commandline_usage,{"help|-h|--help","...",NULL},CLIFLAG_PERMISSIVE_CONFIG,
   "Display command usage."},
  {app_echo,{"echo","[-e]","[--]","...",NULL},CLIFLAG_PERMISSIVE_CONFIG,
   "Output the supplied string."},
  {app_log,{"log","error|warn|hint|info|debug","<message>",NULL},CLIFLAG_PERMISSIVE_CONFIG,
   "Log the supplied message at given level."},
  {app_server_start,{"start" KEYRING_PIN_OPTIONS, "[foreground|exec <path>]",NULL}, 0,
   "Start daemon with instance path from SERVALINSTANCE_PATH environment variable."},
  {app_server_stop,{"stop",NULL},CLIFLAG_PERMISSIVE_CONFIG,
   "Stop a running daemon with instance path from SERVALINSTANCE_PATH environment variable."},
  {app_server_status,{"status",NULL},CLIFLAG_PERMISSIVE_CONFIG,
   "Display information about running daemon."},
  {app_mdp_ping,{"mdp","ping","[--interval=<ms>]","[--timeout=<seconds>]","<SID>|broadcast","[<count>]",NULL}, 0,
   "Attempts to ping specified node via Mesh Datagram Protocol (MDP)."},
  {app_trace,{"mdp","trace","<SID>",NULL}, 0,
   "Trace through the network to the specified node via MDP."},
  {app_config_schema,{"config","schema",NULL},CLIFLAG_PERMISSIVE_CONFIG,
   "Display configuration schema."},
  {app_config_dump,{"config","dump","[--full]",NULL},CLIFLAG_PERMISSIVE_CONFIG,
   "Dump configuration settings."},
  {app_config_set,{"config","set","<variable>","<value>","...",NULL},CLIFLAG_PERMISSIVE_CONFIG,
   "Set and del specified configuration variables."},
  {app_config_set,{"config","del","<variable>","...",NULL},CLIFLAG_PERMISSIVE_CONFIG,
   "Del and set specified configuration variables."},
  {app_config_get,{"config","get","[<variable>]",NULL},CLIFLAG_PERMISSIVE_CONFIG,
   "Get specified configuration variable."},
  {app_vomp_console,{"console",NULL}, 0,
    "Test phone call life-cycle from the console"},
  {app_meshms_conversations,{"meshms","list","conversations" KEYRING_PIN_OPTIONS, "<sid>","[<offset>]","[<count>]",NULL},0,
   "List MeshMS threads that include <sid>"},
  {app_meshms_list_messages,{"meshms","list","messages" KEYRING_PIN_OPTIONS, "<sender_sid>","<recipient_sid>",NULL},0,
   "List MeshMS messages between <sender_sid> and <recipient_sid>"},
  {app_meshms_send_message,{"meshms","send","message" KEYRING_PIN_OPTIONS, "<sender_sid>", "<recipient_sid>", "<payload>",NULL},0,
   "Send a MeshMS message from <sender_sid> to <recipient_sid>"},
  {app_meshms_mark_read,{"meshms","read","messages" KEYRING_PIN_OPTIONS, "<sender_sid>", "[<recipient_sid>]", "[<offset>]",NULL},0,
   "Mark incoming messages from this recipient as read."},
  {app_rhizome_append_manifest, {"rhizome", "append", "manifest", "<filepath>", "<manifestpath>", NULL}, 0,
    "Append a manifest to the end of the file it belongs to."},
  {app_rhizome_hash_file,{"rhizome","hash","file","<filepath>",NULL}, 0,
   "Compute the Rhizome hash of a file"},
  {app_rhizome_add_file,{"rhizome","add","file" KEYRING_PIN_OPTIONS,"<author_sid>","<filepath>","[<manifestpath>]","[<bsk>]",NULL}, 0,
	"Add a file to Rhizome and optionally write its manifest to the given path"},
  {app_rhizome_add_file, {"rhizome", "journal", "append" KEYRING_PIN_OPTIONS, "<author_sid>", "<manifestid>", "<filepath>", "[<bsk>]", NULL}, 0,
	"Append content to a journal bundle"},
  {app_rhizome_import_bundle,{"rhizome","import","bundle","<filepath>","<manifestpath>",NULL}, 0,
	"Import a payload/manifest pair into Rhizome"},
  {app_rhizome_list,{"rhizome","list" KEYRING_PIN_OPTIONS,
	"[<service>]","[<name>]","[<sender_sid>]","[<recipient_sid>]","[<offset>]","[<limit>]",NULL}, 0,
	"List all manifests and files in Rhizome"},
  {app_rhizome_extract,{"rhizome","export","bundle" KEYRING_PIN_OPTIONS,
	"<manifestid>","[<manifestpath>]","[<filepath>]",NULL}, 0,
	"Export a manifest and payload file to the given paths, without decrypting."},
  {app_rhizome_extract,{"rhizome","export","manifest" KEYRING_PIN_OPTIONS,
	"<manifestid>","[<manifestpath>]",NULL}, 0,
	"Export a manifest from Rhizome and write it to the given path"},
  {app_rhizome_export_file,{"rhizome","export","file","<fileid>","[<filepath>]",NULL}, 0,
	"Export a file from Rhizome and write it to the given path without attempting decryption"},
  {app_rhizome_extract,{"rhizome","extract","bundle" KEYRING_PIN_OPTIONS,
	"<manifestid>","[<manifestpath>]","[<filepath>]","[<bsk>]",NULL}, 0,
	"Extract and decrypt a manifest and file to the given paths."},
  {app_rhizome_extract,{"rhizome","extract","file" KEYRING_PIN_OPTIONS,
	"<manifestid>","[<filepath>]","[<bsk>]",NULL}, 0,
        "Extract and decrypt a file from Rhizome and write it to the given path"},
  {app_rhizome_delete,{"rhizome","delete","manifest|payload|bundle","<manifestid>",NULL}, 0,
	"Remove the manifest, or payload, or both for the given Bundle ID from the Rhizome store"},
  {app_rhizome_delete,{"rhizome","delete","|file","<fileid>",NULL}, 0,
	"Remove the file with the given hash from the Rhizome store"},
  {app_rhizome_direct_sync,{"rhizome","direct","sync","[<url>]",NULL}, 0,
	"Synchronise with the specified Rhizome Direct server. Return when done."},
  {app_rhizome_direct_sync,{"rhizome","direct","push","[<url>]",NULL}, 0,
	"Deliver all new content to the specified Rhizome Direct server. Return when done."},
  {app_rhizome_direct_sync,{"rhizome","direct","pull","[<url>]",NULL}, 0,
	"Fetch all new content from the specified Rhizome Direct server. Return when done."},
  {app_rhizome_clean,{"rhizome","clean","[verify]",NULL}, 0,
	"Remove stale and orphaned content from the Rhizome store"},
  {app_keyring_create,{"keyring","create",NULL}, 0,
   "Create a new keyring file."},
  {app_keyring_dump,{"keyring","dump" KEYRING_PIN_OPTIONS,"[--secret]","[<file>]",NULL}, 0,
   "Dump all keyring identities that can be accessed using the specified PINs"},
  {app_keyring_load,{"keyring","load" KEYRING_PIN_OPTIONS,"<file>","[<keyring-pin>]","[<entry-pin>]...",NULL}, 0,
   "Load identities from the given dump text and insert them into the keyring using the specified entry PINs"},
  {app_keyring_list,{"keyring","list" KEYRING_PIN_OPTIONS,NULL}, 0,
   "List identities that can be accessed using the supplied PINs"},
  {app_keyring_add,{"keyring","add" KEYRING_PIN_OPTIONS,"[<pin>]",NULL}, 0,
   "Create a new identity in the keyring protected by the supplied PIN (empty PIN if not given)"},
  {app_keyring_set_did,{"keyring", "set","did" KEYRING_PIN_OPTIONS,"<sid>","<did>","<name>",NULL}, 0,
   "Set the DID for the specified SID (must supply PIN to unlock the SID record in the keyring)"},
  {app_id_self,{"id","self|peers|allpeers",NULL}, 0,
   "Return identity(s) as URIs of own node, or of known routable peers, or all known peers"},
  {app_route_print, {"route","print",NULL}, 0,
  "Print the routing table"},
  {app_network_scan, {"scan","[<address>]",NULL}, 0,
    "Scan the network for serval peers. If no argument is supplied, all local addresses will be scanned."},
  {app_count_peers,{"peer","count",NULL}, 0,
    "Return a count of routable peers on the network"},
  {app_dna_lookup,{"dna","lookup","<did>","[<timeout>]",NULL}, 0,
   "Lookup the subscribers (SID) with the supplied telephone number (DID)."},
  {app_reverse_lookup, {"reverse", "lookup", "<sid>", "[<timeout>]", NULL}, 0,
    "Lookup the phone number (DID) and name of a given subscriber (SID)"},
  {app_monitor_cli,{"monitor",NULL}, 0,
   "Interactive servald monitor interface."},
  {app_crypt_test,{"test","crypt",NULL}, 0,
   "Run cryptography speed test"},
  {app_nonce_test,{"test","nonce",NULL}, 0,
   "Run nonce generation test"},
  {app_byteorder_test,{"test","byteorder",NULL}, 0,
   "Run byte order handling test"},
  {app_slip_test,{"test","slip","[--seed=<N>]","[--duration=<seconds>|--iterations=<N>]",NULL}, 0,
   "Run serial encapsulation test"},
#ifdef HAVE_VOIPTEST
  {app_pa_phone,{"phone",NULL}, 0,
   "Run phone test application"},
#endif
  {NULL,{NULL}}
};
