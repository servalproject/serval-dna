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
#include <sys/stat.h>
#include <sys/time.h>
#include <math.h>
#include <string.h>
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

static int servalNodeRunning(int *pid)
{
  const char *instancepath = serval_instancepath();
  struct stat st;
  int r=stat(instancepath,&st);
  if (r) {
    fprintf(stderr,
	    "ERROR: Instance path '%s' non existant or not accessable.\n"
	    "       Operating system says: %s (errno=%d)\n",
	    instancepath,strerror(errno),errno);
    fprintf(stderr,
	    "       (Set SERVALINSTANCE_PATH to specify an alternate location.)\n");
    return -1;
  }
  if ((st.st_mode&S_IFMT)!=S_IFDIR) {
    fprintf(stderr,
	    "ERROR: Instance path must be a valid directory.\n"
	    "       '%s' is not a directory.\n",instancepath);
    *pid=-1;
    return -1;
  }

  int running=0;
  char filename[1024];
  if (FORM_SERVAL_INSTANCE_PATH(filename, "serval.pid")) {
    FILE *f=fopen(filename,"r");
    if (f) {
      char line[1024];
      line[0]=0; fgets(line,1024,f);    
      *pid = strtoll(line,NULL,10);
      running=*pid;
      if (running) {
	/* Check that process is really running.
	  Some systems don't have /proc (including mac), 
	  so we need to find out some otherway.*/
	running=1; // assume pid means is running for now      
      }
      fclose(f);
    } 
  }

  return running;
}

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

struct outv_field {
  jstring jstr;
};

#define OUTV_BUFFER_ATOM	(8192)
#define OUTC_INCREMENT		(256)

JNIEnv *jni_env = NULL;
int jni_exception = 0;

struct outv_field *outv = NULL;
size_t outc = 0;
size_t outc_limit = 0;

char *outv_buffer = NULL;
char *outv_current = NULL;
char *outv_limit = NULL;

static int outv_growbuf(size_t needed)
{
  size_t newsize = (outv_limit - outv_current < needed) ? (outv_limit - outv_buffer) + needed : 0;
  if (newsize) {
    // Round up to nearest multiple of OUTV_BUFFER_ATOM.
    newsize = newsize + OUTV_BUFFER_ATOM - ((newsize - 1) % OUTV_BUFFER_ATOM + 1);
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
  if (outc == outc_limit) {
    outc_limit += OUTC_INCREMENT;
    size_t newsize = outc_limit * sizeof(struct outv_field);
    outv = realloc(outv, newsize);
  }
  struct outv_field *f = &outv[outc];
  f->jstr = (jstring)(*jni_env)->NewStringUTF(jni_env, outv_buffer);
  outv_current = outv_buffer;
  if (f->jstr == NULL) {
    jni_exception = 1;
    return WHY("Exception thrown from NewStringUTF()");
  }
  ++outc;
  return 0;
}

/* JNI entry point to command line.  See org.servalproject.servald.ServalD class for the Java side.
   JNI method descriptor: "([Ljava/lang/String;)Lorg/servalproject/servald/ServalDResult;"
*/
JNIEXPORT jobject JNICALL Java_org_servalproject_servald_ServalD_command(JNIEnv *env, jobject this, jobjectArray args)
{
  jclass resultClass = NULL;
  jclass stringClass = NULL;
  jmethodID resultConstructorId = NULL;
  jobjectArray outArray = NULL;
  jint status = 0;
  // Enforce non re-entrancy.
  if (jni_env) {
    jclass exceptionClass = NULL;
    if ((exceptionClass = (*env)->FindClass(env, "org/servalproject/servald/ServalDReentranceError")) == NULL)
      return NULL; // exception
    (*env)->ThrowNew(env, exceptionClass, "re-entrancy not supported");
    return NULL;
  }
  // Get some handles to some classes and methods that we use later on.
  if ((resultClass = (*env)->FindClass(env, "org/servalproject/servald/ServalDResult")) == NULL)
    return NULL; // exception
  if ((resultConstructorId = (*env)->GetMethodID(env, resultClass, "<init>", "(I[Ljava/lang/String;)V")) == NULL)
    return NULL; // exception
  if ((stringClass = (*env)->FindClass(env, "java/lang/String")) == NULL)
    return NULL; // exception
  // Construct argv, argc from this method's arguments.
  jsize len = (*env)->GetArrayLength(env, args);
  const char **argv = malloc(sizeof(char*) * (len + 1));
  if (argv == NULL) {
    jclass exceptionClass = NULL;
    if ((exceptionClass = (*env)->FindClass(env, "java/lang/OutOfMemoryError")) == NULL)
      return NULL; // exception
    (*env)->ThrowNew(env, exceptionClass, "malloc returned NULL");
    return NULL;
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
    outc = 0;
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
    return NULL;
  // Pack the output fields into a Java array of strings.
  if ((outArray = (*env)->NewObjectArray(env, outc, stringClass, NULL)) == NULL)
    return NULL; // out of memory exception
  for (i = 0; i != outc; ++i)
    (*env)->SetObjectArrayElement(env, outArray, i, outv[i].jstr);
  // Return the ResultD object constructed with the status integer and the array of output field
  // strings.
  return (*env)->NewObject(env, resultClass, resultConstructorId, status, outArray);
}

#endif /* HAVE_JNI_H */

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
	  fprintf(stderr,"Internal error: command_line_options[%d].word[%d]=\"%s\" not allowed after \"...\"\n", i, j, word);
	  break;
	}
	else if (!(  (wordlen > 2 && word[0] == '<' && word[wordlen-1] == '>')
		  || (wordlen > 4 && word[0] == '[' && word[1] == '<' && word[wordlen-2] == '>' && word[wordlen-1] == ']')
		  || (wordlen > 0)
	)) {
	  fprintf(stderr,"Internal error: command_line_options[%d].word[%d]=\"%s\" is malformed\n", i, j, word);
	  break;
	} else if (word[0] == '<') {
	  ++mandatory;
	  if (optional) {
	    fprintf(stderr,"Internal error: command_line_options[%d].word[%d]=\"%s\" should be optional\n", i, j, word);
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
	  fprintf(stderr,"Ambiguous command line call:\n   ");
	  for(j=0;j<argc;j++) fprintf(stderr," %s",args[j]);
	  fprintf(stderr,"\nMatches the following known command line calls:\n");
	}
	if (ambiguous) {
	  fprintf(stderr,"   ");
	  for(j=0;j<argc;j++) fprintf(stderr," %s",command_line_options[i].words[j]);
	  fprintf(stderr,"\n");
	}
	cli_call=i;
      }
    }

  /* Don't process ambiguous calls */
  if (ambiguous) return -1;
  /* Complain if we found no matching calls */
  if (cli_call<0) return cli_usage();

  /* Otherwise, make call */
  setVerbosity(confValueGet("debug",""));
  return command_line_options[cli_call].function(argc, args, &command_line_options[cli_call]);
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
      if (validator && !(*validator)(value)) {
	fprintf(stderr, "Invalid argument %d '%s': \"%s\"\n", i, argname, value);
	return -1;
      }
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
    outv_end_field();
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

  const char *did;
  if (cli_arg(argc, argv, o, "did", &did, NULL, "*") == -1)
    return -1;

  /* Bind to MDP socket and await confirmation */
  unsigned char srcsid[SID_SIZE];
  int port=32768+(random()&32767);
  if (overlay_mdp_getmyaddr(0,srcsid)) return WHY("Could not get local address");
  printf("binding to %s:%d\n",
	 overlay_render_sid(srcsid),port);
  if (overlay_mdp_bind(srcsid,port)) return WHY("Could not bind to MDP socket");
  WHY("bound port");

  /* use MDP to send the lookup request to MDP_PORT_DNALOOKUP, and wait for
     replies. */
  overlay_mdp_frame mdp;
  bzero(&mdp,sizeof(mdp));

  WHY("polling network");

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
		    fprintf(stderr,"       Error message: %s\n",mdp.error.message);
		  }
		else if (rx.packetTypeAndFlags==MDP_RX)
		  fprintf(stderr,"%s:%s\n",
			  overlay_render_sid(&rx.in.payload[0]),
			  &rx.in.payload[SID_SIZE]);
		if (servalShutdown) break;
	      }
	  }
	if (servalShutdown) break;
	short_timeout=125-(overlay_gettime_ms()-now);
      }
      if (servalShutdown) break;
    }

  return 0;
}

int confValueRotor=0;
char confValue[4][128];
char *confValueGet(char *var,char *defaultValue)
{
  if (!var) return defaultValue;
  int varLen=strlen(var);

  char filename[1024];
  if (!FORM_SERVAL_INSTANCE_PATH(filename, "serval.conf")) {
    fprintf(stderr, "Using default value of %s: %s\n", var, defaultValue);
    return defaultValue;
  }
  FILE *f = fopen(filename,"r");
  if (!f) {
    fprintf(stderr, "Cannot open serval.conf.  Using default value of %s: %s\n", var, defaultValue);
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

int cli_absolute_path(const char *arg)
{
  return arg[0] == '/' && arg[1] != '\0';
}

int app_server_start(int argc, const char *const *argv, struct command_line_option *o)
{
  /* Process optional arguments */
  int foregroundP= (argc >= 3 && !strcasecmp(argv[2], "foreground"));
  if (cli_arg(argc, argv, o, "instance path", &thisinstancepath, cli_absolute_path, NULL) == -1)
    return -1;

  /* Create the instance directory if it does not yet exist */
  if (create_serval_instance_dir() == -1)
    return -1;

  /* Now that we know our instance path, we can ask for the default set of
     network interfaces that we will take interest in. */
  overlay_interface_args(confValueGet("interfaces",""));
  if (strlen(confValueGet("interfaces",""))<1) {
    fprintf(stderr,
	    "WARNING: Noone has told me which network interfaces to listen on.\n"
	    "         You should probably put something in the interfaces setting.\n");
  }

  int pid=-1;
  int running = servalNodeRunning(&pid);
  if (running<0) return -1;
  if (running>0) {
    fprintf(stderr,"ERROR: Serval process already running (pid=%d)\n",pid);
    return -1;
  }
  /* Start the Serval process.
     All server settings will be read by the server process from the
     instance directory when it starts up.
     We can just become the server process ourselves --- no need to fork.
     
  */
  rhizome_datastore_path = serval_instancepath();
  rhizome_opendb();

  overlayMode=1;
  return server(NULL,foregroundP);
}

int app_server_stop(int argc, const char *const *argv, struct command_line_option *o)
{
  if (cli_arg(argc, argv, o, "instance path", &thisinstancepath, cli_absolute_path, NULL) == -1)
    return -1;

  int pid=-1;
  int running = servalNodeRunning(&pid);
  if (running>0) {
    /* Is running, so we can try to kill it.
       This is a little complicated by the fact that we catch most signals
       so that unexpected aborts just restart.
       What we can do is put some code in the signal handler that does abort
       the process if a certain file exists, perhaps instance_path/doshutdown,
       and removes the file.
    */
    if (pid<0) {
      WHY("Could not determine process id of Serval process.  Stale instance perhaps?");
      return -1;
    }

    char stopfile[1024];
    FILE *f;
    if (!(FORM_SERVAL_INSTANCE_PATH(stopfile, "doshutdown") && (f = fopen(stopfile, "w")))) {
      WHY("Could not create shutdown file");
      return -1;
    }
    fclose(f);
    int result=kill(pid,SIGHUP);
    if (!result) {
      fprintf(stderr,"Stop request sent to Serval process.\n");
    } else {
      WHY("Could not send SIGHUP to Serval process.");
      switch (errno) {
      case EINVAL: WHY("This is embarassing, but the operating system says I don't know how to send a signal."); break;
      case EPERM: WHY("I don't have permission to stop the Serval process.  You could try using sudo, or run the stop command as the appropriate user."); break;
      case ESRCH: WHY("The process id I have recorded doesn't seem to exist anymore.  Did someone kill the process without telling me?"); 
	/* Clean up any lingering mess */
	servalShutdownCleanly();
	break;
      default:
	perror("This is reason given by the operating system");
      }
      return -1;
    }

    /* Allow a few seconds for the process to die, and keep an eye on things 
       while this is happening. */
    time_t timeout=time(0)+5;
    while(timeout>time(0)) {
      pid=-1;
      int running = servalNodeRunning(&pid);
      if (running<1) {
	fprintf(stderr,"Serval process appears to have stopped.\n");
	return 0;
      }
    }
    return WHY("I tried to stop it, but it seems that the Serval process is still running.");

  } else {
      return WHY("Serval process for that instance does not appear to be running.");
  }
 
  return WHY("Not implemented");
}

int app_server_status(int argc, const char *const *argv, struct command_line_option *o)
{
  if (cli_arg(argc, argv, o, "instance path", &thisinstancepath, cli_absolute_path, NULL) == -1)
    return -1;
  
  /* Display configuration information */
  char filename[1024];
  FILE *f;
  if (FORM_SERVAL_INSTANCE_PATH(filename, "serval.conf") && (f = fopen(filename, "r"))) {
    char line[1024];
    line[0]=0; fgets(line,1024,f);
    printf("\nServal Mesh configuration:\n");
    while(line[0]) {
      printf("   %s",line);
      line[0]=0; fgets(line,1024,f);
    }
    fclose(f);
  }

  /* Display running status of daemon from serval.pid file */
  int pid=-1;
  int running = servalNodeRunning(&pid);
  if (running<0) return -1;

  printf("For Serval Mesh instance %s:\n", serval_instancepath());
  if (running)
    printf("  Serval mesh process is running (pid=%d)\n",pid);
  else
    printf("  Serval Mesh process not running\n");
  
  return 0;
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
    fprintf(stderr,"WARNING: broadcast ping packets will not be encryped.\n");
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
      fprintf(stderr,"ERROR: Could not dispatch PING frame #%d (error %d)\n",
	      sequence_number-firstSeq,res);
      if (mdp.packetTypeAndFlags==MDP_ERROR) 
	fprintf(stderr,"       Error message: %s\n",mdp.error.message);
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
	    fprintf(stderr,"mdpping: overlay_mdp_recv: %s (code %d)\n",
		    mdp.error.message,mdp.error.error);
	    break;
	  case MDP_RX:
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
	    fprintf(stderr,"mdpping: overlay_mdp_recv: Unexpected MDP frame type"
		    " 0x%x\n",mdp.packetTypeAndFlags);
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

	return 0;
      }
    }
    sequence_number++;
    timeout=now+1000;
  }

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
  const char *s;
  for (s = arg; *s; ++s)
    if (!(isalnum(*s) || *s == '_'))
      return 0;
  return 1;
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

int app_rhizome_add_file(int argc, const char *const *argv, struct command_line_option *o)
{
  const char *filepath, *manifestpath;
  cli_arg(argc, argv, o, "filepath", &filepath, NULL, "");
  cli_arg(argc, argv, o, "manifestpath", &manifestpath, NULL, "");
  /* Ensure the Rhizome database exists and is open */
  if (create_serval_instance_dir() == -1)
    return -1;
  rhizome_datastore_path = serval_instancepath();
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
      - the payload file's basename for "name"
      - current time for "date"
  */
  if (rhizome_manifest_get(m, "name", NULL, 0) == NULL) {
    const char *name = strrchr(filepath, '/');
    name = name ? name + 1 : filepath;
    rhizome_manifest_set(m, "name", name);
  }
  if (rhizome_manifest_get(m, "date", NULL, 0) == NULL) {
    rhizome_manifest_set_ll(m, "date", overlay_gettime_ms());
  }
  /* Add the manifest and its associated file to the Rhizome database, generating an "id" in the
   * process */
  rhizome_manifest *mout = NULL;
  int ret = rhizome_add_manifest(m, &mout, filepath,
				 NULL, // no groups - XXX should allow them
				 255, // ttl - XXX should read from somewhere
				 manifest_file_supplied, // int verifyP
				 1, // int checkFileP
				 1 // int signP
    );
  if (ret == -1)
    return WHY("Manifest not added to Rhizome database");
  /* If successfully added, overwrite the manifest file so that the Java component that is
     invoking this command can read it to obtain feedback on the result. */
  if (manifestpath[0] && rhizome_write_manifest_file(mout, manifestpath) == -1)
    ret = WHY("Could not overwrite manifest file.");
  rhizome_manifest_free(m);
  if (mout != m)
    rhizome_manifest_free(mout);
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
  const char *offset, *limit;
  cli_arg(argc, argv, o, "offset", &offset, cli_uint, "0");
  cli_arg(argc, argv, o, "limit", &limit, cli_uint, "0");
  /* Create the instance directory if it does not yet exist */
  if (create_serval_instance_dir() == -1)
    return -1;
  rhizome_datastore_path = serval_instancepath();
  rhizome_opendb();
  return rhizome_list_manifests(atoi(offset), atoi(limit));
}

int app_keyring_create(int argc, const char *const *argv, struct command_line_option *o)
{
  const char *pin;
  cli_arg(argc, argv, o, "pin,pin ...", &pin, NULL, "");
  keyring_file *k=keyring_open_with_pins(pin);
  if (!k) fprintf(stderr,"keyring create:Failed to create/open keyring file\n");
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
	    if (sid) for(i=0;i<SID_SIZE;i++) printf("%02x",sid[i]);
	    else printf("<blank SID>");
	    if (did) printf(":%s",did); else printf(":<no phone number set>");
	    printf("\n");
	}
      }
  return 0;
 }

int app_keyring_add(int argc, const char *const *argv, struct command_line_option *o)
{
  const char *pin;
  cli_arg(argc, argv, o, "pin", &pin, NULL, "");

  keyring_file *k=keyring_open_with_pins("");
  if (!k) { fprintf(stderr,"keyring add:Failed to create/open keyring file\n");
    return -1; }
  
  if (keyring_create_identity(k,k->contexts[0],(char *)pin)==NULL)
    {
      fprintf(stderr,"Could not create new identity (keyring_create_identity() failed)\n");
      return -1;
    }
  if (keyring_commit(k)) {
    fprintf(stderr,"Could not write new identity (keyring_commit() failed)\n");
    return -1;
  }
  keyring_free(k);
  return 0;
}

int app_keyring_set_did(int argc, const char *const *argv, struct command_line_option *o)
{
  const char *sid, *did, *pin;
  cli_arg(argc, argv, o, "sid", &sid, NULL, "");
  cli_arg(argc, argv, o, "did", &did, NULL, "");
  cli_arg(argc, argv, o, "pin", &pin, NULL, "");

  if (strlen(did)>31) return WHY("DID too long (31 digits max)");

  keyring_file *k=keyring_open_with_pins((char *)pin);
  if (!k) return WHY("Could not open keyring file");

  unsigned char packedSid[SID_SIZE];
  stowSid(packedSid,0,(char *)sid);

  int cn=0,in=0,kp=0;
  int r=keyring_find_sid(k,&cn,&in,&kp,packedSid);
  if (!r) return WHY("No matching SID");
  if (keyring_set_did(k->contexts[cn]->identities[in],(char *)did))
    return WHY("Could not set DID");
  if (keyring_commit(k))
    return WHY("Could not write updated keyring record");

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

   Keep this list alphabetically sorted for user convenience.
*/
command_line_option command_line_options[]={
  {app_dna_lookup,{"dna","lookup","<did>",NULL},CLIFLAG_NONOVERLAY,
   "Lookup the SIP/MDP address of the supplied telephone number (DID)."},
  {cli_usage,{"help",NULL},0,
   "Display command usage."},
  {app_echo,{"echo","...",NULL},CLIFLAG_STANDALONE,
   "Output the supplied string."},
  {app_server_start,{"node","start",NULL},CLIFLAG_STANDALONE,
   "Start Serval Mesh node process with instance path taken from SERVALINSTANCE_PATH environment variable."},
  {app_server_start,{"node","start","in","<instance path>",NULL},CLIFLAG_STANDALONE,
   "Start Serval Mesh node process with given instance path."},
  {app_server_start,{"node","start","foreground",NULL},CLIFLAG_STANDALONE,
   "Start Serval Mesh node process without detatching from foreground."},
  {app_server_start,{"node","start","foreground","in","<instance path>",NULL},CLIFLAG_STANDALONE,
   "Start Serval Mesh node process with given instance path, without detatching from foreground."},
  {app_server_stop,{"node","stop",NULL},0,
   "Stop a running Serval Mesh node process with instance path taken from SERVALINSTANCE_PATH environment variable."},
  {app_server_stop,{"node","stop","in","<instance path>",NULL},0,
   "Stop a running Serval Mesh node process with given instance path."},
  {app_server_status,{"node","status",NULL},0,
   "Display information about any running Serval Mesh node."},
  {app_mdp_ping,{"mdp","ping","<SID|broadcast>",NULL},CLIFLAG_STANDALONE,
   "Attempts to ping specified node via Mesh Datagram Protocol (MDP)."},
  {app_config_set,{"config","set","<variable>","<value>",NULL},CLIFLAG_STANDALONE,
   "Set specified configuration variable."},
  {app_config_del,{"config","del","<variable>",NULL},CLIFLAG_STANDALONE,
   "Set specified configuration variable."},
  {app_config_get,{"config","get","[<variable>]",NULL},CLIFLAG_STANDALONE,
   "Get specified configuration variable."},
  {app_rhizome_add_file,{"rhizome","add","file","<filepath>","[<manifestpath>]",NULL},CLIFLAG_STANDALONE,
   "Add a file to Rhizome and optionally write its manifest to the given path"},
  {app_rhizome_list,{"rhizome","list","[<offset>]","[<limit>]",NULL},CLIFLAG_STANDALONE,
   "List all manifests and files in Rhizome"},
  {app_keyring_create,{"keyring","create",NULL},0,
   "Create a new keyring file."},
  {app_keyring_list,{"keyring","list","[<pin,pin ...>]",NULL},0,
   "List identites in specified key ring that can be accessed using the specified PINs"},
  {app_keyring_add,{"keyring","add","[<pin>]",NULL},CLIFLAG_STANDALONE,
   "Create a new identity in the keyring protected by the provided PIN"},
  {app_keyring_set_did,{"set","did","<sid>","<did>","[<pin>]",NULL},CLIFLAG_STANDALONE,
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
   "Attempt to dial the specified sid and did. Optionally supply the calling number"},
#ifdef HAVE_VOIPTEST
  {app_pa_phone,{"phone",NULL},0,
   "Run phone test application"},
#endif
  {NULL,{NULL}}
};
