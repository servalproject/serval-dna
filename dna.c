/* 
Serval Distributed Numbering Architecture (DNA)
Copyright (C) 2010 Paul Gardner-Stephen 

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
#include "rhizome.h"
#include <stdarg.h>
#include <signal.h>
#include <unistd.h>
#include <dirent.h>

char *gatewayspec=NULL;

char *outputtemplate=NULL;
char *instrumentation_file=NULL;
char *importFile=NULL;

int debug=0;
int timeout=3000; /* 3000ms request timeout */

int serverMode=0;
int clientMode=0;

int returnMultiVars=0;

int hexdigit[16]={'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

int sock=-1;

#ifndef HAVE_BZERO
/* OpenWRT doesn't have bzero */
void bzero(void *m,size_t len)
{
  unsigned char *c=m;
  int i;
  for(i=0;i<len;i++) c[i]=0;
}
#endif

int dump(char *name,unsigned char *addr,int len)
{
  int i,j;
  fprintf(stderr,"Dump of %s\n",name);
  for(i=0;i<len;i+=16) 
    {
      fprintf(stderr,"  %04x :",i);
      for(j=0;j<16&&(i+j)<len;j++) fprintf(stderr," %02x",addr[i+j]);
      for(;j<16;j++) fprintf(stderr,"   ");
      fprintf(stderr,"    ");
      for(j=0;j<16&&(i+j)<len;j++) fprintf(stderr,"%c",addr[i+j]>=' '&&addr[i+j]<0x7f?addr[i+j]:'.');
      fprintf(stderr,"\n");
    }
  return 0;
}

int dumpResponses(struct response_set *responses)
{
  struct response *r;
  if (!responses) {fprintf(stderr,"Response set is NULL\n"); return 0; }
  fprintf(stderr,"Response set claims to contain %d entries.\n",responses->response_count);
  r=responses->responses;
  while(r)
    {
      fprintf(stderr,"  response code 0x%02x\n",r->code);
      if (r->next)
	if (r->next->prev!=r) fprintf(stderr,"    !! response chain is broken\n");
      r=r->next;
    }
  return 0;
}

int setReason(char *fmt, ...)
{
  va_list ap,ap2;
  char msg[8192];

  va_start(ap,fmt);
  va_copy(ap2,ap);

  vsnprintf(msg,8192,fmt,ap2); msg[8191]=0;

  va_end(ap);

  fprintf(stderr,"Error: %s\n",msg);
  return -1;
}


int hexvalue(unsigned char c)
{
  if (c>='0'&&c<='9') return c-'0';
  if (c>='A'&&c<='F') return c-'A'+10;
  if (c>='a'&&c<='f') return c-'a'+10;
  return setReason("Invalid hex digit in SID");
}

int parseAssignment(unsigned char *text,int *var_id,unsigned char *value,int *value_len)
{
  /* Parse an assignment.

     Valid formats are:

     var=@file   - value comes from named file.
     var=[[$]value] - value comes from string, and may be empty.  $ means value is in hex

     Values are length limited to 65535 bytes.
  */

  int i;
  int max_len=*value_len;
  int vlen=0;
  int tlen=strlen((char *)text);

  if (tlen>3072) {
    return setReason("Variable assignment string is too long, use =@file to read value from a file");
  }

  /* Identify which variable */
  *var_id=-1;
  for(i=0;i<tlen;i++) if (text[i]=='=') break;
  
  /* Go through known keyring variables */
  if (!strcasecmp((char *)text,"did")) *var_id=KEYTYPE_DID;

  if (*var_id==-1) return setReason("Illegal variable name in assignment");

  i++;
  switch(text[i])
    {
    case '$': /* hex */
      i++;
      while(i<tlen) {
	int b=hexvalue(text[i++])<<4;
	if (i>=tlen) return setReason("Variable value has an odd number of hex digits.");
	b|=hexvalue(text[i++]);
	if (b<0) return setReason("That doesn't look like hex to me");
	if (vlen>=max_len) return setReason("Variable hex value too long");
	value[vlen++]=b;
      }
      *value_len=vlen;
      return 0;
      break;
    case '@': /* file */
      {
	FILE *f=fopen((char *)&text[i+1],"r");
	int flen;
	fseek(f,0,SEEK_END);
	flen=ftell(f);
	if (flen>max_len) return setReason("Variable value from file too long");
	fseek(f,0,SEEK_SET);
	vlen=fread(value,1,flen,f);
	if (vlen!=flen) return setReason("Could not read all of file");
	fclose(f);
	*value_len=vlen;
	return 0;
      }
      break;
    default: /* literal string */
      vlen=strlen((char *)&text[i]);
      if (vlen>max_len) return setReason("Variable value too long");
      bcopy(&text[i],value,vlen);
      *value_len=vlen;
      return 0;
    }

  return 0;
}

int usage(char *complaint)
{
  fprintf(stderr,"dna: %s\n",complaint);
  fprintf(stderr,"usage:\n");
  fprintf(stderr,"   dna [-v <flags>] -S [-f keyring file] [-N interface,...] [-G gateway specification] [-r rhizome path]\n");
  fprintf(stderr,"or\n");
  fprintf(stderr,"   dna -r <rhizome path> -M <manifest name>\n");
  fprintf(stderr,"or\n");
  fprintf(stderr,"   dna <-d|-s> id -A\n");
  fprintf(stderr,"or\n");
  fprintf(stderr,"   dna <-d|-s> id [-p pin] [-i variable instance] <-R variable[=value]>\n");
  fprintf(stderr,"       [-v <flags>] [-t request timeout in ms] [-O output file name template]\n");
  fprintf(stderr,"or\n");
  fprintf(stderr,"   dna <-d|-s> id [-p pin] [-i variable instance] <-W|-U|-D variable[=[$|@]value]>\n");
  fprintf(stderr,"       [-v <flags>] [-t request timeout in ms]\n");
  fprintf(stderr,"or\n");
  fprintf(stderr,"   dna [-v <flags>] [-t timeout] -d did -C\n");
  fprintf(stderr,"or\n");
  fprintf(stderr,"   dna [-v <flags>] -f <keyring file> -E <export.txt>\n");

  fprintf(stderr,"\n");
  fprintf(stderr,"       -v - Set verbosity.\n");
  fprintf(stderr,"       -A - Ask for address of subscriber.\n");
  fprintf(stderr,"       -b - Specify BATMAN socket to obtain peer list (flaky).\n");
  fprintf(stderr,"       -l - Specify BATMAN socket to obtain peer list (better, but requires Serval patched BATMAN).\n");
  fprintf(stderr,"       -L - Log mesh statistics to specified file.\n");
  fprintf(stderr,"       -m - Return multiple variable values instead of only first response.\n");
  fprintf(stderr,"       -M - Create and import a new bundle from the specified manifest.\n");
  fprintf(stderr,"       -n - Do not detach from foreground in server mode.\n");
  fprintf(stderr,"       -S - Run in server mode.\n");
  fprintf(stderr,"       -f - Location of keyring file.\n");
  fprintf(stderr,"       -d - Search by Direct Inward Dial (DID) number.\n");
  fprintf(stderr,"       -s - Search by Subscriber ID (SID) number.\n");
  fprintf(stderr,"       -p - Specify additional DNA nodes to query.\n");
  fprintf(stderr,"       -P - Authenticate using the supplied pin.\n");
  fprintf(stderr,"       -r - Enable Rhizome store-and-forward transport using the specified data store directory.\n");
  fprintf(stderr,"            To limit the storage: echo space=[KB] > path/rhizome.conf\n");
  fprintf(stderr,"       -R - Read a variable value.\n");
  fprintf(stderr,"       -O - Place read variable value into files using argument as a template.\n");
  fprintf(stderr,"            The following template codes can be used (interpretted by sprintf):\n");
  fprintf(stderr,"               %%1$s - Subscriber ID\n");
  fprintf(stderr,"               %%2$d - Variable ID (0-255)\n");
  fprintf(stderr,"               %%3$d - Variable instance number (0-255)\n");
  fprintf(stderr,"       -W - Write a variable value, keeping previous values.\n");
  fprintf(stderr,"       -U - Update a variable value, replacing the previous value.\n");
  fprintf(stderr,"       -D - Delete a variable value.\n");
  fprintf(stderr,"            $value means interpret value as hexidecimal bytes.\n");
  fprintf(stderr,"            @value means read value from file called value.\n");
  fprintf(stderr,"       -C - Request the creation of a new subscriber with the specified DID.\n");
  fprintf(stderr,"       -t - Specify the request timeout period.\n");
  fprintf(stderr,"       -G - Offer gateway services.  Argument specifies locations of necessary files.\n");
  fprintf(stderr,"            Use -G [potato|android|custom:...] to set defaults for your device type.\n");
  fprintf(stderr,"       -N - Specify one or more interfaces for the DNA overlay mesh to operate.\n");
  fprintf(stderr,"            Interface specifications take the form <+|->[interface[=type][,...]\n");
  fprintf(stderr,"            e.g., -N -en0,+ to use all interfaces except en0\n");
  fprintf(stderr,"\n");
  exit(-1);
}

#ifndef DNA_NO_MAIN
char *exec_args[128];
int exec_argc=0;

int servalShutdown=0;

const char *thisinstancepath=NULL;
const char *serval_instancepath()
{
  if (thisinstancepath) return thisinstancepath;
  const char *instancepath=getenv("SERVALINSTANCE_PATH");
  if (!instancepath) instancepath=DEFAULT_INSTANCE_PATH;
  return instancepath;
}

int form_serval_instance_path(char *buf, size_t bufsiz, const char *path)
{
  if (snprintf(buf, bufsiz, "%s/%s", serval_instancepath(), path) < bufsiz)
    return 1;
  fprintf(stderr, "Cannot form pathname \"%s/%s\" -- buffer too small (%lu bytes)", serval_instancepath(), path, (unsigned long)bufsiz);
  return 0;
}

int create_serval_instance_dir() {
  const char *instancepath = serval_instancepath();
  if (mkdir(instancepath, 0700) == -1) {
    if (errno == EEXIST) {
      DIR *d = opendir(instancepath);
      if (!d) {
	WHYF("Cannot access %s", instancepath);
	perror("opendir");
	return -1;
      }
      closedir(d);
      return 0;
    }
    WHYF("Cannot mkdir %s", instancepath);
    perror("mkdir");
    return -1;
  }
  return 0;
}

void servalShutdownCleanly()
{
  WHY("Shutting down as requested.");
  /* Try to remove shutdown and PID files and exit */
  char filename[1024];
  if (FORM_SERVAL_INSTANCE_PATH(filename, "doshutdown")) {
    unlink(filename);
  }
  if (FORM_SERVAL_INSTANCE_PATH(filename, "serval.pid")) {
    unlink(filename);
  }
  if (mdp_client_socket==-1) {
    if (FORM_SERVAL_INSTANCE_PATH(filename, "mdp.socket")) {
      unlink(filename);
    }
  } else {
    overlay_mdp_client_done();
  }
  exit(0);
}

void signal_handler( int signal ) {
  
  if (signal==SIGQUIT) servalShutdownCleanly();

  if (signal==SIGHUP||signal==SIGINT) {
    /* Shut down.
       The shutting down should be done from the main-line code rather than here,
       so we first try to tell the mainline code to do so.  If, however, this is
       not the first time we have been asked to shut down, then we will do it here. */
    if (servalShutdown) {
      /* We have been asked before, so shut down cleanly */
      servalShutdownCleanly();
    } else {
      WHY("Asking Serval process to shutdown cleanly");
      servalShutdown=1;
    }
    return;    
  }

  /* oops - caught a bad signal -- exec() ourselves fresh */
  char signalName[64];
  snprintf(signalName,63,"signal %d",signal); signalName[63]=0;
  switch(signal) {
#ifdef SIGHUP
  case SIGHUP: snprintf(signalName,63,"SIG %s (%d)","hangup",signal);
    break;
#endif
#ifdef SIGINT
  case SIGINT: snprintf(signalName,63,"SIG %s (%d)","interrupt",signal);
    break;
#endif
#ifdef SIGQUIT
  case SIGQUIT: snprintf(signalName,63,"SIG %s (%d)","quit",signal);
    break;
#endif
#ifdef SIGILL
  case SIGILL: snprintf(signalName,63,"SIG %s (%d)","illegal instruction (not reset when caught)",signal);
    break;
#endif
#ifdef SIGTRAP
  case SIGTRAP: snprintf(signalName,63,"SIG %s (%d)","trace trap (not reset when caught)",signal);
    break;
#endif
#ifdef SIGABRT
  case SIGABRT: snprintf(signalName,63,"SIG %s (%d)","abort()",signal);
    break;
#endif
#ifdef SIGPOLL
  case SIGPOLL: snprintf(signalName,63,"SIG %s (%d)","pollable event ([XSR] generated, not supported)",signal);
    break;
#endif
#ifdef SIGEMT
  case SIGEMT: snprintf(signalName,63,"SIG %s (%d)","EMT instruction",signal);
    break;
#endif
#ifdef SIGFPE
  case SIGFPE: snprintf(signalName,63,"SIG %s (%d)","floating point exception",signal);
    break;
#endif
#ifdef SIGKILL
  case SIGKILL: snprintf(signalName,63,"SIG %s (%d)","kill (cannot be caught or ignored)",signal);
    break;
#endif
#ifdef SIGBUS
  case SIGBUS: snprintf(signalName,63,"SIG %s (%d)","bus error",signal);
    break;
#endif
#ifdef SIGSEGV
  case SIGSEGV: snprintf(signalName,63,"SIG %s (%d)","segmentation violation",signal);
    break;
#endif
#ifdef SIGSYS
  case SIGSYS: snprintf(signalName,63,"SIG %s (%d)","bad argument to system call",signal);
    break;
#endif
#ifdef SIGPIPE
  case SIGPIPE: snprintf(signalName,63,"SIG %s (%d)","write on a pipe with no one to read it",signal);
    break;
#endif
#ifdef SIGALRM
  case SIGALRM: snprintf(signalName,63,"SIG %s (%d)","alarm clock",signal);
    break;
#endif
#ifdef SIGTERM
  case SIGTERM: snprintf(signalName,63,"SIG %s (%d)","software termination signal from kill",signal);
    break;
#endif
#ifdef SIGURG
  case SIGURG: snprintf(signalName,63,"SIG %s (%d)","urgent condition on IO channel",signal);
    break;
#endif
#ifdef SIGSTOP
  case SIGSTOP: snprintf(signalName,63,"SIG %s (%d)","sendable stop signal not from tty",signal);
    break;
#endif
#ifdef SIGTSTP
  case SIGTSTP: snprintf(signalName,63,"SIG %s (%d)","stop signal from tty",signal);
    break;
#endif
#ifdef SIGCONT
  case SIGCONT: snprintf(signalName,63,"SIG %s (%d)","continue a stopped process",signal);
    break;
#endif
#ifdef SIGCHLD
  case SIGCHLD: snprintf(signalName,63,"SIG %s (%d)","to parent on child stop or exit",signal);
    break;
#endif
#ifdef SIGTTIN
  case SIGTTIN: snprintf(signalName,63,"SIG %s (%d)","to readers pgrp upon background tty read",signal);
    break;
#endif
#ifdef SIGTTOU
  case SIGTTOU: snprintf(signalName,63,"SIG %s (%d)","like TTIN for output if (tp->t_local&LTOSTOP)",signal);
    break;
#endif
#ifdef SIGIO
#if SIGIO != SIGPOLL          
  case SIGIO: snprintf(signalName,63,"SIG %s (%d)","input/output possible signal",signal);
    break;
#endif
#endif
#ifdef SIGXCPU
  case SIGXCPU: snprintf(signalName,63,"SIG %s (%d)","exceeded CPU time limit",signal);
    break;
#endif
#ifdef SIGXFSZ
  case SIGXFSZ: snprintf(signalName,63,"SIG %s (%d)","exceeded file size limit",signal);
    break;
#endif
#ifdef SIGVTALRM
  case SIGVTALRM: snprintf(signalName,63,"SIG %s (%d)","virtual time alarm",signal);
    break;
#endif
#ifdef SIGPROF
  case SIGPROF: snprintf(signalName,63,"SIG %s (%d)","profiling time alarm",signal);
    break;
#endif
#ifdef SIGWINCH
  case SIGWINCH: snprintf(signalName,63,"SIG %s (%d)","window size changes",signal);
    break;
#endif
#ifdef SIGINFO
  case SIGINFO: snprintf(signalName,63,"SIG %s (%d)","information request",signal);
    break;
#endif
#ifdef SIGUSR1
  case SIGUSR1: snprintf(signalName,63,"SIG %s (%d)","user defined signal 1",signal);
    break;
#endif
#ifdef SIGUSR2
  case SIGUSR2: snprintf(signalName,63,"SIG %s (%d)","user defined signal 2",signal);
    break;
#endif
  }
  signalName[63]=0;
  fprintf(stderr,"Caught terminal signal %s -- respawning.\n",signalName);
  if (sock>-1) close(sock);
  int i;
  for(i=0;i<overlay_interface_count;i++)
    if (overlay_interfaces[i].fd>-1)
      close(overlay_interfaces[i].fd);
  execv(exec_args[0],exec_args);
  /* Quit if the exec() fails */
  exit(-3);
} 

int setVerbosity(char *optarg) {
  long long old_debug=debug;
  debug=strtoll(optarg,NULL,10);
  if (strstr(optarg,"interfaces")) debug|=DEBUG_OVERLAYINTERFACES;
  if (strstr(optarg,"rx")) debug|=DEBUG_PACKETRX;
  if (strstr(optarg,"tx")) debug|=DEBUG_PACKETTX;
  if (strstr(optarg,"verbose")) debug|=DEBUG_VERBOSE;
  if (strstr(optarg,"verbio")) debug|=DEBUG_VERBOSE_IO;
  if (strstr(optarg,"peers")) debug|=DEBUG_PEERS;
  if (strstr(optarg,"dnaresponses")) debug|=DEBUG_DNARESPONSES;
  if (strstr(optarg,"dnarequests")) debug|=DEBUG_DNAREQUESTS;
  if (strstr(optarg,"simulation")) debug|=DEBUG_SIMULATION;
  if (strstr(optarg,"dnavars")) debug|=DEBUG_DNAVARS;
  if (strstr(optarg,"packetformats")) debug|=DEBUG_PACKETFORMATS;
  if (strstr(optarg,"packetconstruction")) debug|=DEBUG_PACKETCONSTRUCTION;
  if (strstr(optarg,"gateway")) debug|=DEBUG_GATEWAY;
  if (strstr(optarg,"hlr")) debug|=DEBUG_HLR;
  if (strstr(optarg,"sockio")) debug|=DEBUG_IO;
  if (strstr(optarg,"frames")) debug|=DEBUG_OVERLAYFRAMES;
  if (strstr(optarg,"abbreviations")) debug|=DEBUG_OVERLAYABBREVIATIONS;
  if (strstr(optarg,"routing")) debug|=DEBUG_OVERLAYROUTING;
  if (strstr(optarg,"security")) debug|=DEBUG_SECURITY;
  if (strstr(optarg,"rhizome")) debug|=DEBUG_RHIZOME;
  if (strstr(optarg,"norhizome")) 
    { debug|=DEBUG_DISABLERHIZOME; debug&=~DEBUG_RHIZOME; }
  if (strstr(optarg,"filesync")) debug|=DEBUG_RHIZOMESYNC;
  if (strstr(optarg,"monitorroutes")) debug|=DEBUG_OVERLAYROUTEMONITOR;
  if (strstr(optarg,"queues")) debug|=DEBUG_QUEUES;
  if (strstr(optarg,"broadcasts")) debug|=DEBUG_BROADCASTS;

  if (old_debug==debug) {
    fprintf(stderr,"WARNING: Option '%s' had no effect on existing debug/verbosity level.\n",
	    optarg);
  }
  return 0;
}

int main(int argc, char **argv)
{
  int c;
  char *pin=NULL;
  char *did=NULL;
  char *sid=NULL;
  char *keyring_file=NULL;
  int instance=-1;
  int foregroundMode=0;

  memabuseInit();

#if defined WIN32
    WSADATA wsa_data;
    WSAStartup(MAKEWORD(1,1), &wsa_data);
#else
    /* Catch sigsegv and other crash signals so that we can relaunch ourselves */

    for(exec_argc=0;exec_argc<argc;exec_argc++)
      exec_args[exec_argc]=strdup(argv[exec_argc]);
    exec_args[exec_argc]=0;

    signal( SIGSEGV, signal_handler );
    signal( SIGFPE, signal_handler );
    signal( SIGILL, signal_handler );
    signal( SIGBUS, signal_handler );
    signal( SIGABRT, signal_handler );

    /* Catch SIGHUP etc so that we can respond to requests to do things */
    signal( SIGHUP, signal_handler );
    signal( SIGINT, signal_handler );
    signal( SIGQUIT, signal_handler );
#endif

  srandomdev();

  if (argv[1]&&argv[1][0]!='-') {
    /* First argument doesn't start with a dash, so assume it is for the new command line
       parser. */

    /* Don't include name of program in arguments */
    int return_value = parseCommandLine(argc - 1, (const char*const*)&argv[1]);

#if defined WIN32
    WSACleanup();
#endif
    
    return return_value;
  } 

  fprintf(stderr,
	  "WARNING: The use of the old command line structure is being deprecated.\n"
	  "         Type '%s help' to learn about the new command line structure.\n",
	  argv[0]);

  while((c=getopt(argc,argv,"Ab:B:E:G:I:Sf:d:i:l:L:mnp:P:r:s:t:v:R:W:U:D:CO:M:N:")) != -1 ) 
    {
      switch(c)
	{
	case 'S': serverMode=1; break;
	case 'r': /* Enable rhizome */
	  if (rhizome_datastore_path) return WHY("-r specified more than once");
	  rhizome_datastore_path=optarg;
	  rhizome_opendb();
	  /* Also set keyring file to be in the Rhizome directory, to save the need to specify it
	     separately. */
	  char temp[1024];
	  if (snprintf(temp, sizeof(temp), "%s/serval.keyring", optarg)
	      >= sizeof(temp))
	    exit(WHY("Rhizome directory name too long."));
	  keyring_file = strdup(temp);
	  break;
	case 'M': /* Distribute specified manifest and file pair using Rhizome. */
	  /* This option assumes that the manifest is locally produced, and will
	     create any appropriate signatures, replacing any old signatures on the
	     manifest.
	     A different calling would be required to import an existing pre-signed
	     manifest */
	  return rhizome_bundle_import(NULL, NULL, optarg,
				       NULL /* no groups - XXX should allow them */,
				       255 /* ttl - XXX should read from somewhere,
					      e.g., bar if being imported */,
				       0 /* int verifyP */, 
				       1 /* int checkFileP */, 
				       1 /* int signP */);
	  break;
	case 'm': returnMultiVars=1; break;
	case 'N': /* Ask for overlay network to setup one or more interfaces */
	  if (overlay_interface_args(optarg))
	    return WHY("Invalid interface specification(s) passed to -N");
	  overlayMode=1;
	  break;
	case 'G': /* Offer gateway services */
	  gatewayspec=strdup(optarg);
	  if(prepareGateway(gatewayspec)) return usage("Invalid gateway specification");
	  break;
	case 'n': /* don't detach from foreground in server mode */
	  foregroundMode=1; break;
	case 'b': /* talk peers on a BATMAN mesh */
	  batman_socket=strdup(optarg);
	  break;
	case 'l': /* talk peers on a BATMAN mesh */
	  batman_peerfile=strdup(optarg);
	  break;
	case 'L':
	  instrumentation_file=strdup(optarg);
	  break;
	case 'B': /* Set simulated Bit Error Rate for bench-testing */
	  simulatedBER=atof(optarg);
	  fprintf(stderr,"WARNING: Bit error injection enabled -- this will cause packet loss and is intended only for testing.\n");
	  break;
	case 'i':
	  instance=atoi(optarg);
	  if (instance<-1||instance>255) usage("Illegal variable instance ID.");
	  break;
	case 'f':
	  if (clientMode) usage("Only servers use keyring files");
	  keyring_file=strdup(optarg);
	  break;
	case 'p': /* additional peers to query */
	  if (additionalPeer(optarg)) exit(-3);
	  break;
	case 'P': /* Supply pin */
	  pin=strdup(optarg);
	  clientMode=1;
	  break;
	case 'd': /* Ask by DID */
	  clientMode=1;
	  did=strdup(optarg);
	  break;
	case 's': /* Ask by subscriber ID */
	  clientMode=1;
	  sid=strdup(optarg);
	  break;
	case 't': /* request timeout (ms) */
	  timeout=atoi(optarg);
	  break;
	case 'v': /* set verbosity */
	  setVerbosity(optarg);
	  break;
	case 'A': /* get address (IP or otherwise) of a given peer */
	  peerAddress(did,sid,3 /* 1 = print list of addresses to stdout, 2 = set peer list to responders */);
	  break;
	case 'R': /* read a variable */
	  {	    
	    unsigned char buffer[65535];
	    int len=0;
	    requestItem(did,sid,(char *)optarg,instance,buffer,sizeof(buffer),&len,NULL);
	  }
	  break;
	case 'W': /* write a variable */
	  {	    
	    int var_id;
	    unsigned char value[65536];
	    int value_len=65535;
	    if (parseAssignment((unsigned char *)optarg,&var_id,value,&value_len)) return -1;
	    value[value_len]=0;
	    return writeItem(did?did:sid,var_id,instance,value,0,value_len,SET_NOREPLACE,-1,NULL);
	  }
	  break;
	case 'U': /* write or update a variable */
	  {	    
	    int var_id;
	    unsigned char value[65536];
	    int value_len=65535;
	    if (parseAssignment((unsigned char *)optarg,&var_id,value,&value_len)) return -1;
	    value[value_len]=0;
	    return writeItem(did?did:sid,var_id,instance,value,0,value_len,SET_REPLACE,-1,NULL);
	  }
	  break;
	case 'C': /* create a new keyring entry */
	  return WHY("Entries in new keyring format must be used with new command line framework.");
	  break;
	case 'O': /* output to templated files */
	  if (outputtemplate) usage("You can only specify -O once");
	  outputtemplate=strdup(optarg);
	  break;
	default:
	  usage("Invalid option");
	  break;
	}
    }

  if (optind<argc) usage("Extraneous options at end of command");

  if (keyring_file&&clientMode) usage("Only servers use backing files");
  if (serverMode&&clientMode) usage("You asked me to be both server and client.  That's silly.");
  if (serverMode) return server(keyring_file,foregroundMode);
  if (!clientMode) usage("Serval server and client utility.");

#if defined WIN32
    WSACleanup();
#endif

  /* Client mode: */
  return 0;
}
#endif

long long parse_quantity(char *q)
{
  int m;
  char units[80];

  if (strlen(q)>=80) return WHY("quantity string >=80 characters");

  if (sscanf(q,"%d%s",&m,units)==2)
    {
      if (units[1]) return WHY("Units should be single character");
      switch(units[0])
	{
	case 'k': return m*1000LL;
	case 'K': return m*1024LL;
	case 'm': return m*1000LL*1000LL;
	case 'M': return m*1024LL*1024LL;
	case 'g': return m*1000LL*1000LL*1000LL;
	case 'G': return m*1024LL*1024LL*1024LL;
	default:
	  return WHY("Illegal unit: should be k,K,m,M,g, or G.");
	}
    }
  if (sscanf(q,"%d",&m)==1)
    {
      return m;
    }
  else
    {
      return WHY("Could not parse quantity");
    }
}
