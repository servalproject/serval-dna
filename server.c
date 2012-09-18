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

#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>

#include "serval.h"
#include "strbuf.h"
#include "strbuf_helpers.h"

#define PIDFILE_NAME	  "servald.pid"
#define STOPFILE_NAME	  "servald.stop"

#define EXEC_NARGS 20
char *exec_args[EXEC_NARGS + 1];
int exec_argc = 0;

int serverMode=0;
int serverRespawnOnCrash = 0;
int servalShutdown = 0;

static int server_getpid = 0;

char *instrumentation_file=NULL;
FILE *i_f=NULL;

struct in_addr client_addr;
int client_port;

void signal_handler(int signal);
void crash_handler(int signal);
int getKeyring(char *s);
int createServerSocket();

/** Return the PID of the currently running server process, return 0 if there is none.
 */
int server_pid()
{
  const char *instancepath = serval_instancepath();
  struct stat st;
  if (stat(instancepath, &st) == -1) {
    WHY_perror("stat");
    return WHYF("Instance path '%s' non existant or not accessable"
	" (Set SERVALINSTANCE_PATH to specify an alternate location)",
	instancepath
      );
  }
  if ((st.st_mode & S_IFMT) != S_IFDIR)
    return WHYF("Instance path '%s' is not a directory", instancepath);
  char filename[1024];
  if (!FORM_SERVAL_INSTANCE_PATH(filename, PIDFILE_NAME))
    return -1;
  FILE *f = NULL;
  if ((f = fopen(filename, "r"))) {
    char buf[20];
    fgets(buf, sizeof buf, f);
    fclose(f);
    int pid = atoi(buf);
    if (pid > 0 && kill(pid, 0) != -1)
      return pid;
    unlink(filename);
  }
  return 0;
}

void server_save_argv(int argc, const char *const *argv)
{
    /* Save our argv[] to use for relaunching */
    for (exec_argc = 0; exec_argc < argc && exec_argc < EXEC_NARGS; ++exec_argc)
      exec_args[exec_argc] = strdup(argv[exec_argc]);
    exec_args[exec_argc] = NULL;
}

int server(char *backing_file)
{
  /* For testing, it can be very helpful to delay the start of the server
     process, for example to check that the start/stop logic is robust.
   */
  const char *delay = getenv("SERVALD_SERVER_START_DELAY");
  if (delay)
    sleep_ms(atoi(delay));

  serverMode = 1;
  serverRespawnOnCrash = confValueGetBoolean("server.respawn_on_crash", 0);

  /* Catch crash signals so that we can log a backtrace before expiring. */
  struct sigaction sig;
  sig.sa_handler = crash_handler;
  sigemptyset(&sig.sa_mask); // Don't block any signals during handler
  sig.sa_flags = SA_NODEFER | SA_RESETHAND; // So the signal handler can kill the process by re-sending the same signal to itself
  sigaction(SIGSEGV, &sig, NULL);
  sigaction(SIGFPE, &sig, NULL);
  sigaction(SIGILL, &sig, NULL);
  sigaction(SIGBUS, &sig, NULL);
  sigaction(SIGABRT, &sig, NULL);

  /* Catch SIGHUP etc so that we can respond to requests to do things, eg, shut down. */
  sig.sa_handler = signal_handler;
  sigemptyset(&sig.sa_mask); // Block the same signals during handler
  sigaddset(&sig.sa_mask, SIGHUP);
  sigaddset(&sig.sa_mask, SIGINT);
  sigaddset(&sig.sa_mask, SIGQUIT);
  sig.sa_flags = 0;
  sigaction(SIGHUP, &sig, NULL);
  sigaction(SIGINT, &sig, NULL);
  sigaction(SIGQUIT, &sig, NULL);

  if (!overlayMode)
    {
      /* Create a simple socket for listening on if we are not in overlay mesh mode. */
      createServerSocket();     

      /* Get backing store for keyring (overlay sets it up itself) */
      getKeyring(backing_file);
    }
  
  /* Record PID to advertise that the server is now running */
  char filename[1024];
  if (!FORM_SERVAL_INSTANCE_PATH(filename, PIDFILE_NAME))
    return -1;
  FILE *f=fopen(filename,"w");
  if (!f) {
    WHY_perror("fopen");
    WHYF("Could not write to PID file %s", filename);
    return -1;
  }
  server_getpid = getpid();
  fprintf(f,"%d\n", server_getpid);
  fclose(f);

  overlayServerMode();

  return 0;
}

/* Called periodically by the server process in its main loop.
 */
void server_shutdown_check(struct sched_ent *alarm)
{
  if (servalShutdown) {
    INFO("Shutdown flag set -- terminating with cleanup");
    serverCleanUp();
    exit(0);
  }
  if (server_check_stopfile() == 1) {
    INFO("Shutdown file exists -- terminating with cleanup");
    serverCleanUp();
    exit(0);
  }
  /* If this server has been supplanted with another or Serval has been uninstalled, then its PID
      file will change or be unaccessible.  In this case, shut down without all the cleanup.
      Perform this check at most once per second.  */
  static time_ms_t server_pid_time_ms = 0;
  time_ms_t now = gettime_ms();
  if (server_pid_time_ms == 0 || now - server_pid_time_ms > 1000) {
    server_pid_time_ms = now;
    if (server_pid() != server_getpid) {
      WARNF("Server pid file no longer contains pid=%d -- shutting down without cleanup", server_getpid);
      exit(1);
    }
  }
  if (alarm){
    alarm->alarm = now + 1000;
    alarm->deadline = alarm->alarm + 5000;
    schedule(alarm);
  }
}

int server_create_stopfile()
{
  char stopfile[1024];
  if (!FORM_SERVAL_INSTANCE_PATH(stopfile, STOPFILE_NAME))
    return -1;
  FILE *f;
  if ((f = fopen(stopfile, "w")) == NULL) {
    WHY_perror("fopen");
    return WHYF("Could not create stopfile '%s'", stopfile);
  }
  fclose(f);
  return 0;
}

int server_remove_stopfile()
{
  char stopfile[1024];
  if (!FORM_SERVAL_INSTANCE_PATH(stopfile, STOPFILE_NAME))
    return -1;
  if (unlink(stopfile) == -1) {
    if (errno == ENOENT)
      return 0;
    WHY_perror("unlink");
    return WHYF("Could not unlink stopfile '%s'", stopfile);
  }
  return 1;
}

int server_check_stopfile()
{
  char stopfile[1024];
  if (!FORM_SERVAL_INSTANCE_PATH(stopfile, STOPFILE_NAME))
    return -1;
  int r = access(stopfile, F_OK);
  if (r == 0)
    return 1;
  if (r == -1 && errno == ENOENT)
    return 0;
  WHY_perror("access");
  WHYF("Cannot access stopfile '%s'", stopfile);
  return -1;
}

void serverCleanUp()
{
  /* Try to remove shutdown and PID files and exit */
  server_remove_stopfile();
  char filename[1024];
  if (FORM_SERVAL_INSTANCE_PATH(filename, PIDFILE_NAME))
    unlink(filename);
  
  if (FORM_SERVAL_INSTANCE_PATH(filename, "mdp.socket")) {
    unlink(filename);
  }
  dna_helper_shutdown();
}

static void signame(char *buf, size_t len, int signal)
{
  const char *desc = "";
  switch(signal) {
#ifdef SIGHUP
  case SIGHUP: desc = "HUP"; break;
#endif
#ifdef SIGINT
  case SIGINT: desc = "INT"; break;
#endif
#ifdef SIGQUIT
  case SIGQUIT: desc = "QUIT"; break;
#endif
#ifdef SIGILL
  case SIGILL: desc = "ILL (not reset when caught)"; break;
#endif
#ifdef SIGTRAP
  case SIGTRAP: desc = "TRAP (not reset when caught)"; break;
#endif
#ifdef SIGABRT
  case SIGABRT: desc = "ABRT"; break;
#endif
#ifdef SIGPOLL
  case SIGPOLL: desc = "POLL ([XSR] generated, not supported)"; break;
#endif
#ifdef SIGEMT
  case SIGEMT: desc = "EMT"; break;
#endif
#ifdef SIGFPE
  case SIGFPE: desc = "FPE"; break;
#endif
#ifdef SIGKILL
  case SIGKILL: desc = "KILL (cannot be caught or ignored)"; break;
#endif
#ifdef SIGBUS
  case SIGBUS: desc = "BUS"; break;
#endif
#ifdef SIGSEGV
  case SIGSEGV: desc = "SEGV"; break;
#endif
#ifdef SIGSYS
  case SIGSYS: desc = "SYS"; break;
#endif
#ifdef SIGPIPE
  case SIGPIPE: desc = "PIPE"; break;
#endif
#ifdef SIGALRM
  case SIGALRM: desc = "ALRM"; break;
#endif
#ifdef SIGTERM
  case SIGTERM: desc = "TERM"; break;
#endif
#ifdef SIGURG
  case SIGURG: desc = "URG"; break;
#endif
#ifdef SIGSTOP
  case SIGSTOP: desc = "STOP"; break;
#endif
#ifdef SIGTSTP
  case SIGTSTP: desc = "TSTP"; break;
#endif
#ifdef SIGCONT
  case SIGCONT: desc = "CONT"; break;
#endif
#ifdef SIGCHLD
  case SIGCHLD: desc = "CHLD"; break;
#endif
#ifdef SIGTTIN
  case SIGTTIN: desc = "TTIN"; break;
#endif
#ifdef SIGTTOU
  case SIGTTOU: desc = "TTOU"; break;
#endif
#ifdef SIGIO
#if SIGIO != SIGPOLL          
  case SIGIO: desc = "IO"; break;
#endif
#endif
#ifdef SIGXCPU
  case SIGXCPU: desc = "XCPU"; break;
#endif
#ifdef SIGXFSZ
  case SIGXFSZ: desc = "XFSZ"; break;
#endif
#ifdef SIGVTALRM
  case SIGVTALRM: desc = "VTALRM"; break;
#endif
#ifdef SIGPROF
  case SIGPROF: desc = "PROF"; break;
#endif
#ifdef SIGWINCH
  case SIGWINCH: desc = "WINCH"; break;
#endif
#ifdef SIGINFO
  case SIGINFO: desc = "INFO"; break;
#endif
#ifdef SIGUSR1
  case SIGUSR1: desc = "USR1"; break;
#endif
#ifdef SIGUSR2
  case SIGUSR2: desc = "USR2"; break;
#endif
  }
  snprintf(buf, len, "SIG%s (%d) %s", desc, signal, strsignal(signal));
  buf[len - 1] = '\0';
}

void signal_handler(int signal)
{
  char buf[80];
  signame(buf, sizeof(buf), signal);
  INFOF("Caught %s", buf);
  switch (signal) {
    case SIGHUP:
    case SIGINT:
      /* Terminate the server process.  The shutting down should be done from the main-line code
	 rather than here, so we first try to tell the mainline code to do so.  If, however, this is
	 not the first time we have been asked to shut down, then we will do it here. */
      server_shutdown_check(NULL);
      WHY("Asking Serval process to shutdown cleanly");
      servalShutdown = 1;
      return;
  }
  serverCleanUp();
  exit(0);
}

void crash_handler(int signal)
{
  char buf[80];
  signame(buf, sizeof(buf), signal);
  WHYF("Caught %s", buf);
  dump_stack();
  BACKTRACE;
  if (serverRespawnOnCrash) {
    if (sock>-1)
      close(sock);
    int i;
    for(i=0;i<overlay_interface_count;i++)
      if (overlay_interfaces[i].alarm.poll.fd>-1)
	close(overlay_interfaces[i].alarm.poll.fd);
    char execpath[160];
    if (get_self_executable_path(execpath, sizeof execpath) != -1) {
      strbuf b = strbuf_alloca(1024);
      for (i = 0; i < exec_argc; ++i)
	strbuf_append_shell_quotemeta(strbuf_puts(b, i ? " " : ""), exec_args[i]);
      INFOF("Respawning %s as %s", execpath, strbuf_str(b));
      execv(execpath, exec_args);
      /* Quit if the exec() fails */
      WHY_perror("execv");
    } else {
      WHY("Cannot respawn");
    }
  }
  // Now die of the same signal, so that our exit status reflects the cause.
  INFOF("Re-sending signal %d to self", signal);
  kill(getpid(), signal);
  // If that didn't work, then die normally.
  INFOF("exit(%d)", -signal);
  exit(-signal);
} 

int getKeyring(char *backing_file)
{
 if (!backing_file)
    {     
      exit(WHY("Keyring requires a backing file"));
    }
  else
    {
      if (keyring) 
	exit(WHY("Keyring being opened twice"));
      keyring=keyring_open(backing_file);
      /* unlock all entries with blank pins */
      keyring_enter_pins(keyring,"");
    }
 keyring_seed(keyring);

 return 0;
}

int processRequest(unsigned char *packet,int len,
		   struct sockaddr *sender,int sender_len,
		   unsigned char *transaction_id,int recvttl, char *did,char *sid)
{
  /* Find HLR entry by DID or SID, unless creating */
  int prev_pofs=0;
  int pofs=OFS_PAYLOAD;

  while (pofs < len) {
    if (debug & DEBUG_DNARESPONSES)
      DEBUGF("len=%d, pofs=%d, pofs_prev=%d",len,pofs,prev_pofs);
    /* Avoid infinite loops */
    if (pofs<=prev_pofs) break;
    prev_pofs=pofs;

    if (debug & DEBUG_DNARESPONSES)
      DEBUGF("action code 0x%02x @ packet offset 0x%x", packet[pofs], pofs);
    switch (packet[pofs]) {
    case ACTION_CREATEHLR: {
	/* Creating an HLR requires an initial DID number and definitely no SID -
	    you can't choose a SID. */
	if (debug & DEBUG_DNARESPONSES)
	  DEBUGF("Creating a new HLR record. did='%s', sid='%s'",did,sid);
	if (!did[0] || sid[0])
	  return respondSimple(NULL, ACTION_DECLINED, NULL, 0, transaction_id, recvttl, sender, CRYPT_CIPHERED|CRYPT_SIGNED);
	if (debug & DEBUG_DNARESPONSES)
	  DEBUG("Verified that create request supplies DID but not SID");
	/* Creating an identity is nice and easy now with the new keyring */
	keyring_identity *id=keyring_create_identity(keyring,keyring->contexts[0], "");
	if (id)
	  keyring_set_did(id, did, "Mr. Smith");
	if (id==NULL||keyring_commit(keyring))
	  return respondSimple(NULL, ACTION_DECLINED, NULL, 0, transaction_id, recvttl, sender, CRYPT_CIPHERED|CRYPT_SIGNED);
	else
	  return respondSimple(id, ACTION_OKAY, NULL, 0, transaction_id, recvttl, sender, CRYPT_CIPHERED|CRYPT_SIGNED);	
	pofs += 1;
	pofs += 1 + SID_SIZE;
      }
      break;
    case ACTION_PAD: /* Skip padding */
      pofs++;
      pofs+=1+packet[pofs];
      break;
    case ACTION_EOT:  /* EOT */
      pofs=len;
      break;
    case ACTION_STATS: {
      /* short16 variable id,
	  int32 value */
	pofs++;
	short field=packet[pofs+1]+(packet[pofs]<<8);
	int value=packet[pofs+5]+(packet[pofs+4]<<8)+(packet[pofs+3]<<16)+(packet[pofs+2]<<24);
	pofs+=6;
	if (instrumentation_file)
	  {
	    if (!i_f) { if (strcmp(instrumentation_file,"-")) i_f=fopen(instrumentation_file,"a"); else i_f=stdout; }
	    if (i_f) fprintf(i_f,"%ld:%02x%02x%02x%02x:%d:%d\n",time(0),sender->sa_data[0],sender->sa_data[1],sender->sa_data[2],sender->sa_data[3],field,value);
	    if (i_f) fflush(i_f);
	  }
      }
      break;
    case ACTION_SET:
      WHY("You can only set keyring variables locally");
      return respondSimple(NULL,ACTION_ERROR,
			    (unsigned char *)"Would be insecure",
			    0,transaction_id,recvttl,
			    sender,CRYPT_CIPHERED|CRYPT_SIGNED);
      break;
    case ACTION_GET: {
	/* Limit transfer size to MAX_DATA_BYTES, plus an allowance for variable packing. */
	unsigned char data[MAX_DATA_BYTES+16];
	int dlen=0;
	int sendDone=0;

	if (debug&DEBUG_DNARESPONSES)
	  dump("Request bytes", &packet[pofs], 8);

	pofs++;
	int var_id=packet[pofs];
	int instance=-1;
	if (var_id&0x80) instance=packet[++pofs];
	if (instance==0xff) instance=-1;
	pofs++;
	int offset=(packet[pofs]<<8)+packet[pofs+1]; pofs+=2;
	keyring_identity *responding_id=NULL;

	pofs+=2;

	if (debug&DEBUG_DNARESPONSES) {
	  DEBUGF("Processing ACTION_GET (var_id=%02x, instance=%02x, pofs=0x%x, len=%d)",var_id,instance,pofs,len);
	  DEBUGF("Looking for identities with sid=%s did='%s'", (sid&&sid[0])?sid:"null",did?did:"null");
	}
	  
	/* Keyring only has DIDs in it for now.  Location is implied, so we allow that */
	switch (var_id) {
	case VAR_DIDS:
	case VAR_LOCATIONS:
	  break;
	default:
	  return respondSimple(NULL,ACTION_ERROR,
				(unsigned char *)"Unsupported variable",
				0,transaction_id,recvttl,
				sender,CRYPT_CIPHERED|CRYPT_SIGNED);
	}

	{
	  int cn=0,in=0,kp=0;
	  int found=0;
	  int count=0;
	  while(cn<keyring->context_count) {
	    found=0;
	    if (sid&&sid[0]) {
	      unsigned char packedSid[SID_SIZE];
	      stowSid(packedSid,0,sid);
	      found=keyring_find_sid(keyring,&cn,&in,&kp,packedSid);
	    } else {
	      found=keyring_find_did(keyring,&cn,&in,&kp,did);
	    }

	    struct response r;
	    unsigned char packedDid[64];

	    if (found&&(instance==-1||instance==count)) {
	      /* We have a matching identity/DID, now see what variable
		  they want.
		  VAR_DIDS and VAR_LOCATIONS are the only ones we support
		  with the new keyring file format for now. */
	      r.var_id=var_id;
	      r.var_instance=instance;
	      switch(var_id) {
	      case VAR_DIDS:
		/* We need to pack the DID before sending off */
		r.value_len=0;
		stowDid(packedDid,&r.value_len,
			(char *)keyring->contexts[cn]->identities[in]
			->keypairs[kp]->private_key);
		r.response=packedDid;
		break;
	      case VAR_LOCATIONS:
		r.response=(unsigned char *)"4000@";
		r.value_len=strlen((char *)r.response);		      
		break;
	      }

	      /* For multiple packet responses, we want to tag only the
		  last one with DONE, so we queue up the most recently generated
		  packet, and only dispatch it when we are about to produce 
		  another.  Then at the end of the loop, if we have a packet
		  waiting we simply mark that with with DONE, and everything
		  falls into place. */
	      if (sendDone>0)
		/* Send previous packet */
		respondSimple(responding_id,ACTION_DATA,data,dlen,
			      transaction_id,recvttl,sender,
			      CRYPT_CIPHERED|CRYPT_SIGNED);		      
	      /* Prepare new packet */
	      dlen=0;		      
	      if (packageVariableSegment(data,&dlen,&r,offset, MAX_DATA_BYTES+16))
		return WHY("packageVariableSegment() failed.");
	      responding_id = keyring->contexts[cn]->identities[in];

	      /* Remember that we need to send this new packet */
	      sendDone++;

	      count++;
	    }
	    
	    /* look for next record.
		Here the placing of DONE at the end of the response stream 
		becomes challenging, as we may be responding as multiple
		identities.  This means we have to DONE after each identity. */
	    int lastin=in,lastcn=cn;		    
	    kp++;
	    keyring_sanitise_position(keyring,&cn,&in,&kp);
	    if (lastin!=in||lastcn!=cn) {
	      /* moved off last identity, so send waiting packet if there is
		  one. */
	      if (sendDone) {
		data[dlen++]=ACTION_DONE;
		data[dlen++]=sendDone&0xff;
		respondSimple(responding_id,ACTION_DATA,data,dlen,
			      transaction_id,
			      recvttl,sender,CRYPT_CIPHERED|CRYPT_SIGNED);
	      }
	      sendDone=0;
	    }
	  }
	}

	/* Now, see if we have a final queued packet which needs marking with
	    DONE and then sending. */
	if (sendDone) {
	  data[dlen++]=ACTION_DONE;
	  data[dlen++]=sendDone&0xff;
	  respondSimple(responding_id,ACTION_DATA,data,dlen,transaction_id,
			recvttl,sender,CRYPT_CIPHERED|CRYPT_SIGNED);
	}
	
	if (gatewayspec&&(var_id==VAR_LOCATIONS)&&did&&strlen(did))
	  {
	    /* We are a gateway, so offer connection via the gateway as well */
	    unsigned char data[MAX_DATA_BYTES+16];
	    int dlen=0;
	    struct response fake;
	    unsigned char uri[1024];
	    
	    /* We use asterisk to provide the gateway service,
		so we need to create a temporary extension in extensions.conf,
		ask asterisk to re-read extensions.conf, and then make sure it has
		a functional SIP gateway.
	    */
	    if (!asteriskObtainGateway(sid,did,(char *)uri))
	      {
		
		fake.value_len=strlen((char *)uri);
		fake.var_id=var_id;
		fake.response=uri;
		
		if (packageVariableSegment(data,&dlen,&fake,offset,MAX_DATA_BYTES+16))
		  return WHY("packageVariableSegment() of gateway URI failed.");
		
		WHY("Gateway claims to be 1st identity, when it should probably have its own identity");
		respondSimple(keyring->contexts[0]->identities[0],
			      ACTION_DATA,data,dlen,
			      transaction_id,recvttl,sender,
			      CRYPT_CIPHERED|CRYPT_SIGNED);
	      }
	    else
	      {
		  /* Should we indicate the gateway is not available? */
		}
	    }
      
      }
      break;
    default:
      if (debug & DEBUG_PACKETFORMATS) {
	DEBUGF("Asked to perform unsipported action at Packet offset = 0x%x", pofs);
        dump("Packet", packet, len);
      }
      return WHY("unsupported action");
    }
  }

  return 0;
}

int respondSimple(keyring_identity *id,
		  int action,unsigned char *action_text,int action_len,
		  unsigned char *transaction_id,int recvttl,
		  struct sockaddr *recvaddr,int cryptoFlags)
{
  unsigned char packet[8000];
  int pl=0;
  int *packet_len=&pl;
  int packet_maxlen=8000;
  int i;

  /* XXX Complain about invalid crypto flags.
     XXX We don't do anything with the crypto flags right now
     XXX Other packet sending routines need this as well. */
  if (!cryptoFlags) return WHY("Crypto-flags not set.");

  /* ACTION_ERROR is associated with an error message.
     For syntactic simplicity, we do not require the respondSimple() call to provide
     the length of the error message. */
  if (action==ACTION_ERROR) {
    action_len=strlen((char *)action_text);
    /* Make sure the error text isn't too long.
       IF it is, trim it, as we still need to communicate the error */
    if (action_len>255) action_len=255;
  }

  /* Prepare the request packet */
  if (packetMakeHeader(packet,8000,packet_len,transaction_id,cryptoFlags)) 
    return WHY("packetMakeHeader() failed.");
  if (id)
    { if (packetSetSidFromId(packet,8000,packet_len,id)) 
	return WHY("invalid SID in reply"); }
  else 
    { if (packetSetDid(packet,8000,packet_len,"")) 
	return WHY("Could not set empty DID in reply"); }  

  CHECK_PACKET_LEN(1+1+action_len);
  packet[(*packet_len)++]=action;
  if (action==ACTION_ERROR) packet[(*packet_len)++]=action_len;
  for(i=0;i<action_len;i++) packet[(*packet_len)++]=action_text[i];

  if (debug&DEBUG_DNARESPONSES) dump("Simple response octets",action_text,action_len);

  if (packetFinalise(packet,8000,recvttl,packet_len,cryptoFlags))
    return WHY("packetFinalise() failed.");

  if (debug&DEBUG_DNARESPONSES) DEBUGF("Sending response of %d bytes",*packet_len);

  if (packetSendRequest(REQ_REPLY,packet,*packet_len,NONBATCH,transaction_id,recvaddr,NULL)) 
    return WHY("packetSendRequest() failed.");
  
  return 0;
}

int createServerSocket() 
{
  struct sockaddr_in bind_addr;
  
  sock=socket(PF_INET,SOCK_DGRAM,0);
  if (sock<0) {
    WHY_perror("socket");
    WHY("Could not create UDP socket.");
    exit(-3);
  }
  
  /* Automatically close socket on calls to exec().
     This makes life easier when we restart with an exec after receiving
     a bad signal. */
  fcntl(sock, F_SETFL,
	fcntl(sock, F_GETFL, NULL)|O_CLOEXEC);

  int i=1;
  setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &i, sizeof(i));

  errno=0;
  if(setsockopt(sock, IPPROTO_IP, IP_RECVTTL, &i,sizeof(i))<0)
    WHY_perror("setsockopt(IP_RECVTTL)");  

  bind_addr.sin_family = AF_INET;
  bind_addr.sin_port = htons( PORT_DNA );
  bind_addr.sin_addr.s_addr = htonl( INADDR_ANY );
  if(bind(sock,(struct sockaddr *)&bind_addr,sizeof(bind_addr))) {
    WHY_perror("bind");
    WHYF("MP HLR server could not bind to UDP port %d", PORT_DNA);
    exit(-3);
  }
  return 0;
}

#ifdef DEBUG_MEM_ABUSE
unsigned char groundzero[65536];
int memabuseInitP=0;

int memabuseInit()
{
  if (memabuseInitP) {
    WARN("memabuseInit() called more than once");
    return memabuseCheck();
  }

  unsigned char *zero=(unsigned char *)0;
  int i;
  for(i=0;i<65536;i++) {
    groundzero[i]=zero[i];
    //printf("%04x\n",i);
  }
  memabuseInitP=1;
  return 0;
}

int _memabuseCheck(const char *func,const char *file,const int line)
{
  unsigned char *zero=(unsigned char *)0;
  int firstAddr=-1;
  int lastAddr=-1;
  int i;
  for(i=0;i<65536;i++) if (groundzero[i]!=zero[i]) {
      lastAddr=i;
      if (firstAddr==-1) firstAddr=i;
    }
  
  if (lastAddr>0) {
    WARN("Memory corruption in first 64KB of RAM detected");
    DEBUGF("         Changed bytes exist in range 0x%04x - 0x%04x",firstAddr,lastAddr);
    dump("Changed memory content",&zero[firstAddr],lastAddr-firstAddr+1);
    dump("Initial memory content",&groundzero[firstAddr],lastAddr-firstAddr+1);
    sleep(1);
  } else {
    DEBUGF("All's well at %s() %s:%d",func,file,line);
  }
  
  return 0;
}
#endif
