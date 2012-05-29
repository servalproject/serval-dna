/*
Copyright (C) 2010-2012 Paul Gardner-Stephen, Serval Project.
 
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

/*
  Android does unix domain sockets, but only stream sockets, not datagram sockets.
  So we need a separate monitor interface for Android. A bit of a pain, but in
  fact it lets us make a very Android/Java-friendly interface, without any binary
  data structures (except for a binary extent for an audio sample block).
*/

#include "serval.h"
#include "rhizome.h"
#include <sys/stat.h>

#if defined(LOCAL_PEERCRED) && !defined(SO_PEERCRED)
#define SO_PEERCRED LOCAL_PEERCRED
#endif

/* really shouldn't need more than 2:
   1 for rhizome
   1 for VoMP call 
   but spares never hurt, and the cost is low
*/
#define MONITOR_LINE_LENGTH 160
#define MONITOR_DATA_SIZE MAX_AUDIO_BYTES
struct monitor_context {
#define MONITOR_VOMP (1<<0)
#define MONITOR_RHIZOME (1<<1)
#define MONITOR_PEERS (1<<2)
  int flags;
  int socket;
  char line[MONITOR_LINE_LENGTH];
  int line_length;
#define MONITOR_STATE_COMMAND 1
#define MONITOR_STATE_DATA 2
  int state;
  unsigned char buffer[MONITOR_DATA_SIZE];
  int data_expected;
  int data_offset;
  int sample_codec;
  int sample_call_session_token;
};

#define MAX_MONITOR_SOCKETS 8
int monitor_socket_count=0;
struct monitor_context monitor_sockets[MAX_MONITOR_SOCKETS];
long long monitor_last_update_time=0;

int monitor_process_command(int index,char *cmd);
int monitor_process_data(int index);

int monitor_named_socket=-1;
int monitor_setup_sockets()
{
  struct sockaddr_un name;
  int len;
  
  bzero(&name, sizeof(name));
  name.sun_family = AF_UNIX;
  
  if (monitor_named_socket!=-1)
      return 0;
  
  /* ignore SIGPIPE so that we don't explode */
  signal(SIGPIPE, SIG_IGN);
  if ((monitor_named_socket = socket(AF_UNIX, SOCK_STREAM, 0))==-1) {
    WHY_perror("socket");
    goto error;
  }

#ifdef linux
  /* Use abstract namespace as Android has no writable FS which supports sockets */
  name.sun_path[0]=0;
  /* XXX: 104 comes from OSX sys/un.h - no #define (note Linux has UNIX_PATH_MAX and it's 108(!)) */
  snprintf(&name.sun_path[1],104-2,"org.servalproject.servald.monitor.socket");
  /* Doesn't include trailing nul */
  len = 1+strlen(&name.sun_path[1]) + sizeof(name.sun_family);
#else
  snprintf(name.sun_path,104-1,"%s/org.servalproject.servald.monitor.socket",serval_instancepath());
  unlink(name.sun_path);
  /* Includes trailing nul */
  len = 1+strlen(name.sun_path) + sizeof(name.sun_family);
#endif

  if(bind(monitor_named_socket, (struct sockaddr *)&name, len)==-1) {
    WHY_perror("bind");
    goto error;
  }
  if(listen(monitor_named_socket,MAX_MONITOR_SOCKETS)==-1) {
    WHY_perror("listen");
    goto error;
  }

  int reuseP=1;
  if(setsockopt(monitor_named_socket, SOL_SOCKET, SO_REUSEADDR, 
		&reuseP, sizeof(reuseP)) < 0) {
    WHY_perror("setsockopt");
    WHY("Could not indicate reuse addresses. Not necessarily a problem (yet)");
  }
  
  int send_buffer_size=64*1024;    
  if(setsockopt(monitor_named_socket, SOL_SOCKET, SO_RCVBUF, 
		&send_buffer_size, sizeof(send_buffer_size))==-1)
    WHY_perror("setsockopt");
  if (debug&(DEBUG_IO|DEBUG_VERBOSE_IO)) WHY("Monitor server socket setup");

  return 0;
  
  error:
  close(monitor_named_socket);
  monitor_named_socket=-1;
  return -1;
}

int monitor_get_fds(struct pollfd *fds,int *fdcount,int fdmax)
{
  /* Make sure sockets are open */
  monitor_setup_sockets();

  /* This block should work, but in reality it doesn't.
     poll() on linux is ALWAYS claiming that accept() can be
     run.  So we just have to check it whenever some other fd triggers
     poll to break, which fortunately is fairly often. */
  if ((*fdcount)>=fdmax) return -1;
  if (monitor_named_socket>-1)
    {
      if (debug&(DEBUG_IO|DEBUG_VERBOSE_IO)) {
	WHYF("Monitor named unix domain socket is poll() slot #%d (fd %d)\n",
	     *fdcount,monitor_named_socket);
      }
      fds[*fdcount].fd=monitor_named_socket;
      fds[*fdcount].events=POLLIN;
      (*fdcount)++;
    }

  int i;
  if (debug&(DEBUG_IO|DEBUG_VERBOSE_IO)) 
    WHYF("looking at %d monitor clients",monitor_socket_count);
  for(i=0;i<monitor_socket_count;i++) {
    if ((*fdcount)>=fdmax) return -1;
    if (debug&(DEBUG_IO|DEBUG_VERBOSE_IO)) {
      WHYF("Monitor named unix domain client socket is poll() slot #%d (fd %d)\n",
	  *fdcount,monitor_sockets[i].socket);
      }
      fds[*fdcount].fd=monitor_sockets[i].socket;
      fds[*fdcount].events=POLLIN;
      (*fdcount)++;
  }

  return 0;
}

int monitor_poll()
{
  int s;
  unsigned char buffer[1024];
  struct sockaddr *ignored_address=(struct sockaddr *)&buffer[0];
  socklen_t ignored_length=sizeof(ignored_address);

  /* tell all monitor clients about status of all calls periodically */
  long long now=overlay_gettime_ms();
  char msg[128];
  int m;
  if (monitor_last_update_time>(now+1000)) {
    WHY("Fixed run away monitor_last_update_time");
    monitor_last_update_time=now+1000;
  }
  if (now>(monitor_last_update_time+1000)) {
    // WHY("Send keep alives");
    monitor_last_update_time=now;
    int i;
    for(i=0;i<vomp_call_count;i++) {
      /* Push out any undelivered status changes */
      monitor_call_status(&vomp_call_states[i]);
      WHYF("Sending keepalives for call #%d",i);
      
      /* And let far-end know that call is still alive */
      snprintf(msg,128,"\nKEEPALIVE:%06x\n",vomp_call_states[i].local.session);
      for(m=0;m<monitor_socket_count;m++)
	write(monitor_sockets[m].socket,msg,strlen(msg));
    }
  }

  /* Check for new connections */
  fcntl(monitor_named_socket,F_SETFL,
	fcntl(monitor_named_socket, F_GETFL, NULL)|O_NONBLOCK);
  while (
#ifdef HAVE_LINUX_IF_H
	 (s = accept4(monitor_named_socket,ignored_address,&ignored_length,O_NONBLOCK))
#else
	 (s = accept(monitor_named_socket,ignored_address,&ignored_length))
#endif
      != -1
  ) {
    if (0) WHYF("ignored_length=%d",ignored_length);
    int res = fcntl(s,F_SETFL, O_NONBLOCK);
    if (res) { close(s); continue; }
#if defined(HAVE_LINUX_STRUCT_UCRED)
    struct ucred ucred;
#elif defined(HAVE_BSD_STRUCT_UCRED)
    struct xucred ucred;
#else
#error "Unknown ucred struct"
#endif
    uid_t otheruid;
    socklen_t len=sizeof(ucred);
    res = getsockopt(s,SOL_SOCKET,SO_PEERCRED,&ucred,&len);
    if (len>sizeof(ucred)) {
      WHYF("This is likely to be bad (memory overrun by getsockopt())");
    }
    if (res) { 
      WHY("Failed to read credentials of monitor.socket client");
      close(s); continue; }
#if defined(HAVE_LINUX_STRUCT_UCRED)
    otheruid = ucred.uid;
#elif defined(HAVE_BSD_STRUCT_UCRED)
    otheruid = ucred.cr_uid;
#endif
    if (otheruid&&(otheruid!=getuid())) {
      if (0) WHYF("monitor.socket client has wrong uid (%d versus %d)",
		  otheruid,getuid());
      write(s,"\nCLOSE:Incorrect UID\n",strlen("\nCLOSE:Incorrect UID\n"));
      close(s); continue;
    }
    else if (monitor_socket_count>=MAX_MONITOR_SOCKETS
	     ||monitor_socket_count<0) {
      write(s,"\nCLOSE:All sockets busy\n",strlen("\nCLOSE:All sockets busy\n"));
      close(s);
    } else {
      struct monitor_context *c=&monitor_sockets[monitor_socket_count];
      c->socket=s;
      c->line_length=0;
      c->state=MONITOR_STATE_COMMAND;
      monitor_socket_count++;
      write(s,"\nMONITOR:You are talking to servald\n",
	    strlen("\nMONITOR:You are talking to servald\n"));
      WHYF("Got %d clients",monitor_socket_count);
    }
    
    ignored_length=sizeof(ignored_address);
    fcntl(monitor_named_socket,F_SETFL,
	  fcntl(monitor_named_socket, F_GETFL, NULL)|O_NONBLOCK);
  }
  if (errno != EAGAIN) WHY_perror("accept");

  /* Read from any open connections */
  int i;
  for(i=0;i<monitor_socket_count;i++) {
  nextInSameSlot:
    errno=0;
    int bytes;
    struct monitor_context *c=&monitor_sockets[i];
    fcntl(c->socket,F_SETFL,
	  fcntl(c->socket, F_GETFL, NULL)|O_NONBLOCK);
    switch(c->state) {
    case MONITOR_STATE_COMMAND:
      bytes=1;
      while(bytes==1) {
	if (c->line_length>=MONITOR_LINE_LENGTH) {
	  /* line too long */
	  c->line[MONITOR_LINE_LENGTH-1]=0;
	  monitor_process_command(i,c->line);
	  bytes=-1;
	  break;
	}
	errno=0;
	bytes=read(c->socket,&c->line[c->line_length],1);
	if (bytes<1) {
	  switch(errno) {
	  case EINTR:
	  case ENOTRECOVERABLE:
	    /* transient errors */
	    WHY_perror("read");
	    break;
	  case EAGAIN:
	    break;
	  default:
	    WHY_perror("read");
	    /* all other errors; close socket */
	    WHYF("Tearing down monitor client #%d due to errno=%d (%s)",
		 i,errno,strerror(errno)?strerror(errno):"<unknown error>");
	    close(c->socket);
	    if (i==monitor_socket_count-1) {
	      monitor_socket_count--;
	      continue;
	    } else {
	      bcopy(&monitor_sockets[monitor_socket_count-1],
		    &monitor_sockets[i],
		    sizeof(struct monitor_context));
	      monitor_socket_count--;
	      goto nextInSameSlot;
	    }
	  }
	}
	if (bytes>0&&(c->line[c->line_length]!='\r')) 
	  {
	    c->line_length+=bytes;
	    if (c->line[c->line_length-1]=='\n') {
	      /* got command */
	      c->line[c->line_length-1]=0; /* trim new line for easier parsing */
	      monitor_process_command(i,c->line);
	      break;
	    }
	  }
      }
      break;
    case MONITOR_STATE_DATA:
      errno=0;
      bytes=read(c->socket,
		 &c->buffer[c->data_offset],
		 c->data_expected-c->data_offset);
      if (bytes<1) {
	switch(errno) {
	case EAGAIN: case EINTR: 
	  /* transient errors */
	  break;
	default:
	  /* all other errors; close socket */
	    WHYF("Tearing down monitor client #%d due to errno=%d",
		 i,errno);
	    close(c->socket);
	    if (i==monitor_socket_count-1) {
	      monitor_socket_count--;
	      continue;
	    } else {
	      bcopy(&monitor_sockets[monitor_socket_count-1],
		    &monitor_sockets[i],
		    sizeof(struct monitor_context));
	      monitor_socket_count--;
	      goto nextInSameSlot;
	    }
	}
      } else {
	c->data_offset+=bytes;
	if (c->data_offset>=c->data_expected)
	  {
	    /* we have the binary data we were expecting. */
	    monitor_process_data(i);
	    c->state=MONITOR_STATE_COMMAND;
	  }
      }
      break;
    default:
      c->state=MONITOR_STATE_COMMAND;
      WHY("fixed monitor connection state");
    }
      
  }
  return 0;
}

int monitor_process_command(int index,char *cmd) 
{
  int callSessionToken,sampleType,bytes;
  char sid[MONITOR_LINE_LENGTH],localDid[MONITOR_LINE_LENGTH];
  char remoteDid[MONITOR_LINE_LENGTH],digits[MONITOR_LINE_LENGTH];
  overlay_mdp_frame mdp;
  mdp.packetTypeAndFlags=MDP_VOMPEVENT;  

  struct monitor_context *c=&monitor_sockets[index];
  c->line_length=0;

  fcntl(c->socket,F_SETFL,
	fcntl(c->socket, F_GETFL, NULL)|O_NONBLOCK);

  if (strlen(cmd)>MONITOR_LINE_LENGTH) {
    write(c->socket,"\nERROR:Command too long\n",
	  strlen("\nERROR:Command too long\n"));
    return -1;
  }

  char msg[1024];
  int flag;

  if (cmd[0]=='*') {
    /* command with content */
    int ofs=0;
    if (sscanf(cmd,"*%d:%n",&bytes,&ofs)==1) {
      /* work out rest of command */
      cmd=&cmd[ofs];
      c->state=MONITOR_STATE_DATA;
      c->data_expected=bytes;
      c->data_offset=0;
      c->sample_codec=-1;

      if (sscanf(cmd,"AUDIO:%x:%d",
		 &callSessionToken,&sampleType)==2)
	{
	  /* Start getting sample */
	  c->sample_call_session_token=callSessionToken;
	  c->sample_codec=sampleType;
	  return 0;
	}
    }
  }
  else if (!strcasecmp(cmd,"monitor vomp"))
    c->flags|=MONITOR_VOMP;
  else if (!strcasecmp(cmd,"ignore vomp"))
    c->flags&=~MONITOR_VOMP;
  else if (!strcasecmp(cmd,"monitor rhizome"))
    c->flags|=MONITOR_RHIZOME;
  else if (!strcasecmp(cmd,"ignore rhizome"))
    c->flags&=~MONITOR_RHIZOME;
  else if (!strcasecmp(cmd,"monitor peers"))
    c->flags|=MONITOR_PEERS;
  else if (!strcasecmp(cmd,"ignore peers"))
    c->flags&=~MONITOR_PEERS;
  else if (sscanf(cmd,"FASTAUDIO:%x:%d",&callSessionToken,&flag)==2)
    {
      int i;
      for(i=0;i<vomp_call_count;i++)
	if (vomp_call_states[i].local.session==callSessionToken
	    ||callSessionToken==0) {
	  vomp_call_states[i].fast_audio=flag;
	  vomp_call_states[i].local.last_state=-1;
	  monitor_call_status(&vomp_call_states[i]);	  
	}
    }
  else if (sscanf(cmd,"call %s %s %s",sid,localDid,remoteDid)==3) {
    WHY("here");
    if (sid[0]=='*') {
      /* For testing, pick a peer and call them */
      int bin,slot;
      for(bin=0;bin<overlay_bin_count;bin++)
	for(slot=0;slot<overlay_bin_size;slot++)
	  {
	    if (!overlay_nodes[bin][slot].sid[0]) 
	      { 
		continue; }
	    strcpy(sid,overlay_render_sid(overlay_nodes[bin][slot].sid));
	    break;
	  }
    }
    mdp.vompevent.flags=VOMPEVENT_DIAL;
    int cn=0,in=0,kp=0;
    if(!keyring_next_identity(keyring,&cn,&in,&kp))
      {
	snprintf(msg,1024,"\nERROR:no local identity, so cannot place call\n");
	write(c->socket,msg,strlen(msg));
      }
    else {
      bcopy(keyring->contexts[cn]->identities[in]
	    ->keypairs[kp]->public_key,
	    &mdp.vompevent.local_sid[0],SID_SIZE);
      stowSid(&mdp.vompevent.remote_sid[0],0,sid);
      vomp_mdp_event(&mdp,NULL,0);
    }
    WHY("here");
  } 
  else if (sscanf(cmd,"status %x",&callSessionToken)==1) {
    int i;
    for(i=0;i<vomp_call_count;i++)
      if (vomp_call_states[i].local.session==callSessionToken
	  ||callSessionToken==0) {
	vomp_call_states[i].local.last_state=0;
	monitor_call_status(&vomp_call_states[i]);
      }
  } else if (sscanf(cmd,"pickup %x",&callSessionToken)==1) {
     mdp.vompevent.flags=VOMPEVENT_PICKUP;
     mdp.vompevent.call_session_token=callSessionToken;
     vomp_mdp_event(&mdp,NULL,0);
  }
  else if (sscanf(cmd,"hangup %x",&callSessionToken)==1) {
     mdp.vompevent.flags=VOMPEVENT_HANGUP;
     mdp.vompevent.call_session_token=callSessionToken;
     vomp_mdp_event(&mdp,NULL,0);
  } else if (sscanf(cmd,"dtmf %x %s",&callSessionToken,digits)==2) {
    mdp.vompevent.flags=VOMPEVENT_AUDIOPACKET;
    mdp.vompevent.call_session_token=callSessionToken;

    /* One digit per sample block. */
    mdp.vompevent.audio_sample_codec=VOMP_CODEC_DTMF;
    mdp.vompevent.audio_sample_bytes=1;
    
    int i;
    for(i=0;i<strlen(digits);i++) {
      int digit=vomp_parse_dtmf_digit(digits[i]);
      if (digit<0) {
	snprintf(msg,1024,"\nERROR: invalid DTMF digit 0x%02x\n",digit);
	write(c->socket,msg,strlen(msg));
      }
      mdp.vompevent.audio_bytes[mdp.vompevent.audio_sample_bytes]
	=(digit<<4); /* 80ms standard tone duration, so that it is a multiple
			of the majority of codec time units (70ms is the nominal
			DTMF tone length for most systems). */
      if (overlay_mdp_send(&mdp,0,0)) WHY("Send DTMF failed.");
    }
    
  }

  fcntl(c->socket,F_SETFL,
	fcntl(c->socket, F_GETFL, NULL)|O_NONBLOCK);

  snprintf(msg,1024,"\nMONITORSTATUS:%d\n",c->flags);
  write(c->socket,msg,strlen(msg));

  return 0;
}

int monitor_process_data(int index) 
{
  /* Called when we have received an entire data sample */
  struct monitor_context *c=&monitor_sockets[index];
  c->state=MONITOR_STATE_COMMAND;

  if (vomp_sample_size(c->sample_codec)!=c->data_offset)
    return 
      WHYF("Ignoring sample block of incorrect size (expected %d, got %d bytes)",
	   vomp_sample_size(c->sample_codec)!=c->data_offset);

  fcntl(c->socket,F_SETFL,
	fcntl(c->socket, F_GETFL, NULL)|O_NONBLOCK);

  vomp_call_state *call=vomp_find_call_by_session(c->sample_call_session_token);
  if (!call) {
    write(c->socket,"\nERROR:No such call\n",strlen("\nERROR:No such call\n"));
    return -1;
  }

  overlay_mdp_frame mdp;
  mdp.packetTypeAndFlags=MDP_VOMPEVENT;
  mdp.vompevent.flags=VOMPEVENT_AUDIOPACKET;
  mdp.vompevent.call_session_token=c->sample_call_session_token;
  mdp.vompevent.audio_sample_codec=c->sample_codec;
  bcopy(&c->buffer[0],&mdp.vompevent.audio_bytes[0],
	vomp_sample_size(c->sample_codec));
  mdp.vompevent.audio_sample_bytes=vomp_sample_size(c->sample_codec);

  if (overlay_mdp_send(&mdp,0,0)) WHY("Send audio failed.");

  return 0;
}

int monitor_announce_bundle(rhizome_manifest *m)
{
  int i;
  char msg[1024];
  const char *service = rhizome_manifest_get(m, "service", NULL, 0);
  const char *sender = rhizome_manifest_get(m, "sender", NULL, 0);
  const char *recipient = rhizome_manifest_get(m, "recipient", NULL, 0);
  snprintf(msg,1024,"\nBUNDLE:%s:%s:%lld:%lld:%s:%s:%s\n",
	   /* XXX bit of a hack here, since SIDs and cryptosign public keys have the same length */
	   overlay_render_sid(m->cryptoSignPublic),
	   service ? service : "",
	   m->version,
	   m->fileLength,
	   sender,
	   recipient,
	   m->dataFileName?m->dataFileName:"");
  for(i=0;i<monitor_socket_count;i++)
    {
      if (!(monitor_sockets[i].flags&MONITOR_RHIZOME))
	continue;
      nextInSameSlot:
	errno=0;
	fcntl(monitor_sockets[i].socket,F_SETFL,
	      fcntl(monitor_sockets[i].socket, F_GETFL, NULL)|O_NONBLOCK);
	write(monitor_sockets[i].socket,msg,strlen(msg));
	if (errno&&(errno!=EINTR)&&(errno!=EAGAIN)) {
	  /* error sending update, so kill monitor socket */
	  WHYF("Tearing down monitor client #%d due to errno=%d",
	       i,errno);
	  close(monitor_sockets[i].socket);
	  if (i==monitor_socket_count-1) {
	    monitor_socket_count--;
	    continue;
	  } else {
	    bcopy(&monitor_sockets[monitor_socket_count-1],
		  &monitor_sockets[i],
		  sizeof(struct monitor_context));
	    monitor_socket_count--;
	    goto nextInSameSlot;
	  }
	}
      }
  return 0;
}

int monitor_call_status(vomp_call_state *call)
{
  int i;
  char msg[1024];
  int show=0;
  if (call->local.state>call->local.last_state) show=1;
  if (call->remote.state>call->remote.last_state) show=1;
  call->local.last_state=call->local.state;
  call->remote.last_state=call->remote.state;
  if (show) {
    if (0) WHYF("sending call status to monitor");
    snprintf(msg,1024,"\nCALLSTATUS:%06x:%06x:%d:%d:%d:%s:%s:%s:%s\n",
	     call->local.session,call->remote.session,
	     call->local.state,call->remote.state,
	     call->fast_audio,
	     overlay_render_sid(call->local.sid),
	     overlay_render_sid(call->remote.sid),
	     call->local.did,call->remote.did);
    msg[1023]=0;
    for(i=0;i<monitor_socket_count;i++)
      {
	if (!(monitor_sockets[i].flags&MONITOR_VOMP))
	  continue;
      nextInSameSlot:
	errno=0;
	fcntl(monitor_sockets[i].socket,F_SETFL,
	      fcntl(monitor_sockets[i].socket, F_GETFL, NULL)|O_NONBLOCK);
	write(monitor_sockets[i].socket,msg,strlen(msg));
	if (errno&&(errno!=EINTR)&&(errno!=EAGAIN)) {
	  /* error sending update, so kill monitor socket */
	  WHYF("Tearing down monitor client #%d due to errno=%d",
	       i,errno);
	  close(monitor_sockets[i].socket);
	  if (i==monitor_socket_count-1) {
	    monitor_socket_count--;
	    continue;
	  } else {
	    bcopy(&monitor_sockets[monitor_socket_count-1],
		  &monitor_sockets[i],
		  sizeof(struct monitor_context));
	    monitor_socket_count--;
	    goto nextInSameSlot;
	  }
	}
      }
  }
  return 0;
}

int monitor_announce_peer(unsigned char *sid)
{
  unsigned char msg[1024];
  snprintf((char *)msg,1024,"\nNEWPEER:%s\n",overlay_render_sid(sid));
  monitor_tell_clients(msg,strlen((char *)msg),MONITOR_PEERS);
  return 0;
}

int monitor_send_audio(vomp_call_state *call,overlay_mdp_frame *audio)
{
  if (0) WHYF("Tell call monitor about audio for call %06x:%06x",
	      call->local.session,call->remote.session);

  int sample_bytes=vomp_sample_size(audio->vompevent.audio_sample_codec);
  unsigned char msg[1024+MAX_AUDIO_BYTES];
  /* All commands followed by binary data start with *len:, so that 
     they can be easily parsed at the far end, even if not supported.
     Put newline at start of these so that receiving data in command
     mode doesn't confuse the parser.  */
  snprintf((char *)msg,1024,
	   "\n*%d:AUDIOPACKET:%06x:%06x:%d:%d:%d:%lld:%lld\n",
	   sample_bytes,
	   call->local.session,call->remote.session,
	   call->local.state,call->remote.state,
	   audio->vompevent.audio_sample_codec,
	   audio->vompevent.audio_sample_starttime,
	   audio->vompevent.audio_sample_endtime);
  int msglen=strlen((char *)msg);
  bcopy(&audio->vompevent.audio_bytes[0],
	&msg[msglen],sample_bytes);
  msglen+=sample_bytes;

  monitor_tell_clients(msg,msglen,MONITOR_VOMP);

  return 0;
}

int monitor_tell_clients(unsigned char *msg,int msglen,int mask)
{
  int i;
  for(i=0;i<monitor_socket_count;i++)
    {
      if (!(monitor_sockets[i].flags&mask))
	continue;
    nextInSameSlot:
      errno=0;
      fcntl(monitor_sockets[i].socket,F_SETFL,
	    fcntl(monitor_sockets[i].socket, F_GETFL, NULL)|O_NONBLOCK);
      write(monitor_sockets[i].socket,msg,msglen);
      // WHYF("Writing AUDIOPACKET to client");
      if (errno&&(errno!=EINTR)&&(errno!=EAGAIN)) {
	/* error sending update, so kill monitor socket */
	WHYF("Tearing down monitor client #%d due to errno=%d",
	     i,errno);
	close(monitor_sockets[i].socket);
	if (i==monitor_socket_count-1) {
	  monitor_socket_count--;
	  continue;
	} else {
	  bcopy(&monitor_sockets[monitor_socket_count-1],
		&monitor_sockets[i],
		sizeof(struct monitor_context));
	  monitor_socket_count--;
	  goto nextInSameSlot;
	}
      }
    }
  return 0;
}

/* Check if there is a running server, and whether it is responding or not.
 */
int server_probe(int *pid)
{
  int fd=-1;
  struct sockaddr_un addr;
  if ( (fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
    return SERVER_UNKNOWN; 
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  addr.sun_path[0]=0;
  snprintf(&addr.sun_path[1],100,"org.servalproject.servald.monitor.socket");
  int len = 1+strlen(&addr.sun_path[1]) + sizeof(addr.sun_family);
  char *p=(char *)&addr;
  if (0) DEBUGF("last char='%c' %02x\n",p[len-1],p[len-1]);

  if (connect(fd, (struct sockaddr*)&addr, len) == -1) {
    close(fd);
    return SERVER_NOTRUNNING;
  }
  
  /* Give the server 2 seconds to send us something */
  struct pollfd fds[1];
  fds[0].fd=fd;
  fds[0].events=POLLIN;
  poll(fds,1,2000);
  
  fcntl(fd,F_SETFL,fcntl(fd, F_GETFL, NULL)|O_NONBLOCK);

  *pid=-1;
  if (pid!=NULL) {
#if defined(HAVE_LINUX_STRUCT_UCRED)
    struct ucred ucred;
#elif defined(HAVE_BSD_STRUCT_UCRED)
    struct xucred ucred;
#else
#error "Unknown ucred struct"
#endif
    socklen_t len=sizeof(ucred);
    int res=getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&ucred,&len);
    if (len>sizeof(ucred)) {
      WHYF("This is likely to be bad (memory overrun by getsockopt())");
    }
    if (res) { 
      WHY("Failed to read credentials of monitor.socket client");
    } else {
#if defined(HAVE_LINUX_STRUCT_UCRED)
      *pid = ucred.pid;
#elif defined(HAVE_BSD_STRUCT_UCRED)
#warning cannot get PID from ucred on BSD
      *pid = -1;
#endif
    }
  }
  
  char buff[1024];
  int bytes=read(fd,buff,1024);
  close(fd);
  if (bytes<0) {
    return SERVER_NOTRESPONDING;
  } else if (bytes==0) {
    // Could just be really busy.
    return SERVER_NOTRESPONDING;
  } else {
    return SERVER_RUNNING;
  }

}
