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

#include <sys/stat.h>
#include "serval.h"
#include "conf.h"
#include "rhizome.h"
#include "cli.h"
#include "str.h"
#include "overlay_address.h"
#include "monitor-client.h"

#ifdef HAVE_UCRED_H
#include <ucred.h>
#endif

#ifdef linux
#if defined(LOCAL_PEERCRED) && !defined(SO_PEERCRED)
#define SO_PEERCRED LOCAL_PEERCRED
#endif
#endif

#define MONITOR_LINE_LENGTH 160
#define MONITOR_DATA_SIZE MAX_AUDIO_BYTES
struct monitor_context {
  struct sched_ent alarm;
  // monitor interest bitmask
  int flags;
  // what types of audio can we write to this client?
  // (packed bits)
  unsigned char supported_codecs[CODEC_FLAGS_LENGTH];
  
  char line[MONITOR_LINE_LENGTH];
  int line_length;
#define MONITOR_STATE_COMMAND 1
#define MONITOR_STATE_DATA 2
  int state;
  unsigned char buffer[MONITOR_DATA_SIZE];
  int data_expected;
  int data_offset;
};

#define MAX_MONITOR_SOCKETS 8
int monitor_socket_count=0;
struct monitor_context monitor_sockets[MAX_MONITOR_SOCKETS];

int monitor_process_command(struct monitor_context *c);
int monitor_process_data(struct monitor_context *c);
static void monitor_new_client(int s);

struct sched_ent named_socket;
struct profile_total named_stats;
struct profile_total client_stats;

int monitor_setup_sockets()
{
  struct sockaddr_un name;
  int len;
  int sock;
  
  bzero(&name, sizeof(name));
  name.sun_family = AF_UNIX;
  
  if ((sock = socket(AF_UNIX, SOCK_STREAM, 0))==-1) {
    WHYF_perror("socket(AF_UNIX, SOCK_STREAM, 0)");
    goto error;
  }

  len = monitor_socket_name(&name);
#ifndef linux
  unlink(name.sun_path);
#endif

  if(bind(sock, (struct sockaddr *)&name, len)==-1) {
    WHYF_perror("bind(%d, %s)", sock, alloca_toprint(-1, &name, len));
    goto error;
  }
  if(listen(sock,MAX_MONITOR_SOCKETS)==-1) {
    WHYF_perror("listen(%d, %d)", sock, MAX_MONITOR_SOCKETS);
    goto error;
  }

  int reuseP=1;
  if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuseP, sizeof reuseP) < 0) {
    WHYF_perror("setsockopt(%d, SOL_SOCKET, SO_REUSEADDR, &%d, %d)", sock, reuseP, sizeof reuseP);
    WHY("Could not indicate reuse addresses. Not necessarily a problem (yet)");
  }
  
  int send_buffer_size=64*1024;    
  if(setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &send_buffer_size, sizeof send_buffer_size)==-1)
    WHYF_perror("setsockopt(%d, SOL_SOCKET, SO_RCVBUF, &%d, %d)", sock, send_buffer_size, sizeof send_buffer_size);

  if (config.debug.io || config.debug.verbose_io)
    DEBUGF("Monitor server socket bound to %s", alloca_toprint(-1, &name, len));

  named_socket.function=monitor_poll;
  named_stats.name="monitor_poll";
  named_socket.stats=&named_stats;
  named_socket.poll.fd=sock;
  named_socket.poll.events=POLLIN;
  watch(&named_socket);
  return 0;
  
  error:
  close(sock);
  return -1;
}

int monitor_write_error(struct monitor_context *c, const char *error){
  char msg[256];
  snprintf(msg, sizeof(msg), "\nERROR:%s\n", error);
  write_str(c->alarm.poll.fd, msg);
  return -1;
}

void monitor_poll(struct sched_ent *alarm)
{
  int s;
  unsigned char buffer[1024];
  struct sockaddr *ignored_address=(struct sockaddr *)&buffer[0];
  socklen_t ignored_length=sizeof(ignored_address);

  /* Check for new connections */
  /* We don't care about the peer's address */
  ignored_length = 0;
  while (
#ifdef HAVE_LINUX_IF_H
	 (s = accept4(alarm->poll.fd, NULL, &ignored_length,O_NONBLOCK))
#else
	 (s = accept(alarm->poll.fd,NULL, &ignored_length))
#endif
      != -1
  ) {
    monitor_new_client(s);
  }
  if (errno != EAGAIN) {
#ifdef HAVE_LINUX_IF_H
    WHY_perror("accept4(O_NONBLOCK)");
#else
    WHY_perror("accept");
#endif
  }
}

static void monitor_close(struct monitor_context *c){
  struct monitor_context *last;
  
  INFO("Tearing down monitor client");
  
  unwatch(&c->alarm);
  close(c->alarm.poll.fd);
  c->alarm.poll.fd=-1;
  
  monitor_socket_count--;
  last = &monitor_sockets[monitor_socket_count];
  if (last != c){
    unwatch(&last->alarm);
    bcopy(last, c,
	  sizeof(struct monitor_context));
    watch(&c->alarm);
  }
}

void monitor_client_poll(struct sched_ent *alarm)
{
  /* Read available data from a monitor socket */
  struct monitor_context *c=(struct monitor_context *)alarm;
  errno=0;
  int bytes;
  
  if (alarm->poll.revents & POLLIN) {
    switch(c->state) {
    case MONITOR_STATE_COMMAND:
      bytes = 1;
      while(bytes == 1) {
	if (c->line_length >= MONITOR_LINE_LENGTH) {
	  c->line_length=0;
	  monitor_write_error(c,"Command too long");
	  monitor_close(c);
	  return;
	}
	bytes = read(c->alarm.poll.fd, &c->line[c->line_length], 1);
	if (bytes < 1) {
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
	    monitor_close(c);
	    return;
	  }
	}
	
	// silently skip all \r characters
	if (c->line[c->line_length] == '\r')
	  continue;
	
	// parse data length as soon as we see the : delimiter, 
	// so we can read the rest of the line into the start of the buffer
	if (c->data_expected==0 && c->line[0]=='*' && c->line[c->line_length]==':'){
	  c->line[c->line_length]=0;
	  c->data_expected=atoi(c->line +1);
	  c->line_length=0;
	  continue;
	}
	
	if (c->line[c->line_length] == '\n') {
	  /* got whole command line, start reading data if required */
	  c->line[c->line_length]=0;
	  c->state=MONITOR_STATE_DATA;
	  c->data_offset=0;
	  break;
	}
	
	c->line_length += bytes;
      }
	
      if (c->state!=MONITOR_STATE_DATA)
	break;
	
      // else fall through
    case MONITOR_STATE_DATA:
	
      if (c->data_expected - c->data_offset >0){
	bytes = read(c->alarm.poll.fd,
		     &c->buffer[c->data_offset],
		     c->data_expected - c->data_offset);
	if (bytes < 1) {
	  switch(errno) {
	  case EAGAIN: case EINTR: 
	    /* transient errors */
	    break;
	  default:
	    /* all other errors; close socket */
	      WHYF("Tearing down monitor client due to errno=%d",
		   errno);
	      monitor_close(c);
	      return;
	  }
	}
	
	c->data_offset += bytes;
      }
      
      if (c->data_offset < c->data_expected)
	break;
	
      /* we have the next command and all of the binary data we were expecting. Now we can process it */
      monitor_process_command(c);
	
      // fall through
    default:
      // reset parsing state
      c->state = MONITOR_STATE_COMMAND;
      c->data_expected = 0;
      c->data_offset = 0;
      c->line_length = 0;
    }
  }
  
  if (alarm->poll.revents & (POLLHUP | POLLERR)) {
    monitor_close(c);
  }
  return;
}
 
static void monitor_new_client(int s) {
#ifdef SO_PEERCRED
  struct ucred			ucred;
  socklen_t			len;
  int				res;
#elif defined(HAVE_GETPEEREID)
  gid_t				othergid;
#elif defined(HAVE_UCRED_H)
  ucred_t			*ucred;
#endif
  uid_t				otheruid;
  struct monitor_context	*c;

  if (set_nonblock(s) == -1)
    goto error;

#ifdef SO_PEERCRED
  /* Linux way */
  len = sizeof(ucred);
  res = getsockopt(s, SOL_SOCKET, SO_PEERCRED, &ucred, &len);
  if (res) { 
    WHY_perror("getsockopt(SO_PEERCRED)");
    goto error;
  }
  if (len < sizeof(ucred)) {
    WHYF("getsockopt(SO_PEERCRED) returned the wrong size (Got %d expected %d)", len, sizeof(ucred));
    goto error;
  }
  otheruid = ucred.uid;
#elif defined(HAVE_UCRED_H)
  /* Solaris way */
  if (getpeerucred(s, &ucred) != 0) {
    WHY_perror("getpeerucred");
    goto error;
  }
  otheruid = ucred_geteuid(ucred);
  ucred_free(ucred);
#elif defined(HAVE_GETPEEREID)
  /* BSD way */
  if (getpeereid(s, &otheruid, &othergid) != 0) {
    WHY_perror("getpeereid");
    goto error;
  }
#else
#error No way to get socket peer credentials
#endif

  if (otheruid != getuid()) {
    if (otheruid != config.monitor.uid){
      WHYF("monitor.socket client has wrong uid (%d versus %d)", otheruid,getuid());
      write_str(s, "\nCLOSE:Incorrect UID\n");
      goto error;
    }
  }
  if (monitor_socket_count >= MAX_MONITOR_SOCKETS
	     ||monitor_socket_count < 0) {
    write_str(s, "\nCLOSE:All sockets busy\n");
    goto error;
  }
  
  c = &monitor_sockets[monitor_socket_count++];
  c->alarm.function = monitor_client_poll;
  client_stats.name = "monitor_client_poll";
  c->alarm.stats=&client_stats;
  c->alarm.poll.fd = s;
  c->alarm.poll.events=POLLIN;
  c->line_length = 0;
  c->state = MONITOR_STATE_COMMAND;
  write_str(s,"\nINFO:You are talking to servald\n");
  INFOF("Got %d clients", monitor_socket_count);
  watch(&c->alarm);  
  
  return;
  
  error:
    close(s);
    return;
}

void monitor_get_all_supported_codecs(unsigned char *codecs){
  int i, j;
  bzero(codecs,CODEC_FLAGS_LENGTH);
  for(i=monitor_socket_count -1;i>=0;i--) {
    if (monitor_sockets[i].flags & MONITOR_VOMP){
      for (j=0;j<CODEC_FLAGS_LENGTH;j++)
	codecs[j]|=monitor_sockets[i].supported_codecs[j];
    }
  }
}

static int monitor_set(const struct cli_parsed *parsed, void *context)
{
  struct monitor_context *c=context;
  if (strcase_startswith(parsed->args[1],"vomp",NULL)){
    c->flags|=MONITOR_VOMP;
    // store the list of supported codecs against the monitor connection,
    // since we need to forget about them when the client disappears.
    int i;
    for (i = 2; i < parsed->argc; ++i) {
      int codec = atoi(parsed->args[i]);
      if (codec>=0 && codec <=255)
	set_codec_flag(codec, c->supported_codecs);
    }
  }else if (strcase_startswith(parsed->args[1],"rhizome", NULL))
    c->flags|=MONITOR_RHIZOME;
  else if (strcase_startswith(parsed->args[1],"peers", NULL))
    c->flags|=MONITOR_PEERS;
  else if (strcase_startswith(parsed->args[1],"dnahelper", NULL))
    c->flags|=MONITOR_DNAHELPER;
  else if (strcase_startswith(parsed->args[1],"links", NULL))
    c->flags|=MONITOR_LINKS;
  else
    return monitor_write_error(c,"Unknown monitor type");

  char msg[1024];
  snprintf(msg,sizeof(msg),"\nMONITORSTATUS:%d\n",c->flags);
  write_str(c->alarm.poll.fd,msg);
  
  return 0;
}

static int monitor_clear(const struct cli_parsed *parsed, void *context)
{
  struct monitor_context *c=context;
  if (strcase_startswith(parsed->args[1],"vomp",NULL))
    c->flags&=~MONITOR_VOMP;
  else if (strcase_startswith(parsed->args[1],"rhizome", NULL))
    c->flags&=~MONITOR_RHIZOME;
  else if (strcase_startswith(parsed->args[1],"peers", NULL))
    c->flags&=~MONITOR_PEERS;
  else if (strcase_startswith(parsed->args[1],"dnahelper", NULL))
    c->flags&=~MONITOR_DNAHELPER;
  else if (strcase_startswith(parsed->args[1],"links", NULL))
    c->flags&=~MONITOR_LINKS;
  else
    return monitor_write_error(c,"Unknown monitor type");
  
  char msg[1024];
  snprintf(msg,sizeof(msg),"\nINFO:%d\n",c->flags);
  write_str(c->alarm.poll.fd,msg);
  
  return 0;
}

static int monitor_lookup_match(const struct cli_parsed *parsed, void *context)
{
  struct monitor_context *c = context;
  const char *sid = parsed->args[2];
  const char *ext = parsed->args[4];
  const char *name = parsed->argc >= 4 ? parsed->args[5] : "";
  
  if (!my_subscriber)
    return monitor_write_error(c,"I don't know who I am");
  
  struct sockaddr_mdp addr={
    .port = atoi(parsed->args[3]),
  };
  
  if (stowSid((unsigned char *)&addr.sid, 0, sid)==-1)
    return monitor_write_error(c,"Invalid SID");
  
  char uri[256];
  snprintf(uri, sizeof(uri), "sid://%s/external/%s", alloca_tohex_sid(my_subscriber->sid), ext);
  DEBUGF("Sending response to %s for %s", sid, uri);
  overlay_mdp_dnalookup_reply(&addr, my_subscriber->sid, uri, ext, name);
  return 0;
}

static int monitor_call(const struct cli_parsed *parsed, void *context)
{
  struct monitor_context *c=context;
  unsigned char sid[SID_SIZE];
  if (stowSid(sid, 0, parsed->args[1]) == -1)
    return monitor_write_error(c,"invalid SID, so cannot place call");
  
  if (!my_subscriber)
    return monitor_write_error(c,"I don't know who I am");
  struct subscriber *remote = find_subscriber(sid, SID_SIZE, 1);
  vomp_dial(my_subscriber, remote, parsed->args[2], parsed->args[3]);
  return 0;
}

static int monitor_call_ring(const struct cli_parsed *parsed, void *context)
{
  struct vomp_call_state *call=vomp_find_call_by_session(strtol(parsed->args[1],NULL,16));
  if (!call)
    monitor_tell_formatted(MONITOR_VOMP, "\nHANGUP:%s\n", parsed->args[1]);
  else
    vomp_ringing(call);
  return 0;
}

static int monitor_call_pickup(const struct cli_parsed *parsed, void *context)
{
  struct vomp_call_state *call=vomp_find_call_by_session(strtol(parsed->args[1],NULL,16));
  if (!call)
    monitor_tell_formatted(MONITOR_VOMP, "\nHANGUP:%s\n", parsed->args[1]);
  else
    vomp_pickup(call);
  return 0;
}

static int monitor_call_audio(const struct cli_parsed *parsed, void *context)
{
  struct monitor_context *c=context;
  struct vomp_call_state *call=vomp_find_call_by_session(strtol(parsed->args[1],NULL,16));
  
  if (!call){
    monitor_tell_formatted(MONITOR_VOMP, "\nHANGUP:%s\n", parsed->args[1]);
    return 0;
  }
  
  int codec_type = atoi(parsed->args[2]);
  int time = parsed->argc >=4 ? atoi(parsed->args[3]) : -1;
  int sequence = parsed->argc >= 5 ? atoi(parsed->args[4]) : -1;
  
  vomp_received_audio(call, codec_type, time, sequence, c->buffer, c->data_expected);
  return 0;
}

static int monitor_call_hangup(const struct cli_parsed *parsed, void *context)
{
  struct vomp_call_state *call=vomp_find_call_by_session(strtol(parsed->args[1],NULL,16));
  if (!call)
    monitor_tell_formatted(MONITOR_VOMP, "\nHANGUP:%s\n", parsed->args[1]);
  else
    vomp_hangup(call);
  return 0;
}

static int monitor_call_dtmf(const struct cli_parsed *parsed, void *context)
{
  struct monitor_context *c=context;
  struct vomp_call_state *call=vomp_find_call_by_session(strtol(parsed->args[1],NULL,16));
  if (!call)
    return monitor_write_error(c,"Invalid call token");
  const char *digits = parsed->args[2];
  
  int i;
  for(i=0;i<strlen(digits);i++) {
    int digit=vomp_parse_dtmf_digit(digits[i]);
    if (digit<0)
      monitor_write_error(c,"Invalid DTMF digit");
    else{
      /* 80ms standard tone duration, so that it is a multiple
       of the majority of codec time units (70ms is the nominal
       DTMF tone length for most systems). */
      unsigned char code = digit <<4;
      vomp_received_audio(call, VOMP_CODEC_DTMF, -1, -1, &code, 1);
    }
  }
  return 0;
}

static int monitor_help(const struct cli_parsed *parsed, void *context);

struct cli_schema monitor_commands[] = {
  {monitor_help,{"help",NULL},0,""},
  {monitor_set,{"monitor","vomp","<codec>","...",NULL},0,""},
  {monitor_set,{"monitor","<type>",NULL},0,""},
  {monitor_clear,{"ignore","<type>",NULL},0,""},
  {monitor_lookup_match,{"lookup","match","<sid>","<port>","<ext>","[<name>]",NULL},0,""},
  {monitor_call, {"call","<sid>","<local_did>","<remote_did>",NULL},0,""},
  {monitor_call_ring, {"ringing","<token>",NULL},0,""},
  {monitor_call_pickup, {"pickup","<token>",NULL},0,""},
  {monitor_call_audio,{"audio","<token>","<type>","[<time>]","[<sequence>]",NULL},0,""},
  {monitor_call_hangup, {"hangup","<token>",NULL},0,""},
  {monitor_call_dtmf, {"dtmf","<token>","<digits>",NULL},0,""},
  {NULL},
};

int monitor_process_command(struct monitor_context *c) 
{
  char *argv[16]={NULL,};
  int argc = parse_argv(c->line, ' ', argv, 16);
  
  struct cli_parsed parsed;
  if (cli_parse(argc, (const char *const*)argv, monitor_commands, &parsed) || cli_invoke(&parsed, c))
    return monitor_write_error(c, "Invalid command");
  return 0;
}

static int monitor_help(const struct cli_parsed *parsed, void *context)
{
  struct monitor_context *c=context;
  strbuf b = strbuf_alloca(16384);
  strbuf_puts(b, "\nINFO:Usage\n");
  cli_usage(monitor_commands, XPRINTF_STRBUF(b));
  (void)write_all(c->alarm.poll.fd, strbuf_str(b), strbuf_len(b));
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
	   alloca_tohex_sid(m->cryptoSignPublic),
	   service ? service : "",
	   m->version,
	   m->fileLength,
	   sender ? sender : "",
	   recipient ? recipient : "",
	   m->dataFileName?m->dataFileName:"");
  for(i=monitor_socket_count -1;i>=0;i--) {
    if (monitor_sockets[i].flags & MONITOR_RHIZOME) {
      if ( set_nonblock(monitor_sockets[i].alarm.poll.fd) == -1
	|| write_str_nonblock(monitor_sockets[i].alarm.poll.fd, msg) == -1
	|| set_block(monitor_sockets[i].alarm.poll.fd) == -1
      ) {
	INFO("Tearing down monitor client");
	monitor_close(&monitor_sockets[i]);
      }
    }
  }
  return 0;
}

int monitor_announce_peer(const unsigned char *sid)
{
  return monitor_tell_formatted(MONITOR_PEERS, "\nNEWPEER:%s\n", alloca_tohex_sid(sid));
}

int monitor_announce_unreachable_peer(const unsigned char *sid)
{
  return monitor_tell_formatted(MONITOR_PEERS, "\nOLDPEER:%s\n", alloca_tohex_sid(sid));
}

int monitor_announce_link(int hop_count, struct subscriber *transmitter, struct subscriber *receiver)
{
  return monitor_tell_formatted(MONITOR_LINKS, "\nLINK:%d:%s:%s\n", 
    hop_count,
    transmitter?alloca_tohex_sid(transmitter->sid):"",
    alloca_tohex_sid(receiver->sid));
}

// test if any monitor clients are interested in a particular type of event
int monitor_client_interested(int mask){
  int i;
  for(i=monitor_socket_count -1;i>=0;i--) {
    if (monitor_sockets[i].flags & mask)
      return 1;
  }
  return 0;
}

int monitor_tell_clients(char *msg, int msglen, int mask)
{
  int i;
  IN();
  for(i=monitor_socket_count -1;i>=0;i--) {
    if (monitor_sockets[i].flags & mask) {
      // DEBUG("Writing AUDIOPACKET to client");
      if ( set_nonblock(monitor_sockets[i].alarm.poll.fd) == -1
	|| write_all_nonblock(monitor_sockets[i].alarm.poll.fd, msg, msglen) == -1
	|| set_block(monitor_sockets[i].alarm.poll.fd) == -1
      ) {
	INFOF("Tearing down monitor client #%d", i);
	monitor_close(&monitor_sockets[i]);
      }
    }
  }
  RETURN(0);
}

int monitor_tell_formatted(int mask, char *fmt, ...){
  char msg[1024];
  int n;
  va_list ap;
  
  va_start(ap, fmt);
  n=vsnprintf(msg, sizeof(msg), fmt, ap);
  va_end(ap);
  monitor_tell_clients(msg, n, mask);
  return 0;
}
