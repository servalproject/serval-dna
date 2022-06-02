/*
Copyright (C) 2010-2012 Paul Gardner-Stephen
Copyright (C) 2010-2013 Serval Project Inc.
 
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
  Portions Copyright (C) 2013 Petter Reinholdtsen
  Some rights reserved

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
  FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
  COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.
*/

/*
  Android does unix domain sockets, but only stream sockets, not datagram sockets.
  So we need a separate monitor interface for Android. A bit of a pain, but in
  fact it lets us make a very Android/Java-friendly interface, without any binary
  data structures (except for a binary extent for an audio sample block).
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/stat.h>
#include "serval.h"
#include "conf.h"
#include "rhizome.h"
#include "cli.h"
#include "str.h"
#include "strbuf_helpers.h"
#include "overlay_address.h"
#include "overlay_interface.h"
#include "monitor-client.h"
#include "socket.h"
#include "dataformats.h"
#include "server.h"
#include "route_link.h"
#include "debug.h"
#include "mdp_services.h"

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
  enum {
    MONITOR_STATE_UNUSED,
    MONITOR_STATE_COMMAND,
    MONITOR_STATE_DATA
  } state;
  unsigned char buffer[MONITOR_DATA_SIZE];
  int data_expected;
  int data_offset;
};

#define MAX_MONITOR_SOCKETS 8
unsigned monitor_socket_count=0;
struct monitor_context monitor_sockets[MAX_MONITOR_SOCKETS];

int monitor_process_command(struct monitor_context *c);
int monitor_process_data(struct monitor_context *c);
static void monitor_new_client(int s);

struct sched_ent named_socket;
struct profile_total named_stats;
struct profile_total client_stats;

static void monitor_setup_sockets()
{
  if (serverMode == SERVER_NOT_RUNNING)
    return;

  int sock = -1;
  if ((sock = esocket(AF_UNIX, SOCK_STREAM, 0)) == -1)
    goto error;
  struct socket_address addr;
  if (make_local_sockaddr(&addr, "monitor.socket") == -1)
    goto error;
  if (socket_bind(sock, &addr) == -1)
    goto error;
  if (socket_listen(sock, MAX_MONITOR_SOCKETS) == -1)
    goto error;
  if (socket_set_reuseaddr(sock, 1) == -1)
    WHY("Could not indicate reuse addresses. Not necessarily a problem (yet)");
  socket_set_rcvbufsize(sock, 64 * 1024);
  named_socket.function=monitor_poll;
  named_stats.name="monitor_poll";
  named_socket.stats=&named_stats;
  named_socket.poll.fd=sock;
  named_socket.poll.events=POLLIN;
  watch(&named_socket);
  INFOF("Monitor socket: fd=%d %s", sock, alloca_socket_address(&addr));
  return;
  
error:
  if (sock != -1)
    close(sock);
  serverMode = SERVER_NOT_RUNNING;
}
DEFINE_TRIGGER(startup, monitor_setup_sockets);

#define monitor_write_error(C,E) _monitor_write_error(__WHENCE__, C, E)
static int _monitor_write_error(struct __sourceloc __whence, struct monitor_context *c, const char *error){
  char msg[256];
  WHY(error);
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
  while ((s = accept(alarm->poll.fd,NULL, &ignored_length))!= -1) {
    monitor_new_client(s);
  }
  if (errno != EAGAIN) {
    WHY_perror("accept");
  }
}

static void monitor_close(struct monitor_context *c){
  INFOF("Tearing down monitor client fd=%d", c->alarm.poll.fd);
  
  if (serverMode != SERVER_NOT_RUNNING && (c->flags & MONITOR_QUIT_ON_DISCONNECT)){
    INFOF("Stopping server due to client disconnecting");
    server_close();
  }
  unwatch(&c->alarm);
  close(c->alarm.poll.fd);
  c->alarm.poll.fd=-1;
  c->state=MONITOR_STATE_UNUSED;
  c->flags=0;
}

static void monitor_shutdown()
{
  if (named_socket.poll.fd == -1)
    return;
  unwatch(&named_socket);
  close(named_socket.poll.fd);
  named_socket.poll.fd=-1;

  int i;
  for(i=monitor_socket_count -1;i>=0;i--)
    monitor_close(&monitor_sockets[i]);
}
DEFINE_TRIGGER(shutdown, monitor_shutdown);

void monitor_client_poll(struct sched_ent *alarm)
{
  /* Read available data from a monitor socket */
  struct monitor_context *c=(struct monitor_context *)alarm;
  errno=0;
  int bytes;

  if (alarm->poll.revents & POLLIN) {
    switch(c->state) {
    case MONITOR_STATE_UNUSED:
      FATAL("should not poll unused client");

    case MONITOR_STATE_COMMAND:
      bytes = 1;
      while(bytes == 1) {
	if (c->line_length >= MONITOR_LINE_LENGTH) {
	  c->line_length=0;
	  monitor_write_error(c,"Command too long");
	  DEBUG(monitor, "close monitor because command too long");
	  monitor_close(c);
	  return;
	}
	bytes = read_nonblock(c->alarm.poll.fd, &c->line[c->line_length], 1);
	if (bytes == -1) {
	  DEBUG(monitor, "close monitor due to read error");
	  monitor_close(c);
	  return;
	}
	if (bytes == -2 || bytes == 0)
	  continue; // no bytes available to read
	
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
	  // got whole command line, start reading data if required
	  c->line[c->line_length]=0;
	  c->state=MONITOR_STATE_DATA;
	  c->data_offset=0;
	  break;
	}
	
	c->line_length += bytes;
      }
	
      // if run out of characters to read before reaching the end of a command, then check for HUP
      // now in case the client terminated abnormally
      if (c->state != MONITOR_STATE_DATA)
	break;
      // else fall through...

    case MONITOR_STATE_DATA:
      if (c->data_expected - c->data_offset >0){
	bytes = read_nonblock(c->alarm.poll.fd, &c->buffer[c->data_offset], c->data_expected - c->data_offset);
	if (bytes == -2 || bytes == 0)
	  break; // no bytes available to read
	if (bytes == -1) {
	  DEBUG(monitor, "close monitor due to read error");
	  monitor_close(c);
	  return;
	}

	c->data_offset += bytes;
      }
      
      // if run out of characters to read before reaching the expected number, then check for HUP
      // now in case the client terminated abnormally
      if (c->data_offset < c->data_expected)
	break;
	
      // we have received all of the binary data we were expecting
      monitor_process_command(c);
	
      // reset parsing state
      c->state = MONITOR_STATE_COMMAND;
      c->data_expected = 0;
      c->data_offset = 0;
      c->line_length = 0;

      // poll again to finish processing all queued commands before checking for HUP, so that any
      // queued "quit" command (quit on HUP) is processed before the HUP is handled
      return;
    }
  }
  if (alarm->poll.revents & (POLLHUP | POLLERR)) {
    DEBUGF(monitor, "client disconnection (%s)", alloca_poll_events(alarm->poll.revents));
    monitor_close(c);
  }
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
  struct monitor_context	*c=NULL;

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
  if ((size_t)len < sizeof(ucred)) {
    WHYF("getsockopt(SO_PEERCRED) returned the wrong size (Got %d expected %d)", len, (int)sizeof(ucred));
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
  
  unsigned i;
  for (i=0;i<monitor_socket_count;i++){
    if (monitor_sockets[i].state == MONITOR_STATE_UNUSED){
      c = &monitor_sockets[i];
      break;
    }
  }
  
  if (!c){
    if (monitor_socket_count >= MAX_MONITOR_SOCKETS) {
      write_str(s, "\nCLOSE:All sockets busy\n");
      goto error;
    }
    
    c = &monitor_sockets[monitor_socket_count++];
  }
  c->alarm.function = monitor_client_poll;
  client_stats.name = "monitor_client_poll";
  c->alarm.stats=&client_stats;
  c->alarm.poll.fd = s;
  c->alarm.poll.events = POLLIN | POLLHUP;
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

static void monitor_announce_peer(struct subscriber *subscriber, int prior_reachable)
{
  monitor_tell_formatted(MONITOR_LINKS, "\nLINK:%d:%s:%s\n",
    subscriber->hop_count,
    subscriber->prior_hop ? alloca_tohex_sid_t(subscriber->prior_hop->sid) : "",
    alloca_tohex_sid_t(subscriber->sid));

  if ((prior_reachable & REACHABLE) && (!(subscriber->reachable & REACHABLE)))
    monitor_tell_formatted(MONITOR_PEERS, "\nOLDPEER:%s\n", alloca_tohex_sid_t(subscriber->sid));
  if ((!(prior_reachable & REACHABLE)) && (subscriber->reachable & REACHABLE))
    monitor_tell_formatted(MONITOR_PEERS, "\nNEWPEER:%s\n", alloca_tohex_sid_t(subscriber->sid));
}
DEFINE_TRIGGER(link_change, monitor_announce_peer);

static int monitor_announce_all_peers(void **record, void *UNUSED(context))
{
  struct subscriber *subscriber = *record;
  if (subscriber->reachable&REACHABLE)
    monitor_announce_peer(subscriber, REACHABLE_NONE);
  return 0;
}

static int monitor_set(const struct cli_parsed *parsed, struct cli_context *context)
{
  DEBUG_cli_parsed(monitor, parsed);
  struct monitor_context *c=context->context;
  if (strcase_startswith(parsed->args[1],"vomp",NULL)){
    c->flags|=MONITOR_VOMP;
    // store the list of supported codecs against the monitor connection,
    // since we need to forget about them when the client disappears.
    unsigned i;
    for (i = 2; i < parsed->argc; ++i) {
      int codec = atoi(parsed->args[i]);
      if (codec>=0 && codec <=255)
	set_codec_flag(codec, c->supported_codecs);
    }
  }else if (strcase_startswith(parsed->args[1],"rhizome", NULL)){
    c->flags|=MONITOR_RHIZOME;
  }else if (strcase_startswith(parsed->args[1],"peers", NULL)){
    c->flags|=MONITOR_PEERS;
    enum_subscribers(NULL, monitor_announce_all_peers, NULL);
  }else if (strcase_startswith(parsed->args[1],"dnahelper", NULL)){
    c->flags|=MONITOR_DNAHELPER;
  }else if (strcase_startswith(parsed->args[1],"links", NULL)){
    c->flags|=MONITOR_LINKS;
    enum_subscribers(NULL, monitor_announce_all_peers, NULL);
  }else if (strcase_startswith(parsed->args[1],"quit", NULL)){
    c->flags|=MONITOR_QUIT_ON_DISCONNECT;
  }else if (strcase_startswith(parsed->args[1],"interface", NULL)){
    c->flags|=MONITOR_INTERFACE;
    unsigned i;
    for (i=0;i<OVERLAY_MAX_INTERFACES;i++){
      if (overlay_interfaces[i].state == INTERFACE_STATE_UP)
	monitor_tell_formatted(MONITOR_INTERFACE, "\nINTERFACE:%u:%s:UP\n", i, overlay_interfaces[i].name);
    }
  }else
    return monitor_write_error(c,"Unknown monitor type");

  char msg[1024];
  snprintf(msg,sizeof(msg),"\nMONITORSTATUS:%d\n",c->flags);
  write_str(c->alarm.poll.fd,msg);
  
  return 0;
}

static int monitor_clear(const struct cli_parsed *parsed, struct cli_context *context)
{
  DEBUG_cli_parsed(monitor, parsed);
  struct monitor_context *c=context->context;
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
  else if (strcase_startswith(parsed->args[1],"quit", NULL))
    c->flags&=~MONITOR_QUIT_ON_DISCONNECT;
  else if (strcase_startswith(parsed->args[1],"interface", NULL))
    c->flags&=~MONITOR_INTERFACE;
  else
    return monitor_write_error(c,"Unknown monitor type");
  
  char msg[1024];
  snprintf(msg,sizeof(msg),"\nINFO:%d\n",c->flags);
  write_str(c->alarm.poll.fd,msg);
  
  return 0;
}

static int monitor_lookup_match(const struct cli_parsed *parsed, struct cli_context *context)
{
  DEBUG_cli_parsed(monitor, parsed);
  struct monitor_context *c = context->context;
  const char *sid = parsed->args[2];
  const char *ext = parsed->args[4];
  const char *name = parsed->argc >= 4 ? parsed->args[5] : "";
  
  mdp_port_t dest_port = atoi(parsed->args[3]);
  sid_t dest;
  if (str_to_sid_t(&dest, sid) == -1)
    return monitor_write_error(c,"Invalid SID");
    
  struct subscriber *destination = find_subscriber(dest.binary, sizeof(dest), 1);
  
  char uri[256];
  snprintf(uri, sizeof(uri), "sid://%s/external/%s", alloca_tohex_sid_t(get_my_subscriber(1)->sid), ext);
  DEBUGF(monitor, "Sending response to %s for %s", sid, uri);
  overlay_mdp_dnalookup_reply(destination, dest_port, get_my_subscriber(1), uri, ext, name);
  return 0;
}

static int monitor_call(const struct cli_parsed *parsed, struct cli_context *context)
{
  DEBUG_cli_parsed(monitor, parsed);
  struct monitor_context *c=context->context;
  sid_t sid;
  if (str_to_sid_t(&sid, parsed->args[1]) == -1)
    return monitor_write_error(c,"invalid SID, so cannot place call");
  struct subscriber *remote = find_subscriber(sid.binary, SID_SIZE, 1);
  vomp_dial(get_my_subscriber(1), remote, parsed->args[2], parsed->args[3]);
  return 0;
}

static int monitor_call_ring(const struct cli_parsed *parsed, struct cli_context *UNUSED(context))
{
  DEBUG_cli_parsed(monitor, parsed);
  struct vomp_call_state *call=vomp_find_call_by_session(strtol(parsed->args[1],NULL,16));
  if (!call)
    monitor_tell_formatted(MONITOR_VOMP, "\nHANGUP:%s\n", parsed->args[1]);
  else
    vomp_ringing(call);
  return 0;
}

static int monitor_call_pickup(const struct cli_parsed *parsed, struct cli_context *UNUSED(context))
{
  DEBUG_cli_parsed(monitor, parsed);
  struct vomp_call_state *call=vomp_find_call_by_session(strtol(parsed->args[1],NULL,16));
  if (!call)
    monitor_tell_formatted(MONITOR_VOMP, "\nHANGUP:%s\n", parsed->args[1]);
  else
    vomp_pickup(call);
  return 0;
}

static int monitor_call_audio(const struct cli_parsed *parsed, struct cli_context *context)
{
  DEBUG_cli_parsed(monitor, parsed);
  struct monitor_context *c=context->context;
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

static int monitor_call_hangup(const struct cli_parsed *parsed, struct cli_context *UNUSED(context))
{
  DEBUG_cli_parsed(monitor, parsed);
  struct vomp_call_state *call=vomp_find_call_by_session(strtol(parsed->args[1],NULL,16));
  if (!call)
    monitor_tell_formatted(MONITOR_VOMP, "\nHANGUP:%s\n", parsed->args[1]);
  else
    vomp_hangup(call);
  return 0;
}

static int monitor_call_dtmf(const struct cli_parsed *parsed, struct cli_context *context)
{
  DEBUG_cli_parsed(monitor, parsed);
  struct monitor_context *c=context->context;
  struct vomp_call_state *call=vomp_find_call_by_session(strtol(parsed->args[1],NULL,16));
  if (!call)
    return monitor_write_error(c,"Invalid call token");
  const char *digits = parsed->args[2];
  
  unsigned i;
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

static int monitor_help(const struct cli_parsed *parsed, struct cli_context *context);

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
  {NULL, {NULL, NULL, NULL, NULL},0,NULL},
};

int monitor_process_command(struct monitor_context *c) 
{
  char *argv[16]={NULL,};
  int argc = parse_argv(c->line, ' ', argv, 16);
  
  struct cli_parsed parsed;
  struct cli_context context={.context=c};
  if (cli_parse(argc, (const char *const*)argv, monitor_commands, NULL, &parsed) || cli_invoke(&parsed, &context))
    return monitor_write_error(c, "Invalid command");
  return 0;
}

static int monitor_help(const struct cli_parsed *parsed, struct cli_context *context)
{
  DEBUG_cli_parsed(monitor, parsed);
  struct monitor_context *c=context->context;
  strbuf b = strbuf_alloca(16384);
  strbuf_puts(b, "\nINFO:Usage\n");
  cli_usage_parsed(parsed, XPRINTF_STRBUF(b));
  (void)write_all(c->alarm.poll.fd, strbuf_str(b), strbuf_len(b));
  return 0;
}

static void monitor_announce_bundle(rhizome_manifest *m)
{ 
  // This message can contain the entire manifest, which itself can be 1024 bytes long.
  // Thus we need to allow more space.
  char msg[2048];
  int len = snprintf(msg,1024,"\n*%zd:BUNDLE:%s\n",
           m->manifest_all_bytes,
	   alloca_tohex_rhizome_bid_t(m->keypair.public_key));

  if ((len+m->manifest_all_bytes)<sizeof(msg)) {
    bcopy(m->manifestdata, &msg[len], m->manifest_all_bytes);
    len+=m->manifest_all_bytes;
    msg[len++]='\n';
  }
  monitor_tell_clients(msg, len, MONITOR_RHIZOME);
}
DEFINE_TRIGGER(bundle_add, monitor_announce_bundle);

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
  int i, count=0;
  IN();
  for(i=monitor_socket_count -1;i>=0;i--) {
    if (monitor_sockets[i].flags & mask) {
      // DEBUG("Writing AUDIOPACKET to client");
      if ( write_all_nonblock(monitor_sockets[i].alarm.poll.fd, msg, msglen) == -1) {
	INFOF("Tear down monitor client #%d due to write error", i);
	monitor_close(&monitor_sockets[i]);
      }else{
	count++;
      }
    }
  }
  RETURN(count);
}

int monitor_tell_formatted(int mask, char *fmt, ...){
  char msg[1024];
  int n;
  va_list ap;
  
  va_start(ap, fmt);
  n=vsnprintf(msg, sizeof(msg), fmt, ap);
  va_end(ap);
  return monitor_tell_clients(msg, n, mask);
}

static void monitor_dna_helper(struct internal_mdp_header *header, const char *did)
{
    monitor_tell_formatted(MONITOR_DNAHELPER, "LOOKUP:%s:%d:%s\n",
			   alloca_tohex_sid_t(header->source->sid), header->source_port,
			   did);
}
DEFINE_TRIGGER(dna_lookup, monitor_dna_helper);


static void monitor_interface_change(struct overlay_interface *interface, unsigned UNUSED(count)){
  unsigned i = interface - overlay_interfaces;
  if (interface->state==INTERFACE_STATE_UP)
    monitor_tell_formatted(MONITOR_INTERFACE, "\nINTERFACE:%u:%s:UP\n", i, interface->name);
  else if(interface->state==INTERFACE_STATE_DOWN)
    monitor_tell_formatted(MONITOR_INTERFACE, "\nINTERFACE:%u:%s:DOWN\n", i, interface->name);
}

DEFINE_TRIGGER(iupdown, monitor_interface_change);


