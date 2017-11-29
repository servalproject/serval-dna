/* 
 Copyright (C) 2012-2013 Serval Project Inc.
 
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#ifdef HAVE_POLL_H
#include <poll.h>
#endif

#include "serval.h"
#include "console.h"
#include "conf.h"
#include "cli.h"
#include "monitor-client.h"
#include "str.h"
#include "constants.h"
#include "strbuf.h"
#include "strbuf_helpers.h"
#include "commandline.h"
#include "xprintf.h"

static int console_dial(const struct cli_parsed *parsed, struct cli_context *context);
static int console_answer(const struct cli_parsed *parsed, struct cli_context *context);
static int console_hangup(const struct cli_parsed *parsed, struct cli_context *context);
static int console_audio(const struct cli_parsed *parsed, struct cli_context *context);
static int console_usage(const struct cli_parsed *parsed, struct cli_context *context);
static int console_quit(const struct cli_parsed *parsed, struct cli_context *context);
static int console_set(const struct cli_parsed *parsed, struct cli_context *context);
static int console_clear(const struct cli_parsed *parsed, struct cli_context *context);
static void monitor_read(struct sched_ent *alarm);

struct cli_schema console_commands[]={
  {console_answer,{"answer",NULL},0,"Answer an incoming phone call"},
  {console_dial,{"call","<sid>","[<local_number>]","[<remote_extension>]",NULL},0,"Start dialling a given person"},
  {console_hangup,{"hangup",NULL},0,"Hangup the phone line"},
  {console_usage,{"help",NULL},0,"This usage message"},
  {console_audio,{"say","...",NULL},0,"Send a text string to the other party"},
  {console_quit,{"quit",NULL},0,"Exit process"},
  {console_set,{"monitor","<flag>",NULL},0,"Set an arbitrary monitor flag"},
  {console_clear,{"ignore","<flag>",NULL},0,"Clear an arbitrary monitor flag"},
  {NULL, {NULL, NULL, NULL}, 0, NULL},
};

struct profile_total monitor_profile={
  .name="monitor_read",
};
struct sched_ent monitor_alarm={
  .poll = {.fd = STDIN_FILENO,.events = POLLIN},
  .function = monitor_read,
  .stats=&monitor_profile,
};

struct call{
  struct call *_next;
  int token;
  char ring_in;
};

struct call *calls=NULL;

struct monitor_state *monitor_state;
struct command_state *stdin_state;

static void send_hangup(int session_id){
  monitor_client_writeline(monitor_alarm.poll.fd, "hangup %06x\n",session_id);
}
static void send_ringing(int session_id){
  monitor_client_writeline(monitor_alarm.poll.fd, "ringing %06x\n",session_id);
}
static void send_pickup(int session_id){
  monitor_client_writeline(monitor_alarm.poll.fd, "pickup %06x\n",session_id);
}
static void send_call(const char *sid, const char *caller_id, const char *remote_ext){
  monitor_client_writeline(monitor_alarm.poll.fd, "call %s %s %s\n", sid, caller_id, remote_ext);
}
static void send_audio(int session_id, unsigned char *buffer, int len, int codec){
  monitor_client_writeline_and_data(monitor_alarm.poll.fd, buffer, len, "audio %06x %d\n", session_id, codec);
}

static struct call* find_call(int token){
  struct call *call = calls;
  while(call){
    if (call->token==token)
      return call;
    call=call->_next;
  }
  return NULL;
}

static int remote_call(char *UNUSED(cmd), int UNUSED(argc), char **argv, unsigned char *UNUSED(data), int UNUSED(dataLen), void *UNUSED(context))
{
  int token = strtol(argv[0], NULL, 16);
  printf("Incoming call for %s (%s) from %s (%s)\n", argv[1], argv[2], argv[3], argv[4]);
  fflush(stdout);
  struct call *call = emalloc_zero(sizeof(struct call));
  call->_next = calls;
  calls=call;
  call->token = token;
  call->ring_in = 1;
  send_ringing(token);
  return 1;
}

static int remote_ringing(char *UNUSED(cmd), int UNUSED(argc), char **argv, unsigned char *UNUSED(data), int UNUSED(dataLen), void *UNUSED(context))
{
  int token = strtol(argv[0], NULL, 16);
  struct call *call=find_call(token);
  if (call){
    printf("Ringing\n");
    fflush(stdout);
  }else
    send_hangup(token);
  return 1;
}

static int remote_pickup(char *UNUSED(cmd), int UNUSED(argc), char **argv, unsigned char *UNUSED(data), int UNUSED(dataLen), void *UNUSED(context))
{
  int token = strtol(argv[0], NULL, 16);
  struct call *call=find_call(token);
  if (call){
    printf("Picked up\n");
    fflush(stdout);
  }else
    send_hangup(token);
  return 1;
}

static int remote_dialing(char *UNUSED(cmd), int UNUSED(argc), char **argv, unsigned char *UNUSED(data), int UNUSED(dataLen), void *UNUSED(context))
{
  int token = strtol(argv[0], NULL, 16);
  struct call *call=emalloc_zero(sizeof(struct call));
  call->token = token;
  call->_next = calls;
  calls = call;
  printf("Dialling\n");
  fflush(stdout);
  return 1;
}

static int remote_hangup(char *UNUSED(cmd), int UNUSED(argc), char **argv, unsigned char *UNUSED(data), int UNUSED(dataLen), void *UNUSED(context))
{
  int token = strtol(argv[0], NULL, 16);
  
  struct call **call=&calls;
  while(*call){
    if ((*call)->token == token){
      printf("Call ended\n");
      fflush(stdout);
      struct call *p=*call;
      *call = p->_next;
      free(p);
    }else{
      call = &(*call)->_next;
    }
  }
  return 1;
}

static int remote_audio(char *UNUSED(cmd), int UNUSED(argc), char **argv, unsigned char *UNUSED(data), int UNUSED(dataLen), void *UNUSED(context))
{
  int token = strtol(argv[0], NULL, 16);
  
  struct call *call=find_call(token);
  if (call){
    int codec = strtol(argv[1], NULL, 10);
//    int start_time = strtol(argv[2], NULL, 10);
//    int sequence = strtol(argv[3], NULL, 10);
    switch (codec){
      case VOMP_CODEC_TEXT:
	data[dataLen]=0;
	printf("%s\n",data);
	break;
      default:
	printf("Unhandled codec %d, len %d\n", codec, dataLen);
	break;
    }
    fflush(stdout);
  }else
    send_hangup(token);
  return 1;
}

static int remote_codecs(char *UNUSED(cmd), int UNUSED(argc), char **argv, unsigned char *UNUSED(data), int UNUSED(dataLen), void *UNUSED(context))
{
  int token = strtol(argv[0], NULL, 16);
  struct call *call=find_call(token);
  if (call){
    int i;
    printf("Codec list");
    for (i=1;i<argc;i++)
      printf(" %s",argv[i]);
    printf("\n");
    fflush(stdout);
  }else
    send_hangup(token);
  return 1;
}

static int remote_print(char *cmd, int argc, char **argv, unsigned char *data, int dataLen, void *UNUSED(context))
{
  int i;
  printf("%s",cmd);
  for (i=0;i<argc;i++){
    printf(" %s",argv[i]);
  }
  printf("\n");
  if (dataLen){
    xhexdump(XPRINTF_STDIO(stdout), data, dataLen, "");
  }
  fflush(stdout);
  return 1;
}

static int remote_noop(char *UNUSED(cmd), int UNUSED(argc), char **UNUSED(argv), unsigned char *UNUSED(data), int UNUSED(dataLen), void *UNUSED(context))
{
  return 1;
}

struct monitor_command_handler console_handlers[]={
  {.command="CALLFROM",      .handler=remote_call},
  {.command="RINGING",       .handler=remote_ringing},
  {.command="ANSWERED",      .handler=remote_pickup},
  {.command="CALLTO",        .handler=remote_dialing},
  {.command="HANGUP",        .handler=remote_hangup},
  {.command="AUDIO",         .handler=remote_audio},
  {.command="CODECS",        .handler=remote_codecs},
  {.command="INFO",          .handler=remote_print},
  {.command="ERROR",         .handler=remote_print},
  {.command="CALLSTATUS",    .handler=remote_noop},
  {.command="KEEPALIVE",     .handler=remote_noop},
  {.command="MONITORSTATUS", .handler=remote_noop},
};

static int console_dial(const struct cli_parsed *parsed, struct cli_context *UNUSED(context))
{
  const char *sid = parsed->args[1];
  const char *local = parsed->argc >= 3 ? parsed->args[2] : "";
  const char *remote = parsed->argc >= 4 ? parsed->args[3] : "";
  send_call(sid, local, remote);
  return 0;
}

static int console_answer(const struct cli_parsed *UNUSED(parsed), struct cli_context *UNUSED(context))
{
  struct call *call = calls;
  while(call){
    if (call->ring_in){
      send_pickup(call->token);
      call->ring_in = 0;
      return 0;
    }
    call = call->_next;
  }
  printf("No ringing call to answer\n");
  fflush(stdout);
  return 0;
}

static int console_hangup(const struct cli_parsed *UNUSED(parsed), struct cli_context *UNUSED(context))
{
  if (calls){
    send_hangup(calls->token);
  }else{
    printf("No call to hangup\n");
    fflush(stdout);
  }
  return 0;
}

static int console_quit(const struct cli_parsed *UNUSED(parsed), struct cli_context *UNUSED(context))
{
  command_close(stdin_state);
  return 0;
}

static int console_set(const struct cli_parsed *UNUSED(parsed), struct cli_context *UNUSED(context))
{
  const char *flag;
  if (cli_arg(parsed, "flag", &flag, NULL, NULL) != -1){
    monitor_client_writeline(monitor_alarm.poll.fd, "monitor %s\n",
			     flag);
  }
  return 0;
}

static int console_clear(const struct cli_parsed *UNUSED(parsed), struct cli_context *UNUSED(context))
{
  const char *flag;
  if (cli_arg(parsed, "flag", &flag, NULL, NULL) != -1){
    monitor_client_writeline(monitor_alarm.poll.fd, "ignore %s\n",
			     flag);
  }
  return 0;
}

static int console_audio(const struct cli_parsed *parsed, struct cli_context *UNUSED(context))
{
  if (!calls){
    printf("No active call\n");
    fflush(stdout);
  }else{
    static char buf[256];
    static struct strbuf str_buf = STRUCT_STRBUF_EMPTY;
    strbuf_init(&str_buf, buf, sizeof(buf));
    unsigned i;
    for (i = 1; i < parsed->argc; ++i) {
      if (i>1)
	strbuf_putc(&str_buf, ' ');
      if (parsed->args[i])
	strbuf_puts(&str_buf, parsed->args[i]);
      else
	strbuf_puts(&str_buf, "NULL");
    }

    send_audio(calls->token, (unsigned char *)strbuf_str(&str_buf), strbuf_len(&str_buf), VOMP_CODEC_TEXT);
  }
  return 0;
}

static int console_usage(const struct cli_parsed *parsed, struct cli_context *UNUSED(context))
{
  cli_usage_parsed(parsed, XPRINTF_STDIO(stdout));
  fflush(stdout);
  return 0;
}

static void monitor_read(struct sched_ent *alarm){
  if (monitor_client_read(alarm->poll.fd, monitor_state, console_handlers, 
			  sizeof(console_handlers)/sizeof(struct monitor_command_handler))<0){
    if (alarm->poll.fd!=-1){
      unwatch(alarm);
      monitor_client_close(alarm->poll.fd, monitor_state);
      alarm->poll.fd=-1;
    }
  }
}

DEFINE_FEATURE(cli_vomp_console);

DEFINE_CMD(app_vomp_console, 0,
  "Test phone call life-cycle from the console",
  "console");
static int app_vomp_console(const struct cli_parsed *parsed, struct cli_context *UNUSED(context))
{
  DEBUG_cli_parsed(verbose, parsed);
  
  monitor_alarm.poll.fd = monitor_client_open(&monitor_state);
  if (monitor_alarm.poll.fd==-1)
    return -1;
  
  monitor_client_writeline(monitor_alarm.poll.fd, "monitor vomp %d\n",
			   VOMP_CODEC_TEXT);
  
  set_nonblock(STDIN_FILENO);
  set_nonblock(monitor_alarm.poll.fd);
  
  watch(&monitor_alarm);
  stdin_state = command_register(console_commands, STDIN_FILENO);
  
  while(monitor_alarm.poll.fd!=-1 && !is_command_closed(stdin_state) && fd_poll())
    ;
  
  printf("Shutting down\n");
  fflush(stdout);
  
  command_free(stdin_state);
  if (monitor_alarm.poll.fd!=-1){
    unwatch(&monitor_alarm);
    monitor_client_close(monitor_alarm.poll.fd, monitor_state);
    monitor_alarm.poll.fd=-1;
  }
  
  return 0;
}
