/* 
 Copyright (C) 2012 Serval Project
 
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
#include "conf.h"
#include "cli.h"
#include "monitor-client.h"
#include "str.h"
#include "constants.h"
#include "strbuf.h"
#include "strbuf_helpers.h"

int call_token=-1;
int seen_audio=0;
int monitor_client_fd=-1;
struct monitor_state *monitor_state;

struct line_state{
  struct sched_ent alarm;
  int fd;
  char line_buff[1024];
  int line_pos;
  void (*process_line)(char *line);
};

static void send_hangup(int session_id){
  monitor_client_writeline(monitor_client_fd, "hangup %06x\n",session_id);
}
static void send_ringing(int session_id){
  monitor_client_writeline(monitor_client_fd, "ringing %06x\n",session_id);
}
static void send_pickup(int session_id){
  monitor_client_writeline(monitor_client_fd, "pickup %06x\n",session_id);
}
static void send_call(const char *sid, const char *caller_id, const char *remote_ext){
  monitor_client_writeline(monitor_client_fd, "call %s %s %s\n", sid, caller_id, remote_ext);
}
static void send_audio(int session_id, unsigned char *buffer, int len, int codec){
  monitor_client_writeline_and_data(monitor_client_fd, buffer, len, "audio %06x %d\n", session_id, codec);
}

static int remote_call(char *cmd, int argc, char **argv, unsigned char *data, int dataLen, void *context){
  int token = strtol(argv[0], NULL, 16);
  
  if (call_token != -1){
    send_hangup(token);
    printf("Rejected incoming call, already busy\n");
    fflush(stdout);
    return 1;
  }
  
  call_token = token;
  seen_audio = 0;
  printf("Incoming call from %s (%s)\n",argv[3],argv[4]);
  fflush(stdout);
  send_ringing(token);
  return 1;
}

static int remote_ringing(char *cmd, int argc, char **argv, unsigned char *data, int dataLen, void *context){
  int token = strtol(argv[0], NULL, 16);
  if (call_token == token){
    printf("They're ringing\n");
    fflush(stdout);
  }else
    send_hangup(token);
  return 1;
}

static int remote_pickup(char *cmd, int argc, char **argv, unsigned char *data, int dataLen, void *context){
  int token = strtol(argv[0], NULL, 16);
  if (call_token == token){
    printf("They've picked up\n");
    fflush(stdout);
  }else
    send_hangup(token);
  return 1;
}

static int remote_dialing(char *cmd, int argc, char **argv, unsigned char *data, int dataLen, void *context){
  int token = strtol(argv[0], NULL, 16);
  if (call_token == -1){
    call_token=token;
    seen_audio=0;
    printf("Dialling\n");
    fflush(stdout);
  }else
    send_hangup(token);
  return 1;
}

static int remote_hangup(char *cmd, int argc, char **argv, unsigned char *data, int dataLen, void *context){
  int token = strtol(argv[0], NULL, 16);
  if (call_token == token){
    printf("Call ended\n");
    fflush(stdout);
    call_token=-1;
  }
  return 1;
}

static int remote_audio(char *cmd, int argc, char **argv, unsigned char *data, int dataLen, void *context){
  int token = strtol(argv[0], NULL, 16);
  if (call_token == token){
    int codec = strtol(argv[1], NULL, 10);
//    int start_time = strtol(argv[2], NULL, 10);
//    int sequence = strtol(argv[3], NULL, 10);
    switch (codec){
      case VOMP_CODEC_TEXT:
	data[dataLen]=0;
	printf("%s\n",data);
	fflush(stdout);
	break;
    }
  }else
    send_hangup(token);
  return 1;
}

static int remote_codecs(char *cmd, int argc, char **argv, unsigned char *data, int dataLen, void *context){
  int token = strtol(argv[0], NULL, 16);
  if (call_token == token){
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

static int remote_print(char *cmd, int argc, char **argv, unsigned char *data, int dataLen, void *context){
  int i;
  printf("%s",cmd);
  for (i=0;i<argc;i++){
    printf(" %s",argv[i]);
  }
  printf("\n");
  if (dataLen){
    dump(NULL,data,dataLen);
  }
  fflush(stdout);
  return 1;
}

static int remote_noop(char *cmd, int argc, char **argv, unsigned char *data, int dataLen, void *context){
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
  {.command="CALLSTATUS",    .handler=remote_noop},
  {.command="KEEPALIVE",     .handler=remote_noop},
  {.command="MONITORSTATUS", .handler=remote_noop},
};

static int console_dial(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (call_token!=-1){
    printf("Already in a call\n");
    return 0;
  }
  const char *sid = parsed->args[1];
  const char *local = parsed->argc >= 3 ? parsed->args[2] : "";
  const char *remote = parsed->argc >= 4 ? parsed->args[3] : "";
  send_call(sid, local, remote);
  return 0;
}

static int console_answer(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (call_token==-1){
    printf("No active call to answer\n");
    fflush(stdout);
  }else
    send_pickup(call_token);
  return 0;
}

static int console_hangup(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (call_token==-1){
    printf("No call to hangup\n");
    fflush(stdout);
  }else
    send_hangup(call_token);
  return 0;
}

static int console_audio(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (call_token==-1){
    printf("No active call\n");
    fflush(stdout);
  }else{
    static char buf[256];
    static struct strbuf str_buf = STRUCT_STRBUF_EMPTY;
    int i;
    strbuf_init(&str_buf, buf, sizeof(buf));
    for (i = 0; i < parsed->argc; ++i) {
      if (i)
	strbuf_putc(&str_buf, ' ');
      if (parsed->args[i])
	strbuf_toprint_quoted(&str_buf, "\"\"", parsed->args[i]);
      else
	strbuf_puts(&str_buf, "NULL");
    }

    send_audio(call_token, (unsigned char *)strbuf_str(&str_buf), strbuf_len(&str_buf), VOMP_CODEC_TEXT);
  }
  return 0;
}

static int console_usage(const struct cli_parsed *parsed, struct cli_context *context);

struct cli_schema console_commands[]={
  {console_answer,{"answer",NULL},0,"Answer an incoming phone call"},
  {console_dial,{"call","<sid>","[<local_number>]","[<remote_extension>]",NULL},0,"Start dialling a given person"},
  {console_hangup,{"hangup",NULL},0,"Hangup the phone line"},
  {console_usage,{"help",NULL},0,"This usage message"},
  {console_audio,{"say","...",NULL},0,"Send a text string to the other party"},
  {NULL},
};

static int console_usage(const struct cli_parsed *parsed, struct cli_context *context)
{
  cli_usage(console_commands, XPRINTF_STDIO(stdout));
  fflush(stdout);
  return 0;
}

static void console_command(char *line){
  char *argv[16];
  int argc = parse_argv(line, ' ', argv, 16);
  
  struct cli_parsed parsed;
  switch (cli_parse(argc, (const char *const*)argv, console_commands, &parsed)) {
  case 0:
    cli_invoke(&parsed, NULL);
    break;
  case 1:
    printf("Unknown command, try help\n");
    fflush(stdout);
    break;
  case 2:
    printf("Ambiguous command, try help\n");
    fflush(stdout);
    break;
  default:
    printf("Error\n");
    fflush(stdout);
    break;
  }
}

static void read_lines(struct sched_ent *alarm){
  struct line_state *state=(struct line_state *)alarm;
  set_nonblock(STDIN_FILENO);
  int bytes = read(state->alarm.poll.fd, state->line_buff + state->line_pos, sizeof(state->line_buff) - state->line_pos);
  set_block(STDIN_FILENO);
  int i = state->line_pos;
  int processed=0;
  state->line_pos+=bytes;
  char *line_start=state->line_buff;
  
  for (;i<state->line_pos;i++){
    if (state->line_buff[i]=='\n'){
      state->line_buff[i]=0;
      if (*line_start)
	state->process_line(line_start);
      processed=i+1;
      line_start = state->line_buff + processed;
    }
  }
  
  if (processed){
    // squash unprocessed data back to the start of the buffer
    state->line_pos -= processed;
    bcopy(state->line_buff, line_start, state->line_pos);
  }
}

static void monitor_read(struct sched_ent *alarm){
  if (monitor_client_read(alarm->poll.fd, monitor_state, console_handlers, 
			  sizeof(console_handlers)/sizeof(struct monitor_command_handler))<0){
    unwatch(alarm);
    monitor_client_close(alarm->poll.fd, monitor_state);
    alarm->poll.fd=-1;
    monitor_client_fd=-1;
  }
}

int app_vomp_console(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  static struct profile_total stdin_profile={
    .name="read_lines",
  };
  struct line_state stdin_state={
    .alarm.poll.fd = STDIN_FILENO,
    .alarm.poll.events = POLLIN,
    .alarm.function = read_lines,
    .alarm.stats=&stdin_profile,
    .process_line=console_command,
  };
  static struct profile_total monitor_profile={
    .name="monitor_read",
  };
  struct sched_ent monitor_alarm={
    .poll.events = POLLIN,
    .function = monitor_read,
    .stats=&monitor_profile,
  };
  
  monitor_client_fd = monitor_client_open(&monitor_state);
  
  monitor_client_writeline(monitor_client_fd, "monitor vomp %d\n",
			   VOMP_CODEC_TEXT);
  
  set_nonblock(monitor_client_fd);
  
  monitor_alarm.poll.fd = monitor_client_fd;
  watch(&monitor_alarm);
  
  watch(&stdin_state.alarm);
  
  while(monitor_client_fd!=-1){
    fd_poll();
  }
  
  unwatch(&stdin_state.alarm);
  
  return 0;
}
