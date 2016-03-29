/* 
 Copyright (C) 2014 Serval Project Inc.
 
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

#include <stdio.h>

#include "cli.h"
#include "mem.h"
#include "net.h"
#include "str.h"
#include "fdqueue.h"
#include "console.h"

struct command_state{
  struct sched_ent alarm;
  char line_buff[1024];
  size_t line_pos;
  struct cli_schema *cli_commands;
};

struct profile_total stdin_profile={
  .name="command_handler",
};

static void process_command(char *line, struct cli_schema *cli_commands){
  char *argv[16];
  int argc = parse_argv(line, ' ', argv, 16);
  
  struct cli_parsed parsed;
  switch (cli_parse(argc, (const char *const*)argv, cli_commands, NULL, &parsed)) {
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
  struct command_state *state=(struct command_state *)alarm;
  ssize_t bytes = read(alarm->poll.fd, state->line_buff + state->line_pos, sizeof(state->line_buff) - state->line_pos);
  if (bytes<=0){
    // EOF?
    unwatch(alarm);
    alarm->poll.fd=-1;
    return;
  }
  size_t i = state->line_pos;
  size_t processed=0;
  state->line_pos+=bytes;
  char *line_start=state->line_buff;
  
  for (;i<state->line_pos;i++){
    if (state->line_buff[i]=='\n'){
      state->line_buff[i]=0;
      if (*line_start)
	process_command(line_start, state->cli_commands);
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

struct command_state *command_register(struct cli_schema *commands, int fd){
  struct command_state *ret = emalloc_zero(sizeof(struct command_state));
  if (!ret)
    return NULL;
  ret->alarm.poll.fd=fd;
  ret->alarm.poll.events=POLLIN;
  ret->alarm.function=read_lines;
  ret->alarm.stats=&stdin_profile;
  ret->cli_commands = commands;
  watch(&ret->alarm);
  return ret;
}

uint8_t is_command_closed(struct command_state *state){
  return state->alarm.poll.fd==-1;
}

void command_close(struct command_state *state){
  if (is_watching(&state->alarm))
    unwatch(&state->alarm);
  state->alarm.poll.fd=-1;
}

void command_free(struct command_state *state){
  command_close(state);
  free(state);
}
