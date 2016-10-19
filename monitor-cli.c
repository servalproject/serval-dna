/* 
Copyright (C) 2012 Paul Gardner-Stephen 

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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#ifdef HAVE_POLL_H
#include <poll.h>
#endif
#include <fcntl.h>

#include "serval.h"
#include "conf.h"
#include "cli.h"
#include "monitor-client.h"
#include "commandline.h"

DEFINE_FEATURE(cli_monitor);

static int remote_print(char *cmd, int argc, char **argv, unsigned char *data, int dataLen, void *UNUSED(context))
{
  int i;
  printf("%s",cmd);
  for (i=0;i<argc;i++){
    printf(" %s",argv[i]);
  }
  printf("\n");
  if (dataLen){
    dump(NULL,data,dataLen);
  }
  return 1;
}

struct monitor_command_handler monitor_handlers[]={
  {.command="",      .handler=remote_print},
};

DEFINE_CMD(app_monitor_cli, 0,
  "Interactive servald monitor interface.",
  "monitor");
static int app_monitor_cli(const struct cli_parsed *UNUSED(parsed), struct cli_context *UNUSED(context))
{
  struct pollfd fds[2];
  struct monitor_state *state;
  
  int monitor_client_fd = monitor_client_open(&state);
  
  set_nonblock(STDIN_FILENO);
  set_nonblock(monitor_client_fd);
  
  fds[0].fd = STDIN_FILENO;
  fds[0].events = POLLIN;
  fds[1].fd = monitor_client_fd;
  fds[1].events = POLLIN;
  
  while(1){
    int r = poll(fds, 2, 100);
    if (r>0){
      
      if (fds[0].revents & POLLIN){
	char buff[256];
	ssize_t bytes = read(STDIN_FILENO, buff, sizeof buff);
	if (bytes == -1)
	  WHYF_perror("read(%d,%p,%ld)", STDIN_FILENO, buff, (long)sizeof buff);
	else {
	  set_block(monitor_client_fd);
	  size_t to_write = bytes;
	  size_t written = 0;
	  while (written < to_write) {
	    ssize_t n = write(monitor_client_fd, buff + written, to_write - written);
	    if (n == -1)
	      WHYF_perror("write(%d,%p,%ld)", monitor_client_fd, buff, (long)bytes);
	    else
	      written += n;
	  }
	  set_nonblock(monitor_client_fd);
	}
      }
      
      if (fds[1].revents & POLLIN){
	if (monitor_client_read(monitor_client_fd, state, monitor_handlers, 
				sizeof(monitor_handlers)/sizeof(struct monitor_command_handler))<0){
	  break;
	}
      }
      
      if (fds[0].revents & (POLLHUP | POLLERR))
	break;
    }
  }
  
  monitor_client_close(monitor_client_fd, state);
  monitor_client_fd=-1;
  
  return 0;
}

