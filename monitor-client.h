/*
Copyright (C) 2012 Paul Gardner-Stephen
Copyright (C) 2012 Serval Project Inc.
 
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

#ifndef __SERVALD_MONITOR_CLIENT_H
#define __SERVALD_MONITOR_CLIENT_H

struct monitor_state;

struct monitor_command_handler{
  char *command;
  void *context;
  int (*handler)(char *cmd, int argc, char **argv, unsigned char *data, int dataLen, void *context);
};

int monitor_client_open(struct monitor_state **res);
int monitor_client_writeline(int fd,char *fmt, ...);
int monitor_client_writeline_and_data(int fd,unsigned char *data,int bytes,char *fmt,...);
int monitor_client_read(int fd, struct monitor_state *res, struct monitor_command_handler *handlers, int handler_count);
int monitor_client_close(int fd, struct monitor_state *res); 
int monitor_socket_name(struct sockaddr_un *name);

#endif
