/*
Copyright (C) 2012 Paul Gardner-Stephen, Serval Project.
 
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
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <string.h>
#include <signal.h>
#include <sys/types.h>

#ifdef WIN32
#include "win32/win32.h"
#endif
#include <unistd.h>
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#include <sys/un.h>
#include <fcntl.h>
#include <ctype.h>

#include "constants.h"
#include "conf.h"
#include "log.h"
#include "str.h"
#include "strbuf_helpers.h"
#include "socket.h"
#include "monitor-client.h"

#define STATE_INIT 0
#define STATE_DATA 1
#define STATE_READY 2

#define MONITOR_CLIENT_BUFFER_SIZE 8192
#define MAX_ARGS 32

struct monitor_state {
  char *cmd;
  int argc;
  char *argv[MAX_ARGS];
  unsigned char *data;
  int dataBytes;
  int cmdBytes;
  
  int state;
  unsigned char buffer[MONITOR_CLIENT_BUFFER_SIZE];
  int bufferBytes;
};

/* Open monitor interface abstract domain named socket */
int monitor_client_open(struct monitor_state **res)
{
  int fd;
  if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
    return WHYF_perror("socket(AF_UNIX, SOCK_STREAM, 0)");
  struct socket_address addr;
  if (make_local_sockaddr(&addr, "monitor.socket") == -1)
    return -1;
  INFOF("Attempting to connect to %s", alloca_socket_address(&addr));
  if (socket_connect(fd, &addr.addr, addr.addrlen) == -1) {
    close(fd);
    return -1;
  }
  *res = (struct monitor_state*)malloc(sizeof(struct monitor_state));
  memset(*res,0,sizeof(struct monitor_state));
  return fd;
}

int monitor_client_close(int fd, struct monitor_state *res){
  free(res);
  close(fd);
  return 0;
}

int monitor_client_writeline(int fd,char *fmt, ...)
{
  char msg[512];
  int n;
  va_list ap;
  
  if (fd<0)
    return -1;
  
  va_start(ap, fmt);
  n=vsnprintf(msg, sizeof(msg), fmt, ap);
  va_end(ap);
  
  return write(fd,msg,n);
}

int monitor_client_writeline_and_data(int fd,unsigned char *data,int bytes,char *fmt,...)
{
  int maxlen=512+bytes;
  char out[maxlen];
  va_list ap;
  int n;
  
  if (fd<0)
    return -1;
  
  n=snprintf(out,maxlen-bytes,"*%d:",bytes);
  
  va_start(ap, fmt);
  n+=vsnprintf(out+n, maxlen-bytes-n, fmt, ap);
  va_end(ap);
  
  bcopy(data,out+n,bytes);
  n+=bytes;
  return write(fd,out,n);
}

int monitor_client_read(int fd, struct monitor_state *res, struct monitor_command_handler *handlers, int handler_count)
{
  /* Read any available bytes */
  int oldOffset = res->bufferBytes;
  
  if (oldOffset+1>=MONITOR_CLIENT_BUFFER_SIZE)
    return WHY("Buffer full without finding command");
  
  if (res->bufferBytes==0)
    res->cmd = (char *)res->buffer;
  
  int bytesRead = read(fd, res->buffer + oldOffset, MONITOR_CLIENT_BUFFER_SIZE - oldOffset);
  if (bytesRead == -1){
    switch(errno) {
      case ENOTRECOVERABLE:
	/* transient errors */
	break;
      case EINTR:
      case EAGAIN:
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
      case EWOULDBLOCK: 
#endif
	return 0;
    }
    WHYF_perror("read(%d, %p, %d)", fd, res->buffer + oldOffset, MONITOR_CLIENT_BUFFER_SIZE - oldOffset);
    return -1;
  } else if (bytesRead == 0) {
    WHYF("read(%d, %p, %d) returned %d", fd, res->buffer + oldOffset, MONITOR_CLIENT_BUFFER_SIZE - oldOffset, bytesRead);
    return -1;
  }
  res->bufferBytes+=bytesRead;

again:
  // wait until we have the whole command line
  if (res->state == STATE_INIT){
    int i;
    for(i=oldOffset;i<res->bufferBytes;i++){
      if (res->buffer[i]=='\n'){
	// skip any leading \n's
	if ((char*)(res->buffer+i) == res->cmd){
	  res->cmd++;
	  continue;
	}
	
	res->buffer[i]=0;
	res->dataBytes = 0;
	res->cmdBytes = i + 1;
	if (*res->cmd=='*'){
	  res->cmd++;
	  for (; isdigit(*res->cmd); ++res->cmd)
	    res->dataBytes = res->dataBytes * 10 + *res->cmd - '0';
	  if (res->dataBytes<0 || res->dataBytes > MONITOR_CLIENT_BUFFER_SIZE)
	    return WHYF("Invalid data length %d", res->dataBytes);
	  if (*res->cmd==':')
	    res->cmd++;
	}
	
	// find all arguments, initialise argc / argv && null terminate strings
	{
	  char *p=res->cmd;
	  res->argc=0;
	  while (*p && res->argc<MAX_ARGS){
	    if (*p==':'){
	      *p=0;
	      res->argv[res->argc]=p+1;
	      res->argc++;
	    }
	    p++;
	  }
	}
	
	if (res->dataBytes){
	  res->data=(unsigned char *)&res->buffer[i+1];
	  res->state = STATE_DATA;
	}else{
	  res->data=NULL;
	  res->state = STATE_READY;
	}
	break;
      }
    }
  }
  
  // make sure all the data has arrived
  if (res->state == STATE_DATA){
    if (res->bufferBytes >= res->dataBytes + res->cmdBytes){
      res->state = STATE_READY;
    }
  }
  
  // ok, now we can try to process the command
  if (res->state == STATE_READY){
    int handled=0;
    int i;
    // call all handlers that match (yes there might be more than one)
    for (i=0;i<handler_count;i++){
      /* since we know res->cmd is terminated with a '\n', 
       and there shouldn't be a '\n' in h->command, 
       this shouldn't run past the end of the buffer */
      if (handlers[i].handler && (!handlers[i].command || strcase_startswith(res->cmd,handlers[i].command, NULL))){
	if (handlers[i].handler(res->cmd, res->argc, res->argv, res->data, res->dataBytes, handlers[i].context)>0)
	  handled=1;
      }
    }
    
    if (!handled){
      INFOF("Event \"%s\" was not handled", res->cmd);
    }
      
    // shuffle any unprocessed bytes
    int remaining = res->bufferBytes - (res->dataBytes + res->cmdBytes);
    if (remaining>0){
      bcopy(res->buffer+res->dataBytes + res->cmdBytes,res->buffer,remaining);
    }
    res->bufferBytes=remaining;
    res->cmdBytes=0;
    res->dataBytes=0;
    res->state = STATE_INIT;
    res->cmd = (char *)res->buffer;
    oldOffset = 0;
    goto again;
  }
  
  if (res->bufferBytes >= MONITOR_CLIENT_BUFFER_SIZE)
    return WHY("Buffer full");
  
  return 0;
}
