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

#include "monitor-client.h"


/* Open monitor interface abstract domain named socket */
int monitor_client_open()
{
  int fd;
  struct sockaddr_un addr;

  if ( (fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
    perror("socket");
    exit(-1);
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  /* XXX - On non-linux systems, we need to use a regular named socket */
  addr.sun_path[0]=0;
  snprintf(&addr.sun_path[1],100,
	   "%s", confValueGet("monitor.socket",DEFAULT_MONITOR_SOCKET_NAME));
  int len = 1+strlen(&addr.sun_path[1]) + sizeof(addr.sun_family);
  char *p=(char *)&addr;
  printf("last char='%c' %02x\n",p[len-1],p[len-1]);

  if (connect(fd, (struct sockaddr*)&addr, len) == -1) {
    perror("connect");
    exit(-1);
  }
  return fd;
}

int monitor_client_writeline(int fd,char *msg)
{
  return write(fd,msg,strlen(msg));
}

int monitor_client_writeline_and_data(int fd,char *msg,unsigned char *data,int bytes)
{
  int maxlen=strlen(msg)+20+bytes;
  char out[maxlen];
  snprintf(out,maxlen,"*%d:%s\n",bytes,msg);
  int len=strlen(msg);
  bcopy(&data[0],&msg[len],bytes);
  len+=bytes;
  return write(fd,msg,len);
}

static unsigned char buffer[MONITOR_CLIENT_BUFFER_SIZE];
static int buffer_bytes=0;

int monitor_client_readline(int fd, monitor_result **res)
{
  monitor_result *r=*res;

  /* Read any available bytes */
  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, NULL) | O_NONBLOCK);
  int bytesRead=read(fd,&buffer[buffer_bytes],
		     MONITOR_CLIENT_BUFFER_SIZE-buffer_bytes);
  if (bytesRead>0) buffer_bytes+=bytesRead;

  /* Now see if we have a full line of results to return */
  int i;
  for(i=0;i<buffer_bytes;i++)
    if (buffer[i]=='\n') {
      /* Found an end of line marker.
         Now check if there is a data section to extract. */
      int dataBytes=0;
      int lineStart=0;
      if (sscanf("*%d:%n",(char *)buffer,&dataBytes,&lineStart)==1)
	{
	  if ((dataBytes+i)>buffer_bytes)
	    {
	      /* We don't yet have enough bytes to return */
	      return -1;
	    }
	  /* Copy data section */
	  r->dataBytes=dataBytes;
	  bcopy(&buffer[i],&r->data[0],dataBytes);
	  /* copy line from after the *len: part, and without the
	     new line.  Then null-terminate it */
	  bcopy(&buffer[lineStart],&r->line[0],i-lineStart);
	  r->line[i-lineStart]=0;
	  /* remember to discard the data section from the buffer */
	  i+=dataBytes;
	} else {
	/* no data section */
	r->dataBytes=0;
      }
      /* shuffle buffer down */
      bcopy(&buffer[i],&buffer[0],buffer_bytes-i);
      buffer_bytes-=i;
      return 0;
    }
  /* no end of line, so need to read more */
  return -1;
}
