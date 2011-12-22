/*
Serval Distributed Numbering Architecture (DNA)
Copyright (C) 2010 Paul Gardner-Stephen
 
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

#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>

#include "mphlr.h"
#include "rhizome.h"

/*
  HTTP server and client code for rhizome transfers.

 */

int rhizome_server_socket=-1;
int sigPipeFlag=0;
int sigIoFlag=0;

typedef struct rhizome_http_request {
  int socket;
  long long last_activity; /* time of last activity in ms */
  long long initiate_time; /* time connection was initiated */

  /* The HTTP request as currently received */
  int request_length;
#define RHIZOME_HTTP_REQUEST_MAXLEN 1024
  char request[RHIZOME_HTTP_REQUEST_MAXLEN];

  /* Nature of the request */
  int request_type;
#define RHIZOME_HTTP_REQUEST_RECEIVING -1
#define RHIZOME_HTTP_REQUEST_FROMBUFFER 0
#define RHIZOME_HTTP_REQUEST_FILE 1
#define RHIZOME_HTTP_REQUEST_SUBSCRIBEDGROUPLIST 2
#define RHIZOME_HTTP_REQUEST_ALLGROUPLIST 3
#define RHIZOME_HTTP_REQUEST_BUNDLESINGROUP 4
#define RHIZOME_HTTP_REQUEST_BUNDLEMANIFEST 5

  /* Local buffer of data to be sent.
     If a RHIZOME_HTTP_REQUEST_FROMBUFFER, then the buffer is sent, and when empty
     the request is closed.
     Else emptying the buffer triggers a request to fetch more data.  Only if no
     more data is provided do we then close the request. */
  unsigned char *buffer;
  int buffer_size; // size
  int buffer_length; // number of bytes loaded into buffer
  int buffer_offset; // where we are between [0,buffer_length)

  /* The source specification data which are used in different ways by different 
     request types */
  unsigned char source[1024];
  long long source_index;

} rhizome_http_request;

int rhizome_server_free_http_request(rhizome_http_request *r);
int rhizome_server_close_http_request(int i);


#define RHIZOME_SERVER_MAX_LIVE_REQUESTS 32
rhizome_http_request *rhizome_live_http_requests[RHIZOME_SERVER_MAX_LIVE_REQUESTS];
int rhizome_server_live_request_count=0;

void sigPipeHandler(int signal)
{
  sigPipeFlag++;
  return;
}

void sigIoHandler(int signal)
{
  printf("sigio\n");
  sigIoFlag++;
  return;
}

int rhizome_server_start()
{
  if (rhizome_server_socket>-1) return 0;

  struct sockaddr_in address;
  int on=1;

  /* Catch broken pipe signals */
  signal(SIGPIPE,sigPipeHandler);
  signal(SIGIO,sigIoHandler);

  rhizome_server_socket=socket(AF_INET,SOCK_STREAM,0);
  if (rhizome_server_socket<0)
    return WHY("socket() failed starting rhizome http server");

  setsockopt(rhizome_server_socket, SOL_SOCKET,  SO_REUSEADDR,
                  (char *)&on, sizeof(on));

  bzero((char *) &address, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(RHIZOME_HTTP_PORT);
  if (bind(rhizome_server_socket, (struct sockaddr *) &address,
	   sizeof(address)) < 0) 
    {
      close(rhizome_server_socket);
      rhizome_server_socket=-1;
      return WHY("bind() failed starting rhizome http server\n");
    }

  int rc = ioctl(rhizome_server_socket, FIONBIO, (char *)&on);
  if (rc < 0)
  {
    perror("ioctl() failed");
    close(rhizome_server_socket);
    exit(-1);
  }

  if (listen(rhizome_server_socket,20))
    {
      close(rhizome_server_socket);
      rhizome_server_socket=-1;
      return WHY("listen() failed starting rhizome http server\n");
    }

  printf("server socket = %d\n",rhizome_server_socket);

  return 0;
}

int rhizome_server_poll()
{
  struct sockaddr addr;
  unsigned int addr_len=0;
  int sock;
  int i;
  
  printf("checking on rhizome server connections (and possibly accepting new connections)\n");

  /* Having the starting of the server here is helpful in that
     if the port is taken by someone else, we will grab it fairly
     swiftly once it becomes available. */
  if (rhizome_server_socket<0) rhizome_server_start();
  if (rhizome_server_socket<0) return 0;

  /* Process the existing requests.
     XXX - should use poll or select here */
  if (debug) printf("Checking %d active connections\n",
		    rhizome_server_live_request_count);
  for(i=0;i<rhizome_server_live_request_count;i++)
    {
      rhizome_http_request *r=rhizome_live_http_requests[i];
      switch(r->request_type) {
      case RHIZOME_HTTP_REQUEST_RECEIVING:
	/* Keep reading until we have two CR/LFs in a row */
	
	sigPipeFlag=0;

	/* Make socket non-blocking */
	fcntl(r->socket,F_SETFL,fcntl(r->socket, F_GETFL, NULL)|O_NONBLOCK);

	errno=0;
	int bytes=read(r->socket,&r->request[r->request_length],
		       RHIZOME_HTTP_REQUEST_MAXLEN-r->request_length);
	printf("Read %d bytes, errno=%d\n",bytes,errno);

	/* Make socket blocking again for poll()/select() */
	fcntl(r->socket,F_SETFL,fcntl(r->socket, F_GETFL, NULL)&(~O_NONBLOCK));

	if (sigPipeFlag||((bytes==0)&&(errno==0))) {
	  /* broken pipe, so close connection */
	  WHY("Closing connection due to sigpipe");
	  rhizome_server_close_http_request(i);
	  continue;
	}

	break;
      }
      WHY("Processing live HTTP requests not implemented.");
    }

  /* Deal with any new requests */
  /* Make socket non-blocking */
  fcntl(rhizome_server_socket,F_SETFL,
	fcntl(rhizome_server_socket, F_GETFL, NULL)|O_NONBLOCK);

  while ((rhizome_server_live_request_count<RHIZOME_SERVER_MAX_LIVE_REQUESTS)
	 &&((sock=accept(rhizome_server_socket,&addr,&addr_len))>-1))
    {
      printf("accepting connection.\n");
      rhizome_http_request *request = calloc(sizeof(rhizome_http_request),1);	
      request->socket=sock;
      /* We are now trying to read the HTTP request */
      request->request_type=RHIZOME_HTTP_REQUEST_RECEIVING;
      rhizome_live_http_requests[rhizome_server_live_request_count++]=request;	   
    }

  fcntl(rhizome_server_socket,F_SETFL,
	fcntl(rhizome_server_socket, F_GETFL, NULL)&(~O_NONBLOCK));
  
  printf("done rhizome checking.\n");
  return 0;
}

int rhizome_server_close_http_request(int i)
{
  rhizome_server_free_http_request(rhizome_live_http_requests[i]);
  /* Make it null, so that if we are the list in the list, the following
     assignment still yields the correct behaviour */
  rhizome_live_http_requests[i]=NULL;
  rhizome_live_http_requests[i]=
    rhizome_live_http_requests[rhizome_server_live_request_count-1];
  rhizome_server_live_request_count--;
  return 0;
}

int rhizome_server_free_http_request(rhizome_http_request *r)
{
  if (r->buffer&&r->buffer_size) free(r->buffer);

  free(r);
  return 0;
}

int rhizome_server_get_fds(struct pollfd *fds,int *fdcount,int fdmax)
{
  int i;
  if ((*fdcount)>=fdmax) return -1;

  if (rhizome_server_socket>-1)
    {
      fds[*fdcount].fd=rhizome_server_socket;
      fds[*fdcount].events=POLLIN;
      (*fdcount)++;
    }

  for(i=0;i<rhizome_server_live_request_count;i++)
    {
      if ((*fdcount)>=fdmax) return -1;
      fds[*fdcount].fd=rhizome_live_http_requests[i]->socket;
      fds[*fdcount].events=POLLIN;
      (*fdcount)++;    
    }
   return 0;
}
