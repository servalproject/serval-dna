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

  return 0;
}

int rhizome_server_poll()
{
  struct sockaddr addr;
  unsigned int addr_len=0;
  int sock;
  int rn;
  
  /* Having the starting of the server here is helpful in that
     if the port is taken by someone else, we will grab it fairly
     swiftly once it becomes available. */
  if (rhizome_server_socket<0) rhizome_server_start();
  if (rhizome_server_socket<0) return 0;

  /* Process the existing requests.
     XXX - should use poll or select here */
  if (debug>1) printf("Checking %d active connections\n",
		    rhizome_server_live_request_count);
  for(rn=0;rn<rhizome_server_live_request_count;rn++)
    {
      rhizome_http_request *r=rhizome_live_http_requests[rn];
      switch(r->request_type) {
      case RHIZOME_HTTP_REQUEST_RECEIVING:
	/* Keep reading until we have two CR/LFs in a row */
	
	sigPipeFlag=0;

	/* Make socket non-blocking */
	fcntl(r->socket,F_SETFL,fcntl(r->socket, F_GETFL, NULL)|O_NONBLOCK);

	errno=0;
	int bytes=read(r->socket,&r->request[r->request_length],
		       RHIZOME_HTTP_REQUEST_MAXLEN-r->request_length-1);

	/* If we got some data, see if we have found the end of the HTTP request */
	if (bytes>0) {
	  int i=r->request_length-160;
	  int lfcount=0;
	  if (i<0) i=0;
	  r->request_length+=bytes;
	  if (r->request_length<RHIZOME_HTTP_REQUEST_MAXLEN)
	    r->request[r->request_length]=0;
	  dump("request",(unsigned char *)r->request,r->request_length);
	  for(;i<(r->request_length+bytes);i++)
	    {
	      switch(r->request[i]) {
	      case '\n': lfcount++; break;
	      case '\r': /* ignore CR */ break;
	      case 0: /* ignore NUL (telnet inserts them) */ break;
	      default: lfcount=0; break;
	      }
	      if (lfcount==2) break;
	    }
	  if (lfcount==2) {
	    /* We have the request. Now parse it to see if we can respond to it */
	    rhizome_server_parse_http_request(rn,r);
	  }
	  
	  r->request_length+=bytes;
	}

	/* Make socket blocking again for poll()/select() */
	fcntl(r->socket,F_SETFL,fcntl(r->socket, F_GETFL, NULL)&(~O_NONBLOCK));

	if (sigPipeFlag||((bytes==0)&&(errno==0))) {
	  /* broken pipe, so close connection */
	  WHY("Closing connection due to sigpipe");
	  rhizome_server_close_http_request(rn);
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
      rhizome_http_request *request = calloc(sizeof(rhizome_http_request),1);	
      request->socket=sock;
      /* We are now trying to read the HTTP request */
      request->request_type=RHIZOME_HTTP_REQUEST_RECEIVING;
      rhizome_live_http_requests[rhizome_server_live_request_count++]=request;	   
    }

  fcntl(rhizome_server_socket,F_SETFL,
	fcntl(rhizome_server_socket, F_GETFL, NULL)&(~O_NONBLOCK));
  
  return 0;
}

int rhizome_server_close_http_request(int i)
{
  close(rhizome_live_http_requests[i]->socket);
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
      switch(rhizome_live_http_requests[i]->request_type) {
      case RHIZOME_HTTP_REQUEST_RECEIVING:
	fds[*fdcount].events=POLLIN; break;
      default:
	fds[*fdcount].events=POLLOUT; break;
      }
      (*fdcount)++;    
    }
   return 0;
}

int rhizome_server_parse_http_request(int rn,rhizome_http_request *r)
{
  WHY("not implemented. just returning an HTTP error for now.");
  char id[1024];

  if (strlen(r->request)<1024) {
    if (!strncasecmp("GET /rhizome/groups HTTP/1.",r->request,
		     strlen("GET /rhizome/groups HTTP/1.")))
      {
	/* Return the list of known groups */
	printf("get /rhizome/groups (list of groups)\n");
	rhizome_server_simple_http_response(r,200,"<html><h1>List of groups</h1></html>\r\n");	
      }
    else if (sscanf("GET /rhizome/file/%[0-9a-f] HTTP/1.",r->request,
	       id)==1)
      {
	/* Stream the specified file */
	printf("get /rhizome/file/ [%s]\n",id);
	rhizome_server_simple_http_response(r,400,"<html><h1>A specific file</h1></html>\r\n");
      }
    else if (sscanf("GET /rhizome/manifest/%[0-9a-f] HTTP/1.",r->request,
	       id)==1)
      {
	/* Stream the specified manifest */
	printf("get /rhizome/manifest/ [%s]\n",id);
	rhizome_server_simple_http_response(r,400,"<html><h1>A specific manifest</h1></html>\r\n");      }
    else 
      rhizome_server_simple_http_response(r,400,"<html><h1>Sorry, couldn't parse your request.</h1></html>\r\n");
  }
  else 
    rhizome_server_simple_http_response(r,400,"<html><h1>Sorry, your request was too long.</h1></html>\r\n");
  
  /* Try sending data immediately. */
  rhizome_server_http_send_bytes(rn,r);

  return 0;
}

int rhizome_server_simple_http_response(rhizome_http_request *r,int result, char *response)
{
  r->buffer_size=strlen(response)+strlen("HTTP/1.0 XXX Foo\r\n\r\n")+100;
  r->buffer=(unsigned char *)malloc(r->buffer_size);
  snprintf((char *)r->buffer,r->buffer_size,"HTTP/1.0 %03d FooContent-type: text/html\r\nContent-length: %d\r\n\r\n%s",result,(int)strlen(response),response);
  
  r->buffer_size=strlen((char *)r->buffer)+1;
  r->buffer_length=r->buffer_size-1;
  r->buffer_offset=0;

  r->request_type=RHIZOME_HTTP_REQUEST_FROMBUFFER;
  return 0;
}

int rhizome_server_http_send_bytes(int rn,rhizome_http_request *r)
{
  int bytes;
  fcntl(r->socket,F_SETFL,fcntl(r->socket, F_GETFL, NULL)|O_NONBLOCK);

  switch(r->request_type)
    {
    case RHIZOME_HTTP_REQUEST_FROMBUFFER:
      bytes=r->buffer_length-r->buffer_offset;
      bytes=write(r->socket,&r->buffer[r->buffer_offset],bytes);
      if (bytes>0) {
	r->buffer_offset+=bytes;
	if (r->buffer_offset>=r->buffer_length) {
	  /* Our work is done. close socket and go home */
	  WHY("Finished sending data");
	  return rhizome_server_close_http_request(rn);	  
	}
      }
      break;
    default:
      WHY("sending data from this type of HTTP request not implemented");
      break;
    }

  fcntl(r->socket,F_SETFL,fcntl(r->socket, F_GETFL, NULL)&(~O_NONBLOCK));
  return 0;
}
