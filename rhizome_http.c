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

#include "mphlr.h"
#include "rhizome.h"

/*
  HTTP server and client code for rhizome transfers.

 */

int rhizome_server_socket=-1;

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
  int buffer_length;
  int buffer_offset;

  /* The source specification data which are used in different ways by different 
     request types */
  unsigned char source[1024];
  long long source_index;

} rhizome_http_request;

#define RHIZOME_SERVER_MAX_LIVE_REQUESTS 32
rhizome_http_request *rhizome_live_http_requests[RHIZOME_SERVER_MAX_LIVE_REQUESTS];
int rhizome_server_live_request_count=0;

int rhizome_server_start()
{
  if (rhizome_server_socket>-1) return 0;

  struct sockaddr_in address;

  rhizome_server_socket=socket(AF_INET,SOCK_STREAM,0);
  if (rhizome_server_socket<0)
    return WHY("socket() failed starting rhizome http server");
  bzero((char *) &address, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(RHIZOME_HTTP_PORT);
  if (bind(rhizome_server_socket, (struct sockaddr *) &address,
	   sizeof(address)) < 0) 
    return WHY("bind() failed starting rhizome http server\n");

  if (listen(rhizome_server_socket,20))
    return WHY("listen() failed starting rhizome http server\n");

  return 0;
}

int rhizome_server_poll()
{
  struct sockaddr addr;
  unsigned int addr_len=0;
  int sock;
  int i;
  
  /* Process the existing requests.
     XXX - should use poll or select here */
  for(i=0;i<rhizome_server_live_request_count;i++)
    {
      WHY("Processing live HTTP requests not implemented.");
    }

  /* Deal with any new requests */
  while ((rhizome_server_live_request_count<RHIZOME_SERVER_MAX_LIVE_REQUESTS)
	 &&((sock=accept(rhizome_server_socket,&addr,&addr_len))>-1))
    {
      rhizome_http_request *request = calloc(sizeof(rhizome_http_request),1);	
      request->socket=sock;
      /* We are now trying to read the HTTP request */
      request->request_type=RHIZOME_HTTP_REQUEST_RECEIVING;
      rhizome_live_http_requests[rhizome_server_live_request_count++]=request;	   
    }
  
  return 0;
}
