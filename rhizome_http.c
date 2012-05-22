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

#include "serval.h"
#include "rhizome.h"

/*
  HTTP server and client code for rhizome transfers.

 */

int rhizome_server_socket=-1;
int sigPipeFlag=0;
int sigIoFlag=0;

rhizome_http_request *rhizome_live_http_requests[RHIZOME_SERVER_MAX_LIVE_REQUESTS];
int rhizome_server_live_request_count=0;

// Format icon data using:
//   od -vt u1 ~/Downloads/favicon.ico | cut -c9- | sed 's/  */,/g'
unsigned char favicon_bytes[]={
0,0,1,0,1,0,16,16,16,0,0,0,0,0,40,1
,0,0,22,0,0,0,40,0,0,0,16,0,0,0,32,0
,0,0,1,0,4,0,0,0,0,0,128,0,0,0,0,0
,0,0,0,0,0,0,16,0,0,0,0,0,0,0,104,158
,168,0,163,233,247,0,104,161,118,0,0,0,0,0,0,0
,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
,0,0,0,0,0,0,0,0,0,0,0,0,0,0,17,17
,17,17,17,18,34,17,17,18,34,17,17,18,34,17,17,2
,34,17,17,18,34,17,16,18,34,1,17,17,1,17,1,17
,1,16,1,16,17,17,17,17,1,17,16,16,17,17,17,17
,1,17,18,34,17,17,17,16,17,17,2,34,17,17,17,16
,17,16,18,34,17,17,17,16,17,1,17,1,17,17,17,18
,34,17,17,16,17,17,17,18,34,17,17,18,34,17,17,18
,34,17,17,18,34,17,17,16,17,17,17,18,34,17,17,16
,17,17,17,17,17,0,17,1,17,17,17,17,17,17,0,0
,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
int favicon_len=318;

void sigPipeHandler(int signal)
{
  sigPipeFlag++;
  return;
}

void sigIoHandler(int signal)
{
  WHY("sigio");
  sigIoFlag++;
  return;
}

int rhizome_server_start()
{
  if (rhizome_server_socket>-1) return 0;

  /* Only try to start http server periodically */
  if (rhizome_server_socket<-1) { rhizome_server_socket++; return -1; }

  struct sockaddr_in address;
  int on=1;

  if (debug&DEBUG_RHIZOME) WHYF("Trying to start rhizome server.");

  /* Catch broken pipe signals */
  signal(SIGPIPE,sigPipeHandler);
  signal(SIGIO,sigIoHandler);

  rhizome_server_socket=socket(AF_INET,SOCK_STREAM,0);
  if (rhizome_server_socket<0)
    {
      rhizome_server_socket=-1000;
      return WHY("socket() failed starting rhizome http server");
    }

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
      rhizome_server_socket=-1000;
      if (debug&DEBUG_RHIZOME)  WHY("bind() failed starting rhizome http server");
      return -1;
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
      return WHY("listen() failed starting rhizome http server");
    }

  return 0;
}

int rhizome_poll_httpP=0;

int rhizome_server_poll()
{
  struct sockaddr addr;
  unsigned int addr_len=0;
  int sock;
  int rn;
  
  if (!rhizome_poll_httpP) return 0;

  /* Having the starting of the server here is helpful in that
     if the port is taken by someone else, we will grab it fairly
     swiftly once it becomes available. */
  if (rhizome_server_socket<0) rhizome_server_start();
  if (rhizome_server_socket<0) return 0;

  /* Process the existing requests.
     XXX - should use poll or select here */
  if (debug&DEBUG_RHIZOME) WHYF("Checking %d active connections",
		    rhizome_server_live_request_count);
  for(rn=0;rn<rhizome_server_live_request_count;rn++)
    {
      rhizome_http_request *r=rhizome_live_http_requests[rn];
      switch(r->request_type) 
	{
	case RHIZOME_HTTP_REQUEST_RECEIVING:
	  /* Keep reading until we have two CR/LFs in a row */
	  r->request[r->request_length]=0;
	  WHYF("http request so far: [%s]",r->request);
	  
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
	default:
	  /* Socket already has request -- so just try to send some data. */
	  rhizome_server_http_send_bytes(rn,r);
	  break;
      }      
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
  if (r->blob_table) free(r->blob_table);
  if (r->blob_column) free(r->blob_column);
  
  free(r);
  return 0;
}

long long rhizome_last_http_send=0;
int rhizome_server_get_fds(struct pollfd *fds,int *fdcount,int fdmax)
{
  int i;
  if ((*fdcount)>=fdmax) return -1;
  rhizome_poll_httpP=0;
  /* Don't send quickly during voice calls */
  long long now=overlay_gettime_ms();
  if (now<rhizome_voice_timeout)
    {
      /* only send data once per 500ms during calls */
      if ((rhizome_last_http_send+500)>now)
	return 0;
    }
  rhizome_last_http_send=now;
  rhizome_poll_httpP=1;

  if (rhizome_server_socket>-1)
    {
      if (debug&DEBUG_IO) {
	WHYF("rhizome http server is poll() slot #%d (fd %d)",
		*fdcount,rhizome_server_socket);
      }
      fds[*fdcount].fd=rhizome_server_socket;
      fds[*fdcount].events=POLLIN;
      (*fdcount)++;
    }

  for(i=0;i<rhizome_server_live_request_count;i++)
    {
      if ((*fdcount)>=fdmax) return -1;
      if (debug&DEBUG_IO) {
	WHYF("rhizome http request #%d is poll() slot #%d (fd %d)",
		i,*fdcount,rhizome_live_http_requests[i]->socket); }
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

int hexFilter(char *s)
{
  int l=strlen(s);
  int i;
  int o=0;
  int e=0;
  for(i=0;i<l;i++)
    {
      if ((s[i]>='0'&&s[i]<='9')
	  ||(s[i]>='a'&&s[i]<='f')
	  ||(s[i]>='A'&&s[i]<='F'))
	s[o++]=s[i];
      else e++;
    }
  s[o]=0;
  return -e;
}

int rhizome_server_sql_query_http_response(int rn,rhizome_http_request *r,
					   char *column,char *table,char *query_body,
					   int bytes_per_row,int dehexP)
{
  /* Run the provided SQL query progressively and return the values of the first
     column it returns.  As the result list may be very long, we will add the
     LIMIT <skip>,<count> clause to do it piece by piece.

     Otherwise, the response is prefixed by a 256 byte header, including the public
     key of the sending node, and allowing space for information about encryption of
     the body, although encryption is not yet implemented here.
 */

  char query[1024];

  if (r->buffer) { free(r->buffer); r->buffer=NULL; }
  r->buffer_size=16384;
  r->buffer=malloc(r->buffer_size);
  if (!r->buffer) return WHY("malloc() failed to allocate response buffer");
  r->buffer_length=0;
  r->buffer_offset=0;

  snprintf(query,1024,"SELECT COUNT(*) %s",query_body);
  query[1023]=0;

  r->source_record_size=bytes_per_row;
  r->source_count=sqlite_exec_int64(query);

  if (r->source_count<1) r->source_count=0;
    
  /* Work out total response length */
  long long response_bytes=256+r->source_count*r->source_record_size;
  rhizome_server_http_response_header(r,200,"servalproject.org/rhizome-list", 
				      response_bytes);
  WHYF("headers consumed %d bytes.",r->buffer_length);

  /* Clear and prepare response header */
  bzero(&r->buffer[r->buffer_length],256);
  
  r->buffer[r->buffer_length]=0x01; /* type of response (list) */
  r->buffer[r->buffer_length+1]=0x01; /* version of response */

  WHYF("Found %lld records.",r->source_count);
  /* Number of records we intend to return */
  r->buffer[r->buffer_length+4]=(r->source_count>>0)&0xff;
  r->buffer[r->buffer_length+5]=(r->source_count>>8)&0xff;
  r->buffer[r->buffer_length+6]=(r->source_count>>16)&0xff;
  r->buffer[r->buffer_length+7]=(r->source_count>>24)&0xff;

  r->buffer_length+=256;

  /* copy our public key in to bytes 32+ */
  WHY("no function yet exists to obtain our public key?");

  /* build templated query */
  snprintf(query,1024,"SELECT %s,rowid %s",column,query_body);
  query[1023]=0;
  bcopy(query,r->source,1024);
  r->source_index=0;
  r->source_flags=dehexP;
  r->blob_column=strdup(column);
  r->blob_table=strdup(table);

  WHYF("buffer_length=%d",r->buffer_length);

  /* Populate spare space in buffer with rows of data */
  return rhizome_server_sql_query_fill_buffer(rn,r);
}

int rhizome_server_sql_query_fill_buffer(int rn,rhizome_http_request *r)
{
  unsigned char blob_value[r->source_record_size*2+1];

  WHYF("populating with sql rows at offset %d",r->buffer_length);
  if (r->source_index>=r->source_count)
    {
      /* All done */
      return 0;
    }

  int record_count=(r->buffer_size-r->buffer_length)/r->source_record_size;
  if (record_count<1) {
    WHYF("r->buffer_size=%d, r->buffer_length=%d, r->source_record_size=%d",
	   r->buffer_size, r->buffer_length, r->source_record_size);
    return WHY("Not enough space to fit any records");
  }

  char query[1024];
  snprintf(query,1024,"%s LIMIT %lld,%d",r->source,r->source_index,record_count);

  sqlite3_stmt *statement;
  WHY(query);
  switch (sqlite3_prepare_v2(rhizome_db,query,-1,&statement,NULL))
    {
    case SQLITE_OK: case SQLITE_DONE: case SQLITE_ROW:
      break;
    default:
      sqlite3_finalize(statement);
      sqlite3_close(rhizome_db);
      rhizome_db=NULL;
      WHY(query);
      WHY(sqlite3_errmsg(rhizome_db));
      return WHY("Could not prepare sql statement.");
    }
  while(((r->buffer_length+r->source_record_size)<r->buffer_size)
	&&(sqlite3_step(statement)==SQLITE_ROW))
    {
      r->source_index++;
      
      if (sqlite3_column_count(statement)!=2) {
	sqlite3_finalize(statement);
	return WHY("sqlite3 returned multiple columns for a single column query");
      }
      sqlite3_blob *blob;
      const unsigned char *value;
      int column_type=sqlite3_column_type(statement, 0);
      switch(column_type) {
      case SQLITE_TEXT:	value=sqlite3_column_text(statement, 0); break;
      case SQLITE_BLOB:
	WHYF("table='%s',col='%s',rowid=%lld",
	       r->blob_table,r->blob_column,
	       sqlite3_column_int64(statement,1));
	if (sqlite3_blob_open(rhizome_db,"main",r->blob_table,r->blob_column,
			      sqlite3_column_int64(statement,1) /* rowid */,
			      0 /* read only */,&blob)!=SQLITE_OK)
	  {
	    WHY("Couldn't open blob");
	    continue;
	  }
	if (sqlite3_blob_read(blob,&blob_value[0],
			  /* copy number of bytes based on whether we need to
			     de-hex the string or not */
			      r->source_record_size*(1+(r->source_flags&1)),0)
	    !=SQLITE_OK) {
	  WHY("Couldn't read from blob");
	  sqlite3_blob_close(blob);
	  continue;
	}
	WHY("Did read blob");
	value=blob_value;
	sqlite3_blob_close(blob);
	break;
      default:
	/* improper column type, so don't include in report */
	WHY("Bad column type");
	WHYF("colunnt_type=%d",column_type);
	continue;
      }
      if (r->source_flags&1) {
	/* hex string to be converted */
	int i;
	for(i=0;i<r->source_record_size;i++)
	  /* convert the two nybls and make a byte */
	  r->buffer[r->buffer_length+i]
	    =(chartonybl(value[i<<1])<<4)|chartonybl(value[(i<<1)+1]);
      } else
	/* direct binary value */
	bcopy(value,&r->buffer[r->buffer_length],r->source_record_size);
      r->buffer_length+=r->source_record_size;
      
      WHYF("wrote row %lld, buffer_length=%d",
	     r->source_index,r->buffer_length);
    }
  sqlite3_finalize(statement);

  return 0;  
}


int rhizome_server_parse_http_request(int rn,rhizome_http_request *r)
{
  char id[1024];
  
  /* Clear request type flags */
  r->request_type=0;

  if (strlen(r->request)<1024) {
    if (!strncasecmp(r->request,"GET /favicon.ico HTTP/1.",
		     strlen("GET /favicon.ico HTTP/1.")))
      {
	r->request_type=RHIZOME_HTTP_REQUEST_FAVICON;
	rhizome_server_http_response_header(r,200,"image/vnd.microsoft.icon",
					    favicon_len);	
      }
    else if (!strncasecmp(r->request,"GET /rhizome/groups HTTP/1.",
		     strlen("GET /rhizome/groups HTTP/1.")))
      {
	/* Return the list of known groups */
	WHYF("get /rhizome/groups (list of groups)");
	rhizome_server_sql_query_http_response(rn,r,"id","groups","from groups",32,1);
      }
    else if (!strncasecmp(r->request,"GET /rhizome/files HTTP/1.",
		     strlen("GET /rhizome/files HTTP/1.")))
      {
	/* Return the list of known files */
	WHYF("get /rhizome/files (list of files)");
	rhizome_server_sql_query_http_response(rn,r,"id","files","from files",32,1);
      }
    else if (!strncasecmp(r->request,"GET /rhizome/bars HTTP/1.",
		     strlen("GET /rhizome/bars HTTP/1.")))
      {
	/* Return the list of known files */
	WHYF("get /rhizome/bars (list of BARs)");
	rhizome_server_sql_query_http_response(rn,r,"bar","manifests","from manifests",32,0);
      }
    else if (sscanf(r->request,"GET /rhizome/file/%s HTTP/1.",
	       id)==1)
      {
	/* Stream the specified file */
	int dud=0;
	int i;
	hexFilter(id);
	WHYF("get /rhizome/file/ [%s]",id);
	WHY("Check for range: header, and return 206 if returning partial content");
	for(i=0;i<strlen(id);i++) if ((id[i]<'0')||(id[i]>'f')||(id[i]=='\'')) dud++;
	if (dud) rhizome_server_simple_http_response(r,400,"<html><h1>That doesn't look like hex to me.</h1></html>\r\n");
	else {
	  long long rowid = sqlite_exec_int64("select rowid from files where id='%s';",id);
	  sqlite3_blob *blob;
	  if (rowid>=0) 
	    if (sqlite3_blob_open(rhizome_db,"main","files","data",rowid,0,&blob)
		!=SQLITE_OK)
	      rowid=-1;

	  if (rowid<0) {
	    rhizome_server_simple_http_response(r,404,"<html><h1>Sorry, can't find that here.</h1></html>\r\n");
	    WHY("File not found / blob not opened");
	  }
	  else {
	    r->blob_table=strdup("files");
	    r->blob_column=strdup("data");
	    r->blob_rowid=rowid;
	    r->source_index=0;	    
	    r->blob_end=sqlite3_blob_bytes(blob);
	    rhizome_server_http_response_header(r,200,"application/binary",
						r->blob_end-r->source_index);
	    r->request_type|=RHIZOME_HTTP_REQUEST_BLOB;
	    sqlite3_blob_close(blob);
	    WHY("opened blob and file -- but still need to send file body.");
	  }
	}
      }
    else if (sscanf(r->request,"GET /rhizome/manifest/%s HTTP/1.",
	       id)==1)
      {
	/* Stream the specified manifest */
	hexFilter(id);
	WHYF("get /rhizome/manifest/ [%s]",id);
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


/* Return appropriate message for HTTP response codes, both known and unknown. */
#define A_VALUE_GREATER_THAN_FOUR (2+3)
char *httpResultString(int id) {
  switch (id) {
  case 200: return "OK"; break;
  case 206: return "Partial Content"; break;
  case 404: return "Not found"; break;
  default: 
  case A_VALUE_GREATER_THAN_FOUR:
    if (id>4) return "A suffusion of yellow";
    /* The following MUST be the longest string returned by this function */
    else return "THE JUDGEMENT OF KING WEN: Chun Signifies Difficulties At Outset, As Of Blade Of Grass Pushing Up Against Stone.";
  }
}

int rhizome_server_simple_http_response(rhizome_http_request *r,int result, char *response)
{
  if (r->buffer) free(r->buffer);
  r->buffer_size=strlen(response)+strlen("HTTP/1.0 000 \r\n\r\n")+strlen(httpResultString(A_VALUE_GREATER_THAN_FOUR))+100;

  r->buffer=(unsigned char *)malloc(r->buffer_size);
  snprintf((char *)r->buffer,r->buffer_size,"HTTP/1.0 %03d %s\r\nContent-type: text/html\r\nContent-length: %d\r\n\r\n%s",result,httpResultString(result),(int)strlen(response),response);
  
  r->buffer_size=strlen((char *)r->buffer)+1;
  r->buffer_length=r->buffer_size-1;
  r->buffer_offset=0;

  r->request_type=RHIZOME_HTTP_REQUEST_FROMBUFFER;
  return 0;
}

/*
  return codes:
  1: connection still open.
  0: connection finished.
  <0: an error occurred.
*/
int rhizome_server_http_send_bytes(int rn,rhizome_http_request *r)
{
  sqlite3_blob *blob;
  int bytes;
  fcntl(r->socket,F_SETFL,fcntl(r->socket, F_GETFL, NULL)|O_NONBLOCK);

  if (debug&DEBUG_RHIZOME) WHYF("Request #%d, type=0x%x\n",rn,r->request_type);

  /* Flush anything out of the buffer if present, before doing any further
     processing */
  if (r->request_type&RHIZOME_HTTP_REQUEST_FROMBUFFER)
    {
      bytes=r->buffer_length-r->buffer_offset;
      bytes=write(r->socket,&r->buffer[r->buffer_offset],bytes);
      if (bytes>0) {
	WHYF("wrote %d bytes\n",bytes);
	dump("bytes written",&r->buffer[r->buffer_offset],bytes);
	r->buffer_offset+=bytes;
	if (r->buffer_offset>=r->buffer_length) {
	  /* Our work is done. close socket and go home */
	  r->request_type&=~RHIZOME_HTTP_REQUEST_FROMBUFFER;
	  r->buffer_offset=0; r->buffer_length=0;
	  if (!r->request_type) {
	    WHY("Finished sending data");
	    return rhizome_server_close_http_request(rn);	  
	  } else {
	    if (debug&DEBUG_RHIZOME) { WHYF("request type = 0x%x after sending buffer.",
				   r->request_type);
	    }
	  }
	} else {
	  /* Still more stuff in the buffer, so return now */
	  return 1;
	}
      }
    }

  switch(r->request_type&(~RHIZOME_HTTP_REQUEST_FROMBUFFER))
    {
    case RHIZOME_HTTP_REQUEST_FAVICON:
      if (r->buffer_size<favicon_len) {
	free(r->buffer);
	r->buffer_size=0;
	r->buffer=malloc(favicon_len);
	if (!r->buffer) r->request_type=0;
      }
      if (r->buffer)
      {
	  int i;
	  for(i=0;i<favicon_len;i++)
	    r->buffer[i]=favicon_bytes[i];
	  r->buffer_length=i;
	  printf("buffer_length for favicon is %d\n",r->buffer_length);
	  r->request_type=RHIZOME_HTTP_REQUEST_FROMBUFFER;
      }
      
      break;
    case RHIZOME_HTTP_REQUEST_BLOB:
      /* Get more data from the file and put it in the buffer */
      r->buffer_length=r->blob_end-r->source_index;
      if (r->buffer_length<=0) {
	/* end of blob reached */
	r->request_type=0; break;
      }
      if (r->buffer_size<65536) {
	free(r->buffer); r->buffer=malloc(65536);
	if (!r->buffer) {
	  if (debug&DEBUG_RHIZOME) WHY("malloc() failed");
	  r->request_type=0; break;
	}
	r->buffer_size=65536;
      }
      if (r->buffer_length>r->buffer_size) r->buffer_length=r->buffer_size;
      if (sqlite3_blob_open(rhizome_db,"main",r->blob_table,r->blob_column,
			    r->blob_rowid,0,&blob)==SQLITE_OK)
	{
	  if(sqlite3_blob_read(blob,&r->buffer[0],r->buffer_length,r->source_index)
	     ==SQLITE_OK)
	    {
	      r->request_type|=RHIZOME_HTTP_REQUEST_FROMBUFFER;
	      r->source_index+=r->buffer_length;
	    }
	  else
	    r->request_type=0;
	  sqlite3_blob_close(blob);
	}
      else
	{
	  if (debug&DEBUG_RHIZOME) WHY("could not open blob to send more data");
	  r->request_type=0;
	}
      break;
    case RHIZOME_HTTP_REQUEST_FROMBUFFER:
      /* This really shouldn't happen! */
      
      return WHY("Something impossible happened.");
      break;
    default:
      WHY("sending data from this type of HTTP request not implemented");
      break;
    }

  if (!r->request_type) return rhizome_server_close_http_request(rn);	  

  fcntl(r->socket,F_SETFL,fcntl(r->socket, F_GETFL, NULL)&(~O_NONBLOCK));
  return 1;
}

int rhizome_server_http_response_header(rhizome_http_request *r,int result,
					char *mime_type,unsigned long long bytes)
{
  if (!r->buffer) {
    r->buffer_size=bytes+strlen("HTTP/1.0 000 \r\n\r\n")+strlen(httpResultString(A_VALUE_GREATER_THAN_FOUR))+100;
    r->buffer=(unsigned char *)malloc(r->buffer_size);
  }
  snprintf((char *)r->buffer,r->buffer_size,"HTTP/1.0 %03d \r\nContent-type: %s\r\nContent-length: %lld\r\n\r\n",result,mime_type,bytes);
  
  r->buffer_length=strlen((char *)r->buffer);
  r->buffer_offset=0;

  r->request_type|=RHIZOME_HTTP_REQUEST_FROMBUFFER;
  return 0;
}
	    
