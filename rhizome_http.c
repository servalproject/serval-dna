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
#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif

#include "serval.h"
#include "overlay_address.h"
#include "conf.h"
#include "str.h"
#include "rhizome.h"
#define RHIZOME_SERVER_MAX_LIVE_REQUESTS 32

struct sched_ent server_alarm;
struct profile_total server_stats;

struct profile_total connection_stats;

/*
  HTTP server and client code for rhizome transfers and rhizome direct.
  Selection of either use is made when starting the HTTP server and
  specifying the call-back function to use on client connections. 
 */

uint16_t rhizome_http_server_port = 0;
static int rhizome_server_socket = -1;
static int request_count=0;
static time_ms_t rhizome_server_last_start_attempt = -1;

int (*rhizome_http_parse_func)(rhizome_http_request *)=NULL;
const char *rhizome_http_parse_func_description="(null)";

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

int is_rhizome_http_server_running()
{
  return rhizome_server_socket != -1;
}

/* Start the Rhizome HTTP server by creating a socket, binding it to an available port, and
   marking it as passive.  If called repeatedly and frequently, this function will only try to start
   the server after a certain time has elapsed since the last attempt.
   Return -1 if an error occurs (message logged).
   Return 0 if the server was started.
   Return 1 if the server is already started successfully.
   Return 2 if the server was not started because it is too soon since last failed attempt.
 */
int rhizome_http_server_start(int (*parse_func)(rhizome_http_request *),
			      const char *parse_func_desc,
			      uint16_t port_low, uint16_t port_high)
{
  if (rhizome_server_socket != -1)
    return 1;

  /* Only try to start http server every five seconds. */
  time_ms_t now = gettime_ms();
  if (now < rhizome_server_last_start_attempt + 5000)
    return 2;
  rhizome_server_last_start_attempt  = now;
  if (config.debug.rhizome_tx)
    DEBUGF("Starting rhizome HTTP server");

  uint16_t port;
  for (port = port_low; port <= port_high; ++port) {
    /* Create a new socket, reusable and non-blocking. */
    if (rhizome_server_socket == -1) {
      rhizome_server_socket = socket(AF_INET,SOCK_STREAM,0);
      if (rhizome_server_socket == -1) {
	WHY_perror("socket");
	goto error;
      }
      int on=1;
      if (setsockopt(rhizome_server_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on)) == -1) {
	WHY_perror("setsockopt(REUSEADDR)");
	goto error;
      }
      if (ioctl(rhizome_server_socket, FIONBIO, (char *)&on) == -1) {
	WHY_perror("ioctl(FIONBIO)");
	goto error;
      }
    }
    /* Bind it to the next port we want to try. */
    struct sockaddr_in address;
    bzero((char *) &address, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);
    if (bind(rhizome_server_socket, (struct sockaddr *) &address, sizeof(address)) == -1) {
      if (errno != EADDRINUSE) {
	WHY_perror("bind");
	goto error;
      }
    } else {
      /* We bound to a port.  The battle is half won.  Now we have to successfully listen on that
	port, which could also fail with EADDRINUSE, in which case we have to scrap the socket and
	create a new one, because once bound, a socket stays bound.
      */
      if (listen(rhizome_server_socket, 20) != -1)
	goto success;
      if (errno != EADDRINUSE) {
	WHY_perror("listen");
	goto error;
      }
      close(rhizome_server_socket);
      rhizome_server_socket = -1;
    }
  }
  WHYF("No ports available in range %u to %u", RHIZOME_HTTP_PORT, RHIZOME_HTTP_PORT_MAX);
error:
  if (rhizome_server_socket != -1) {
    close(rhizome_server_socket);
    rhizome_server_socket = -1;
  }
  return WHY("Failed to start rhizome HTTP server");

success:
  if (config.rhizome.http.enable)
    INFOF("RHIZOME HTTP SERVER, START port=%"PRIu16" fd=%d", port, rhizome_server_socket);
  else
    INFOF("HTTP SERVER (LIMITED SERVICE), START port=%"PRIu16" fd=%d", port, rhizome_server_socket);

  /* Remember which function to call when handling client connections */
  rhizome_http_parse_func=parse_func;
  rhizome_http_parse_func_description=parse_func_desc;

  rhizome_http_server_port = port;
  /* Add Rhizome HTTPd server to list of file descriptors to watch */
  server_alarm.function = rhizome_server_poll;
  server_stats.name="rhizome_server_poll";
  server_alarm.stats=&server_stats;
  server_alarm.poll.fd = rhizome_server_socket;
  server_alarm.poll.events = POLLIN;
  watch(&server_alarm);
  return 0;

}

void rhizome_client_poll(struct sched_ent *alarm)
{
  rhizome_http_request *r = (rhizome_http_request *)alarm;
  if (alarm->poll.revents == 0 || alarm->poll.revents & (POLLHUP | POLLERR)){
    if (config.debug.rhizome_tx)
      DEBUGF("Closing connection due to timeout or error %d", alarm->poll.revents);
    rhizome_server_free_http_request(r);
    return;
  }
  
  if (alarm->poll.revents & POLLIN){
    switch(r->request_type)
      {
      case RHIZOME_HTTP_REQUEST_RECEIVING_MULTIPART:
	{
	  /* Reading multi-part form data. Read some bytes and proces them. */
	  char buffer[16384];
	  sigPipeFlag=0;
	  int bytes = read_nonblock(r->alarm.poll.fd, buffer, 16384);
	  /* If we got some data, see if we have found the end of the HTTP request */
	  if (bytes > 0) {
	    // reset inactivity timer
	    r->alarm.alarm = gettime_ms() + RHIZOME_IDLE_TIMEOUT;
	    r->alarm.deadline = r->alarm.alarm + RHIZOME_IDLE_TIMEOUT;
	    unschedule(&r->alarm);
	    schedule(&r->alarm);
	    rhizome_direct_process_post_multipart_bytes(r,buffer,bytes);
	  }
	  /* We don't drop the connection on an empty read, because that results
	     in connections dropping when they shouldn't, including during testing.
	     The idle timeout should drop the connections instead.
	  */
	  if (sigPipeFlag) {
	    if (config.debug.rhizome_tx)
	      DEBUG("Received SIGPIPE, closing connection");
	    rhizome_server_free_http_request(r);
	    return;
	  }
	}
	break;
	
      case RHIZOME_HTTP_REQUEST_RECEIVING:
	/* Keep reading until we have two CR/LFs in a row */
	r->request[r->request_length] = '\0';
	sigPipeFlag=0;
	int bytes = read_nonblock(r->alarm.poll.fd, &r->request[r->request_length], sizeof r->request - r->request_length);
	/* If we got some data, see if we have found the end of the HTTP request */
	if (bytes > 0) {
	  // reset inactivity timer
	  r->alarm.alarm = gettime_ms() + RHIZOME_IDLE_TIMEOUT;
	  r->alarm.deadline = r->alarm.alarm + RHIZOME_IDLE_TIMEOUT;
	  unschedule(&r->alarm);
	  schedule(&r->alarm);
	  r->request_length += bytes;
	  r->header_length = http_header_complete(r->request, r->request_length, bytes);
	  if (r->header_length){
	    /* We have the request. Now parse it to see if we can respond to it */
	    if (rhizome_http_parse_func!=NULL) 
	      rhizome_http_parse_func(r);
	  }
	} else {
	  if (config.debug.rhizome_tx)
	    DEBUG("Empty read, closing connection");
	  rhizome_server_free_http_request(r);
	  return;
	}
	if (sigPipeFlag) {
	  if (config.debug.rhizome_tx)
	    DEBUG("Received SIGPIPE, closing connection");
	  rhizome_server_free_http_request(r);
	  return;
	}
	break;
      }
  }
  
  if (alarm->poll.revents & POLLOUT){
    /* Socket already has request -- so just try to send some data. */
    rhizome_server_http_send_bytes(r);
  }
  return;
}

static unsigned int rhizome_http_request_uuid_counter=0;

void rhizome_server_poll(struct sched_ent *alarm)
{
  if (alarm->poll.revents & (POLLIN | POLLOUT)) {
    struct sockaddr addr;
    unsigned int addr_len = sizeof addr;
    int sock;
    if ((sock = accept(rhizome_server_socket, &addr, &addr_len)) != -1) {
      struct sockaddr_in *peerip=NULL;
      if (addr.sa_family == AF_INET) {
	peerip = (struct sockaddr_in *)&addr;
	INFOF("RHIZOME HTTP SERVER, ACCEPT addrlen=%u family=%u port=%u addr=%u.%u.%u.%u",
	    addr_len, peerip->sin_family, peerip->sin_port,
	    ((unsigned char*)&peerip->sin_addr.s_addr)[0],
	    ((unsigned char*)&peerip->sin_addr.s_addr)[1],
	    ((unsigned char*)&peerip->sin_addr.s_addr)[2],
	    ((unsigned char*)&peerip->sin_addr.s_addr)[3]
	  );
      } else {
	INFOF("RHIZOME HTTP SERVER, ACCEPT addrlen=%u family=%u data=%s",
	    addr_len, addr.sa_family, alloca_tohex((unsigned char *)addr.sa_data, sizeof addr.sa_data)
	  );
      }
      rhizome_http_request *request = calloc(sizeof(rhizome_http_request), 1);
      if (request == NULL) {
	WHYF_perror("calloc(%u, 1)", (int)sizeof(rhizome_http_request));
	WHY("Cannot respond to request, out of memory");
	close(sock);
      } else {
	request_count++;
	request->uuid=rhizome_http_request_uuid_counter++;
	if (peerip) request->requestor=*peerip; 
	else bzero(&request->requestor,sizeof(request->requestor));
	request->data_file_name[0]=0;
	/* We are now trying to read the HTTP request */
	request->request_type=RHIZOME_HTTP_REQUEST_RECEIVING;
	request->alarm.function = rhizome_client_poll;
	request->read_state.blob_fd=-1;
	request->read_state.blob_rowid=-1;
	connection_stats.name="rhizome_client_poll";
	request->alarm.stats=&connection_stats;
	request->alarm.poll.fd=sock;
	request->alarm.poll.events=POLLIN;
	request->alarm.alarm = gettime_ms()+RHIZOME_IDLE_TIMEOUT;
	request->alarm.deadline = request->alarm.alarm+RHIZOME_IDLE_TIMEOUT;
	// watch for the incoming http request
	watch(&request->alarm);
	// set an inactivity timeout to close the connection
	schedule(&request->alarm);
      }
    }
    if (errno && errno != EAGAIN)
      WARN_perror("accept");
  }
  if (alarm->poll.revents & (POLLHUP | POLLERR)) {
    INFO("Error on tcp listen socket");
  }
}

int rhizome_server_free_http_request(rhizome_http_request *r)
{
  unwatch(&r->alarm);
  unschedule(&r->alarm);
  close(r->alarm.poll.fd);
  if (r->buffer)
    free(r->buffer);
  rhizome_read_close(&r->read_state);
  free(r);
  request_count--;
  return 0;
}

int http_header_complete(const char *buf, size_t len, size_t read_since_last_call)
{
  IN();
  const char *bufend = buf + len;
  const char *p = buf;
  size_t tail = read_since_last_call + 4;
  if (tail < len)
    p = bufend - tail;
  int count = 0;
  for (; p != bufend; ++p) {
    switch (*p) {
      case '\n': 
	if (++count==2)
	  RETURN(p - buf);
      case '\r': // ignore CR
      case '\0': // ignore NUL (telnet inserts them)
	break;
      default: 
	count = 0; 
	break;
    }
  }
  RETURN(0);
  OUT();
}

static int neighbour_page(rhizome_http_request *r, const char *remainder, const char *headers)
{
  char buf[8*1024];
  strbuf b=strbuf_local(buf, sizeof buf);
  
  sid_t neighbour_sid;
  if (str_to_sid_t(&neighbour_sid, remainder) == -1)
    return -1;
    
  struct subscriber *neighbour = find_subscriber(neighbour_sid.binary, sizeof(neighbour_sid.binary), 0);
  if (!neighbour)
    return 1;
    
  strbuf_puts(b, "<html><head><meta http-equiv=\"refresh\" content=\"5\" ></head><body>");
  link_neighbour_status_html(b, neighbour);
  strbuf_puts(b, "</body></html>");
  if (strbuf_overrun(b))
    return -1;
  rhizome_server_simple_http_response(r, 200, buf);
  return 0;
}

static int interface_page(rhizome_http_request *r, const char *remainder, const char *headers)
{
  char buf[8*1024];
  strbuf b=strbuf_local(buf, sizeof buf);
  int index=atoi(remainder);
  if (index<0 || index>=OVERLAY_MAX_INTERFACES)
    return 1;
    
  strbuf_puts(b, "<html><head><meta http-equiv=\"refresh\" content=\"5\" ></head><body>");
  interface_state_html(b, &overlay_interfaces[index]);
  strbuf_puts(b, "</body></html>");
  if (strbuf_overrun(b))
    return -1;
    
  rhizome_server_simple_http_response(r, 200, buf);
  return 0;
}

static int rhizome_status_page(rhizome_http_request *r, const char *remainder, const char *headers)
{
  if (!is_rhizome_http_enabled())
    return 1;
  if (*remainder)
    return 1;
    
  char buf[32*1024];
  struct strbuf b;
  strbuf_init(&b, buf, sizeof buf);
  strbuf_puts(&b, "<html><head><meta http-equiv=\"refresh\" content=\"5\" ></head><body>");
  strbuf_sprintf(&b, "%d HTTP requests<br>", request_count);
  strbuf_sprintf(&b, "%d Bundles transferring via MDP<br>", rhizome_cache_count());
  rhizome_fetch_status_html(&b);
  strbuf_puts(&b, "</body></html>");
  if (strbuf_overrun(&b))
    return -1;
  rhizome_server_simple_http_response(r, 200, buf);
  return 0;
}

static int rhizome_file_content(rhizome_http_request *r)
{
  int suggested_size=65536;
  if (suggested_size > r->read_state.length - r->read_state.offset)
    suggested_size = r->read_state.length - r->read_state.offset;
  if (suggested_size<=0)
    return 0;
  
  if (r->buffer_size < suggested_size){
    r->buffer_size = suggested_size;
    if (r->buffer)
      free(r->buffer);
    r->buffer = malloc(r->buffer_size);
  }
  
  if (!r->buffer)
    return -1;
  
  r->buffer_length = rhizome_read(&r->read_state, r->buffer, r->buffer_size);
  return 0;
}

static int rhizome_file_page(rhizome_http_request *r, const char *remainder, const char *headers)
{
  /* Stream the specified payload */
  if (!is_rhizome_http_enabled())
    return 1;
  
  rhizome_filehash_t filehash;
  if (str_to_rhizome_filehash_t(&filehash, remainder) == -1)
    return -1;
  
  bzero(&r->read_state, sizeof(r->read_state));

  /* Refuse to honour HTTP request if required (used for debugging and 
     testing transition from HTTP to MDP) */
  if (rhizome_open_read(&r->read_state, &filehash))
    return 1;
    
  if (r->read_state.length==-1){
    if (rhizome_read(&r->read_state, NULL, 0)){
      rhizome_read_close(&r->read_state);
      return 1;
    }
  }
  
  const char *range=str_str((char*)headers,"Range: bytes=",-1);
  r->read_state.offset = r->source_index = 0;
  
  if (range){
    sscanf(range, "Range: bytes=%"PRId64"-", &r->read_state.offset);
    if (0)
      DEBUGF("Found range header %"PRId64,r->read_state.offset);
  }
  
  if (r->read_state.length - r->read_state.offset<=0){
    rhizome_server_simple_http_response(r, 200, "");
    return 0;
  }
  
  struct http_response hr;
  bzero(&hr, sizeof hr);
  hr.result_code = 200;
  hr.content_type = "application/binary";
  hr.content_start = r->read_state.offset;
  hr.content_end = r->read_state.length;
  hr.content_length = r->read_state.length;
  hr.body = NULL;
  r->generator = rhizome_file_content;
  rhizome_server_set_response(r, &hr);
  return 0;
}

static int manifest_by_prefix_page(rhizome_http_request *r, const char *remainder, const char *headers)
{
  if (!is_rhizome_http_enabled())
    return 1;
  rhizome_bid_t prefix;
  const char *endp = NULL;
  unsigned prefix_len = strn_fromhex(prefix.binary, sizeof prefix.binary, remainder, &endp);
  if (endp == NULL || *endp != '\0' || prefix_len < 1)
    return 1; // not found
  rhizome_manifest *m = rhizome_new_manifest();
  int ret = rhizome_retrieve_manifest_by_prefix(prefix.binary, prefix_len, m);
  if (ret==0)
    rhizome_server_http_response(r, 200, "application/binary", (const char *)m->manifestdata, m->manifest_all_bytes);
  rhizome_manifest_free(m);
  return ret;
}

static int fav_icon_header(rhizome_http_request *r, const char *remainder, const char *headers)
{
  if (*remainder)
    return 1;
  rhizome_server_http_response(r, 200, "image/vnd.microsoft.icon", (const char *)favicon_bytes, favicon_len);
  return 0;
}

static int root_page(rhizome_http_request *r, const char *remainder, const char *headers)
{
  if (*remainder)
    return 1;
  
  char temp[8192];
  strbuf b=strbuf_local(temp, sizeof(temp));
  strbuf_sprintf(b, "<html><head><meta http-equiv=\"refresh\" content=\"5\" ></head><body>"
	   "<h1>Hello, I'm %s*</h1><br>"
	   "Interfaces;<br>",
	   alloca_tohex_sid_t_trunc(my_subscriber->sid, 16));
  int i;
  for (i=0;i<OVERLAY_MAX_INTERFACES;i++){
    if (overlay_interfaces[i].state==INTERFACE_STATE_UP)
      strbuf_sprintf(b, "<a href=\"/interface/%d\">%d: %s, TX: %d, RX: %d</a><br>", 
	i, i, overlay_interfaces[i].name, overlay_interfaces[i].tx_count, overlay_interfaces[i].recv_count);
  }
  
  strbuf_puts(b, "Neighbours;<br>");
  link_neighbour_short_status_html(b, "/neighbour");
  
  if (is_rhizome_http_enabled()){
    strbuf_puts(b, "<a href=\"/rhizome/status\">Rhizome Status</a><br>");
  }
  strbuf_puts(b, "</body></html>");
  if (strbuf_overrun(b))
    return -1;
  rhizome_server_simple_http_response(r, 200, temp);
  return 0;
}

struct http_handler{
  const char *path;
  int (*parser)(rhizome_http_request *r, const char *remainder, const char *headers);
};

struct http_handler paths[]={
  {"/rhizome/status", rhizome_status_page},
  {"/rhizome/file/", rhizome_file_page},
  {"/rhizome/manifestbyprefix/", manifest_by_prefix_page},
  {"/interface/", interface_page},
  {"/neighbour/", neighbour_page},
  {"/favicon.ico", fav_icon_header},
  {"/", root_page},
};

int rhizome_direct_parse_http_request(rhizome_http_request *r);
int rhizome_server_parse_http_request(rhizome_http_request *r)
{
  // Start building up a response.
  // Parse the HTTP "GET" line.
  char *path = NULL;
  char *headers = NULL;
  if (str_startswith(r->request, "POST ", (const char **)&path)) {
    return rhizome_direct_parse_http_request(r);
  } else if (str_startswith(r->request, "GET ", (const char **)&path)) {
    const char *p;
    size_t header_length = 0;
    size_t pathlen = 0;
    // This loop is guaranteed to terminate before the end of the buffer, because we know that the
    // buffer contains at least "\n\n" and maybe "\r\n\r\n" at the end of the header block.
    for (p = path; !isspace(*p); ++p)
      ;
    pathlen = p - path;
    if ( str_startswith(p, " HTTP/1.", &p)
      && (str_startswith(p, "0", &p) || str_startswith(p, "1", &p))
      && (str_startswith(p, "\r\n", (const char **)&headers) || str_startswith(p, "\n", (const char **)&headers))
    ){
      path[pathlen] = '\0';
      header_length = r->header_length - (headers - r->request);
      headers[header_length] = '\0';
    }else
      path = NULL;
  }
  
  if (!path) {
    if (config.debug.rhizome_tx)
      DEBUGF("Received malformed HTTP request: %s", alloca_toprint(120, (const char *)r->request, r->request_length));
    rhizome_server_simple_http_response(r, 400, "<html><h1>Malformed request</h1></html>\r\n");
    return 0;
  }
  
  char *id = NULL;
  INFOF("RHIZOME HTTP SERVER, GET %s", path);
  
  int i;
  r->generator=NULL;
  
  for (i=0;i<sizeof(paths)/sizeof(struct http_handler);i++){
    if (str_startswith(path, paths[i].path, (const char **)&id)){
      int ret=paths[i].parser(r, id, headers);
      if (ret<0)
	rhizome_server_simple_http_response(r, 500, "<html><h1>Internal Error</h1></html>\r\n");
      if (ret>0)
	rhizome_server_simple_http_response(r, 404, "<html><h1>Not Found</h1></html>\r\n");
      
      /* Try sending data immediately. */
      rhizome_server_http_send_bytes(r);

      return 0;
    }
  }
  
  rhizome_server_simple_http_response(r, 404, "<html><h1>Not Found</h1></html>\r\n");
  return 0;
}


/* Return appropriate message for HTTP response codes, both known and unknown. */
static const char *httpResultString(int response_code) {
  switch (response_code) {
  case 200: return "OK";
  case 201: return "Created";
  case 206: return "Partial Content";
  case 404: return "Not found";
  case 500: return "Internal server error";
  default:  
    if (response_code<=4)
      return "Unknown status code";
    else
      return "A suffusion of yellow";
  }
}

static strbuf strbuf_build_http_response(strbuf sb, const struct http_response *h)
{
  strbuf_sprintf(sb, "HTTP/1.0 %03u %s\r\n", h->result_code, httpResultString(h->result_code));
  strbuf_sprintf(sb, "Content-type: %s\r\n", h->content_type);
  if (h->content_end && h->content_length && (h->content_start!=0 || h->content_end!=h->content_length))
    strbuf_sprintf(sb, 
	  "Content-range: bytes %"PRIu64"-%"PRIu64"/%"PRIu64"\r\n"
	  "Content-length: %"PRIu64"\r\n", 
      h->content_start, h->content_end, h->content_length, h->content_end - h->content_start);
  else if (h->content_length)
    strbuf_sprintf(sb, "Content-length: %"PRIu64"\r\n", h->content_length);
  strbuf_puts(sb, "\r\n");
  return sb;
}

int rhizome_server_set_response(rhizome_http_request *r, const struct http_response *h)
{
  r->request_type=0;
  
  if (config.debug.rhizome_nohttptx)
    unwatch(&r->alarm);
  else{
    /* Switching to writing, so update the call-back */
    r->alarm.poll.events=POLLOUT;
    watch(&r->alarm);
  }  
  
  strbuf b = strbuf_local((char *) r->buffer, r->buffer_size);
  strbuf_build_http_response(b, h);
  if (r->buffer == NULL || strbuf_overrun(b) || (h->body && strbuf_remaining(b) < h->content_length)) {
    // Need a bigger buffer
    if (r->buffer)
      free(r->buffer);
    r->buffer_size = strbuf_count(b) + 1;
    if (h->body)
      r->buffer_size += h->content_length;
    r->buffer = malloc(r->buffer_size);
    if (r->buffer == NULL) {
      WHYF_perror("malloc(%u)", r->buffer_size);
      r->buffer_size = 0;
      return WHY("Cannot send response, out of memory");
    }
    strbuf_init(b, (char *) r->buffer, r->buffer_size);
    strbuf_build_http_response(b, h);
    if (strbuf_overrun(b) || (h->body && strbuf_remaining(b) < h->content_length))
      return WHYF("Bug! Cannot send response, buffer not big enough");
  }
  r->buffer_length = strbuf_len(b);
  if (h->body){
    bcopy(h->body, strbuf_end(b), h->content_length);
    r->buffer_length+=h->content_length;
  }
  r->buffer_offset = 0;
  if (config.debug.rhizome_tx)
    DEBUGF("Sending HTTP response: %s", alloca_toprint(160, (const char *)r->buffer, r->buffer_length));
  return 0;
}

int rhizome_server_simple_http_response(rhizome_http_request *r, int result, const char *response)
{
  struct http_response hr;
  bzero(&hr, sizeof hr);
  hr.result_code = result;
  hr.content_type = "text/html";
  hr.content_length = strlen(response);
  hr.body = response;
  if (result==400) {
    DEBUGF("Rejecting http request as malformed due to: %s",
	   response);
  }
  return rhizome_server_set_response(r, &hr);
}

int rhizome_server_http_response(rhizome_http_request *r, int result, 
    const char *mime_type, const char *body, uint64_t bytes)
{
  struct http_response hr;
  bzero(&hr, sizeof hr);
  hr.result_code = result;
  hr.content_type = mime_type;
  hr.content_length = bytes;
  hr.body = body;
  return rhizome_server_set_response(r, &hr);
}

int rhizome_server_http_response_header(rhizome_http_request *r, int result, const char *mime_type, uint64_t bytes)
{
  return rhizome_server_http_response(r, result, mime_type, NULL, bytes);
}

/*
  return codes:
  1: connection still open.
  0: connection finished.
  <0: an error occurred.
*/
int rhizome_server_http_send_bytes(rhizome_http_request *r)
{
  // Don't send anything if disabled for testing HTTP->MDP Rhizome failover
  if (config.debug.rhizome_nohttptx)
    return 1;

  // write one block of buffered data
  if(r->buffer_offset < r->buffer_length){
    int bytes=r->buffer_length - r->buffer_offset;
    bytes=write(r->alarm.poll.fd,&r->buffer[r->buffer_offset],bytes);
    if (bytes<0){
      // stop writing when the tcp buffer is full
      // TODO errors?
      return 1;
    }
    r->buffer_offset+=bytes;
    
    // reset inactivity timer
    r->alarm.alarm = gettime_ms()+RHIZOME_IDLE_TIMEOUT;
    r->alarm.deadline = r->alarm.alarm+RHIZOME_IDLE_TIMEOUT;
    unschedule(&r->alarm);
    schedule(&r->alarm);
    
    // allow other alarms to fire and wait for the next POLLOUT
    return 1;
  }
  
  r->buffer_offset=r->buffer_length=0;
  
  if (r->generator){
    r->generator(r);
  }
  
  // once we've written the whole buffer, and nothing new has been generated, close the connection
  if (!r->buffer_length){
    if (config.debug.rhizome_tx)
      DEBUG("Closing connection, done");
    return rhizome_server_free_http_request(r);
  }
  return 1;
}
