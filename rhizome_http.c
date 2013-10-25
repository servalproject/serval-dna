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
#include <assert.h>

#include "serval.h"
#include "overlay_address.h"
#include "conf.h"
#include "str.h"
#include "rhizome.h"
#include "http_server.h"

#define RHIZOME_SERVER_MAX_LIVE_REQUESTS 32

struct http_handler{
  const char *path;
  int (*parser)(rhizome_http_request *r, const char *remainder);
};

static int rhizome_status_page(rhizome_http_request *r, const char *remainder);
static int rhizome_file_page(rhizome_http_request *r, const char *remainder);
static int manifest_by_prefix_page(rhizome_http_request *r, const char *remainder);
static int interface_page(rhizome_http_request *r, const char *remainder);
static int neighbour_page(rhizome_http_request *r, const char *remainder);
static int fav_icon_header(rhizome_http_request *r, const char *remainder);
static int root_page(rhizome_http_request *r, const char *remainder);

extern int rhizome_direct_import(rhizome_http_request *r, const char *remainder);
extern int rhizome_direct_enquiry(rhizome_http_request *r, const char *remainder);
extern int rhizome_direct_dispatch(rhizome_http_request *r, const char *remainder);

struct http_handler paths[]={
  {"/rhizome/status", rhizome_status_page},
  {"/rhizome/file/", rhizome_file_page},
  {"/rhizome/import", rhizome_direct_import},
  {"/rhizome/enquiry", rhizome_direct_enquiry},
  {"/rhizome/manifestbyprefix/", manifest_by_prefix_page},
  {"/rhizome/", rhizome_direct_dispatch},
  {"/interface/", interface_page},
  {"/neighbour/", neighbour_page},
  {"/favicon.ico", fav_icon_header},
  {"/", root_page},
};

static int rhizome_dispatch(struct http_request *hr)
{
  rhizome_http_request *r = (rhizome_http_request *) hr;
  INFOF("RHIZOME HTTP SERVER, %s %s", r->http.verb, r->http.path);
  r->http.response.content_generator = NULL;
  unsigned i;
  for (i = 0; i < NELS(paths); ++i) {
    const char *remainder;
    if (str_startswith(r->http.path, paths[i].path, &remainder)){
      int ret = paths[i].parser(r, remainder);
      if (ret < 0) {
	http_request_simple_response(&r->http, 500, NULL);
	return 0;
      }
      if (ret == 0)
	return 0;
    }
  }
  http_request_simple_response(&r->http, 404, NULL);
  return 0;
}

struct sched_ent server_alarm;
struct profile_total server_stats = {
  .name = "rhizome_server_poll",
};

/*
  HTTP server and client code for rhizome transfers and rhizome direct.
  Selection of either use is made when starting the HTTP server and
  specifying the call-back function to use on client connections. 
 */

uint16_t rhizome_http_server_port = 0;
static int rhizome_server_socket = -1;
static int request_count=0;
static time_ms_t rhizome_server_last_start_attempt = -1;

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
int rhizome_http_server_start(uint16_t port_low, uint16_t port_high)
{
  if (rhizome_server_socket != -1)
    return 1;

  /* Only try to start http server every five seconds. */
  time_ms_t now = gettime_ms();
  if (now < rhizome_server_last_start_attempt + 5000)
    return 2;
  rhizome_server_last_start_attempt  = now;
  if (config.debug.rhizome_httpd)
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

  rhizome_http_server_port = port;
  /* Add Rhizome HTTPd server to list of file descriptors to watch */
  server_alarm.function = rhizome_server_poll;
  server_alarm.stats = &server_stats;
  server_alarm.poll.fd = rhizome_server_socket;
  server_alarm.poll.events = POLLIN;
  watch(&server_alarm);
  return 0;

}

static void rhizome_server_finalise_http_request(struct http_request *_r)
{
  rhizome_http_request *r = (rhizome_http_request *) _r;
  rhizome_read_close(&r->read_state);
  request_count--;
}

static int rhizome_dispatch(struct http_request *);

static unsigned int rhizome_http_request_uuid_counter = 0;

void rhizome_server_poll(struct sched_ent *alarm)
{
  if (alarm->poll.revents & (POLLIN | POLLOUT)) {
    struct sockaddr addr;
    unsigned int addr_len = sizeof addr;
    int sock;
    if ((sock = accept(rhizome_server_socket, &addr, &addr_len)) == -1) {
      if (errno && errno != EAGAIN)
	WARN_perror("accept");
    } else {
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
      rhizome_http_request *request = emalloc_zero(sizeof(rhizome_http_request));
      if (request == NULL) {
	WHY("Cannot respond to HTTP request, out of memory");
	close(sock);
      } else {
	request_count++;
	request->uuid = rhizome_http_request_uuid_counter++;
	request->data_file_name[0] = '\0';
	request->read_state.blob_fd = -1;
	request->read_state.blob_rowid = -1;
	if (peerip)
	  request->http.client_in_addr = *peerip;
	request->http.handle_headers = rhizome_dispatch;
	request->http.debug_flag = &config.debug.rhizome_httpd;
	request->http.disable_tx_flag = &config.debug.rhizome_nohttptx;
	request->http.finalise = rhizome_server_finalise_http_request;
	request->http.free = free;
	request->http.idle_timeout = RHIZOME_IDLE_TIMEOUT;
	http_request_init(&request->http, sock);
      }
    }
  }
  if (alarm->poll.revents & (POLLHUP | POLLERR)) {
    INFO("Error on tcp listen socket");
  }
}

int is_http_header_complete(const char *buf, size_t len, size_t read_since_last_call)
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

static int neighbour_page(rhizome_http_request *r, const char *remainder)
{
  if (r->http.verb != HTTP_VERB_GET) {
    http_request_simple_response(&r->http, 405, NULL);
    return 0;
  }
  char buf[8*1024];
  strbuf b = strbuf_local(buf, sizeof buf);
  sid_t neighbour_sid;
  if (str_to_sid_t(&neighbour_sid, remainder) == -1)
    return 1;
  struct subscriber *neighbour = find_subscriber(neighbour_sid.binary, sizeof(neighbour_sid.binary), 0);
  if (!neighbour)
    return 1;
  strbuf_puts(b, "<html><head><meta http-equiv=\"refresh\" content=\"5\" ></head><body>");
  link_neighbour_status_html(b, neighbour);
  strbuf_puts(b, "</body></html>");
  if (strbuf_overrun(b))
    return -1;
  http_request_response(&r->http, 200, "text/html", buf, strbuf_len(b));
  return 0;
}

static int interface_page(rhizome_http_request *r, const char *remainder)
{
  if (r->http.verb != HTTP_VERB_GET) {
    http_request_simple_response(&r->http, 405, NULL);
    return 0;
  }
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
  http_request_response(&r->http, 200, "text/html", buf, strbuf_len(b));
  return 0;
}

static int rhizome_status_page(rhizome_http_request *r, const char *remainder)
{
  if (!is_rhizome_http_enabled())
    return 1;
  if (*remainder)
    return 1;
  if (r->http.verb != HTTP_VERB_GET) {
    http_request_simple_response(&r->http, 405, NULL);
    return 0;
  }
  char buf[32*1024];
  strbuf b = strbuf_local(buf, sizeof buf);
  strbuf_puts(b, "<html><head><meta http-equiv=\"refresh\" content=\"5\" ></head><body>");
  strbuf_sprintf(b, "%d HTTP requests<br>", request_count);
  strbuf_sprintf(b, "%d Bundles transferring via MDP<br>", rhizome_cache_count());
  rhizome_fetch_status_html(b);
  strbuf_puts(b, "</body></html>");
  if (strbuf_overrun(b))
    return -1;
  http_request_response(&r->http, 200, "text/html", buf, strbuf_len(b));
  return 0;
}

static int rhizome_file_content(struct http_request *hr)
{
  rhizome_http_request *r = (rhizome_http_request *) hr;
  assert(r->http.response_length < r->http.response_buffer_size);
  assert(r->read_state.offset <= r->read_state.length);
  uint64_t readlen = r->read_state.length - r->read_state.offset;
  if (readlen == 0)
    return 0;
  size_t suggested_size = 64 * 1024;
  if (suggested_size > readlen)
    suggested_size = readlen;
  if (r->http.response_buffer_size < suggested_size)
    http_request_set_response_bufsize(&r->http, suggested_size);
  if (r->http.response_buffer == NULL)
    http_request_set_response_bufsize(&r->http, 1);
  if (r->http.response_buffer == NULL)
    return -1;
  size_t space = r->http.response_buffer_size - r->http.response_length;
  int len = rhizome_read(&r->read_state,
		         (unsigned char *)r->http.response_buffer + r->http.response_length,
			 space);
  if (len == -1)
    return -1;
  assert(len <= space);
  r->http.response_length += len;
  return 0;
}

static int rhizome_file_page(rhizome_http_request *r, const char *remainder)
{
  /* Stream the specified payload */
  if (!is_rhizome_http_enabled())
    return 1;
  if (r->http.verb != HTTP_VERB_GET) {
    http_request_simple_response(&r->http, 405, NULL);
    return 0;
  }
  if (r->http.request_header.content_range_count > 1) {
    // To support byte range sets, eg, Range: bytes=0-100,200-300,400- we would have
    // to reply with a multipart/byteranges MIME content.
    http_request_simple_response(&r->http, 501, "Not Implemented: Byte range sets");
    return 0;
  }
  rhizome_filehash_t filehash;
  if (str_to_rhizome_filehash_t(&filehash, remainder) == -1)
    return 1;
  bzero(&r->read_state, sizeof r->read_state);
  int n = rhizome_open_read(&r->read_state, &filehash);
  if (n == -1) {
    http_request_simple_response(&r->http, 500, NULL);
    return 0;
  }
  if (n != 0)
    return 1;
  if (r->read_state.length == -1 && rhizome_read(&r->read_state, NULL, 0)) {
    rhizome_read_close(&r->read_state);
    return 1;
  }
  assert(r->read_state.length != -1);
  int result_code = 200;
  struct http_range closed = (struct http_range){ .first = 0, .last = r->read_state.length };
  if (r->http.request_header.content_range_count > 0) {
    if (http_range_bytes(r->http.request_header.content_ranges,
			 r->http.request_header.content_range_count,
			 r->read_state.length
			) == 0
    ) {
      http_request_simple_response(&r->http, 416, NULL); // Request Range Not Satisfiable
      return 0;
    }
    result_code = 206; // Partial Content
    http_range_close(&closed, &r->http.request_header.content_ranges[0], 1, r->read_state.length);
  }
  r->http.response.header.content_range_start = closed.first;
  r->http.response.header.resource_length = closed.last;
  r->http.response.header.content_length = closed.last - closed.first;
  r->read_state.offset = closed.first;
  r->http.response.content_generator = rhizome_file_content;
  http_request_response(&r->http, result_code, "application/binary", NULL, 0);
  return 0;
}

static int manifest_by_prefix_page(rhizome_http_request *r, const char *remainder)
{
  if (!is_rhizome_http_enabled())
    return 1;
  if (r->http.verb != HTTP_VERB_GET) {
    http_request_simple_response(&r->http, 405, NULL);
    return 0;
  }
  rhizome_bid_t prefix;
  const char *endp = NULL;
  unsigned prefix_len = strn_fromhex(prefix.binary, sizeof prefix.binary, remainder, &endp);
  if (endp == NULL || *endp != '\0' || prefix_len < 1)
    return 1; // not found
  rhizome_manifest *m = rhizome_new_manifest();
  int ret = rhizome_retrieve_manifest_by_prefix(prefix.binary, prefix_len, m);
  if (ret == -1)
    http_request_simple_response(&r->http, 500, NULL);
  else if (ret == 0)
    http_request_response(&r->http, 200, "application/binary", (const char *)m->manifestdata, m->manifest_all_bytes);
  rhizome_manifest_free(m);
  return ret <= 0 ? 0 : 1;
}

static int fav_icon_header(rhizome_http_request *r, const char *remainder)
{
  if (*remainder)
    return 1;
  http_request_response(&r->http, 200, "image/vnd.microsoft.icon", (const char *)favicon_bytes, favicon_len);
  return 0;
}

static int root_page(rhizome_http_request *r, const char *remainder)
{
  if (*remainder)
    return 1;
  if (r->http.verb != HTTP_VERB_GET) {
    http_request_simple_response(&r->http, 405, NULL);
    return 0;
  }
  char temp[8192];
  strbuf b = strbuf_local(temp, sizeof temp);
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
  if (strbuf_overrun(b)) {
    WHY("HTTP Root page buffer overrun");
    http_request_simple_response(&r->http, 500, NULL);
  } else
    http_request_response(&r->http, 200, "text/html", temp, strbuf_len(b));
  return 0;
}
