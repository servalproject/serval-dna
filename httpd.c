/*
Serval DNA HTTP external interface
Copyright (C) 2014 Serval Project Inc.
 
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

#include <sys/ioctl.h>
#include "httpd.h"
#include "mem.h"
#include "net.h"
#include "conf.h"

#define RHIZOME_SERVER_MAX_LIVE_REQUESTS 32

static int httpd_dispatch(struct http_request *hr)
{
  httpd_request *r = (httpd_request *) hr;
  INFOF("HTTP SERVER, %s %s", r->http.verb, r->http.path);
  r->http.response.content_generator = NULL;
  
  struct http_handler *handler, *parser=NULL;
  const char *remainder=NULL;
  size_t match_len=0;
  
  for (handler = SECTION_START(httpd); handler < SECTION_END(httpd); ++handler) {
    size_t path_len = strlen(handler->path);
    if (parser && path_len < match_len)
      continue;
    
    const char *p;
    if (str_startswith(r->http.path, handler->path, &p)){
      match_len = path_len;
      parser = handler;
      remainder = p;
    }
  }
  if (parser){
    int result = parser->parser(r, remainder);
    if (result == -1 || (result >= 200 && result < 600))
      return result;
    if (result == 1)
      return 0;
    if (result)
      return WHYF("dispatch function for %s returned invalid result %d", parser->path, result);
  }
  return 404;
}

void httpd_server_poll(struct sched_ent *);
struct sched_ent server_alarm;
struct profile_total server_stats = {
  .name = "httpd_server_poll",
};

uint16_t httpd_server_port = 0;

static int httpd_server_socket = -1;
static time_ms_t httpd_server_last_start_attempt = -1;

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

int is_httpd_server_running()
{
  return httpd_server_socket != -1;
}

/* Start the Rhizome HTTP server by creating a socket, binding it to an available port, and
   marking it as passive.  If called repeatedly and frequently, this function will only try to start
   the server after a certain time has elapsed since the last attempt.
   Return -1 if an error occurs (message logged).
   Return 0 if the server was started.
   Return 1 if the server is already started successfully.
   Return 2 if the server was not started because it is too soon since last failed attempt.
 */
int httpd_server_start(const uint16_t port_low, const uint16_t port_high)
{
  if (httpd_server_socket != -1)
    return 1;

  /* Only try to start http server every five seconds. */
  time_ms_t now = gettime_ms();
  if (now < httpd_server_last_start_attempt + 5000)
    return 2;
  httpd_server_last_start_attempt  = now;
  DEBUGF(httpd, "Starting HTTP server");

  uint16_t port;
  for (port = port_low; port <= port_high; ++port) {
    /* Create a new socket, reusable and non-blocking. */
    if (httpd_server_socket == -1) {
      httpd_server_socket = socket(AF_INET, SOCK_STREAM, 0);
      if (httpd_server_socket == -1) {
	WHY_perror("socket(AF_INET, SOCK_STREAM, 0)");
	goto error;
      }
      int on=1;
      if (setsockopt(httpd_server_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on)) == -1) {
	WHY_perror("setsockopt(REUSEADDR)");
	goto error;
      }
      if (ioctl(httpd_server_socket, FIONBIO, (char *)&on) == -1) {
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
    if (bind(httpd_server_socket, (struct sockaddr *) &address, sizeof(address)) == -1) {
      if (errno != EADDRINUSE) {
	WHY_perror("bind");
	goto error;
      }
    } else {
      /* We bound to a port.  The battle is half won.  Now we have to successfully listen on that
	port, which could also fail with EADDRINUSE, in which case we have to scrap the socket and
	create a new one, because once bound, a socket stays bound.
      */
      if (listen(httpd_server_socket, 20) != -1)
	goto success;
      if (errno != EADDRINUSE) {
	WHY_perror("listen");
	goto error;
      }
      close(httpd_server_socket);
      httpd_server_socket = -1;
    }
  }
  WHYF("No ports available in range %u to %u", port_low, port_high);
error:
  if (httpd_server_socket != -1) {
    close(httpd_server_socket);
    httpd_server_socket = -1;
  }
  return WHY("Failed to start HTTP server");

success:
  httpd_server_port = port;
  /* Add Rhizome HTTPd server to list of file descriptors to watch */
  server_alarm.function = httpd_server_poll;
  server_alarm.stats = &server_stats;
  server_alarm.poll.fd = httpd_server_socket;
  server_alarm.poll.events = POLLIN;
  watch(&server_alarm);
  
  INFOF("HTTP SERVER START port=%u fd=%d services=RESTful%s%s",
      httpd_server_port,
      httpd_server_socket,
      config.rhizome.http.enable ? ",Rhizome" : "",
      config.rhizome.api.addfile.uri_path[0] ? ",RhizomeDirect" : ""
    );
 
  return 0;
}

static int httpd_dispatch(struct http_request *);

static unsigned int http_request_uuid_counter = 0;
static httpd_request * current_httpd_requests = NULL;
unsigned int current_httpd_request_count = 0;

static void httpd_server_finalise_http_request(struct http_request *hr)
{
  httpd_request *r = (httpd_request *) hr;
  DEBUGF(httpd, "current_httpd_request_count=%u current_httpd_requests=%p r=%p r->next=%p r->prev=%p", current_httpd_request_count, current_httpd_requests, r, r->next, r->prev);
  if (r->next) {
    assert(current_httpd_request_count >= 2);
    assert(r->next->prev == r);
    r->next->prev = r->prev;
  }
  if (r->prev) {
    assert(current_httpd_request_count >= 2);
    assert(r->prev->next == r);
    r->prev->next = r->next;
  }
  else {
    assert(current_httpd_requests == r);
    current_httpd_requests = r->next;
  }
  r->next = r->prev = NULL;
  assert(current_httpd_request_count > 0);
  --current_httpd_request_count;
  if (current_httpd_requests == NULL) {
    assert(current_httpd_request_count == 0);
  }
  if (r->manifest) {
    rhizome_manifest_free(r->manifest);
    r->manifest = NULL;
  }
  if (r->finalise_union) {
    r->finalise_union(r);
    r->finalise_union = NULL;
  }
}

void httpd_server_poll(struct sched_ent *alarm)
{
  if (alarm->poll.revents & (POLLIN | POLLOUT)) {
    struct sockaddr addr;
    unsigned int addr_len = sizeof addr;
    int sock;
    if ((sock = accept(httpd_server_socket, &addr, &addr_len)) == -1) {
      if (errno && errno != EAGAIN)
	WARN_perror("accept");
    } else {
      ++http_request_uuid_counter;
      strbuf_sprintf(&log_context, "httpd/%u", http_request_uuid_counter);
      struct sockaddr_in *peerip=NULL;
      if (addr.sa_family == AF_INET) {
	peerip = (struct sockaddr_in *)&addr; // network order
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
      httpd_request *request = emalloc_zero(sizeof(httpd_request));
      if (request == NULL) {
	WHY("Cannot respond to HTTP request, out of memory");
	close(sock);
      } else {
	request->next = current_httpd_requests;
	request->prev = NULL;
	if (current_httpd_requests) {
	  assert(current_httpd_request_count > 0);
	  current_httpd_requests->prev = request;
	}
	current_httpd_requests = request;
	++current_httpd_request_count;
	request->payload_status = INVALID_RHIZOME_PAYLOAD_STATUS;
	request->bundle_status = INVALID_RHIZOME_BUNDLE_STATUS;
	if (peerip)
	  request->http.client_sockaddr_in = *peerip;
	request->http.uuid = http_request_uuid_counter;
	request->http.handle_headers = httpd_dispatch;
	request->http.debug = INDIRECT_CONFIG_DEBUG(httpd);
	request->http.disable_tx = INDIRECT_CONFIG_DEBUG(nohttptx);
	request->http.finalise = httpd_server_finalise_http_request;
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

static void trigger_rhizome_bundle_added(rhizome_manifest *m)
{
  httpd_request *r;
  for (r = current_httpd_requests; r; r = r->next) {
    if (r->trigger_rhizome_bundle_added) {
      (*r->trigger_rhizome_bundle_added)(r, m);
    }
  }
}

DEFINE_TRIGGER(bundle_add, trigger_rhizome_bundle_added)

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

static int is_from_loopback(const struct http_request *r)
{
  return   r->client_sockaddr_in.sin_family == AF_INET
	&& ((unsigned char*)&r->client_sockaddr_in.sin_addr.s_addr)[0] == IN_LOOPBACKNET;
}

/* Return 1 if the given authorization credentials are acceptable.
 * Return 0 if not.
 */
static int is_authorized_restful(const struct http_client_authorization *auth)
{
  if (auth->scheme != BASIC)
    return 0;
  unsigned i;
  for (i = 0; i != config.api.restful.users.ac; ++i) {
    if (   strcmp(config.api.restful.users.av[i].key, auth->credentials.basic.user) == 0
	&& strcmp(config.api.restful.users.av[i].value.password, auth->credentials.basic.password) == 0
    )
      return 1;
  }
  return 0;
}

int authorize_restful(struct http_request *r)
{
  if (!is_from_loopback(r))
    return 403;
  if (r->request_header.origin){
    const char *remainder;
    if (strcasecmp(r->request_header.origin, "null")==0
      || (strcase_startswith(r->request_header.origin, "http://localhost", &remainder)
	&& (*remainder==':' || *remainder=='\0'))
      || (strcase_startswith(r->request_header.origin, "http://127.0.0.1", &remainder)
	&& (*remainder==':' || *remainder=='\0'))
      || (strcase_startswith(r->request_header.origin, "file://", &remainder))
      ){
      strncpy(r->response.header.allow_origin,r->request_header.origin, sizeof r->response.header.allow_origin);
      r->response.header.allow_methods="GET, POST, OPTIONS";
      r->response.header.allow_headers="Authorization";
    }else
      return 403;
  }
  if (r->verb == HTTP_VERB_OPTIONS){
    http_request_simple_response(r, 200, NULL);
    return 200;
  }
  if (!is_authorized_restful(&r->request_header.authorization)) {
    r->response.header.www_authenticate.scheme = BASIC;
    r->response.header.www_authenticate.realm = "Serval RESTful API";
    return 401;
  }
  return 0;
}

int accumulate_text(httpd_request *r, const char *partname, char *textbuf, size_t textsiz, size_t *textlenp, const char *buf, size_t len)
{
  if (len) {
    size_t newlen = *textlenp + len;
    if (newlen > textsiz) {
      DEBUGF(httpd, "Form part \"%s\" too long, %zu bytes overflows maximum %zu by %zu",
	     partname, newlen, textsiz, (size_t)(newlen - textsiz)
	);
      strbuf msg = strbuf_alloca(100);
      strbuf_sprintf(msg, "Overflow in \"%s\" form part", partname);
      http_request_simple_response(&r->http, 403, strbuf_str(msg));
      return 0;
    }
    memcpy(textbuf + *textlenp, buf, len);
    *textlenp = newlen;
  }
  return 1;
}

int form_buf_malloc_init(struct form_buf_malloc *f, size_t size_limit)
{
  assert(f->buffer == NULL);
  assert(f->buffer_alloc_size == 0);
  assert(f->length == 0);
  f->size_limit = size_limit;
  return 0;
}

int form_buf_malloc_accumulate(httpd_request *r, const char *partname, struct form_buf_malloc *f, const char *buf, size_t len)
{
  if (len == 0)
    return 0;
  size_t newlen = f->length + len;
  if (newlen > f->size_limit) {
    DEBUGF(httpd, "form part \"%s\" overflow, %zu bytes exceeds limit %zu by %zu",
	   partname, newlen, f->size_limit, (size_t)(newlen - f->size_limit)
      );
    strbuf msg = strbuf_alloca(100);
    strbuf_sprintf(msg, "Overflow in \"%s\" form part", partname);
    http_request_simple_response(&r->http, 403, strbuf_str(msg));
    return 403;
  }
  if (newlen > f->buffer_alloc_size) {
    if ((f->buffer = erealloc(f->buffer, newlen)) == NULL) {
      http_request_simple_response(&r->http, 500, NULL);
      return 500;
    }
    f->buffer_alloc_size = newlen;
  }
  memcpy(f->buffer + f->length, buf, len);
  f->length = newlen;
  return 0;
}

void form_buf_malloc_release(struct form_buf_malloc *f)
{
  if (f->buffer) {
    free(f->buffer);
    f->buffer = NULL;
  }
  f->buffer_alloc_size = 0;
  f->length = 0;
  f->size_limit = 0;
}

int http_response_content_type(httpd_request *r, const char *what, const struct mime_content_type *ct)
{
  DEBUGF(httpd, "%s Content-Type: %s/%s%s%s%s%s", what, ct->type, ct->subtype,
	 ct->charset[0] ? "; charset=" : "",
	 ct->charset,
	 ct->multipart_boundary[0] ? "; boundary=" : "",
	 ct->multipart_boundary
      );
  strbuf msg = strbuf_alloca(200);
  strbuf_sprintf(msg, "%s Content-Type:", what);
  if (ct->type[0])
    strbuf_sprintf(msg, " %s", ct->type);
  if (ct->subtype[0])
    strbuf_sprintf(msg, "/%s", ct->subtype);
  if (ct->charset[0])
    strbuf_sprintf(msg, "; charset=%s", ct->charset);
  if (ct->multipart_boundary[0])
    strbuf_sprintf(msg, "; boundary=%s", ct->multipart_boundary);
  http_request_simple_response(&r->http, 403, strbuf_str(msg));
  return 403;
}

int http_response_content_disposition(httpd_request *r, const char *what, const char *type)
{
  DEBUGF(httpd, "%s Content-Disposition: %s %s", what, type);
  strbuf msg = strbuf_alloca(100);
  strbuf_sprintf(msg, "%s Content-Disposition: %s", what, type);
  http_request_simple_response(&r->http, 403, strbuf_str(msg));
  return 403;
}

int http_response_form_part(httpd_request *r, const char *what, const char *partname, const char *text, size_t textlen)
{
  DEBUGF(httpd, "%s \"%s\" form part %s", what, partname, text ? alloca_toprint(-1, text, textlen) : "");
  strbuf msg = strbuf_alloca(100);
  strbuf_sprintf(msg, "%s \"%s\" form part", what, partname);
  http_request_simple_response(&r->http, 403, strbuf_str(msg));
  return 403;
}

int http_response_init_content_range(httpd_request *r, size_t resource_length)
{
  r->http.response.header.resource_length = resource_length;
  if (r->http.request_header.content_range_count == 1) {
    struct http_range closed;
    unsigned n = http_range_close(&closed, r->http.request_header.content_ranges, 1, resource_length);
    if (n == 0 || http_range_bytes(&closed, 1) == 0)
      return 416; // Request Range Not Satisfiable
    r->http.response.header.content_range_start = closed.first;
    r->http.response.header.content_length = closed.last - closed.first + 1;
  }else{
    r->http.response.header.content_range_start = 0;
    r->http.response.header.content_length = resource_length;
  }
  return 0;
}
