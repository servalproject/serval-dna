/*
Serval DNA Rhizome HTTP external interface
Copyright (C) 2013 Serval Project Inc.
 
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
# include <sys/filio.h>
#endif
#include <sys/uio.h>
#include <assert.h>

#include "serval.h"
#include "overlay_address.h"
#include "conf.h"
#include "str.h"
#include "strbuf_helpers.h"
#include "rhizome.h"
#include "http_server.h"

#define RHIZOME_SERVER_MAX_LIVE_REQUESTS 32

typedef int HTTP_HANDLER(rhizome_http_request *r, const char *remainder);

struct http_handler{
  const char *path;
  HTTP_HANDLER *parser;
};

static HTTP_HANDLER restful_rhizome_bundlelist_json;
static HTTP_HANDLER restful_rhizome_newsince;
static HTTP_HANDLER restful_rhizome_;

static HTTP_HANDLER rhizome_status_page;
static HTTP_HANDLER rhizome_file_page;
static HTTP_HANDLER manifest_by_prefix_page;
static HTTP_HANDLER interface_page;
static HTTP_HANDLER neighbour_page;
static HTTP_HANDLER fav_icon_header;
static HTTP_HANDLER root_page;

extern HTTP_HANDLER rhizome_direct_import;
extern HTTP_HANDLER rhizome_direct_enquiry;
extern HTTP_HANDLER rhizome_direct_dispatch;

struct http_handler paths[]={
  {"/restful/rhizome/bundlelist.json", restful_rhizome_bundlelist_json},
  {"/restful/rhizome/newsince/", restful_rhizome_newsince},
  {"/restful/rhizome/", restful_rhizome_},
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
      int result = paths[i].parser(r, remainder);
      if (result == -1 || (result >= 200 && result < 600))
	return result;
      if (result == 1)
	return 0;
      if (result)
	return WHYF("dispatch function for %s returned invalid result %d", paths[i].path, result);
    }
  }
  return 404;
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
  rhizome_read_close(&r->u.read_state);
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
      rhizome_http_request *request = emalloc_zero(sizeof(rhizome_http_request));
      if (request == NULL) {
	WHY("Cannot respond to HTTP request, out of memory");
	close(sock);
      } else {
	request_count++;
	request->uuid = rhizome_http_request_uuid_counter++;
	request->data_file_name[0] = '\0';
	request->u.read_state.blob_fd = -1;
	request->u.read_state.blob_rowid = 0;
	if (peerip)
	  request->http.client_sockaddr_in = *peerip;
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

static int is_from_loopback(const struct http_request *r)
{
  return   r->client_sockaddr_in.sin_family == AF_INET
	&& ((unsigned char*)&r->client_sockaddr_in.sin_addr.s_addr)[0] == IN_LOOPBACKNET;
}

/* Return 1 if the given authorization credentials are acceptable.
 * Return 0 if not.
 */
static int is_authorized(const struct http_client_authorization *auth)
{
  if (auth->scheme != BASIC)
    return 0;
  unsigned i;
  for (i = 0; i != config.rhizome.api.restful.users.ac; ++i) {
    if (   strcmp(config.rhizome.api.restful.users.av[i].key, auth->credentials.basic.user) == 0
	&& strcmp(config.rhizome.api.restful.users.av[i].value.password, auth->credentials.basic.password) == 0
    )
      return 1;
  }
  return 0;
}

static int authorize(struct http_request *r)
{
  if (!is_from_loopback(r))
    return 403;
  if (!is_authorized(&r->request_header.authorization)) {
    r->response.header.www_authenticate.scheme = BASIC;
    r->response.header.www_authenticate.realm = "Serval Rhizome";
    return 401;
  }
  return 0;
}

#define LIST_TOKEN_STRLEN (BASE64_ENCODED_LEN(sizeof(uuid_t) + 8))
#define alloca_list_token(rowid) list_token_to_str(alloca(LIST_TOKEN_STRLEN + 1), (rowid))

static char *list_token_to_str(char *buf, uint64_t rowid)
{
  struct iovec iov[2];
  iov[0].iov_base = rhizome_db_uuid.u.binary;
  iov[0].iov_len = sizeof rhizome_db_uuid.u.binary;
  iov[1].iov_base = &rowid;
  iov[1].iov_len = sizeof rowid;
  size_t n = base64url_encodev(buf, iov, 2);
  assert(n == LIST_TOKEN_STRLEN);
  buf[n] = '\0';
  return buf;
}

static int strn_to_list_token(const char *str, uint64_t *rowidp, const char **afterp)
{
  unsigned char token[sizeof rhizome_db_uuid.u.binary + sizeof *rowidp];
  if (base64url_decode(token, sizeof token, str, 0, afterp, 0, NULL) != sizeof token)
    return 0;
  if (cmp_uuid_t(&rhizome_db_uuid, (uuid_t *) &token) != 0)
    return 0;
  memcpy(rowidp, token + sizeof rhizome_db_uuid.u.binary, sizeof *rowidp);
  return 1;
}

static HTTP_CONTENT_GENERATOR restful_rhizome_bundlelist_json_content;

static int restful_rhizome_bundlelist_json(rhizome_http_request *r, const char *remainder)
{
  if (!is_rhizome_http_enabled())
    return 403;
  if (*remainder)
    return 404;
  if (r->http.verb != HTTP_VERB_GET)
    return 405;
  int ret = authorize(&r->http);
  if (ret)
    return ret;
  r->u.list.phase = LIST_HEADER;
  r->u.list.rowcount = 0;
  bzero(&r->u.list.cursor, sizeof r->u.list.cursor);
  http_request_response_generated(&r->http, 200, "application/json", restful_rhizome_bundlelist_json_content);
  return 1;
}

static int restful_rhizome_newsince(rhizome_http_request *r, const char *remainder)
{
  if (!is_rhizome_http_enabled())
    return 403;
  uint64_t rowid;
  const char *end = NULL;
  if (!strn_to_list_token(remainder, &rowid, &end) || strcmp(end, "/bundlelist.json") != 0)
    return 404;
  if (r->http.verb != HTTP_VERB_GET)
    return 405;
  int ret = authorize(&r->http);
  if (ret)
    return ret;
  r->u.list.phase = LIST_HEADER;
  r->u.list.rowcount = 0;
  bzero(&r->u.list.cursor, sizeof r->u.list.cursor);
  r->u.list.cursor.rowid_since = rowid;
  r->u.list.end_time = gettime_ms() + config.rhizome.api.restful.newsince_timeout * 1000;
  http_request_response_generated(&r->http, 200, "application/json", restful_rhizome_bundlelist_json_content);
  return 1;
}

static int restful_rhizome_bundlelist_json_content_chunk(sqlite_retry_state *retry, struct rhizome_http_request *r, strbuf b)
{
  const char *headers[] = {
    ".token",
    "_id",
    "service",
    "id",
    "version",
    "date",
    ".inserttime",
    ".author",
    ".fromhere",
    "filesize",
    "filehash",
    "sender",
    "recipient",
    "name"
  };
  switch (r->u.list.phase) {
    case LIST_HEADER:
      strbuf_puts(b, "{\n\"header\":[");
      unsigned i;
      for (i = 0; i != NELS(headers); ++i) {
	if (i)
	  strbuf_putc(b, ',');
	strbuf_json_string(b, headers[i]);
      }
      strbuf_puts(b, "],\n\"rows\":[");
      if (!strbuf_overrun(b))
	r->u.list.phase = LIST_ROWS;
      return 1;
    case LIST_ROWS:
      {
	int ret = rhizome_list_next(retry, &r->u.list.cursor);
	if (ret == -1)
	  return -1;
	if (ret == 0) {
	  time_ms_t now;
	  if (r->u.list.cursor.rowid_since == 0 || (now = gettime_ms()) >= r->u.list.end_time) {
	    strbuf_puts(b, "\n]\n}\n");
	    if (!strbuf_overrun(b))
	      r->u.list.phase = LIST_DONE;
	    return 0;
	  }
	  time_ms_t wake_at = now + config.rhizome.api.restful.newsince_poll_ms;
	  if (wake_at > r->u.list.end_time)
	    wake_at = r->u.list.end_time;
	  http_request_pause_response(&r->http, wake_at);
	  return 0;
	}
	rhizome_manifest *m = r->u.list.cursor.manifest;
	assert(m->filesize != RHIZOME_SIZE_UNSET);
	rhizome_lookup_author(m);
	if (r->u.list.rowcount != 0)
	  strbuf_putc(b, ',');
	strbuf_puts(b, "\n[");
	if (m->rowid > r->u.list.rowid_highest) {
	  strbuf_json_string(b, alloca_list_token(m->rowid));
	  r->u.list.rowid_highest = m->rowid;
	} else
	  strbuf_json_null(b);
	strbuf_putc(b, ',');
	strbuf_sprintf(b, "%"PRIu64, m->rowid);
	strbuf_putc(b, ',');
	strbuf_json_string(b, m->service);
	strbuf_putc(b, ',');
	strbuf_json_hex(b, m->cryptoSignPublic.binary, sizeof m->cryptoSignPublic.binary);
	strbuf_putc(b, ',');
	strbuf_sprintf(b, "%"PRIu64, m->version);
	strbuf_putc(b, ',');
	if (m->has_date)
	  strbuf_sprintf(b, "%"PRItime_ms_t, m->date);
	else
	  strbuf_json_null(b);
	strbuf_putc(b, ',');
	strbuf_sprintf(b, "%"PRItime_ms_t",", m->inserttime);
	switch (m->authorship) {
	  case AUTHOR_LOCAL:
	  case AUTHOR_AUTHENTIC:
	    strbuf_json_hex(b, m->author.binary, sizeof m->author.binary);
	    strbuf_puts(b, ",1,");
	    break;
	  default:
	    strbuf_json_null(b);
	    strbuf_puts(b, ",1,");
	    break;
	}
	strbuf_sprintf(b, "%"PRIu64, m->filesize);
	strbuf_putc(b, ',');
	strbuf_json_hex(b, m->filesize ? m->filehash.binary : NULL, sizeof m->filehash.binary);
	strbuf_putc(b, ',');
	strbuf_json_hex(b, m->has_sender ? m->sender.binary : NULL, sizeof m->sender.binary);
	strbuf_putc(b, ',');
	strbuf_json_hex(b, m->has_recipient ? m->recipient.binary : NULL, sizeof m->recipient.binary);
	strbuf_putc(b, ',');
	strbuf_json_string(b, m->name);
	strbuf_puts(b, "]");
	if (!strbuf_overrun(b)) {
	  rhizome_list_commit(&r->u.list.cursor);
	  ++r->u.list.rowcount;
	}
	return 1;
      }
    case LIST_DONE:
      return 0;
  }
  abort();
}

static int restful_rhizome_bundlelist_json_content(struct http_request *hr, unsigned char *buf, size_t bufsz, struct http_content_generator_result *result)
{
  rhizome_http_request *r = (rhizome_http_request *) hr;
  assert(bufsz > 0);
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  int ret = rhizome_list_open(&retry, &r->u.list.cursor);
  if (ret == -1)
    return -1;
  strbuf b = strbuf_local((char *)buf, bufsz);
  while ((ret = restful_rhizome_bundlelist_json_content_chunk(&retry, r, b)) != -1) {
    if (strbuf_overrun(b)) {
      if (config.debug.rhizome)
	DEBUGF("overrun by %zu bytes", strbuf_count(b) - strbuf_len(b));
      result->need = strbuf_count(b) + 1 - result->generated;
      break;
    }
    result->generated = strbuf_len(b);
    if (ret == 0)
      break;
  }
  rhizome_list_release(&r->u.list.cursor);
  return ret;
}

static int rhizome_response_content_init_filehash(rhizome_http_request *r, const rhizome_filehash_t *hash);
static int rhizome_response_content_init_payload(rhizome_http_request *r, rhizome_manifest *);

static HTTP_CONTENT_GENERATOR rhizome_payload_content;

static HTTP_RENDERER render_manifest_headers;

static HTTP_HANDLER restful_rhizome_bid_rhm;
static HTTP_HANDLER restful_rhizome_bid_raw_bin;
static HTTP_HANDLER restful_rhizome_bid_decrypted_bin;

static int restful_rhizome_(rhizome_http_request *r, const char *remainder)
{
  if (!is_rhizome_http_enabled())
    return 403;
  HTTP_HANDLER *handler = NULL;
  rhizome_bid_t bid;
  const char *end;
  if (strn_to_rhizome_bid_t(&bid, remainder, &end) != -1) {
    if (strcmp(end, ".rhm") == 0) {
      handler = restful_rhizome_bid_rhm;
      remainder = "";
    } else if (strcmp(end, "/raw.bin") == 0) {
      handler = restful_rhizome_bid_raw_bin;
      remainder = "";
    } else if (strcmp(end, "/decrypted.bin") == 0) {
      handler = restful_rhizome_bid_decrypted_bin;
      remainder = "";
    }
  }
  if (handler == NULL)
    return 404;
  if (r->http.verb != HTTP_VERB_GET)
    return 405;
  int ret = authorize(&r->http);
  if (ret)
    return ret;
  rhizome_manifest *m = rhizome_new_manifest();
  ret = rhizome_retrieve_manifest(&bid, m);
  if (ret == -1) {
    rhizome_manifest_free(m);
    return 500;
  }
  if (ret == 0) {
    rhizome_authenticate_author(m);
    r->manifest = m;
    r->http.render_extra_headers = render_manifest_headers;
  } else {
    assert(r->manifest == NULL);
    assert(r->http.render_extra_headers == NULL);
  }
  ret = handler(r, remainder);
  rhizome_manifest_free(m);
  return ret;
}

static int restful_rhizome_bid_rhm(rhizome_http_request *r, const char *remainder)
{
  if (*remainder || r->manifest == NULL)
    return 404;
  http_request_response_static(&r->http, 200, "x-servalproject/rhizome-manifest-text",
      (const char *)r->manifest->manifestdata, r->manifest->manifest_all_bytes
    );
  return 1;
}

static int restful_rhizome_bid_raw_bin(rhizome_http_request *r, const char *remainder)
{
  if (*remainder || r->manifest == NULL)
    return 404;
  if (r->manifest->filesize == 0) {
    http_request_response_static(&r->http, 200, "application/binary", "", 0);
    return 1;
  }
  int ret = rhizome_response_content_init_filehash(r, &r->manifest->filehash);
  if (ret)
    return ret;
  http_request_response_generated(&r->http, 200, "application/binary", rhizome_payload_content);
  return 1;
}

static int restful_rhizome_bid_decrypted_bin(rhizome_http_request *r, const char *remainder)
{
  if (*remainder || r->manifest == NULL)
    return 404;
  if (r->manifest->filesize == 0) {
    // TODO use Content Type from manifest (once it is implemented)
    http_request_response_static(&r->http, 200, "application/binary", "", 0);
    return 1;
  }
  int ret = rhizome_response_content_init_payload(r, r->manifest);
  if (ret)
    return ret;
  // TODO use Content Type from manifest (once it is implemented)
  http_request_response_generated(&r->http, 200, "application/binary", rhizome_payload_content);
  return 1;
}

static int neighbour_page(rhizome_http_request *r, const char *remainder)
{
  if (r->http.verb != HTTP_VERB_GET)
    return 405;
  char buf[8*1024];
  strbuf b = strbuf_local(buf, sizeof buf);
  sid_t neighbour_sid;
  if (str_to_sid_t(&neighbour_sid, remainder) == -1)
    return 404;
  struct subscriber *neighbour = find_subscriber(neighbour_sid.binary, sizeof(neighbour_sid.binary), 0);
  if (!neighbour)
    return 404;
  strbuf_puts(b, "<html><head><meta http-equiv=\"refresh\" content=\"5\" ></head><body>");
  link_neighbour_status_html(b, neighbour);
  strbuf_puts(b, "</body></html>");
  if (strbuf_overrun(b))
    return -1;
  http_request_response_static(&r->http, 200, "text/html", buf, strbuf_len(b));
  return 1;
}

static int interface_page(rhizome_http_request *r, const char *remainder)
{
  if (r->http.verb != HTTP_VERB_GET)
    return 405;
  char buf[8*1024];
  strbuf b=strbuf_local(buf, sizeof buf);
  int index=atoi(remainder);
  if (index<0 || index>=OVERLAY_MAX_INTERFACES)
    return 404;
  strbuf_puts(b, "<html><head><meta http-equiv=\"refresh\" content=\"5\" ></head><body>");
  interface_state_html(b, &overlay_interfaces[index]);
  strbuf_puts(b, "</body></html>");
  if (strbuf_overrun(b))
    return -1;
  http_request_response_static(&r->http, 200, "text/html", buf, strbuf_len(b));
  return 1;
}

static int rhizome_status_page(rhizome_http_request *r, const char *remainder)
{
  if (!is_rhizome_http_enabled())
    return 403;
  if (*remainder)
    return 404;
  if (r->http.verb != HTTP_VERB_GET)
    return 405;
  char buf[32*1024];
  strbuf b = strbuf_local(buf, sizeof buf);
  strbuf_puts(b, "<html><head><meta http-equiv=\"refresh\" content=\"5\" ></head><body>");
  strbuf_sprintf(b, "%d HTTP requests<br>", request_count);
  strbuf_sprintf(b, "%d Bundles transferring via MDP<br>", rhizome_cache_count());
  rhizome_fetch_status_html(b);
  strbuf_puts(b, "</body></html>");
  if (strbuf_overrun(b))
    return -1;
  http_request_response_static(&r->http, 200, "text/html", buf, strbuf_len(b));
  return 1;
}

static int rhizome_response_content_init_read_state(rhizome_http_request *r)
{
  if (r->u.read_state.length == RHIZOME_SIZE_UNSET && rhizome_read(&r->u.read_state, NULL, 0)) {
    rhizome_read_close(&r->u.read_state);
    return 404;
  }
  assert(r->u.read_state.length != RHIZOME_SIZE_UNSET);
  r->http.response.header.resource_length = r->u.read_state.length;
  if (r->http.request_header.content_range_count > 0) {
    assert(r->http.request_header.content_range_count == 1);
    struct http_range closed;
    unsigned n = http_range_close(&closed, r->http.request_header.content_ranges, 1, r->u.read_state.length);
    if (n == 0 || http_range_bytes(&closed, 1) == 0)
      return 416; // Request Range Not Satisfiable
    r->http.response.header.content_range_start = closed.first;
    r->http.response.header.content_length = closed.last - closed.first + 1;
    r->u.read_state.offset = closed.first;
  } else {
    r->http.response.header.content_range_start = 0;
    r->http.response.header.content_length = r->http.response.header.resource_length;
    r->u.read_state.offset = 0;
  }
  return 0;
}

static int rhizome_response_content_init_filehash(rhizome_http_request *r, const rhizome_filehash_t *hash)
{
  bzero(&r->u.read_state, sizeof r->u.read_state);
  int n = rhizome_open_read(&r->u.read_state, hash);
  if (n == -1)
    return -1;
  if (n != 0)
    return 404;
  return rhizome_response_content_init_read_state(r);
}

static int rhizome_response_content_init_payload(rhizome_http_request *r, rhizome_manifest *m)
{
  bzero(&r->u.read_state, sizeof r->u.read_state);
  int n = rhizome_open_decrypt_read(m, &r->u.read_state);
  if (n == -1)
    return -1;
  if (n != 0)
    return 404;
  return rhizome_response_content_init_read_state(r);
}

static int rhizome_payload_content(struct http_request *hr, unsigned char *buf, size_t bufsz, struct http_content_generator_result *result)
{
  // Only read multiples of 4k from disk.
  const size_t blocksz = 1 << 12;
  // Ask for a large buffer for all future reads.
  const size_t preferred_bufsz = 16 * blocksz;
  // Reads the next part of the payload into the supplied buffer.
  rhizome_http_request *r = (rhizome_http_request *) hr;
  assert(r->u.read_state.length != RHIZOME_SIZE_UNSET);
  assert(r->u.read_state.offset < r->u.read_state.length);
  uint64_t remain = r->u.read_state.length - r->u.read_state.offset;
  size_t readlen = bufsz;
  if (remain < bufsz)
    readlen = remain;
  else
    readlen &= ~(blocksz - 1);
  if (readlen > 0) {
    ssize_t n = rhizome_read(&r->u.read_state, buf, readlen);
    if (n == -1)
      return -1;
    result->generated = (size_t) n;
  }
  assert(r->u.read_state.offset <= r->u.read_state.length);
  remain = r->u.read_state.length - r->u.read_state.offset;
  result->need = remain < preferred_bufsz ? remain : preferred_bufsz;
  return remain ? 1 : 0;
}

static int rhizome_file_page(rhizome_http_request *r, const char *remainder)
{
  /* Stream the specified payload */
  if (!is_rhizome_http_enabled())
    return 403;
  if (r->http.verb != HTTP_VERB_GET)
    return 405;
  if (r->http.request_header.content_range_count > 1) {
    // To support byte range sets, eg, Range: bytes=0-100,200-300,400- we would have
    // to reply with a multipart/byteranges MIME content.
    http_request_simple_response(&r->http, 501, "Not Implemented: Byte range sets");
    return 1;
  }
  rhizome_filehash_t filehash;
  if (str_to_rhizome_filehash_t(&filehash, remainder) == -1)
    return 1;
  int ret = rhizome_response_content_init_filehash(r, &filehash);
  if (ret)
    return ret;
  http_request_response_generated(&r->http, 200, "application/binary", rhizome_payload_content);
  return 1;
}

static int manifest_by_prefix_page(rhizome_http_request *r, const char *remainder)
{
  if (!is_rhizome_http_enabled())
    return 403;
  if (r->http.verb != HTTP_VERB_GET)
    return 405;
  rhizome_bid_t prefix;
  const char *endp = NULL;
  unsigned prefix_len = strn_fromhex(prefix.binary, sizeof prefix.binary, remainder, &endp);
  if (endp == NULL || *endp != '\0' || prefix_len < 1)
    return 404; // not found
  rhizome_manifest *m = rhizome_new_manifest();
  int ret = rhizome_retrieve_manifest_by_prefix(prefix.binary, prefix_len, m);
  if (ret == -1)
    return 500;
  if (ret == 0) {
    http_request_response_static(&r->http, 200, "application/binary", (const char *)m->manifestdata, m->manifest_all_bytes);
    rhizome_manifest_free(m);
    return 1;
  }
  rhizome_manifest_free(m);
  return 404;
}

static int fav_icon_header(rhizome_http_request *r, const char *remainder)
{
  if (*remainder)
    return 404;
  http_request_response_static(&r->http, 200, "image/vnd.microsoft.icon", (const char *)favicon_bytes, favicon_len);
  return 1;
}

static void render_manifest_headers(struct http_request *hr, strbuf sb)
{
  rhizome_http_request *r = (rhizome_http_request *) hr;
  rhizome_manifest *m = r->manifest;
  strbuf_sprintf(sb, "Serval-Rhizome-Bundle-Id: %s\r\n", alloca_tohex_rhizome_bid_t(m->cryptoSignPublic));
  strbuf_sprintf(sb, "Serval-Rhizome-Bundle-Version: %"PRIu64"\r\n", m->version);
  strbuf_sprintf(sb, "Serval-Rhizome-Bundle-Filesize: %"PRIu64"\r\n", m->filesize);
  if (m->filesize != 0)
    strbuf_sprintf(sb, "Serval-Rhizome-Bundle-Filehash: %s\r\n", alloca_tohex_rhizome_filehash_t(m->filehash));
  if (m->has_bundle_key)
    strbuf_sprintf(sb, "Serval-Rhizome-Bundle-BK: %s\r\n", alloca_tohex_rhizome_bk_t(m->bundle_key));
  if (m->has_date)
    strbuf_sprintf(sb, "Serval-Rhizome-Bundle-Date: %"PRIu64"\r\n", m->date);
  if (m->name) {
    strbuf_puts(sb, "Serval-Rhizome-Bundle-Name: ");
    strbuf_append_quoted_string(sb, m->name);
    strbuf_puts(sb, "\r\n");
  }
  if (m->service)
    strbuf_sprintf(sb, "Serval-Rhizome-Bundle-Service: %s\r\n", m->service);
  assert(m->authorship != AUTHOR_LOCAL);
  if (m->authorship == AUTHOR_AUTHENTIC)
    strbuf_sprintf(sb, "Serval-Rhizome-Bundle-Author: %s\r\n", alloca_tohex_sid_t(m->author));
  assert(m->haveSecret);
  {
    char secret[RHIZOME_BUNDLE_KEY_STRLEN + 1];
    rhizome_bytes_to_hex_upper(m->cryptoSignSecret, secret, RHIZOME_BUNDLE_KEY_BYTES);
    strbuf_sprintf(sb, "Serval-Rhizome-Bundle-Secret: %s\r\n", secret);
  }
  strbuf_sprintf(sb, "Serval-Rhizome-Bundle-Rowid: %"PRIu64"\r\n", m->rowid);
  strbuf_sprintf(sb, "Serval-Rhizome-Bundle-Inserttime: %"PRIu64"\r\n", m->inserttime);
}

static int root_page(rhizome_http_request *r, const char *remainder)
{
  if (*remainder)
    return 404;
  if (r->http.verb != HTTP_VERB_GET)
    return 405;
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
    return 500;
  }
  http_request_response_static(&r->http, 200, "text/html", temp, strbuf_len(b));
  return 1;
}
