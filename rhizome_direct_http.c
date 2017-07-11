/*
Serval Mesh Software
Copyright (C) 2010-2012 Paul Gardner-Stephen

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

#include <assert.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#include "serval.h"
#include "rhizome.h"
#include "httpd.h"
#include "conf.h"
#include "str.h"
#include "strbuf.h"
#include "strbuf_helpers.h"
#include "socket.h"

DEFINE_FEATURE(http_rhizome_direct);

DECLARE_HANDLER("/rhizome/import", rhizome_direct_import);
DECLARE_HANDLER("/rhizome/enquiry", rhizome_direct_enquiry);
DECLARE_HANDLER("/rhizome/", rhizome_direct_dispatch);

static char PART_MANIFEST[] = "manifest";
static char PART_PAYLOAD[] = "payload";
// TODO: "data" is deprecated in favour of "payload" to match the restful API
static char PART_DATA[] = "data";

static int _form_temporary_file_path(struct __sourceloc __whence, httpd_request *r, char *pathbuf, size_t bufsiz, const char *field)
{
  // TODO: use a temporary directory
  return formf_serval_tmp_path(pathbuf, bufsiz,
			       "rhizomedirect.%d.%s", r->http.alarm.poll.fd, field);
}

#define form_temporary_file_path(r,buf,field) _form_temporary_file_path(__WHENCE__, (r), (buf), sizeof(buf), (field))

static void rhizome_direct_clear_temporary_files(httpd_request *r)
{
  const char *fields[] = { PART_MANIFEST, PART_PAYLOAD };
  int i;
  for (i = 0; i != NELS(fields); ++i) {
    char path[1024];
    if (form_temporary_file_path(r, path, fields[i]) != -1)
      if (unlink(path) == -1 && errno != ENOENT)
	WARNF_perror("unlink(%s)", alloca_str_toprint(path));
  }
}

static void http_request_rhizome_bundle_status_response(httpd_request *r, struct rhizome_bundle_result result, rhizome_manifest *m)
{
  int http_status = 500;
  switch (result.status) {
  case RHIZOME_BUNDLE_STATUS_NEW:
    http_status = 201; // Created
    break;
  case RHIZOME_BUNDLE_STATUS_DUPLICATE:
  case RHIZOME_BUNDLE_STATUS_SAME:
    http_status = 200; // OK
    break;
  case RHIZOME_BUNDLE_STATUS_OLD:
  case RHIZOME_BUNDLE_STATUS_NO_ROOM:
    http_status = 202; // Accepted
    break;
  case RHIZOME_BUNDLE_STATUS_INVALID:
  case RHIZOME_BUNDLE_STATUS_INCONSISTENT:
  case RHIZOME_BUNDLE_STATUS_MANIFEST_TOO_BIG:
    http_status = 422; // Unprocessable Entity
    break;
  case RHIZOME_BUNDLE_STATUS_BUSY:
    http_status = 423; // Locked
    break;
  case RHIZOME_BUNDLE_STATUS_READONLY:
  case RHIZOME_BUNDLE_STATUS_FAKE:
    http_status = 419; // Authentication Timeout
    break;
  case RHIZOME_BUNDLE_STATUS_ERROR:
    break;
  }
  if (m)
    http_request_response_static(&r->http, http_status, CONTENT_TYPE_TEXT, (const char *)m->manifestdata, m->manifest_all_bytes);
  else
    http_request_simple_response(&r->http, http_status, rhizome_bundle_result_message(result));
}

static int rhizome_direct_import_end(struct http_request *hr)
{
  httpd_request *r = (httpd_request *) hr;
  if (!r->u.direct_import.received_manifest) {
    http_request_simple_response(&r->http, 400, "Missing 'manifest' part");
    return 0;
  }
  if (!r->u.direct_import.received_data) {
    http_request_simple_response(&r->http, 400, "Missing 'data' part");
    return 0;
  }
  /* Got a bundle to import */
  char manifest_path[512];
  char payload_path[512];
  if (   form_temporary_file_path(r, manifest_path, PART_MANIFEST) == -1
      || form_temporary_file_path(r, payload_path, PART_PAYLOAD) == -1
  ) {
    http_request_simple_response(&r->http, 500, "Internal Error: Buffer overrun");
    return 0;
  }
  DEBUGF(rhizome, "Call rhizome_bundle_import_files(%s, %s)",
	 alloca_str_toprint(manifest_path),
	 alloca_str_toprint(payload_path)
        );
  rhizome_manifest *m = rhizome_new_manifest();
  if (!m) {
    http_request_simple_response(&r->http, 429, "Manifest table full"); // Too Many Requests
    return 0;
  }
  struct rhizome_bundle_result result = INVALID_RHIZOME_BUNDLE_RESULT;
  result.status = rhizome_bundle_import_files(m, NULL, manifest_path, payload_path, 0);
  rhizome_manifest_free(m);
  rhizome_direct_clear_temporary_files(r);
  http_request_rhizome_bundle_status_response(r, result, NULL);
  rhizome_bundle_result_free(&result);
  return 0;
}

int rhizome_direct_enquiry_end(struct http_request *hr)
{
  httpd_request *r = (httpd_request *) hr;
  if (!r->u.direct_import.received_data) {
    http_request_simple_response(&r->http, 400, "Missing 'data' part");
    return 0;
  }
  char data_path[512];
  if (form_temporary_file_path(r, data_path, PART_PAYLOAD) == -1) {
    http_request_simple_response(&r->http, 500, "Internal Error: Buffer overrun");
    return 0;
  }
  DEBUGF(rhizome, "Call rhizome_direct_fill_response(%s)", alloca_str_toprint(data_path));
  /* Read data buffer in, pass to rhizome direct for comparison with local
      rhizome database, and send back responses. */
  int fd = open(data_path, O_RDONLY);
  if (fd == -1) {
    WHYF_perror("open(%s, O_RDONLY)", alloca_str_toprint(data_path));
    /* Clean up after ourselves */
    rhizome_direct_clear_temporary_files(r);
    http_request_simple_response(&r->http, 500, "Internal Error: Couldn't read file");
    return 0;
  }
  struct stat stat;
  if (fstat(fd, &stat) == -1) {
    WHYF_perror("stat(%d)", fd);
    /* Clean up after ourselves */
    close(fd);
    rhizome_direct_clear_temporary_files(r);
    http_request_simple_response(&r->http, 500, "Internal Error: Couldn't stat file");
    return 0;
  }
  unsigned char *addr = mmap(NULL, stat.st_size, PROT_READ, MAP_SHARED, fd, 0);
  if (addr==MAP_FAILED) {
    WHYF_perror("mmap(NULL,%"PRId64",PROT_READ,MAP_SHARED,%d,0)", (int64_t) stat.st_size, fd);
    /* Clean up after ourselves */
    close(fd);
    rhizome_direct_clear_temporary_files(r);
    http_request_simple_response(&r->http, 500, "Internal Error: Couldn't mmap file");
    return 0;
  }
  /* Ask for a fill response.  Regardless of the size of the set of BARs passed
      to us, we will allow up to 64KB of response. */
  rhizome_direct_bundle_cursor *c = rhizome_direct_get_fill_response(addr, stat.st_size, 65536);
  munmap(addr,stat.st_size);
  close(fd);
  if (c) {
    size_t bytes = c->buffer_offset_bytes + c->buffer_used;
    if (http_request_set_response_bufsize(&r->http, bytes) == -1)
      http_request_simple_response(&r->http, 500, "Internal Error: Out of memory");
    else
      http_request_response_static(&r->http, 200, "binary/octet-stream", (const char *)c->buffer, bytes);
    rhizome_direct_bundle_iterator_free(&c);
  } else
    http_request_simple_response(&r->http, 500, "Internal Error: No response to enquiry");
  rhizome_direct_clear_temporary_files(r);
  return 0;
}

static int rhizome_direct_addfile_end(struct http_request *hr)
{
  httpd_request *r = (httpd_request *) hr;
  // If given a file without a manifest, we should only accept if it we are configured to do so, and
  // the connection is from localhost.  Otherwise people could cause your servald to create
  // arbitrary bundles, which would be bad.
  if (!r->u.direct_import.received_manifest) {
    char payload_path[512];
    if (form_temporary_file_path(r, payload_path, PART_PAYLOAD) == -1) {
      http_request_simple_response(&r->http, 500, "Internal Error: Buffer overrun");
      return 0;
    }
    DEBUGF(rhizome, "Call rhizome_store_payload_file(%s)", alloca_str_toprint(payload_path));
    char manifestTemplate[1024];
    manifestTemplate[0] = '\0';
    if (config.rhizome.api.addfile.manifest_template_file[0]) {
      if (!FORMF_SERVAL_ETC_PATH(manifestTemplate, "%s", config.rhizome.api.addfile.manifest_template_file)) {
	rhizome_direct_clear_temporary_files(r);
	http_request_simple_response(&r->http, 500, "Internal Error: Template path too long");
	return 0;
      }
      if (access(manifestTemplate, R_OK) != 0) {
	rhizome_direct_clear_temporary_files(r);
	http_request_simple_response(&r->http, 500, "Internal Error: Cannot read template");
	return 0;
      }
      DEBUGF(rhizome, "Using manifest template %s", alloca_str_toprint(manifestTemplate));
    }
    rhizome_manifest *m = rhizome_new_manifest();
    if (!m) {
      WHY("Manifest struct could not be allocated -- not added to rhizome");
      http_request_simple_response(&r->http, 500, "Internal Error: No free manifest slots");
      rhizome_direct_clear_temporary_files(r);
      return 0;
    }
    if (manifestTemplate[0] && rhizome_read_manifest_from_file(m, manifestTemplate) == -1) {
      WHY("Manifest template read failed");
      rhizome_manifest_free(m);
      rhizome_direct_clear_temporary_files(r);
      http_request_simple_response(&r->http, 500, "Internal Error: Malformed manifest template");
      return 0;
    }
    if (rhizome_stat_payload_file(m, payload_path) != RHIZOME_PAYLOAD_STATUS_NEW) {
      WHY("Payload file stat failed");
      rhizome_manifest_free(m);
      rhizome_direct_clear_temporary_files(r);
      http_request_simple_response(&r->http, 500, "Internal Error: Could not store file");
      return 0;
    }
    if (!rhizome_is_bk_none(&config.rhizome.api.addfile.bundle_secret_key))
      rhizome_apply_bundle_secret(m, &config.rhizome.api.addfile.bundle_secret_key);
    // If manifest template did not specify a service field, then by default it is "file".
    if (m->service == NULL)
      rhizome_manifest_set_service(m, RHIZOME_SERVICE_FILE);
    if (!is_sid_t_any(config.rhizome.api.addfile.default_author))
      rhizome_manifest_set_author(m, &config.rhizome.api.addfile.default_author);
    struct rhizome_bundle_result result = rhizome_fill_manifest(m, r->u.direct_import.data_file_name);
    rhizome_manifest *mout = NULL;
    if (result.status == RHIZOME_BUNDLE_STATUS_NEW) {
      rhizome_bundle_result_free(&result);
      rhizome_manifest_set_crypt(m, PAYLOAD_CLEAR);
      // import file contents
      // TODO, stream file into database
      assert(m->filesize != RHIZOME_SIZE_UNSET);
      if (m->filesize == 0 || rhizome_store_payload_file(m, payload_path) == RHIZOME_PAYLOAD_STATUS_NEW) {
	result = rhizome_manifest_finalise(m, &mout, 1);
	if (mout)
	  DEBUGF(rhizome, "Import sans-manifest appeared to succeed");
      }
    }
    /* Respond with the manifest that was added. */
    http_request_rhizome_bundle_status_response(r, result, mout);
    /* Clean up after ourselves. */
    rhizome_bundle_result_free(&result);
    rhizome_direct_clear_temporary_files(r);
    if (mout && mout != m)
      rhizome_manifest_free(mout);
    rhizome_manifest_free(m);
    return 0;
  } else {
    http_request_simple_response(&r->http, 501, "Not Implemented: Rhizome add with manifest");
    return 0;
  }
}

static int rhizome_direct_process_mime_start(struct http_request *hr)
{
  httpd_request *r = (httpd_request *) hr;
  assert(r->u.direct_import.current_part == NULL);
  assert(r->u.direct_import.part_fd == -1);
  return 0;
}

static int rhizome_direct_process_mime_end(struct http_request *hr)
{
  httpd_request *r = (httpd_request *) hr;
  if (r->u.direct_import.part_fd != -1) {
    if (close(r->u.direct_import.part_fd) == -1) {
      WHYF_perror("close(%d)", r->u.direct_import.part_fd);
      http_request_simple_response(&r->http, 500, "Internal Error: Close temporary file failed");
      return 500;
    }
    r->u.direct_import.part_fd = -1;
  }
  if (r->u.direct_import.current_part == PART_MANIFEST)
    r->u.direct_import.received_manifest = 1;
  else if (   r->u.direct_import.current_part == PART_DATA
	   || r->u.direct_import.current_part == PART_PAYLOAD)
    r->u.direct_import.received_data = 1;
  r->u.direct_import.current_part = NULL;
  return 0;
}

static int rhizome_direct_process_mime_part_header(struct http_request *hr, const struct mime_part_headers *h)
{
  httpd_request *r = (httpd_request *) hr;
  if (!h->content_disposition.type[0])
    return http_response_content_disposition(r, 415, "Missing", h->content_disposition.type);
  if (strcmp(h->content_disposition.type, "form-data") != 0)
    return http_response_content_disposition(r, 415, "Unsupported", h->content_disposition.type);
  if (   strcmp(h->content_disposition.name, PART_PAYLOAD) == 0
      || strcmp(h->content_disposition.name, PART_DATA) == 0
  ) {
    r->u.direct_import.current_part = PART_PAYLOAD;
    strncpy(r->u.direct_import.data_file_name,
	    h->content_disposition.filename,
	    sizeof r->u.direct_import.data_file_name)
     [sizeof r->u.direct_import.data_file_name - 1] = '\0';
  }
  else if (strcmp(h->content_disposition.name, PART_MANIFEST) == 0) {
    r->u.direct_import.current_part = PART_MANIFEST;
  } else
    return 0;
  char path[512];
  if (form_temporary_file_path(r, path, r->u.direct_import.current_part) == -1) {
    http_request_simple_response(&r->http, 500, "Internal Error: Buffer overrun");
    return 0;
  }
  if ((r->u.direct_import.part_fd = open(path, O_WRONLY | O_CREAT, 0666)) == -1) {
    WHYF_perror("open(%s,O_WRONLY|O_CREAT,0666)", alloca_str_toprint(path));
    http_request_simple_response(&r->http, 500, "Internal Error: Create temporary file failed");
    return 0;
  }
  return 0;
}

static int rhizome_direct_process_mime_body(struct http_request *hr, char *buf, size_t len)
{
  httpd_request *r = (httpd_request *) hr;
  if (r->u.direct_import.part_fd != -1) {
    if (write_all(r->u.direct_import.part_fd, buf, len) == -1) {
      http_request_simple_response(&r->http, 500, "Internal Error: Write temporary file failed");
      return 500;
    }
  }
  return 0;
}

static int rhizome_direct_import(httpd_request *r, const char *remainder)
{
  if (*remainder)
    return 404;
  if (r->http.verb != HTTP_VERB_POST)
    return 405;
  r->http.form_data.handle_mime_part_start = rhizome_direct_process_mime_start;
  r->http.form_data.handle_mime_part_end = rhizome_direct_process_mime_end;
  r->http.form_data.handle_mime_part_header = rhizome_direct_process_mime_part_header;
  r->http.form_data.handle_mime_body = rhizome_direct_process_mime_body;
  r->http.handle_content_end = rhizome_direct_import_end;
  r->u.direct_import.current_part = NULL;
  r->u.direct_import.part_fd = -1;
  r->u.direct_import.data_file_name[0] = '\0';
  return 1;
}

static int rhizome_direct_enquiry(httpd_request *r, const char *remainder)
{
  if (*remainder)
    return 404;
  if (r->http.verb != HTTP_VERB_POST)
    return 405;
  // backwards compatibility, rhizome_fetch used to allow HTTP/1.0 responses only
  r->http.response.header.minor_version=0;
  r->http.form_data.handle_mime_part_start = rhizome_direct_process_mime_start;
  r->http.form_data.handle_mime_part_end = rhizome_direct_process_mime_end;
  r->http.form_data.handle_mime_part_header = rhizome_direct_process_mime_part_header;
  r->http.form_data.handle_mime_body = rhizome_direct_process_mime_body;
  r->http.handle_content_end = rhizome_direct_enquiry_end;
  r->u.direct_import.current_part = NULL;
  r->u.direct_import.part_fd = -1;
  r->u.direct_import.data_file_name[0] = '\0';
  return 1;
}

/* Servald can be configured to accept files without manifests via HTTP from localhost, so that
 * rhizome bundles can be created programatically.  There are probably still some security
 * loop-holes here, which is part of why we leave it disabled by default, but it will be sufficient
 * for testing possible uses, including integration with OpenDataKit.
 */
int rhizome_direct_addfile(httpd_request *r, const char *remainder)
{
  if (*remainder)
    return 404;
  if (r->http.verb != HTTP_VERB_POST)
    return 405;
  if (   r->http.client_addr.addr.sa_family != AF_INET
      || r->http.client_addr.inet.sin_addr.s_addr != config.rhizome.api.addfile.allow_host.s_addr
  ) {
    INFOF("rhizome.api.addfile request received from %s, but is only allowed from AF_INET %s",
	alloca_socket_address(&r->http.client_addr),
	alloca_in_addr(&config.rhizome.api.addfile.allow_host)
      );
    rhizome_direct_clear_temporary_files(r);
    return 403; // Forbidden
  }
  r->http.form_data.handle_mime_part_start = rhizome_direct_process_mime_start;
  r->http.form_data.handle_mime_part_end = rhizome_direct_process_mime_end;
  r->http.form_data.handle_mime_part_header = rhizome_direct_process_mime_part_header;
  r->http.form_data.handle_mime_body = rhizome_direct_process_mime_body;
  r->http.handle_content_end = rhizome_direct_addfile_end;
  r->u.direct_import.current_part = NULL;
  r->u.direct_import.part_fd = -1;
  r->u.direct_import.data_file_name[0] = '\0';
  return 1;
}

static int rhizome_direct_dispatch(httpd_request *r, const char *UNUSED(remainder))
{
  if (   config.rhizome.api.addfile.uri_path[0]
      && strcmp(r->http.path, config.rhizome.api.addfile.uri_path) == 0
  )
    return rhizome_direct_addfile(r, "");
  return 404;
}

static int receive_http_response(int sock, char *buffer, size_t buffer_len, struct http_response_parts *parts)
{
  size_t len = 0;
  ssize_t count;
  do {
      if ((count = read(sock, &buffer[len], buffer_len - len)) == -1)
	return WHYF_perror("read(%d, %p, %d)", sock, &buffer[len], (int)(buffer_len - len));
      len += (size_t)count;
  } while (len < buffer_len && count != 0 && !is_http_header_complete(buffer, len, len));
  DEBUGF(rhizome_rx, "Received HTTP response %s", alloca_toprint(-1, buffer, len));
  if (unpack_http_response(buffer, parts) == -1)
    return -1;
  if (parts->code != 200 && parts->code != 201) {
    INFOF("Failed HTTP request: server returned %03u %s", parts->code, parts->reason);
    return -1;
  }
  if (parts->content_length == HTTP_RESPONSE_CONTENT_LENGTH_UNSET) {
    DEBUGF(rhizome_rx, "Invalid HTTP reply: missing Content-Length header");
    return -1;
  }
  DEBUGF(rhizome_rx, "content_length=%"PRIu64, parts->content_length);
  return len - (parts->content_start - buffer);
}

static int fill_buffer(int sock, unsigned char *buffer, int len, int buffer_size){
  int count;
  do {
    if ((count = read(sock, &buffer[len], buffer_size - len)) == -1)
      return WHYF_perror("read(%d, %p, %d)", sock, &buffer[len], buffer_size - len);
    len += count;
  } while (len < buffer_size);
  return 0;
}

static rhizome_manifest *rhizome_direct_get_manifest(unsigned char *bid_prefix, size_t prefix_length);

void rhizome_direct_http_dispatch(rhizome_direct_sync_request *r)
{
  DEBUGF(rhizome_tx, "Dispatch size_high=%"PRId64,r->cursor->size_high);
  rhizome_direct_transport_state_http *state = r->transport_specific_state;

  struct socket_address addr;
  bzero(&addr,sizeof(addr));

  if (socket_resolve_name(AF_INET, state->host, NULL, &addr)==-1){
    DEBUGF(rhizome_tx, "could not resolve hostname");
    goto end;
  }
  addr.inet.sin_port=htons(state->port);

  int sock=socket(addr.addr.sa_family, SOCK_STREAM, 0);
  if (sock==-1) {
    WHY_perror("socket");
    goto end;
  }

  if (connect(sock, &addr.addr, addr.addrlen) == -1) {
    WHYF_perror("connect(%s)", alloca_socket_address(&addr));
    close(sock);
    goto end;
  }

  char boundary[20];
  char buffer[8192];

  strbuf bb = strbuf_local_buf(boundary);
  strbuf_sprintf(bb, "%08lx%08lx", random(), random());
  assert(!strbuf_overrun(bb));
  strbuf content_preamble = strbuf_alloca(200);
  strbuf content_postamble = strbuf_alloca(40);
  strbuf_sprintf(content_preamble,
      "--%s\r\n"
      "Content-Disposition: form-data; name=\"data\"; filename=\"IHAVEs\"\r\n"
      "Content-Type: %s\r\n"
      "\r\n",
      boundary, CONTENT_TYPE_BLOB
    );
  strbuf_sprintf(content_postamble, "\r\n--%s--\r\n", boundary);
  assert(!strbuf_overrun(content_preamble));
  assert(!strbuf_overrun(content_postamble));
  int content_length = strbuf_len(content_preamble)
		     + r->cursor->buffer_offset_bytes
		     + r->cursor->buffer_used
		     + strbuf_len(content_postamble);
  strbuf request = strbuf_local_buf(buffer);
  strbuf_sprintf(request,
      "POST /rhizome/enquiry HTTP/1.0\r\n"
      "Content-Length: %d\r\n"
      "Content-Type: multipart/form-data; boundary=%s\r\n"
      "\r\n%s",
      content_length, boundary, strbuf_str(content_preamble)
    );
  assert(!strbuf_overrun(request));

  /* TODO: Refactor this code so that it uses our asynchronous framework.
   */
  int len = strbuf_len(request);
  int sent=0;
  while(sent<len) {
    DEBUGF(rhizome_tx, "write(%d, %s, %d)", sock, alloca_toprint(-1, &buffer[sent], len-sent), len-sent);
    int count=write(sock,&buffer[sent],len-sent);
    if (count == -1) {
      if (errno==EPIPE) goto rx;
      WHYF_perror("write(%d)", len - sent);
      close(sock);
      goto end;
    }
    sent+=count;
  }

  len=r->cursor->buffer_offset_bytes+r->cursor->buffer_used;
  sent=0;
  while(sent<len) {
    int count=write(sock,&r->cursor->buffer[sent],len-sent);
    if (count == -1) {
      if (errno == EPIPE)
	goto rx;
      WHYF_perror("write(%d)", count);
      close(sock);
      goto end;
    }
    sent+=count;
  }

  strbuf_reset(request);
  strbuf_puts(request, strbuf_str(content_postamble));
  len = strbuf_len(request);
  sent=0;
  while(sent<len) {
    DEBUGF(rhizome_tx, "write(%d, %s, %d)", sock, alloca_toprint(-1, &buffer[sent], len-sent), len-sent);
    int count=write(sock,&buffer[sent],len-sent);
    if (count == -1) {
      if (errno==EPIPE) goto rx;
      WHYF_perror("write(%d)", len - sent);
      close(sock);
      goto end;
    }
    sent+=count;
  }

  struct http_response_parts parts;
 rx:
  /* request sent, now get response back. */
  len=receive_http_response(sock, buffer, sizeof buffer, &parts);
  if (len == -1) {
    close(sock);
    goto end;
  }

  /* Allocate a buffer to receive the entire action list */
  content_length = parts.content_length;
  unsigned char *actionlist=emalloc(content_length);
  if (!actionlist){
    close(sock);
    goto end;
  }
  bcopy(parts.content_start, actionlist, len);
  if (fill_buffer(sock, actionlist, len, content_length)==-1){
    free(actionlist);
    close(sock);
    goto end;
  }
  close(sock);

  /* We now have the list of (1+RHIZOME_BAR_PREFIX_BYTES)-byte records that indicate
     the list of BAR prefixes that differ between the two nodes.  We can now action
     those which are relevant, i.e., based on whether we are pushing, pulling or
     synchronising (both).

     I am currently undecided as to whether it is cleaner to have some general
     rhizome direct function for doing that, or whether it just adds unnecessary
     complication, and the responses should just be handled in here.

     For now, I am just going to implement it in here, and we can generalise later.
  */
  int i;
  for(i=10;i<content_length;i+=(1+RHIZOME_BAR_PREFIX_BYTES))
    {
      int type=actionlist[i];
      if (type==2&&r->pullP) {
	/* Need to fetch manifest.  Once we have the manifest, then we can
	   use our normal bundle fetch routines from rhizome_fetch.c

	   Generate a request like: GET /rhizome/manifestbybar/<hex of bar>
	   and add it to our list of HTTP fetch requests, then watch
	   until the request is finished.  That will give us the manifest.
	   Then as noted above, we can use that to pull the file down using
	   existing routines.
	*/
	DEBUGF(rhizome_tx, "Fetching manifest %s* @ 0x%x",alloca_tohex(&actionlist[i], 1+RHIZOME_BAR_PREFIX_BYTES),i);
	if (!rhizome_fetch_request_manifest_by_prefix(&addr, NULL, &actionlist[i+1], RHIZOME_BAR_PREFIX_BYTES))
	  {
	    /* Fetching the manifest, and then using it to see if we want to
	       fetch the file for import is all handled asynchronously, so just
	       wait for it to finish. */
	    while (rhizome_any_fetch_active() || rhizome_any_fetch_queued())
	      fd_poll();
	  }

      } else if (type==1&&r->pushP) {
	/* Form up the POST request to submit the appropriate bundle. */

	/* Start by getting the manifest, which is the main thing we need, and also
	   gives us the information we need for sending any associated file. */
	rhizome_manifest *m = rhizome_direct_get_manifest(&actionlist[i+1], RHIZOME_BAR_PREFIX_BYTES);
	if (m == NULL) {
	  WHY("This should never happen.  The manifest exists, but when I went looking for it, it doesn't appear to be there.");
	  goto next_item;
	}

	/* Get filehash and size from manifest if present */
	DEBUGF(rhizome_tx, "bundle id = %s", alloca_tohex_rhizome_bid_t(m->keypair.public_key));
	DEBUGF(rhizome_tx, "bundle filehash = %s", alloca_tohex_rhizome_filehash_t(m->filehash));
	DEBUGF(rhizome_tx, "file size = %"PRId64, m->filesize);
	DEBUGF(rhizome_tx, "version = %"PRIu64, m->version);

	/* We now have everything we need to compose the POST request and send it.
	 */
	char *template="POST /rhizome/import HTTP/1.0\r\n"
	  "Content-Length: %d\r\n"
	  "Content-Type: multipart/form-data; boundary=%s\r\n"
	  "\r\n";
	char *template2="--%s\r\n"
	  "Content-Disposition: form-data; name=\"manifest\"; filename=\"m\"\r\n"
	  "Content-Type: application/octet-stream\r\n"
	  "\r\n";
	char *template3=
	  "\r\n--%s\r\n"
	  "Content-Disposition: form-data; name=\"data\"; filename=\"d\"\r\n"
	  "Content-Type: application/octet-stream\r\n"
	  "\r\n";
	/* Work out what the content length should be */
	DEBUGF(rhizome_tx, "manifest_all_bytes=%zu, manifest_body_bytes=%zu", m->manifest_all_bytes, m->manifest_body_bytes);
	assert(m->filesize != RHIZOME_SIZE_UNSET);
	size_t content_length =
	    strlen(template2) - 2 /* minus 2 for the "%s" that gets replaced */
	  + strlen(boundary)
	  + m->manifest_all_bytes
	  + strlen(template3) - 2 /* minus 2 for the "%s" that gets replaced */
	  + strlen(boundary)
	  + m->filesize
	  + strlen("\r\n--") + strlen(boundary) + strlen("--\r\n");

	int len=snprintf(buffer,8192,template,content_length,boundary);
	len+=snprintf(&buffer[len],8192-len,template2,boundary);
	memcpy(&buffer[len],m->manifestdata,m->manifest_all_bytes);
	len+=m->manifest_all_bytes;
	len+=snprintf(&buffer[len],8192-len,template3,boundary);

	sock=socket(AF_INET, SOCK_STREAM, 0);
	if (sock==-1) {
	  DEBUGF(rhizome_tx, "could not open socket");
	  goto closeit;
	}
	if (connect(sock,&addr.addr,addr.addrlen) == -1) {
	  DEBUGF(rhizome_tx, "Could not connect to remote");
	  goto closeit;
	}

	int sent=0;
	/* Send buffer now */
	while(sent<len) {
	  int r=write(sock,&buffer[sent],len-sent);
	  if (r>0) sent+=r;
	  if (r<0) goto closeit;
	}

	/* send file contents */
	{
	  rhizome_filehash_t filehash;
	  if (rhizome_database_filehash_from_id(&m->keypair.public_key, m->version, &filehash) == -1)
	    goto closeit;

	  struct rhizome_read read;
	  bzero(&read, sizeof read);
	  enum rhizome_payload_status pstatus = rhizome_open_read(&read, &filehash);
	  switch (pstatus) {
	    case RHIZOME_PAYLOAD_STATUS_EMPTY:
	    case RHIZOME_PAYLOAD_STATUS_STORED:
	      goto pstatus_ok;
	    case RHIZOME_PAYLOAD_STATUS_NEW:
	    case RHIZOME_PAYLOAD_STATUS_ERROR:
	    case RHIZOME_PAYLOAD_STATUS_BUSY:
	    case RHIZOME_PAYLOAD_STATUS_WRONG_SIZE:
	    case RHIZOME_PAYLOAD_STATUS_WRONG_HASH:
	    case RHIZOME_PAYLOAD_STATUS_CRYPTO_FAIL:
	    case RHIZOME_PAYLOAD_STATUS_TOO_BIG:
	    case RHIZOME_PAYLOAD_STATUS_EVICTED:
	      goto closeit;
	    // No "default" label, so the compiler will warn us if a case is not handled.
	  }
	  FATALF("pstatus = %d", pstatus);
	pstatus_ok:
	  ;
	  uint64_t read_ofs;
	  for(read_ofs=0;read_ofs<m->filesize;){
	    unsigned char buffer[4096];
	    read.offset=read_ofs;
	    ssize_t bytes_read = rhizome_read(&read, buffer, sizeof buffer);
	    if (bytes_read == -1) {
	      rhizome_read_close(&read);
	      goto closeit;
	    }
	    size_t write_ofs = 0;
	    while (write_ofs < (size_t) bytes_read){
	      ssize_t written = write(sock, buffer + write_ofs, (size_t) bytes_read - write_ofs);
	      if (written == -1){
		WHY_perror("write");
		rhizome_read_close(&read);
		goto closeit;
	      }
	      write_ofs += (size_t) written;
	    }
	    read_ofs += (size_t) bytes_read;
	  }
	  rhizome_read_close(&read);
	}
	/* Send final mime boundary */
	len=snprintf(buffer,8192,"\r\n--%s--\r\n",boundary);
	sent=0;
	while(sent<len) {
	  int r=write(sock,&buffer[sent],len-sent);
	  if (r>0) sent+=r;
	  if (r<0) goto closeit;
	}

	/* get response back. */
	if (receive_http_response(sock, buffer, sizeof buffer, &parts) == -1)
	  goto closeit;
	INFOF("Received HTTP response %03u %s", parts.code, parts.reason);

      closeit:
	close(sock);

	if (m) rhizome_manifest_free(m);
      }
    next_item:
      continue;
    }

  free(actionlist);

  /* now update cursor according to what range was covered in the response.
     We set our current position to just past the high limit of the returned
     cursor.

     XXX - This introduces potential problems with the returned cursor range.
     If the far end returns an earlier cursor position than we are in, we could
     end up in an infinite loop.  We could also end up in a very long finite loop
     if the cursor doesn't advance far.  A simple solution is to not adjust the
     cursor position, and simply re-attempt the sync until no actions result.
     That will do for now.
 */
#ifdef FANCY_CURSOR_POSITION_HANDLING
  rhizome_direct_bundle_cursor *c=rhizome_direct_bundle_iterator(10);
  assert(c!=NULL);
  if (rhizome_direct_bundle_iterator_unpickle_range(c,(unsigned char *)&p[0],10)) {
    DEBUGF(rhizome_tx, "Couldn't unpickle range. This should never happen.  Assuming near and far cursor ranges match.");
  }
  else {
    DEBUGF(rhizome_tx, "unpickled size_high=%"PRId64", limit_size_high=%"PRId64, c->size_high, c->limit_size_high);
    DEBUGF(rhizome_tx, "c->buffer_size=%d",c->buffer_size);
    r->cursor->size_low=c->limit_size_high;
    /* Set tail of BID to all high, as we assume the far end has returned all
       BIDs with the specified prefix. */
    r->cursor->bid_low = RHIZOME_BID_MAX;
    bcopy(c->limit_bid_high.binary, r->cursor->bid_low.binary, 4);
  }
  rhizome_direct_bundle_iterator_free(&c);
#endif

  end:
  /* Warning: tail recursion when done this way.
     Should be triggered by an asynchronous event.
     But this will do for now. */
  rhizome_direct_continue_sync_request(r);
}

static rhizome_manifest *rhizome_direct_get_manifest(unsigned char *bid_prefix, size_t prefix_length)
{
  /* Give a BID prefix, e.g., from a BAR, find the matching manifest and return it.
     Of course, it is possible that more than one manifest matches.  This should
     occur only very rarely (with the possible exception of intentional attack, and
     even then a 64-bit prefix creates a reasonable barrier.  If we move to a new
     BAR format with 120 or 128 bits of BID prefix, then we should be safe for some
     time, thus this function taking the BID prefix as an input in preparation for
     that change).

     Of course, we need to be able to find the manifest.
     Easiest way is to select with a BID range.  We could instead have an extra
     database column with the prefix.
  */
  rhizome_bid_t low = RHIZOME_BID_ZERO;
  rhizome_bid_t high = RHIZOME_BID_MAX;
  assert(prefix_length <= sizeof(rhizome_bid_t));
  bcopy(bid_prefix, low.binary, prefix_length);
  bcopy(bid_prefix, high.binary, prefix_length);
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  sqlite3_stmt *statement = sqlite_prepare_bind(&retry,
      "SELECT manifest, rowid FROM MANIFESTS WHERE id >= ? AND id <= ?",
      RHIZOME_BID_T, &low,
      RHIZOME_BID_T, &high,
      END);
  sqlite3_blob *blob=NULL;
  if (sqlite_step_retry(&retry, statement) == SQLITE_ROW)
    {
      int ret;
      int64_t rowid = sqlite3_column_int64(statement, 1);
      do ret = sqlite3_blob_open(rhizome_db, "main", "manifests", "bar",
				 rowid, 0 /* read only */, &blob);
      while (sqlite_code_busy(ret) && sqlite_retry(&retry, "sqlite3_blob_open"));
      if (!sqlite_code_ok(ret)) {
	WHYF("sqlite3_blob_open() failed, %s", sqlite3_errmsg(rhizome_db));
	sqlite3_finalize(statement);
	return NULL;
	
      }
      sqlite_retry_done(&retry, "sqlite3_blob_open");

      /* Read manifest data from blob */

      size_t manifestblobsize = sqlite3_column_bytes(statement, 0);
      if (manifestblobsize<1||manifestblobsize>1024) goto error;

      const char *manifestblob = (char *) sqlite3_column_blob(statement, 0);
      if (!manifestblob)
	goto error;

      rhizome_manifest *m = rhizome_new_manifest();
      if (!m)
	goto error;
      memcpy(m->manifestdata, manifestblob, manifestblobsize);
      m->manifest_all_bytes = manifestblobsize;
      if (   rhizome_manifest_parse(m) == -1
	  || !rhizome_manifest_validate(m)
      ) {
	rhizome_manifest_free(m);
	goto error;
      }
      
      DEBUGF(rhizome_direct, "Read manifest");
      sqlite3_blob_close(blob);
      sqlite3_finalize(statement);
      return m;

 error:
      sqlite3_blob_close(blob);
      sqlite3_finalize(statement);
      return NULL;
    }
  else 
    {
      DEBUGF(rhizome_direct, "no matching manifests");
      sqlite3_finalize(statement);
      return NULL;
    }

}

