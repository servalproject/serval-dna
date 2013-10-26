/*
Serval DNA - HTTP Server API
Copyright (C) 2013 Serval Project, Inc.
 
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

#ifndef __SERVALDNA__HTTP_SERVER_H
#define __SERVALDNA__HTTP_SERVER_H

#include <limits.h>
#include "constants.h"
#include "strbuf.h"
#include "fdqueue.h"

/* Generic HTTP request handling.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */

extern const char HTTP_VERB_GET[];
extern const char HTTP_VERB_POST[];
extern const char HTTP_VERB_PUT[];
extern const char HTTP_VERB_HEAD[];
extern const char HTTP_VERB_DELETE[];
extern const char HTTP_VERB_TRACE[];
extern const char HTTP_VERB_OPTIONS[];
extern const char HTTP_VERB_CONNECT[];
extern const char HTTP_VERB_PATCH[];

typedef uint64_t http_size_t;
#define PRIhttp_size_t  PRIu64

struct http_request;

struct http_range {
  enum http_range_type { NIL = 0, CLOSED, OPEN, SUFFIX } type;
  http_size_t first; // only for CLOSED or OPEN
  http_size_t last; // only for CLOSED or SUFFIX
};

unsigned http_range_close(struct http_range *dst, const struct http_range *src, unsigned nranges, http_size_t content_length);
http_size_t http_range_bytes(const struct http_range *range, unsigned nranges);

#define CONTENT_LENGTH_UNKNOWN   UINT64_MAX

struct http_request_headers {
  http_size_t content_length;
  const char *content_type;
  const char *content_subtype;
  const char *boundary;
  unsigned short content_range_count;
  struct http_range content_ranges[5];
};

struct http_response_headers {
  http_size_t content_length;
  http_size_t content_range_start; // range_end = range_start + content_length - 1
  http_size_t resource_length; // size of entire resource
  const char *content_type; // "type/subtype"
  const char *boundary;
};

typedef int (*HTTP_CONTENT_GENERATOR)(struct http_request *);

struct http_response {
  uint16_t result_code;
  struct http_response_headers header;
  const char *content;
  HTTP_CONTENT_GENERATOR content_generator; // callback to produce more content
};

#define MIME_FILENAME_MAXLEN 127

struct mime_content_disposition {
  char type[64];
  char name[64];
  char filename[MIME_FILENAME_MAXLEN + 1];
  http_size_t size;
  time_t creation_date;
  time_t modification_date;
  time_t read_date;
};

struct http_mime_handler {
  void (*handle_mime_preamble)(struct http_request *, const char *, size_t);
  void (*handle_mime_part_start)(struct http_request *);
  void (*handle_mime_content_disposition)(struct http_request *, const struct mime_content_disposition *);
  void (*handle_mime_header)(struct http_request *, const char *label, const char *, size_t);
  void (*handle_mime_body)(struct http_request *, const char *, size_t);
  void (*handle_mime_part_end)(struct http_request *);
  void (*handle_mime_epilogue)(struct http_request *, const char *, size_t);
};

struct http_request;

void http_request_init(struct http_request *r, int sockfd);
void http_request_free_response_buffer(struct http_request *r);
int http_request_set_response_bufsize(struct http_request *r, size_t bufsiz);
void http_request_finalise(struct http_request *r);
void http_request_response_static(struct http_request *r, int result, const char *mime_type, const char *body, uint64_t bytes);
void http_request_response_generated(struct http_request *r, int result, const char *mime_type, HTTP_CONTENT_GENERATOR);
void http_request_simple_response(struct http_request *r, uint16_t result, const char *body);

typedef int (*HTTP_REQUEST_PARSER)(struct http_request *);

struct http_request {
  struct sched_ent alarm; // MUST BE FIRST ELEMENT
  enum http_request_phase { RECEIVE, TRANSMIT, DONE } phase;
  bool_t *debug_flag;
  bool_t *disable_tx_flag;
  time_ms_t initiate_time; // time connection was initiated
  time_ms_t idle_timeout; // disconnect if no bytes received for this long
  struct sockaddr_in client_in_addr;
  HTTP_REQUEST_PARSER parser; // current parser function
  HTTP_REQUEST_PARSER handle_first_line; // called after first line is parsed
  HTTP_REQUEST_PARSER handle_headers; // called after all headers are parsed
  HTTP_REQUEST_PARSER handle_content_end; // called after all content is received
  enum mime_state { START, PREAMBLE, HEADER, BODY, EPILOGUE } form_data_state;
  struct http_mime_handler form_data; // called to parse multipart/form-data body
  void (*finalise)(struct http_request *);
  void (*free)(void*);
  const char *verb; // points to nul terminated static string, "GET", "PUT", etc.
  const char *path; // points into buffer; nul terminated
  uint8_t version_major; // m from from HTTP/m.n
  uint8_t version_minor; // n from HTTP/m.n
  struct http_request_headers request_header;
  const char *received; // start of received data in buffer[]
  const char *end; // end of received data in buffer[]
  const char *end_content; // end of content if within buffer[], else NULL
  const char *parsed; // start of unparsed data in buffer[]
  const char *cursor; // for parsing
  http_size_t request_content_remaining;
  struct http_response response;
  http_size_t response_length; // total response bytes (header + content)
  http_size_t response_sent; // for counting up to response_length
  char *response_buffer;
  size_t response_buffer_size;
  size_t response_buffer_length;
  size_t response_buffer_sent;
  void (*response_free_buffer)(void*);
  char buffer[8 * 1024];
};

#endif // __SERVALDNA__HTTP_SERVER_H
