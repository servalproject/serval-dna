/*
Serval DNA - HTTP Server
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

#include <assert.h>
#include <inttypes.h>
#include <time.h>
#include "serval_types.h"
#include "http_server.h"
#include "sighandlers.h"
#include "conf.h"
#include "log.h"
#include "debug.h"
#include "str.h"
#include "strbuf.h"
#include "strbuf_helpers.h"
#include "net.h"
#include "mem.h"

#define BOUNDARY_STRING_MAXLEN  70 // legislated limit from RFC-1341

/* The (struct http_request).verb field points to one of these static strings, so that a simple
 * equality test can be used, eg, (r->verb == HTTP_VERB_GET) instead of a strcmp().
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
const char HTTP_VERB_GET[] = "GET";
const char HTTP_VERB_POST[] = "POST";
const char HTTP_VERB_PUT[] = "PUT";
const char HTTP_VERB_HEAD[] = "HEAD";
const char HTTP_VERB_DELETE[] = "DELETE";
const char HTTP_VERB_TRACE[] = "TRACE";
const char HTTP_VERB_OPTIONS[] = "OPTIONS";
const char HTTP_VERB_CONNECT[] = "CONNECT";
const char HTTP_VERB_PATCH[] = "PATCH";

static struct {
  const char *word;
  size_t wordlen;
} http_verbs[] = {
#define VERB_ENTRY(NAME) { HTTP_VERB_##NAME, sizeof HTTP_VERB_##NAME - 1 }
  VERB_ENTRY(GET),
  VERB_ENTRY(POST),
  VERB_ENTRY(PUT),
  VERB_ENTRY(HEAD),
  VERB_ENTRY(DELETE),
  VERB_ENTRY(TRACE),
  VERB_ENTRY(OPTIONS),
  VERB_ENTRY(CONNECT),
  VERB_ENTRY(PATCH)
#undef VERB_ENTRY
};

const char CONTENT_TYPE_TEXT[] = "text/plain";
const char CONTENT_TYPE_HTML[] = "text/html";
const char CONTENT_TYPE_JSON[] = "application/json";
const char CONTENT_TYPE_BLOB[] = "application/octet-stream";

static struct profile_total http_server_stats = {
  .name = "http_server_poll",
};

#define DEBUG_DUMP_PARSED(r) \
      DEBUGF(http_server, "%s %s HTTP/%u.%u", r->verb ? r->verb : "NULL", alloca_str_toprint(r->path), r->version_major, r->version_minor)

#define DEBUG_DUMP_PARSER(r) \
      DEBUGF(http_server, "parsed %d %s cursor %d %s end %d remain %"PRIhttp_size_t, \
	  (int)(r->parsed - r->received), alloca_toprint(-1, r->parsed, r->cursor - r->parsed), \
	  (int)(r->cursor - r->received), alloca_toprint(50, r->cursor, r->end - r->cursor), \
	  (int)(r->end - r->received), \
	  r->request_content_remaining \
	)

static void http_server_poll(struct sched_ent *);
static void http_request_set_idle_timeout(struct http_request *r);
static int http_request_parse_verb(struct http_request *r);
static int http_request_parse_path(struct http_request *r);
static int http_request_parse_http_version(struct http_request *r);
static int http_request_start_parsing_headers(struct http_request *r);
static int http_request_parse_header(struct http_request *r);
static int http_request_start_body(struct http_request *r);
static int http_request_reject_content(struct http_request *r);
static int http_request_parse_body_form_data(struct http_request *r);
static void http_request_start_response(struct http_request *r);

void http_request_init(struct http_request *r, int sockfd)
{
  assert(sockfd != -1);
  r->request_header.content_length = CONTENT_LENGTH_UNKNOWN;
  r->request_content_remaining = CONTENT_LENGTH_UNKNOWN;
  r->response.header.content_length = CONTENT_LENGTH_UNKNOWN;
  r->response.header.resource_length = CONTENT_LENGTH_UNKNOWN;
  r->alarm.stats = &http_server_stats;
  r->alarm.function = http_server_poll;
  assert(r->idle_timeout >= 0);
  if (r->idle_timeout == 0)
    r->idle_timeout = 10000; // 10 seconds
  r->alarm.poll.fd = sockfd;
  r->alarm.poll.events = POLLIN;
  r->phase = RECEIVE;
  r->reserved = r->buffer;
  // Put aside a few bytes for reserving strings, so that the path and query parameters can be
  // reserved ok.
  r->received = r->end = r->parsed = r->cursor = r->buffer + sizeof(void*) * (1 + NELS(r->query_parameters));
  r->parser = http_request_parse_verb;
  watch(&r->alarm);
  http_request_set_idle_timeout(r);
}

static void http_request_set_idle_timeout(struct http_request *r)
{
  assert(r->phase == RECEIVE || r->phase == TRANSMIT);
  r->alarm.alarm = gettime_ms() + r->idle_timeout;
  r->alarm.deadline = r->alarm.alarm + 500;
  unschedule(&r->alarm);
  schedule(&r->alarm);
}

void http_request_free_response_buffer(struct http_request *r)
{
  if (r->response_free_buffer) {
    IDEBUGF(r->debug, "Free response buffer of %zu bytes", r->response_buffer_size);
    r->response_free_buffer(r->response_buffer);
    r->response_free_buffer = NULL;
  }
  r->response_buffer = NULL;
  r->response_buffer_size = 0;
}

int http_request_set_response_bufsize(struct http_request *r, size_t bufsiz)
{
  // Don't allocate a new buffer if the existing one contains content.
  assert(r->response_buffer_sent == r->response_buffer_length);
  const char *const bufe = r->buffer + sizeof r->buffer;
  assert(r->reserved < bufe);
  size_t rbufsiz = bufe - r->reserved;
  if (bufsiz <= rbufsiz) {
    http_request_free_response_buffer(r);
    r->response_buffer = (char *) r->reserved;
    r->response_buffer_size = rbufsiz;
    IDEBUGF(r->debug, "Static response buffer %zu bytes", r->response_buffer_size);
    return 0;
  }
  if (bufsiz != r->response_buffer_size) {
    http_request_free_response_buffer(r);
    if ((r->response_buffer = emalloc(bufsiz)) == NULL)
      return -1;
    r->response_free_buffer = free;
    r->response_buffer_size = bufsiz;
    IDEBUGF(r->debug, "Allocated response buffer %zu bytes", r->response_buffer_size);
  }
  assert(r->response_buffer_size >= bufsiz);
  assert(r->response_buffer != NULL);
  return 0;
}

void http_request_finalise(struct http_request *r)
{
  IN();
  if (r->phase == DONE)
    RETURNVOID;
  assert(r->phase == RECEIVE || r->phase == TRANSMIT || r->phase == PAUSE);
  unschedule(&r->alarm);
  if (r->phase != PAUSE)
    unwatch(&r->alarm);
  close(r->alarm.poll.fd);
  r->alarm.poll.fd = -1;
  if (r->finalise)
    r->finalise(r);
  r->finalise = NULL;
  http_request_free_response_buffer(r);
  r->phase = DONE;
  OUT();
}

struct substring {
  const char *start;
  const char *end;
};

#define alloca_substring_toprint(sub) alloca_toprint(-1, (sub).start, (sub).end - (sub).start)

const struct substring substring_NULL = { NULL, NULL };

#if 0
static int _matches(struct substring str, const char *text)
{
  return strlen(text) == str.end - str.start && memcmp(str.start, text, str.end - str.start) == 0;
}
#endif

static void write_pointer(unsigned char *mem, const void *v)
{
  memcpy(mem, &v, sizeof(void*));
}

static void *read_pointer(const unsigned char *mem)
{
  void *v;
  memcpy(&v, mem, sizeof(void*));
  return v;
}

/* Allocate space from the start of the request buffer to hold a given number of bytes plus a
 * terminating NUL.  Enough bytes must have already been marked as parsed in order to make room,
 * otherwise the reservation fails and returns 0.  If successful, returns 1.
 *
 * Keeps a copy to the pointer 'resp', so that when the reserved area is released, all pointers into
 * it can be set to NULL automatically.  This provides some safety: if the pointer is accidentally
 * dereferenced after the release it will cause a SEGV instead of using a string that has been
 * overwritten.  It does not protect from using copies of '*resp', which of course will not be have
 * been set to NULL by the release.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static int _reserve(struct http_request *r, const char **resp, const char *src, size_t len, void (*mover)(char *, const char *, size_t))
{
  // Reserved string pointer must lie within this http_request struct.
  assert((char*)resp >= (char*)r);
  assert((char*)resp < (char*)(r + 1));
  char *reslim = r->buffer + sizeof r->buffer - 1024; // always leave this much unreserved space
  assert(r->reserved <= reslim);
  size_t siz = sizeof(char**) + len + 1;
  if (r->reserved + siz > reslim) {
    r->response.result_code = 414;
    return 0;
  }
  if (r->reserved + siz > r->parsed) {
    WARNF("Error during HTTP parsing, unparsed content %s would be overwritten by reserving %zu bytes",
	alloca_toprint(30, r->parsed, r->end - r->parsed), len + 1
      );
    r->response.result_code = 500;
    return 0;
  }
  const char ***respp = (const char ***) r->reserved;
  char *restr = (char *)(respp + 1);
  mover(restr, src, len);
  restr[len] = '\0';
  r->reserved += siz;
  assert(r->reserved == &restr[len+1]);
  if (r->reserved > r->received)
    r->received = r->reserved;
  assert(r->received <= r->parsed);
  // Only store the pointer _after_ the memmove() above, to avoid overwriting part of the source
  // string before we copy it, in the case that the source string is located within r->buffer[].
  write_pointer((unsigned char*)respp, resp); // can't use *respp = resp; could cause SIGBUS if not aligned
  *resp = restr;
  return 1;
}

static void _mover_mem(char *dst, const char *src, size_t len)
{
  if (dst != src)
    memmove(dst, src, len);
}

/* Allocate space from the start of the request buffer to hold the given substring plus a
 * terminating NUL.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static int _reserve_substring(struct http_request *r, const char **resp, struct substring str)
{
  size_t len = str.end - str.start;
  // Substring must contain no NUL chars.
  assert(strnchr(str.start, len, '\0') == NULL);
  return _reserve(r, resp, str.start, len, _mover_mem);
}

/* The same as _reserve(), but takes a NUL-terminated string as a source argument instead of a
 * substring.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static int _reserve_str(struct http_request *r, const char **resp, const char *str)
{
  return _reserve(r, resp, str, strlen(str), _mover_mem);
}

/* The same as _reserve(), but decodes the source bytes using www-form-urlencoding.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static void _mover_www_form_uri_decode(char *, const char *, size_t);
static int _reserve_www_form_uriencoded(struct http_request *r, const char **resp, struct substring str)
{
  assert(str.end > str.start);
  const char *after = NULL;
  size_t len = www_form_uri_decode(NULL, -1, (char *)str.start, str.end - str.start, &after);
  assert(len <= (size_t)(str.end - str.start)); // decoded must not be longer than encoded
  assert(after == str.end);
  return _reserve(r, resp, str.start, len, _mover_www_form_uri_decode);
}
static void _mover_www_form_uri_decode(char *dst, const char *src, size_t len)
{
  www_form_uri_decode(dst, len, src, -1, NULL);
}

/* Release all the strings reserved by _reserve(), returning the space to the request buffer, and
 * resetting to NULL all the pointers to reserved strings that were set by _reserve().
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static void _release_reserved(struct http_request *r)
{
  char *res = r->buffer;
  while (res < r->reserved) {
    assert(res + sizeof(char**) + 1 <= r->reserved);
    const char ***respp = (const char ***) res;
    char *restr = (char *)(respp + 1);
    const char **resp = read_pointer((const unsigned char*)respp); // can't use resp = *respp; could cause SIGBUS if not aligned
    assert((const char*)resp >= (const char*)r);
    assert((const char*)resp < (const char*)(r + 1));
    assert(*resp == restr);
    *resp = NULL;
    for (res = restr; res < r->reserved && *res; ++res)
      ;
    assert(res < r->reserved);
    assert(*res == '\0');
    ++res;
  }
  assert(res == r->reserved);
  r->reserved = r->buffer;
}

static inline int _end_of_content(struct http_request *r)
{
  return r->cursor == r->end && r->request_content_remaining == 0;
}

static inline int _run_out(struct http_request *r)
{
  assert(r->cursor <= r->end);
  return r->cursor == r->end;
}

static inline int _buffer_full(struct http_request *r)
{
  const char *const bufend = r->buffer + sizeof r->buffer;
  return r->parsed == r->received && (r->end == bufend || r->request_content_remaining == 0);
}

static inline void _rewind(struct http_request *r)
{
  assert(r->parsed >= r->received);
  r->cursor = r->parsed;
}

static inline void _commit(struct http_request *r)
{
  assert(r->cursor <= r->end);
  r->parsed = r->cursor;
}

static inline int _skip_any(struct http_request *r)
{
  if (_run_out(r))
    return 0;
  ++r->cursor;
  return 1;
}

static inline void _skip_all(struct http_request *r)
{
  r->cursor = r->end;
}

static inline int _skip_crlf(struct http_request *r)
{
  return !_run_out(r) && *r->cursor == '\r' && ++r->cursor && !_run_out(r) && *r->cursor == '\n' && ++r->cursor;
}

static inline int _skip_to_crlf(struct http_request *r)
{
  for (; !_run_out(r); ++r->cursor)
    if (r->cursor + 1 < r->end && r->cursor[0] == '\r' && r->cursor[1] == '\n')
      return 1;
  return 0;
}

static inline void _rewind_optional_cr(struct http_request *r)
{
  if (r->cursor > r->parsed && r->cursor[-1] == '\r')
    --r->cursor;
}

static inline void _rewind_crlf(struct http_request *r)
{
  assert(r->cursor >= r->parsed + 2);
  assert(r->cursor[-2] == '\r');
  assert(r->cursor[-1] == '\n');
  r->cursor -= 2;
}

/* More permissive than _skip_crlf(), this counts NUL characters preceding and between the CR and LF
 * as part of the end-of-line sequence and treats the CR as optional.  This allows simple manual
 * testing using telnet(1).
 */
static inline int _skip_eol(struct http_request *r)
{
  unsigned crcount = 0;
  for (; !_run_out(r); ++r->cursor) {
    switch (*r->cursor) {
      case '\0': // ignore any leading NULs (telnet inserts them)
	break;
      case '\r': // ignore up to one leading CR
	if (++crcount > 1)
	  return 0;
	break;
      case '\n':
	++r->cursor;
	return 1;
      default:
	return 0;
    }
  }
  return 0;
}

/* More permissive than _skip_crlf(), this counts NUL characters preceding and between the CR and LF
 * as part of the end-of-line sequence and treats the CR as optional.  This allows simple manual
 * testing using telnet(1).
 */
static int _skip_to_eol(struct http_request *r)
{
  const char *const start = r->cursor;
  while (!_run_out(r) && *r->cursor != '\n')
    ++r->cursor;
  if (_run_out(r))
    return 0;
  // consume preceding NULs (telnet inserts them)
  while (r->cursor > start && r->cursor[-1] == '\0')
    --r->cursor;
  // consume a single preceding CR
  if (r->cursor > start && r->cursor[-1] == '\r')
    --r->cursor;
  // consume any more preceding NULs
  while (r->cursor > start && r->cursor[-1] == '\0')
    --r->cursor;
  return 1;
}

static int _skip_literal(struct http_request *r, const char *literal)
{
  while (!_run_out(r) && *literal && *r->cursor == *literal)
    ++literal, ++r->cursor;
  return *literal == '\0';
}

static int _skip_literal_nocase(struct http_request *r, const char *literal)
{
  while (!_run_out(r) && *literal && toupper(*r->cursor) == toupper(*literal))
    ++literal, ++r->cursor;
  return *literal == '\0';
}

static int is_http_space(char c)
{
  return c == ' ' || c == '\t';
}

static int _skip_optional_space(struct http_request *r)
{
  while (!_run_out(r) && is_http_space(*r->cursor))
    ++r->cursor;
  return 1;
}

static inline int _skip_space(struct http_request *r)
{
  const char *const start = r->cursor;
  _skip_optional_space(r);
  return r->cursor > start;
}

static size_t _skip_word_printable(struct http_request *r, struct substring *str, char until)
{
  if (_run_out(r) || isspace(*r->cursor) || !isprint(*r->cursor) || *r->cursor == until)
    return 0;
  const char *start = r->cursor;
  for (++r->cursor; !_run_out(r) && !isspace(*r->cursor) && isprint(*r->cursor) && *r->cursor != until; ++r->cursor)
    ;
  if (_run_out(r))
    return 0;
  assert(r->cursor > start);
  assert(isspace(*r->cursor) || *r->cursor == until);
  if (str) {
    str->start = start;
    str->end = r->cursor;
  }
  return r->cursor - start;
}

static size_t _skip_token(struct http_request *r, struct substring *str)
{
  if (_run_out(r) || !is_http_token(*r->cursor))
    return 0;
  const char *start = r->cursor;
  for (++r->cursor; !_run_out(r) && is_http_token(*r->cursor); ++r->cursor)
    ;
  if (_run_out(r))
    return 0;
  assert(r->cursor > start);
  assert(!is_http_token(*r->cursor));
  if (str) {
    str->start = start;
    str->end = r->cursor;
  }
  return r->cursor - start;
}

static size_t _parse_token(struct http_request *r, char *dst, size_t dstsiz)
{
  struct substring str;
  size_t len = _skip_token(r, &str);
  if (len && dst) {
    size_t cpy = len < dstsiz - 1 ? len : dstsiz - 1;
    strncpy(dst, str.start, cpy)[cpy] = '\0';
  }
  return len;
}

static size_t _parse_quoted_string(struct http_request *r, char *dst, size_t dstsiz)
{
  assert(r->cursor <= r->end);
  if (_run_out(r) || *r->cursor != '"')
    return 0;
  int slosh = 0;
  size_t len = 0;
  for (++r->cursor; !_run_out(r); ++r->cursor) {
    if (!isprint(*r->cursor))
      return 0;
    if (slosh) {
      if (dst && len < dstsiz - 1)
	dst[len] = *r->cursor;
      ++len;
      slosh = 0;
    } else if (*r->cursor == '"')
      break;
    else if (*r->cursor == '\\')
      slosh = 1;
    else {
      if (dst && len < dstsiz - 1)
	dst[len] = *r->cursor;
      ++len;
    }
  }
  if (dst)
    dst[len < dstsiz - 1 ? len : dstsiz - 1] = '\0';
  if (_run_out(r))
    return 0;
  assert(*r->cursor == '"');
  ++r->cursor;
  return len;
}

static size_t _parse_token_or_quoted_string(struct http_request *r, char *dst, size_t dstsiz)
{
  assert(dstsiz > 0);
  if (!_run_out(r) && *r->cursor == '"')
    return _parse_quoted_string(r, dst, dstsiz);
  return _parse_token(r, dst, dstsiz);
}

static inline int _parse_http_size_t(struct http_request *r, http_size_t *szp)
{
  return !_run_out(r) && isdigit(*r->cursor) && str_to_uint64(r->cursor, 10, szp, (const char **)&r->cursor);
}

static inline int _parse_uint32(struct http_request *r, uint32_t *uint32p)
{
  return !_run_out(r) && isdigit(*r->cursor) && str_to_uint32(r->cursor, 10, uint32p, (const char **)&r->cursor);
}

static unsigned _parse_ranges(struct http_request *r, struct http_range *range, unsigned nrange)
{
  unsigned i = 0;
  while (1) {
    enum http_range_type type;
    http_size_t first = 0, last = 0;
    if (_skip_literal(r, "-")) {
      if (!_parse_http_size_t(r, &last))
	return 0;
      type = SUFFIX;
    }
    else if (_parse_http_size_t(r, &first) && _skip_literal(r, "-")) {
      if (_parse_http_size_t(r, &last)) {
	if (last < first)
	  return 0;
	type = CLOSED;
      } else
	type = OPEN;
    } else
      return 0;
    if (i < nrange) {
      range[i].type = type;
      range[i].first = first;
      range[i].last = last;
    }
    ++i;
    if (!_skip_literal(r, ","))
      break;
    _skip_optional_space(r);
  }
  return i;
}

static int _parse_content_type(struct http_request *r, struct mime_content_type *ct)
{
  size_t n = _parse_token(r, ct->type, sizeof ct->type);
  if (n == 0)
    return 0;
  if (n >= sizeof ct->type) {
    WARNF("HTTP Content-Type type truncated: %s", alloca_str_toprint(ct->type));
    return 0;
  }
  if (!_skip_literal(r, "/"))
    return 0;
  n = _parse_token(r, ct->subtype, sizeof ct->subtype);
  if (n == 0)
    return 0;
  if (n >= sizeof ct->subtype) {
    WARNF("HTTP Content-Type subtype truncated: %s", alloca_str_toprint(ct->subtype));
    return 0;
  }
  while (_skip_optional_space(r) && _skip_literal(r, ";") && _skip_optional_space(r)) {
    char *start = r->cursor;
    if (_skip_literal(r, "charset=")) {
      size_t n = _parse_token_or_quoted_string(r, ct->charset, sizeof ct->charset);
      if (n == 0)
	return 0;
      if (n >= sizeof ct->charset) {
	WARNF("HTTP Content-Type charset truncated: %s", alloca_str_toprint(ct->charset));
	return 0;
      }
      continue;
    }
    r->cursor = start;
    if (_skip_literal(r, "boundary=")) {
      size_t n = _parse_token_or_quoted_string(r, ct->multipart_boundary, sizeof ct->multipart_boundary);
      if (n == 0)
	return 0;
      if (n >= sizeof ct->multipart_boundary) {
	WARNF("HTTP Content-Type boundary truncated: %s", alloca_str_toprint(ct->multipart_boundary));
	return 0;
      }
      continue;
    }
    r->cursor = start;
    if (_skip_literal(r, "format=")) {
      size_t n = _parse_token_or_quoted_string(r, ct->format, sizeof ct->format);
      if (n == 0)
	return 0;
      if (n >= sizeof ct->format) {
	WARNF("HTTP Content-Type format truncated: %s", alloca_str_toprint(ct->format));
	return 0;
      }
      continue;
    }
    r->cursor = start;
    struct substring param;
    if (_skip_token(r, &param) && _skip_literal(r, "=") && _parse_token_or_quoted_string(r, NULL, 0)) {
      IDEBUGF(r->debug, "Skipping HTTP Content-Type parameter: %s", alloca_substring_toprint(param));
      continue;
    }
    WARNF("Malformed HTTP Content-Type: %s", alloca_toprint(50, r->cursor, r->end - r->cursor));
    return 0;
  }
  return 1;
}

static size_t _parse_base64(struct http_request *r, char *bin, size_t binsize)
{
  return base64_decode((unsigned char *)bin, binsize, r->cursor, r->end - r->cursor, (const char **)&r->cursor, B64_CONSUME_ALL, is_http_space);
}

static int _parse_authorization_credentials_basic(struct http_request *r, struct http_client_credentials_basic *cred, char *buf, size_t bufsz)
{
  size_t n = _parse_base64(r, buf, bufsz - 1); // leave room for NUL terminator on password
  assert(n < bufsz); // buffer must be big enough
  char *pw = (char *) strnchr(buf, n, ':');
  if (pw == NULL)
    return 0; // malformed
  cred->user = buf;
  *pw++ = '\0'; // NUL terminate user
  cred->password = pw;
  buf[n] = '\0'; // NUL terminate password
  return 1;
}

static int _parse_authorization(struct http_request *r, struct http_client_authorization *auth, size_t header_bytes)
{
  char *start = r->cursor;
  if (_skip_literal(r, "Basic") && _skip_space(r)) {
    size_t bufsz = 5 + header_bytes * 3 / 4; // enough for base64 decoding
    char buf[bufsz];
    if (_parse_authorization_credentials_basic(r, &auth->credentials.basic, buf, bufsz)) {
      auth->scheme = BASIC;
      _commit(r); // make room for following reservations
      if (   !_reserve_str(r, &auth->credentials.basic.user, auth->credentials.basic.user)
	  || !_reserve_str(r, &auth->credentials.basic.password, auth->credentials.basic.password)
      )
	return 0; // error
      return 1;
    }
    IDEBUGF(r->debug, "Malformed HTTP header: Authorization: %s", alloca_toprint(50, start, header_bytes));
    return 0;
  }
  if (_skip_literal(r, "Digest") && _skip_space(r)) {
    IDEBUG(r->debug, "Ignoring unsupported HTTP Authorization scheme: Digest");
    r->cursor += header_bytes;
    return 1;
  }
  struct substring scheme;
  if (_skip_token(r, &scheme) && _skip_space(r)) {
    IDEBUGF(r->debug, "Unrecognised HTTP Authorization scheme: %s", alloca_toprint(-1, scheme.start, scheme.end - scheme.start));
    return 0;
  }
  IDEBUGF(r->debug, "Malformed HTTP Authorization header: %s", alloca_toprint(50, r->parsed, r->end - r->parsed));
  return 0;
}

static int _parse_quoted_rfc822_time(struct http_request *r, time_t *timep)
{
  char datestr[40];
  size_t n = _parse_quoted_string(r, datestr, sizeof datestr);
  if (n == 0 || n >= sizeof datestr)
    return 0;
  // TODO: Move the following code into its own function in str.c
  struct tm tm;
  bzero(&tm, sizeof tm);
  // TODO: Ensure this works in non-English locales, ie, "%a" still accepts "Mon", "Tue" etc. and
  // "%b" still accepts "Jan", "Feb" etc.
  // TODO: Support symbolic time zones, eg, "UT", "GMT", "UTC", "EST"...
  const char *c = strptime(datestr, "%a, %d %b %Y %T ", &tm);
  if ((c[0] == '-' || c[0] == '+') && isdigit(c[1]) && isdigit(c[2]) && isdigit(c[3]) && isdigit(c[4]) && c[5] == '\0') {
    time_t zone = (c[0] == '-' ? -1 : 1) * ((c[1] - '0') * 600 + (c[2] - '0') * 60 + (c[3] - '0') * 10 + (c[4] - '0'));
    const char *tz = getenv("TZ");
    if (tz)
      tz = alloca_strdup(tz);
    setenv("TZ", "", 1);
    tzset();
    *timep = mktime(&tm) - zone;
    if (tz)
      setenv("TZ", tz, 1);
    else
      unsetenv("TZ");
    tzset();
    return 1;
  }
  return 0;
}

/* If parsing completes, then sets r->parser to the next parsing function and returns 0.  If parsing
 * cannot complete due to running out of data, returns 100 without changing r->parser, so this
 * function will be called again once more data has been read.  Returns a 4nn or 5nn HTTP result
 * code if parsing fails.  Returns -1 if an unexpected error occurs.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static int http_request_parse_verb(struct http_request *r)
{
  DEBUG_DUMP_PARSER(r);
  _rewind(r);
  assert(r->cursor >= r->received);
  assert(!_run_out(r));
  // Parse verb: GET, PUT, POST, etc.
  assert(r->verb == NULL);
  unsigned i;
  for (i = 0; i < NELS(http_verbs); ++i) {
    _rewind(r);
    if (_skip_literal(r, http_verbs[i].word) && _skip_literal(r, " ")) {
      r->verb = http_verbs[i].word;
      break;
    }
    if (_run_out(r))
      return 100; // read more and try again
  }
  if (r->verb == NULL) {
    IDEBUGF(r->debug, "Malformed HTTP request, invalid verb: %s", alloca_toprint(20, r->cursor, r->end - r->cursor));
    return 400;
  }
  _commit(r);
  r->parser = http_request_parse_path;
  return 0;
}

/* If parsing completes, then sets r->parser to the next parsing function and returns 0.  If parsing
 * cannot complete due to running out of data, returns 100 without changing r->parser, so this
 * function will be called again once more data has been read.  Returns a 4nn or 5nn HTTP result
 * code if parsing fails.  Returns -1 if an unexpected error occurs.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static int http_request_parse_path(struct http_request *r)
{
  DEBUG_DUMP_PARSER(r);
  // Parse path: word immediately following verb, delimited by spaces.
  assert(r->path == NULL);
  struct substring path;
  struct {
    struct substring name;
    struct substring value;
  } params[NELS(r->query_parameters)];
  unsigned count = 0;
  if (_skip_word_printable(r, &path, '?')) {
    struct substring param;
    while (   count < NELS(params)
	   && (_skip_literal(r, "?") || _skip_literal(r, "&"))
	   && _skip_word_printable(r, &param, '&')
    ) {
      const char *eq = strnchr(param.start, param.end - param.start, '=');
      params[count].name.start = param.start;
      if (eq) {
	params[count].name.end = eq;
	params[count].value.start = eq + 1;
	params[count].value.end = param.end;
      } else {
	params[count].name.end = param.end;
	params[count].value.start = NULL;
	params[count].value.end = NULL;
      }
      IDEBUGF(r->debug, "Query parameter: %s%s%s",
	  alloca_substring_toprint(params[count].name),
	  params[count].value.start ? "=" : "",
	  params[count].value.start ? alloca_substring_toprint(params[count].value) : ""
	);
      ++count;
    }
  }
  if (!_skip_literal(r, " ")) {
    if (_run_out(r))
      return 100; // read more and try again
    if (count == NELS(params))
      IDEBUGF(r->debug, "Unsupported HTTP %s request, too many query parameters: %s", r->verb, alloca_toprint(20, r->parsed, r->end - r->parsed));
    else
      IDEBUGF(r->debug, "Malformed HTTP %s request at path: %s", r->verb, alloca_toprint(20, r->parsed, r->end - r->parsed));
    return 400;
  }
  _commit(r);
  if (!_reserve_www_form_uriencoded(r, &r->path, path))
    return 0; // error
  unsigned i;
  for (i = 0; i != count; ++i) {
    if (!_reserve_www_form_uriencoded(r, &r->query_parameters[i].name, params[i].name))
      return 0; // error
    if (params[i].value.start && !_reserve_www_form_uriencoded(r, &r->query_parameters[i].value, params[i].value))
      return 0; // error
  }
  r->parser = http_request_parse_http_version;
  return 0;
}

const char HTTP_REQUEST_PARAM_NOVALUE[] = "";

const char *http_request_get_query_param(struct http_request *r, const char *name)
{
  unsigned i;
  for (i = 0; i != NELS(r->query_parameters) && r->query_parameters[i].name; ++i) {
    if (strcmp(r->query_parameters[i].name, name) == 0)
      return r->query_parameters[i].value ? r->query_parameters[i].value : HTTP_REQUEST_PARAM_NOVALUE;
  }
  return NULL;
}

/* If parsing completes, then sets r->parser to the next parsing function and returns 0.  If parsing
 * cannot complete due to running out of data, returns 100 without changing r->parser, so this
 * function will be called again once more data has been read.  Returns a 4nn or 5nn HTTP result
 * code if parsing fails.  Returns -1 if an unexpected error occurs.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static int http_request_parse_http_version(struct http_request *r)
{
  DEBUG_DUMP_PARSER(r);
  // Parse HTTP version: HTTP/m.n followed by CRLF.
  assert(r->version_major == 0);
  assert(r->version_minor == 0);
  uint32_t major, minor;
  if (!(   _skip_literal(r, "HTTP/")
	&& _parse_uint32(r, &major)
	&& major > 0 && major < UINT8_MAX
	&& _skip_literal(r, ".")
	&& _parse_uint32(r, &minor)
	&& minor < UINT8_MAX
	&& _skip_eol(r)
       )
  ) {
    if (_run_out(r))
      return 100; // read more and try again
    IDEBUGF(r->debug, "Malformed HTTP %s request at version: %s", r->verb, alloca_toprint(20, r->parsed, r->end - r->parsed));
    return 400;
  }
  _commit(r);
  r->version_major = major;
  r->version_minor = minor;
  r->parser = http_request_start_parsing_headers;
  if (r->handle_first_line)
    return r->handle_first_line(r);
  return 0; // parsing complete
}

/* Select the header parser.  Returns 0 after setting the new parser function.  Returns a 4nn or 5nn
 * HTTP result code if the request cannot be handled (eg, unsupported HTTP version or invalid path).
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static int http_request_start_parsing_headers(struct http_request *r)
{
  DEBUG_DUMP_PARSER(r);
  assert(r->verb != NULL);
  assert(r->path != NULL);
  assert(r->version_major != 0);
  if (r->version_major != 1) {
    IDEBUGF(r->debug, "Unsupported HTTP version: %u.%u", r->version_major, r->version_minor);
    return 400;
  }
  r->parser = http_request_parse_header;
  return 0;
}

/* Parse one request header line.
 *
 * If the end of headers is parsed (blank line), then sets r->parser to the next parsing function
 * and returns 0.  If a single header line is successfully parsed, returns 0 after advancing
 * r->parsed.  If parsing cannot complete due to running out of data, returns 0 without changing
 * r->parser, so this function will be called again once more data has been read.  Returns a 4nn or
 * 5nn HTTP result code if parsing fails.  Returns -1 if an unexpected error occurs.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static int http_request_parse_header(struct http_request *r)
{
  DEBUG_DUMP_PARSER(r);
  _skip_to_eol(r);
  const char *const eol = r->cursor;
  _skip_eol(r);
  if (eol == r->parsed) { // if EOL is at start of line (ie, blank line)...
    _commit(r);
    if (r->request_header.content_length != CONTENT_LENGTH_UNKNOWN) {
      size_t unparsed = r->end - r->parsed;
      if (unparsed > r->request_header.content_length) {
	WARNF("HTTP parsing: already read %zu bytes past end of content", (size_t)(unparsed - r->request_header.content_length));
	r->request_content_remaining = 0;
      }
      else
	r->request_content_remaining = r->request_header.content_length - unparsed;
    }
    r->parser = http_request_start_body;
    if (r->handle_headers)
      return r->handle_headers(r);
    return 0;
  }
  char *const nextline = r->cursor;
  _rewind(r);
  const char *const sol = r->cursor;
  if (_skip_literal_nocase(r, "Content-Length:")) {
    if (r->request_header.content_length != CONTENT_LENGTH_UNKNOWN) {
      IDEBUGF(r->debug, "Skipping duplicate HTTP header Content-Length: %s", alloca_toprint(50, sol, r->end - sol));
      r->cursor = nextline;
      _commit(r);
      return 0;
    }
    _skip_optional_space(r);
    http_size_t length;
    if (_parse_http_size_t(r, &length) && _skip_optional_space(r) && r->cursor == eol) {
      r->cursor = nextline;
      _commit(r);
      r->request_header.content_length = length;
      IDEBUGF(r->debug, "Parsed HTTP request Content-Length: %"PRIhttp_size_t, r->request_header.content_length);
      return 0;
    }
    goto malformed;
  }
  _rewind(r);
  if (_skip_literal_nocase(r, "Content-Type:")) {
    if (r->request_header.content_type.type[0]) {
      IDEBUGF(r->debug, "Skipping duplicate HTTP header Content-Type: %s", alloca_toprint(50, sol, r->end - sol));
      r->cursor = nextline;
      _commit(r);
      return 0;
    }
    _skip_optional_space(r);
    if (   _parse_content_type(r, &r->request_header.content_type)
	&& _skip_optional_space(r)
	&& r->cursor == eol
    ) {
      r->cursor = nextline;
      _commit(r);
      IDEBUGF(r->debug, "Parsed HTTP request Content-type: %s", alloca_mime_content_type(&r->request_header.content_type));
      return 0;
    }
    goto malformed;
  }
  _rewind(r);
  if (_skip_literal_nocase(r, "Range:")) {
    if (r->request_header.content_range_count) {
      IDEBUGF(r->debug, "Skipping duplicate HTTP header Range: %s", alloca_toprint(50, sol, r->end - sol));
      r->cursor = nextline;
      _commit(r);
      return 0;
    }
    _skip_optional_space(r);
    unsigned int n;
    if (   _skip_literal(r, "bytes=")
	&& (n = _parse_ranges(r, r->request_header.content_ranges, NELS(r->request_header.content_ranges)))
	&& _skip_optional_space(r)
	&& r->cursor == eol
    ) {
      r->cursor = nextline;
      _commit(r);
      if (n > NELS(r->request_header.content_ranges)) {
	IDEBUGF(r->debug, "HTTP request Range header overflow (%u ranges in set, can only handle %zu): %s",
	      n, NELS(r->request_header.content_ranges), alloca_toprint(-1, sol, eol - sol));
	// In this case ignore the Range: header -- respond with the entire resource.
	r->request_header.content_range_count = 0;
      } else {
	r->request_header.content_range_count = n;
	IDEBUGF(r->debug, "Parsed HTTP request Range: bytes=%s", alloca_http_ranges(r->request_header.content_ranges));
      }
      return 0;
    }
    goto malformed;
  }
  _rewind(r);
  if (_skip_literal_nocase(r, "Authorization:")) {
    if (r->request_header.authorization.scheme != NOAUTH) {
      IDEBUGF(r->debug, "Skipping duplicate HTTP header Authorization: %s", alloca_toprint(50, sol, r->end - sol));
      r->cursor = nextline;
      _commit(r);
      return 0;
    }
    _skip_optional_space(r);
    if (   _parse_authorization(r, &r->request_header.authorization, eol - r->cursor)
	&& _skip_optional_space(r)
	&& r->cursor == eol
    ) {
      assert(r->request_header.authorization.scheme != NOAUTH);
      r->cursor = nextline;
      _commit(r);
      return 0;
    }
    if (r->response.result_code)
	return r->response.result_code;
    goto malformed;
  }
  _rewind(r);
  if (_skip_literal_nocase(r, "Origin:")) {
    if (r->request_header.origin) {
      IDEBUGF(r->debug, "Skipping duplicate HTTP header Origin: %s", alloca_toprint(50, sol, r->end - sol));
      r->cursor = nextline;
      _commit(r);
      return 0;
    }
    _skip_optional_space(r);
    struct substring origin;
    if (_skip_word_printable(r, &origin, ' ') 
	&& _skip_optional_space(r)
	&& r->cursor == eol) {
      r->cursor = nextline;
      _commit(r);
      _reserve_substring(r, &r->request_header.origin, origin);
      return 0;
    }
    goto malformed;
  }
  _rewind(r);
  IDEBUGF(r->debug, "Skipped HTTP request header: %s", alloca_toprint(-1, sol, eol - sol));
  r->cursor = nextline;
  _commit(r);
  return 0;
malformed:
  IDEBUGF(r->debug, "Malformed HTTP request header: %s", alloca_toprint(-1, sol, eol - sol));
  return 400;
}

/* If parsing completes, then sets r->parser to the next parsing function and returns 0.  If parsing
 * cannot complete due to running out of data, returns 0 without changing r->parser, so this
 * function will be called again once more data has been read.  Returns a 4nn or 5nn HTTP result
 * code if parsing fails.  Returns -1 if an unexpected error occurs.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static int http_request_start_body(struct http_request *r)
{
  DEBUG_DUMP_PARSER(r);
  assert(r->verb != NULL);
  assert(r->path != NULL);
  assert(r->version_major != 0);
  assert(r->parsed <= r->end);
  if (r->verb == HTTP_VERB_GET) {
    // TODO: Implement HEAD requests (only send response header, not body)
    if (r->request_header.content_length != 0 && r->request_header.content_length != CONTENT_LENGTH_UNKNOWN) {
      IDEBUGF(r->debug, "Malformed HTTP %s request: non-zero Content-Length not allowed", r->verb);
      return 400;
    }
    if (r->request_header.content_type.type[0]) {
      IDEBUGF(r->debug, "Malformed HTTP %s request: Content-Type not allowed", r->verb);
      return 400;
    }
    r->parser = NULL;
  }
  else if (r->verb == HTTP_VERB_POST) {
    if (r->request_header.content_length == CONTENT_LENGTH_UNKNOWN) {
      IDEBUGF(r->debug, "Malformed HTTP %s request: missing Content-Length header", r->verb);
      return 411;
    }
    if (r->request_header.content_length == 0) {
      r->parser = http_request_reject_content;
    } else {
      if (r->request_header.content_type.type[0] == '\0') {
	IDEBUGF(r->debug, "Malformed HTTP %s request: missing Content-Type header", r->verb);
	return 400;
      }
      if (   strcmp(r->request_header.content_type.type, "multipart") == 0
	  && strcmp(r->request_header.content_type.subtype, "form-data") == 0
      ) {
	if (   r->request_header.content_type.multipart_boundary[0] == '\0'
	) {
	  IDEBUGF(r->debug, "Malformed HTTP %s request: Content-Type %s/%s missing boundary parameter",
		r->verb, r->request_header.content_type.type, r->request_header.content_type.subtype);
	  return 400;
	}
	r->parser = http_request_parse_body_form_data;
	r->form_data_state = START;
      } else {
	IDEBUGF(r->debug, "Unsupported HTTP %s request: Content-Type %s not supported",
	      r->verb, alloca_mime_content_type(&r->request_header.content_type));
	return 415;
      }
    }
  }
  else {
    IDEBUGF(r->debug, "Unsupported HTTP %s request", r->verb);
    r->parser = NULL;
    return 501;
  }
  if (_run_out(r))
    return 100;
  return 0;
}

/* A special content parser that rejects any content, used when a Content-Type: 0 header was
 * received.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static int http_request_reject_content(struct http_request *r)
{
  if (r->request_header.content_length != CONTENT_LENGTH_UNKNOWN)
    IDEBUGF(r->debug, "Malformed HTTP %s request (Content-Length %"PRIhttp_size_t"): spurious content", r->verb, r->request_header.content_length);
  else
    IDEBUGF(r->debug, "Malformed HTTP %s request: spurious content", r->verb);
  return 400;
}

/* Returns 1 if a MIME delimiter is skipped, 2 if a MIME close-delimiter is skipped.
 */
static int _skip_mime_boundary(struct http_request *r)
{
  if (!_skip_literal(r, "--") || !_skip_literal(r, r->request_header.content_type.multipart_boundary))
    return 0;
  if (_skip_literal(r, "--") && _skip_crlf(r))
    return 2;
  if (_skip_crlf(r))
    return 1;
  return 0;
}

static int _parse_content_disposition(struct http_request *r, struct mime_content_disposition *cd)
{
  size_t n = _parse_token(r, cd->type, sizeof cd->type);
  if (n == 0)
    return 0;
  if (n >= sizeof cd->type) {
    WARNF("HTTP Content-Disposition type truncated: %s", alloca_str_toprint(cd->type));
    return 0;
  }
  while (_skip_optional_space(r) && _skip_literal(r, ";") && _skip_optional_space(r)) {
    char *start = r->cursor;
    if (_skip_literal(r, "filename=")) {
      size_t n = _parse_token_or_quoted_string(r, cd->filename, sizeof cd->filename);
      if (n == 0)
	return 0;
      if (n >= sizeof cd->filename) {
	WARNF("HTTP Content-Disposition filename truncated: %s", alloca_str_toprint(cd->filename));
	return 0;
      }
      continue;
    }
    r->cursor = start;
    if (_skip_literal(r, "name=")) {
      size_t n = _parse_token_or_quoted_string(r, cd->name, sizeof cd->name);
      if (n == 0)
	return 0;
      if (n >= sizeof cd->name) {
	WARNF("HTTP Content-Disposition name truncated: %s", alloca_str_toprint(cd->name));
	return 0;
      }
      continue;
    }
    r->cursor = start;
    if (_skip_literal(r, "size=")) {
      if (!_parse_http_size_t(r, &cd->size))
	goto malformed;
      continue;
    }
    r->cursor = start;
    if (_skip_literal(r, "creation-date=")) {
      if (!_parse_quoted_rfc822_time(r, &cd->creation_date))
	goto malformed;
      continue;
    }
    r->cursor = start;
    if (_skip_literal(r, "modification-date=")) {
      if (!_parse_quoted_rfc822_time(r, &cd->modification_date))
	goto malformed;
      continue;
    }
    r->cursor = start;
    if (_skip_literal(r, "read-date=")) {
      if (!_parse_quoted_rfc822_time(r, &cd->read_date))
	goto malformed;
      continue;
    }
    r->cursor = start;
    struct substring param;
    if (_skip_token(r, &param) && _skip_literal(r, "=") && _parse_token_or_quoted_string(r, NULL, 0)) {
      IDEBUGF(r->debug, "Skipping HTTP Content-Disposition parameter: %s", alloca_substring_toprint(param));
      continue;
    }
malformed:
    WARNF("Malformed HTTP Content-Disposition: %s", alloca_toprint(50, r->cursor, r->end - r->cursor));
    return 0;
  }
  return 1;
}

#define _HANDLER_RESULT(result) do { \
    if (r->phase != RECEIVE) \
      return 1; \
    if (result) { \
      assert((result) >= 400); \
      assert((result) < 600); \
      return (result); \
    } \
  } while (0)
#define _INVOKE_HANDLER_VOID(FUNC) do { \
    if (r->form_data.FUNC) { \
      IDEBUGF(r->debug, #FUNC "()"); \
      int result = r->form_data.FUNC(r); \
      _HANDLER_RESULT(result); \
    } \
  } while (0)
#define _INVOKE_HANDLER_BUF_LEN(FUNC, START, END) do { \
    if (r->form_data.FUNC && (START) != (END)) { \
      IDEBUGF(r->debug, #FUNC "(%s length=%zu)", alloca_toprint(50, (START), (END) - (START)), (END) - (START)); \
      int result = r->form_data.FUNC(r, (START), (END) - (START)); \
      _HANDLER_RESULT(result); \
    } \
  } while (0)

static int http_request_form_data_start_part(struct http_request *r, int b)
{
  switch (r->form_data_state) {
    case BODY:
      if (   r->part_header.content_length != CONTENT_LENGTH_UNKNOWN
	  && r->part_body_length != r->part_header.content_length
      ) {
	WARNF("HTTP multipart part body length (%"PRIhttp_size_t") does not match Content-Length header (%"PRIhttp_size_t")",
	      r->part_body_length,
	      r->part_header.content_length
	    );
      }
      // fall through...
    case HEADER:
      _INVOKE_HANDLER_VOID(handle_mime_part_end);
      break;
    default:
      break;
  }
  if (b == 1) {
    r->form_data_state = HEADER;
    bzero(&r->part_header, sizeof r->part_header);
    r->part_body_length = 0;
    r->part_header.content_length = CONTENT_LENGTH_UNKNOWN;
    _INVOKE_HANDLER_VOID(handle_mime_part_start);
  } else
    r->form_data_state = EPILOGUE;
  return 0;
}

/* If parsing completes (ie, parsed to end of epilogue), then sets r->parser to NULL and returns 0,
 * so this function will not be called again.  If parsing cannot complete due to running out of
 * data, returns 100, so this function will not be called again until more data has been read.
 * Returns a 4nn or 5nn HTTP result code if parsing fails.  Returns -1 if an unexpected error
 * occurs.
 *
 * NOTE: No support for nested/mixed parts, as that would considerably complicate the parser.  If
 * the need arises in future, we will deal with it then.  In the meantime, we will have something
 * that meets our immediate needs for Rhizome Direct and the RESTful API.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static int http_request_parse_body_form_data(struct http_request *r)
{
  DEBUG_DUMP_PARSER(r);
  int at_start = 0;
  switch (r->form_data_state) {
    case START:
      DEBUGF(http_server, "START");
      // The logic here allows for a missing initial CRLF before the first boundary line.
      at_start = 1;
      r->form_data_state = PREAMBLE;
      // fall through
    case PREAMBLE: {
	DEBUGF(http_server, "PREAMBLE");
	char *start = r->parsed;
	while (at_start || _skip_to_crlf(r)) {
	  char *end_preamble = r->cursor;
	  int b;
	  if ((at_start || _skip_crlf(r)) && (b = _skip_mime_boundary(r))) {
	    assert(end_preamble >= r->parsed);
	    _INVOKE_HANDLER_BUF_LEN(handle_mime_preamble, start, end_preamble);
	    _rewind_crlf(r);
	    _commit(r);
	    return http_request_form_data_start_part(r, b);
	  }
	  if (!at_start) {
	    r->cursor = end_preamble;
	    _skip_any(r);
	  }
	  at_start = 0;
	}
	if (_end_of_content(r)) {
	  IDEBUGF(r->debug, "Malformed HTTP %s form data: missing first boundary", r->verb);
	  return 400;
	}
	_rewind_optional_cr(r);
	_commit(r);
	assert(r->parsed >= start);
	_INVOKE_HANDLER_BUF_LEN(handle_mime_preamble, start, r->parsed);
      }
      return 100; // need more data
    case HEADER: {
	DEBUGF(http_server, "HEADER");
	// If not at a CRLF, then we are skipping through an over-long header that didn't
	// fit into the buffer.  Just discard bytes up to the next CRLF.
	if (!_skip_crlf(r)) {
	  _skip_to_crlf(r); // advance to next CRLF or end of buffer
	  _rewind_optional_cr(r); // don't skip a CR at end of buffer (it might be part of a half-received CRLF)
	  assert(r->cursor > r->parsed);
	  IDEBUGF(r->debug, "skipping %zu header bytes", r->cursor - r->parsed);
	  _commit(r);
	  return 0;
	}
	char *const sol = r->cursor;
	// A blank line finishes the headers.  The CRLF does not form part of the body.
	if (_skip_crlf(r)) {
	  _commit(r);
	  if (r->form_data.handle_mime_part_header) {
	    IDEBUGF(r->debug, "handle_mime_part_header(Content-Length: %"PRIhttp_size_t", Content-Type: %s, Content-Disposition: %s)",
		  r->part_header.content_length,
		  alloca_mime_content_type(&r->part_header.content_type),
		  alloca_mime_content_disposition(&r->part_header.content_disposition)
		);
	    int result = r->form_data.handle_mime_part_header(r, &r->part_header);
	    _HANDLER_RESULT(result); \
	  }
	  r->form_data_state = BODY;
	  return 0;
	}
	if (_run_out(r))
	  return 100; // read more and try again
	r->cursor = sol;
	// A mime boundary technically should not occur in the middle of the headers, but if it
	// does, treat it as a zero-length body.
	int b;
	if ((b = _skip_mime_boundary(r))) {
	  _rewind_crlf(r);
	  _commit(r);
	  // A boundary in the middle of headers finishes the current part and starts a new part.
	  // An end boundary terminates the current part and starts the epilogue.
	  return http_request_form_data_start_part(r, b);
	}
	if (_run_out(r))
	  return 100; // read more and try again
	r->cursor = sol;
	struct substring label;
	if (_skip_token(r, &label) && _skip_literal(r, ":") && _skip_optional_space(r)) {
	  size_t labellen = label.end - label.start;
	  char labelstr[labellen + 1];
	  strncpy(labelstr, label.start, labellen)[labellen] = '\0';
	  str_tolower_inplace(labelstr);
	  if (strcmp(labelstr, "content-length") == 0) {
	    if (r->part_header.content_length != CONTENT_LENGTH_UNKNOWN) {
	      IDEBUGF(r->debug, "Skipping duplicate HTTP multipart header %s", alloca_toprint(50, sol, r->end - sol));
	      return 400;
	    }
	    http_size_t length;
	    if (_parse_http_size_t(r, &length) && _skip_optional_space(r) && _skip_crlf(r)) {
	      _rewind_crlf(r);
	      _commit(r);
	      r->part_header.content_length = length;
	      IDEBUGF(r->debug, "Parsed HTTP multipart header Content-Length: %"PRIhttp_size_t, r->part_header.content_length);
	      return 0;
	    }
	  }
	  else if (strcmp(labelstr, "content-type") == 0) {
	    if (r->part_header.content_type.type[0]) {
	      IDEBUGF(r->debug, "Skipping duplicate HTTP multipart header %s", alloca_toprint(50, sol, r->end - sol));
	      return 400;
	    }
	    if (_parse_content_type(r, &r->part_header.content_type) && _skip_optional_space(r) && _skip_crlf(r)) {
	      _rewind_crlf(r);
	      _commit(r);
	      IDEBUGF(r->debug, "Parsed HTTP multipart header Content-Type: %s", alloca_mime_content_type(&r->part_header.content_type));
	      return 0;
	    }
	  }
	  else if (strcmp(labelstr, "content-disposition") == 0) {
	    if (r->part_header.content_disposition.type[0]) {
	      IDEBUGF(r->debug, "Skipping duplicate HTTP multipart header %s", alloca_toprint(50, sol, r->end - sol));
	      return 400;
	    }
	    if (_parse_content_disposition(r, &r->part_header.content_disposition) && _skip_optional_space(r) && _skip_crlf(r)) {
	      _rewind_crlf(r);
	      _commit(r);
	      IDEBUGF(r->debug, "Parsed HTTP multipart header Content-Disposition: %s", alloca_mime_content_disposition(&r->part_header.content_disposition));
	      return 0;
	    }
	  }
	  else if (_skip_to_crlf(r)) {
	    _commit(r);
	    IDEBUGF(r->debug, "Skip HTTP multipart header: %s", alloca_toprint(50, sol, r->parsed - sol));
	    return 0;
	  }
	}
	r->cursor = sol;
	if (_buffer_full(r)) {
	  // The line does not start with "Token:" and is too long to fit into the buffer.  Start
	  // skipping it.
	  WARNF("Skipping unterminated HTTP MIME header %s", alloca_toprint(50, sol, r->end - sol));
	  r->cursor = r->end;
	  _rewind_optional_cr(r);
	  IDEBUGF(r->debug, "skipping %zu header bytes", r->cursor - r->parsed);
	  _commit(r);
	  return 0;
	}
	if (_run_out(r))
	  return 100; // read more and try again
	IDEBUGF(r->debug, "Malformed HTTP %s form data part: invalid header %s", r->verb, alloca_toprint(50, sol, r->end - sol));
	DEBUG_DUMP_PARSER(r);
      }
      return 400;
    case BODY:
      DEBUGF(http_server, "BODY");
      char *start = r->parsed;
      while (_skip_to_crlf(r)) {
	int b;
	char *end_body = r->cursor;
	_skip_crlf(r);
	if ((b = _skip_mime_boundary(r))) {
	  _rewind_crlf(r);
	  _commit(r);
	  assert(end_body >= start);
	  r->part_body_length += end_body - start;
	  // Note: the handler function may modify the data in-place (eg, Rhizome does encryption
	  // that way).
	  _INVOKE_HANDLER_BUF_LEN(handle_mime_body, start, end_body); // excluding CRLF at end
	  return http_request_form_data_start_part(r, b);
	}
      }
      if (_end_of_content(r)) {
	IDEBUGF(r->debug, "Malformed HTTP %s form data part: missing end boundary", r->verb);
	return 400;
      }
      _rewind_optional_cr(r);
      _commit(r);
      assert(r->parsed >= start);
      r->part_body_length += r->parsed - start;
	// Note: the handler function may modify the data in-place
      _INVOKE_HANDLER_BUF_LEN(handle_mime_body, start, r->parsed);
      return 100; // need more data
  case EPILOGUE:
    DEBUGF(http_server, "EPILOGUE");
    r->cursor = r->end;
    assert(r->cursor >= r->parsed);
    _INVOKE_HANDLER_BUF_LEN(handle_mime_epilogue, r->parsed, r->cursor);
    _commit(r);
    assert(_run_out(r));
    if (_end_of_content(r))
      return 0; // done
    return 100; // need more data
  default:
    FATALF("form_data_state = %d", r->form_data_state);
  }
  abort(); // not reached
}

static ssize_t http_request_read(struct http_request *r, char *buf, size_t len)
{
  sigPipeFlag = 0;
  ssize_t bytes = read_nonblock(r->alarm.poll.fd, buf, len);
  if (bytes == -1) {
    IDEBUG(r->debug, "HTTP socket read error, closing connection");
    http_request_finalise(r);
    return -1;
  }
  if (sigPipeFlag) {
    IDEBUG(r->debug, "Received SIGPIPE on HTTP socket read, closing connection");
    http_request_finalise(r);
    return -1;
  }
  return bytes;
}

static void http_request_receive(struct http_request *r)
{
  IN();
  assert(r->phase == RECEIVE);
  const char *const bufend = r->buffer + sizeof r->buffer;
  assert(r->end <= bufend);
  assert(r->parsed >= r->received);
  assert(r->parsed <= r->end);
  // If the end of content falls within the buffer, then there is no need to make any more room,
  // just read up to the end of content.  Otherwise, If buffer is running short on unused space,
  // shift existing content in buffer down to make more room if possible.
  size_t room = bufend - r->end;
  if (r->request_content_remaining != CONTENT_LENGTH_UNKNOWN && room > r->request_content_remaining)
    room = r->request_content_remaining;
  else {
    size_t spare = r->parsed - r->received;
    if (spare && (room < 128 || (room < 1024 && spare >= 32))) {
      size_t unparsed = r->end - r->parsed;
      memmove((char *)r->received, r->parsed, unparsed); // memcpy() does not handle overlapping src and dst
      r->parsed = r->received;
      r->end = r->received + unparsed;
      room = bufend - r->end;
      if (r->request_content_remaining != CONTENT_LENGTH_UNKNOWN && room > r->request_content_remaining)
	room = r->request_content_remaining;
    }
  }
  // If there is no more buffer space, fail the request.
  if (room == 0) {
    IDEBUG(r->debug, "Buffer size reached, reporting overflow");
    http_request_simple_response(r, 431, NULL);
    RETURNVOID;
  }
  // Read up to the end of available buffer space or the end of content, whichever is first.  Read
  // as many bytes as possible into the unused buffer space.  Any read error closes the connection
  // without any response.
  assert(room > 0);
  if (r->request_content_remaining != CONTENT_LENGTH_UNKNOWN)
    assert(room <= r->request_content_remaining);
  ssize_t bytes = http_request_read(r, (char *)r->end, room);
  if (bytes == -1)
    RETURNVOID;
  assert((size_t) bytes <= room);
  // If no data was read, then just return to polling.  Don't drop the connection on an empty read,
  // because that drops connections when they shouldn't, including during testing.  The inactivity
  // timeout will drop inactive connections.
  if (bytes == 0)
    RETURNVOID;
  r->end += (size_t) bytes;
  if (r->request_content_remaining != CONTENT_LENGTH_UNKNOWN)
    r->request_content_remaining -= (size_t) bytes;
  // We got some data, so reset the inactivity timer and invoke the parsing state machine to process
  // it.  The state machine invokes the caller-supplied callback functions.
  http_request_set_idle_timeout(r);
  // Parse the unparsed and received data.
  while (r->phase == RECEIVE) {
    int result;
    _rewind(r);
    DEBUG_DUMP_PARSER(r);
    if (_end_of_content(r)) {
      if (r->handle_content_end)
	result = r->handle_content_end(r);
      else {
	IDEBUG(r->debug, "Internal failure parsing HTTP request: no end-of-content function set");
	result = 500;
      }
    } else {
      HTTP_REQUEST_PARSER *oldparser = r->parser;
      const char *oldparsed = r->parsed;
      if (r->parser == NULL) {
	IDEBUGF(r->debug, "No HTTP parser function set -- skipping %zu bytes", (size_t)(r->end - r->cursor));
	_skip_all(r);
	_commit(r);
	result = 0;
      } else {
	result = r->parser(r);
	assert(r->parsed >= oldparsed);
      }
      if (r->phase != RECEIVE)
	break;
      if (result == 100)
	RETURNVOID; // needs more data; poll again
      if (result == 0 && r->parsed == oldparsed && r->parser == oldparser) {
	IDEBUG(r->debug, "Internal failure parsing HTTP request: parser function did not advance");
	DEBUG_DUMP_PARSER(r);
	result = 500;
      }
    }
    if (result >= 200 && result < 600) {
      assert(r->response.result_code == 0 || r->response.result_code == result);
      r->response.result_code = result;
    } else if (result) {
      IDEBUGF(r->debug, "Internal failure parsing HTTP request: invalid result=%d", result);
      r->response.result_code = 500;
    }
    if (r->response.result_code)
      break;
    if (result == -1) {
      IDEBUG(r->debug, "Unrecoverable error parsing HTTP request, closing connection");
      http_request_finalise(r);
      RETURNVOID;
    }
  }
  if (r->phase != RECEIVE) {
    assert(r->response.result_code != 0);
    RETURNVOID;
  }
  if (r->response.result_code == 0) {
    WHY("No HTTP response set, using 500 Server Error");
    r->response.result_code = 500;
  }
  http_request_start_response(r);
  OUT();
}

/* Write the current contents of the response buffer to the HTTP socket.  When no more bytes can be
 * written, return so that socket polling can continue.  Once all bytes are sent, if there is a
 * content generator function and the request is not paused, invoke it to put more content in the
 * response buffer, and write that content.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static void http_request_send_response(struct http_request *r)
{
  IN();
  assert(r->phase == TRANSMIT);
  while (1) {
    if (r->response_length != CONTENT_LENGTH_UNKNOWN)
      assert(r->response_sent <= r->response_length);
    assert(r->response_buffer_sent <= r->response_buffer_length);
    uint64_t remaining = CONTENT_LENGTH_UNKNOWN;
    size_t unsent = r->response_buffer_length - r->response_buffer_sent;
    IDEBUGF(r->debug, "HTTP response buffer contains %zu bytes unsent", unsent);
    if (r->response_length != CONTENT_LENGTH_UNKNOWN) {
      remaining = r->response_length - r->response_sent;
      assert(unsent <= remaining);
      assert(r->response_buffer_need <= remaining);
      if (remaining == 0)
	break; // no more to generate
    }
    if (unsent == 0)
      r->response_buffer_sent = r->response_buffer_length = 0;
    if (r->phase == PAUSE) {
      // If the generator has paused the request, keep polling i/o for output until the response
      // buffer is all sent, then stop polling i/o.
      if (unsent == 0) {
	unwatch(&r->alarm);
	RETURNVOID; // nothing left to send
      }
    } else if (r->response.content_generator) {
      // If the buffer is smaller than the content generator needs, and it contains no unsent
      // content, then allocate a larger buffer.
      if (r->response_buffer_need > r->response_buffer_size && unsent == 0) {
	if (http_request_set_response_bufsize(r, r->response_buffer_need) == -1) {
	  WHYF("HTTP response truncated at offset=%"PRIhttp_size_t" due to insufficient buffer space",
	      r->response_sent);
	  http_request_finalise(r);
	  RETURNVOID;
	}
      }
      // If there are some sent bytes at the start of the buffer and only a few unsent bytes, then
      // move the unsent content to the start of the buffer to make more room.
      if (r->response_buffer_sent > 0 && unsent < 128) {
	memmove(r->response_buffer, r->response_buffer + r->response_buffer_sent, unsent);
	r->response_buffer_length -= r->response_buffer_sent;
	r->response_buffer_sent = 0;
      }
      // If there is enough unfilled room at the end of the buffer, then fill the buffer with some
      // more content.
      assert(r->response_buffer_length <= r->response_buffer_size);
      size_t unfilled = r->response_buffer_size - r->response_buffer_length;
      if (unfilled > 0 && unfilled >= r->response_buffer_need) {
	// The content generator must fill or partly fill the part of the buffer we indicate and
	// return the number of bytes appended.  If it returns zero, it means it has no more
	// content (EOF), and must not be called again.  If the return value exceeds the buffer size
	// we supply, it gives the amount of free space the generator needs in order to append; the
	// generator will not append any bytes until that much free space is available.  If returns
	// -1, it means an unrecoverable error occurred, and the generator must not be called again.
	struct http_content_generator_result result;
	bzero(&result, sizeof result);
	int ret = r->response.content_generator(r, (unsigned char *) r->response_buffer + r->response_buffer_length, unfilled, &result);
	if (ret == -1) {
	  WHY("Content generation error, closing connection");
	  http_request_finalise(r);
	  RETURNVOID;
	}
	assert(result.generated <= unfilled);
	r->response_buffer_length += result.generated;
	r->response_buffer_need = result.need;
	if (result.generated == 0 && result.need <= unfilled && r->phase != PAUSE) {
	  WHYF("HTTP response generator produced no content at offset %"PRIhttp_size_t" (ret=%d)", r->response_sent, ret);
	  http_request_finalise(r);
	  RETURNVOID;
	}
	IDEBUGF(r->debug, "Generated HTTP %zu bytes of content, need %zu bytes of buffer (ret=%d)", result.generated, result.need, ret);
	if (r->phase != PAUSE && ret == 0)
	  r->response.content_generator = NULL; // ensure we never invoke again
	continue;
      }
    } else if (remaining != CONTENT_LENGTH_UNKNOWN && unsent < remaining) {
      WHYF("HTTP response generator finished prematurely at offset %"PRIhttp_size_t"/%"PRIhttp_size_t" (%"PRIhttp_size_t" bytes remaining)",
	  r->response_sent, r->response_length, remaining);
      http_request_finalise(r);
      RETURNVOID;
    } else if (unsent == 0)
      break;
    assert(unsent > 0);
    if (remaining != CONTENT_LENGTH_UNKNOWN && unsent > remaining) {
      WHYF("HTTP response overruns Content-Length (%"PRIhttp_size_t") by %"PRIhttp_size_t" bytes -- truncating",
	  r->response_length, unsent - remaining);
      unsent = remaining;
    }
    sigPipeFlag = 0;
    ssize_t written = write_nonblock(r->alarm.poll.fd, r->response_buffer + r->response_buffer_sent, unsent);
    if (written == -1) {
      IDEBUG(r->debug, "HTTP socket write error, closing connection");
      http_request_finalise(r);
      RETURNVOID;
    }
    if (sigPipeFlag) {
      IDEBUG(r->debug, "Received SIGPIPE on HTTP socket write, closing connection");
      http_request_finalise(r);
      RETURNVOID;
    }
    // If we wrote nothing, go back to polling.
    if (written == 0)
      RETURNVOID;
    r->response_sent += (size_t) written;
    assert(r->response_sent <= r->response_length);
    IDEBUGF(r->debug, "Wrote %zu bytes to HTTP socket, total %"PRIhttp_size_t", remaining=%"PRIhttp_size_t,
	  (size_t) written, r->response_sent, r->response_length - r->response_sent);
    IDEBUGF(r->debug, "%s", alloca_toprint(-1, r->response_buffer + r->response_buffer_sent, unsent));
    r->response_buffer_sent += (size_t) written;
    assert(r->response_buffer_sent <= r->response_buffer_length);
    // Reset inactivity timer.
    if (r->phase != PAUSE)
      http_request_set_idle_timeout(r);
    // If we wrote less than we tried, then go back to polling, otherwise keep generating content.
    if ((size_t) written < (size_t) unsent)
      RETURNVOID;
  }
  IDEBUG(r->debug, "Done, closing connection");
  http_request_finalise(r);
  OUT();
}

static void _http_request_start_transmitting(struct http_request *r)
{
  assert(r->phase == RECEIVE || r->phase == PAUSE);
  r->phase = TRANSMIT;
  r->alarm.poll.events = POLLOUT;
  watch(&r->alarm);
  http_request_set_idle_timeout(r);
}

/* Generator functions can call this method to "pause" processing of the response until a given real
 * time.  Once paused, all existing buffered output will be sent but the generator function will not
 * be called until the pause time has been reached.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
void http_request_pause_response(struct http_request *r, time_ms_t until)
{
  IDEBUGF(r->debug, "Pausing response for %.3f sec", (double)(until - gettime_ms()) / 1000.0);
  assert(r->phase == TRANSMIT);
  r->phase = PAUSE;
  r->alarm.alarm = until;
  r->alarm.deadline = until + r->idle_timeout;
  unschedule(&r->alarm);
  schedule(&r->alarm);
}

/* This method can be called to "un-pause" a paused response.  If the response is not currently
 * paused, then this has no effect.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
void http_request_resume_response(struct http_request *r)
{
  if (r->phase == PAUSE) {
    IDEBUGF(r->debug, "Resuming paused response for %.3f sec early", (double)(r->alarm.alarm - gettime_ms()) / 1000.0);
    _http_request_start_transmitting(r);
  }
}

static void http_server_poll(struct sched_ent *alarm)
{
  struct http_request *r = (struct http_request *) alarm;
  strbuf_sprintf(&log_context, "httpd/%u", r->uuid);
  if (alarm->poll.revents == 0) {
    // Called due to alarm: if paused then resume polling for output, otherwise the inactivity
    // (idle) timeout has occurred, so terminate the response.
    if (r->phase == PAUSE) {
      http_request_resume_response(r);
    } else {
      IDEBUGF(r->debug, "Timeout, closing connection");
      http_request_finalise(r);
    }
  }
  else if (alarm->poll.revents & (POLLHUP | POLLERR)) {
    IDEBUGF(r->debug, "Poll error (%s), closing connection", alloca_poll_events(alarm->poll.revents));
    http_request_finalise(r);
  }
  else if (alarm->poll.revents & POLLIN) {
    assert((alarm->poll.revents & POLLOUT) == 0);
    http_request_receive(r); // could change the phase to TRANSMIT or DONE
  }
  else if (alarm->poll.revents & POLLOUT) {
    assert((alarm->poll.revents & POLLIN) == 0);
    http_request_send_response(r); // could change the phase to PAUSE or DONE
  }
  else
    abort(); // should not be any other POLL bits set
  // Any of the above calls could change the phase to DONE.
  if (r->phase == DONE && r->free)
    r->free(r); // after this, *r is no longer valid
}

/* Copy the array of byte ranges, closing it (converting all ranges to CLOSED) using the supplied
 * resource length.  If a range is not satisfiable it is omitted from 'dst'.  Returns the number of
 * closed ranges written to 'dst'.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
unsigned http_range_close(struct http_range *dst, const struct http_range *src, unsigned nranges, http_size_t resource_length)
{
  unsigned i;
  unsigned ndst = 0;
  for (i = 0; i != nranges; ++i) {
    http_size_t first = 0;
    http_size_t last = resource_length - 1;
    const struct http_range *range = &src[i];
    switch (range->type) {
      case CLOSED:
	last = range->last < resource_length ? range->last : resource_length - 1;
      case OPEN:
	first = range->first < resource_length ? range->first : resource_length;
	break;
      case SUFFIX:
	first = range->last < resource_length ? resource_length - range->last : 0;
	break;
      default:
	abort(); // not reached
    }
    if (first <= last)
      dst[ndst++] = (struct http_range){ .type = CLOSED, .first=first, .last=last };
  }
  return ndst;
}

/* Return the total number of bytes represented by the given ranges which must all be CLOSED and
 * valid.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
http_size_t http_range_bytes(const struct http_range *range, unsigned nranges)
{
  http_size_t bytes = 0;
  unsigned i;
  for (i = 0; i != nranges; ++i) {
    assert(range[i].type == CLOSED);
    assert(range[i].last >= range[i].first);
    bytes += range[i].last - range[i].first + 1;
  }
  return bytes;
}

/* Return appropriate message for HTTP response codes, both known and unknown.
 */
static const char *httpResultString(int response_code)
{
  switch (response_code) {
  case 200: return "OK";
  case 201: return "Created";
  case 204: return "No Content";
  case 206: return "Partial Content";
  case 400: return "Bad Request";
  case 401: return "Unauthorized";
  case 403: return "Forbidden";
  case 404: return "Not Found";
  case 405: return "Method Not Allowed";
  case 408: return "Request Timeout";
  case 409: return "Conflict";
  case 411: return "Length Required";
  case 414: return "Request-URI Too Long";
  case 415: return "Unsupported Media Type";
  case 416: return "Requested Range Not Satisfiable";
  case 431: return "Request Header Fields Too Large";
  case 500: return "Internal Server Error";
  case 501: return "Not Implemented";
  default:  return (response_code <= 4) ? "Unknown status code" : "A suffusion of yellow";
  }
}

static strbuf strbuf_status_body(strbuf sb, struct http_response *hr, const char *message)
{
  if (   hr->header.content_type == CONTENT_TYPE_TEXT
      || (hr->header.content_type && strcmp(hr->header.content_type, CONTENT_TYPE_TEXT) == 0)
  ) {
    hr->header.content_type = CONTENT_TYPE_TEXT;
    strbuf_sprintf(sb, "%03u %s", hr->result_code, message);
    unsigned i;
    for (i = 0; i < NELS(hr->result_extra); ++i)
      if (hr->result_extra[i].label) {
	strbuf_puts(sb, "\r\n");
	strbuf_puts(sb, hr->result_extra[i].label);
	strbuf_puts(sb, "=");
	strbuf_json_atom_as_text(sb, &hr->result_extra[i].value);
      }
    strbuf_puts(sb, "\r\n");
  }
  else if (    hr->header.content_type == CONTENT_TYPE_JSON
           || (hr->header.content_type && strcmp(hr->header.content_type, CONTENT_TYPE_JSON) == 0)
  ) {
    hr->header.content_type = CONTENT_TYPE_JSON;
    strbuf_sprintf(sb, "{\n \"http_status_code\": %u,\n \"http_status_message\": ", hr->result_code);
    strbuf_json_string(sb, message);
    unsigned i;
    for (i = 0; i < NELS(hr->result_extra); ++i)
      if (hr->result_extra[i].label) {
	strbuf_puts(sb, ",\n ");
	strbuf_json_string(sb, hr->result_extra[i].label);
	strbuf_puts(sb, ": ");
	strbuf_json_atom(sb, &hr->result_extra[i].value);
      }
    strbuf_puts(sb, "\n}");
  }
  else {
    hr->header.content_type = CONTENT_TYPE_HTML;
    strbuf_sprintf(sb, "<html>\n<h1>%03u %s</h1>", hr->result_code, message);
    unsigned i;
    for (i = 0; i < NELS(hr->result_extra); ++i)
      if (hr->result_extra[i].label) {
	strbuf_puts(sb, "\n<dl><dt>");
	strbuf_html_escape(sb, hr->result_extra[i].label, strlen(hr->result_extra[i].label));
	strbuf_puts(sb, "</dt><dd>");
	strbuf_json_atom_as_html(sb, &hr->result_extra[i].value);
	strbuf_puts(sb, "</dd></dl>");
      }
    strbuf_puts(sb, "\n</html>");
  }
  return sb;
}

/* Render the HTTP response into the current response buffer.  Return 1 if it fits, 0 if it does
 * not.  The buffer response_pointer may be NULL, in which case no response is rendered, but the
 * content_length is still computed
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static int _render_response(struct http_request *r)
{
  struct http_response hr = r->response;
  assert(hr.result_code >= 100);
  assert(hr.result_code < 600);
  // Status code 401 must be accompanied by a WWW-Authenticate header.
  if (hr.result_code == 401)
    assert(hr.header.www_authenticate.scheme != NOAUTH);
  const char *result_string = httpResultString(hr.result_code);
  strbuf sb = strbuf_local(r->response_buffer, r->response_buffer_size);
  // Cannot specify both static (pre-rendered) content AND generated content.
  assert(!(hr.content && hr.content_generator));
  if (hr.content || hr.content_generator) {
    // With static (pre-rendered) content, the content length is mandatory (so we know how much data
    // follows the 'hr.content' pointer.  Generated content will generally not send a Content-Length
    // header, nor send partial content, but they might.
    if (hr.content)
      assert(hr.header.content_length != CONTENT_LENGTH_UNKNOWN);
    // Ensure that all partial content fields are consistent.  If content length or resource length
    // are unknown, there can be no range field.
    if (   hr.header.content_length != CONTENT_LENGTH_UNKNOWN
	&& hr.header.resource_length != CONTENT_LENGTH_UNKNOWN
    ) {
      assert(hr.header.content_length <= hr.header.resource_length);
      assert(hr.header.content_range_start + hr.header.content_length <= hr.header.resource_length);
    } else {
      assert(hr.header.content_range_start == 0);
    }
    // Convert a 200 status code into 206 if only partial content is being sent.  This saves page
    // handlers having to decide between 200 (OK) and 206 (Partial Content), they can just set the
    // content and resource length fields and pass 200 to http_request_response_static(), and this
    // logic will change it to 206 if appropriate.
    if (   hr.header.content_length != CONTENT_LENGTH_UNKNOWN
	&& hr.header.resource_length != CONTENT_LENGTH_UNKNOWN
	&& hr.header.content_length > 0
	&& hr.header.content_length < hr.header.resource_length
    ) {
      if (hr.result_code == 200)
	hr.result_code = 206; // Partial Content
    }
  } else {
    // If no content is supplied at all, then render a standard, short body based solely on result
    // code, consistent with the response Content-Type if already set (HTML if not set).
    assert(hr.header.content_length == CONTENT_LENGTH_UNKNOWN);
    assert(hr.header.resource_length == CONTENT_LENGTH_UNKNOWN);
    assert(hr.header.content_range_start == 0);
    assert(hr.result_code != 206);
    strbuf cb;
    STRBUF_ALLOCA_FIT(cb, 40 + strlen(result_string), (strbuf_status_body(cb, &hr, result_string)));
    hr.content = strbuf_str(cb);
    hr.header.content_length = strbuf_len(cb);
    hr.header.resource_length = hr.header.content_length;
    hr.header.content_range_start = 0;
  }
  assert(hr.header.content_type != NULL);
  assert(hr.header.content_type[0]);
  strbuf_sprintf(sb, "HTTP/1.0 %03u %s\r\n", hr.result_code, result_string);
  strbuf_sprintf(sb, "Content-Type: %s", hr.header.content_type);
  if (hr.header.boundary) {
    strbuf_puts(sb, "; boundary=");
    if (strchr(hr.header.boundary, '"') || strchr(hr.header.boundary, '\\'))
      strbuf_append_quoted_string(sb, hr.header.boundary);
    else
      strbuf_puts(sb, hr.header.boundary);
  }
  strbuf_puts(sb, "\r\n");
  if (hr.result_code == 206) {
    // Must only use result code 206 (Partial Content) if the content is in fact less than the whole
    // resource length.
    assert(hr.header.content_length != CONTENT_LENGTH_UNKNOWN);
    assert(hr.header.resource_length != CONTENT_LENGTH_UNKNOWN);
    assert(hr.header.content_length > 0);
    assert(hr.header.content_length < hr.header.resource_length);
    strbuf_sprintf(sb,
	  "Content-Range: bytes %"PRIhttp_size_t"-%"PRIhttp_size_t"/%"PRIhttp_size_t"\r\n",
	  hr.header.content_range_start,
	  hr.header.content_range_start + hr.header.content_length - 1,
	  hr.header.resource_length
	);
  }
  if (hr.header.content_length != CONTENT_LENGTH_UNKNOWN)
    strbuf_sprintf(sb, "Content-Length: %"PRIhttp_size_t"\r\n", hr.header.content_length);
  
  if (hr.header.allow_origin)
    strbuf_sprintf(sb, "Access-Control-Allow-Origin: %s\r\n", hr.header.allow_origin);
  if (hr.header.allow_methods)
    strbuf_sprintf(sb, "Access-Control-Allow-Methods: %s\r\n", hr.header.allow_methods);
  if (hr.header.allow_headers)
    strbuf_sprintf(sb, "Access-Control-Allow-Headers: %s\r\n", hr.header.allow_headers);
  
  const char *scheme = NULL;
  switch (hr.header.www_authenticate.scheme) {
    case NOAUTH: break;
    case BASIC: scheme = "Basic"; break;
  }
  if (scheme) {
    assert(hr.result_code == 401);
    strbuf_sprintf(sb, "WWW-Authenticate: %s realm=", scheme);
    strbuf_append_quoted_string(sb, hr.header.www_authenticate.realm);
    strbuf_puts(sb, "\r\n");
  }
  if (r->render_extra_headers)
    r->render_extra_headers(r, sb);
  assert(strcmp(strbuf_substr(sb, -2), "\r\n") == 0);
  strbuf_puts(sb, "\r\n");
  if (hr.header.content_length != CONTENT_LENGTH_UNKNOWN)
    r->response_length = strbuf_count(sb) + hr.header.content_length;
  else
    r->response_length = CONTENT_LENGTH_UNKNOWN;
  r->response_buffer_need = strbuf_count(sb) + 1; // the header and the strbuf terminating NUL
  if (hr.content) {
    assert(r->response_length != CONTENT_LENGTH_UNKNOWN);
    if (r->response_buffer_need < r->response_length)
      r->response_buffer_need = r->response_length;
  } else
    assert(hr.content_generator);
  if (r->response_buffer_size < r->response_buffer_need)
    return 0; // doesn't fit
  assert(!strbuf_overrun(sb));
  if (hr.content) {
    bcopy(hr.content, strbuf_end(sb), hr.header.content_length);
    r->response_buffer_length = r->response_length;
  } else {
    r->response_buffer_length = strbuf_count(sb);
  }
  r->response_buffer_sent = 0;
  return 1;
}

/* Returns with the length of the rendered response in r->response_length.  If the rendered response
 * did not fit into any available buffer, then returns with r->response_buffer == NULL, otherwise
 * r->response_buffer points to the rendered response.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static void http_request_render_response(struct http_request *r)
{
  // If there is no response buffer allocated yet, use the available part of the in-struct buffer.
  http_request_set_response_bufsize(r, 1);
  // Try rendering the response into the existing buffer.  This will discover the length of the
  // rendered headers, so after this step, whether or not the buffer was overrun, we know the total
  // length of the response.
  if (!_render_response(r)) {
    // If the static response did not fit into the existing buffer, then allocate a large buffer
    // from the heap and try rendering again.
    if (http_request_set_response_bufsize(r, r->response_buffer_need) == -1)
      WHY("Cannot render HTTP response, out of memory");
    else if (!_render_response(r))
      FATAL("Re-render of HTTP response overflowed buffer");
  }
}

static size_t http_request_drain(struct http_request *r)
{
  assert(r->phase == RECEIVE);
  char buf[8192];
  size_t drained = 0;
  ssize_t bytes;
  while ((bytes = http_request_read(r, buf, sizeof buf)) != -1 && bytes != 0)
    drained += (size_t) bytes;
  return drained;
}

static void http_request_start_response(struct http_request *r)
{
  IN();
  assert(r->phase == RECEIVE);
  _release_reserved(r);
  if (r->response.content || r->response.content_generator) {
    assert(r->response.header.content_type != NULL);
    assert(r->response.header.content_type[0]);
  }
  // If HTTP responses are disabled (eg, for testing purposes) then skip all response construction
  // and close the connection.
  if (IF_IDEBUG(r->disable_tx)) {
    INFO("HTTP transmit disabled, closing connection");
    http_request_finalise(r);
    RETURNVOID;
  }
  // Drain the rest of the request that has not been received yet (eg, if sending an error response
  // provoked while parsing the early part of a partially-received request).  If a read error
  // occurs, the connection is closed so the phase changes to DONE.
  http_request_drain(r);
  if (r->phase != RECEIVE)
    RETURNVOID;
  // Ensure conformance to HTTP standards.
  if (r->response.result_code == 401 && r->response.header.www_authenticate.scheme == NOAUTH) {
    WHY("HTTP 401 response missing WWW-Authenticate header, sending 500 Server Error instead");
    r->response.result_code = 500;
    r->response.content = NULL;
    r->response.content_generator = NULL;
  }
  // If the response cannot be rendered, then render a 500 Server Error instead.  If that fails,
  // then just close the connection.
  http_request_render_response(r);
  if (r->response_buffer == NULL) {
    WARN("Cannot render HTTP response, sending 500 Server Error instead");
    r->response.result_code = 500;
    r->response.content = NULL;
    r->response.content_generator = NULL;
    http_request_render_response(r);
    if (r->response_buffer == NULL) {
      WHY("Cannot render HTTP 500 Server Error response, closing connection");
      http_request_finalise(r);
      RETURNVOID;
    }
  }
  r->response_buffer_need = 0;
  r->response_sent = 0;
  IDEBUGF(r->debug, "Sending HTTP response: %s", alloca_toprint(160, (const char *)r->response_buffer, r->response_buffer_length));
  _http_request_start_transmitting(r);
  OUT();
}

/* Start sending a static (pre-computed) response back to the client.  The response's Content-Type
 * is set by the 'mime_type' parameter (in the standard format "type/subtype").  The response's
 * content is set from the 'body' and 'bytes' parameters, which need not point to persistent data,
 * ie, the memory pointed to by 'body' is no longer referenced once this function returns.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
void http_request_response_static(struct http_request *r, int result, const char *mime_type, const char *body, uint64_t bytes)
{
  assert(r->phase == RECEIVE);
  assert(mime_type != NULL);
  assert(mime_type[0]);
  r->response.result_code = result;
  r->response.header.content_type = mime_type;
  r->response.header.content_range_start = 0;
  r->response.header.content_length = r->response.header.resource_length = bytes;
  r->response.content = body;
  r->response.content_generator = NULL;
  http_request_start_response(r);
}

void http_request_response_generated(struct http_request *r, int result, const char *mime_type, HTTP_CONTENT_GENERATOR generator)
{
  assert(r->phase == RECEIVE);
  assert(mime_type != NULL);
  assert(mime_type[0]);
  r->response.result_code = result;
  r->response.header.content_type = mime_type;
  r->response.content = NULL;
  r->response.content_generator = generator;
  http_request_start_response(r);
}

/* Start sending a short response back to the client.  The result code must be either a success
 * (2xx), redirection (3xx) or client error (4xx) or server error (5xx) code.  The 'message'
 * argument may be a bare message which is enclosed in an HTML envelope to form the response
 * content, so it may contain HTML markup.  If the 'message' argument is NULL, then the response
 * content is generated automatically from the result code.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
void http_request_simple_response(struct http_request *r, uint16_t result, const char *message)
{
  assert(r->phase == RECEIVE);
  r->response.result_code = result;
  r->response.header.content_range_start = 0;
  strbuf h = NULL;
  if (message)
    STRBUF_ALLOCA_FIT(h, 40 + strlen(message), (strbuf_status_body(h, &r->response, message)));
  if (h) {
    r->response.header.resource_length = r->response.header.content_length = strbuf_len(h);
    r->response.content = strbuf_str(h);
  }
  r->response.content_generator = NULL;
  http_request_start_response(r);
}

int generate_http_content_from_strbuf_chunks(
  struct http_request *r,
  char *buf,
  size_t bufsz,
  struct http_content_generator_result *result,
  HTTP_CONTENT_GENERATOR_STRBUF_CHUNKER *chunker
)
{
  assert(bufsz > 0);
  strbuf b = strbuf_local((char *)buf, bufsz);
  int ret;
  while ((ret = chunker(r, b)) != -1) {
    if (strbuf_overrun(b)) {
      IDEBUGF(r->debug, "overrun by %zu bytes", strbuf_count(b) - strbuf_len(b));
      result->need = strbuf_count(b) + 1 - result->generated;
      break;
    }
    result->generated = strbuf_len(b);
    if (ret == 0)
      break;
  }
  return ret;
}
