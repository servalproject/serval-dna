/*
Serval DNA - HTTP Server
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

#include <assert.h>
#include <inttypes.h>
#include <time.h>
#include "serval.h"
#include "conf.h"
#include "http_server.h"
#include "log.h"
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

static struct profile_total http_server_stats = {
  .name = "http_server_poll",
};

#define DEBUG_DUMP_PARSED(r) do { \
      if (config.debug.httpd) \
	DEBUGF("%s %s HTTP/%u.%u", r->verb ? r->verb : "NULL", alloca_str_toprint(r->path), r->version_major, r->version_minor);\
    } while (0)

#define DEBUG_DUMP_PARSER(r) do { \
      if (config.debug.httpd) \
	DEBUGF("parsed %d %s cursor %d %s end %d remain %"PRIhttp_size_t, \
	    (int)(r->parsed - r->received), alloca_toprint(-1, r->parsed, r->cursor - r->parsed), \
	    (int)(r->cursor - r->received), alloca_toprint(50, r->cursor, r->end - r->cursor), \
	    (int)(r->end - r->received), \
	    r->request_content_remaining \
	  ); \
    } while (0)

static void http_server_poll(struct sched_ent *);
static int http_request_parse_verb(struct http_request *r);
static int http_request_parse_path(struct http_request *r);
static int http_request_parse_http_version(struct http_request *r);
static int http_request_start_parsing_headers(struct http_request *r);
static int http_request_parse_header(struct http_request *r);
static int http_request_start_body(struct http_request *r);
static int http_request_parse_body_form_data(struct http_request *r);
static void http_request_start_response(struct http_request *r);

void http_request_init(struct http_request *r, int sockfd)
{
  assert(sockfd != -1);
  r->request_header.content_length = CONTENT_LENGTH_UNKNOWN;
  r->request_content_remaining = CONTENT_LENGTH_UNKNOWN;
  r->alarm.stats = &http_server_stats;
  r->alarm.function = http_server_poll;
  if (r->idle_timeout == 0)
    r->idle_timeout = 10000; // 10 seconds
  r->alarm.alarm = gettime_ms() + r->idle_timeout;
  r->alarm.deadline = r->alarm.alarm + r->idle_timeout;
  r->alarm.poll.fd = sockfd;
  r->alarm.poll.events = POLLIN;
  r->phase = RECEIVE;
  r->received = r->end = r->parsed = r->cursor = r->buffer;
  r->parser = http_request_parse_verb;
  watch(&r->alarm);
  schedule(&r->alarm);
}

void http_request_free_response_buffer(struct http_request *r)
{
  if (r->response_free_buffer) {
    r->response_free_buffer(r->response_buffer);
    r->response_free_buffer = NULL;
  }
  r->response_buffer = NULL;
  r->response_buffer_size = 0;
}

int http_request_set_response_bufsize(struct http_request *r, size_t bufsiz)
{
  const char *const bufe = r->buffer + sizeof r->buffer;
  assert(r->received < bufe);
  size_t rbufsiz = bufe - r->received;
  if (bufsiz <= rbufsiz) {
    http_request_free_response_buffer(r);
    r->response_buffer = (char *) r->received;
    r->response_buffer_size = rbufsiz;
    return 0;
  }
  if (bufsiz != r->response_buffer_size) {
    http_request_free_response_buffer(r);
    if ((r->response_buffer = emalloc(bufsiz)) == NULL)
      return -1;
    r->response_free_buffer = free;
    r->response_buffer_size = bufsiz;
  }
  assert(r->response_buffer_size >= bufsiz);
  assert(r->response_buffer != NULL);
  return 0;
}

void http_request_finalise(struct http_request *r)
{
  if (r->phase == DONE)
    return;
  assert(r->phase == RECEIVE || r->phase == TRANSMIT);
  unschedule(&r->alarm);
  unwatch(&r->alarm);
  close(r->alarm.poll.fd);
  r->alarm.poll.fd = -1;
  if (r->finalise)
    r->finalise(r);
  r->finalise = NULL;
  http_request_free_response_buffer(r);
  r->phase = DONE;
}

#define _SEP (1 << 0)
#define _BND (1 << 1)

uint8_t http_ctype[256] = {
  ['0'] = _BND, ['1'] = _BND, ['2'] = _BND, ['3'] = _BND, ['4'] = _BND,
  ['5'] = _BND, ['6'] = _BND, ['7'] = _BND, ['8'] = _BND, ['9'] = _BND,
  ['A'] = _BND, ['B'] = _BND, ['C'] = _BND, ['D'] = _BND, ['E'] = _BND,
  ['F'] = _BND, ['G'] = _BND, ['H'] = _BND, ['I'] = _BND, ['J'] = _BND,
  ['K'] = _BND, ['L'] = _BND, ['M'] = _BND, ['N'] = _BND, ['O'] = _BND,
  ['P'] = _BND, ['Q'] = _BND, ['R'] = _BND, ['S'] = _BND, ['T'] = _BND,
  ['U'] = _BND, ['V'] = _BND, ['W'] = _BND, ['X'] = _BND, ['Y'] = _BND,
  ['Z'] = _BND,
  ['a'] = _BND, ['b'] = _BND, ['c'] = _BND, ['d'] = _BND, ['e'] = _BND,
  ['f'] = _BND, ['g'] = _BND, ['h'] = _BND, ['i'] = _BND, ['j'] = _BND,
  ['k'] = _BND, ['l'] = _BND, ['m'] = _BND, ['n'] = _BND, ['o'] = _BND,
  ['p'] = _BND, ['q'] = _BND, ['r'] = _BND, ['s'] = _BND, ['t'] = _BND,
  ['u'] = _BND, ['v'] = _BND, ['w'] = _BND, ['x'] = _BND, ['y'] = _BND,
  ['z'] = _BND,
  ['+'] = _BND, ['-'] = _BND, ['.'] = _BND, ['/'] = _BND, [':'] = _BND,
  ['_'] = _BND,
  ['('] = _SEP | _BND,
  [')'] = _SEP | _BND,
  [','] = _SEP | _BND,
  ['?'] = _SEP | _BND,
  ['='] = _SEP | _BND,
  [' '] = _SEP | _BND,
  ['\t'] = _SEP,
  ['<'] = _SEP,
  ['>'] = _SEP,
  ['@'] = _SEP,
  [';'] = _SEP,
  [':'] = _SEP,
  ['\\'] = _SEP,
  ['"'] = _SEP,
  ['/'] = _SEP,
  ['['] = _SEP,
  [']'] = _SEP,
  ['{'] = _SEP,
  ['}'] = _SEP,
};

inline int is_http_char(char c)
{
  return c >= 0;
}

inline int is_http_ctl(char c)
{
  return iscntrl(c);
}

inline int is_http_separator(char c)
{
  return (http_ctype[(unsigned char) c] & _SEP) != 0;
}

inline int is_http_boundary(char c)
{
  return (http_ctype[(unsigned char) c] & _BND) != 0;
}

inline int is_http_token(char c)
{
  return is_http_char(c) && !is_http_ctl(c) && !is_http_separator(c);
}

inline int is_valid_http_boundary_string(const char *s)
{
  if (s[0] == '\0')
    return 0;
  for (; *s; ++s)
    if (!is_http_boundary(*s))
      return 0;
  return s[-1] != ' ';
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

static const char * _reserve(struct http_request *r, struct substring str)
{
  char *reslim = r->buffer + sizeof r->buffer - 1024; // always leave this much unreserved space
  assert(r->received <= reslim);
  size_t len = str.end - str.start;
  size_t siz = len + 1;
  if (r->received + siz > reslim) {
    r->response.result_code = 414;
    return NULL;
  }
  if (r->received + siz > r->parsed) {
    WARNF("Error during HTTP parsing, unparsed content %s would be overwritten by reserving %s",
	alloca_toprint(30, r->parsed, r->end - r->parsed),
	alloca_substring_toprint(str)
      );
    r->response.result_code = 500;
    return NULL;
  }
  char *ret = (char *) r->received;
  if (ret != str.start)
    memmove(ret, str.start, len);
  ret[len] = '\0';
  r->received += siz;
  assert(r->received <= r->parsed);
  return ret;
}

static const char * _reserve_str(struct http_request *r, const char *str)
{
  struct substring sub = { .start = str, .end = str + strlen(str) };
  return _reserve(r, sub);
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

static int _skip_optional_space(struct http_request *r)
{
  while (!_run_out(r) && (*r->cursor == ' ' || *r->cursor == '\t'))
    ++r->cursor;
  return 1;
}

static inline int _skip_space(struct http_request *r)
{
  const char *const start = r->cursor;
  _skip_optional_space(r);
  return r->cursor > start;
}

static size_t _skip_word_printable(struct http_request *r, struct substring *str)
{
  if (_run_out(r) || isspace(*r->cursor) || !isprint(*r->cursor))
    return 0;
  const char *start = r->cursor;
  for (++r->cursor; !_run_out(r) && !isspace(*r->cursor) && isprint(*r->cursor); ++r->cursor)
    ;
  if (_run_out(r))
    return 0;
  assert(r->cursor > start);
  assert(isspace(*r->cursor));
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
  return !_run_out(r) && isdigit(*r->cursor) && str_to_uint64(r->cursor, 10, szp, &r->cursor);
}

static inline int _parse_uint(struct http_request *r, unsigned int *uintp)
{
  return !_run_out(r) && isdigit(*r->cursor) && str_to_uint(r->cursor, 10, uintp, &r->cursor);
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
    if (r->debug_flag && *r->debug_flag)
      DEBUGF("Malformed HTTP request, invalid verb: %s", alloca_toprint(20, r->cursor, r->end - r->cursor));
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
  if (!(_skip_word_printable(r, &path) && _skip_literal(r, " "))) {
    if (_run_out(r))
      return 100; // read more and try again
    if (r->debug_flag && *r->debug_flag)
      DEBUGF("Malformed HTTP %s request at path: %s", r->verb, alloca_toprint(20, r->parsed, r->end - r->parsed));
    return 400;
  }
  _commit(r);
  if ((r->path = _reserve(r, path)) == NULL)
    return 0; // error
  r->parser = http_request_parse_http_version;
  return 0;
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
  unsigned major, minor;
  if (!(   _skip_literal(r, "HTTP/")
	&& _parse_uint(r, &major)
	&& major > 0 && major < UINT8_MAX
	&& _skip_literal(r, ".")
	&& _parse_uint(r, &minor)
	&& minor < UINT8_MAX
	&& _skip_eol(r)
       )
  ) {
    if (_run_out(r))
      return 100; // read more and try again
    if (r->debug_flag && *r->debug_flag)
      DEBUGF("Malformed HTTP %s request at version: %s", r->verb, alloca_toprint(20, r->parsed, r->end - r->parsed));
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
    if (r->debug_flag && *r->debug_flag)
      DEBUGF("Unsupported HTTP version: %u.%u", r->version_major, r->version_minor);
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
  const char *const nextline = r->cursor;
  _rewind(r);
  const char *const sol = r->cursor;
  if (_skip_literal_nocase(r, "Content-Length:")) {
    _skip_optional_space(r);
    http_size_t length;
    if (_parse_http_size_t(r, &length) && _skip_optional_space(r) && r->cursor == eol) {
      r->cursor = nextline;
      _commit(r);
      r->request_header.content_length = length;
      if (r->debug_flag && *r->debug_flag)
	DEBUGF("Parsed HTTP request Content-Length: %"PRIhttp_size_t, r->request_header.content_length);
      return 0;
    }
    goto malformed;
  }
  _rewind(r);
  if (_skip_literal_nocase(r, "Content-Type:")) {
    _skip_optional_space(r);
    struct substring type = substring_NULL;
    struct substring subtype = substring_NULL;
    char boundary[BOUNDARY_STRING_MAXLEN + 1];
    boundary[0] = '\0';
    if (_skip_token(r, &type) && _skip_literal(r, "/") && _skip_token(r, &subtype)) {
      // Parse zero or more content-type parameters.
      for (_skip_optional_space(r); r->cursor < eol && _skip_literal(r, ";"); _skip_optional_space(r)) {
	_skip_optional_space(r);
	const char *startparam = r->cursor;
	if (_skip_literal(r, "boundary=")) {
	  size_t n = _parse_token_or_quoted_string(r, boundary, sizeof boundary);
	  if (n == 0 || n >= sizeof boundary || !is_valid_http_boundary_string(boundary))
	    goto malformed;
	  continue;
	}
	// Silently ignore unrecognised parameters (eg, charset=) if they are well formed.
	r->cursor = startparam; // partial rewind
	if (_skip_token(r, NULL) && _skip_literal(r, "=") && _parse_token_or_quoted_string(r, NULL, 0))
	  continue;
	break;
      }
      if (r->cursor == eol) {
	r->cursor = nextline;
	_commit(r);
	if (   (r->request_header.content_type = _reserve(r, type)) == NULL
	    || (r->request_header.content_subtype = _reserve(r, subtype)) == NULL
	    || (boundary[0] && (r->request_header.boundary = _reserve_str(r, boundary)) == NULL)
	)
	  return 0; // error
	if (r->debug_flag && *r->debug_flag)
	  DEBUGF("Parsed HTTP request Content-type: %s/%s%s%s",
	      r->request_header.content_type,
	      r->request_header.content_subtype,
	      r->request_header.boundary ? "; boundary=" : "",
	      r->request_header.boundary ? alloca_str_toprint(r->request_header.boundary) : ""
	    );
	return 0;
      }
    }
    goto malformed;
  }
  _rewind(r);
  if (_skip_literal_nocase(r, "Range:")) {
    _skip_optional_space(r);
    unsigned int n;
    if (   _skip_literal(r, "bytes=")
	&& (n = _parse_ranges(r, r->request_header.content_ranges, NELS(r->request_header.content_ranges)))
	&& _skip_optional_space(r)
	&& (r->cursor == eol)
    ) {
      r->cursor = nextline;
      _commit(r);
      if (n > NELS(r->request_header.content_ranges)) {
	if (r->debug_flag && *r->debug_flag)
	  DEBUGF("HTTP request Range header overflow (%u ranges in set, can only handle %zu): %s",
	      n, NELS(r->request_header.content_ranges), alloca_toprint(-1, sol, eol - sol));
	// In this case ignore the Range: header -- respond with the entire resource.
	r->request_header.content_range_count = 0;
      } else {
	r->request_header.content_range_count = n;
	if (r->debug_flag && *r->debug_flag)
	  DEBUGF("Parsed HTTP request Range: bytes=%s", alloca_http_ranges(r->request_header.content_ranges));
      }
      return 0;
    }
    goto malformed;
  }
  _rewind(r);
  if (r->debug_flag && *r->debug_flag)
    DEBUGF("Skipped HTTP request header: %s", alloca_toprint(-1, sol, eol - sol));
  r->cursor = nextline;
  _commit(r);
  return 0;
malformed:
  if (r->debug_flag && *r->debug_flag)
    DEBUGF("Malformed HTTP request header: %s", alloca_toprint(-1, sol, eol - sol));
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
      if (r->debug_flag && *r->debug_flag)
	DEBUGF("Malformed HTTP %s request: non-zero Content-Length not allowed", r->verb);
      return 400;
    }
    if (r->request_header.content_type) {
      if (r->debug_flag && *r->debug_flag)
	DEBUGF("Malformed HTTP %s request: Content-Type not allowed", r->verb);
      return 400;
    }
    r->parser = NULL;
  }
  else if (r->verb == HTTP_VERB_POST) {
    if (r->request_header.content_length == CONTENT_LENGTH_UNKNOWN) {
      if (r->debug_flag && *r->debug_flag)
	DEBUGF("Malformed HTTP %s request: missing Content-Length header", r->verb);
      return 411;
    }
    if (r->request_header.content_type == NULL) {
      if (r->debug_flag && *r->debug_flag)
	DEBUGF("Malformed HTTP %s request: missing Content-Type header", r->verb);
      return 400;
    }
    if (   strcmp(r->request_header.content_type, "multipart") == 0
	&& strcmp(r->request_header.content_subtype, "form-data") == 0
    ) {
      if (r->request_header.boundary == NULL || r->request_header.boundary[0] == '\0') {
	if (r->debug_flag && *r->debug_flag)
	  DEBUGF("Malformed HTTP %s request: Content-Type %s/%s missing boundary parameter",
	      r->verb, r->request_header.content_type, r->request_header.content_subtype);
	return 400;
      }
      r->parser = http_request_parse_body_form_data;
      r->form_data_state = START;
    } else {
      if (r->debug_flag && *r->debug_flag)
	DEBUGF("Unsupported HTTP %s request: Content-Type %s/%s not supported",
	    r->verb, r->request_header.content_type, r->request_header.content_subtype);
      return 415;
    }
  }
  else {
    if (r->debug_flag && *r->debug_flag)
      DEBUGF("Unsupported HTTP %s request", r->verb);
    r->parser = NULL;
    return 501;
  }
  if (_run_out(r))
    return 100;
  return 0;
}

/* Returns 1 if a MIME delimiter is skipped, 2 if a MIME close-delimiter is skipped.
 */
static int _skip_mime_boundary(struct http_request *r)
{
  if (!_skip_literal(r, "--") || !_skip_literal(r, r->request_header.boundary))
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
    const char *start = r->cursor;
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
      if (r->debug_flag && *r->debug_flag)
	DEBUGF("Skipping HTTP Content-Disposition parameter: %s", alloca_substring_toprint(param));
      continue;
    }
malformed:
    WARNF("Malformed HTTP Content-Disposition: %s", alloca_toprint(50, r->cursor, r->end - r->cursor));
    return 0;
  }
  return 1;
}

/* If parsing completes (ie, parsed to end of epilogue), then sets r->parser to NULL and returns 0,
 * so this function will not be called again.  If parsing cannot complete due to running out of
 * data, returns 100, so this function will not be called again until more data has been read.
 * Returns a 4nn or 5nn HTTP result code if parsing fails.  Returns -1 if an unexpected error
 * occurs.
 *
 * NOTE: No support for nested/mixed parts, as that would considerably complicate the parser.  If
 * the need arises in future, we will deal with it then.  In the meantime, we will have something
 * that meets our immediate needs for Rhizome Direct and a variety of use cases.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static int http_request_parse_body_form_data(struct http_request *r)
{
  DEBUG_DUMP_PARSER(r);
  int at_start = 0;
  switch (r->form_data_state) {
    case START:
      if (config.debug.httpd)
	DEBUGF("START");
      // The logic here allows for a missing initial CRLF before the first boundary line.
      at_start = 1;
      r->form_data_state = PREAMBLE;
      // fall through
    case PREAMBLE: {
	if (config.debug.httpd)
	  DEBUGF("PREAMBLE");
	const char *start = r->parsed;
	for (; at_start || _skip_to_crlf(r); at_start = 0) {
	  const char *end_preamble = r->cursor;
	  int b;
	  if ((b = _skip_mime_boundary(r))) {
	    assert(end_preamble >= r->parsed);
	    if (r->form_data.handle_mime_preamble && end_preamble != r->parsed) {
	      if (r->debug_flag && *r->debug_flag)
		DEBUGF("handle_mime_preamble(%s length=%zu)",
		    alloca_toprint(50, r->parsed, end_preamble - r->parsed), end_preamble - r->parsed);
	      r->form_data.handle_mime_preamble(r, r->parsed, end_preamble - r->parsed);
	    }
	    _rewind_crlf(r);
	    _commit(r);
	    if (b == 1) {
	      r->form_data_state = HEADER;
	      if (r->form_data.handle_mime_part_start) {
		if (r->debug_flag && *r->debug_flag)
		  DEBUGF("handle_mime_part_start()");
		r->form_data.handle_mime_part_start(r);
	      }
	    } else
	      r->form_data_state = EPILOGUE;
	    return 0;
	  }
	}
	if (_end_of_content(r)) {
	  if (r->debug_flag && *r->debug_flag)
	    DEBUGF("Malformed HTTP %s form data: missing first boundary", r->verb);
	  return 400;
	}
	_rewind_optional_cr(r);
	_commit(r);
	if (r->parsed > start && r->form_data.handle_mime_preamble) {
	  if (r->debug_flag && *r->debug_flag)
	    DEBUGF("handle_mime_preamble(%s length=%zu)",
		alloca_toprint(50, start, r->parsed - start), r->parsed - start);
	  r->form_data.handle_mime_preamble(r, start, r->parsed - start);
	}
      }
      return 100; // need more data
    case HEADER: {
      if (config.debug.httpd)
	DEBUGF("HEADER");
	// If not at a CRLF, then we are skipping through an over-long header that didn't
	// fit into the buffer.  Just discard bytes up to the next CRLF.
	if (!_skip_crlf(r)) {
	  _skip_to_crlf(r); // advance to next CRLF or end of buffer
	  _rewind_optional_cr(r); // don't skip a CR at end of buffer (it might be part of a half-received CRLF)
	  assert(r->cursor > r->parsed);
	  if (r->debug_flag && *r->debug_flag)
	    DEBUGF("skipping %zu header bytes", r->cursor - r->parsed);
	  _commit(r);
	  return 0;
	}
	const char *sol = r->cursor;
	// A blank line finishes the headers.  The CRLF does not form part of the body.
	if (_skip_crlf(r)) {
	  _commit(r);
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
	  if (r->form_data.handle_mime_part_end) {
	    if (r->debug_flag && *r->debug_flag)
	      DEBUGF("handle_mime_part_end()");
	    r->form_data.handle_mime_part_end(r);
	  }
	  // A boundary in the middle of headers finishes the current part and starts a new part.
	  // An end boundary terminates the current part and starts the epilogue.
	  if (b == 1) {
	    r->form_data_state = HEADER;
	    if (r->form_data.handle_mime_part_start) {
	      if (r->debug_flag && *r->debug_flag)
		DEBUGF("handle_mime_part_start()");
	      r->form_data.handle_mime_part_start(r);
	    }
	  }
	  else
	    r->form_data_state = EPILOGUE;
	  return 0;
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
	  const char *value = r->cursor;
	  if (strcmp(labelstr, "content-disposition") == 0) {
	    struct mime_content_disposition cd;
	    bzero(&cd, sizeof cd);
	    if (_parse_content_disposition(r, &cd) && _skip_optional_space(r) && _skip_crlf(r)) {
	      _rewind_crlf(r);
	      _commit(r);
	      if (r->form_data.handle_mime_content_disposition) {
		if (r->debug_flag && *r->debug_flag)
		  DEBUGF("handle_mime_content_disposition(%s)", alloca_mime_content_disposition(&cd));
		r->form_data.handle_mime_content_disposition(r, &cd);
	      }
	      return 0;
	    }
	  }
	  else if (_skip_to_crlf(r)) {
	    _commit(r);
	    if (r->form_data.handle_mime_header) {
	      if (r->debug_flag && *r->debug_flag)
		DEBUGF("handle_mime_header(%s, %s)", alloca_str_toprint(labelstr), alloca_toprint(-1, value, value - r->cursor));
	      r->form_data.handle_mime_header(r, labelstr, value, value - r->cursor); // excluding CRLF at end
	    }
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
	  if (r->debug_flag && *r->debug_flag)
	    DEBUGF("skipping %zu header bytes", r->cursor - r->parsed);
	  _commit(r);
	  return 0;
	}
	if (_run_out(r))
	  return 100; // read more and try again
	if (r->debug_flag && *r->debug_flag)
	  DEBUGF("Malformed HTTP %s form data part: invalid header %s", r->verb, alloca_toprint(50, sol, r->end - sol));
	DEBUG_DUMP_PARSER(r);
      }
      return 400;
    case BODY:
      if (config.debug.httpd)
	DEBUGF("BODY");
      const char *start = r->parsed;
      while (_skip_to_crlf(r)) {
	int b;
	const char *end_body = r->cursor;
	_skip_crlf(r);
	if ((b = _skip_mime_boundary(r))) {
	  _rewind_crlf(r);
	  _commit(r);
	  if (end_body > start && r->form_data.handle_mime_body) {
	    if (r->debug_flag && *r->debug_flag)
	      DEBUGF("handle_mime_body(%s length=%zu)", alloca_toprint(80, start, end_body - start), end_body - start);
	    r->form_data.handle_mime_body(r, start, end_body - start); // excluding CRLF at end
	  }
	  if (r->form_data.handle_mime_part_end) {
	    if (r->debug_flag && *r->debug_flag)
	      DEBUGF("handle_mime_part_end()");
	    r->form_data.handle_mime_part_end(r);
	  }
	  r->form_data_state = EPILOGUE;
	  if (b == 1) {
	    r->form_data_state = HEADER;
	    if (r->form_data.handle_mime_part_start) {
	      if (r->debug_flag && *r->debug_flag)
		DEBUGF("handle_mime_part_start()");
	      r->form_data.handle_mime_part_start(r);
	    }
	  }
	  return 0;
	}
      }
      if (_end_of_content(r)) {
	if (r->debug_flag && *r->debug_flag)
	  DEBUGF("Malformed HTTP %s form data part: missing end boundary", r->verb);
	return 400;
      }
      _rewind_optional_cr(r);
      _commit(r);
      if (r->parsed > start && r->form_data.handle_mime_body) {
	if (r->debug_flag && *r->debug_flag)
	  DEBUGF("handle_mime_body(%s length=%zu)", alloca_toprint(80, start, r->parsed - start), r->parsed - start);
	r->form_data.handle_mime_body(r, start, r->parsed - start);
      }
      return 100; // need more data
  case EPILOGUE:
      if (config.debug.httpd)
	DEBUGF("EPILOGUE");
    r->cursor = r->end;
    if (r->form_data.handle_mime_epilogue && r->cursor != r->parsed) {
      if (r->debug_flag && *r->debug_flag)
	DEBUGF("handle_mime_epilogue(%s length=%zu)",
	    alloca_toprint(50, r->parsed, r->cursor - r->parsed), r->cursor - r->parsed);
      r->form_data.handle_mime_epilogue(r, r->parsed, r->cursor - r->parsed);
    }
    _commit(r);
    assert(_run_out(r));
    if (_end_of_content(r))
      return 0; // done
    return 100; // need more data
  }
  abort(); // not reached
}

static ssize_t http_request_read(struct http_request *r, char *buf, size_t len)
{
  sigPipeFlag = 0;
  ssize_t bytes = read_nonblock(r->alarm.poll.fd, buf, len);
  if (bytes == -1) {
    if (r->debug_flag && *r->debug_flag)
      DEBUG("HTTP socket read error, closing connection");
    http_request_finalise(r);
    return -1;
  }
  if (sigPipeFlag) {
    if (r->debug_flag && *r->debug_flag)
      DEBUG("Received SIGPIPE on HTTP socket read, closing connection");
    http_request_finalise(r);
    return -1;
  }
  return bytes;
}

static void http_request_receive(struct http_request *r)
{
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
    if (r->debug_flag && *r->debug_flag)
      DEBUG("Buffer size reached, reporting overflow");
    http_request_simple_response(r, 431, NULL);
    return;
  }
  // Read up to the end of available buffer space or the end of content, whichever is first.  Read
  // as many bytes as possible into the unused buffer space.  Any read error closes the connection
  // without any response.
  assert(room > 0);
  if (r->request_content_remaining != CONTENT_LENGTH_UNKNOWN)
    assert(room <= r->request_content_remaining);
  ssize_t bytes = http_request_read(r, (char *)r->end, room);
  if (bytes == -1)
    return;
  assert((size_t) bytes <= room);
  // If no data was read, then just return to polling.  Don't drop the connection on an empty read,
  // because that drops connections when they shouldn't, including during testing.  The inactivity
  // timeout will drop inactive connections.
  if (bytes == 0)
    return;
  r->end += (size_t) bytes;
  if (r->request_content_remaining != CONTENT_LENGTH_UNKNOWN)
    r->request_content_remaining -= (size_t) bytes;
  // We got some data, so reset the inactivity timer and invoke the parsing state machine to process
  // it.  The state machine invokes the caller-supplied callback functions.
  r->alarm.alarm = gettime_ms() + r->idle_timeout;
  r->alarm.deadline = r->alarm.alarm + r->idle_timeout;
  unschedule(&r->alarm);
  schedule(&r->alarm);
  // Parse the unparsed and received data.
  while (r->phase == RECEIVE) {
    int result;
    _rewind(r);
    DEBUG_DUMP_PARSER(r);
    if (_end_of_content(r)) {
      if (r->handle_content_end)
	result = r->handle_content_end(r);
      else {
	if (r->debug_flag && *r->debug_flag)
	  DEBUG("Internal failure parsing HTTP request: no end-of-content function set");
	result = 500;
      }
    } else {
      HTTP_REQUEST_PARSER oldparser = r->parser;
      const char *oldparsed = r->parsed;
      if (r->parser == NULL) {
	if (r->debug_flag && *r->debug_flag)
	  DEBUGF("No HTTP parser function set -- skipping %zu bytes", (size_t)(r->end - r->cursor));
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
	return; // needs more data; poll again
      if (result == 0 && r->parsed == oldparsed && r->parser == oldparser) {
	if (r->debug_flag && *r->debug_flag)
	  DEBUG("Internal failure parsing HTTP request: parser function did not advance");
	DEBUG_DUMP_PARSER(r);
	result = 500;
      }
    }
    if (result >= 300)
      r->response.result_code = result;
    else if (result) {
      if (r->debug_flag && *r->debug_flag)
	DEBUGF("Internal failure parsing HTTP request: invalid result=%d", result);
      r->response.result_code = 500;
    }
    if (r->response.result_code)
      break;
    if (result == -1) {
      if (r->debug_flag && *r->debug_flag)
	DEBUG("Unrecoverable error parsing HTTP request, closing connection");
      http_request_finalise(r);
      return;
    }
  }
  if (r->phase != RECEIVE)
    return;
  if (r->response.result_code == 0) {
    WHY("No HTTP response set, using 500 Server Error");
    r->response.result_code = 500;
  }
  http_request_start_response(r);
}

/* Write the current contents of the response buffer to the HTTP socket.  When no more bytes can be
 * written, return so that socket polling can continue.  Once all bytes are sent, if there is a
 * content generator function, invoke it to put more content in the response buffer, and write that
 * content.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static void http_request_send_response(struct http_request *r)
{
  assert(r->response_sent <= r->response_length);
  while (r->response_sent < r->response_length) {
    assert(r->response_buffer_sent <= r->response_buffer_length);
    if (r->response_buffer_sent == r->response_buffer_length) {
      if (r->response.content_generator) {
	// Content generator must fill or partly fill response_buffer and set response_buffer_sent
	// and response_buffer_length.  May also malloc() a bigger buffer and set response_buffer to
	// point to it.
	r->response_buffer_sent = r->response_buffer_length = 0;
	if (r->response.content_generator(r) == -1) {
	  if (r->debug_flag && *r->debug_flag)
	    DEBUG("Content generation error, closing connection");
	  http_request_finalise(r);
	  return;
	}
	assert(r->response_buffer_sent <= r->response_buffer_length);
	if (r->response_buffer_sent == r->response_buffer_length) {
	  WHYF("HTTP response generator produced no content at offset %"PRIhttp_size_t"/%"PRIhttp_size_t" (%"PRIhttp_size_t" bytes remaining)",
	      r->response_sent, r->response_length, r->response_length - r->response_sent);
	  http_request_finalise(r);
	  return;
	}
      } else {
	WHYF("HTTP response is short of total length (%"PRIhttp_size_t") by %"PRIhttp_size_t" bytes",
	    r->response_length, r->response_length - r->response_sent);
	http_request_finalise(r);
	return;
      }
    }
    assert(r->response_buffer_sent < r->response_buffer_length);
    size_t bytes = r->response_buffer_length - r->response_buffer_sent;
    if (r->response_sent + bytes > r->response_length) {
      WHYF("HTTP response overruns total length (%"PRIhttp_size_t") by %"PRIhttp_size_t"  bytes -- truncating",
	  r->response_length,
	  r->response_sent + bytes - r->response_length);
      bytes = r->response_length - r->response_sent;
    }
    sigPipeFlag = 0;
    ssize_t written = write_nonblock(r->alarm.poll.fd, r->response_buffer + r->response_buffer_sent, bytes);
    if (written == -1) {
      if (r->debug_flag && *r->debug_flag)
	DEBUG("HTTP socket write error, closing connection");
      http_request_finalise(r);
      return;
    }
    if (sigPipeFlag) {
      if (r->debug_flag && *r->debug_flag)
	DEBUG("Received SIGPIPE on HTTP socket write, closing connection");
      http_request_finalise(r);
      return;
    }
    // If we wrote nothing, go back to polling.
    if (written == 0)
      return;
    r->response_sent += (size_t) written;
    r->response_buffer_sent += (size_t) written;
    assert(r->response_sent <= r->response_length);
    assert(r->response_buffer_sent <= r->response_buffer_length);
    // Reset inactivity timer.
    r->alarm.alarm = gettime_ms() + r->idle_timeout;
    r->alarm.deadline = r->alarm.alarm + r->idle_timeout;
    unschedule(&r->alarm);
    schedule(&r->alarm);
    // If we wrote less than we tried, then go back to polling.
    if (written < (size_t) bytes)
      return;
  }
  if (r->debug_flag && *r->debug_flag)
    DEBUG("Done, closing connection");
  http_request_finalise(r);
}

static void http_server_poll(struct sched_ent *alarm)
{
  struct http_request *r = (struct http_request *) alarm;
  if (alarm->poll.revents == 0) {
    if (r->debug_flag && *r->debug_flag)
      DEBUGF("Timeout, closing connection");
    http_request_finalise(r);
  }
  else if (alarm->poll.revents & (POLLHUP | POLLERR)) {
    if (r->debug_flag && *r->debug_flag)
      DEBUGF("Poll error (%s), closing connection", alloca_poll_events(alarm->poll.revents));
    http_request_finalise(r);
  }
  else {
    if (r->phase == RECEIVE && (alarm->poll.revents & POLLIN))
      http_request_receive(r); // this could change the phase to TRANSMIT
    if (r->phase == TRANSMIT && (alarm->poll.revents & POLLOUT))
      http_request_send_response(r);
  }
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
  case 206: return "Partial Content";
  case 400: return "Bad Request";
  case 401: return "Unauthorized";
  case 403: return "Forbidden";
  case 404: return "Not Found";
  case 405: return "Method Not Allowed";
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

static strbuf strbuf_append_quoted_string(strbuf sb, const char *str)
{
  strbuf_putc(sb, '"');
  for (; *str; ++str) {
    if (*str == '"' || *str == '\\')
      strbuf_putc(sb, '\\');
    strbuf_putc(sb, *str);
  }
  strbuf_putc(sb, '"');
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
  assert(hr.result_code != 0);
  assert(hr.header.content_range_start <= hr.header.resource_length);
  assert(hr.header.content_length <= hr.header.resource_length);
  // To save page handlers having to decide between 200 (OK) and 206 (Partial Content), they can
  // just send 200 and the content range fields, and this logic will detect if it should be 206.
  if (hr.header.content_length > 0 && hr.header.content_length < hr.header.resource_length && hr.result_code == 200)
    hr.result_code = 206; // Partial Content
  const char *result_string = httpResultString(hr.result_code);
  strbuf sb = strbuf_local(r->response_buffer, r->response_buffer_size);
  if (hr.content == NULL && hr.content_generator == NULL) {
    strbuf cb = strbuf_alloca(100 + strlen(result_string));
    strbuf_puts(cb, "<html><h1>");
    strbuf_puts(cb, result_string);
    strbuf_puts(cb, "</h1></html>\r\n");
    hr.content = strbuf_str(cb);
    hr.header.resource_length = hr.header.content_length = strbuf_len(cb);
    hr.header.content_type = "text/html";
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
    assert(hr.header.content_length > 0);
    assert(hr.header.content_length < hr.header.resource_length);
    strbuf_sprintf(sb,
	  "Content-Range: bytes %"PRIhttp_size_t"-%"PRIhttp_size_t"/%"PRIhttp_size_t"\r\n",
	  hr.header.content_range_start,
	  hr.header.content_range_start + hr.header.content_length - 1,
	  hr.header.resource_length
	);
  }
  strbuf_sprintf(sb, "Content-Length: %"PRIhttp_size_t"\r\n", hr.header.content_length);
  strbuf_puts(sb, "\r\n");
  if (strbuf_overrun(sb))
    return 0;
  r->response_length = strbuf_len(sb) + hr.header.content_length;
  if (hr.content) {
    if (r->response_buffer_size < r->response_length)
      return 0;
    bcopy(hr.content, strbuf_end(sb), hr.header.content_length);
    r->response_buffer_length = r->response_length;
  } else {
    r->response_buffer_length = strbuf_len(sb);
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
    // If the response did not fit into the existing buffer, then allocate a large buffer from the
    // heap and try rendering again.
    if (http_request_set_response_bufsize(r, r->response_length + 1) == -1)
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
  assert(r->phase == RECEIVE);
  assert(r->response.result_code != 0);
  if (r->response.content || r->response.content_generator) {
    assert(r->response.header.content_type != NULL);
    assert(r->response.header.content_type[0]);
  }
  // If HTTP responses are disabled (eg, for testing purposes) then skip all response construction
  // and close the connection.
  if (r->disable_tx_flag && *r->disable_tx_flag) {
    INFO("HTTP transmit disabled, closing connection");
    http_request_finalise(r);
    return;
  }
  // Drain the rest of the request that has not been received yet (eg, if sending an error response
  // provoked while parsing the early part of a partially-received request).  If a read error
  // occurs, the connection is closed so the phase changes to DONE.
  http_request_drain(r);
  if (r->phase != RECEIVE)
    return;
  // If the response cannot be rendered, then render a 500 Server Error instead.  If that fails,
  // then just close the connection.
  http_request_render_response(r);
  if (r->response_buffer == NULL) {
    WARN("Cannot render HTTP response, sending 500 Server Error instead");
    r->response.result_code = 500;
    r->response.content = NULL;
    http_request_render_response(r);
    if (r->response_buffer == NULL) {
      WHY("Cannot render HTTP 500 Server Error response, closing connection");
      http_request_finalise(r);
      return;
    }
  }
  r->response_sent = 0;
  if (r->debug_flag && *r->debug_flag)
    DEBUGF("Sending HTTP response: %s", alloca_toprint(160, (const char *)r->response_buffer, r->response_buffer_length));
  r->phase = TRANSMIT;
  r->alarm.poll.events = POLLOUT;
  watch(&r->alarm);
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
  assert(result >= 100);
  assert(result < 300);
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
  assert(result >= 100);
  assert(result < 300);
  assert(mime_type != NULL);
  assert(mime_type[0]);
  r->response.result_code = result;
  r->response.header.content_type = mime_type;
  r->response.content = NULL;
  r->response.content_generator = generator;
  http_request_start_response(r);
}

/* Start sending a short response back to the client.  The result code must be either a success
 * (2xx), redirection (3xx) or client error (4xx) or server error (5xx) code.  The 'body' argument
 * may be a bare message which is enclosed in an HTML envelope to form the response content, so it
 * may contain HTML markup.  If the 'body' argument is NULL, then the response content is generated
 * automatically from the result code.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
void http_request_simple_response(struct http_request *r, uint16_t result, const char *body)
{
  assert(r->phase == RECEIVE);
  assert(result >= 200);
  assert(result < 600);
  strbuf h = NULL;
  if (body) {
    size_t html_len = strlen(body) + 40;
    h = strbuf_alloca(html_len);
    strbuf_sprintf(h, "<html><h1>%03u %s</h1></html>", result, body);
  }
  r->response.result_code = result;
  r->response.header.content_type = "text/html";
  r->response.header.content_range_start = 0;
  r->response.header.resource_length = r->response.header.content_length = h ? strbuf_len(h) : 0;
  r->response.content = h ? strbuf_str(h) : NULL;
  r->response.content_generator = NULL;
  http_request_start_response(r);
}
