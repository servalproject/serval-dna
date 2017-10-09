/*
Serval DNA Rhizome HTTP RESTful interface
Copyright (C) 2013-2015 Serval Project Inc.
 
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

#include "serval.h"
#include "conf.h"
#include "httpd.h"
#include "str.h"
#include "base64.h"
#include "strbuf_helpers.h"
#include "numeric_str.h"

DEFINE_FEATURE(http_rest_rhizome);

DECLARE_HANDLER("/restful/rhizome/bundlelist.json", restful_rhizome_bundlelist_json);
DECLARE_HANDLER("/restful/rhizome/newsince/", restful_rhizome_newsince);
DECLARE_HANDLER("/restful/rhizome/insert", restful_rhizome_insert);
DECLARE_HANDLER("/restful/rhizome/import", restful_rhizome_import);
DECLARE_HANDLER("/restful/rhizome/append", restful_rhizome_append);
DECLARE_HANDLER("/restful/rhizome/", restful_rhizome_);

static HTTP_RENDERER render_manifest_headers;
static void on_rhizome_bundle_added(httpd_request *r, rhizome_manifest *m);

static void finalise_union_read_state(httpd_request *r)
{
  rhizome_read_close(&r->u.read_state);
}

static void finalise_union_rhizome_insert(httpd_request *r)
{
  form_buf_malloc_release(&r->u.insert.manifest);
  if (r->u.insert.write.blob_fd != -1)
    rhizome_fail_write(&r->u.insert.write);
}

static void finalise_union_rhizome_list(httpd_request *r)
{
  if (r->u.rhlist.cursor.service)
    free((void*)r->u.rhlist.cursor.service);
  r->u.rhlist.cursor.service=NULL;
  if (r->u.rhlist.cursor.name)
    free((void*)r->u.rhlist.cursor.name);
  r->u.rhlist.cursor.name=NULL;
}

#define LIST_TOKEN_STRLEN (BASE64_ENCODED_LEN(sizeof(serval_uuid_t) + 8))
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
  if (base64url_decode(token, sizeof token, str, 0, afterp, 0, NULL) == sizeof token
    && cmp_serval_uuid_t(&rhizome_db_uuid, (serval_uuid_t *) &token) == 0
    && **afterp=='/'){
    memcpy(rowidp, token + sizeof rhizome_db_uuid.u.binary, sizeof *rowidp);
    (*afterp)++;
  }else{
    // don't skip the token
    *afterp=str;
    *rowidp=1;
  }
  return 1;
}

static int http_request_rhizome_response(struct httpd_request *r, uint16_t http_status, const char *http_reason)
{
  uint16_t rhizome_http_status = 0;
  switch (r->bundle_result.status) {
    case RHIZOME_BUNDLE_STATUS_SAME:
    case RHIZOME_BUNDLE_STATUS_DUPLICATE:
      rhizome_http_status = 200; // OK
      break;
    case RHIZOME_BUNDLE_STATUS_NEW:
      rhizome_http_status = 201; // Created
      break;
    case RHIZOME_BUNDLE_STATUS_NO_ROOM:
    case RHIZOME_BUNDLE_STATUS_OLD:
      rhizome_http_status = 202; // Accepted
      break;
    case RHIZOME_BUNDLE_STATUS_FAKE:
    case RHIZOME_BUNDLE_STATUS_READONLY:
      rhizome_http_status = 419; // Authentication Timeout
      break;
    case RHIZOME_BUNDLE_STATUS_INVALID:
    case RHIZOME_BUNDLE_STATUS_INCONSISTENT:
    case RHIZOME_BUNDLE_STATUS_MANIFEST_TOO_BIG:
      rhizome_http_status = 422; // Unprocessable Entity
      break;
    case RHIZOME_BUNDLE_STATUS_BUSY:
      rhizome_http_status = 423; // Locked
      break;
    case RHIZOME_BUNDLE_STATUS_ERROR:
      rhizome_http_status = 500;
      break;
  }
  if (rhizome_http_status) {
    r->http.response.result_extra[0].label = "rhizome_bundle_status_code";
    r->http.response.result_extra[0].value.type = JSON_INTEGER;
    r->http.response.result_extra[0].value.u.integer = r->bundle_result.status;
    const char *status_message = rhizome_bundle_result_message(r->bundle_result);
    if (status_message) {
      r->http.response.result_extra[1].label = "rhizome_bundle_status_message";
      r->http.response.result_extra[1].value.type = JSON_STRING_NULTERM;
      r->http.response.result_extra[1].value.u.string.content = status_message;
    }
    if (rhizome_http_status > http_status) {
      http_status = rhizome_http_status;
      if (!http_reason)
	http_reason = status_message;
    }
  }
  rhizome_http_status = 0;
  switch (r->payload_status) {
    case RHIZOME_PAYLOAD_STATUS_STORED:
    case RHIZOME_PAYLOAD_STATUS_EMPTY:
      rhizome_http_status = 200;
      break;
    case RHIZOME_PAYLOAD_STATUS_NEW:
      rhizome_http_status = 201;
      break;
    case RHIZOME_PAYLOAD_STATUS_TOO_BIG:
    case RHIZOME_PAYLOAD_STATUS_EVICTED:
      rhizome_http_status = 202; // Accepted
      break;
    case RHIZOME_PAYLOAD_STATUS_CRYPTO_FAIL:
      rhizome_http_status = 419; // Authentication Timeout
      break;
    case RHIZOME_PAYLOAD_STATUS_WRONG_SIZE:
    case RHIZOME_PAYLOAD_STATUS_WRONG_HASH:
      rhizome_http_status = 422; // Unprocessable Entity
      break;
    case RHIZOME_PAYLOAD_STATUS_BUSY:
    case RHIZOME_PAYLOAD_STATUS_ERROR:
      rhizome_http_status = 500;
      break;
  }
  if (rhizome_http_status) {
    r->http.response.result_extra[2].label = "rhizome_payload_status_code";
    r->http.response.result_extra[2].value.type = JSON_INTEGER;
    r->http.response.result_extra[2].value.u.integer = r->payload_status;
    const char *status_message = rhizome_payload_status_message(r->payload_status);
    if (status_message) {
      r->http.response.result_extra[3].label = "rhizome_payload_status_message";
      r->http.response.result_extra[3].value.type = JSON_STRING_NULTERM;
      r->http.response.result_extra[3].value.u.string.content = status_message;
    }
    if (rhizome_http_status > http_status) {
      http_status = rhizome_http_status;
      if (!http_reason)
	http_reason = status_message;
    }
  }
  if (http_status == 0) {
    http_status = 500;
    http_reason = "Invalid result";
  }
  http_request_simple_response(&r->http, http_status, http_reason);
  return http_status;
}

static HTTP_CONTENT_GENERATOR restful_rhizome_bundlelist_json_content;

static int restful_open_cursor(httpd_request *r)
{
  assert(r->finalise_union == NULL);
  r->finalise_union = finalise_union_rhizome_list;
  r->u.rhlist.phase = LIST_HEADER;
  r->u.rhlist.rowcount = 0;

  const char *service = http_request_get_query_param(&r->http, "service");
  if (service && *service){
    r->u.rhlist.cursor.service = str_edup(service);
    // TODO fail?
  }

  const char *name = http_request_get_query_param(&r->http, "name");
  if (name && *name){
    r->u.rhlist.cursor.name = str_edup(name);
    // TODO fail?
  }

  const char *sender = http_request_get_query_param(&r->http, "sender");
  if (sender && *sender){
    if (str_to_sid_t(&r->u.rhlist.cursor.sender, sender) != -1)
      r->u.rhlist.cursor.is_sender_set = 1;
    // TODO fail?
  }

  const char *recipient = http_request_get_query_param(&r->http, "recipient");
  if (recipient && *recipient){
    if (str_to_sid_t(&r->u.rhlist.cursor.recipient, recipient) != -1)
      r->u.rhlist.cursor.is_recipient_set = 1;
    // TODO fail?
  }

  int ret = rhizome_list_open(&r->u.rhlist.cursor);
  if (ret == -1)
    return http_request_rhizome_response(r, 500, "Failed to open list");

  http_request_response_generated(&r->http, 200, CONTENT_TYPE_JSON, restful_rhizome_bundlelist_json_content);
  return 1;
}

static int restful_rhizome_bundlelist_json(httpd_request *r, const char *remainder)
{
  r->http.response.header.content_type = CONTENT_TYPE_JSON;
  r->http.render_extra_headers = render_manifest_headers;
  if (!is_rhizome_http_enabled())
    return 404;
  int ret = authorize_restful(&r->http);
  if (ret)
    return ret;
  if (*remainder)
    return 404;
  if (r->http.verb != HTTP_VERB_GET)
    return 405;
  bzero(&r->u.rhlist.cursor, sizeof r->u.rhlist.cursor);
  return restful_open_cursor(r);
}

static HTTP_CONTENT_GENERATOR_STRBUF_CHUNKER restful_rhizome_bundlelist_json_content_chunk;

static int restful_rhizome_bundlelist_json_content(struct http_request *hr, unsigned char *buf, size_t bufsz, struct http_content_generator_result *result)
{
  httpd_request *r = (httpd_request *) hr;
  int ret = generate_http_content_from_strbuf_chunks(hr, (char *)buf, bufsz, result, restful_rhizome_bundlelist_json_content_chunk);
  rhizome_list_release(&r->u.rhlist.cursor);
  return ret;
}

static int restful_rhizome_newsince(httpd_request *r, const char *remainder)
{
  r->http.response.header.content_type = CONTENT_TYPE_JSON;
  if (!is_rhizome_http_enabled())
    return 404;
  int ret = authorize_restful(&r->http);
  if (ret)
    return ret;
  uint64_t rowid;
  const char *end = NULL;
  if (!strn_to_list_token(remainder, &rowid, &end) || strcmp(end, "bundlelist.json") != 0)
    return 404;
  if (r->http.verb != HTTP_VERB_GET)
    return 405;
  bzero(&r->u.rhlist.cursor, sizeof r->u.rhlist.cursor);
  r->u.rhlist.cursor.rowid_since = rowid;
  r->u.rhlist.cursor.oldest_first = 1;
  r->u.rhlist.end_time = gettime_ms() + config.api.restful.newsince_timeout * 1000;
  r->trigger_rhizome_bundle_added = on_rhizome_bundle_added;
  return restful_open_cursor(r);
}

static void on_rhizome_bundle_added(httpd_request *r, rhizome_manifest *UNUSED(m))
{
  http_request_resume_response(&r->http);
}

static int restful_rhizome_bundlelist_json_content_chunk(struct http_request *hr, strbuf b)
{
  httpd_request *r = (httpd_request *) hr;
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
  switch (r->u.rhlist.phase) {
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
	r->u.rhlist.phase = LIST_ROWS;
      return 1;
    case LIST_FIRST:
    case LIST_ROWS:
      {
	int ret = rhizome_list_next(&r->u.rhlist.cursor);
	if (ret == -1)
	  return -1;
	if (ret == 0) {
	  time_ms_t now;
	  if (r->u.rhlist.cursor.oldest_first == 0 || (now = gettime_ms()) >= r->u.rhlist.end_time) {
	    r->u.rhlist.phase = LIST_END;
	    return 1;
	  }
	  http_request_pause_response(&r->http, r->u.rhlist.end_time);
	  return 0;
	}
	rhizome_manifest *m = r->u.rhlist.cursor.manifest;
	assert(m->filesize != RHIZOME_SIZE_UNSET);
	rhizome_lookup_author(m);
	if (r->u.rhlist.rowcount != 0)
	  strbuf_putc(b, ',');
	strbuf_puts(b, "\n[");
	if (m->rowid > r->u.rhlist.rowid_highest) {
	  strbuf_json_string(b, alloca_list_token(m->rowid));
	  r->u.rhlist.rowid_highest = m->rowid;
	} else
	  strbuf_json_null(b);
	strbuf_putc(b, ',');
	strbuf_sprintf(b, "%"PRIu64, m->rowid);
	strbuf_putc(b, ',');
	strbuf_json_string(b, m->service);
	strbuf_putc(b, ',');
	strbuf_json_hex(b, m->keypair.public_key.binary, sizeof m->keypair.public_key.binary);
	strbuf_putc(b, ',');
	strbuf_sprintf(b, "%"PRIu64, m->version);
	strbuf_putc(b, ',');
	if (m->has_date)
	  strbuf_sprintf(b, "%"PRItime_ms_t, m->date);
	else
	  strbuf_json_null(b);
	strbuf_putc(b, ',');
	strbuf_sprintf(b, "%"PRItime_ms_t",", m->inserttime);
	// The 'fromhere' flag indicates if the author is a known (unlocked) identity in the local
	// keyring.  The values are 0 (no), 1 (yes), 2 (yes and cryptographically verified).  In the
	// implementation below, the 0 value (no) is redundant, because it only occurs when the
	// 'author' column is null, but in future the author SID might be reported for non-local
	// authors, so clients should only use 'fromhere != 0', never 'author != null', to detect
	// local authorship.
	int fromhere = 0;
	switch (m->authorship) {
	  case AUTHOR_AUTHENTIC:
	    fromhere = 2;
	    strbuf_json_hex(b, m->author.binary, sizeof m->author.binary);
	    break;
	  case AUTHOR_LOCAL:
	    fromhere = 1;
	    strbuf_json_hex(b, m->author.binary, sizeof m->author.binary);
	    break;
	  case AUTHOR_REMOTE:
	    strbuf_json_hex(b, m->author.binary, sizeof m->author.binary);
	    break;
	  default:
	    strbuf_json_null(b);
	    break;
	}
	strbuf_putc(b, ',');
	strbuf_sprintf(b, "%d", fromhere);
	strbuf_putc(b, ',');
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
	  rhizome_list_commit(&r->u.rhlist.cursor);
	  ++r->u.rhlist.rowcount;
	}
      }
      return 1;
    case LIST_END:
      strbuf_puts(b, "\n]\n}\n");
      if (!strbuf_overrun(b))
	r->u.rhlist.phase = LIST_DONE;
      // fall through...
    case LIST_DONE:
      return 0;
  }
  abort();
}

static HTTP_REQUEST_PARSER restful_rhizome_insert_end;
static int insert_mime_part_start(struct http_request *);
static int insert_mime_part_end(struct http_request *);
static int insert_mime_part_header(struct http_request *, const struct mime_part_headers *);
static int insert_mime_part_body(struct http_request *, char *, size_t);

static int restful_rhizome_insert(httpd_request *r, const char *remainder)
{
  r->http.response.header.content_type = CONTENT_TYPE_JSON;
  r->http.render_extra_headers = render_manifest_headers;
  if (!is_rhizome_http_enabled())
    return 404;
  int ret = authorize_restful(&r->http);
  if (ret)
    return ret;
  if (*remainder)
    return 404;
  if (r->http.verb != HTTP_VERB_POST)
    return 405;
  // Parse the request body as multipart/form-data.
  assert(r->u.insert.current_part == NULL);
  assert(!r->u.insert.received_author);
  assert(!r->u.insert.received_secret);
  assert(!r->u.insert.received_bundleid);
  assert(!r->u.insert.received_manifest);
  assert(!r->u.insert.received_payload);
  bzero(&r->u.insert.write, sizeof r->u.insert.write);
  r->u.insert.write.blob_fd = -1;
  r->finalise_union = finalise_union_rhizome_insert;
  r->http.form_data.handle_mime_part_start = insert_mime_part_start;
  r->http.form_data.handle_mime_part_end = insert_mime_part_end;
  r->http.form_data.handle_mime_part_header = insert_mime_part_header;
  r->http.form_data.handle_mime_body = insert_mime_part_body;
  // Perform the insert once the body has arrived.
  r->http.handle_content_end = restful_rhizome_insert_end;
  return 1;
}

static int restful_rhizome_import(httpd_request *r, const char *remainder)
{
  int ret;
  r->u.insert.importing = 1;
  if ((ret = restful_rhizome_insert(r, remainder))!=1)
    return ret;

  const char *s_id = http_request_get_query_param(&r->http, "id");
  const char *s_version = http_request_get_query_param(&r->http, "version");

  // if we can reject the request now, the client won't have to send us the full manifest and payload
  if (s_id && s_version){
    rhizome_bid_t bid;
    uint64_t version;
    if (str_to_rhizome_bid_t(&bid, s_id) != -1
      && str_to_uint64(s_version, 10, &version, NULL) == 1){

      r->bundle_result.status = rhizome_is_interesting(&bid, version);
      switch (r->bundle_result.status){
	case RHIZOME_BUNDLE_STATUS_NEW:
	case RHIZOME_BUNDLE_STATUS_BUSY:
	  break;
	default:
	  return http_request_rhizome_response(r, 0, NULL);
      }
    }
  }

  return 1;
}

static int restful_rhizome_append(httpd_request *r, const char *remainder)
{
  r->u.insert.appending = 1;
  return restful_rhizome_insert(r, remainder);
}

static char PART_MANIFEST[] = "manifest";
static char PART_PAYLOAD[] = "payload";
static char PART_BUNDLEID[] = "bundle-id";
static char PART_AUTHOR[] = "bundle-author";
static char PART_SECRET[] = "bundle-secret";

static int insert_mime_part_start(struct http_request *hr)
{
  httpd_request *r = (httpd_request *) hr;
  assert(r->u.insert.current_part == NULL);
  return 0;
}

static int insert_make_manifest(httpd_request *r)
{
  if (!r->u.insert.received_manifest)
    return http_response_form_part(r, 400, "Missing", PART_MANIFEST, NULL, 0);
  if ((r->manifest = rhizome_new_manifest()) == NULL)
    return http_request_rhizome_response(r, 429, "Manifest table full"); // Too Many Requests
  assert(r->u.insert.manifest.length <= sizeof r->manifest->manifestdata);
  memcpy(r->manifest->manifestdata, r->u.insert.manifest.buffer, r->u.insert.manifest.length);
  r->manifest->manifest_all_bytes = r->u.insert.manifest.length;
  int n = rhizome_manifest_parse(r->manifest);
  switch (n) {
    case 0:
      if (r->u.insert.importing){
	const char *invalid_reason;
	if ((invalid_reason = rhizome_manifest_validate_reason(r->manifest))){
	  r->bundle_result = rhizome_bundle_result_static(RHIZOME_BUNDLE_STATUS_INVALID, invalid_reason);
	  break;
	}
	if (!rhizome_manifest_verify(r->manifest)){
	  r->bundle_result = rhizome_bundle_result_static(RHIZOME_BUNDLE_STATUS_INVALID, "Invalid manifest: Invalid signature");
	  break;
	}
	r->bundle_result.status = rhizome_manifest_check_stored(r->manifest, NULL);
	break;
      }

      if (r->manifest->malformed) {
	r->bundle_result = rhizome_bundle_result_sprintf(RHIZOME_BUNDLE_STATUS_INVALID, "Malformed manifest: %s", r->manifest->malformed);
      } else {
	rhizome_manifest *mout = NULL;
	r->bundle_result = rhizome_manifest_add_file(r->u.insert.appending, r->manifest, &mout,
						    r->u.insert.received_bundleid ? &r->bid : NULL,
						    r->u.insert.received_secret ? &r->u.insert.bundle_secret : NULL,
						    r->u.insert.received_author ? &r->u.insert.author : NULL,
						    NULL, 0, NULL);
	if (mout && mout != r->manifest){
	  rhizome_manifest_free(r->manifest);
	  r->manifest = mout;
	}
      }
      break;
    case 1:
      r->bundle_result = rhizome_bundle_result_static(RHIZOME_BUNDLE_STATUS_INVALID, "Invalid manifest");
      break;
    default:
      WHYF("rhizome_manifest_parse() returned %d", n);
      // fall through
    case -1:
      r->bundle_result = rhizome_bundle_result_static(RHIZOME_BUNDLE_STATUS_ERROR, "Error while parsing manifest");
      break;
  }

  switch (r->bundle_result.status) {
  case RHIZOME_BUNDLE_STATUS_NEW:
    break;
  case RHIZOME_BUNDLE_STATUS_OLD:
  case RHIZOME_BUNDLE_STATUS_SAME:
  case RHIZOME_BUNDLE_STATUS_DUPLICATE:
  case RHIZOME_BUNDLE_STATUS_NO_ROOM:
  case RHIZOME_BUNDLE_STATUS_INCONSISTENT:
  case RHIZOME_BUNDLE_STATUS_INVALID:
  case RHIZOME_BUNDLE_STATUS_BUSY:
  case RHIZOME_BUNDLE_STATUS_FAKE:
  case RHIZOME_BUNDLE_STATUS_READONLY:
  case RHIZOME_BUNDLE_STATUS_MANIFEST_TOO_BIG:
  case RHIZOME_BUNDLE_STATUS_ERROR:
    return http_request_rhizome_response(r, 0, NULL);
  }
  assert(r->manifest != NULL);
  return 0;
}

static int insert_mime_part_header(struct http_request *hr, const struct mime_part_headers *h)
{
  httpd_request *r = (httpd_request *) hr;
  if (!h->content_disposition.type[0])
    return http_response_content_disposition(r, 415, "Missing", h->content_disposition.type);
  if (strcmp(h->content_disposition.type, "form-data") != 0)
    return http_response_content_disposition(r, 415, "Unsupported", h->content_disposition.type);
  if (strcmp(h->content_disposition.name, PART_AUTHOR) == 0) {
    if (r->u.insert.received_author)
      return http_response_form_part(r, 400, "Duplicate", PART_AUTHOR, NULL, 0);
    // Reject a request if this parameter comes after the manifest part.
    if (r->u.insert.received_manifest || r->u.insert.importing)
      return http_response_form_part(r, 400, "Spurious", PART_AUTHOR, NULL, 0);
    // TODO enforce correct content type
    r->u.insert.current_part = PART_AUTHOR;
    assert(r->u.insert.author_hex_len == 0);
  }
  else if (strcmp(h->content_disposition.name, PART_SECRET) == 0) {
    if (r->u.insert.received_secret)
      return http_response_form_part(r, 400, "Duplicate", PART_SECRET, NULL, 0);
    // Reject a request if this parameter comes after the manifest part.
    if (r->u.insert.received_manifest || r->u.insert.importing)
      return http_response_form_part(r, 400, "Spurious", PART_SECRET, NULL, 0);
    // TODO enforce correct content type
    r->u.insert.current_part = PART_SECRET;
    assert(r->u.insert.secret_text_len == 0);
  }
  else if (strcmp(h->content_disposition.name, PART_BUNDLEID) == 0) {
    if (r->u.insert.received_bundleid)
      return http_response_form_part(r, 400, "Duplicate", PART_BUNDLEID, NULL, 0);
    // Reject a request if this parameter comes after the manifest part.
    if (r->u.insert.received_manifest || r->u.insert.importing)
      return http_response_form_part(r, 400, "Spurious", PART_BUNDLEID, NULL, 0);
    // TODO enforce correct content type
    r->u.insert.current_part = PART_BUNDLEID;
    assert(r->u.insert.bid_text_len == 0);
  }
  else if (strcmp(h->content_disposition.name, PART_MANIFEST) == 0) {
    // Reject a request if it has a repeated manifest part.
    if (r->u.insert.received_manifest)
      return http_response_form_part(r, 400, "Duplicate", PART_MANIFEST, NULL, 0);
    form_buf_malloc_init(&r->u.insert.manifest, MAX_MANIFEST_BYTES);
    if (   strcmp(h->content_type.type, "rhizome") != 0
	|| strcmp(h->content_type.subtype, "manifest") != 0
    )
      return http_response_form_part(r, 415, "Unsupported Content-Type in", PART_MANIFEST, NULL, 0);
    if ((strcmp(h->content_type.format, "text+binarysig") != 0)
        &&strlen(h->content_type.format))
      return http_response_form_part(r, 415, "Unsupported rhizome/manifest format in", PART_MANIFEST, NULL, 0);
    r->u.insert.current_part = PART_MANIFEST;
  }
  else if (strcmp(h->content_disposition.name, PART_PAYLOAD) == 0) {
    // Reject a request if it has a repeated payload part.
    if (r->u.insert.received_payload)
      return http_response_form_part(r, 400, "Duplicate", PART_PAYLOAD, NULL, 0);
    // Reject a request if it has a missing manifest part preceding the payload part.
    if (!r->u.insert.received_manifest)
      return http_response_form_part(r, 400, "Missing", PART_MANIFEST, NULL, 0);
    assert(r->manifest != NULL);
    if (r->u.insert.importing && (r->manifest->filesize == 0 || !r->manifest->has_filehash))
      return http_response_form_part(r, 400, "Spurious", PART_PAYLOAD, NULL, 0);

    // TODO enforce correct content type
    r->u.insert.current_part = PART_PAYLOAD;

    if (r->u.insert.importing){
      r->payload_status = rhizome_open_write(&r->u.insert.write, &r->manifest->filehash, r->manifest->filesize);
    }else{
      // If the manifest does not contain a 'name' field, then assign it from the payload filename.
      if (strcasecmp(RHIZOME_SERVICE_FILE, r->manifest->service) == 0
	  && r->manifest->name == NULL
	  && *h->content_disposition.filename
      )
	rhizome_manifest_set_name_from_path(r->manifest, h->content_disposition.filename);
      // Start writing the payload content into the Rhizome store.
      if (r->u.insert.appending) {
	r->payload_status = rhizome_write_open_journal(&r->u.insert.write, r->manifest, 0, RHIZOME_SIZE_UNSET);
      } else {
	// Note: r->manifest->filesize can be RHIZOME_SIZE_UNSET at this point, if the manifest did
	// not contain a 'filesize' field.
	r->payload_status = rhizome_write_open_manifest(&r->u.insert.write, r->manifest);
      }
    }
    // complete early so the client doesn't have to send the payload
    if (r->payload_status != RHIZOME_PAYLOAD_STATUS_NEW)
      return http_request_rhizome_response(r, 0, NULL);

    r->u.insert.payload_size = 0;
  }
  else
    return http_response_form_part(r, 400, "Unsupported", h->content_disposition.name, NULL, 0);
  return 0;
}

static int insert_mime_part_body(struct http_request *hr, char *buf, size_t len)
{
  httpd_request *r = (httpd_request *) hr;
  if (r->u.insert.current_part == PART_AUTHOR) {
    accumulate_text(r, PART_AUTHOR,
		    r->u.insert.author_hex,
		    sizeof r->u.insert.author_hex,
		    &r->u.insert.author_hex_len,
		    buf, len);
  }
  else if (r->u.insert.current_part == PART_SECRET) {
    accumulate_text(r, PART_SECRET,
		    r->u.insert.secret_text,
		    sizeof r->u.insert.secret_text,
		    &r->u.insert.secret_text_len,
		    buf, len);
  }
  else if (r->u.insert.current_part == PART_BUNDLEID) {
    accumulate_text(r, PART_BUNDLEID,
		    r->u.insert.bid_text,
		    sizeof r->u.insert.bid_text,
		    &r->u.insert.bid_text_len,
		    buf, len);
  }
  else if (r->u.insert.current_part == PART_MANIFEST) {
    form_buf_malloc_accumulate(r, PART_MANIFEST, &r->u.insert.manifest, buf, len);
  }
  else if (r->u.insert.current_part == PART_PAYLOAD) {
    r->u.insert.payload_size += len;
    switch (r->payload_status) {
      case RHIZOME_PAYLOAD_STATUS_NEW:
	if (rhizome_write_buffer(&r->u.insert.write, (unsigned char *)buf, len) == -1)
	  return http_request_rhizome_response(r, 500, "Error in payload write");
	break;
      case RHIZOME_PAYLOAD_STATUS_STORED:
	// TODO: calculate payload hash so it can be compared with stored payload
	break;
      default:
	break;
    }
  } else
    FATALF("current_part = %s", alloca_str_toprint(r->u.insert.current_part));
  return 0;
}

static int insert_mime_part_end(struct http_request *hr)
{
  httpd_request *r = (httpd_request *) hr;
  if (r->u.insert.current_part == PART_AUTHOR) {
    if (   r->u.insert.author_hex_len != sizeof r->u.insert.author_hex
	|| strn_to_sid_t(&r->u.insert.author, r->u.insert.author_hex, sizeof r->u.insert.author_hex) == -1
    )
      return http_response_form_part(r, 400, "Invalid", PART_AUTHOR, r->u.insert.author_hex, r->u.insert.author_hex_len);
    r->u.insert.received_author = 1;
    DEBUGF(rhizome, "received %s = %s", PART_AUTHOR, alloca_tohex_sid_t(r->u.insert.author));
  }
  else if (r->u.insert.current_part == PART_SECRET) {
    if (strn_to_rhizome_bsk_t(&r->u.insert.bundle_secret, r->u.insert.secret_text, r->u.insert.secret_text_len) == -1)
      return http_response_form_part(r, 400, "Invalid", PART_SECRET, r->u.insert.secret_text, r->u.insert.secret_text_len);
    r->u.insert.received_secret = 1;
    DEBUGF(rhizome, "received %s = %s", PART_SECRET, alloca_tohex_rhizome_bk_t(r->u.insert.bundle_secret));
  }
  else if (r->u.insert.current_part == PART_BUNDLEID) {
    if (strn_to_rhizome_bid_t(&r->bid, r->u.insert.bid_text, r->u.insert.bid_text_len) == -1)
      return http_response_form_part(r, 400, "Invalid", PART_BUNDLEID, r->u.insert.secret_text, r->u.insert.secret_text_len);
    r->u.insert.received_bundleid = 1;
    DEBUGF(rhizome, "received %s = %s", PART_BUNDLEID, alloca_tohex_rhizome_bid_t(r->bid));
  }
  else if (r->u.insert.current_part == PART_MANIFEST) {
    r->u.insert.received_manifest = 1;
    DEBUGF(rhizome, "received %s = %s", PART_MANIFEST, alloca_toprint(-1, r->u.insert.manifest.buffer, r->u.insert.manifest.length));
    int result = insert_make_manifest(r);
    if (result)
      return result;
  }
  else if (r->u.insert.current_part == PART_PAYLOAD) {
    r->u.insert.received_payload = 1;
    DEBUGF(rhizome, "received %s, %zd bytes", PART_PAYLOAD, r->u.insert.payload_size);
    r->payload_status = rhizome_finish_write(&r->u.insert.write);
  } else
    FATALF("current_part = %s", alloca_str_toprint(r->u.insert.current_part));
  r->u.insert.current_part = NULL;
  return 0;
}

static int restful_rhizome_insert_end(struct http_request *hr)
{
  httpd_request *r = (httpd_request *) hr;
  if (!r->u.insert.received_manifest)
    return http_response_form_part(r, 400, "Missing", PART_MANIFEST, NULL, 0);
  if (!r->u.insert.received_payload)
    return http_response_form_part(r, 400, "Missing", PART_PAYLOAD, NULL, 0);
  // Fill in the missing manifest fields and ensure payload and manifest are consistent.
  assert(r->manifest != NULL);
  DEBUGF(rhizome, "r->payload_status=%d %s", r->payload_status, rhizome_payload_status_message(r->payload_status));
  assert(r->u.insert.write.file_length != RHIZOME_SIZE_UNSET);
  if (r->u.insert.appending) {
    // For journal appends, the user cannot supply a 'filesize' field.  This will have been caught
    // by previous logic.  The manifest should also have a 'filesize' field by now.  The new payload
    // size should be the sum of 'filesize' and the appended portion.
    assert(r->manifest->is_journal);
    assert(r->manifest->filesize != RHIZOME_SIZE_UNSET);
    DEBUGF(rhizome, "file_length=%"PRIu64" filesize=%"PRIu64" payload_size=%"PRIu64,
	  r->u.insert.write.file_length,
	  r->manifest->filesize,
	  r->u.insert.payload_size);
    if (r->u.insert.write.file_length != r->manifest->filesize + r->u.insert.payload_size)
      r->payload_status = RHIZOME_PAYLOAD_STATUS_WRONG_SIZE;
  } else {
    // The Rhizome CLI 'add file' operation allows the user to supply a 'filesize' field which is
    // smaller than the supplied file, for convenience, to allow only the first part of a file to be
    // added as a payload.  But the RESTful interface doesn't allow that.
    assert(!r->manifest->is_journal);
    if (r->manifest->filesize != RHIZOME_SIZE_UNSET && r->u.insert.payload_size != r->manifest->filesize)
      r->payload_status = RHIZOME_PAYLOAD_STATUS_WRONG_SIZE;
  }
  r->payload_status = rhizome_finish_store(&r->u.insert.write, r->manifest, r->payload_status);
  int status_valid = 0;
  switch (r->payload_status) {
    case RHIZOME_PAYLOAD_STATUS_NEW:
    case RHIZOME_PAYLOAD_STATUS_STORED:
    case RHIZOME_PAYLOAD_STATUS_EMPTY:
      status_valid = 1;
      break;
    case RHIZOME_PAYLOAD_STATUS_WRONG_SIZE:
      r->bundle_result = rhizome_bundle_result_sprintf(RHIZOME_BUNDLE_STATUS_INCONSISTENT,
						       "Payload size (%"PRIu64") contradicts manifest (filesize=%"PRIu64")",
						       r->u.insert.payload_size, r->manifest->filesize);
      return http_request_rhizome_response(r, 0, "Inconsistent filesize");
    case RHIZOME_PAYLOAD_STATUS_WRONG_HASH:
      r->bundle_result = rhizome_bundle_result_sprintf(RHIZOME_BUNDLE_STATUS_INCONSISTENT,
						       "Payload hash (%s) contradicts manifest (filehash=%s)",
						       alloca_tohex_rhizome_filehash_t(r->u.insert.write.id),
						       alloca_tohex_rhizome_filehash_t(r->manifest->filehash));
      return http_request_rhizome_response(r, 0, "Inconsistent filehash");
    case RHIZOME_PAYLOAD_STATUS_CRYPTO_FAIL:
      r->bundle_result = rhizome_bundle_result(RHIZOME_BUNDLE_STATUS_READONLY);
      return http_request_rhizome_response(r, 0, NULL);
    case RHIZOME_PAYLOAD_STATUS_TOO_BIG:
      r->bundle_result = rhizome_bundle_result(RHIZOME_BUNDLE_STATUS_NO_ROOM);
      return http_request_rhizome_response(r, 0, NULL);
    case RHIZOME_PAYLOAD_STATUS_EVICTED:
      r->bundle_result = rhizome_bundle_result(RHIZOME_BUNDLE_STATUS_NO_ROOM);
      return http_request_rhizome_response(r, 0, NULL);
    case RHIZOME_PAYLOAD_STATUS_BUSY:
      r->bundle_result = rhizome_bundle_result(RHIZOME_BUNDLE_STATUS_BUSY);
      return http_request_rhizome_response(r, 0, NULL);
    case RHIZOME_PAYLOAD_STATUS_ERROR:
      return http_request_rhizome_response(r, 500, "Payload store error");
  }
  if (!status_valid)
    FATALF("rhizome_finish_store() returned status = %d", r->payload_status);

  rhizome_manifest *mout = NULL;
  if (r->u.insert.importing){
    r->bundle_result = rhizome_bundle_result(rhizome_add_manifest_to_store(r->manifest, &mout));
  }else{
    // Finalise the manifest and add it to the store.
    const char *invalid_reason = rhizome_manifest_validate_reason(r->manifest);
    if (invalid_reason) {
      r->bundle_result = rhizome_bundle_result_static(RHIZOME_BUNDLE_STATUS_INVALID, invalid_reason);
      return http_request_rhizome_response(r, 0, NULL);
    }
    if (r->manifest->malformed) {
      r->bundle_result = rhizome_bundle_result_static(RHIZOME_BUNDLE_STATUS_INVALID, r->manifest->malformed);
      return http_request_rhizome_response(r, 0, NULL);
    }
    if (!r->manifest->haveSecret) {
      r->bundle_result = rhizome_bundle_result_static(RHIZOME_BUNDLE_STATUS_READONLY, "Missing bundle secret");
      return http_request_rhizome_response(r, 0, NULL);
    }
    rhizome_bundle_result_free(&r->bundle_result);
    r->bundle_result = rhizome_manifest_finalise(r->manifest, &mout, !r->u.insert.force_new);
  }
  int http_status = 500;
  switch (r->bundle_result.status) {
    case RHIZOME_BUNDLE_STATUS_NEW:
      if (mout && mout != r->manifest)
	rhizome_manifest_free(mout);
      http_status = 201;
      break;
    case RHIZOME_BUNDLE_STATUS_OLD:
      if (mout && mout != r->manifest) {
	rhizome_manifest_free(r->manifest);
	r->manifest = mout;
      }
      http_status = 202;
      break;
    case RHIZOME_BUNDLE_STATUS_SAME:
    case RHIZOME_BUNDLE_STATUS_DUPLICATE:
      if (mout && mout != r->manifest) {
	rhizome_manifest_free(r->manifest);
	r->manifest = mout;
      }
      http_status = 200;
      break;
    case RHIZOME_BUNDLE_STATUS_ERROR:
    case RHIZOME_BUNDLE_STATUS_INVALID:
    case RHIZOME_BUNDLE_STATUS_FAKE:
    case RHIZOME_BUNDLE_STATUS_INCONSISTENT:
    case RHIZOME_BUNDLE_STATUS_NO_ROOM:
    case RHIZOME_BUNDLE_STATUS_READONLY:
    case RHIZOME_BUNDLE_STATUS_BUSY:
    case RHIZOME_BUNDLE_STATUS_MANIFEST_TOO_BIG:
      if (mout && mout != r->manifest)
	rhizome_manifest_free(mout);
      rhizome_manifest_free(r->manifest);
      r->manifest = NULL;
      return http_request_rhizome_response(r, 0, NULL);
  }
  if (http_status == 500)
    FATALF("rhizome_manifest_finalise() returned status=%d", r->bundle_result.status);
  if (r->u.insert.importing){
    return http_request_rhizome_response(r, http_status, NULL);
  }else{
    rhizome_authenticate_author(r->manifest);
    http_request_response_static(&r->http, http_status, "rhizome-manifest/text",
	(const char *)r->manifest->manifestdata, r->manifest->manifest_all_bytes
      );
  }
  return 0;
}

static HTTP_HANDLER restful_rhizome_bid_rhm;
static HTTP_HANDLER restful_rhizome_bid_raw_bin;
static HTTP_HANDLER restful_rhizome_bid_decrypted_bin;

static int restful_rhizome_(httpd_request *r, const char *remainder)
{
  r->http.response.header.content_type = CONTENT_TYPE_JSON;
  r->http.render_extra_headers = render_manifest_headers;
  if (!is_rhizome_http_enabled())
    return 404;
  int ret = authorize_restful(&r->http);
  if (ret)
    return ret;
  HTTP_HANDLER *handler = NULL;
  rhizome_bid_t bid;
  const char *end;
  if (parse_rhizome_bid_t(&bid, remainder, -1, &end) != -1) {
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
  if ((r->manifest = rhizome_new_manifest()) == NULL)
    return http_request_rhizome_response(r, 429, "Manifest table full"); // Too Many Requests
  r->bundle_result.status = rhizome_retrieve_manifest(&bid, r->manifest);
  switch(r->bundle_result.status){
    case RHIZOME_BUNDLE_STATUS_SAME:
      rhizome_authenticate_author(r->manifest);
      break;
    case RHIZOME_BUNDLE_STATUS_NEW:
      rhizome_manifest_free(r->manifest);
      r->manifest = NULL;
      break;
    case RHIZOME_BUNDLE_STATUS_BUSY:
      rhizome_manifest_free(r->manifest);
      return http_request_rhizome_response(r, 0, NULL);
    case RHIZOME_BUNDLE_STATUS_ERROR:
      rhizome_manifest_free(r->manifest);
      r->manifest = NULL;
      return http_request_rhizome_response(r, 500, "Manifest retrieve error");
    default: // should not return others
      FATALF("rhizome_retrieve_manifest() returned status = %d", r->bundle_result.status);
  }
  return handler(r, remainder);
}

static int restful_rhizome_bid_rhm(httpd_request *r, const char *remainder)
{
  if (*remainder)
    return 404;
  if (r->manifest == NULL)
    return http_request_rhizome_response(r, 404, "Bundle not found"); // Not Found
  http_request_response_static(&r->http, 200, "rhizome-manifest/text",
      (const char *)r->manifest->manifestdata, r->manifest->manifest_all_bytes
    );
  return 1;
}

static int restful_rhizome_bid_raw_bin(httpd_request *r, const char *remainder)
{
  if (*remainder)
    return 404;
  if (r->manifest == NULL)
    return http_request_rhizome_response(r, 404, "Bundle not found"); // Not Found
  if (r->manifest->filesize == 0) {
    http_request_response_static(&r->http, 200, CONTENT_TYPE_BLOB, "", 0);
    return 1;
  }
  int ret = rhizome_response_content_init_filehash(r, &r->manifest->filehash);
  if (ret)
    return ret;
  http_request_response_generated(&r->http, 200, CONTENT_TYPE_BLOB, rhizome_payload_content);
  return 1;
}

static int restful_rhizome_bid_decrypted_bin(httpd_request *r, const char *remainder)
{
  if (*remainder)
    return 404;
  if (r->manifest == NULL)
    return http_request_rhizome_response(r, 404, "Bundle not found"); // Not Found
  if (r->manifest->filesize == 0) {
    // TODO use Content Type from manifest (once it is implemented)
    http_request_response_static(&r->http, 200, CONTENT_TYPE_BLOB, "", 0);
    return 1;
  }
  int ret = rhizome_response_content_init_payload(r, r->manifest);
  if (ret)
    return ret;
  // TODO use Content Type from manifest (once it is implemented)
  http_request_response_generated(&r->http, 200, CONTENT_TYPE_BLOB, rhizome_payload_content);
  return 1;
}

static int rhizome_response_content_init_read_state(httpd_request *r)
{
  if (r->u.read_state.length == RHIZOME_SIZE_UNSET && rhizome_read(&r->u.read_state, NULL, 0)) {
    rhizome_read_close(&r->u.read_state);
    return http_request_rhizome_response(r, 404, "Payload not found");
  }
  assert(r->u.read_state.length != RHIZOME_SIZE_UNSET);
  int ret = http_response_init_content_range(r, r->u.read_state.length);
  if (ret==0)
    r->u.read_state.offset = r->http.response.header.content_range_start;
  return ret;
}

int rhizome_response_content_init_filehash(httpd_request *r, const rhizome_filehash_t *hash)
{
  bzero(&r->u.read_state, sizeof r->u.read_state);
  r->u.read_state.blob_fd = -1;
  assert(r->finalise_union == NULL);
  r->finalise_union = finalise_union_read_state;
  r->payload_status = rhizome_open_read(&r->u.read_state, hash);
  switch (r->payload_status) {
    case RHIZOME_PAYLOAD_STATUS_EMPTY:
    case RHIZOME_PAYLOAD_STATUS_STORED:
      return rhizome_response_content_init_read_state(r);
    case RHIZOME_PAYLOAD_STATUS_NEW:
      return http_request_rhizome_response(r, 404, "Payload not found");
    case RHIZOME_PAYLOAD_STATUS_ERROR:
    case RHIZOME_PAYLOAD_STATUS_BUSY:
    case RHIZOME_PAYLOAD_STATUS_WRONG_SIZE:
    case RHIZOME_PAYLOAD_STATUS_WRONG_HASH:
    case RHIZOME_PAYLOAD_STATUS_CRYPTO_FAIL:
    case RHIZOME_PAYLOAD_STATUS_TOO_BIG:
    case RHIZOME_PAYLOAD_STATUS_EVICTED:
      return http_request_rhizome_response(r, 500, "Payload read error");
  }
  FATALF("rhizome_open_read() returned status = %d", r->payload_status);
}

int rhizome_response_content_init_payload(httpd_request *r, rhizome_manifest *m)
{
  bzero(&r->u.read_state, sizeof r->u.read_state);
  r->u.read_state.blob_fd = -1;
  assert(r->finalise_union == NULL);
  r->finalise_union = finalise_union_read_state;
  r->payload_status = rhizome_open_decrypt_read(m, &r->u.read_state);
  switch (r->payload_status) {
    case RHIZOME_PAYLOAD_STATUS_EMPTY:
    case RHIZOME_PAYLOAD_STATUS_STORED:
      return rhizome_response_content_init_read_state(r);
    case RHIZOME_PAYLOAD_STATUS_NEW:
      return http_request_rhizome_response(r, 404, "Payload not found");
    case RHIZOME_PAYLOAD_STATUS_CRYPTO_FAIL:
      return http_request_rhizome_response(r, 419, "Payload decryption error"); // Authentication Timeout
    case RHIZOME_PAYLOAD_STATUS_BUSY:
    case RHIZOME_PAYLOAD_STATUS_ERROR:
    case RHIZOME_PAYLOAD_STATUS_WRONG_SIZE:
    case RHIZOME_PAYLOAD_STATUS_WRONG_HASH:
    case RHIZOME_PAYLOAD_STATUS_TOO_BIG:
    case RHIZOME_PAYLOAD_STATUS_EVICTED:
      return http_request_rhizome_response(r, 500, "Payload read error");
  }
  FATALF("rhizome_open_decrypt_read() returned status = %d", r->payload_status);
}

int rhizome_payload_content(struct http_request *hr, unsigned char *buf, size_t bufsz, struct http_content_generator_result *result)
{
  // Only read multiples of 4k from disk.
  const size_t blocksz = 1 << 12;
  // Ask for a large buffer for all future reads.
  const size_t preferred_bufsz = 16 * blocksz;
  // Reads the next part of the payload into the supplied buffer.
  httpd_request *r = (httpd_request *) hr;
  assert(r->u.read_state.length != RHIZOME_SIZE_UNSET);
  assert(r->u.read_state.offset < r->u.read_state.length);
  uint64_t remain = r->u.read_state.length - r->u.read_state.offset;
  size_t readlen = bufsz;
  if (remain <= bufsz)
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

static void render_manifest_headers(struct http_request *hr, strbuf sb)
{
  httpd_request *r = (httpd_request *) hr;
  switch (r->bundle_result.status) {
    case RHIZOME_BUNDLE_STATUS_NEW:
    case RHIZOME_BUNDLE_STATUS_SAME:
    case RHIZOME_BUNDLE_STATUS_DUPLICATE:
    case RHIZOME_BUNDLE_STATUS_OLD:
    case RHIZOME_BUNDLE_STATUS_INVALID:
    case RHIZOME_BUNDLE_STATUS_FAKE:
    case RHIZOME_BUNDLE_STATUS_INCONSISTENT:
    case RHIZOME_BUNDLE_STATUS_NO_ROOM:
    case RHIZOME_BUNDLE_STATUS_READONLY:
    case RHIZOME_BUNDLE_STATUS_BUSY:
    case RHIZOME_BUNDLE_STATUS_MANIFEST_TOO_BIG:
    case RHIZOME_BUNDLE_STATUS_ERROR:
      strbuf_sprintf(sb, "Serval-Rhizome-Result-Bundle-Status-Code: %d\r\n", r->bundle_result.status);
      strbuf_puts(sb, "Serval-Rhizome-Result-Bundle-Status-Message: ");
      strbuf_json_string(sb, rhizome_bundle_result_message_nonnull(r->bundle_result));
      strbuf_puts(sb, "\r\n");
      break;
  }
  const char *status_message = rhizome_payload_status_message(r->payload_status);
  if (status_message) {
      strbuf_sprintf(sb, "Serval-Rhizome-Result-Payload-Status-Code: %d\r\n", r->payload_status);
      strbuf_puts(sb, "Serval-Rhizome-Result-Payload-Status-Message: ");
      strbuf_json_string(sb, status_message);
      strbuf_puts(sb, "\r\n");
  }
  rhizome_manifest *m = r->manifest;
  if (m) {
    if (m->has_id)
      strbuf_sprintf(sb, "Serval-Rhizome-Bundle-Id: %s\r\n", alloca_tohex_rhizome_bid_t(m->keypair.public_key));
    if (m->version)
      strbuf_sprintf(sb, "Serval-Rhizome-Bundle-Version: %"PRIu64"\r\n", m->version);
    if (m->filesize != RHIZOME_SIZE_UNSET)
      strbuf_sprintf(sb, "Serval-Rhizome-Bundle-Filesize: %"PRIu64"\r\n", m->filesize);
    if (m->has_filehash)
      strbuf_sprintf(sb, "Serval-Rhizome-Bundle-Filehash: %s\r\n", alloca_tohex_rhizome_filehash_t(m->filehash));
    if (m->has_sender)
      strbuf_sprintf(sb, "Serval-Rhizome-Bundle-Sender: %s\r\n", alloca_tohex_sid_t(m->sender));
    if (m->has_recipient)
      strbuf_sprintf(sb, "Serval-Rhizome-Bundle-Recipient: %s\r\n", alloca_tohex_sid_t(m->recipient));
    if (m->has_bundle_key)
      strbuf_sprintf(sb, "Serval-Rhizome-Bundle-BK: %s\r\n", alloca_tohex_rhizome_bk_t(m->bundle_key));
    switch (m->payloadEncryption) {
      case PAYLOAD_CRYPT_UNKNOWN:
	break;
      case PAYLOAD_CLEAR:
	strbuf_sprintf(sb, "Serval-Rhizome-Bundle-Crypt: 0\r\n");
	break;
      case PAYLOAD_ENCRYPTED:
	strbuf_sprintf(sb, "Serval-Rhizome-Bundle-Crypt: 1\r\n");
	break;
    }
    if (m->is_journal)
      strbuf_sprintf(sb, "Serval-Rhizome-Bundle-Tail: %"PRIu64"\r\n", m->tail);
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
    if (m->haveSecret) {
      char secret[RHIZOME_BUNDLE_KEY_STRLEN + 1];
      rhizome_bytes_to_hex_upper(m->keypair.binary, secret, RHIZOME_BUNDLE_KEY_BYTES);
      strbuf_sprintf(sb, "Serval-Rhizome-Bundle-Secret: %s\r\n", secret);
    }
    if (m->rowid)
      strbuf_sprintf(sb, "Serval-Rhizome-Bundle-Rowid: %"PRIu64"\r\n", m->rowid);
    if (m->inserttime)
      strbuf_sprintf(sb, "Serval-Rhizome-Bundle-Inserttime: %"PRIu64"\r\n", m->inserttime);
  }
}
