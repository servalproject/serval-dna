/*
Serval DNA Rhizome HTTP RESTful interface
Copyright (C) 2013,2014 Serval Project Inc.
 
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

#include "conf.h"
#include "serval.h"
#include "httpd.h"
#include "strbuf_helpers.h"

static HTTP_RENDERER render_manifest_headers;

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
  if (base64url_decode(token, sizeof token, str, 0, afterp, 0, NULL) != sizeof token)
    return 0;
  if (cmp_uuid_t(&rhizome_db_uuid, (serval_uuid_t *) &token) != 0)
    return 0;
  memcpy(rowidp, token + sizeof rhizome_db_uuid.u.binary, sizeof *rowidp);
  return 1;
}

static HTTP_CONTENT_GENERATOR restful_rhizome_bundlelist_json_content;

int restful_rhizome_bundlelist_json(httpd_request *r, const char *remainder)
{
  r->http.response.header.content_type = CONTENT_TYPE_JSON;
  if (!is_rhizome_http_enabled())
    return 403;
  if (*remainder)
    return 404;
  if (r->http.verb != HTTP_VERB_GET)
    return 405;
  int ret = authorize(&r->http);
  if (ret)
    return ret;
  r->u.rhlist.phase = LIST_HEADER;
  r->u.rhlist.rowcount = 0;
  bzero(&r->u.rhlist.cursor, sizeof r->u.rhlist.cursor);
  http_request_response_generated(&r->http, 200, CONTENT_TYPE_JSON, restful_rhizome_bundlelist_json_content);
  return 1;
}

static HTTP_CONTENT_GENERATOR_STRBUF_CHUNKER restful_rhizome_bundlelist_json_content_chunk;

static int restful_rhizome_bundlelist_json_content(struct http_request *hr, unsigned char *buf, size_t bufsz, struct http_content_generator_result *result)
{
  httpd_request *r = (httpd_request *) hr;
  int ret = rhizome_list_open(&r->u.rhlist.cursor);
  if (ret == -1)
    return -1;
  ret = generate_http_content_from_strbuf_chunks(hr, (char *)buf, bufsz, result, restful_rhizome_bundlelist_json_content_chunk);
  rhizome_list_release(&r->u.rhlist.cursor);
  return ret;
}

int restful_rhizome_newsince(httpd_request *r, const char *remainder)
{
  r->http.response.header.content_type = CONTENT_TYPE_JSON;
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
  r->u.rhlist.phase = LIST_HEADER;
  r->u.rhlist.rowcount = 0;
  bzero(&r->u.rhlist.cursor, sizeof r->u.rhlist.cursor);
  r->u.rhlist.cursor.rowid_since = rowid;
  r->u.rhlist.end_time = gettime_ms() + config.rhizome.api.restful.newsince_timeout * 1000;
  http_request_response_generated(&r->http, 200, CONTENT_TYPE_JSON, restful_rhizome_bundlelist_json_content);
  return 1;
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
    case LIST_ROWS:
      {
	int ret = rhizome_list_next(&r->u.rhlist.cursor);
	if (ret == -1)
	  return -1;
	if (ret == 0) {
	  time_ms_t now;
	  if (r->u.rhlist.cursor.rowid_since == 0 || (now = gettime_ms()) >= r->u.rhlist.end_time) {
	    r->u.rhlist.phase = LIST_END;
	    return 1;
	  }
	  time_ms_t wake_at = now + config.rhizome.api.restful.newsince_poll_ms;
	  if (wake_at > r->u.rhlist.end_time)
	    wake_at = r->u.rhlist.end_time;
	  http_request_pause_response(&r->http, wake_at);
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

int restful_rhizome_insert(httpd_request *r, const char *remainder)
{
  r->http.response.header.content_type = CONTENT_TYPE_JSON;
  if (*remainder)
    return 404;
  if (!is_rhizome_http_enabled())
    return 403;
  if (r->http.verb != HTTP_VERB_POST)
    return 405;
  int ret = authorize(&r->http);
  if (ret)
    return ret;
  // Parse the request body as multipart/form-data.
  assert(r->u.insert.current_part == NULL);
  assert(!r->u.insert.received_author);
  assert(!r->u.insert.received_secret);
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

static char PART_MANIFEST[] = "manifest";
static char PART_PAYLOAD[] = "payload";
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
    return http_response_form_part(r, "Missing", PART_MANIFEST, NULL, 0);
  if ((r->manifest = rhizome_new_manifest())) {
    if (r->u.insert.manifest.length == 0)
      return 0;
    assert(r->u.insert.manifest.length <= sizeof r->manifest->manifestdata);
    memcpy(r->manifest->manifestdata, r->u.insert.manifest.buffer, r->u.insert.manifest.length);
    r->manifest->manifest_all_bytes = r->u.insert.manifest.length;
    int n = rhizome_manifest_parse(r->manifest);
    switch (n) {
      case -1:
	break;
      case 0:
	if (!r->manifest->malformed)
	  return 0;
	// fall through
      case 1:
	http_request_simple_response(&r->http, 403, "Malformed manifest");
	return 403;
      default:
	WHYF("rhizome_manifest_parse() returned %d", n);
	break;
    }
  }
  return 500;
}

static int insert_mime_part_header(struct http_request *hr, const struct mime_part_headers *h)
{
  httpd_request *r = (httpd_request *) hr;
  if (strcmp(h->content_disposition.type, "form-data") != 0)
    return http_response_content_disposition(r, "Unsupported", h->content_disposition.type);
  if (strcmp(h->content_disposition.name, PART_AUTHOR) == 0) {
    if (r->u.insert.received_author)
      return http_response_form_part(r, "Duplicate", PART_AUTHOR, NULL, 0);
    r->u.insert.current_part = PART_AUTHOR;
    assert(r->u.insert.author_hex_len == 0);
  }
  else if (strcmp(h->content_disposition.name, PART_SECRET) == 0) {
    if (r->u.insert.received_secret)
      return http_response_form_part(r, "Duplicate", PART_SECRET, NULL, 0);
    r->u.insert.current_part = PART_SECRET;
    assert(r->u.insert.secret_hex_len == 0);
  }
  else if (strcmp(h->content_disposition.name, PART_MANIFEST) == 0) {
    // Reject a request if it has a repeated manifest part.
    if (r->u.insert.received_manifest)
      return http_response_form_part(r, "Duplicate", PART_MANIFEST, NULL, 0);
    form_buf_malloc_init(&r->u.insert.manifest, MAX_MANIFEST_BYTES);
    if (   strcmp(h->content_type.type, "rhizome-manifest") != 0
	|| strcmp(h->content_type.subtype, "text") != 0
    )
      return http_response_form_part(r, "Unsupported Content-Type in", PART_MANIFEST, NULL, 0);
    r->u.insert.current_part = PART_MANIFEST;
  }
  else if (strcmp(h->content_disposition.name, PART_PAYLOAD) == 0) {
    // Reject a request if it has a repeated payload part.
    if (r->u.insert.received_payload)
      return http_response_form_part(r, "Duplicate", PART_PAYLOAD, NULL, 0);
    // Reject a request if it has a missing manifest part preceding the payload part.
    if (!r->u.insert.received_manifest)
      return http_response_form_part(r, "Missing", PART_MANIFEST, NULL, 0);
    assert(r->manifest != NULL);
    r->u.insert.current_part = PART_PAYLOAD;
    // If the manifest does not contain a 'name' field, then assign it from the payload filename.
    if (   strcasecmp(RHIZOME_SERVICE_FILE, r->manifest->service) == 0
	&& r->manifest->name == NULL
	&& *h->content_disposition.filename
    )
      rhizome_manifest_set_name_from_path(r->manifest, h->content_disposition.filename);
    // Start writing the payload content into the Rhizome store.  Note: r->manifest->filesize can be
    // RHIZOME_SIZE_UNSET at this point, if the manifest did not contain a 'filesize' field.
    r->u.insert.payload_status = rhizome_write_open_manifest(&r->u.insert.write, r->manifest);
    r->u.insert.payload_size = 0;
    switch (r->u.insert.payload_status) {
      case RHIZOME_PAYLOAD_STATUS_ERROR:
	WHYF("rhizome_write_open_manifest() returned %d", r->u.insert.payload_status);
	return 500;
      case RHIZOME_PAYLOAD_STATUS_STORED:
	// TODO: initialise payload hash so it can be compared with stored payload
	break;
      default:
	break;
    }
  }
  else
    return http_response_form_part(r, "Unsupported", h->content_disposition.name, NULL, 0);
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
		    r->u.insert.secret_hex,
		    sizeof r->u.insert.secret_hex,
		    &r->u.insert.secret_hex_len,
		    buf, len);
  }
  else if (r->u.insert.current_part == PART_MANIFEST) {
    form_buf_malloc_accumulate(r, PART_MANIFEST, &r->u.insert.manifest, buf, len);
  }
  else if (r->u.insert.current_part == PART_PAYLOAD) {
    r->u.insert.payload_size += len;
    switch (r->u.insert.payload_status) {
      case RHIZOME_PAYLOAD_STATUS_NEW:
	if (rhizome_write_buffer(&r->u.insert.write, (unsigned char *)buf, len) == -1)
	  return 500;
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
	|| strn_to_sid_t(&r->u.insert.author, r->u.insert.author_hex, sizeof r->u.insert.author_hex, NULL) == -1
    )
      return http_response_form_part(r, "Invalid", PART_AUTHOR, r->u.insert.author_hex, r->u.insert.author_hex_len);
    r->u.insert.received_author = 1;
    if (config.debug.rhizome)
      DEBUGF("received %s = %s", PART_AUTHOR, alloca_tohex_sid_t(r->u.insert.author));
  }
  else if (r->u.insert.current_part == PART_SECRET) {
    if (   r->u.insert.secret_hex_len != sizeof r->u.insert.secret_hex
	|| strn_to_rhizome_bk_t(&r->u.insert.bundle_secret, r->u.insert.secret_hex, NULL) == -1
    )
      return http_response_form_part(r, "Invalid", PART_SECRET, r->u.insert.secret_hex, r->u.insert.secret_hex_len);
    r->u.insert.received_secret = 1;
    if (config.debug.rhizome)
      DEBUGF("received %s = %s", PART_SECRET, alloca_tohex_rhizome_bk_t(r->u.insert.bundle_secret));
  }
  else if (r->u.insert.current_part == PART_MANIFEST) {
    r->u.insert.received_manifest = 1;
    int result = insert_make_manifest(r);
    if (result)
      return result;
    if (r->manifest->has_id && r->u.insert.received_secret)
      rhizome_apply_bundle_secret(r->manifest, &r->u.insert.bundle_secret);
    if (r->manifest->service == NULL)
      rhizome_manifest_set_service(r->manifest, RHIZOME_SERVICE_FILE);
    if (rhizome_fill_manifest(r->manifest, NULL, r->u.insert.received_author ? &r->u.insert.author: NULL) == -1) {
      WHY("rhizome_fill_manifest() failed");
      return 500;
    }
    if (r->manifest->is_journal) {
      http_request_simple_response(&r->http, 403, "Insert not supported for journals");
      return 403;
    }
    assert(r->manifest != NULL);
  }
  else if (r->u.insert.current_part == PART_PAYLOAD) {
    r->u.insert.received_payload = 1;
    if (r->u.insert.payload_status == RHIZOME_PAYLOAD_STATUS_NEW)
      r->u.insert.payload_status = rhizome_finish_write(&r->u.insert.write);
    if (r->u.insert.payload_status == RHIZOME_PAYLOAD_STATUS_ERROR) {
      WHYF("rhizome_finish_write() returned status = %d", r->u.insert.payload_status);
      return 500;
    }
  } else
    FATALF("current_part = %s", alloca_str_toprint(r->u.insert.current_part));
  r->u.insert.current_part = NULL;
  return 0;
}

static int restful_rhizome_insert_end(struct http_request *hr)
{
  httpd_request *r = (httpd_request *) hr;
  if (!r->u.insert.received_manifest)
    return http_response_form_part(r, "Missing", PART_MANIFEST, NULL, 0);
  if (!r->u.insert.received_payload)
    return http_response_form_part(r, "Missing", PART_PAYLOAD, NULL, 0);
  // Fill in the missing manifest fields and ensure payload and manifest are consistent.
  assert(r->manifest != NULL);
  assert(r->u.insert.write.file_length != RHIZOME_SIZE_UNSET);
  switch (r->u.insert.payload_status) {
    case RHIZOME_PAYLOAD_STATUS_ERROR:
      return 500;
    case RHIZOME_PAYLOAD_STATUS_NEW:
      if (r->manifest->filesize == RHIZOME_SIZE_UNSET)
	rhizome_manifest_set_filesize(r->manifest, r->u.insert.write.file_length);
      // fall through
    case RHIZOME_PAYLOAD_STATUS_STORED:
      // TODO: check that stored hash matches received payload's hash
      // fall through
    case RHIZOME_PAYLOAD_STATUS_EMPTY:
      assert(r->manifest->filesize != RHIZOME_SIZE_UNSET);
      if (r->u.insert.payload_size == r->manifest->filesize)
	break;
      // fall through
    case RHIZOME_PAYLOAD_STATUS_WRONG_SIZE:
      {
	strbuf msg = strbuf_alloca(200);
	strbuf_sprintf(msg, "Payload size (%"PRIu64") contradicts manifest (filesize=%"PRIu64")", r->u.insert.payload_size, r->manifest->filesize);
	http_request_simple_response(&r->http, 403, strbuf_str(msg));
	return 403;
      }
    case RHIZOME_PAYLOAD_STATUS_TOO_BIG:
    case RHIZOME_PAYLOAD_STATUS_UNINITERESTING:
      http_request_simple_response(&r->http, 403, "Not enough space");
      return 403;
    case RHIZOME_PAYLOAD_STATUS_WRONG_HASH:
      http_request_simple_response(&r->http, 403, "Payload hash contradicts manifest");
      return 403;
    case RHIZOME_PAYLOAD_STATUS_CRYPTO_FAIL:
      http_request_simple_response(&r->http, 403, "Missing bundle secret");
      return 403;
    default:
      FATALF("payload_status = %d", r->u.insert.payload_status);
  }
  // Finalise the manifest and add it to the store.
  if (r->manifest->filesize) {
    if (!r->manifest->has_filehash)
      rhizome_manifest_set_filehash(r->manifest, &r->u.insert.write.id);
    else
      assert(cmp_rhizome_filehash_t(&r->u.insert.write.id, &r->manifest->filehash) == 0);
  }
  if (!rhizome_manifest_validate(r->manifest) || r->manifest->malformed) {
    http_request_simple_response(&r->http, 403, "Manifest is malformed");
    return 403;
  }
  if (!r->manifest->haveSecret) {
    http_request_simple_response(&r->http, 403, "Missing bundle secret");
    return 403;
  }
  rhizome_manifest *mout = NULL;
  int result;
  switch (rhizome_manifest_finalise(r->manifest, &mout, !r->u.insert.force_new)) {
    case RHIZOME_BUNDLE_STATUS_NEW:
      result = 201;
      if (mout && mout != r->manifest)
	rhizome_manifest_free(mout);
      mout = NULL;
      break;
    case RHIZOME_BUNDLE_STATUS_SAME:
    case RHIZOME_BUNDLE_STATUS_OLD:
    case RHIZOME_BUNDLE_STATUS_DUPLICATE:
      result = 200;
      break;
    case RHIZOME_BUNDLE_STATUS_INVALID:
      result = 403;
      break;
    case RHIZOME_BUNDLE_STATUS_ERROR:
    default:
      result = 500;
      break;
  }
  if (mout && mout != r->manifest) {
    rhizome_manifest_free(r->manifest);
    r->manifest = mout;
  }
  if (result >= 400)
    return result;
  rhizome_authenticate_author(r->manifest);
  r->http.render_extra_headers = render_manifest_headers;
  http_request_response_static(&r->http, result, "rhizome-manifest/text",
      (const char *)r->manifest->manifestdata, r->manifest->manifest_all_bytes
    );
  return 0;
}

static HTTP_HANDLER restful_rhizome_bid_rhm;
static HTTP_HANDLER restful_rhizome_bid_raw_bin;
static HTTP_HANDLER restful_rhizome_bid_decrypted_bin;

int restful_rhizome_(httpd_request *r, const char *remainder)
{
  r->http.response.header.content_type = CONTENT_TYPE_JSON;
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
  if ((r->manifest = rhizome_new_manifest()) == NULL)
    return 500;
  ret = rhizome_retrieve_manifest(&bid, r->manifest);
  if (ret == -1)
    return 500;
  if (ret == 0) {
    rhizome_authenticate_author(r->manifest);
    r->http.render_extra_headers = render_manifest_headers;
  } else {
    assert(r->manifest == NULL);
    assert(r->http.render_extra_headers == NULL);
  }
  ret = handler(r, remainder);
  return ret;
}

static int restful_rhizome_bid_rhm(httpd_request *r, const char *remainder)
{
  if (*remainder || r->manifest == NULL)
    return 404;
  http_request_response_static(&r->http, 200, "rhizome-manifest/text",
      (const char *)r->manifest->manifestdata, r->manifest->manifest_all_bytes
    );
  return 1;
}

static int restful_rhizome_bid_raw_bin(httpd_request *r, const char *remainder)
{
  if (*remainder || r->manifest == NULL)
    return 404;
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
  if (*remainder || r->manifest == NULL)
    return 404;
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

int rhizome_response_content_init_filehash(httpd_request *r, const rhizome_filehash_t *hash)
{
  bzero(&r->u.read_state, sizeof r->u.read_state);
  r->u.read_state.blob_fd = -1;
  assert(r->finalise_union == NULL);
  r->finalise_union = finalise_union_read_state;
  enum rhizome_payload_status status = rhizome_open_read(&r->u.read_state, hash);
  switch (status) {
    case RHIZOME_PAYLOAD_STATUS_EMPTY:
    case RHIZOME_PAYLOAD_STATUS_STORED:
      break;
    case RHIZOME_PAYLOAD_STATUS_NEW:
      return 404;
    case RHIZOME_PAYLOAD_STATUS_ERROR:
    case RHIZOME_PAYLOAD_STATUS_WRONG_SIZE:
    case RHIZOME_PAYLOAD_STATUS_WRONG_HASH:
    case RHIZOME_PAYLOAD_STATUS_CRYPTO_FAIL:
      return -1;
    default:
      FATALF("status = %d", status);
  }
  return rhizome_response_content_init_read_state(r);
}

int rhizome_response_content_init_payload(httpd_request *r, rhizome_manifest *m)
{
  bzero(&r->u.read_state, sizeof r->u.read_state);
  r->u.read_state.blob_fd = -1;
  assert(r->finalise_union == NULL);
  r->finalise_union = finalise_union_read_state;
  enum rhizome_payload_status status = rhizome_open_decrypt_read(m, &r->u.read_state);
  switch (status) {
    case RHIZOME_PAYLOAD_STATUS_EMPTY:
    case RHIZOME_PAYLOAD_STATUS_STORED:
      break;
    case RHIZOME_PAYLOAD_STATUS_NEW:
      return 404;
    case RHIZOME_PAYLOAD_STATUS_ERROR:
    case RHIZOME_PAYLOAD_STATUS_WRONG_SIZE:
    case RHIZOME_PAYLOAD_STATUS_WRONG_HASH:
    case RHIZOME_PAYLOAD_STATUS_CRYPTO_FAIL:
      return -1;
    default:
      FATALF("status = %d", status);
  }
  return rhizome_response_content_init_read_state(r);
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

static void render_manifest_headers(struct http_request *hr, strbuf sb)
{
  httpd_request *r = (httpd_request *) hr;
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

