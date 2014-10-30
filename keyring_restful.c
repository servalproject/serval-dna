/*
Serval DNA HTTP RESTful interface
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

#include "serval.h"
#include "conf.h"
#include "httpd.h"
#include "server.h"
#include "keyring.h"
#include "strbuf_helpers.h"

extern keyring_file *keyring;

#define keyring_TOKEN_STRLEN (BASE64_ENCODED_LEN(sizeof(rhizome_bid_t) + sizeof(uint64_t)))
#define alloca_keyring_token(bid, offset) keyring_    token_to_str(alloca(keyring_TOKEN_STRLEN + 1), (bid), (offset))

static HTTP_HANDLER restful_keyring_identitylist_json;

int restful_keyring_(httpd_request *r, const char *remainder)
{
  r->http.response.header.content_type = CONTENT_TYPE_JSON;
  if (!is_rhizome_http_enabled())
    return 403;
  int ret = authorize_restful(&r->http);
  if (ret)
    return ret;
  const char *verb = HTTP_VERB_GET;
  http_size_t content_length = CONTENT_LENGTH_UNKNOWN;
  HTTP_HANDLER *handler = NULL;
  
  if (strcmp(remainder, "identities.json") == 0) {
    handler = restful_keyring_identitylist_json;
    verb = HTTP_VERB_GET;
    remainder = "";
  }

  if (handler == NULL)
    return 404;
  if (	 content_length != CONTENT_LENGTH_UNKNOWN
      && r->http.request_header.content_length != CONTENT_LENGTH_UNKNOWN
      && r->http.request_header.content_length != content_length) {
    http_request_simple_response(&r->http, 400, "Bad content length");
    return 400;
  }
  if (r->http.verb != verb)
    return 405;
  return handler(r, remainder);
}

static HTTP_CONTENT_GENERATOR restful_keyring_identitylist_json_content;

static int restful_keyring_identitylist_json(httpd_request *r, const char *remainder)
{
  if (*remainder)
    return 404;

  r->u.sidlist.phase = LIST_HEADER;
  r->u.sidlist.cn = 0;
  r->u.sidlist.in = 0;

  http_request_response_generated(&r->http, 200, CONTENT_TYPE_JSON, restful_keyring_identitylist_json_content);
  return 1;
}

static HTTP_CONTENT_GENERATOR_STRBUF_CHUNKER restful_keyring_identitylist_json_content_chunk;

static int restful_keyring_identitylist_json_content(struct http_request *hr, unsigned char *buf, size_t bufsz, struct http_content_generator_result *result)
{
  return generate_http_content_from_strbuf_chunks(hr, (char *)buf, bufsz, result, restful_keyring_identitylist_json_content_chunk);
}

static int restful_keyring_identitylist_json_content_chunk(struct http_request *hr, strbuf b)
{
  httpd_request *r = (httpd_request *) hr;
  // The "my_sid" and "their_sid" per-conversation fields allow the same JSON structure to be used
  // in a future, non-SID-specific request, eg, to list all conversations for all currently open
  // identities.
  const char *headers[] = {
    "sid",
    "did",
    "name"
  };
  switch (r->u.sidlist.phase) {
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
  r->u.sidlist.phase = LIST_ROWS;
      return 1;
    case LIST_ROWS:
  if (r->u.sidlist.cn != 0 || r->u.sidlist.in != 0)
    strbuf_putc(b, ',');

  if (keyring->context_count == 0 || keyring->contexts[r->u.sidlist.cn]->identity_count == 0) {
    r->u.sidlist.phase = LIST_END;
    return 1;
  }

  const sid_t *sidp = NULL;
  const char *did = NULL;
  const char *name = NULL;
  keyring_identity_extract(keyring->contexts[r->u.sidlist.cn]->identities[r->u.sidlist.in], &sidp, &did, &name);
  if (sidp || did) {
    strbuf_puts(b, "\n[");
    strbuf_json_string(b, alloca_tohex_sid_t(*sidp));
    strbuf_puts(b, ",");
    strbuf_json_string(b, did);
    strbuf_puts(b, ",");
    strbuf_json_string(b, name);
    strbuf_puts(b, "]");
  }

  if (!strbuf_overrun(b)) {
    ++r->u.sidlist.in;
    if (r->u.sidlist.in >= keyring->contexts[r->u.sidlist.cn]->identity_count) {
      r->u.sidlist.in = 0;

      ++r->u.sidlist.cn;
      if (r->u.sidlist.cn >= keyring->context_count) {
        r->u.sidlist.phase = LIST_END;
      }
    }
  }
  return 1;
      // }
      // fall through...
    case LIST_END:
      strbuf_puts(b, "\n]\n}\n");
      if (!strbuf_overrun(b))
  r->u.sidlist.phase = LIST_DONE;
      // fall through...
    case LIST_DONE:
      return 0;
  }
  abort();
  return 0;
}

