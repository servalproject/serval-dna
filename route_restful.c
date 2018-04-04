/*
Serval DNA Routing HTTP RESTful interface
Copyright (C) 2018 Flinders University
 
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

#include "lang.h" // for bool_t, FALLTHROUGH
#include "serval.h"
#include "conf.h"
#include "httpd.h"
#include "server.h"
#include "strbuf_helpers.h"
#include "dataformats.h"
#include "overlay_address.h"
#include "overlay_interface.h"

DEFINE_FEATURE(http_rest_route);

DECLARE_HANDLER("/restful/route/", restful_route_);

static HTTP_HANDLER restful_route_list_json;

static int restful_route_(httpd_request *r, const char *remainder)
{
  r->http.response.header.content_type = &CONTENT_TYPE_JSON;
  int ret = authorize_restful(&r->http);
  if (ret)
    return ret;
  if (r->http.verb == HTTP_VERB_GET && strcmp(remainder, "all.json") == 0)
    return restful_route_list_json(r, "");
  return 404;
}

static void finalise_union_subscriberlist(httpd_request *r)
{
  subscriber_iterator_free(&r->u.subscriberlist.it);
}

static HTTP_CONTENT_GENERATOR restful_route_list_json_content;

static int restful_route_list_json(httpd_request *r, const char *remainder)
{
  if (*remainder)
    return 404;
  r->u.subscriberlist.phase = LIST_HEADER;
  subscriber_iterator_start(&r->u.subscriberlist.it);
  r->finalise_union = finalise_union_subscriberlist;
  http_request_response_generated(&r->http, 200, &CONTENT_TYPE_JSON, restful_route_list_json_content);
  return 1;
}

static HTTP_CONTENT_GENERATOR_STRBUF_CHUNKER restful_route_list_json_content_chunk;

static int restful_route_list_json_content(struct http_request *hr, unsigned char *buf, size_t bufsz, struct http_content_generator_result *result)
{
  return generate_http_content_from_strbuf_chunks(hr, (char *)buf, bufsz, result, restful_route_list_json_content_chunk);
}

static int restful_route_list_json_content_chunk(struct http_request *hr, strbuf b)
{
  httpd_request *r = (httpd_request *) hr;
  const char *headers[] = {
    "sid",
    "did",
    "name",
    "is_self",
    "reachable_broadcast",
    "reachable_unicast",
    "reachable_indirect",
    "interface",
    "hop_count",
    "first_hop",
    "penultimate_hop"
  };
  switch (r->u.subscriberlist.phase) {
    case LIST_HEADER:
      strbuf_puts(b, "{\n\"header\":[");
      unsigned i;
      for (i = 0; i != NELS(headers); ++i) {
	if (i)
	  strbuf_putc(b, ',');
	strbuf_json_string(b, headers[i]);
      }
      strbuf_puts(b, "],\n\"rows\":[");
      if (!strbuf_overrun(b)){
	r->u.subscriberlist.phase = LIST_FIRST;
	if (!subscriber_iterator_get_current(&r->u.subscriberlist.it))
	  r->u.subscriberlist.phase = LIST_END;
      }
      return 1;

    case LIST_ROWS:
      strbuf_putc(b, ',');
      FALLTHROUGH;
    case LIST_FIRST:
      r->u.subscriberlist.phase = LIST_ROWS;
      struct subscriber **subscriberp = subscriber_iterator_get_current(&r->u.subscriberlist.it);
      assert(subscriberp);
      struct subscriber *subscriber = *subscriberp;
      const char *did = NULL;
      const char *name = NULL;
      if (subscriber->identity)
	keyring_identity_extract(subscriber->identity, &did, &name);
      // sid
      strbuf_puts(b, "\n[");
      strbuf_json_string(b, alloca_tohex_sid_t(subscriber->sid));
      // did
      strbuf_puts(b, ",");
      strbuf_json_string(b, did);
      // name
      strbuf_puts(b, ",");
      strbuf_json_string(b, name);
      // is_self
      strbuf_puts(b, ",");
      strbuf_json_boolean(b, subscriber->reachable & REACHABLE_SELF);
      // reachable_broadcast
      strbuf_puts(b, ",");
      strbuf_json_boolean(b, subscriber->reachable & REACHABLE_BROADCAST);
      // reachable_unicast
      strbuf_puts(b, ",");
      strbuf_json_boolean(b, subscriber->reachable & REACHABLE_UNICAST);
      // reachable_indirect
      strbuf_puts(b, ",");
      strbuf_json_boolean(b, subscriber->reachable & REACHABLE_INDIRECT);
      // interface
      strbuf_puts(b, ",");
      if (subscriber->destination && subscriber->destination->interface)
	strbuf_json_string(b, subscriber->destination->interface->name);
      else
	strbuf_json_null(b);
      // hop_count
      strbuf_puts(b, ",");
      strbuf_json_integer(b, subscriber->hop_count);
      // first_hop
      strbuf_puts(b, ",");
      if (subscriber->next_hop)
	strbuf_json_string(b, alloca_tohex_sid_t(subscriber->next_hop->sid));
      else
	strbuf_json_null(b);
      // penultimate_hop
      strbuf_puts(b, ",");
      if (subscriber->prior_hop)
	strbuf_json_string(b, alloca_tohex_sid_t(subscriber->prior_hop->sid));
      else
	strbuf_json_null(b);
      strbuf_puts(b, "]");
      if (!strbuf_overrun(b)) {
	subscriber_iterator_advance(&r->u.subscriberlist.it);
	if (!subscriber_iterator_get_current(&r->u.subscriberlist.it))
	  r->u.subscriberlist.phase = LIST_END;
      }
      return 1;

    case LIST_END:
      strbuf_puts(b, "\n]\n}\n");
      if (strbuf_overrun(b))
	return 1;

      r->u.subscriberlist.phase = LIST_DONE;
      // fall through...
    case LIST_DONE:
      return 0;
  }
  abort();
  return 0;
}
