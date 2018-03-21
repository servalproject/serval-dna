/*
Serval DNA Keyring HTTP RESTful interface
Copyright (C) 2018 Flinders University
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

#include "lang.h" // for bool_t, FALLTHROUGH
#include "serval.h"
#include "conf.h"
#include "httpd.h"
#include "server.h"
#include "keyring.h"
#include "strbuf_helpers.h"
#include "dataformats.h"

DEFINE_FEATURE(http_rest_keyring);

DECLARE_HANDLER("/restful/keyring/", restful_keyring_);

static HTTP_HANDLER restful_keyring_identitylist_json;
static HTTP_HANDLER restful_keyring_add;
static HTTP_HANDLER restful_keyring_get;
static HTTP_HANDLER restful_keyring_set;
static HTTP_HANDLER restful_keyring_remove;
static HTTP_HANDLER restful_keyring_lock;

static int restful_keyring_(httpd_request *r, const char *remainder)
{
  r->http.response.header.content_type = &CONTENT_TYPE_JSON;
  int ret = authorize_restful(&r->http);
  if (ret)
    return ret;
  const char *end;
  if (r->http.verb == HTTP_VERB_GET && strcmp(remainder, "identities.json") == 0)
    return restful_keyring_identitylist_json(r, "");
  if (r->http.verb == HTTP_VERB_POST && strcmp(remainder, "add") == 0)
    return restful_keyring_add(r, "");
  if (parse_sid_t(&r->sid1, remainder, -1, &end) != -1) {
    if (strcmp(end, "") == 0) {
      if (r->http.verb == HTTP_VERB_GET)
	return restful_keyring_get(r, "");
      if (r->http.verb == HTTP_VERB_PATCH || r->http.verb == HTTP_VERB_POST)
	return restful_keyring_set(r, "");
      if (r->http.verb == HTTP_VERB_DELETE)
	return restful_keyring_remove(r, "");
    }
    else if (r->http.verb == HTTP_VERB_PUT && strcmp(end, "/lock") == 0)
      return restful_keyring_lock(r, "");
  }
  // Legacy API requests that use GET but should use another verb instead (see above).  Eventually
  // this support should be removed and some text in the response should refer the client to the
  // correct request.
  if (r->http.verb == HTTP_VERB_GET) {
    if (strcmp(remainder, "add") == 0) {
      return restful_keyring_add(r, "");
    }
    else if (parse_sid_t(&r->sid1, remainder, -1, &end) != -1) {
      if (strcmp(end, "/remove") == 0)
	return restful_keyring_remove(r, "");
      else if (strcmp(end, "/set") == 0)
	return restful_keyring_set(r, "");
      else if (strcmp(end, "/lock") == 0)
	return restful_keyring_lock(r, "");
    }
  }
  return 404;
}

static int http_request_keyring_response(struct httpd_request *r, uint16_t result, const char *message)
{
  http_request_simple_response(&r->http, result, message);
  return result;
}

static int http_request_keyring_response_identity(struct httpd_request *r, uint16_t result, const keyring_identity *id)
{
  const char *did = NULL;
  const char *name = NULL;
  keyring_identity_extract(id, &did, &name);
  struct json_atom json_id;
  struct json_key_value json_id_kv[4];
  struct json_atom json_sid;
  struct json_atom json_sas;
  struct json_atom json_did;
  struct json_atom json_name;
  json_id.type = JSON_OBJECT;
  json_id.u.object.itemc = 2;
  json_id.u.object.itemv = json_id_kv;
  json_id_kv[0].key = "sid";
  json_id_kv[0].value = &json_sid;
  json_sid.type = JSON_STRING_NULTERM;
  json_sid.u.string.content = alloca_tohex_sid_t(*id->box_pk);
  json_id_kv[1].key = "identity";
  json_id_kv[1].value = &json_sas;
  json_sas.type = JSON_STRING_NULTERM;
  json_sas.u.string.content = alloca_tohex_identity_t(&id->sign_keypair->public_key);
  if (did) {
    json_id_kv[json_id.u.object.itemc].key = "did";
    json_id_kv[json_id.u.object.itemc].value = &json_did;
    ++json_id.u.object.itemc;
    json_did.type = JSON_STRING_NULTERM;
    json_did.u.string.content = did;
  }
  if (name) {
    json_id_kv[json_id.u.object.itemc].key = "name";
    json_id_kv[json_id.u.object.itemc].value = &json_name;
    ++json_id.u.object.itemc;
    json_name.type = JSON_STRING_NULTERM;
    json_name.u.string.content = name;
  }
  r->http.response.result_extra[0].label = "identity";
  r->http.response.result_extra[0].value = json_id;
  return http_request_keyring_response(r, result, NULL);
}

static HTTP_CONTENT_GENERATOR restful_keyring_identitylist_json_content;

static int restful_keyring_identitylist_json(httpd_request *r, const char *remainder)
{
  if (*remainder)
    return 404;
  const char *pin = http_request_get_query_param(&r->http, "pin");
  if (pin)
    keyring_enter_pin(keyring, pin);
  r->u.sidlist.phase = LIST_HEADER;
  keyring_iterator_start(keyring, &r->u.sidlist.it);
  http_request_response_generated(&r->http, 200, &CONTENT_TYPE_JSON, restful_keyring_identitylist_json_content);
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
  const char *headers[] = {
    "sid",
    "identity",
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
      if (!strbuf_overrun(b)){
	r->u.sidlist.phase = LIST_FIRST;
	if (!keyring_next_identity(&r->u.sidlist.it))
	  r->u.sidlist.phase = LIST_END;
      }
      return 1;
      
    case LIST_ROWS:
      strbuf_putc(b, ',');
      FALLTHROUGH;
    case LIST_FIRST:
      r->u.sidlist.phase = LIST_ROWS;
      const char *did = NULL;
      const char *name = NULL;
      keyring_identity_extract(r->u.sidlist.it.identity, &did, &name);
      strbuf_puts(b, "\n[");
      strbuf_json_string(b, alloca_tohex_sid_t(*r->u.sidlist.it.identity->box_pk));
      strbuf_puts(b, ",");
      strbuf_json_string(b, alloca_tohex_identity_t(&r->u.sidlist.it.identity->sign_keypair->public_key));
      strbuf_puts(b, ",");
      strbuf_json_string(b, did);
      strbuf_puts(b, ",");
      strbuf_json_string(b, name);
      strbuf_puts(b, "]");

      if (!strbuf_overrun(b)) {
	if (!keyring_next_identity(&r->u.sidlist.it))
	  r->u.sidlist.phase = LIST_END;
      }
      return 1;
      
    case LIST_END:
      strbuf_puts(b, "\n]\n}\n");
      if (strbuf_overrun(b))
	return 1;
      
      r->u.sidlist.phase = LIST_DONE;
      // fall through...
    case LIST_DONE:
      return 0;
  }
  abort();
  return 0;
}

static int restful_keyring_add(httpd_request *r, const char *remainder)
{
  if (*remainder)
    return 404;
  const char *pin = http_request_get_query_param(&r->http, "pin");
  const char *did = http_request_get_query_param(&r->http, "did");
  const char *name = http_request_get_query_param(&r->http, "name");
  if (did && did[0] && !str_is_did(did))
    return http_request_keyring_response(r, 400, "Invalid DID");
  if (name && name[0] && !str_is_identity_name(name))
    return http_request_keyring_response(r, 400, "Invalid Name");
  keyring_identity *id = keyring_create_identity(keyring, pin ? pin : "");
  if (id == NULL)
    return http_request_keyring_response(r, 500, "Could not create identity");
  if ((did || name) && keyring_set_did_name(id, did ? did : "", name ? name : "") == -1) {
    keyring_free_identity(id);
    return http_request_keyring_response(r, 500, "Could not set identity DID/Name");
  }
  if (keyring_commit(keyring) == -1) {
    keyring_free_identity(id);
    return http_request_keyring_response(r, 500, "Could not store new identity");
  }
  return http_request_keyring_response_identity(r, 201, id);
}

static int restful_keyring_get(httpd_request *r, const char *remainder)
{
  if (*remainder)
    return 404;
  const char *pin = http_request_get_query_param(&r->http, "pin");
  if (pin)
    keyring_enter_pin(keyring, pin);
  keyring_identity *id = keyring_find_identity_sid(keyring, &r->sid1);
  if (!id)
    return http_request_keyring_response(r, 404, "Identity not found");
  int ret = http_request_keyring_response_identity(r, 200, id);
  keyring_free_identity(id);
  return ret;
}

static int restful_keyring_remove(httpd_request *r, const char *remainder)
{
  if (*remainder)
    return 404;
  const char *pin = http_request_get_query_param(&r->http, "pin");
  if (pin)
    keyring_enter_pin(keyring, pin);
  keyring_identity *id = keyring_find_identity_sid(keyring, &r->sid1);
  if (!id)
    return http_request_keyring_response(r, 404, "Identity not found");
  keyring_destroy_identity(keyring, id);
  if (keyring_commit(keyring) == -1)
    return http_request_keyring_response(r, 500, "Could not erase removed identity");
  int ret = http_request_keyring_response_identity(r, 200, id);
  keyring_free_identity(id);
  return ret;
}

static int restful_keyring_set(httpd_request *r, const char *remainder)
{
  if (*remainder)
    return 404;
  const char *pin = http_request_get_query_param(&r->http, "pin");
  const char *did = http_request_get_query_param(&r->http, "did");
  const char *name = http_request_get_query_param(&r->http, "name");
  if (did && did[0] && !str_is_did(did))
    return http_request_keyring_response(r, 400, "Invalid DID");
  if (name && name[0] && !str_is_identity_name(name))
    return http_request_keyring_response(r, 400, "Invalid Name");
  if (pin)
    keyring_enter_pin(keyring, pin);
  keyring_identity *id = keyring_find_identity_sid(keyring, &r->sid1);
  if (!id)
    return http_request_keyring_response(r, 404, "Identity not found");
  if (keyring_set_did_name(id, did, name) == -1)
    return http_request_keyring_response(r, 500, "Could not set identity DID/Name");
  if (keyring_commit(keyring) == -1)
    return http_request_keyring_response(r, 500, "Could not store new identity");
  return http_request_keyring_response_identity(r, 200, id);
}

static int restful_keyring_lock(httpd_request *r, const char *remainder)
{
  if (*remainder)
    return 404;
  keyring_identity *id = keyring_find_identity_sid(keyring, &r->sid1);
  if (!id)
    return http_request_keyring_response(r, 404, "Identity not found");
  keyring_release_identity(keyring, id);
  keyring_free_identity(id);
  return http_request_keyring_response(r, 200, "Identity locked");
}
