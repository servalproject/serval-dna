#include "serval.h"
#include "conf.h"
#include "httpd.h"
#include "str.h"
#include "numeric_str.h"
#include "base64.h"
#include "strbuf_helpers.h"
#include "meshmb.h"

DEFINE_FEATURE(http_rest_meshmb);

static char *PART_MESSAGE = "message";
static int send_part_start(struct http_request *hr)
{
  httpd_request *r = (httpd_request *) hr;
  assert(r->u.sendmsg.current_part == NULL);
  return 0;
}

static int send_part_end(struct http_request *hr)
{
  httpd_request *r = (httpd_request *) hr;
  if (r->u.sendmsg.current_part == PART_MESSAGE) {
    if (r->u.sendmsg.message.length == 0)
      return http_response_form_part(r, 400, "Invalid (empty)", PART_MESSAGE, NULL, 0);
    r->u.sendmsg.received_message = 1;
    DEBUGF(httpd, "received %s = %s", PART_MESSAGE, alloca_toprint(-1, r->u.sendmsg.message.buffer, r->u.sendmsg.message.length));
  } else
    FATALF("current_part = %s", alloca_str_toprint(r->u.sendmsg.current_part));
  r->u.sendmsg.current_part = NULL;
  return 0;
}

static int send_part_header(struct http_request *hr, const struct mime_part_headers *h)
{
  httpd_request *r = (httpd_request *) hr;
  if (!h->content_disposition.type[0])
    return http_response_content_disposition(r, 415, "Missing", h->content_disposition.type);
  if (strcmp(h->content_disposition.type, "form-data") != 0)
    return http_response_content_disposition(r, 415, "Unsupported", h->content_disposition.type);
  if (strcmp(h->content_disposition.name, PART_MESSAGE) == 0) {
    if (r->u.sendmsg.received_message)
      return http_response_form_part(r, 400, "Duplicate", PART_MESSAGE, NULL, 0);
    r->u.sendmsg.current_part = PART_MESSAGE;
    form_buf_malloc_init(&r->u.sendmsg.message, MESSAGE_PLY_MAX_LEN);
  }
  else
    return http_response_form_part(r, 415, "Unsupported", h->content_disposition.name, NULL, 0);
  if (!h->content_type.type[0] || !h->content_type.subtype[0])
    return http_response_content_type(r, 400, "Missing", &h->content_type);
  if (strcmp(h->content_type.type, "text") != 0 || strcmp(h->content_type.subtype, "plain") != 0)
    return http_response_content_type(r, 415, "Unsupported", &h->content_type);
  if (!h->content_type.charset[0])
    return http_response_content_type(r, 400, "Missing charset", &h->content_type);
  if (strcmp(h->content_type.charset, "utf-8") != 0)
    return http_response_content_type(r, 415, "Unsupported charset", &h->content_type);
  return 0;
}

static int send_part_body(struct http_request *hr, char *buf, size_t len)
{
  httpd_request *r = (httpd_request *) hr;
  if (r->u.sendmsg.current_part == PART_MESSAGE) {
    form_buf_malloc_accumulate(r, PART_MESSAGE, &r->u.sendmsg.message, buf, len);
  } else
    FATALF("current_part = %s", alloca_str_toprint(r->u.sendmsg.current_part));
  return 0;
}

static int send_content_end(struct http_request *hr)
{
  httpd_request *r = (httpd_request *) hr;
  if (!r->u.sendmsg.received_message)
    return http_response_form_part(r, 400, "Missing", PART_MESSAGE, NULL, 0);
  assert(r->u.sendmsg.message.length > 0);
  assert(r->u.sendmsg.message.length <= MESSAGE_PLY_MAX_LEN);

  keyring_identity *id = keyring_find_identity(keyring, &r->bid);
  if (!id){
    http_request_simple_response(&r->http, 500, "TODO, detailed errors");
    return 500;
  }
  if (meshmb_send(id, r->u.sendmsg.message.buffer, r->u.sendmsg.message.length, 0, NULL)==-1){
    http_request_simple_response(&r->http, 500, "TODO, detailed errors");
    return 500;
  }
  http_request_simple_response(&r->http, 201, "TODO, detailed response");
  return 201;
}

static void send_finalise(httpd_request *r)
{
  form_buf_malloc_release(&r->u.sendmsg.message);
}

static int restful_meshmb_send(httpd_request *r, const char *remainder)
{
  if (*remainder)
    return 404;
  assert(r->finalise_union == NULL);
  r->finalise_union = send_finalise;
  // Parse the request body as multipart/form-data.
  assert(r->u.sendmsg.current_part == NULL);
  assert(!r->u.sendmsg.received_message);
  r->http.form_data.handle_mime_part_start = send_part_start;
  r->http.form_data.handle_mime_part_end = send_part_end;
  r->http.form_data.handle_mime_part_header = send_part_header;
  r->http.form_data.handle_mime_body = send_part_body;
  // Send the message once the body has arrived.
  r->http.handle_content_end = send_content_end;
  return 1;
}

DECLARE_HANDLER("/restful/meshmb/", restful_meshmb_);
static int restful_meshmb_(httpd_request *r, const char *remainder)
{
  r->http.response.header.content_type = CONTENT_TYPE_JSON;
  if (!is_rhizome_http_enabled())
    return 404;
  int ret = authorize_restful(&r->http);
  if (ret)
    return ret;
  const char *verb = HTTP_VERB_GET;
  HTTP_HANDLER *handler = NULL;
  const char *end;

  if (strn_to_identity_t(&r->bid, remainder, &end) != -1) {
    remainder = end;

    if (strcmp(remainder, "/sendmessage") == 0) {
      handler = restful_meshmb_send;
      verb = HTTP_VERB_POST;
      remainder = "";
    }
  }

  if (handler == NULL)
    return 404;
  if (r->http.verb != verb)
    return 405;
  return handler(r, remainder);
}
