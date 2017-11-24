#include "lang.h" // for FALLTHROUGH
#include "serval.h"
#include "dataformats.h"
#include "conf.h"
#include "httpd.h"
#include "str.h"
#include "numeric_str.h"
#include "base64.h"
#include "strbuf_helpers.h"
#include "keyring.h"
#include "meshmb.h"
#include "debug.h"

DEFINE_FEATURE(http_rest_meshmb);

// allow multiple requests to re-use the same struct meshmb_feeds *, keeping it up to date as bundles arrive
struct meshmb_session{
  struct meshmb_session *next;
  struct meshmb_session *prev;
  unsigned ref_count;
  keyring_identity *id;
  struct meshmb_feeds *feeds;
};

#define FLAG_FOLLOW (1)
#define FLAG_IGNORE (2)
#define FLAG_BLOCK (3)

static struct meshmb_session *sessions = NULL;

static struct meshmb_session *open_session(const identity_t *identity){
  keyring_identity *id = keyring_find_identity(keyring, identity);
  if (!id)
    return NULL;

  struct meshmb_session *session = sessions;
  while(session){
    if (session->id == id){
      session->ref_count++;
      return session;
    }
    session = session->next;
  }

  struct meshmb_feeds *feeds = NULL;
  if (meshmb_open(id, &feeds)==-1)
    return NULL;

  meshmb_update(feeds);
  session = emalloc(sizeof (struct meshmb_session));
  if (!session){
    meshmb_close(feeds);
    return NULL;
  }
  session->next = sessions;
  session->prev = NULL;
  if (sessions)
    sessions->prev = session;
  sessions = session;

  session->ref_count = 1;
  session->id = id;
  session->feeds = feeds;

  return session;
}

static void close_session(struct meshmb_session *session){
  if (--session->ref_count == 0){
    if (session->next)
      session->next->prev = session->prev;
    if (session->prev)
      session->prev->next = session->next;
    else
      sessions = session->next;

    meshmb_close(session->feeds);
    free(session);
  }
}

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
    DEBUGF(meshmb, "received %s = %s", PART_MESSAGE, alloca_toprint(-1, r->u.sendmsg.message.buffer, r->u.sendmsg.message.length));
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
  assert(keyring != NULL);

  struct meshmb_session *session = open_session(&r->bid);
  int ret;

  if (session
    && meshmb_send(session->feeds, r->u.sendmsg.message.buffer, r->u.sendmsg.message.length, 0, NULL)!=-1
    && meshmb_flush(session->feeds)!=-1){
    http_request_simple_response(&r->http, 201, "TODO, detailed response");
    ret = 201;
  }else{
    http_request_simple_response(&r->http, 500, "TODO, detailed response");
    ret = 500;
  }
  if (session)
    close_session(session);
  return ret;
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

static strbuf position_token_to_str(strbuf b, uint64_t position)
{
  uint8_t tmp[12];
  char tmp_str[BASE64_ENCODED_LEN(12)+1];

  int len = pack_uint(tmp, position);
  assert(len <= (int)sizeof tmp);
  size_t n = base64url_encode(tmp_str, tmp, len);
  tmp_str[n] = '\0';
  return strbuf_puts(b, tmp_str);
}

static int strn_to_position_token(const char *str, uint64_t *position, const char **afterp)
{
  uint8_t token[12];
  size_t token_len = base64url_decode(token, sizeof token, str, 0, afterp, 0, NULL);

  int unpacked;
  if ((unpacked = unpack_uint(token, token_len, position))!=-1
    && **afterp=='/'){
    (*afterp)++;
  } else {
    *position = 0;
    *afterp=str;
  }
  return 1;
}

static strbuf activity_token_to_str(strbuf b, const httpd_request *r)
{
  uint8_t tmp[12];
  char tmp_str[BASE64_ENCODED_LEN(12)+1];
  unsigned len = 0;
  len += pack_uint(&tmp[len], r->u.meshmb_feeds.current_ack_offset);
  len += pack_uint(&tmp[len], r->u.meshmb_feeds.current_msg_offset);
  assert(len <= sizeof tmp);
  size_t n = base64url_encode(tmp_str, tmp, len);
  tmp_str[n] = '\0';
  return strbuf_puts(b, tmp_str);
}

static int strn_to_activity_token(const char *str, httpd_request *r, const char **afterp)
{
  uint8_t token[12];
  size_t token_len = base64url_decode(token, sizeof token, str, 0, afterp, 0, NULL);

  int unpacked;
  if ((unpacked = unpack_uint(token, token_len, &r->u.meshmb_feeds.end_ack_offset))!=-1
    && (unpacked = unpack_uint(token + unpacked, token_len - unpacked, &r->u.meshmb_feeds.end_msg_offset))!=-1
    && **afterp=='/'){
    (*afterp)++;
  } else {
    r->u.meshmb_feeds.end_ack_offset=0;
    r->u.meshmb_feeds.end_msg_offset=0;
    *afterp=str;
  }
  return 1;
}

static int next_ply_message(httpd_request *r){
  if (!message_ply_is_open(&r->u.plylist.ply_reader)){
    if (message_ply_read_open(&r->u.plylist.ply_reader, &r->bid, NULL)==-1){
      r->u.plylist.eof = 1;
      return -1;
    }

    // skip back to where we were
    if (r->u.plylist.current_offset)
      r->u.plylist.ply_reader.read.offset = r->u.plylist.current_offset;

    DEBUGF(meshmb, "Opened ply @%"PRIu64, r->u.plylist.ply_reader.read.offset);
  }

  if (r->u.plylist.current_offset==0){
    // enumerate everything from the top
    DEBUGF(meshmb, "Started reading @%"PRIu64, r->u.plylist.ply_reader.read.length);
    r->u.plylist.current_offset =
    r->u.plylist.start_offset =
    r->u.plylist.ply_reader.read.offset =
      r->u.plylist.ply_reader.read.length;
  }

  while(message_ply_read_prev(&r->u.plylist.ply_reader) == 0){
    r->u.plylist.current_offset = r->u.plylist.ply_reader.record_end_offset;
    if (r->u.plylist.current_offset <= r->u.plylist.end_offset){
      DEBUGF(meshmb, "Hit end %"PRIu64" @%"PRIu64,
	r->u.plylist.end_offset, r->u.plylist.current_offset);
      break;
    }

    switch(r->u.plylist.ply_reader.type){
      case MESSAGE_BLOCK_TYPE_TIME:
	if (message_ply_parse_timestamp(&r->u.plylist.ply_reader, &r->u.plylist.timestamp)!=0){
	  WARN("Malformed ply, expected timestamp");
	  continue;
	}
	break;

      case MESSAGE_BLOCK_TYPE_MESSAGE:
	r->u.plylist.eof = 0;
	return 1;

      case MESSAGE_BLOCK_TYPE_ACK:
	// TODO, link to some other ply?
	break;

      default:
	//ignore unknown types
	break;
    }
  }
  r->u.plylist.eof = 1;
  return 0;
}

static int restful_meshmb_list_json_content_chunk(struct http_request *hr, strbuf b)
{
  httpd_request *r = (httpd_request *) hr;
  // The "my_sid" and "their_sid" per-conversation fields allow the same JSON structure to be used
  // in a future, non-SID-specific request, eg, to list all conversations for all currently open
  // identities.
  const char *headers[] = {
    "offset",
    "token",
    "text",
    "timestamp"
  };

  DEBUGF(meshmb, "Phase %d", r->u.plylist.phase);

  switch (r->u.plylist.phase) {
    case LIST_HEADER:

      strbuf_puts(b, "{\n");

      // open the ply now in order to read the manifest name
      if (!message_ply_is_open(&r->u.plylist.ply_reader))
	next_ply_message(r);

      if (r->u.plylist.ply_reader.name)
	strbuf_sprintf(b, "\"name\":\"%s\",\n", r->u.plylist.ply_reader.name);

      strbuf_puts(b, "\"header\":[");
      unsigned i;
      for (i = 0; i != NELS(headers); ++i) {
	if (i)
	  strbuf_putc(b, ',');
	strbuf_json_string(b, headers[i]);
      }
      strbuf_puts(b, "],\n\"rows\":[");
      if (!strbuf_overrun(b))
	r->u.plylist.phase = LIST_ROWS;
      return 1;

ROWS:
    case LIST_ROWS: FALLTHROUGH;
    case LIST_FIRST:

      if (!message_ply_is_open(&r->u.plylist.ply_reader)){
	// re-load the current message text
	if (next_ply_message(r)!=1)
	  goto END;
      } else if (r->u.plylist.eof)
	  goto END;

      if (r->u.plylist.rowcount!=0)
	strbuf_putc(b, ',');
      strbuf_puts(b, "\n[");

      strbuf_sprintf(b, "%"PRIu64, r->u.plylist.current_offset);
      strbuf_puts(b, ",\"");
      position_token_to_str(b, r->u.plylist.current_offset);
      strbuf_puts(b, "\",");
      strbuf_json_string(b, (const char *)r->u.plylist.ply_reader.record);
      strbuf_putc(b, ',');
      strbuf_sprintf(b, "%d", r->u.plylist.timestamp);
      strbuf_puts(b, "]");

      if (!strbuf_overrun(b)) {
	++r->u.plylist.rowcount;
	if (next_ply_message(r)!=1)
	  r->u.plylist.phase = LIST_END;
      }
      return 1;

END:
      r->u.plylist.phase = LIST_END;
      FALLTHROUGH;
    case LIST_END:

      {
	time_ms_t now;
	// during a new-since request, we don't really want to end until the time limit has elapsed
	if (r->u.plylist.end_time && (now = gettime_ms()) < r->u.plylist.end_time) {
	  // where we started this time, will become where we end on the next pass;
	  r->u.plylist.end_offset = r->u.plylist.start_offset;
	  r->u.plylist.current_offset = 0;
	  r->u.plylist.phase = LIST_ROWS;

	  if (r->u.plylist.ply_reader.read.length > r->u.plylist.start_offset && next_ply_message(r)==1)
	    // new content arrived while we were iterating, we can resume immediately
	    goto ROWS;

	  message_ply_read_close(&r->u.plylist.ply_reader);
	  http_request_pause_response(&r->http, r->u.plylist.end_time);
	  return 0;
	}
      }

      strbuf_puts(b, "\n]\n}\n");
      if (!strbuf_overrun(b))
	r->u.plylist.phase = LIST_DONE;
      FALLTHROUGH;
    case LIST_DONE:
      return 0;
  }
  abort();
  return 0;
}

static int restful_meshmb_list_json_content(struct http_request *hr, unsigned char *buf, size_t bufsz, struct http_content_generator_result *result)
{
  return generate_http_content_from_strbuf_chunks(hr, (char *)buf, bufsz, result, restful_meshmb_list_json_content_chunk);
}

static void list_on_rhizome_add(httpd_request *r, rhizome_manifest *m)
{
  if (strcmp(m->service, RHIZOME_SERVICE_MESHMB) == 0
    && cmp_rhizome_bid_t(&m->keypair.public_key, &r->bid)==0) {
    message_ply_read_close(&r->u.plylist.ply_reader);
    http_request_resume_response(&r->http);
  }
}

static void list_finalise(httpd_request *r)
{
  message_ply_read_close(&r->u.plylist.ply_reader);
}

static int restful_meshmb_list(httpd_request *r, const char *remainder)
{
  if (*remainder)
    return 404;
  assert(r->finalise_union == NULL);
  r->finalise_union = list_finalise;
  r->trigger_rhizome_bundle_added = list_on_rhizome_add;
  r->u.plylist.phase = LIST_HEADER;
  r->u.plylist.rowcount = 0;
  r->u.plylist.end_offset = r->ui64;

  http_request_response_generated(&r->http, 200, &CONTENT_TYPE_JSON, restful_meshmb_list_json_content);
  return 1;
}

static int restful_meshmb_newsince_list(httpd_request *r, const char *remainder)
{
  int ret;
  if ((ret = restful_meshmb_list(r, remainder))==1){
    r->u.plylist.end_time = gettime_ms() + config.api.restful.newsince_timeout * 1000;
  }
  return ret;
}

/*
static char *find_token_to_str(char *buf, uint64_t rowid)
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

static int strn_to_find_token(const char *str, uint64_t *rowidp, const char **afterp)
{
  unsigned char token[sizeof rhizome_db_uuid.u.binary + sizeof *rowidp];
  if (base64url_decode(token, sizeof token, str, 0, afterp, 0, NULL) == sizeof token
    && cmp_uuid_t(&rhizome_db_uuid, (serval_uuid_t *) &token) == 0
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

static int restful_meshmb_find(httpd_request *r, const char *remainder)
{
  return -1;
}

static int restful_meshmb_newsince_find(httpd_request *r, const char *remainder)
{
  return -1;
}
*/


static int restful_meshmb_follow_ignore(httpd_request *r, const char *remainder)
{
  if (*remainder)
    return 404;
  assert(r->finalise_union == NULL);

  const char *name = http_request_get_query_param(&r->http, "name");
  const char *sender_hex = http_request_get_query_param(&r->http, "sender");
  sid_t sender;
  bzero(&sender, sizeof sender);
  if (sender_hex && *sender_hex){
    if (str_to_sid_t(&sender, sender_hex) == -1)
      return 400;
  }

  struct meshmb_session *session = open_session(&r->bid);
  int ret=-1;

  if (session){

    switch(r->ui64){
      case FLAG_FOLLOW:
	ret = meshmb_follow(session->feeds, &r->u.meshmb_feeds.bundle_id,
	  (sender_hex && *sender_hex) ? &sender : NULL,
	  name);
	break;
      case FLAG_IGNORE:
	ret = meshmb_ignore(session->feeds, &r->u.meshmb_feeds.bundle_id);
	break;
      case FLAG_BLOCK:
	ret = meshmb_block (session->feeds, &r->u.meshmb_feeds.bundle_id,
	  (sender_hex && *sender_hex) ? &sender : NULL);
	break;
      default:
	FATAL("Unexpected value");
    }
  }

  if (ret!=-1
    && meshmb_flush(session->feeds)!=-1){
    http_request_simple_response(&r->http, 201, "TODO, detailed response");
    ret = 201;
  }else{
    http_request_simple_response(&r->http, 500, "TODO, detailed response");
    ret = 500;
  }
  if (session)
    close_session(session);
  return ret;
}

struct enum_state{
  httpd_request *request;
  strbuf buffer;
};

static int restful_feedlist_enum(struct meshmb_feed_details *details, void *context){
  struct enum_state *state = context;
  size_t checkpoint = strbuf_len(state->buffer);

  if (state->request->u.meshmb_feeds.rowcount!=0)
    strbuf_putc(state->buffer, ',');
  strbuf_puts(state->buffer, "\n[");
  strbuf_json_hex(state->buffer, details->ply.bundle_id.binary, sizeof details->ply.bundle_id.binary);
  strbuf_puts(state->buffer, ",");
  strbuf_json_hex(state->buffer, details->ply.author.binary, sizeof details->ply.author.binary);
  strbuf_puts(state->buffer, details->blocked ? ",true," : ",false,");
  strbuf_json_string(state->buffer, details->name);
  strbuf_puts(state->buffer, ",");
  strbuf_sprintf(state->buffer, "%d", details->timestamp);
  strbuf_puts(state->buffer, ",");
  strbuf_json_string(state->buffer, details->last_message);
  strbuf_puts(state->buffer, "]");

  if (strbuf_overrun(state->buffer)){
    strbuf_trunc(state->buffer, checkpoint);
    return 1;
  }else{
    ++state->request->u.meshmb_feeds.rowcount;
    state->request->u.meshmb_feeds.bundle_id = details->ply.bundle_id;
    return 0;
  }
}

static int restful_meshmb_feedlist_json_content_chunk(struct http_request *hr, strbuf b)
{
  httpd_request *r = (httpd_request *) hr;
  const char *headers[] = {
    "id",
    "author",
    "blocked",
    "name",
    "timestamp",
    "last_message"
  };

  DEBUGF(meshmb, "Phase %d", r->u.meshmb_feeds.phase);

  switch (r->u.meshmb_feeds.phase) {
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
	r->u.meshmb_feeds.phase = LIST_ROWS;
      return 1;

    case LIST_ROWS: FALLTHROUGH;
    case LIST_FIRST:
      {
	struct enum_state state={
	  .request = r,
	  .buffer = b
	};
	int gen = meshmb_flush(r->u.meshmb_feeds.session->feeds);
	if (gen>=0 && gen != r->u.meshmb_feeds.generation)
	  r->u.meshmb_feeds.generation = gen;
	if (meshmb_enum(r->u.meshmb_feeds.session->feeds, &r->u.meshmb_feeds.bundle_id, restful_feedlist_enum, &state)!=0)
	  return 0;
      }
      r->u.meshmb_feeds.phase = LIST_END;
      FALLTHROUGH;
    case LIST_END:
      strbuf_puts(b, "\n]\n}\n");
      if (!strbuf_overrun(b))
	r->u.plylist.phase = LIST_DONE;
      FALLTHROUGH;
    case LIST_DONE:
      return 0;
  }
  return -1;
}

static int restful_meshmb_feedlist_json_content(struct http_request *hr, unsigned char *buf, size_t bufsz, struct http_content_generator_result *result)
{
  return generate_http_content_from_strbuf_chunks(hr, (char *)buf, bufsz, result, restful_meshmb_feedlist_json_content_chunk);
}

static void feedlist_on_rhizome_add(httpd_request *r, rhizome_manifest *m)
{
  struct message_ply_read reader;
  bzero(&reader, sizeof(reader));
  int ret = meshmb_bundle_update(r->u.meshmb_feeds.session->feeds, m, &reader);
  message_ply_read_close(&reader);
  if (ret!=1)
    return;

  http_request_resume_response(&r->http);
}

static void feedlist_finalise(httpd_request *r)
{
  if (r->u.meshmb_feeds.iterator){
    meshmb_activity_close(r->u.meshmb_feeds.iterator);
    r->u.meshmb_feeds.iterator = NULL;
  }
  close_session(r->u.meshmb_feeds.session);
}

static int restful_meshmb_feedlist(httpd_request *r, const char *remainder)
{
  if (*remainder)
    return 404;

  struct meshmb_session *session = open_session(&r->bid);
  if (!session){
    http_request_simple_response(&r->http, 500, "TODO, detailed response");
    return 500;
  }

  assert(r->finalise_union == NULL);
  r->finalise_union = feedlist_finalise;
  r->trigger_rhizome_bundle_added = feedlist_on_rhizome_add;
  r->u.meshmb_feeds.phase = LIST_HEADER;
  r->u.meshmb_feeds.session = session;
  r->u.meshmb_feeds.generation = meshmb_flush(session->feeds);
  bzero(&r->u.meshmb_feeds.bundle_id, sizeof r->u.meshmb_feeds.bundle_id);

  http_request_response_generated(&r->http, 200, &CONTENT_TYPE_JSON, restful_meshmb_feedlist_json_content);
  return 1;
}

static void activity_test_end(httpd_request *r){
  struct meshmb_activity_iterator *iterator = r->u.meshmb_feeds.iterator;
  if (iterator){
    if (iterator->ack_reader.record_end_offset > r->u.meshmb_feeds.end_ack_offset
     || (iterator->ack_reader.record_end_offset == r->u.meshmb_feeds.end_ack_offset
      && iterator->msg_reader.record_end_offset > r->u.meshmb_feeds.end_msg_offset)){

      r->u.meshmb_feeds.phase = LIST_ROWS;

      DEBUGF(meshmb,"Iterator @ack %"PRIu64", @msg %"PRIu64,
	r->u.meshmb_feeds.current_ack_offset,
	r->u.meshmb_feeds.current_msg_offset);
      return;
    }
  }
  r->u.meshmb_feeds.phase = LIST_END;
}

static void activity_next(httpd_request *r){
  struct meshmb_activity_iterator *iterator = r->u.meshmb_feeds.iterator;
  while(iterator && meshmb_activity_next(iterator)==1){
    switch(iterator->msg_reader.type){
      case MESSAGE_BLOCK_TYPE_MESSAGE:

      r->u.meshmb_feeds.current_ack_offset = iterator->ack_reader.record_end_offset;
      r->u.meshmb_feeds.current_msg_offset = iterator->msg_reader.record_end_offset;
      activity_test_end(r);
      return;
    }
  }

  r->u.meshmb_feeds.phase = LIST_END;
}

static void activity_iterator_open(httpd_request *r){
  int gen = meshmb_flush(r->u.meshmb_feeds.session->feeds);
  if (gen>=0 && gen != r->u.meshmb_feeds.generation){
    if (r->u.meshmb_feeds.iterator){
      meshmb_activity_close(r->u.meshmb_feeds.iterator);
      r->u.meshmb_feeds.iterator = NULL;
    }
    r->u.meshmb_feeds.generation = gen;
  }

  if (r->u.meshmb_feeds.iterator)
    return;
  struct meshmb_activity_iterator *iterator = meshmb_activity_open(r->u.meshmb_feeds.session->feeds);
  if (iterator){
    r->u.meshmb_feeds.iterator = iterator;
    meshmb_activity_seek(iterator, r->u.meshmb_feeds.current_ack_offset, r->u.meshmb_feeds.current_msg_offset);
    if (r->u.meshmb_feeds.start_ack_offset == 0)
      r->u.meshmb_feeds.start_ack_offset = iterator->ack_reader.read.length;
    r->u.meshmb_feeds.current_ack_offset = iterator->ack_reader.record_end_offset;
    r->u.meshmb_feeds.current_msg_offset = iterator->msg_reader.record_end_offset;
    if (iterator->msg_reader.type != MESSAGE_BLOCK_TYPE_MESSAGE){
      activity_next(r);
      return;
    }
  }
  activity_test_end(r);
}

static int restful_meshmb_activity_json_content_chunk(struct http_request *hr, strbuf b)
{
  httpd_request *r = (httpd_request *) hr;
  const char *headers[] = {
    ".token",
    "ack_offset",
    "id",
    "author",
    "name",
    "timestamp",
    "offset",
    "message"
  };

  DEBUGF(meshmb, "Phase %d", r->u.meshmb_feeds.phase);

  switch (r->u.meshmb_feeds.phase) {
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
	activity_iterator_open(r);

      return 1;

    case LIST_ROWS:
    case LIST_FIRST:
      {
	activity_iterator_open(r);
	if (r->u.meshmb_feeds.phase == LIST_END)
	  return 1;

	struct meshmb_activity_iterator *iterator = r->u.meshmb_feeds.iterator;

	if (r->u.meshmb_feeds.rowcount!=0)
	  strbuf_putc(b, ',');
	strbuf_puts(b, "\n[\"");
	activity_token_to_str(b, r);
	strbuf_puts(b, "\",");
	strbuf_sprintf(b, "%"PRIu64, iterator->ack_reader.record_end_offset);
	strbuf_puts(b, ",");
	strbuf_json_hex(b, iterator->msg_reader.bundle_id.binary, sizeof iterator->msg_reader.bundle_id.binary);
	strbuf_puts(b, ",");
	strbuf_json_hex(b, iterator->msg_reader.author.binary, sizeof iterator->msg_reader.author.binary);
	strbuf_puts(b, ",");
	strbuf_json_string(b, iterator->msg_reader.name);
	strbuf_puts(b, ",");
	strbuf_sprintf(b, "%d", iterator->ack_timestamp);
	strbuf_puts(b, ",");
	strbuf_sprintf(b, "%"PRIu64, iterator->msg_reader.record_end_offset);
	strbuf_puts(b, ",");
	strbuf_json_string(b, (const char *)iterator->msg_reader.record);
	strbuf_puts(b, "]");
	if (!strbuf_overrun(b)){
	  r->u.meshmb_feeds.rowcount++;
	  DEBUGF(meshmb, "Wrote record %u (%s)", r->u.meshmb_feeds.rowcount, (const char *)iterator->msg_reader.record);
	  activity_next(r);
	}
	return 1;
      }

    case LIST_END:

      {
	time_ms_t now;
	// during a new-since request, we don't really want to end until the time limit has elapsed
	if (r->u.meshmb_feeds.end_time && (now = gettime_ms()) < r->u.meshmb_feeds.end_time) {
	  // where we started this time, will become where we end on the next pass;
	  r->u.meshmb_feeds.end_ack_offset = r->u.meshmb_feeds.start_ack_offset;
	  r->u.meshmb_feeds.end_msg_offset = 0;
	  r->u.meshmb_feeds.phase = LIST_ROWS;

	  struct meshmb_activity_iterator *iterator = r->u.meshmb_feeds.iterator;
	  if (iterator && iterator->ack_reader.read.length > r->u.meshmb_feeds.start_ack_offset){
	    DEBUGF(meshmb, "Seeking back to ack %"PRIu64", msg (0) to resume now", iterator->ack_reader.read.length);
	    r->u.meshmb_feeds.start_ack_offset = iterator->ack_reader.read.length;
	    meshmb_activity_seek(iterator, r->u.meshmb_feeds.start_ack_offset, 0);
	    r->u.meshmb_feeds.current_ack_offset = iterator->ack_reader.record_end_offset;
	    r->u.meshmb_feeds.current_msg_offset = iterator->msg_reader.record_end_offset;
	    if (iterator->msg_reader.type != MESSAGE_BLOCK_TYPE_MESSAGE)
	      activity_next(r);
	    return 1;
	  }

	  r->u.meshmb_feeds.start_ack_offset = 0;
	  r->u.meshmb_feeds.current_ack_offset = 0;
	  r->u.meshmb_feeds.current_msg_offset = 0;
	  if (iterator)
	    meshmb_activity_close(iterator);
	  r->u.meshmb_feeds.iterator = NULL;
	  http_request_pause_response(&r->http, r->u.meshmb_feeds.end_time);
	  return 0;
	}
      }

      strbuf_puts(b, "\n]\n}\n");
      if (!strbuf_overrun(b))
	r->u.plylist.phase = LIST_DONE;

      // fall through...
    case LIST_DONE:
      return 0;
  }
  return -1;
}

static int restful_meshmb_activity_json_content(struct http_request *hr, unsigned char *buf, size_t bufsz, struct http_content_generator_result *result)
{
  return generate_http_content_from_strbuf_chunks(hr, (char *)buf, bufsz, result, restful_meshmb_activity_json_content_chunk);
}

static int restful_meshmb_activity(httpd_request *r, const char *remainder)
{
  if (*remainder)
    return 404;

  struct meshmb_session *session = open_session(&r->bid);
  if (!session){
    http_request_simple_response(&r->http, 500, "TODO, detailed response");
    return 500;
  }
  assert(r->finalise_union == NULL);
  r->finalise_union = feedlist_finalise;
  r->trigger_rhizome_bundle_added = feedlist_on_rhizome_add;
  r->u.meshmb_feeds.phase = LIST_HEADER;
  r->u.meshmb_feeds.session = session;
  r->u.meshmb_feeds.iterator = NULL;
  r->u.meshmb_feeds.generation = meshmb_flush(session->feeds);
  r->u.meshmb_feeds.current_ack_offset = 0;
  r->u.meshmb_feeds.current_msg_offset = 0;
  bzero(&r->u.meshmb_feeds.bundle_id, sizeof r->u.meshmb_feeds.bundle_id);

  http_request_response_generated(&r->http, 200, &CONTENT_TYPE_JSON, restful_meshmb_activity_json_content);
  return 1;
}

DECLARE_HANDLER("/restful/meshmb/", restful_meshmb_);
static int restful_meshmb_(httpd_request *r, const char *remainder)
{
  r->http.response.header.content_type = &CONTENT_TYPE_JSON;
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
    } else if (strcmp(remainder, "/messagelist.json") == 0) {
      handler = restful_meshmb_list;
      remainder = "";
      r->ui64 = 0;
    } else if (strcmp(remainder, "/feedlist.json") == 0) {
      handler = restful_meshmb_feedlist;
      remainder = "";
      r->ui64 = 0;
    } else if (strcmp(remainder, "/activity.json") == 0) {
      handler = restful_meshmb_activity;
      remainder = "";
      r->u.meshmb_feeds.end_ack_offset = 0;
      r->u.meshmb_feeds.end_msg_offset = 0;
      r->u.meshmb_feeds.end_time = 0;
    } else if (   str_startswith(remainder, "/activity/", &end)
	       && strn_to_activity_token(end, r, &end)
	       && strcmp(end, "activity.json") == 0) {
      r->u.meshmb_feeds.end_time = gettime_ms() + config.api.restful.newsince_timeout * 1000;
      handler = restful_meshmb_activity;
      remainder = "";
    } else if (   str_startswith(remainder, "/newsince/", &end)
	       && strn_to_position_token(end, &r->ui64, &end)
	       && strcmp(end, "messagelist.json") == 0) {
      handler = restful_meshmb_newsince_list;
      remainder = "";
    } else if(str_startswith(remainder, "/follow/", &end)
	&& strn_to_identity_t(&r->u.meshmb_feeds.bundle_id, end, &end) != -1) {
      handler = restful_meshmb_follow_ignore;
      verb = HTTP_VERB_POST;
      r->ui64 = FLAG_FOLLOW;
      remainder = "";
    } else if(str_startswith(remainder, "/ignore/", &end)
	&& strn_to_identity_t(&r->u.meshmb_feeds.bundle_id, end, &end) != -1) {
      handler = restful_meshmb_follow_ignore;
      verb = HTTP_VERB_POST;
      r->ui64 = FLAG_IGNORE;
      remainder = "";
    } else if(str_startswith(remainder, "/block/", &end)
	&& strn_to_identity_t(&r->u.meshmb_feeds.bundle_id, end, &end) != -1) {
      handler = restful_meshmb_follow_ignore;
      verb = HTTP_VERB_POST;
      r->ui64 = FLAG_BLOCK;
      remainder = "";
    }
/*
  } else if(strcmp(remainder, "/find.json") == 0) {
    handler = restful_meshmb_find;
    remainder = "";
  } else if (   str_startswith(remainder, "/newsince/", &end) {
	     && strn_to_find_token(end, &r->ui64, &end)
	     && strcmp(end, "find.json") == 0) {
    handler = restful_meshmb_newsince_find;
    remainder = "";
    */
  }

  if (handler == NULL)
    return 404;
  if (r->http.verb != verb)
    return 405;
  return handler(r, remainder);
}
