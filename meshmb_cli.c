#include "serval.h"
#include "serval_types.h"
#include "dataformats.h"
#include "cli.h"
#include "log.h"
#include "debug.h"
#include "instance.h"
#include "commandline.h"
#include "keyring.h"
#include "rhizome.h"
#include "message_ply.h"
#include "meshmb.h"
#include "feature.h"

DEFINE_FEATURE(cli_meshmb);

DEFINE_CMD(app_meshmb_send, 0,
  "Append a public broadcast message to your feed",
  "meshmb", "send" KEYRING_PIN_OPTIONS, "<id>", "<message>", "...");
static int app_meshmb_send(const struct cli_parsed *parsed, struct cli_context *UNUSED(context))
{
  const char *idhex, *message;
  if (cli_arg(parsed, "id", &idhex, str_is_identity, "") == -1
    || cli_arg(parsed, "message", &message, NULL, "") == -1)
    return -1;

  unsigned nfields = (parsed->varargi == -1) ? 0 : parsed->argc - (unsigned)parsed->varargi;
  struct rhizome_manifest_field_assignment fields[nfields];

  if (nfields){
    if (rhizome_parse_field_assignments(fields, nfields, parsed->args + parsed->varargi)==-1)
      return -1;
  }

  identity_t identity;
  if (str_to_identity_t(&identity, idhex) == -1)
    return WHY("Invalid identity");

  if (create_serval_instance_dir() == -1
    || rhizome_opendb() == -1
    || !(keyring = keyring_open_instance_cli(parsed)))
    return -1;

  keyring_identity *id = keyring_find_identity(keyring, &identity);
  if (!id)
    return WHY("Invalid identity");

  return meshmb_send(id, message, strlen(message)+1, nfields, fields);
}

// TODO from offset....?
DEFINE_CMD(app_meshmb_read, 0,
  "Read all messages in a broadcast message feed.",
  "meshmb", "read", "<id>");
static int app_meshmb_read(const struct cli_parsed *parsed, struct cli_context *context)
{
  const char *hex_id;
  if (cli_arg(parsed, "id", &hex_id, str_is_identity, "") == -1)
    return -1;

  rhizome_bid_t bid;
  if (str_to_rhizome_bid_t(&bid, hex_id) == -1)
    return WHY("Invalid Identity");

  /* Ensure the Rhizome database exists and is open */
  if (create_serval_instance_dir() == -1
    || rhizome_opendb() == -1)
    return -1;

  struct message_ply_read read;
  bzero(&read, sizeof read);

  if (message_ply_read_open(&read, &bid)==-1)
    return -1;

  int ret=0;
  size_t row_id = 0;
  const char *names[]={
    "_id","offset","age","message"
  };
  cli_start_table(context, NELS(names), names);
  time_s_t timestamp = 0;
  time_s_t now = gettime();

  while(message_ply_read_prev(&read)==0){
    switch(read.type){
      case MESSAGE_BLOCK_TYPE_TIME:
	if (read.record_length<4){
	  WARN("Malformed ply, expected 4 byte timestamp");
	  continue;
	}
	timestamp = read_uint32(read.record);
	break;

      case MESSAGE_BLOCK_TYPE_MESSAGE:
	cli_put_long(context, row_id++, ":");
	cli_put_long(context, read.record_end_offset, ":");
	cli_put_long(context, timestamp ? (long)(now - timestamp) : (long)-1, ":");
	cli_put_string(context, (const char *)read.record, "\n");

	break;

      case MESSAGE_BLOCK_TYPE_ACK:
	// TODO, link to some other ply?
	break;

      default:
	//ignore unknown types
	break;
    }
  }
  cli_end_table(context, row_id);

  message_ply_read_close(&read);
  return ret;
}

DEFINE_CMD(app_meshmb_find, 0,
  "Browse available broadcast message feeds",
  "meshmb", "find", "[<search>]");
static int app_meshmb_find(const struct cli_parsed *parsed, struct cli_context *context)
{
  const char *search=NULL;
  cli_arg(parsed, "search", &search, NULL, "");
  // Ensure the Rhizome database exists and is open
  if (create_serval_instance_dir() == -1
    || rhizome_opendb() == -1)
    return -1;

  struct rhizome_list_cursor cursor;
  bzero(&cursor, sizeof cursor);
  cursor.service = RHIZOME_SERVICE_MESHMB;
  cursor.name = search && search[0] ? search : NULL;

  //TODO hide feeds that have been blocked

  if (rhizome_list_open(&cursor) == -1)
    return -1;

  const char *names[]={
    "_id",
    "id",
    "version",
    "date",
    "name"
  };
  cli_start_table(context, NELS(names), names);

  unsigned rowcount=0;
  int n;

  while ((n = rhizome_list_next(&cursor)) == 1) {
    rowcount++;
    rhizome_manifest *m = cursor.manifest;
    cli_put_long(context, m->rowid, ":");
    cli_put_hexvalue(context, m->keypair.public_key.binary, sizeof m->keypair.public_key.binary, ":");
    cli_put_long(context, m->version, ":");
    cli_put_long(context, m->has_date ? m->date : 0, ":");
    cli_put_string(context, m->name, "\n");
  }
  rhizome_list_release(&cursor);
  cli_end_table(context, rowcount);
  return 0;
}


DEFINE_CMD(app_meshmb_follow, 0,
  "Start or stop following a broadcast feed",
  "meshmb", "follow|ignore" KEYRING_PIN_OPTIONS, "<id>", "<peer>");
static int app_meshmb_follow(const struct cli_parsed *parsed, struct cli_context *UNUSED(context))
{
  const char *idhex, *peerhex;
  if (cli_arg(parsed, "id", &idhex, str_is_identity, "") == -1
    ||cli_arg(parsed, "peer", &peerhex, str_is_identity, "") == -1)
    return -1;

  int follow = cli_arg(parsed, "follow", NULL, NULL, NULL) == 0;

  identity_t identity;
  identity_t peer;
  if (str_to_identity_t(&identity, idhex) == -1
    ||str_to_identity_t(&peer, peerhex) == -1)
    return WHY("Invalid identity");

  if (create_serval_instance_dir() == -1
    || rhizome_opendb() == -1
    || !(keyring = keyring_open_instance_cli(parsed)))
    return -1;

  int ret = -1;
  struct meshmb_feeds *feeds = NULL;

  keyring_identity *id = keyring_find_identity(keyring, &identity);
  if (!id){
    WHY("Invalid identity");
    goto end;
  }

  if (meshmb_open(id, &feeds)==-1)
    goto end;

  if (follow){
    if (meshmb_follow(feeds, &peer)==-1)
      goto end;
  }else{
    if (meshmb_ignore(feeds, &peer)==-1)
      goto end;
  }

  if (meshmb_flush(feeds)==-1)
    goto end;

  ret = 0;

end:
  if (feeds)
    meshmb_close(feeds);
  if (keyring)
    keyring_free(keyring);
  keyring = NULL;
  return ret;
}

struct cli_enum_context{
  unsigned rowcount;
  struct cli_context *context;
};

static int list_callback(struct meshmb_feed_details *details, void *context)
{
  struct cli_enum_context *enum_context = context;
  enum_context->rowcount++;
  cli_put_long(enum_context->context, enum_context->rowcount, ":");
  cli_put_string(enum_context->context, alloca_tohex_rhizome_bid_t(details->bundle_id), ":");
  cli_put_string(enum_context->context, details->name, ":");
  cli_put_long(enum_context->context, details->timestamp ? (long)(gettime() - details->timestamp) : (long)-1, ":");
  cli_put_string(enum_context->context, details->last_message, "\n");
  return 0;
}

DEFINE_CMD(app_meshmb_list, 0,
  "List the feeds that you are currently following",
  "meshmb", "list", "following" KEYRING_PIN_OPTIONS, "<id>");
static int app_meshmb_list(const struct cli_parsed *parsed, struct cli_context *context)
{
  const char *idhex;
  if (cli_arg(parsed, "id", &idhex, str_is_identity, "") == -1)
    return -1;

  identity_t identity;
  if (str_to_identity_t(&identity, idhex) == -1)
    return WHY("Invalid identity");

  if (create_serval_instance_dir() == -1
    || rhizome_opendb() == -1
    || !(keyring = keyring_open_instance_cli(parsed)))
    return -1;

  int ret = -1;
  struct meshmb_feeds *feeds = NULL;

  keyring_identity *id = keyring_find_identity(keyring, &identity);
  if (!id){
    WHY("Invalid identity");
    goto end;
  }

  if (meshmb_open(id, &feeds)==-1)
    goto end;

  const char *names[]={
    "_id",
    "id",
    "name",
    "age",
    "last_message"
  };
  cli_start_table(context, NELS(names), names);
  struct cli_enum_context enum_context = {
    .rowcount = 0,
    .context = context,
  };

  meshmb_enum(feeds, NULL, list_callback, &enum_context);

  cli_end_table(context, enum_context.rowcount);
  ret = 0;

end:
  if (feeds)
    meshmb_close(feeds);
  keyring_free(keyring);
  keyring = NULL;
  return 0;
}

/*
DEFINE_CMD(app_meshmb_news, 0,
  "",
  "meshmb", "news" KEYRING_PIN_OPTIONS, "<id>");
static int app_meshmb_news(const struct cli_parsed *parsed, struct cli_context *context)
{
  return 0;
}
*/
