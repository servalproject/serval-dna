#include "serval_types.h"
#include "dataformats.h"
#include "cli.h"
#include "log.h"
#include "debug.h"
#include "instance.h"
#include "conf.h"
#include "commandline.h"
#include "overlay_buffer.h"

/*
DEFINE_CMD(app_meshmb_news, 0,
  "",
  "meshmb", "news" KEYRING_PIN_OPTIONS, "<sid>");
static int app_meshmb_news(const struct cli_parsed *parsed, struct cli_context *context)
{
  return 0;
}
*/

static int meshmb_send(keyring_identity *id, const char *message, size_t message_len){
  struct message_ply ply;
  bzero(&ply, sizeof ply);

  bcopy(id->sign_pk, &ply.bundle_id, sizeof(ply.bundle_id));
  ply.known_bid = 1;

  struct overlay_buffer *b = ob_new();
  message_ply_append_message(b, message, message_len);
  message_ply_append_timestamp(b);
  assert(!ob_overrun(b));

  int ret = message_ply_append(id, RHIZOME_SERVICE_MESHMB, NULL, &ply, b);
  ob_free(b);

  return ret;
}

DEFINE_CMD(app_meshmb_send, 0,
  "",
  "meshmb", "send" KEYRING_PIN_OPTIONS, "<id>", "<message>");
static int app_meshmb_send(const struct cli_parsed *parsed, struct cli_context *UNUSED(context))
{
  const char *idhex, *message;
  if (cli_arg(parsed, "id", &idhex, str_is_identity, "") == -1
    || cli_arg(parsed, "message", &message, NULL, "") == -1)
    return -1;

  identity_t identity;
  if (str_to_identity_t(&identity, idhex) == -1)
    return WHY("Invalid identity");

  if (create_serval_instance_dir() == -1)
    return -1;
  if (!(keyring = keyring_open_instance_cli(parsed)))
    return -1;

  int ret = -1;
  if (rhizome_opendb() == -1)
    goto end;

  keyring_identity *id = keyring_find_identity(keyring, &identity);
  if (!id){
    WHY("Invalid identity");
    goto end;
  }

  ret = meshmb_send(id, message, strlen(message)+1);
end:
  keyring_free(keyring);
  keyring = NULL;
  return ret;
}

/*
DEFINE_CMD(app_meshmb_list, 0,
  "",
  "meshmb", "list", "following|blocked" KEYRING_PIN_OPTIONS, "--last-message", "<sid>");
static int app_meshmb_list(const struct cli_parsed *parsed, struct cli_context *context)
{
  return 0;
}

DEFINE_CMD(app_meshmb_follow, 0,
  "",
  "meshmb", "follow|ignore|block" KEYRING_PIN_OPTIONS, "<sid>", "<id>");
static int app_meshmb_follow(const struct cli_parsed *parsed, struct cli_context *context)
{
  return 0;
}

DEFINE_CMD(app_meshmb_find, 0,
  "",
  "meshmb", "find", "[<search>]");
static int app_meshmb_find(const struct cli_parsed *parsed, struct cli_context *context)
{
  return 0;
}
*/

DEFINE_CMD(app_meshmb_read, 0,
  "",
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
  if (create_serval_instance_dir() == -1)
    return -1;
  if (rhizome_opendb() == -1)
    return -1;

  struct message_ply_read read;
  bzero(&read, sizeof read);

  if (message_ply_read_open(&read, &bid)==-1)
    return -1;

  int ret=0;
  int row_id=0;
  const char *names[]={
    "_id","offset","age","message"
  };
  cli_columns(context, 4, names);
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
	cli_put_long(context, timestamp ? (now - timestamp) : (long)-1, ":");
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

  message_ply_read_close(&read);
  return ret;
}
