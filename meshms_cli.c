#include <inttypes.h>
#include "serval_types.h"
#include "dataformats.h"
#include "cli.h"
#include "meshms.h"
#include "log.h"
#include "debug.h"
#include "instance.h"
#include "conf.h"
#include "commandline.h"


// output the list of existing conversations for a given local identity
DEFINE_CMD(app_meshms_conversations, 0,
  "List MeshMS threads that include <sid>",
  "meshms","list","conversations" KEYRING_PIN_OPTIONS, "[--include-message]", "<sid>","[<offset>]","[<count>]");
static int app_meshms_conversations(const struct cli_parsed *parsed, struct cli_context *context)
{
  const char *sidhex, *offset_str, *count_str;
  if (cli_arg(parsed, "sid", &sidhex, str_is_subscriber_id, "") == -1
    || cli_arg(parsed, "offset", &offset_str, NULL, "0")==-1
    || cli_arg(parsed, "count", &count_str, NULL, "-1")==-1)
    return -1;

  int include_message = cli_arg(parsed, "--include-message", NULL, NULL, NULL) == 0;
  sid_t sid;
  struct meshms_conversations *conv = NULL;
  enum meshms_status status = MESHMS_STATUS_ERROR;

  fromhex(sid.binary, sidhex, sizeof(sid.binary));
  int offset=atoi(offset_str);
  int count=atoi(count_str);

  if (create_serval_instance_dir() == -1)
    goto end;
  if (!(keyring = keyring_open_instance_cli(parsed)))
    goto end;

  if (rhizome_opendb() == -1)
    goto end;

  if (meshms_failed(status = meshms_conversations_list(NULL, &sid, NULL, &conv)))
    goto end;

  const char *names[]={
    "_id","recipient","read", "last_message", "read_offset", "message"
  };

  cli_columns(context, include_message? 6: 5, names);
  int rows = 0;
  if (conv) {
    struct meshms_conversation_iterator it;
    for (meshms_conversation_iterator_start(&it, conv);
	it.current && (count < 0 || rows < offset + count);
	meshms_conversation_iterator_advance(&it), ++rows
    ) {
      if (rows >= offset) {
	cli_put_long(context, rows, ":");
	cli_put_hexvalue(context, it.current->them.binary, sizeof(it.current->them), ":");
	cli_put_string(context, it.current->read_offset < it.current->their_last_message ? "unread":"", ":");
	cli_put_long(context, it.current->their_last_message, ":");
	cli_put_long(context, it.current->read_offset, include_message?":":"\n");
	if (include_message){
	  int output = 0;
	  if (it.current->their_last_message && it.current->their_ply.found){
	    struct message_ply_read reader;
	    bzero(&reader, sizeof reader);
	    if (message_ply_read_open(&reader, &it.current->their_ply.bundle_id) == 0){
	      reader.read.offset = it.current->their_last_message;
	      if (message_ply_read_prev(&reader)==0){
		cli_put_string(context, (const char *)reader.record, "\n");
		output = 1;
	      }
	      message_ply_read_close(&reader);
	    }
	  }
	  if (!output)
	    cli_put_string(context, "", "\n");
	}
      }
    }
  }
  cli_row_count(context, rows);
  status=MESHMS_STATUS_OK;

end:
  if (conv)
    meshms_free_conversations(conv);
  if (keyring)
    keyring_free(keyring);
  keyring = NULL;
  return status;
}

DEFINE_CMD(app_meshms_send_message, 0,
  "Send a MeshMS message from <sender_sid> to <recipient_sid>",
  "meshms","send","message" KEYRING_PIN_OPTIONS, "<sender_sid>", "<recipient_sid>", "<payload>");
static int app_meshms_send_message(const struct cli_parsed *parsed, struct cli_context *UNUSED(context))
{
  const char *my_sidhex, *their_sidhex, *message;
  if (cli_arg(parsed, "sender_sid", &my_sidhex, str_is_subscriber_id, "") == -1
    || cli_arg(parsed, "recipient_sid", &their_sidhex, str_is_subscriber_id, "") == -1
    || cli_arg(parsed, "payload", &message, NULL, "") == -1)
    return -1;

  sid_t my_sid, their_sid;
  if (str_to_sid_t(&my_sid, my_sidhex) == -1)
    return WHY("Invalid sender SID");
  if (str_to_sid_t(&their_sid, their_sidhex) == -1)
    return WHY("Invalid recipient SID");

  if (create_serval_instance_dir() == -1)
    return -1;
  if (!(keyring = keyring_open_instance_cli(parsed)))
    return -1;
  if (rhizome_opendb() == -1){
    keyring_free(keyring);
    keyring = NULL;
    return -1;
  }

  // include terminating NUL
  enum meshms_status status = meshms_send_message(&my_sid, &their_sid, message, strlen(message) + 1);
  keyring_free(keyring);
  keyring = NULL;
  return meshms_failed(status) ? status : 0;
}

DEFINE_CMD(app_meshms_list_messages, 0,
   "List MeshMS messages between <sender_sid> and <recipient_sid>",
   "meshms","list","messages" KEYRING_PIN_OPTIONS, "<sender_sid>","<recipient_sid>");
static int app_meshms_list_messages(const struct cli_parsed *parsed, struct cli_context *context)
{
  const char *my_sidhex, *their_sidhex;
  if (cli_arg(parsed, "sender_sid", &my_sidhex, str_is_subscriber_id, "") == -1
    || cli_arg(parsed, "recipient_sid", &their_sidhex, str_is_subscriber_id, "") == -1)
    return -1;
  if (create_serval_instance_dir() == -1)
    return -1;
  if (!(keyring = keyring_open_instance_cli(parsed)))
    return -1;
  if (rhizome_opendb() == -1){
    keyring_free(keyring);
    keyring = NULL;
    return -1;
  }
  sid_t my_sid, their_sid;
  if (str_to_sid_t(&my_sid, my_sidhex) == -1){
    keyring_free(keyring);
    keyring = NULL;
    return WHY("invalid sender SID");
  }
  if (str_to_sid_t(&their_sid, their_sidhex) == -1){
    keyring_free(keyring);
    keyring = NULL;
    return WHY("invalid recipient SID");
  }
  struct meshms_message_iterator iter;
  enum meshms_status status;
  if (meshms_failed(status = meshms_message_iterator_open(&iter, &my_sid, &their_sid))) {
    keyring_free(keyring);
    keyring = NULL;
    return status;
  }
  const char *names[]={
    "_id","offset","age","type","message"
  };
  cli_columns(context, 5, names);
  bool_t marked_delivered = 0;
  bool_t marked_read = 0;
  time_s_t now = gettime();
  int id = 0;
  while ((status = meshms_message_iterator_prev(&iter)) == MESHMS_STATUS_UPDATED) {
    switch (iter.type) {
      case MESSAGE_SENT:
	if (iter.delivered && !marked_delivered){
	  cli_put_long(context, id++, ":");
	  cli_put_long(context, iter.latest_ack_offset, ":");
	  cli_put_long(context, iter.timestamp ? (now - iter.timestamp):(long)-1, ":");
	  cli_put_string(context, "ACK", ":");
	  cli_put_string(context, "delivered", "\n");
	  marked_delivered = 1;
	}
	// TODO new message format here
	cli_put_long(context, id++, ":");
	cli_put_long(context, iter.offset, ":");
	cli_put_long(context, iter.timestamp ? (now - iter.timestamp):(long)-1, ":");
	cli_put_string(context, ">", ":");
	cli_put_string(context, iter.text, "\n");
	break;
      case ACK_RECEIVED:
	break;
      case MESSAGE_RECEIVED:
	if (iter.read && !marked_read) {
	  cli_put_long(context, id++, ":");
	  cli_put_long(context, iter.read_offset, ":");
	  cli_put_long(context, iter.timestamp ? (now - iter.timestamp):(long)-1, ":");
	  cli_put_string(context, "MARK", ":");
	  cli_put_string(context, "read", "\n");
	  marked_read = 1;
	}
	// TODO new message format here
	cli_put_long(context, id++, ":");
	cli_put_long(context, iter.offset, ":");
	cli_put_long(context, iter.timestamp ? (now - iter.timestamp):(long)-1, ":");
	cli_put_string(context, "<", ":");
	cli_put_string(context, iter.text, "\n");
	break;
    }
  }
  if (!meshms_failed(status))
    cli_row_count(context, id);
  meshms_message_iterator_close(&iter);
  keyring_free(keyring);
  keyring = NULL;
  return status;
}

DEFINE_CMD(app_meshms_mark_read, 0,
  "Mark incoming messages from this recipient as read.",
  "meshms","read","messages" KEYRING_PIN_OPTIONS, "<sender_sid>", "[<recipient_sid>]", "[<offset>]");
static int app_meshms_mark_read(const struct cli_parsed *parsed, struct cli_context *UNUSED(context))
{
  const char *my_sidhex, *their_sidhex, *offset_str;
  if (cli_arg(parsed, "sender_sid", &my_sidhex, str_is_subscriber_id, "") == -1
    || cli_arg(parsed, "recipient_sid", &their_sidhex, str_is_subscriber_id, NULL) == -1
    || cli_arg(parsed, "offset", &offset_str, str_is_uint64_decimal, NULL)==-1)
   return -1;

  if (create_serval_instance_dir() == -1)
    return -1;
  if (!(keyring = keyring_open_instance_cli(parsed)))
    return -1;
  int ret = -1;
  if (rhizome_opendb() == -1)
    goto done;
  sid_t my_sid, their_sid;
  if (str_to_sid_t(&my_sid, my_sidhex) == -1) {
    ret = WHYF("my_sidhex=%s", my_sidhex);
    goto done;
  }
  if (their_sidhex && str_to_sid_t(&their_sid, their_sidhex) == -1) {
    ret = WHYF("their_sidhex=%s", their_sidhex);
    goto done;
  }
  uint64_t offset = UINT64_MAX;
  if (offset_str) {
    if (!their_sidhex) {
      ret = WHY("missing recipient_sid");
      goto done;
    }
    if (!str_to_uint64(offset_str, 10, &offset, NULL)) {
      ret = WHYF("offset_str=%s", offset_str);
      goto done;
    }
  }
  enum meshms_status status = meshms_mark_read(&my_sid, their_sidhex ? &their_sid : NULL, offset);
  ret = (status == MESHMS_STATUS_UPDATED) ? MESHMS_STATUS_OK : status;
done:
  keyring_free(keyring);
  keyring = NULL;
  return ret;
}
