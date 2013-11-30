#include <assert.h>
#include "serval.h"
#include "rhizome.h"
#include "log.h"
#include "conf.h"
#include "crypto.h"
#include "strlcpy.h"
#include "keyring.h"
#include "dataformats.h"

#define MESHMS_BLOCK_TYPE_ACK 0x01
#define MESHMS_BLOCK_TYPE_MESSAGE 0x02
#define MESHMS_BLOCK_TYPE_BID_REFERENCE 0x03

// the manifest details for one half of a conversation
struct ply{
  rhizome_bid_t bundle_id;
  uint64_t version;
  uint64_t tail;
  uint64_t size;
};

struct conversations{
  // binary tree
  struct conversations *_left;
  struct conversations *_right;
  
  // who are we talking to?
  sid_t them;
  
  char found_my_ply;
  struct ply my_ply;
  
  char found_their_ply;
  struct ply their_ply;
  
  // what is the offset of their last message
  uint64_t their_last_message;
  // what is the last message we marked as read
  uint64_t read_offset;
  // our cached value for the last known size of their ply
  uint64_t their_size;
};

// cursor state for reading one half of a conversation
struct ply_read{
  // rhizome payload
  struct rhizome_read read;
  // block buffer
  struct rhizome_read_buffer buff;
  
  // details of the current record
  uint64_t record_end_offset;
  uint16_t record_length;
  size_t buffer_size;
  char type;
  // raw record data
  unsigned char *buffer;
};

static int meshms_conversations_list(const sid_t *my_sid, const sid_t *their_sid, struct conversations **conv);

static void free_conversations(struct conversations *conv){
  if (!conv)
    return;
  free_conversations(conv->_left);
  free_conversations(conv->_right);
  free(conv);
}

static int get_my_conversation_bundle(const sid_t *my_sidp, rhizome_manifest *m)
{
  /* Find our private key */
  int cn=0,in=0,kp=0;
  if (!keyring_find_sid(keyring,&cn,&in,&kp,my_sidp))
    return WHYF("SID was not found in keyring: %s", alloca_tohex_sid_t(*my_sidp));
  
  char seed[1024];
  snprintf(seed, sizeof(seed), 
    "incorrection%sconcentrativeness", 
	alloca_tohex(keyring->contexts[cn]->identities[in]
	->keypairs[kp]->private_key, crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES));
	
  if (rhizome_get_bundle_from_seed(m, seed) == -1)
    return -1;
  
  // always consider the content encrypted, we don't need to rely on the manifest itself.
  rhizome_manifest_set_crypt(m, PAYLOAD_ENCRYPTED);
  assert(m->haveSecret);
  if (m->haveSecret == NEW_BUNDLE_ID) {
    rhizome_manifest_set_service(m, RHIZOME_SERVICE_FILE);
    if (rhizome_fill_manifest(m, NULL, my_sidp) == -1)
      return WHY("Invalid manifest");
    if (config.debug.meshms) {
      char secret[RHIZOME_BUNDLE_KEY_STRLEN + 1];
      rhizome_bytes_to_hex_upper(m->cryptoSignSecret, secret, RHIZOME_BUNDLE_KEY_BYTES);
      // The 'meshms' automated test depends on this message; do not alter.
      DEBUGF("MESHMS CONVERSATION BUNDLE bid=%s secret=%s",
	    alloca_tohex_rhizome_bid_t(m->cryptoSignPublic),
	    secret
	  );
    }
  } else {
    if (strcmp(m->service, RHIZOME_SERVICE_FILE) != 0)
      return WHYF("Invalid manifest, service=%s but should be %s", m->service, RHIZOME_SERVICE_MESHMS2);
  }
  return 0;
}

static struct conversations *add_conv(struct conversations **conv, const sid_t *them)
{
  struct conversations **ptr = conv;
  while(*ptr){
    int cmp = cmp_sid_t(&(*ptr)->them, them);
    if (cmp == 0)
      break;
    if (cmp < 0)
      ptr = &(*ptr)->_left;
    else
      ptr = &(*ptr)->_right;
  }
  if (!*ptr){
    *ptr = emalloc_zero(sizeof(struct conversations));
    if (*ptr)
      (*ptr)->them = *them;
  }
  return *ptr;
}

// find matching conversations
// if their_sid == my_sid, return all conversations with any recipient
static int get_database_conversations(const sid_t *my_sid, const sid_t *their_sid, struct conversations **conv)
{
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  sqlite3_stmt *statement = sqlite_prepare_bind(&retry,
      "SELECT id, version, filesize, tail, sender, recipient"
      " FROM manifests"
      " WHERE service = ?3"
      " AND (sender=?1 or recipient=?1)"
      " AND (sender=?2 or recipient=?2)",
      SID_T, my_sid,
      SID_T, their_sid ? their_sid : my_sid,
      STATIC_TEXT, RHIZOME_SERVICE_MESHMS2,
      END
    );
  if (!statement)
    return -1;
  if (config.debug.meshms) {
    const char *my_sid_hex = alloca_tohex_sid_t(*my_sid);
    const char *their_sid_hex = alloca_tohex_sid_t(*(their_sid ? their_sid : my_sid));
    DEBUGF("Looking for conversations for %s, %s", my_sid_hex, their_sid_hex);
  }
  while (sqlite_step_retry(&retry, statement) == SQLITE_ROW) {
    const char *id_hex = (const char *)sqlite3_column_text(statement, 0);
    int64_t version = sqlite3_column_int64(statement, 1);
    int64_t size = sqlite3_column_int64(statement, 2);
    int64_t tail = sqlite3_column_int64(statement, 3);
    const char *sender = (const char *)sqlite3_column_text(statement, 4);
    const char *recipient = (const char *)sqlite3_column_text(statement, 5);
    if (config.debug.meshms)
      DEBUGF("found id %s, sender %s, recipient %s", id_hex, sender, recipient);
    rhizome_bid_t bid;
    if (str_to_rhizome_bid_t(&bid, id_hex) == -1) {
      WHYF("invalid Bundle ID hex: %s -- skipping", alloca_str_toprint(id_hex));
      continue;
    }
    const char *them = recipient;
    sid_t their_sid;
    if (str_to_sid_t(&their_sid, them) == -1) {
      WHYF("invalid SID hex: %s -- skipping", alloca_str_toprint(them));
      continue;
    }
    if (cmp_sid_t(&their_sid, my_sid) == 0) {
      them = sender;
      if (str_to_sid_t(&their_sid, them) == -1) {
	WHYF("invalid SID hex: %s -- skipping", alloca_str_toprint(them));
	continue;
      }
    }
    struct conversations *ptr = add_conv(conv, &their_sid);
    if (!ptr)
      break;
    struct ply *p;
    if (them==sender){
      ptr->found_their_ply=1;
      p=&ptr->their_ply;
    }else{
      ptr->found_my_ply=1;
      p=&ptr->my_ply;
    }
    p->bundle_id = bid;
    p->version = version;
    p->tail = tail;
    p->size = size;
  }
  sqlite3_finalize(statement);
  return 0;
}

static struct conversations * find_or_create_conv(const sid_t *my_sid, const sid_t *their_sid)
{
  struct conversations *conv=NULL;
  if (meshms_conversations_list(my_sid, their_sid, &conv))
    return NULL;
  if (!conv){
    conv = emalloc_zero(sizeof(struct conversations));
    conv->them = *their_sid;
  }
  return conv;
}

static int create_ply(const sid_t *my_sid, struct conversations *conv, rhizome_manifest *m)
{
  if (config.debug.meshms)
    DEBUGF("Creating ply for my_sid=%s them=%s",
	alloca_tohex_sid_t(conv->them),
	alloca_tohex_sid_t(*my_sid));
  rhizome_manifest_set_service(m, RHIZOME_SERVICE_MESHMS2);
  rhizome_manifest_set_sender(m, my_sid);
  rhizome_manifest_set_recipient(m, &conv->them);
  rhizome_manifest_set_filesize(m, 0);
  rhizome_manifest_set_tail(m, 0);
  if (rhizome_fill_manifest(m, NULL, my_sid))
    return -1;
  assert(m->haveSecret);
  assert(m->payloadEncryption == PAYLOAD_ENCRYPTED);
  conv->my_ply.bundle_id = m->cryptoSignPublic;
  conv->found_my_ply = 1;
  return 0;
}

static int append_footer(unsigned char *buffer, char type, int payload_len)
{
  payload_len = (payload_len << 4) | (type&0xF);
  write_uint16(buffer, payload_len);
  return 2;
}

static int ply_read_open(struct ply_read *ply, const rhizome_bid_t *bid, rhizome_manifest *m)
{
  if (config.debug.meshms)
    DEBUGF("Opening ply %s", alloca_tohex_rhizome_bid_t(*bid));
  if (rhizome_retrieve_manifest(bid, m))
    return -1;
  int ret = rhizome_open_decrypt_read(m, &ply->read);
  if (ret == 1)
    WARNF("Payload was not found for manifest %s, %"PRId64, alloca_tohex_rhizome_bid_t(m->cryptoSignPublic), m->version);
  if (ret != 0)
    return ret;
  assert(m->filesize != RHIZOME_SIZE_UNSET);
  ply->read.offset = ply->read.length = m->filesize;
  return 0;
}

static int ply_read_close(struct ply_read *ply)
{
  if (ply->buffer){
    free(ply->buffer);
    ply->buffer=NULL;
  }
  ply->buffer_size=0;
  ply->buff.len=0;
  return rhizome_read_close(&ply->read);
}

// read the next record from the ply (backwards)
// returns 1 on EOF, -1 on failure
static int ply_read_next(struct ply_read *ply)
{
  ply->record_end_offset = ply->read.offset;
  unsigned char footer[2];
  if (ply->read.offset <= sizeof footer) {
    if (config.debug.meshms)
      DEBUGF("EOF");
    return 1;
  }
  ply->read.offset -= sizeof footer;
  ssize_t read;
  read = rhizome_read_buffered(&ply->read, &ply->buff, footer, sizeof footer);
  if (read == -1)
    return WHYF("rhizome_read_buffered() failed");
  if ((size_t) read != sizeof footer)
    return WHYF("Expected %zu bytes read, got %zu", (size_t) sizeof footer, (size_t) read);
  // (rhizome_read automatically advances the offset by the number of bytes read)
  ply->record_length=read_uint16(footer);
  ply->type = ply->record_length & 0xF;
  ply->record_length = ply->record_length>>4;
  
  if (config.debug.meshms)
    DEBUGF("Found record %d, length %d @%"PRId64, ply->type, ply->record_length, ply->record_end_offset);
  
  // need to allow for advancing the tail and cutting a message in half.
  if (ply->record_length + sizeof footer > ply->read.offset){
    if (config.debug.meshms)
      DEBUGF("EOF");
    return 1;
  }
  
  ply->read.offset -= ply->record_length + sizeof(footer);
  uint64_t record_start = ply->read.offset;
  
  if (ply->buffer_size < ply->record_length){
    ply->buffer_size = ply->record_length;
    unsigned char *b=realloc(ply->buffer, ply->buffer_size);
    if (!b)
      return WHY("realloc() failed");
    ply->buffer = b;
  }
  
  read = rhizome_read_buffered(&ply->read, &ply->buff, ply->buffer, ply->record_length);
  if (read == -1)
    return WHYF("rhizome_read_buffered() failed");
  if ((size_t) read != ply->record_length)
    return WHYF("Expected %u bytes read, got %zu", ply->record_length, (size_t) read);
  
  ply->read.offset = record_start;
  return 0;
}

// keep reading past messages until you find this type.
static int ply_find_next(struct ply_read *ply, char type){
  while(1){
    int ret = ply_read_next(ply);
    if (ret || ply->type==type)
      return ret;
  }
}

static int append_meshms_buffer(const sid_t *my_sid, struct conversations *conv, unsigned char *buffer, int len)
{
  int ret=-1;
  rhizome_manifest *mout = NULL;
  rhizome_manifest *m = rhizome_new_manifest();
  if (!m)
    goto end;
  
  if (conv->found_my_ply){
    if (rhizome_retrieve_manifest(&conv->my_ply.bundle_id, m))
      goto end;
    rhizome_authenticate_author(m);
    if (!m->haveSecret || m->authorship != AUTHOR_AUTHENTIC)
      goto end;
  }else{
    if (create_ply(my_sid, conv, m))
      goto end;
  }
  assert(m->haveSecret);
  assert(m->authorship == AUTHOR_AUTHENTIC);
  
  if (rhizome_append_journal_buffer(m, 0, buffer, len))
    goto end;
  
  if (rhizome_manifest_finalise(m, &mout, 1))
    goto end;

  ret=0;
  
end:
  if (mout && mout!=m)
    rhizome_manifest_free(mout);
  if (m)
    rhizome_manifest_free(m);
  return ret;
}

// update if any conversations are unread or need to be acked.
// return -1 for failure, 1 if the conversation index needs to be saved.
static int update_conversation(const sid_t *my_sid, struct conversations *conv){
  if (config.debug.meshms)
    DEBUG("Checking if conversation needs to be acked");
    
  // Nothing to be done if they have never sent us anything
  if (!conv->found_their_ply)
    return 0;
  
  rhizome_manifest *m_ours = NULL;
  rhizome_manifest *m_theirs = rhizome_new_manifest();
  if (!m_theirs)
    return -1;
    
  struct ply_read ply;
  bzero(&ply, sizeof(ply));
  int ret=-1;
  
  if (config.debug.meshms)
    DEBUG("Locating their last message");
    
  // find the offset of their last message
  if (rhizome_retrieve_manifest(&conv->their_ply.bundle_id, m_theirs))
    goto end;
  
  if (ply_read_open(&ply, &conv->their_ply.bundle_id, m_theirs))
    goto end;
    
  ret = ply_find_next(&ply, MESHMS_BLOCK_TYPE_MESSAGE);
  if (ret!=0){
    // no messages indicates that we didn't do anthing
    if (ret>0)
      ret=0;
    goto end;
  }
  
  if (conv->their_last_message == ply.record_end_offset){
    // nothing has changed since last time
    ret=0;
    goto end;
  }
    
  conv->their_last_message = ply.record_end_offset;
  if (config.debug.meshms)
    DEBUGF("Found last message @%"PRId64, conv->their_last_message);
  ply_read_close(&ply);
  
  // find our previous ack
  uint64_t previous_ack = 0;
  
  if (conv->found_my_ply){
    if (config.debug.meshms)
      DEBUG("Locating our previous ack");
      
    m_ours = rhizome_new_manifest();
    if (!m_ours)
      goto end;
    if (rhizome_retrieve_manifest(&conv->my_ply.bundle_id, m_ours))
      goto end;
    
    if (ply_read_open(&ply, &conv->my_ply.bundle_id, m_ours))
      goto end;
      
    ret = ply_find_next(&ply, MESHMS_BLOCK_TYPE_ACK);
    if (ret == -1)
      goto end;
      
    if (ret==0){
      if (unpack_uint(ply.buffer, ply.record_length, &previous_ack) == -1)
	previous_ack=0;
    }
    if (config.debug.meshms)
      DEBUGF("Previous ack is %"PRId64, previous_ack);
    ply_read_close(&ply);
  }else{
    if (config.debug.meshms)
      DEBUGF("No outgoing ply");
  }
  
  if (previous_ack >= conv->their_last_message){
    // their last message has already been acked
    ret=1;
    goto end;
  }
  
  // append an ack for their message
  if (config.debug.meshms)
    DEBUGF("Creating ACK for %"PRId64" - %"PRId64, previous_ack, conv->their_last_message);
  
  unsigned char buffer[24];
  int ofs=0;
  ofs+=pack_uint(&buffer[ofs], conv->their_last_message);
  if (previous_ack)
    ofs+=pack_uint(&buffer[ofs], conv->their_last_message - previous_ack);
  ofs+=append_footer(buffer+ofs, MESHMS_BLOCK_TYPE_ACK, ofs);
  ret = append_meshms_buffer(my_sid, conv, buffer, ofs);
  
end:
  ply_read_close(&ply);
  if (m_ours)
    rhizome_manifest_free(m_ours);
  if (m_theirs)
    rhizome_manifest_free(m_theirs);
  
  // if it's all good, remember the size of their ply at the time we examined it.
  if (ret>=0)
    conv->their_size = conv->their_ply.size;

  return ret;
}

// update conversations, and return 1 if the conversation index should be saved
static int update_conversations(const sid_t *my_sid, struct conversations *conv){
  if (!conv)
    return 0;
  int ret = 0;
  if (update_conversations(my_sid, conv->_left))
    ret=1;
    
  if (conv->their_size != conv->their_ply.size){
    if (update_conversation(my_sid, conv)>0)
      ret=1;
  }
  
  if (update_conversations(my_sid, conv->_right))
    ret=1;

  return ret;
}

// read our cached conversation list from our rhizome payload
// if we can't load the existing data correctly, just ignore it.
static int read_known_conversations(rhizome_manifest *m, const sid_t *their_sid, struct conversations **conv)
{
  if (m->haveSecret==NEW_BUNDLE_ID)
    return 0;
  
  struct rhizome_read read;
  bzero(&read, sizeof(read));
  struct rhizome_read_buffer buff;
  bzero(&buff, sizeof(buff));
  
  int ret = rhizome_open_decrypt_read(m, &read);
  if (ret == -1)
    goto end;
  
  unsigned char version=0xFF;
  ssize_t r = rhizome_read_buffered(&read, &buff, &version, 1);
  ret = -1;
  if (r == -1)
    goto end;
  if (version != 1) {
    WARNF("Expected version 1 (got 0x%02x)", version);
    goto end;
  }
  
  while (1) {
    sid_t sid;
    r = rhizome_read_buffered(&read, &buff, sid.binary, sizeof sid.binary);
    if (r != sizeof sid.binary)
      break;
    if (config.debug.meshms)
      DEBUGF("Reading existing conversation for %s", alloca_tohex_sid_t(sid));
    if (their_sid && cmp_sid_t(&sid, their_sid) != 0)
      continue;
    struct conversations *ptr = add_conv(conv, &sid);
    if (!ptr)
      goto end;
    unsigned char details[8*3];
    r = rhizome_read_buffered(&read, &buff, details, sizeof details);
    if (r == -1)
      break;
    int bytes = r;
    int ofs = 0;
    int unpacked = unpack_uint(details, bytes, &ptr->their_last_message);
    if (unpacked == -1)
      break;
    ofs += unpacked;
    unpacked = unpack_uint(details+ofs, bytes-ofs, &ptr->read_offset);
    if (unpacked == -1)
      break;
    ofs += unpacked;
    unpacked = unpack_uint(details+ofs, bytes-ofs, &ptr->their_size);
    if (unpacked == -1)
      break;
    ofs += unpacked;
    read.offset += ofs - bytes;
  }
  ret = 0;
end:
  rhizome_read_close(&read);
  return ret;
}

static ssize_t write_conversation(struct rhizome_write *write, struct conversations *conv)
{
  size_t len=0;
  if (!conv)
    return len;
  {
    unsigned char buffer[sizeof(conv->them) + (8*3)];
    if (write)
      bcopy(conv->them.binary, buffer, sizeof(conv->them));
    len+=sizeof(conv->them);
    if (write){
      len+=pack_uint(&buffer[len], conv->their_last_message);
      len+=pack_uint(&buffer[len], conv->read_offset);
      len+=pack_uint(&buffer[len], conv->their_size);
      int ret=rhizome_write_buffer(write, buffer, len);
      if (ret == -1)
	return ret;
    }else{
      len+=measure_packed_uint(conv->their_last_message);
      len+=measure_packed_uint(conv->read_offset);
      len+=measure_packed_uint(conv->their_size);
    }
    DEBUGF("len %s, %"PRId64", %"PRId64", %"PRId64" = %zu", 
      alloca_tohex_sid_t(conv->them),
      conv->their_last_message,
      conv->read_offset,
      conv->their_size,
      len);
  }
  // write the two child nodes
  ssize_t ret = write_conversation(write, conv->_left);
  if (ret == -1)
    return ret;
  len += (size_t) ret;
  ret = write_conversation(write, conv->_right);
  if (ret == -1)
    return ret;
  len += (size_t) ret;
  return len;
}

static int write_known_conversations(rhizome_manifest *m, struct conversations *conv)
{
  rhizome_manifest *mout=NULL;
  
  struct rhizome_write write;
  bzero(&write, sizeof(write));
  int ret=-1;
  
  // TODO rebalance tree...
  
  // measure the final payload first
  ssize_t len=write_conversation(NULL, conv);
  if (len == -1)
    goto end;
  
  // then write it
  rhizome_manifest_set_version(m, m->version + 1);
  rhizome_manifest_set_filesize(m, (size_t)len + 1);
  
  if (rhizome_write_open_manifest(&write, m) == -1)
    goto end;
  unsigned char version=1;
  if (rhizome_write_buffer(&write, &version, 1) == -1)
    goto end;
  if (write_conversation(&write, conv) == -1)
    goto end;
  if (rhizome_finish_write(&write))
    goto end;
  rhizome_manifest_set_filehash(m, &write.id);
  if (rhizome_manifest_finalise(m, &mout, 1))
    goto end;
  
  ret=0;
end:
  if (ret)
    rhizome_fail_write(&write);
  if (mout && m!=mout)
    rhizome_manifest_free(mout);
  return ret;
}

// read information about existing conversations from a rhizome payload
static int meshms_conversations_list(const sid_t *my_sid, const sid_t *their_sid, struct conversations **conv)
{
  int ret=-1;
  rhizome_manifest *m = rhizome_new_manifest();
  if (!m)
    goto end;
  if (get_my_conversation_bundle(my_sid, m))
    goto end;
    
  // read conversations payload
  if (read_known_conversations(m, their_sid, conv))
    goto end;
  
  if (get_database_conversations(my_sid, their_sid, conv))
    goto end;
    
  if (update_conversations(my_sid, *conv) && !their_sid){
    if (write_known_conversations(m, *conv))
      goto end;
  }
  ret=0;
  
end:
  rhizome_manifest_free(m);
  return ret;
}

// recursively traverse the conversation tree in sorted order and output the details of each conversation
static int output_conversations(struct cli_context *context, struct conversations *conv, 
      int output, int offset, int count){
  if (!conv)
    return 0;
  
  int traverse_count = output_conversations(context, conv->_left, output, offset, count);
  if (count <0 || output + traverse_count < offset + count){
    if (output + traverse_count >= offset){
      cli_put_long(context, output + traverse_count, ":");
      cli_put_hexvalue(context, conv->them.binary, sizeof(conv->them), ":");
      cli_put_string(context, conv->read_offset < conv->their_last_message ? "unread":"", ":");
      cli_put_long(context, conv->their_last_message, ":");
      cli_put_long(context, conv->read_offset, "\n");
    }
    traverse_count++;
  }
  traverse_count += output_conversations(context, conv->_right, output + traverse_count, offset, count);
  return traverse_count;
}

// output the list of existing conversations for a given local identity
int app_meshms_conversations(const struct cli_parsed *parsed, struct cli_context *context){
  const char *sidhex, *offset_str, *count_str;
  if (cli_arg(parsed, "sid", &sidhex, str_is_subscriber_id, "") == -1
    || cli_arg(parsed, "offset", &offset_str, NULL, "0")==-1
    || cli_arg(parsed, "count", &count_str, NULL, "-1")==-1)
    return -1;
    
  sid_t sid;
  fromhex(sid.binary, sidhex, sizeof(sid.binary));
  
  int offset=atoi(offset_str);
  int count=atoi(count_str);

  if (create_serval_instance_dir() == -1)
    return -1;
  if (!(keyring = keyring_open_instance_cli(parsed)))
    return -1;
  if (rhizome_opendb() == -1){
    keyring_free(keyring);
    return -1;
  }
  
  struct conversations *conv=NULL;
  if (meshms_conversations_list(&sid, NULL, &conv)){
    keyring_free(keyring);
    return -1;
  }  
  const char *names[]={
    "_id","recipient","read", "last_message", "read_offset"
  };

  cli_columns(context, 5, names);
  int rows = output_conversations(context, conv, 0, offset, count);
  cli_row_count(context, rows);

  free_conversations(conv);
  keyring_free(keyring);
  return 0;
}

int app_meshms_send_message(const struct cli_parsed *parsed, struct cli_context *context)
{
  const char *my_sidhex, *their_sidhex, *message;
  if (cli_arg(parsed, "sender_sid", &my_sidhex, str_is_subscriber_id, "") == -1
    || cli_arg(parsed, "recipient_sid", &their_sidhex, str_is_subscriber_id, "") == -1
    || cli_arg(parsed, "payload", &message, NULL, "") == -1)
    return -1;
  
  if (create_serval_instance_dir() == -1)
    return -1;
  if (!(keyring = keyring_open_instance_cli(parsed)))
    return -1;
  if (rhizome_opendb() == -1){
    keyring_free(keyring);
    return -1;
  }
  
  sid_t my_sid, their_sid;
  if (str_to_sid_t(&my_sid, my_sidhex) == -1)
    return WHY("invalid sender SID");
  if (str_to_sid_t(&their_sid, their_sidhex) == -1)
    return WHY("invalid recipient SID");
  struct conversations *conv = find_or_create_conv(&my_sid, &their_sid);
  if (!conv) {
    keyring_free(keyring);
    return -1;
  }  
  // construct a message payload
  int message_len = strlen(message)+1;
  
  // TODO, new format here.
  unsigned char buffer[message_len+3];
  strcpy((char*)buffer, message);  // message
  message_len+=append_footer(buffer+message_len, MESHMS_BLOCK_TYPE_MESSAGE, message_len);
  int ret = append_meshms_buffer(&my_sid, conv, buffer, message_len);
  
  free_conversations(conv);
  keyring_free(keyring);
  return ret;
}

int app_meshms_list_messages(const struct cli_parsed *parsed, struct cli_context *context)
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
    return -1;
  }    
  sid_t my_sid, their_sid;
  if (str_to_sid_t(&my_sid, my_sidhex) == -1){
    keyring_free(keyring);
    return WHY("invalid sender SID");
  }
  if (str_to_sid_t(&their_sid, their_sidhex) == -1){
    keyring_free(keyring);
    return WHY("invalid recipient SID");
  }  
  struct conversations *conv=find_or_create_conv(&my_sid, &their_sid);
  if (!conv){
    keyring_free(keyring);
    return -1;
  }
  int ret=-1;
  
  const char *names[]={
    "_id","offset","type","message"
  };

  cli_columns(context, 4, names);
  
  rhizome_manifest *m_ours=NULL, *m_theirs=NULL;
  struct ply_read read_ours, read_theirs;
  
  // if we've never sent a message, (or acked theirs), there is nothing to show
  if (!conv->found_my_ply){
    ret=0;
    cli_row_count(context, 0);
    if (config.debug.meshms)
      DEBUGF("Did not find my ply");
    goto end;
  }
  
  // start reading messages from both ply's in reverse order
  bzero(&read_ours, sizeof(read_ours));
  bzero(&read_theirs, sizeof(read_theirs));
  
  m_ours = rhizome_new_manifest();
  if (!m_ours)
    goto end;
  if (ply_read_open(&read_ours, &conv->my_ply.bundle_id, m_ours))
    goto end;
  
  uint64_t their_last_ack=0;
  uint64_t their_ack_offset=0;
  int64_t unread_mark=conv->read_offset;
  
  if (conv->found_their_ply){
    m_theirs = rhizome_new_manifest();
    if (!m_theirs)
      goto end;
    if (ply_read_open(&read_theirs, &conv->their_ply.bundle_id, m_theirs))
      goto end;
      
    // find their last ACK so we know if messages have been received
    int r = ply_find_next(&read_theirs, MESHMS_BLOCK_TYPE_ACK);
    if (r==0){
      if (unpack_uint(read_theirs.buffer, read_theirs.record_length, &their_last_ack) == -1)
	their_last_ack=0;
      else
	their_ack_offset = read_theirs.record_end_offset;
      if (config.debug.meshms)
	DEBUGF("Found their last ack @%"PRId64, their_last_ack);
    }
  }
  
  int id=0;
  while(ply_read_next(&read_ours)==0){
    if (config.debug.meshms)
      DEBUGF("Offset %"PRId64", type %d, read_offset %"PRId64, read_ours.read.offset, read_ours.type, conv->read_offset);
      
    if (their_last_ack && their_last_ack >= read_ours.record_end_offset){
      cli_put_long(context, id++, ":");
      cli_put_long(context, their_ack_offset, ":");
      cli_put_string(context, "ACK", ":");
      cli_put_string(context, "delivered", "\n");
      their_last_ack = 0;
    }
    
    switch(read_ours.type){
      case MESHMS_BLOCK_TYPE_ACK:
	// read their message list, and insert all messages that are included in the ack range
	if (conv->found_their_ply){
	  int ofs=unpack_uint(read_ours.buffer, read_ours.record_length, (uint64_t*)&read_theirs.read.offset);
	  if (ofs == -1)
	    break;
	  uint64_t end_range;
	  int x = unpack_uint(read_ours.buffer+ofs, read_ours.record_length - ofs, &end_range);
	  if (x == -1)
	    end_range=0;
	  else
	    end_range = read_theirs.read.offset - end_range;
	  
	  // TODO tail
	  // just incase we don't have the full bundle anymore
	  if (read_theirs.read.offset > read_theirs.read.length)
	    read_theirs.read.offset = read_theirs.read.length;
	    
	  if (config.debug.meshms)
	    DEBUGF("Reading other log from %"PRId64", to %"PRId64, read_theirs.read.offset, end_range);
	  while(ply_find_next(&read_theirs, MESHMS_BLOCK_TYPE_MESSAGE)==0){
	    if (read_theirs.read.offset < end_range)
	      break;
	      
	    if (unread_mark >= (int64_t)read_theirs.record_end_offset){
	      cli_put_long(context, id++, ":");
	      cli_put_long(context, unread_mark, ":");
	      cli_put_string(context, "MARK", ":");
	      cli_put_string(context, "read", "\n");
	      unread_mark = -1;
	    }
	  
	    cli_put_long(context, id++, ":");
	    cli_put_long(context, read_theirs.record_end_offset, ":");
	    cli_put_string(context, "<", ":");
	    cli_put_string(context, (char *)read_theirs.buffer, "\n");
	  }
	}
	break;
      case MESHMS_BLOCK_TYPE_MESSAGE:
	// TODO new message format here
	cli_put_long(context, id++, ":");
	cli_put_long(context, read_ours.record_end_offset, ":");
	cli_put_string(context, ">", ":");
	cli_put_string(context, (char *)read_ours.buffer, "\n");
	break;
    }
  }
  
  cli_row_count(context, id);
  ret=0;
  
end:
  if (m_ours){
    rhizome_manifest_free(m_ours);
    ply_read_close(&read_ours);
  }
  if (m_theirs){
    rhizome_manifest_free(m_theirs);
    ply_read_close(&read_theirs);
  }
  free_conversations(conv);
  keyring_free(keyring);
  return ret;
}

static int mark_read(struct conversations *conv, const sid_t *their_sid, const char *offset_str){
  int ret=0;
  if (conv){
    int cmp = their_sid ? cmp_sid_t(&conv->them, their_sid) : 0;
    if (!their_sid || cmp<0){
      ret+=mark_read(conv->_left, their_sid, offset_str);
    }
    if (!their_sid || cmp==0){
      // update read offset
      // - never rewind
      // - never past their last message
      uint64_t offset = conv->their_last_message;
      if (offset_str){
	uint64_t x = atol(offset_str);
	if (x<offset)
	  offset=x;
      }
      if (offset > conv->read_offset){
	if (config.debug.meshms)
	  DEBUGF("Moving read marker for %s, from %"PRId64" to %"PRId64, 
	    alloca_tohex_sid_t(conv->them), conv->read_offset, offset);
	conv->read_offset = offset;
	ret++;
      }
    }
    if (!their_sid || cmp>0){
      ret+=mark_read(conv->_right, their_sid, offset_str);
    }
  }
  return ret;
}

int app_meshms_mark_read(const struct cli_parsed *parsed, struct cli_context *context)
{
  const char *my_sidhex, *their_sidhex, *offset_str;
  if (cli_arg(parsed, "sender_sid", &my_sidhex, str_is_subscriber_id, "") == -1
    || cli_arg(parsed, "recipient_sid", &their_sidhex, str_is_subscriber_id, NULL) == -1
    || cli_arg(parsed, "offset", &offset_str, NULL, NULL)==-1)
   return -1;
  
  if (create_serval_instance_dir() == -1)
    return -1;
  if (!(keyring = keyring_open_instance_cli(parsed)))
    return -1;
  if (rhizome_opendb() == -1){
    keyring_free(keyring);
    return -1;
  }  
  sid_t my_sid, their_sid;
  fromhex(my_sid.binary, my_sidhex, sizeof(my_sid.binary));
  if (their_sidhex)
    fromhex(their_sid.binary, their_sidhex, sizeof(their_sid.binary));
  
  int ret=-1;
  struct conversations *conv=NULL;
  rhizome_manifest *m = rhizome_new_manifest();
  if (!m)
    goto end;
  if (get_my_conversation_bundle(&my_sid, m))
    goto end;
    
  // read all conversations, so we can write them again
  if (read_known_conversations(m, NULL, &conv))
    goto end;
  
  // read the full list of conversations from the database too
  if (get_database_conversations(&my_sid, NULL, &conv))
    goto end;
  
  // check if any incoming conversations need to be acked or have new messages and update the read offset
  int changed = update_conversations(&my_sid, conv);
  if (mark_read(conv, their_sidhex?&their_sid:NULL, offset_str))
    changed =1;
  if (changed){
    // save the conversation list
    if (write_known_conversations(m, conv))
      goto end;
  }
  
  ret=0;
  
end:
  if (m)
    rhizome_manifest_free(m);
  free_conversations(conv);
  keyring_free(keyring);
  return ret;
}
