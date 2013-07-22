#include "serval.h"
#include "rhizome.h"
#include "log.h"
#include "conf.h"

#define MESHMS_BLOCK_TYPE_ACK 0x01
#define MESHMS_BLOCK_TYPE_MESSAGE 0x02
#define MESHMS_BLOCK_TYPE_BID_REFERENCE 0x03

struct ply{
  char bundle_id[RHIZOME_MANIFEST_ID_STRLEN+1];
  uint64_t version;
  uint64_t tail;
  uint64_t size;
  
  uint64_t last_message;
  uint64_t last_ack;
  uint64_t last_ack_offset;
};

struct conversations{
  struct conversations *_left;
  struct conversations *_right;
  char them[SID_STRLEN+1];
  char found_my_ply;
  struct ply my_ply;
  char found_their_ply;
  struct ply their_ply;
};

struct ply_read{
  struct rhizome_read read;
  uint64_t record_end_offset;
  uint16_t record_length;
  int buffer_size;
  unsigned char *buffer;
};

static void free_conversations(struct conversations *conv){
  if (!conv)
    return;
  free_conversations(conv->_left);
  free_conversations(conv->_right);
  free(conv);
}

// find matching conversations
// if their_sid_hex == my_sid_hex, return all conversations with any recipient
static int meshms_conversations_list(const char *my_sid_hex, const char *their_sid_hex, struct conversations **conv){
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  sqlite3_stmt *statement = sqlite_prepare(&retry,
    "SELECT id, version, filesize, tail, sender, recipient "
    "FROM manifests "
    "WHERE service = 'MeshMS1' "
    "AND (sender=?1 or recipient=?1) "
    "AND (sender=?2 or recipient=?2)");
  if (!statement)
    return -1;
    
  int ret = sqlite3_bind_text(statement, 1, my_sid_hex, -1, SQLITE_STATIC);
  if (ret!=SQLITE_OK)
    goto end;

  ret = sqlite3_bind_text(statement, 2, their_sid_hex, -1, SQLITE_STATIC);
  if (ret!=SQLITE_OK)
    goto end;

  if (config.debug.meshms)
    DEBUGF("Looking for conversations for %s, %s", my_sid_hex, their_sid_hex);
  
  while (sqlite_step_retry(&retry, statement) == SQLITE_ROW) {
    const char *id = (const char *)sqlite3_column_text(statement, 0);
    long long version = sqlite3_column_int64(statement, 1);
    long long size = sqlite3_column_int64(statement, 2);
    long long tail = sqlite3_column_int64(statement, 3);
    const char *sender = (const char *)sqlite3_column_text(statement, 4);
    const char *recipient = (const char *)sqlite3_column_text(statement, 5);
    const char *them = recipient;
    
    if (strcasecmp(them, my_sid_hex)==0)
      them=sender;
    
    if (config.debug.meshms)
      DEBUGF("found id %s, sender %s, recipient %s", id, sender, recipient);
    
    struct conversations **ptr=conv;
    while(*ptr){
      int cmp = strcmp((*ptr)->them, them);
      if (cmp==0)
	break;
      if (cmp<0)
	ptr = &(*ptr)->_left;
      else
	ptr = &(*ptr)->_right;
    }
    if (!*ptr){
      *ptr = emalloc_zero(sizeof(struct conversations));
      strncpy((*ptr)->them, them, SID_STRLEN);
    }
    struct ply *p;
    if (them==sender){
      (*ptr)->found_their_ply=1;
      p=&(*ptr)->their_ply;
    }else{
      (*ptr)->found_my_ply=1;
      p=&(*ptr)->my_ply;
    }
    strncpy(p->bundle_id, id, RHIZOME_MANIFEST_ID_STRLEN+1);
    p->version = version;
    p->tail = tail;
    p->size = size;
  }
end:
  if (ret!=SQLITE_OK){
    WHYF("Query failed: %s", sqlite3_errmsg(rhizome_db));
    free_conversations(*conv);
    *conv=NULL;
  }
  sqlite3_finalize(statement);
  return (ret==SQLITE_OK)?0:-1;
}

static struct conversations * find_or_create_conv(const char *my_sid, const char *their_sid){
  struct conversations *conv=NULL;
  if (meshms_conversations_list(my_sid, their_sid, &conv))
    return NULL;
  if (!conv){
    conv = emalloc_zero(sizeof(struct conversations));
    strncpy(conv->them, their_sid, SID_STRLEN);
  }
  return conv;
}

static int create_ply(const char *my_sidhex, struct conversations *conv, rhizome_manifest *m){
  m->journalTail = 0;
  
  rhizome_manifest_set(m, "service", RHIZOME_SERVICE_MESHMS);
  rhizome_manifest_set(m, "sender", my_sidhex);
  rhizome_manifest_set(m, "recipient", conv->them);
  rhizome_manifest_set_ll(m, "tail", m->journalTail);
  
  sid_t authorSid;
  if (str_to_sid_t(&authorSid, my_sidhex)==-1)
    return -1;
  if (rhizome_fill_manifest(m, NULL, &authorSid, NULL))
    return -1;
  
  rhizome_manifest_get(m, "id", conv->my_ply.bundle_id, sizeof(conv->my_ply.bundle_id));
  conv->found_my_ply=1;
  return 0;
}

static int ply_read_open(struct ply_read *ply, const char *id, rhizome_manifest *m){
  if (rhizome_retrieve_manifest(id, m))
    return -1;
  if (rhizome_open_decrypt_read(m, NULL, &ply->read, 0))
    return -1;
  ply->read.offset = ply->read.length = m->fileLength;
  return 0;
}

static int ply_read_close(struct ply_read *ply){
  if (ply->buffer){
    free(ply->buffer);
    ply->buffer=NULL;
  }
  return rhizome_read_close(&ply->read);
}

// read the next record from the ply (backwards)
// returns 1 on EOF, -1 on failure
static int ply_read_next(struct ply_read *ply){
  // TODO read in RHIZOME_CRYPT_PAGE_SIZE blocks, aligned to boundaries
  if (config.debug.meshms)
    DEBUGF("Attempting to read next record ending @%"PRId64,ply->read.offset);
  ply->record_end_offset=ply->read.offset;
  ply->read.offset-=2;
  if (ply->read.offset<=0)
    return 1;
  unsigned char offset[2];
  if (rhizome_read(&ply->read, offset, sizeof(offset))!=2)
    return -1;
  // (rhizome_read automatically advances the offset by the number of bytes read)
  
  ply->record_length=read_uint16(offset);
  if (config.debug.meshms)
    DEBUGF("Found record length %d", ply->record_length);
  
  // need to allow for advancing the tail and cutting a message in half.
  if (ply->record_length > ply->read.offset-2)
    return 1;
    
  uint64_t record_start = ply->read.offset -= ply->record_length + 5;
  if (ply->buffer_size < ply->record_length +3){
    ply->buffer_size = ply->record_length +3;
    unsigned char *b=realloc(ply->buffer, ply->buffer_size);
    if (!b)
      return WHY("realloc() failed");
    ply->buffer = b;
  }
  
  if (rhizome_read(&ply->read, ply->buffer, ply->record_length +3)!=ply->record_length +3)
    return -1;
  
  uint16_t length_check = read_uint16(ply->buffer);
  if (length_check != ply->record_length)
    return WHYF("Length check failed, expected %u found %u @%"PRId64, 
      ply->record_length, length_check, record_start);
  ply->read.offset = record_start;
  return 0;
}

static int ply_find_next(struct ply_read *ply, char type){
  while(1){
    int ret = ply_read_next(ply);
    if (ret)
      return ret;
    if (ply->buffer[2]==type)
      return 0;
  }
}

static int append_meshms_buffer(const char *my_sidhex, struct conversations *conv, unsigned char *buffer, int len){
  int ret=-1;
  rhizome_manifest *mout = NULL;
  rhizome_manifest *m = rhizome_new_manifest();
  if (!m)
    goto end;
  
  if (conv->found_my_ply){
    if (rhizome_retrieve_manifest(conv->my_ply.bundle_id, m))
      goto end;
    if (rhizome_find_bundle_author(m))
      goto end;
  }else{
    if (create_ply(my_sidhex, conv, m))
      goto end;
  }
  
  if (rhizome_append_journal_buffer(m, NULL, 0, buffer, len))
    goto end;
  
  if (rhizome_manifest_finalise(m,&mout))
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
static int update_conversation(const char *my_sidhex, struct conversations *conv){
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
  if (rhizome_retrieve_manifest(conv->their_ply.bundle_id, m_theirs))
    goto end;
  
  if (ply_read_open(&ply, conv->their_ply.bundle_id, m_theirs))
    goto end;
    
  ret = ply_find_next(&ply, MESHMS_BLOCK_TYPE_MESSAGE);
  if (ret!=0)
    goto end;
  
  uint64_t last_message_offset = ply.record_end_offset;
  if (config.debug.meshms)
    DEBUGF("Found last message @%"PRId64, last_message_offset);
  ply_read_close(&ply);
  
  // find our last ack
  uint64_t last_ack = 0;
  
  if (conv->found_my_ply){
    if (config.debug.meshms)
      DEBUG("Locating our last ack");
      
    m_ours = rhizome_new_manifest();
    if (!m_ours)
      goto end;
    if (rhizome_retrieve_manifest(conv->my_ply.bundle_id, m_ours))
      goto end;
    
    if (ply_read_open(&ply, conv->my_ply.bundle_id, m_ours))
      goto end;
      
    ret = ply_find_next(&ply, MESHMS_BLOCK_TYPE_ACK);
    if (ret<0)
      goto end;
    if (ret==0){
      last_ack = read_uint64(&ply.buffer[3]);
      if (config.debug.meshms)
	DEBUGF("Found last ack for %"PRId64, last_ack);
    }
    ply_read_close(&ply);
  }else{
    if (config.debug.meshms)
      DEBUGF("No outgoing ply");
  }
  
  if (last_ack >= last_message_offset){
    // their last message has already been acked
    ret=0;
    goto end;
  }
  
  // append an ack for their message
  // TODO shorter format here?
  if (config.debug.meshms)
    DEBUGF("Creating ACK for %"PRId64" - %"PRId64, last_ack, last_message_offset);
  unsigned char buffer[5+8+8];
  int ofs=2;
  buffer[ofs++]=MESHMS_BLOCK_TYPE_ACK;
  write_uint64(&buffer[ofs], last_message_offset);
  ofs+=8;
  write_uint64(&buffer[ofs], last_ack);
  ofs+=8;
  write_uint16(&buffer[0], ofs - 3);
  write_uint16(&buffer[ofs], ofs - 3);
  ofs+=2;
  ret = append_meshms_buffer(my_sidhex, conv, buffer, ofs);
  
end:
  ply_read_close(&ply);
  if (m_ours)
    rhizome_manifest_free(m_ours);
  if (m_theirs)
    rhizome_manifest_free(m_theirs);
  return ret;
}

// check if any conversations have changed
static int update_conversations(const char *my_sidhex, struct conversations *conv){
  if (!conv)
    return 0;
  update_conversations(my_sidhex, conv->_left);
  update_conversation(my_sidhex, conv);
  update_conversations(my_sidhex, conv->_right);
  return 0;
}

// recursively traverse the conversation tree in sorted order and output the details of each conversation
static int output_conversations(struct cli_context *context, struct conversations *conv, 
      int output, int offset, int count){
  if (!conv)
    return 0;
  
  int traverse_count = output_conversations(context, conv->_left, output, offset, count);
  if (count <0 || output + traverse_count < offset + count){
    if (output + traverse_count >= offset){
      cli_put_string(context, conv->them, ":");
      cli_put_string(context, "read", ":");// TODO
      cli_put_string(context, "delivered", "\n");// TODO
    }
    traverse_count++;
  }
  if (count <0 || output + traverse_count < offset + count){
    traverse_count += output_conversations(context, conv->_right, output + traverse_count, offset, count);
  }
  return traverse_count;
}

// output the list of existing conversations for a given local identity
int app_meshms_conversations(const struct cli_parsed *parsed, struct cli_context *context){
  const char *sidhex, *offset_str, *count_str;
  if (cli_arg(parsed, "sid", &sidhex, str_is_subscriber_id, "") == -1
    || cli_arg(parsed, "offset", &offset_str, NULL, "0")==-1
    || cli_arg(parsed, "count", &count_str, NULL, "-1")==-1)
    return -1;
    
  int offset=atoi(offset_str);
  int count=atoi(count_str);

  if (create_serval_instance_dir() == -1)
    return -1;
  if (!(keyring = keyring_open_instance_cli(parsed)))
    return -1;
  if (rhizome_opendb() == -1)
    return -1;
  
  struct conversations *conv=NULL;
  if (meshms_conversations_list(sidhex, sidhex, &conv))
    return -1;
  
  //TODO, when we are tracking read state
  //update_conversations(my_sidhex, conv);
  
  const char *names[]={
    "sid","read","delivered"
  };

  cli_columns(context, 3, names);
  output_conversations(context, conv, 0, offset, count);
  free_conversations(conv);
  return 0;
}

int app_meshms_send_message(const struct cli_parsed *parsed, struct cli_context *context){
  const char *my_sidhex, *their_sidhex, *message;
  if (cli_arg(parsed, "sender_sid", &my_sidhex, str_is_subscriber_id, "") == -1
    || cli_arg(parsed, "recipient_sid", &their_sidhex, str_is_subscriber_id, "") == -1
    || cli_arg(parsed, "payload", &message, NULL, "") == -1)
    return -1;
  
  if (create_serval_instance_dir() == -1)
    return -1;
  if (!(keyring = keyring_open_instance_cli(parsed)))
    return -1;
  if (rhizome_opendb() == -1)
    return -1;
    
  struct conversations *conv=find_or_create_conv(my_sidhex, their_sidhex);
  if (!conv)
    return -1;
  
  // construct a message payload
  int message_len = strlen(message)+1;
  
  // TODO, new format here.
  unsigned char buffer[message_len+13];
  int ofs=2;
  buffer[ofs++]=MESHMS_BLOCK_TYPE_MESSAGE;
  write_uint64(&buffer[ofs], 0);//timestamp
  ofs+=8;
  strcpy((char*)&buffer[ofs], message);  // message
  ofs+=message_len;
  write_uint16(&buffer[0], ofs - 3);
  write_uint16(&buffer[ofs], ofs - 3);
  ofs+=2;
  int ret = append_meshms_buffer(my_sidhex, conv, buffer, ofs);
  
  free_conversations(conv);
  return ret;
}

int app_meshms_list_messages(const struct cli_parsed *parsed, struct cli_context *context){
  const char *my_sidhex, *their_sidhex;
  if (cli_arg(parsed, "sender_sid", &my_sidhex, str_is_subscriber_id, "") == -1
    || cli_arg(parsed, "recipient_sid", &their_sidhex, str_is_subscriber_id, "") == -1)
    return -1;
  
  if (create_serval_instance_dir() == -1)
    return -1;
  if (!(keyring = keyring_open_instance_cli(parsed)))
    return -1;
  if (rhizome_opendb() == -1)
    return -1;
    
  struct conversations *conv=find_or_create_conv(my_sidhex, their_sidhex);
  if (!conv)
    return -1;
  
  update_conversation(my_sidhex, conv);
  
  int ret=-1;
  
  const char *names[]={
    "_id","offset","sender","status","message"
  };

  cli_columns(context, 5, names);
  
  // if we've never sent a message, (or acked theirs), there is nothing to show
  if (!conv->found_my_ply){
    ret=0;
    goto end;
  }
  
  // start reading messages from both ply's in reverse order
  rhizome_manifest *m_ours=NULL, *m_theirs=NULL;
  struct ply_read read_ours, read_theirs;
  bzero(&read_ours, sizeof(read_ours));
  bzero(&read_theirs, sizeof(read_theirs));
  
  if (conv->found_my_ply){
    rhizome_manifest *m_ours = rhizome_new_manifest();
    if (!m_ours)
      goto end;
    if (ply_read_open(&read_ours, conv->my_ply.bundle_id, m_ours))
      goto end;
  }
  
  uint64_t their_last_ack=0;
  
  if (conv->found_their_ply){
    rhizome_manifest *m_theirs = rhizome_new_manifest();
    if (!m_theirs)
      goto end;
    if (ply_read_open(&read_theirs, conv->their_ply.bundle_id, m_theirs))
      goto end;
      
    // find their last ACK so we know if messages have been received
    int r = ply_find_next(&read_theirs, MESHMS_BLOCK_TYPE_ACK);
    if (r==0)
      their_last_ack = read_uint64(&read_theirs.buffer[3]);
  }
  
  int id=0;
  while(ply_read_next(&read_ours)==0){
    char type = read_ours.buffer[2];
    if (config.debug.meshms)
      DEBUGF("%"PRId64", found %d", read_ours.read.offset, type);
    switch(type){
      case MESHMS_BLOCK_TYPE_ACK:
	// read their message list, and insert all messages that are included in the ack range
	if (conv->found_their_ply){
	  read_theirs.read.offset = read_uint64(&read_ours.buffer[3]);
	  // TODO tail
	  // just incase we don't have the full bundle anymore
	  if (read_theirs.read.offset > read_theirs.read.length)
	    read_theirs.read.offset = read_theirs.read.length;
	  uint64_t end_range = read_uint64(&read_ours.buffer[3+8]);
	  while(ply_find_next(&read_theirs, MESHMS_BLOCK_TYPE_MESSAGE)==0){
	    if (read_theirs.read.offset < end_range)
	      break;
	    cli_put_long(context, id++, ":");
	    cli_put_long(context, read_theirs.read.offset, ":");
	    cli_put_string(context, their_sidhex, ":");
	    cli_put_string(context, "read", ":");
	    cli_put_string(context, (char *)&read_theirs.buffer[11], "\n");
	  }
	}
	break;
      case MESHMS_BLOCK_TYPE_MESSAGE:
	// TODO new message format here
	cli_put_long(context, id++, ":");
	cli_put_long(context, read_ours.read.offset, ":");
	cli_put_string(context, my_sidhex, ":");
	cli_put_string(context, their_last_ack >= read_ours.record_end_offset ? "delivered":"", ":");
	cli_put_string(context, (char *)&read_ours.buffer[11], "\n");
	break;
    }
  }
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
  return ret;
}