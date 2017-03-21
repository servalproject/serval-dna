#include "serval.h"
#include "serval_types.h"
#include "dataformats.h"
#include "log.h"
#include "debug.h"
#include "conf.h"
#include "overlay_buffer.h"
#include "keyring.h"
#include "crypto.h"
#include "mem.h"
#include "meshmb.h"

struct feed_metadata{
  size_t tree_depth;
  struct message_ply ply; // (ply starts with a rhizome_bid_t, so this is consistent with a nibble tree)
  struct meshmb_feed_details details;
  // what is the offset of their last message
  uint64_t last_message_offset;
  // what is the last message we processed?
  uint64_t last_seen;
  // our cached value for the last known size of their ply
  uint64_t size;
};

struct meshmb_feeds{
  struct tree_root root;
  keyring_identity *id;
  sign_keypair_t bundle_keypair;
  sign_keypair_t ack_bundle_keypair;
  rhizome_manifest *ack_manifest;
  struct rhizome_write ack_writer;
  bool_t dirty;
  uint8_t generation;
};

struct meshmb_activity_iterator *meshmb_activity_open(struct meshmb_feeds *feeds){
  struct meshmb_activity_iterator *ret = emalloc_zero(sizeof(struct meshmb_activity_iterator));
  if (!ret)
    return NULL;

  ret->feeds = feeds;
  if (message_ply_read_open(&ret->ack_reader, NULL, &feeds->ack_bundle_keypair)==-1){
    free(ret);
    ret = NULL;
  }

  return ret;
}

static int activity_next_ack(struct meshmb_activity_iterator *i){
  while(1){
    // read the next ack
    if (message_ply_read_prev(&i->ack_reader)==-1)
      return 0;

    switch (i->ack_reader.type) {
      case MESSAGE_BLOCK_TYPE_TIME:
	message_ply_parse_timestamp(&i->ack_reader, &i->ack_timestamp);
	continue;

      case MESSAGE_BLOCK_TYPE_ACK:{
	struct message_ply_ack ack;
	if (message_ply_parse_ack(&i->ack_reader, &ack) == -1)
	  return -1;

	DEBUGF(meshmb, "Found ack for %s, %u to %u",
	  alloca_tohex(ack.binary, ack.binary_length), ack.start_offset, ack.end_offset);

	struct feed_metadata *metadata;
	if (tree_find(&i->feeds->root, (void**)&metadata, ack.binary, ack.binary_length, NULL, NULL)==TREE_FOUND){
	  if (i->metadata == metadata){
	    // shortcut for consecutive acks for the same incoming feed
	    DEBUGF(meshmb, "Ply still open @%u",
	      i->msg_reader.read.offset);
	  }else{
	    message_ply_read_close(&i->msg_reader);
	    if (message_ply_read_open(&i->msg_reader, &metadata->ply.bundle_id, NULL)==-1){
	      i->metadata = NULL;
	      continue;
	    }
	    i->metadata = metadata;
	  }
	}

	i->ack_start = ack.start_offset;
	i->msg_reader.read.offset = ack.end_offset;
	return 1;

      } break;

      default:
	continue;
    }
  }
}

int meshmb_activity_seek(struct meshmb_activity_iterator *i, uint64_t ack_offset, uint64_t msg_offset){
  if (ack_offset)
    i->ack_reader.read.offset = ack_offset;
  int r;
  if ((r = activity_next_ack(i))!=1)
    return r;
  if (msg_offset){
    if (msg_offset > i->msg_reader.read.offset || msg_offset < i->ack_start)
      return -1;
    i->msg_reader.read.offset = msg_offset;
  }
  return meshmb_activity_next(i);
}

int meshmb_activity_next(struct meshmb_activity_iterator *i){
  while(1){
    // can we read another message?
    if (message_ply_is_open(&i->msg_reader)
      && i->msg_reader.read.offset > i->ack_start){
      DEBUGF(meshmb, "Reading next incoming record from %u",
	i->msg_reader.read.offset);
      if (message_ply_read_prev(&i->msg_reader)!=-1
      && i->msg_reader.read.offset >= i->ack_start)
	return 1;
    }
    int r;
    if ((r = activity_next_ack(i))!=1)
      return r;
  }
}

void meshmb_activity_close(struct meshmb_activity_iterator *i){
  message_ply_read_close(&i->ack_reader);
  message_ply_read_close(&i->msg_reader);
  free(i);
}


// only remember this many bytes of ply names & last messages
#define MAX_NAME_LEN (256)  // ??
#define MAX_MSG_LEN (256)  // ??

static int finish_ack_writing(struct meshmb_feeds *feeds){
  if (!feeds->ack_manifest)
    return 0;

  int ret;

  DEBUGF(meshmb, "Completing private ply for ack thread");
  {
    struct overlay_buffer *b = ob_new();
    message_ply_append_timestamp(b);
    ret = rhizome_write_buffer(&feeds->ack_writer, ob_ptr(b), ob_position(b));
    ob_free(b);
  }

  if (ret==0){
    ret =-1;
    enum rhizome_payload_status status = rhizome_finish_write(&feeds->ack_writer);
    status = rhizome_finish_store(&feeds->ack_writer, feeds->ack_manifest, status);

    if (status == RHIZOME_PAYLOAD_STATUS_NEW){
      rhizome_manifest *mout=NULL;
      struct rhizome_bundle_result result = rhizome_manifest_finalise(feeds->ack_manifest, &mout, 0);
      if (mout && mout!=feeds->ack_manifest)
	rhizome_manifest_free(mout);

      if (result.status == RHIZOME_BUNDLE_STATUS_NEW)
	ret = 0;
      rhizome_bundle_result_free(&result);
    }
  }

  if (ret!=0)
    rhizome_fail_write(&feeds->ack_writer);
  bzero(&feeds->ack_writer, sizeof feeds->ack_writer);

  rhizome_manifest_free(feeds->ack_manifest);
  feeds->ack_manifest = NULL;
  return ret;
}

static int update_stats(struct meshmb_feeds *feeds, struct feed_metadata *metadata, struct message_ply_read *reader)
{
  if (!metadata->ply.found){
    // get the current size from the db
    sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
    if (sqlite_exec_uint64_retry(&retry, &metadata->ply.size,
      "SELECT filesize FROM manifests WHERE id = ?",
      RHIZOME_BID_T, &metadata->ply.bundle_id,
      END) == SQLITE_ROW)
	metadata->ply.found = 1;
    else
      return -1;
  }

  DEBUGF(meshmb, "Size from %u to %u", metadata->size, metadata->ply.size);
  if (metadata->size == metadata->ply.size)
    return 0;

  if (!message_ply_is_open(reader)
    && message_ply_read_open(reader, &metadata->ply.bundle_id, NULL)!=0)
    return -1;

  // TODO allow the user to specify an overridden name?
  if (metadata->details.name){
    free((void*)metadata->details.name);
    metadata->details.name = NULL;
  }
  metadata->details.author = reader->author;

  if (reader->name){
    size_t len = strlen(reader->name);
    if (len >= MAX_NAME_LEN)
      len = MAX_NAME_LEN -1;
    metadata->details.name = strn_edup(reader->name, len);
  }

  reader->read.offset = reader->read.length;
  time_s_t timestamp = 0;
  uint64_t last_offset = metadata->last_message_offset;

  while (message_ply_read_prev(reader) == 0){
    if (reader->record_end_offset <= metadata->size)
      break;
    if (reader->type == MESSAGE_BLOCK_TYPE_TIME){
      if (message_ply_parse_timestamp(reader, &timestamp)!=0){
	WARN("Malformed ply, expected timestamp");
	continue;
      }

    }else if(reader->type == MESSAGE_BLOCK_TYPE_MESSAGE){
      if (metadata->last_message_offset == reader->record_end_offset)
	break;

      last_offset = reader->record_end_offset;

      if (metadata->details.last_message)
	free((void*)metadata->details.last_message);
      size_t len = reader->record_length;
      if (len >= MAX_MSG_LEN)
	len = MAX_MSG_LEN -1;
      metadata->details.last_message = strn_edup((const char *)reader->record, len);
      metadata->details.timestamp = timestamp;
      break;
    }
  }

  DEBUGF(meshmb, "Last message from %u to %u", metadata->last_message_offset, last_offset);
  if (last_offset > metadata->last_message_offset){
    // add an ack to our journal to thread new messages
    if (!feeds->ack_manifest){
      rhizome_manifest *m = rhizome_new_manifest();

      DEBUGF(meshmb, "Opening private ply for ack thread");

      struct rhizome_bundle_result result = rhizome_private_bundle(m, &feeds->ack_bundle_keypair);
      switch(result.status){
	case RHIZOME_BUNDLE_STATUS_NEW:
	  rhizome_manifest_set_tail(m, 0);
	  rhizome_manifest_set_filesize(m, 0);
	case RHIZOME_BUNDLE_STATUS_SAME:
	{
	  enum rhizome_payload_status pstatus = rhizome_write_open_journal(&feeds->ack_writer, m, 0, RHIZOME_SIZE_UNSET);
	  if (pstatus==RHIZOME_PAYLOAD_STATUS_NEW)
	    break;
	}
	  // fallthrough
	case RHIZOME_BUNDLE_STATUS_BUSY:
	  rhizome_bundle_result_free(&result);
	  rhizome_manifest_free(m);
	  return -1;

	default:
	  // everything else should be impossible.
	  FATALF("Cannot create manifest: %s", alloca_rhizome_bundle_result(result));
      }

      rhizome_bundle_result_free(&result);
      feeds->ack_manifest = m;
    }

    {
      struct overlay_buffer *b = ob_new();

      struct message_ply_ack ack;
      bzero(&ack, sizeof ack);

      ack.start_offset = metadata->size;
      ack.end_offset = metadata->ply.size;
      ack.binary = metadata->ply.bundle_id.binary;
      ack.binary_length = (metadata->tree_depth >> 3) + 3;

      message_ply_append_ack(b, &ack);
      int r = rhizome_write_buffer(&feeds->ack_writer, ob_ptr(b), ob_position(b));
      DEBUGF(meshmb, "Acked incoming messages");
      ob_free(b);
      if (r == -1)
	return -1;
    }
  }

  metadata->last_message_offset = last_offset;
  metadata->size = metadata->ply.size;

  feeds->dirty=1;
  return 1;
}

// TODO, might be quicker to fetch all meshmb bundles and test if they are in the feed list
static int update_stats_tree(void **record, void *context)
{
  struct feed_metadata *metadata = (struct feed_metadata *)*record;
  struct meshmb_feeds *feeds = (struct meshmb_feeds *)context;
  struct message_ply_read reader;
  bzero(&reader, sizeof(reader));
  update_stats(feeds, metadata, &reader);
  message_ply_read_close(&reader);
  return 0;
}

// eg, if a bundle_add trigger occurs while the feed list is open
int meshmb_bundle_update(struct meshmb_feeds *feeds, rhizome_manifest *m, struct message_ply_read *reader)
{
  struct feed_metadata *metadata;
  if (strcmp(m->service, RHIZOME_SERVICE_MESHMB) == 0
    && tree_find(&feeds->root, (void**)&metadata, m->keypair.public_key.binary, sizeof m->keypair.public_key.binary, NULL, NULL)==0){

    metadata->ply.found = 1;
    if (metadata->ply.size != m->filesize){
      metadata->ply.size = m->filesize;
      if (update_stats(feeds, metadata, reader)==-1)
	return -1;
    }
    return 1;
  }
  return 0;
}

int meshmb_update(struct meshmb_feeds *feeds)
{
  return tree_walk(&feeds->root, NULL, 0, update_stats_tree, feeds);
}

static int write_metadata(void **record, void *context)
{
  struct feed_metadata *metadata = (struct feed_metadata *)*record;
  struct rhizome_write *write = (struct rhizome_write *)context;

  assert(metadata->size >= metadata->last_message_offset);
  assert(metadata->size >= metadata->last_seen);
  unsigned name_len = (metadata->details.name ? strlen(metadata->details.name) : 0) + 1;
  assert(name_len <= MAX_NAME_LEN);
  unsigned msg_len = (metadata->details.last_message ? strlen(metadata->details.last_message) : 0) + 1;
  assert(msg_len <= MAX_MSG_LEN);

  uint8_t buffer[sizeof (rhizome_bid_t) + sizeof (sid_t) + 1 + 12*4 + name_len + msg_len];
  size_t len = 0;
  bcopy(metadata->ply.bundle_id.binary, &buffer[len], sizeof (rhizome_bid_t));
  len += sizeof (rhizome_bid_t);
  bcopy(metadata->details.author.binary, &buffer[len], sizeof (sid_t));
  len += sizeof (sid_t);
  buffer[len++]=0;// flags?
  len+=pack_uint(&buffer[len], metadata->size);
  len+=pack_uint(&buffer[len], metadata->size - metadata->last_message_offset);
  len+=pack_uint(&buffer[len], metadata->size - metadata->last_seen);
  len+=pack_uint(&buffer[len], metadata->details.timestamp);
  if (name_len > 1)
    strncpy_nul((char *)&buffer[len], metadata->details.name, name_len);
  else
    buffer[len]=0;
  len+=name_len;
  if (msg_len > 1)
    strncpy_nul((char *)&buffer[len], metadata->details.last_message, msg_len);
  else
    buffer[len]=0;
  len+=msg_len;
  assert(len < sizeof buffer);
  DEBUGF(meshmb, "Write %u bytes of metadata for %s/%s",
    len,
    alloca_tohex_rhizome_bid_t(metadata->ply.bundle_id),
    alloca_tohex_sid_t(metadata->details.author)
  );
  return rhizome_write_buffer(write, buffer, len);
}

#define CURRENT_VERSION 0

int meshmb_flush(struct meshmb_feeds *feeds)
{
  finish_ack_writing(feeds);

  if (!feeds->dirty){
    DEBUGF(meshmb, "Ignoring flush, not dirty");
    return feeds->generation;
  }

  rhizome_manifest *mout = NULL;
  rhizome_manifest *m = rhizome_new_manifest();
  if (!m)
    return -1;

  int ret =-1;
  struct rhizome_bundle_result result = rhizome_private_bundle(m, &feeds->bundle_keypair);

  switch(result.status){
    case RHIZOME_BUNDLE_STATUS_SAME:
      rhizome_manifest_set_version(m, m->version + 1);
      rhizome_manifest_set_filesize(m, RHIZOME_SIZE_UNSET);
      rhizome_manifest_set_filehash(m, NULL);
      // fallthrough
    case RHIZOME_BUNDLE_STATUS_NEW:
    {
      struct rhizome_write write;
      bzero(&write, sizeof(write));

      enum rhizome_payload_status pstatus = rhizome_write_open_manifest(&write, m);
      if (pstatus==RHIZOME_PAYLOAD_STATUS_NEW){
	uint8_t version = CURRENT_VERSION;
	rhizome_write_buffer(&write, &version, 1);

	if (tree_walk(&feeds->root, NULL, 0, write_metadata, &write)==0){
	  pstatus = rhizome_finish_write(&write);
	  if (pstatus == RHIZOME_PAYLOAD_STATUS_NEW){

	    rhizome_manifest_set_filehash(m, &write.id);
	    rhizome_manifest_set_filesize(m, write.file_length);
	    struct rhizome_bundle_result result = rhizome_manifest_finalise(m, &mout, 1);
	    if (result.status == RHIZOME_BUNDLE_STATUS_NEW){
	      ret = ++feeds->generation;
	      feeds->dirty = 0;
	    }
	    rhizome_bundle_result_free(&result);
	  }
	}
      }
      if (ret==-1)
	rhizome_fail_write(&write);
      break;
    }
    default:
      break;
  }

  rhizome_manifest_free(m);
  return ret;
}

static int free_feed(void **record, void *context)
{
  struct meshmb_feeds *feeds = (struct meshmb_feeds *)context;
  struct feed_metadata *f = *record;
  if (f->details.name)
    free((void *)f->details.name);
  if (f->details.last_message)
    free((void *)f->details.last_message);
  free(f);
  DEBUGF(meshmb, "free feed");
  *record = NULL;
  feeds->dirty = 1;
  return 0;
}

void meshmb_close(struct meshmb_feeds *feeds)
{
  tree_walk(&feeds->root, NULL, 0, free_feed, feeds);
  free(feeds);
}

static void* alloc_feed(void *context, const uint8_t *binary, size_t UNUSED(bin_length))
{
  struct meshmb_feeds *feeds = (struct meshmb_feeds *)context;
  struct feed_metadata *feed = emalloc_zero(sizeof(struct feed_metadata));
  if (feed){
    feed->ply.bundle_id = *(rhizome_bid_t *)binary;
    feeds->dirty = 1;
    DEBUGF(meshmb, "Allocated feed");
  }
  return feed;
}

static int read_metadata(struct meshmb_feeds *feeds, struct rhizome_read *read)
{
  struct rhizome_read_buffer buff;
  bzero(&buff, sizeof(buff));
  uint8_t buffer[sizeof (rhizome_bid_t) + sizeof (sid_t) + 12*3 + MAX_NAME_LEN + MAX_MSG_LEN];

  uint8_t version=0xFF;
  if (rhizome_read_buffered(read, &buff, &version, 1)==-1)
    return -1;

  if (version > CURRENT_VERSION)
    return WHYF("Unknown file format version (got 0x%02x)", version);

  while(1){
    ssize_t bytes = rhizome_read_buffered(read, &buff, buffer, sizeof buffer);
    if (bytes==0)
      break;

    uint64_t delta=0;
    uint64_t size;
    uint64_t last_message_offset;
    uint64_t last_seen;
    uint64_t timestamp;

    int unpacked;
    const rhizome_bid_t *bid = (const rhizome_bid_t *)&buffer[0];
    unsigned offset = sizeof(rhizome_bid_t);
    if (offset >= (unsigned)bytes)
      goto error;

    const sid_t *author = (const sid_t *)&buffer[offset];
    offset+= sizeof(sid_t);
    if (offset >= (unsigned)bytes)
      goto error;

    //uint8_t flags = buffer[offset++];
    offset++;
    if (offset >= (unsigned)bytes)
      goto error;

    if ((unpacked = unpack_uint(buffer+offset, bytes-offset, &size)) == -1)
      goto error;
    offset += unpacked;

    if ((unpacked = unpack_uint(buffer+offset, bytes-offset, &delta)) == -1)
      goto error;
    offset += unpacked;
    last_message_offset = size - delta;

    if ((unpacked = unpack_uint(buffer+offset, bytes-offset, &delta)) == -1)
      goto error;
    offset += unpacked;
    last_seen = size - delta;

    if ((unpacked = unpack_uint(buffer+offset, bytes-offset, &timestamp)) == -1)
      goto error;
    offset += unpacked;

    const char *name = (const char *)&buffer[offset];
    while(buffer[offset++]){
      if (offset >= (unsigned)bytes)
	goto error;
    }

    const char *msg = (const char *)&buffer[offset];
    while(buffer[offset++]){
      if (offset >= (unsigned)bytes)
	goto error;
    }

    read->offset += offset - bytes;
    struct feed_metadata *result;
    if (tree_find(&feeds->root, (void**)&result, bid->binary, sizeof *bid, alloc_feed, feeds)<0)
      return WHY("Failed to allocate metadata");

    result->last_message_offset = last_message_offset;
    result->last_seen = last_seen;
    result->size = size;
    result->details.bundle_id = *bid;
    result->details.author = *author;
    result->details.name = (name && *name) ? str_edup(name) : NULL;
    result->details.last_message = (msg && *msg) ? str_edup(msg) : NULL;
    result->details.timestamp = timestamp;

    DEBUGF(meshmb, "Processed %u bytes of metadata for %s",
      offset,
      alloca_tohex_rhizome_bid_t(result->ply.bundle_id),
      alloca_tohex_sid_t(result->details.author)
    );
  }
  feeds->dirty = 0;
  return 0;

error:
  return WHY("Buffer overflow while parsing metadata");
}

int meshmb_open(keyring_identity *id, struct meshmb_feeds **feeds)
{
  int ret = -1;

  *feeds = emalloc_zero(sizeof(struct meshmb_feeds));
  if (*feeds){
    (*feeds)->root.binary_length = sizeof(rhizome_bid_t);
    (*feeds)->id = id;
    rhizome_manifest *m = rhizome_new_manifest();
    if (m){
      // deterministic bundle id's for storing active follow / ignore state;
      crypto_seed_keypair(&(*feeds)->bundle_keypair,
	"91656c3d62e9fe2678a1a81fabe3f413%s5a37120ca55d911634560e4d4dc1283f",
	alloca_tohex(id->sign_keypair->private_key.binary, sizeof id->sign_keypair->private_key));

      // and for threading incoming feed messages;
      crypto_seed_keypair(&(*feeds)->ack_bundle_keypair,
	"de3f2e21d9735d41b1fd7ddf03a58f2b%s937a440c12f9478d026bbf579ab115c0",
	alloca_tohex(id->sign_keypair->private_key.binary, sizeof id->sign_keypair->private_key));

      struct rhizome_bundle_result result = rhizome_private_bundle(m, &(*feeds)->bundle_keypair);
      DEBUGF(meshmb, "Private bundle %s, %s",
	alloca_tohex_identity_t(&(*feeds)->bundle_keypair.public_key),
	alloca_rhizome_bundle_result(result));
      switch(result.status){
	case RHIZOME_BUNDLE_STATUS_SAME:{
	  struct rhizome_read read;
	  bzero(&read, sizeof(read));

	  enum rhizome_payload_status pstatus = rhizome_open_decrypt_read(m, &read);
	  if (pstatus == RHIZOME_PAYLOAD_STATUS_STORED){
	    if (read_metadata(*feeds, &read)==-1)
	      WHYF("Failed to read metadata");
	    else
	      ret = 0;
	  }else
	    WHYF("Failed to read metadata: %s", rhizome_payload_status_message(pstatus));

	  rhizome_read_close(&read);
	}break;

	case RHIZOME_BUNDLE_STATUS_NEW:
	  ret = 0;
	  break;

	case RHIZOME_BUNDLE_STATUS_BUSY:
	  break;

	default:
	  // everything else should be impossible.
	  FATALF("Cannot create manifest: %s", alloca_rhizome_bundle_result(result));
      }

      rhizome_bundle_result_free(&result);
    }

    rhizome_manifest_free(m);
  }

  if (ret!=0){
    meshmb_close(*feeds);
    *feeds=NULL;
  }
  return ret;
}

int meshmb_follow(struct meshmb_feeds *feeds, rhizome_bid_t *bid)
{
  struct feed_metadata *metadata;
  DEBUGF(meshmb, "Attempting to follow %s", alloca_tohex_rhizome_bid_t(*bid));

  // TODO load the manifest and check the service!

  if (tree_find(&feeds->root, (void**)&metadata, bid->binary, sizeof *bid, alloc_feed, feeds)!=TREE_FOUND)
    return WHYF("Failed to follow feed");

  struct message_ply_read reader;
  bzero(&reader, sizeof(reader));
  update_stats(feeds, metadata, &reader);
  message_ply_read_close(&reader);
  return 0;
}

int meshmb_ignore(struct meshmb_feeds *feeds, rhizome_bid_t *bid)
{
  DEBUGF(meshmb, "Attempting to ignore %s", alloca_tohex_rhizome_bid_t(*bid));
  tree_walk_prefix(&feeds->root, bid->binary, sizeof *bid, free_feed, feeds);
  return 0;
}

struct enum_context{
  meshmb_callback callback;
  void *context;
};

static int enum_callback(void **record, void *context)
{
  struct feed_metadata *feed = *record;
  struct enum_context *enum_context = context;
  return enum_context->callback(&feed->details, enum_context->context);
}

int meshmb_enum(struct meshmb_feeds *feeds, rhizome_bid_t *restart_from, meshmb_callback callback, void *context)
{
  DEBUGF(meshmb, "Enumerating feeds from %s",
    restart_from?alloca_tohex_rhizome_bid_t(*restart_from):"the beginning");
  struct enum_context enum_context = {
    .callback = callback,
    .context = context
  };
  return tree_walk(&feeds->root, restart_from ? restart_from->binary : NULL, sizeof *restart_from, enum_callback, &enum_context);
}

int meshmb_send(const keyring_identity *id, const char *message, size_t message_len,
  unsigned nassignments, const struct rhizome_manifest_field_assignment *assignments){

  const char *did=NULL, *name=NULL;
  struct message_ply ply;
  bzero(&ply, sizeof ply);

  ply.bundle_id = id->sign_keypair->public_key;
  ply.known_bid = 1;

  struct overlay_buffer *b = ob_new();
  message_ply_append_message(b, message, message_len);
  message_ply_append_timestamp(b);
  assert(!ob_overrun(b));

  keyring_identity_extract(id, &did, &name);
  int ret = message_ply_append(id, RHIZOME_SERVICE_MESHMB, NULL, &ply, b, name, nassignments, assignments);
  ob_free(b);

  return ret;
}
