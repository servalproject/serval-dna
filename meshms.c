/* 
Serval DNA MeshMS
Copyright (C) 2013 Serval Project Inc.

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

#define __MESHMS_INLINE
#include <assert.h>
#include "serval.h"
#include "rhizome_types.h"
#include "meshms.h"
#include "log.h"
#include "debug.h"
#include "conf.h"
#include "crypto.h"
#include "strbuf.h"
#include "keyring.h"
#include "str.h"
#include "dataformats.h"
#include "overlay_buffer.h"

static unsigned mark_read(struct meshms_conversations *conv, const sid_t *their_sid, const uint64_t offset);

void meshms_free_conversations(struct meshms_conversations *conv)
{
  while(conv){
    struct meshms_conversations *n = conv;
    conv = conv->_next;
    free(n);
  }
}

static enum meshms_status get_my_conversation_bundle(const keyring_identity *id, rhizome_manifest *m)
{
  /* Find our private key */
  sign_keypair_t key;
  crypto_seed_keypair(&key,
    "incorrection%sconcentrativeness",
    alloca_tohex(id->box_sk, crypto_box_SECRETKEYBYTES));

  struct rhizome_bundle_result result = rhizome_private_bundle(m, &key);

  switch (result.status) {
    case RHIZOME_BUNDLE_STATUS_NEW:
    case RHIZOME_BUNDLE_STATUS_SAME:
    case RHIZOME_BUNDLE_STATUS_DUPLICATE:
      // The 'meshms' automated test depends on this message; do not alter.
      DEBUGF(meshms, "MESHMS CONVERSATION BUNDLE bid=%s secret=%s",
	     alloca_tohex_rhizome_bid_t(m->keypair.public_key),
	     alloca_tohex(m->keypair.private_key.binary, RHIZOME_BUNDLE_KEY_BYTES)
	    );
      break;
    case RHIZOME_BUNDLE_STATUS_ERROR:
    case RHIZOME_BUNDLE_STATUS_INVALID:
    case RHIZOME_BUNDLE_STATUS_INCONSISTENT:
      WHYF("Error creating conversation manifest: %s", alloca_rhizome_bundle_result(result));
      rhizome_bundle_result_free(&result);
      return MESHMS_STATUS_ERROR;
    case RHIZOME_BUNDLE_STATUS_BUSY:
      // TODO
    case RHIZOME_BUNDLE_STATUS_OLD:
    case RHIZOME_BUNDLE_STATUS_FAKE:
    case RHIZOME_BUNDLE_STATUS_NO_ROOM:
    case RHIZOME_BUNDLE_STATUS_MANIFEST_TOO_BIG:
      WARNF("Cannot create conversation manifest: %s", alloca_rhizome_bundle_result(result));
      rhizome_bundle_result_free(&result);
      return MESHMS_STATUS_PROTOCOL_FAULT;
    case RHIZOME_BUNDLE_STATUS_READONLY:
      INFOF("Cannot create conversation manifest: %s", alloca_rhizome_bundle_result(result));
      rhizome_bundle_result_free(&result);
      return MESHMS_STATUS_SID_LOCKED;
  }
  rhizome_bundle_result_free(&result);
  return MESHMS_STATUS_OK;
}

static struct meshms_conversations *add_conv(struct meshms_conversations **conv, const sid_t *them)
{
  struct meshms_conversations **ptr = conv;
  while (*ptr) {
    int cmp = cmp_sid_t(&(*ptr)->them, them);
    if (cmp == 0)
      return *ptr;
    ptr=&(*ptr)->_next;
  }
  struct meshms_conversations *n = emalloc_zero(sizeof(struct meshms_conversations));
  if (n){
    n->them = *them;
    n->_next = *conv;
    *conv = n;
  }
  return n;
}

// find matching conversations
// if their_sid == my_sid, return all conversations with any recipient
static enum meshms_status get_database_conversations(const keyring_identity *id, struct meshms_conversations **conv)
{
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  sqlite3_stmt *statement = sqlite_prepare_bind(&retry,
      "SELECT id, version, filesize, tail, sender, recipient"
      " FROM manifests"
      " WHERE service = ?2"
      " AND (sender=?1 or recipient=?1)",
      SID_T, id->box_pk,
      STATIC_TEXT, RHIZOME_SERVICE_MESHMS2,
      END
    );
  if (!statement)
    return MESHMS_STATUS_ERROR;
  DEBUGF(meshms, "Looking for conversations for %s", alloca_tohex_sid_t(*id->box_pk));
  int r;
  while ((r=sqlite_step_retry(&retry, statement)) == SQLITE_ROW) {
    const char *id_hex = (const char *)sqlite3_column_text(statement, 0);
    uint64_t version = sqlite3_column_int64(statement, 1);
    int64_t size = sqlite3_column_int64(statement, 2);
    int64_t tail = sqlite3_column_int64(statement, 3);
    const char *sender = (const char *)sqlite3_column_text(statement, 4);
    const char *recipient = (const char *)sqlite3_column_text(statement, 5);
    DEBUGF(meshms, "found id %s, sender %s, recipient %s, size %"PRId64, id_hex, sender, recipient, size);
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
    if (cmp_sid_t(&their_sid, id->box_pk) == 0) {
      them = sender;
      if (str_to_sid_t(&their_sid, them) == -1) {
	WHYF("invalid SID hex: %s -- skipping", alloca_str_toprint(them));
	continue;
      }
    }
    struct meshms_conversations *ptr = add_conv(conv, &their_sid);
    if (!ptr)
      break;
    struct message_ply *p;
    if (them==sender){
      p=&ptr->their_ply;
    }else{
      p=&ptr->my_ply;
    }
    p->found = p->known_bid = 1;
    p->bundle_id = bid;
    p->version = version;
    p->tail = tail;
    p->size = size;
  }
  sqlite3_finalize(statement);
  if (!sqlite_code_ok(r))
    return MESHMS_STATUS_ERROR;
  return MESHMS_STATUS_OK;
}

static enum meshms_status open_ply(struct message_ply *ply, struct message_ply_read *reader)
{
  if (ply->found
  && !message_ply_is_open(reader)
  && message_ply_read_open(reader, &ply->bundle_id)!=0)
    return MESHMS_STATUS_ERROR;
  return MESHMS_STATUS_OK;
}

static enum meshms_status update_their_stats(struct meshms_metadata *metadata, struct message_ply *ply, struct message_ply_read *reader)
{
  DEBUGF(meshms, "Update their stats? (theirsize=%"PRIu64", plysize=%"PRIu64", lastmessage=%"PRIu64", lastackoffset=%"PRIu64", lastack=%"PRIu64")",
    metadata->their_size,
    ply->size,
    metadata->their_last_message,
    metadata->their_last_ack_offset,
    metadata->their_last_ack
  );
  if (metadata->their_size != ply->size){
    enum meshms_status status;
    if (meshms_failed(status = open_ply(ply, reader)))
      return status;

    uint8_t found_their_msg=0;
    uint8_t found_their_ack=0;
    reader->read.offset = reader->read.length;

    while((!found_their_msg || !found_their_ack) && message_ply_read_prev(reader) == 0){
      // stop if we've seen these records before
      if (reader->record_end_offset <= metadata->their_size)
	break;

      switch(reader->type){
	case MESSAGE_BLOCK_TYPE_MESSAGE:
	  if (!found_their_msg){
	    found_their_msg = 1;
	    metadata->their_last_message = reader->record_end_offset;
	    DEBUGF(meshms, "Found their last message @%"PRIu64, metadata->their_last_message);
	  }
	  break;
	case MESSAGE_BLOCK_TYPE_ACK:
	  if (!found_their_ack){
	    found_their_ack = 1;
	    uint64_t value=0;
	    metadata->their_last_ack_offset = reader->record_end_offset;
	    if (unpack_uint(reader->record, reader->record_length, &value) != -1){
	      metadata->their_last_ack = value;
	    }
	    DEBUGF(meshms, "Found their last ack @%"PRIu64" = %"PRIu64,
	      metadata->their_last_ack_offset, metadata->their_last_ack);
	  }
	  break;
      }
    }
    metadata->their_size = ply->size;
    message_ply_read_rewind(reader);
    return MESHMS_STATUS_UPDATED;
  }
  return MESHMS_STATUS_OK;
}

static enum meshms_status update_my_stats(struct meshms_metadata *metadata, struct message_ply *ply, struct message_ply_read *reader)
{
  DEBUGF(meshms, "Update my stats? (mysize=%"PRIu64", plysize=%"PRIu64", lastack=%"PRIu64")",
    metadata->my_size,
    ply->size,
    metadata->my_last_ack);
  if (metadata->my_size != ply->size){
    enum meshms_status status;
    if (meshms_failed(status = open_ply(ply, reader)))
      return status;

    reader->read.offset = reader->read.length;
    if (message_ply_find_prev(reader, MESSAGE_BLOCK_TYPE_ACK)==0){
      uint64_t my_ack = 0;
      if (unpack_uint(reader->record, reader->record_length, &my_ack) != -1){
	metadata->my_last_ack = my_ack;
	DEBUGF(meshms, "Found my last ack %"PRId64, my_ack);
      }
    }
    metadata->my_size = ply->size;
    message_ply_read_rewind(reader);
    return MESHMS_STATUS_UPDATED;
  }

  return MESHMS_STATUS_OK;
}

static enum meshms_status update_stats(struct meshms_conversations *conv)
{
  enum meshms_status status = MESHMS_STATUS_OK;
  struct message_ply_read reader;
  bzero(&reader, sizeof reader);

  enum meshms_status tmp_status = update_their_stats(&conv->metadata, &conv->their_ply, &reader);
  message_ply_read_close(&reader);
  if (meshms_failed(tmp_status))
    return tmp_status;
  if (tmp_status == MESHMS_STATUS_UPDATED)
    status = tmp_status;

  // Nothing else to be done if they have never sent us anything
  if (!conv->metadata.their_last_message)
    return status;

  tmp_status = update_my_stats(&conv->metadata, &conv->my_ply, &reader);
  message_ply_read_close(&reader);

  if (meshms_failed(tmp_status))
    return tmp_status;
  if (tmp_status == MESHMS_STATUS_UPDATED)
    status = tmp_status;

  return status;
}

// create an ack if required.
// return MESHMS_STATUS_UPDATED if the conversation index needs to be saved.
static enum meshms_status update_conversation(const keyring_identity *id, struct meshms_conversations *conv)
{
  DEBUG(meshms, "Checking if conversation needs to be acked");

  enum meshms_status status = update_stats(conv);
  if (meshms_failed(status))
    return status;

  if (conv->metadata.my_last_ack >= conv->metadata.their_last_message)
    return status;

  // append an ack for their message
  DEBUGF(meshms, "Creating ACK for %"PRId64" - %"PRId64, conv->metadata.my_last_ack, conv->metadata.their_last_message);
  unsigned char buffer[30];
  struct overlay_buffer *b = ob_static(buffer, sizeof buffer);

  message_ply_append_ack(b, conv->metadata.their_last_message, conv->metadata.my_last_ack);
  message_ply_append_timestamp(b);
  assert(!ob_overrun(b));

  if (message_ply_append(id, RHIZOME_SERVICE_MESHMS2, &conv->them, &conv->my_ply, b, NULL, 0, NULL)!=0){
    status = MESHMS_STATUS_ERROR;
  }else{
    conv->metadata.my_last_ack = conv->metadata.their_last_message;
    conv->metadata.my_size += ob_position(b);
    status = MESHMS_STATUS_UPDATED;
  }

  ob_free(b);

  return status;
}

// update conversations, and return MESHMS_STATUS_UPDATED if the conversation index should be saved
static enum meshms_status update_conversations(const keyring_identity *id, struct meshms_conversations **conv)
{
  enum meshms_status rstatus = MESHMS_STATUS_OK;
  struct meshms_conversations **ptr = conv;
  while (*ptr) {
    struct meshms_conversations *n = *ptr;
    enum meshms_status status;
    if (meshms_failed(status = update_conversation(id, n)))
      return status;
    if (status == MESHMS_STATUS_UPDATED){
      rstatus = MESHMS_STATUS_UPDATED;
      if (n != *conv){
	DEBUGF(meshms, "Bumping conversation from %s", alloca_tohex_sid_t(n->them));
	*ptr = n->_next;
	n->_next = *conv;
	*conv = n;
	continue;
      }
    }
    ptr = &(*ptr)->_next;
  }
  return rstatus;
}

// read our cached conversation list from our rhizome payload
// if we can't load the existing data correctly, just ignore it.
static enum meshms_status read_known_conversations(rhizome_manifest *m, struct meshms_conversations **conv)
{
  if (m->haveSecret==NEW_BUNDLE_ID)
    return MESHMS_STATUS_OK;

  struct meshms_conversations **ptr = conv;
  struct rhizome_read read;
  bzero(&read, sizeof(read));
  struct rhizome_read_buffer buff;
  bzero(&buff, sizeof(buff));

  enum meshms_status status = MESHMS_STATUS_OK;
  enum rhizome_payload_status pstatus = rhizome_open_decrypt_read(m, &read);
  if (pstatus == RHIZOME_PAYLOAD_STATUS_NEW) {
    WARNF("Payload was not found for manifest %s, %"PRIu64, alloca_tohex_rhizome_bid_t(m->keypair.public_key), m->version);
    goto end;
  }
  if (pstatus != RHIZOME_PAYLOAD_STATUS_STORED && pstatus != RHIZOME_PAYLOAD_STATUS_EMPTY)
    goto end;

  uint8_t version=0xFF;
  ssize_t r = rhizome_read_buffered(&read, &buff, &version, 1);
  if (r == -1)
    goto end;
  if (version < 1 || version > 2) {
    WARNF("Unknown file format version (got 0x%02x)", version);
    goto end;
  }
  
  while (1) {
    uint8_t buffer[SID_SIZE + 12*3 + 1];

    ssize_t bytes = rhizome_read_buffered(&read, &buff, buffer, sizeof buffer);
    if (bytes == 0) {
      status = MESHMS_STATUS_OK;
      goto end;
    }
    if (bytes < (ssize_t)SID_SIZE+1)
      break;

    const sid_t *sid = (sid_t *)&buffer[0];

    int ofs = SID_SIZE;

    //TODO flags byte uint8_t flags = 0;
    struct meshms_metadata metadata;
    bzero(&metadata, sizeof metadata);
    int unpacked;

    if (version==1){
      // force re-reading ply details
      uint64_t ignored=0;
      if ((unpacked = unpack_uint(buffer+ofs, bytes-ofs, &ignored)) == -1)
	break;
      ofs += unpacked;
      if ((unpacked = unpack_uint(buffer+ofs, bytes-ofs, &ignored)) == -1)
	break;
      ofs += unpacked;
      if ((unpacked = unpack_uint(buffer+ofs, bytes-ofs, &ignored)) == -1)
	break;
      ofs += unpacked;
    }else if(version>=2){
      uint64_t delta=0;

      ofs ++; // flags = buffer[ofs++];

      if ((unpacked = unpack_uint(buffer+ofs, bytes-ofs, &metadata.their_size)) == -1)
	break;
      ofs += unpacked;
      if ((unpacked = unpack_uint(buffer+ofs, bytes-ofs, &metadata.my_size)) == -1)
	break;
      ofs += unpacked;

      if ((unpacked = unpack_uint(buffer+ofs, bytes-ofs, &delta)) == -1)
	break;
      ofs += unpacked;
      metadata.their_last_message = metadata.their_size - delta;

      if ((unpacked = unpack_uint(buffer+ofs, bytes-ofs, &delta)) == -1)
	break;
      ofs += unpacked;
      metadata.read_offset = metadata.their_size - delta;

      if ((unpacked = unpack_uint(buffer+ofs, bytes-ofs, &delta)) == -1)
	break;
      ofs += unpacked;
      metadata.their_last_ack_offset = metadata.their_size - delta;

      if ((unpacked = unpack_uint(buffer+ofs, bytes-ofs, &delta)) == -1)
	break;
      ofs += unpacked;
      metadata.my_last_ack = metadata.their_size - delta;

      if ((unpacked = unpack_uint(buffer+ofs, bytes-ofs, &delta)) == -1)
	break;
      ofs += unpacked;
      metadata.their_last_ack = metadata.my_size - delta;
    }

    read.offset += ofs - bytes;
    
    struct meshms_conversations *n = emalloc_zero(sizeof(struct meshms_conversations));
    if (!n)
      goto end;
    
    *ptr = n;
    ptr = &n->_next;
    
    n->them = *sid;
    n->metadata = metadata;

    DEBUGF(meshms, "Unpacked existing conversation for %s (their_size=%"PRIu64", my_size=%"PRIu64", last_message=%"PRIu64", read_offset=%"PRIu64", my_ack=%"PRIu64", their_ack=%"PRIu64")",
      alloca_tohex_sid_t(*sid),
      metadata.their_size,
      metadata.my_size,
      metadata.their_last_message,
      metadata.read_offset,
      metadata.my_last_ack,
      metadata.their_last_ack
    );
  }
end:
  rhizome_read_close(&read);
  return status;
}

static ssize_t write_conversation(struct rhizome_write *write, struct meshms_conversations *conv)
{
  size_t len=0;
  unsigned char buffer[sizeof(conv->them) + (12*3) + 1];

  bcopy(conv->them.binary, buffer, sizeof(conv->them));
  len+=sizeof(conv->them);
  buffer[len++] = 0; // TODO reserved for flags

  assert(conv->metadata.their_size >= conv->metadata.their_last_message);
  assert(conv->metadata.their_size >= conv->metadata.read_offset);
  assert(conv->metadata.their_size >= conv->metadata.my_last_ack);
  assert(conv->metadata.their_size >= conv->metadata.their_last_ack_offset);
  assert(conv->metadata.my_size >= conv->metadata.their_last_ack);

  // assume that most ack & read offsets are going to be near the ply length
  // so store them as delta's.
  len+=pack_uint(&buffer[len], conv->metadata.their_size);
  len+=pack_uint(&buffer[len], conv->metadata.my_size);
  len+=pack_uint(&buffer[len], conv->metadata.their_size - conv->metadata.their_last_message);
  len+=pack_uint(&buffer[len], conv->metadata.their_size - conv->metadata.read_offset);
  len+=pack_uint(&buffer[len], conv->metadata.their_size - conv->metadata.their_last_ack_offset);
  len+=pack_uint(&buffer[len], conv->metadata.their_size - conv->metadata.my_last_ack);
  len+=pack_uint(&buffer[len], conv->metadata.my_size - conv->metadata.their_last_ack);

  assert(len <= sizeof buffer);

  if (write){
    int ret=rhizome_write_buffer(write, buffer, len);
    if (ret == -1)
      return ret;
  }

  DEBUGF(meshms, "len %s, %"PRId64", %"PRId64", %"PRId64" = %zu",
         alloca_tohex_sid_t(conv->them),
         conv->metadata.their_last_message,
         conv->metadata.read_offset,
         conv->metadata.their_size,
         len
	);
  return len;
}

static ssize_t write_conversations(struct rhizome_write *write, struct meshms_conversations *conv)
{
  ssize_t len=0;
  while(conv){
    ssize_t this_len = write_conversation(write, conv);
    if (this_len==-1)
      return this_len;
    len+=this_len;
    conv = conv->_next;
  }
  return len;
}

static enum meshms_status write_known_conversations(rhizome_manifest *m, struct meshms_conversations *conv)
{
  rhizome_manifest *mout=NULL;
  
  struct rhizome_write write;
  bzero(&write, sizeof(write));
  enum meshms_status status = MESHMS_STATUS_ERROR;
  
  // TODO rebalance tree...?
  
  rhizome_manifest_set_version(m, m->version + 1);
  rhizome_manifest_set_filesize(m, RHIZOME_SIZE_UNSET);
  rhizome_manifest_set_filehash(m, NULL);

  enum rhizome_payload_status pstatus = rhizome_write_open_manifest(&write, m);
  if (pstatus!=RHIZOME_PAYLOAD_STATUS_NEW)
    goto end;
  
  uint8_t version=2;
  if (rhizome_write_buffer(&write, &version, 1) == -1)
    goto end;
  if (write_conversations(&write, conv) == -1)
    goto end;

  if (write.file_offset == 1){
    // Don't bother if we don't know anyone.
    status = MESHMS_STATUS_OK;
    goto end;
  }

  pstatus = rhizome_finish_write(&write);
  if (pstatus != RHIZOME_PAYLOAD_STATUS_NEW)
    goto end;
  rhizome_manifest_set_filehash(m, &write.id);
  rhizome_manifest_set_filesize(m, write.file_length);

  struct rhizome_bundle_result result = rhizome_manifest_finalise(m, &mout, 1);
  switch (result.status) {
    case RHIZOME_BUNDLE_STATUS_ERROR:
      // error is already logged
      break;
    case RHIZOME_BUNDLE_STATUS_NEW:
      status = MESHMS_STATUS_UPDATED;
      break;
    case RHIZOME_BUNDLE_STATUS_SAME:
    case RHIZOME_BUNDLE_STATUS_DUPLICATE:
    case RHIZOME_BUNDLE_STATUS_OLD:
      status = MESHMS_STATUS_PROTOCOL_FAULT;
      WARNF("MeshMS conversation manifest (version=%"PRIu64") gazumped by Rhizome store (version=%"PRIu64")",
	  m->version, mout->version);
      break;
    case RHIZOME_BUNDLE_STATUS_NO_ROOM:
      status = MESHMS_STATUS_PROTOCOL_FAULT;
      WARNF("MeshMS ply manifest evicted from store");
      break;
    case RHIZOME_BUNDLE_STATUS_INCONSISTENT:
      status = MESHMS_STATUS_PROTOCOL_FAULT;
      WARN("MeshMS conversation manifest not consistent with payload");
      break;
    case RHIZOME_BUNDLE_STATUS_FAKE:
    case RHIZOME_BUNDLE_STATUS_READONLY:
      status = MESHMS_STATUS_PROTOCOL_FAULT;
      WARN("MeshMS conversation manifest is not signed");
      break;
    case RHIZOME_BUNDLE_STATUS_INVALID:
    case RHIZOME_BUNDLE_STATUS_MANIFEST_TOO_BIG:
      status = MESHMS_STATUS_PROTOCOL_FAULT;
      WARN("MeshMS conversation manifest is invalid");
      break;
    case RHIZOME_BUNDLE_STATUS_BUSY:
      status = MESHMS_STATUS_PROTOCOL_FAULT;
      WARNF("MeshMS conversation manifest not stored due to database locking");
      break;
  }
  rhizome_bundle_result_free(&result);
end:
  if (meshms_failed(status))
    rhizome_fail_write(&write);
  if (mout && m!=mout)
    rhizome_manifest_free(mout);
  return status;
}

static enum meshms_status meshms_open_list(const keyring_identity *id, rhizome_manifest *m, struct meshms_conversations **conv)
{
  enum meshms_status status;

  if (meshms_failed(status = get_my_conversation_bundle(id, m)))
    goto end;
  // read conversations payload
  if (meshms_failed(status = read_known_conversations(m, conv)))
    goto end;
  status = get_database_conversations(id, conv);
end:
  return status;
}

static enum meshms_status meshms_save_list(const keyring_identity *id, rhizome_manifest *m, struct meshms_conversations **conv)
{
  enum meshms_status status;

  if ((status = update_conversations(id, conv)) == MESHMS_STATUS_UPDATED)
    status = write_known_conversations(m, *conv);

  return status;
}

// read information about existing conversations from a rhizome payload
enum meshms_status meshms_conversations_list(const keyring_identity *id, const sid_t *my_sid, struct meshms_conversations **conv)
{
  enum meshms_status status = MESHMS_STATUS_ERROR;
  rhizome_manifest *m=NULL;

  assert(keyring != NULL);
  assert(id || my_sid);
  if (!my_sid){
    my_sid = id->box_pk;
  }else if(!id){
    id = keyring_find_identity_sid(keyring, my_sid);
    if (!id){
      status = MESHMS_STATUS_SID_LOCKED;
      goto end;
    }
  }

  m = rhizome_new_manifest();
  if (!m)
    goto end;

  if (meshms_failed(status = meshms_open_list(id, m, conv)))
    goto end;

  if (meshms_failed(status = meshms_save_list(id, m, conv)))
    goto end;

end:
  rhizome_manifest_free(m);
  DEBUGF(meshms, "status=%d", status);
  return status;
}

/* Start traversing the given conversation binary tree in infix order.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
void meshms_conversation_iterator_start(struct meshms_conversation_iterator *it, struct meshms_conversations *conv)
{
  it->current = conv;
}

/* Advance to the next conversation in the tree.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
void meshms_conversation_iterator_advance(struct meshms_conversation_iterator *it)
{
  assert(it->current != NULL); // do not call on a finished iterator
  it->current = it->current->_next;
}

enum meshms_status meshms_message_iterator_open(struct meshms_message_iterator *iter, const sid_t *me, const sid_t *them)
{
  assert(keyring != NULL);
  bzero(iter, sizeof *iter);
  DEBUGF(meshms, "iter=%p me=%s them=%s", iter,
	 me ? alloca_tohex_sid_t(*me) : "NULL",
	 them ? alloca_tohex_sid_t(*them) : "NULL"
	);

  enum meshms_status status = MESHMS_STATUS_ERROR;
  struct meshms_conversations *conv = NULL;
  rhizome_manifest *m = NULL;

  keyring_identity *id = keyring_find_identity_sid(keyring, me);
  if (!id){
    status = MESHMS_STATUS_SID_LOCKED;
    WHY("Identity not found");
    goto fail;
  }

  if (!(m = rhizome_new_manifest()))
    goto error;

  if (meshms_failed(status = meshms_open_list(id, m, &conv)))
    goto fail;

  iter->identity = id;
  iter->timestamp = 0;
  iter->_in_ack = 0;
  iter->my_sid = *me;
  iter->their_sid = *them;

  struct meshms_conversations *c = conv;
  while(c){
    if (cmp_sid_t(them, &c->them)==0){
      DEBUGF(meshms, "Found matching conversation, found_mine=%d, found_theirs=%d, read_offset=%"PRId64,
	c->my_ply.found, c->their_ply.found, c->metadata.read_offset);

      if (meshms_failed(status = update_conversation(id, c)))
	goto fail;
      if (status == MESHMS_STATUS_UPDATED)
	// ignore failures, we can retry later anyway.
	write_known_conversations(m, conv);

      if (meshms_failed(status = open_ply(&c->my_ply, &iter->_my_reader)))
	goto fail;
      if (meshms_failed(status = open_ply(&c->their_ply, &iter->_their_reader)))
	goto fail;

      iter->metadata = c->metadata;
      iter->my_ply = c->my_ply;
      iter->their_ply = c->their_ply;

      if (c->their_ply.found && c->metadata.their_last_message > c->metadata.my_last_ack){
	iter->_in_ack = 1;
	iter->_their_reader.read.offset = c->metadata.their_last_message;
	iter->_end_range = c->metadata.my_last_ack;
      }

      break;
    }
    c = c->_next;
  }

  meshms_free_conversations(conv);
  return MESHMS_STATUS_OK;

error:
  status = MESHMS_STATUS_ERROR;
fail:
  meshms_message_iterator_close(iter);
  meshms_free_conversations(conv);
  return status;
}

void meshms_message_iterator_close(struct meshms_message_iterator *iter)
{
  DEBUGF(meshms, "iter=%p", iter);
  message_ply_read_close(&iter->_my_reader);
  message_ply_read_close(&iter->_their_reader);
}

enum meshms_status meshms_message_iterator_prev(struct meshms_message_iterator *iter)
{
  DEBUGF(meshms, "iter=%p, in_ack=%d, found_mine=%d, my_offset=%"PRIu64", their_offset=%"PRIu64,
    iter, iter->_in_ack, iter->my_ply.found,
    iter->_my_reader.read.offset, iter->_their_reader.read.offset);
  while (1) {
    if (iter->their_ply.found && iter->_in_ack) {
      DEBUGF(meshms, "Reading other log from %"PRIu64", to %"PRIu64, iter->_their_reader.read.offset, iter->_end_range);
      // just in case we don't have the full bundle in this rhizome store
      if (iter->_their_reader.read.offset > iter->_their_reader.read.length)
	iter->_their_reader.read.offset = iter->_their_reader.read.length;

      // eof or other read errors, skip over messages (the tail is allowed to advance)
      if (message_ply_read_prev(&iter->_their_reader)==0){
	iter->which_ply = THEIR_PLY;
	if (iter->_their_reader.read.offset >= iter->_end_range) {
	  switch (iter->_their_reader.type) {
	    case MESSAGE_BLOCK_TYPE_ACK:
	      iter->type = ACK_RECEIVED;
	      iter->their_offset = iter->_their_reader.record_end_offset;
	      iter->text = NULL;
	      iter->text_length = 0;
	      if (unpack_uint(iter->_their_reader.record, iter->_their_reader.record_length, &iter->ack_offset) == -1)
		iter->ack_offset = 0;
	      iter->read = 0;
	      return MESHMS_STATUS_UPDATED;
	    case MESSAGE_BLOCK_TYPE_MESSAGE:
	      iter->type = MESSAGE_RECEIVED;
	      iter->their_offset = iter->_their_reader.record_end_offset;
	      iter->text = (const char *)iter->_their_reader.record;
	      iter->text_length = iter->_their_reader.record_length;
	      if (   iter->_their_reader.record_length != 0
		  && iter->_their_reader.record[iter->_their_reader.record_length - 1] == '\0'
	      ) {
		iter->read = iter->_their_reader.record_end_offset <= iter->metadata.read_offset;
		return MESHMS_STATUS_UPDATED;
	      }
	      WARN("Malformed MeshMS2 ply journal, missing NUL terminator");
	      return MESHMS_STATUS_PROTOCOL_FAULT;
	  }
	  continue;
	}
      }
      iter->_in_ack = 0;
    }else if(iter->my_ply.found){
      if (message_ply_read_prev(&iter->_my_reader) != 0)
	return MESHMS_STATUS_OK;

      DEBUGF(meshms, "Offset %"PRId64", type %d, read_offset %"PRId64,
	iter->_my_reader.read.offset, iter->_my_reader.type, iter->metadata.read_offset);
      iter->which_ply = MY_PLY;
      switch (iter->_my_reader.type) {
	case MESSAGE_BLOCK_TYPE_TIME:
	  if (iter->_my_reader.record_length<4){
	    WARN("Malformed MeshMS2 ply journal, expected 4 byte timestamp");
	    return MESHMS_STATUS_PROTOCOL_FAULT;
	  }
	  iter->timestamp = read_uint32(iter->_my_reader.record);
	  DEBUGF(meshms, "Parsed timestamp %ds old", gettime() - iter->timestamp);
	  break;
	case MESSAGE_BLOCK_TYPE_ACK:
	  // Read the received messages up to the ack'ed offset
	  if (iter->their_ply.found) {
	    iter->my_offset = iter->_my_reader.record_end_offset;
	    int ofs = unpack_uint(iter->_my_reader.record, iter->_my_reader.record_length, (uint64_t*)&iter->_their_reader.read.offset);
	    if (ofs == -1) {
	      WHYF("Malformed ACK");
	      return MESHMS_STATUS_PROTOCOL_FAULT;
	    }
	    uint64_t end_range;
	    int x = unpack_uint(iter->_my_reader.record + ofs, iter->_my_reader.record_length - ofs, &end_range);
	    if (x == -1)
	      iter->_end_range = 0;
	    else
	      iter->_end_range = iter->_their_reader.read.offset - end_range;
	    // TODO tail
	    iter->_in_ack = 1;
	  }
	  break;
	case MESSAGE_BLOCK_TYPE_MESSAGE:
	  iter->type = MESSAGE_SENT;
	  iter->my_offset = iter->_my_reader.record_end_offset;
	  iter->their_offset = 0;
	  iter->text = (const char *)iter->_my_reader.record;
	  iter->text_length = iter->_my_reader.record_length;
	  iter->delivered = iter->_my_reader.record_end_offset <= iter->metadata.their_last_ack;
	  return MESHMS_STATUS_UPDATED;
      }
    }else{
      return MESHMS_STATUS_OK;
    }
  }
}

enum meshms_status meshms_send_message(const sid_t *sender, const sid_t *recipient, const char *message, size_t message_len)
{
  assert(keyring != NULL);
  assert(message_len != 0);
  if (message_len > MESSAGE_PLY_MAX_LEN) {
    WHY("message too long");
    return MESHMS_STATUS_ERROR;
  }
  struct meshms_conversations *conv = NULL;
  enum meshms_status status = MESHMS_STATUS_ERROR;
  rhizome_manifest *m=NULL;

  keyring_identity *id = keyring_find_identity_sid(keyring, sender);
  if (!id)
    return MESHMS_STATUS_SID_LOCKED;

  m = rhizome_new_manifest();
  if (!m)
    goto end;

  if (meshms_failed(status = meshms_open_list(id, m, &conv)))
    goto end;

  struct meshms_conversations *c = conv;
  while(c && cmp_sid_t(recipient, &c->them)!=0)
    c = c->_next;

  if (!c){
    c = (struct meshms_conversations *) emalloc_zero(sizeof(struct meshms_conversations));
    if (!c)
      goto end;
    c->them = *recipient;
    c->_next = conv;
    conv = c;
    status = MESHMS_STATUS_UPDATED;
  }

  enum meshms_status tmp_status = update_stats(c);
  if (meshms_failed(tmp_status))
    return tmp_status;
  if (tmp_status == MESHMS_STATUS_UPDATED)
    status = tmp_status;

  // construct a message payload
  struct overlay_buffer *b = ob_new();

  // if we didn't "know" them, or we just received a new message, we may need to add an ack now.
  // lets do that in one hit
  uint8_t ack = (c->metadata.my_last_ack < c->metadata.their_last_message) ? 1:0;
  DEBUGF(meshms,"Our ack %"PRIu64", their message %"PRIu64, c->metadata.my_last_ack, c->metadata.their_last_message);
  if (ack)
    message_ply_append_ack(b, c->metadata.their_last_message, c->metadata.my_last_ack);

  message_ply_append_message(b, message, message_len);
  message_ply_append_timestamp(b);

  assert(!ob_overrun(b));

  if (message_ply_append(id, RHIZOME_SERVICE_MESHMS2, recipient, &c->my_ply, b, NULL, 0, NULL)==0){
    if (ack)
      c->metadata.my_last_ack = c->metadata.their_last_message;
    c->metadata.my_size += ob_position(b);

    // save known conversations since our stats will always change.
    write_known_conversations(m, conv);

    status = MESHMS_STATUS_UPDATED;
  }else{
    status = MESHMS_STATUS_ERROR;
  }

  ob_free(b);

end:
  if (m)
    rhizome_manifest_free(m);
  meshms_free_conversations(conv);
  return status;
}

enum meshms_status meshms_mark_read(const sid_t *sender, const sid_t *recipient, uint64_t offset)
{
  assert(keyring != NULL);
  rhizome_manifest *m=NULL;
  enum meshms_status status = MESHMS_STATUS_ERROR;
  struct meshms_conversations *conv = NULL;

  keyring_identity *id = keyring_find_identity_sid(keyring, sender);
  if (!id){
    status = MESHMS_STATUS_SID_LOCKED;
    goto end;
  }

  DEBUGF(meshms, "sender=%s recipient=%s offset=%"PRIu64,
	 alloca_tohex_sid_t(*sender),
	 recipient ? alloca_tohex_sid_t(*recipient) : "(all)",
	 offset
	);
  m = rhizome_new_manifest();
  if (!m)
    goto end;

  if (meshms_failed(status = meshms_open_list(id, m, &conv)))
    goto end;

  unsigned changed = 0;
  // check if any incoming conversations need to be acked or have new messages
  if (meshms_failed(status = update_conversations(id, &conv)))
    goto end;
  if (status == MESHMS_STATUS_UPDATED)
    changed ++;
  // update the read offset
  changed += mark_read(conv, recipient, offset);
  DEBUGF(meshms, "changed=%u", changed);
  if (changed)
    status = write_known_conversations(m, conv);
end:
  if (m)
    rhizome_manifest_free(m);
  meshms_free_conversations(conv);
  return status;
}

// Returns the number of read markers moved.
static unsigned mark_read(struct meshms_conversations *conv, const sid_t *their_sid, const uint64_t offset)
{
  unsigned ret=0;
  while (conv){
    if (!their_sid || cmp_sid_t(&conv->them, their_sid)==0){
      // update read offset
      // - never past their last message
      // - never rewind, only advance
      uint64_t new_offset = offset;
      if (new_offset > conv->metadata.their_last_message)
	new_offset = conv->metadata.their_last_message;

      DEBUGF(meshms, "Read marker for %s, to %"PRIu64" (asked for %"PRIu64", was %"PRIu64")",
	alloca_tohex_sid_t(conv->them),
	new_offset,
	offset,
	conv->metadata.read_offset);

      if (new_offset > conv->metadata.read_offset) {
	conv->metadata.read_offset = new_offset;
	ret++;
      }
      if (their_sid)
	break;
    }
    conv = conv->_next;
  }
  return ret;
}


const char *meshms_status_message(enum meshms_status status)
{
  switch (status) {
  case MESHMS_STATUS_OK:             return "OK";
  case MESHMS_STATUS_UPDATED:        return "Updated";
  case MESHMS_STATUS_SID_LOCKED:     return "Identity unknown";
  case MESHMS_STATUS_PROTOCOL_FAULT: return "MeshMS protocol fault";
  case MESHMS_STATUS_ERROR:          return "Internal error";
  }
  return NULL;
}
