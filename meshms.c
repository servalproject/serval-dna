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
  strbuf sb = strbuf_alloca(1024);
  strbuf_puts(sb, "incorrection");
  strbuf_tohex(sb, crypto_box_SECRETKEYBYTES * 2, id->box_sk);
  strbuf_puts(sb, "concentrativeness");
  assert(!strbuf_overrun(sb));
  if (rhizome_get_bundle_from_seed(m, strbuf_str(sb)) == -1)
    return MESHMS_STATUS_ERROR;
  
  // always consider the content encrypted, we don't need to rely on the manifest itself.
  rhizome_manifest_set_crypt(m, PAYLOAD_ENCRYPTED);
  assert(m->haveSecret);

  // The 'meshms' automated test depends on this message; do not alter.
  DEBUGF(meshms, "MESHMS CONVERSATION BUNDLE bid=%s secret=%s",
	 alloca_tohex_rhizome_bid_t(m->cryptoSignPublic),
	 alloca_tohex(m->cryptoSignSecret, RHIZOME_BUNDLE_KEY_BYTES)
	);

  if (m->haveSecret == NEW_BUNDLE_ID) {
    rhizome_manifest_set_service(m, RHIZOME_SERVICE_FILE);
    rhizome_manifest_set_name(m, "");
    rhizome_manifest_set_author_identity(m, id);
    struct rhizome_bundle_result result = rhizome_fill_manifest(m, NULL);
    switch (result.status) {
    case RHIZOME_BUNDLE_STATUS_NEW:
    case RHIZOME_BUNDLE_STATUS_SAME:
    case RHIZOME_BUNDLE_STATUS_DUPLICATE:
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
  } else {
    if (strcmp(m->service, RHIZOME_SERVICE_FILE) != 0) {
      WARNF("Invalid conversations manifest, service=%s but should be %s", m->service, RHIZOME_SERVICE_FILE);
      return MESHMS_STATUS_PROTOCOL_FAULT;
    }
  }
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
static enum meshms_status get_database_conversations(const keyring_identity *id, const sid_t *their_sid, struct meshms_conversations **conv)
{
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  sqlite3_stmt *statement = sqlite_prepare_bind(&retry,
      "SELECT id, version, filesize, tail, sender, recipient"
      " FROM manifests"
      " WHERE service = ?3"
      " AND (sender=?1 or recipient=?1)"
      " AND (sender=?2 or recipient=?2)",
      SID_T, id->box_pk,
      SID_T, their_sid ? their_sid : id->box_pk,
      STATIC_TEXT, RHIZOME_SERVICE_MESHMS2,
      END
    );
  if (!statement)
    return MESHMS_STATUS_ERROR;
  DEBUGF(meshms, "Looking for conversations for %s, %s",
	 alloca_tohex_sid_t(*id->box_pk),
	 alloca_tohex_sid_t(*(their_sid ? their_sid : id->box_pk))
	);
  int r;
  while ((r=sqlite_step_retry(&retry, statement)) == SQLITE_ROW) {
    const char *id_hex = (const char *)sqlite3_column_text(statement, 0);
    uint64_t version = sqlite3_column_int64(statement, 1);
    int64_t size = sqlite3_column_int64(statement, 2);
    int64_t tail = sqlite3_column_int64(statement, 3);
    const char *sender = (const char *)sqlite3_column_text(statement, 4);
    const char *recipient = (const char *)sqlite3_column_text(statement, 5);
    DEBUGF(meshms, "found id %s, sender %s, recipient %s", id_hex, sender, recipient);
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
    p->found = 1;
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

static enum meshms_status find_or_create_conv(keyring_identity *id, const sid_t *their_sid, struct meshms_conversations **conv)
{
  enum meshms_status status;
  if (meshms_failed(status = meshms_conversations_list(id, NULL, their_sid, conv)))
    return status;
  if (*conv == NULL) {
    if ((*conv = (struct meshms_conversations *) emalloc_zero(sizeof(struct meshms_conversations))) == NULL)
      return MESHMS_STATUS_ERROR;
    (*conv)->them = *their_sid;
    status = MESHMS_STATUS_UPDATED;
  }
  return status;
}

// update if any conversations are unread or need to be acked.
// return MESHMS_STATUS_UPDATED if the conversation index needs to be saved.
static enum meshms_status update_conversation(const keyring_identity *id, struct meshms_conversations *conv)
{
  DEBUG(meshms, "Checking if conversation needs to be acked");
    
  // Nothing to be done if they have never sent us anything
  if (!conv->their_ply.found)
    return MESHMS_STATUS_OK;

  uint64_t last_offset=0;
  {
    struct message_ply_read ply;
    bzero(&ply, sizeof ply);
    if (message_ply_read_open(&ply, &conv->their_ply.bundle_id)!=0)
      return MESHMS_STATUS_ERROR;

    DEBUG(meshms, "Locating their last message");
    if (message_ply_find_prev(&ply, MESSAGE_BLOCK_TYPE_MESSAGE)==0){
      last_offset = ply.record_end_offset;
      DEBUGF(meshms, "Found last message @%"PRId64, last_offset);
    }
    message_ply_read_close(&ply);
  }

  // Perhaps only an ack has been added
  if (last_offset == 0 || conv->their_last_message == last_offset)
    return MESHMS_STATUS_OK;

  // find our previous ack
  uint64_t previous_ack = 0;
  
  if (conv->my_ply.found){
    struct message_ply_read ply;
    bzero(&ply, sizeof ply);
    if (message_ply_read_open(&ply, &conv->my_ply.bundle_id)!=0)
      return MESHMS_STATUS_ERROR;

    DEBUG(meshms, "Locating our previous ack");
    if (message_ply_find_prev(&ply, MESSAGE_BLOCK_TYPE_ACK)==0){
      if (unpack_uint(ply.record, ply.record_length, &previous_ack) == -1)
	previous_ack=0;
      else
	DEBUGF(meshms, "Previous ack is %"PRId64, previous_ack);
    }
    message_ply_read_close(&ply);
  }else{
    DEBUGF(meshms, "No outgoing ply");
  }

  // Note that we may have already acked this message, but failed to record it in our conversation list bundle
  enum meshms_status status = MESHMS_STATUS_UPDATED;

  if (previous_ack < last_offset){
    // append an ack for their message
    DEBUGF(meshms, "Creating ACK for %"PRId64" - %"PRId64, previous_ack, last_offset);
    unsigned char buffer[30];
    struct overlay_buffer *b = ob_static(buffer, sizeof buffer);

    message_ply_append_ack(b, last_offset, previous_ack);
    message_ply_append_timestamp(b);
    assert(!ob_overrun(b));

    if (message_ply_append(id, RHIZOME_SERVICE_MESHMS2, &conv->them, &conv->my_ply, b)!=0)
      status = MESHMS_STATUS_ERROR;

    ob_free(b);
  }

  if (!meshms_failed(status)){
    // if it's all good, remember the size of their ply at the time we examined it.
    conv->their_last_message = last_offset;
    conv->their_size = conv->their_ply.size;
  }

  return status;
}

// update conversations, and return MESHMS_STATUS_UPDATED if the conversation index should be saved
static enum meshms_status update_conversations(const keyring_identity *id, struct meshms_conversations **conv)
{
  enum meshms_status rstatus = MESHMS_STATUS_OK;
  struct meshms_conversations **ptr = conv;
  while (*ptr) {
    struct meshms_conversations *n = *ptr;
    if (n->their_size != n->their_ply.size) {
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
    }
    ptr = &(*ptr)->_next;
  }
  return rstatus;
}

// read our cached conversation list from our rhizome payload
// if we can't load the existing data correctly, just ignore it.
static enum meshms_status read_known_conversations(rhizome_manifest *m, const sid_t *their_sid, struct meshms_conversations **conv)
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
    WARNF("Payload was not found for manifest %s, %"PRIu64, alloca_tohex_rhizome_bid_t(m->cryptoSignPublic), m->version);
    goto end;
  }
  if (pstatus != RHIZOME_PAYLOAD_STATUS_STORED && pstatus != RHIZOME_PAYLOAD_STATUS_EMPTY)
    goto end;

  unsigned char version=0xFF;
  ssize_t r = rhizome_read_buffered(&read, &buff, &version, 1);
  if (r == -1)
    goto end;
  if (version != 1) {
    WARNF("Expected version 1 (got 0x%02x)", version);
    goto end;
  }
  
  while (1) {
    sid_t sid;
    r = rhizome_read_buffered(&read, &buff, sid.binary, sizeof sid.binary);
    if (r == 0) {
      status = MESHMS_STATUS_OK;
      goto end;
    }
    if (r != sizeof sid.binary)
      break;
    DEBUGF(meshms, "Reading existing conversation for %s", alloca_tohex_sid_t(sid));
    
    // unpack the stored details first so we know where the next record is
    unsigned char details[12*3];
    r = rhizome_read_buffered(&read, &buff, details, sizeof details);
    if (r == -1)
      break;
    int bytes = r;
    
    uint64_t last_message=0;
    uint64_t read_offset=0;
    uint64_t their_size=0;
    
    int ofs = 0;
    int unpacked = unpack_uint(details, bytes, &last_message);
    if (unpacked == -1)
      break;
    ofs += unpacked;
    unpacked = unpack_uint(details+ofs, bytes-ofs, &read_offset);
    if (unpacked == -1)
      break;
    ofs += unpacked;
    unpacked = unpack_uint(details+ofs, bytes-ofs, &their_size);
    if (unpacked == -1)
      break;
    ofs += unpacked;
    read.offset += ofs - bytes;
    
    // skip uninteresting records
    if (their_sid && cmp_sid_t(&sid, their_sid) != 0)
      continue;
    
    struct meshms_conversations *n = emalloc_zero(sizeof(struct meshms_conversations));
    if (!n)
      goto end;
    
    *ptr = n;
    ptr = &n->_next;
    
    n->them = sid;
    n->their_last_message = last_message;
    n->read_offset = read_offset;
    n->their_size = their_size;
  }
end:
  rhizome_read_close(&read);
  return status;
}

static ssize_t write_conversation(struct rhizome_write *write, struct meshms_conversations *conv)
{
  size_t len=0;
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
  DEBUGF(meshms, "len %s, %"PRId64", %"PRId64", %"PRId64" = %zu",
         alloca_tohex_sid_t(conv->them),
         conv->their_last_message,
         conv->read_offset,
         conv->their_size,
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
  
  // TODO rebalance tree...
  
  // measure the final payload first
  ssize_t len=write_conversations(NULL, conv);
  if (len == -1)
    goto end;
  
  // then write it
  rhizome_manifest_set_version(m, m->version + 1);
  rhizome_manifest_set_filesize(m, (size_t)len + 1);
  rhizome_manifest_set_filehash(m, NULL);

  enum rhizome_payload_status pstatus = rhizome_write_open_manifest(&write, m);
  if (pstatus!=RHIZOME_PAYLOAD_STATUS_NEW)
    // TODO log something?
    goto end;
  
  unsigned char version=1;
  if (rhizome_write_buffer(&write, &version, 1) == -1)
    goto end;
  if (write_conversations(&write, conv) == -1)
    goto end;
  pstatus = rhizome_finish_write(&write);
  if (pstatus != RHIZOME_PAYLOAD_STATUS_NEW)
    goto end;
  rhizome_manifest_set_filehash(m, &write.id);
  
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

// read information about existing conversations from a rhizome payload
enum meshms_status meshms_conversations_list(const keyring_identity *id, const sid_t *my_sid, const sid_t *their_sid, struct meshms_conversations **conv)
{
  enum meshms_status status = MESHMS_STATUS_ERROR;
  rhizome_manifest *m = rhizome_new_manifest();
  if (!m)
    goto end;

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

  if (meshms_failed(status = get_my_conversation_bundle(id, m)))
    goto end;
  // read conversations payload
  if (meshms_failed(status = read_known_conversations(m, their_sid, conv)))
    goto end;
  if (meshms_failed(status = get_database_conversations(id, their_sid, conv)))
    goto end;
  if ((status = update_conversations(id, conv)) == MESHMS_STATUS_UPDATED && their_sid == NULL)
    status = write_known_conversations(m, *conv);
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
  DEBUGF(meshms, "iter=%p me=%s them=%s", iter,
	 me ? alloca_tohex_sid_t(*me) : "NULL",
	 them ? alloca_tohex_sid_t(*them) : "NULL"
	);
  enum meshms_status status = MESHMS_STATUS_ERROR;
  bzero(iter, sizeof *iter);

  keyring_identity *id = keyring_find_identity_sid(keyring, me);
  if (!id){
    status = MESHMS_STATUS_SID_LOCKED;
    WHY("Identity not found");
    goto fail;
  }

  if (meshms_failed(status = find_or_create_conv(id, them, &iter->_conv)))
    goto fail;
  assert(iter->_conv != NULL);
  iter->identity = id;
  iter->_my_sid = *me;
  iter->my_sid = &iter->_my_sid;
  iter->their_sid = &iter->_conv->them;
  iter->my_ply_bid = &iter->_conv->my_ply.bundle_id;
  iter->their_ply_bid = &iter->_conv->their_ply.bundle_id;
  iter->read_offset = iter->_conv->read_offset;
  iter->timestamp = 0;
  // If I have never sent a message (or acked any of theirs), there are no messages in the thread.
  if (iter->_conv->my_ply.found) {
    int r = message_ply_read_open(&iter->_my_reader, &iter->_conv->my_ply.bundle_id);
    if (r != 0)
      goto error;
    if (iter->_conv->their_ply.found) {
      r = message_ply_read_open(&iter->_their_reader, &iter->_conv->their_ply.bundle_id);
      if (r != 0)
	goto error;
      // Find their latest ACK so we know which of my messages have been delivered.
      if (message_ply_find_prev(&iter->_their_reader, MESSAGE_BLOCK_TYPE_ACK)==0){
	if (unpack_uint(iter->_their_reader.record, iter->_their_reader.record_length, &iter->latest_ack_my_offset) == -1)
	  iter->latest_ack_my_offset = 0;
	else{
	  iter->latest_ack_offset = iter->_their_reader.record_end_offset;
	  DEBUGF(meshms, "Found their last ack @%"PRId64, iter->latest_ack_offset);
	}
      }
      // Re-seek to end of their ply.
      iter->_their_reader.read.offset = iter->_their_reader.read.length;
    }
  } else {
    DEBUGF(meshms, "Did not find sender's ply; no messages in thread");
  }
  iter->_in_ack = 0;
  return MESHMS_STATUS_OK;
error:
  status = MESHMS_STATUS_ERROR;
fail:
  meshms_message_iterator_close(iter);
  return status;
}

int meshms_message_iterator_is_open(const struct meshms_message_iterator *iter)
{
  return iter->_conv != NULL;
}

void meshms_message_iterator_close(struct meshms_message_iterator *iter)
{
  DEBUGF(meshms, "iter=%p", iter);
  message_ply_read_close(&iter->_my_reader);
  message_ply_read_close(&iter->_their_reader);
  meshms_free_conversations(iter->_conv);
  iter->_conv = NULL;
}

enum meshms_status meshms_message_iterator_prev(struct meshms_message_iterator *iter)
{
  assert(iter->_conv != NULL);
  enum meshms_status status = MESHMS_STATUS_UPDATED;
  while (status == MESHMS_STATUS_UPDATED) {
    if (iter->_in_ack) {
      DEBUGF(meshms, "Reading other log from %"PRId64", to %"PRId64, iter->_their_reader.read.offset, iter->_end_range);
      // eof or other read errors, skip over messages (the tail is allowed to advance)
      if (message_ply_read_prev(&iter->_their_reader)==0){
	iter->which_ply = THEIR_PLY;
	if (iter->_their_reader.read.offset >= iter->_end_range) {
	  switch (iter->_their_reader.type) {
	    case MESSAGE_BLOCK_TYPE_ACK:
	      iter->type = ACK_RECEIVED;
	      iter->offset = iter->_their_reader.record_end_offset;
	      iter->text = NULL;
	      iter->text_length = 0;
	      if (unpack_uint(iter->_their_reader.record, iter->_their_reader.record_length, &iter->ack_offset) == -1)
		iter->ack_offset = 0;
	      iter->read = 0;
	      return status;
	    case MESSAGE_BLOCK_TYPE_MESSAGE:
	      iter->type = MESSAGE_RECEIVED;
	      iter->offset = iter->_their_reader.record_end_offset;
	      iter->text = (const char *)iter->_their_reader.record;
	      iter->text_length = iter->_their_reader.record_length;
	      if (   iter->_their_reader.record_length != 0
		  && iter->_their_reader.record[iter->_their_reader.record_length - 1] == '\0'
	      ) {
		iter->read = iter->_their_reader.record_end_offset <= iter->_conv->read_offset;
		return status;
	      }
	      WARN("Malformed MeshMS2 ply journal, missing NUL terminator");
	      return MESHMS_STATUS_PROTOCOL_FAULT;
	  }
	  continue;
	}
      }
      iter->_in_ack = 0;
      status = MESHMS_STATUS_UPDATED;
    }else if (message_ply_read_prev(&iter->_my_reader) == 0) {
      DEBUGF(meshms, "Offset %"PRId64", type %d, read_offset %"PRId64, iter->_my_reader.read.offset, iter->_my_reader.type, iter->read_offset);
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
	  if (iter->_conv->their_ply.found) {
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
	    // just in case we don't have the full bundle anymore
	    if (iter->_their_reader.read.offset > iter->_their_reader.read.length)
	      iter->_their_reader.read.offset = iter->_their_reader.read.length;
	    iter->_in_ack = 1;
	  }
	  break;
	case MESSAGE_BLOCK_TYPE_MESSAGE:
	  iter->type = MESSAGE_SENT;
	  iter->offset = iter->_my_reader.record_end_offset;
	  iter->text = (const char *)iter->_my_reader.record;
	  iter->text_length = iter->_my_reader.record_length;
	  iter->delivered = iter->latest_ack_my_offset && iter->_my_reader.record_end_offset <= iter->latest_ack_my_offset;
	  return status;
      }
    }else{
      status = MESHMS_STATUS_OK;
    }
  }
  return status;
}

enum meshms_status meshms_send_message(const sid_t *sender, const sid_t *recipient, const char *message, size_t message_len)
{
  assert(message_len != 0);
  if (message_len > MESSAGE_PLY_MAX_LEN) {
    WHY("message too long");
    return MESHMS_STATUS_ERROR;
  }
  struct meshms_conversations *conv = NULL;
  enum meshms_status status = MESHMS_STATUS_ERROR;

  keyring_identity *id = keyring_find_identity_sid(keyring, sender);
  if (!id)
    return MESHMS_STATUS_SID_LOCKED;

  if (meshms_failed(status = find_or_create_conv(id, recipient, &conv)))
    goto end;

  assert(conv != NULL);

  // construct a message payload
  struct overlay_buffer *b = ob_new();
  message_ply_append_message(b, message, message_len);
  message_ply_append_timestamp(b);

  assert(!ob_overrun(b));

  if (message_ply_append(id, RHIZOME_SERVICE_MESHMS2, recipient, &conv->my_ply, b)==0)
    status = MESHMS_STATUS_UPDATED;

  ob_free(b);

end:
  meshms_free_conversations(conv);
  return status;
}

enum meshms_status meshms_mark_read(const sid_t *sender, const sid_t *recipient, uint64_t offset)
{
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
	 recipient ? alloca_tohex_sid_t(*recipient) : "NULL",
	 offset
	);
  m = rhizome_new_manifest();
  if (!m)
    goto end;
  if (meshms_failed(status = get_my_conversation_bundle(id, m)))
    goto end;
  // read all conversations, so we can write them again
  if (meshms_failed(status = read_known_conversations(m, NULL, &conv)))
    goto end;
  // read the full list of conversations from the database too
  if (meshms_failed(status = get_database_conversations(id, NULL, &conv)))
    goto end;
  // check if any incoming conversations need to be acked or have new messages and update the read offset
  unsigned changed = 0;
  if (meshms_failed(status = update_conversations(id, &conv)))
    goto end;
  if (status == MESHMS_STATUS_UPDATED)
    changed = 1;
  changed += mark_read(conv, recipient, offset);
  DEBUGF(meshms, "changed=%u", changed);
  if (changed) {
    if (meshms_failed(status = write_known_conversations(m, conv)))
      goto end;
    if (status != MESHMS_STATUS_UPDATED) {
      WHYF("expecting %d (MESHMS_STATUS_UPDATED), got %s", MESHMS_STATUS_UPDATED, status);
      status = MESHMS_STATUS_ERROR;
    }
  }
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
      if (new_offset > conv->their_last_message)
	new_offset = conv->their_last_message;
      if (new_offset > conv->read_offset) {
	DEBUGF(meshms, "Moving read marker for %s, from %"PRId64" to %"PRId64, 
	       alloca_tohex_sid_t(conv->them), conv->read_offset, new_offset
	      );
	conv->read_offset = new_offset;
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
