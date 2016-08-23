/*
Serval DNA MeshMS
Copyright (C) 2014 Serval Project Inc.
 
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

#ifndef __SERVAL_DNA__MESHMS_H
#define __SERVAL_DNA__MESHMS_H

#ifndef __MESHMS_INLINE
# if __GNUC__ && !__GNUC_STDC_INLINE__
#  define __MESHMS_INLINE extern inline
# else
#  define __MESHMS_INLINE inline
# endif
#endif

#include "rhizome.h"
#include "message_ply.h"

/* The result of a MeshMS operation.  Negative indicates failure, zero or
 * positive success.
 */
enum meshms_status {
    MESHMS_STATUS_ERROR = -1, // unexpected error (underlying failure)
    MESHMS_STATUS_OK = 0, // operation succeeded, no bundle changed
    MESHMS_STATUS_UPDATED = 1, // operation succeeded, bundle updated
    MESHMS_STATUS_SID_LOCKED = 2, // cannot decode or send messages for that SID
    MESHMS_STATUS_PROTOCOL_FAULT = 3, // missing or faulty ply bundle
};

__MESHMS_INLINE int meshms_failed(enum meshms_status status) {
    return status != MESHMS_STATUS_OK && status != MESHMS_STATUS_UPDATED;
}

const char *meshms_status_message(enum meshms_status);

struct meshms_metadata{
  // what is the offset of their last message
  uint64_t their_last_message;
  // what is the offset of their last ack
  uint64_t their_last_ack_offset;
  // where in our ply, does their ack point
  uint64_t their_last_ack;
  // what is the last message we marked as read
  uint64_t read_offset;
  // our cached value for the last known size of their ply
  uint64_t their_size;

  // where in their ply, does our last ack point
  uint64_t my_last_ack;
  // our cached value for the last known size of our ply
  uint64_t my_size;
};

struct meshms_conversations {
  struct meshms_conversations *_next;
  
  // who are we talking to?
  sid_t them;
  
  struct message_ply my_ply;
  struct message_ply their_ply;

  struct meshms_metadata metadata;

  uint8_t blocked:1;
  uint8_t known:1;
};

/* Fetch the list of all MeshMS conversations into a binary tree whose nodes
 * are all allocated by malloc(3).
 */
enum meshms_status meshms_conversations_list(const struct keyring_identity *id, const sid_t *my_sid, struct meshms_conversations **conv);
void meshms_free_conversations(struct meshms_conversations *conv);

/* For iterating over a binary tree of all MeshMS conversations, as created by
 * meshms_conversations_list().
 *
 *      struct meshms_conversation_iterator it;
 *      meshms_conversation_iterator_start(&it, conv);
 *      while (it.current) {
 *          ...
 *          meshms_conversation_iterator_advance(&it);
 *      }
 */
struct meshms_conversation_iterator {
  struct meshms_conversations *current;
};
void meshms_conversation_iterator_start(struct meshms_conversation_iterator *, struct meshms_conversations *);
void meshms_conversation_iterator_advance(struct meshms_conversation_iterator *);

/* For iterating through the messages in a single MeshMS conversation; both
 * plys threaded (interleaved) in the order as seen by the sender.  The
 * meshms_message_iterator_prev() function returns MESHMS_STATUS_UPDATED if it
 * advances the iterator to a message, or MESHMS_STATUS_OK if there are no more
 * messages.  Any other return value indicates failure.
 *
 *      struct meshms_message_iterator it;
 *      enum meshms_status status;
 *      if (meshms_failed(status = meshms_message_iterator_open(&it, &sender_sid, &recip_sid)))
 *          return -1;
 *      while ((status = meshms_message_iterator_prev(&it)) == MESHMS_STATUS_UPDATED) {
 *          ...
 *      }
 *      meshms_message_iterator_close(&it);
 *      if (meshms_failed(status))
 *          return -1;
 *      ...
 */
struct meshms_message_iterator {
  // Public fields that remain fixed for the life of the iterator:
  struct keyring_identity *identity;
  sid_t my_sid;
  sid_t their_sid;

  struct message_ply my_ply;
  struct message_ply their_ply;

  struct meshms_metadata metadata;

  // The following public fields change per message:
  enum meshms_which_ply { NEITHER_PLY, MY_PLY, THEIR_PLY } which_ply;
  enum { MESSAGE_SENT, MESSAGE_RECEIVED, ACK_RECEIVED } type;
  // For MESSAGE_SENT 'offset' is the byte position within the local ply
  // (mine).  For MESSAGE_RECEIVED and ACK_RECEIVED, it is the byte position
  // within the remote ply (theirs).
  time_s_t timestamp;
  uint64_t offset;
  const char *text; // text of UTF8 message (NUL terminated)
  size_t text_length; // excluding terminating NUL
  union {
    bool_t delivered; // for MESSAGE_SENT
    bool_t read; // for MESSAGE_RECEIVED
    uint64_t ack_offset; // for ACK_RECEIVED
  };
  // Private implementation -- could change, so don't use them.
  struct message_ply_read _my_reader;
  struct message_ply_read _their_reader;
  uint64_t _end_range;
  uint8_t _in_ack:1;
};
enum meshms_status meshms_message_iterator_open(struct meshms_message_iterator *, const sid_t *me, const sid_t *them);
void meshms_message_iterator_close(struct meshms_message_iterator *);
enum meshms_status meshms_message_iterator_prev(struct meshms_message_iterator *);

/* Append a message ('message_len' bytes of UTF8 at 'message') to the sender's
 * ply in the conversation between 'sender' and 'recipient'.  If no
 * conversation (ply bundle) exists, then create it.  Returns
 * MESHMS_STATUS_UPDATED on success, any other value indicates a failure or
 * error (which is already logged).
 */
enum meshms_status meshms_send_message(const sid_t *sender, const sid_t *recipient, uint8_t mark_known, const char *message, size_t message_len);

/* Update the read offset for one or more conversations.  Returns
 * MESHMS_STATUS_UPDATED on success, any other value indicates a failure or
 * error (which is already logged).
 *
 * If 'offset' is greater than a conversation's last-received offset, then it
 * is clamped to the last-received offset.  This means that passing an offset
 * of UINT64_MAX will mark the conversation as fully read, and an offset of
 * zero will have no effect.
 *
 * If 'recipient' is NULL then all of the sender's conversations are marked
 * with the given read offset.  In this case it only makes sense to pass an
 * offest of UINT64_MAX.
 */
enum meshms_status meshms_mark_read(const sid_t *sender, const sid_t *recipient, uint64_t offset);

#endif // __SERVAL_DNA__MESHMS_H
