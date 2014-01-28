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

#include "serval.h"
#include "rhizome.h"

// the manifest details for one half of a conversation
struct meshms_ply {
  rhizome_bid_t bundle_id;
  uint64_t version;
  uint64_t tail;
  uint64_t size;
};

struct meshms_conversations {
  // binary tree
  struct meshms_conversations *_left;
  struct meshms_conversations *_right;
  // keeping a pointer to parent node here means the traversal iterator does not need a stack, so
  // there is no fixed limit on the tree depth
  struct meshms_conversations *_parent;
  
  // who are we talking to?
  sid_t them;
  
  char found_my_ply;
  struct meshms_ply my_ply;
  
  char found_their_ply;
  struct meshms_ply their_ply;
  
  // what is the offset of their last message
  uint64_t their_last_message;
  // what is the last message we marked as read
  uint64_t read_offset;
  // our cached value for the last known size of their ply
  uint64_t their_size;
};

// cursor state for reading one half of a conversation
struct meshms_ply_read {
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

/* Fetch the list of all MeshMS conversations into a binary tree whose nodes
 * are all allocated by malloc(3).
 */
int meshms_conversations_list(const sid_t *my_sid, const sid_t *their_sid, struct meshms_conversations **conv);
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
 * plys threaded (interleaved) in the order as seen by the sender.
 *
 *      struct meshms_message_iterator it;
 *      if (meshms_message_iterator_open(&it, &sender_sid, &recip_sid) == -1)
 *          return -1;
 *      int ret;
 *      while ((ret = meshms_message_iterator_prev(&it)) == 0) {
 *          ...
 *      }
 *      meshms_message_iterator_close(&it);
 *      if (ret == -1)
 *          return -1;
 *      ...
 */
struct meshms_message_iterator {
  // Public fields that remain fixed for the life of the iterator.
  uint64_t recipient_ack_offset; // offset in recipient ply of most recent ack
  uint64_t sent_ack_offset; // offset in sender ply of most recent message acked by recipient
  uint64_t received_read_offset; // offset in recipient ply of most recent message read by (displayed to) sender
  // Public fields that change per message.
  uint64_t offset;
  const char *text; // NUL terminated text of message
  enum { SENT, RECEIVED } direction;
  union {
    bool_t delivered; // for SENT
    bool_t read; // for RECEIVED
  };
  // Private implementation -- could change, so don't use them.
  struct meshms_conversations *_conv;
  rhizome_manifest *_manifest_sender;
  rhizome_manifest *_manifest_recipient;
  struct meshms_ply_read _read_sender;
  struct meshms_ply_read _read_recipient;
  uint64_t _end_range;
  bool_t _in_ack;
};
int meshms_message_iterator_open(struct meshms_message_iterator *, const sid_t *sender, const sid_t *recipient);
void meshms_message_iterator_close(struct meshms_message_iterator *);
int meshms_message_iterator_prev(struct meshms_message_iterator *);

#endif // __SERVAL_DNA__MESHMS_H
