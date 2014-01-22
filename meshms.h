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

/* Fetch the list of all MeshMS conversations into a binary tree whose nodes
 * are all allocated by malloc(3).
 */
int meshms_conversations_list(const sid_t *my_sid, const sid_t *their_sid, struct meshms_conversations **conv);
void meshms_free_conversations(struct meshms_conversations *conv);

/* For iterating over a binary tree of all MeshMS conversations, as created by
 * meshms_conversations_list().
 */
struct meshms_conversation_iterator {
  struct meshms_conversations *current;
};
void meshms_conversation_iterator_start(struct meshms_conversation_iterator *, struct meshms_conversations *);
void meshms_conversation_iterator_advance(struct meshms_conversation_iterator *);

#endif // __SERVAL_DNA__MESHMS_H
