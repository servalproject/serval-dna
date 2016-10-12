/*
Serval DNA
Copyright (C) 2012-2015 Serval Project Inc.
Copyright (C) 2016 Flinders University

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

#include <stdint.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include "mem.h"
#include "nibble_tree.h"

static uint8_t get_nibble(const uint8_t *binary, int pos)
{
  uint8_t byte = binary[pos>>1];
  if (!(pos&1))
    byte=byte>>4;
  return byte&0xF;
}

enum tree_error_reason tree_find(struct tree_root *root, void **result, const uint8_t *binary, size_t bin_length,
  tree_create_callback create_node, void *context)
{
  assert(bin_length <= root->binary_length);
  struct tree_node *ptr = &root->_root_node;

  if (result)
    *result = NULL;

  unsigned pos=0;
  while(1) {
    if (pos>>1 >= bin_length)
      return TREE_NOT_UNIQUE;

    uint8_t nibble = get_nibble(binary, pos++);
    void *node_ptr = ptr->tree_nodes[nibble];

    if (ptr->is_tree & (1<<nibble)){
      // search the next level of the tree
      ptr = (struct tree_node *)node_ptr;

    }else if(!node_ptr){
      // allow caller to provide a node constructor
      if (create_node && bin_length == root->binary_length){
	node_ptr = create_node(context, binary, bin_length);
	if (!node_ptr)
	  return TREE_ERROR;
	struct tree_record *tree_record = (struct tree_record *)node_ptr;
	assert(memcmp(tree_record->binary, binary, bin_length) == 0);
	tree_record ->tree_depth = pos*4;
	if (result)
	  *result = node_ptr;
	ptr->tree_nodes[nibble] = node_ptr;
	return TREE_FOUND;
      }
      return TREE_NOT_FOUND;

    }else{
      struct tree_record *tree_record = (struct tree_record *)node_ptr;

      // check that the remaining bytes of the value are the same
      if (memcmp(tree_record->binary, binary, bin_length) == 0){
	if (result)
	  *result = node_ptr;
	return TREE_FOUND;
      }

      if (!create_node)
	return TREE_NOT_FOUND;

      // no match? we need to bump this leaf node down a level so we can create a new record
      struct tree_node *new_node = (struct tree_node *) emalloc_zero(sizeof(struct tree_node));
      if (!new_node)
	return TREE_ERROR;

      ptr->tree_nodes[nibble] = new_node;
      ptr->is_tree |= (1<<nibble);
      ptr = new_node;

      // get the nibble of the existing node
      nibble = get_nibble(tree_record->binary, pos);
      tree_record->tree_depth = (pos+1)*4;
      ptr->tree_nodes[nibble] = node_ptr;
    }
  }
}

static int walk(struct tree_node *node, unsigned pos,
	      uint8_t *empty, const uint8_t *binary, size_t bin_length,
	      walk_callback callback, void *context){
  unsigned i=0, e=16;
  int ret=0;
  *empty=1;

  if (binary){
    assert(pos*2 < bin_length);
    uint8_t n = get_nibble(binary, pos);
    for(;i<n;i++){
      if (node->tree_nodes[i]){
	*empty=0;
	break;
      }
    }
  }

  for (;i<e;i++){
    if (node->is_tree & (1<<i)){
      uint8_t child_empty=1;
      ret = walk((struct tree_node *)node->tree_nodes[i], pos+1, &child_empty, binary, bin_length, callback, context);
      if (child_empty){
	free(node->tree_nodes[i]);
	node->tree_nodes[i]=NULL;
	node->is_tree&=~(1<<i);
      }
    }else if(node->tree_nodes[i]){
      ret = callback(&node->tree_nodes[i], context);
    }
    if (ret)
      return ret;
    if (node->tree_nodes[i])
      *empty=0;
    // stop comparing the start binary after looking at the first branch of the tree
    binary=NULL;
  }

  return ret;
}

// start enumerating the tree from binary, and continue until the end
// callback is allowed to free any nodes while the walk is in progress
int tree_walk(struct tree_root *root, const uint8_t *binary, size_t bin_length, walk_callback callback, void *context)
{
  assert(!binary || bin_length <= root->binary_length);
  uint8_t ignore;
  return walk(&root->_root_node, 0, &ignore, binary, bin_length, callback, context);
}

int tree_walk_prefix(struct tree_root *root, const uint8_t *binary, size_t bin_length, walk_callback callback, void *context)
{
  assert(bin_length <= root->binary_length);
  //TODO if callback free's nodes, collapse parent tree nodes too without needing to walk again?
  struct tree_node *node = &root->_root_node;
  unsigned pos=0;
  // look for a branch of the tree with a partial match
  for (; node && pos<bin_length*2; pos++){
    uint8_t i=get_nibble(binary, pos);
    if ((node->is_tree & (1<<i))==0){
      struct tree_record *tree_record = (struct tree_record *)node->tree_nodes[i];
      // only one match?
      if (tree_record && memcmp(tree_record->binary, binary, bin_length)==0){
	return callback(&node->tree_nodes[i], context);
      }
      return 0;
    }
    node = node->tree_nodes[i];
  }
  // walk the whole branch
  uint8_t ignore;
  return walk(node, pos+1, &ignore, NULL, 0, callback, context);
}
