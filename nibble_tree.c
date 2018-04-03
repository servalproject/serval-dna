/*
Serval DNA
Copyright (C) 2012-2015 Serval Project Inc.
Copyright (C) 2016-2018 Flinders University

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
#include <strings.h>
#include "lang.h" // for bool_t
#include "mem.h"
#include "nibble_tree.h"

static unsigned get_nibble(const uint8_t *binary, int pos)
{
  unsigned byte = binary[pos>>1];
  if (!(pos&1))
    byte=byte>>4;
  return byte&0xF;
}

enum tree_error_reason tree_find(struct tree_root *root, void **result, const uint8_t *binary, size_t binary_size_bytes,
  tree_create_callback create_node, void *context)
{
  assert(binary_size_bytes <= root->index_size_bytes);
  struct tree_node *ptr = &root->_root_node;

  if (result)
    *result = NULL;

  unsigned pos=0;
  while(1) {
    if (pos >= binary_size_bytes * 2)
      return TREE_NOT_UNIQUE;

    unsigned nibble = get_nibble(binary, pos++);
    void *node_ptr = ptr->slot[nibble];

    if (ptr->is_tree & (1<<nibble)){
      // search the next level of the tree
      ptr = (struct tree_node *)node_ptr;

    }else if(!node_ptr){
      // allow caller to provide a node constructor
      if (create_node && binary_size_bytes == root->index_size_bytes){
	node_ptr = create_node(context, binary, binary_size_bytes);
	if (!node_ptr)
	  return TREE_ERROR;
	struct tree_record *tree_record = (struct tree_record *)node_ptr;
	assert(memcmp(tree_record->binary, binary, binary_size_bytes) == 0);
	tree_record->binary_size_bits = pos*4;
	if (result)
	  *result = node_ptr;
	ptr->slot[nibble] = node_ptr;
	return TREE_FOUND;
      }
      return TREE_NOT_FOUND;

    }else{
      struct tree_record *tree_record = (struct tree_record *)node_ptr;

      // check that the remaining bytes of the value are the same
      if (memcmp(tree_record->binary, binary, binary_size_bytes) == 0){
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

      ptr->slot[nibble] = new_node;
      ptr->is_tree |= (1<<nibble);
      ptr = new_node;

      // get the nibble of the existing node
      nibble = get_nibble(tree_record->binary, pos);
      tree_record->binary_size_bits = (pos+1)*4;
      ptr->slot[nibble] = node_ptr;
    }
  }
}

void tree_iterator_start(tree_iterator *it, struct tree_root *root)
{
  it->stack = &it->bottom;
  it->bottom.down = NULL;
  it->bottom.node = &root->_root_node;
  it->bottom.slotnum = 0;
  root->_root_node.ref_count++;
}

static bool_t push(tree_iterator *it)
{
  assert(it->stack->node->is_tree & (1 << it->stack->slotnum));
  struct tree_node *child = it->stack->node->slot[it->stack->slotnum];
  assert(child);
  tree_node_iterator *nit = (tree_node_iterator *) emalloc_zero(sizeof(tree_node_iterator));
  if (!nit)
    return 0;
  nit->down = it->stack;
  nit->node = child;
  nit->slotnum = 0;
  it->stack = nit;
  child->ref_count++;
  return 1;
}

static inline bool_t is_empty(struct tree_node *node)
{
  unsigned i;
  for (i = 0; i < 16; ++i)
    if (node->slot[i])
      return 0;
  return 1;
}

static void pop(tree_iterator *it)
{
  assert(it->stack);
  assert(it->stack->node->ref_count != 0);
  tree_node_iterator *popped = it->stack;
  it->stack = it->stack->down;
  if (--popped->node->ref_count == 0 && it->stack && is_empty(popped->node)) {
    assert(it->stack->slotnum < 16);
    assert(it->stack->node->is_tree & (1 << it->stack->slotnum));
    assert(it->stack->node->slot[it->stack->slotnum] == popped->node);
    if (it->stack) {
      assert(popped != &it->bottom);
      assert(popped->node != it->bottom.node);
      free(popped->node);
    }
    else {
      assert(popped == &it->bottom);
      assert(popped->node == it->bottom.node);
    }
    popped->node = NULL;
    it->stack->node->slot[it->stack->slotnum] = NULL;
    it->stack->node->is_tree &= ~(1 << it->stack->slotnum);
  }
  if (it->stack) {
    free(popped);
    it->stack->slotnum++;
  }
  else
    assert(popped == &it->bottom);
}

void tree_iterator_advance_to(tree_iterator *it, const uint8_t *binary, size_t binary_size_bytes)
{
  // can only call this function once on an iterator, straight after tree_iterator_start()
  assert(it->stack == &it->bottom);
  assert(it->stack->slotnum == 0);
  assert(it->stack->node);
  unsigned n;
  for (n = 0; n < binary_size_bytes * 2; ++n) {
    it->stack->slotnum = get_nibble(binary, n);
    if (!((it->stack->node->is_tree & (1 << it->stack->slotnum)) && push(it)))
      break;
  }
}

void **tree_iterator_get_node(tree_iterator *it)
{
  while (it->stack) {
    if (it->stack->slotnum < 16) {
      if (it->stack->node->is_tree & (1 << it->stack->slotnum)) {
	if (!push(it))
	  return NULL;
      }
      else {
	void **childp = &it->stack->node->slot[it->stack->slotnum];
	if (*childp)
	  return childp;
	else
	  it->stack->slotnum++;
      }
    }
    else {
      assert(it->stack->slotnum == 16);
      pop(it);
    }
  }
  return NULL;
}

void tree_iterator_advance(tree_iterator *it)
{
  if (tree_iterator_get_node(it)) {
    assert(it->stack);
    assert(it->stack->slotnum < 16);
    it->stack->slotnum++;
  }
}

void tree_iterator_free(tree_iterator *it)
{
  while (it->stack)
    pop(it);
}

// start enumerating the tree from binary, and continue until the end
// callback is allowed to free any nodes while the walk is in progress
int tree_walk(struct tree_root *root, const uint8_t *binary, size_t binary_size_bytes, walk_callback callback, void *context)
{
  int ret = 0;
  tree_iterator it;
  tree_iterator_start(&it, root);
  if (binary) {
    assert(binary_size_bytes <= root->index_size_bytes);
    tree_iterator_advance_to(&it, binary, binary_size_bytes);
  }
  void **node;
  while ((node = tree_iterator_get_node(&it)) && (ret = callback(node, context)) == 0)
      tree_iterator_advance(&it);
  tree_iterator_free(&it);
  return ret;
}

int tree_walk_prefix(struct tree_root *root, const uint8_t *binary, size_t binary_size_bytes, walk_callback callback, void *context)
{
  assert(binary);
  assert(binary_size_bytes <= root->index_size_bytes);
  int ret = 0;
  tree_iterator it;
  tree_iterator_start(&it, root);
  tree_iterator_advance_to(&it, binary, binary_size_bytes);
  void **node;
  while (   (node = tree_iterator_get_node(&it))
	 && memcmp(((struct tree_record *)*node)->binary, binary, binary_size_bytes) == 0
	 && (ret = callback(node, context)) == 0)
      tree_iterator_advance(&it);
  tree_iterator_free(&it);
  return ret;
}

static void walk_statistics(struct tree_node *node, unsigned depth, struct tree_statistics *stats)
{
  stats->node_count++;
  if (depth > stats->maximum_depth)
    stats->maximum_depth = depth;
  if (is_empty(node))
    stats->empty_node_count++;
  unsigned i;
  for (i = 0; i < 16; ++i)
    if (node->is_tree & (1 << i))
      walk_statistics(node->slot[i], depth + 1, stats);
    else if (node->slot[i])
      stats->record_count++;
}

struct tree_statistics tree_compute_statistics(struct tree_root *root)
{
  struct tree_statistics stats;
  bzero(&stats, sizeof stats);
  walk_statistics(&root->_root_node, 0, &stats);
  return stats;
}
