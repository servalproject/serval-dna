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

#ifndef __SERVAL_DNA__NIBBLE_TREE_H
#define __SERVAL_DNA__NIBBLE_TREE_H

#include <stdint.h> // for uint8_t, size_t

// Every record in a nibble tree has the following structure:
// - a count of the number of bits in the binary index
// - the binary index itself, consisting of the number of bytes as specified by
//   root.binary_size_bytes
// - the rest of the record
struct tree_record {
  size_t binary_size_bits;
  uint8_t binary[0];
};

// Each node in the nibble tree has 16 slots based on the next 4 bits of the
// binary value.
struct tree_node {
  // A reference count that is incremented by an iterator while it has a
  // pointer to the node, and decremented when it discards the pointer.  The
  // iterator free()s the node if its count decrements to zero and all of its
  // slots are NULL.  This prevents nodes being free()d while in-use.
  unsigned ref_count;

  // A bitmask that has tbe bit (1 << slot_number) set if the corresponding
  // slot points to a sub-tree.
  uint16_t is_tree;

  // Each slot either points to another tree node or a data record, depending
  // on its corresponding bit in 'is_tree'.
  void *slot[16];
};

// The root of a nibble tree specifies the binary index size, in bytes, and
// contains the root node.
struct tree_root {
  size_t index_size_bytes;
  struct tree_node _root_node;
};

enum tree_error_reason {
  TREE_NOT_UNIQUE = -3,
  TREE_NOT_FOUND = -2,
  TREE_ERROR = -1,
  TREE_FOUND = 0
};

// allocate a new record and return it
// the returned memory buffer *must* begin with the same memory layout as struct tree_record
typedef void* (*tree_create_callback) (void *context, const uint8_t *binary, size_t binary_size_bytes);

// find the record related to the given binary value
// if not found, the supplied create_node function will be called
// if the callback returns a non-null value it will be inserted into the tree
// returns either the current depth in the tree or a tree_error_reason
enum tree_error_reason tree_find(struct tree_root *root, void **result, const uint8_t *binary, size_t binary_size_bytes,
  tree_create_callback create_node, void *context);

// Iteration:
//
//      tree_iterator it;
//      tree_iterator_advance_to(&it, index, sizeof index); // optional
//      node_type **node;
//      for (tree_iterator_start(&it, root); (node = tree_iterator_get_node(&it)); tree_iterator_advance(&it)) {
//          ..
//      }
//      tree_iterator_free(&it);
//
// An iterator advances through nodes in order of ascending binary index.
//
// The tree_iterator_get_node() function returns the same pointer on all
// successive invocations until tree_iterator_advance() is called, and returns
// NULL once the iterator has been advanced past the last node.
//
// The tree_iterator_advance_to() function rapidly positions the iterator at
// the first node whose binary index is >= the given binary index.  This
// function can only be called once, straight after tree_iterator_start().
//
// Deletion:
//
//      tree_iterator it;
//      tree_iterator_start(&it, root);
//      ...
//      node_type **node = tree_iterator_get_node(&it));
//      *node = NULL;
//      node = tree_iterator_get_node(&it)); // returns the next node
//      ...
//      tree_iterator_free(&it);
//
// The tree_iterator_get_node(), tree_iterator_advance() and
// tree_iterator_free() functions all free() empty nodes as long as no other
// iterator is currently traversing the node.  If there are several iterators
// positioned within an empty node, then only the last one to advance out of it
// will free() the node.

typedef struct tree_node_iterator {
  struct tree_node_iterator *down;
  struct tree_node *node;
  unsigned slotnum;
} tree_node_iterator;

typedef struct tree_iterator {
  struct tree_node_iterator bottom;
  struct tree_node_iterator *stack;
} tree_iterator;

void tree_iterator_start(tree_iterator *it, struct tree_root *root);
void tree_iterator_advance_to(tree_iterator *it, const uint8_t *binary, size_t binary_size_bytes);
void **tree_iterator_get_node(tree_iterator *it);
void tree_iterator_advance(tree_iterator *it);
void tree_iterator_free(tree_iterator *it);

// The following legacy API functions are now implemented using iterators.

// callback function for walking the tree
// return 0 to continue enumeration, anything else to stop
// set (*record) to null to indicate that memory has been released and the node should be removed from the tree
typedef int (*walk_callback) (void **record, void *context);

// walk the tree, calling walk_callback for each node.
// if binary & binary_size_bytes have been supplied, skip all records < this binary value
int tree_walk(struct tree_root *root, const uint8_t *binary, size_t binary_size_bytes, walk_callback callback, void *context);

// walk the tree where nodes match the prefix binary / binary_size_bytes
int tree_walk_prefix(struct tree_root *root, const uint8_t *binary, size_t binary_size_bytes, walk_callback callback, void *context);

// Tree statistics.

struct tree_statistics {
  size_t record_count;
  size_t node_count;
  size_t empty_node_count;
  size_t maximum_depth;
};

struct tree_statistics tree_compute_statistics(struct tree_root *root);

#endif // __SERVAL_DNA__NIBBLE_TREE_H
