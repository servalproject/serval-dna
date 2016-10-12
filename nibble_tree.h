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

#ifndef __SERVAL_DNA__NIBBLE_TREE_H
#define __SERVAL_DNA__NIBBLE_TREE_H

struct tree_record{
  // number of bits of the binary value, to uniquely identify this record within the tree's current contents
  size_t tree_depth;
  uint8_t binary[0];
};

// each node has 16 slots based on the next 4 bits of the binary value
// each slot either points to another tree node or a data record
struct tree_node{
  // bit flags for the type of object each element points to
  uint16_t is_tree;
  void  *tree_nodes[16];
};

struct tree_root{
  size_t binary_length;
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
typedef void* (*tree_create_callback) (void *context, const uint8_t *binary, size_t bin_length);

// find the record related to the given binary value
// if not found, the supplied not_found function will be called
// if the callback returns a non-null value it will be inserted into the tree
// returns either the current depth in the tree or a tree_error_reason
enum tree_error_reason tree_find(struct tree_root *root, void **result, const uint8_t *binary, size_t bin_length,
  tree_create_callback create_node, void *context);

// callback function for walking the tree
// return 0 to continue enumeration, anything else to stop
// set (*record) to null to indicate that memory has been released and the node should be removed from the tree
typedef int (*walk_callback) (void **record, void *context);

// walk the tree, calling walk_callback for each node.
// if binary & bin_length have been supplied, skip all records <= this binary value
int tree_walk(struct tree_root *root, const uint8_t *binary, size_t bin_length, walk_callback callback, void *context);

// walk the tree where nodes match the prefix binary / bin_length
int tree_walk_prefix(struct tree_root *root, const uint8_t *binary, size_t bin_length, walk_callback callback, void *context);

#endif // __SERVAL_DNA__NIBBLE_TREE_H
