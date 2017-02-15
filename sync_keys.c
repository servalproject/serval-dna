#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "sync_keys.h"
#include "mem.h"

// Definitions of what a key is

#define KEY_LEN_BITS (KEY_LEN<<3)

// Note PREFIX_STEP_BITS >1 hasn't been tested yet
#define NODE_CHILDREN (1<<PREFIX_STEP_BITS)
#define INTERESTING_COUNT 16

typedef struct {
  uint8_t min_prefix_len:7;
  uint8_t stored:1;
  uint8_t prefix_len;
  sync_key_t key;
}key_message_t;

#define MESSAGE_FROM_KEY(K) {.key=*K, .prefix_len=KEY_LEN_BITS}
#define MESSAGE_BYTES (KEY_LEN +2)

// definitions for how we track the state of a set of keys

#define NOT_SENT 0
#define SENT 1
#define QUEUED 2
#define DONT_SEND 3

struct node{
  struct node *transmit_next;
  struct node *transmit_prev;
  key_message_t message;
  uint8_t send_state;
  uint8_t sent_count;
  void *context;
  struct node *children[NODE_CHILDREN];
};

struct sync_peer_state{
  struct sync_peer_state *next;
  void *peer_context;
  unsigned send_count;
  unsigned recv_count;
  struct node *root;
};

struct sync_state{
  void *context;
  peer_has has;
  peer_does_not_have has_not;
  peer_now_has now_has;
  unsigned key_count;
  unsigned sent_root;
  unsigned sent_messages;
  unsigned sent_record_count;
  unsigned received_record_count;
  unsigned received_uninteresting;
  unsigned progress;
  struct sync_peer_state *peers;
  struct node *root;
  struct node *transmit_ptr;
};



// XOR the source key into the destination key
// the leading prefix_len bits of the source key will be copied, the remaining bits will be XOR'd
static void sync_xor(const sync_key_t *src_key, key_message_t *dest_key)
{
  unsigned i=0;

  assert(dest_key->prefix_len < KEY_LEN_BITS);

  // Assign whole prefix bytes
  for(;i<(dest_key->prefix_len>>3);i++)
    dest_key->key.key[i] = src_key->key[i];

  if (dest_key->prefix_len&7){
    // Mix assignment and xor for the byte of overlap
    uint8_t mask = (0xFF00>>(dest_key->prefix_len&7)) & 0xFF;
    dest_key->key.key[i] = (mask & src_key->key[i]) | (dest_key->key.key[i] ^ src_key->key[i]);
    i++;
  }

  // Xor whole remaining bytes
  for (;i<KEY_LEN;i++)
    dest_key->key.key[i] ^= src_key->key[i];
}

#define sync_xor_node(N,K) sync_xor((K), &(N)->message)

// return len bits from the key, starting at offset
static uint8_t sync_get_bits(uint8_t offset, uint8_t len, const sync_key_t *key)
{
  assert(len <= 8);
  assert(offset+len < KEY_LEN_BITS);
  unsigned start_byte = (offset>>3);
  uint16_t context = key->key[start_byte] <<8;
  if (start_byte+1 < KEY_LEN)
    context |= key->key[start_byte+1];
  return (context >> (16 - (offset & 7) - len)) & ((1<<len) -1);
}

#define MIN_VAL(X,Y) ((X)<(Y)?(X):(Y))
#define MAX_VAL(X,Y) ((X)<(Y)?(Y):(X))

// Compare two keys, returning zero if they represent the same set of leaf nodes.
static int cmp_message(const key_message_t *first, const key_message_t *second)
{
  uint8_t common_prefix_len = MIN_VAL(first->prefix_len, second->prefix_len);
  uint8_t first_xor_begin = (first->prefix_len == KEY_LEN_BITS)?first->min_prefix_len:first->prefix_len;
  uint8_t second_xor_begin = (second->prefix_len == KEY_LEN_BITS)?second->min_prefix_len:second->prefix_len;
  uint8_t xor_begin_offset = MAX_VAL(first_xor_begin, second_xor_begin);
  int ret=0;

  // TODO at least we can compare before common_prefix_len and after xor_begin_offset
  // But we aren't comparing the bits in the middle

  if (common_prefix_len < xor_begin_offset){
    if (common_prefix_len>=8 && memcmp(&first->key, &second->key, common_prefix_len>>3)!=0)
      ret = -1;
    else{
      uint8_t xor_begin_byte = (xor_begin_offset+7)>>3;
      if (xor_begin_byte < KEY_LEN && memcmp(&first->key.key[xor_begin_byte], &second->key.key[xor_begin_byte], KEY_LEN - xor_begin_byte)!=0)
	ret = -1;
    }
  }else{
    ret = memcmp(&first->key, &second->key, KEY_LEN);
  }
  return ret;
}

// XOR all existing children of *node, into this destination key.
static void xor_children(struct node *node, key_message_t *dest)
{
  if (node->message.prefix_len == KEY_LEN_BITS){
    sync_xor(&node->message.key, dest);
  }else{
    unsigned i;
    for (i=0;i<NODE_CHILDREN;i++){
      if (node->children[i])
	xor_children(node->children[i], dest);
    }
  }
}

// Add a new key into the state tree, XOR'ing the key into each parent node
static struct node *add_key(struct node **root, const sync_key_t *key, void *context, uint8_t stored)
{
  uint8_t prefix_len = 0;
  struct node **node = root;
  uint8_t min_prefix_len = prefix_len;
  while(*node){
    uint8_t child_index = sync_get_bits(prefix_len, PREFIX_STEP_BITS, key);

    if ((*node)->message.prefix_len == prefix_len){
      sync_xor_node((*node), key);

      if ((*node)->send_state == SENT)
	(*node)->send_state = NOT_SENT;
      if ((*node)->send_state == QUEUED && (*node)->sent_count>0)
	(*node)->send_state = DONT_SEND;

      // reset the send counter
      (*node)->sent_count=0;
      prefix_len += PREFIX_STEP_BITS;
      min_prefix_len = prefix_len;
      node = &(*node)->children[child_index];
      if (!*node)
	break;
      continue;
    }

    // this node represents a range of prefix bits
    uint8_t node_child_index = sync_get_bits(prefix_len, PREFIX_STEP_BITS, &(*node)->message.key);

    // if the prefix matches the key, keep searching.
    if (child_index == node_child_index){
      prefix_len += PREFIX_STEP_BITS;
      continue;
    }

    // if there is a mismatch in the range of prefix bits, we need to create a new node to represent the new range.
    struct node *parent = emalloc_zero(sizeof(struct node));
    parent->message.min_prefix_len = min_prefix_len;
    parent->message.prefix_len = prefix_len;
    parent->message.stored = stored;
    parent->children[node_child_index] = *node;

    min_prefix_len = prefix_len + PREFIX_STEP_BITS;
    assert(min_prefix_len <= (*node)->message.prefix_len);

    (*node)->message.min_prefix_len = min_prefix_len;

    // xor all the existing children of this node, we can't assume the prefix bits are right in the existing node.
    // we might be able to speed this up by using the prefix bits of the passed in key
    xor_children(parent, &parent->message);

    *node = parent;
  }
  // create final leaf node
  *node = emalloc_zero(sizeof(struct node));
  (*node)->message.key = *key;
  (*node)->message.min_prefix_len = min_prefix_len;
  (*node)->message.prefix_len = KEY_LEN_BITS;
  (*node)->message.stored = stored;
  (*node)->context = context;
  return (*node);
}

// Recursively free the memory used by this tree
static void free_node(struct sync_state *state, struct node *node)
{
  if (!node)
    return;
  unsigned i;
  for (i=0;i<NODE_CHILDREN;i++)
    free_node(state, node->children[i]);

  if (node->transmit_next){
    assert(state);
    assert(node->transmit_prev);

    if (node->transmit_next == node){
      assert(node->transmit_prev==node);
      state->transmit_ptr = NULL;
    }else{
      if (state->transmit_ptr == node)
	state->transmit_ptr = node->transmit_prev;
      node->transmit_next->transmit_prev = node->transmit_prev;
      node->transmit_prev->transmit_next = node->transmit_next;
    }
  }

  free(node);
}

static void remove_key(struct sync_state *state, struct node **root, const sync_key_t *key)
{
  uint8_t prefix_len = 0;
  struct node **node = root;
  struct node **parent = NULL;

  while((*node)->message.prefix_len != KEY_LEN_BITS){
    uint8_t child_index = sync_get_bits(prefix_len, PREFIX_STEP_BITS, key);

    // this node represents a range of prefix bits
    if (prefix_len < (*node)->message.prefix_len){
      uint8_t node_child_index = sync_get_bits(prefix_len, PREFIX_STEP_BITS, &(*node)->message.key);
      assert(child_index == node_child_index);
      prefix_len += PREFIX_STEP_BITS;
      continue;
    }

    sync_xor_node((*node), key);
    if ((*node)->send_state == SENT)
      (*node)->send_state = NOT_SENT;
    if ((*node)->send_state == QUEUED && (*node)->sent_count>0)
      (*node)->send_state = DONT_SEND;

    // reset the send counter
    (*node)->sent_count=0;

    parent = node;
    node = &(*node)->children[child_index];
    assert(*node);
    prefix_len += PREFIX_STEP_BITS;
  }

  free_node(state, (*node));
  *node = NULL;

  if (!parent)
    return;

  node = NULL;
  // If *parent has <= 1 child now, we need to remove *parent as well
  unsigned i;
  for (i=0;i<NODE_CHILDREN;i++){
    if ((*parent)->children[i]){
      if (node)
	return;
      node = &(*parent)->children[i];
    }
  }
  assert(node);

  struct node *c = *node;

  // remove child ptr so it isn't free'd
  *node = NULL;
  c->message.min_prefix_len = (*parent)->message.min_prefix_len;

  free_node(state, *parent);

  *parent = c;
}

// find the node which matches this key, or NULL
static const struct node * find_message(const struct node *node, const key_message_t *message)
{
  if (!node)
    return NULL;
  uint8_t prefix_len = node->message.prefix_len;

  while(1){
    if (cmp_message(&node->message, message)==0)
      return node;
    if (node->message.prefix_len == KEY_LEN_BITS)
      return NULL;

    uint8_t child_index = sync_get_bits(prefix_len, PREFIX_STEP_BITS, &message->key);

    if (prefix_len < node->message.prefix_len){
      // TODO optimise this case by comparing all possible prefix bits in one hit
      uint8_t node_index = sync_get_bits(prefix_len, PREFIX_STEP_BITS, &node->message.key);
      if (node_index != child_index)
	return NULL;
    }else{
      node = node->children[child_index];
      if (!node)
	return NULL;
    }
    prefix_len+=PREFIX_STEP_BITS;
  }
}

int sync_key_exists(const struct sync_state *state, const sync_key_t *key)
{
  key_message_t message = MESSAGE_FROM_KEY(key);
  return find_message(state->root, &message) ? 1:0;
}

int sync_has_transmit_queued(const struct sync_state *state)
{
  return state->transmit_ptr?1:0;
}

// returns NULL if the node already exists
static struct node * add_key_if_missing(struct node **root, const key_message_t *message, uint8_t stored)
{
  assert(message->prefix_len == KEY_LEN_BITS);
  if (find_message(*root, message)!=NULL)
    return NULL;
  return add_key(root, &message->key, NULL, stored);
}

void sync_add_key(struct sync_state *state, const sync_key_t *key, void *context)
{
  key_message_t message = MESSAGE_FROM_KEY(key);
  struct node *node = (struct node *)find_message(state->root, &message);
  if (node){
    node->message.stored = 1;
    node->context = context;
    return;
  }

  state->key_count++;
  state->progress=0;
  add_key(&state->root, key, context, 1);

  struct sync_peer_state *peer_state = state->peers;
  while(peer_state){
    if (find_message(peer_state->root, &message)){
      remove_key(state, &peer_state->root, key);
      peer_state->recv_count--;
    }
    peer_state = peer_state->next;
  }
}

void sync_free_peer_state(struct sync_state *state, void *peer_context){
  struct sync_peer_state **peer_state = &state->peers;
  while(*peer_state){
    if ((*peer_state)->peer_context == peer_context){
      struct sync_peer_state *free_peer = (*peer_state);
      free_node(state, free_peer->root);
      *peer_state = free_peer->next;
      free(free_peer);
      return;
    }
  }
}

struct sync_state* sync_alloc_state(void *context, peer_has has, peer_does_not_have has_not, peer_now_has now_has){
  struct sync_state *state = emalloc_zero(sizeof (struct sync_state));
  state->context = context;
  state->has = has;
  state->has_not = has_not;
  state->now_has = now_has;
  return state;
}

// clear all memory used by this state
void sync_free_state(struct sync_state *state){
  while(state->transmit_ptr){
    struct node *p = state->transmit_ptr;
    state->transmit_ptr = state->transmit_ptr->transmit_next;
    p->transmit_next=NULL;
    p->transmit_prev=NULL;
  }

  free_node(NULL, state->root);

  while(state->peers){
    struct sync_peer_state *peer_state = state->peers;

    free_node(NULL, peer_state->root);

    state->peers = peer_state->next;
    free(peer_state);
  }

  free(state);
}

static void copy_message(uint8_t *buff, const key_message_t *message)
{
  if (message){
    buff[0] = (message->stored?0x80:0) | (message->min_prefix_len & 0x7f);
    buff[1] = message->prefix_len;
    memcpy(&buff[2], &message->key.key[0], KEY_LEN);
  }else{
    bzero(buff, MESSAGE_BYTES);
    buff[0] = 0x80;
    buff[1] = KEY_LEN_BITS+1;
  }
}

// prepare a network packet buffer, with as many queued outgoing messages that we can fit
size_t sync_build_message(struct sync_state *state, uint8_t *buff, size_t len)
{
  size_t offset=0;
  state->sent_messages++;
  state->progress++;

  struct node *tail = state->transmit_ptr;

  while(tail && offset + MESSAGE_BYTES<=len){
    struct node *head = tail->transmit_next;
    assert(head->transmit_prev == tail);

    if (head->send_state == QUEUED){
      copy_message(&buff[offset], &head->message);
      offset+=MESSAGE_BYTES;
      head->sent_count++;
      state->sent_record_count++;
      if (head->sent_count>=SYNC_MAX_RETRIES)
	head->send_state = SENT;
    }

    if (head->send_state == QUEUED){
      // advance tail pointer
      tail = head;
    }else{
      struct node *next = head->transmit_next;
      head->transmit_next = NULL;
      head->transmit_prev = NULL;

      if (head == tail || next == head){
	// transmit loop is now empty
	tail = NULL;
	break;
      }else{
	// remove from the transmit loop
	tail->transmit_next = next;
	next->transmit_prev = tail;
      }
    }

    // stop if we just sent everything in the loop once.
    if (head == state->transmit_ptr)
      break;
  }

  state->transmit_ptr = tail;

  // If we don't have anything else to send, always send our root tree node
  if(offset + MESSAGE_BYTES<=len && offset==0){
    state->sent_root++;
    copy_message(&buff[offset], state->root ? &state->root->message : NULL);
    offset+=MESSAGE_BYTES;
    state->sent_record_count++;
  }


  return offset;
}

// prepare a network packet buffer, with no outgoing messages.
// Only used to advertise rhizome_sync_keys capability.
size_t sync_build_empty_message(uint8_t *buff, size_t len)
{
  assert(len >= MESSAGE_BYTES);

  copy_message(&buff[0], NULL);

  return MESSAGE_BYTES;
}


// Add a tree node into our transmission queue
// the node can be added to the head or tail of the list.
static void queue_node(struct sync_state *state, struct node *node, uint8_t head)
{
  node->send_state = QUEUED;
  if (node->transmit_next)
    return;

  if (node->message.prefix_len == KEY_LEN_BITS)
    state->progress=0;

  // insert this node into the transmit loop
  if (!state->transmit_ptr){
    state->transmit_ptr = node;
    node->transmit_next = node;
    node->transmit_prev = node;
  }else{
    node->transmit_next = state->transmit_ptr->transmit_next;
    node->transmit_prev = state->transmit_ptr;

    node->transmit_next->transmit_prev = node;
    node->transmit_prev->transmit_next = node;

    // advance past this node to transmit it last
    if (!head)
      state->transmit_ptr = node;
  }
}

static unsigned peer_is_missing(struct sync_state *state, struct sync_peer_state *peer, const struct node *node, uint8_t allow_remove)
{
  const struct node *peer_node = find_message(peer->root, &node->message);
  if (peer_node){
    if (peer_node->message.stored && allow_remove){
      // peer has now received this key?
      if (state->now_has)
	state->now_has(state->context, peer->peer_context, node->context, &node->message.key);
      remove_key(state, &peer->root, &node->message.key);
      peer->send_count --;
      return 1;
    }
    return 0;
  }

  add_key(&peer->root, &node->message.key, node->context, 1);
  peer->send_count ++;
  state->progress=0;
  if (state->has_not)
    state->has_not(state->context, peer->peer_context, node->context, &node->message.key);
  return 1;
}

// traverse the children of this node, and add them all to the transmit queue
// optionally ignoring a single child of this node.
static void peer_missing_leaf_nodes(
    struct sync_state *state, struct sync_peer_state *peer,
    struct node *node, unsigned except, uint8_t allow_remove)
{
  if (node->message.prefix_len == KEY_LEN_BITS){
    if (peer_is_missing(state, peer, node, allow_remove))
      queue_node(state, node, 1);
  }else{
    unsigned i;
    for (i=0;i<NODE_CHILDREN;i++){
      if (i!=except && node->children[i])
	peer_missing_leaf_nodes(state, peer, node->children[i], NODE_CHILDREN, allow_remove);
    }
  }
}

static void peer_add_key(struct sync_state *state, struct sync_peer_state *peer_state, const key_message_t *message)
{
  if (message->prefix_len != KEY_LEN_BITS || !message->stored)
    return;

  struct node *node = add_key_if_missing(&peer_state->root, message, 0);

  if (node){
    //Yay, they told us something we didn't know.
    state->progress=0;
    peer_state->recv_count++;

    if (state->has)
      state->has(state->context, peer_state->peer_context, &message->key);
    queue_node(state, node, 0);
  }
}

/*
static void de_queue(struct node *node){
  if (node->send_state == QUEUED)
    node->send_state = DONT_SEND;
  for (unsigned i=0;i<NODE_CHILDREN;i++)
    if (node->children[i])
      de_queue(node->children[i]);
}
*/

static unsigned peer_has_received_all(struct sync_state *state, struct sync_peer_state *peer_state, struct node *peer_node)
{
  if (!peer_node)
    return 0;
  unsigned ret=0;
  if (peer_node->message.prefix_len == KEY_LEN_BITS){
    if (peer_node->message.stored){
      if (state->now_has)
	state->now_has(state->context, peer_state->peer_context, peer_node->context, &peer_node->message.key);
      remove_key(state, &peer_state->root, &peer_node->message.key);
      peer_state->send_count --;
      ret=1;
    }
  }else{
    // duplicate the child pointers, as removing an immediate child key *will* also free this peer node.
    struct node *children[NODE_CHILDREN];
    memcpy(children, peer_node->children, sizeof(children));
    unsigned i;
    for (i=0;i<NODE_CHILDREN;i++)
      ret+=peer_has_received_all(state, peer_state, children[i]);
  }
  return ret;
}

// add information about keys sent to this peer,
// remove information about keys received from this peer
// (both operations are XOR's)
// returns a struct node if this message is an exact match
static struct node * remove_differences(struct sync_peer_state *peer_state, key_message_t *message)
{
  if (!peer_state->root || !message->stored)
    return NULL;

  struct node *peer_node = peer_state->root;
  uint8_t prefix_len = 0;

  while(prefix_len < message->prefix_len){

    if (peer_node->message.prefix_len == KEY_LEN_BITS){
      if (cmp_message(message, &peer_node->message)==0)
	break;
      if (message->prefix_len == KEY_LEN_BITS)
	return NULL;
    }

    uint8_t child_index = sync_get_bits(prefix_len, PREFIX_STEP_BITS, &message->key);

    if (prefix_len < peer_node->message.prefix_len){
      // TODO optimise this case by comparing all possible prefix bits in one hit
      uint8_t node_index = sync_get_bits(prefix_len, PREFIX_STEP_BITS, &peer_node->message.key);
      if (node_index != child_index)
	return NULL; // no match
    }else{
      peer_node = peer_node->children[child_index];
      if (!peer_node)
	return NULL;
    }
    prefix_len+=PREFIX_STEP_BITS;
  }

  if (message->prefix_len < KEY_LEN_BITS){
    if (peer_node->message.prefix_len == message->prefix_len || peer_node->message.prefix_len == KEY_LEN_BITS){
      // shortcut, we can xor the nodes
      sync_xor(&peer_node->message.key, message);
    }else{
      // we need to xor all children so we can get the prefix bits right.
      xor_children(peer_node, message);
    }
  }
  return peer_node;
}

// Proccess one incoming tree record.
static int recv_key(struct sync_state *state, struct sync_peer_state *peer_state, const key_message_t *message)
{
  // sanity check on two header bytes.
  if (message->min_prefix_len > message->prefix_len || message->prefix_len > KEY_LEN_BITS+1)
    return WHYF("Malformed message (min_prefix = %u, prefix = %u)", message->min_prefix_len, message->prefix_len);

  state->received_record_count++;
  /* Possible outcomes;
    key is an exact match for part of our tree
      Yay, nothing to do.

    key->prefix_len == KEY_LEN_BITS && we don't have this node
      Woohoo, we discovered something we didn't know before!

    they are missing sibling nodes between their min_prefix_len and prefix_len
      queue all the sibling leaf nodes!

    our node doesn't match
      XOR our node against theirs
      search our tree for a single leaf node that matches this result
      if found;
	queue this leaf node for transmission
      else
	drill down our tree while our node has only one child? TODO our tree nodes should never have one child
	queue (N-1 of?) this node's children for transmission
  */
  if (!state->root){
    peer_add_key(state, peer_state, message);
    return 0;
  }

  if (message->prefix_len == KEY_LEN_BITS+1){
    // peer has no node of their own, they don't have anything that we have.
    peer_missing_leaf_nodes(state, peer_state, state->root, NODE_CHILDREN, 0);
    return 0;
  }

  key_message_t peer_message = *message;

  // first, remove information from peer_message that we have already learnt about this peer
  struct node *peer_node = remove_differences(peer_state, &peer_message);
  struct node *node = state->root;
  uint8_t prefix_len = 0;
  uint8_t is_blank = 1;
  unsigned i;
  for (i=(peer_message.prefix_len>>3)+1;i<KEY_LEN && is_blank;i++)
    if (peer_message.key.key[i])
      is_blank = 0;

  while(1){
    if (cmp_message(message, &node->message)==0){
      // if we queued this exact message, there's no point sending it now.
      // but don't cancel every child, that breaks with multiple peers.
      if (node->send_state == QUEUED)
	node->send_state = DONT_SEND;

      if (message->stored){
	// we can mark any keys they need as being received
	if (peer_has_received_all(state, peer_state, peer_node)==0)
	  state->received_uninteresting++;
      }else{
	// peer is ACK'ing that they need to know this key, which we have
	if (peer_is_missing(state, peer_state, node, 0)==0)
	  state->received_uninteresting++;
      }
      return 0;
    }

    // Nothing to do if we understand the rest of the differences
    if (cmp_message(&peer_message, &node->message)==0){
      state->received_uninteresting++;
      return 0;
    }

    // once we've looked at all of the prefix_len bits of the incoming key
    // we need to stop
    if (peer_message.prefix_len <= prefix_len){
      if (is_blank){
	// This peer doesn't know any of the children of this node
	peer_missing_leaf_nodes(state, peer_state, node, NODE_CHILDREN, 1);
      }else if (node->message.prefix_len > peer_message.prefix_len){
	// reply with our matching node
	queue_node(state, node, 1);
      }else{
	// compare their node to our tree, test if we can easily detect a part of our tree they don't know
	// Note, this only works if there are an odd number of different leaf nodes
	// With an even number of keys, the XOR will wipe out the prefix bits.

	// work out the difference between their node and ours
	key_message_t test_message = peer_message;
	sync_xor(&node->message.key, &test_message);

	// if we can explain the difference based on a matching node, queue all leaf nodes
	struct node *test_node = node;
	uint8_t test_prefix = prefix_len;
	while(test_node) {
	  if (cmp_message(&test_message, &test_node->message)==0){
	    // This peer doesn't know any of the children of this node
	    peer_missing_leaf_nodes(state, peer_state, test_node, NODE_CHILDREN, 1);
	    return 0;
	  }
	  if (test_node->message.prefix_len == KEY_LEN_BITS)
	    break;
	  uint8_t child_index = sync_get_bits(test_prefix, PREFIX_STEP_BITS, &test_message.key);
	  if (test_prefix<test_node->message.prefix_len){
	    // TODO optimise this case by comparing all possible prefix bits in one hit
	    uint8_t node_index = sync_get_bits(test_prefix, PREFIX_STEP_BITS, &test_node->message.key);
	    if (node_index != child_index)
	      break; // no match
	  }else{
	    test_node = test_node->children[child_index];
	  }
	  test_prefix+=PREFIX_STEP_BITS;
	}

	// queue the transmission of all child nodes of this node
        unsigned i;
	for (i=0;i<NODE_CHILDREN;i++){
	  if (node->children[i])
	    queue_node(state, node->children[i], 0);
	}
      }
      return 0;
    }

    // which branch of the tree should we look at next
    uint8_t key_index = sync_get_bits(prefix_len, PREFIX_STEP_BITS, &peer_message.key);

    // if our node represents a large range of the keyspace, find the first prefix bit that differs
    while (prefix_len < node->message.prefix_len && prefix_len < peer_message.prefix_len){
      // check the next step bits
      uint8_t existing_index = sync_get_bits(prefix_len, PREFIX_STEP_BITS, &node->message.key);
      if (key_index != existing_index){
	// If the prefix of our node differs from theirs, they don't have any of these keys
	// send them all
	if (prefix_len >= peer_message.min_prefix_len && peer_message.stored){
	  peer_missing_leaf_nodes(state, peer_state, node, NODE_CHILDREN, 0);

	  if (peer_message.prefix_len != KEY_LEN_BITS)
	    // and after they have added all these missing keys, they need to know
	    // this summary node so they can be reminded to send this key or it's children again.
	    queue_node(state, node, 0);
	}

	if (peer_message.prefix_len == KEY_LEN_BITS)
	  peer_add_key(state, peer_state, &peer_message);
	return 0;
      }
      prefix_len += PREFIX_STEP_BITS;
      key_index = sync_get_bits(prefix_len, PREFIX_STEP_BITS, &peer_message.key);
    }

    if (message->prefix_len <= prefix_len)
      continue;

    assert(prefix_len == node->message.prefix_len);

    if (peer_message.min_prefix_len <= node->message.prefix_len && peer_message.stored){
      // send all keys to the other party, except for the child @key_index
      // they don't have any of these siblings
      peer_missing_leaf_nodes(state, peer_state, node, key_index, 0);
    }

    // look at the next node in our graph
    if (!node->children[key_index]){
      // we know nothing about this key
      if (peer_message.prefix_len == KEY_LEN_BITS){
	peer_add_key(state, peer_state, &peer_message);
      }else{
	// hopefully the other party will tell us something,
	// and we won't get stuck in a loop talking about the same node.
	queue_node(state, node, 0);
      }
      return 0;
    }

    // Don't retransmit if we have heard some kind of confirmation of delivery from a peer
    // this is broken!
    //if (node->sent_count>0 && node->send_state == QUEUED)
    //  node->send_state = SENT;

    node = node->children[key_index];
    prefix_len += PREFIX_STEP_BITS;
  }
}

// Process all incoming messages from this packet buffer
int sync_recv_message(struct sync_state *state, void *peer_context, const uint8_t *buff, size_t len)
{
  assert(peer_context);

  struct sync_peer_state *peer_state = state->peers;
  while(peer_state && peer_state->peer_context != peer_context){
    peer_state = peer_state->next;
  }

  if (!peer_state){
    peer_state = emalloc_zero(sizeof(struct sync_peer_state));
    peer_state->peer_context = peer_context;
    peer_state->next = state->peers;
    state->peers = peer_state;
  }

  size_t offset=0;
  if (len%MESSAGE_BYTES)
    return -1;
  while(offset + MESSAGE_BYTES<=len){
    const uint8_t *p = &buff[offset];
    key_message_t message;
    bzero(&message, sizeof message);

    message.stored = (p[0]&0x80)?1:0;
    message.min_prefix_len = p[0]&0x7F;
    message.prefix_len = p[1];
    memcpy(&message.key.key[0], &p[2], KEY_LEN);

    if (recv_key(state, peer_state, &message)==-1)
      return -1;

    offset+=MESSAGE_BYTES;
  }
  return 0;
}

static void enum_diffs(struct sync_state *state, struct sync_peer_state *peer_state, struct node *node,
  void (*callback)(void *context, void *peer_context, const sync_key_t *key, uint8_t theirs))
{
  if (!node)
    return;
  if (node->message.prefix_len == KEY_LEN_BITS){
    callback(state->context, peer_state->peer_context, &node->message.key, node->message.stored);
  }else{
    unsigned i;
    for (i=0;i<NODE_CHILDREN;i++){
      enum_diffs(state, peer_state, node->children[i], callback);
    }
  }
}

void sync_enum_differences(struct sync_state *state,
  void (*callback)(void *context, void *peer_context, const sync_key_t *key, uint8_t theirs))
{
  struct sync_peer_state *peer_state = state->peers;
  while(peer_state){
    enum_diffs(state, peer_state, peer_state->root, callback);
    peer_state = peer_state->next;
  }
}

