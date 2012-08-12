//
//  subscribers.c
//  
//
//  Created by Jeremy Lakeman on 11/08/12.
//  Copyright (c) 2012 __MyCompanyName__. All rights reserved.
//

#include <stdlib.h>
#include "constants.h"
#include "log.h"
#include "serval.h"
#include "subscribers.h"

// each node has 16 slots based on the next 4 bits of a subscriber id
// each slot either points to another tree node or a struct subscriber.
struct tree_node{
  // bit flags for the type of object each element points to
  int is_tree;
  
  union{
    struct tree_node *tree_nodes[16];
    struct subscriber *subscribers[16];
  };
};

struct tree_node root;

int isSame(const unsigned char *ptr1, const unsigned char *ptr2, int len){
  int i;
  for (i=0;i<len;i++)
    if (ptr1[i]!=ptr2[i])
      return 0;
  return 1;
}

unsigned char get_nibble(const unsigned char *sid, int pos){
  unsigned char byte = sid[pos>>1];
  if (!(pos&1))
    byte=byte>>4;
  return byte&0xF;
}

// find a subscriber struct from a subscriber id
// TODO find abreviated sid's
struct subscriber *find(const unsigned char *sid, int len, int create){
  struct tree_node *ptr = &root;
  int pos=0;
  if (len!=SID_SIZE)
    create =0;
  
  do{
    unsigned char nibble = get_nibble(sid, pos++);
    
    if (ptr->is_tree & (1<<nibble)){
      ptr = ptr->tree_nodes[nibble];
      
    }else if(!ptr->subscribers[nibble]){
      // subscriber is not yet known
      
      if (create){
	struct subscriber *ret=(struct subscriber *)malloc(sizeof(struct subscriber));
	ptr->subscribers[nibble]=ret;
	bcopy(sid, ret->sid, SID_SIZE);
	ret->abbreviate_len=pos;
      }
      return ptr->subscribers[nibble];
      
    }else{
      // there's a subscriber in this slot, does it match the rest of the sid we've been given?
      struct subscriber *ret = ptr->subscribers[nibble];
      if (isSame(ret->sid,sid,len)){
	return ret;
      }
      
      // if we need to insert this subscriber, we have to make a new tree node first
      if (!create)
	return NULL;
      
      // create a new tree node and move the existing subscriber into it
      struct tree_node *new=(struct tree_node *)malloc(sizeof(struct tree_node));
      memset(new,0,sizeof(struct tree_node));
      ptr->tree_nodes[nibble]=new;
      ptr->is_tree |= (1<<nibble);
      
      ptr=new;
      nibble=get_nibble(ret->sid,pos);
      ptr->subscribers[nibble]=ret;
      ret->abbreviate_len=pos+1;
      // then go around the loop again to compare the next nibble against the sid until we find an empty slot.
    }
  }while(pos < len*2);
  
  // abbreviation is not unique
  return NULL;
}

void dump_subscriber_tree(struct tree_node *node, int depth){
  int i;
  for (i=0;i<16;i++){
    if (node->is_tree & (1<<i)){
      DEBUGF("%d, %x",depth,i);
      dump_subscriber_tree(node->tree_nodes[i],depth+1);
    }else if(node->subscribers[i]){
      DEBUGF("%d, %x, %s", node->subscribers[i]->abbreviate_len, i, alloca_tohex_sid(node->subscribers[i]->sid));
    }
  }
}

void dump_subscribers(){
  dump_subscriber_tree(&root,0);
}
