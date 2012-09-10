/*
Serval Distributed Numbering Architecture (DNA)
Copyright (C) 2010 Paul Gardner-Stephen
 
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

/*
  Smart-flooding of broadcast information is also a requirement.  The long addresses help here, as we can make any address that begins
  with the first 192 bits all ones be broadcast, and use the remaining 64 bits as a "broadcast packet identifier" (BPI).  
  Nodes can remember recently seen BPIs and not forward broadcast frames that have been seen recently.  This should get us smart flooding
  of the majority of a mesh (with some node mobility issues being a factor).  We could refine this later, but it will do for now, especially
  since for things like number resolution we are happy to send repeat requests.
 */

#include "serval.h"
#include "overlay_address.h"
#include "overlay_buffer.h"

#define MAX_BPIS 1024
#define BPI_MASK 0x3ff
static struct broadcast bpilist[MAX_BPIS];

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

static struct tree_node root;

static struct subscriber *previous=NULL;
static struct subscriber *sender=NULL;
static struct broadcast *previous_broadcast=NULL;
struct subscriber *my_subscriber=NULL;

static unsigned char get_nibble(const unsigned char *sid, int pos){
  unsigned char byte = sid[pos>>1];
  if (!(pos&1))
    byte=byte>>4;
  return byte&0xF;
}

// find a subscriber struct from a subscriber id
// TODO find abreviated sid's
struct subscriber *find_subscriber(const unsigned char *sid, int len, int create){
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
	memset(ret,0,sizeof(struct subscriber));
	ptr->subscribers[nibble]=ret;
	bcopy(sid, ret->sid, SID_SIZE);
	ret->abbreviate_len=pos;
	// always send the full sid on first use
	ret->send_full=1;
	
	// always send my full sid when we hear about someone new
	if (my_subscriber)
	  my_subscriber->send_full = 1;
      }
      return ptr->subscribers[nibble];
      
    }else{
      // there's a subscriber in this slot, does it match the rest of the sid we've been given?
      struct subscriber *ret = ptr->subscribers[nibble];
      if (memcmp(ret->sid,sid,len)==0){
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

/* 
 Walk the subscriber tree, calling the callback function for each subscriber.
 if start is a valid pointer, the first entry returned will be after this subscriber
 if the callback returns non-zero, the process will stop.
 */
static int walk_tree(struct tree_node *node, int pos, 
	      unsigned char *start, int start_len, 
	      unsigned char *end, int end_len,
	      int(*callback)(struct subscriber *, void *), void *context){
  int i=0, e=16;
  
  if (start && pos < start_len*2){
    i=get_nibble(start,pos);
  }
  
  if (end && pos < end_len*2){
    e=get_nibble(end,pos) +1;
  }
  
  for (;i<e;i++){
    if (node->is_tree & (1<<i)){
      if (walk_tree(node->tree_nodes[i], pos+1, start, start_len, end, end_len, callback, context))
	return 1;
    }else if(node->subscribers[i]){
      if ((!start) || start_len<SID_SIZE || memcmp(node->subscribers[i]->sid, start, start_len)!=0)
	if (callback(node->subscribers[i], context))
	  return 1;
    }
    // stop comparing the start sid after looking at the first branch of the tree
    start=NULL;
  }
  return 0;
}

/*
 walk the tree, starting at start, calling the supplied callback function
 */
void enum_subscribers(struct subscriber *start, int(*callback)(struct subscriber *, void *), void *context){
  walk_tree(&root, 0, start->sid, SID_SIZE, NULL, 0, callback, context);
}

// quick test to make sure the specified route is valid.
int subscriber_is_reachable(struct subscriber *subscriber){
  if (!subscriber)
    return REACHABLE_NONE;
  
  if (subscriber->reachable==REACHABLE_INDIRECT){
    if (!subscriber->next_hop)
      return REACHABLE_NONE;
    
    // avoid infinite recursion...
    if (subscriber->next_hop->reachable!=REACHABLE_DIRECT && 
	subscriber->next_hop->reachable!=REACHABLE_UNICAST)
      return REACHABLE_NONE;
    
    int r = subscriber_is_reachable(subscriber->next_hop);
    if (r!=REACHABLE_DIRECT && r!= REACHABLE_UNICAST)
      return REACHABLE_NONE;
  }
  
  if (subscriber->reachable==REACHABLE_DIRECT || 
      subscriber->reachable==REACHABLE_UNICAST){
    // make sure the interface is still up
    if (!subscriber->interface)
      return REACHABLE_NONE;
    if (subscriber->interface->state!=INTERFACE_STATE_UP)
      return REACHABLE_NONE;
  }
  
  return subscriber->reachable;
}

// mark the subscriber as reachable via reply unicast packet
int reachable_unicast(struct subscriber *subscriber, overlay_interface *interface, struct in_addr addr, int port){
  if (subscriber->reachable!=REACHABLE_NONE)
    return WHYF("Subscriber %s is already reachable", alloca_tohex_sid(subscriber->sid));
  
  if (subscriber->node)
    return WHYF("Subscriber %s is already known for overlay routing", alloca_tohex_sid(subscriber->sid));
  
  subscriber->interface = interface;
  subscriber->reachable = REACHABLE_UNICAST;
  subscriber->address.sin_family = AF_INET;
  subscriber->address.sin_addr = addr;
  subscriber->address.sin_port = htons(port);
  
  // may be used in tests
  DEBUGF("ADD DIRECT ROUTE TO %s via %s:%d", alloca_tohex_sid(subscriber->sid), inet_ntoa(addr), port);
  
  /* Pre-emptively check if we have their sas in memory, or send a request */
  keyring_find_sas_public(keyring, subscriber->sid);
  return 0;
}

// generate a new random broadcast address
int overlay_broadcast_generate_address(struct broadcast *addr)
{
  int i;
  for(i=0;i<BROADCAST_LEN;i++) addr->id[i]=random()&0xff;
  return 0;
}

// test if the broadcast address has been seen
int overlay_broadcast_drop_check(struct broadcast *addr)
{
  /* Hash the BPI and see if we have seen it recently.
     If so, drop the frame.
     The occassional failure to supress a broadcast frame is not
     something we are going to worry about just yet.  For byzantine
     robustness it is however required. */
  int bpi_index=0;
  int i;
  for(i=0;i<BROADCAST_LEN;i++)
    {
      bpi_index=((bpi_index<<3)&0xfff8)+((bpi_index>>13)&0x7);
      bpi_index^=addr->id[i];
    }
  bpi_index&=BPI_MASK;
  
  if (memcmp(bpilist[bpi_index].id, addr->id, BROADCAST_LEN)){
    if (debug&DEBUG_BROADCASTS)
      DEBUGF("BPI %s is new", alloca_tohex(addr->id, BROADCAST_LEN));
    bcopy(addr->id, bpilist[bpi_index].id, BROADCAST_LEN);
    return 0; /* don't drop */
  }else{
    if (debug&DEBUG_BROADCASTS)
      DEBUGF("BPI %s is a duplicate", alloca_tohex(addr->id, BROADCAST_LEN));
    return 1; /* drop frame because we have seen this BPI recently */
  }
}

int overlay_broadcast_append(struct overlay_buffer *b, struct broadcast *broadcast)
{
  if (ob_append_byte(b, OA_CODE_BROADCAST)) return -1;
  if (ob_append_bytes(b, broadcast->id, BROADCAST_LEN)) return -1;
  previous=NULL;
  return 0;
}

// append an appropriate abbreviation into the address
int overlay_address_append(struct overlay_buffer *b, struct subscriber *subscriber)
{
  if (subscriber==sender){
    ob_append_byte(b, OA_CODE_SELF);
    
  }else if(subscriber==previous){
    ob_append_byte(b, OA_CODE_PREVIOUS);
    
  }else if(subscriber->send_full || subscriber->abbreviate_len >= 24){
    subscriber->send_full=0;
    ob_append_bytes(b, subscriber->sid, SID_SIZE);
    
  }else if(subscriber->abbreviate_len <= 4){
    ob_append_byte(b, OA_CODE_PREFIX3);
    ob_append_bytes(b, subscriber->sid, 3);
    
  }else if(subscriber->abbreviate_len <= 12){
    ob_append_byte(b, OA_CODE_PREFIX7);
    ob_append_bytes(b, subscriber->sid, 7);
    
  }else{
    ob_append_byte(b, OA_CODE_PREFIX11);
    ob_append_bytes(b, subscriber->sid, 11);
  }
  
  previous = subscriber;
  return 0;
}

int overlay_address_append_self(overlay_interface *interface, struct overlay_buffer *b){
  static int ticks_per_full_address = -1;
  if (ticks_per_full_address == -1) {
    ticks_per_full_address = confValueGetInt64Range("mdp.selfannounce.ticks_per_full_address", 4LL, 1LL, 1000000LL);
    INFOF("ticks_per_full_address = %d", ticks_per_full_address);
  }
  
  if (!my_subscriber)
    return WHY("I don't know who I am yet");
  
  if (++interface->ticks_since_sent_full_address < ticks_per_full_address){
    interface->ticks_since_sent_full_address = 0;
    my_subscriber->send_full=1;
  }
  
  if (overlay_address_append(b, my_subscriber))
    return WHY("Could not append my sid");
  
  return 0;
}

static int mark_full(struct subscriber *subscriber, void *context){
  subscriber->send_full=1;
  return 0;
}

int find_subscr_buffer(struct overlay_buffer *b, int len, int create, struct subscriber **subscriber){
  unsigned char *id = ob_get_bytes_ptr(b, len);
  if (!id)
    return WHY("Not enough space in buffer to parse address");
  if (!subscriber)
    return WHY("Expected subscriber");
  *subscriber=find_subscriber(id, len, create);
  
  if (!*subscriber){
    INFOF("Abbreviation %s not found", alloca_tohex(id, len));
    
    // If the abbreviation is too short, mark any subscribers that match to send full SID's
    walk_tree(&root, 0, id, len, id, len, mark_full, NULL);
    
    // HACK, imperfect... better to send a sas key request
    // always send my full sid when we fail to resolve an abbreviation
    // they may not know us either
    if (my_subscriber)
      my_subscriber->send_full = 1;
    return 1;
  }
  previous=*subscriber;
  previous_broadcast=NULL;
  return 0;
}

// returns 0 = success, -1 = fatal parsing error, 1 = unable to identify address
int overlay_address_parse(struct overlay_buffer *b, struct broadcast *broadcast, struct subscriber **subscriber)
{
  int code = ob_getbyte(b,b->position);
  switch(code){
    case OA_CODE_BROADCAST:
      b->position++;
      if (subscriber)
	*subscriber=NULL;
      
      if (!broadcast)
	return WHY("No broadcast structure for receiving broadcast address");
      
      ob_get_bytes(b, broadcast->id, BROADCAST_LEN);
      previous=NULL;
      previous_broadcast=broadcast;
      return 0;
      
    case OA_CODE_SELF:
      b->position++;
      if (!subscriber)
	return WHY("Expected subscriber");
      if (!sender){
	INFO("Could not resolve address, sender has not been set");
	return 1;
      }
      *subscriber=sender;
      previous=sender;
      return 0;
      
    case OA_CODE_PREVIOUS:
      b->position++;
      if (!subscriber)
	return WHY("Expected subscriber");
      // previous may be null, if the previous address was a broadcast. 
      // In this case we want the subscriber to be null as well and not report an error,
      if (previous)
	*subscriber=previous;
      
      // not an error if broadcast is NULL, as the previous OA_CODE_BROADCAST address must have been valid.
      else if (previous_broadcast){
	if (broadcast)
	  bcopy(previous_broadcast->id, broadcast->id, BROADCAST_LEN);
      }else{
	INFO("Unable to decode previous address");
	return 1;
      }
      return 0;
      
    case OA_CODE_PREFIX3:
      b->position++;
      return find_subscr_buffer(b,3,0,subscriber);
      
    case OA_CODE_PREFIX7:
      b->position++;
      return find_subscr_buffer(b,7,0,subscriber);
      
    case OA_CODE_PREFIX11:
      b->position++;
      return find_subscr_buffer(b,11,0,subscriber);
  }
  
  if (code<=0x0f)
    return WHYF("Unsupported abbreviation code %d", code);
  return find_subscr_buffer(b,SID_SIZE,1,subscriber);
}

void overlay_address_clear(void){
  sender=NULL;
  previous=NULL;
  previous_broadcast=NULL;
}

void overlay_address_set_sender(struct subscriber *subscriber){
  sender = subscriber;
}
