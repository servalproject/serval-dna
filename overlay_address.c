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
#include "conf.h"
#include "str.h"
#include "overlay_address.h"
#include "overlay_buffer.h"
#include "overlay_packet.h"
#include <arpa/inet.h>

#define MAX_BPIS 1024
#define BPI_MASK 0x3ff
static struct broadcast bpilist[MAX_BPIS];

#define OA_CODE_SELF 0xff
#define OA_CODE_PREVIOUS 0xfe
#define OA_CODE_P2P_YOU 0xfd
#define OA_CODE_P2P_ME 0xfc

// each node has 16 slots based on the next 4 bits of a subscriber id
// each slot either points to another tree node or a struct subscriber.
struct tree_node{
  // bit flags for the type of object each element points to
  uint16_t is_tree;
  
  union{
    struct tree_node *tree_nodes[16];
    struct subscriber *subscribers[16];
  };
};

static struct tree_node root;

struct subscriber *my_subscriber=NULL;

static unsigned char get_nibble(const unsigned char *sidp, int pos)
{
  unsigned char byte = sidp[pos>>1];
  if (!(pos&1))
    byte=byte>>4;
  return byte&0xF;
}

static void free_subscriber(struct subscriber *subscriber)
{
  if (subscriber->link_state || subscriber->destination)
    FATAL("Can't free a subscriber that is being used in routing");
  if (subscriber->sync_state)
    FATAL("Can't free a subscriber that is being used by rhizome");
  if (subscriber->identity)
    FATAL("Can't free a subscriber that is unlocked in the keyring");
  free(subscriber);
}

static void free_children(struct tree_node *parent)
{
  int i;
  for (i=0;i<16;i++){
    if (parent->is_tree & (1<<i)){
      free_children(parent->tree_nodes[i]);
      free(parent->tree_nodes[i]);
      parent->tree_nodes[i]=NULL;
    }else if(parent->subscribers[i]){
      free_subscriber(parent->subscribers[i]);
      parent->subscribers[i]=NULL;
    }
  }
  parent->is_tree=0;
}

void free_subscribers()
{
  // don't attempt to free anything if we're running as a server
  // who knows where subscriber ptr's may have leaked to.
  if (serverMode)
    FATAL("Freeing subscribers from a running daemon is not supported");
  free_children(&root);
}

// find a subscriber struct from a whole or abbreviated subscriber id
struct subscriber *find_subscriber(const unsigned char *sidp, int len, int create)
{
  struct tree_node *ptr = &root;
  int pos=0;
  if (len!=SID_SIZE)
    create =0;
  
  do{
    unsigned char nibble = get_nibble(sidp, pos++);
    
    if (ptr->is_tree & (1<<nibble)){
      ptr = ptr->tree_nodes[nibble];
      
    }else if(!ptr->subscribers[nibble]){
      // subscriber is not yet known
      
      if (create){
	struct subscriber *ret=(struct subscriber *)malloc(sizeof(struct subscriber));
	memset(ret,0,sizeof(struct subscriber));
	ptr->subscribers[nibble]=ret;
	ret->sid = *(const sid_t *)sidp;
	ret->abbreviate_len=pos;
      }
      return ptr->subscribers[nibble];
      
    }else{
      // there's a subscriber in this slot, does it match the rest of the sid we've been given?
      struct subscriber *ret = ptr->subscribers[nibble];
      if (memcmp(ret->sid.binary, sidp, len) == 0)
	return ret;
      
      // if we need to insert this subscriber, we have to make a new tree node first
      if (!create)
	return NULL;
      
      // create a new tree node and move the existing subscriber into it
      struct tree_node *new=(struct tree_node *)malloc(sizeof(struct tree_node));
      memset(new,0,sizeof(struct tree_node));
      ptr->tree_nodes[nibble]=new;
      ptr->is_tree |= (1<<nibble);
      
      ptr=new;
      nibble=get_nibble(ret->sid.binary, pos);
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
      if (callback(node->subscribers[i], context))
	return 1;
    }
    // stop comparing the start sid after looking at the first branch of the tree
    start=NULL;
  }
  return 0;
}

/*
 walk the tree, starting at start inclusive, calling the supplied callback function
 */
void enum_subscribers(struct subscriber *start, int(*callback)(struct subscriber *, void *), void *context)
{
  walk_tree(&root, 0, start->sid.binary, SID_SIZE, NULL, 0, callback, context);
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
    if (config.debug.broadcasts)
      DEBUGF("BPI %s is new", alloca_tohex(addr->id, BROADCAST_LEN));
    bcopy(addr->id, bpilist[bpi_index].id, BROADCAST_LEN);
    return 0; /* don't drop */
  }else{
    if (config.debug.broadcasts)
      DEBUGF("BPI %s is a duplicate", alloca_tohex(addr->id, BROADCAST_LEN));
    return 1; /* drop frame because we have seen this BPI recently */
  }
}

int overlay_broadcast_append(struct overlay_buffer *b, struct broadcast *broadcast)
{
  return ob_append_bytes(b, broadcast->id, BROADCAST_LEN);
}

// append an appropriate abbreviation into the address
int overlay_address_append(struct decode_context *context, struct overlay_buffer *b, struct subscriber *subscriber)
{
  if (!subscriber)
    return WHY("No address supplied");

  if(context
      && subscriber == context->point_to_point_device){
    if (ob_append_byte(b, OA_CODE_P2P_YOU))
      return -1;
  }else if(context
      && !subscriber->send_full
      && subscriber == my_subscriber
      && context->point_to_point_device
      && (context->encoding_header==0 || !context->interface->local_echo)){
    if (ob_append_byte(b, OA_CODE_P2P_ME))
      return -1;
  }else if (context && subscriber==context->sender){
    if (ob_append_byte(b, OA_CODE_SELF))
      return -1;
  }else if(context && subscriber==context->previous){
    if (ob_append_byte(b, OA_CODE_PREVIOUS))
      return -1;
  }else{
    int len=SID_SIZE;
    if (subscriber->send_full){
      subscriber->send_full=0;
    }else{
      len=(subscriber->abbreviate_len+2)/2;
      if (context && context->encoding_header)
	len++;
      if (len>SID_SIZE)
	len=SID_SIZE;
    }
    if (ob_append_byte(b, len))
      return -1;
    if (ob_append_bytes(b, subscriber->sid.binary, len))
      return -1;
  }
  if (context)
    context->previous = subscriber;
  return 0;
}

static int add_explain_response(struct subscriber *subscriber, void *context){
  struct decode_context *response = context;
  // only explain a SID once every half second.
  time_ms_t now = gettime_ms();
  if (now - subscriber->last_explained < 500)
    return 0;
  subscriber->last_explained = now;

  if (!response->please_explain){
    response->please_explain = calloc(sizeof(struct overlay_frame),1);
    response->please_explain->payload=ob_new();
    ob_limitsize(response->please_explain->payload, 1024);
  }
  
  // if one of our identities is unknown, 
  // the header of this packet must include our full sid.
  if (subscriber->reachable==REACHABLE_SELF){
    if (subscriber==my_subscriber){
      response->please_explain->source_full=1;
      return 0;
    }
    subscriber->send_full=1;
  }
  
  // add the whole subscriber id to the payload, stop if we run out of space
  DEBUGF("Adding full sid by way of explanation %s", alloca_tohex_sid_t(subscriber->sid));
  if (ob_append_byte(response->please_explain->payload, SID_SIZE))
    return 1;
  if (ob_append_bytes(response->please_explain->payload, subscriber->sid.binary, SID_SIZE))
    return 1;

  // let the routing engine know that we had to explain this sid, we probably need to re-send routing info
  link_explained(subscriber);
  return 0;
}

static int find_subscr_buffer(struct decode_context *context, struct overlay_buffer *b, int len, struct subscriber **subscriber){
  if (len<=0 || len>SID_SIZE){
    return WHYF("Invalid abbreviation length %d", len);
  }
  
  unsigned char *id = ob_get_bytes_ptr(b, len);
  if (!id){
    return WHY("Not enough space in buffer to parse address");
  }
  
  if (!subscriber){
    WARN("Could not resolve address, no buffer supplied");
    context->invalid_addresses=1;
    return 0;
  }
  
  *subscriber=find_subscriber(id, len, 1);
  
  if (!*subscriber){
    context->invalid_addresses=1;
    
    // generate a please explain in the passed in context
    
    // add the abbreviation you told me about
    if (!context->please_explain){
      context->please_explain = calloc(sizeof(struct overlay_frame),1);
      context->please_explain->payload=ob_new();
      ob_limitsize(context->please_explain->payload, MDP_MTU);
    }
    
    // And I'll tell you about any subscribers I know that match this abbreviation, 
    // so you don't try to use an abbreviation that's too short in future.
    walk_tree(&root, 0, id, len, id, len, add_explain_response, context);
    
    INFOF("Asking for explanation of %s", alloca_tohex(id, len));
    ob_append_byte(context->please_explain->payload, len);
    ob_append_bytes(context->please_explain->payload, id, len);
    
  }else{
    if (context)
      context->previous=*subscriber;
  }
  return 0;
}

int overlay_broadcast_parse(struct overlay_buffer *b, struct broadcast *broadcast)
{
  return ob_get_bytes(b, broadcast->id, BROADCAST_LEN);
}

// returns 0 = success, -1 = fatal parsing error, 1 = unable to identify address
int overlay_address_parse(struct decode_context *context, struct overlay_buffer *b, struct subscriber **subscriber)
{
  int len = ob_get(b);
  if (len<0)
    return WHY("Buffer too small");
  
  switch(len){
    case OA_CODE_P2P_YOU:
      // if we don't know who they are, we can't assume they mean us.
      if (context->point_to_point_device){
        *subscriber=my_subscriber;
	context->previous=my_subscriber;
      }else{
	WHYF("Could not resolve address on %s, this isn't a configured point to point link", context->interface->name);
	context->invalid_addresses=1;
      }
      return 0;

    case OA_CODE_P2P_ME:
      if (context->point_to_point_device){
        *subscriber=context->point_to_point_device;
	context->previous=*subscriber;
      }else{
	// add the abbreviation you told me about
	if (!context->please_explain){
	  context->please_explain = calloc(sizeof(struct overlay_frame),1);
	  context->please_explain->payload=ob_new();
	  ob_limitsize(context->please_explain->payload, MDP_MTU);
	}
	
	INFOF("Asking for explanation of YOU");
	ob_append_byte(context->please_explain->payload, OA_CODE_P2P_YOU);
	context->invalid_addresses=1;
      }
      return 0;

    case OA_CODE_SELF:
      if (!context->sender){
	INFO("Could not resolve address, sender has not been set");
	context->invalid_addresses=1;
      }else{
	*subscriber=context->sender;
	context->previous=context->sender;
      }
      return 0;
      
    case OA_CODE_PREVIOUS:
      if (!context->previous){
	INFO("Unable to decode previous address");
	context->invalid_addresses=1;
      }else{
	*subscriber=context->previous;
      }
      return 0;
  }
  
  return find_subscr_buffer(context, b, len, subscriber);
}

// once we've finished parsing a packet, complete and send a please explain if required.
int send_please_explain(struct decode_context *context, struct subscriber *source, struct subscriber *destination){
  IN();
  struct overlay_frame *frame=context->please_explain;
  if (!frame)
    RETURN(0);
  frame->type = OF_TYPE_PLEASEEXPLAIN;
  
  if (source)
    frame->source = source;
  else
    frame->source = my_subscriber;
  
  if (!context->sender)
    frame->source_full=1;
  
  if (destination){
    frame->ttl = PAYLOAD_TTL_DEFAULT; // MAX?
    frame->destination = destination;
    frame->source_full=1;
  }else{
    // send both a broadcast & unicast response out the same interface this packet arrived on.
    frame->ttl=1;// how will this work with olsr??
    if (context->interface){
      frame->destination = destination;
      frame->destinations[frame->destination_count++].destination=add_destination_ref(context->interface->destination);
      
      struct network_destination *dest = create_unicast_destination(context->addr, context->interface);
      if (dest)
	frame->destinations[frame->destination_count++].destination=dest;
    
    }else{
      FATAL("This context doesn't have an interface?");
    }
  }
  
  frame->queue=OQ_MESH_MANAGEMENT;
  if (!overlay_payload_enqueue(frame))
    RETURN(0);
  op_free(frame);
  RETURN(-1);
  OUT();
}

// process an incoming request for explanation of subscriber abbreviations
int process_explain(struct overlay_frame *frame){
  struct overlay_buffer *b=frame->payload;
  
  struct decode_context context;
  bzero(&context, sizeof context);
  context.sender = frame->source;
  context.interface = frame->interface;
  
  while(ob_remaining(b)>0){
    int len = ob_get(b);
    
    if (len==OA_CODE_P2P_YOU){
      add_explain_response(my_subscriber, &context);
      continue;
    }
    
    if (len<=0 || len>SID_SIZE)
      return WHY("Badly formatted explain message");
    unsigned char *sid = ob_get_bytes_ptr(b, len);
    if (!sid)
      return WHY("Ran past end of buffer");
    
    if (len==SID_SIZE){
      // This message is also used to inform people of previously unknown subscribers
      // make sure we know this one
      find_subscriber(sid,len,1);
    }else{
      // reply to the sender with all subscribers that match this abbreviation
      INFOF("Sending responses for %s", alloca_tohex(sid, len));
      walk_tree(&root, 0, sid, len, sid, len, add_explain_response, &context);
    }
  }
  
  send_please_explain(&context, frame->destination, frame->source);
  return 0;
}
