/*
Serval DNA MDP addressing
Copyright (C) 2012-2013 Serval Project Inc.
Copyright (C) 2012 Paul Gardner-Stephen
 
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

#include <assert.h>
#include <arpa/inet.h>
#include "serval.h"
#include "conf.h"
#include "str.h"
#include "overlay_address.h"
#include "overlay_buffer.h"
#include "overlay_interface.h"
#include "overlay_packet.h"
#include "server.h"
#include "route_link.h"

#define MAX_BPIS 1024
#define BPI_MASK 0x3ff
static struct broadcast bpilist[MAX_BPIS];

#define OA_CODE_SELF 0xff
#define OA_CODE_PREVIOUS 0xfe
#define OA_CODE_P2P_YOU 0xfd
#define OA_CODE_P2P_ME 0xfc
#define OA_CODE_SIGNKEY 0xfb // full sign key of an identity, from which a SID can be derived

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

static __thread struct tree_node root;

static __thread struct subscriber *my_subscriber=NULL;

struct subscriber *get_my_subscriber(){
  if (!serverMode)
    return NULL;
  if (my_subscriber && my_subscriber->reachable != REACHABLE_SELF)
    my_subscriber = NULL;
  if (!my_subscriber){
    keyring_identity *id = keyring->identities;
    while(id && id->subscriber->reachable != REACHABLE_SELF)
      id = id->next;
    if (!id)
      id = keyring_inmemory_identity();
    my_subscriber = id->subscriber;
  }
  return my_subscriber;
}

void release_my_subscriber(){
  if (my_subscriber && my_subscriber->identity->slot==0)
    keyring_free_identity(my_subscriber->identity);
  my_subscriber = NULL;
}

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
struct subscriber *_find_subscriber(struct __sourceloc __whence, const unsigned char *sidp, int len, int create)
{
  IN();
  struct tree_node *ptr = &root;
  int pos=0;
  if (len!=SID_SIZE)
    create =0;
  struct subscriber *ret = NULL;
  do {
    unsigned char nibble = get_nibble(sidp, pos++);
    if (ptr->is_tree & (1<<nibble)){
      ptr = ptr->tree_nodes[nibble];
    }else if(!ptr->subscribers[nibble]){
      // subscriber is not yet known
      if (create && (ret = (struct subscriber *) emalloc_zero(sizeof(struct subscriber)))) {
	ptr->subscribers[nibble] = ret;
	ret->sid = *(const sid_t *)sidp;
	ret->abbreviate_len = pos;
	DEBUGF(subscriber, "Storing %s, abbrev_len=%d", alloca_tohex_sid_t(ret->sid), ret->abbreviate_len);
      }
      goto done;
    }else{
      // there's a subscriber in this slot, does it match the rest of the sid we've been given?
      ret = ptr->subscribers[nibble];
      if (memcmp(ret->sid.binary, sidp, len) == 0)
	goto done;
      // if we need to insert this subscriber, we have to make a new tree node first
      if (!create) {
	if (len != SID_SIZE)
	  DEBUGF(subscriber, "Prefix %s is not unique", alloca_tohex(sidp, len));
	ret = NULL;
	goto done;
      }
      // create a new tree node and move the existing subscriber into it
      struct tree_node *new = (struct tree_node *) emalloc_zero(sizeof(struct tree_node));
      if (new == NULL) {
	ret = NULL;
	goto done;
      }
      ptr->tree_nodes[nibble] = new;
      ptr->is_tree |= (1<<nibble);
      ptr = new;
      nibble = get_nibble(ret->sid.binary, pos);
      ptr->subscribers[nibble] = ret;
      ret->abbreviate_len = pos + 1;
      DEBUGF(subscriber, "Bumped %s, abbrev_len=%d (+ %p)", alloca_tohex_sid_t(ret->sid), ret->abbreviate_len, ptr);
      // then go around the loop again to compare the next nibble against the sid until we find an empty slot.
    }
  } while(pos < len*2);
done:
  RETURN(ret);
}

/* 
 Walk the subscriber tree, calling the callback function for each subscriber.
 if start is a valid pointer, the first entry returned will be after this subscriber
 if the callback returns non-zero, the process will stop.
 */
static int walk_tree(struct tree_node *node, int pos, 
	      const struct subscriber *start,
	      int(*callback)(struct subscriber *, void *), void *context){
  int i=0, e=16;
  
  if (start)
    i=get_nibble(start->sid.binary, pos);
  
  for (;i<e;i++){
    if (node->is_tree & (1<<i)){
      if (walk_tree(node->tree_nodes[i], pos+1, start, callback, context))
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

// walk the sub-tree for all subscribers that exactly match this id/len prefix.
static void prefix_matches(uint8_t *id, unsigned len, 
			   int(*callback)(struct subscriber *, void *), void *context)
{
  struct tree_node *node = &root;
  unsigned pos=0;
  DEBUGF(subscriber, "Looking for %s", alloca_tohex(id, len));
  for (; node && pos<len*2; pos++){
    int i=get_nibble(id, pos);
    DEBUGF(subscriber, "Nibble %d = %d, node %p, is tree %d", pos, i, node, node->is_tree & (1<<i));
    if ((node->is_tree & (1<<i))==0){
      if (node->subscribers[i] && memcmp(node->subscribers[i]->sid.binary, id, len)==0)
	callback(node->subscribers[i], context);
      return;
    }
    node = node->tree_nodes[i];
  }
  DEBUGF(subscriber, "Walking from %p", node);
  walk_tree(node, pos+1, NULL, callback, context);
}

/*
 walk the tree, starting at start inclusive, calling the supplied callback function
 */
void enum_subscribers(struct subscriber *start, int(*callback)(struct subscriber *, void *), void *context)
{
  walk_tree(&root, 0, start, callback, context);
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
    DEBUGF(broadcasts, "BPI %s is new", alloca_tohex(addr->id, BROADCAST_LEN));
    bcopy(addr->id, bpilist[bpi_index].id, BROADCAST_LEN);
    return 0; /* don't drop */
  }else{
    DEBUGF(broadcasts, "BPI %s is a duplicate", alloca_tohex(addr->id, BROADCAST_LEN));
    return 1; /* drop frame because we have seen this BPI recently */
  }
}

void overlay_broadcast_append(struct overlay_buffer *b, struct broadcast *broadcast)
{
  ob_append_bytes(b, broadcast->id, BROADCAST_LEN);
}

// append an appropriate abbreviation into the address
void overlay_address_append(struct decode_context *context, struct overlay_buffer *b, struct subscriber *subscriber)
{
  assert(subscriber != NULL);
  if (context && subscriber == context->point_to_point_device)
    ob_append_byte(b, OA_CODE_P2P_YOU);
  else if(context
      && !subscriber->send_full
      && subscriber == get_my_subscriber()
      && context->point_to_point_device
      && ((context->flags & DECODE_FLAG_ENCODING_HEADER)==0 || !context->interface->local_echo))
    ob_append_byte(b, OA_CODE_P2P_ME);
  else if (context && subscriber==context->sender)
    ob_append_byte(b, OA_CODE_SELF);
  else if (context && subscriber==context->previous)
    ob_append_byte(b, OA_CODE_PREVIOUS);
  else {
    if (subscriber->send_full){
      // TODO work out when we can use OA_CODE_SIGNKEY
      ob_append_byte(b, SID_SIZE);
      ob_append_bytes(b, subscriber->sid.binary, SID_SIZE);
      subscriber->send_full=0;
    }else{
      int len=(subscriber->abbreviate_len+2)/2;
      if (context && (context->flags & DECODE_FLAG_ENCODING_HEADER))
	len++;
      if (len>SID_SIZE)
	len=SID_SIZE;
      ob_append_byte(b, len);
      ob_append_bytes(b, subscriber->sid.binary, len);
    }
  }
  if (context)
    context->previous = subscriber;
}

static int add_explain_response(struct subscriber *subscriber, void *context)
{
  struct decode_context *response = context;
  // only explain a SID once every half second.
  time_ms_t now = gettime_ms();
  if (now - subscriber->last_explained < 500)
    return 0;
  subscriber->last_explained = now;

  if (!response->please_explain){
    if ((response->please_explain = emalloc_zero(sizeof(struct overlay_frame))) == NULL)
      return 1; // stop walking
    if ((response->please_explain->payload = ob_new()) == NULL) {
      free(response->please_explain);
      response->please_explain = NULL;
      return 1; // stop walking
    }
    ob_limitsize(response->please_explain->payload, 1024);
  }

  // if our primary routing identities is unknown,
  // the header of this packet must include our full sid.
  if (subscriber==get_my_subscriber()){
    DEBUGF(subscriber, "Explaining SELF sid=%s", alloca_tohex_sid_t(subscriber->sid));
    response->please_explain->source_full=1;
    return 0;
  }
  
  struct overlay_buffer *b = response->please_explain->payload;

  // add the whole subscriber id to the payload, stop if we run out of space
  DEBUGF(subscriber, "Explaining sid=%s", alloca_tohex_sid_t(subscriber->sid));
  ob_checkpoint(b);

  if (subscriber->id_combined && response->sender && response->sender->id_combined){
    // TODO better condition for when we should send this?
    ob_append_byte(b, OA_CODE_SIGNKEY);
    ob_append_bytes(b, subscriber->id_public.binary, crypto_sign_PUBLICKEYBYTES);
  }else{
    ob_append_byte(b, SID_SIZE);
    ob_append_bytes(b, subscriber->sid.binary, SID_SIZE);
  }

  if (ob_overrun(b)) {
    ob_rewind(b);
    return 1;
  }
  // let the routing engine know that we had to explain this sid, we probably need to re-send routing info
  link_explained(subscriber);
  return 0;
}

static int find_subscr_buffer(struct decode_context *context, struct overlay_buffer *b, int len, struct subscriber **subscriber)
{
  assert(subscriber);
  if (len<=0 || len>SID_SIZE)
    return WHYF("Invalid abbreviation length %d", len);
  
  uint8_t *id = ob_get_bytes_ptr(b, len);
  if (!id)
    return WHY("Not enough space in buffer to parse address");
  
  *subscriber=find_subscriber(id, len, 1);
  
  if (!*subscriber){
    if (!context)
      return WHYF("Unable to decode %s, with no context", alloca_tohex(id, len));

    context->flags|=DECODE_FLAG_INVALID_ADDRESS;
    
    if (context->flags & DECODE_FLAG_DONT_EXPLAIN){
      DEBUGF(subscriber, "Ignoring prefix %s", alloca_tohex(id, len));
    }else{
      // generate a please explain in the passed in context
      
      // add the abbreviation you told me about
      if (!context->please_explain){
	context->please_explain = calloc(sizeof(struct overlay_frame),1);
	if ((context->please_explain->payload = ob_new()) == NULL)
	  return -1;
	ob_limitsize(context->please_explain->payload, MDP_MTU);
      }
      
      // And I'll tell you about any subscribers I know that match this abbreviation, 
      // so you don't try to use an abbreviation that's too short in future.
      prefix_matches(id, len, add_explain_response, context);
      
      DEBUGF(subscriber, "Asking for explanation of %s", alloca_tohex(id, len));
      ob_append_byte(context->please_explain->payload, len);
      ob_append_bytes(context->please_explain->payload, id, len);
    }
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

static int decode_sid_from_signkey(struct overlay_buffer *b, struct subscriber **subscriber)
{
  const uint8_t *id = ob_get_bytes_ptr(b, crypto_sign_PUBLICKEYBYTES);
  if (!id)
    return WHY("Not enough space in buffer to parse address");
  sid_t sid;
  if (crypto_sign_ed25519_pk_to_curve25519(sid.binary, id))
    return WHY("Failed to convert sign key to sid");
  struct subscriber *s = find_subscriber(sid.binary, SID_SIZE, 1);
  if (s && !s->id_combined){
    bcopy(id, s->id_public.binary, crypto_sign_PUBLICKEYBYTES);
    s->id_valid=1;
    s->id_combined=1;
    DEBUGF(subscriber, "Stored combined SID:SAS mapping, SID=%s SAS=%s",
       alloca_tohex_sid_t(s->sid),
       alloca_tohex_identity_t(&s->id_public)
    );
  }
  if (subscriber)
    *subscriber=s;
  return 0;
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
        context->previous = *subscriber = get_my_subscriber();
      }else{
	WHYF("Could not resolve address on %s, this isn't a configured point to point link", context->interface->name);
	context->flags|=DECODE_FLAG_INVALID_ADDRESS;
      }
      return 0;

    case OA_CODE_P2P_ME:
      if (context->point_to_point_device){
        *subscriber=context->point_to_point_device;
	context->previous=*subscriber;
      }else{
	if ((context->flags & DECODE_FLAG_DONT_EXPLAIN) == 0){
	  // add the abbreviation you told me about
	  if (!context->please_explain){
	    context->please_explain = calloc(sizeof(struct overlay_frame),1);
	    if ((context->please_explain->payload = ob_new()) == NULL)
	      return -1;
	    ob_limitsize(context->please_explain->payload, MDP_MTU);
	  }
	  
	  DEBUGF(subscriber, "Asking for explanation of YOU");
	  ob_append_byte(context->please_explain->payload, OA_CODE_P2P_YOU);
	}
	context->flags|=DECODE_FLAG_INVALID_ADDRESS;
      }
      return 0;

    case OA_CODE_SELF:
      if (!context->sender){
	DEBUGF(subscriber, "Could not resolve address, sender has not been set");
	context->flags|=DECODE_FLAG_INVALID_ADDRESS;
      }else{
	*subscriber=context->sender;
	context->previous=context->sender;
      }
      return 0;
      
    case OA_CODE_PREVIOUS:
      if (!context->previous){
	DEBUGF(subscriber, "Unable to decode previous address");
	context->flags|=DECODE_FLAG_INVALID_ADDRESS;
      }else{
	*subscriber=context->previous;
      }
      return 0;

    case OA_CODE_SIGNKEY:
      return decode_sid_from_signkey(b, subscriber);
  }
  
  return find_subscr_buffer(context, b, len, subscriber);
}

// once we've finished parsing a packet, complete and send a please explain if required.
int send_please_explain(struct decode_context *context, struct subscriber *source, struct subscriber *destination)
{
  IN();
  struct overlay_frame *frame=context->please_explain;
  if (frame == NULL)
    RETURN(0);
  assert(frame->payload != NULL);
  frame->type = OF_TYPE_PLEASEEXPLAIN;
  
  if (source)
    frame->source = source;
  else
    frame->source = get_my_subscriber();
  
  if (!context->sender)
    frame->source_full=1;
  
  frame->destination = destination;
  if (destination){
    frame->ttl = PAYLOAD_TTL_DEFAULT; // MAX?
    frame->source_full=1;
  }else{
    // send both a broadcast & unicast response out the same interface this packet arrived on.
    frame->ttl=1;// how will this work with olsr??
    if (context->interface){
      frame_add_destination(frame, NULL, context->interface->destination);
      
      struct network_destination *dest = create_unicast_destination(&context->addr, context->interface);
      if (dest)
	frame_add_destination(frame, NULL, dest);
    
    }else{
      FATAL("This context doesn't have an interface?");
    }
  }
  
  frame->queue=OQ_MESH_MANAGEMENT;
  if (overlay_payload_enqueue(frame) != -1)
    RETURN(0);
  op_free(frame);
  RETURN(-1);
  OUT();
}

// process an incoming request for explanation of subscriber abbreviations
int process_explain(struct overlay_frame *frame)
{
  struct overlay_buffer *b=frame->payload;
  
  struct decode_context context;
  bzero(&context, sizeof context);
  context.sender = frame->source;
  context.interface = frame->interface;
  
  while(ob_remaining(b)>0){
    int len = ob_get(b);
    switch (len){
      case OA_CODE_P2P_YOU:
	add_explain_response(get_my_subscriber(), &context);
	break;
      case OA_CODE_SIGNKEY:
	decode_sid_from_signkey(b, NULL);
	break;
      case SID_SIZE:
      {
	// This message is also used to inform people of previously unknown subscribers
	// make sure we know this one
	uint8_t *sid = ob_get_bytes_ptr(b, SID_SIZE);
	if (!sid)
	  return WHY("Ran past end of buffer");
	DEBUGF(subscriber, "Storing explain response for %s", alloca_tohex(sid, SID_SIZE));
	find_subscriber(sid, SID_SIZE, 1);
	break;
      }
      default:
      {
	if (len<=0 || len>SID_SIZE)
	  return WHY("Badly formatted explain message");
	uint8_t *sid = ob_get_bytes_ptr(b, len);
	// reply to the sender with all subscribers that match this abbreviation
	DEBUGF(subscriber, "Sending explain responses for %s", alloca_tohex(sid, len));
	prefix_matches(sid, len, add_explain_response, &context);
      }
    }
  }
  if (context.please_explain)
    send_please_explain(&context, frame->destination, frame->source);
  return 0;
}
