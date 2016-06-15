
#include "rhizome.h"
#include "overlay_address.h"
#include "overlay_buffer.h"
#include "overlay_packet.h"
#include "mdp_client.h"
#include "msp_server.h"
#include "log.h"
#include "debug.h"
#include "conf.h"
#include "sync_keys.h"
#include "fdqueue.h"
#include "overlay_interface.h"
#include "route_link.h"
#include "mem.h"

#define STATE_SEND (1)
#define STATE_REQ (2)
#define STATE_RECV (3)

#define STATE_BAR (4)
#define STATE_MANIFEST (8)
#define STATE_PAYLOAD (12)

#define STATE_NONE (0)
#define STATE_SEND_BAR (STATE_SEND|STATE_BAR)
#define STATE_REQ_MANIFEST (STATE_REQ|STATE_MANIFEST)
#define STATE_SEND_MANIFEST (STATE_SEND|STATE_MANIFEST)
#define STATE_REQ_PAYLOAD (STATE_REQ|STATE_PAYLOAD)
#define STATE_SEND_PAYLOAD (STATE_SEND|STATE_PAYLOAD)
#define STATE_RECV_PAYLOAD (STATE_RECV|STATE_PAYLOAD)

// approx size of a signed manifest
#define DUMMY_MANIFEST_SIZE 256

#define REACHABLE_BIAS 2

struct transfers{
  struct transfers *next;
  sync_key_t key;
  uint8_t state;
  uint8_t rank;
  rhizome_manifest *manifest;
  size_t req_len;
  union{
    struct rhizome_read *read;
    struct rhizome_write *write;
    rhizome_bar_t bar;
  };
};

struct rhizome_sync_keys{
  struct transfers *queue;
  struct msp_server_state *connection;
};

#define MAX_REQUEST_BYTES (16*1024)

struct sync_state *sync_tree=NULL;
struct msp_server_state *sync_connections=NULL;
DEFINE_ALARM(sync_send);

static struct rhizome_sync_keys *get_peer_sync_state(struct subscriber *peer){
  if (!peer->sync_keys_state)
    peer->sync_keys_state = emalloc_zero(sizeof(struct rhizome_sync_keys));
  return peer->sync_keys_state;
}

static const char *get_state_name(uint8_t state)
{
  switch(state){
    case STATE_NONE: return "NONE";
    case STATE_SEND_BAR: return "SEND_BAR";
    case STATE_REQ_MANIFEST: return "REQ_MANIFEST";
    case STATE_SEND_MANIFEST: return "SEND_MANIFEST";
    case STATE_REQ_PAYLOAD: return "REQ_PAYLOAD";
    case STATE_SEND_PAYLOAD: return "SEND_PAYLOAD";
    case STATE_RECV_PAYLOAD: return "RECV_PAYLOAD";
  }
  return "Unknown";
}

static void _clear_transfer(struct __sourceloc __whence, struct transfers *ptr)
{
  DEBUGF(rhizome_sync_keys, "Clearing %s %s", get_state_name(ptr->state), alloca_sync_key(&ptr->key));
  switch (ptr->state){
    case STATE_SEND_PAYLOAD:
      if (ptr->read){
	rhizome_read_close(ptr->read);
	free(ptr->read);
      }
      ptr->read=NULL;
      break;
    case STATE_RECV_PAYLOAD:
      if (ptr->write){
	rhizome_fail_write(ptr->write);
	free(ptr->write);
      }
      ptr->write=NULL;
      break;
  }
  ptr->state=STATE_NONE;
}
#define clear_transfer(P) _clear_transfer(__WHENCE__,P)

static struct transfers **find_and_update_transfer(struct subscriber *peer, struct rhizome_sync_keys *keys_state, const sync_key_t *key, uint8_t state, int rank)
{
  if (rank>0xFF)
    rank = 0xFF;
  if (state){
    if (!keys_state->connection)
      keys_state->connection = msp_find_or_connect(&sync_connections,
	  peer, MDP_PORT_RHIZOME_SYNC_KEYS,
	  get_my_subscriber(), MDP_PORT_RHIZOME_SYNC_KEYS,
	  OQ_OPPORTUNISTIC);

    if (msp_can_send(keys_state->connection)){
      time_ms_t next_action = gettime_ms();
      struct sched_ent *alarm=&ALARM_STRUCT(sync_send);
      if (next_action < alarm->alarm || !is_scheduled(alarm))
	RESCHEDULE(alarm, next_action, next_action, next_action);
    }
  }

  struct transfers **ptr = &keys_state->queue;
  while(*ptr){
    if (memcmp(key, &(*ptr)->key, sizeof(sync_key_t))==0){
      if (state){
	if ((*ptr)->state && (*ptr)->state!=state){
	  DEBUGF(rhizome_sync_keys, "Updating state from %s to %s %s", 
            get_state_name((*ptr)->state), get_state_name(state), alloca_sync_key(key));
	  clear_transfer(*ptr);
	}
	(*ptr)->state = state;
      }
      return ptr;
    }
    if (rank>=0 && (*ptr)->rank > rank)
      break;
    ptr = &(*ptr)->next;
  }
  if (rank<0)
    return NULL;
  struct transfers *ret = emalloc_zero(sizeof(struct transfers));
  ret->key = *key;
  ret->rank = rank;
  ret->state = state;
  ret->next = (*ptr);
  (*ptr) = ret;
  DEBUGF(rhizome_sync_keys, "Queued transfer message %s %s", get_state_name(ret->state), alloca_sync_key(key));
  return ptr;
}

static void sync_key_diffs(void *UNUSED(context), void *peer_context, const sync_key_t *key, uint8_t ours)
{
  struct subscriber *peer = (struct subscriber *)peer_context;
  struct rhizome_sync_keys *sync_keys = get_peer_sync_state(peer);
  struct transfers **transfer = find_and_update_transfer(peer, sync_keys, key, 0, -1);
  
  DEBUGF(rhizome_sync_keys, "Peer %s %s %s %s",
    alloca_tohex_sid_t(peer->sid),
    ours?"missing":"has",
    alloca_sync_key(key),
    transfer?get_state_name((*transfer)->state):"No transfer");
    
  if (transfer){
    struct transfers *msg = *transfer;
    switch(msg->state){
      case STATE_REQ_PAYLOAD:
	DEBUGF(rhizome_sync_keys, " - Requesting payload [%zu of %zu]", msg->write->file_offset, msg->write->file_length);
	break;
      case STATE_SEND_PAYLOAD:
	DEBUGF(rhizome_sync_keys, " - Sending payload [%zu of %zu]", msg->read->offset, msg->read->length);
	break;
      case STATE_RECV_PAYLOAD:
	DEBUGF(rhizome_sync_keys, " - Receiving payload [%zu of %zu]", msg->write->file_offset, msg->write->file_length);
	break;
    }
  }
}

DEFINE_ALARM(sync_keys_status);
void sync_keys_status(struct sched_ent *alarm)
{
  if (!IF_DEBUG(rhizome_sync_keys))
    return;
  
  DEBUGF(rhizome_sync_keys, "Sync state;");
  sync_enum_differences(sync_tree, sync_key_diffs);
  
  time_ms_t next = gettime_ms()+1000;
  RESCHEDULE(alarm, next, next, next);
}

static void sync_send_peer(struct rhizome_sync_keys *sync_state)
{
  size_t mtu = MSP_MESSAGE_SIZE; // FIX ME, use link mtu?
  
  struct overlay_buffer *payload=NULL;
  uint8_t buff[mtu];
  
  // send requests for more data, stop when we hit MAX_REQUEST_BYTES
  // Note that requests are ordered by rank, 
  // so we will still request a high rank item even if there is a low ranked item being received
  struct transfers **ptr = &sync_state->queue;
  size_t requested_bytes = 0;
  time_ms_t now = gettime_ms();

  while((*ptr) && msp_can_send(sync_state->connection) && requested_bytes < MAX_REQUEST_BYTES){
    struct transfers *msg = *ptr;
    if (msg->state == STATE_RECV_PAYLOAD){
      requested_bytes+=msg->req_len;
    }else if ((msg->state & 3) == STATE_REQ){
      if (!payload){
	payload = ob_static(buff, sizeof(buff));
	ob_limitsize(payload, sizeof(buff));
      }
      
      DEBUGF(rhizome_sync_keys, "Sending sync messsage %s %s", get_state_name(msg->state), alloca_sync_key(&msg->key));
      ob_append_byte(payload, msg->state);
      ob_append_bytes(payload, msg->key.key, sizeof(msg->key));
      ob_append_byte(payload, msg->rank);
      
      // start from the specified file offset (eg journals, but one day perhaps resuming transfers)
      if (msg->state == STATE_REQ_PAYLOAD){
	ob_append_packed_ui64(payload, msg->write->file_offset);
	ob_append_packed_ui64(payload, msg->req_len);
      }
      
      if (ob_overrun(payload)){
	ob_rewind(payload);
	msp_send_packet(sync_state->connection, ob_ptr(payload), ob_position(payload));
	ob_clear(payload);
	ob_limitsize(payload, sizeof(buff));
      }else{
	ob_checkpoint(payload);
	requested_bytes+=msg->req_len;
	if (msg->state == STATE_REQ_PAYLOAD){
	  // keep hold of the manifest pointer
	  msg->state = STATE_RECV_PAYLOAD;
	}else{
	  *ptr = msg->next;
	  clear_transfer(msg);
	  if (msg->manifest)
	    rhizome_manifest_free(msg->manifest);
	  msg->manifest=NULL;
	  free(msg);
	  continue;
	}
      }
    }
    ptr = &msg->next;
  }
  
  // now send requested data
  ptr = &sync_state->queue;
  while((*ptr) && msp_can_send(sync_state->connection)){
    struct transfers *msg = *ptr;
    if ((msg->state & 3) != STATE_SEND){
      ptr = &msg->next;
      continue;
    }
    
    if (!payload){
      payload = ob_static(buff, sizeof(buff));
      ob_limitsize(payload, sizeof(buff));
    }
    
    uint8_t msg_complete=1;
    uint8_t send_payload=0;
    DEBUGF(rhizome_sync_keys, "Sending sync messsage %s %s", get_state_name(msg->state), alloca_sync_key(&msg->key));
    ob_append_byte(payload, msg->state);
    ob_append_bytes(payload, msg->key.key, sizeof(msg->key));
    
    switch(msg->state){
      case STATE_SEND_BAR:{
	ob_append_bytes(payload, msg->bar.binary, sizeof(msg->bar));
	break;
      }
      case STATE_SEND_MANIFEST:{
	rhizome_manifest *m = rhizome_new_manifest();
	if (!m){
	  ob_rewind(payload);
	  assert(ob_position(payload));
	  msg_complete = 0;
	}else{
	  enum rhizome_bundle_status status = rhizome_retrieve_manifest_by_hash_prefix(msg->key.key, sizeof(msg->key), m);
	  switch(status){
	    case RHIZOME_BUNDLE_STATUS_SAME:
	      // TODO fragment manifests
	      ob_append_bytes(payload, m->manifestdata, m->manifest_all_bytes);
	      send_payload=1;
	      break;
	    case RHIZOME_BUNDLE_STATUS_NEW:
	      // TODO we don't have this bundle anymore!
	    default:
	      ob_rewind(payload);
	  }
	  rhizome_manifest_free(m);
	}
	break;
      }
      case STATE_SEND_PAYLOAD:{
	size_t max_len = ob_remaining(payload);
	if (max_len > msg->req_len)
	  max_len = msg->req_len;
	ssize_t payload_len = rhizome_read(msg->read, ob_current_ptr(payload), max_len);
	if (payload_len==-1){
	  ob_rewind(payload);
	}else{
	  ob_append_space(payload, payload_len);
	  send_payload=1;
	}
	DEBUGF(rhizome_sync_keys, "Sending %s %zd bytes (now %zd of %zd)", 
	  alloca_sync_key(&msg->key), payload_len, msg->read->offset, msg->read->length);
	
	msg->req_len -= payload_len;
	if (msg->read->offset < msg->read->length && msg->req_len>0)
	  msg_complete=0;
	
	break;
      }
      default:
	FATALF("Unexpected state %x", msg->state);
    }
    
    if (ob_overrun(payload)){
      ob_rewind(payload);
      msg_complete=0;
      send_payload=1;
    }else{
      ob_checkpoint(payload);
    }
    
    if (send_payload){
      msp_send_packet(sync_state->connection, ob_ptr(payload), ob_position(payload));
      ob_clear(payload);
      ob_limitsize(payload, sizeof(buff));
    }
    
    if (msg_complete){
      *ptr = msg->next;
      clear_transfer(msg);
      if (msg->manifest)
	rhizome_manifest_free(msg->manifest);
      msg->manifest=NULL;
      free(msg);
    }
    // else, try to send another chunk of this payload immediately
  }
  
  if (payload){
    if (ob_position(payload))
      msp_send_packet(sync_state->connection, ob_ptr(payload), ob_position(payload));
    ob_free(payload);
  }

  if (msp_queued_packet_count(sync_state->connection)==0 &&
    (msp_get_connection_state(sync_state->connection) & MSP_STATE_RECEIVED_PACKET) &&
    now - msp_last_packet(sync_state->connection) > 5000){
    DEBUGF(rhizome_sync_keys, "Closing idle connection");
    msp_shutdown_stream(sync_state->connection);
  }
}

void sync_send(struct sched_ent *alarm)
{
  struct msp_iterator iterator;
  msp_iterator_open(&sync_connections, &iterator);
  
  while(1){
    struct msp_server_state *connection = msp_process_next(&iterator);
    if (!connection)
      break;
    
    struct subscriber *peer = msp_remote_peer(connection);
    struct rhizome_sync_keys *sync_state = get_peer_sync_state(peer);
    sync_state->connection = connection;
    sync_send_peer(sync_state);
  }
  
  while(1){
    struct msp_server_state *connection = msp_next_closed(&iterator);
    if (!connection)
      break;
    
    struct subscriber *peer = msp_remote_peer(connection);
    struct rhizome_sync_keys *sync_state = get_peer_sync_state(peer);
    
    DEBUGF(rhizome_sync_keys, "Connection closed %s", alloca_tohex_sid_t(peer->sid));
    
    // drop all transfer records
    while(sync_state->queue){
      struct transfers *msg = sync_state->queue;
      sync_state->queue = msg->next;
      clear_transfer(msg);
      free(msg);
    }
    
    sync_state->connection = NULL;
    // eg connection timeout; drop all sync state
    if (msp_get_connection_state(connection)& (MSP_STATE_ERROR|MSP_STATE_STOPPED))
      sync_free_peer_state(sync_tree, peer);
  }
  
  time_ms_t next_action = msp_iterator_close(&iterator);
  RESCHEDULE(alarm, next_action, next_action, next_action);
}

static void sync_peer_has (void * UNUSED(context), void *peer_context, const sync_key_t *key)
{
  // request manifest? keep trying?
  // remember & ignore expired manifest id's?
  struct subscriber *peer = (struct subscriber *)peer_context;
  DEBUGF(rhizome_sync_keys, "Neighbour %s has %s that we need",
    alloca_tohex_sid_t(peer->sid),
    alloca_sync_key(key));
  
  // noop, just wait for the BAR to arrive.
}

static void sync_peer_does_not_have (void * UNUSED(context), void *peer_context, void * UNUSED(key_context), const sync_key_t *key)
{
  // pre-emptively announce the manifest?
  // use some form of stream socket to manage available bandwidth?
  // build a default rank ordered list of manifests to announce?
  struct subscriber *peer = (struct subscriber *)peer_context;
  DEBUGF(rhizome_sync_keys, "Neighbour %s does not have %s that we do",
    alloca_tohex_sid_t(peer->sid),
    alloca_sync_key(key));
  
  // queue BAR for transmission based on the manifest details.
  // add a rank bias if there is no reachable recipient to prioritise messaging

  rhizome_manifest *m = rhizome_new_manifest();
  if (!m)
    return;

  enum rhizome_bundle_status status = rhizome_retrieve_manifest_by_hash_prefix(key->key, sizeof(sync_key_t), m);
  switch(status){
    case RHIZOME_BUNDLE_STATUS_SAME:
      break;
    case RHIZOME_BUNDLE_STATUS_NEW:
      // TODO We don't have this bundle anymore!
    default:
      goto end;
  }

  uint8_t bias = REACHABLE_BIAS;
  int rank = log2ll(m->filesize);

  if (m->has_recipient){
    struct subscriber *recipient = find_subscriber(m->recipient.binary, sizeof m->recipient, 0);
    if (recipient && (recipient->reachable & (REACHABLE | REACHABLE_SELF)))
      bias=0;
  }

  struct rhizome_sync_keys *sync_state = get_peer_sync_state(peer);
  if (!sync_state)
    goto end;

  struct transfers *send_bar = *find_and_update_transfer(peer, sync_state, key, STATE_SEND_BAR, rank + bias);
  if (!send_bar)
    goto end;

  rhizome_manifest_to_bar(m, &send_bar->bar);

end:
  rhizome_manifest_free(m);
}

static void sync_peer_now_has (void * UNUSED(context), void *peer_context, void * UNUSED(key_context), const sync_key_t *key)
{
  // remove transfer state?
  struct subscriber *peer = (struct subscriber *)peer_context;
  DEBUGF(rhizome_sync_keys, "Neighbour %s has now received %s",
    alloca_tohex_sid_t(peer->sid),
    alloca_sync_key(key));
}

// this is probably fast enough. For huge stores, or slow storage media
// we might need to use an alarm to slowly build this tree
static void build_tree()
{
  sync_tree = sync_alloc_state(NULL, sync_peer_has, sync_peer_does_not_have, sync_peer_now_has);
  
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  sqlite3_stmt *statement = sqlite_prepare(&retry, "SELECT manifest_hash FROM manifests "
    "WHERE manifests.filehash IS NULL OR EXISTS(SELECT 1 FROM files WHERE files.id = manifests.filehash);");
  while (sqlite_step_retry(&retry, statement) == SQLITE_ROW) {
    const char *hash = (const char *) sqlite3_column_text(statement, 0);
    rhizome_filehash_t manifest_hash;
    if (str_to_rhizome_filehash_t(&manifest_hash, hash)==0){
      sync_key_t key;
      memcpy(key.key, manifest_hash.binary, sizeof(sync_key_t));
      DEBUGF(rhizome_sync_keys, "Adding %s to tree",
	alloca_sync_key(&key));
      sync_add_key(sync_tree, &key, NULL);
    }
  }
  sqlite3_finalize(statement);
}

DEFINE_ALARM(sync_send_keys);
void sync_send_keys(struct sched_ent *alarm)
{
  if (!sync_tree)
    build_tree();
  
  uint8_t buff[MDP_MTU];
  size_t len = sync_build_message(sync_tree, buff, sizeof buff);
  if (len==0)
    return;

  if (IF_DEBUG(rhizome_sync_keys)){
    DEBUG(rhizome_sync_keys,"Sending message");
    //dump("Raw message", buff, len);
  }
  
  struct overlay_buffer *payload = ob_static(buff, sizeof(buff));
  ob_limitsize(payload, len);
  
  struct internal_mdp_header header;
  bzero(&header, sizeof header);
  
  header.crypt_flags = MDP_FLAG_NO_CRYPT | MDP_FLAG_NO_SIGN;
  header.source = get_my_subscriber();
  header.source_port = MDP_PORT_RHIZOME_SYNC_KEYS;
  header.destination_port = MDP_PORT_RHIZOME_SYNC_KEYS;
  header.qos = OQ_OPPORTUNISTIC;
  header.ttl = 1;
  overlay_send_frame(&header, payload);
  
  time_ms_t now = gettime_ms();
  
  if (sync_has_transmit_queued(sync_tree)){
    DEBUG(rhizome_sync_keys,"Queueing next message for now");
    RESCHEDULE(alarm, now, now, now);
  }else{
    DEBUG(rhizome_sync_keys,"Queueing next message for 5s");
    RESCHEDULE(alarm, now+5000, now+30000, TIME_MS_NEVER_WILL);
  }
}

static void process_transfer_message(struct subscriber *peer, struct rhizome_sync_keys *sync_state, struct overlay_buffer *payload)
{
  while(ob_remaining(payload)){
    ob_checkpoint(payload);
    int msg_state = ob_get(payload);
    if (msg_state<0)
      return;
    sync_key_t key;
    if (ob_get_bytes(payload, key.key, sizeof key)<0)
      return;
    
    int rank=-1;
    if (msg_state & STATE_REQ){
      rank = ob_get(payload);
      if (rank < 0)
	return;
    }
    
    DEBUGF(rhizome_sync_keys, "Processing sync message %s %s %d", 
      get_state_name(msg_state), alloca_sync_key(&key), rank);
    switch(msg_state){
      case STATE_SEND_BAR:{
	rhizome_bar_t bar;
	if (ob_get_bytes(payload, bar.binary, sizeof(rhizome_bar_t))<0)
	  return;
	
	if (!config.rhizome.fetch)
	  break;
	if (!rhizome_is_bar_interesting(&bar)){
	  DEBUGF(rhizome_sync_keys, "Ignoring BAR for %s, (Uninteresting)", 
	    alloca_sync_key(&key));
	  break;
        }
	
	// send a request for the manifest
	rank = rhizome_bar_log_size(&bar);
	struct transfers *transfer = *find_and_update_transfer(peer, sync_state, &key, STATE_REQ_MANIFEST, rank);
	transfer->req_len = DUMMY_MANIFEST_SIZE;
	break;
      }
      
      case STATE_REQ_MANIFEST:{
	// queue the transmission of the manifest
	find_and_update_transfer(peer, sync_state, &key, STATE_SEND_MANIFEST, rank);
	break;
      }
      
      case STATE_SEND_MANIFEST:{
	// process the incoming manifest
	size_t len = ob_remaining(payload);
	uint8_t *data = ob_get_bytes_ptr(payload, len);
	
	if (!config.rhizome.fetch)
	  break;
	
	struct rhizome_manifest_summary summ;
	if (!rhizome_manifest_inspect((char *)data, len, &summ)){
	  WHYF("Ignoring manifest for %s, (Malformed)", 
	    alloca_sync_key(&key));
	  break;
	}
	
	// The manifest looks potentially interesting, so now do a full parse and validation.
	rhizome_manifest *m = rhizome_new_manifest();
	if (!m){
	  // don't consume the payload
	  ob_rewind(payload);
	  return;
	}
	
	memcpy(m->manifestdata, data, len);
	m->manifest_all_bytes = len;
	if (   rhizome_manifest_parse(m) == -1
	    || !rhizome_manifest_validate(m)
	) {
	  WHYF("Ignoring manifest for %s, (Malformed)", 
	    alloca_sync_key(&key));
	  rhizome_manifest_free(m);
	  break;
	}
	
	if (!rhizome_is_manifest_interesting(m)){
	  DEBUGF(rhizome_sync_keys, "Ignoring manifest for %s, (Uninteresting)", 
	    alloca_sync_key(&key));
	  rhizome_manifest_free(m);
	  break;
	}
	
	// start writing the payload
	
	enum rhizome_payload_status status;
	struct rhizome_write *write = emalloc_zero(sizeof(struct rhizome_write));
	
	if (m->filesize==0){
	  status = RHIZOME_PAYLOAD_STATUS_STORED;
	}else{
	  status = rhizome_open_write(write, &m->filehash, m->filesize);
	}
	
	if (status == RHIZOME_PAYLOAD_STATUS_STORED){
	  enum rhizome_bundle_status add_status = rhizome_add_manifest_to_store(m, NULL);
	  DEBUGF(rhizome_sync_keys, "Already have payload, imported manifest for %s, (%s)", 
	    alloca_sync_key(&key), rhizome_bundle_status_message_nonnull(add_status));
	  rhizome_manifest_free(m);
	  free(write);
	  break;
	}else if (status!=RHIZOME_PAYLOAD_STATUS_NEW){
	  DEBUGF(rhizome_sync_keys, "Ignoring manifest for %s, (%s)", 
	    alloca_sync_key(&key), rhizome_payload_status_message_nonnull(status));
	  rhizome_manifest_free(m);
	  free(write);
	  break;
	}
	
	
	if (m->is_journal){
	  // if we're fetching a journal bundle, copy any bytes we have of a previous version
	  // and therefore work out what range of bytes we still need
	  rhizome_manifest *previous = rhizome_new_manifest();
	  if (rhizome_retrieve_manifest(&m->cryptoSignPublic, previous)==RHIZOME_BUNDLE_STATUS_SAME &&
	    previous->is_journal &&
	    previous->tail <= m->tail &&
	    previous->filesize + previous->tail > m->tail
	  ){
	    uint64_t start = m->tail - previous->tail;
	    uint64_t length = previous->filesize - start;
	    // required by tests;
	    DEBUGF(rhizome_sync_keys, "%s Copying %"PRId64" bytes from previous journal", alloca_sync_key(&key), length);
	    rhizome_journal_pipe(write, &previous->filehash, start, length);
	  }
	  rhizome_manifest_free(previous);
	  
	  if (write->file_offset >= m->filesize){
	    // no new content in the new version, we can import now
	    enum rhizome_payload_status status = rhizome_finish_write(write);
	    DEBUGF(rhizome_sync_keys, "Write complete %s (%d)", alloca_sync_key(&key), status);
	    free(write);
	    if (status == RHIZOME_PAYLOAD_STATUS_NEW || status == RHIZOME_PAYLOAD_STATUS_STORED){
	      enum rhizome_bundle_status add_state = rhizome_add_manifest_to_store(m, NULL);
	      DEBUGF(rhizome_sync_keys, "Import %s = %s", 
		alloca_sync_key(&key), rhizome_bundle_status_message_nonnull(add_state));
	    }
	    rhizome_manifest_free(m);
	    break;
	  }
	}

	// TODO improve rank algo here;
	// Note that we still need to deal with this manifest, we don't want to run out of RAM
	rank = log2ll(m->filesize - write->file_offset);
	uint8_t bias = REACHABLE_BIAS;

	if (m->has_recipient){
	  struct subscriber *recipient = find_subscriber(m->recipient.binary, sizeof m->recipient, 0);
	  if (recipient && (recipient->reachable & (REACHABLE | REACHABLE_SELF)))
	    bias=0;
	}

	struct transfers *transfer = *find_and_update_transfer(peer, sync_state, &key, STATE_REQ_PAYLOAD, rank + bias);
	transfer->manifest = m;
	transfer->req_len = m->filesize - write->file_offset;
	transfer->write = write;
	break;
      }
      case STATE_REQ_PAYLOAD:{
	// open the payload for reading
	uint64_t offset = ob_get_packed_ui64(payload);
	uint64_t length = ob_get_packed_ui64(payload);
	
	rhizome_manifest *m = rhizome_new_manifest();
	if (!m){
	  ob_rewind(payload);
	  return;
	}

	enum rhizome_bundle_status status = rhizome_retrieve_manifest_by_hash_prefix(key.key, sizeof(sync_key_t), m);
	if (status == RHIZOME_BUNDLE_STATUS_NEW){
	  // TODO We don't have this bundle anymore!
	}
	if (status != RHIZOME_BUNDLE_STATUS_SAME){
	  rhizome_manifest_free(m);
	  break;
	}

	struct rhizome_read *read = emalloc_zero(sizeof (struct rhizome_read));
	
	if (rhizome_open_read(read, &m->filehash) != RHIZOME_PAYLOAD_STATUS_STORED){
	  free(read);
	  rhizome_manifest_free(m);
	  break;
	}
	rhizome_manifest_free(m);
	
	struct transfers *transfer = *find_and_update_transfer(peer, sync_state, &key, STATE_SEND_PAYLOAD, rank);
	transfer->read = read;
	transfer->req_len = length;
	read->offset = offset;
	break;
      }
      case STATE_SEND_PAYLOAD:{
	size_t len = ob_remaining(payload);
	uint8_t *buff = ob_get_bytes_ptr(payload, len);
	
	struct transfers **ptr = find_and_update_transfer(peer, sync_state, &key, STATE_RECV_PAYLOAD, -1);
	if (!ptr){
	  WHYF("Ignoring message for %s, no transfer in progress!", alloca_sync_key(&key));
	  break;
	}
	struct transfers *transfer = *ptr;
	transfer->req_len -= len;
	uint8_t all_done = 0;
	if (rhizome_write_buffer(transfer->write, buff, len)==-1){
	  WHYF("Write failed for %s!", alloca_sync_key(&key));
	  all_done=1;
	}else{
	  DEBUGF(rhizome_sync_keys, "Wrote to %s %zu, now %zu of %zu", 
	    alloca_sync_key(&key), len, transfer->write->file_offset, transfer->write->file_length);
	  if (transfer->write->file_offset >= transfer->write->file_length){
	    enum rhizome_payload_status status = rhizome_finish_write(transfer->write);
	    DEBUGF(rhizome_sync_keys, "Write complete %s (%d)", alloca_sync_key(&key), status);
	    free(transfer->write);
	    transfer->write = NULL;
	    if (status == RHIZOME_PAYLOAD_STATUS_NEW || status == RHIZOME_PAYLOAD_STATUS_STORED){
	      enum rhizome_bundle_status add_state = rhizome_add_manifest_to_store(transfer->manifest, NULL);
	      DEBUGF(rhizome_sync_keys, "Import %s = %s", 
		alloca_sync_key(&key), rhizome_bundle_status_message_nonnull(add_state));
	    }
	    all_done=1;
	  }
	}
	
	if (all_done){
	  if (transfer->manifest)
	    rhizome_manifest_free(transfer->manifest);
	  transfer->manifest=NULL;
	  clear_transfer(transfer);
	  *ptr = transfer->next;
	  free(transfer);
	}
	break;
      }
      default:
	WHYF("Unknown message type %x", msg_state);
    }
  }
}


DEFINE_BINDING(MDP_PORT_RHIZOME_SYNC_KEYS, sync_keys_recv);
static int sync_keys_recv(struct internal_mdp_header *header, struct overlay_buffer *payload)
{
  if (header->source->reachable == REACHABLE_SELF || !is_rhizome_advertise_enabled())
    return 0;
  
  if (!sync_tree)
    build_tree();
  
  header->source->sync_version = 1;
  
  if (!header->destination){
    if (IF_DEBUG(rhizome_sync_keys)){
      DEBUGF(rhizome_sync_keys,"Processing message from %s", alloca_tohex_sid_t(header->source->sid));
      //dump("Raw message", ob_current_ptr(payload), ob_remaining(payload));
    }
    sync_recv_message(sync_tree, header->source, ob_current_ptr(payload), ob_remaining(payload));
    if (sync_has_transmit_queued(sync_tree)){
      struct sched_ent *alarm=&ALARM_STRUCT(sync_send_keys);
      time_ms_t next = gettime_ms() + 5;
      if (alarm->alarm > next || !is_scheduled(alarm)){
	DEBUG(rhizome_sync_keys,"Queueing next message for 5ms");
	RESCHEDULE(alarm, next, next, next);
      }
    }
    
    if (IF_DEBUG(rhizome_sync_keys)){
      struct sched_ent *alarm=&ALARM_STRUCT(sync_keys_status);
      if (alarm->alarm == TIME_MS_NEVER_WILL){
	time_ms_t next = gettime_ms() + 1000;
	RESCHEDULE(alarm, next, next, next);
      }
    }
  }else{
    struct msp_server_state *connection_state = msp_find_and_process(&sync_connections, header, payload);
    if (connection_state){
      struct rhizome_sync_keys *sync_state = get_peer_sync_state(header->source);
      sync_state->connection = connection_state;
      
      while(1){
	struct msp_packet *packet = msp_recv_next(connection_state);
	if (!packet)
	  break;
	struct overlay_buffer *recv_payload = msp_unpack(connection_state, packet);
	if (recv_payload)
	  process_transfer_message(header->source, sync_state, recv_payload);
	msp_consumed(connection_state, packet, recv_payload);
      }
      
      sync_send_peer(sync_state);
      time_ms_t next_action = msp_next_action(connection_state);
      
      struct sched_ent *alarm=&ALARM_STRUCT(sync_send);
      if (alarm->alarm > next_action || !is_scheduled(alarm))
	RESCHEDULE(alarm, next_action, next_action, next_action);
    }
  }
  
  return 0;
}

static void sync_neighbour_changed(struct subscriber *neighbour, uint8_t found, unsigned count)
{
  struct sched_ent *alarm = &ALARM_STRUCT(sync_send_keys);
  
  if (count>0 && is_rhizome_advertise_enabled()){
    time_ms_t now = gettime_ms();
    if (alarm->alarm == TIME_MS_NEVER_WILL){
      DEBUG(rhizome_sync_keys,"Queueing next message now");
      RESCHEDULE(alarm, now, now, TIME_MS_NEVER_WILL);
    }
  }else{
    DEBUG(rhizome_sync_keys,"Stop queueing messages");
    RESCHEDULE(alarm, TIME_MS_NEVER_WILL, TIME_MS_NEVER_WILL, TIME_MS_NEVER_WILL);
  }
  
  if (!found){
    struct rhizome_sync_keys *sync_state = get_peer_sync_state(neighbour);
    // if there's no connection, there shouldn't be any items in the transfer queue
    if (sync_state->connection)
      msp_stop_stream(sync_state->connection);
  }
}
DEFINE_TRIGGER(nbr_change, sync_neighbour_changed);

static void sync_bundle_add(rhizome_manifest *m)
{
  if (!sync_tree){
    DEBUG(rhizome_sync_keys, "Ignoring added manifest, tree not built yet");
    return;
  }
  
  sync_key_t key;
  memcpy(key.key, m->manifesthash.binary, sizeof(sync_key_t));
  DEBUGF(rhizome_sync_keys, "Adding %s to tree",
    alloca_sync_key(&key));
  sync_add_key(sync_tree, &key, NULL);
  
  if (link_has_neighbours()){
    struct sched_ent *alarm = &ALARM_STRUCT(sync_send_keys);
    time_ms_t next = gettime_ms()+5;
    if (alarm->alarm > next || !is_scheduled(alarm)){
      DEBUG(rhizome_sync_keys,"Queueing next message for 5ms");
      RESCHEDULE(alarm, next, next, next);
    }
  }
}

DEFINE_TRIGGER(bundle_add, sync_bundle_add);
