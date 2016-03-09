
#include "rhizome.h"
#include "overlay_address.h"
#include "overlay_buffer.h"
#include "overlay_packet.h"
#include "mdp_client.h"
#include "log.h"
#include "debug.h"
#include "conf.h"
#include "sync_keys.h"
#include "fdqueue.h"
#include "overlay_interface.h"
#include "route_link.h"

struct sync_state *sync_tree=NULL;

static void sync_peer_has (void * UNUSED(context), void *peer_context, const sync_key_t *key)
{
  // request manifest? keep trying?
  // remember & ignore expired manifest id's?
  struct subscriber *peer = (struct subscriber *)peer_context;
  DEBUGF(rhizome_sync_keys, "Neighbour %s has %s that we need",
    alloca_tohex_sid_t(peer->sid),
    alloca_sync_key(key));
  
  // TODO queue transfers, with retry
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
  
  // TODO queue these advertisements based on rank!
  
  rhizome_manifest *m = rhizome_new_manifest();
  if (!m)
    return;
  
  if (rhizome_retrieve_manifest_by_hash_prefix(key->key, sizeof(*key), m)==RHIZOME_BUNDLE_STATUS_SAME){
    rhizome_advertise_manifest(peer, m);
    // pre-emptively send the payload if it will fit in a single packet
    if (m->filesize > 0 && m->filesize <= 1024)
      rhizome_mdp_send_block(peer, &m->cryptoSignPublic, m->version, 0, 0, m->filesize);
  }
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

DEFINE_ALARM(sync_send_data);
void sync_send_data(struct sched_ent *alarm)
{
  if (!sync_tree)
    build_tree();
  
  uint8_t buff[MDP_MTU];
  size_t len = sync_build_message(sync_tree, buff, sizeof buff);
  if (len==0)
    return;
  
  DEBUG(rhizome_sync_keys,"Sending message");
  dump("Raw message", buff, len);
  
  struct overlay_buffer *payload = ob_static(buff, sizeof(buff));
  ob_limitsize(payload, len);
  
  struct internal_mdp_header header;
  bzero(&header, sizeof header);
  
  header.crypt_flags = MDP_FLAG_NO_CRYPT | MDP_FLAG_NO_SIGN;
  header.source = my_subscriber;
  header.source_port = MDP_PORT_RHIZOME_SYNC_KEYS;
  header.destination_port = MDP_PORT_RHIZOME_SYNC_KEYS;
  header.qos = OQ_OPPORTUNISTIC;
  header.ttl = 1;
  overlay_send_frame(&header, payload);
  
  time_ms_t now = gettime_ms();
  
  if (sync_has_transmit_queued(sync_tree)){
    DEBUG(rhizome_sync_keys,"Queueing next message for 5ms");
    RESCHEDULE(alarm, now+5, now+5, now+5);
  }else{
    DEBUG(rhizome_sync_keys,"Queueing next message for 5s");
    RESCHEDULE(alarm, now+5000, now+30000, TIME_MS_NEVER_WILL);
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
    DEBUGF(rhizome_sync_keys,"Processing message from %s", alloca_tohex_sid_t(header->source->sid));
    dump("Raw message", ob_current_ptr(payload), ob_remaining(payload));
    sync_recv_message(sync_tree, header->source, ob_current_ptr(payload), ob_remaining(payload));
    if (sync_has_transmit_queued(sync_tree)){
      struct sched_ent *alarm=&ALARM_STRUCT(sync_send_data);
      time_ms_t next = gettime_ms() + 5;
      if (alarm->alarm > next){
	DEBUG(rhizome_sync_keys,"Queueing next message for 5ms");
	RESCHEDULE(alarm, next, next, next);
      }
    }
  }else{
    // TODO 
  }
  
  return 0;
}

static void sync_neighbour_changed(struct subscriber *UNUSED(neighbour), uint8_t UNUSED(found), unsigned count)
{
  struct sched_ent *alarm = &ALARM_STRUCT(sync_send_data);
  
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
    struct sched_ent *alarm = &ALARM_STRUCT(sync_send_data);
    time_ms_t next = gettime_ms()+5;
    if (alarm->alarm > next){
      DEBUG(rhizome_sync_keys,"Queueing next message for 5ms");
      RESCHEDULE(alarm, next, next, next);
    }
  }
}

DEFINE_TRIGGER(bundle_add, sync_bundle_add);
