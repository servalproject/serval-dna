/*
Copyright (C) Serval Project Inc.
Copyright (C) 2017 Bernhard Noelte

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


/** @addtogroup rhizome-sync
 * @{
 */

/** @defgroup rhizome-sync-keys Rhizome store synchronisation using keys.
 *
 * The protocol announces keys (bundle manifest hash) using broadcasts on port MDP_PORT_RHIZOME_SYNC_KEYS.
 *
 * The transfer of bundles between the bundle stores is done using dedicated MSP connections to peers also on port MDP_PORT_RHIZOME_SYNC_KEYS.
 * To prevent message overrun in case of multiple peers the number of active transfers and the total number of transfered bytes is limited.
 *
 * The synchronisation of bundles between peers is managed by the synchronisation tree that holds the difference between the peers bundle stores.
 * The content of the sync tree is exchanged by announcement messages. If both trees hold the same bundle the key of the bundle is deleted from the
 * synchronisation tree of both peers.
 *
 * In case a bundle breaks after synchronisation (broken paylaod/ manifest) a resynchronisation is issued by emptying the synchronisation tree
 * and incrementing the sync tree sequence number. The incremented sequence number is propagated to all peers which detect the increment and
 * empty the peer part within their own synchronisation tree. This leads to a full resynchronisation.
 *
 * Also every hour a re-synchronisation is triggered.
 *
 * @{
 */


/// Rhizome store sync keys synchonization control.
static struct sync_keys_control {
  /** Synchronisation tree (synchronization management structure) with other peers.
   *
   * Manages the keys (of bundles) that are different between us and the peers.
   */
  struct sync_state *tree;

  /// Time when the tree synchronization started.
  time_ms_t tree_use_start;

  /// Time of last management access to synchronisation tree.
  time_ms_t tree_use_last;

  /// Sequence number of sync tree.
  uint8_t tree_seqno;

  /// Number of broken bundles detected on last store alignment.
  int broken_count;

  /// Time when the broken count was increased the last time.
  time_ms_t broken_inc_last;

  /// Queue of connections to other peers.
  struct msp_server_state *connections;

  /// Maximum number of active bundle transfers to still init a new bundle transfer.
  int transfer_max_init;

  /// Maximum number of bytes to be requested by all bundle transfers.
  size_t transfer_max_request_bytes;
} sync_keys_control = { .transfer_max_init          = 6,
                        .transfer_max_request_bytes = (16*1024),
                      };


struct transfers {
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

// Forward declaration
static void _sync_keys_transfer_clear(struct __sourceloc __whence, struct transfers *ptr);
#define sync_keys_transfer_clear(P) _sync_keys_transfer_clear(__WHENCE__,P)


/** Is rhizome sync keys enabled.
 *
 * @return enabled 1 if enabled, 0 if not enabled.
 */
static int sync_keys_enabled(void)
{
  int enabled = 1;

  if ((config.rhizome.mdp.protocol >= 0) && (config.rhizome.mdp.protocol != RHIZOME_SYNC_PROTOCOL_VERSION_KEYS)) {
    // Sync protocol version is forced to another protocol.
    enabled = 0;
  }
  return enabled;
}


/** @name Peer synchronisation state
 *
 * @{
 */

/// State of synchronisation for a subscriber/ peer.
struct rhizome_sync_keys_peer_state {
  /// Sequence number of peers synchronization tree.
  uint8_t tree_seqno_peer;
  /// Sequence number of peers sync tree we did synchronize to.
  uint8_t tree_seqno_peer_synchronized;
  /// Sequence number of local sync tree we did synchronize to.
  uint8_t tree_seqno_local_synchronized;

  /// Time of last usage of synchronization status.
  time_ms_t last_use;

  /// Key of the bundle the last transfer was inited for (a bar was send).
  sync_key_t last_transfer_init_key;
  // The time the last transfer was initiated.
  time_ms_t last_transfer_init_time;

  /// Queue of bundle transfers.
  struct transfers *queue;
  /// Connection used for transfers with peer.
  struct msp_server_state *connection;
};


/** Mark peers synchronisation status to be used.
 *
 * Create the synchronisation status if not available.
 *
 * @param peer
 * @return sync_keys_state The synchronisation status.
 */
static struct rhizome_sync_keys_peer_state *sync_keys_peer_state_use(struct subscriber *peer)
{
  if (!peer->sync_keys_state)
    peer->sync_keys_state = emalloc_zero(sizeof(struct rhizome_sync_keys_peer_state));
  peer->sync_keys_state->last_use = gettime_ms();
  return peer->sync_keys_state;
}


/** Mark peers synchronization status to be unused.
 *
 * Stops the MSP connection immediatedly.
 *
 * Clears the sync state after some timeout.
 *
 * @param peer
 * @return sync_keys_state Synchronisation status or Null in case there is no synchronisation status (anymore).
 */
static struct rhizome_sync_keys_peer_state *sync_keys_peer_state_unuse(struct subscriber *peer)
{
  if (peer->sync_keys_state) {
    // Stop connection if still running
    if (peer->sync_keys_state->connection) {
      msp_stop_stream(peer->sync_keys_state->connection);
      // drop all transfer records (if any)
      while(peer->sync_keys_state->queue){
        struct transfers *transfer = peer->sync_keys_state->queue;
        peer->sync_keys_state->queue = transfer->next;
        sync_keys_transfer_clear(transfer);
        free(transfer);
      }
      peer->sync_keys_state->connection = NULL;
    }
    if ((gettime_ms() - peer->sync_keys_state->last_use) > 600000) {
      // No access to synchronisation status for > 600000 ms.
      // Don't make the timeout too short as we may have short communication interruptions.

      // Drop sync state of this peer.
      sync_free_peer_state(sync_keys_control.tree, peer);
      peer->sync_keys_state = NULL;
      peer->sync_version = RHIZOME_SYNC_PROTOCOL_VERSION_BARS; // reset to default
    }
  }
  return peer->sync_keys_state;
}


/** Number of transfers currently registered in the peer synchronization state.
 *
 * @param sync_keys_peer_state Synchronisation state of a peer.
 * @return num_transfers Number of transfers.
 */
static int sync_keys_peer_state_transfer_count(const struct rhizome_sync_keys_peer_state *sync_keys_peer_state)
{
  int num_transfers = 0;
  if (sync_keys_peer_state->connection != NULL && sync_keys_peer_state->queue != NULL) {
    struct transfers *transfer = sync_keys_peer_state->queue;
    while (transfer) {
      num_transfers++;
      transfer = transfer->next;
    }
  }
  return num_transfers;
}

/** We are currently synchronizing with peer.
 *
 * Only reachable peers (not self) are checked.
 *
 * @param peer
 * @return num_transfers Number of synchonizing transfers with this peer.
 */
static int sync_keys_peer_state_is_synchronizing(struct subscriber *peer)
{
  if (peer->reachable == REACHABLE_NONE || peer->sync_version != RHIZOME_SYNC_PROTOCOL_VERSION_KEYS) {
    // Peer not reachable or does not use sync keys protocol.
    sync_keys_peer_state_unuse(peer);
  } else if (!(peer->reachable == REACHABLE_SELF)) {
    // This peer is__NOT__ ourself.
    struct rhizome_sync_keys_peer_state *sync_keys_peer_state = sync_keys_peer_state_use(peer);
    return sync_keys_peer_state_transfer_count(sync_keys_peer_state);
  }
  return 0;
}


/** Are we currently synchronizing with peer (callback).
 *
 * Increments the use count if the peer is currently synchronizing.
 * Only reachable peers (not self) are counted.
 *
 * @param subscriber A pointer to a subscriber struct, the peer to check for synchronization.
 * @param context Pointer to int, incremented if peer is currently synchronizing.
 */
static int sync_keys_peer_state_is_synchronizing_cb(void **record, void *context)
{
  struct subscriber *peer = *record;
  int *synchronizing = context;

  *synchronizing += sync_keys_peer_state_is_synchronizing(peer);

  return 0;
}


/** Count the number of transfers of the peers that are currently synchronizing.
 *
 * @return num_transfers Number of synchonizing transfers to peers.
 */
static int sync_keys_peer_state_all_transfers(void)
{
  int num_transfers = 0;

  enum_subscribers(NULL, sync_keys_peer_state_is_synchronizing_cb, &num_transfers);

  DEBUGF(rhizome_sync_keys, "Rhizome sync keys %d synchronizing transfers with peers.",
         num_transfers);

  return num_transfers;
}

/** @} Peer Synchronisation state */


/** @name Announcement
 *
 * @{
 */

/** Size of capability data to be added to announcement.
 * 1 byte: tree sequence number
 */
#define SYNC_KEYS_ANNOUNCE_CAPABILITY_BYTES 1


/// Alarm to be scheduled by fdqueue.
DEFINE_ALARM(rhizome_sync_keys_announce_alarm);


/** Reschedule next rhizome sync keys announcement.
 *
 * @param interval_ms Interval to next keys message.
 */
static void sync_keys_announce_reschedule(time_ms_t interval_ms)
{
  // If interval is infinite - do not schedule
  if (interval_ms > INT_MAX) {
    return;
  }
  // Assure not to schedule in the past - give some headroom.
  if (interval_ms < 5) {
    interval_ms = 5;
  }
  struct sched_ent *alarm=&ALARM_STRUCT(rhizome_sync_keys_announce_alarm);
  time_ms_t next_schedule = gettime_ms() + interval_ms;
  if ((alarm->alarm > next_schedule) || !is_scheduled(alarm)) {
    DEBUGF(rhizome_sync_keys,"Reschedule rhizome sync keys announce for %dms", (int)interval_ms);
    RESCHEDULE(alarm, next_schedule, next_schedule, TIME_MS_NEVER_WILL);
  }
}


/** Announce bundle keys to all peers.
 *
 * Creates a broadcast message and sends it.
 *
 * @param message message that contains the keys.
 * @param max_len maximum message len
 * @param len message length.
 */
static void sync_keys_announce_send_to_peers(uint8_t *message, size_t max_len, size_t len)
{
  DEBUGF(rhizome_sync_keys, "Sending announce, len = %d, 1st key = %s", len, alloca_tohex(&message[2], KEY_LEN));

  // Add capability info to announcement.
  assert((len + SYNC_KEYS_ANNOUNCE_CAPABILITY_BYTES) <= max_len);
  message[len++] = sync_keys_control.tree_seqno;

  struct overlay_buffer *payload = ob_static(message, len);
  ob_limitsize(payload, len);

  struct internal_mdp_header header;
  bzero(&header, sizeof header);

  header.crypt_flags = MDP_FLAG_NO_CRYPT | MDP_FLAG_NO_SIGN;
  header.source = get_my_subscriber(1);
  header.source_port = MDP_PORT_RHIZOME_SYNC_KEYS;
  header.destination_port = MDP_PORT_RHIZOME_SYNC_KEYS;
  header.qos = OQ_OPPORTUNISTIC;
  header.ttl = 1;

  overlay_send_frame(&header, payload);
}


/** Send announce message.
 *
 * Send the rhizome sync protocol version 1 announce message.
 *
 * @param alarm
 */
void rhizome_sync_keys_announce_alarm(struct sched_ent *alarm)
{
  uint8_t buff[MDP_MTU];
  size_t len;

  DEBUGF(rhizome_sync_keys, "Rhizome sync keys send announce alarm, tree = %d.",
         sync_keys_control.tree ? 1 : 0);

  if (!sync_keys_control.tree || ((gettime_ms() - sync_keys_control.tree_use_start) < 3000)) {
    // No synchronisation - assure capability propagates to peers.
    // Just resynced - assure capability (and tree sequence number) propagates to all listening peers
    //                 and give peers some time to react.
    // We just announce that we are capable to use rhizome_sync_keys (protocol version 1).
    len = sync_build_empty_message(buff, sizeof(buff) - SYNC_KEYS_ANNOUNCE_CAPABILITY_BYTES);
    sync_keys_announce_send_to_peers(buff, sizeof(buff), len);
  } else {
    if ((len = sync_build_message(sync_keys_control.tree, buff, sizeof(buff) - SYNC_KEYS_ANNOUNCE_CAPABILITY_BYTES)) != 0) {
      // Send message build before in buff.
      sync_keys_announce_send_to_peers(buff, sizeof(buff), len);

      if (sync_has_transmit_queued(sync_keys_control.tree)) {
        // reschedule - there is something left to do.
        assert(alarm == &ALARM_STRUCT(rhizome_sync_keys_announce_alarm));
        sync_keys_announce_reschedule(50);
      }
    }
  }
}

/** @} Announcement */


/** @name Transfer
 *
 * @{
 */

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


/// Approx. size of a signed manifest
#define DUMMY_MANIFEST_SIZE 256

#define REACHABLE_BIAS 2

/// Alarm to be scheduled by fdqueue.
DEFINE_ALARM(rhizome_sync_keys_transfer_alarm);


/** Reschedule next rhizome sync keys bundle transfer execution.
 *
 * @param interval_ms Interval to next protocol execution.
 */
static void sync_keys_transfer_reschedule(time_ms_t interval_ms)
{
  // If interval is infinite - do not schedule
  if (interval_ms > INT_MAX) {
    return;
  }
  // Assure not to schedule in the past - give some headroom.
  if (interval_ms < 5) {
    interval_ms = 5;
  }
  struct sched_ent *alarm=&ALARM_STRUCT(rhizome_sync_keys_transfer_alarm);
  time_ms_t next_schedule = gettime_ms() + interval_ms;
  if ((alarm->alarm > next_schedule) || !is_scheduled(alarm)) {
    DEBUGF(rhizome_sync_keys,"Reschedule rhizome sync keys transfer for %dms", (int)interval_ms);
    RESCHEDULE(alarm, next_schedule, next_schedule, TIME_MS_NEVER_WILL);
  }
}


static const char *sync_keys_transfer_state_name(uint8_t state)
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


static void _sync_keys_transfer_clear(struct __sourceloc __whence, struct transfers *ptr)
{
  DEBUGF(rhizome_sync_keys, "Transfer cleared - %s %s", sync_keys_transfer_state_name(ptr->state), alloca_sync_key(&ptr->key));
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


/** Find and update a transfer of the peers synchronisation status.
 *
 * @param sync_keys_peer_state If state == STATE_NONE do not create a connection.
 * @param rank If rank < 0 do not create a new transfer, just look for an existing one.
 * @return transfers_ptr Pointer to the next pointer of the transfer before the transfer in the queue of transfers of the synchronization state. Null if no transfer was found (only possible if rank < 0).
 */
static struct transfers **sync_keys_transfer_find_and_update(struct subscriber *peer, struct rhizome_sync_keys_peer_state *sync_keys_peer_state, const sync_key_t *key, uint8_t state, int rank)
{
  if (rank > 0xFF)
    rank = 0xFF;
  if (state != STATE_NONE) {
    // Assure we have a connection to this peer.
    if (!sync_keys_peer_state->connection) {
      sync_keys_peer_state->connection = msp_find_or_connect(&sync_keys_control.connections,
          peer, MDP_PORT_RHIZOME_SYNC_KEYS,
          get_my_subscriber(1), MDP_PORT_RHIZOME_SYNC_KEYS,
          OQ_OPPORTUNISTIC);
    }

    if (msp_can_send(sync_keys_peer_state->connection)){
      // Schedule soon
      sync_keys_transfer_reschedule(0);
    }
  }

  struct transfers **transfers_ptr = &sync_keys_peer_state->queue;
  while(*transfers_ptr) {
    if (memcmp(key, &(*transfers_ptr)->key, sizeof(sync_key_t)) == 0) {
      // Key of transfer equals key to find.
      if (state != STATE_NONE) {
        uint8_t last_state = (*transfers_ptr)->state;
        // transfer state shall be updated
        if ((last_state != STATE_NONE) && (last_state != state)) {
          // There is a state change - clear last transfer.
          sync_keys_transfer_clear(*transfers_ptr);
        }
        DEBUGF(rhizome_sync_keys, "Transfer updated - %s (was %s) %s",
          sync_keys_transfer_state_name(state), sync_keys_transfer_state_name(last_state), alloca_sync_key(key));
        if (rank >= 0)
          (*transfers_ptr)->rank = rank;
        (*transfers_ptr)->state = state;
      } else {
        DEBUGF(rhizome_sync_keys, "Transfer found - %s %s",
          sync_keys_transfer_state_name((*transfers_ptr)->state), alloca_sync_key(key));
      }
      return transfers_ptr;
    }
    if ((rank >= 0) && ((*transfers_ptr)->rank > rank))
      break;
    transfers_ptr = &(*transfers_ptr)->next;
  }

  if (rank < 0) {
    // Only search for transfer - do not create a new one.
    DEBUGF(rhizome_sync_keys, "Transfer not found - %s %s", sync_keys_transfer_state_name(state), alloca_sync_key(key));
    return NULL;
  }

  // Create a new transfer for this key.
  struct transfers *transfer = emalloc_zero(sizeof(struct transfers));
  memcpy(&transfer->key, key, sizeof(sync_key_t));
  transfer->rank = rank;
  transfer->state = state;
  // Insert transfer into transfers queue.
  transfer->next = (*transfers_ptr);
  (*transfers_ptr) = transfer;

  DEBUGF(rhizome_sync_keys, "Transfer created - %s %s", sync_keys_transfer_state_name(transfer->state), alloca_sync_key(&transfer->key));
  return transfers_ptr;
}


/** Get a rank for the bundle transfer.
 *
 * The rank is calculated based on manifest data and hop distance.
 *
 * @param peer The peer the bundle transfer is done with.
 * @param key
 * @param next_state The next state of transfer we want to enter.
 * @param bar
 * @param manifest
 * @param written_offset offset into payload.
 * @return rank The rank.
 */
static int sync_keys_transfer_rank(struct subscriber *peer, const sync_key_t *key, int next_state, const rhizome_bar_t *bar, const rhizome_manifest *manifest, uint64_t written_offset)
{
  assert(bar || manifest); // one has to be provided

  int rank = -1; // Default rank (-1) indicates to use existing transfer if available or to fail.
  uint8_t bias = REACHABLE_BIAS; // rank improvement for directly reachable peers.

  switch (next_state) {
    case STATE_SEND_BAR:
      // Initialise a new transfer- from us to peer.
      // Rank is the zero-based index of the most significant 1 bit in the payload filesize.
      // -> rank 0..63.
      rank = log2ll(manifest->filesize) + bias;
      if (manifest->has_recipient){
        struct subscriber *recipient = find_subscriber(manifest->recipient.binary, sizeof manifest->recipient, 0);
        // if the recipient is routable and this bundle is heading the right way;
        // give the bundle's rank a boost
        if (recipient
            && (recipient->reachable & (REACHABLE | REACHABLE_SELF))
            && (recipient->next_hop == peer)) {
          DEBUGF(rhizome_sync_keys, "Boosting rank for %s to deliver to recipient %s",
            alloca_tohex(&key->key[0], sizeof(sync_key_t)),
            alloca_tohex_sid_t(recipient->sid));
          rank -= bias;
        }
      }
      break;
    case STATE_REQ_MANIFEST:
      // We want to transfer a bundle from the peer to us.
      // Bundle transfer will start with manifest transfer.
      if (bar) {
        rank = rhizome_bar_log_size(bar);
      } else {
        rank = log2ll(manifest->filesize);
      }
      break;
    case STATE_REQ_PAYLOAD:
      // We got a Manifest and want to request (additional) payload from the peer.
      // Rank is the zero-based index of the most significant 1 bit in the remaining payload filesize.
      // -> rank 0..63.
      rank = log2ll(manifest->filesize - written_offset) + bias;
      if (manifest->has_recipient){
        struct subscriber *recipient = find_subscriber(manifest->recipient.binary, sizeof manifest->recipient, 0);
        // if the recipient is routable and this bundle is heading the right way;
        // give the bundle's rank a boost
        if (recipient
            && (recipient->reachable & (REACHABLE | REACHABLE_SELF))
            && (recipient->next_hop != peer)) {
          DEBUGF(rhizome_sync_keys, "Boosting rank for %s to deliver to recipient %s",
            alloca_tohex(&key->key[0], sizeof(sync_key_t)),
            alloca_tohex_sid_t(recipient->sid));
          rank -= bias;
        }
      }
      break;
    default:
      break;
  }
  DEBUGF(rhizome_sync_keys, "Got rank %d for %s to synchronize with %s.",
    rank,
    alloca_tohex(&key->key[0], sizeof(sync_key_t)),
    alloca_tohex_sid_t(peer->sid));
  return rank;
}


/** Init bundle transfer by sending bundle advertisement record to peer.
 *
 * @param peer Peer to send to.
 * @param key Hash of manifest file.
 */
static void sync_keys_transfer_init(struct subscriber *peer, const sync_key_t *key)
{
  struct rhizome_sync_keys_peer_state *sync_keys_peer_state = sync_keys_peer_state_use(peer);
  struct transfers **transfers_ptr = sync_keys_transfer_find_and_update(peer, sync_keys_peer_state, key, STATE_NONE, -1);
  if (transfers_ptr && (*transfers_ptr)) {
    // We already have a transfer
    DEBUGF(rhizome_sync_keys, "Peer %s is missing %s - transfer already ongoing - state = %s.",
      alloca_tohex_sid_t(peer->sid),
      alloca_sync_key(key),
      sync_keys_transfer_state_name((*transfers_ptr)->state));
    return;
  }
  if (sync_keys_peer_state_all_transfers() >= sync_keys_control.transfer_max_init) {
    // Limit synchronization with peers.
    DEBUGF(rhizome_sync_keys, "Peer %s is missing %s - failed to init transfer - limit exceeded.",
      alloca_tohex_sid_t(peer->sid),
      alloca_sync_key(key));
    return;
  }
  if ((memcmp(&sync_keys_peer_state->last_transfer_init_key.key, key, sizeof(sync_key_t)) == 0)
      && ((gettime_ms() - sync_keys_peer_state->last_transfer_init_time) < 1000)) {
    // we initiated this transfer some time ago - wait a little bit for next init.
    DEBUGF(rhizome_sync_keys, "Peer %s is missing %s - wait for re-init transfer timeout - ignore",
      alloca_tohex_sid_t(peer->sid),
      alloca_sync_key(key));
    return;
  }

  rhizome_manifest *m = rhizome_new_manifest();
  if (!m) {
    DEBUGF(rhizome_sync_keys, "Peer %s is missing %s - failed to init transfer - memory exceeded.",
      alloca_tohex_sid_t(peer->sid),
      alloca_sync_key(key));
    return;
  }

  enum rhizome_bundle_status status = rhizome_retrieve_manifest_by_hash_prefix(key->key, sizeof(sync_key_t), m);
  int rank;
  switch(status) {
    case RHIZOME_BUNDLE_STATUS_SAME:
      // queue BAR for transmission based on the manifest details.
      // add a rank bias if there is no reachable recipient to prioritise messaging
      rank = sync_keys_transfer_rank(peer, key, STATE_SEND_BAR, NULL, m, 0);
      transfers_ptr = sync_keys_transfer_find_and_update(peer, sync_keys_peer_state, key, STATE_SEND_BAR, rank);
      if (transfers_ptr && (*transfers_ptr)) {
        // success - transfer added to queue
        rhizome_manifest_to_bar(m, &(*transfers_ptr)->bar);

        // remember transfer initialisation.
        memcpy(&sync_keys_peer_state->last_transfer_init_key.key, key, sizeof(sync_key_t));
        sync_keys_peer_state->last_transfer_init_time = gettime_ms();

        DEBUGF(rhizome_sync_keys, "Peer %s is missing %s - init transfer - bundle status = %s",
          alloca_tohex_sid_t(peer->sid),
          alloca_sync_key(key),
          rhizome_bundle_status_message_nonnull(status));
        break;
      }
      // We could not send bundle announcement record
      // Fall through
    case RHIZOME_BUNDLE_STATUS_NEW:
      // We don't have this bundle (anymore)!
      // Fall through
    case RHIZOME_BUNDLE_STATUS_ERROR:
      // Bundle is broken
      // Fall through
    case RHIZOME_BUNDLE_STATUS_BUSY:
      // Database is busy
      // Fall through
    default:
      DEBUGF(rhizome_sync_keys, "Peer %s is missing %s - failed to init transfer - bundle status = %s",
        alloca_tohex_sid_t(peer->sid),
        alloca_sync_key(key),
        rhizome_bundle_status_message_nonnull(status));
      break;
  }

  rhizome_manifest_free(m);
}


/** Request peer to transfer bundle to us by sending manifest request to peer.
 *
 * @param peer Peer to send to.
 * @param key Hash of manifest file
 * @param bar bundle advertisement record or Null.
 * @return transfer_count 1 if transfer was scheduled, 0 otherwise.
 */
static int sync_keys_transfer_request(struct subscriber *peer, const sync_key_t *key, const rhizome_bar_t *bar)
{
  int rank;
  if (!bar) {
    rhizome_manifest *manifest = rhizome_new_manifest();
    if (!manifest) {
      DEBUGF(rhizome_sync_keys, "Peer %s has %s - failed to request transfer - memory exceeded.",
        alloca_tohex_sid_t(peer->sid),
        alloca_sync_key(key));
      return 0;
    }
    enum rhizome_bundle_status status = rhizome_retrieve_manifest_by_hash_prefix(key->key, sizeof(sync_key_t), manifest);
    switch(status) {
      case RHIZOME_BUNDLE_STATUS_SAME:
        rank = sync_keys_transfer_rank(peer, key, STATE_REQ_MANIFEST, NULL, manifest, 0);
        break;
      case RHIZOME_BUNDLE_STATUS_NEW:
        // We don't have this bundle anymore!
        // Use a low rank
        rank = 63;
        break;
      default:
        DEBUGF(rhizome_sync_keys, "Peer %s has %s - failed to request transfer - bundle status = %s.",
          alloca_tohex_sid_t(peer->sid),
          alloca_sync_key(key),
          rhizome_bundle_status_message_nonnull(status));
        return 0;
    }
    rhizome_manifest_free(manifest);
  } else {
    rank = sync_keys_transfer_rank(peer, key, STATE_REQ_MANIFEST, bar, NULL, 0);
  }
  // send a request for the manifest
  struct rhizome_sync_keys_peer_state *sync_keys_peer_state = sync_keys_peer_state_use(peer);
  struct transfers **transfers_ptr = sync_keys_transfer_find_and_update(peer, sync_keys_peer_state, key, STATE_REQ_MANIFEST, rank);
  if (!transfers_ptr || !(*transfers_ptr)) {
    DEBUGF(rhizome_sync_keys, "Peer %s has %s - failed to request transfer - limit exceeded.",
      alloca_tohex_sid_t(peer->sid), alloca_sync_key(key));
    return 0;
  }
  (*transfers_ptr)->req_len = DUMMY_MANIFEST_SIZE;

  DEBUGF(rhizome_sync_keys, "Peer %s has %s - transfer requested - rank = %d.",
    alloca_tohex_sid_t(peer->sid), alloca_sync_key(key), rank);
  return 1;
}


/** Send transfer message(s) to peer.
 *
 * @param peer
 */
static void sync_keys_transfer_send_to_peer(struct subscriber *peer)
{
  size_t mtu = MSP_MESSAGE_SIZE; // FIX ME, use link mtu?
  struct rhizome_sync_keys_peer_state *sync_keys_peer_state = sync_keys_peer_state_use(peer);

  struct overlay_buffer *payload=NULL;
  uint8_t buff[mtu];

  // send requests for more data, stop when we hit sync_keys_control.transfer_max_request_bytes
  // Note that requests are ordered by rank,
  // so we will still request a high rank item even if there is a low ranked item being received
  struct transfers **transfers_ptr = &sync_keys_peer_state->queue;
  size_t request_bytes = 0;
  time_ms_t now = gettime_ms();

  while((*transfers_ptr) && msp_can_send(sync_keys_peer_state->connection) && (request_bytes < sync_keys_control.transfer_max_request_bytes)){
    struct transfers *transfer = *transfers_ptr;
    if (transfer->state == STATE_RECV_PAYLOAD){
      request_bytes+=transfer->req_len;
    } else if ((transfer->state & 3) == STATE_REQ){
      if (!payload){
        payload = ob_static(buff, sizeof(buff));
        ob_limitsize(payload, sizeof(buff));
      }

      DEBUGF(rhizome_sync_keys, "Sending transfer %s %s", sync_keys_transfer_state_name(transfer->state), alloca_sync_key(&transfer->key));

      ob_append_byte(payload, transfer->state);
      ob_append_bytes(payload, transfer->key.key, sizeof(transfer->key));
      ob_append_byte(payload, transfer->rank);

      // start from the specified file offset (eg journals, but one day perhaps resuming transfers)
      if (transfer->state == STATE_REQ_PAYLOAD){
        ob_append_packed_ui64(payload, transfer->write->file_offset);
        ob_append_packed_ui64(payload, transfer->req_len);
      }

      if (ob_overrun(payload)) {
        ob_rewind(payload);
        msp_send_packet(sync_keys_peer_state->connection, ob_ptr(payload), ob_position(payload));
        ob_clear(payload);
        ob_limitsize(payload, sizeof(buff));
      } else {
        ob_checkpoint(payload);
        request_bytes+=transfer->req_len;
        if (transfer->state == STATE_REQ_PAYLOAD){
          // keep hold of the manifest pointer
          transfer->state = STATE_RECV_PAYLOAD;
        } else {
          *transfers_ptr = transfer->next;
          sync_keys_transfer_clear(transfer);
          if (transfer->manifest)
            rhizome_manifest_free(transfer->manifest);
          transfer->manifest=NULL;
          free(transfer);
          continue;
        }
      }
    }
    transfers_ptr = &transfer->next;
  }

  // now send requested data
  transfers_ptr = &sync_keys_peer_state->queue;
  while((*transfers_ptr) && msp_can_send(sync_keys_peer_state->connection)){
    struct transfers *transfer = *transfers_ptr;

    if ((transfer->state & 3) != STATE_SEND) {
      // transfer does not need to send currently.
      transfers_ptr = &transfer->next;
      continue;
    }

    if (!payload){
      payload = ob_static(buff, sizeof(buff));
      ob_limitsize(payload, sizeof(buff));
    }

    uint8_t transfer_complete=1;
    uint8_t send_payload=0;
    DEBUGF(rhizome_sync_keys, "Sending transfer %s %s", sync_keys_transfer_state_name(transfer->state), alloca_sync_key(&transfer->key));
    ob_append_byte(payload, transfer->state);
    ob_append_bytes(payload, transfer->key.key, sizeof(transfer->key));

    switch(transfer->state) {
      case STATE_SEND_BAR: {
        ob_append_bytes(payload, transfer->bar.binary, sizeof(transfer->bar));
        break;
      }
      case STATE_SEND_MANIFEST: {
        rhizome_manifest *m = rhizome_new_manifest();
        if (!m){
          ob_rewind(payload);
          assert(ob_position(payload));
          transfer_complete = 0;
        }else{
          enum rhizome_bundle_status status = rhizome_retrieve_manifest_by_hash_prefix(transfer->key.key, sizeof(transfer->key), m);
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
      case STATE_SEND_PAYLOAD: {
        size_t max_len = ob_remaining(payload);
        if (max_len > transfer->req_len)
          max_len = transfer->req_len;
        ssize_t payload_len = rhizome_read(transfer->read, ob_current_ptr(payload), max_len);
        if (payload_len==-1){
          ob_rewind(payload);
        }else{
          ob_append_space(payload, payload_len);
          send_payload=1;
        }
        DEBUGF(rhizome_sync_keys, "Sending %s %zd bytes (now %zd of %zd)",
          alloca_sync_key(&transfer->key), payload_len, transfer->read->offset, transfer->read->length);

        transfer->req_len -= payload_len;
        if (transfer->read->offset < transfer->read->length && transfer->req_len>0)
          transfer_complete=0;

        break;
      }
      default:
        FATALF("Unexpected state %x", transfer->state);
    }

    if (ob_overrun(payload)){
      ob_rewind(payload);
      transfer_complete=0;
      send_payload=1;
    }else{
      ob_checkpoint(payload);
    }

    if (send_payload){
      msp_send_packet(sync_keys_peer_state->connection, ob_ptr(payload), ob_position(payload));
      ob_clear(payload);
      ob_limitsize(payload, sizeof(buff));
    }

    if (transfer_complete){
      *transfers_ptr = transfer->next;
      sync_keys_transfer_clear(transfer);
      if (transfer->manifest)
        rhizome_manifest_free(transfer->manifest);
      transfer->manifest=NULL;
      free(transfer);
    }
    // else, try to send another chunk of this payload immediately
  }

  if (payload){
    if (ob_position(payload))
      msp_send_packet(sync_keys_peer_state->connection, ob_ptr(payload), ob_position(payload));
    ob_free(payload);
  }

  if ((msp_queued_packet_count(sync_keys_peer_state->connection) == 0)
      && (msp_get_connection_state(sync_keys_peer_state->connection) & MSP_STATE_RECEIVED_PACKET)
      && !(msp_get_connection_state(sync_keys_peer_state->connection) & MSP_STATE_SHUTDOWN_LOCAL) // already local shutdown
      && (now - msp_last_packet(sync_keys_peer_state->connection) > 5000)) {
    DEBUGF(rhizome_sync_keys, "Local shutdowm of MSP connection");
    msp_shutdown_stream(sync_keys_peer_state->connection);
  }
}


/** Callback on key difference between peer and us to init transfer.
 *
 * @param context unused
 * @param peer_context Pointer to subcriber, the peer.
 * @param key The key.
 * @param ours We own the differing key (>0), or the peer owns it (=0).
 */
static void sync_keys_transfer_init_cb(void *UNUSED(context), void *peer_context, const sync_key_t *key, uint8_t ours)
{
  if (ours) {
    // We own the bundle and the peer is missing it.
    struct subscriber *peer = (struct subscriber *)peer_context;
    sync_keys_transfer_init(peer, key);
  }
}


/** Execute the rhizome sync keys transfer protocol.
 *
 * Exchange bundles with peers using the mesh stream protocol (MSP).
 *
 * @param alarm
 */
void rhizome_sync_keys_transfer_alarm(struct sched_ent *alarm)
{
  int num_transfers = 0; // Total number of active transfers.
  struct msp_iterator iterator;
  msp_iterator_open(&sync_keys_control.connections, &iterator);

  DEBUG(rhizome_sync_keys, "Rhizome sync keys transfer alarm.");

  // Iterate over all MSP connections.
  while(1) {
    struct msp_server_state *connection = msp_process_next(&iterator);
    if (!connection)
      break;

    struct subscriber *peer = msp_remote_peer(connection);
    struct rhizome_sync_keys_peer_state *sync_keys_peer_state = sync_keys_peer_state_use(peer);

    int peer_transfers = sync_keys_peer_state_transfer_count(sync_keys_peer_state);

    DEBUGF(rhizome_sync_keys, "Synchronize with %s %d transfer(s)", alloca_tohex_sid_t(peer->sid), peer_transfers);

    num_transfers += peer_transfers;
    sync_keys_peer_state->connection = connection;
    sync_keys_transfer_send_to_peer(peer);
  }

  // Iterate over MSP connections that are in CLOSED state.
  while(1) {
    struct msp_server_state *connection = msp_next_closed(&iterator);
    if (!connection)
      break;

    struct subscriber *peer = msp_remote_peer(connection);
    sync_keys_peer_state_unuse(peer); // Sets peer connection to NULL.

    DEBUGF(rhizome_sync_keys, "Synchronize with %s stopped (connection closed)", alloca_tohex_sid_t(peer->sid));
  }

  // Close iterator and provide time of next action required.
  time_ms_t next_action = msp_iterator_close(&iterator);

  if (sync_keys_control.tree && (num_transfers < sync_keys_control.transfer_max_init)) {
    // Maybe we can init a new transfer
    DEBUGF(rhizome_sync_keys, "Synchronize %d transfer(s) - init additional transfer if possible", num_transfers);
    sync_enum_differences(sync_keys_control.tree, sync_keys_transfer_init_cb);
  }

  // Calculate time interval to next action
  time_ms_t interval_ms = next_action - gettime_ms();

  assert(alarm == &ALARM_STRUCT(rhizome_sync_keys_transfer_alarm));
  sync_keys_transfer_reschedule(interval_ms);
}


/** Process transfer message received from peer.
 *
 * @param peer
 * @param sync_keys_peer_state
 * @param payload
 */
static void sync_keys_transfer_process_from_peer(struct subscriber *peer, struct rhizome_sync_keys_peer_state *sync_keys_peer_state, struct overlay_buffer *payload)
{
  while(ob_remaining(payload)){
    ob_checkpoint(payload);
    int transfer_state = ob_get(payload);
    if (transfer_state < 0) {
      DEBUGF(rhizome_sync_keys, "Processing transfer %s from %s - ignored (invalid transfer state).",
        sync_keys_transfer_state_name(transfer_state), alloca_tohex_sid_t(peer->sid));
      return;
    }
    sync_key_t key;
    if (ob_get_bytes(payload, key.key, sizeof key) < 0) {
      DEBUGF(rhizome_sync_keys, "Processing transfer %s from %s - ignored (missing/invalid key).",
        sync_keys_transfer_state_name(transfer_state), alloca_tohex_sid_t(peer->sid));
      return;
    }
    int rank=-1;
    if (transfer_state & STATE_REQ){
      rank = ob_get(payload);
      if (rank < 0) {
        DEBUGF(rhizome_sync_keys, "Processing transfer %s %s %d from %s - ignored (invalid rank)).",
          sync_keys_transfer_state_name(transfer_state), alloca_sync_key(&key), rank, alloca_tohex_sid_t(peer->sid)) ;
        return;
      }
    }

    DEBUGF(rhizome_sync_keys, "Processing transfer %s %s %d from %s",
      sync_keys_transfer_state_name(transfer_state), alloca_sync_key(&key), rank, alloca_tohex_sid_t(peer->sid));
    switch(transfer_state){
      case STATE_SEND_BAR:{
        rhizome_bar_t bar;
        if (ob_get_bytes(payload, bar.binary, sizeof(rhizome_bar_t))<0)
          return;

        if (!config.rhizome.fetch)
          break;
        if (!rhizome_is_bar_interesting(&bar)){
          DEBUGF(rhizome_sync_keys, "Peer %s has %s - omit to request transfer - uninteresting",
            alloca_tohex_sid_t(peer->sid), alloca_sync_key(&key));
          break;
        }
        // queue manifest request
        sync_keys_transfer_request(peer, &key, &bar);
        break;
      }

      case STATE_REQ_MANIFEST:{
        // queue the transmission of the manifest
        sync_keys_transfer_find_and_update(peer, sync_keys_peer_state, &key, STATE_SEND_MANIFEST, rank);
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
          // We already have the manifest.
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
          if (rhizome_retrieve_manifest(&m->keypair.public_key, previous)==RHIZOME_BUNDLE_STATUS_SAME &&
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

        rank = sync_keys_transfer_rank(peer, &key, STATE_REQ_PAYLOAD, NULL, m, write->file_offset);

        struct transfers **transfers_ptr = sync_keys_transfer_find_and_update(peer, sync_keys_peer_state, &key, STATE_REQ_PAYLOAD, rank);
        if (!transfers_ptr || !(*transfers_ptr)) {
            // Could not initiate transfer - no transfer added to queue
            break;
        }
        (*transfers_ptr)->manifest = m;
        (*transfers_ptr)->req_len = m->filesize - write->file_offset;
        (*transfers_ptr)->write = write;
        break;
      }
      case STATE_REQ_PAYLOAD:{
        // Peer is requesting payload from us.
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

        struct transfers *transfer = *sync_keys_transfer_find_and_update(peer, sync_keys_peer_state, &key, STATE_SEND_PAYLOAD, rank);
        transfer->read = read;
        transfer->req_len = length;
        read->offset = offset;
        break;
      }
      case STATE_SEND_PAYLOAD:{
        // Peer is sending payload to us.
        size_t len = ob_remaining(payload);
        uint8_t *buff = ob_get_bytes_ptr(payload, len);
        uint8_t all_done = 0;

        struct transfers **transfers_ptr = sync_keys_transfer_find_and_update(peer, sync_keys_peer_state, &key, STATE_RECV_PAYLOAD, -1);
        if (!transfers_ptr || !(*transfers_ptr)){
          WHYF("Ignoring message for %s, no transfer in progress!", alloca_sync_key(&key));
          break;
        }
        if (!(*transfers_ptr)->write) {
          DEBUGF(rhizome_sync_keys, "Processing transfer %s - stopped (transfer is missing write specification)",
            sync_keys_transfer_state_name(transfer_state));
          all_done = 1;
        }
        if (!all_done && ((*transfers_ptr)->write->file_offset + len > (*transfers_ptr)->write->file_length)) {
          DEBUGF(rhizome_sync_keys, "Processing transfer %s - stopped (unexpected payload, trying to write %s %zu to %zu of %zu)",
            sync_keys_transfer_state_name(transfer_state),
            alloca_sync_key(&key), len, (*transfers_ptr)->write->file_offset, (*transfers_ptr)->write->file_length);
          all_done = 1;
        }
        if (!all_done && (rhizome_write_buffer((*transfers_ptr)->write, buff, len) == -1)) {
          WHYF("Write failed for %s!", alloca_sync_key(&key));
          all_done=1;
        }
        if (!all_done) {
          struct transfers *transfer = *transfers_ptr;
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
            all_done = 1;
          } else {
            transfer->req_len -= len;
          }
        }
        if (all_done) {
          struct transfers *transfer = *transfers_ptr;
          if (transfer->manifest)
            rhizome_manifest_free(transfer->manifest);
          transfer->manifest=NULL;
          sync_keys_transfer_clear(transfer);
          *transfers_ptr = transfer->next;
          free(transfer);
        }
        break;
      }
      default:
        WHYF("Unknown bundle transfer state %x", transfer_state);
    }
  }
}

/** @} Transfer */


/** @name Synchronisation tree
 *
 * @{
 */

/** Callback on peer has bundle that we do not have.
 */
static void sync_keys_tree_peer_has_cb(void * UNUSED(context), void *peer_context, const sync_key_t *key)
{
  // request manifest? keep trying?
  // remember & ignore expired manifest id's?
  struct subscriber *peer = (struct subscriber *)peer_context;
  DEBUGF(rhizome_sync_keys, "Neighbour %s has %s that we need",
    alloca_tohex_sid_t(peer->sid),
    alloca_sync_key(key));

  // noop, just wait for the BAR to arrive.
}


/** Callback on peer does not have bundle.
 */
static void sync_keys_tree_peer_does_not_have_cb(void * UNUSED(context), void *peer_context, void * UNUSED(key_context), const sync_key_t *key)
{
  // We own the bundle and the peer is missing it.
  struct subscriber *peer = (struct subscriber *)peer_context;
  DEBUGF(rhizome_sync_keys, "Neighbour %s is missing %s that we have",
    alloca_tohex_sid_t(peer->sid),
    alloca_sync_key(key));
  sync_keys_transfer_init(peer, key);
}


/** Callback on peer now has bundle.
 */
static void sync_keys_tree_peer_now_has_cb (void * UNUSED(context), void *peer_context, void * UNUSED(key_context), const sync_key_t *key)
{
  // remove transfer state?
  struct subscriber *peer = (struct subscriber *)peer_context;
  DEBUGF(rhizome_sync_keys, "Neighbour %s has now received %s",
    alloca_tohex_sid_t(peer->sid),
    alloca_sync_key(key));
}


/** Align synchronization tree to a bundle info in the local rhizome store.
 *
 * @param manifest_hash hash value of manifest file of bundle (the key) to align synchronisation tree to.
 * @param broken 0 if bundle is ok, 1 if broken.
 */
static inline void sync_keys_tree_align_to_bundle_manifest_hash(rhizome_filehash_t *manifest_hash, int broken)
{
  sync_key_t key;
  memcpy(key.key, manifest_hash->binary, sizeof(sync_key_t));
  if (!broken) {
    DEBUGF(rhizome_sync_keys, "Align sync tree to %s, seqno = %d - add.", alloca_sync_key(&key), (int)sync_keys_control.tree_seqno);
    sync_add_key(sync_keys_control.tree, &key, NULL);
  } else {
    DEBUGF(rhizome_sync_keys, "Align sync tree to %s, seqno = %d - ignore (broken).", alloca_sync_key(&key), (int)sync_keys_control.tree_seqno);
  }
}


/** Mark synchronization tree (synchronization management structure) to be used.
 *
 * Creates an empty synchronization tree if not available.
 *
 * @return tree Synchronisation tree.
 */
static struct sync_state * sync_keys_tree_use(void)
{
  if (!sync_keys_control.tree) {
    // Create sync tree.
    sync_keys_control.tree = sync_alloc_state(NULL, sync_keys_tree_peer_has_cb, sync_keys_tree_peer_does_not_have_cb, sync_keys_tree_peer_now_has_cb);
    sync_keys_control.tree_use_start = gettime_ms();
    DEBUGF(rhizome_sync_keys, "Created empty sync tree, seqno = %d.", (int)sync_keys_control.tree_seqno);
  }

  sync_keys_control.tree_use_last = gettime_ms();

  return sync_keys_control.tree;
}


/** Mark synchronization tree (synchronization management structure) to be unused.
 *
 * Deletes the synchronization tree if not used for a certain time.
 *
 * @return tree Synchronisation tree or Null in case there is no synchronisation tree (anymore).
 */
static struct sync_state * sync_keys_tree_unuse(void)
{
  if (sync_keys_control.tree && ((gettime_ms() - sync_keys_control.tree_use_last) > 7200000)) {
    // No use of sync tree for more than 2 hours.
    sync_free_state(sync_keys_control.tree);
    DEBUGF(rhizome_sync_keys, "Deleted sync tree, seqno = %d.", (int)sync_keys_control.tree_seqno);
    sync_keys_control.tree = NULL;
    sync_keys_control.tree_use_start = 0;
    sync_keys_control.tree_use_last = 0;
    sync_keys_control.tree_seqno = 0;
  }
  return sync_keys_control.tree;
}


/** Do a synchronisation tree re-sync if appropriate.
 *
 * Re-synchronization is done by deleting the current sync tree and incrementing the tree sequence number.
 *
 * Re-synchonisations is done if:
 *   There is no transfer ongoing
 *   _AND_ There was no re-sync done for at least an hour
 *         _OR_ We have broken bundles
 *              _AND_ the last broken bundle was detected after we (re-)started synchronization
 *              _AND_ the there was no new broken bundle within the last 10 seconds.
 */
static void sync_keys_tree_check_and_resync(void)
{
  if (sync_keys_control.tree && !sync_has_transmit_queued(sync_keys_control.tree)) {
    // No synchronization ongoing - we have time to look for re-syncing.
    if (((gettime_ms() - sync_keys_control.tree_use_start) > 3600000)
        || ((sync_keys_control.broken_count > 0)
            && (sync_keys_control.broken_inc_last > sync_keys_control.tree_use_start)
            && ((gettime_ms() - sync_keys_control.broken_inc_last) > 10000))) {
      sync_free_state(sync_keys_control.tree);
      sync_keys_control.tree = sync_alloc_state(NULL, sync_keys_tree_peer_has_cb, sync_keys_tree_peer_does_not_have_cb, sync_keys_tree_peer_now_has_cb);
      sync_keys_control.tree_use_start = gettime_ms();
      sync_keys_control.tree_seqno++;
      DEBUGF(rhizome_sync_keys, "Re-created empty sync tree, seqno = %d.", (int)sync_keys_control.tree_seqno);
    }
  }
}


/** Do a resync to the peer part of the synchronisation tree if appropriate.
 *
 * Re-synchronization is done by deleting the peer state of the current sync tree.
 * The current sequence number of the peers synchronisation tree and of the local synchronisation
 * tree is remembered to check for change later on.
 *
 * Re-synchronisation is done if the peers synchronisation tree sequence number differs
 * from the one remembered locally.
 *
 * @param peer
 * @param tree_seqno Sequence number of the peers synchronisation tree.
 */
static void sync_keys_tree_peer_check_and_resync(struct subscriber *peer, int tree_seqno)
{
  struct rhizome_sync_keys_peer_state *sync_keys_peer_state = sync_keys_peer_state_use(peer);

  sync_keys_peer_state->tree_seqno_peer = tree_seqno;
  if (tree_seqno != sync_keys_peer_state->tree_seqno_peer_synchronized) {
    // peer sync tree sequence number changed -> we have to re-synchronize to peer.
    DEBUGF(rhizome_sync_keys, "Re-created sync tree part of peer %s, peer seqno = %d, seqno = %d.",
           alloca_tohex_sid_t(peer->sid), (int)tree_seqno, sync_keys_control.tree_seqno);
    sync_free_peer_state(sync_keys_control.tree, peer);
    sync_keys_peer_state->tree_seqno_peer_synchronized = tree_seqno;
    sync_keys_peer_state->tree_seqno_local_synchronized = sync_keys_control.tree_seqno;
  }
}

/** @} Synchronisation tree */


/** @name Sync tree status
 *
 * @{
 */

/// Alarm to be scheduled by fdqueue.
DEFINE_ALARM(rhizome_sync_keys_status_alarm);


/** Reschedule next sync keys status debug output.
 *
 * @param interval_ms Interval to next status output.
 */
static void sync_keys_status_reschedule(time_ms_t interval_ms)
{
  // If interval is infinite - do not schedule
  if (interval_ms > INT_MAX) {
    return;
  }
  // Assure not to schedule in the past - give some headroom.
  if (interval_ms < 5) {
    interval_ms = 5;
  }
  struct sched_ent *alarm=&ALARM_STRUCT(rhizome_sync_keys_status_alarm);
  time_ms_t next_schedule = gettime_ms() + interval_ms;
  if ((alarm->alarm > next_schedule) || !is_scheduled(alarm)) {
    DEBUGF(rhizome_sync_keys,"Reschedule rhizome sync keys status for %dms", (int)interval_ms);
    RESCHEDULE(alarm, next_schedule, next_schedule, TIME_MS_NEVER_WILL);
  }
}


static void sync_keys_status_peer_cb(void *UNUSED(context), void *peer_context, const sync_key_t *key, uint8_t ours)
{
  struct subscriber *peer = (struct subscriber *)peer_context;
  struct rhizome_sync_keys_peer_state *sync_keys = sync_keys_peer_state_use(peer);
  struct transfers **transfers_ptr = sync_keys_transfer_find_and_update(peer, sync_keys, key, STATE_NONE, -1);

  struct transfers *transfer;
  if (!transfers_ptr) {
    // no transfer
    transfer = NULL;
  } else {
    transfer = *transfers_ptr;
  }

  DEBUGF(rhizome_sync_keys, "Peer %s %s %s %s",
    alloca_tohex_sid_t(peer->sid),
    ours ? "missing" : "has",
    alloca_sync_key(key),
    transfer ? sync_keys_transfer_state_name(transfer->state) : "No transfer");

  if (transfer) {
    switch(transfer->state){
      case STATE_REQ_PAYLOAD:
	DEBUGF(rhizome_sync_keys, " - Requesting payload [%zu of %zu]", transfer->write->file_offset, transfer->write->file_length);
	break;
      case STATE_SEND_PAYLOAD:
	DEBUGF(rhizome_sync_keys, " - Sending payload [%zu of %zu]", transfer->read->offset, transfer->read->length);
	break;
      case STATE_RECV_PAYLOAD:
	DEBUGF(rhizome_sync_keys, " - Receiving payload [%zu of %zu]", transfer->write->file_offset, transfer->write->file_length);
	break;
    }
  }
}


void rhizome_sync_keys_status_alarm(struct sched_ent *UNUSED(alarm))
{
  DEBUGF(rhizome_sync_keys, "Rhizome sync keys status alarm:");
  sync_enum_differences(sync_keys_control.tree, sync_keys_status_peer_cb);
}

/** @} Sync tree status */


/** @name Rhizome sync interface
 *
 * @{
 */

/** Is rhizome sync keys fit for a new round of alignment to the bundle store content.
 *
 * @param broken_count Number of broken bundles in rhizome store.
 * @return fit 1 if fit, 0 otherwise.
 */
int rhizome_sync_keys_fit_for_realign(int broken_count)
{
  if (!sync_keys_enabled() || !sync_keys_control.tree) {
    // No synchronization.
    return 1;
  }

  if (broken_count > sync_keys_control.broken_count) {
     // More broken bundles detected.
     sync_keys_control.broken_inc_last = gettime_ms();
  }
  sync_keys_control.broken_count = broken_count;
  // We now know the actual broken count - check for resync.
  sync_keys_tree_check_and_resync();

  if (!sync_has_transmit_queued(sync_keys_control.tree)) {
    return 1;
  }
  return 0;
}


/** Align synchronization tree to bundle in bundle store given by manifest.
 *
 * Update synchronisation tree;
 * we are no longer interested in this bundle from other subscribers.
 *
 * Schedule bundle advertisement for bundle added.
 *
 * @param m manifest of bundle added.
 * @param broken 0 if bundle is ok, 1 if broken.
 */
void rhizome_sync_keys_align_to_bundle_manifest(rhizome_manifest *m, int broken)
{
  if (!sync_keys_enabled()) {
    // protocol is forced to another version.
    return;
  }
  if (!sync_keys_control.tree) {
    DEBUG(rhizome_sync_keys, "Ignoring added manifest, sync tree not build");
    return;
  }
  sync_keys_tree_align_to_bundle_manifest_hash(&m->manifesthash, broken);
}


/** Broadcast bundle keys message to all subscribers.
 *
 * @param protocol_count Number of subscribers using this synchronization protocol.
 * @param other_count Number of subscribers using another synchronization protocol.
 */
void rhizome_sync_keys_announce(int protocol_count, int UNUSED(other_count))
{
  if (!sync_keys_enabled()) {
    // protocol is forced to another version.
    return;
  }

  // time to schedule announcement - default immediate.
  time_ms_t interval_ms = 0;

  if (protocol_count == 0) {
    // No subscriber uses rhizome_sync_keys (protocol version 1)
    // -> prepare to delete synchronisation tree.
    sync_keys_tree_unuse();
    // throttle announcements
    interval_ms = config.rhizome.advertise.interval * 5;
  }
  // schedule announcement message transmission.
  sync_keys_announce_reschedule(interval_ms);
  // Assure protocol execution will be redone at least every 5 seconds.
  sync_keys_transfer_reschedule(5000);
}


/** Process neighbour change trigger.
 *
 * @param neighbour neighbour
 * @param found 1 on new neighbour found, 0 on neighbour lost.
 * @param count Number of neighbours.
 */
void rhizome_sync_keys_on_neighbour_change(struct subscriber *neighbour, uint8_t found, unsigned UNUSED(count))
{
  if (!sync_keys_enabled()) {
    // protocol is forced to another version.
    return;
  }

  if (!found) {
    sync_keys_peer_state_unuse(neighbour);
  }
}

/** @} Rhizome sync interface */


DEFINE_BINDING(MDP_PORT_RHIZOME_SYNC_KEYS, rhizome_sync_keys_recv);
static int rhizome_sync_keys_recv(struct internal_mdp_header *header, struct overlay_buffer *payload)
{
  int message_len = ob_remaining(payload);
  uint8_t *message = ob_current_ptr(payload);

  if (header->source->reachable == REACHABLE_SELF) {
    // Dont respond to own message
    DEBUGF(rhizome_sync_keys, "Received sync keys message from %s - ignored (self): len = %d, payload = 0x%s.",
           alloca_tohex_sid_t(header->source->sid),
           message_len, alloca_tohex(message, message_len));
    return 0;
  }

  if (config.rhizome.mdp.protocol >= 0) {
    // Sync protocol version is forced.
    header->source->sync_version = (uint8_t)config.rhizome.mdp.protocol;
  } else if (header->source->sync_version < RHIZOME_SYNC_PROTOCOL_VERSION_KEYS) {
    header->source->sync_version = RHIZOME_SYNC_PROTOCOL_VERSION_KEYS;
  }

  if ( !config.rhizome.enable                                                   // rhizome not enabled
       || !rhizome_db                                                           // No rhizome database
       || header->source->sync_version != RHIZOME_SYNC_PROTOCOL_VERSION_KEYS    // Subscriber uses another sync protocol version.
     ) {
    DEBUGF(rhizome_sync_keys, "Received sync keys message from %s - ignored (sync protocol version = %d, rhizome.enable = %d, rhizome.fetch = %d, rhizome_db = %d).",
           alloca_tohex_sid_t(header->source->sid),
           header->source->sync_version,
           config.rhizome.enable,
           config.rhizome.fetch,
           rhizome_db != NULL);
    return 0;
  }

  // We definitly use RHIZOME_SYNC_PROTOCOL_VERSION_KEYS
  // Assure sync tree is available.
  sync_keys_tree_use();
  struct rhizome_sync_keys_peer_state *sync_keys_peer_state = sync_keys_peer_state_use(header->source);

  // Time interval to activate synchronization to peers - default if there is nothing to do.
  time_ms_t interval_ms = 5000;

  if (!header->destination) {
    // Broadcast -> announcement
    uint8_t tree_seqno_peer;

    // Newer sync keys announcement protocol added one byte to the announcement giving it in effect an odd number of message bytes.
    // Detect new type of announcement message just by this odd number of message bytes.
    if (message_len & 0x01) {
      // new type announcement
      tree_seqno_peer = message[--message_len]; // sequence number is last byte of message
    } else {
      // old type announcement - no tree sequence number.
      tree_seqno_peer = 0;
    }

    DEBUGF(rhizome_sync_keys, "Received sync keys message from %s - processing announcement: remote tree seqno = %d, len = %d, payload = 0x%s",
           alloca_tohex_sid_t(header->source->sid), (int)tree_seqno_peer,
           ob_remaining(payload), alloca_tohex(ob_current_ptr(payload), ob_remaining(payload)));

    // Check peer sync tree sequence number and init resync if we are out of sync.
    sync_keys_tree_peer_check_and_resync(header->source, tree_seqno_peer);

    if (sync_keys_peer_state->tree_seqno_local_synchronized != sync_keys_control.tree_seqno) {
      DEBUGF(rhizome_sync_keys, "Sync tree sequence number of %s out of sync: local = %d, local synchronized = %d - ignoring announcement.",
             alloca_tohex_sid_t(header->source->sid),
             (int)sync_keys_control.tree_seqno,
             (int)sync_keys_peer_state->tree_seqno_local_synchronized);
    } else if (sync_recv_message(sync_keys_control.tree, header->source, message, message_len) >= 0) {
      // We probably got something new - lets check whether we can synchronize
      // Don't do it immediatedly as there might follow some announcements immediatedly
      interval_ms = 50;
    } else {
      DEBUGF(rhizome_sync_keys, "Error while processing announcement from %s",
             alloca_tohex_sid_t(header->source->sid));
    }

    if (sync_has_transmit_queued(sync_keys_control.tree)) {
      // There is something to send - do transfer immediatedly.
      interval_ms = 0;
    }

    if (IF_DEBUG(rhizome_sync_keys)) {
      sync_keys_status_reschedule(1000);
    }

  } else {
    DEBUGF(rhizome_sync_keys, "Received sync keys message from %s - processing transfer: len = %d, payload = 0x%s",
           alloca_tohex_sid_t(header->source->sid),
           ob_remaining(payload), alloca_tohex(ob_current_ptr(payload), ob_remaining(payload)));
    struct msp_server_state *connection_state = msp_find_and_process(&sync_keys_control.connections, header, payload);
    if (!connection_state) {
      DEBUGF(rhizome_sync_keys, "Error (no connection state) while processing transfer with %s",
            alloca_tohex_sid_t(header->source->sid));
    } else {
      sync_keys_peer_state->connection = connection_state;

      while(1) {
        struct msp_packet *packet = msp_recv_next(connection_state);
        if (!packet)
          break;
        struct overlay_buffer *recv_payload = msp_unpack(connection_state, packet);
        if (recv_payload)
          sync_keys_transfer_process_from_peer(header->source, sync_keys_peer_state, recv_payload);
        msp_consumed(connection_state, packet, recv_payload);
      }

      sync_keys_transfer_send_to_peer(header->source);
      interval_ms = msp_next_action(connection_state) - gettime_ms();
    }
  }

  sync_keys_transfer_reschedule(interval_ms);

  return 0;
}


/** @} rhizome-sync-keys */

/** @} rhizome-sync */
