
#include "serval.h"
#include "rhizome.h"
#include "overlay_address.h"
#include "overlay_buffer.h"
#include "overlay_packet.h"
#include "mdp_client.h"
#include "log.h"
#include "debug.h"
#include "conf.h"
#include "route_link.h"


/** @addtogroup rhizome-sync
 * @{
 */

/** @defgroup rhizome-sync-bars Rhizome store synchronisation using bundle advertisement records.
 *
 * # Annoncements
 *
 * Announcements are sent using bundle advertizement packets where source and destination is the MDP_PORT_RHIZOME_SYNC_BARS port.
 * A bundle advertizement packet may contain information about several bundles. The information associated to one
 * bundle is the bundle advertizement record of type rhizome_bar_t.
 *
 * Which advertizement records are sent is determined by several factors:
 * 1) a specific bar is requested by another store - overlay_mdp_service_rhizome_sync_bars()
 * 2) a bundle was added/ updated in this store - store_sync_status_align_to_bundle_manifest()
 * 3) the bundles in this store are advertized regularly - store_sync_status_align()
 *
 * # Synchronisation (bundle transfer)
 *
 * This rhizome store holds a synchronization status to each subscriberś rhizome store (subscriber_sync_status).
 * It also holds a status of bundles with broken/ missing payloads. The store synchronisation status is kept up to date by:
 * 1) regular alignment to current bundles in store, including detection of missing/ broken payloads - store_sync_status_align(),
 * 2) managing the interest in bundles of other stores:
 *    - remove interest in bundle on bundle addition - store_sync_status_align_to_bundle_manifest().
 *    - add interest in bundle on the reception of bundle advertizements from other stores - process_bars_list_from_subscriber()
 *
 * @{
 */


#define MSG_TYPE_BARS 0
#define MSG_TYPE_REQ 1

#define MAX_TRIES 10
#define CACHE_BARS 60
#define MAX_OLD_BARS 40
#define BARS_PER_RESPONSE ((int)400/RHIZOME_BAR_BYTES)


/// Bundle announcement record entry.
struct bar_entry
{
  rhizome_bar_t bar;
  unsigned tries;
  time_ms_t next_request;
};


/** Rhizome bundle store subscriber synchronisation status.
 *
 * Synchronization status between this serval daemon rhizome store
 * and the subscribers rhizome store.
 */
struct rhizome_sync_bars_subscriber_state
{
  /// Time of last usage of synchronization status.
  time_ms_t last_use;

  // window of BAR's we have synced
  uint64_t sync_start;
  uint64_t sync_end;
  uint64_t highest_seen;
  unsigned char sync_complete;
  uint32_t bars_seen;
  uint32_t bars_skipped;
  time_ms_t start_time;
  time_ms_t completed;
  time_ms_t next_request;
  time_ms_t last_extended;
  time_ms_t last_response;
  time_ms_t last_new_bundle;

  /** A short list of BAR's this store is interested in (from the last parsed message).
   * A BAR is removed from the list when this store gets the bundle.
   */
  struct bar_entry *bars;

  /// how many bars are we interested in?
  int bar_count;
};


/** Mark peers synchronisation status to be used.
 *
 * Create the synchronisation status if not available.
 *
 * @param peer
 * @return sync_keys_state The synchronisation status.
 */
static struct rhizome_sync_bars_subscriber_state *sync_bars_peer_state_use(struct subscriber *peer)
{
  if (!peer->sync_bars_state) {
    peer->sync_bars_state = emalloc_zero(sizeof(struct rhizome_sync_bars_subscriber_state));
    peer->sync_bars_state->start_time = gettime_ms();
  }
  peer->sync_bars_state->last_use = gettime_ms();
  return peer->sync_bars_state;
}


/** Mark peers synchronization status to be unused.
 *
 * @param peer
 * @return sync_keys_state Synchronisation status or Null in case there is no synchronisation status (anymore).
 */
static struct rhizome_sync_bars_subscriber_state *sync_bars_peer_state_unuse(struct subscriber *peer)
{
  if (peer->sync_bars_state && ((gettime_ms() - peer->sync_bars_state->last_use) > 30000)) {
    // No access to synchronisation status for > 30000 ms.
    // Don't make the timeout too short as we may have short communication interruptions.
    // @TODO
  }
  return peer->sync_bars_state;
}


/** Rhizome bundle store payload status.
 *
 * Status of payloads of this serval daemon
 */
static struct
{
  /// List of bundle advertisement records of manifests in store with missing/ broken payload.
  rhizome_bar_t borken_payload_bars[3];

  /// Number of bars for broken payload.
  int borken_payload_count;
} sync_state_payload = { .borken_payload_count = 0 };


/** Remember broken payload in store.
 * @param m Manifest of bundle with broken payload.
 */
static void sync_state_payload_add_broken(rhizome_manifest *m)
{
  if (sync_state_payload.borken_payload_count >= 3) {
    // full
    return;
  }
  rhizome_bar_t *bar = &sync_state_payload.borken_payload_bars[sync_state_payload.borken_payload_count];
  rhizome_manifest_to_bar(m, bar);

  // Search whether in list.
  for (int i = 0; i < sync_state_payload.borken_payload_count; i++) {
    if (bcmp(&bar->binary[0], &sync_state_payload.borken_payload_bars[i].binary[0], sizeof(bar->binary)) == 0) {
      // already in list
      return;
    }
  }
  sync_state_payload.borken_payload_count++;
}


/** Check whether the bar denotes a bundle with broken payload.
 *
 * Removes the bundle from the broken payload status if the bar fits.
 *
 * @param bar the bundle advertizement record.
 * @return 1 if the bar denotes a bundle with broken payload, 0 otherwise.
 */
static int sync_state_payload_is_broken(const rhizome_bar_t *bar)
{
  for (int i = 0; i < sync_state_payload.borken_payload_count; i++) {
    if (bcmp(&bar->binary[0], &sync_state_payload.borken_payload_bars[i].binary[0], sizeof(bar->binary)) == 0) {
      // this is a broken payload
      sync_state_payload.borken_payload_count--;
      if (i != sync_state_payload.borken_payload_count) {
        bcopy(&sync_state_payload.borken_payload_bars[sync_state_payload.borken_payload_count].binary[0],
              &sync_state_payload.borken_payload_bars[i].binary[0], sizeof(bar->binary));
      }
      return 1;
    }
  }
  return 0;
}


/** Rhizome bundle store announcement status.
 *
 * Status of bundle announcements by this serval daemon
 * to any other serval subscriber.
 */
static struct
{
  /// Bundle to include in next announcement
  uint64_t announce_next;
  /// Out of sequence announcements
  uint64_t announce_out_of_sequence[3];
  /// Number of out of sequence announcements
  int announce_out_of_sequence_count;
  /// First bundle to be announced.
  uint64_t announce_begin;
  /// Last bundle to be announced.
  uint64_t announce_end;
} sync_state_announcement = { .announce_next = INVALID_TOKEN,
                                .announce_out_of_sequence_count = 0,
                                .announce_begin = INVALID_TOKEN,
                                .announce_end = INVALID_TOKEN };


/** Schedule an announcement.
 *
 * @param rowid Row id of bundle in rhizome bundle store.
 * @param next 0 = normal, >0 = force inclusion in next announcement list.
 */
static void announcement_schedule(uint64_t rowid, int next) {
    if (rowid == INVALID_TOKEN) {
        return;
    }
    if (next) {
        sync_state_announcement.announce_next = rowid;
    } else {
        if (sync_state_announcement.announce_begin == INVALID_TOKEN && sync_state_announcement.announce_end == INVALID_TOKEN) {
        // nothing to announce - just add it
            sync_state_announcement.announce_begin = rowid;
            sync_state_announcement.announce_end = rowid;
        } else if (rowid >= sync_state_announcement.announce_begin) {
        // rowid >= begin
            if (rowid <= sync_state_announcement.announce_end) {
                // already scheduled for announcement
            } else if (rowid >= sync_state_announcement.announce_end + BARS_PER_RESPONSE) {
                // We would have to add too many bars to announce
                // Try whether we can do an out of sequence announce.
                if (sync_state_announcement.announce_out_of_sequence_count < 3) {
                    sync_state_announcement.announce_out_of_sequence[sync_state_announcement.announce_out_of_sequence_count] = rowid;
                    sync_state_announcement.announce_out_of_sequence_count++;
                } else {
                    sync_state_announcement.announce_end = rowid;
                }
            } else {
                sync_state_announcement.announce_end = rowid;
            }
        // rowid < begin
        } else if (sync_state_announcement.announce_end < BARS_PER_RESPONSE) {
            sync_state_announcement.announce_begin = rowid;
        } else if (rowid <= sync_state_announcement.announce_end - BARS_PER_RESPONSE) {
            // We would have to add too many bars to announce
            // Try whether we can do an out of sequence announce.
            if (sync_state_announcement.announce_out_of_sequence_count < 3) {
                sync_state_announcement.announce_out_of_sequence[sync_state_announcement.announce_out_of_sequence_count] = rowid;
                sync_state_announcement.announce_out_of_sequence_count++;
            } else if (rowid < sync_state_announcement.announce_begin) {
                sync_state_announcement.announce_begin = rowid;
            }
        } else {
            sync_state_announcement.announce_begin = rowid;
        }
    }
    DEBUGF(rhizome_sync_bars, "announcement schedule, rowid=%"PRId64", next=%"PRId64", begin=%"PRId64", end=%"PRId64", oos_count=%d, oos1=%"PRId64", oos2=%"PRId64", oos3=%"PRId64".",
                            rowid, sync_state_announcement.announce_next,
                            sync_state_announcement.announce_begin, sync_state_announcement.announce_end,
                            sync_state_announcement.announce_out_of_sequence_count,
                            sync_state_announcement.announce_out_of_sequence[0],
                            sync_state_announcement.announce_out_of_sequence[1],
                            sync_state_announcement.announce_out_of_sequence[2]);
}


/** List announcements to be made.
 *
 *  Removes the listed announcements from the announcement status.
 *
 * @param count Maximum number of announcements to list.
 * @param forwards forwards (>0) or backwards (==0) listing.
 * @param rowid_start [out] Row id of bundle in rhizome bundle store that is the head of the list.
 * @return number of announcements listed.
 */
static uint64_t announcement_list(uint64_t count, int forwards, uint64_t *rowid_start) {
    if (count == 0) {
        return 0;
    }
    // Set announcement window to next announcement, will be INVALID_TOKEN if there is no next announcement.
    uint64_t window_begin = sync_state_announcement.announce_next;
    uint64_t window_end = sync_state_announcement.announce_next;

    uint64_t window_limit_begin;
    uint64_t window_limit_end;
    int regard_out_of_sequence = 1;
    while (1) {
        if (window_begin != INVALID_TOKEN) {
            // we have a window - calculate window limits.
            if (count > window_end) {
                window_limit_begin = 0;
            } else {
                window_limit_begin = window_end - count;
            }
            window_limit_end = window_begin + count;
        }
        if (regard_out_of_sequence && sync_state_announcement.announce_out_of_sequence_count > 0) {
            // Out of sequence announcements available (high prio)
            uint64_t rowid = sync_state_announcement.announce_out_of_sequence[sync_state_announcement.announce_out_of_sequence_count - 1];
            if (window_begin == INVALID_TOKEN) {
                // Initial state
                window_begin = window_end = rowid;
                sync_state_announcement.announce_out_of_sequence_count--;
            } else if ((rowid >= window_limit_begin) && (rowid <= window_limit_end)) {
                if (rowid > window_end) {
                    window_end = rowid;
                } else if (rowid < window_begin) {
                    window_begin = rowid;
                }
                sync_state_announcement.announce_out_of_sequence_count--;
            } else {
                // out of sequence announcement does not fit into window.
                regard_out_of_sequence = 0;
            }
        } else if (sync_state_announcement.announce_begin == INVALID_TOKEN && sync_state_announcement.announce_end == INVALID_TOKEN) {
            // nothing to announce
            break;
        } else if (window_begin == INVALID_TOKEN) {
            // window not set - no mandatory announcement
            if (forwards) {
                window_begin = sync_state_announcement.announce_begin;
                window_end = window_begin + count;
                if (window_end >= sync_state_announcement.announce_end) {
                    // window covers all anouncements
                    window_end = sync_state_announcement.announce_end;
                    sync_state_announcement.announce_begin = INVALID_TOKEN;
                    sync_state_announcement.announce_end = INVALID_TOKEN;
                } else {
                    sync_state_announcement.announce_begin = window_end + 1;
                }
            } else {
                window_end = sync_state_announcement.announce_end;
                if (count > window_end) {
                    window_begin = 0;
                } else {
                    window_begin = window_end - count;
                }
                if (window_begin <= sync_state_announcement.announce_begin) {
                    // window covers all anouncements
                    window_begin = sync_state_announcement.announce_begin;
                    sync_state_announcement.announce_begin = INVALID_TOKEN;
                    sync_state_announcement.announce_end = INVALID_TOKEN;
                } else {
                    sync_state_announcement.announce_end = window_begin - 1;
                }
            }
            // Window made as big as possible.
            break;
        } else if (forwards) {
            // window already set - forwards listing
            if (sync_state_announcement.announce_end <= window_limit_end
                && sync_state_announcement.announce_end >= window_limit_begin) {
                if (sync_state_announcement.announce_end >= window_begin) {
                    if (sync_state_announcement.announce_end > window_end) {
                        window_end = sync_state_announcement.announce_end;
                    }
                } else {
                    // announce_end < window_begin
                    window_begin = sync_state_announcement.announce_begin;
                    if (window_begin < window_limit_begin) {
                        window_begin = window_limit_begin;
                    }
                }
                // announce_end is now included in window
                if (sync_state_announcement.announce_begin >= window_begin) {
                    sync_state_announcement.announce_begin = INVALID_TOKEN;
                    sync_state_announcement.announce_end = INVALID_TOKEN;
                    // announcement window fully covered by window
                    break;
                }
                sync_state_announcement.announce_end = window_begin - 1;
                // try backwards - we expanded as much as possible in forwards direction.
                forwards = 0;
            } else {
                // cannot attach to existing window
                // either window is fully within announcement window then we would have to create
                // two announcement windows cutting out in between
                // or the window is fully outside of the announcement window
                break;
            }
        } else {
            // window already set - backwards listing
            if (sync_state_announcement.announce_begin <= window_limit_end
                && sync_state_announcement.announce_begin >= window_limit_begin) {
                if (sync_state_announcement.announce_begin >= window_begin) {
                    if (sync_state_announcement.announce_end > window_end) {
                        window_end = sync_state_announcement.announce_end;
                        if (window_end > window_limit_end) {
                            window_end = window_limit_end;
                        }
                    }
                } else {
                    // announce_begin < window_begin
                    window_begin = sync_state_announcement.announce_begin;
                }
                // announce_begin is now included in window
                if (sync_state_announcement.announce_end <= window_end) {
                    sync_state_announcement.announce_begin = INVALID_TOKEN;
                    sync_state_announcement.announce_end = INVALID_TOKEN;
                    // announcement window fully covered by window
                    break;
                }
                sync_state_announcement.announce_begin = window_end + 1;
                // try forwards - we expanded as much as possible in bachwards direction.
                forwards = 1;
            } else {
                // cannot attach to existing window
                break;
            }
        }
    };
    if (window_begin == INVALID_TOKEN) {
        // no announcements
        count = 0;
    } else {
        *rowid_start = forwards ? window_begin : window_end;
        count = window_end - window_begin + 1;

        DEBUGF(rhizome_sync_bars, "announcement list, start=%"PRId64", forwards=%d, count=%"PRId64", begin=%"PRId64", end=%"PRId64".",
                             *rowid_start, forwards, count, window_begin, window_end);
    }

    sync_state_announcement.announce_next = INVALID_TOKEN;

    return count;
}


/** Number of announcements currently scheduled.
 *
 * @return Number of announcements.
 */
static uint64_t announcement_count(void)
{
    uint64_t count = sync_state_announcement.announce_out_of_sequence_count;

    if (sync_state_announcement.announce_begin != INVALID_TOKEN || sync_state_announcement.announce_end != INVALID_TOKEN) {
        count += sync_state_announcement.announce_end - sync_state_announcement.announce_begin + 1;
    }
    if (sync_state_announcement.announce_next != INVALID_TOKEN) {
        count++;
    }
    return count;
}


/** Is rhizome sync bars enabled.
 *
 * @return enabled 1 if enaled, 0 if not enabled.
 */
static int sync_bars_enabled(void)
{
  int enabled = 1;

  if ((config.rhizome.mdp.protocol >= 0) && (config.rhizome.mdp.protocol != RHIZOME_SYNC_PROTOCOL_VERSION_BARS)) {
    // Sync protocol version is forced to another protocol.
    enabled = 0;
  }
  return enabled;
}


/** Send request for list of bundle advertisement records to subscriber.
 *
 * BARs are requested starting at token and either going forward or backward.
 *
 * @param subscriber A pointer to a subscriber struct, the subscriber to request the BARs from.
 * @param token The token of the starting BAR to include in answer.
 * @param forwards forwards (>0) or backwards (==0) listing.
 */
static void request_bars_list_from_subscriber(struct subscriber *subscriber, uint64_t token, unsigned char forwards)
{
  struct internal_mdp_header header;
  bzero(&header, sizeof header);

  header.source = get_my_subscriber(1);
  header.source_port = MDP_PORT_RHIZOME_SYNC_BARS;
  header.destination = subscriber;
  header.destination_port = MDP_PORT_RHIZOME_SYNC_BARS;
  header.qos = OQ_OPPORTUNISTIC;

  struct overlay_buffer *b = ob_new();
  ob_append_byte(b, MSG_TYPE_REQ);
  ob_append_byte(b, forwards);
  ob_append_packed_ui64(b, token);

  DEBUGF(rhizome_sync_bars, "Sending request to %s for BARs from %"PRIu64" %s", alloca_tohex_sid_t(subscriber->sid), token, forwards?"forwards":"backwards");

  ob_flip(b);
  overlay_send_frame(&header, b);
  ob_free(b);
}


/** Request manifests from subscriber.
 *
 * If there is space left in the request also request bundle advertisement records.
 *
 * @param subscriber Subscriber to send requests to.
 * @param state The rhizome syncronisation status associated to the subscriber.
 */
static void request_manifests_from_subscriber(struct subscriber *subscriber, struct rhizome_sync_bars_subscriber_state *state)
{
  int i, requests=0;
  time_ms_t now = gettime_ms();

  // send requests for manifests that we have room to fetch
  struct internal_mdp_header header;
  bzero(&header, sizeof header);
  struct overlay_buffer *payload = NULL;

  for (i=state->bar_count -1;i>=0;i--){
    if (state->bars[i].next_request > now)
      continue;

    unsigned char *prefix = rhizome_bar_prefix(&state->bars[i].bar);

    if (rhizome_ignore_manifest_check(prefix, RHIZOME_BAR_PREFIX_BYTES))
      continue;

    // do we have free space now in the appropriate fetch queue?
    unsigned char log2_size = rhizome_bar_log_size(&state->bars[i].bar);
    if (log2_size!=0xFF && rhizome_fetch_has_queue_space(log2_size)!=1)
      continue;

    if (rhizome_fetch_bar_queued(&state->bars[i].bar)){
      state->bars[i].next_request = now+2000;
      continue;
    }

    if (!payload){
      header.source = get_my_subscriber(1);
      header.source_port = MDP_PORT_RHIZOME_RESPONSE;
      header.destination = subscriber;
      header.destination_port = MDP_PORT_RHIZOME_MANIFEST_REQUEST;
      header.qos = OQ_OPPORTUNISTIC;
      payload = ob_new();
      ob_limitsize(payload, MDP_MTU);
    }

    if (ob_remaining(payload)<RHIZOME_BAR_BYTES)
      break;

    DEBUGF(rhizome_sync_bars, "Requesting manifest for BAR %s", alloca_tohex_rhizome_bar_t(&state->bars[i].bar));

    ob_append_bytes(payload, state->bars[i].bar.binary, RHIZOME_BAR_BYTES);

    state->bars[i].tries--;
    state->bars[i].next_request = now+5000;
    if (!state->bars[i].tries){
      // remove this BAR and shift the last BAR down to this position if required.
      DEBUGF(rhizome_sync_bars, "Giving up on fetching BAR %s", alloca_tohex_rhizome_bar_t(&state->bars[i].bar));
      state->bar_count --;
      if (i<state->bar_count)
        state->bars[i] = state->bars[state->bar_count];
      state->bars_skipped++;

      if (state->bar_count==0){
        free(state->bars);
        state->bars=NULL;
      }
    }

    requests++;
    if (requests>=BARS_PER_RESPONSE)
      break;
  }

  if (payload){
    ob_flip(payload);
    overlay_send_frame(&header, payload);
    ob_free(payload);
  }

  // send request for more bars if we have room to cache them
  if (state->bar_count >= CACHE_BARS)
    return;

  if (state->next_request<=now){
    if (state->sync_end < state->highest_seen){
      request_bars_list_from_subscriber(subscriber, state->sync_end, 1);
    }else if(state->sync_start >0){
      if (state->bar_count < MAX_OLD_BARS)
        request_bars_list_from_subscriber(subscriber, state->sync_start, 0);
    }else if(!state->sync_complete){
      state->sync_complete = 1;
      state->completed = gettime_ms();
      DEBUGF(rhizome_sync_bars, "BAR sync with %s complete", alloca_tohex_sid_t(subscriber->sid));
    }
    state->next_request = now+5000;
  }
}


/** Remove bundle advertisement record from the list of bars this store is interested in.
 *
 * @param subscriber A pointer to a subscriber struct, the subscriber to update the synchronisation status.
 * @param context Pointer to rhizome_bar_t, the bundle advertisement record to remove.
 */
static int sync_state_subscriber_remove_from_bars_interested(void **record, void *context)
{
  struct subscriber *subscriber = *record;
  const rhizome_bar_t *bar = context;

  if (subscriber->sync_version != RHIZOME_SYNC_PROTOCOL_VERSION_BARS) {
    // Subscriber does not use the rhizome_sync_bars (protocol version 0).
    sync_bars_peer_state_unuse(subscriber);
    return 0;
  }

  const unsigned char *id = rhizome_bar_prefix(bar);
  uint64_t version = rhizome_bar_version(bar);

  struct rhizome_sync_bars_subscriber_state *state = sync_bars_peer_state_use(subscriber);
  int i;
  for (i=state->bar_count -1;i>=0;i--){
    rhizome_bar_t *this_bar = &state->bars[i].bar;
    unsigned char *this_id = rhizome_bar_prefix(this_bar);
    uint64_t this_version = rhizome_bar_version(this_bar);
    if (memcmp(this_id, id, RHIZOME_BAR_PREFIX_BYTES)==0 && version >= this_version){
      // remove this BAR and shift the last BAR down to this position if required.
      DEBUGF(rhizome_sync_bars, "Removing BAR %s from queue", alloca_tohex_rhizome_bar_t(this_bar));
      state->bar_count --;
      if (i<state->bar_count)
        state->bars[i] = state->bars[state->bar_count];
      if (state->bar_count==0){
        free(state->bars);
        state->bars=NULL;
      }
    }
  }

  return 0;
}

/** Align all subscribers synchronization stati to a bundle info in this store.
 *
 * @param m manifest of bundle to align synchronisaion status to.
 * @param broken 0 if bundle is ok, 1 if broken.
 */
void rhizome_sync_bars_align_to_bundle_manifest(rhizome_manifest *m, int broken)
{
  if (!sync_bars_enabled()) {
    // protocol is forced to another version.
    return;
  }

  if (broken) {
    sync_state_payload_add_broken(m);
    return;
  }

  rhizome_bar_t bar;
  rhizome_manifest_to_bar(m, &bar);
  // Update rhizome synchronisation status of all subscribers.
  enum_subscribers(NULL, sync_state_subscriber_remove_from_bars_interested, (void *)&bar);

  if (m->rowid != INVALID_TOKEN) {
    // Bundle is already in store, otherwise rowid would be 0.
    // Announce locally created/ updated bundle as soon as possible, but low priority
    announcement_schedule(m->rowid, 0);
  }
}


/** Process bundle advertisement record received.
 *
 * Updates the subscriber's rhizome synchronisation status. Caches the bundle advertisement record if
 * this rhizome store is interested in the bundle.
 *
 * @param state The rhizome syncronisation status associated to the subscriber that sent the record.
 * @param bar bundle advertisement record.
 * @param token The token of the bundle in the subscribers rhizome store.
 * @return -1 (no memory to cache bar)
 *         0 (bar cache full, can not process)
 *         1 (bar processed)
 */
static int process_bar_from_subscriber(struct rhizome_sync_bars_subscriber_state *state, const rhizome_bar_t *bar, uint64_t token)
{
  int ret=0;
  if (state->bar_count>=CACHE_BARS)
    return 0;
  // check the database before adding the BAR to the list
  if ((token != INVALID_TOKEN) && (sync_state_payload_is_broken(bar) || (rhizome_is_bar_interesting(bar) != 0))) {
    if (!state->bars){
      state->bars = emalloc(sizeof(struct bar_entry) * CACHE_BARS);
      if (!state->bars)
        return -1;
    }

    DEBUGF(rhizome_sync_bars, "Remembering BAR %s", alloca_tohex_rhizome_bar_t(bar));

    state->bars[state->bar_count].bar = *bar;
    state->bars[state->bar_count].next_request = gettime_ms();
    state->bars[state->bar_count].tries = MAX_TRIES;
    state->bar_count++;
    ret=1;
  }
  if (state->sync_end < token){
    state->sync_end = token;
    state->last_extended = gettime_ms();
    if (token!=0)
      state->bars_seen++;
    ret=1;
  }
  if (state->sync_start > token){
    state->sync_start = token;
    state->last_extended = gettime_ms();
    if (token!=0)
      state->bars_seen++;
    ret=1;
  }
  return ret;
}


/** Process bundle advertisement records list received from subscriber.
 *
 * @param subscriber Subscriber that provided the bundle advertisement records.
 * @param state The rhizome syncronisation status associated to the subscriber.
 * @param b The overlay packet reveived from the subscriber.
 */
static void process_bars_list_from_subscriber(struct subscriber *subscriber, struct rhizome_sync_bars_subscriber_state *state, struct overlay_buffer *b)
{
  // find all interesting BARs in the payload and extend our sync range

  const rhizome_bar_t *bars[BARS_PER_RESPONSE];
  uint64_t bar_tokens[BARS_PER_RESPONSE];
  int bar_count = 0;
  int has_before=0, has_after=0;
  int mid_point = -1;
  time_ms_t now = gettime_ms();

  DEBUGF(rhizome_sync_bars, "Process BARs list, source=%s.", alloca_tohex_sid_t(subscriber->sid));

  if (now - state->start_time > (60*60*1000)){
    // restart rhizome sync every hour, no matter what state it is in
    bzero(state, sizeof(struct rhizome_sync_bars_subscriber_state));
    state->start_time = now;
  }
  state->last_response = now;

  while(ob_remaining(b)>0 && bar_count < BARS_PER_RESPONSE){
    bar_tokens[bar_count]=ob_get_packed_ui64(b);
    bars[bar_count]=(const rhizome_bar_t *)ob_get_bytes_ptr(b, RHIZOME_BAR_BYTES);
    if (!bars[bar_count])
      break;
    // allow the sender to identify the edge of the range this packet represents
    // even if there is no manifest that falls exactly on the boundary (eg deleted manifest or zero lower bound)
    if (rhizome_is_bar_none(bars[bar_count]))
      bars[bar_count]=NULL;

    // track the highest BAR we've seen, even if we can't sync it yet, so we know what BARs to request.
    if (state->highest_seen < bar_tokens[bar_count]){
      state->highest_seen = bar_tokens[bar_count];
      state->last_new_bundle = gettime_ms();
      state->sync_complete = 0;
    }

    if (state->sync_end!=0){
      if (bar_tokens[bar_count]<=state->sync_end)
        has_before = 1;
      if (bar_tokens[bar_count]>=state->sync_start)
        has_after = 1;

      // we can completely ignore BARSs we have already synced
      if (state->sync_end>0 && bar_tokens[bar_count] <= state->sync_end && bar_tokens[bar_count] >= state->sync_start)
        continue;

      if (has_before && has_after && mid_point == -1)
        mid_point = bar_count;
    }

    bar_count++;
  }

  if (bar_count>0 && has_before && has_after && mid_point == -1)
    mid_point = bar_count -1;

  if (bar_count>0 && state->sync_end == 0 && bar_tokens[0]>=bar_tokens[bar_count -1]){
    // make sure we start syncing from the end
    DEBUGF(rhizome_sync_bars, "Starting BAR sync with %s", alloca_tohex_sid_t(subscriber->sid));
    state->sync_start = state->sync_end = state->highest_seen;
    mid_point=0;
  }

  // ignore the BARs in this packet if it doesn't include something we already know
  if (bar_count>0 && mid_point>=0){
    int i;
    // extend the set of BARs we have synced from this peer
    // we require the list of BARs to be either ASC or DESC and include BARs for *all* manifests in that range
    // TODO stop if we are taking too much CPU time.
    int added=0;
    for (i=mid_point; i<bar_count; i++){
      int r=process_bar_from_subscriber(state, bars[i], bar_tokens[i]);
      if (r==-1)
        return;
      if (r==1)
        added=1;
    }
    for (i=mid_point -1; i>=0; i--){
      if (state->bar_count >= MAX_OLD_BARS)
        break;
      int r=process_bar_from_subscriber(state, bars[i], bar_tokens[i]);
      if (r==-1)
        return;
      if (r==1)
        added=1;
    }
    DEBUGF(rhizome_sync_bars, "Synced %"PRIu64" - %"PRIu64" with %s", state->sync_start, state->sync_end, alloca_tohex_sid_t(subscriber->sid));
    if (added)
      state->next_request = gettime_ms();
  }

}


/** Append bundle advertisement record to list of bars in message.
 *
 * @param b The overlay packet to be send to subscriber.
 * @param token rowid of bundle in this rhizome bundle store.
 * @param bar bundle advertisement record.
 */
static void send_bars_list_append_bar(struct overlay_buffer *b, uint64_t token, const unsigned char *bar)
{
  ob_append_packed_ui64(b, token);
  if (bar)
    ob_append_bytes(b, bar, RHIZOME_BAR_BYTES);
  else{
    unsigned char *ptr = ob_append_space(b, RHIZOME_BAR_BYTES);
    if (ptr)
      bzero(ptr, RHIZOME_BAR_BYTES);
  }
}


/** Send bundle advertisement records list to subscriber.
 *
 * @param dest Subcriber to send response to. If Null a broadcast message is generated.
 * @param forwards list bars forward (>0) or backwards(==0).
 * @param max_count Maximum of bars to be included in response message.
 */
static void send_bars_list_to_subscriber(struct subscriber *dest, int forwards, uint64_t max_count)
{
  IN();

  if (max_count == 0 || max_count > BARS_PER_RESPONSE)
    max_count = BARS_PER_RESPONSE;

  struct internal_mdp_header header;
  bzero(&header, sizeof header);

  header.source = get_my_subscriber(1);
  header.source_port = MDP_PORT_RHIZOME_SYNC_BARS;
  header.destination = dest;
  header.destination_port = MDP_PORT_RHIZOME_SYNC_BARS;
  header.qos = OQ_OPPORTUNISTIC;

  if (!dest) {
    // Special case - broadcast of announcements.
    header.crypt_flags = (MDP_FLAG_NO_CRYPT|MDP_FLAG_NO_SIGN);
    header.ttl = 1;
  }

  uint64_t rowid_start = INVALID_TOKEN;
  max_count = announcement_list(max_count, forwards, &rowid_start);
  if (max_count == 0) {
    DEBUGF(rhizome_sync_bars, "No BARs to send from %"PRIu64, rowid_start);
    OUT();
    return;
  }

  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  sqlite3_stmt *statement;
  if (forwards){
    statement = sqlite_prepare(&retry, "SELECT rowid, bar FROM manifests WHERE rowid >= ? ORDER BY rowid ASC");
  }else{
    statement = sqlite_prepare(&retry, "SELECT rowid, bar FROM manifests WHERE rowid <= ? ORDER BY rowid DESC");
  }

  if (!statement) {
    OUT();
    return;
  }

  sqlite3_bind_int64(statement, 1, rowid_start);
  uint64_t count=0;
  uint64_t last=0;

  struct overlay_buffer *b = ob_new();
  ob_limitsize(b, MDP_MTU);
  ob_append_byte(b, MSG_TYPE_BARS);
  ob_checkpoint(b);

  while(sqlite_step_retry(&retry, statement)==SQLITE_ROW){
    uint64_t bar_rowid = sqlite3_column_int64(statement, 0);
    const unsigned char *bar = sqlite3_column_blob(statement, 1);
    size_t bar_size = sqlite3_column_bytes(statement, 1);

    if (bar_size != RHIZOME_BAR_BYTES)
      continue;

    // make sure we include the manifest of rowid_start (the presumable last token requested),
    // even if we just deleted / replaced the manifest
    if (count == 0 && bar_rowid != rowid_start) {
      ob_checkpoint(b);
      send_bars_list_append_bar(b, rowid_start, NULL);
      if (ob_overrun(b))
        ob_rewind(b);
      else {
        count++;
        last = rowid_start;
      }
    }

    ob_checkpoint(b);
    send_bars_list_append_bar(b, bar_rowid, bar);
    if (ob_overrun(b))
      ob_rewind(b);
    else {
      last = bar_rowid;
      count++;
    }
    if (count >= max_count)
      break;
  }

  sqlite3_finalize(statement);

  // send a zero lower bound if we reached the end of our manifest list
  if (count && count < max_count && !forwards){
    ob_checkpoint(b);
    send_bars_list_append_bar(b, INVALID_TOKEN, NULL);
    if (ob_overrun(b))
      ob_rewind(b);
    else {
      last = 0;
      count++;
    }
  }

  if (count){
    DEBUGF(rhizome_sync_bars, "Sending %d BARs from %"PRIu64" to %"PRIu64, (int)count, rowid_start, last);
    ob_flip(b);
    overlay_send_frame(&header, b);
  } else {
    DEBUGF(rhizome_sync_bars, "No BARs to send from %"PRIu64" to %"PRIu64, rowid_start, last);
  }
  ob_free(b);
  OUT();
}


/** Is rhizome sync bars fit for a new round of alignment to the bundle stor content.
 *
 * @param broken_count Number of broken bundles in rhizome store.
 * @return fit 1 if fit, 0 otherwise.
 */
int rhizome_sync_bars_fit_for_realign(int UNUSED(broken_count))
{
  return !sync_bars_enabled() || (announcement_count() == 0);
}


/** Send empty bundle advertisement records list to all subscribers.
 */
static void sync_bars_announce_capability(void)
{
  struct internal_mdp_header header;
  bzero(&header, sizeof header);

  // broadcast
  header.source = get_my_subscriber(1);
  header.source_port = MDP_PORT_RHIZOME_SYNC_BARS;
  header.destination = NULL;
  header.destination_port = MDP_PORT_RHIZOME_SYNC_BARS;
  header.qos = OQ_OPPORTUNISTIC;
  header.crypt_flags = (MDP_FLAG_NO_CRYPT|MDP_FLAG_NO_SIGN);
  header.ttl = 1;

  struct overlay_buffer *b = ob_new();

  ob_limitsize(b, MDP_MTU);
  ob_append_byte(b, MSG_TYPE_BARS);
  ob_checkpoint(b);
  send_bars_list_append_bar(b, INVALID_TOKEN, NULL);
  DEBUG(rhizome_sync_bars, "Sending empty BARs");
  ob_flip(b);
  overlay_send_frame(&header, b);
  ob_free(b);
}


/** Broadcast bundle advertisement records list to all subscribers.
 */
void rhizome_sync_bars_announce(int protocol_count, int other_count)
{
  static int throttle = 5;

  if (!sync_bars_enabled()) {
    // protocol is forced to another version.
    return;
  }

  if (protocol_count == 0) {
    if ((other_count > 0) || (throttle <= 0)) {
      sync_bars_announce_capability();
      throttle = 5;
    } else {
      throttle--;
    }
  } else {
    int (*oldfunc)() = sqlite_set_tracefunc(is_debug_rhizome_ads);
    send_bars_list_to_subscriber(NULL, 0, 5);
    sqlite_set_tracefunc(oldfunc);
  }
}


DEFINE_BINDING(MDP_PORT_RHIZOME_SYNC_BARS, rhizome_sync_bars_recv);
static int rhizome_sync_bars_recv(struct internal_mdp_header *header, struct overlay_buffer *payload)
{
  int type = ob_get(payload);

  DEBUGF(rhizome_sync_bars, "Received %s from %s, self = %d, sync protocol version = %d, rhizome.enable = %d, rhizome.fetch = %d, rhizome_db = %d.",
            type == MSG_TYPE_BARS ? "BARs list" : type == MSG_TYPE_REQ ? "BARs request" : "<unknown>",
            alloca_tohex_sid_t(header->source->sid),
            header->source->reachable == REACHABLE_SELF,
            header->source->sync_version,
            config.rhizome.enable,
            config.rhizome.fetch,
            rhizome_db != NULL);

  if (header->source->reachable == REACHABLE_SELF) {
    // Dont respond to own message
    return 0;
  }

  if (config.rhizome.mdp.protocol >= 0) {
    // Sync protocol version is forced.
    header->source->sync_version = (uint8_t)config.rhizome.mdp.protocol;
  }

  if ( !config.rhizome.enable                                                   // rhizome not enabled
       || !rhizome_db                                                           // No rhizome database
       || header->source->sync_version != RHIZOME_SYNC_PROTOCOL_VERSION_BARS    // Subscriber uses another sync protocol version.
     ) {
    return 0;
  }

  struct rhizome_sync_bars_subscriber_state *state = sync_bars_peer_state_use(header->source);
  // Reply and request.
  switch (type){
    case MSG_TYPE_BARS:
      if (config.rhizome.fetch)
        process_bars_list_from_subscriber(header->source, state, payload);
      break;
    case MSG_TYPE_REQ:
      {
        int forwards = ob_get(payload);
        uint64_t token = ob_get_packed_ui64(payload);
        // Schedule token to be included in next announcement.
        announcement_schedule(token, 1);
        send_bars_list_to_subscriber(header->source, forwards, 0);
      }
      break;
  }
  if (config.rhizome.fetch)
    request_manifests_from_subscriber(header->source, state);
  return 0;
}



void rhizome_sync_bars_subscriber_status_html(struct strbuf *b, struct subscriber *subscriber)
{
  if (!subscriber->sync_bars_state)
    return;
  struct rhizome_sync_bars_subscriber_state *state=subscriber->sync_bars_state;
  strbuf_sprintf(b, "Seen %u BARs [%"PRId64" to %"PRId64" of %"PRId64"], %d interesting, %d skipped<br>",
    state->bars_seen,
    state->sync_start,
    state->sync_end,
    state->highest_seen,
    state->bar_count,
    state->bars_skipped);
}


/** Provide debug output on rhizome syncronisation status of a subscriber.
 *
 * @param record A pointer to pointer to subscriber struct, the subscriber.
 * @param context unused.
 */
static int sync_bars_subscriber_status(void **record, void *UNUSED(context))
{
  struct subscriber *subscriber = *record;
  if (!subscriber->sync_bars_state)
    return 0;
  struct rhizome_sync_bars_subscriber_state *state=subscriber->sync_bars_state;
  DEBUGF(rhizome_sync_bars, "%s seen %u BARs [%"PRId64" to %"PRId64" of %"PRId64"], %d interesting, %d skipped",
    alloca_tohex_sid_t(subscriber->sid),
    state->bars_seen,
    state->sync_start,
    state->sync_end,
    state->highest_seen,
    state->bar_count,
    state->bars_skipped);
  return 0;
}


/** Provide debug output on rhizome syncronisation status of all subscribers.
 */
void rhizome_sync_bars_status()
{
  // call subscriber_sync_status_debug() for all subscribers.
  enum_subscribers(NULL, sync_bars_subscriber_status, NULL);
}


/** @} rhizome-sync-bars */

/** @} rhizome-sync */