/*
Copyright (C) 2010-2012 Serval Project Inc.

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


/** @addtogroup rhizome
 * @{
 */

/** @defgroup rhizome-sync Rhizome store synchronisation
 *
 * Synchronization of rhizome stores consist of two basic operations:
 * - announce the content of this rhizome store
 * - synchronize the content of this rhizome store with the content of another rhizome store.
 *
 * Both operations are executed on a regular basis scheduled by an alarm service that executes
 * rhizome_sync_announce() or by an explicit request from another store processed by
 * rhizome_sync_keys_recv() or rhizome_sync_bars_recv().
 *
 * Rhizome synchronization supports two protocol versions:
 * - rhizome-sync-bars
 * - rhizome-sync-keys
 *
 * @{
 */


#define HEAD_FLAG INT64_MAX

/// Rhizome store synchonization control.
static struct sync_store_control {
  /// Alignment of all subscribers synchronisation stati enabled.
  int align_enabled;
  /// Rowid of last bundle that the store sync status was aligned to.
  uint64_t align_last_bundle;
  /// Number of broken bundles in store.
  int broken_count;
} sync_store_control;


/// Alarm to be scheduled by fdqueue.
DEFINE_ALARM(rhizome_sync_announce);


/** Reschedule next rhizome store announcement.
 *
 * @param interval_ms Interval to next nsynchronisation.
 */
static void sync_announce_reschedule(time_ms_t interval_ms)
{
  // If interval is infinite - do not schedule
  if (interval_ms > INT_MAX) {
    return;
  }
  // Assure not to schedule in the past - give some headroom.
  if (interval_ms < 5) {
    interval_ms = 5;
  }
  struct sched_ent *alarm = &ALARM_STRUCT(rhizome_sync_announce);
  time_ms_t next_schedule = gettime_ms() + interval_ms;
  if ((alarm->alarm > next_schedule) || !is_scheduled(alarm)) {
    DEBUGF(rhizome_sync,"Reschedule rhizome sync announce for %dms", (int)interval_ms);
    RESCHEDULE(alarm, next_schedule, next_schedule, TIME_MS_NEVER_WILL);
  }
}


/** Check what protocol the subscriber uses to sync the stores.
 *
 * Increment the use count if the subscriber uses the respective protocol.
 * Only reachable subscribers (not self) are counted.
 *
 * @param subscriber A pointer to a subscriber struct, the subscriber to update the synchronisation status.
 * @param context Pointer to an array of ints, each array element counts the number of subscribers that uses the respective rhizome_sync protocol version to sync the stores.
 */
static int sync_store_subscriber_uses_rhizome_sync(void **record, void *context)
{
  struct subscriber *subscriber = *record;
  int *rhizome_sync_subscribers = context;

  if ((subscriber->reachable != REACHABLE_NONE) && (subscriber->reachable != REACHABLE_SELF)) {
    assert(subscriber->sync_version < RHIZOME_SYNC_PROTOCOL_NUMBER);
    rhizome_sync_subscribers[subscriber->sync_version] += 1;
  }
  return 0;
}


/** Check what protocol the subscribers use to sync the stores.
 *
 * Increment the use count if a subscriber uses the respective protocol
 *
 * @param rhizome_sync_subscribers Array of integers repesenting the protocol use count.
 */
static void sync_store_subscribers_use_rhizome_sync(int * rhizome_sync_subscribers)
{
  for(int version = 0; version < RHIZOME_SYNC_PROTOCOL_NUMBER; version++) {
    rhizome_sync_subscribers[version] = 0;
  }

  enum_subscribers(NULL, sync_store_subscriber_uses_rhizome_sync, (void *)rhizome_sync_subscribers);

  DEBUGF(rhizome_sync, "Rhizome sync protocol subscribers, SYNC_BARS = %d, SYNC_KEYS = %d.",
         rhizome_sync_subscribers[RHIZOME_SYNC_PROTOCOL_VERSION_BARS],
         rhizome_sync_subscribers[RHIZOME_SYNC_PROTOCOL_VERSION_KEYS]);

  return;
}

/** Reset the store synchronisation status regarding the alignment to the stores content.
 *
 * @param rowid Row id to reset the alignment to. Use INVALID_TOKEN to restart from beginning.
 */
static void sync_store_align_reset(uint64_t rowid)
{
  sync_store_control.align_enabled = 1;

  if (rowid == INVALID_TOKEN) {
    sync_store_control.align_last_bundle = INVALID_TOKEN;
  } else if (rowid <= sync_store_control.align_last_bundle) {
    sync_store_control.align_last_bundle = rowid - 1;
  }
}


/** Align all subscribers synchronisation stati to the bundle given by manifest.
 */
static void sync_store_align_to_manifest(rhizome_manifest *m, int broken)
{
  rhizome_sync_keys_align_to_bundle_manifest(m, broken);
  rhizome_sync_bars_align_to_bundle_manifest(m, broken);
}


/** Align all subscribers synchronisation stati to this store content.
 */
static int sync_store_align(void)
{
  if (!sync_store_control.align_enabled) {
    // We are currently not allowd to sync to store content.
    // Should also prevent unnecessary access to database.
    return 0;
  }

  int num_borken = 0; // Number of broken bundles
  int result = SQLITE_DONE;
  uint64_t rowid_head = HEAD_FLAG;

  // rowid_current > last_bundle_aligned or we take the head
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  sqlite3_stmt *statement = sqlite_prepare_bind(&retry,
      "SELECT rowid, manifest FROM manifests WHERE rowid > ? AND rowid <= ? ORDER BY rowid ASC;",
      INT64, sync_store_control.align_last_bundle, INT64, rowid_head, END);

  while ((result = sqlite_step_retry(&retry, statement)) == SQLITE_ROW) {
    uint64_t rowid = sqlite3_column_int64(statement, 0);
    const void *blob = sqlite3_column_blob(statement, 1);
    size_t blob_length = sqlite3_column_bytes(statement, 1);
    rhizome_manifest *m = rhizome_new_manifest();

    if (rowid_head == HEAD_FLAG) {
      rowid_head = rowid;
    }

    if (m) {
      memcpy(m->manifestdata, blob, blob_length);
      m->manifest_all_bytes = blob_length;
      if (rhizome_manifest_parse(m) >= 0) {
        // manifest can be parsed (no 'unrecoverable' error (e.g. malloc failed))
        int borken = 0;
        if (!rhizome_manifest_validate(m)) {
          // some essential (transport) fields are not present or not well formed.
          num_borken++;
          borken = 1;
        } else if (!rhizome_manifest_verify(m)) {
          // no or no valid signature
          num_borken++;
          borken = 1;
        } else if (m->filesize > 0 && !rhizome_exists(&m->filehash)) {
          // payload missing
          num_borken++;
          borken = 1;
        }
        m->rowid = rowid;
        sync_store_align_to_manifest(m, borken);
      }
      rhizome_manifest_free(m);
    }
  }
  sqlite3_finalize(statement);

  DEBUGF(rhizome_sync, "Aligned from %"PRIu64" to %"PRIu64", result = %d",
                       sync_store_control.align_last_bundle + 1, rowid_head, result);

  if (rowid_head != HEAD_FLAG) {
    sync_store_control.align_last_bundle = rowid_head;
  }

  if (result == SQLITE_DONE) {
      sync_store_control.align_enabled = 0; // There must be a reset until we align again.
      sync_store_control.broken_count = num_borken;
      result = 0;
  } else {
      result = -1;
  }
  return result;
}


/** Announce this bundle store content to neighbour stores.
 *
 * @param alarm
 */
void rhizome_sync_announce(struct sched_ent *alarm)
{
  uint32_t interval_ms;

  DEBUGF(rhizome_sync, "Rhizome sync announce, is_rhizome_advertise_enabled = %d, rhizome.enable = %d, rhizome_db = %d.",
         is_rhizome_advertise_enabled(),
         config.rhizome.enable,
         rhizome_db != NULL
        );

  if (!is_rhizome_advertise_enabled()) {
    // Rhizome not enabled or no database or advertising not allowed - no synchronisation
    // throttle
    interval_ms = config.rhizome.advertise.interval * 10;
  } else if (sync_store_align() != 0) {
     // Could not align the rhizome store synchronisation status to the rhizome store content.
     // possibly the rhizome database is locked/busy - try again soon.
    interval_ms = 50;
  } else {
    interval_ms = config.rhizome.advertise.interval;

    // check what synchronisation protocol the known subscribers are using.
    int sync_protocol_subscriber_count[RHIZOME_SYNC_PROTOCOL_NUMBER];
    sync_store_subscribers_use_rhizome_sync(&sync_protocol_subscriber_count[0]);

    // Sync KEYS, protocol version 1.
    rhizome_sync_keys_announce(sync_protocol_subscriber_count[RHIZOME_SYNC_PROTOCOL_VERSION_KEYS],
                               sync_protocol_subscriber_count[RHIZOME_SYNC_PROTOCOL_VERSION_BARS]);

    // Sync BARS, protocol version 0.
    rhizome_sync_bars_announce(sync_protocol_subscriber_count[RHIZOME_SYNC_PROTOCOL_VERSION_BARS],
                               sync_protocol_subscriber_count[RHIZOME_SYNC_PROTOCOL_VERSION_KEYS]);

    // realign
    if (rhizome_sync_keys_fit_for_realign(sync_store_control.broken_count)
        && rhizome_sync_bars_fit_for_realign(sync_store_control.broken_count)) {
      sync_store_align_reset(INVALID_TOKEN);
    }
  }

  assert(alarm == &ALARM_STRUCT(rhizome_sync_announce));
  sync_announce_reschedule(interval_ms);
}


/** Process bundle add trigger.
 *
 * Update rhizome synchronisation status of all subscribers;
 * we are no longer interested in this bundle from other subscribers.
 *
 * Schedule bundle advertisement for bundle added.
 *
 * @param m manifest of bundle added.
 */
static void rhizome_sync_on_bundle_add(rhizome_manifest *m)
{
  DEBUG(rhizome_sync, "Bundle add detected");

  sync_store_align_reset(m->rowid);
  sync_store_align();

  // Reschedule rhizome_sync_announce to be called at least within configured interval.
  sync_announce_reschedule(config.rhizome.advertise.interval);
}


/// Trigger on_bundle_add() by bundle_add.
DEFINE_TRIGGER(bundle_add, rhizome_sync_on_bundle_add);


/** Process neighbour change trigger.
 *
 * Reset store synchronization status to start announcements again.
 *
 * @param neighbour neighbour
 * @param found 1 on new neighbour found, 0 on neighbour lost.
 * @param count Number of neighbours.
 */
static void rhizome_sync_on_neighbour_change(struct subscriber *neighbour, uint8_t found, unsigned count)
{
  DEBUGF(rhizome_sync, "Neighbour change detected, %d neigbours now.", (int)count);

  rhizome_sync_keys_on_neighbour_change(neighbour, found, count);

  if (found) {
    // We have a new neighbour.
    // Force reset of store synchronisation status.
    sync_store_align_reset(INVALID_TOKEN);

    // Reschedule rhizome_sync_announce to be called at least within configured interval.
    sync_announce_reschedule(config.rhizome.advertise.interval);
  }
}


/// Trigger on_neighbour_change() by nbr_change.
DEFINE_TRIGGER(nbr_change, rhizome_sync_on_neighbour_change);


/** Provide html output on rhizome synchronisation status of a subscribers.
 */
void rhizome_sync_status_html(struct strbuf *b, struct subscriber *subscriber)
{
  rhizome_sync_bars_subscriber_status_html(b, subscriber);
}


/** Provide debug output on rhizome synchronisation status of all subscribers.
 */
void rhizome_sync_status()
{
  // status of subscribers using rhizome_sync_bars.
  rhizome_sync_bars_status();
}


/** @} rhizome-sync */

/** @} rhizome */
