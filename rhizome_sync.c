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

#define MSG_TYPE_BARS 0
#define MSG_TYPE_REQ 1

#define MAX_TRIES 10
#define CACHE_BARS 60
#define MAX_OLD_BARS 40
#define BARS_PER_RESPONSE ((int)400/RHIZOME_BAR_BYTES)

#define HEAD_FLAG INT64_MAX

struct bar_entry
{
  rhizome_bar_t bar;
  unsigned tries;
  time_ms_t next_request;
};

struct rhizome_sync
{
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
  // a short list of BAR's we are interested in from the last parsed message
  struct bar_entry *bars;
  // how many bars are we interested in?
  int bar_count;
};

static uint64_t max_token=0;

DEFINE_ALARM(rhizome_sync_announce);

void rhizome_sync_status_html(struct strbuf *b, struct subscriber *subscriber)
{
  if (!subscriber->sync_state)
    return;
  struct rhizome_sync *state=subscriber->sync_state;
  strbuf_sprintf(b, "Seen %u BARs [%"PRId64" to %"PRId64" of %"PRId64"], %d interesting, %d skipped<br>",
    state->bars_seen,
    state->sync_start,
    state->sync_end,
    state->highest_seen,
    state->bar_count,
    state->bars_skipped);
}

static int sync_status(struct subscriber *subscriber, void *UNUSED(context))
{
  if (!subscriber->sync_state)
    return 0;
  struct rhizome_sync *state=subscriber->sync_state;
  DEBUGF(rhizome_sync, "%s seen %u BARs [%"PRId64" to %"PRId64" of %"PRId64"], %d interesting, %d skipped",
    alloca_tohex_sid_t(subscriber->sid),
    state->bars_seen,
    state->sync_start,
    state->sync_end,
    state->highest_seen,
    state->bar_count,
    state->bars_skipped);
  return 0;
}

void rhizome_sync_status()
{
  enum_subscribers(NULL, sync_status, NULL);
}

static void rhizome_sync_request(struct subscriber *subscriber, uint64_t token, unsigned char forwards)
{
  struct internal_mdp_header header;
  bzero(&header, sizeof header);
  
  header.source = get_my_subscriber();
  header.source_port = MDP_PORT_RHIZOME_SYNC;
  header.destination = subscriber;
  header.destination_port = MDP_PORT_RHIZOME_SYNC;
  header.qos = OQ_OPPORTUNISTIC;
  
  struct overlay_buffer *b = ob_new();
  ob_append_byte(b, MSG_TYPE_REQ);
  ob_append_byte(b, forwards);
  ob_append_packed_ui64(b, token);

  DEBUGF(rhizome_sync, "Sending request to %s for BARs from %"PRIu64" %s", alloca_tohex_sid_t(subscriber->sid), token, forwards?"forwards":"backwards");
    
  ob_flip(b);
  overlay_send_frame(&header, b);
  ob_free(b);
}

static void rhizome_sync_send_requests(struct subscriber *subscriber, struct rhizome_sync *state)
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
      header.source = get_my_subscriber();
      header.source_port = MDP_PORT_RHIZOME_RESPONSE;
      header.destination = subscriber;
      header.destination_port = MDP_PORT_RHIZOME_MANIFEST_REQUEST;
      header.qos = OQ_OPPORTUNISTIC;
      payload = ob_new();
      ob_limitsize(payload, MDP_MTU);
    }

    if (ob_remaining(payload)<RHIZOME_BAR_BYTES)
      break;
      
    DEBUGF(rhizome_sync, "Requesting manifest for BAR %s", alloca_tohex_rhizome_bar_t(&state->bars[i].bar));
      
    ob_append_bytes(payload, state->bars[i].bar.binary, RHIZOME_BAR_BYTES);
    
    state->bars[i].tries--;
    state->bars[i].next_request = now+5000;
    if (!state->bars[i].tries){
      // remove this BAR and shift the last BAR down to this position if required.
      DEBUGF(rhizome_sync, "Giving up on fetching BAR %s", alloca_tohex_rhizome_bar_t(&state->bars[i].bar));
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
      rhizome_sync_request(subscriber, state->sync_end, 1);
    }else if(state->sync_start >0){
      if (state->bar_count < MAX_OLD_BARS)
	rhizome_sync_request(subscriber, state->sync_start, 0);
    }else if(!state->sync_complete){
      state->sync_complete = 1;
      state->completed = gettime_ms();
      DEBUGF(rhizome_sync, "BAR sync with %s complete", alloca_tohex_sid_t(subscriber->sid));
    }
    state->next_request = now+5000;
  }
}

static int sync_bundle_inserted(struct subscriber *subscriber, void *context)
{
  const rhizome_bar_t *bar = context;
  if (!subscriber->sync_state)
    return 0;

  const unsigned char *id = rhizome_bar_prefix(bar);
  uint64_t version = rhizome_bar_version(bar);

  struct rhizome_sync *state = subscriber->sync_state;
  int i;
  for (i=state->bar_count -1;i>=0;i--){
    rhizome_bar_t *this_bar = &state->bars[i].bar;
    unsigned char *this_id = rhizome_bar_prefix(this_bar);
    uint64_t this_version = rhizome_bar_version(this_bar);
    if (memcmp(this_id, id, RHIZOME_BAR_PREFIX_BYTES)==0 && version >= this_version){
      // remove this BAR and shift the last BAR down to this position if required.
      DEBUGF(rhizome_sync, "Removing BAR %s from queue", alloca_tohex_rhizome_bar_t(this_bar));
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

static void annouce_cli_bundle_add(uint64_t row_id)
{
  if (row_id<=max_token)
    return;
    
  if (max_token!=0){
    sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
    sqlite3_stmt *statement = sqlite_prepare_bind(&retry, 
      "SELECT manifest FROM manifests WHERE rowid > ? AND rowid <= ? ORDER BY rowid ASC;",
      INT64, max_token, INT64, row_id, END);
    while (sqlite_step_retry(&retry, statement) == SQLITE_ROW) {
      const void *blob = sqlite3_column_blob(statement, 0);
      size_t blob_length = sqlite3_column_bytes(statement, 0);
      rhizome_manifest *m = rhizome_new_manifest();
      if (m) {
	memcpy(m->manifestdata, blob, blob_length);
	m->manifest_all_bytes = blob_length;
	if (   rhizome_manifest_parse(m) != -1
	    && rhizome_manifest_validate(m)
	    && rhizome_manifest_verify(m)
	) {
	  assert(m->finalised);
	  CALL_TRIGGER(bundle_add, m);
	}
	rhizome_manifest_free(m);
      }
    }
    sqlite3_finalize(statement);
  }
  
  max_token = row_id;
}

static void rhizome_sync_bundle_inserted(rhizome_manifest *m)
{
  annouce_cli_bundle_add(m->rowid - 1);
  if (m->rowid > max_token)
    max_token = m->rowid;
  
  rhizome_bar_t bar;
  rhizome_manifest_to_bar(m, &bar);
  enum_subscribers(NULL, sync_bundle_inserted, (void *)&bar);
  
  if (link_has_neighbours()){
    struct sched_ent *alarm = &ALARM_STRUCT(rhizome_sync_announce);
    time_ms_t now = gettime_ms();
    if (alarm->alarm > now+50)
      RESCHEDULE(alarm, now+50, now+50, TIME_MS_NEVER_WILL);
  }
}

DEFINE_TRIGGER(bundle_add, rhizome_sync_bundle_inserted);

static int sync_cache_bar(struct rhizome_sync *state, const rhizome_bar_t *bar, uint64_t token)
{
  int ret=0;
  if (state->bar_count>=CACHE_BARS)
    return 0;
  // check the database before adding the BAR to the list
  if (token!=0 && rhizome_is_bar_interesting(bar)!=0){
    if (!state->bars){
      state->bars = emalloc(sizeof(struct bar_entry) * CACHE_BARS);
      if (!state->bars)
	return -1;
    }
    
    DEBUGF(rhizome_sync, "Remembering BAR %s", alloca_tohex_rhizome_bar_t(bar));
    
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

static void sync_process_bar_list(struct subscriber *subscriber, struct rhizome_sync *state, struct overlay_buffer *b)
{
  // find all interesting BARs in the payload and extend our sync range

  const rhizome_bar_t *bars[BARS_PER_RESPONSE];
  uint64_t bar_tokens[BARS_PER_RESPONSE];
  int bar_count = 0;
  int has_before=0, has_after=0;
  int mid_point = -1;
  time_ms_t now = gettime_ms();
  
  if (now - state->start_time > (60*60*1000)){
    // restart rhizome sync every hour, no matter what state it is in
    bzero(state, sizeof(struct rhizome_sync));
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
    DEBUGF(rhizome_sync, "Starting BAR sync with %s", alloca_tohex_sid_t(subscriber->sid));
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
      int r=sync_cache_bar(state, bars[i], bar_tokens[i]);
      if (r==-1)
	return;
      if (r==1)
	added=1;
    }
    for (i=mid_point -1; i>=0; i--){
      if (state->bar_count >= MAX_OLD_BARS)
	break;
      int r=sync_cache_bar(state, bars[i], bar_tokens[i]);
      if (r==-1)
	return;
      if (r==1)
	added=1;
    }
    DEBUGF(rhizome_sync, "Synced %"PRIu64" - %"PRIu64" with %s", state->sync_start, state->sync_end, alloca_tohex_sid_t(subscriber->sid));
    if (added)
      state->next_request = gettime_ms();
  }

}

static void append_response(struct overlay_buffer *b, uint64_t token, const unsigned char *bar)
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

static void sync_send_response(struct subscriber *dest, int forwards, uint64_t token, int max_count)
{
  IN();
    
  if (max_count == 0 || max_count > BARS_PER_RESPONSE)
    max_count = BARS_PER_RESPONSE;
    
  struct internal_mdp_header header;
  bzero(&header, sizeof header);
  
  header.source = get_my_subscriber();
  header.source_port = MDP_PORT_RHIZOME_SYNC;
  header.destination = dest;
  header.destination_port = MDP_PORT_RHIZOME_SYNC;
  header.qos = OQ_OPPORTUNISTIC;
  
  if (!dest){
    header.crypt_flags = (MDP_FLAG_NO_CRYPT|MDP_FLAG_NO_SIGN);
    header.ttl = 1;
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

  sqlite3_bind_int64(statement, 1, token);
  int count=0;
  uint64_t last=0;

  struct overlay_buffer *b = ob_new();
  ob_limitsize(b, MDP_MTU);
  ob_append_byte(b, MSG_TYPE_BARS);
  ob_checkpoint(b);

  while(sqlite_step_retry(&retry, statement)==SQLITE_ROW){
    uint64_t rowid = sqlite3_column_int64(statement, 0);
    const unsigned char *bar = sqlite3_column_blob(statement, 1);
    size_t bar_size = sqlite3_column_bytes(statement, 1);

    if (bar_size != RHIZOME_BAR_BYTES)
      continue;
      
    if (count < max_count){
      // make sure we include the exact rowid that was requested, even if we just deleted / replaced the manifest
      if (count==0 && rowid!=token){
        if (token!=HEAD_FLAG){
	  ob_checkpoint(b);
          append_response(b, token, NULL);
	  if (ob_overrun(b))
	    ob_rewind(b);
	  else {
            count++;
            last = token;
	  }
        }else
          token = rowid;
      }
      ob_checkpoint(b);
      append_response(b, rowid, bar);
      if (ob_overrun(b))
	ob_rewind(b);
      else {
        last = rowid;
        count++;
      }
    }
    if (count >= max_count && rowid <= max_token)
      break;
  }

  sqlite3_finalize(statement);

  if (token != HEAD_FLAG && token > max_token){
    // report bundles added by cli
    annouce_cli_bundle_add(token);
  }

  // send a zero lower bound if we reached the end of our manifest list
  if (count && count < max_count && !forwards){
    ob_checkpoint(b);
    append_response(b, 0, NULL);
    if (ob_overrun(b))
      ob_rewind(b);
    else {
      last = 0;
      count++;
    }
  }

  if (count){
    DEBUGF(rhizome_sync, "Sending %d BARs from %"PRIu64" to %"PRIu64, count, token, last);
    ob_flip(b);
    overlay_send_frame(&header, b);
  }
  ob_free(b);
  OUT();
}

void rhizome_sync_announce(struct sched_ent *alarm)
{
  if (!is_rhizome_advertise_enabled())
    return;
  int (*oldfunc)() = sqlite_set_tracefunc(is_debug_rhizome_ads);
  sync_send_response(NULL, 0, HEAD_FLAG, 5);
  sqlite_set_tracefunc(oldfunc);
  alarm->alarm = gettime_ms()+config.rhizome.advertise.interval;
  alarm->deadline = alarm->alarm+10000;
  schedule(alarm);
}

static void neighbour_changed(struct subscriber *UNUSED(neighbour), uint8_t UNUSED(found), unsigned count)
{
  struct sched_ent *alarm = &ALARM_STRUCT(rhizome_sync_announce);
  
  if (count>0){
    time_ms_t now = gettime_ms();
    if (alarm->alarm == TIME_MS_NEVER_WILL)
      RESCHEDULE(alarm, now+50, now+50, TIME_MS_NEVER_WILL);
  }else{
    RESCHEDULE(alarm, TIME_MS_NEVER_WILL, TIME_MS_NEVER_WILL, TIME_MS_NEVER_WILL);
  }
}
DEFINE_TRIGGER(nbr_change, neighbour_changed);

DEFINE_BINDING(MDP_PORT_RHIZOME_SYNC, overlay_mdp_service_rhizome_sync);
static int overlay_mdp_service_rhizome_sync(struct internal_mdp_header *header, struct overlay_buffer *payload)
{
  if (!config.rhizome.enable || !rhizome_db)
    return 0;
    
  struct rhizome_sync *state = header->source->sync_state;
  
  if (header->source->sync_version>0){
    if (state){
      if (state->bars)
	free(state->bars);
      free(state);
      header->source->sync_state=NULL;
    }
    return 0;
  }
  
  if (!state){
    state = header->source->sync_state = emalloc_zero(sizeof(struct rhizome_sync));
    state->start_time=gettime_ms();
  }
  int type = ob_get(payload);
  switch (type){
    case MSG_TYPE_BARS:
      if (config.rhizome.fetch)
	sync_process_bar_list(header->source, state, payload);
      break;
    case MSG_TYPE_REQ:
      {
        int forwards = ob_get(payload);
        uint64_t token = ob_get_packed_ui64(payload);
        sync_send_response(header->source, forwards, token, 0);
      }
      break;
  }
  if (config.rhizome.fetch)
    rhizome_sync_send_requests(header->source, state);
  return 0;
}

