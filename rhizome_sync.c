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
#include "conf.h"

#define MSG_TYPE_BARS 0
#define MSG_TYPE_REQ 1

#define CACHE_BARS 60
#define MAX_OLD_BARS 40
#define BARS_PER_RESPONSE ((int)400/RHIZOME_BAR_BYTES)

#define HEAD_FLAG INT64_MAX

struct bar_entry
{
  unsigned char bar[RHIZOME_BAR_BYTES];
  time_ms_t next_request;
};

struct rhizome_sync
{
  // window of BAR's we have synced
  uint64_t sync_start;
  uint64_t sync_end;
  uint64_t highest_seen;
  unsigned char sync_complete;
  uint64_t bars_seen;
  time_ms_t start_time;
  time_ms_t completed;
  time_ms_t next_request;
  time_ms_t last_extended;
  time_ms_t last_response;
  time_ms_t last_new_bundle;
  // a short list of BAR's we are interested in from the last parsed message
  struct bar_entry bars[CACHE_BARS];
  // how many bars are we interested in?
  int bar_count;
};

void rhizome_sync_status_html(struct strbuf *b, struct subscriber *subscriber)
{
  if (!subscriber->sync_state)
    return;
  struct rhizome_sync *state=subscriber->sync_state;
  strbuf_sprintf(b, "Seen %"PRId64" BARs [%"PRId64" to %"PRId64" of %"PRId64"], %d interesting<br>",
    state->bars_seen,
    state->sync_start,
    state->sync_end,
    state->highest_seen,
    state->bar_count);
}

static void rhizome_sync_request(struct subscriber *subscriber, uint64_t token, unsigned char forwards)
{
  overlay_mdp_frame mdp;
  bzero(&mdp,sizeof(mdp));

  mdp.out.src.sid = my_subscriber->sid;
  mdp.out.src.port=MDP_PORT_RHIZOME_SYNC;
  mdp.out.dst.sid = subscriber->sid;
  mdp.out.dst.port=MDP_PORT_RHIZOME_SYNC;
  mdp.packetTypeAndFlags=MDP_TX;
  mdp.out.queue=OQ_OPPORTUNISTIC;

  struct overlay_buffer *b = ob_static(mdp.out.payload, sizeof(mdp.out.payload));
  ob_append_byte(b, MSG_TYPE_REQ);
  ob_append_byte(b, forwards);
  ob_append_packed_ui64(b, token);

  mdp.out.payload_length = ob_position(b);
  if (config.debug.rhizome)
    DEBUGF("Sending request to %s for BARs from %"PRIu64" %s", alloca_tohex_sid_t(subscriber->sid), token, forwards?"forwards":"backwards");
  overlay_mdp_dispatch(&mdp, NULL);
  ob_free(b);
}

static void rhizome_sync_send_requests(struct subscriber *subscriber, struct rhizome_sync *state)
{
  int i, requests=0;
  time_ms_t now = gettime_ms();

  // send requests for manifests that we have room to fetch
  overlay_mdp_frame mdp;
  bzero(&mdp,sizeof(mdp));

  for (i=0;i < state->bar_count;i++){
    if (state->bars[i].next_request > now)
      continue;

    unsigned char *prefix = &state->bars[i].bar[RHIZOME_BAR_PREFIX_OFFSET];

    if (rhizome_ignore_manifest_check(prefix, RHIZOME_BAR_PREFIX_BYTES))
      continue;

    // do we have free space now in the appropriate fetch queue?
    unsigned char log2_size = state->bars[i].bar[RHIZOME_BAR_FILESIZE_OFFSET];
    if (log2_size!=0xFF && rhizome_fetch_has_queue_space(log2_size)!=1)
      continue;

    uint64_t version = rhizome_bar_version(state->bars[i].bar);
    // are we already fetching this bundle [or later]?
    rhizome_manifest *m=rhizome_fetch_search(prefix, RHIZOME_BAR_PREFIX_BYTES);
    if (m && m->version >= version)
      continue;

    if (mdp.out.payload_length==0){
      mdp.out.src.sid = my_subscriber->sid;
      mdp.out.src.port=MDP_PORT_RHIZOME_RESPONSE;
      mdp.out.dst.sid = subscriber->sid;
      mdp.out.dst.port=MDP_PORT_RHIZOME_MANIFEST_REQUEST;
      mdp.packetTypeAndFlags=MDP_TX;

      mdp.out.queue=OQ_OPPORTUNISTIC;
    }
    if (mdp.out.payload_length + RHIZOME_BAR_BYTES>MDP_MTU)
      break;
    if (config.debug.rhizome)
      DEBUGF("Requesting manifest for BAR %s", alloca_tohex(state->bars[i].bar, RHIZOME_BAR_BYTES));
    bcopy(state->bars[i].bar, &mdp.out.payload[mdp.out.payload_length], RHIZOME_BAR_BYTES);
    mdp.out.payload_length+=RHIZOME_BAR_BYTES;
    state->bars[i].next_request = now+1000;
    requests++;
    if (requests>=BARS_PER_RESPONSE)
      break;
  }
  if (mdp.out.payload_length!=0)
    overlay_mdp_dispatch(&mdp, NULL);

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
      if (config.debug.rhizome)
        DEBUGF("BAR sync with %s complete", alloca_tohex_sid_t(subscriber->sid));
    }
    state->next_request = now+5000;
  }
}

static int sync_bundle_inserted(struct subscriber *subscriber, void *context)
{
  const unsigned char *bar = context;
  if (!subscriber->sync_state)
    return 0;

  const unsigned char *id = &bar[RHIZOME_BAR_PREFIX_OFFSET];
  uint64_t version = rhizome_bar_version(bar);

  struct rhizome_sync *state = subscriber->sync_state;
  int i;
  for (i=state->bar_count -1;i>=0;i--){
    unsigned char *this_bar = state->bars[i].bar;
    unsigned char *this_id = &this_bar[RHIZOME_BAR_PREFIX_OFFSET];
    uint64_t this_version = rhizome_bar_version(this_bar);
    if (memcmp(this_id, id, RHIZOME_BAR_PREFIX_BYTES)==0 && version >= this_version){
      // remove this BAR and shift the last BAR down to this position if required.
      if (config.debug.rhizome)
        DEBUGF("Removing BAR %s from queue", alloca_tohex(this_bar, RHIZOME_BAR_BYTES));
      state->bar_count --;
      if (i<state->bar_count){
        state->bars[i] = state->bars[state->bar_count];
      }
    }
  }

  return 0;
}

int rhizome_sync_bundle_inserted(const unsigned char *bar)
{
  enum_subscribers(NULL, sync_bundle_inserted, (void *)bar);
  return 0;
}

static int sync_cache_bar(struct rhizome_sync *state, unsigned char *bar, uint64_t token)
{
  int ret=0;
  if (state->bar_count>=CACHE_BARS)
    return 0;
  // check the database before adding the BAR to the list
  if (token!=0 && rhizome_is_bar_interesting(bar)!=0){
    bcopy(bar, state->bars[state->bar_count].bar, RHIZOME_BAR_BYTES);
    state->bars[state->bar_count].next_request = gettime_ms();
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

  unsigned char *bars[BARS_PER_RESPONSE];
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
    bars[bar_count]=ob_get_bytes_ptr(b, RHIZOME_BAR_BYTES);
    if (!bars[bar_count])
      break;
    // allow the sender to identify the edge of the range this packet represents
    // even if there is no manifest that falls exactly on the boundary (eg deleted manifest or zero lower bound)
    if (is_all_matching(bars[bar_count], RHIZOME_BAR_BYTES, 0))
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
    if (config.debug.rhizome)
      DEBUGF("Starting BAR sync with %s", alloca_tohex_sid_t(subscriber->sid));
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
      if (sync_cache_bar(state, bars[i], bar_tokens[i]))
	added=1;
    }
    for (i=mid_point -1; i>=0; i--){
      if (state->bar_count >= MAX_OLD_BARS)
	break;
      if (sync_cache_bar(state, bars[i], bar_tokens[i]))
	added=1;
    }
    if (config.debug.rhizome)
      DEBUGF("Synced %"PRIu64" - %"PRIu64" with %s", state->sync_start, state->sync_end, alloca_tohex_sid_t(subscriber->sid));
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

static uint64_t max_token=0;
static void sync_send_response(struct subscriber *dest, int forwards, uint64_t token, int max_count)
{
  IN();
  if (max_count == 0 || max_count > BARS_PER_RESPONSE)
    max_count = BARS_PER_RESPONSE;
    
  overlay_mdp_frame mdp;
  bzero(&mdp,sizeof(mdp));

  mdp.out.src.sid = my_subscriber->sid;
  mdp.out.src.port=MDP_PORT_RHIZOME_SYNC;
  mdp.out.dst.port=MDP_PORT_RHIZOME_SYNC;
  mdp.packetTypeAndFlags=MDP_TX;
  mdp.out.queue=OQ_OPPORTUNISTIC;

  if (dest){
    mdp.out.dst.sid = dest->sid;
  }else{
    mdp.out.dst.sid = SID_BROADCAST;
    mdp.packetTypeAndFlags|=(MDP_NOCRYPT|MDP_NOSIGN);
  }

  if (!dest)
    mdp.out.ttl=1;

  struct overlay_buffer *b = ob_static(mdp.out.payload, sizeof(mdp.out.payload));
  ob_append_byte(b, MSG_TYPE_BARS);
  ob_checkpoint(b);

  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  sqlite3_stmt *statement;
  if (forwards){
    statement = sqlite_prepare(&retry, "SELECT rowid, bar FROM manifests WHERE rowid >= ? ORDER BY rowid ASC");
  }else{
    statement = sqlite_prepare(&retry, "SELECT rowid, bar FROM manifests WHERE rowid <= ? ORDER BY rowid DESC");
  }

  if (!statement)
    return;

  sqlite3_bind_int64(statement, 1, token);
  int count=0;
  uint64_t last=0;

  while(sqlite_step_retry(&retry, statement)==SQLITE_ROW){
    uint64_t rowid = sqlite3_column_int64(statement, 0);
    const unsigned char *bar = sqlite3_column_blob(statement, 1);
    size_t bar_size = sqlite3_column_bytes(statement, 1);

    if (bar_size != RHIZOME_BAR_BYTES)
      continue;

    if (rowid>max_token){
      // a new bundle has been imported
      if (!rhizome_is_bar_interesting(bar))
	rhizome_sync_bundle_inserted(bar);
    }

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

  if (token != HEAD_FLAG && token > max_token)
    max_token = token;

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

  sqlite3_finalize(statement);

  if (count){
    mdp.out.payload_length = ob_position(b);
    if (config.debug.rhizome_ads)
      DEBUGF("Sending %d BARs from %"PRIu64" to %"PRIu64, count, token, last);
    overlay_mdp_dispatch(&mdp, NULL);
  }
  ob_free(b);
  OUT();
}

int rhizome_sync_announce()
{
  int (*oldfunc)() = sqlite_set_tracefunc(is_debug_rhizome_ads);
  sync_send_response(NULL, 0, HEAD_FLAG, 5);
  sqlite_set_tracefunc(oldfunc);
  return 0;
}

int overlay_mdp_service_rhizome_sync(struct overlay_frame *frame, overlay_mdp_frame *mdp)
{
  if (!frame)
    return 0;
  struct rhizome_sync *state = frame->source->sync_state;
  if (!state){
    state = frame->source->sync_state = emalloc_zero(sizeof(struct rhizome_sync));
    state->start_time=gettime_ms();
  }
  struct overlay_buffer *b = ob_static(mdp->out.payload, sizeof(mdp->out.payload));
  ob_limitsize(b, mdp->out.payload_length);
  int type = ob_get(b);
  switch (type){
    case MSG_TYPE_BARS:
      sync_process_bar_list(frame->source, state, b);
      break;
    case MSG_TYPE_REQ:
      {
        int forwards = ob_get(b);
        uint64_t token = ob_get_packed_ui64(b);
        sync_send_response(frame->source, forwards, token, 0);
      }
      break;
  }
  ob_free(b);
  rhizome_sync_send_requests(frame->source, state);
  return 0;
}

