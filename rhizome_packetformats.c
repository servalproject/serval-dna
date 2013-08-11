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

#include "serval.h"
#include "conf.h"
#include "rhizome.h"
#include <assert.h>
#include "overlay_buffer.h"
#include "overlay_address.h"
#include "overlay_packet.h"
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "parallel.h"

/* Android doesn't have log2(), and we don't really need to do floating point
   math to work out how big a file is.
 */
int log2ll(uint64_t x)
{
  unsigned char lookup[16]={0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4};
  int v=-1;
  if (x>0xffffffff) { v+=32; x=x>>32LL; }
  if (x>0xffff)     { v+=16; x=x>>16LL; }
  if (x>0xff)       { v+= 8; x=x>> 8LL; }
  if (x>0xf)        { v+= 4; x=x>> 4LL; }
  v+=lookup[x&0xf];
  return v;
}


int rhizome_manifest_to_bar(rhizome_manifest *m,unsigned char *bar)
{
  IN();
  /* BAR = Bundle Advertisement Record.
     Basically a 32byte precis of a given manifest, that includes version, time-to-live
     and geographic bounding box information that is used to help manage flooding of
     bundles.

     Old BAR format (no longer used):

     64 bits - manifest ID prefix.
     56 bits - low 56 bits of version number.
     8 bits  - TTL of bundle in hops.
     64 bits - length of associated file.
     16 bits - min latitude (-90 - +90).
     16 bits - min longitude (-180 - +180).
     16 bits - max latitude (-90 - +90).
     16 bits - max longitude (-180 - +180).

     New BAR format with longer manifest ID prefix:

     120 bits - manifest ID prefix.
     8 bits - log2(length) of associated file.
     56 bits - low 56 bits of version number.
     16 bits - min latitude (-90 - +90).
     16 bits - min longitude (-180 - +180).
     16 bits - max latitude (-90 - +90).
     16 bits - max longitude (-180 - +180).
     8 bits  - TTL of bundle in hops (0xff = unlimited distribution)

 */

  if (!m) { RETURN(WHY("null manifest passed in")); }

  int i;

  /* Manifest prefix */
  for(i=0;i<RHIZOME_BAR_PREFIX_BYTES;i++) 
    bar[RHIZOME_BAR_PREFIX_OFFSET+i]=m->cryptoSignPublic[i];
  /* file length */
  bar[RHIZOME_BAR_FILESIZE_OFFSET]=log2ll(m->fileLength);
  /* Version */
  for(i=0;i<7;i++) bar[RHIZOME_BAR_VERSION_OFFSET+6-i]=(m->version>>(8*i))&0xff;

  /* geo bounding box */
  double minLat=rhizome_manifest_get_double(m,"min_lat",-90);
  if (minLat<-90) minLat=-90; if (minLat>90) minLat=90;
  double minLong=rhizome_manifest_get_double(m,"min_long",-180);
  if (minLong<-180) minLong=-180; if (minLong>180) minLong=180;
  double maxLat=rhizome_manifest_get_double(m,"max_lat",+90);
  if (maxLat<-90) maxLat=-90; if (maxLat>90) maxLat=90;
  double maxLong=rhizome_manifest_get_double(m,"max_long",+180);
  if (maxLong<-180) maxLong=-180; if (maxLong>180) maxLong=180;  
  unsigned short v;
  int o=RHIZOME_BAR_GEOBOX_OFFSET;
  v=(minLat+90)*(65535/180); bar[o++]=(v>>8)&0xff; bar[o++]=(v>>0)&0xff;
  v=(minLong+180)*(65535/360); bar[o++]=(v>>8)&0xff; bar[o++]=(v>>0)&0xff;
  v=(maxLat+90)*(65535/180); bar[o++]=(v>>8)&0xff; bar[o++]=(v>>0)&0xff;
  v=(maxLong+180)*(65535/360); bar[o++]=(v>>8)&0xff; bar[o++]=(v>>0)&0xff;

  /* TTL */
  if (m->ttl>0) bar[RHIZOME_BAR_TTL_OFFSET]=m->ttl-1; 
  else bar[RHIZOME_BAR_TTL_OFFSET]=0;
  
  RETURN(0);
  OUT();
}

int64_t rhizome_bar_version(const unsigned char *bar)
{
  int64_t version=0;
  int i;
  for(i=0;i<7;i++) 
    version|=((int64_t)(bar[RHIZOME_BAR_VERSION_OFFSET+6-i]))<<(8LL*i);
  return version;
}

/* This function only displays the first 8 bytes, and should not be used
   for comparison. */
uint64_t rhizome_bar_bidprefix_ll(unsigned char *bar)
{
  uint64_t bidprefix=0;
  int i;
  for(i=0;i<8;i++) 
    bidprefix|=((uint64_t)bar[RHIZOME_BAR_PREFIX_OFFSET+7-i])<<(8*i);
  return bidprefix;
}

static int append_bars(struct overlay_buffer *e, sqlite_retry_state *retry, const char *sql, int64_t *last_rowid){
  int count=0;
  
  sqlite3_stmt *statement=sqlite_prepare(retry, sql, *last_rowid);
  
  while(sqlite_step_retry(retry, statement) == SQLITE_ROW) {
    count++;
    if (sqlite3_column_type(statement, 0)!=SQLITE_BLOB)
      continue;
    
    const void *data = sqlite3_column_blob(statement, 0);
    int blob_bytes = sqlite3_column_bytes(statement, 0);
    int64_t rowid = sqlite3_column_int64(statement, 1);
    
    if (blob_bytes!=RHIZOME_BAR_BYTES) {
      if (config.debug.rhizome_ads)
	DEBUG("Found a BAR that is the wrong size - ignoring");
      continue;
    }
    
    if (ob_append_bytes(e, (unsigned char *)data, blob_bytes)){
      // out of room
      count--;
      break;
    }
    
    *last_rowid=rowid;
  }
  
  if (statement)
    sqlite3_finalize(statement);
  
  return count;
}

/* Periodically queue BAR advertisements
 Always advertise the most recent 3 manifests in the table, cycle through the rest of the table, adding 17 BAR's at a time
 */
int64_t bundles_available=0;
void overlay_rhizome_advertise(struct sched_ent *alarm){
  ASSERT_THREAD(rhizome_thread);
  bundles_available=0;
  static int64_t bundle_last_rowid=INT64_MAX;
  
  if (!is_rhizome_advertise_enabled())
    return;
  
  // TODO deprecate the below announcement method and move this alarm to rhizome_sync.c
  rhizome_sync_announce();

  int (*oldfunc)() = sqlite_set_tracefunc(is_debug_rhizome_ads);
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;

  /* Get number of bundles available */
  if (sqlite_exec_int64_retry(&retry, &bundles_available, "SELECT COUNT(BAR) FROM MANIFESTS;") != 1){
    WHY("Could not count BARs for advertisement");
    goto end;
  }
  
  if (bundles_available<1)
    goto end;
  
  struct overlay_buffer *payload = ob_new();
  if (!payload) OUT_OF_MEMORY;
  ob_limitsize(payload, 800);
  ob_append_byte(payload, 2);
  ob_append_ui16(payload, rhizome_http_server_port);
  
  int64_t rowid=0;
  int count = append_bars(payload, &retry,
			  "SELECT BAR,ROWID FROM MANIFESTS ORDER BY ROWID DESC LIMIT 3", 
			  &rowid);
  
  if (count>=3){
    if (bundle_last_rowid>rowid || bundle_last_rowid<=0)
      bundle_last_rowid=rowid;
    
    count = append_bars(payload, &retry,
			"SELECT BAR,ROWID FROM MANIFESTS WHERE ROWID < %lld ORDER BY ROWID DESC LIMIT 17", 
			&bundle_last_rowid);
    if (count<17)
      bundle_last_rowid=INT64_MAX;
  }
  
  post_runnable(overlay_payload_enqueue_alarm, payload, &main_fdqueue);
end:
  sqlite_set_tracefunc(oldfunc);
  alarm->alarm = gettime_ms()+config.rhizome.advertise.interval;
  alarm->deadline = alarm->alarm+10000;
  schedule(alarm);
}

#define HAS_PORT (1<<1)
#define HAS_MANIFESTS (1<<0)

void rhizome_advertise_manifest_alarm(struct sched_ent *alarm) {
  ASSERT_THREAD(main_thread);
  struct ram_arg *arg = alarm->context;
  free(alarm);
  rhizome_advertise_manifest(arg->manifest_all_bytes, arg->manifestdata);
  free(arg);
}

/* Queue an advertisment for a single manifest */
int rhizome_advertise_manifest(int manifest_all_bytes,
                               unsigned char *manifestdata) {
  ASSERT_THREAD(main_thread);
  struct overlay_frame *frame = malloc(sizeof(struct overlay_frame));
  bzero(frame,sizeof(struct overlay_frame));
  frame->type = OF_TYPE_RHIZOME_ADVERT;
  frame->source = my_subscriber;
  frame->ttl = 1;
  frame->queue = OQ_OPPORTUNISTIC;
  frame->payload = ob_new();
  ob_limitsize(frame->payload, 800);
  
  if (ob_append_byte(frame->payload, HAS_PORT|HAS_MANIFESTS)) goto error;
  if (ob_append_ui16(frame->payload, is_rhizome_http_enabled()?rhizome_http_server_port:0)) goto error;
  if (ob_append_ui16(frame->payload, manifest_all_bytes)) goto error;
  if (ob_append_bytes(frame->payload, manifestdata, manifest_all_bytes)) goto error;
  ob_append_byte(frame->payload, 0xFF);
  if (overlay_payload_enqueue(frame)) goto error;
  return 0;
  
error:
  op_free(frame);
  return -1;
}

time_ms_t lookup_time=0;

void overlay_rhizome_saw_advertisements_alarm(struct sched_ent *alarm) {
  ASSERT_THREAD(rhizome_thread);
  struct orsa_arg *arg = alarm->context;
  free(alarm);
  overlay_rhizome_saw_advertisements(arg->id, arg->payload, arg->src_sid,
                                     arg->src_reachable,
                                     arg->use_new_sync_protocol, arg->recvaddr,
                                     arg->now);
  free(arg->payload);
  free(arg);
}

int overlay_rhizome_saw_advertisements(int i, struct overlay_buffer *payload,
                                       unsigned char *src_sid,
                                       int src_reachable,
                                       int use_new_sync_protocol,
                                       struct sockaddr_in recvaddr,
                                       time_ms_t now)
{
  ASSERT_THREAD(rhizome_thread);
  IN();
  
  if (!(rhizome_db && config.rhizome.fetch)) 
    RETURN(0);
  
  int ad_frame_type = ob_get(payload);
  struct sockaddr_in httpaddr = recvaddr;
  httpaddr.sin_port = htons(RHIZOME_HTTP_PORT);
  int manifest_length;
  rhizome_manifest *m=NULL;

  int (*oldfunc)() = sqlite_set_tracefunc(is_debug_rhizome_ads);

  if (ad_frame_type & HAS_PORT){
    httpaddr.sin_port = htons(ob_get_ui16(payload));
  }
  
  if (ad_frame_type & HAS_MANIFESTS){
    /* Extract whole manifests */
    while (payload->position < payload->sizeLimit) {
      if (ob_getbyte(payload, payload->position) == 0xff) {
        payload->position++;
        break;
      }

      manifest_length=ob_get_ui16(payload);
      if (manifest_length==0) continue;
      
      unsigned char *data = ob_get_bytes_ptr(payload, manifest_length);
      if (!data) {
	WHYF("Illegal manifest length field in rhizome advertisement frame %d vs %d.", 
	     manifest_length, payload->sizeLimit - payload->position);
	break;
      }

      /* Read manifest without verifying signatures (which would waste lots of
	 energy, everytime we see a manifest that we already have).
	 In fact, it would be better here to do a really rough and ready parser
	 to get the id and version fields out, and avoid the memory copies that
	 otherwise happen. 
	 But we do need to make sure that at least one signature is there.
      */	
      m = rhizome_new_manifest();
      if (!m) {
	WHY("Out of manifests");
	goto next;
      }
      
      if (rhizome_read_manifest_file(m, (char *)data, manifest_length) == -1) {
	WHY("Error parsing manifest body");
	goto next;
      }
      
      char manifest_id_prefix[RHIZOME_MANIFEST_ID_STRLEN + 1];
      if (rhizome_manifest_get(m, "id", manifest_id_prefix, sizeof manifest_id_prefix) == NULL) {
	WHY("Manifest does not contain 'id' field");
	goto next;
      }

      /* trim manifest ID to a prefix for ease of debugging
	 (that is the only use of this */
      if (config.debug.rhizome_ads){
        manifest_id_prefix[8]=0;
	long long version = rhizome_manifest_get_ll(m, "version");
	DEBUGF("manifest id=%s* version=%lld", manifest_id_prefix, version);
      }

      /* Crude signature presence test */
      for(i=m->manifest_all_bytes-1;i>0;i--)
	if (!m->manifestdata[i]) {
	  /* A null in the middle says we have a signature */
	  break;
	}
      if (!i) {
	/* ignore the announcement, but don't ignore other people
	   offering the same manifest */
	if (config.debug.rhizome_ads)
	  DEBUG("Ignoring manifest announcment with no signature");
	goto next;
      }

      if (rhizome_ignore_manifest_check(m->cryptoSignPublic,
					crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES)){
	/* Ignoring manifest that has caused us problems recently */
	if (config.debug.rhizome_ads)
	  DEBUGF("Ignoring manifest with errors: %s*", manifest_id_prefix);
	goto next;
      }

      if (m->errors > 0){
	if (config.debug.rhizome_ads)
	  DEBUG("Unverified manifest has errors - so not processing any further.");
	/* Don't waste any time on this manifest in future attempts for at least
	     a minute. */
	rhizome_queue_ignore_manifest(m->cryptoSignPublic,
					crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES, 60000);
	goto next;
      }

      /* Manifest is okay, so see if it is worth storing */
      if (rhizome_manifest_version_cache_lookup(m)) {
	/* We already have this version or newer */
	if (config.debug.rhizome_ads)
	  DEBUG("We already have that manifest or newer.");
	goto next;
      }

      if (config.debug.rhizome_ads)
	DEBUG("Not seen before.");

      // start the fetch process!
      rhizome_suggest_queue_manifest_import(m, &httpaddr, src_sid);
      // the above function will free the manifest structure, make sure we don't free it again
      m=NULL;

next:
      if (m) {
	rhizome_manifest_free(m);
	m = NULL;
      }
    }
  }

  // if we're using the new sync protocol, ignore the rest of the packet
  if (use_new_sync_protocol)
    goto end;

  overlay_mdp_frame *mdp = calloc(1, sizeof(overlay_mdp_frame));
  if (!mdp) OUT_OF_MEMORY;

  // parse BAR's
  unsigned char *bars[50];
  int bar_count=0;
  while(ob_remaining(payload)>0 && bar_count<50){
    unsigned char *bar;
    bars[bar_count]=bar=ob_get_bytes_ptr(payload, RHIZOME_BAR_BYTES);
    if (!bar){
      WARNF("Expected whole BAR @%x (only %d bytes remain)", ob_position(payload), ob_remaining(payload));
      break;
    }

    // are we ignoring this manifest?
    if (rhizome_ignore_manifest_check(&bar[RHIZOME_BAR_PREFIX_OFFSET], RHIZOME_BAR_PREFIX_BYTES))
      continue;

    // do we have free space in a fetch queue?
    unsigned char log2_size = bar[RHIZOME_BAR_FILESIZE_OFFSET];
    if (log2_size!=0xFF && rhizome_fetch_has_queue_space(log2_size)!=1)
      continue;

    int64_t version = rhizome_bar_version(bar);
    // are we already fetching this bundle [or later]?
    rhizome_manifest *m=rhizome_fetch_search(&bar[RHIZOME_BAR_PREFIX_OFFSET], RHIZOME_BAR_PREFIX_BYTES);
    if (m && m->version >= version)
      continue;

    bar_count++;
  }

  // perform costly database lookups
  int index;
  int test_count=0;
  int max_tests = (lookup_time?(int)(40 / lookup_time):bar_count);
  if (max_tests<=0)
    max_tests=2;

  time_ms_t start_time = gettime_ms();

  for (index=0;index<bar_count;index++){
    if (test_count > max_tests || gettime_ms() - start_time >40)
      break;
    if (bar_count > max_tests && random()%bar_count >= max_tests)
      continue;
    test_count++;
    if (rhizome_is_bar_interesting(bars[index])==1){
      // add a request for the manifest
      if (mdp->out.payload_length == 0) {
        bcopy(my_subscriber->sid, mdp->out.src.sid,SID_SIZE);
        mdp->out.src.port = MDP_PORT_RHIZOME_RESPONSE;
        bcopy(src_sid, mdp->out.dst.sid, SID_SIZE);
        mdp->out.dst.port = MDP_PORT_RHIZOME_MANIFEST_REQUEST;
        if (src_reachable & REACHABLE_DIRECT)
          mdp->out.ttl = 1;
        else
          mdp->out.ttl = 64;
        mdp->packetTypeAndFlags = MDP_TX;
        mdp->out.queue = OQ_ORDINARY;
      }
      DEBUGF("Requesting manifest for BAR %s", alloca_tohex(bars[index], RHIZOME_BAR_BYTES));
      bcopy(bars[index], &mdp->out.payload[mdp->out.payload_length], RHIZOME_BAR_BYTES);
      mdp->out.payload_length += RHIZOME_BAR_BYTES;
    }
  }
  
  time_ms_t end_time=gettime_ms();

  if (test_count)
    lookup_time=(end_time-start_time)/test_count;
  else
    lookup_time = (end_time - start_time);

  if (mdp->out.payload_length > 0) {
    post_runnable(overlay_mdp_dispatch_alarm, mdp, &main_fdqueue);
  } else {
    free(mdp);
  }

end:
  sqlite_set_tracefunc(oldfunc);
  RETURN(0);
  OUT();
}

