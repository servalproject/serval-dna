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
#include <arpa/inet.h>

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

  /* Manifest prefix */
  unsigned i;
  for(i=0;i<RHIZOME_BAR_PREFIX_BYTES;i++) 
    bar[RHIZOME_BAR_PREFIX_OFFSET+i]=m->cryptoSignPublic.binary[i];
  /* file length */
  assert(m->filesize != RHIZOME_SIZE_UNSET);
  bar[RHIZOME_BAR_FILESIZE_OFFSET]=log2ll(m->filesize);
  /* Version */
  for(i=0;i<7;i++) bar[RHIZOME_BAR_VERSION_OFFSET+6-i]=(m->version>>(8*i))&0xff;

#if 0
  /* geo bounding box TODO: replace with bounding circle!!! */
  double minLat=rhizome_manifest_get_double(m,"min_lat",-90);
  if (minLat<-90) minLat=-90; if (minLat>90) minLat=90;
  double minLong=rhizome_manifest_get_double(m,"min_long",-180);
  if (minLong<-180) minLong=-180; if (minLong>180) minLong=180;
  double maxLat=rhizome_manifest_get_double(m,"max_lat",+90);
  if (maxLat<-90) maxLat=-90; if (maxLat>90) maxLat=90;
  double maxLong=rhizome_manifest_get_double(m,"max_long",+180);
  if (maxLong<-180) maxLong=-180; if (maxLong>180) maxLong=180;  
#else
  double minLat = -90;
  double minLong = -180;
  double maxLat = +90;
  double maxLong = +180;
#endif
  unsigned short v;
  int o=RHIZOME_BAR_GEOBOX_OFFSET;
  v=(minLat+90)*(65535/180); bar[o++]=(v>>8)&0xff; bar[o++]=(v>>0)&0xff;
  v=(minLong+180)*(65535/360); bar[o++]=(v>>8)&0xff; bar[o++]=(v>>0)&0xff;
  v=(maxLat+90)*(65535/180); bar[o++]=(v>>8)&0xff; bar[o++]=(v>>0)&0xff;
  v=(maxLong+180)*(65535/360); bar[o++]=(v>>8)&0xff; bar[o++]=(v>>0)&0xff;

  bar[RHIZOME_BAR_TTL_OFFSET]=0;
  
  RETURN(0);
  OUT();
}

uint64_t rhizome_bar_version(const unsigned char *bar)
{
  uint64_t version=0;
  int i;
  for(i=0;i<7;i++) 
    version|=((uint64_t)(bar[RHIZOME_BAR_VERSION_OFFSET+6-i]))<<(8LL*i);
  return version;
}

/* This function only displays the first 8 bytes, and should not be used
   for comparison. */
uint64_t rhizome_bar_bidprefix_ll(const unsigned char *bar)
{
  uint64_t bidprefix=0;
  int i;
  for(i=0;i<8;i++) 
    bidprefix|=((uint64_t)bar[RHIZOME_BAR_PREFIX_OFFSET+7-i])<<(8*i);
  return bidprefix;
}

static int append_bars(struct overlay_buffer *e, sqlite_retry_state *retry, const char *sql, int64_t *last_rowid)
{
  sqlite3_stmt *statement = sqlite_prepare(retry, sql);
  if (statement == NULL)
    return -1;
  int params = sqlite3_bind_parameter_count(statement);
  switch (params) {
    case 0: break;
    case 1:
      if (sqlite_bind(retry, statement, INT64, *last_rowid, END) == -1)
	return -1;
      break;
    default:
      return WHYF("query has invalid number of parameters (%d): %s", params, sqlite3_sql(statement));
  }
  int count = 0;
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
    if (ob_remaining(e) < RHIZOME_BAR_BYTES) {
      // out of room
      count--;
      break;
    }
    ob_append_bytes(e, (unsigned char *)data, RHIZOME_BAR_BYTES);
    *last_rowid=rowid;
  }
  if (statement)
    sqlite3_finalize(statement);
  return count;
}

/* Periodically queue BAR advertisements
 Always advertise the most recent 3 manifests in the table, cycle through the rest of the table, adding 17 BAR's at a time
 */
static uint64_t bundles_available=0;
void overlay_rhizome_advertise(struct sched_ent *alarm)
{
  bundles_available=0;
  static int64_t bundle_last_rowid=INT64_MAX;
  
  if (!is_rhizome_advertise_enabled())
    return;
  
  // TODO deprecate the below announcement method and move this alarm to rhizome_sync.c
  rhizome_sync_announce();

  int (*oldfunc)() = sqlite_set_tracefunc(is_debug_rhizome_ads);
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;

  // TODO: DEPRECATE REST OF THIS CODE WHICH SEEMS TO BE CAUSING TOO MUCH CHATTER
  // ESPECIALLY FOR PACKET-RADIO
  goto end;

  /* Get number of bundles available */
  if (sqlite_exec_uint64_retry(&retry, &bundles_available, "SELECT COUNT(BAR) FROM MANIFESTS;", END) != 1){
    WHY("Could not count BARs for advertisement");
    goto end;
  }
  
  if (bundles_available<1)
    goto end;
  
  struct overlay_frame *frame = malloc(sizeof(struct overlay_frame));
  bzero(frame,sizeof(struct overlay_frame));
  frame->type = OF_TYPE_RHIZOME_ADVERT;
  frame->source = my_subscriber;
  frame->ttl = 1;
  frame->queue = OQ_OPPORTUNISTIC;
  if ((frame->payload = ob_new()) == NULL) {
    op_free(frame);
    goto end;
  }
  ob_limitsize(frame->payload, 800);
  ob_append_byte(frame->payload, 2);
  ob_append_ui16(frame->payload, httpd_server_port);
  int64_t rowid=0;
  int count = append_bars(frame->payload, &retry, 
			  "SELECT BAR,ROWID FROM MANIFESTS ORDER BY ROWID DESC LIMIT 3", 
			  &rowid);
  if (count>=3){
    if (bundle_last_rowid>rowid || bundle_last_rowid<=0)
      bundle_last_rowid=rowid;
    count = append_bars(frame->payload, &retry, 
			"SELECT BAR,ROWID FROM MANIFESTS WHERE ROWID < ? ORDER BY ROWID DESC LIMIT 17", 
			&bundle_last_rowid);
    if (count<17)
      bundle_last_rowid=INT64_MAX;
  }
  if (overlay_payload_enqueue(frame) == -1)
    op_free(frame);
end:
  sqlite_set_tracefunc(oldfunc);
  alarm->alarm = gettime_ms()+config.rhizome.advertise.interval;
  alarm->deadline = alarm->alarm+10000;
  schedule(alarm);
}

#define HAS_PORT (1<<1)
#define HAS_MANIFESTS (1<<0)

/* Queue an advertisment for a single manifest */
int rhizome_advertise_manifest(struct subscriber *dest, rhizome_manifest *m){
  struct overlay_frame *frame = malloc(sizeof(struct overlay_frame));
  bzero(frame,sizeof(struct overlay_frame));
  frame->type = OF_TYPE_RHIZOME_ADVERT;
  frame->source = my_subscriber;
  if (dest && dest->reachable&REACHABLE)
    frame->destination = dest;
  else
    frame->ttl = 1;
  frame->queue = OQ_OPPORTUNISTIC;
  if ((frame->payload = ob_new()) == NULL)
    goto error;
  ob_limitsize(frame->payload, 800);
  ob_append_byte(frame->payload, HAS_PORT|HAS_MANIFESTS);
  ob_append_ui16(frame->payload, is_rhizome_http_enabled()? httpd_server_port : 0);
  ob_append_ui16(frame->payload, m->manifest_all_bytes);
  ob_append_bytes(frame->payload, m->manifestdata, m->manifest_all_bytes);
  ob_append_byte(frame->payload, 0xFF);
  if (overlay_payload_enqueue(frame) == -1)
    goto error;
  if (config.debug.rhizome_ads)
    DEBUGF("Advertising manifest %s %"PRIu64" to %s", 
      alloca_tohex_rhizome_bid_t(m->cryptoSignPublic), m->version, dest?alloca_tohex_sid_t(dest->sid):"broadcast");
  return 0;
error:
  op_free(frame);
  return -1;
}

time_ms_t lookup_time=0;

int overlay_rhizome_saw_advertisements(struct decode_context *context, struct overlay_frame *f)
{
  IN();
  if (!f)
    RETURN(-1);
  
  if (!(rhizome_db && config.rhizome.fetch)) 
    RETURN(0);
  
  int ad_frame_type=ob_get(f->payload);
  struct socket_address httpaddr;
  if (context->addr.addr.sa_family == AF_UNIX){
    // try loopback http connections while testing with local sockets
    httpaddr.inet.sin_family=AF_INET;
    httpaddr.inet.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    httpaddr.addrlen = sizeof(httpaddr.inet);
  }else{
    httpaddr=context->addr;
  }
  if (httpaddr.addr.sa_family == AF_INET)
    httpaddr.inet.sin_port = htons(HTTPD_PORT);
  rhizome_manifest *m=NULL;

  int (*oldfunc)() = sqlite_set_tracefunc(is_debug_rhizome_ads);

  if (ad_frame_type & HAS_PORT){
    uint16_t port = ob_get_ui16(f->payload);
    if (httpaddr.addr.sa_family == AF_INET)
      httpaddr.inet.sin_port = htons(port);
  }
  
  if (ad_frame_type & HAS_MANIFESTS){
    /* Extract whole manifests */
    while (ob_remaining(f->payload) > 0) {
      if (ob_peek(f->payload) == 0xff) {
	ob_skip(f->payload, 1);
	break;
      }

      size_t manifest_length = ob_get_ui16(f->payload);
      if (manifest_length==0) continue;
      
      unsigned char *data = ob_get_bytes_ptr(f->payload, manifest_length);
      if (!data) {
	WHYF("Illegal manifest length field in rhizome advertisement frame %zu vs %zd", 
	     manifest_length, ob_remaining(f->payload));
	break;
      }

      // Briefly inspect the manifest to see if it looks interesting.
      struct rhizome_manifest_summary summ;
      if (!rhizome_manifest_inspect((char *)data, manifest_length, &summ)) {
	if (config.debug.rhizome_ads)
	  DEBUG("Ignoring manifest that looks malformed");
	goto next;
      }
      
      if (config.debug.rhizome_ads)
	DEBUGF("manifest id=%s version=%"PRIu64, alloca_tohex_rhizome_bid_t(summ.bid), summ.version);

      // If it looks like there is no signature at all, ignore the announcement but don't brown-list
      // the manifest ID, so that we will still process other offers of the same manifest with
      // signatures.
      if (summ.body_len == manifest_length) {
	if (config.debug.rhizome_ads)
	  DEBUG("Ignoring manifest announcment with no signature");
	goto next;
      }

      if (rhizome_ignore_manifest_check(summ.bid.binary, sizeof summ.bid.binary)){
	/* Ignoring manifest that has caused us problems recently */
	if (config.debug.rhizome_ads)
	  DEBUGF("Ignoring manifest with errors bid=%s", alloca_tohex_rhizome_bid_t(summ.bid));
	goto next;
      }

      // The manifest looks potentially interesting, so now do a full parse and validation.
      if ((m = rhizome_new_manifest()) == NULL)
	goto next;
      memcpy(m->manifestdata, data, manifest_length);
      m->manifest_all_bytes = manifest_length;
      if (   rhizome_manifest_parse(m) == -1
	  || !rhizome_manifest_validate(m)
      ) {
	WARN("Malformed manifest");
	// Don't attend to this manifest for at least a minute
	rhizome_queue_ignore_manifest(m->cryptoSignPublic.binary, sizeof m->cryptoSignPublic.binary, 60000);
	goto next;
      }
      assert(m->has_id);
      assert(m->version != 0);
      assert(cmp_rhizome_bid_t(&m->cryptoSignPublic, &summ.bid) == 0);
      assert(m->version == summ.version);
      assert(m->manifest_body_bytes == summ.body_len);
      
      // are we already fetching this bundle [or later]?
      rhizome_manifest *mf=rhizome_fetch_search(m->cryptoSignPublic.binary, sizeof m->cryptoSignPublic.binary);
      if (mf && mf->version >= m->version)
	goto next;
	
      if (!rhizome_is_manifest_interesting(m)) {
	/* We already have this version or newer */
	if (config.debug.rhizome_ads)
	  DEBUG("We already have that manifest or newer.");
	goto next;
      }

      if (config.debug.rhizome_ads)
	DEBUG("Not seen before.");

      // start the fetch process!
      rhizome_suggest_queue_manifest_import(m, &httpaddr, f->source);
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
  if (f->source->sync_state)
    goto end;

  struct internal_mdp_header header;
  bzero(&header, sizeof header);
  
  struct overlay_buffer *payload = NULL;
  
  // parse BAR's
  unsigned char *bars[50];
  int bar_count=0;
  while(ob_remaining(f->payload)>0 && bar_count<50){
    unsigned char *bar;
    bars[bar_count]=bar=ob_get_bytes_ptr(f->payload, RHIZOME_BAR_BYTES);
    if (!bar){
      WARNF("Expected whole BAR @%zx (only %zd bytes remain)", ob_position(f->payload), ob_remaining(f->payload));
      break;
    }

    // are we ignoring this manifest?
    if (rhizome_ignore_manifest_check(&bar[RHIZOME_BAR_PREFIX_OFFSET], RHIZOME_BAR_PREFIX_BYTES))
      continue;

    // do we have free space in a fetch queue?
    unsigned char log2_size = bar[RHIZOME_BAR_FILESIZE_OFFSET];
    if (log2_size!=0xFF && rhizome_fetch_has_queue_space(log2_size)!=1)
      continue;

    uint64_t version = rhizome_bar_version(bar);
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
      if (!payload){
	header.source = my_subscriber;
	header.source_port = MDP_PORT_RHIZOME_RESPONSE;
	header.destination = f->source;
	header.destination_port = MDP_PORT_RHIZOME_MANIFEST_REQUEST;
	
	if (f->source->reachable&REACHABLE_DIRECT)
	  header.ttl=1;
	else
	  header.ttl=64;
	
	header.qos=OQ_ORDINARY;
	
	payload = ob_new();
      }
      if (config.debug.rhizome)
	DEBUGF("Requesting manifest for BAR %s", alloca_tohex(bars[index], RHIZOME_BAR_BYTES));
      ob_append_bytes(payload, bars[index], RHIZOME_BAR_BYTES);
    }
  }
  
  time_ms_t end_time=gettime_ms();

  if (test_count)
    lookup_time=(end_time-start_time)/test_count;
  else
    lookup_time = (end_time - start_time);

  if (payload){
    ob_flip(payload);
    overlay_send_frame(&header, payload);
    ob_free(payload);
  }

end:
  sqlite_set_tracefunc(oldfunc);
  RETURN(0);
  OUT();
}

