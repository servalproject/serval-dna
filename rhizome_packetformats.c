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


int rhizome_manifest_to_bar(rhizome_manifest *m, rhizome_bar_t *bar)
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
    bar->binary[RHIZOME_BAR_PREFIX_OFFSET+i]=m->cryptoSignPublic.binary[i];
  /* file length */
  assert(m->filesize != RHIZOME_SIZE_UNSET);
  bar->binary[RHIZOME_BAR_FILESIZE_OFFSET]=log2ll(m->filesize);
  /* Version */
  for(i=0;i<7;i++) 
    bar->binary[RHIZOME_BAR_VERSION_OFFSET+6-i]=(m->version>>(8*i))&0xff;

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
  v=(minLat+90)*(65535/180); bar->binary[o++]=(v>>8)&0xff; bar->binary[o++]=(v>>0)&0xff;
  v=(minLong+180)*(65535/360); bar->binary[o++]=(v>>8)&0xff; bar->binary[o++]=(v>>0)&0xff;
  v=(maxLat+90)*(65535/180); bar->binary[o++]=(v>>8)&0xff; bar->binary[o++]=(v>>0)&0xff;
  v=(maxLong+180)*(65535/360); bar->binary[o++]=(v>>8)&0xff; bar->binary[o++]=(v>>0)&0xff;

  bar->binary[RHIZOME_BAR_TTL_OFFSET]=0;
  
  RETURN(0);
  OUT();
}

uint64_t rhizome_bar_version(const rhizome_bar_t *bar)
{
  uint64_t version=0;
  int i;
  for(i=0;i<7;i++) 
    version|=((uint64_t)(bar->binary[RHIZOME_BAR_VERSION_OFFSET+6-i]))<<(8LL*i);
  return version;
}

/* This function only displays the first 8 bytes, and should not be used
   for comparison. */
uint64_t rhizome_bar_bidprefix_ll(const rhizome_bar_t *bar)
{
  uint64_t bidprefix=0;
  int i;
  for(i=0;i<8;i++) 
    bidprefix|=((uint64_t)bar->binary[RHIZOME_BAR_PREFIX_OFFSET+7-i])<<(8*i);
  return bidprefix;
}

#define HAS_PORT (1<<1)
#define HAS_MANIFESTS (1<<0)

/* Queue an advertisment for a single manifest */
int rhizome_advertise_manifest(struct subscriber *dest, rhizome_manifest *m){
  struct overlay_frame *frame = malloc(sizeof(struct overlay_frame));
  bzero(frame,sizeof(struct overlay_frame));
  frame->type = OF_TYPE_RHIZOME_ADVERT;
  frame->source = get_my_subscriber();
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
  DEBUGF(rhizome_ads, "Advertising manifest %s %"PRIu64" to %s", 
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
    httpaddr.inet.sin_port = HTTPD_PORT_DEFAULT;
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
	DEBUG(rhizome_ads, "Ignoring manifest that looks malformed");
	goto next;
      }
      
      DEBUGF(rhizome_ads, "manifest id=%s version=%"PRIu64, alloca_tohex_rhizome_bid_t(summ.bid), summ.version);

      // If it looks like there is no signature at all, ignore the announcement but don't brown-list
      // the manifest ID, so that we will still process other offers of the same manifest with
      // signatures.
      if (summ.body_len == manifest_length) {
	DEBUG(rhizome_ads, "Ignoring manifest announcment with no signature");
	goto next;
      }

      if (rhizome_ignore_manifest_check(summ.bid.binary, sizeof summ.bid.binary)){
	/* Ignoring manifest that has caused us problems recently */
	DEBUGF(rhizome_ads, "Ignoring manifest with errors bid=%s", alloca_tohex_rhizome_bid_t(summ.bid));
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
  const rhizome_bar_t *bars[50];
  int bar_count=0;
  while(ob_remaining(f->payload)>0 && bar_count<50){
    const rhizome_bar_t *bar;
    bars[bar_count]=bar=(const rhizome_bar_t *)ob_get_bytes_ptr(f->payload, RHIZOME_BAR_BYTES);
    if (!bar){
      WARNF("Expected whole BAR @%zx (only %zd bytes remain)", ob_position(f->payload), ob_remaining(f->payload));
      break;
    }

    // are we ignoring this manifest?
    if (rhizome_ignore_manifest_check(rhizome_bar_prefix(bar), RHIZOME_BAR_PREFIX_BYTES))
      continue;

    // do we have free space in a fetch queue?
    unsigned char log2_size = rhizome_bar_log_size(bar);
    if (log2_size!=0xFF && rhizome_fetch_has_queue_space(log2_size)!=1)
      continue;

    // are we already fetching this bundle [or later]?
    if (rhizome_fetch_bar_queued(bar))
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
	header.source = get_my_subscriber();
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
      DEBUGF(rhizome, "Requesting manifest for BAR %s", alloca_tohex_rhizome_bar_t(bars[index]));
      ob_append_bytes(payload, bars[index]->binary, RHIZOME_BAR_BYTES);
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

