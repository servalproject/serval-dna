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
#include "rhizome.h"
#include <assert.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


int rhizome_manifest_to_bar(rhizome_manifest *m,unsigned char *bar)
{
  IN();
  /* BAR = Bundle Advertisement Record.
     Basically a 32byte precis of a given manifest, that includes version, time-to-live
     and geographic bounding box information that is used to help manage flooding of
     bundles.

     64 bits - manifest ID prefix.
     56 bits - low 56 bits of version number.
     8 bits  - TTL of bundle in hops.
     64 bits - length of associated file.
     16 bits - min latitude (-90 - +90).
     16 bits - min longitude (-180 - +180).
     16 bits - max latitude (-90 - +90).
     16 bits - max longitude (-180 - +180).
 */

  if (!m) { RETURN(WHY("null manifest passed in")); }

  int i;

  /* Manifest prefix */
  for(i=0;i<8;i++) bar[i]=m->cryptoSignPublic[i];
  /* Version */
  for(i=0;i<7;i++) bar[8+6-i]=(m->version>>(8*i))&0xff;
  /* TTL */
  if (m->ttl>0) bar[15]=m->ttl-1; else bar[15]=0;
  /* file length */
  for(i=0;i<8;i++) bar[16+7-i]=(m->fileLength>>(8*i))&0xff;
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
  v=(minLat+90)*(65535/180); bar[24]=(v>>8)&0xff; bar[25]=(v>>0)&0xff;
  v=(minLong+180)*(65535/360); bar[26]=(v>>8)&0xff; bar[27]=(v>>0)&0xff;
  v=(maxLat+90)*(65535/180); bar[28]=(v>>8)&0xff; bar[29]=(v>>0)&0xff;
  v=(maxLong+180)*(65535/360); bar[30]=(v>>8)&0xff; bar[31]=(v>>0)&0xff;
  
  RETURN(0);
}

long long rhizome_bar_version(unsigned char *bar)
{
  long long version=0;
  int i;
  // for(i=0;i<7;i++) bar[8+6-i]=(m->version>>(8*i))&0xff;
  for(i=0;i<7;i++) version|=bar[8+6-i]<<(8LL*i);
  return version;
}

unsigned long long rhizome_bar_bidprefix(unsigned char *bar)
{
  long long bidprefix=0;
  int i;
  for(i=0;i<8;i++) bidprefix|=((unsigned long long)bar[7-i])<<(8*i);
  return bidprefix;
}


int bundles_available=-1;
int bundle_offset[2]={0,0};
int overlay_rhizome_add_advertisements(int interface_number,overlay_buffer *e)
{
  IN();
  int voice_mode=0;

  /* behave differently during voice mode.
     Basically don't encourage people to grab stuff from us, but keep
     just enough activity going so that it is possible to send a (small)
     message/file during a call. 

     XXX Eventually only advertise small/recently changed files during voice calls.
     We need to change manifest table to include payload length to make our life
     easy here (also would let us order advertisements by size of payload).
     For now, we will just advertised only occassionally.

     XXX Actually, we will move all processing of Rhizome into a separate process
     so that the CPU delays caused by Rhizome verifying signatures isn't a problem.
     We will still want to limit network usage during calls, however.
 */
  time_ms_t now = gettime_ms();
  if (now<rhizome_voice_timeout) voice_mode=1;
  if (voice_mode) if (random()&3) { RETURN(0); }

  int pass;
  int bytes=e->sizeLimit-e->length;
  int overhead=1+11+1+2+2; /* maximum overhead */
  int slots=(bytes-overhead)/RHIZOME_BAR_BYTES;
  if (slots>30) slots=30;
  int slots_used=0;
  int bytes_used=0;
  int bytes_available=bytes-overhead-1 /* one byte held for expanding RFS */;
  int bundles_advertised=0;

  if (slots<1) { RETURN(WHY("No room for node advertisements")); }

  if (!rhizome_db) { RETURN(WHY("Rhizome not enabled")); }

  if (ob_append_byte(e,OF_TYPE_RHIZOME_ADVERT))
    RETURN(WHY("could not add rhizome bundle advertisement header"));
  ob_append_byte(e, 1); /* TTL (1 byte) */

  ob_append_rfs(e,1+11+1+2+RHIZOME_BAR_BYTES*slots_used/* RFS */);

  /* Stuff in dummy address fields (11 bytes) */
  ob_append_byte(e,OA_CODE_BROADCAST);
  { int i; for(i=0;i<8;i++) ob_append_byte(e,random()&0xff); } /* BPI for broadcast */
  ob_append_byte(e,OA_CODE_PREVIOUS);
  overlay_abbreviate_clear_most_recent_address();
  overlay_abbreviate_append_address(e, overlay_get_my_sid());

  /* Randomly choose whether to advertise manifests or BARs first. */
  int skipmanifests=random()&1;
  /* Version of rhizome advert block (1 byte):
     1 = manifests then BARs,
     2 = BARs only,
     3 = HTTP port then manifests then BARs,
     4 = HTTP port then BARs only
   */
  ob_append_byte(e,3+skipmanifests);
  /* Rhizome HTTP server port number (2 bytes) */
  ob_append_short(e, rhizome_http_server_port);

  /* XXX Should add priority bundles here.
     XXX Should prioritise bundles for subscribed groups, Serval-authorised files
     etc over common bundles.
     XXX Should wait a while after going through bundle list so that we don't waste
     CPU on db queries if there are not many bundles.  Actually, we probably just
     shouldn't be sending bundles blindly on every tick.
     XXX How do we indicate group membership with BARs? Or do groups actively poll?

     XXX XXX XXX We should cache database results so that we don't waste all our time
     and energy asking the database much the same questions possibly many times per
     second.
  */

  // TODO Group handling not completely thought out here yet.

  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;

  /* Get number of bundles available if required */
  long long tmp = 0;
  if (sqlite_exec_int64_retry(&retry, &tmp, "SELECT COUNT(BAR) FROM MANIFESTS;") != 1)
    { RETURN(WHY("Could not count BARs for advertisement")); }
  bundles_available = (int) tmp;
  if (bundles_available==-1||(bundle_offset[0]>=bundles_available)) 
    bundle_offset[0]=0;
  if (bundles_available==-1||(bundle_offset[1]>=bundles_available)) 
    bundle_offset[1]=0;
  if(0)
    DEBUGF("%d bundles in database (%d %d), slots=%d.",bundles_available,
	   bundle_offset[0],bundle_offset[1],slots);
  
  sqlite3_stmt *statement=NULL;
  sqlite3_blob *blob=NULL;

  for(pass=skipmanifests;pass<2;pass++) {
    switch(pass) {
    case 0: /* Full manifests */
      statement = sqlite_prepare("SELECT MANIFEST,ROWID FROM MANIFESTS LIMIT %d,%d", bundle_offset[pass], slots);
      break;
    case 1: /* BARs */
      statement = sqlite_prepare("SELECT BAR,ROWID FROM MANIFESTS LIMIT %d,%d", bundle_offset[pass], slots);
      break;
    }
    if (!statement)
      RETURN(WHY("Could not prepare sql statement for fetching BARs for advertisement"));
    while(  bytes_used < bytes_available
	&&  sqlite_step_retry(&retry, statement) == SQLITE_ROW
	&&  e->length + RHIZOME_BAR_BYTES <= e->sizeLimit
    ) {
      int column_type=sqlite3_column_type(statement, 0);
      switch(column_type) {
      case SQLITE_BLOB:
	if (blob)
	  sqlite3_blob_close(blob);
	blob = NULL;
	int ret;
	int64_t rowid = sqlite3_column_int64(statement, 1);
	do ret = sqlite3_blob_open(rhizome_db, "main", "manifests", pass?"bar":"manifest", rowid, 0 /* read only */, &blob);
	  while (sqlite_code_busy(ret) && sqlite_retry(&retry, "sqlite3_blob_open"));
	if (!sqlite_code_ok(ret)) {
	  WHYF("sqlite3_blob_open() failed, %s", sqlite3_errmsg(rhizome_db));
	  continue;
	}
	sqlite_retry_done(&retry, "sqlite3_blob_open");

	int blob_bytes=sqlite3_blob_bytes(blob);
	if (pass&&(blob_bytes!=RHIZOME_BAR_BYTES)) {
	  if (debug&DEBUG_RHIZOME)
	    DEBUG("Found a BAR that is the wrong size - ignoring");
	  sqlite3_blob_close(blob);
	  blob=NULL;
	  continue;
	}

	/* Only include manifests that are <=1KB inline.
	    Longer ones are only advertised by BAR */
	if (blob_bytes>1024) {
	  WARN("ignoring manifest > 1k");
	  sqlite3_blob_close(blob);
	  blob = NULL;
	  bundle_offset[pass]++;
	  continue;
	}

	/* XXX This whole section is too hard to follow how the frame gets
	    built up. In particular the calculations for space required etc
	    are quite opaque... and I wrote it!  */
	int overhead=0;
	int frameFull=0;
	if (!pass) overhead=2;
	if (0) DEBUGF("e=%p, e->bytes=%p,e->length=%d, e->allocSize=%d", e,e->bytes,e->length,e->allocSize);

	if (ob_makespace(e,overhead+2+blob_bytes)) {
	  if (0||debug&DEBUG_RHIZOME) {
	    rhizome_manifest *m=rhizome_new_manifest();
	    char mdata[blob_bytes]; mdata[0]=0; mdata[1]=0;
	    sqlite3_blob_read(blob,&mdata[0],blob_bytes,0);
	    rhizome_read_manifest_file(m,mdata, blob_bytes);
	    long long version = rhizome_manifest_get_ll(m, "version");
	    DEBUGF("Stop cramming %s advertisements: not enough space for %s*:v%lld (%d bytes, size limit=%d, used=%d)",
		    pass?"BARs":"manifests",
		    alloca_tohex(m->cryptoSignPublic, 8),
		    version,
		    blob_bytes,e->sizeLimit,e->length);
	    rhizome_manifest_free(m);
	  }
	  frameFull=1;
	} else if (!pass) {
	  /* put manifest length field and manifest ID */
	  /* XXX why on earth is this being done this way, instead of
	      with ob_append_byte() ??? */
	  ob_setbyte(e,e->length,(blob_bytes>>8)&0xff);
	  ob_setbyte(e,e->length+1,(blob_bytes>>0)&0xff);
	  if (0&&debug&DEBUG_RHIZOME)
	    DEBUGF("length bytes written at offset 0x%x",e->length);
	}
	if (frameFull) {
	  sqlite3_blob_close(blob);
	  blob=NULL;
	  goto stopStuffing;
	}
	if (e->length+overhead+blob_bytes>=e->allocSize) {
	  WHY("Reading blob will overflow overlay_buffer");
	  sqlite3_blob_close(blob);
	  blob=NULL;
	  continue;
	}
	if (sqlite3_blob_read(blob,&e->bytes[e->length+overhead],blob_bytes,0) != SQLITE_OK) {
	  WHYF("sqlite3_blob_read() failed, %s", sqlite3_errmsg(rhizome_db));
	  sqlite3_blob_close(blob);
	  blob=NULL;
	  continue;
	}

	/* debug: show which BID/version combos we are advertising */
	if (0 && (!pass)) {
	  rhizome_manifest *m = rhizome_new_manifest();
	  rhizome_read_manifest_file(m, (char *)&e->bytes[e->length+overhead], blob_bytes);
	  long long version = rhizome_manifest_get_ll(m, "version");
	  DEBUGF("Advertising manifest %s* version %lld", alloca_tohex(m->cryptoSignPublic, 8), version);
	  rhizome_manifest_free(m);
	}

	e->length+=overhead+blob_bytes;
	if (e->length>e->allocSize) {
	  sqlite3_blob_close(blob);
	  blob=NULL;
	  FATAL("e->length > e->size");
	}
	bytes_used+=overhead+blob_bytes;
	bundles_advertised++;
	bundle_offset[pass]++;

	sqlite3_blob_close(blob);
	blob=NULL;
      }
    }
  stopStuffing:
    if (blob)
      sqlite3_blob_close(blob);
    blob = NULL;
    if (statement)
      sqlite3_finalize(statement);
    statement = NULL;
    if (!pass) {
      /* Mark end of whole manifests by writing 0xff, which is more than the MSB
	  of a manifest's length is allowed to be. */
      ob_append_byte(e,0xff);
      bytes_used++;
    }
  }

  if (blob)
    sqlite3_blob_close(blob);
  blob = NULL;
  if (statement)
    sqlite3_finalize(statement);
  statement = NULL;

  if (debug & DEBUG_RHIZOME)
    DEBUGF("Appended %d rhizome advertisements to packet using %d bytes", bundles_advertised, bytes_used);
  ob_patch_rfs(e, COMPUTE_RFS_LENGTH);

  RETURN(0);
}

int overlay_rhizome_saw_advertisements(int i,overlay_frame *f, long long now)
{
  IN();
  if (!f) { RETURN(-1); }
  int ofs=0;
  int ad_frame_type=f->payload->bytes[ofs++];
  struct sockaddr_in httpaddr = *(struct sockaddr_in *)f->recvaddr;
  httpaddr.sin_port = htons(RHIZOME_HTTP_PORT);
  int manifest_length;
  rhizome_manifest *m=NULL;
  char httpaddrtxt[INET_ADDRSTRLEN];
  
  switch (ad_frame_type) {
    case 3:
      /* The same as type=1, but includes the source HTTP port number */
      httpaddr.sin_port = htons((f->payload->bytes[ofs] << 8) + f->payload->bytes[ofs + 1]);
      ofs += 2;
      // FALL THROUGH ...
    case 1:
      /* Extract whole manifests */
      while(ofs<f->payload->length) {
	manifest_length=(f->payload->bytes[ofs]<<8)+f->payload->bytes[ofs+1];
	if (manifest_length>=0xff00) {
	  ofs++;
	  break;
	}
	if (manifest_length>f->payload->length - ofs) {
	  assert(inet_ntop(AF_INET, &httpaddr.sin_addr, httpaddrtxt, sizeof(httpaddrtxt)) != NULL);
	  WHYF("Illegal manifest length field in rhizome advertisement frame from %s:%d (%d vs %d)",
	       httpaddrtxt, ntohs(httpaddr.sin_port), manifest_length, f->payload->length - ofs);
	  break;
	}

	ofs+=2;
	if (manifest_length==0) continue;

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
	  RETURN(0);
	}
	if (rhizome_read_manifest_file(m, (char *)&f->payload->bytes[ofs], 
				       manifest_length) == -1) {
	  WHY("Error importing manifest body");
	  rhizome_manifest_free(m);
	  RETURN(0);
	}
	char manifest_id_prefix[RHIZOME_MANIFEST_ID_STRLEN + 1];
	if (rhizome_manifest_get(m, "id", manifest_id_prefix, sizeof manifest_id_prefix) == NULL) {
	  WHY("Manifest does not contain 'id' field");
	  rhizome_manifest_free(m);
	  RETURN(0);
	}
	/* trim manifest ID to a prefix for ease of debugging 
	   (that is the only use of this */
	manifest_id_prefix[8]=0; 
	long long version = rhizome_manifest_get_ll(m, "version");
	if (debug & DEBUG_RHIZOME_RX) DEBUGF("manifest id=%s* version=%lld", manifest_id_prefix, version);

	/* Crude signature presence test */
	for(i=m->manifest_all_bytes-1;i>0;i--)
	  if (!m->manifestdata[i]) {
	    /* A null in the middle says we have a signature */
	    break;
	  }
	if (!i) {
	  /* ignore the announcement, but don't ignore other people
	     offering the same manifest */
	  WARN("Ignoring manifest announcment with no signature");
	  rhizome_manifest_free(m);
	  RETURN(0);
	}
	int importManifest=0;	
	if (rhizome_ignore_manifest_check(m, &httpaddr))
	  {
	    /* Ignoring manifest that has caused us problems recently */
	    if (1) WARNF("Ignoring manifest with errors: %s*", manifest_id_prefix);
	  }
	else if (m&&(!m->errors))
	  {
	    /* Manifest is okay, so see if it is worth storing */
	    if (rhizome_manifest_version_cache_lookup(m)) {
	      /* We already have this version or newer */
	      if (debug & DEBUG_RHIZOME_RX) DEBUG("We already have that manifest or newer.");
	      importManifest=0;
	    } else {
	      if (debug & DEBUG_RHIZOME_RX) DEBUG("Not seen before.");
	      importManifest=1;
	    }
	  }
	else
	  {
	    if (debug & DEBUG_RHIZOME) DEBUG("Unverified manifest has errors - so not processing any further.");
	    /* Don't waste any time on this manifest in future attempts for at least
	       a minute. */
	    rhizome_queue_ignore_manifest(m, &httpaddr, 60000);
	  }
	if (m) rhizome_manifest_free(m);
	m=NULL;
	if (importManifest) {
	  /* Okay, so the manifest looks like it is potentially interesting to us,
	     i.e., we don't already have it or a later version of it.
	     Now reread the manifest, this time verifying signatures */
	  if ((m = rhizome_new_manifest()) == NULL)
	    WHY("Out of manifests");
	  else if (rhizome_read_manifest_file(m, (char *)&f->payload->bytes[ofs], manifest_length) == -1) {
	    WHY("Error importing manifest body");
	    rhizome_manifest_free(m);
	    m = NULL;
	    /* PGS @20120626 - Used to verify manifest here, which is before
	       checking if we already have the bundle or newer.  Trouble is
	       that signature verification is VERY expensive (~400ms on the ideos
	       phones), so we now defer it to inside 
	       rhizome_suggest_queue_manifest_import(), where it only gets called
	       after checking that it is worth adding to the queue. */
	  } else if (m->errors) {
	    if (debug&DEBUG_RHIZOME) DEBUGF("Verifying manifest %s* revealed errors -- not storing.", manifest_id_prefix);
	    rhizome_queue_ignore_manifest(m, &httpaddr, 60000);
	    rhizome_manifest_free(m);
	    m = NULL;
	  } else {
	    if (debug&DEBUG_RHIZOME) DEBUGF("Verifying manifest %s* revealed no errors -- will try to store.", manifest_id_prefix);
	    /* Add manifest to import queue. We need to know originating IPv4 address
	       so that we can transfer by HTTP. */
	    if (0) DEBUG("Suggesting fetching of a bundle");
	    rhizome_suggest_queue_manifest_import(m, &httpaddr);
	  }
	}
	if (!manifest_length) {
	  WHY("Infinite loop in packet decoding");
	  break;
	}
	ofs+=manifest_length;
      }
      break;
    }
  RETURN(0);
}
