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
#include <stdlib.h>

int rhizome_manifest_to_bar(rhizome_manifest *m,unsigned char *bar)
{
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

  if (!m) return WHY("null manifest passed in");

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
  
  return 0;
}

int bundles_available=-1;
int bundle_offset[2]={0,0};
int overlay_rhizome_add_advertisements(int interface_number,overlay_buffer *e)
{
  int voice_mode=0;

  /* behave differently during voice mode.
     Basically don't encourage people to grab stuff from us, but keep
     just enough activity going so that it is possible to send a (small)
     message/file during a call. 

     XXX Eventually only advertise small/recently changed files during voice calls.
     We need to change manifest table to include payload length to make our life
     easy here (also would let us order advertisements by size of payload).
     For now, we will just advertised only occassionally.
 */
  long long now=overlay_gettime_ms();
  if (now<rhizome_voice_timeout) voice_mode=1;
  if (voice_mode) if (random()&3) return 0;

  int pass;
  int bytes=e->sizeLimit-e->length;
  int overhead=1+8+1+3+1+1+1; /* maximum overhead */
  int slots=(bytes-overhead)/RHIZOME_BAR_BYTES;
  if (slots>30) slots=30;
  int slots_used=0;
  int bytes_used=0;
  int bytes_available=bytes-overhead-1 /* one byte held for expanding RFS */;
  int bundles_advertised=0;

  if (slots<1) return WHY("No room for node advertisements");

  if (!rhizome_db) return WHY("Rhizome not enabled");

  if (ob_append_byte(e,OF_TYPE_RHIZOME_ADVERT))
    return WHY("could not add rhizome bundle advertisement header");
  ob_append_byte(e,1); /* TTL */
  int rfs_offset=e->length; /* remember where the RFS byte gets stored 
			       so that we can patch it later */
  ob_append_byte(e,1+8+1+1+1+RHIZOME_BAR_BYTES*slots_used/* RFS */);

  /* Stuff in dummy address fields */
  ob_append_byte(e,OA_CODE_BROADCAST);
  { int i; for(i=0;i<8;i++) ob_append_byte(e,random()&0xff); } /* BPI for broadcast */
  ob_append_byte(e,OA_CODE_PREVIOUS);
  ob_append_byte(e,OA_CODE_SELF);

  /* Randomly choose whether to advertise manifests or BARs first. */
  int skipmanifests=random()&1;
  /* Version of rhizome advert block:
     1 = manifests then BARs,
     2 = BARs only */
  ob_append_byte(e,1+skipmanifests);

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
  
  if (debug&DEBUG_RHIZOME) {
#warning    DEBUG("Group handling not completely thought out here yet.");
  }

  /* Get number of bundles available if required */
  bundles_available=sqlite_exec_int64("SELECT COUNT(BAR) FROM MANIFESTS;");
  if (bundles_available==-1||(bundle_offset[0]>=bundles_available)) 
    bundle_offset[0]=0;
  if (bundles_available==-1||(bundle_offset[1]>=bundles_available)) 
    bundle_offset[1]=0;
  if(0)
    DEBUGF("%d bundles in database (%d %d), slots=%d.",bundles_available,
	    bundle_offset[0],bundle_offset[1],slots);
  
  sqlite3_stmt *statement=NULL;
  sqlite3_blob *blob=NULL;

  for(pass=skipmanifests;pass<2;pass++)
    {
      char query[1024];
      switch(pass) {
      case 0: /* Full manifests */
	snprintf(query,1024,"SELECT MANIFEST,ROWID FROM MANIFESTS LIMIT %d,%d",
		 bundle_offset[pass],slots);
	break;
      case 1: /* BARs */
	snprintf(query,1024,"SELECT BAR,ROWID FROM MANIFESTS LIMIT %d,%d",
		 bundle_offset[pass],slots);
	break;
      }

      switch (sqlite3_prepare_v2(rhizome_db,query,-1,&statement,NULL))
	{
	case SQLITE_OK: case SQLITE_DONE: case SQLITE_ROW:
	  break;
	default:
	  sqlite3_finalize(statement); statement=NULL;
	  sqlite3_close(rhizome_db); rhizome_db=NULL;
	  WHY(query);
	  WHY(sqlite3_errmsg(rhizome_db));
	  return WHY("Could not prepare sql statement for fetching BARs for advertisement.");
	}
      while((bytes_used<bytes_available)&&(sqlite3_step(statement)==SQLITE_ROW)&&
	    (e->length+RHIZOME_BAR_BYTES<=e->sizeLimit))
	{
	  int column_type=sqlite3_column_type(statement, 0);
	  switch(column_type) {
	  case SQLITE_BLOB:
	    if (blob) sqlite3_blob_close(blob); blob=NULL;
	    if (sqlite3_blob_open(rhizome_db,"main","manifests",
				  pass?"bar":"manifest",
				  sqlite3_column_int64(statement,1) /* rowid */,
				  0 /* read only */,&blob)!=SQLITE_OK)
	      {
		WHY("Couldn't open blob");
		continue;
	      }
	    int blob_bytes=sqlite3_blob_bytes(blob);
	    if (pass&&(blob_bytes!=RHIZOME_BAR_BYTES)) {
	      if (debug&DEBUG_RHIZOME) 
		DEBUG("Found a BAR that is the wrong size - ignoring");
	      sqlite3_blob_close(blob); blob=NULL;
	      continue;
	    }
	    
	    /* Only include manifests that are <=1KB inline.
	       Longer ones are only advertised by BAR */
	    if (blob_bytes>1024) { 
	      WARN("blob>1k - ignoring");
	      sqlite3_blob_close(blob); blob=NULL;
	      continue;
	    }

	    /* XXX This whole section is too hard to follow how the frame gets
	       built up. In particular the calculations for space required etc
	       are quite opaque... and I wrote it!  */
	    int overhead=0;
	    int frameFull=0;
	    if (!pass) overhead=2;
	    if (0) DEBUGF("e=%p, e->bytes=%p,e->length=%d, e->allocSize=%d",
		   e,e->bytes,e->length,e->allocSize);	    
	    
	    if (ob_makespace(e,overhead+2+blob_bytes)) {
	      if (0&&debug&DEBUG_RHIZOME) 
		DEBUGF("Stopped cramming %s into Rhizome advertisement frame.",
		     pass?"BARs":"manifests");
	      frameFull=1;
	    }
	    if (!pass) {
	      /* put manifest length field and manifest ID */
	      /* XXX why on earth is this being done this way, instead of 
		 with ob_append_byte() ??? */		
	      ob_setbyte(e,e->length,(blob_bytes>>8)&0xff);
	      ob_setbyte(e,e->length+1,(blob_bytes>>0)&0xff);
	      if (0&&debug&DEBUG_RHIZOME)
		DEBUGF("length bytes written at offset 0x%x",e->length);
	    }
	    if (frameFull) { 
	      sqlite3_blob_close(blob); blob=NULL;
	      goto stopStuffing;
	    }
	    if (e->length+overhead+blob_bytes>=e->allocSize) {
	      WHY("Reading blob will overflow overlay_buffer");
	      sqlite3_blob_close(blob); blob=NULL;
	      continue;
	    }
	    if (sqlite3_blob_read(blob,&e->bytes[e->length+overhead],blob_bytes,0)
		!=SQLITE_OK) {
	      if (!pass) {
		if (0) {
		  DEBUG("  Manifest:");
		  int i;
		  for(i=0;i<blob_bytes;i++) DEBUGF("  %c",e->bytes[e->length+overhead+i]);
		}
	      }
	      if (debug&DEBUG_RHIZOME) DEBUG("Couldn't read from blob");
	      sqlite3_blob_close(blob); blob=NULL;
	    dump("buffer (225)",(unsigned char *)e,sizeof(*e));
	    
	      continue;
	    }
	    e->length+=overhead+blob_bytes;
	    if (e->length>e->allocSize) {
	      WHY("e->length > e->size");
	      sqlite3_blob_close(blob); blob=NULL;
	      abort();
	    }
	    bytes_used+=overhead+blob_bytes;
	    bundles_advertised++;
	    bundle_offset[pass]=sqlite3_column_int64(statement,1);
	    
	    sqlite3_blob_close(blob); blob=NULL;
	  }
	}
    stopStuffing:
      if (blob) sqlite3_blob_close(blob); blob=NULL;
      if (statement) sqlite3_finalize(statement); statement=NULL;
      if (!pass) 
	{
	  /* Mark end of whole manifests by writing 0xff, which is more than the MSB
	     of a manifest's length is allowed to be. */
	  ob_append_byte(e,0xff);
	  bytes_used++;
	}
    }

  if (blob) sqlite3_blob_close(blob); blob=NULL;
  if (statement) sqlite3_finalize(statement); statement=NULL;
  
  if (0&&debug&DEBUG_RHIZOME) DEBUGF("Appended %d rhizome advertisements to packet using %d bytes.",bundles_advertised,bytes_used);
  int rfs_value=1+8+1+1+1+bytes_used;
  if (rfs_value<0xfa)
    ob_setbyte(e,rfs_offset,rfs_value);
  else
    {
      ob_makespace(e,1);
      ob_bcopy(e,rfs_offset,rfs_offset+1,
	    e->length-rfs_offset);
      ob_setbyte(e,rfs_offset,0xfa+(rfs_value-250)/256);
      ob_setbyte(e,rfs_offset+1,(rfs_value-250)&0xff);
      e->length++;
    }
  
  return 0;
}

int overlay_rhizome_saw_advertisements(int i,overlay_frame *f, long long now)
{
  if (!f) return -1;
  if (debug&DEBUG_RHIZOMESYNC) {
    DEBUGF("rhizome f->bytecount=%d",f->payload->length);
    //    dump("payload",f->payload->bytes,f->payload->length);
  }

  int ofs=0;
  int ad_frame_type=f->payload->bytes[ofs++];
  int manifest_length;
  rhizome_manifest *m=NULL;

  if (ad_frame_type==1)
    {
      /* Extract whole manifests */
      while(ofs<f->payload->length) {
	char manifest_id_buf[RHIZOME_MANIFEST_ID_STRLEN + 1];
	char *manifest_id = NULL;
	manifest_length=(f->payload->bytes[ofs]<<8)+f->payload->bytes[ofs+1];
	if (manifest_length>=0xff00) {
	  ofs++;
	  break;
	}
	if (ofs+manifest_length>f->payload->length) {
	  WHY("Illegal manifest length field in rhizome advertisement frame.");
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
	  return 0;
	}
	if (rhizome_read_manifest_file(m, (char *)&f->payload->bytes[ofs], manifest_length, RHIZOME_DONTVERIFY) == -1) {
	  WHY("Error importing manifest body");
	  rhizome_manifest_free(m);
	  return 0;
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
	  WARN("Ignoring manifest announcment with no signature");
	  rhizome_manifest_free(m);
	  return 0;
	}
	int importManifest=0;	
	if (rhizome_ignore_manifest_check(m,(struct sockaddr_in *)f->recvaddr))
	  {
	    /* Ignoring manifest that has caused us problems recently */
	    if (0) WARNF("Ignoring manifest with errors: %s",
			rhizome_manifest_get(m,"id",NULL,0));
	  }
	else if (m&&(!m->errors))
	  {
	    /* Manifest is okay, so see if it is worth storing */
	    if (rhizome_manifest_version_cache_lookup(m)) {
	      /* We already have this version or newer */
	      if (debug&DEBUG_RHIZOMESYNC) {
		DEBUGF("manifest id=%s, version=%lld",
		     rhizome_manifest_get(m,"id",NULL,0),
			rhizome_manifest_get_ll(m,"version"));
		DEBUG("We already have that manifest or newer.");
	      }
	      importManifest=0;
	    } else {
	      if (debug&DEBUG_RHIZOMESYNC) {
		DEBUGF("manifest id=%s, version=%lld is new to us.",
			rhizome_manifest_get(m,"id",NULL,0),
			rhizome_manifest_get_ll(m,"version"));
	      }
	      importManifest=1;
	    }

	    manifest_id = rhizome_manifest_get(m, "id", manifest_id_buf, sizeof manifest_id_buf);
	  }
	else
	  {
	    if (debug&DEBUG_RHIZOME) DEBUG("Unverified manifest has errors - so not processing any further.");
	    /* Don't waste any time on this manifest in future attempts for at least
	       a minute. */
	    rhizome_queue_ignore_manifest(m,(struct sockaddr_in*)f->recvaddr,60000);
	  }
	if (m) rhizome_manifest_free(m);
	m=NULL;
	if (importManifest) {
	  /* Okay, so the manifest looks like it is potentially interesting to us,
	     i.e., we don't already have it or a later version of it.
	     Now reread the manifest, this time verifying signatures */
	  if ((m = rhizome_new_manifest()) == NULL)
	    WHY("Out of manifests");
	  else if (rhizome_read_manifest_file(m, (char *)&f->payload->bytes[ofs], manifest_length, RHIZOME_VERIFY) == -1) {
	    WHY("Error importing manifest body");
	    rhizome_manifest_free(m);
	    m = NULL;
	  } else if (m->errors) {
	    if (debug&DEBUG_RHIZOME) DEBUGF("Verifying manifest %s revealed errors -- not storing.", manifest_id);
	    rhizome_queue_ignore_manifest(m,(struct sockaddr_in*)f->recvaddr,60000);
	    rhizome_manifest_free(m);
	    m = NULL;
	  } else {
	    if (debug&DEBUG_RHIZOME) DEBUGF("Verifying manifest %s revealed no errors -- will try to store.", manifest_id);
	    /* Add manifest to import queue. We need to know originating IPv4 address
	       so that we can transfer by HTTP. */
	    if (0) DEBUG("Suggesting fetching of a bundle");
	    rhizome_suggest_queue_manifest_import(m,(struct sockaddr_in *)f->recvaddr);
	  }
	}
	if (!manifest_length) {
	  WHY("Infinite loop in packet decoding");
	  break;
	}
	ofs+=manifest_length;
      }
    }
  
  return 0;
}
