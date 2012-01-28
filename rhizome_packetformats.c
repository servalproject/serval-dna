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

#include "mphlr.h"
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
  */
  
  if (debug&DEBUG_RHIZOME)
    WHY("Group handling not completely thought out here yet.");

  /* Get number of bundles available if required */
  bundles_available=sqlite_exec_int64("SELECT COUNT(BAR) FROM MANIFESTS;");
  if (bundles_available==-1||(bundle_offset[0]>=bundles_available)) 
    bundle_offset[0]=0;
  if (bundles_available==-1||(bundle_offset[1]>=bundles_available)) 
    bundle_offset[1]=0;
  
  for(pass=skipmanifests;pass<2;pass++)
    {
      sqlite3_stmt *statement;
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
	  sqlite3_finalize(statement);
	  sqlite3_close(rhizome_db);
	  rhizome_db=NULL;
	  WHY(query);
	  WHY(sqlite3_errmsg(rhizome_db));
	  return WHY("Could not prepare sql statement for fetching BARs for advertisement.");
	}
      while((bytes_used<bytes_available)&&(sqlite3_step(statement)==SQLITE_ROW)&&
	    (e->length+RHIZOME_BAR_BYTES<=e->sizeLimit))
	{
	  sqlite3_blob *blob;
	  int column_type=sqlite3_column_type(statement, 0);
	  switch(column_type) {
	  case SQLITE_BLOB:
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
		fprintf(stderr,"Found a BAR that is the wrong size - ignoring\n");
	      continue;
	    }
	    
	    /* Only include manifests that are <=1KB inline.
	       Longer ones are only advertised by BAR */
	    if (blob_bytes>1024) continue;

	    int overhead=0;
	    if (!pass) overhead=2;
	    if (ob_makespace(e,overhead+blob_bytes)) {
	      if (debug&DEBUG_RHIZOME) 
		fprintf(stderr,"Stopped cramming %s into Rhizome advertisement frame.\n",
			pass?"BARs":"manifests");
	      break;
	    }
	    if (!pass) {
	      /* put manifest length field and manifest ID */
	      e->bytes[e->length]=(blob_bytes>>8)&0xff;
	      e->bytes[e->length+1]=(blob_bytes>>0)&0xff;
	      if (debug&DEBUG_RHIZOME)
		fprintf(stderr,"length bytes written at offset 0x%x\n",e->length);
	    }
	    if (sqlite3_blob_read(blob,&e->bytes[e->length+overhead],blob_bytes,0)
		!=SQLITE_OK) {
	      if (debug&DEBUG_RHIZOME) WHY("Couldn't read from blob");
	      sqlite3_blob_close(blob);
	      continue;
	    }
	    e->length+=overhead+blob_bytes;
	    bytes_used+=overhead+blob_bytes;
	    bundles_advertised++;
	    
	    sqlite3_blob_close(blob);
	  }
	}
      sqlite3_finalize(statement);
      if (!pass) 
	{
	  /* Mark end of whole manifests by writing 0xff, which is more than the MSB
	     of a manifest's length is allowed to be. */
	  ob_append_byte(e,0xff);
	}
    }
  
  if (debug&DEBUG_RHIZOME) printf("Appended %d rhizome advertisements to packet.\n",bundles_advertised);
  int rfs_value=1+8+1+1+1+bytes_used;
  if (rfs_value<0xfa)
    e->bytes[rfs_offset]=rfs_value;
  else
    {
      ob_makespace(e,1);
      bcopy(&e->bytes[rfs_offset],&e->bytes[rfs_offset+1],
	    e->length-rfs_offset);
      e->bytes[rfs_offset]=0xfa+(rfs_value-250)/256;
      e->bytes[rfs_offset+1]=(rfs_value-250)&0xff;
      e->length++;
    }

  return 0;
}

int overlay_rhizome_saw_advertisements(int i,overlay_frame *f, long long now)
{
  if (!f) return -1;
  if (debug&DEBUG_RHIZOME) fprintf(stderr,"rhizome f->bytecount=%d\n",
				   f->payload->length);

  int ofs=0;
  int ad_frame_type=f->payload->bytes[ofs++];
  int manifest_length;
  rhizome_manifest *m=NULL;


  if (ad_frame_type==1)
    {
      /* Extract whole manifests */
      while(ofs<f->payload->length) {
	char *manifest_id=NULL;
	manifest_length=(f->payload->bytes[ofs]<<8)+f->payload->bytes[ofs+1];
	if (manifest_length>=0xff00) {
	  ofs++;
	  break;
	} 

	ofs+=2;
	if (manifest_length==0) continue;

	/* Read manifest without verifying signatures (which would waste lots of
	   energy, everytime we see a manifest that we already have).
	   In fact, it would be better here to do a really rough and ready parser
	   to get the id and version fields out, and avoid the memory copies that
	   otherwise happen. */
	m=rhizome_read_manifest_file((char *)&f->payload->bytes[ofs],
				     manifest_length,RHIZOME_DONTVERIFY);
	int importManifest=0;
	if (!m->errors)
	  {
	    /* Manifest is okay, so see if it is worth storing */
	    if (rhizome_manifest_version_cache_lookup(m)) {
	      /* We already have this version or newer */
	      if (debug&DEBUG_RHIZOMESYNC) {
		fprintf(stderr,"manifest id=%s, version=%lld\n",
			rhizome_manifest_get(m,"id",NULL,0),
			rhizome_manifest_get_ll(m,"version"));
		WHY("We already have that manifest or newer.\n");
	      }
	      importManifest=0;
	    } else {
	      if (debug&DEBUG_RHIZOMESYNC) {
		fprintf(stderr,"manifest id=%s, version=%lld is new to us.\n",
			rhizome_manifest_get(m,"id",NULL,0),
			rhizome_manifest_get_ll(m,"version"));
	      }
	      importManifest=1;
	    }

	    manifest_id=rhizome_manifest_get(m,"id",NULL,0);
	  }
	else
	  {
	    if (debug&DEBUG_RHIZOME) fprintf(stderr,"Unverified manifest has errors - so not processing any further.\n");
	  }
	rhizome_manifest_free(m);
	m=NULL;

	if (importManifest) {
	  /* Okay, so the manifest looks like it is potentially interesting to us,
	     i.e., we don't already have it or a later version of it.
	     Now reread the manifest, this time verifying signatures */
	  m=rhizome_read_manifest_file((char *)&f->payload->bytes[ofs],
				       manifest_length,RHIZOME_VERIFY);
	  if (m->errors) {
	    if (debug&DEBUG_RHIZOME) fprintf(stderr,"Verifying manifest %s revealed errors -- not storing.\n",manifest_id);
	    rhizome_manifest_free(m);	  
	  } else {
	    if (debug&DEBUG_RHIZOME) fprintf(stderr,"Verifying manifest %s revealed no errors -- will try to store.\n",manifest_id);
	    
	    /* Add manifest to import queue. We need to know originating IPv4 address
	       so that we can transfer by HTTP. */
	    if (rhizome_queue_manifest_import(m,f->recvaddr))
	      rhizome_manifest_free(m);
	  }
	}
	else
	  rhizome_manifest_free(m);	  
	
	ofs+=manifest_length;
      }
      
    }
  
  return 0;
}
