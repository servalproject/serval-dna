/*
Serval Mesh Software
Copyright (C) 2010-2012 Paul Gardner-Stephen

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

/*
  Rhizome Direct (github issue #9)
  @author Paul Gardner-Stephen <paul@servalproject.org>

  The base rhizome protocol allows the automatic and progressive transfer of data
  bundles (typically files and their associated meta-data) between devices sharing
  a common network interface.

  There are several use-cases where that is insufficient, e.g.:

  1. User wishes to cause two near-by devices to completely synchronise, e.g., as
  part of a regular data courier activity, or a field operation centre wishing to
  extract all field-collected data from a device, and possibly provide the field
  device with updated operational information and software.

  2. Two remote devices wish to synchronise, e.g., redundant Serval Rhizome servers
  forming part of a humanitarian or governmental emergency/disaster response
  capability.

  3. As (2), but with regular synchronisation.

  In all cases what is required is a mechanism for one Serval daemon instance to
  communicate via another Serval daemon instance, and determine the bundles that
  need to be transfered in each direction, and effect those transfers.

  Several challenges complicate this objective:

  1. Network Address Translation (NAT) or some other barrier may make it impossible
  for one of the devices to initiate a TCP connection to the other device.  Thus
  the protocol must be able to operate "one-sided", yet be able to synchronise
  bundles in both directions.

  2. The protocol must not impair the real-time requirements of the Serval daemon
  at either end. Therefore the protocol must be implemented in a separate thread
  or process.  As the Serval design is for single-threaded processes to improve
  portability and reliability, a separate process will be used.  That separate
  process will be another instance of the Serval daemon that will be run from the
  command line, and terminate when the synchronisation has completed, or when it
  receives an appropriate signal.  This approach also ensures that the Rhizome 
  databases at each end will always be consistent (or more properly, not become
  inconsistent due to the operation of this protocol).

  The test suites to exercise this protocol are located in "tests/rhizomeprotocol".

  The above functionality resolves down to several specific functions:

  1. Ability to enquire running servald and generate a list of BARs that it has
  stored, and present that list of "IHAVE"'s to the far end for examination.

  2. Ability to respond to such a list of BAR's, compare the list to the local
  servald instance's Rhizome database, and send back a list of "IHAVE"'s for any
  bundles that are newer than those presented in the list, or that were not present
  in the list.

  3. Ability to parse such a list of "IHAVE"'s, and from that determine the set of
  bundles to synchronise in each direction.

  4. As each server may have very many bundles, the above transactions must be able
  to operate on a limited range of bundle-IDs.  Each request shall therefore include
  the lowest and highest bundle-ID covered by the list.

  Note that the above actions are between the two Rhizome Direct processes, and not
  the Serval daemon processes (although each Rhizome Direct process will necessarily
  need to communicate with their local Serval daemon instances).

  5. Ability to present a BAR to the remote end Serval daemon instance and fetch the
  associated data bundle, and then present it to the local Serval daemon instance
  for adding to the local Rhizome database.

  It is recognised that the Serval daemon's real-time behaviour is compromised by
  the current mechanism for importing bundles into the Rhizome database.  This will
  be addressed as part of the on-going development of the main Rhizome protocol, and
  its rectification is beyond the scope of Rhizome Direct.

  6. Ability to present manifest and associated data for a bundle to the remote
  Rhizome Direct process for that process to schedule its insertion into the Rhizome
  database.

  As with the existing Rhizome protocol, it seems reasonable to use HTTP as the
  basis. The interactions will be M2M, so we do not need a fully-fledged HTTP
  server at this stage, but can make use of our own spartan HTTP server already
  integrated into servald.

  In light of the above, all rhizome services and HTTP services are being
  transitioned from running in the main servald process, into a separate process
  started by servald calling fork() (but not exec, since the same starting image
  will be fine).
  
*/

#include "serval.h"
#include "rhizome.h"
#include "str.h"
#include <assert.h>

rhizome_direct_sync_request *rd_sync_handles[RHIZOME_DIRECT_MAX_SYNC_HANDLES];
int rd_sync_handle_count=0;

/* Create (but don't start) a rhizome direct sync request. 
   This creates the record to say that we want to undertake this synchronisation,
   either once or at intervals as specified.

   The start process actually triggers the first filling of a cursor buffer, and
   then calls the transport specific dispatch function.  The transport specific
   dispatch function is expected to be asynchronous, and to call the continue
   process.  

   The transport specific dispatch function is also expected to tell rhizome
   direct about which bundles to send or receive, or to fetch/push them itself.
   For IP-based transports, the built-in http transport will be suitable in
   many cases.  For non-IP transports the transport will have to take care of
   the bundle transport as well.
 */
rhizome_direct_sync_request
*rhizome_direct_new_sync_request(
				 void (*transport_specific_dispatch_function)
				 (struct rhizome_direct_sync_request *),
				 int buffer_size,int interval, int mode, void *state)
{
  assert(mode&3);

  if (rd_sync_handle_count>=RHIZOME_DIRECT_MAX_SYNC_HANDLES)
    {
      DEBUGF("Too many Rhizome Direct synchronisation policies.");
      return NULL;
    }

  rhizome_direct_sync_request *r=calloc(sizeof(rhizome_direct_sync_request),1);
  assert(r!=NULL);

  r->dispatch_function=transport_specific_dispatch_function;
  r->transport_specific_state=state;
  r->pushP=mode&1;
  r->pullP=mode&2;
  r->interval=interval;
  r->cursor=rhizome_direct_bundle_iterator(buffer_size);
  assert(r->cursor);
  
  rd_sync_handles[rd_sync_handle_count++]=r;
  return r;
}

/*
  Initiate a synchronisation episode.
*/
int rhizome_direct_start_sync_request(rhizome_direct_sync_request *r)
{
  assert(r);
  assert(r->syncs_started==r->syncs_completed);

  r->syncs_started++;

  return rhizome_direct_continue_sync_request(r);  
}

int rhizome_direct_continue_sync_request(rhizome_direct_sync_request *r)
{
  assert(r);
  assert(r->syncs_started==r->syncs_completed+1);

  /* We might not get any BARs in the final fill, but it doesn't mean that
     this cursor fill didn't cover a part of the BAR address space, so we 
     still have to send it. 
     We detect completion solely by whether on entering the call we have no
     more BAR address space or bundle data size bin space left to explore.

     In short, if the cursor's current position is the limit position, 
     then we can stop. 
  */

  if (r->cursor->size_high>=r->cursor->limit_size_high)
    {
      DEBUG("Out of bins");
      if (memcmp(r->cursor->bid_low,r->cursor->limit_bid_high,
		 RHIZOME_MANIFEST_ID_BYTES)>=0)
	{
	  DEBUG("out of BIDs");
	  /* Sync has finished.
	     The transport may have initiated one or more transfers, so
	     we cannot declare the sync complete until we know the transport
	     has finished transferring. */
	  if (!r->bundle_transfers_in_progress)
	    {
	      /* seems that all is done */
	      DEBUG("All done");
	      return rhizome_direct_conclude_sync_request(r);
	    } else 
	    DEBUG("Stuck on in-progress transfers");
	} else
	DEBUGF("bid_low<limit_bid_high");
    }

  int count=rhizome_direct_bundle_iterator_fill(r->cursor,-1);

  DEBUGF("Got %d BARs",count);
  dump("BARs",r->cursor->buffer,
       r->cursor->buffer_used+r->cursor->buffer_offset_bytes);
  
  r->dispatch_function(r);

  r->fills_sent++;

  return count;
}

int rhizome_direct_conclude_sync_request(rhizome_direct_sync_request *r)
{
  assert(r);
  r->syncs_completed++;

  /* reschedule if interval driven?
     if one-shot, should we remove from the list of active sync requests?
  */

  if (r->interval==0) {
    DEBUG("concluding one-shot");
    int i;
    for(i=0;i<rd_sync_handle_count;i++)
      if (r==rd_sync_handles[i])
	{
	  DEBUG("Found it");
	  rhizome_direct_bundle_iterator_free(&r->cursor);
	  free(r);
	  
	  if (i!=rd_sync_handle_count-1)
	    rd_sync_handles[i]=rd_sync_handles[rd_sync_handle_count-1];
	  rd_sync_handle_count--;
	  DEBUGF("handle count=%d",rd_sync_handle_count);
	  return 0;
	}    
    DEBUGF("Couldn't find sync request handle in list.");
    return -1;
  }
  
  return 0;
}

/*
  This function is called with the list of BARs for a specified cursor range
  that the far-end possesses, i.e., what we are given is a list of the far end's 
  "I have"'s.  To produce our reply, we need to work out corresponding list of
  "I have"'s, and then compare them to produce the list of "you have and I want" 
  and "I have and you want" that if fulfilled, would result in both ends having the
  same set of BARs for the specified cursor range.  The potential presense of
  multiple versions of a given bundle introduces only a slight complication. 
*/

rhizome_direct_bundle_cursor *rhizome_direct_get_fill_response
(unsigned char *buffer,int size, int max_response_bytes)
{
  if (size<10) return NULL;
  if (size>65536) return NULL;
  if (max_response_bytes<10) return NULL;
  if (max_response_bytes>1048576) return NULL;

  int them_count=(size-10)/RHIZOME_BAR_BYTES;

  /* We need to get a list of BARs that will fit into max_response_bytes when we
     have summarised them into (1+RHIZOME_BAR_PREFIX_BYTES)-byte PUSH/PULL hints.
     So we need an intermediate buffer that is somewhat larger to allow the actual
     maximum response buffer to be completely filled. */
  int max_intermediate_bytes
    =10+((max_response_bytes-10)/(1+RHIZOME_BAR_PREFIX_BYTES))*RHIZOME_BAR_BYTES;
  unsigned char usbuffer[max_intermediate_bytes];
  rhizome_direct_bundle_cursor 
    *c=rhizome_direct_bundle_iterator(max_intermediate_bytes);
  assert(c!=NULL);
  if (rhizome_direct_bundle_iterator_unpickle_range(c,buffer,10))
    {
      DEBUGF("Couldn't unpickle range");
      rhizome_direct_bundle_iterator_free(&c);
      return NULL;
    }
  DEBUGF("unpickled size_high=%lld, limit_size_high=%lld",
	 c->size_high,c->limit_size_high);
  DEBUGF("c->buffer_size=%d",c->buffer_size);

  /* Get our list of BARs for the same cursor range */
  int us_count=rhizome_direct_bundle_iterator_fill(c,-1);
  DEBUGF("Found %d manifests in that range",us_count);
  
  /* Transfer to a temporary buffer, so that we can overwrite
     the cursor's buffer with the response data. */
  bcopy(c->buffer,usbuffer,10+us_count*RHIZOME_BAR_BYTES);
  c->buffer_offset_bytes=10;
  c->buffer_used=0;

  /* Iterate until we are through both lists.
     Note that the responses are (1+RHIZOME_BAR_PREFIX_BYTES)-bytes each, much 
     smaller than the 32 bytes used by BARs, therefore the response will never be
     bigger than the request, and so we don't need to worry about overflows. */
  int them=0,us=0;
  DEBUGF("themcount=%d, uscount=%d",them_count,us_count);
  while(them<them_count||us<us_count)
    {
      DEBUGF("them=%d, us=%d",them,us);
      unsigned char *them_bar=&buffer[10+them*RHIZOME_BAR_BYTES];
      unsigned char *us_bar=&usbuffer[10+us*RHIZOME_BAR_BYTES];
      int relation=0;
      if (them<them_count&&us<us_count) {
	relation=memcmp(them_bar,us_bar,RHIZOME_BAR_COMPARE_BYTES);
	DEBUGF("relation = %d",relation);
	dump("them BAR",them_bar,RHIZOME_BAR_BYTES);
	dump("us BAR",us_bar,RHIZOME_BAR_BYTES);
      }
      else if (us==us_count) relation=-1; /* they have a bundle we don't have */
      else if (them==them_count) relation=+1; /* we have a bundle they don't have */
      else {
	DEBUGF("This should never happen.");
	break;
      }
      int who=0;
      if (relation<0) {
	/* They have a bundle that we don't have any version of.
	   Append 16-byte "please send" record consisting of 0x01 followed
	   by the eight-byte BID prefix from the BAR. */
	c->buffer[c->buffer_offset_bytes+c->buffer_used]=0x01; /* Please send */
	bcopy(&buffer[10+them*RHIZOME_BAR_BYTES+RHIZOME_BAR_PREFIX_OFFSET],
	      &c->buffer[c->buffer_offset_bytes+c->buffer_used+1],
	      RHIZOME_BAR_PREFIX_BYTES);
	c->buffer_used+=1+RHIZOME_BAR_PREFIX_BYTES;
	who=-1;
	DEBUGF("They have previously unseen bundle %016llx*",
	       rhizome_bar_bidprefix_ll(&buffer[10+them*RHIZOME_BAR_BYTES]));
      } else if (relation>0) {
	/* We have a bundle that they don't have any version of
	   Append 16-byte "I have [newer]" record consisting of 0x02 followed
	   by the eight-byte BID prefix from the BAR. */
	c->buffer[c->buffer_offset_bytes+c->buffer_used]=0x02; /* I have [newer] */
	bcopy(&usbuffer[10+us*RHIZOME_BAR_BYTES+RHIZOME_BAR_PREFIX_OFFSET],
	      &c->buffer[c->buffer_offset_bytes+c->buffer_used+1],
	      RHIZOME_BAR_PREFIX_BYTES);
	c->buffer_used+=1+RHIZOME_BAR_PREFIX_BYTES;
	who=+1;
	DEBUGF("We have previously unseen bundle %016llx*",
	       rhizome_bar_bidprefix_ll(&usbuffer[10+us*RHIZOME_BAR_BYTES]));
      } else {
	/* We each have a version of this bundle, so see whose is newer */
	long long them_version
	  =rhizome_bar_version(&buffer[10+them*RHIZOME_BAR_BYTES]);
	long long us_version
	  =rhizome_bar_version(&usbuffer[10+us*RHIZOME_BAR_BYTES]);
	if (them_version>us_version) {
	  /* They have the newer version of the bundle */
	  c->buffer[c->buffer_offset_bytes+c->buffer_used]=0x01; /* Please send */
	  bcopy(&buffer[10+them*RHIZOME_BAR_BYTES+RHIZOME_BAR_PREFIX_OFFSET],
		&c->buffer[c->buffer_offset_bytes+c->buffer_used+1],
		RHIZOME_BAR_PREFIX_BYTES);
	  c->buffer_used+=1+RHIZOME_BAR_PREFIX_BYTES;
	  DEBUGF("They have newer version of bundle %016llx* (%lld versus %lld)",
		 rhizome_bar_bidprefix_ll(&usbuffer[10+us*RHIZOME_BAR_BYTES]),
		 rhizome_bar_version(&usbuffer[10+us*RHIZOME_BAR_BYTES]),
		 rhizome_bar_version(&buffer[10+them*RHIZOME_BAR_BYTES]));
	} else if (them_version<us_version) {
	  /* We have the newer version of the bundle */
	  c->buffer[c->buffer_offset_bytes+c->buffer_used]=0x02; /* I have [newer] */
	  bcopy(&usbuffer[10+us*RHIZOME_BAR_BYTES+RHIZOME_BAR_PREFIX_OFFSET],
		&c->buffer[c->buffer_offset_bytes+c->buffer_used+1],
		RHIZOME_BAR_PREFIX_BYTES);
	  c->buffer_used+=1+RHIZOME_BAR_PREFIX_BYTES;
	  DEBUGF("We have newer version of bundle %016llx* (%lld versus %lld)",
		 rhizome_bar_bidprefix_ll(&usbuffer[10+us*RHIZOME_BAR_BYTES]),
		 rhizome_bar_version(&usbuffer[10+us*RHIZOME_BAR_BYTES]),
		 rhizome_bar_version(&buffer[10+them*RHIZOME_BAR_BYTES]));
	} else {
	  DEBUGF("We both have the same version of %016llx*",
		 rhizome_bar_bidprefix_ll(&buffer[10+them*RHIZOME_BAR_BYTES]));
	}
      }

      /* Advance through lists accordingly */
      switch(who) {
      case -1: them++; break;
      case +1: us++; break;
      case 0: them++; us++; break;
      }
    }

  return c;
}

rhizome_manifest *rhizome_direct_get_manifest(unsigned char *bid_prefix,int prefix_length)
{
  /* Give a BID prefix, e.g., from a BAR, find the matching manifest and return it.
     Of course, it is possible that more than one manifest matches.  This should
     occur only very rarely (with the possible exception of intentional attack, and
     even then a 64-bit prefix creates a reasonable barrier.  If we move to a new
     BAR format with 120 or 128 bits of BID prefix, then we should be safe for some
     time, thus this function taking the BID prefix as an input in preparation for
     that change).

     Of course, we need to be able to find the manifest.
     Easiest way is to select with a BID range.  We could instead have an extra
     database column with the prefix.
  */
  assert(prefix_length>=0);
  assert(prefix_length<=RHIZOME_MANIFEST_ID_BYTES);
  DEBUGF("here");
  unsigned char low[RHIZOME_MANIFEST_ID_BYTES];
  unsigned char high[RHIZOME_MANIFEST_ID_BYTES];

  memset(low,0x00,RHIZOME_MANIFEST_ID_BYTES);
  memset(high,0xff,RHIZOME_MANIFEST_ID_BYTES);
  bcopy(bid_prefix,low,prefix_length);
  bcopy(bid_prefix,high,prefix_length);

  char query[1024];
  snprintf(query,1024,"SELECT MANIFEST,ROWID FROM MANIFESTS WHERE ID>='%s' AND ID<='%s'",
	   alloca_tohex(low,RHIZOME_MANIFEST_ID_BYTES),
	   alloca_tohex(high,RHIZOME_MANIFEST_ID_BYTES));
  
  sqlite3_stmt *statement=sqlite_prepare(query);
  sqlite3_blob *blob=NULL;  
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;

  if (sqlite_step_retry(&retry, statement) == SQLITE_ROW)
    {
      int ret;
      int64_t rowid = sqlite3_column_int64(statement, 1);
      do ret = sqlite3_blob_open(rhizome_db, "main", "manifests", "bar",
				 rowid, 0 /* read only */, &blob);
      while (sqlite_code_busy(ret) && sqlite_retry(&retry, "sqlite3_blob_open"));
      if (!sqlite_code_ok(ret)) {
	WHYF("sqlite3_blob_open() failed, %s", sqlite3_errmsg(rhizome_db));
	sqlite3_finalize(statement);
	return NULL;
	
      }
      sqlite_retry_done(&retry, "sqlite3_blob_open");

      /* Read manifest data from blob */

      size_t manifestblobsize = sqlite3_column_bytes(statement, 0);
      if (manifestblobsize<1||manifestblobsize>1024) goto error;

      const char *manifestblob = (char *) sqlite3_column_blob(statement, 0);
      if (!manifestblob) goto error;

      rhizome_manifest *m=rhizome_new_manifest();
      if (rhizome_read_manifest_file(m,manifestblob,manifestblobsize)==-1)
	{
	  rhizome_manifest_free(m);
	  goto error;
	}
      
      DEBUGF("Read manifest");
      sqlite3_blob_close(blob);
      sqlite3_finalize(statement);
      return m;

 error:
      sqlite3_blob_close(blob);
      sqlite3_finalize(statement);
      return NULL;
    }
  else 
    {
      DEBUGF("no matching manifests");
      sqlite3_finalize(statement);
      return NULL;
    }

}

int app_rhizome_direct_sync(int argc, const char *const *argv, 
			    struct command_line_option *o)
{
  /* Attempt to connect with a remote Rhizome Direct instance,
     and negotiate which BARs to synchronise. */
  const char *modeName = (argc >= 3 ? argv[2] : "sync");
  int mode=3; /* two-way sync */
  if (!strcasecmp(modeName,"push")) mode=1; /* push only */
  if (!strcasecmp(modeName,"pull")) mode=2; /* pull only */

  DEBUGF("sync direction = %d",mode);

  /* Get iterator capable of 64KB buffering.
     In future we should parse the sync URL and base the buffer size on the
     transport and allowable traffic volumes. */
  rhizome_direct_transport_state_http 
    *state=calloc(sizeof(rhizome_direct_transport_state_http),1);
  const char *sync_url=NULL;
  int peer_count=confValueGetInt64("rhizome.direct.peer.count",0);
  int peer_number=0;
  char peer_var[128];

  if (argv[3]) {
    peer_count=1;
    sync_url=argv[3];
  } 

  if (peer_count<1) {
    DEBUG("No rhizome direct peers were configured or supplied.");
  }

  /* XXX This code runs each sync in series, when we can probably do them in
     parallel.  But we can't really do them in parallel until we make the
     synchronisation process fully asynchronous, which probably won't happen
     for a while yet.
     Also, we don't currently parse the URI protocol field fully. */
 next_peer:
  if (!sync_url) {
    snprintf(peer_var,128,"rhizome.direct.peer.%d",peer_number);
    sync_url=confValueGet(peer_var, NULL);
  }
   
  if (strlen(sync_url)>1020)
    {
      DEBUG("rhizome direct URI too long");
      return -1;
    }

  char protocol[1024];
  state->port=RHIZOME_HTTP_PORT;
  int ok=0;
  if (sscanf(sync_url,"%[^:]://%[^:]:%d",protocol,state->host,&state->port)>=2)
    ok=1;
  if (!ok) sprintf(protocol,"http");
  if ((!ok)&&(sscanf(sync_url,"%[^:]:%d",state->host,&state->port)>=1))
    ok=2;
  if (!ok)
    {
      DEBUG("could not parse rhizome direct URI");     
      return -1;
    } 
  DEBUGF("Rhizome direct peer is %s://%s:%d (parse route %d)",
	 protocol,state->host,state->port,ok);

  if (strcasecmp(protocol,"http")) {
    DEBUG("Unsupport Rhizome Direct synchronisation protocol."
	  "  Only HTTP is supported at present.");
    return -1;
  }
  
  rhizome_direct_sync_request 
    *s = rhizome_direct_new_sync_request(rhizome_direct_http_dispatch,
					 65536,0,mode,state);
  
  rhizome_direct_start_sync_request(s);
  
  if (rd_sync_handle_count>0)
    while(fd_poll()&&(rd_sync_handle_count>0)) continue;   
  
  sync_url=NULL;
  peer_number++;
  if (peer_number<peer_count) goto next_peer;

  return 0;
}
 
rhizome_direct_bundle_cursor *rhizome_direct_bundle_iterator(int buffer_size)
{
  rhizome_direct_bundle_cursor *r=calloc(sizeof(rhizome_direct_bundle_cursor),1);
  assert(r!=NULL);
  r->buffer=malloc(buffer_size);
  assert(r->buffer);
  r->buffer_size=buffer_size;

  r->size_low=0;
  r->size_high=1024;

  /* Make cursor initially unlimited in range */
  rhizome_direct_bundle_iterator_unlimit(r);

  return r;
}

void rhizome_direct_bundle_iterator_unlimit(rhizome_direct_bundle_cursor *r)
{
  assert(r!=NULL);

  r->limit_size_high=1LL<<48LL;
  memset(r->limit_bid_high,0xff,RHIZOME_MANIFEST_ID_BYTES);
  return;
}

int rhizome_direct_bundle_iterator_pickle_range(rhizome_direct_bundle_cursor *r,
						unsigned char *pickled,
						int pickle_buffer_size)
{
  assert(r);
  assert(pickle_buffer_size>=(1+4+1+4));

  /* Pickled cursor ranges use the format:

     byte - log2(start_size_high)
     4 bytes - first eight bytes of start_bid_low.

     byte - log2(size_high)
     4 bytes - first eight bytes of bid_high.

     For a total of 10 bytes.

     We can get away with the short prefixes for the BIDs, because the worst case
     scenario is that we include a small part of the BID address space that we
     don't need to.  That will happen MUCH less often than transferring cursor
     ranges, which will happen with every rhizome direct sync.
  */

  long long v;
  int ltwov=0;

  v=r->start_size_high;
  while(v>1) { ltwov++; v=v>>1; }
  pickled[0]=ltwov;
  for(v=0;v<4;v++) pickled[1+v]=r->start_bid_low[v];
  v=r->size_high;
  DEBUGF("pickling size_high=%lld",r->size_high);
  ltwov=0;
  while(v>1) { ltwov++; v=v>>1; }
  pickled[1+4]=ltwov;
  for(v=0;v<4;v++) pickled[1+4+1+v]=r->bid_high[v];

  return 1+4+1+4;
}

int rhizome_direct_bundle_iterator_unpickle_range(rhizome_direct_bundle_cursor *r,
						  const unsigned char *pickled,
						  int pickle_buffer_size)
{
  assert(r);
  if (pickle_buffer_size!=10) {
    DEBUGF("pickled rhizome direct cursor ranges should be 10 bytes.");
    return -1;
  }

  int v;

  /* Get start of range */
  r->size_high=1LL<<pickled[0];
  r->size_low=(r->size_high/2)+1;
  if (r->size_low<=1024) r->size_low=0;
  for(v=0;v<4;v++) r->bid_low[v]=pickled[1+v];
  for(;v<RHIZOME_MANIFEST_ID_BYTES;v++) r->bid_low[v]=0x00;

  /* Get end of range */
  r->limit_size_high=1LL<<pickled[1+4];
  for(v=0;v<4;v++) r->limit_bid_high[v]=pickled[1+4+1+v];
  for(;v<RHIZOME_MANIFEST_ID_BYTES;v++) r->limit_bid_high[v]=0xff;

  return 0;
}

int rhizome_direct_bundle_iterator_fill(rhizome_direct_bundle_cursor *c,int max_bars)
{
  int bundles_stuffed=0;
  c->buffer_used=0;

  /* Note where we are starting the cursor fill from, so that the caller can easily
     communicate the range of interest to the far end.  We will eventually have a 
     cursor set function that will allow that information to be loaded back in at
     the far end.  We will similarly need to have a mechanism to limit the end of
     the range that the cursor will cover, so that responses to the exact range
     covered can be provided.. But first things first, remembering where the cursor
     started.
     We keep the space for the pickled cursor range at the start of the buffer,
     and fill it in at the end.
  */
  /* This is the only information required to remember where we started: */
  c->start_size_high=c->size_high;
  bcopy(c->bid_low,c->start_bid_low,RHIZOME_MANIFEST_ID_BYTES);
  c->buffer_offset_bytes=1+4+1+4; /* space for pickled cursor range */

  /* -1 is magic value for fill right up */
  if (max_bars==-1)
    max_bars=(c->buffer_size-c->buffer_offset_bytes)/RHIZOME_BAR_BYTES;

  DEBUGF("Iterating cursor size high %lld..%lld, max_bars=%d",
	 c->size_high,c->limit_size_high,max_bars);

  while (bundles_stuffed<max_bars&&c->size_high<=c->limit_size_high) 
    {
      /* Don't overrun the cursor's buffer */
      int stuffable
	=(c->buffer_size-c->buffer_used-c->buffer_offset_bytes)/RHIZOME_BAR_BYTES;
      if (stuffable<=0) break;

      /* Make sure we only get the range of BIDs allowed by the cursor limit.
	 If we are not yet at the bundle data size limit, then any bundle is okay.
	 If we are at the bundle data size limit, then we need to honour
	 c->limit_bid_high. */
      unsigned char bid_max[RHIZOME_MANIFEST_ID_BYTES];
      if (c->size_high==c->limit_size_high)
	bcopy(c->limit_bid_high,bid_max,RHIZOME_MANIFEST_ID_BYTES);
      else
	memset(bid_max,0xff,RHIZOME_MANIFEST_ID_BYTES);

      int stuffed_now=rhizome_direct_get_bars(c->bid_low,c->bid_high,
					      c->size_low,c->size_high,
					      bid_max,
					      &c->buffer[c->buffer_used
							 +c->buffer_offset_bytes],
					      stuffable);
      bundles_stuffed+=stuffed_now;
      c->buffer_used+=RHIZOME_BAR_BYTES*stuffed_now;
      if (!stuffed_now) {
	/* no more matches in this size bin, so move up a size bin */
	c->size_low=c->size_high+1;
	if (c->size_low<=1025) c->size_low=0;
	c->size_high*=2;
	/* Record that we covered to the end of that size bin */
	memset(c->bid_high,0xff,RHIZOME_MANIFEST_ID_BYTES);
	if (c->size_high>c->limit_size_high)
	  memset(c->bid_low,0xff,RHIZOME_MANIFEST_ID_BYTES);
	else
	  memset(c->bid_low,0x00,RHIZOME_MANIFEST_ID_BYTES);
      } else {
	/* Continue from next BID */
	bcopy(c->bid_high,c->bid_low,RHIZOME_MANIFEST_ID_BYTES);
	int i;
	for(i=RHIZOME_BAR_BYTES-1;i>=0;i--)
	  {
	    c->bid_low[i]++;
	    if (c->bid_low[i]) break;
	  }
	if (i<0) break;
      }
    }  

  /* Record range of cursor that this call covered. */
  rhizome_direct_bundle_iterator_pickle_range(c,c->buffer,c->buffer_offset_bytes);

  return bundles_stuffed;
}

void rhizome_direct_bundle_iterator_free(rhizome_direct_bundle_cursor **c)
{
  free((*c)->buffer); (*c)->buffer=NULL;
  bzero(*c,sizeof(rhizome_direct_bundle_cursor));
  *c=NULL;
}

/* Read upto the <bars_requested> next BARs from the Rhizome database,
   beginning from the first BAR that corresponds to a manifest with 
   BID>=<bid_low>.
   Sets <bid_high> to the highest BID for which a BAR was returned.
   Return value is the number of BARs written into <bars_out>.

   Only returns BARs for bundles within the specified size range.
   This is used by the cursor wrapper function that passes over all of the
   BARs in prioritised order.

   XXX Once the rhizome database gets big, we will need to make sure
   that we have suitable indexes.  It is tempting to just pack BARs
   by row_id, but the far end needs them in an orderly manner so that
   it is possible to make provably complete comparison of the contents
   of the respective rhizome databases.
*/
int rhizome_direct_get_bars(const unsigned char bid_low[RHIZOME_MANIFEST_ID_BYTES],
			    unsigned char bid_high[RHIZOME_MANIFEST_ID_BYTES],
			    long long size_low,long long size_high,
			    const unsigned char bid_max[RHIZOME_MANIFEST_ID_BYTES],
			    unsigned char *bars_out,
			    int bars_requested)
{
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  char query[1024];

  snprintf(query,1024,
	   "SELECT BAR,ROWID,ID,FILESIZE FROM MANIFESTS"
	   " WHERE ID>='%s' AND ID<='%s' AND FILESIZE BETWEEN %lld AND %lld"
	   // The following formulation doesn't remove the weird returning of
	   // bundles with out of range filesize values
	   //	   " WHERE ID>='%s' AND ID<='%s' AND FILESIZE > %lld AND FILESIZE < %lld"
	   " ORDER BY BAR LIMIT %d;",
	   alloca_tohex(bid_low,RHIZOME_MANIFEST_ID_BYTES),
	   alloca_tohex(bid_max,RHIZOME_MANIFEST_ID_BYTES),
	   size_low,size_high,
	   bars_requested);

  sqlite3_stmt *statement=sqlite_prepare(query);
  sqlite3_blob *blob=NULL;  

  int bars_written=0;

  while(bars_written<bars_requested
	&&  sqlite_step_retry(&retry, statement) == SQLITE_ROW)
    {
      int column_type=sqlite3_column_type(statement, 0);
      switch(column_type) {
      case SQLITE_BLOB:
	if (blob)
	  sqlite3_blob_close(blob);
	blob = NULL;
	int ret;
	int64_t filesize = sqlite3_column_int64(statement, 3);
	if (filesize<size_low||filesize>size_high) {
	  DEBUGF("WEIRDNESS ALERT: filesize=%lld, but query was: %s",
		 filesize,query);
	  break;
	}
	int64_t rowid = sqlite3_column_int64(statement, 1);
	do ret = sqlite3_blob_open(rhizome_db, "main", "manifests", "bar",
				   rowid, 0 /* read only */, &blob);
	while (sqlite_code_busy(ret) && sqlite_retry(&retry, "sqlite3_blob_open"));
	if (!sqlite_code_ok(ret)) {
	  WHYF("sqlite3_blob_open() failed, %s", sqlite3_errmsg(rhizome_db));
	  continue;
	}
	sqlite_retry_done(&retry, "sqlite3_blob_open");
	
	int blob_bytes=sqlite3_blob_bytes(blob);
	if (blob_bytes!=RHIZOME_BAR_BYTES) {
	  if (debug&DEBUG_RHIZOME)
	    DEBUG("Found a BAR that is the wrong size - ignoring");
	  sqlite3_blob_close(blob);
	  blob=NULL;
	  continue;
	}	
	sqlite3_blob_read(blob,&bars_out[bars_written*RHIZOME_BAR_BYTES],
			  RHIZOME_BAR_BYTES,0);
	sqlite3_blob_close(blob);
	blob=NULL;

	/* Remember the BID so that we cant write it into bid_high so that the
	   caller knows how far we got. */
	fromhex(bid_high,
		(const char *)sqlite3_column_text(statement, 2),
		RHIZOME_MANIFEST_ID_BYTES);

	bars_written++;
	break;
      default:
	/* non-BLOB field.  This is an error, but we will persevere with subsequent
	   rows, because they might be fine. */
	break;
      }
    }
  if (statement)
    sqlite3_finalize(statement);
  statement = NULL;
  
  return bars_written;
}
  
