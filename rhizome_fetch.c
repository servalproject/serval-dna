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

#include <time.h>
#include "serval.h"
#include "rhizome.h"

extern int sigPipeFlag;
extern int sigIoFlag;


typedef struct rhizome_file_fetch_record {
  struct sched_ent alarm;
  rhizome_manifest *manifest;
  char fileid[RHIZOME_FILEHASH_STRLEN + 1];
  FILE *file;
  
  char request[1024];
  int request_len;
  int request_ofs;
  
  long long file_len;
  long long file_ofs;

  int state;
  
#define RHIZOME_FETCH_CONNECTING 1
#define RHIZOME_FETCH_SENDINGHTTPREQUEST 2
#define RHIZOME_FETCH_RXHTTPHEADERS 3
#define RHIZOME_FETCH_RXFILE 4
  
} rhizome_file_fetch_record;

struct profile_total fetch_stats;

/* List of queued transfers */
#define MAX_QUEUED_FILES 4
int rhizome_file_fetch_queue_count=0;
rhizome_file_fetch_record file_fetch_queue[MAX_QUEUED_FILES];
/* 
   Queue a manifest for importing.

   There are three main cases that can occur here:

   1. The manifest has no associated file (filesize=0);
   2. The associated file is already in our database; or
   3. The associated file is not already in our database, and so we need
   to fetch it before we can import it.

   Cases (1) and (2) are more or less identical, and all we need to do is to
   import the manifest into the database.

   Case (3) requires that we fetch the associated file.

   This is where life gets interesting.
   
   First, we need to make sure that we can free up enough space in the database
   for the file.

   Second, we need to work out how we are going to get the file. 
   If we are on an IPv4 wifi network, then HTTP is probably the way to go.
   If we are not on an IPv4 wifi network, then HTTP is not an option, and we need
   to use a Rhizome/Overlay protocol to fetch it.  It might even be HTTP over MDP
   (Serval Mesh Datagram Protocol) or MTCP (Serval Mesh Transmission Control Protocol
   -- yet to be specified).

   For efficiency, the MDP transfer protocol should allow multiple listeners to
   receive the data. In contrast, it would be nice to have the data auth-crypted, if
   only to deal with packet errors (but also naughty people who might want to mess
   with the transfer.

   For HTTP over IPv4, the biggest problem is that we don't know the IPv4 address of
   the sender, or in fact that the link is over IPv4 and thus that HTTP over IPv4 is
   an option.  We probably need to be passed this information.  This has since been
   incorporated.
*/

/* As defined below uses 64KB */
#define RHIZOME_VERSION_CACHE_NYBLS 2 /* 256=2^8=2nybls */
#define RHIZOME_VERSION_CACHE_SHIFT 1
#define RHIZOME_VERSION_CACHE_SIZE 128
#define RHIZOME_VERSION_CACHE_ASSOCIATIVITY 16
typedef struct rhizome_manifest_version_cache_slot {
  unsigned char idprefix[24];
  long long version;
} rhizome_manifest_version_cache_slot;
rhizome_manifest_version_cache_slot rhizome_manifest_version_cache
[RHIZOME_VERSION_CACHE_SIZE][RHIZOME_VERSION_CACHE_ASSOCIATIVITY];

int rhizome_manifest_version_cache_store(rhizome_manifest *m)
{
  int bin=0;
  int slot;
  int i;

  char *id=rhizome_manifest_get(m,"id",NULL,0);
  if (!id) return 1; // dodgy manifest, so don't suggest that we want to RX it.

  /* Work out bin number in cache */
  for(i=0;i<RHIZOME_VERSION_CACHE_NYBLS;i++)
    {
      int nybl=hexvalue(id[i]);
      bin=(bin<<4)|nybl;
    }
  bin=bin>>RHIZOME_VERSION_CACHE_SHIFT;

  slot=random()%RHIZOME_VERSION_CACHE_ASSOCIATIVITY;
  rhizome_manifest_version_cache_slot *entry
    =&rhizome_manifest_version_cache[bin][slot];
  unsigned long long manifest_version = rhizome_manifest_get_ll(m,"version");

  entry->version=manifest_version;
  for(i=0;i<24;i++)
    {
      int byte=(hexvalue(id[(i*2)])<<4)|hexvalue(id[(i*2)+1]);
      entry->idprefix[i]=byte;
    }

  return 0;
}

int rhizome_manifest_version_cache_lookup(rhizome_manifest *m)
{
  int bin=0;
  int slot;
  int i;

  char id[RHIZOME_MANIFEST_ID_STRLEN + 1];
  if (!rhizome_manifest_get(m, "id", id, sizeof id))
    // dodgy manifest, we don't want to receive it
    return WHY("Ignoring bad manifest (no ID field)");
  str_toupper_inplace(id);
  m->version = rhizome_manifest_get_ll(m, "version");
  
  // skip the cache for now
  long long dbVersion = -1;
  if (sqlite_exec_int64(&dbVersion, "SELECT version FROM MANIFESTS WHERE id='%s';", id) == -1)
    return WHY("Select failure");
  if (dbVersion >= m->version) {
    if (0) WHYF("We already have %s (%lld vs %lld)", id, dbVersion, m->version);
    return -1;
  }
  return 0;

  /* Work out bin number in cache */
  for(i=0;i<RHIZOME_VERSION_CACHE_NYBLS;i++)
    {
      int nybl=hexvalue(id[i]);
      bin=(bin<<4)|nybl;
    }
  bin=bin>>RHIZOME_VERSION_CACHE_SHIFT;
  
  for(slot=0;slot<RHIZOME_VERSION_CACHE_ASSOCIATIVITY;slot++)
    {
      rhizome_manifest_version_cache_slot *entry
	=&rhizome_manifest_version_cache[bin][slot];
      for(i=0;i<24;i++)
	{
	  int byte=
	    (hexvalue(id[(i*2)])<<4)
	    |hexvalue(id[(i*2)+1]);
	  if (byte!=entry->idprefix[i]) break;
	}
      if (i==24) {
	/* Entries match -- so check version */
	long long rev = rhizome_manifest_get_ll(m,"version");
	if (1) DEBUGF("cached version %lld vs manifest version %lld", entry->version,rev);
	if (rev > entry->version) {
	  /* If we only have an old version, try refreshing the cache
	     by querying the database */
	  if (sqlite_exec_int64(&entry->version, "select version from manifests where id='%s'", id) != 1)
	    return WHY("failed to select stored manifest version");
	  DEBUGF("Refreshed stored version from database: entry->version=%lld", entry->version);
	}
	if (rev < entry->version) {
	  /* the presented manifest is older than we have.
	     This allows the caller to know that they can tell whoever gave them the
	     manifest it's time to get with the times.  May or not ever be
	     implemented, but it would be nice. XXX */
	  WHYF("cached version is NEWER than presented version (%lld is newer than %lld)",
	      entry->version,rev);
	  return -2;
	} else if (rev<=entry->version) {
	  /* the presented manifest is already stored. */	   
	  if (1) DEBUG("cached version is NEWER/SAME as presented version");
	  return -1;
	} else {
	  /* the presented manifest is newer than we have */
	  DEBUG("cached version is older than presented version");
	  return 0;
	}
      }
    }

  DEBUG("Not in manifest cache");

  /* Not in cache, so all is well, well, maybe.
     What we do know is that it is unlikely to be in the database, so it probably
     doesn't hurt to try to receive it.  

     Of course, we can just ask the database if it is there already, and populate
     the cache in the process if we find it.  The tradeoff is that the whole point
     of the cache is to AVOID database lookups, not incurr them whenever the cache
     has a negative result.  But if we don't ask the database, then we can waste
     more effort fetching the file associated with the manifest, and will ultimately
     incurr a database lookup (and more), so while it seems a little false economy
     we need to do the lookup now.

     What this all suggests is that we need fairly high associativity so that misses
     are rare events. But high associativity then introduces a linear search cost,
     although that is unlikely to be nearly as much cost as even thinking about a
     database query.

     It also says that on a busy network that things will eventually go pear-shaped
     and require regular database queries, and that memory allowing, we should use
     a fairly large cache here.
 */
  long long manifest_version = rhizome_manifest_get_ll(m, "version");
  long long count;
  switch (sqlite_exec_int64(&count, "select count(*) from manifests where id='%s' and version>=%lld", id, manifest_version)) {
    case -1:
      return WHY("database error reading stored manifest version");
    case 1:
      if (count) {
	/* Okay, we have a stored version which is newer, so update the cache
	  using a random replacement strategy. */
	long long stored_version;
	if (sqlite_exec_int64(&stored_version, "select version from manifests where id='%s'", id) < 1)
	  return WHY("database error reading stored manifest version"); // database is broken, we can't confirm that it is here
	DEBUGF("stored version=%lld, manifest_version=%lld (not fetching; remembering in cache)",
	    stored_version,manifest_version);
	slot=random()%RHIZOME_VERSION_CACHE_ASSOCIATIVITY;
	rhizome_manifest_version_cache_slot *entry
	  =&rhizome_manifest_version_cache[bin][slot];
	entry->version=stored_version;
	for(i=0;i<24;i++)
	  {
	    int byte=(hexvalue(id[(i*2)])<<4)|hexvalue(id[(i*2)+1]);
	    entry->idprefix[i]=byte;
	  }
	/* Finally, say that it isn't worth RXing this manifest */
	return stored_version > manifest_version ? -2 : -1;
      }
      break;
    default:
      return WHY("bad select result");
  }
  /* At best we hold an older version of this manifest, and at worst we
     don't hold any copy. */
  return 0;
}

typedef struct ignored_manifest {
  unsigned char bid[crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES];
  struct sockaddr_in peer;
  long long timeout;
} ignored_manifest;

#define IGNORED_BIN_SIZE 8
#define IGNORED_BIN_COUNT 64
#define IGNORED_BIN_BITS 6
typedef struct ignored_manifest_bin {
  int bins_used;
  ignored_manifest m[IGNORED_BIN_SIZE];
} ignored_manifest_bin;

typedef struct ignored_manifest_cache {
  ignored_manifest_bin bins[IGNORED_BIN_COUNT];
} ignored_manifest_cache;

/* used uninitialised, since the probability of
   a collision is exceedingly remote */
ignored_manifest_cache ignored;

int rhizome_ignore_manifest_check(rhizome_manifest *m,
				  struct sockaddr_in *peerip)
{
  int bin = m->cryptoSignPublic[0]>>(8-IGNORED_BIN_BITS);
  int slot;
  for(slot = 0; slot != IGNORED_BIN_SIZE; ++slot)
    {
      if (!memcmp(ignored.bins[bin].m[slot].bid,
		  m->cryptoSignPublic,
		  crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES))
	{
	  if (ignored.bins[bin].m[slot].timeout>gettime_ms())
	    return 1;
	  else 
	    return 0;
	}
    }
  return 0;
}

int rhizome_queue_ignore_manifest(rhizome_manifest *m,
				  struct sockaddr_in *peerip,int timeout)
{
  /* The supplied manifest from a given IP has errors, so remember 
     that it isn't worth considering */
  int bin = m->cryptoSignPublic[0]>>(8-IGNORED_BIN_BITS);
  int slot;
  for(slot = 0; slot != IGNORED_BIN_SIZE; ++slot)
    {
      if (!memcmp(ignored.bins[bin].m[slot].bid,
		  m->cryptoSignPublic,
		  crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES))
	break;
    }
  if (slot>=IGNORED_BIN_SIZE) slot=random()%IGNORED_BIN_SIZE;
  bcopy(&m->cryptoSignPublic[0],
	&ignored.bins[bin].m[slot].bid[0],
	crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES);
  /* ignore for a while */
  ignored.bins[bin].m[slot].timeout=gettime_ms()+timeout;
  bcopy(peerip,
	&ignored.bins[bin].m[slot].peer,
	sizeof(struct sockaddr_in));
  return 0;

}

typedef struct rhizome_candidates {
  rhizome_manifest *manifest;
  struct sockaddr_in peer;
  long long size;
  /* XXX Need group memberships/priority level here */
  int priority;
} rhizome_candidates;

rhizome_candidates candidates[MAX_CANDIDATES];
int candidate_count=0;

/* sort indicated candidate from starting position down
   (or up) */
int rhizome_position_candidate(int position)
{
  while(position<candidate_count&&position>=0) {
    rhizome_candidates *c1=&candidates[position];
    rhizome_candidates *c2=&candidates[position+1];
    if (c1->priority>c2->priority
	||(c1->priority==c2->priority
	   &&c1->size>c2->size))
      {
	rhizome_candidates c=*c1;
	*c1=*c2;
	*c2=c;
	position++;
      } 
    else {
      /* doesn't need moving down, but does it need moving up? */
      if (!position) return 0;
      rhizome_candidates *c0=&candidates[position-1];
      if (c1->priority<c0->priority
	  ||(c1->priority==c0->priority
	     &&c1->size<c0->size))
	{
	  rhizome_candidates c=*c1;
	  *c1=*c2;
	  *c2=c;
	  position--;
	} 
      else return 0;   
    }
  }
  return 0;
}

void rhizome_import_received_bundle(struct rhizome_manifest *m)
{
  // TODO: We already have the manifest struct in memory, should import the bundle
  // directly from that, not by writing it to a file and re-reading it!
  const char *id = rhizome_manifest_get(m, "id", NULL, 0);
  if (id == NULL) {
    WHY("Manifest missing ID");
    return;
  }
  if (create_rhizome_import_dir() == -1)
    return;
  char filename[1024];
  if (!FORM_RHIZOME_IMPORT_PATH(filename, "manifest.%s", id))
    return;
  /* Do really write the manifest unchanged */
  m->finalised = 1;
  m->manifest_bytes = m->manifest_all_bytes;
  if (debug & DEBUG_RHIZOME_RX) {
    DEBUGF("manifest bid=%s len=%d has %d signatories", id, m->manifest_bytes, m->sig_count);
    dump("manifest", m->manifestdata, m->manifest_all_bytes);
  }
  if (rhizome_write_manifest_file(m, filename) != -1)
    rhizome_bundle_import(m, NULL, id, m->ttl - 1 /* TTL */);
}

/* Verifies manifests as late as possible to avoid wasting time. */
int rhizome_suggest_queue_manifest_import(rhizome_manifest *m, struct sockaddr_in *peerip)
{
  IN();
  /* must free manifest when done with it */
  char *id = rhizome_manifest_get(m, "id", NULL, 0);
  int priority=100; /* normal priority */

  if (debug & DEBUG_RHIZOME_RX)
    DEBUGF("Considering manifest import bid=%s version=%lld size=%lld priority=%d:", id, m->version, m->fileLength, priority);

  if (rhizome_manifest_version_cache_lookup(m)) {
    if (debug & DEBUG_RHIZOME_RX)
      DEBUG("   already have that version or newer");
    rhizome_manifest_free(m);
    RETURN(-1);
  }

  if (debug & DEBUG_RHIZOME_RX) {
    long long stored_version;
    if (sqlite_exec_int64(&stored_version, "select version from manifests where id='%s'",id) > 0)
      DEBUGF("   is new (have version %lld)", stored_version);
  }

  if (m->fileLength == 0) {
    if (rhizome_manifest_verify(m) != 0) {
      WHY("Error verifying manifest when considering for import");
      /* Don't waste time looking at this manifest again for a while */
      rhizome_queue_ignore_manifest(m, peerip, 60000);
      rhizome_manifest_free(m);
      RETURN(-1);
    }
    rhizome_import_received_bundle(m);
    RETURN(0);
  }

  /* work out where to put it in the list */
  int i;
  for(i=0;i<candidate_count;i++)
    {
      /* If this manifest is already in the list, stop.
         (also replace older manifest versions with newer ones,
          which can upset the ordering.) */
      if (candidates[i].manifest==NULL) continue;
      if (!strcasecmp(id,rhizome_manifest_get(candidates[i].manifest,"id",NULL,0)))
	  {
	    /* duplicate.
	       XXX - Check versions! We should replace older with newer,
	       and then update position in queue based on size */
	  long long list_version = rhizome_manifest_get_ll(candidates[i].manifest, "version");
	  if (list_version >= m->version) {
	    /* this version is older than the one in the list, so don't list this one */
	    rhizome_manifest_free(m);
	    RETURN(0); 
	  } else {
	    /* replace listed version with this newer version */
	    if (rhizome_manifest_verify(m)) {
	      WHY("Error verifying manifest when considering queuing for import");
	      /* Don't waste time looking at this manifest again for a while */
	      rhizome_queue_ignore_manifest(m,peerip,60000);
	      rhizome_manifest_free(m);
	      RETURN(-1);
	    }

	    rhizome_manifest_free(candidates[i].manifest);
	    candidates[i].manifest=m;
	    /* update position in list */
	    rhizome_position_candidate(i);
	    RETURN(0);
	  }
	}

      /* if we have a higher priority file than the one at this
	 point in the list, stop, and we will shuffle the rest of
	 the list down. */
      if (candidates[i].priority>priority
	  ||(candidates[i].priority==priority
	     &&candidates[i].size>m->fileLength))
	break;
    }
  if (i>=MAX_CANDIDATES) {
    /* our list is already full of higher-priority items */
    rhizome_manifest_free(m);
    RETURN(-1);
  }

  if (rhizome_manifest_verify(m)) {
    WHY("Error verifying manifest when considering queuing for import");
    /* Don't waste time looking at this manifest again for a while */
    rhizome_queue_ignore_manifest(m,peerip,60000);
    rhizome_manifest_free(m);
    RETURN(-1);
  }

  if (candidate_count==MAX_CANDIDATES) {
    /* release manifest structure for whoever we are bumping from the list */
    rhizome_manifest_free(candidates[MAX_CANDIDATES-1].manifest);
    candidates[MAX_CANDIDATES-1].manifest=NULL;
  } else candidate_count++;
  /* shuffle down */
  int bytes=(candidate_count-(i+1))*sizeof(rhizome_candidates);
  if (0) DEBUGF("Moving slot %d to slot %d (%d bytes = %d slots)",
	      i,i+1,bytes,bytes/sizeof(rhizome_candidates));
  bcopy(&candidates[i],
	&candidates[i+1],
	bytes);
  /* put new candidate in */
  candidates[i].manifest=m;
  candidates[i].size=m->fileLength;
  candidates[i].priority=priority;
  candidates[i].peer=*peerip;

  int j;
  if (0) {
    DEBUG("Rhizome priorities fetch list now:");
    for(j=0;j<candidate_count;j++)
      DEBUGF("%02d:%s:size=%lld, priority=%d",
	   j,
	   rhizome_manifest_get(candidates[j].manifest,"id",NULL,0),
	   candidates[j].size,candidates[j].priority);
  }

  RETURN(0);
}

void rhizome_enqueue_suggestions(struct sched_ent *alarm)
{
  int i;
  for(i=0;i<candidate_count;i++)
    {
      if (rhizome_file_fetch_queue_count>=MAX_QUEUED_FILES) 
	break;
      int manifest_kept = 0;
      rhizome_queue_manifest_import(candidates[i].manifest,&candidates[i].peer, &manifest_kept);
      if (!manifest_kept) {
	rhizome_manifest_free(candidates[i].manifest);
	candidates[i].manifest = NULL;
      }
    }
  if (i) {
    /* now shuffle up */
    int bytes=(candidate_count-i)*sizeof(rhizome_candidates);
    if (0) DEBUGF("Moving slot %d to slot 0 (%d bytes = %d slots)",
		i,bytes,bytes/sizeof(rhizome_candidates));
    bcopy(&candidates[i],&candidates[0],bytes);
    candidate_count-=i;
  }
  alarm->alarm = gettime_ms() + rhizome_fetch_interval_ms;
  alarm->deadline = alarm->alarm + rhizome_fetch_interval_ms*3;
  schedule(alarm);
  return;
}

int rhizome_queue_manifest_import(rhizome_manifest *m, struct sockaddr_in *peerip, int *manifest_kept)
{
  *manifest_kept = 0;

  const char *bid = alloca_tohex_bid(m->cryptoSignPublic);
  long long filesize = rhizome_manifest_get_ll(m, "filesize");

  /* Do the quick rejection tests first, before the more expensive once,
     like querying the database for manifests. 

     We probably need a cache of recently rejected manifestid:versionid
     pairs so that we can avoid database lookups in most cases.  Probably
     the first 64bits of manifestid is sufficient to make it resistant to
     collission attacks, but using 128bits or the full 256 bits would be safer.
     Let's make the cache use 256 bit (32byte) entries for power of two
     efficiency, and so use the last 64bits for version id, thus using 192 bits
     for collission avoidance --- probably sufficient for many years yet (from
     time of writing in 2012).  We get a little more than 192 bits by using
     the cache slot number to implicitly store the first bits.
  */

  if (debug & DEBUG_RHIZOME_RX)
    DEBUGF("Fetching manifest bid=%s version=%lld size=%lld:", bid, m->version, filesize);

  if (rhizome_manifest_version_cache_lookup(m)) {
    /* We already have this version or newer */
    if (debug & DEBUG_RHIZOME_RX)
      DEBUG("   already have that version or newer");
    return 1;
  }
  if (debug & DEBUG_RHIZOME_RX)
    DEBUGF("   is new");

  /* Don't queue if queue slots already full */
  if (rhizome_file_fetch_queue_count >= MAX_QUEUED_FILES) {
    if (debug & DEBUG_RHIZOME_RX)
      DEBUG("   all fetch queue slots full");
    return 2;
  }

  /* Don't queue if already queued */
  int i;
  for (i = 0; i < rhizome_file_fetch_queue_count; ++i) {
    if (memcmp(m->cryptoSignPublic, file_fetch_queue[i].manifest->cryptoSignPublic, RHIZOME_MANIFEST_ID_BYTES) == 0) {
      if (debug & DEBUG_RHIZOME_RX)
	DEBUGF("   manifest fetch already queued");
      return 3;
    }
  }

  if (!rhizome_manifest_get(m, "filehash", m->fileHexHash, sizeof m->fileHexHash))
    return WHY("Manifest missing filehash");
  if (!rhizome_str_is_file_hash(m->fileHexHash))
    return WHYF("Invalid file hash: %s", m->fileHexHash);
  str_toupper_inplace(m->fileHexHash);
  m->fileHashedP = 1;

  if (filesize > 0 && m->fileHexHash[0]) {
    if (debug & DEBUG_RHIZOME_RX) 
      DEBUGF("   Getting ready to fetch filehash=%s for bid=%s", m->fileHexHash, bid);

    long long gotfile = 0;
    if (sqlite_exec_int64(&gotfile, "SELECT COUNT(*) FROM FILES WHERE ID='%s' and datavalid=1;", m->fileHexHash) != 1)
      return WHY("select failed");
    if (gotfile == 0) {
      /* We need to get the file, unless already queued */
      int i;
      for (i = 0; i < rhizome_file_fetch_queue_count; ++i) {
	if (strcasecmp(m->fileHexHash, file_fetch_queue[i].fileid) == 0) {
	  if (debug & DEBUG_RHIZOME_RX)
	    DEBUGF("Payload fetch already queued, slot %d filehash=%s", m->fileHexHash);
	  return 0;
	}
      }

      if (peerip) {
	/* Transfer via HTTP over IPv4 */
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1)
	  return WHY_perror("socket");
	if (set_nonblock(sock) == -1) {
	  close(sock);
	  return -1;
	}
	struct sockaddr_in addr = *peerip;
	addr.sin_family = AF_INET;
	INFOF("HTTP CONNECT family=%u port=%u addr=%u.%u.%u.%u",
	    addr.sin_family, ntohs(addr.sin_port),
	    ((unsigned char*)&addr.sin_addr.s_addr)[0],
	    ((unsigned char*)&addr.sin_addr.s_addr)[1],
	    ((unsigned char*)&addr.sin_addr.s_addr)[2],
	    ((unsigned char*)&addr.sin_addr.s_addr)[3]
	  );
	if (connect(sock, (struct sockaddr*)&addr, sizeof addr) == -1) {
	  if (errno == EINPROGRESS) {
	    if (debug & DEBUG_RHIZOME_RX)
	      DEBUGF("connect() returned EINPROGRESS");
	  } else {
	    WHY_perror("connect");
	    WHY("Failed to open socket to peer's rhizome web server");
	    close(sock);
	    return -1;
	  }
	}
	rhizome_file_fetch_record *q=&file_fetch_queue[rhizome_file_fetch_queue_count];
	q->manifest = m;
	*manifest_kept = 1;
	q->alarm.poll.fd=sock;
	strncpy(q->fileid, m->fileHexHash, RHIZOME_FILEHASH_STRLEN + 1);
	snprintf(q->request,1024,"GET /rhizome/file/%s HTTP/1.0\r\n\r\n", q->fileid);
	q->request_len=strlen(q->request);
	q->request_ofs=0;
	q->state=RHIZOME_FETCH_CONNECTING;
	q->file_len=-1;
	q->file_ofs=0;

	/* XXX Don't forget to implement resume */
	/* XXX We should stream file straight into the database */
	const char *id = rhizome_manifest_get(q->manifest, "id", NULL, 0);
	if (id == NULL) {
	  close(sock);
	  return WHY("Manifest missing ID");
	}
	if (create_rhizome_import_dir() == -1)
	  return -1;
	char filename[1024];
	if (!FORM_RHIZOME_IMPORT_PATH(filename, "file.%s", id)) {
	  close(sock);
	  return -1;
	}
	q->manifest->dataFileName = strdup(filename);
	if ((q->file = fopen(q->manifest->dataFileName, "w")) == NULL) {
	  WHY_perror("fopen");
	  if (debug & DEBUG_RHIZOME_RX)
	    DEBUGF("Could not open '%s' to write received file", q->manifest->dataFileName);
	  close(sock);
	  return -1;
	}
	
	/* Watch for activity on the socket */
	q->alarm.function=rhizome_fetch_poll;
	fetch_stats.name="rhizome_fetch_poll";
	q->alarm.stats=&fetch_stats;
	q->alarm.poll.events=POLLIN|POLLOUT;
	watch(&q->alarm);
	/* And schedule a timeout alarm */
	q->alarm.alarm=gettime_ms() + RHIZOME_IDLE_TIMEOUT;
	q->alarm.deadline = q->alarm.alarm + RHIZOME_IDLE_TIMEOUT;

	schedule(&q->alarm);

	rhizome_file_fetch_queue_count++;
	if (debug & DEBUG_RHIZOME_RX)
	  DEBUGF("Queued file for fetching into %s (%d in queue)",
	      q->manifest->dataFileName, rhizome_file_fetch_queue_count);
	return 0;
      } else {
	/* TODO: fetch via overlay */
	return WHY("Rhizome fetching via overlay not implemented");
      }
    }
    else
      {
	if (debug & DEBUG_RHIZOME_RX) 
	  DEBUGF("We already have the file for this manifest; importing from manifest alone.");
	if (create_rhizome_import_dir() == -1)
	  return -1;
	char filename[1024];
	if (!FORM_RHIZOME_IMPORT_PATH(filename, "manifest.%s", bid))
	  return -1;
	if (!rhizome_write_manifest_file(m, filename)) {
	  rhizome_bundle_import(m, NULL, bid, m->ttl-1);
	}
      }
  }

  return 0;
}

int rhizome_fetch_close(rhizome_file_fetch_record *q){
  /* Free ephemeral data */
  if (q->file) fclose(q->file);
  q->file=NULL;
  if (q->manifest) 
    rhizome_manifest_free(q->manifest);
  q->manifest=NULL;
  
  /* close socket and stop watching it */
  unwatch(&q->alarm);
  unschedule(&q->alarm);
  close(q->alarm.poll.fd);
  q->alarm.poll.fd=-1;
  
  /* Reduce count of open connections */	
  rhizome_file_fetch_queue_count--;
  
  if (debug & DEBUG_RHIZOME_RX) 
    DEBUGF("Released rhizome fetch slot (%d used)", rhizome_file_fetch_queue_count);
  return 0;
}

void rhizome_fetch_write(rhizome_file_fetch_record *q){
  int bytes = write_nonblock(q->alarm.poll.fd, &q->request[q->request_ofs], q->request_len-q->request_ofs);
  if (bytes == -1) {
    WHY("Got error while sending HTTP request.  Closing.");
    rhizome_fetch_close(q);
  } else {
    // reset timeout
    unschedule(&q->alarm);
    q->alarm.alarm=gettime_ms() + RHIZOME_IDLE_TIMEOUT;
    q->alarm.deadline = q->alarm.alarm + RHIZOME_IDLE_TIMEOUT;
    schedule(&q->alarm);
    q->request_ofs+=bytes;
    if (q->request_ofs>=q->request_len) {
      /* Sent all of request.  Switch to listening for HTTP response headers.
       */
      q->request_len=0; q->request_ofs=0;
      q->state=RHIZOME_FETCH_RXHTTPHEADERS;
      q->alarm.poll.events=POLLIN;
      watch(&q->alarm);
    }else if(q->state==RHIZOME_FETCH_CONNECTING)
      q->state = RHIZOME_FETCH_SENDINGHTTPREQUEST;
  }
}

void rhizome_write_content(rhizome_file_fetch_record *q, char *buffer, int bytes){
  
  if (bytes>(q->file_len-q->file_ofs))
    bytes=q->file_len-q->file_ofs;
  if (fwrite(buffer,bytes,1,q->file)!=1)
  {
    if (debug & DEBUG_RHIZOME_RX)
      DEBUGF("Failed to write %d bytes to file @ offset %d", bytes, q->file_ofs);
    rhizome_fetch_close(q);
    return;
  }
  q->file_ofs+=bytes;
  
  if (q->file_ofs>=q->file_len)
  {
    /* got all of file */
    if (debug & DEBUG_RHIZOME_RX)
      DEBUGF("Received all of file via rhizome -- now to import it");
    fclose(q->file);
    q->file = NULL;
    rhizome_import_received_bundle(q->manifest);
    rhizome_manifest_free(q->manifest);
    q->manifest = NULL;
    rhizome_fetch_close(q);
    return;
  }
  
  // reset timeout due to activity
  unschedule(&q->alarm);
  q->alarm.alarm=gettime_ms() + RHIZOME_IDLE_TIMEOUT;
  q->alarm.deadline = q->alarm.alarm+RHIZOME_IDLE_TIMEOUT;
  schedule(&q->alarm);
}

void rhizome_fetch_poll(struct sched_ent *alarm)
{
  rhizome_file_fetch_record *q=(rhizome_file_fetch_record *)alarm;
  
  if (alarm->poll.revents==0){
    // timeout, close the socket
    rhizome_fetch_close(q);
    return;
  }
  
  switch(q->state) {
    case RHIZOME_FETCH_CONNECTING:
    case RHIZOME_FETCH_SENDINGHTTPREQUEST:
      rhizome_fetch_write(q);
      break;
    case RHIZOME_FETCH_RXFILE: {
	/* Keep reading until we have the promised amount of data */
	char buffer[8192];
	sigPipeFlag = 0;
	int bytes = read_nonblock(q->alarm.poll.fd, buffer, sizeof buffer);
	/* If we got some data, see if we have found the end of the HTTP request */
	if (bytes > 0) {
	  rhizome_write_content(q, buffer, bytes);
	} else {
	  if (debug & DEBUG_RHIZOME_RX)
	    DEBUG("Empty read, closing connection");
	  rhizome_fetch_close(q);
	  return;
	}
	if (sigPipeFlag) {
	  if (debug & DEBUG_RHIZOME_RX)
	    DEBUG("Received SIGPIPE, closing connection");
	  rhizome_fetch_close(q);
	  return;
	}
      }
      break;
    case RHIZOME_FETCH_RXHTTPHEADERS: {
	/* Keep reading until we have two CR/LFs in a row */
	sigPipeFlag = 0;
	int bytes = read_nonblock(q->alarm.poll.fd, &q->request[q->request_len], 1024 - q->request_len - 1);
	/* If we got some data, see if we have found the end of the HTTP reply */
	if (bytes > 0) {
	  // reset timeout
	  unschedule(&q->alarm);
	  q->alarm.alarm = gettime_ms() + RHIZOME_IDLE_TIMEOUT;
	  q->alarm.deadline = q->alarm.alarm + RHIZOME_IDLE_TIMEOUT;
	  schedule(&q->alarm);
	  q->request_len += bytes;
	  if (http_header_complete(q->request, q->request_len, bytes + 4)) {
	    if (debug & DEBUG_RHIZOME_RX)
	      DEBUGF("Got HTTP reply: %s", alloca_toprint(160, q->request, q->request_len));
	    /* We have all the reply headers, so parse them, taking care of any following bytes of
	      content. */
	    char *p = NULL;
	    if (!str_startswith(q->request, "HTTP/1.0 ", &p)) {
	      if (debug&DEBUG_RHIZOME_RX)
		DEBUGF("Malformed HTTP reply: missing HTTP/1.0 preamble");
	      rhizome_fetch_close(q);
	      return;
	    }
	    int http_response_code = 0;
	    char *nump;
	    for (nump = p; isdigit(*p); ++p)
	      http_response_code = http_response_code * 10 + *p - '0';
	    if (p == nump || *p != ' ') {
	      if (debug&DEBUG_RHIZOME_RX)
		DEBUGF("Malformed HTTP reply: missing decimal status code");
	      rhizome_fetch_close(q);
	      return;
	    }
	    if (http_response_code != 200) {
	      if (debug & DEBUG_RHIZOME_RX)
		DEBUGF("Failed HTTP request: rhizome server returned %d != 200 OK", http_response_code);
	      rhizome_fetch_close(q);
	      return;
	    }
	    // This loop will terminate, because http_header_complete() above found at least
	    // "\n\n" at the end of the header, and probably "\r\n\r\n".
	    while (*p++ != '\n')
	      ;
	    // Iterate over header lines until the last blank line.
	    long long content_length = -1;
	    while (*p != '\r' && *p != '\n') {
	      if (strcase_startswith(p, "Content-Length:", &p)) {
		while (*p == ' ')
		  ++p;
		content_length = 0;
		for (nump = p; isdigit(*p); ++p)
		  content_length = content_length * 10 + *p - '0';
		if (p == nump || (*p != '\r' && *p != '\n')) {
		  if (debug & DEBUG_RHIZOME_RX)  {
		    DEBUGF("Invalid HTTP reply: malformed Content-Length header");
		    rhizome_fetch_close(q);
		    return;
		  }
		}
	      }
	      while (*p++ != '\n')
		;
	    }
	    if (*p == '\r')
	      ++p;
	    ++p; // skip '\n' at end of blank line
	    if (content_length == -1) {
	      if (debug & DEBUG_RHIZOME_RX)
		DEBUGF("Invalid HTTP reply: missing Content-Length header");
	      rhizome_fetch_close(q);
	      return;
	    }
	    q->file_len = content_length;
	    /* We have all we need.  The file is already open, so just write out any initial bytes of
	      the body we read.
	    */
	    q->state = RHIZOME_FETCH_RXFILE;
	    int content_bytes = q->request + q->request_len - p;
	    if (content_bytes > 0)
	      rhizome_write_content(q, p, content_bytes);
	  }
	} else {
	  if (debug & DEBUG_RHIZOME_RX)
	    DEBUG("Empty read, closing connection");
	  rhizome_fetch_close(q);
	  return;
	}
	if (sigPipeFlag) {
	  if (debug & DEBUG_RHIZOME_RX)
	    DEBUG("Received SIGPIPE, closing connection");
	  rhizome_fetch_close(q);
	  return;
	}
      }
      break;
    default:
      if (debug & DEBUG_RHIZOME_RX) 
	DEBUG("Closing rhizome fetch connection due to illegal/unimplemented state.");
      rhizome_fetch_close(q);
      return;
    }
  return;
}
