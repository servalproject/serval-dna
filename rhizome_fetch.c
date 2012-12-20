/*
Serval Distributed Numbering Architecture (DNA)
Copyright (C) 2012 Serval Project, Inc.
 
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
#include <arpa/inet.h>
#include <assert.h>
#include "serval.h"
#include "conf.h"
#include "rhizome.h"
#include "str.h"
#include "strbuf_helpers.h"
#include "overlay_address.h"

/* Represents a queued fetch of a bundle payload, for which the manifest is already known.
 */
struct rhizome_fetch_candidate {
  rhizome_manifest *manifest;

  /* Address of node offering manifest.
     Can be either IP+port for HTTP or it can be a SID 
     for MDP. */
  struct sockaddr_in peer_ipandport;
  unsigned char peer_sid[SID_SIZE];

  int priority;
};

/* Represents an active fetch (in progress) of a bundle payload (.manifest != NULL) or of a bundle
 * manifest (.manifest == NULL).
 */
struct rhizome_fetch_slot {
  struct sched_ent alarm; // must be first element in struct
  rhizome_manifest *manifest;

  struct sockaddr_in peer_ipandport;
  unsigned char peer_sid[SID_SIZE];

  int state;
#define RHIZOME_FETCH_FREE 0
#define RHIZOME_FETCH_CONNECTING 1
#define RHIZOME_FETCH_SENDINGHTTPREQUEST 2
#define RHIZOME_FETCH_RXHTTPHEADERS 3
#define RHIZOME_FETCH_RXFILE 4
#define RHIZOME_FETCH_RXFILEMDP 5

  /* Keep track of how much of the file we have read */
  SHA512_CTX sha512_context;
  int64_t rowid;
  int64_t file_len;
  int64_t file_ofs;

  int64_t last_write_time;
  int64_t start_time;

#define RHIZOME_BLOB_BUFFER_MAXIMUM_SIZE (1024*1024)
  int blob_buffer_size;
  unsigned char *blob_buffer;
  int blob_buffer_bytes;

  /* HTTP transport specific elements */
  char request[1024];
  int request_len;
  int request_ofs;

  /* HTTP streaming reception of manifests */
  char manifest_buffer[1024];
  int manifest_bytes;

  /* MDP transport specific elements */
  unsigned char bid[RHIZOME_MANIFEST_ID_BYTES];
  int64_t bidVersion;
  int bidP;
  unsigned char prefix[RHIZOME_MANIFEST_ID_BYTES];
  int prefix_length;
  int mdpIdleTimeout;
  int mdpResponsesOutstanding;
  int mdpRXBlockLength;
  uint32_t mdpRXBitmap;
  uint64_t mdpRequestFrontier;
  uint32_t mdpDuplicatePackets;
  short mdpRXdeferredPacketCount;
  // bitmap holds 32 entries, therefore only 31 can be out of order
  // at any point in time.
#define RHIZOME_MDP_MAX_DEFERRED_PACKETS 31
  unsigned char *mdpRXdeferredPackets[RHIZOME_MDP_MAX_DEFERRED_PACKETS];
  uint32_t mdpRXdeferredPacketStarts[RHIZOME_MDP_MAX_DEFERRED_PACKETS];
  unsigned short mdpRXdeferredPacketLengths[RHIZOME_MDP_MAX_DEFERRED_PACKETS];
  unsigned short mdpRXdeferredPacketTypes[RHIZOME_MDP_MAX_DEFERRED_PACKETS];
};

static int rhizome_fetch_switch_to_mdp(struct rhizome_fetch_slot *slot);
#define NONPIPELINE_REQUEST 0
#define PIPELINE_REQUEST 1
#define NO_BARRIER -1
static int rhizome_fetch_mdp_requestblocks(struct rhizome_fetch_slot *slot,
					   int pipelineRequest,int barrierAddress);
static int rhizome_fetch_mdp_requestmanifest(struct rhizome_fetch_slot *slot);

/* Represents a queue of fetch candidates and a single active fetch for bundle payloads whose size
 * is less than a given threshold.
 *
 * TODO: If the queues ever get much larger, use pointer-linked queue instead of physically ordered
 * in memory, to avoid the need for memory copies when deleting or inserting queue entries.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
struct rhizome_fetch_queue {
  struct rhizome_fetch_slot active; // must be first element in struct
  int candidate_queue_size;
  struct rhizome_fetch_candidate *candidate_queue;
  long long size_threshold; // will only hold fetches of fewer than this many bytes
};

/* Static allocation of the candidate queues.
 */
struct rhizome_fetch_candidate queue0[5];
struct rhizome_fetch_candidate queue1[4];
struct rhizome_fetch_candidate queue2[3];
struct rhizome_fetch_candidate queue3[2];
struct rhizome_fetch_candidate queue4[1];

#define NELS(a) (sizeof (a) / sizeof *(a))
#define slotno(slot) ((struct rhizome_fetch_queue *)(slot) - &rhizome_fetch_queues[0])

/* Static allocation of the queue structures.  Must be in order of ascending size_threshold.
 */
struct rhizome_fetch_queue rhizome_fetch_queues[] = {
  { .candidate_queue_size = NELS(queue0), .candidate_queue = queue0, .size_threshold =     10000, .active = { .state = RHIZOME_FETCH_FREE } },
  { .candidate_queue_size = NELS(queue1), .candidate_queue = queue1, .size_threshold =    100000, .active = { .state = RHIZOME_FETCH_FREE } },
  { .candidate_queue_size = NELS(queue2), .candidate_queue = queue2, .size_threshold =   1000000, .active = { .state = RHIZOME_FETCH_FREE } },
  { .candidate_queue_size = NELS(queue3), .candidate_queue = queue3, .size_threshold =  10000000, .active = { .state = RHIZOME_FETCH_FREE } },
  { .candidate_queue_size = NELS(queue4), .candidate_queue = queue4, .size_threshold =        -1, .active = { .state = RHIZOME_FETCH_FREE } }
};

#define NQUEUES	    NELS(rhizome_fetch_queues)

static struct sched_ent sched_activate = STRUCT_SCHED_ENT_UNUSED;
static struct profile_total fetch_stats;

/* Find a queue suitable for a fetch of the given number of bytes.  If there is no suitable queue,
 * return NULL.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static struct rhizome_fetch_queue *rhizome_find_queue(long long size)
{
  int i;
  for (i = 0; i < NQUEUES; ++i) {
    struct rhizome_fetch_queue *q = &rhizome_fetch_queues[i];
    if (q->size_threshold < 0 || size < q->size_threshold)
      return q;
  }
  return NULL;
}

/* Find a free fetch slot suitable for fetching the given number of bytes.  This could be a slot in
 * any queue that would accept the candidate, ie, with a larger size threshold.  Returns NULL if
 * there is no suitable free slot.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static struct rhizome_fetch_slot *rhizome_find_fetch_slot(long long size)
{
  int i;
  for (i = 0; i < NQUEUES; ++i) {
    struct rhizome_fetch_queue *q = &rhizome_fetch_queues[i];
    if ((q->size_threshold < 0 || size < q->size_threshold) && q->active.state == RHIZOME_FETCH_FREE)
      return &q->active;
  }
  return NULL;
}

/* Insert a candidate into a given queue at a given position.  All candidates succeeding the given
 * position are copied backward in the queue to open up an empty element at the given position.  If
 * the queue was full, then the tail element is discarded, freeing the manifest it points to.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static struct rhizome_fetch_candidate *rhizome_fetch_insert(struct rhizome_fetch_queue *q, int i)
{
  struct rhizome_fetch_candidate * const c = &q->candidate_queue[i];
  struct rhizome_fetch_candidate * e = &q->candidate_queue[q->candidate_queue_size - 1];
  if (config.debug.rhizome_rx)
    DEBUGF("insert queue[%d] candidate[%d]", q - rhizome_fetch_queues, i);
  assert(i >= 0 && i < q->candidate_queue_size);
  assert(i == 0 || c[-1].manifest);
  if (e->manifest) // queue is full
    rhizome_manifest_free(e->manifest);
  else
    while (e > c && !e[-1].manifest)
      --e;
  for (; e > c; --e)
    e[0] = e[-1];
  assert(e == c);
  c->manifest = NULL;
  return c;
}

/* Remove the given candidate from a given queue.  If the element points to a manifest structure,
 * then frees the manifest.  All succeeding candidates are copied forward in the queue to close up
 * the gap, leaving an empty element at the tail of the queue.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static void rhizome_fetch_unqueue(struct rhizome_fetch_queue *q, int i)
{
  assert(i >= 0 && i < q->candidate_queue_size);
  struct rhizome_fetch_candidate *c = &q->candidate_queue[i];
  if (config.debug.rhizome_rx)
    DEBUGF("unqueue queue[%d] candidate[%d] manifest=%p", q - rhizome_fetch_queues, i, c->manifest);
  if (c->manifest) {
    rhizome_manifest_free(c->manifest);
    c->manifest = NULL;
  }
  struct rhizome_fetch_candidate *e = &q->candidate_queue[q->candidate_queue_size - 1];
  for (; c < e && c[1].manifest; ++c)
    c[0] = c[1];
  c->manifest = NULL;
}

/* Return true if there are any active fetches currently in progress.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int rhizome_any_fetch_active()
{
  int i;
  for (i = 0; i < NQUEUES; ++i)
    if (rhizome_fetch_queues[i].active.state != RHIZOME_FETCH_FREE)
      return 1;
  return 0;
}

/* Return true if there are any fetches queued.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int rhizome_any_fetch_queued()
{
  int i;
  for (i = 0; i < NQUEUES; ++i)
    if (rhizome_fetch_queues[i].candidate_queue[0].manifest)
      return 1;
  return 0;
}

/* As defined below uses 64KB */
#define RHIZOME_VERSION_CACHE_NYBLS 2 /* 256=2^8=2nybls */
#define RHIZOME_VERSION_CACHE_SHIFT 1
#define RHIZOME_VERSION_CACHE_SIZE 128
#define RHIZOME_VERSION_CACHE_ASSOCIATIVITY 16

struct rhizome_manifest_version_cache_slot {
  unsigned char idprefix[24];
  long long version;
};

struct rhizome_manifest_version_cache_slot rhizome_manifest_version_cache[RHIZOME_VERSION_CACHE_SIZE][RHIZOME_VERSION_CACHE_ASSOCIATIVITY];

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
  struct rhizome_manifest_version_cache_slot *entry
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
      struct rhizome_manifest_version_cache_slot *entry
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
	struct rhizome_manifest_version_cache_slot *entry = &rhizome_manifest_version_cache[bin][slot];
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
  struct sockaddr_in peer_ipandport;
  unsigned char peer_sid[SID_SIZE];
  time_ms_t timeout;
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

int rhizome_ignore_manifest_check(rhizome_manifest *m, const struct sockaddr_in *peerip,const unsigned char *peersid)
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

int rhizome_queue_ignore_manifest(rhizome_manifest *m, const struct sockaddr_in *peerip, const unsigned char peersid[SID_SIZE], int timeout)
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
	&ignored.bins[bin].m[slot].peer_ipandport,
	sizeof(struct sockaddr_in));
  bcopy(peersid,
	ignored.bins[bin].m[slot].peer_sid,
	SID_SIZE);
  return 0;

}

static int rhizome_import_received_bundle(struct rhizome_manifest *m)
{
  m->finalised = 1;
  m->manifest_bytes = m->manifest_all_bytes; // store the signatures too
  if (config.debug.rhizome_rx) {
    DEBUGF("manifest len=%d has %d signatories. Associated file = %lld bytes", 
	   m->manifest_bytes, m->sig_count,(long long)m->fileLength);
    dump("manifest", m->manifestdata, m->manifest_all_bytes);
  }
  return rhizome_bundle_import(m, m->ttl - 1 /* TTL */);
}

static int schedule_fetch(struct rhizome_fetch_slot *slot)
{
  int sock = -1;
  /* TODO Don't forget to implement resume */
  /* TODO We should stream file straight into the database */
  slot->start_time=gettime_ms();
  if (create_rhizome_import_dir() == -1)
    return -1;
  if (slot->manifest) {
    slot->file_len=slot->manifest->fileLength;
    slot->rowid=
      rhizome_database_create_blob_for(slot->manifest->fileHexHash,
				       slot->file_len,
				       RHIZOME_PRIORITY_DEFAULT);
    if (slot->rowid<0) {
      return WHYF_perror("Could not obtain rowid for blob for file '%s'",
		  alloca_tohex_sid(slot->bid));
    }
  } else {
    slot->rowid=-1;
  }

  slot->request_ofs = 0;
  slot->state = RHIZOME_FETCH_CONNECTING;
  slot->file_len = -1;
  slot->file_ofs = 0;
  slot->blob_buffer_bytes = 0;
  if (slot->blob_buffer) {
    free(slot->blob_buffer);
    slot->blob_buffer=NULL;
  }
  slot->blob_buffer_size=0;

  SHA512_Init(&slot->sha512_context);
    
  if (slot->peer_ipandport.sin_family == AF_INET && slot->peer_ipandport.sin_port) {
    /* Transfer via HTTP over IPv4 */
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
      WHY_perror("socket");
      goto bail_http;
    }
    if (set_nonblock(sock) == -1)
      goto bail_http;
    char buf[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &slot->peer_ipandport.sin_addr, buf, sizeof buf) == NULL) {
      buf[0] = '*';
      buf[1] = '\0';
    }
    if (connect(sock, (struct sockaddr*)&slot->peer_ipandport, 
		sizeof slot->peer_ipandport) == -1) {
      if (errno == EINPROGRESS) {
	if (config.debug.rhizome_rx)
	  DEBUGF("connect() returned EINPROGRESS");
      } else {
	WHYF_perror("connect(%d, %s:%u)", sock, buf, 
		    ntohs(slot->peer_ipandport.sin_port));
	goto bail_http;
      }
    }
    if (config.debug.rhizome_rx)
      DEBUGF("RHIZOME HTTP REQUEST family=%u addr=%s sid=%s port=%u %s",
	     slot->peer_ipandport.sin_family, 
	     alloca_tohex_sid(slot->peer_sid),
	     buf, ntohs(slot->peer_ipandport.sin_port), alloca_str_toprint(slot->request)
	);
    slot->alarm.poll.fd = sock;
    /* Watch for activity on the socket */
    slot->alarm.function = rhizome_fetch_poll;
    fetch_stats.name = "rhizome_fetch_poll";
    slot->alarm.stats = &fetch_stats;
    slot->alarm.poll.events = POLLIN|POLLOUT;
    watch(&slot->alarm);
    /* And schedule a timeout alarm */
    unschedule(&slot->alarm);
    slot->alarm.alarm = gettime_ms() + RHIZOME_IDLE_TIMEOUT;
    slot->alarm.deadline = slot->alarm.alarm + RHIZOME_IDLE_TIMEOUT;
    schedule(&slot->alarm);
    return 0;
  }

 bail_http:
    /* Fetch via overlay, either because no IP address was provided, or because
       the connection/attempt to fetch via HTTP failed. */
  slot->state=RHIZOME_FETCH_RXFILEMDP;
  rhizome_fetch_switch_to_mdp(slot);
  return 0;
}

/* Start fetching a bundle's payload ready for importing.
 *
 * Three main cases that can occur here:
 * 1) The manifest has a nil payload (filesize=0);
 * 2) The payload is already in the database; or
 * 3) The payload is not in the database.
 *
 * Cases (1) and (2) are more or less identical: the bundle can be imported into the database
 * immediately.  Case (3) requires the payload to be fetched from a remote node.
 *
 * First, obtain enough space in the database for the file.
 *
 * Second, work out how we are going to get the file.
 * - On an IPv4 WiFi network, HTTP can be used.  The IP address and port number are sent in the
 *   bundle advertisement packet.
 * - On a non-IPv4 WiFi network, HTTP is not an option, so MDP must be used.
 *
 * For efficiency, the MDP transfer protocol could allow multiple listeners to receive the payload
 * by eavesdropping on the transfer.  In contrast, sending the payload auth-crypted would detect
 * packet errors and hostile parties trying to inject false data into the transfer.
 *
 * Returns STARTED (0) if the fetch was started.
 * Returns IMPORTED if a fetch was not started because the payload is nil or already in the
 * Rhizome store, so the import was performed instead.
 * Returns SAMEPAYLOAD if a fetch of the same payload (file ID) is already active.
 * Returns SUPERSEDED if the fetch was not started because a newer version of the same bundle is
 * already present.
 * Returns SAMEBUNDLE if a fetch of the same bundle is already active.
 * Returns OLDERBUNDLE if a fetch of an older version of the same bundle is already active.
 * Returns NEWERBUNDLE if a fetch of a newer version of the same bundle is already active.
 * Returns SLOTBUSY if the given slot is currently being used for another fetch.
 * Returns -1 on error.
 *
 * In the STARTED case, the caller should not free the manifest because the fetch slot now has a
 * copy of the pointer, and the manifest will be freed once the fetch finishes or is terminated.  In
 * all other cases, the caller is responsible for freeing the manifest.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static enum rhizome_start_fetch_result
rhizome_fetch(struct rhizome_fetch_slot *slot, rhizome_manifest *m, const struct sockaddr_in *peerip,unsigned const char *peersid)
{
  if (slot->state != RHIZOME_FETCH_FREE)
    return SLOTBUSY;

  const char *bid = alloca_tohex_bid(m->cryptoSignPublic);

  /* Do the quick rejection tests first, before the more expensive ones,
     like querying the database for manifests.

     We probably need a cache of recently rejected manifestid:versionid
     pairs so that we can avoid database lookups in most cases.  Probably
     the first 64bits of manifestid is sufficient to make it resistant to
     collission attacks, but using 128bits or the full 256 bits would be safer.
     Let's make the cache use 256 bit (32byte) entries for power of two
     efficiency, and so use the last 64bits for version id, thus using 192 bits
     for collision avoidance --- probably sufficient for many years yet (from
     time of writing in 2012).  We get a little more than 192 bits by using
     the cache slot number to implicitly store the first bits.
  */

  if (config.debug.rhizome_rx)
    DEBUGF("Fetching bundle slot=%d bid=%s version=%lld size=%lld peerip=%s",
	slotno(slot),
	bid,
	m->version,
	m->fileLength,
	alloca_sockaddr(peerip)
      );

  // If the payload is empty, no need to fetch, so import now.
  if (m->fileLength == 0) {
    if (config.debug.rhizome_rx)
      DEBUGF("   manifest fetch not started -- nil payload, so importing instead");
    if (rhizome_import_received_bundle(m) == -1)
      return WHY("bundle import failed");
    return IMPORTED;
  }

  // If we already have this version or newer, do not fetch.
  if (rhizome_manifest_version_cache_lookup(m)) {
    if (config.debug.rhizome_rx)
      DEBUG("   fetch not started -- already have that version or newer");
    return SUPERSEDED;
  }
  if (config.debug.rhizome_rx)
    DEBUGF("   is new");

  /* Don't fetch if already in progress.  If a fetch of an older version is already in progress,
   * then this logic will let it run to completion before the fetch of the newer version is queued.
   * This avoids the problem of indefinite postponement of fetching if new versions are constantly
   * being published faster than we can fetch them.
   */
  int i;
  for (i = 0; i < NQUEUES; ++i) {
    struct rhizome_fetch_slot *as = &rhizome_fetch_queues[i].active;
    const rhizome_manifest *am = as->manifest;
    if (as->state != RHIZOME_FETCH_FREE && memcmp(m->cryptoSignPublic, am->cryptoSignPublic, RHIZOME_MANIFEST_ID_BYTES) == 0) {
      if (am->version < m->version) {
	if (config.debug.rhizome_rx)
	  DEBUGF("   fetch already in progress -- older version");
	return OLDERBUNDLE;
      } else if (am->version > m->version) {
	if (config.debug.rhizome_rx)
	  DEBUGF("   fetch already in progress -- newer version");
	return NEWERBUNDLE;
      } else {
	if (config.debug.rhizome_rx)
	  DEBUGF("   fetch already in progress -- same version");
	return SAMEBUNDLE;
      }
    }
  }

  if (!m->fileHashedP)
    return WHY("Manifest missing filehash");

  // If the payload is already available, no need to fetch, so import now.
  long long gotfile = 0;
  if (sqlite_exec_int64(&gotfile, "SELECT COUNT(*) FROM FILES WHERE ID='%s' and datavalid=1;", m->fileHexHash) != 1)
    return WHY("select failed");
  if (gotfile) {
    if (config.debug.rhizome_rx)
      DEBUGF("   fetch not started - payload already present, so importing instead");
    if (rhizome_add_manifest(m, m->ttl-1) == -1)
      return WHY("add manifest failed");
    return IMPORTED;
  }

  // Fetch the file, unless already queued.
  for (i = 0; i < NQUEUES; ++i) {
    struct rhizome_fetch_slot *s = &rhizome_fetch_queues[i].active;
    const rhizome_manifest *sm = s->manifest;
    if (s->state != RHIZOME_FETCH_FREE && strcasecmp(m->fileHexHash, sm->fileHexHash) == 0) {
      if (config.debug.rhizome_rx)
	DEBUGF("   fetch already in progress, slot=%d filehash=%s", i, m->fileHexHash);
      return SAMEPAYLOAD;
    }
  }

  // Start the fetch.
  //dump("peerip", peerip, sizeof *peerip);

  /* Prepare for fetching via HTTP */
  slot->peer_ipandport = *peerip;
  strbuf r = strbuf_local(slot->request, sizeof slot->request);
  strbuf_sprintf(r, "GET /rhizome/file/%s HTTP/1.0\r\n\r\n", m->fileHexHash);
  if (strbuf_overrun(r))
    return WHY("request overrun");
  slot->request_len = strbuf_len(r);

  /* Prepare for fetching via MDP */
  bcopy(peersid,slot->peer_sid,SID_SIZE);
  bcopy(m->cryptoSignPublic,slot->bid,RHIZOME_MANIFEST_ID_BYTES);
  slot->bidVersion=m->version;
  slot->bidP=1;

  /* Don't provide a filename, because we will stream the file straight into
     the database. */
  m->dataFileName = NULL;
  m->dataFileUnlinkOnFree = 0;
  slot->manifest = m;
  if (schedule_fetch(slot) == -1) {
    return -1;
  }
  if (config.debug.rhizome_rx) 
    DEBUGF("   started fetch bid %s version 0x%llx into %s, slot=%d filehash=%s", 
	   alloca_tohex_bid(slot->bid), slot->bidVersion, slot->manifest->dataFileName, slotno(slot), m->fileHexHash);
  return STARTED;
}

/* Returns STARTED (0) if the fetch was started.
 * Returns SLOTBUSY if there is no available fetch slot for performing the fetch.
 * Returns -1 on error.
 */
enum rhizome_start_fetch_result
rhizome_fetch_request_manifest_by_prefix(const struct sockaddr_in *peerip, 
					 const unsigned char peersid[SID_SIZE],
					 const unsigned char *prefix, size_t prefix_length)
{
  assert(peerip);
  struct rhizome_fetch_slot *slot = rhizome_find_fetch_slot(MAX_MANIFEST_BYTES);
  if (slot == NULL)
    return SLOTBUSY;

  /* Prepare for fetching via HTTP */
  slot->peer_ipandport = *peerip;
  slot->manifest = NULL;
  strbuf r = strbuf_local(slot->request, sizeof slot->request);
  strbuf_sprintf(r, "GET /rhizome/manifestbyprefix/%s HTTP/1.0\r\n\r\n", alloca_tohex(prefix, prefix_length));
  if (strbuf_overrun(r))
    return WHY("request overrun");
  slot->request_len = strbuf_len(r);

  /* Prepare for fetching via MDP */
  bcopy(peersid,slot->peer_sid,SID_SIZE);
  bcopy(prefix,slot->prefix,prefix_length);
  slot->prefix_length=prefix_length;
  slot->bidP=0;

  /* Don't stream into a file blob in the database, because it is a manifest.
     We do need to cache it in the slot structure, though, and then offer it
     for inserting into the database, but we can avoid the temporary file in
     the process. */
  slot->rowid=-1;
  slot->manifest_bytes=0;
  
  if (schedule_fetch(slot) == -1) {
    return -1;
  }
  return STARTED;
}

/* Activate the next fetch for the given slot.  This takes the next job from the head of the slot's
 * own queue.  If there is none, then takes jobs from other queues.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static void rhizome_start_next_queued_fetch(struct rhizome_fetch_slot *slot)
{
  struct rhizome_fetch_queue *q;
  for (q = (struct rhizome_fetch_queue *) slot; q >= rhizome_fetch_queues; --q) {
    int i = 0;
    struct rhizome_fetch_candidate *c;
    while (i < q->candidate_queue_size && (c = &q->candidate_queue[i])->manifest) {
      int result = rhizome_fetch(slot, c->manifest, &c->peer_ipandport,c->peer_sid);
      switch (result) {
      case SLOTBUSY:
	return;
      case STARTED:
	c->manifest = NULL;
	rhizome_fetch_unqueue(q, i);
	return;
      case IMPORTED:
      case SAMEBUNDLE:
      case SAMEPAYLOAD:
      case SUPERSEDED:
      case NEWERBUNDLE:
      default:
	// Discard the candidate fetch and loop to try the next in queue.
	rhizome_fetch_unqueue(q, i);
	break;
      case OLDERBUNDLE:
	// Do not un-queue, so that when the fetch of the older bundle finishes, we will start
	// fetching a newer one.
	++i;
	break;
      }
    }
  }
}

/* Called soon after any fetch candidate is queued, to start any queued fetches.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static void rhizome_start_next_queued_fetches(struct sched_ent *alarm)
{
  int i;
  for (i = 0; i < NQUEUES; ++i)
    rhizome_start_next_queued_fetch(&rhizome_fetch_queues[i].active);
}

/* Queue a fetch for the payload of the given manifest.  If 'peerip' is not NULL, then it is used as
 * the port and IP address of an HTTP server from which the fetch is performed.  Otherwise the fetch
 * is performed over MDP.
 *
 * If the fetch cannot be queued for any reason (error, queue full, no suitable queue) then the
 * manifest is freed and returns -1.  Otherwise, the pointer to the manifest is stored in the queue
 * entry and the manifest is freed when the fetch has completed or is abandoned for any reason.
 *
 * Verifies manifests as late as possible to avoid wasting time.
 *
 * This function does not activate any fetches, it just queues the fetch candidates and sets an
 * alarm that will trip as soon as there is no pending I/O, or at worst, in 500ms.  This allows a
 * full packet's worth of Rhizome advertisements to be processed, queued and prioritised before
 * deciding which fetches to perform first.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int rhizome_suggest_queue_manifest_import(rhizome_manifest *m, const struct sockaddr_in *peerip,const unsigned char peersid[SID_SIZE])
{
  IN();
  const char *bid = alloca_tohex_bid(m->cryptoSignPublic);
  int priority=100; /* normal priority */

  if (config.debug.rhizome_rx)
    DEBUGF("Considering import bid=%s version=%lld size=%lld priority=%d:", bid, m->version, m->fileLength, priority);

  if (rhizome_manifest_version_cache_lookup(m)) {
    if (config.debug.rhizome_rx)
      DEBUG("   already have that version or newer");
    rhizome_manifest_free(m);
    RETURN(-1);
  }

  if (config.debug.rhizome_rx) {
    long long stored_version;
    if (sqlite_exec_int64(&stored_version, "select version from manifests where id='%s'", bid) > 0)
      DEBUGF("   is new (have version %lld)", stored_version);
  }

  if (m->fileLength == 0) {
    if (rhizome_manifest_verify(m) != 0) {
      WHY("Error verifying manifest when considering for import");
      /* Don't waste time looking at this manifest again for a while */
      rhizome_queue_ignore_manifest(m, peerip, peersid, 60000);
      rhizome_manifest_free(m);
      RETURN(-1);
    }
    rhizome_import_received_bundle(m);
    RETURN(0);
  }

  // Find the proper queue for the payload.  If there is none suitable, it is an error.
  struct rhizome_fetch_queue *qi = rhizome_find_queue(m->fileLength);
  if (!qi) {
    WHYF("No suitable fetch queue for bundle size=%lld", m->fileLength);
    rhizome_manifest_free(m);
    RETURN(-1);
  }

  // Search all the queues for the same manifest (it could be in any queue because its payload size
  // may have changed between versions.) If a newer or the same version is already queued, then
  // ignore this one.  Otherwise, unqueue all older candidates.
  int ci = -1;
  int i, j;
  for (i = 0; i < NQUEUES; ++i) {
    struct rhizome_fetch_queue *q = &rhizome_fetch_queues[i];
    for (j = 0; j < q->candidate_queue_size; ) {
      struct rhizome_fetch_candidate *c = &q->candidate_queue[j];
      if (c->manifest) {
	if (memcmp(m->cryptoSignPublic, c->manifest->cryptoSignPublic, RHIZOME_MANIFEST_ID_BYTES) == 0) {
	  if (c->manifest->version >= m->version) {
	    rhizome_manifest_free(m);
	    RETURN(0);
	  }
	  if (!m->selfSigned && rhizome_manifest_verify(m)) {
	    WHY("Error verifying manifest when considering queuing for import");
	    /* Don't waste time looking at this manifest again for a while */
	    rhizome_queue_ignore_manifest(m, peerip, peersid, 60000);
	    rhizome_manifest_free(m);
	    RETURN(-1);
	  }
	  rhizome_fetch_unqueue(q, j);
	} else {
	  if (ci == -1 && q == qi && c->priority < priority)
	    ci = j;
	  ++j;
	}
      } else {
	if (ci == -1 && q == qi)
	  ci = j;
	break;
      }
    }
  }
  // No duplicate was found, so if no free queue place was found either then bail out.
  if (ci == -1) {
    rhizome_manifest_free(m);
    RETURN(1);
  }

  if (!m->selfSigned && rhizome_manifest_verify(m)) {
    WHY("Error verifying manifest when considering queuing for import");
    /* Don't waste time looking at this manifest again for a while */
    rhizome_queue_ignore_manifest(m, peerip, peersid, 60000);
    rhizome_manifest_free(m);
    RETURN(-1);
  }

  struct rhizome_fetch_candidate *c = rhizome_fetch_insert(qi, ci);
  c->manifest = m;
  c->priority = priority;
  c->peer_ipandport = *peerip;
  bcopy(peersid,c->peer_sid,SID_SIZE);

  if (config.debug.rhizome_rx) {
    DEBUG("Rhizome fetch queues:");
    int i, j;
    for (i = 0; i < NQUEUES; ++i) {
      struct rhizome_fetch_queue *q = &rhizome_fetch_queues[i];
      for (j = 0; j < q->candidate_queue_size; ++j) {
	struct rhizome_fetch_candidate *c = &q->candidate_queue[j];
	if (!c->manifest)
	  break;
	DEBUGF("%d:%d manifest=%p bid=%s priority=%d size=%lld", i, j,
	    c->manifest,
	    alloca_tohex_bid(c->manifest->cryptoSignPublic),
	    c->priority,
	    (long long) c->manifest->fileLength
	  );
      }
    }
  }

  if (!is_scheduled(&sched_activate)) {
    sched_activate.function = rhizome_start_next_queued_fetches;
    sched_activate.stats = NULL;
    sched_activate.alarm = gettime_ms() + rhizome_fetch_delay_ms();
    sched_activate.deadline = sched_activate.alarm + 5000;
    schedule(&sched_activate);
  }

  RETURN(0);
}

static int rhizome_fetch_close(struct rhizome_fetch_slot *slot)
{
  if (config.debug.rhizome_rx)
    DEBUGF("close Rhizome fetch slot=%d", slotno(slot));
  assert(slot->state != RHIZOME_FETCH_FREE);

  /* close socket and stop watching it */
  unschedule(&slot->alarm);
  if (slot->alarm.poll.fd>=0){
    unwatch(&slot->alarm);
    close(slot->alarm.poll.fd);
  }
  slot->alarm.poll.fd = -1;
  slot->alarm.function=NULL;

  /* Free ephemeral data */
  if (slot->manifest)
    rhizome_manifest_free(slot->manifest);
  slot->manifest = NULL;

  if (slot->blob_buffer) free(slot->blob_buffer);
  slot->blob_buffer=NULL;
  slot->blob_buffer_size=0;

  // free any deferred out-of-order packets
  int i;
  for(i=0;i<slot->mdpRXdeferredPacketCount;i++)
    {
      free(slot->mdpRXdeferredPackets[i]);
    }
  slot->mdpRXdeferredPacketCount=0;

  slot->file_ofs=0;
  slot->mdpRequestFrontier=0;

  // Release the fetch slot.
  slot->state = RHIZOME_FETCH_FREE;

  // Activate the next queued fetch that is eligible for this slot.  Try starting candidates from
  // all queues with the same or smaller size thresholds until the slot is taken.
  rhizome_start_next_queued_fetch(slot);

  return 0;
}

static void rhizome_fetch_mdp_slot_callback(struct sched_ent *alarm)
{
  struct rhizome_fetch_slot *slot=(struct rhizome_fetch_slot*)alarm;

  if (slot->state!=5) {
    DEBUGF("Stale alarm triggered on idle/reclaimed slot. Ignoring");
    unschedule(alarm);
    return;
  }

  long long now=gettime_ms();
  if (now-slot->last_write_time>slot->mdpIdleTimeout) {
    DEBUGF("MDP connection timed out: last RX %lldms ago",
	   now-slot->last_write_time);
    rhizome_queue_ignore_manifest(slot->manifest, 
				  &slot->peer_ipandport, slot->peer_sid, 60000);
    rhizome_fetch_close(slot);
    return;
  }
  if (config.debug.rhizome_rx)
    DEBUGF("Timeout waiting for blocks. Resending request for slot=0x%p",
	   slot);
  if (slot->bidP)
    rhizome_fetch_mdp_requestblocks(slot,NONPIPELINE_REQUEST,NO_BARRIER);
  else
    rhizome_fetch_mdp_requestmanifest(slot);
}

static int previousBarrierAddress=0;
static int rhizome_fetch_mdp_requestblocks(struct rhizome_fetch_slot *slot,
					   int pipelineRequest,int barrierAddress)
{
  IN();
  // only issue new requests after allowing enough time for them to be sent to us.
  // we automatically re-issue once we have received all packets in this
  // request also, so if there is no packet loss, we can go substantially
  // faster.  Optimising behaviour when there is no packet loss is an
  // outstanding task.
  
  overlay_mdp_frame mdp;

  if (0&&barrierAddress!=NO_BARRIER)
    DEBUGF("Requesting retransmission of dropped packets between 0x%x and 0x%x",
	   previousBarrierAddress,barrierAddress);

  bzero(&mdp,sizeof(mdp));
  bcopy(my_subscriber->sid,mdp.out.src.sid,SID_SIZE);
  mdp.out.src.port=MDP_PORT_RHIZOME_RESPONSE;
  bcopy(slot->peer_sid,mdp.out.dst.sid,SID_SIZE);
  mdp.out.dst.port=MDP_PORT_RHIZOME_REQUEST;
  mdp.out.ttl=1;
  mdp.packetTypeAndFlags=MDP_TX;

  mdp.out.queue=OQ_ORDINARY;
  mdp.out.payload_length=RHIZOME_MANIFEST_ID_BYTES+8+8+4+2;
  bcopy(slot->bid,&mdp.out.payload[0],RHIZOME_MANIFEST_ID_BYTES);

  // XXX Recalculate mdpRXbitmap taking into account any out-of-order packets we
  // have received.
  slot->mdpRXBitmap=0x0;
  int i;
  for(i=0;i<slot->mdpRXdeferredPacketCount;i++)
    {
      int start=slot->mdpRXdeferredPacketStarts[i];
      int length=slot->mdpRXdeferredPacketLengths[i];
      int start_slot=(start-slot->file_ofs)/slot->mdpRXBlockLength;
      if (start%slot->mdpRXBlockLength) start_slot++;
      int end_slot=(start-slot->file_ofs+length)/slot->mdpRXBlockLength;
      if (slot->mdpRXdeferredPacketTypes[i]=='T') end_slot++;
      if (0) DEBUGF("Deferred packet #%d @ 0x%x - 0x%x covers slots %d - %d",
		    i,start,start+length-1,start_slot,end_slot);
      assert(start_slot>0);
      if (start_slot>=0&&start_slot<=31&&end_slot>0&&end_slot<=32) {
	int j;
	for(j=start_slot;j<end_slot;j++)
	  slot->mdpRXBitmap|=(1<<(31-j));
      }
    }

  // When pipelining, just request new stuff
  int pipelineBlocks=0;
  if (pipelineRequest==PIPELINE_REQUEST) {
    if (0) DEBUGF("This is a pipeline request");
    for(i=0;i<32;i++) {
      if ((slot->file_ofs+i*slot->mdpRXBlockLength)<slot->mdpRequestFrontier)
	slot->mdpRXBitmap|=(1<<(31-i));
      else 
	pipelineBlocks++;
    }
  }
  // Don't request anything beyond the supplied address
  if (barrierAddress!=NO_BARRIER) {
    if (0) DEBUGF("Applying barrier address accept range 0x%x -- 0x%x",
		  previousBarrierAddress,barrierAddress);
    unsigned int barrierMask=0;
    for(i=0;i<32;i++) {
      unsigned int address=slot->file_ofs+i*slot->mdpRXBlockLength;
      if (address>=barrierAddress) barrierMask|=(1<<(31-i));
      if (address<previousBarrierAddress) barrierMask|=(1<<(31-i));
    }
    slot->mdpRXBitmap|=barrierMask;
    if (0) DEBUGF("barrier mask = 0x%08x",barrierMask);       
  }

  if (barrierAddress!=NO_BARRIER) previousBarrierAddress=barrierAddress;

  if (0)
    DEBUGF("slot %p: Request bitmap = 0x%08x, block_length=0x%x, offset=0x%x",
	   slot,slot->mdpRXBitmap,slot->mdpRXBlockLength,slot->file_ofs);
  if (slot->mdpRXBitmap==0xffffffff) {
    // Request ends up empty, so do nothing
    RETURN(0);
  }

  write_uint64(&mdp.out.payload[RHIZOME_MANIFEST_ID_BYTES],slot->bidVersion);
  write_uint64(&mdp.out.payload[RHIZOME_MANIFEST_ID_BYTES+8],slot->file_ofs);
  write_uint32(&mdp.out.payload[RHIZOME_MANIFEST_ID_BYTES+8+8],slot->mdpRXBitmap);
  write_uint16(&mdp.out.payload[RHIZOME_MANIFEST_ID_BYTES+8+8+4],slot->mdpRXBlockLength);  

  if (0)
    DEBUGF("src sid=%s, dst sid=%s, mdpRXWindowStart=0x%x",
	   alloca_tohex_sid(mdp.out.src.sid),alloca_tohex_sid(mdp.out.dst.sid),
	   slot->file_ofs);

  overlay_mdp_dispatch(&mdp,0 /* system generated */,NULL,0);
  
  // Work out how many packets we are expecting, so that we can continue
  // immediately when we have them all.
  if (pipelineRequest==NONPIPELINE_REQUEST) {
    slot->mdpResponsesOutstanding=32; 
    { int j; for(j=0;j<32;j++) if (slot->mdpRXBitmap&(1<<j)) 
				 slot->mdpResponsesOutstanding--; }
  } else {
    slot->mdpResponsesOutstanding+=pipelineBlocks;
  }

  // Work out furthest point we have requested
  if (slot->mdpRequestFrontier<slot->file_ofs+32*slot->mdpRXBlockLength)    
    slot->mdpRequestFrontier=slot->file_ofs+32*slot->mdpRXBlockLength;

  unschedule(&slot->alarm);
  slot->alarm.function = rhizome_fetch_mdp_slot_callback;
  // 266ms @ 1mbit (WiFi broadcast speed) = 32x1024 byte packets.
  // Scaling timeout to the number of packets being requested is smarter,
  // and certainly helps when faced with heavy packet loss.
  double ms_per_packet=1000.0*(slot->mdpRXBlockLength*8)/1000000.0;
  if (pipelineRequest==NONPIPELINE_REQUEST) {
    slot->alarm.alarm=gettime_ms()+ms_per_packet*slot->mdpResponsesOutstanding;
    slot->alarm.deadline=slot->alarm.alarm+500;
  } else {
    slot->alarm.alarm+=ms_per_packet*pipelineBlocks;
    slot->alarm.deadline+=ms_per_packet*pipelineBlocks;
  }
  slot->mdpIdleTimeout=gettime_ms()+RHIZOME_IDLE_TIMEOUT;

  schedule(&slot->alarm); 
  
  RETURN(0);
}

static int rhizome_fetch_mdp_requestmanifest(struct rhizome_fetch_slot *slot)
{
  if (slot->prefix_length<1||slot->prefix_length>32) {
    // invalid request
    WARNF("invalid MDP Rhizome request");
    return rhizome_fetch_close(slot);
  }

  if ((gettime_ms()-slot->last_write_time)>slot->mdpIdleTimeout) {
    // connection timed out
    DEBUGF("MDP connection timedout");
    rhizome_queue_ignore_manifest(slot->manifest, 
				  &slot->peer_ipandport, slot->peer_sid, 60000);
    return rhizome_fetch_close(slot);
  }
  
  overlay_mdp_frame mdp;

  bzero(&mdp,sizeof(mdp));
  assert(my_subscriber);
  assert(my_subscriber->sid);
  bcopy(my_subscriber->sid,mdp.out.src.sid,SID_SIZE);
  mdp.out.src.port=MDP_PORT_RHIZOME_RESPONSE;
  bcopy(slot->peer_sid,mdp.out.dst.sid,SID_SIZE);
  mdp.out.dst.port=MDP_PORT_RHIZOME_REQUEST;
  mdp.out.ttl=1;
  mdp.packetTypeAndFlags=MDP_TX;

  mdp.out.queue=OQ_ORDINARY;
  mdp.out.payload_length=slot->prefix_length;
  bcopy(slot->prefix,&mdp.out.payload[0],slot->prefix_length);

  overlay_mdp_dispatch(&mdp,0 /* system generated */,NULL,0);
  
  slot->alarm.function = rhizome_fetch_mdp_slot_callback;
  slot->alarm.alarm=gettime_ms()+100;
  slot->alarm.deadline=slot->alarm.alarm+500;
  schedule(&slot->alarm);

  return 0;
}

static int rhizome_fetch_switch_to_mdp(struct rhizome_fetch_slot *slot)
{
  /* In Rhizome Direct we use the same fetch slot system, but we aren't actually
     a running servald instance, so we cannot fall back to MDP.  This is detected
     by checking if we have a SID for this instance. If not, then we are not a
     running servald instance, and we shouldn't try to use MDP.

     Later on we could use MDP, but as a client of a running servald instance,
     or with a temporary generated SID, so that we don't end up with two
     instances with the same SID.
  */
  if (!my_subscriber) {
    DEBUGF("I don't have an identity, so we cannot fall back to MDP");
    return rhizome_fetch_close(slot);
  }

  if (config.debug.rhizome_rx)
    DEBUGF("Trying to switch to MDP for Rhizome fetch: slot=0x%p",slot);
  
  /* close socket and stop watching it */
  if (slot->alarm.poll.fd>=0) {
    unwatch(&slot->alarm);
    close(slot->alarm.poll.fd);
    slot->alarm.poll.fd = -1;
  }
  unschedule(&slot->alarm);

  /* Begin MDP fetch process.
     1. Send initial request.
     2. Set timeout for next request (if fetching a file).
     3. Set timeout for no traffic received.
  */

  slot->state=RHIZOME_FETCH_RXFILEMDP;

  slot->last_write_time=gettime_ms();
  if (slot->bidP) {
    /* We are requesting a file.  The http request may have already received
       some of the file, so take that into account when setting up ring buffer. 
       Then send the request for the next block of data, and set our alarm to
       re-ask in a little while. "In a little while" is 266ms, which is roughly
       the time it takes to send 32KB via WiFi broadcast at the 1Mbit base rate 
       (this will need tuning for non-WiFi interfaces). 32KB = 32 x 1024 bytes
       which is the block size we will use.  200bytes would allow for several
       blocks to fit into a packet, and probably fit at least one any any,
       outgoing packet that is not otherwise full. But then the whole thing slows
       down too much.  Much careful thought is required to optimise this
       transport.
    */
    slot->file_len=slot->manifest->fileLength;

    slot->mdpIdleTimeout=5000; // give up if nothing received for 5 seconds
    slot->mdpRXBitmap=0x00000000; // no blocks received yet
    slot->mdpRXBlockLength=1024;
    slot->mdpRequestFrontier=0;
    slot->mdpDuplicatePackets=0;

    rhizome_fetch_mdp_requestblocks(slot,NONPIPELINE_REQUEST,NO_BARRIER);
  } else {
    /* We are requesting a manifest, which is stateless, except that we eventually
       give up. All we need to do now is send the request, and set our alarm to
       try again in case we haven't heard anything back. */
    slot->mdpIdleTimeout=2000; // only try for two seconds
    rhizome_fetch_mdp_requestmanifest(slot);
  }

  return 0;
}

void rhizome_fetch_write(struct rhizome_fetch_slot *slot)
{
  if (config.debug.rhizome_rx)
    DEBUGF("write_nonblock(%d, %s)", slot->alarm.poll.fd, alloca_toprint(-1, &slot->request[slot->request_ofs], slot->request_len-slot->request_ofs));
  int bytes = write_nonblock(slot->alarm.poll.fd, &slot->request[slot->request_ofs], slot->request_len-slot->request_ofs);
  if (bytes == -1) {
    WHY("Got error while sending HTTP request.");
    rhizome_fetch_switch_to_mdp(slot);
    return;
  } else {
    // reset timeout
    unschedule(&slot->alarm);
    slot->alarm.alarm=gettime_ms() + RHIZOME_IDLE_TIMEOUT;
    slot->alarm.deadline = slot->alarm.alarm + RHIZOME_IDLE_TIMEOUT;
    schedule(&slot->alarm);
    slot->request_ofs+=bytes;
    if (slot->request_ofs>=slot->request_len) {
      /* Sent all of request.  Switch to listening for HTTP response headers.
       */
      slot->request_len=0; slot->request_ofs=0;
      slot->state=RHIZOME_FETCH_RXHTTPHEADERS;
      slot->alarm.poll.events=POLLIN;
      watch(&slot->alarm);
    }else if(slot->state==RHIZOME_FETCH_CONNECTING)
      slot->state = RHIZOME_FETCH_SENDINGHTTPREQUEST;
  }
}

int rhizome_fetch_flush_blob_buffer(struct rhizome_fetch_slot *slot)
{
  sqlite3_blob *blob;
  int ret = sqlite3_blob_open(rhizome_db, "main", "FILEBLOBS", "data", slot->rowid, 1 /* read/write */, &blob);
  if (ret!=SQLITE_OK) {
    if (blob) sqlite3_blob_close(blob);
    return -1;
  }
  ret=sqlite3_blob_write(blob, slot->blob_buffer, slot->blob_buffer_bytes, 
			 slot->file_ofs-slot->blob_buffer_bytes);
  sqlite3_blob_close(blob); blob=NULL;

  if (ret!=SQLITE_OK) {
    WHYF("sqlite3_blob_write(,,%d,%lld) failed, %s", 
	 slot->blob_buffer_bytes,slot->file_ofs-slot->blob_buffer_bytes,
	 sqlite3_errmsg(rhizome_db));
    rhizome_queue_ignore_manifest(slot->manifest, 
				  &slot->peer_ipandport, slot->peer_sid, 60000);
    rhizome_fetch_close(slot);
    return -1;
  }
  slot->blob_buffer_bytes=0;
  return 0;
}

int rhizome_write_content(struct rhizome_fetch_slot *slot, char *buffer, int bytes)
{
  IN();
  // Truncate to known length of file (handy for reading from journal bundles that
  // might grow while we are reading from them).
  if (bytes>(slot->file_len-slot->file_ofs))
    bytes=slot->file_len-slot->file_ofs;

  if (slot->rowid==-1) {
    /* We are reading a manifest.  Read it into a buffer. */
    int count=bytes;
    if (count+slot->manifest_bytes>1024) count=1024-slot->manifest_bytes;
    bcopy(buffer,&slot->manifest_buffer[slot->manifest_bytes],count);
    slot->manifest_bytes+=count;
    slot->file_ofs+=count;
  } else {
    /* We are reading a file. Stream it into the database. */  
    if (bytes>0)
      SHA512_Update(&slot->sha512_context,(unsigned char *)buffer,bytes);

    if (config.debug.rhizome_rx) {
      DEBUGF("slot->blob_buffer_bytes=%d, slot->file_ofs=%d",
	     slot->blob_buffer_bytes,slot->file_ofs);
      // dump("buffer",buffer,bytes);
    }

    if (!slot->blob_buffer_size) {
      /* Allocate an appropriately sized buffer so that we don't have to pay
	 the cost of blob_open() and blob_close() too often. */
      slot->blob_buffer_size=slot->file_len;
      if (slot->blob_buffer_size>RHIZOME_BLOB_BUFFER_MAXIMUM_SIZE)
	slot->blob_buffer_size=RHIZOME_BLOB_BUFFER_MAXIMUM_SIZE;
      slot->blob_buffer=malloc(slot->blob_buffer_size);
      assert(slot->blob_buffer);
    }

    assert(slot->blob_buffer_size);
    int bytesRemaining=bytes;
    while(bytesRemaining>0) {      
      int count=slot->blob_buffer_size-slot->blob_buffer_bytes;
      if (count>bytes) count=bytesRemaining;
      //      DEBUGF("copying %d bytes to &blob_buffer[0x%x]",
      //	     count,slot->blob_buffer_bytes);
      //      dump("buffer",buffer,count);
      bcopy(buffer,&slot->blob_buffer[slot->blob_buffer_bytes],count);
      //      dump("first bytes into slot->blob_buffer",slot->blob_buffer,256);
      slot->blob_buffer_bytes+=count;
      slot->file_ofs+=count;
      buffer+=count; bytesRemaining-=count;
      if (slot->blob_buffer_bytes==slot->blob_buffer_size)
	rhizome_fetch_flush_blob_buffer(slot);
    }
  }

  slot->last_write_time=gettime_ms();
  if (slot->file_ofs>=slot->file_len) {
    /* got all of file */
    if (config.debug.rhizome_rx)
      DEBUGF("Received all of file via rhizome -- now to import it");
    if (slot->manifest) {
      // Were fetching payload, now we have it.

      char hash_out[SHA512_DIGEST_STRING_LENGTH+1];
      SHA512_End(&slot->sha512_context, (char *)hash_out);      
      if (slot->blob_buffer_bytes) rhizome_fetch_flush_blob_buffer(slot);
      
      sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
      if (strcasecmp(hash_out,slot->manifest->fileHexHash)) {
	if (config.debug.rhizome_rx)
	  DEBUGF("Hash mismatch -- dropping row from table.");	
	WARNF("Expected hash=%s, got %s",
	       slot->manifest->fileHexHash,hash_out);
	sqlite_exec_void_retry(&retry,
			       "DELETE FROM FILEBLOBS WHERE rowid=%lld",slot->rowid);
	sqlite_exec_void_retry(&retry,
			       "DELETE FROM FILES WHERE id='%s'",
			       slot->manifest->fileHexHash);
	rhizome_queue_ignore_manifest(slot->manifest, 
				      &slot->peer_ipandport, slot->peer_sid, 60000);
	rhizome_fetch_close(slot);
	RETURN(-1);
      } else {
	int ret=sqlite_exec_void_retry(&retry,
				       "UPDATE FILES SET datavalid=1 WHERE id='%s'",
				       slot->manifest->fileHexHash);
	if (ret!=SQLITE_OK) 
	  if (config.debug.rhizome_rx)
	    DEBUGF("error marking row valid: %s",sqlite3_errmsg(rhizome_db));
      }

      if (!rhizome_import_received_bundle(slot->manifest)){
	if (slot->state==RHIZOME_FETCH_RXFILE) {
	  char buf[INET_ADDRSTRLEN];
	  if (inet_ntop(AF_INET, &slot->peer_ipandport.sin_addr, buf, sizeof buf) == NULL) {
	    buf[0] = '*';
	    buf[1] = '\0';
	  }
	  INFOF("Completed http request from %s:%u  for file %s",
		buf, ntohs(slot->peer_ipandport.sin_port), 
		slot->manifest->fileHexHash);
	} else {
	  INFOF("Completed MDP request from %s for file %s",
		alloca_tohex_sid(slot->peer_sid), slot->manifest->fileHexHash);
	}
	INFOF("Received %lld bytes in %lldms (%lldKB/sec), %d duplicate packets.",
	      (long long)slot->file_ofs,(long long)gettime_ms()-slot->start_time,
	      (long long)slot->file_ofs/(gettime_ms()-slot->start_time),
	      slot->mdpDuplicatePackets);
      }
    } else {
      /* This was to fetch the manifest, so now fetch the file if needed */
      if (config.debug.rhizome_rx)
	DEBUGF("Received a manifest in response to supplying a manifest prefix.");
      /* Read the manifest and add it to suggestion queue, then immediately
	 call schedule queued items. */
      rhizome_manifest *m = rhizome_new_manifest();
      if (m) {
	if (rhizome_read_manifest_file(m, slot->manifest_buffer, 
				       slot->manifest_bytes) == -1) {
	  DEBUGF("Couldn't read manifest");
	  rhizome_manifest_free(m);
	} else {
	  if (config.debug.rhizome_rx){
	    DEBUGF("All looks good for importing manifest id=%s", alloca_tohex_bid(m->cryptoSignPublic));
	    dump("slot->peerip",&slot->peer_ipandport,sizeof(slot->peer_ipandport));
	    dump("slot->peersid",&slot->peer_sid,sizeof(slot->peer_sid));
	  }
	  rhizome_suggest_queue_manifest_import(m, &slot->peer_ipandport,
						slot->peer_sid);
	}
      }
    }
    if (config.debug.rhizome_rx)
      DEBUGF("Closing rhizome fetch slot = 0x%p.  Received %lld bytes in %lldms (%lldKB/sec).  Buffer size = %d",
	     slot,(long long)slot->file_ofs,(long long)gettime_ms()-slot->start_time,
	     (long long)slot->file_ofs/(gettime_ms()-slot->start_time),
	     slot->blob_buffer_size);
    rhizome_fetch_close(slot);
    RETURN(-1);
  }

  // slot is still open
  RETURN(0);
}

int rhizome_received_content(unsigned char *sender_sid,
			     unsigned char *bidprefix,
			     uint64_t version, uint64_t offset,
			     int count,unsigned char *bytes,int type)
{
  IN();
  int i;
  if (config.debug.rhizome_mdp)
    DEBUGF("received data @ 0x%llx -- 0x%llx",offset,offset+count-1);
  for(i=0;i<NQUEUES;i++) {
    struct rhizome_fetch_slot *slot=&rhizome_fetch_queues[i].active;
    if (slot->state==RHIZOME_FETCH_RXFILEMDP&&slot->bidP) {
      // Make sure that this is a block for this slot, and that it is
      // from whoever we requested it from.  We check elsewhere that the
      // MDP packet was signed to make sure that noone can have substituted
      // an incorrect block.
      if ((!memcmp(slot->bid,bidprefix,16))
	  &&(!memcmp(slot->peer_sid,sender_sid,SID_SIZE)))
	{
	  // Whenever we receive a packet, we make sure that the timeout
	  // is deferred a bit, so that we make sure to drain all pending 
	  // packets in the sender's queue
	  long long new_alarm_time=gettime_ms()+75;
	  slot->mdpIdleTimeout=gettime_ms()+RHIZOME_IDLE_TIMEOUT;
	  if (slot->alarm.alarm<new_alarm_time
	      ||slot->alarm.deadline<new_alarm_time) {
	    unschedule(&slot->alarm);
	    slot->alarm.alarm=new_alarm_time;
	    if (slot->alarm.deadline<new_alarm_time)
	      slot->alarm.deadline = new_alarm_time;
	    slot->alarm.function = rhizome_fetch_poll;
	    schedule(&slot->alarm);
	  }

	  if (slot->file_ofs==offset) {
	    if (!rhizome_write_content(slot,(char *)bytes,count))
	      {		
		// Try flushing out stuck packets that we have kept due to
		// packet loss / out-of-order delivery.
		int i=0;
		while(i<slot->mdpRXdeferredPacketCount)
		  {
		    if (slot->mdpRXdeferredPacketStarts[i]==slot->file_ofs)
		      {
			// Get packet we are about to apply
			bytes=slot->mdpRXdeferredPackets[i];
			offset=slot->mdpRXdeferredPacketStarts[i];
			count=slot->mdpRXdeferredPacketLengths[i];
			type=slot->mdpRXdeferredPacketTypes[i];
			
			// Remove said packet from list
			int n=slot->mdpRXdeferredPacketCount-1;
			slot->mdpRXdeferredPackets[i]=slot->mdpRXdeferredPackets[n];
			slot->mdpRXdeferredPacketStarts[i]
			  =slot->mdpRXdeferredPacketStarts[n];
			slot->mdpRXdeferredPacketLengths[i]
			  =slot->mdpRXdeferredPacketLengths[n];
			slot->mdpRXdeferredPacketTypes[i]
			  =slot->mdpRXdeferredPacketTypes[n];
			slot->mdpRXdeferredPacketCount--;
			
			// now we can safely recursively call ourself
			// because we have finished fiddling with the list of 
			// deferred packets		  
			rhizome_received_content(slot->peer_sid,
						 bidprefix,
						 version,offset,
						 count,bytes,type);
			// Clean up
			free(bytes);

			// Start searching from beginning of list again
			i=0;
		      }
		    else
		      i++;		    
		  }

		// Then see if we need to ask for any more content.
		slot->mdpResponsesOutstanding--;
		if (slot->mdpResponsesOutstanding==0) {
		  // We have received all responses, so immediately ask for more
		  rhizome_fetch_mdp_requestblocks(slot,NONPIPELINE_REQUEST,
						  NO_BARRIER);		  
		} else {
		  // We have requests outstanding, so consider sending a pipeline
		  // request or re-request for skipped blocks
		  if (0)
		    DEBUGF("%d blocks outstanding. We have advanced 0x%x since last request.",
			   slot->mdpResponsesOutstanding,
			   slot->file_ofs-slot->mdpRequestFrontier
			   +32*slot->mdpRXBlockLength);
		  if ((slot->mdpRequestFrontier
		       -32*slot->mdpRXBlockLength
		       +8*slot->mdpRXBlockLength)
		      <slot->file_ofs) {
		    if (0) DEBUGF("Sending pipeline request.");
		    rhizome_fetch_mdp_requestblocks(slot,PIPELINE_REQUEST,
						    NO_BARRIER);
		  } 
		}
		  
	      }

	    RETURN(0);
	  } else {
	    // TODO: Implement out-of-order buffering so that lost packets
	    // don't cause wastage

	    // Rerequest any dropped packets prior to this one, that follow
	    // the previvous re-send request range
	    rhizome_fetch_mdp_requestblocks(slot,NONPIPELINE_REQUEST,
					    offset);		  


	    if (offset<slot->file_ofs) {
	      slot->mdpDuplicatePackets++;
	    } else if (offset>slot->file_ofs) {
	      int replacementSlot=-2;
	      int highestAddressSlot=slot->mdpRXdeferredPacketCount;
	      for(i=0;i<slot->mdpRXdeferredPacketCount;i++)
		{
		  if (slot->mdpRXdeferredPacketStarts[i]<slot->file_ofs) {
		    // possibly stale deferred packet
		    // (but check if there are any extra bytes we can commit first)
		  }
		  if (offset==slot->mdpRXdeferredPacketStarts[i])
		    {
		      // we seem to have this packet already.
		      slot->mdpDuplicatePackets++;
		      // (but check if there are any extra bytes we should remember)
		      if (count<=slot->mdpRXdeferredPacketLengths[i])
			replacementSlot=-1; // don't replace
		      else {
			replacementSlot=i; 
		      }
		      // either way, don't keep looking
		      break;
		    }
		  if (highestAddressSlot==slot->mdpRXdeferredPacketCount
		      ||slot->mdpRXdeferredPacketStarts[i]>
		      slot->mdpRXdeferredPacketStarts[highestAddressSlot])
		    highestAddressSlot=i;
		}
	      if (replacementSlot==-2) {
		if (slot->mdpRXdeferredPacketCount
		    >=RHIZOME_MDP_MAX_DEFERRED_PACKETS)
		  replacementSlot=highestAddressSlot;
		else
		  replacementSlot=slot->mdpRXdeferredPacketCount;
	      }
	      if (replacementSlot>=0)
		{
		  if (replacementSlot<slot->mdpRXdeferredPacketCount)
		    free(slot->mdpRXdeferredPackets[replacementSlot]);
		  slot->mdpRXdeferredPackets[replacementSlot]=malloc(count);
		  bcopy(bytes,slot->mdpRXdeferredPackets[replacementSlot],count);
		  slot->mdpRXdeferredPacketStarts[replacementSlot]=offset;
		  slot->mdpRXdeferredPacketLengths[replacementSlot]=count;
		  slot->mdpRXdeferredPacketTypes[replacementSlot]=type;
		  if (slot->mdpRXdeferredPacketCount<=replacementSlot)
		    slot->mdpRXdeferredPacketCount=replacementSlot+1;
		  if(0)
		  DEBUGF("Keeping out-of-order packet for 0x%llx -- 0x%llx (slot#%d)",
			 offset,offset+count-1,replacementSlot);
		}
	    }
	  }
	  RETURN(0);
	}
    }
  }  

  RETURN(-1);
}

void rhizome_fetch_poll(struct sched_ent *alarm)
{
  struct rhizome_fetch_slot *slot = (struct rhizome_fetch_slot *) alarm;

  if (alarm->poll.revents & (POLLIN | POLLOUT)) {
    switch (slot->state) {
    case RHIZOME_FETCH_CONNECTING:
    case RHIZOME_FETCH_SENDINGHTTPREQUEST:
      rhizome_fetch_write(slot);
      return;
    case RHIZOME_FETCH_RXFILE: {
      /* Keep reading until we have the promised amount of data */
      char buffer[8192];
      sigPipeFlag = 0;
      int bytes = read_nonblock(slot->alarm.poll.fd, buffer, sizeof buffer);
      /* If we got some data, see if we have found the end of the HTTP request */
      if (bytes > 0) {
	rhizome_write_content(slot, buffer, bytes);
	if (slot->state!=RHIZOME_FETCH_FREE) {
	  // reset inactivity timeout
	  // DEBUGF("Resetting inactivity timer");
	  unschedule(&slot->alarm);
	  slot->alarm.alarm=gettime_ms() + RHIZOME_IDLE_TIMEOUT;
	  slot->alarm.deadline = slot->alarm.alarm + RHIZOME_IDLE_TIMEOUT;
	  slot->alarm.function = rhizome_fetch_poll;
	  schedule(&slot->alarm);
	}
	return;
      } else {
	if (config.debug.rhizome_rx)
	  DEBUGF("Empty read, closing connection: received %lld of %lld bytes",
		 slot->file_ofs,slot->file_len);
	rhizome_fetch_switch_to_mdp(slot);
	return;
      }
      if (sigPipeFlag) {
	if (config.debug.rhizome_rx)
	  DEBUG("Received SIGPIPE, closing connection");
	rhizome_fetch_switch_to_mdp(slot);
	return;
      }
    }
      break;
    case RHIZOME_FETCH_RXHTTPHEADERS: {
      /* Keep reading until we have two CR/LFs in a row */
      sigPipeFlag = 0;
      int bytes = read_nonblock(slot->alarm.poll.fd, &slot->request[slot->request_len], 1024 - slot->request_len - 1);
      /* If we got some data, see if we have found the end of the HTTP reply */
      if (bytes > 0) {
	// reset timeout
	unschedule(&slot->alarm);
	slot->alarm.alarm = gettime_ms() + RHIZOME_IDLE_TIMEOUT;
	slot->alarm.deadline = slot->alarm.alarm + RHIZOME_IDLE_TIMEOUT;
	schedule(&slot->alarm);
	slot->request_len += bytes;
	if (http_header_complete(slot->request, slot->request_len, bytes)) {
	  if (config.debug.rhizome_rx)
	    DEBUGF("Got HTTP reply: %s", alloca_toprint(160, slot->request, slot->request_len));
	  /* We have all the reply headers, so parse them, taking care of any following bytes of
	     content. */
	  struct http_response_parts parts;
	  if (unpack_http_response(slot->request, &parts) == -1) {
	    if (config.debug.rhizome_rx)
	      DEBUGF("Failed HTTP request: failed to unpack http response");
	    rhizome_fetch_switch_to_mdp(slot);
	    return;
	  }
	  if (parts.code != 200) {
	    if (config.debug.rhizome_rx)
	      DEBUGF("Failed HTTP request: rhizome server returned %d != 200 OK", parts.code);
	    slot->file_ofs=0;
	    rhizome_fetch_switch_to_mdp(slot);
	    return;
	  }
	  if (parts.content_length == -1) {
	    if (config.debug.rhizome_rx)
	      DEBUGF("Invalid HTTP reply: missing Content-Length header");
	    rhizome_fetch_switch_to_mdp(slot);
	    return;
	  }
	  slot->file_len = parts.content_length;
	  /* We have all we need.  The file is already open, so just write out any initial bytes of
	     the body we read.
	  */
	  slot->state = RHIZOME_FETCH_RXFILE;
	  int content_bytes = slot->request + slot->request_len - parts.content_start;
	  if (content_bytes > 0){
	    rhizome_write_content(slot, parts.content_start, content_bytes);
	    if (slot->state!=RHIZOME_FETCH_FREE) {
	      // reset inactivity timeout
	      unschedule(&slot->alarm);
	      slot->alarm.alarm=gettime_ms() + RHIZOME_IDLE_TIMEOUT;
	      slot->alarm.deadline = slot->alarm.alarm + RHIZOME_IDLE_TIMEOUT;
	      slot->alarm.function = rhizome_fetch_poll;
	      schedule(&slot->alarm);
	    }
	    return;
	  }
	}
      }
      assert(slot->state!=RHIZOME_FETCH_FREE);
      break;
      default:
	WARNF("Closing rhizome fetch connection due to illegal/unimplemented state=%d.",slot->state);
	rhizome_queue_ignore_manifest(slot->manifest, 
				      &slot->peer_ipandport, slot->peer_sid, 60000);
	rhizome_fetch_close(slot);
	return;
    }
    }
  }
  if (alarm->poll.revents==0 || alarm->poll.revents & (POLLHUP | POLLERR)){
    // timeout or socket error, close the socket
    if (config.debug.rhizome_rx)
      DEBUGF("Closing due to timeout or error: events=%x (POLLHUP=%x POLLERR=%x)", alarm->poll.revents, POLLHUP, POLLERR);
    if (slot->state!=RHIZOME_FETCH_FREE)
      rhizome_queue_ignore_manifest(slot->manifest, 
				    &slot->peer_ipandport, slot->peer_sid, 60000);
      rhizome_fetch_close(slot);
  }
}

/*
   This function takes a pointer to a buffer into which the entire HTTP response header has been
   read.  The caller must have ensured that the buffer contains at least one consecutive pair of
   newlines '\n', optionally with carriage returns '\r' preceding and optionally interspersed with
   nul characters '\0' (which can originate from telnet).  The http_header_complete() function
   is useful for this.
   This returns pointers to within the supplied buffer, and may overwrite some characters in the
   buffer, for example to nul-terminate a string that was terminated by space ' ' or newline '\r'
   '\n' in the buffer.  For that reason, it takes char* not const char* arguments and returns the
   same.  It is up to the caller to manage the lifetime of the returned pointers, which of course
   will only be valid for as long as the buffer persists and is not overwritten.
   @author Andrew Bettison <andrew@servalproject.com>
 */
int unpack_http_response(char *response, struct http_response_parts *parts)
{
  parts->code = -1;
  parts->reason = NULL;
  parts->content_length = -1;
  parts->content_start = NULL;
  char *p = NULL;
  if (!str_startswith(response, "HTTP/1.0 ", (const char **)&p)) {
    if (config.debug.rhizome_rx)
      DEBUGF("Malformed HTTP reply: missing HTTP/1.0 preamble");
    return -1;
  }
  if (!(isdigit(p[0]) && isdigit(p[1]) && isdigit(p[2]) && p[3] == ' ')) {
    if (config.debug.rhizome_rx)
      DEBUGF("Malformed HTTP reply: missing three-digit status code");
    return -1;
  }
  parts->code = (p[0]-'0') * 100 + (p[1]-'0') * 10 + p[2]-'0';
  p += 4;
  parts->reason = p;
  while (*p != '\n')
    ++p;
  if (p[-1] == '\r')
    p[-1] = '\0';
  *p++ = '\0';
  // Iterate over header lines until the last blank line.
  while (!(p[0] == '\n' || (p[0] == '\r' && p[1] == '\n'))) {
    if (strcase_startswith(p, "Content-Length:", (const char **)&p)) {
      while (*p == ' ')
	++p;
      parts->content_length = 0;
      char *nump = p;
      while (isdigit(*p))
	parts->content_length = parts->content_length * 10 + *p++ - '0';
      if (p == nump || (*p != '\r' && *p != '\n')) {
	if (config.debug.rhizome_rx)
	  DEBUGF("Invalid HTTP reply: malformed Content-Length header");
	return -1;
      }
    }
    while (*p++ != '\n')
      ;
  }
  if (*p == '\r')
    ++p;
  ++p; // skip '\n' at end of blank line
  parts->content_start = p;
  return 0;
}
