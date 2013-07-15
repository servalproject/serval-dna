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
  struct rhizome_write write_state;

  int64_t last_write_time;
  int64_t start_time;

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
  unsigned char mdpRXWindow[32*200];
};

static int rhizome_fetch_switch_to_mdp(struct rhizome_fetch_slot *slot);
static int rhizome_fetch_mdp_requestblocks(struct rhizome_fetch_slot *slot);
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
  unsigned char log_size_threshold; // will only queue payloads smaller than this.
};

/* Static allocation of the candidate queues.
 */
struct rhizome_fetch_candidate queue0[10];
struct rhizome_fetch_candidate queue1[8];
struct rhizome_fetch_candidate queue2[6];
struct rhizome_fetch_candidate queue3[4];
struct rhizome_fetch_candidate queue4[2];
struct rhizome_fetch_candidate queue5[2];

#define NELS(a) (sizeof (a) / sizeof *(a))
#define slotno(slot) (int)((struct rhizome_fetch_queue *)(slot) - &rhizome_fetch_queues[0])

/* Static allocation of the queue structures.  Must be in order of ascending log_size_threshold.
 */
struct rhizome_fetch_queue rhizome_fetch_queues[] = {
  { .candidate_queue_size = NELS(queue0), .candidate_queue = queue0, .log_size_threshold =   10, .active = { .state = RHIZOME_FETCH_FREE } },
  { .candidate_queue_size = NELS(queue1), .candidate_queue = queue1, .log_size_threshold =   13, .active = { .state = RHIZOME_FETCH_FREE } },
  { .candidate_queue_size = NELS(queue2), .candidate_queue = queue2, .log_size_threshold =   16, .active = { .state = RHIZOME_FETCH_FREE } },
  { .candidate_queue_size = NELS(queue3), .candidate_queue = queue3, .log_size_threshold =   19, .active = { .state = RHIZOME_FETCH_FREE } },
  { .candidate_queue_size = NELS(queue4), .candidate_queue = queue4, .log_size_threshold =   22, .active = { .state = RHIZOME_FETCH_FREE } },
  { .candidate_queue_size = NELS(queue5), .candidate_queue = queue5, .log_size_threshold = 0xFF, .active = { .state = RHIZOME_FETCH_FREE } }
};

#define NQUEUES	    NELS(rhizome_fetch_queues)

int rhizome_active_fetch_count()
{
  int i,active=0;
  for(i=0;i<NQUEUES;i++)
    if (rhizome_fetch_queues[i].active.state!=RHIZOME_FETCH_FREE)
      active++;
  return active;
}

int rhizome_active_fetch_bytes_received(int q)
{
  if (q<0) return -1;
  if (q>=NQUEUES) return -1;
  if (rhizome_fetch_queues[q].active.state==RHIZOME_FETCH_FREE) return -1;
  return (int)rhizome_fetch_queues[q].active.write_state.file_offset + rhizome_fetch_queues[q].active.write_state.data_size;
}

int rhizome_fetch_queue_bytes(){
  int i,j,bytes=0;
  for(i=0;i<NQUEUES;i++){
    if (rhizome_fetch_queues[i].active.state!=RHIZOME_FETCH_FREE){
      int received=rhizome_fetch_queues[i].active.write_state.file_offset + rhizome_fetch_queues[i].active.write_state.data_size;
      bytes+=rhizome_fetch_queues[i].active.manifest->fileLength - received;
    }
    for (j=0;j<rhizome_fetch_queues[i].candidate_queue_size;j++){
      if (rhizome_fetch_queues[i].candidate_queue[j].manifest)
        bytes+=rhizome_fetch_queues[i].candidate_queue[j].manifest->fileLength;
    }
  }
  return bytes;
}

int rhizome_fetch_status_html(struct strbuf *b)
{
  int i,j;
  for(i=0;i<NQUEUES;i++){
    struct rhizome_fetch_queue *q=&rhizome_fetch_queues[i];
    strbuf_sprintf(b, "<p>Slot %d, ", i);
    if (q->active.state!=RHIZOME_FETCH_FREE){
      strbuf_sprintf(b, "%lld[+%d] of %lld",
	q->active.write_state.file_offset,
	q->active.write_state.data_size,
	q->active.manifest->fileLength);
    }else{
      strbuf_puts(b, "inactive");
    }
    int candidates=0;
    long long candidate_size=0;
    for (j=0; j< q->candidate_queue_size;j++){
      if (q->candidate_queue[j].manifest){
	candidates++;
	candidate_size += q->candidate_queue[j].manifest->fileLength;
      }
    }
    if (candidates)
      strbuf_sprintf(b, ", %d candidates [%lld bytes]", candidates, candidate_size);
  }
  return 0;
}

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
  unsigned char log_size = log2ll(size);
  for (i = 0; i < NQUEUES; ++i) {
    struct rhizome_fetch_queue *q = &rhizome_fetch_queues[i];
    if (log_size < q->log_size_threshold)
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
  unsigned char log_size = log2ll(size);
  for (i = 0; i < NQUEUES; ++i) {
    struct rhizome_fetch_queue *q = &rhizome_fetch_queues[i];
    if (log_size < q->log_size_threshold && q->active.state == RHIZOME_FETCH_FREE)
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
    DEBUGF("insert queue[%d] candidate[%d]", (int)(q - rhizome_fetch_queues), i);
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
    DEBUGF("unqueue queue[%d] candidate[%d] manifest=%p", (int)(q - rhizome_fetch_queues), i, c->manifest);
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
  int64_t version;
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
  
  // TODO, work out why the cache was failing and fix it, then prove that it is faster than accessing the database.
  
  // skip the cache for now
  int64_t dbVersion = -1;
  if (sqlite_exec_int64(&dbVersion, "SELECT version FROM MANIFESTS WHERE id='%s';", id) == -1)
    return WHY("Select failure");
  if (dbVersion >= m->version) {
    if (0) WHYF("We already have %s (%"PRId64" vs %"PRId64")", id, dbVersion, m->version);
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
	int64_t rev = rhizome_manifest_get_ll(m,"version");
	if (1) DEBUGF("cached version %"PRId64" vs manifest version %"PRId64, entry->version,rev);
	if (rev > entry->version) {
	  /* If we only have an old version, try refreshing the cache
	     by querying the database */
	  if (sqlite_exec_int64(&entry->version, "select version from manifests where id='%s'", id) != 1)
	    return WHY("failed to select stored manifest version");
	  DEBUGF("Refreshed stored version from database: entry->version=%"PRId64, entry->version);
	}
	if (rev < entry->version) {
	  /* the presented manifest is older than we have.
	     This allows the caller to know that they can tell whoever gave them the
	     manifest it's time to get with the times.  May or not ever be
	     implemented, but it would be nice. XXX */
	  WHYF("cached version is NEWER than presented version (%"PRId64" is newer than %"PRId64")",
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
  int64_t manifest_version = rhizome_manifest_get_ll(m, "version");
  int64_t count;
  switch (sqlite_exec_int64(&count, "select count(*) from manifests where id='%s' and version>=%lld", id, manifest_version)) {
    case -1:
      return WHY("database error reading stored manifest version");
    case 1:
      if (count) {
	/* Okay, we have a stored version which is newer, so update the cache
	  using a random replacement strategy. */
	int64_t stored_version;
	if (sqlite_exec_int64(&stored_version, "select version from manifests where id='%s'", id) < 1)
	  return WHY("database error reading stored manifest version"); // database is broken, we can't confirm that it is here
	DEBUGF("stored version=%"PRId64", manifest_version=%"PRId64" (not fetching; remembering in cache)",
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
  unsigned char bid[RHIZOME_BAR_PREFIX_BYTES];
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

int rhizome_ignore_manifest_check(unsigned char *bid_prefix, int prefix_len)
{
  if (prefix_len < RHIZOME_BAR_PREFIX_BYTES)
    FATAL("Prefix length is too short");
  
  int bin = bid_prefix[0]>>(8-IGNORED_BIN_BITS);
  int slot;
  for(slot = 0; slot != IGNORED_BIN_SIZE; ++slot)
    {
      if (!memcmp(ignored.bins[bin].m[slot].bid,
		  bid_prefix,
		  RHIZOME_BAR_PREFIX_BYTES))
	{
	  if (ignored.bins[bin].m[slot].timeout>gettime_ms())
	    return 1;
	  else 
	    return 0;
	}
    }
  return 0;
}

int rhizome_queue_ignore_manifest(unsigned char *bid_prefix, int prefix_len, int timeout)
{
  if (prefix_len < RHIZOME_BAR_PREFIX_BYTES)
    FATAL("Prefix length is too short");
  
  /* The supplied manifest from a given IP has errors, or we already have it,
     so remember that it isn't worth considering for a while */
  int bin = bid_prefix[0]>>(8-IGNORED_BIN_BITS);
  int slot;
  for(slot = 0; slot != IGNORED_BIN_SIZE; ++slot)
    {
      if (!memcmp(ignored.bins[bin].m[slot].bid,
		  bid_prefix,
		  RHIZOME_BAR_PREFIX_BYTES))
	break;
    }
  if (slot>=IGNORED_BIN_SIZE) slot=random()%IGNORED_BIN_SIZE;
  bcopy(&bid_prefix[0],
	&ignored.bins[bin].m[slot].bid[0],
	RHIZOME_BAR_PREFIX_BYTES);
  /* ignore for a while */
  ignored.bins[bin].m[slot].timeout=gettime_ms()+timeout;
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
  IN();
  int sock = -1;
  /* TODO Don't forget to implement resume */
  slot->start_time=gettime_ms();
  slot->alarm.poll.fd = -1;
  slot->write_state.blob_fd=-1;
  slot->write_state.blob_rowid=-1;

  if (slot->manifest) {
    if (rhizome_open_write(&slot->write_state, slot->manifest->fileHexHash, slot->manifest->fileLength, RHIZOME_PRIORITY_DEFAULT))
      RETURN(-1);
  } else {
    slot->write_state.file_offset=0;
    slot->write_state.file_length=-1;
  }

  slot->request_ofs = 0;
  slot->state = RHIZOME_FETCH_CONNECTING;

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
	     buf,
	     alloca_tohex_sid(slot->peer_sid),
	     ntohs(slot->peer_ipandport.sin_port), 
	     alloca_str_toprint(slot->request)
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
    slot->alarm.alarm = gettime_ms() + config.rhizome.idle_timeout;
    slot->alarm.deadline = slot->alarm.alarm + config.rhizome.idle_timeout;
    schedule(&slot->alarm);
    RETURN(0);
  }

 bail_http:
    /* Fetch via overlay, either because no IP address was provided, or because
       the connection/attempt to fetch via HTTP failed. */
  slot->state=RHIZOME_FETCH_RXFILEMDP;
  rhizome_fetch_switch_to_mdp(slot);
  RETURN(0);
  OUT();
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
  IN();
  if (slot->state != RHIZOME_FETCH_FREE)
    RETURN(SLOTBUSY);

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
    DEBUGF("Fetching bundle slot=%d bid=%s version=%"PRId64" size=%"PRId64" peerip=%s",
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
      RETURN(WHY("bundle import failed"));
    RETURN(IMPORTED);
  }

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
	RETURN(OLDERBUNDLE);
      } else if (am->version > m->version) {
	if (config.debug.rhizome_rx)
	  DEBUGF("   fetch already in progress -- newer version");
	RETURN(NEWERBUNDLE);
      } else {
	if (config.debug.rhizome_rx)
	  DEBUGF("   fetch already in progress -- same version");
	RETURN(SAMEBUNDLE);
      }
    }
    if (as->state != RHIZOME_FETCH_FREE && strcasecmp(m->fileHexHash, am->fileHexHash) == 0) {
      if (config.debug.rhizome_rx)
	DEBUGF("   fetch already in progress, slot=%d filehash=%s", i, m->fileHexHash);
      RETURN(SAMEPAYLOAD);
    }
  }

  // If we already have this version or newer, do not fetch.
  if (rhizome_manifest_version_cache_lookup(m)) {
    if (config.debug.rhizome_rx)
      DEBUG("   fetch not started -- already have that version or newer");
    RETURN(SUPERSEDED);
  }
  if (config.debug.rhizome_rx)
    DEBUGF("   is new");

  // If the payload is already available, no need to fetch, so import now.
  if (rhizome_exists(m->fileHexHash)){
    if (config.debug.rhizome_rx)
      DEBUGF("   fetch not started - payload already present, so importing instead");
    if (rhizome_add_manifest(m, m->ttl-1) == -1)
      RETURN(WHY("add manifest failed"));
    RETURN(IMPORTED);
  }

  // Start the fetch.
  //dump("peerip", peerip, sizeof *peerip);

  /* Prepare for fetching via HTTP */
  slot->peer_ipandport = *peerip;
  slot->alarm.poll.fd=-1;
  
  strbuf r = strbuf_local(slot->request, sizeof slot->request);
  strbuf_sprintf(r, "GET /rhizome/file/%s HTTP/1.0\r\n\r\n", m->fileHexHash);
  if (strbuf_overrun(r))
    RETURN(WHY("request overrun"));
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
  if (schedule_fetch(slot) == -1)
    RETURN(-1);
  if (config.debug.rhizome_rx)
    DEBUGF("   started fetch bid %s version 0x%"PRIx64" into %s, slot=%d filehash=%s",
	   alloca_tohex_bid(slot->bid), slot->bidVersion,
	   alloca_str_toprint(slot->manifest->dataFileName), slotno(slot), m->fileHexHash);
  RETURN(STARTED);
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
  slot->write_state.blob_rowid=-1;
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
  IN();
  struct rhizome_fetch_queue *q;
  for (q = (struct rhizome_fetch_queue *) slot; q >= rhizome_fetch_queues; --q) {
    int i = 0;
    struct rhizome_fetch_candidate *c;
    while (i < q->candidate_queue_size && (c = &q->candidate_queue[i])->manifest) {
      int result = rhizome_fetch(slot, c->manifest, &c->peer_ipandport,c->peer_sid);
      switch (result) {
      case SLOTBUSY:
	OUT(); return;
      case STARTED:
	c->manifest = NULL;
	rhizome_fetch_unqueue(q, i);
	OUT(); return;
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
  OUT();
}

/* Called soon after any fetch candidate is queued, to start any queued fetches.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static void rhizome_start_next_queued_fetches(struct sched_ent *alarm)
{
  IN();
  int i;
  for (i = 0; i < NQUEUES; ++i)
    rhizome_start_next_queued_fetch(&rhizome_fetch_queues[i].active);
  OUT();
}

/* Search all fetch slots, including active downloads, for a matching manifest */
rhizome_manifest * rhizome_fetch_search(unsigned char *id, int prefix_length){
  int i, j;
  for (i = 0; i < NQUEUES; ++i) {
    struct rhizome_fetch_queue *q = &rhizome_fetch_queues[i];
    
    if (q->active.state != RHIZOME_FETCH_FREE && 
	memcmp(id, q->active.manifest->cryptoSignPublic, prefix_length) == 0)
      return q->active.manifest;
      
    for (j = 0; j < q->candidate_queue_size; j++) {
      struct rhizome_fetch_candidate *c = &q->candidate_queue[j];
      if (c->manifest && memcmp(id, c->manifest->cryptoSignPublic, prefix_length) == 0)
	return c->manifest;
    }
  }
  
  return NULL;
}

/* Do we have space to add a fetch candidate of this size? */
int rhizome_fetch_has_queue_space(unsigned char log2_size){
  int i;
  for (i = 0; i < NQUEUES; ++i) {
    struct rhizome_fetch_queue *q = &rhizome_fetch_queues[i];
    if (log2_size < q->log_size_threshold){
      // is there an empty candidate?
      int j=0;
      for (j=0;j < q->candidate_queue_size;j++)
	if (!q->candidate_queue[j].manifest)
	  return 1;
      return 0;
    }
  }
  return 0;
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
struct profile_total rsnqf_stats={.name="rhizome_start_next_queued_fetches"};
struct profile_total rfmsc_stats={.name="rhizome_fetch_mdp_slot_callback"};

int rhizome_suggest_queue_manifest_import(rhizome_manifest *m, const struct sockaddr_in *peerip,const unsigned char peersid[SID_SIZE])
{
  IN();
  
  if (!config.rhizome.fetch){
    rhizome_manifest_free(m);
    RETURN(0);
  }

  const char *bid = alloca_tohex_bid(m->cryptoSignPublic);
  int priority=100; /* normal priority */

  if (config.debug.rhizome_rx)
    DEBUGF("Considering import bid=%s version=%"PRId64" size=%"PRId64" priority=%d:", bid, m->version, m->fileLength, priority);

  if (rhizome_manifest_version_cache_lookup(m)) {
    if (config.debug.rhizome_rx)
      DEBUG("   already have that version or newer");
    rhizome_manifest_free(m);
    RETURN(-1);
  }

  if (config.debug.rhizome_rx) {
    int64_t stored_version;
    if (sqlite_exec_int64(&stored_version, "select version from manifests where id='%s'", bid) > 0)
      DEBUGF("   is new (have version %"PRId64")", stored_version);
  }

  if (m->fileLength == 0) {
    if (rhizome_manifest_verify(m) != 0) {
      WHY("Error verifying manifest when considering for import");
      /* Don't waste time looking at this manifest again for a while */
      rhizome_queue_ignore_manifest(m->cryptoSignPublic,
				    crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES, 60000);
      rhizome_manifest_free(m);
      RETURN(-1);
    }
    rhizome_import_received_bundle(m);
    rhizome_manifest_free(m);
    RETURN(0);
  }

  // Find the proper queue for the payload.  If there is none suitable, it is an error.
  struct rhizome_fetch_queue *qi = rhizome_find_queue(m->fileLength);
  if (!qi) {
    WHYF("No suitable fetch queue for bundle size=%"PRId64, m->fileLength);
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
	    rhizome_queue_ignore_manifest(m->cryptoSignPublic,
					  crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES, 60000);
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
    rhizome_queue_ignore_manifest(m->cryptoSignPublic,
				  crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES, 60000);
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
    sched_activate.stats = &rsnqf_stats;
    sched_activate.alarm = gettime_ms() + rhizome_fetch_delay_ms();
    sched_activate.deadline = sched_activate.alarm + config.rhizome.idle_timeout;
    schedule(&sched_activate);
  }

  RETURN(0);
  OUT();
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

  if (slot->write_state.buffer)
    rhizome_fail_write(&slot->write_state);

  // Release the fetch slot.
  slot->state = RHIZOME_FETCH_FREE;

  // Activate the next queued fetch that is eligible for this slot.  Try starting candidates from
  // all queues with the same or smaller size thresholds until the slot is taken.
  rhizome_start_next_queued_fetch(slot);

  return 0;
}

static void rhizome_fetch_mdp_slot_callback(struct sched_ent *alarm)
{
  IN();
  struct rhizome_fetch_slot *slot=(struct rhizome_fetch_slot*)alarm;

  if (slot->state!=5) {
    DEBUGF("Stale alarm triggered on idle/reclaimed slot. Ignoring");
    unschedule(alarm);
    OUT();
    return;
  }

  long long now=gettime_ms();
  if (now-slot->last_write_time>slot->mdpIdleTimeout) {
    DEBUGF("MDP connection timed out: last RX %lldms ago (read %"PRId64" of %"PRId64" bytes)",
	   now-slot->last_write_time,
	   slot->write_state.file_offset + slot->write_state.data_size,slot->write_state.file_length);
    rhizome_fetch_close(slot);
    OUT();
    return;
  }
  if (config.debug.rhizome_rx)
    DEBUGF("Timeout: Resending request for slot=0x%p (%"PRId64" of %"PRId64" received)",
	   slot,slot->write_state.file_offset + slot->write_state.data_size,slot->write_state.file_length);
  if (slot->bidP)
    rhizome_fetch_mdp_requestblocks(slot);
  else
    rhizome_fetch_mdp_requestmanifest(slot);
  OUT();
}

static int rhizome_fetch_mdp_touch_timeout(struct rhizome_fetch_slot *slot)
{
  // 266ms @ 1mbit (WiFi broadcast speed) = 32x1024 byte packets.
  // But on a packet radio interface at perhaps 50kbit, this is clearly
  // a bad policy.  Ideally we should know about the interface speed
  // and adjust behaviour accordingly. Also the packet size should be smaller
  // on lossy links.  1K packets seem to get through only very rarely.
  // For now, we will just make the timeout 1 second from the time of the last
  // received block.
  unschedule(&slot->alarm);
  slot->alarm.stats=&rfmsc_stats;
  slot->alarm.function = rhizome_fetch_mdp_slot_callback;
  slot->alarm.alarm=gettime_ms()+1000; 
  slot->alarm.deadline=slot->alarm.alarm+500;
  schedule(&slot->alarm);
  return 0;
}

static int rhizome_fetch_mdp_requestblocks(struct rhizome_fetch_slot *slot)
{
  IN();
  // only issue new requests every 133ms.  
  // we automatically re-issue once we have received all packets in this
  // request also, so if there is no packet loss, we can go substantially
  // faster.  Optimising behaviour when there is no packet loss is an
  // outstanding task.
  
  overlay_mdp_frame mdp;

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

  write_uint64(&mdp.out.payload[RHIZOME_MANIFEST_ID_BYTES],slot->bidVersion);
  write_uint64(&mdp.out.payload[RHIZOME_MANIFEST_ID_BYTES+8],slot->write_state.file_offset + slot->write_state.data_size);
  write_uint32(&mdp.out.payload[RHIZOME_MANIFEST_ID_BYTES+8+8],slot->mdpRXBitmap);
  write_uint16(&mdp.out.payload[RHIZOME_MANIFEST_ID_BYTES+8+8+4],slot->mdpRXBlockLength);  

  if (config.debug.rhizome_tx)
    DEBUGF("src sid=%s, dst sid=%s, mdpRXWindowStart=0x%"PRIx64,
	   alloca_tohex_sid(mdp.out.src.sid),alloca_tohex_sid(mdp.out.dst.sid),
	   slot->write_state.file_offset + slot->write_state.data_size);

  overlay_mdp_dispatch(&mdp,0 /* system generated */,NULL,0);
  
  // remember when we sent the request so that we can adjust the inter-request
  // interval based on how fast the packets arrive.
  slot->mdpResponsesOutstanding=32; // TODO: set according to bitmap

  rhizome_fetch_mdp_touch_timeout(slot);
  
  RETURN(0);
  OUT();
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
  IN()
  if (!my_subscriber) {
    DEBUGF("I don't have an identity, so we cannot fall back to MDP");
    RETURN(rhizome_fetch_close(slot));
  }

  if (config.debug.rhizome_rx)
    DEBUGF("Trying to switch to MDP for Rhizome fetch: slot=0x%p (%"PRId64" bytes)",
	   slot,slot->write_state.file_length);
  
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
    slot->mdpIdleTimeout=config.rhizome.idle_timeout; // give up if nothing received for 5 seconds
    slot->mdpRXBitmap=0x00000000; // no blocks received yet
    slot->mdpRXBlockLength=config.rhizome.rhizome_mdp_block_size; // Rhizome over MDP block size
    rhizome_fetch_mdp_requestblocks(slot);    
  } else {
    /* We are requesting a manifest, which is stateless, except that we eventually
       give up. All we need to do now is send the request, and set our alarm to
       try again in case we haven't heard anything back. */
    slot->mdpIdleTimeout=config.rhizome.idle_timeout;
    rhizome_fetch_mdp_requestmanifest(slot);
  }

  RETURN(0);
  OUT();
}

void rhizome_fetch_write(struct rhizome_fetch_slot *slot)
{
  IN();
  if (config.debug.rhizome_rx)
    DEBUGF("write_nonblock(%d, %s)", slot->alarm.poll.fd, alloca_toprint(-1, &slot->request[slot->request_ofs], slot->request_len-slot->request_ofs));
  int bytes = write_nonblock(slot->alarm.poll.fd, &slot->request[slot->request_ofs], slot->request_len-slot->request_ofs);
  if (bytes == -1) {
    WHY("Got error while sending HTTP request.");
    rhizome_fetch_switch_to_mdp(slot);
    OUT();
    return;
  } else {
    // reset timeout
    unschedule(&slot->alarm);
    slot->alarm.alarm=gettime_ms() + config.rhizome.idle_timeout;
    slot->alarm.deadline = slot->alarm.alarm + config.rhizome.idle_timeout;
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
  OUT();
  return;
}

int rhizome_write_content(struct rhizome_fetch_slot *slot, char *buffer, int bytes)
{
  IN();
  
  if (bytes<=0)
    RETURN(0);
  
  // Truncate to known length of file (handy for reading from journal bundles that
  // might grow while we are reading from them).
  if (bytes>(slot->write_state.file_length-(slot->write_state.file_offset+slot->write_state.data_size))){
    bytes=slot->write_state.file_length-(slot->write_state.file_offset+slot->write_state.data_size);
  }

  if (!slot->manifest){
    /* We are reading a manifest.  Read it into a buffer. */
    int count=bytes;
    if (count+slot->manifest_bytes>1024) count=1024-slot->manifest_bytes;
    bcopy(buffer,&slot->manifest_buffer[slot->manifest_bytes],count);
    slot->manifest_bytes+=count;
    slot->write_state.file_offset+=count;
  } else {
    
    /* We are reading a file. Stream it into the database. */
    int ofs=0;
    while (ofs<bytes){
      int block_size = bytes - ofs;
      if (block_size > slot->write_state.buffer_size - slot->write_state.data_size)
	block_size = slot->write_state.buffer_size - slot->write_state.data_size;
      
      if (block_size>0){
	bcopy(buffer+ofs, slot->write_state.buffer + slot->write_state.data_size, block_size);
	slot->write_state.data_size+=block_size;
	ofs+=block_size;
      }
      
      if (slot->write_state.data_size>=slot->write_state.buffer_size){
	int ret = rhizome_flush(&slot->write_state);
	if (ret!=0){
	  rhizome_fetch_close(slot);
	  RETURN(-1);
	}
      }
    }
  }

  slot->last_write_time=gettime_ms();
  if (slot->write_state.file_offset + slot->write_state.data_size>=slot->write_state.file_length) {
    /* got all of file */
    if (config.debug.rhizome_rx)
      DEBUGF("Received all of file via rhizome -- now to import it");
    if (slot->manifest) {
      
      // Were fetching payload, now we have it.
      if (rhizome_finish_write(&slot->write_state)){
	rhizome_fetch_close(slot);
	RETURN(-1);
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
	  INFOF("Completed MDP request from %s  for file %s",
		alloca_tohex_sid(slot->peer_sid), slot->manifest->fileHexHash);
	}
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
	     slot,(long long)slot->write_state.file_offset+slot->write_state.data_size,
	     (long long)gettime_ms()-slot->start_time,
	     (long long)(slot->write_state.file_offset+slot->write_state.data_size)/(gettime_ms()-slot->start_time),
	     slot->write_state.buffer_size);
    rhizome_fetch_close(slot);
    RETURN(-1);
  }

  // slot is still open
  RETURN(0);
  OUT();
}

int rhizome_received_content(unsigned char *bidprefix,
			     uint64_t version, uint64_t offset,
			     int count,unsigned char *bytes,int type)
{
  IN();
  int i;
  for(i=0;i<NQUEUES;i++) {
    struct rhizome_fetch_slot *slot=&rhizome_fetch_queues[i].active;
    if (slot->state==RHIZOME_FETCH_RXFILEMDP&&slot->bidP) {
      if (!memcmp(slot->bid,bidprefix,16))
	{
	  if (slot->write_state.file_offset + slot->write_state.data_size==offset) {
	    if (!rhizome_write_content(slot,(char *)bytes,count))
	      {
		rhizome_fetch_mdp_touch_timeout(slot);
		slot->mdpResponsesOutstanding--;
		if (slot->mdpResponsesOutstanding==0) {
		  // We have received all responses, so immediately ask for more
		  rhizome_fetch_mdp_requestblocks(slot);
		}
		
		// TODO: Try flushing out stuck packets that we have kept due to
		// packet loss / out-of-order delivery.
	      }

	    RETURN(0);
	  } else {
	    // TODO: Implement out-of-order buffering so that lost packets
	    // don't cause wastage
	  }
	  RETURN(0);
	}
    }
  }  

  RETURN(-1);
  OUT();
}

void rhizome_fetch_poll(struct sched_ent *alarm)
{
  struct rhizome_fetch_slot *slot = (struct rhizome_fetch_slot *) alarm;

  if (alarm->poll.revents & POLLOUT) {
    switch (slot->state) {
    case RHIZOME_FETCH_CONNECTING:
    case RHIZOME_FETCH_SENDINGHTTPREQUEST:
      rhizome_fetch_write(slot);
      return;
    }
  }
  if (alarm->poll.revents & POLLIN) {
    switch (slot->state) {
    case RHIZOME_FETCH_RXFILE: {
      /* Keep reading until we have the promised amount of data */
      char buffer[8192];
      sigPipeFlag = 0;
      int bytes = read_nonblock(slot->alarm.poll.fd, buffer, sizeof buffer);
      /* If we got some data, see if we have found the end of the HTTP request */
      if (bytes > 0) {
	rhizome_write_content(slot, buffer, bytes);
	// reset inactivity timeout
	unschedule(&slot->alarm);
	slot->alarm.alarm=gettime_ms() + config.rhizome.idle_timeout;
	slot->alarm.deadline = slot->alarm.alarm + config.rhizome.idle_timeout;
	slot->alarm.function = rhizome_fetch_poll;
	schedule(&slot->alarm);	
	return;
      } else {
	if (config.debug.rhizome_rx)
	  DEBUGF("Empty read, closing connection: received %"PRId64" of %"PRId64" bytes",
		slot->write_state.file_offset + slot->write_state.data_size,slot->write_state.file_length);
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
	slot->alarm.alarm = gettime_ms() + config.rhizome.idle_timeout;
	slot->alarm.deadline = slot->alarm.alarm + config.rhizome.idle_timeout;
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
	    rhizome_fetch_switch_to_mdp(slot);
	    return;
	  }
	  if (parts.content_length == -1) {
	    if (config.debug.rhizome_rx)
	      DEBUGF("Invalid HTTP reply: missing Content-Length header");
	    rhizome_fetch_switch_to_mdp(slot);
	    return;
	  }
	  if (slot->write_state.file_length==-1)
	    slot->write_state.file_length=parts.content_length;
	  else if (parts.content_length != slot->write_state.file_length)
	    WARNF("Expected content length %"PRId64", got %"PRId64, slot->write_state.file_length, parts.content_length);
	  /* We have all we need.  The file is already open, so just write out any initial bytes of
	     the body we read.
	  */
	  slot->state = RHIZOME_FETCH_RXFILE;
	  int content_bytes = slot->request + slot->request_len - parts.content_start;
	  if (content_bytes > 0){
	    rhizome_write_content(slot, parts.content_start, content_bytes);
	    // reset inactivity timeout
	    unschedule(&slot->alarm);
	    slot->alarm.alarm=gettime_ms() + config.rhizome.idle_timeout;
	    slot->alarm.deadline = slot->alarm.alarm + config.rhizome.idle_timeout;
	    slot->alarm.function = rhizome_fetch_poll;
	    schedule(&slot->alarm);

	    return;
	  }
	}
      }
      break;
      default:
	WARNF("Closing rhizome fetch connection due to illegal/unimplemented state=%d.",slot->state);
	rhizome_fetch_close(slot);
	return;
    }
    }
  }
  if (alarm->poll.revents==0 || alarm->poll.revents & (POLLHUP | POLLERR)){
    // timeout or socket error, close the socket
    if (config.debug.rhizome_rx)
      DEBUGF("Closing due to timeout or error %x (%x %x)", alarm->poll.revents, POLLHUP, POLLERR);
    if (slot->state!=RHIZOME_FETCH_FREE)
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
  IN();
  parts->code = -1;
  parts->reason = NULL;
  parts->content_length = -1;
  parts->content_start = NULL;
  char *p = NULL;
  if (!str_startswith(response, "HTTP/1.0 ", (const char **)&p)) {
    if (config.debug.rhizome_rx)
      DEBUGF("Malformed HTTP reply: missing HTTP/1.0 preamble");
    RETURN(-1);
  }
  if (!(isdigit(p[0]) && isdigit(p[1]) && isdigit(p[2]) && p[3] == ' ')) {
    if (config.debug.rhizome_rx)
      DEBUGF("Malformed HTTP reply: missing three-digit status code");
    RETURN(-1);
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
	RETURN(-1);
      }
    }
    while (*p++ != '\n')
      ;
  }
  if (*p == '\r')
    ++p;
  ++p; // skip '\n' at end of blank line
  parts->content_start = p;
  RETURN(0);
  OUT();
}
