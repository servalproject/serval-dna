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
#include "socket.h"
#include "dataformats.h"

/* Represents a queued fetch of a bundle payload, for which the manifest is already known.
 */
struct rhizome_fetch_candidate {
  rhizome_manifest *manifest;

  /* Address of node offering manifest.
     Can be either IP+port for HTTP or it can be a SID 
     for MDP. */
  struct sockaddr_in peer_ipandport;
  sid_t peer_sid;

  int priority;
};

/* Represents an active fetch (in progress) of a bundle payload (.manifest != NULL) or of a bundle
 * manifest (.manifest == NULL).
 */
struct rhizome_fetch_slot {
  struct sched_ent alarm; // must be first element in struct
  rhizome_manifest *manifest;

  struct sockaddr_in peer_ipandport;
  sid_t peer_sid;

  int state;
#define RHIZOME_FETCH_FREE 0
#define RHIZOME_FETCH_CONNECTING 1
#define RHIZOME_FETCH_SENDINGHTTPREQUEST 2
#define RHIZOME_FETCH_RXHTTPHEADERS 3
#define RHIZOME_FETCH_RXFILE 4
#define RHIZOME_FETCH_RXFILEMDP 5

  /* Keep track of how much of the file we have read */
  struct rhizome_write write_state;

  time_ms_t last_write_time;
  time_ms_t start_time;

  /* HTTP transport specific elements */
  char request[1024];
  int request_len;
  int request_ofs;
  rhizome_manifest *previous;

  /* HTTP streaming reception of manifests */
  char manifest_buffer[1024];
  unsigned manifest_bytes;

  /* MDP transport specific elements */
  rhizome_bid_t bid;
  int64_t bidVersion;
  int prefix_length;
  int mdpIdleTimeout;
  time_ms_t mdp_last_request_time;
  uint64_t mdp_last_request_offset;
  int mdpResponsesOutstanding;
  int mdpRXBlockLength;
  unsigned char mdpRXWindow[32*200];
};

static int rhizome_fetch_switch_to_mdp(struct rhizome_fetch_slot *slot);
static int rhizome_fetch_mdp_requestblocks(struct rhizome_fetch_slot *slot);

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
  unsigned candidate_queue_size;
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

static const char * fetch_state(int state)
{
  switch (state){
    case RHIZOME_FETCH_FREE:
    return "FREE";
    case RHIZOME_FETCH_CONNECTING:
    return "HTTP_CONNECTING";
    case RHIZOME_FETCH_SENDINGHTTPREQUEST:
    return "HTTP_SENDING_HEADERS";
    case RHIZOME_FETCH_RXHTTPHEADERS:
    return "HTTP_RECEIVING_HEADERS";
    case RHIZOME_FETCH_RXFILE:
    return "HTTP_RECEIVING_FILE";
    case RHIZOME_FETCH_RXFILEMDP:
    return "MDP_RECEIVING_FILE";
    default:
    return "UNKNOWN";
  }
}

static uint64_t rhizome_active_fetch_bytes_received(int q)
{
  if (q<0 || q>=NQUEUES) return -1;
  if (rhizome_fetch_queues[q].active.state==RHIZOME_FETCH_FREE) return -1;
  return rhizome_fetch_queues[q].active.write_state.file_offset;
}

static uint64_t rhizome_fetch_queue_bytes()
{
  uint64_t bytes = 0;
  unsigned i;
  for(i=0;i<NQUEUES;i++){
    if (rhizome_fetch_queues[i].active.state!=RHIZOME_FETCH_FREE){
      assert(rhizome_fetch_queues[i].active.manifest->filesize != RHIZOME_SIZE_UNSET);
      bytes += rhizome_fetch_queues[i].active.manifest->filesize - rhizome_fetch_queues[i].active.write_state.file_offset;
    }
    unsigned j;
    for (j=0;j<rhizome_fetch_queues[i].candidate_queue_size;j++){
      if (rhizome_fetch_queues[i].candidate_queue[j].manifest) {
        assert(rhizome_fetch_queues[i].candidate_queue[j].manifest->filesize != RHIZOME_SIZE_UNSET);
        bytes += rhizome_fetch_queues[i].candidate_queue[j].manifest->filesize;
      }
    }
  }
  return bytes;
}

void rhizome_fetch_log_short_status()
{
  int i,active=0;
  for(i=0;i<NQUEUES;i++)
    if (rhizome_fetch_queues[i].active.state!=RHIZOME_FETCH_FREE)
      active++;
  if (!active)
    return;
  
  INFOF("Rhizome transfer progress: %"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64" (remaining %"PRIu64")",
	rhizome_active_fetch_bytes_received(0),
	rhizome_active_fetch_bytes_received(1),
	rhizome_active_fetch_bytes_received(2),
	rhizome_active_fetch_bytes_received(3),
	rhizome_active_fetch_bytes_received(4),
	rhizome_active_fetch_bytes_received(5),
	rhizome_fetch_queue_bytes());
}

int rhizome_fetch_status_html(strbuf b)
{
  unsigned i;
  for(i=0;i<NQUEUES;i++){
    struct rhizome_fetch_queue *q=&rhizome_fetch_queues[i];
    unsigned used=0;
    unsigned j;
    for (j=0;j<q->candidate_queue_size;j++){
      if (q->candidate_queue[j].manifest)
	used++;
    }
    strbuf_sprintf(b, "<p>Slot %u, (%u of %u): ", i, used, q->candidate_queue_size);
    if (q->active.state!=RHIZOME_FETCH_FREE){
      strbuf_sprintf(b, "%s %"PRIu64" of %"PRIu64" from %s*",
	fetch_state(q->active.state),
	q->active.write_state.file_offset,
	q->active.manifest->filesize,
	alloca_tohex_sid_t_trunc(q->active.peer_sid, 16));
    }else{
      strbuf_puts(b, "inactive");
    }
    int candidates=0;
    uint64_t candidate_size = 0;
    for (j=0; j< q->candidate_queue_size;j++){
      if (q->candidate_queue[j].manifest){
	candidates++;
	assert(q->candidate_queue[j].manifest->filesize != RHIZOME_SIZE_UNSET);
	candidate_size += q->candidate_queue[j].manifest->filesize;
      }
    }
    if (candidates)
      strbuf_sprintf(b, ", %d candidates [%"PRIu64" bytes]", candidates, candidate_size);
  }
  return 0;
}

static struct sched_ent sched_activate = STRUCT_SCHED_ENT_UNUSED;
static struct profile_total rsnqf_stats = { .name="rhizome_start_next_queued_fetches" };
static struct profile_total fetch_stats = { .name="rhizome_fetch_poll" };

/* Find a queue suitable for a fetch of the given number of bytes.  If there is no suitable queue,
 * return NULL.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static struct rhizome_fetch_queue *rhizome_find_queue(unsigned char log_size)
{
  int i;
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
static struct rhizome_fetch_slot *rhizome_find_fetch_slot(uint64_t size)
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


// find the first matching active slot for this bundle
static struct rhizome_fetch_slot *fetch_search_slot(const unsigned char *id, int prefix_length)
{
  int i;
  for (i = 0; i < NQUEUES; ++i) {
    struct rhizome_fetch_queue *q = &rhizome_fetch_queues[i];
    
    if (q->active.state != RHIZOME_FETCH_FREE && 
	memcmp(id, q->active.manifest->cryptoSignPublic.binary, prefix_length) == 0)
      return &q->active;
  }
  return NULL;
}

// find the first matching candidate for this bundle
static struct rhizome_fetch_candidate *fetch_search_candidate(const unsigned char *id, int prefix_length)
{
  unsigned i;
  for (i = 0; i < NQUEUES; ++i) {
    struct rhizome_fetch_queue *q = &rhizome_fetch_queues[i];
    unsigned j;
    for (j = 0; j < q->candidate_queue_size; j++) {
      struct rhizome_fetch_candidate *c = &q->candidate_queue[j];
      if (!c->manifest)
	continue;
      if (memcmp(c->manifest->cryptoSignPublic.binary, id, prefix_length))
	continue;
      return c;
    }
  }
  return NULL;
}

/* Search all fetch slots, including active downloads, for a matching manifest */
rhizome_manifest * rhizome_fetch_search(const unsigned char *id, int prefix_length){
  struct rhizome_fetch_slot *s = fetch_search_slot(id, prefix_length);
  if (s)
    return s->manifest;
  struct rhizome_fetch_candidate *c = fetch_search_candidate(id, prefix_length);
  if (c)
    return c->manifest;
  return NULL;
}

/* Insert a candidate into a given queue at a given position.  All candidates succeeding the given
 * position are copied backward in the queue to open up an empty element at the given position.  If
 * the queue was full, then the tail element is discarded, freeing the manifest it points to.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static struct rhizome_fetch_candidate *rhizome_fetch_insert(struct rhizome_fetch_queue *q, unsigned i)
{
  struct rhizome_fetch_candidate * const c = &q->candidate_queue[i];
  struct rhizome_fetch_candidate * e = &q->candidate_queue[q->candidate_queue_size - 1];
  if (config.debug.rhizome_rx)
    DEBUGF("insert queue[%d] candidate[%u]", (int)(q - rhizome_fetch_queues), i);
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
static void rhizome_fetch_unqueue(struct rhizome_fetch_queue *q, unsigned i)
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

static void candidate_unqueue(struct rhizome_fetch_candidate *c)
{
  unsigned i;
  for (i = 0; i < NQUEUES; ++i) {
    struct rhizome_fetch_queue *q = &rhizome_fetch_queues[i];
    unsigned index = c - q->candidate_queue;
    if (index>=0 && index < q->candidate_queue_size){
      rhizome_fetch_unqueue(q, index);
      return;
    }
  }
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
    DEBUGF("manifest len=%u has %u signatories. Associated filesize=%"PRIu64" bytes", 
	   m->manifest_bytes, m->sig_count, m->filesize);
    dump("manifest", m->manifestdata, m->manifest_all_bytes);
  }
  return rhizome_add_manifest(m, m->ttl - 1 /* TTL */);
}

// begin fetching a bundle
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
    slot->bid = slot->manifest->cryptoSignPublic;
    slot->prefix_length = sizeof slot->bid.binary;
    slot->bidVersion=slot->manifest->version;
    /* Don't provide a filename, because we will stream the file straight into
       the database. */
    slot->manifest->dataFileName = NULL;
    slot->manifest->dataFileUnlinkOnFree = 0;
    
    strbuf r = strbuf_local(slot->request, sizeof slot->request);
    strbuf_sprintf(r, "GET /rhizome/file/%s HTTP/1.0\r\n", alloca_tohex_rhizome_filehash_t(slot->manifest->filehash));
    
    if (slot->manifest->is_journal){
      // if we're fetching a journal bundle, work out how many bytes we have of a previous version
      // and therefore what range of bytes we should ask for
      slot->previous = rhizome_new_manifest();
      if (rhizome_retrieve_manifest(&slot->manifest->cryptoSignPublic, slot->previous)){
	rhizome_manifest_free(slot->previous);
	slot->previous=NULL;
      // check that the new journal is valid and has some overlapping bytes
      }else if (   !slot->previous->is_journal
		|| slot->previous->tail > slot->manifest->tail
		|| slot->previous->filesize + slot->previous->tail < slot->manifest->tail
      ){
	rhizome_manifest_free(slot->previous);
	slot->previous=NULL;
      }else{
	assert(slot->previous->filesize >= slot->manifest->tail);
	assert(slot->manifest->filesize > 0);
	strbuf_sprintf(r, "Range: bytes=%"PRIu64"-%"PRIu64"\r\n",
	    slot->previous->filesize - slot->manifest->tail,
	    slot->manifest->filesize - 1
	  );
      }
    }

    strbuf_puts(r, "\r\n");

    if (strbuf_overrun(r))
      RETURN(WHY("request overrun"));
    slot->request_len = strbuf_len(r);

    if (rhizome_open_write(&slot->write_state, &slot->manifest->filehash, slot->manifest->filesize, RHIZOME_PRIORITY_DEFAULT))
      RETURN(-1);
  } else {
    strbuf r = strbuf_local(slot->request, sizeof slot->request);
    strbuf_sprintf(r, "GET /rhizome/manifestbyprefix/%s HTTP/1.0\r\n\r\n", alloca_tohex(slot->bid.binary, slot->prefix_length));
    if (strbuf_overrun(r))
      RETURN(WHY("request overrun"));
    slot->request_len = strbuf_len(r);

    slot->manifest_bytes=0;
    slot->write_state.file_offset = 0;
    slot->write_state.file_length = RHIZOME_SIZE_UNSET;
  }

  slot->request_ofs = 0;

  slot->state = RHIZOME_FETCH_CONNECTING;
  slot->alarm.function = rhizome_fetch_poll;
  slot->alarm.stats = &fetch_stats;

  if (slot->peer_ipandport.sin_family == AF_INET && slot->peer_ipandport.sin_port) {
    /* Transfer via HTTP over IPv4 */
    if ((sock = esocket(AF_INET, SOCK_STREAM, 0)) == -1)
      goto bail_http;
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
	     alloca_tohex_sid_t(slot->peer_sid),
	     ntohs(slot->peer_ipandport.sin_port), 
	     alloca_str_toprint(slot->request)
	);
    slot->alarm.poll.fd = sock;
    /* Watch for activity on the socket */
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
rhizome_fetch(struct rhizome_fetch_slot *slot, rhizome_manifest *m, const struct sockaddr_in *peerip, const sid_t *peersidp)
{
  IN();
  if (slot->state != RHIZOME_FETCH_FREE)
    RETURN(SLOTBUSY);

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
    DEBUGF("Fetching bundle slot=%d bid=%s version=%"PRId64" size=%"PRIu64" peerip=%s",
	   slotno(slot),
	   alloca_tohex_rhizome_bid_t(m->cryptoSignPublic),
	   m->version,
	   m->filesize,
	   alloca_sockaddr(peerip, sizeof(struct sockaddr_in))
	   );

  // If the payload is empty, no need to fetch, so import now.
  if (m->filesize == 0) {
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
  {
    struct rhizome_fetch_slot *as = fetch_search_slot(m->cryptoSignPublic.binary, sizeof m->cryptoSignPublic.binary);
    if (as){
      const rhizome_manifest *am = as->manifest;
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
  }
  int i;
  for (i = 0; i < NQUEUES; ++i) {
    struct rhizome_fetch_slot *as = &rhizome_fetch_queues[i].active;
    const rhizome_manifest *am = as->manifest;
    if (as->state != RHIZOME_FETCH_FREE && cmp_rhizome_filehash_t(&m->filehash, &am->filehash) == 0) {
      if (config.debug.rhizome_rx)
	DEBUGF("   fetch already in progress, slot=%d filehash=%s", i, alloca_tohex_rhizome_filehash_t(m->filehash));
      RETURN(SAMEPAYLOAD);
    }
  }

  // If we already have this version or newer, do not fetch.
  if (!rhizome_is_manifest_interesting(m)) {
    if (config.debug.rhizome_rx)
      DEBUG("   fetch not started -- already have that version or newer");
    RETURN(SUPERSEDED);
  }
  if (config.debug.rhizome_rx)
    DEBUGF("   is new");

  // If the payload is already available, no need to fetch, so import now.
  if (rhizome_exists(&m->filehash)){
    if (config.debug.rhizome_rx)
      DEBUGF("   fetch not started - payload already present, so importing instead");
    if (rhizome_add_manifest(m, m->ttl-1) == -1)
      RETURN(WHY("add manifest failed"));
    RETURN(IMPORTED);
  }

  /* Prepare for fetching */
  slot->peer_ipandport = *peerip;
  slot->peer_sid = *peersidp;
  slot->manifest = m;

  if (schedule_fetch(slot) == -1)
    RETURN(-1);
  RETURN(STARTED);
}

/* Returns STARTED (0) if the fetch was started.
 * Returns SLOTBUSY if there is no available fetch slot for performing the fetch.
 * Returns -1 on error.
 */
enum rhizome_start_fetch_result
rhizome_fetch_request_manifest_by_prefix(const struct sockaddr_in *peerip, 
					 const sid_t *peersidp,
					 const unsigned char *prefix, size_t prefix_length)
{
  assert(peerip);
  struct rhizome_fetch_slot *slot = rhizome_find_fetch_slot(MAX_MANIFEST_BYTES);
  if (slot == NULL)
    return SLOTBUSY;

  /* Prepare for fetching via HTTP */
  slot->peer_ipandport = *peerip;
  slot->manifest = NULL;
  slot->peer_sid = *peersidp;
  bcopy(prefix, slot->bid.binary, prefix_length);
  slot->prefix_length=prefix_length;

  /* Don't stream into a file blob in the database, because it is a manifest.
     We do need to cache it in the slot structure, though, and then offer it
     for inserting into the database, but we can avoid the temporary file in
     the process. */
  
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
    unsigned i = 0;
    struct rhizome_fetch_candidate *c;
    while (i < q->candidate_queue_size && (c = &q->candidate_queue[i])->manifest) {
      int result = rhizome_fetch(slot, c->manifest, &c->peer_ipandport, &c->peer_sid);
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

/* Do we have space to add a fetch candidate of this size? */
int rhizome_fetch_has_queue_space(unsigned char log2_size){
  struct rhizome_fetch_queue *q = rhizome_find_queue(log2_size);
  if (q){
    // is there an empty candidate?
    unsigned j=0;
    for (j=0;j < q->candidate_queue_size;j++)
      if (!q->candidate_queue[j].manifest)
	return 1;
    return 0;
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
int rhizome_suggest_queue_manifest_import(rhizome_manifest *m, const struct sockaddr_in *peerip, const sid_t *peersidp)
{
  IN();
  
  if (!config.rhizome.fetch){
    rhizome_manifest_free(m);
    RETURN(0);
  }

  int priority=100; /* normal priority */

  if (config.debug.rhizome_rx)
    DEBUGF("Considering import bid=%s version=%"PRId64" size=%"PRIu64" priority=%d:",
	alloca_tohex_rhizome_bid_t(m->cryptoSignPublic), m->version, m->filesize, priority);

  if (!rhizome_is_manifest_interesting(m)) {
    if (config.debug.rhizome_rx)
      DEBUG("   already have that version or newer");
    rhizome_manifest_free(m);
    RETURN(-1);
  }

  if (config.debug.rhizome_rx) {
    int64_t stored_version;
    if (sqlite_exec_int64(&stored_version, "SELECT version FROM MANIFESTS WHERE id = ?", RHIZOME_BID_T, &m->cryptoSignPublic, END) > 0)
      DEBUGF("   is new (have version %"PRId64")", stored_version);
  }

  assert(m->filesize != RHIZOME_SIZE_UNSET);
  if (m->filesize == 0) {
    if (rhizome_manifest_verify(m) != 0) {
      WHY("Error verifying manifest when considering for import");
      /* Don't waste time looking at this manifest again for a while */
      rhizome_queue_ignore_manifest(m->cryptoSignPublic.binary, sizeof m->cryptoSignPublic.binary, 60000);
      rhizome_manifest_free(m);
      RETURN(-1);
    }
    rhizome_import_received_bundle(m);
    rhizome_manifest_free(m);
    RETURN(0);
  }

  // Find the proper queue for the payload.  If there is none suitable, it is an error.
  struct rhizome_fetch_queue *qi = rhizome_find_queue(log2ll(m->filesize));
  if (!qi) {
    WHYF("No suitable fetch queue for bundle size=%"PRIu64, m->filesize);
    rhizome_manifest_free(m);
    RETURN(-1);
  }

  // Search all the queues for the same manifest (it could be in any queue because its payload size
  // may have changed between versions.) If a newer or the same version is already queued, then
  // ignore this one.  Otherwise, unqueue all older candidates.
  int ci = -1;
  unsigned i;
  for (i = 0; i < NQUEUES; ++i) {
    struct rhizome_fetch_queue *q = &rhizome_fetch_queues[i];
    unsigned j;
    for (j = 0; j < q->candidate_queue_size; ) {
      struct rhizome_fetch_candidate *c = &q->candidate_queue[j];
      if (c->manifest) {
	if (cmp_rhizome_bid_t(&m->cryptoSignPublic, &c->manifest->cryptoSignPublic) == 0) {
	  if (c->manifest->version >= m->version) {
	    rhizome_manifest_free(m);
	    RETURN(0);
	  }
	  if (!m->selfSigned && rhizome_manifest_verify(m)) {
	    WHY("Error verifying manifest when considering queuing for import");
	    /* Don't waste time looking at this manifest again for a while */
	    rhizome_queue_ignore_manifest(m->cryptoSignPublic.binary, sizeof m->cryptoSignPublic.binary, 60000);
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
    rhizome_queue_ignore_manifest(m->cryptoSignPublic.binary, sizeof m->cryptoSignPublic.binary, 60000);
    rhizome_manifest_free(m);
    RETURN(-1);
  }

  struct rhizome_fetch_candidate *c = rhizome_fetch_insert(qi, ci);
  c->manifest = m;
  c->priority = priority;
  c->peer_ipandport = *peerip;
  c->peer_sid = *peersidp;

  if (config.debug.rhizome_rx) {
    DEBUG("Rhizome fetch queues:");
    unsigned i, j;
    for (i = 0; i < NQUEUES; ++i) {
      struct rhizome_fetch_queue *q = &rhizome_fetch_queues[i];
      for (j = 0; j < q->candidate_queue_size; ++j) {
	struct rhizome_fetch_candidate *c = &q->candidate_queue[j];
	if (!c->manifest)
	  break;
	DEBUGF("%d:%d manifest=%p bid=%s priority=%d size=%"PRIu64, i, j,
	    c->manifest,
	    alloca_tohex_rhizome_bid_t(c->manifest->cryptoSignPublic),
	    c->priority,
	    c->manifest->filesize
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

  /* Free ephemeral data */
  if (slot->manifest)
    rhizome_manifest_free(slot->manifest);
  slot->manifest = NULL;

  if (slot->previous)
    rhizome_manifest_free(slot->previous);
  slot->previous = NULL;
  
  if (slot->write_state.blob_fd>=0 ||
      slot->write_state.blob_rowid>=0)
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

  time_ms_t now = gettime_ms();
  if (now - slot->last_write_time > slot->mdpIdleTimeout) {
    DEBUGF("MDP connection timed out: last RX %"PRId64"ms ago (read %"PRId64" of %"PRId64" bytes)",
	   now-slot->last_write_time,
	   slot->write_state.file_offset,
	   slot->write_state.file_length);
    rhizome_fetch_close(slot);
    OUT();
    return;
  }
  if (config.debug.rhizome_rx)
    DEBUGF("Timeout: Resending request for slot=0x%p (%"PRIu64" of %"PRIu64" received)",
	   slot, slot->write_state.file_offset,
	   slot->write_state.file_length);
  rhizome_fetch_mdp_requestblocks(slot);
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
  slot->alarm.alarm=gettime_ms()+config.rhizome.mdp_stall_timeout; 
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
  mdp.out.src.sid = my_subscriber->sid;
  mdp.out.src.port=MDP_PORT_RHIZOME_RESPONSE;
  mdp.out.dst.sid = slot->peer_sid;
  mdp.out.dst.port=MDP_PORT_RHIZOME_REQUEST;
  mdp.out.ttl=1;
  mdp.packetTypeAndFlags=MDP_TX;

  mdp.out.queue=OQ_ORDINARY;
  mdp.out.payload_length= sizeof slot->bid.binary + 8 + 8 + 4 + 2;
  bcopy(slot->bid.binary, &mdp.out.payload[0], sizeof slot->bid.binary);

  uint32_t bitmap=0;
  int requests=32;
  int i;
  struct rhizome_write_buffer *p = slot->write_state.buffer_list;
  uint64_t offset = slot->write_state.file_offset;
  for (i=0;i<32;i++){
    while(p && p->offset + p->data_size < offset)
      p=p->_next;
    if (!p)
      break;
    if (p->offset <= offset && p->offset+p->data_size >= offset+slot->mdpRXBlockLength){
      bitmap |= 1<<(31-i);
      requests --;
    }
    offset+=slot->mdpRXBlockLength;
  }

  write_uint64(&mdp.out.payload[sizeof slot->bid.binary], slot->bidVersion);
  write_uint64(&mdp.out.payload[sizeof slot->bid.binary + 8], slot->write_state.file_offset);
  write_uint32(&mdp.out.payload[sizeof slot->bid.binary + 8 + 8], bitmap);
  write_uint16(&mdp.out.payload[sizeof slot->bid.binary + 8 + 8 + 4], slot->mdpRXBlockLength);

  if (config.debug.rhizome_tx)
    DEBUGF("src sid=%s, dst sid=%s, mdpRXWindowStart=0x%"PRIx64", slot->bidVersion=0x%"PRIx64,
	   alloca_tohex_sid_t(mdp.out.src.sid),
	   alloca_tohex_sid_t(mdp.out.dst.sid),
	   slot->write_state.file_offset,
	   slot->bidVersion);

  overlay_mdp_dispatch(&mdp, NULL);
  
  // remember when we sent the request so that we can adjust the inter-request
  // interval based on how fast the packets arrive.
  slot->mdpResponsesOutstanding=requests;
  slot->mdp_last_request_offset = slot->write_state.file_offset;
  slot->mdp_last_request_time = gettime_ms();
  
  rhizome_fetch_mdp_touch_timeout(slot);
  
  RETURN(0);
  OUT();
}

static int pipe_journal(struct rhizome_fetch_slot *slot){
  if (!slot->previous)
    return 0;
    
  /* we need to work out the overlapping range that we can copy from the previous version
   * then we can start to transfer only the new content in the journal
   *   old; [  tail  |0                   length]
   *   new; [  tail         |0                          length]
   *        [               | written | overlap |  new content]
   */
  
  assert(slot->manifest->tail != RHIZOME_SIZE_UNSET);
  assert(slot->previous->tail != RHIZOME_SIZE_UNSET);
  assert(slot->previous->filesize != RHIZOME_SIZE_UNSET);
  uint64_t start = slot->manifest->tail - slot->previous->tail + slot->write_state.file_offset;
  uint64_t length = slot->previous->filesize - slot->manifest->tail - slot->write_state.file_offset;
  
  // of course there might not be any overlap
  if (start>=0 && start < slot->previous->filesize && length>0){
    if (config.debug.rhizome)
      DEBUGF("Copying %"PRId64" bytes from previous journal", length);
    rhizome_journal_pipe(&slot->write_state, &slot->previous->filehash, start, length);
  }
  
  // and we don't need to do this again, so drop the manifest
  rhizome_manifest_free(slot->previous);
  slot->previous=NULL;
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
  IN();
  if (!is_rhizome_mdp_enabled()){
    RETURN(rhizome_fetch_close(slot));
  }
  if (!my_subscriber) {
    DEBUGF("I don't have an identity, so we cannot fall back to MDP");
    RETURN(rhizome_fetch_close(slot));
  }

  if (config.debug.rhizome_rx)
    DEBUGF("Trying to switch to MDP for Rhizome fetch: slot=0x%p (%"PRIu64" bytes)",
	   slot, slot->write_state.file_length);
  
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
  
  pipe_journal(slot);
  
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
  slot->mdpIdleTimeout = config.rhizome.idle_timeout; // give up if nothing received for 5 seconds
  
  unsigned char log_size=log2ll(slot->manifest->filesize);
  struct rhizome_fetch_queue *q=rhizome_find_queue(log_size);
  // increase the timeout based on the queue number
  if (q)
    slot->mdpIdleTimeout *= 1+(q - rhizome_fetch_queues);
  
  slot->mdpRXBlockLength = config.rhizome.rhizome_mdp_block_size; // Rhizome over MDP block size
  rhizome_fetch_mdp_requestblocks(slot);

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

int rhizome_write_complete(struct rhizome_fetch_slot *slot)
{
  IN();

  if (slot->manifest) {
    if (slot->write_state.file_offset < slot->write_state.file_length)
      RETURN(0);

    // Were fetching payload, now we have it.
    if (config.debug.rhizome_rx)
      DEBUGF("Received all of file via rhizome -- now to import it");

    if (rhizome_finish_write(&slot->write_state)){
      rhizome_fetch_close(slot);
      RETURN(-1);
    }

    if (rhizome_import_received_bundle(slot->manifest)){
      rhizome_fetch_close(slot);
      RETURN(-1);
    }

    if (slot->state==RHIZOME_FETCH_RXFILE) {
      char buf[INET_ADDRSTRLEN];
      if (inet_ntop(AF_INET, &slot->peer_ipandport.sin_addr, buf, sizeof buf) == NULL) {
	buf[0] = '*';
	buf[1] = '\0';
      }
      INFOF("Completed http request from %s:%u  for file %s",
	      buf, ntohs(slot->peer_ipandport.sin_port), 
	      alloca_tohex_rhizome_filehash_t(slot->manifest->filehash));
    } else {
      INFOF("Completed MDP request from %s  for file %s",
	    alloca_tohex_sid_t(slot->peer_sid),
	    alloca_tohex_rhizome_filehash_t(slot->manifest->filehash));
    }
  } else {
    /* This was to fetch the manifest, so now fetch the file if needed */
    if (config.debug.rhizome_rx)
      DEBUGF("Received a manifest in response to supplying a manifest prefix.");
    /* Read the manifest and add it to suggestion queue, then immediately
       call schedule queued items. */
    rhizome_manifest *m = rhizome_new_manifest();
    if (m) {
      if (rhizome_read_manifest_file(m, slot->manifest_buffer, (size_t)slot->manifest_bytes) == -1) {
	DEBUGF("Couldn't read manifest");
	rhizome_manifest_free(m);
      } else {
	if (config.debug.rhizome_rx){
	  DEBUGF("All looks good for importing manifest id=%s", alloca_tohex_rhizome_bid_t(m->cryptoSignPublic));
	  dump("slot->peerip",&slot->peer_ipandport,sizeof(slot->peer_ipandport));
	  dump("slot->peersid",&slot->peer_sid,sizeof(slot->peer_sid));
	}
	rhizome_suggest_queue_manifest_import(m, &slot->peer_ipandport, &slot->peer_sid);
      }
    }
  }

  if (config.debug.rhizome_rx) {
    time_ms_t now = gettime_ms();
    time_ms_t interval = now - slot->start_time;
    if (interval <= 0)
      interval = 1;
    DEBUGF("Closing rhizome fetch slot = 0x%p.  Received %"PRIu64" bytes in %"PRIu64"ms (%"PRIu64"KB/sec).",
           slot, slot->write_state.file_offset,
           (uint64_t)interval,
           slot->write_state.file_offset / (uint64_t)interval
	  );
  }

  rhizome_fetch_close(slot);
  RETURN(-1);
}

int rhizome_write_content(struct rhizome_fetch_slot *slot, unsigned char *buffer, size_t bytes)
{
  IN();
  
  if (bytes<=0)
    RETURN(0);
  
  // Truncate to known length of file (handy for reading from journal bundles that
  // might grow while we are reading from them).
  if (bytes > slot->write_state.file_length - slot->write_state.file_offset) {
    bytes = slot->write_state.file_length - slot->write_state.file_offset;
  }

  if (!slot->manifest){
    /* We are reading a manifest.  Read it into a buffer. */
    unsigned count = bytes;
    if (count + slot->manifest_bytes > 1024)
      count = 1024 - slot->manifest_bytes;
    bcopy(buffer,&slot->manifest_buffer[slot->manifest_bytes],count);
    slot->manifest_bytes+=count;
    slot->write_state.file_offset += count;
  } else {
    
    /* We are reading a file. Stream it into the database. */
    if (rhizome_write_buffer(&slot->write_state, buffer, bytes)){
      rhizome_fetch_close(slot);
      RETURN(-1);
    }

  }

  slot->last_write_time=gettime_ms();
  RETURN(rhizome_write_complete(slot));

  // slot is still open
  RETURN(0);
  OUT();
}

int rhizome_received_content(const unsigned char *bidprefix,
			     uint64_t version, uint64_t offset,
			     size_t count, unsigned char *bytes, int type)
{
  IN();
  if (!is_rhizome_mdp_enabled()) {
    RETURN(-1);
  }
  struct rhizome_fetch_slot *slot=fetch_search_slot(bidprefix, 16);
  
  if (slot && slot->bidVersion == version && slot->state == RHIZOME_FETCH_RXFILEMDP){
    if (config.debug.rhizome)
      DEBUGF("Rhizome over MDP receiving %zu bytes.", count);
    if (rhizome_random_write(&slot->write_state, offset, bytes, count)){
      if (config.debug.rhizome)
	DEBUGF("Write failed!");
      RETURN (-1);
    }
    
    if (rhizome_write_complete(slot)){
      if (config.debug.rhizome)
	DEBUGF("Complete failed!");
      RETURN(-1);
    }
    
    slot->last_write_time=gettime_ms();
    rhizome_fetch_mdp_touch_timeout(slot);

    slot->mdpResponsesOutstanding--;
    if (slot->mdpResponsesOutstanding==0) {
      // We have received all responses, so immediately ask for more
      rhizome_fetch_mdp_requestblocks(slot);
    }
    RETURN(0);
  }
  
  // if we get a packet containing an entire payload
  // we may wish to store it, even if we aren't already fetching this payload via MDP
  if (offset == 0){
    rhizome_manifest *m = NULL;
    struct rhizome_fetch_candidate *c = NULL;
    
    if (slot && slot->bidVersion == version && slot->manifest->filesize == count 
	  && slot->state != RHIZOME_FETCH_RXFILEMDP) {
      m=slot->manifest;
    }else{
      slot = NULL;
      c = fetch_search_candidate(bidprefix, 16);
      if (c && c->manifest->version == version && c->manifest->filesize == count)
	m=c->manifest;
    }
    
    if (m){
      if (rhizome_import_buffer(m, bytes, count) >= 0 && !rhizome_import_received_bundle(m)){
	INFOF("Completed MDP transfer in one hit for file %s",
	    alloca_tohex_rhizome_filehash_t(m->filehash));
	if (c)
	  candidate_unqueue(c);
      }
      
      if (slot)
	rhizome_fetch_close(slot);
      
      RETURN(0);
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
      unsigned char buffer[8192];
      sigPipeFlag = 0;
      errno=0;
      int bytes = read_nonblock(slot->alarm.poll.fd, buffer, sizeof buffer);
      /* If we got some data, see if we have found the end of the HTTP request */
      if (bytes > 0) {
	rhizome_write_content(slot, buffer, bytes);
	// reset inactivity timeout
	unschedule(&slot->alarm);
	slot->alarm.alarm=gettime_ms() + config.rhizome.idle_timeout;
	slot->alarm.deadline = slot->alarm.alarm + config.rhizome.idle_timeout;
	schedule(&slot->alarm);
	return;
      } else {
	if (errno!=EAGAIN) {
	  if (config.debug.rhizome_rx)
	    DEBUGF("Empty read, closing connection: received %"PRIu64" of %"PRIu64" bytes",
		   slot->write_state.file_offset,
		   slot->write_state.file_length);
	  rhizome_fetch_switch_to_mdp(slot);
	}
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
	if (is_http_header_complete(slot->request, slot->request_len, bytes)) {
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
	  if (parts.code != 200 && parts.code != 206) {
	    if (config.debug.rhizome_rx)
	      DEBUGF("Failed HTTP request: rhizome server returned %03u", parts.code);
	    rhizome_fetch_switch_to_mdp(slot);
	    return;
	  }
	  if (parts.content_length == -1) {
	    if (config.debug.rhizome_rx)
	      DEBUGF("Invalid HTTP reply: missing Content-Length header");
	    rhizome_fetch_switch_to_mdp(slot);
	    return;
	  }
	  if (slot->write_state.file_length == RHIZOME_SIZE_UNSET)
	    slot->write_state.file_length = parts.content_length;
	  else if (parts.content_length + parts.range_start != slot->write_state.file_length)
	    WARNF("Expected content length %"PRIu64", got %"PRIu64" + %"PRIu64, 
	      slot->write_state.file_length, parts.content_length, parts.range_start);
	  /* We have all we need.  The file is already open, so just write out any initial bytes of
	     the body we read.
	  */
	  slot->state = RHIZOME_FETCH_RXFILE;
	  if (slot->previous && parts.range_start){
	    if (parts.range_start != slot->previous->filesize - slot->manifest->tail)
	      WARNF("Expected Content-Range header to start @%"PRIu64, slot->previous->filesize - slot->manifest->tail);
	    pipe_journal(slot);
	  }
	  
	  int content_bytes = slot->request + slot->request_len - parts.content_start;
	  if (content_bytes > 0){
	    rhizome_write_content(slot, (unsigned char*)parts.content_start, content_bytes);
	    // reset inactivity timeout
	    unschedule(&slot->alarm);
	    slot->alarm.alarm=gettime_ms() + config.rhizome.idle_timeout;
	    slot->alarm.deadline = slot->alarm.alarm + config.rhizome.idle_timeout;
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
    switch (slot->state){
      case RHIZOME_FETCH_RXFILEMDP:
	rhizome_fetch_mdp_slot_callback(alarm);
	break;

      default:
        // timeout or socket error, close the socket
        if (config.debug.rhizome_rx)
          DEBUGF("Closing due to timeout or error %x (%x %x)", alarm->poll.revents, POLLHUP, POLLERR);
        if (slot->state!=RHIZOME_FETCH_FREE&&slot->state!=RHIZOME_FETCH_RXFILEMDP)
          rhizome_fetch_switch_to_mdp(slot);
    }
  }
}

/*
   This function takes a pointer to a buffer into which the entire HTTP response header has been
   read.  The caller must have ensured that the buffer contains at least one consecutive pair of
   newlines '\n', optionally with carriage returns '\r' preceding and optionally interspersed with
   nul characters '\0' (which can originate from telnet).  The is_http_header_complete() function
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
  parts->code = 0;
  parts->reason = NULL;
  parts->range_start=0;
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
    if (strcase_startswith(p, "Content-Range: bytes ", (const char **)&p)) {
      char *nump = p;
      while (isdigit(*p))
	parts->range_start = parts->range_start * 10 + *p++ - '0';
      if (p == nump) {
	if (config.debug.rhizome_rx)
	  DEBUGF("Invalid HTTP reply: malformed Content-Range header");
	RETURN(-1);
      }
    }
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
