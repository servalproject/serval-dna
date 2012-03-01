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

#define TRANS_CACHE_BUCKETS   (128)
#define TRANS_CACHE_SIZE      (500)

struct entry {
  unsigned char transaction_id[TRANSID_SIZE];
  struct entry *bucket_next; // also used as free list pointer
  struct entry *lru_prev;
  struct entry *lru_next;
};

static struct entry *buckets[TRANS_CACHE_SIZE];
static struct entry *lru_head = NULL;
static struct entry *lru_tail = NULL;
// Static allocation of cache entry pool, but could easily be malloc'd
// instead, in init_pool().
static struct entry entry_pool[TRANS_CACHE_SIZE];
static struct entry *entry_freelist = NULL;
static int entry_pool_initialised = 0;

/* Initialise the transaction cache entry pool.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static void init_pool()
{
  if (!entry_pool_initialised) {
    entry_freelist = NULL;
    int i;
    for (i = 0; i != TRANS_CACHE_SIZE - 1; ++i) {
      entry_pool[i].bucket_next = entry_freelist;
      entry_freelist = &entry_pool[i];
    }
    entry_pool_initialised = 1;
  }
}

/* Hash a 64-bit transaction id to a 32-bit value 0 <= H < 2^32.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static size_t hashTransactionId(unsigned char *transaction_id, size_t len)
{
  // Fold all the bits of the transaction ID into a single 32-bit int.  This code assumes that
  // transaction IDs are uniformly distributed in the range 0..2^64-1, in which case the 32-bit hash
  // will also be uniformly distributed.
#if TRANSID_SIZE != 8
#error "This code assumes that TRANSID_SIZE == 8."
#endif
  uint32_t hash = *(uint32_t*)&transaction_id[0] | *(uint32_t*)&transaction_id[4];
  // If 'len' is an integral factor of 2^32 then the return value will also be uniformly
  // distributed.  Otherwise, if 'len' is much smaller than 2^32, the return value will still be
  // very close to uniform.
  return hash % len;
}

/* Return the hash entry for the given transaction_id, if it exists, otherwise
 * simply return NULL.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static struct entry * findTransactionCacheEntry(unsigned char *transaction_id)
{
  size_t hash = hashTransactionId(transaction_id, TRANS_CACHE_BUCKETS);
  struct entry **bucket = &buckets[hash];
  struct entry *e = *bucket;
  while (e && memcmp(e->transaction_id, transaction_id, TRANSID_SIZE) != 0) {
    e = e->bucket_next;
  }
  return e;
}

/* Insert a cache entry at the head of the LRU list (youngest).
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static void lru_insert_head(struct entry *e)
{
  e->lru_next = lru_head;
  e->lru_prev = NULL;
  lru_head->lru_prev = e;
  lru_head = e;
}

/* Remove a cache entry from the LRU list.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static void lru_remove(struct entry *e)
{
  if (e->lru_prev) {
    e->lru_prev->lru_next = e->lru_next;
  } else {
    lru_head = e->lru_next;
  }
  if (e->lru_next) {
    e->lru_next->lru_prev = e->lru_prev;
  } else {
    lru_tail = e->lru_prev;
  }
}

/* Evict the oldest entry from the cache, if there is one.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
static void evict()
{
  if (lru_tail) {
    struct entry *e = lru_tail;
    lru_remove(e);
    e->bucket_next = entry_freelist;
    entry_freelist = e;
  }
}

/* Insert a transaction ID into the cache, evicting the oldest cache entry to
 * make room, if necessary.
 *
 * Only call this if isTransactionInCache(transaction_id) just returned FALSE,
 * ie, it is known that the transaction ID is not already in the cache.
 * Violating this pre-condition will result in duplicate transaction IDs being
 * added to the cache.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
void insertTransactionInCache(unsigned char *transaction_id)
{
  size_t hash = hashTransactionId(transaction_id, TRANS_CACHE_BUCKETS);
  if (!entry_freelist) {
    init_pool();
  }
  if (!entry_freelist) {
    evict();
  }
  struct entry *e = entry_freelist;
  entry_freelist = e->bucket_next;
  memcpy(e->transaction_id, transaction_id, TRANSID_SIZE);
  struct entry **bucket = &buckets[hash];
  e->bucket_next = *bucket;
  lru_insert_head(e);
  *bucket = e;
}

/* Return TRUE if the given transaction ID is in the cache.  If it is, promote
 * it to the head of the LRU list.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int isTransactionInCache(unsigned char *transaction_id)
{
  struct entry *e = findTransactionCacheEntry(transaction_id);
  if (e && e != lru_head) {
    lru_remove(e);
    lru_insert_head(e);
  }
  return e != NULL;
}
