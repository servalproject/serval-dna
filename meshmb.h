#ifndef __SERVAL_DNA__MESHMB_H
#define __SERVAL_DNA__MESHMB_H

struct meshmb_feeds;

enum meshmb_send_status{
  MESHMB_ERROR = -1,
  MESHMB_OK = 0,
};

// details of a feed that you are following
struct meshmb_feed_details{
  struct message_ply ply;
  const char *name;
  const char *last_message;
  time_s_t timestamp;
  bool_t blocked:1;
  bool_t overridden_name:1;
};

// threaded feed iterator state
struct meshmb_activity_iterator{
  struct meshmb_feeds *feeds;
  struct message_ply_read ack_reader;
  time_s_t ack_timestamp;
  uint64_t ack_start;
  struct feed_metadata *metadata;
  struct message_ply_read msg_reader;
};

struct rhizome_manifest_field_assignment;
int meshmb_send(struct meshmb_feeds *feeds, const char *message, size_t message_len,
  unsigned nassignments, const struct rhizome_manifest_field_assignment *assignments);

// feed tracking
int meshmb_open(keyring_identity *id, struct meshmb_feeds **feeds);
void meshmb_close(struct meshmb_feeds *feeds);

// re-write metadata if required
// returns -1 on failure, or a generation number that is incremented only if something has changed.
int meshmb_flush(struct meshmb_feeds *feeds);

// set / clear follow flag for this feed
int meshmb_follow(struct meshmb_feeds *feeds, const rhizome_bid_t *bid, const sid_t *sender, const char *name);
int meshmb_ignore(struct meshmb_feeds *feeds, const rhizome_bid_t *bid);
int meshmb_block(struct meshmb_feeds *feeds, const rhizome_bid_t *bid, const sid_t *sender);

// enumerate feeds, starting from restart_from
typedef int (*meshmb_callback) (struct meshmb_feed_details *details, void *context);
int meshmb_enum(struct meshmb_feeds *feeds, rhizome_bid_t *restart_from, meshmb_callback callback, void *context);

// enumerate messages, starting with the most recently received
struct meshmb_activity_iterator *meshmb_activity_open(struct meshmb_feeds *feeds);
int meshmb_activity_next(struct meshmb_activity_iterator *i);
int meshmb_activity_seek(struct meshmb_activity_iterator *i, uint64_t ack_offset, uint64_t msg_offset);
void meshmb_activity_close(struct meshmb_activity_iterator *i);

// update metadata of all feeds based on current rhizome contents (optionally call after opening)
int meshmb_update(struct meshmb_feeds *feeds);
// update metadata of a single feed, eg because of a new bundle or when about to read a single ply.
// it is the callers reponsibility to supply a reader and close it
int meshmb_bundle_update(struct meshmb_feeds *feeds, rhizome_manifest *m, struct message_ply_read *reader);

#endif
