
#ifndef __SERVAL_DNA__MESSAGE_PLY_H
#define __SERVAL_DNA__MESSAGE_PLY_H

#define MESSAGE_PLY_MAX_LEN  4095

#define MESSAGE_BLOCK_TYPE_ACK 0x01
#define MESSAGE_BLOCK_TYPE_MESSAGE 0x02 // NUL-terminated UTF8 string
#define MESSAGE_BLOCK_TYPE_TIME 0x03 // local timestamp record

// the manifest details for one ply
struct message_ply {
  rhizome_bid_t bundle_id;
  uint64_t version;
  uint64_t tail;
  uint64_t size;
  uint8_t found:1;
  uint8_t known_bid:1;
};

// cursor state for reading one ply
struct message_ply_read {
  // rhizome payload
  struct rhizome_read read;
  // block buffer
  struct rhizome_read_buffer buff;
  // copy of the manifest name field
  const char *name;
  // details of the current record
  uint64_t record_end_offset;
  uint16_t record_length;
  size_t record_size;
  uint8_t type;
  // raw record data
  uint8_t *record;
};

int message_ply_read_open(struct message_ply_read *ply, const rhizome_bid_t *bid);
void message_ply_read_close(struct message_ply_read *ply);
int message_ply_read_prev(struct message_ply_read *ply);
int message_ply_find_prev(struct message_ply_read *ply, char type);
int message_ply_is_open(struct message_ply_read *ply);
void message_ply_read_rewind(struct message_ply_read *ply);

void message_ply_append_ack(struct overlay_buffer *b, uint64_t message_offset, uint64_t previous_ack_offset);
void message_ply_append_timestamp(struct overlay_buffer *b);
void message_ply_append_message(struct overlay_buffer *b, const char *message, size_t message_len);
int message_ply_append(const struct keyring_identity *id, const char *service, const sid_t *recipient, struct message_ply *ply, struct overlay_buffer *b,
  const char *name, unsigned nassignments, const struct rhizome_manifest_field_assignment *assignments);

#endif