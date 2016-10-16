
#include "serval.h"
#include "dataformats.h"
#include "rhizome.h"
#include "message_ply.h"
#include "log.h"
#include "debug.h"
#include "conf.h"
#include "overlay_buffer.h"

static int message_ply_load_manifest(const keyring_identity *id, struct message_ply *ply, rhizome_manifest *m)
{
  assert(ply->known_bid);
  if (rhizome_retrieve_manifest(&ply->bundle_id, m) != RHIZOME_BUNDLE_STATUS_SAME)
    return 1;
  rhizome_authenticate_author(m);
  if (!m->haveSecret || m->authorship != AUTHOR_AUTHENTIC)
    return -1;
  assert(m->author_identity == id);
  return 0;
}

static int message_ply_fill_manifest(const keyring_identity *id, const sid_t *recipient, struct message_ply *ply, rhizome_manifest *m)
{
  assert(!ply->found);
  rhizome_manifest_set_sender(m, id->box_pk);
  rhizome_manifest_set_recipient(m, recipient);
  rhizome_manifest_set_filesize(m, 0);
  rhizome_manifest_set_tail(m, 0);
  rhizome_manifest_set_author_identity(m, id);
  int ret=-1;
  struct rhizome_bundle_result result = rhizome_fill_manifest(m, NULL);
  switch (result.status) {
    case RHIZOME_BUNDLE_STATUS_NEW:
    case RHIZOME_BUNDLE_STATUS_SAME:
    case RHIZOME_BUNDLE_STATUS_DUPLICATE:
      ret = 0;
      break;
    case RHIZOME_BUNDLE_STATUS_ERROR:
    case RHIZOME_BUNDLE_STATUS_INVALID:
    case RHIZOME_BUNDLE_STATUS_INCONSISTENT:
      WHYF("Error creating ply manifest: %s", alloca_rhizome_bundle_result(result));
      break;
    case RHIZOME_BUNDLE_STATUS_BUSY:
      // TODO
    case RHIZOME_BUNDLE_STATUS_OLD:
    case RHIZOME_BUNDLE_STATUS_FAKE:
    case RHIZOME_BUNDLE_STATUS_NO_ROOM:
    case RHIZOME_BUNDLE_STATUS_MANIFEST_TOO_BIG:
      WARNF("Cannot create ply manifest: %s", alloca_rhizome_bundle_result(result));
      break;
    case RHIZOME_BUNDLE_STATUS_READONLY:
      INFOF("Cannot create ply manifest: %s", alloca_rhizome_bundle_result(result));
      break;
  }
  rhizome_bundle_result_free(&result);
  if (ret==0){
    assert(m->haveSecret);
    assert(!recipient || m->payloadEncryption == PAYLOAD_ENCRYPTED);
    ply->bundle_id = m->keypair.public_key;
    ply->found = ply->known_bid = 1;
  }
  return ret;
}

int message_ply_append(const keyring_identity *id, const char *service, const sid_t *recipient, struct message_ply *ply, struct overlay_buffer *b,
  const char *name, unsigned nassignments, const struct rhizome_manifest_field_assignment *assignments)
{
  rhizome_manifest *mout = NULL;
  rhizome_manifest *m = rhizome_new_manifest();
  if (!m)
    return -1;

  int ret=-1;

  if (ply->known_bid){
    switch(message_ply_load_manifest(id, ply, m)){
      case 0:
	ply->found = 1;
	break;
      case 1:
	ply->found = 0;
	break;
      default:
	goto end;
    }
  }

  // TODO add sender name?
  // if recipient, actual sender & name should be encrypted...
  if (name)
	  rhizome_manifest_set_name(m, name);

  struct rhizome_bundle_result result = rhizome_apply_assignments(m, nassignments, assignments);
  if (result.status != RHIZOME_BUNDLE_STATUS_NEW){
    WARNF("Cannot create message ply manifest: %s", alloca_rhizome_bundle_result(result));
    rhizome_bundle_result_free(&result);
    goto end;
  }
  rhizome_bundle_result_free(&result);

  if (!ply->found){
    rhizome_manifest_set_service(m, service);
    if (ply->known_bid)
      rhizome_manifest_set_id(m, &ply->bundle_id);
    if (message_ply_fill_manifest(id, recipient, ply, m)!=0)
      goto end;
  }

  enum rhizome_payload_status pstatus = rhizome_append_journal_buffer(m, 0, ob_ptr(b), ob_position(b));
  if (pstatus != RHIZOME_PAYLOAD_STATUS_NEW)
    goto end;

  result = rhizome_manifest_finalise(m, &mout, 1);
  if (result.status != RHIZOME_BUNDLE_STATUS_NEW){
    WARNF("Cannot create message ply manifest: %s", alloca_rhizome_bundle_result(result));
    rhizome_bundle_result_free(&result);
    goto end;
  }
  rhizome_bundle_result_free(&result);

  ret = 0;

end:
  if (mout && mout!=m)
    rhizome_manifest_free(mout);
  if (m)
    rhizome_manifest_free(m);
  return ret;
}

int message_ply_read_open(struct message_ply_read *ply, const rhizome_bid_t *bid)
{
  DEBUGF(meshms, "Opening ply %s", alloca_tohex_rhizome_bid_t(*bid));

  rhizome_manifest *m = rhizome_new_manifest();
  if (!m)
    return -1;

  int ret=-1;
  if (rhizome_retrieve_manifest(bid, m) == RHIZOME_BUNDLE_STATUS_SAME
    && rhizome_open_decrypt_read(m, &ply->read) == RHIZOME_PAYLOAD_STATUS_STORED){

    assert(m->filesize != RHIZOME_SIZE_UNSET);
    ply->read.offset = ply->read.length = m->filesize;
    if (m->name && *m->name)
      ply->name = str_edup(m->name);
    ret = 0;
  }
  rhizome_manifest_free(m);
  return ret;
}

void message_ply_read_rewind(struct message_ply_read *ply)
{
  ply->read.offset = ply->read.length;
}

int message_ply_is_open(struct message_ply_read *ply)
{
  return ply->read.length>0;
}

void message_ply_read_close(struct message_ply_read *ply)
{
  if (ply->record){
    free(ply->record);
    ply->record=NULL;
  }
  if (ply->name){
    free((void*)ply->name);
    ply->name = NULL;
  }
  ply->record_size=0;
  ply->buff.len=0;
  rhizome_read_close(&ply->read);
}

// read the next record from the ply (backwards)
// returns -1 if there is an error, or if at the end of records
int message_ply_read_prev(struct message_ply_read *ply)
{
  ply->record_end_offset = ply->read.offset;
  uint8_t footer[2];
  if (ply->read.offset <= sizeof footer) {
    DEBUG(meshms, "EOF");
    return -1;
  }
  ply->read.offset -= sizeof footer;
  ssize_t read = rhizome_read_buffered(&ply->read, &ply->buff, footer, sizeof footer);
  if (read == -1)
    return WHYF("rhizome_read_buffered() failed");
  if ((size_t) read != sizeof footer)
    return WHYF("Expected %zu bytes read, got %zu", (size_t) sizeof footer, (size_t) read);
  // (rhizome_read automatically advances the offset by the number of bytes read)
  {
    uint16_t r = read_uint16(footer);
    ply->type = r & 0xF;
    ply->record_length = r >> 4;
  }
  DEBUGF(meshms, "Found record %d, length %d @%"PRId64, ply->type, ply->record_length, ply->record_end_offset);
  // need to allow for advancing the tail and cutting a message in half.
  if (ply->record_length + sizeof footer > ply->read.offset){
    DEBUGF(meshms, "EOF");
    return -1;
  }
  ply->read.offset -= ply->record_length + sizeof(footer);
  uint64_t record_start = ply->read.offset;
  if (ply->record_size < ply->record_length){
    ply->record_size = ply->record_length;
    unsigned char *b = erealloc(ply->record, ply->record_size);
    if (!b)
      return -1;
    ply->record = b;
  }
  read = rhizome_read_buffered(&ply->read, &ply->buff, ply->record, ply->record_length);
  if (read == -1)
    return WHYF("rhizome_read_buffered() failed");
  if ((size_t) read != ply->record_length)
    return WHYF("Expected %u bytes read, got %zu", ply->record_length, (size_t) read);
  ply->read.offset = record_start;
  return 0;
}

// keep reading past messages until you find this type.
int message_ply_find_prev(struct message_ply_read *ply, const char message_type)
{
  int ret;
  while ((ret = message_ply_read_prev(ply)) == 0 && ply->type != message_type)
    ;
  return ret;
}

static void append_footer(struct overlay_buffer *b, char type)
{
  size_t message_len = ob_position(b) - ob_mark(b);
  assert(message_len <= MESSAGE_PLY_MAX_LEN);
  ob_append_ui16_rv(b, (message_len << 4) | (type&0xF));
}

// append a timestamp as a uint32_t with 1s precision
void message_ply_append_timestamp(struct overlay_buffer *b)
{
  if (!config.rhizome.reliable_clock)
    return;
  ob_checkpoint(b);
  ob_append_ui32_rv(b, gettime());
  append_footer(b, MESSAGE_BLOCK_TYPE_TIME);
}

void message_ply_append_ack(struct overlay_buffer *b, uint64_t message_offset, uint64_t previous_ack_offset)
{
  ob_checkpoint(b);
  ob_append_packed_ui64(b, message_offset);
  // append the number of bytes acked (should be smaller than an absolute offset)
  if (previous_ack_offset)
    ob_append_packed_ui64(b, message_offset - previous_ack_offset);
  append_footer(b, MESSAGE_BLOCK_TYPE_ACK);
}

void message_ply_append_message(struct overlay_buffer *b, const char *message, size_t message_len)
{
  ob_checkpoint(b);
  ob_append_strn(b, message, message_len);
  append_footer(b, MESSAGE_BLOCK_TYPE_MESSAGE);
}

