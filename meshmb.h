#ifndef __SERVAL_DNA__MESHMB_H
#define __SERVAL_DNA__MESHMB_H

int meshmb_send(keyring_identity *id, const char *message, size_t message_len,
  unsigned nassignments, const struct rhizome_manifest_field_assignment *assignments);

#endif