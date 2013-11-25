#ifndef __SERVALD_DATA_FORMATS_H
#define __SERVALD_DATA_FORMATS_H

int str_is_subscriber_id(const char *sid);
int strn_is_subscriber_id(const char *sid, size_t *lenp);
int str_is_did(const char *did);
int strn_is_did(const char *did, size_t *lenp);

int rhizome_strn_is_manifest_id(const char *text);
int rhizome_str_is_manifest_id(const char *text);
int rhizome_strn_is_bundle_key(const char *text);
int rhizome_str_is_bundle_key(const char *text);
int rhizome_strn_is_bundle_crypt_key(const char *text);
int rhizome_str_is_bundle_crypt_key(const char *text);
int rhizome_strn_is_file_hash(const char *text);
int rhizome_str_is_file_hash(const char *text);
int rhizome_str_is_manifest_service(const char *text);

void write_uint64(unsigned char *o,uint64_t v);
void write_uint16(unsigned char *o,uint16_t v);
void write_uint32(unsigned char *o,uint32_t v);
uint64_t read_uint64(const unsigned char *o);
uint32_t read_uint32(const unsigned char *o);
uint16_t read_uint16(const unsigned char *o);

#endif
