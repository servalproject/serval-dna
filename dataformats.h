/*
Serval DNA data interchange formats
Copyright (C) 2012-2013 Serval Project Inc.

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
#ifndef __SERVAL_DNA___DATA_FORMATS_H
#define __SERVAL_DNA___DATA_FORMATS_H

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
int rhizome_str_is_manifest_name(const char *text);

void write_uint64(unsigned char *o,uint64_t v);
void write_uint16(unsigned char *o,uint16_t v);
void write_uint32(unsigned char *o,uint32_t v);
uint64_t read_uint64(const unsigned char *o);
uint32_t read_uint32(const unsigned char *o);
uint16_t read_uint16(const unsigned char *o);

// compare sequence numbers that wrap
// returns <0 if one is before two, 0 if they are the same, else >0
int compare_wrapped_uint8(uint8_t one, uint8_t two);
int compare_wrapped_uint16(uint16_t one, uint16_t two);

#define parse_hex_t(bin, hex) fromhexstr(bin->binary, sizeof bin->binary, hex)
#define parse_hexn_t(bin, hex, hexlen, endp) fromhexstrn(bin->binary, sizeof bin->binary, hex, hexlen, endp)

#endif //__SERVAL_DNA___DATA_FORMATS_H
