/* 
 Serval Daemon
 Copyright (C) 2012 Serval Project Inc.
 
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

#ifndef _SERVALD_OVERLAY_BUFFER_H
#define _SERVALD_OVERLAY_BUFFER_H

struct overlay_buffer {
  unsigned char *bytes;
  
  // remembered position for rewinding
  int checkpointLength;
  
  // position of data read / written
  int position;
  
  // maximum allowed bytes for reading / writing
  int sizeLimit;
  
  // size of buffer
  int allocSize;
  
  // is this an allocated buffer? can it be resized? Should it be freed?
  unsigned char * allocated;
  
  // length position for later patching
  int var_length_offset;
};

struct overlay_buffer *ob_new(void);
struct overlay_buffer *ob_static(unsigned char *bytes, int size);
struct overlay_buffer *ob_slice(struct overlay_buffer *b, int offset, int length);
struct overlay_buffer *ob_dup(struct overlay_buffer *b);
int ob_free(struct overlay_buffer *b);
int ob_checkpoint(struct overlay_buffer *b);
int ob_rewind(struct overlay_buffer *b);
int ob_limitsize(struct overlay_buffer *b,int bytes);
int ob_unlimitsize(struct overlay_buffer *b);
int ob_makespace(struct overlay_buffer *b,int bytes);
int ob_set(struct overlay_buffer *b, int ofs, unsigned char byte);
int ob_append_byte(struct overlay_buffer *b,unsigned char byte);
int ob_append_bytes(struct overlay_buffer *b,const unsigned char *bytes,int count);
int ob_append_buffer(struct overlay_buffer *b,const struct overlay_buffer *s);
unsigned char *ob_append_space(struct overlay_buffer *b,int count);
int ob_append_ui16(struct overlay_buffer *b, uint16_t v);
int ob_append_ui32(struct overlay_buffer *b, uint32_t v);
int ob_append_ui64(struct overlay_buffer *b, uint64_t v);
int ob_append_packed_ui32(struct overlay_buffer *b, uint32_t v);
int ob_append_packed_ui64(struct overlay_buffer *b, uint64_t v);
int ob_patch_rfs(struct overlay_buffer *b);
int ob_append_rfs(struct overlay_buffer *b,int l);
// get one byte, -ve number indicates failure
int ob_getbyte(struct overlay_buffer *b,int ofs);
// get one byte from the current position, -ve number indicates failure
int ob_get(struct overlay_buffer *b);
int ob_get_bytes(struct overlay_buffer *b, unsigned char *buff, int len);
unsigned char * ob_get_bytes_ptr(struct overlay_buffer *b, int len);
uint64_t ob_get_ui64(struct overlay_buffer *b);
uint32_t ob_get_ui32(struct overlay_buffer *b);
uint16_t ob_get_ui16(struct overlay_buffer *b);
int ob_dump(struct overlay_buffer *b,char *desc);
int ob_set_ui16(struct overlay_buffer *b, int offset, uint16_t v);

uint32_t ob_get_packed_ui32(struct overlay_buffer *b);
uint64_t ob_get_packed_ui64(struct overlay_buffer *b);

// information routines
int ob_position(struct overlay_buffer *b);
int ob_limit(struct overlay_buffer *b);
int ob_remaining(struct overlay_buffer *b);
unsigned char* ob_ptr(struct overlay_buffer *b);
#endif
