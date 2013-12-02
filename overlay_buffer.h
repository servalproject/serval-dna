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

#ifndef __SERVALD__OVERLAY_BUFFER_H
#define __SERVALD__OVERLAY_BUFFER_H

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

struct overlay_buffer *_ob_new(struct __sourceloc __whence);
struct overlay_buffer *_ob_static(struct __sourceloc __whence, unsigned char *bytes, int size);
struct overlay_buffer *_ob_slice(struct __sourceloc __whence, struct overlay_buffer *b, int offset, int length);
struct overlay_buffer *_ob_dup(struct __sourceloc __whence, struct overlay_buffer *b);
void _ob_free(struct __sourceloc __whence, struct overlay_buffer *b);
int _ob_checkpoint(struct __sourceloc __whence, struct overlay_buffer *b);
int _ob_rewind(struct __sourceloc __whence, struct overlay_buffer *b);
void _ob_limitsize(struct __sourceloc __whence, struct overlay_buffer *b,int bytes);
void _ob_flip(struct __sourceloc __whence, struct overlay_buffer *b);
void _ob_unlimitsize(struct __sourceloc __whence, struct overlay_buffer *b);
ssize_t _ob_makespace(struct __sourceloc whence, struct overlay_buffer *b, size_t bytes);
void _ob_set(struct __sourceloc __whence, struct overlay_buffer *b, int ofs, unsigned char byte);
void _ob_set_ui16(struct __sourceloc __whence, struct overlay_buffer *b, int offset, uint16_t v);
void _ob_patch_rfs(struct __sourceloc __whence, struct overlay_buffer *b);

void _ob_append_byte(struct __sourceloc whence, struct overlay_buffer *b,unsigned char byte);
void _ob_append_bytes(struct __sourceloc whence, struct overlay_buffer *b,const unsigned char *bytes,int count);
void _ob_append_buffer(struct __sourceloc whence, struct overlay_buffer *b,struct overlay_buffer *s);
unsigned char *_ob_append_space(struct __sourceloc whence, struct overlay_buffer *b,int count);
void _ob_append_ui16(struct __sourceloc whence, struct overlay_buffer *b, uint16_t v);
void _ob_append_ui32(struct __sourceloc whence, struct overlay_buffer *b, uint32_t v);
void _ob_append_ui64(struct __sourceloc whence, struct overlay_buffer *b, uint64_t v);
void _ob_append_packed_ui32(struct __sourceloc whence, struct overlay_buffer *b, uint32_t v);
void _ob_append_packed_ui64(struct __sourceloc whence, struct overlay_buffer *b, uint64_t v);
void _ob_append_rfs(struct __sourceloc whence, struct overlay_buffer *b,int l);

#define ob_new() _ob_new(__WHENCE__)
#define ob_static(bytes, size) _ob_static(__WHENCE__, bytes, size)
#define ob_slice(b, off, len) _ob_slice(__WHENCE__, b, off, len)
#define ob_dup(b) _ob_dup(__WHENCE__, b)
#define ob_free(b) _ob_free(__WHENCE__, b)
#define ob_checkpoint(b) _ob_checkpoint(__WHENCE__, b)
#define ob_rewind(b) _ob_rewind(__WHENCE__, b)
#define ob_limitsize(b, size) _ob_limitsize(__WHENCE__, b, size)
#define ob_flip(b) _ob_flip(__WHENCE__, b)
#define ob_unlimitsize(b) _ob_unlimitsize(__WHENCE__, b)
#define ob_makespace(b, bytes) _ob_makespace(__WHENCE__, b, bytes)
#define ob_set(b, off, byte) _ob_set(__WHENCE__, b, off, byte)
#define ob_set_ui16(b, off, v) _ob_set_ui16(__WHENCE__, b, off, v)
#define ob_patch_rfs(b) _ob_patch_rfs(__WHENCE__, b)

#define ob_append_byte(b, byte) _ob_append_byte(__WHENCE__, b, byte)
#define ob_append_bytes(b, bytes, count) _ob_append_bytes(__WHENCE__, b, bytes, count)
#define ob_append_buffer(b, s) _ob_append_buffer(__WHENCE__, b, s)
#define ob_append_space(b, count) _ob_append_space(__WHENCE__, b, count)
#define ob_append_ui16(b, v) _ob_append_ui16(__WHENCE__, b, v)
#define ob_append_ui32(b, v) _ob_append_ui32(__WHENCE__, b, v)
#define ob_append_ui64(b, v) _ob_append_ui64(__WHENCE__, b, v)
#define ob_append_packed_ui32(b, v) _ob_append_packed_ui32(__WHENCE__, b, v)
#define ob_append_packed_ui64(b, v) _ob_append_packed_ui64(__WHENCE__, b, v)
#define ob_append_rfs(b, l) _ob_append_rfs(__WHENCE__, b, l)

// get one byte, -ve number indicates failure
int ob_peek(struct overlay_buffer *b);
void ob_skip(struct overlay_buffer *b, unsigned n);
// get one byte from the current position, -ve number indicates failure
int ob_get(struct overlay_buffer *b);
int ob_get_bytes(struct overlay_buffer *b, unsigned char *buff, int len);
unsigned char * ob_get_bytes_ptr(struct overlay_buffer *b, int len);
uint64_t ob_get_ui64(struct overlay_buffer *b);
uint32_t ob_get_ui32(struct overlay_buffer *b);
uint16_t ob_get_ui16(struct overlay_buffer *b);
int ob_dump(struct overlay_buffer *b,char *desc);

uint32_t ob_get_packed_ui32(struct overlay_buffer *b);
uint64_t ob_get_packed_ui64(struct overlay_buffer *b);

// information routines
int ob_position(struct overlay_buffer *b);
int ob_limit(struct overlay_buffer *b);
int ob_remaining(struct overlay_buffer *b);
int _ob_overrun(struct __sourceloc, struct overlay_buffer *b);
unsigned char* ob_ptr(struct overlay_buffer *b);

#define ob_overrun(b) _ob_overrun(__WHENCE__, b)

#endif //__SERVALD__OVERLAY_BUFFER_H
