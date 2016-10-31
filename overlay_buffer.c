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

#include <assert.h>
#include "serval.h"
#include "conf.h"
#include "mem.h"
#include "str.h"
#include "overlay_buffer.h"

/*
 When writing to a buffer, sizeLimit may place an upper bound on the amount of space to use
 
 When reading from a buffer, sizeLimit should first be set to the length of any existing data.
 
 In either case, functions that don't take an offset use and advance the position.
 */

struct overlay_buffer *_ob_new(struct __sourceloc __whence)
{
  struct overlay_buffer *ret = emalloc_zero(sizeof(struct overlay_buffer));
  DEBUGF(overlaybuffer, "ob_new() return %p", ret);
  if (ret == NULL)
    return NULL;
  ob_unlimitsize(ret);
  return ret;
}

// index an existing static buffer.
// and allow other callers to use the ob_ convenience methods for reading and writing up to size bytes.
struct overlay_buffer *_ob_static(struct __sourceloc __whence, unsigned char *bytes, size_t size)
{
  struct overlay_buffer *ret = emalloc_zero(sizeof(struct overlay_buffer));
  DEBUGF(overlaybuffer, "ob_static(bytes=%p, size=%zu) return %p", bytes, size, ret);
  if (ret == NULL)
    return NULL;
  ret->bytes = bytes;
  ret->allocSize = size;
  ret->allocated = NULL;
  ob_unlimitsize(ret);
  return ret;
}

// create a new overlay buffer from an existing piece of another buffer.
// Both buffers will point to the same memory region.
// It is up to the caller to ensure this buffer is not used after the parent buffer is freed.
struct overlay_buffer *_ob_slice(struct __sourceloc __whence, struct overlay_buffer *b, size_t offset, size_t length)
{
  if (offset + length > b->allocSize) {
    WHY("Buffer isn't long enough to slice");
    return NULL;
  }
  struct overlay_buffer *ret = emalloc_zero(sizeof(struct overlay_buffer));
  DEBUGF(overlaybuffer, "ob_slice(b=%p, offset=%zu, length=%zu) return %p", b, offset, length, ret);
  if (ret == NULL)
      return NULL;
  ret->bytes = b->bytes + offset;
  ret->allocSize = length;
  ret->allocated = NULL;
  ob_unlimitsize(ret);
  return ret;
}

struct overlay_buffer *_ob_dup(struct __sourceloc __whence, struct overlay_buffer *b)
{
  struct overlay_buffer *ret = emalloc_zero(sizeof(struct overlay_buffer));
  DEBUGF(overlaybuffer, "ob_dup(b=%p) return %p", b, ret);
  if (ret == NULL)
    return NULL;
  ret->sizeLimit = b->sizeLimit;
  ret->position = b->position;
  ret->checkpointLength = b->checkpointLength;
  if (b->bytes && b->allocSize){
    // duplicate any bytes that might be relevant
    size_t byteCount = b->position;
    if (b->sizeLimit != SIZE_MAX) {
      assert(b->position <= b->sizeLimit);
      byteCount = b->sizeLimit;
    }
    if (byteCount > b->allocSize)
      byteCount = b->allocSize;
    if (byteCount)
      ob_append_bytes(ret, b->bytes, byteCount);
  }
  return ret;
}

void _ob_free(struct __sourceloc __whence, struct overlay_buffer *b)
{
  assert(b != NULL);
  DEBUGF(overlaybuffer, "ob_free(b=%p)", b);
  if (b->allocated)
    free(b->allocated);
  free(b);
}

int _ob_checkpoint(struct __sourceloc __whence, struct overlay_buffer *b)
{
  assert(b != NULL);
  b->checkpointLength = b->position;
  DEBUGF(overlaybuffer, "ob_checkpoint(b=%p) checkpointLength=%zu", b, b->checkpointLength);
  return 0;
}

int _ob_rewind(struct __sourceloc __whence, struct overlay_buffer *b)
{
  assert(b != NULL);
  b->position = b->checkpointLength;
  DEBUGF(overlaybuffer, "ob_rewind(b=%p) position=%zu", b, b->position);
  return 0;
}

void _ob_limitsize(struct __sourceloc __whence, struct overlay_buffer *b, size_t bytes)
{
  assert(b != NULL);
  assert(bytes != SIZE_MAX);
  assert(b->position <= bytes);
  assert(b->checkpointLength <= bytes);
  if (b->bytes && b->allocated == NULL)
    assert(bytes <= b->allocSize);
  b->sizeLimit = bytes;
  DEBUGF(overlaybuffer, "ob_limitsize(b=%p, bytes=%zu) sizeLimit=%zu", b, bytes, b->sizeLimit);
}

void _ob_unlimitsize(struct __sourceloc __whence, struct overlay_buffer *b)
{
  assert(b != NULL);
  b->sizeLimit = SIZE_MAX;
  DEBUGF(overlaybuffer, "ob_unlimitsize(b=%p) sizeLimit=%zu", b, b->sizeLimit);
}

void _ob_flip(struct __sourceloc __whence, struct overlay_buffer *b)
{
  DEBUGF(overlaybuffer, "ob_flip(b=%p) checkpointLength=0 position=0", b);
  b->checkpointLength = 0;
  ob_limitsize(b, b->position);
  b->position = 0;
}

void _ob_clear(struct __sourceloc __whence, struct overlay_buffer *b)
{
  DEBUGF(overlaybuffer, "ob_clear(b=%p) checkpointLength=0 position=0", b);
  b->checkpointLength = 0;
  b->position = 0;
  ob_unlimitsize(b);
}

/* Return 1 if space is available, 0 if not.
 */
ssize_t _ob_makespace(struct __sourceloc __whence, struct overlay_buffer *b, size_t bytes)
{
  assert(b != NULL);
  DEBUGF(overlaybuffer, "ob_makespace(b=%p, bytes=%zd) b->bytes=%p b->position=%zu b->allocSize=%zu",
	 b, bytes, b->bytes, b->position, b->allocSize);
  if (b->position)
    assert(b->bytes != NULL);
  if (b->position + bytes > b->sizeLimit) {
    DEBUGF(overlaybuffer, "ob_makespace(): asked for space to %zu, beyond size limit of %zu", b->position + bytes, b->sizeLimit);
    return 0;
  }
  if (b->position + bytes <= b->allocSize)
    return 1;
  // Don't realloc a static buffer.
  if (b->bytes && b->allocated == NULL) {
    DEBUGF(overlaybuffer, "ob_makespace(): asked for space to %zu, beyond static buffer size of %zu", b->position + bytes, b->allocSize);
    return 0;
  }
  size_t newSize = b->position + bytes;
  if (newSize<64) newSize=64;
  if (newSize&63) newSize+=64-(newSize&63);
  if (newSize>1024 && (newSize&1023))
    newSize+=1024-(newSize&1023);
  if (newSize>65536 && (newSize&65535))
    newSize+=65536-(newSize&65535);
  DEBUGF(overlaybuffer, "realloc(b->bytes=%p, newSize=%zu)", b->bytes, newSize);
  unsigned char *new = emalloc(newSize);
  if (!new)
    return 0;
  if (b->position)
    bcopy(b->bytes,new,b->position);
  if (b->allocated) {
    assert(b->allocated == b->bytes);
    free(b->allocated);
  }
  b->bytes=new;
  b->allocated=new;
  b->allocSize=newSize;
  return 1;
}

/*
 Functions that append data and increase the size of the buffer if possible / required
 */

void _ob_append_byte(struct __sourceloc __whence, struct overlay_buffer *b, unsigned char byte)
{
  const int bytes = 1;
  if (ob_makespace(b, bytes)) {
    b->bytes[b->position] = byte;
    DEBUGF(overlaybuffer, "ob_append_byte(b=%p, byte=0x%02x) %p[%zd]=%02x position=%zu", b, byte, b->bytes, b->position, byte, b->position + bytes);
  } else {
    DEBUGF(overlaybuffer, "ob_append_byte(b=%p, byte=0x%02x) OVERRUN position=%zu", b, byte, b->position + bytes);
  }
  b->position += bytes;
}

unsigned char *_ob_append_space(struct __sourceloc __whence, struct overlay_buffer *b, size_t count)
{
  assert(count > 0);
  unsigned char *r = ob_makespace(b, count) ? &b->bytes[b->position] : NULL;
  b->position += count;
  DEBUGF(overlaybuffer, "ob_append_space(b=%p, count=%zu) position=%zu return %p", b, count, b->position, r);
  return r;
}

void _ob_append_bytes(struct __sourceloc __whence, struct overlay_buffer *b, const unsigned char *bytes, size_t count)
{
  assert(count > 0);
  unsigned char *r = ob_makespace(b, count) ? &b->bytes[b->position] : NULL;
  if (r) {
    bcopy(bytes, r, count);
    DEBUGF(overlaybuffer, "ob_append_bytes(b=%p, bytes=%p, count=%zu) position=%zu return %p", b, bytes, count, b->position + count, r);
  } else {
    DEBUGF(overlaybuffer, "ob_append_bytes(b=%p, bytes=%p, count=%zu) OVERRUN position=%zu return NULL", b, bytes, count, b->position + count);
  }
  if (IF_DEBUG(overlaybuffer))
    dump("{overlaybuffer} ob_append_bytes", bytes, count);
  b->position += count;
}

void _ob_append_str(struct __sourceloc whence, struct overlay_buffer *b, const char *str)
{
  _ob_append_bytes(whence, b, (const uint8_t*)str, strlen(str)+1);
}

void _ob_append_strn(struct __sourceloc whence, struct overlay_buffer *b, const char *str, size_t max_len)
{
  _ob_append_bytes(whence, b, (const uint8_t*)str, strnlen(str, max_len));
  _ob_append_byte(whence, b, 0);
}

void _ob_append_ui16(struct __sourceloc __whence, struct overlay_buffer *b, uint16_t v)
{
  const int bytes = 2;
  if (ob_makespace(b, bytes)) {
    b->bytes[b->position] = (v >> 8) & 0xFF;
    b->bytes[b->position+1] = v & 0xFF;
    DEBUGF(overlaybuffer, "ob_append_ui16(b=%p, v=%u) %p[%zd]=%s position=%zu", b, v, b->bytes, b->position, alloca_tohex(&b->bytes[b->position], bytes), b->position + bytes);
  } else {
    DEBUGF(overlaybuffer, "ob_append_ui16(b=%p, v=%u) OVERRUN position=%zu", b, v, b->position + bytes);
  }
  b->position += bytes;
}

void _ob_append_ui16_rv(struct __sourceloc __whence, struct overlay_buffer *b, uint16_t v)
{
  const int bytes = 2;
  if (ob_makespace(b, bytes)) {
    b->bytes[b->position] = v & 0xFF;
    b->bytes[b->position+1] = (v >> 8) & 0xFF;
    DEBUGF(overlaybuffer, "ob_append_ui16(b=%p, v=%u) %p[%zd]=%s position=%zu", b, v, b->bytes, b->position, alloca_tohex(&b->bytes[b->position], bytes), b->position + bytes);
  } else {
    DEBUGF(overlaybuffer, "ob_append_ui16(b=%p, v=%u) OVERRUN position=%zu", b, v, b->position + bytes);
  }
  b->position += bytes;
}

void _ob_append_ui32(struct __sourceloc __whence, struct overlay_buffer *b, uint32_t v)
{
  const int bytes = 4;
  if (ob_makespace(b, bytes)) {
    b->bytes[b->position] = (v >> 24) & 0xFF;
    b->bytes[b->position+1] = (v >> 16) & 0xFF;
    b->bytes[b->position+2] = (v >> 8) & 0xFF;
    b->bytes[b->position+3] = v & 0xFF;
    DEBUGF(overlaybuffer, "ob_append_ui32(b=%p, v=%"PRIu32") %p[%zd]=%s position=%zu",
	   b, v, b->bytes, b->position, alloca_tohex(&b->bytes[b->position], bytes), b->position + bytes);
  } else {
    DEBUGF(overlaybuffer, "ob_append_ui32(b=%p, v=%"PRIu32") OVERRUN position=%zu", b, v, b->position + bytes);
  }
  b->position += bytes;
}

void _ob_append_ui32_rv(struct __sourceloc __whence, struct overlay_buffer *b, uint32_t v)
{
  const int bytes = 4;
  if (ob_makespace(b, bytes)) {
    b->bytes[b->position] = v & 0xFF;
    b->bytes[b->position+1] = (v >> 8) & 0xFF;
    b->bytes[b->position+2] = (v >> 16) & 0xFF;
    b->bytes[b->position+3] = (v >> 24) & 0xFF;
    DEBUGF(overlaybuffer, "ob_append_ui32(b=%p, v=%"PRIu32") %p[%zd]=%s position=%zu",
	   b, v, b->bytes, b->position, alloca_tohex(&b->bytes[b->position], bytes), b->position + bytes);
  } else {
    DEBUGF(overlaybuffer, "ob_append_ui32(b=%p, v=%"PRIu32") OVERRUN position=%zu", b, v, b->position + bytes);
  }
  b->position += bytes;
}

void _ob_append_ui64(struct __sourceloc __whence, struct overlay_buffer *b, uint64_t v)
{
  const int bytes = 8;
  if (ob_makespace(b, bytes)) {
    b->bytes[b->position] = (v >> 56) & 0xFF;
    b->bytes[b->position+1] = (v >> 48) & 0xFF;
    b->bytes[b->position+2] = (v >> 40) & 0xFF;
    b->bytes[b->position+3] = (v >> 32) & 0xFF;
    b->bytes[b->position+4] = (v >> 24) & 0xFF;
    b->bytes[b->position+5] = (v >> 16) & 0xFF;
    b->bytes[b->position+6] = (v >> 8) & 0xFF;
    b->bytes[b->position+7] = v & 0xFF;
    DEBUGF(overlaybuffer, "ob_append_ui64(b=%p, v=%"PRIu64") %p[%zd]=%s position=%zu",
	   b, v, b->bytes, b->position, alloca_tohex(&b->bytes[b->position], bytes), b->position + bytes);
  } else {
    DEBUGF(overlaybuffer, "ob_append_ui64(b=%p, v=%"PRIu64") OVERRUN position=%zu", b, v, b->position + bytes);
  }
  b->position += bytes;
}

void _ob_append_ui64_rv(struct __sourceloc __whence, struct overlay_buffer *b, uint64_t v)
{
  const int bytes = 8;
  if (ob_makespace(b, bytes)) {
    b->bytes[b->position] = v & 0xFF;
    b->bytes[b->position+1] = (v >> 8) & 0xFF;
    b->bytes[b->position+2] = (v >> 16) & 0xFF;
    b->bytes[b->position+3] = (v >> 24) & 0xFF;
    b->bytes[b->position+4] = (v >> 32) & 0xFF;
    b->bytes[b->position+5] = (v >> 40) & 0xFF;
    b->bytes[b->position+6] = (v >> 48) & 0xFF;
    b->bytes[b->position+7] = (v >> 56) & 0xFF;
    DEBUGF(overlaybuffer, "ob_append_ui64(b=%p, v=%"PRIu64") %p[%zd]=%s position=%zu",
	   b, v, b->bytes, b->position, alloca_tohex(&b->bytes[b->position], bytes), b->position + bytes);
  } else {
    DEBUGF(overlaybuffer, "ob_append_ui64(b=%p, v=%"PRIu64") OVERRUN position=%zu", b, v, b->position + bytes);
  }
  b->position += bytes;
}

int measure_packed_uint(uint64_t v){
  int ret=0;
  do{
    v>>=7;
    ret++;
  }while(v);
  return ret;
}

int pack_uint(unsigned char *buffer, uint64_t v){
  int ret=0;
  do{
    *buffer++=(v&0x7f) | (v>0x7f?0x80:0);
    v>>=7;
    ret++;
  }while(v);
  return ret;
}

int unpack_uint(unsigned char *buffer, int buff_size, uint64_t *v){
  int i=0;
  *v=0;
  while(1){
    if (i>=buff_size)
      return -1;
    char byte = buffer[i];
    *v |= (byte&0x7f)<<(i*7);
    i++;
    if (!(byte&0x80))
      break;
  }
  return i;
}

void _ob_append_packed_ui32(struct __sourceloc __whence, struct overlay_buffer *b, uint32_t v)
{
  do {
    ob_append_byte(b, (v&0x7f) | (v>0x7f?0x80:0));
    v = v >> 7;
  } while (v != 0);
}

void _ob_append_packed_ui64(struct __sourceloc __whence, struct overlay_buffer *b, uint64_t v)
{
  do {
    ob_append_byte(b, (v&0x7f) | (v>0x7f?0x80:0));
    v = v >> 7;
  } while (v != 0);
}



/*
 Functions that read / write data within the existing length limit
 */


// make sure a range of bytes is valid for reading
static int test_offset(struct overlay_buffer *b, size_t length)
{
  if (b->position + length > b->sizeLimit)
    return -1;
  if (b->position + length > b->allocSize)
    return -1;
  return 0;
}

// next byte without advancing
int ob_peek(struct overlay_buffer *b)
{
  if (test_offset(b, 1))
    return -1;
  return b->bytes[b->position];
}

void ob_skip(struct overlay_buffer *b, unsigned n)
{
  b->position += n;
}

// return a null terminated string pointer and advance past the string
const char *ob_get_str_ptr(struct overlay_buffer *b)
{
  const char *ret = (const char*)(b->bytes + b->position);
  off_t ofs=0;
  while (test_offset(b, ofs)==0){
    if (ret[ofs]=='\0'){
      b->position+=ofs+1;
      return ret;
    }
    ofs++;
  }
  return NULL;
}

int ob_get_bytes(struct overlay_buffer *b, unsigned char *buff, size_t len)
{
  if (test_offset(b, len))
    return -1;
  bcopy(b->bytes + b->position, buff, len);
  b->position+=len;
  return 0;
}

unsigned char * ob_get_bytes_ptr(struct overlay_buffer *b, size_t len)
{
  if (test_offset(b, len))
    return NULL;
  unsigned char *ret = b->bytes + b->position;
  b->position+=len;
  return ret;
}

uint32_t ob_get_ui32(struct overlay_buffer *b)
{
  if (test_offset(b, 4))
    return 0xFFFFFFFF; // ... unsigned
  uint32_t ret = (unsigned)b->bytes[b->position] << 24
	| b->bytes[b->position +1] << 16
	| b->bytes[b->position +2] << 8
	| b->bytes[b->position +3];
  b->position+=4;
  return ret;
}

uint32_t ob_get_ui32_rv(struct overlay_buffer *b)
{
  if (test_offset(b, 4))
    return 0xFFFFFFFF; // ... unsigned
  uint32_t ret = b->bytes[b->position]
	| b->bytes[b->position +1] << 8
	| b->bytes[b->position +2] << 16
	| (unsigned)b->bytes[b->position +3] << 24;
  b->position+=4;
  return ret;
}

uint64_t ob_get_ui64(struct overlay_buffer *b)
{
  if (test_offset(b, 8))
    return 0xFFFFFFFF; // ... unsigned
  uint64_t ret = (uint64_t)b->bytes[b->position] << 56
	| (uint64_t)b->bytes[b->position +1] << 48
	| (uint64_t)b->bytes[b->position +2] << 40
	| (uint64_t)b->bytes[b->position +3] << 36
	| b->bytes[b->position +4] << 24
	| b->bytes[b->position +5] << 16
	| b->bytes[b->position +6] << 8
	| b->bytes[b->position +7];
  b->position+=8;
  return ret;
}

uint64_t ob_get_ui64_rv(struct overlay_buffer *b)
{
  if (test_offset(b, 8))
    return 0xFFFFFFFF; // ... unsigned
  uint64_t ret = (uint64_t)b->bytes[b->position]
	| (uint64_t)b->bytes[b->position +1] << 8
	| (uint64_t)b->bytes[b->position +2] << 16
	| (uint64_t)b->bytes[b->position +3] << 24
	| (uint64_t)b->bytes[b->position +4] << 32
	| (uint64_t)b->bytes[b->position +5] << 40
	| (uint64_t)b->bytes[b->position +6] << 48
	| (uint64_t)b->bytes[b->position +7] << 56;
  b->position+=8;
  return ret;
}

uint16_t ob_get_ui16(struct overlay_buffer *b)
{
  if (test_offset(b, 2))
    return 0xFFFF; // ... unsigned
  uint16_t ret = b->bytes[b->position] << 8
	| b->bytes[b->position +1];
  b->position+=2;
  return ret;
}

uint16_t ob_get_ui16_rv(struct overlay_buffer *b)
{
  if (test_offset(b, 2))
    return 0xFFFF; // ... unsigned
  uint16_t ret = b->bytes[b->position]
	| b->bytes[b->position +1] << 8;
  b->position+=2;
  return ret;
}

uint32_t ob_get_packed_ui32(struct overlay_buffer *b)
{
  uint32_t ret=0;
  int shift=0;
  int byte;
  do{
    byte = ob_get(b);
    if (byte<0)
      return WHY("Failed to unpack integer");
    ret |= (byte&0x7f)<<shift;
    shift+=7;
  }while(byte & 0x80);
  return ret;
}

uint64_t ob_get_packed_ui64(struct overlay_buffer *b)
{
  uint64_t ret=0;
  int shift=0;
  int byte;
  do{
    byte = ob_get(b);
    if (byte<0)
      return WHY("Failed to unpack integer");
    ret |= (byte&0x7f)<<shift;
    shift+=7;
  }while(byte & 0x80);
  return ret;
}

int ob_get(struct overlay_buffer *b)
{
  if (test_offset(b, 1))
    return -1;
  return b->bytes[b->position++];
}

void _ob_set_ui16(struct __sourceloc __whence, struct overlay_buffer *b, size_t offset, uint16_t v)
{
  const int bytes = 2;
  assert(b != NULL);
  assert(offset + bytes <= b->sizeLimit);
  assert(offset + bytes <= b->allocSize);
  b->bytes[offset] = (v >> 8) & 0xFF;
  b->bytes[offset+1] = v & 0xFF;
  DEBUGF(overlaybuffer, "ob_set_ui16(b=%p, offset=%zd, v=%u) %p[%zd]=%s", b, offset, v, b->bytes, offset, alloca_tohex(&b->bytes[offset], bytes));
}

void _ob_set(struct __sourceloc __whence, struct overlay_buffer *b, size_t offset, unsigned char byte)
{
  const int bytes = 1;
  assert(b != NULL);
  assert(offset + bytes <= b->sizeLimit);
  assert(offset + bytes <= b->allocSize);
  b->bytes[offset] = byte;
  DEBUGF(overlaybuffer, "ob_set(b=%p, offset=%zd, byte=0x%02x) %p[%zd]=%s", b, offset, byte, b->bytes, offset, alloca_tohex(&b->bytes[offset], bytes));
}



size_t ob_position(struct overlay_buffer *b)
{
  return b->position;
}

size_t ob_mark(struct overlay_buffer *b)
{
  return b->checkpointLength;
}

size_t ob_limit(struct overlay_buffer *b)
{
  return b->sizeLimit;
}

size_t ob_remaining(struct overlay_buffer *b)
{
  assert(b->sizeLimit != SIZE_MAX);
  assert(b->position <= b->sizeLimit);
  return (size_t)(b->sizeLimit - b->position);
}

int _ob_overrun(struct __sourceloc __whence, struct overlay_buffer *b)
{
  int ret = b->position > (b->sizeLimit != SIZE_MAX && b->sizeLimit < b->allocSize ? b->sizeLimit : b->allocSize);
  DEBUGF(overlaybuffer, "ob_overrun(b=%p) return %d", b, ret);
  return ret;
}

unsigned char *ob_ptr(struct overlay_buffer *b)
{
  return b->bytes;
}

unsigned char *ob_current_ptr(struct overlay_buffer *b)
{
  return &b->bytes[b->position];
}

int asprintable(int c)
{
  if (c<' ') return '.';
  if (c>0x7e) return '.';
  return c;
}

int ob_dump(struct overlay_buffer *b, char *desc)
{
  _DEBUGF("overlay_buffer '%s' at %p (%p) : checkpoint=%zu, position=%zu, limit=%zu, size=%zu",
          desc, b, b->bytes, b->checkpointLength, b->position, b->sizeLimit, b->allocSize);
  if (b->bytes) {
    if (b->sizeLimit != SIZE_MAX && b->sizeLimit > 0) {
      assert(b->position <= b->sizeLimit);
      dump(desc, b->bytes, b->sizeLimit);
    } else if (b->position > 0)
      dump(desc, b->bytes, b->position);
  }
  return 0;
}
