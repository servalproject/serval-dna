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
#include "conf.h"
#include "mem.h"
#include "overlay_buffer.h"

/*
 When writing to a buffer, sizeLimit may place an upper bound on the amount of space to use
 
 When reading from a buffer, sizeLimit should first be set to the length of any existing data.
 
 In either case, functions that don't take an offset use and advance the position.
 */



struct overlay_buffer *ob_new(void)
{
  struct overlay_buffer *ret=calloc(sizeof(struct overlay_buffer),1);
  if (!ret) return NULL;
  
  ob_unlimitsize(ret);

  return ret;
}

// index an existing static buffer.
// and allow other callers to use the ob_ convenience methods for reading and writing up to size bytes.
struct overlay_buffer *ob_static(unsigned char *bytes, int size){
  struct overlay_buffer *ret=calloc(sizeof(struct overlay_buffer),1);
  if (!ret) return NULL;
  ret->bytes = bytes;
  ret->allocSize = size;
  ret->allocated = NULL;
  ob_unlimitsize(ret);
  
  return ret;
}

// create a new overlay buffer from an existing piece of another buffer.
// Both buffers will point to the same memory region.
// It is up to the caller to ensure this buffer is not used after the parent buffer is freed.
struct overlay_buffer *ob_slice(struct overlay_buffer *b, int offset, int length){
  if (offset+length > b->allocSize) {
    WHY("Buffer isn't long enough to slice");
	return NULL;
  }
      
  struct overlay_buffer *ret=calloc(sizeof(struct overlay_buffer),1);
  if (!ret)
      return NULL;
  ret->bytes = b->bytes+offset;
  ret->allocSize = length;
  ret->allocated = NULL;
  ob_unlimitsize(ret);
  
  return ret;
}

struct overlay_buffer *ob_dup(struct overlay_buffer *b){
  struct overlay_buffer *ret=calloc(sizeof(struct overlay_buffer),1);
  ret->sizeLimit = b->sizeLimit;
  ret->position = b->position;
  ret->checkpointLength = b->checkpointLength;
  
  if (b->bytes && b->allocSize){
    // duplicate any bytes that might be relevant
    int byteCount = b->sizeLimit;
    if (byteCount < b->position)
      byteCount = b->position;
    if (byteCount > b->allocSize)
      byteCount = b->allocSize;
    
    ob_append_bytes(ret, b->bytes, byteCount);
  }
  return ret;
}

int ob_free(struct overlay_buffer *b)
{
  if (!b) return WHY("Asked to free NULL");
  if (b->bytes && b->allocated) free(b->allocated);
  // we're about to free this anyway, why are we clearing it?
  b->bytes=NULL;
  b->allocated=NULL;
  b->allocSize=0;
  b->sizeLimit=0;
  free(b);
  return 0;
}

int ob_checkpoint(struct overlay_buffer *b)
{
  if (!b) return WHY("Asked to checkpoint NULL");
  b->checkpointLength=b->position;
  return 0;
}

int ob_rewind(struct overlay_buffer *b)
{
  if (!b) return WHY("Asked to rewind NULL");
  b->position=b->checkpointLength;
  return 0;
}

int ob_limitsize(struct overlay_buffer *b,int bytes)
{
  if (!b) return WHY("Asked to limit size of NULL");
  if (b->position>bytes) return WHY("Length of data in buffer already exceeds size limit");
  if (b->checkpointLength>bytes) return WHY("Checkpointed length of data in buffer already exceeds size limit");
  if (b->bytes && (!b->allocated) && bytes > b->allocSize) return WHY("Size limit exceeds buffer size");
  if (bytes<0) return WHY("Can't limit buffer to a negative size");
  b->sizeLimit=bytes;
  return 0;
}

int ob_unlimitsize(struct overlay_buffer *b)
{
  if (!b) return WHY("b is NULL");
  b->sizeLimit=-1;
  return 0;
}

int ob_makespace(struct overlay_buffer *b,int bytes)
{
  if (b->sizeLimit!=-1 && b->position+bytes>b->sizeLimit) {
    if (config.debug.packetformats) WHY("Asked to make space beyond size limit");
    return -1;
  }
  
  // already enough space?
  if (b->position + bytes <= b->allocSize)
    return 0;
  
  if (b->bytes && !b->allocated)
    return WHY("Can't resize a static buffer");
  
  if (0)
    DEBUGF("ob_makespace(%p,%d)\n  b->bytes=%p,b->position=%d,b->allocSize=%d\n",
	   b,bytes,b->bytes,b->position,b->allocSize);

  int newSize=b->position+bytes;
  if (newSize<64) newSize=64;
  if (newSize&63) newSize+=64-(newSize&63);
  if (newSize>1024) {
    if (newSize&1023) newSize+=1024-(newSize&1023);
  }
  if (newSize>65536) {
    if (newSize&65535) newSize+=65536-(newSize&65535);
  }
  if (0) DEBUGF("realloc(b->bytes=%p,newSize=%d)", b->bytes,newSize);
  /* XXX OSX realloc() seems to be able to corrupt things if the heap is not happy when calling realloc(), making debugging memory corruption much harder.
     So will do a three-stage malloc,bcopy,free to see if we can tease bugs out that way. */
  /*
    unsigned char *r=realloc(b->bytes,newSize);
    if (!r) return WHY("realloc() failed");
    b->bytes=r; 
  */
#ifdef MALLOC_PARANOIA
#warning adding lots of padding to try to catch overruns
  if (b->bytes) {
    int i;
    int corrupt=0;
    for(i=0;i<4096;i++) if (b->bytes[b->allocSize+i]!=0xbd) corrupt++;
    if (corrupt) {
      WHYF("!!!!!! %d corrupted bytes in overrun catch tray", corrupt);
      dump("overrun catch tray",&b->bytes[b->allocSize],4096);
      sleep(3600);
    }
  }
  unsigned char *new=malloc(newSize+4096);
  if (!new) return WHY("realloc() failed");
  {
    int i;
    for(i=0;i<4096;i++) new[newSize+i]=0xbd;
  }
#else
  unsigned char *new=malloc(newSize);
#endif
  bcopy(b->bytes,new,b->position);
  if (b->allocated) free(b->allocated);
  b->bytes=new;
  b->allocated=new;
  b->allocSize=newSize;
  return 0;
}



/*
 Functions that append data and increase the size of the buffer if possible / required
 */

int ob_append_byte(struct overlay_buffer *b,unsigned char byte)
{
  if (ob_makespace(b,1)) return WHY("ob_makespace() failed");
  b->bytes[b->position++] = byte;
  return 0;
}

unsigned char *ob_append_space(struct overlay_buffer *b,int count)
{
  if (ob_makespace(b,count))  {
    WHY("ob_makespace() failed");
    return NULL;
  }
  
  unsigned char *r=&b->bytes[b->position];
  b->position+=count;
  return r;
}

int ob_append_bytes(struct overlay_buffer *b,unsigned char *bytes,int count)
{
  if (ob_makespace(b,count)) return WHY("ob_makespace() failed");
  
  bcopy(bytes,&b->bytes[b->position],count);
  b->position+=count;
  return 0;
}

int ob_append_buffer(struct overlay_buffer *b,struct overlay_buffer *s){
  return ob_append_bytes(b, s->bytes, s->position);
}

int ob_append_ui16(struct overlay_buffer *b, uint16_t v)
{
  if (ob_makespace(b, 2)) return WHY("ob_makespace() failed");
  b->bytes[b->position] = (v >> 8) & 0xFF;
  b->bytes[b->position+1] = v & 0xFF;
  b->position+=2;
  return 0;
}

int ob_append_ui32(struct overlay_buffer *b, uint32_t v)
{
  if (ob_makespace(b, 4)) return WHY("ob_makespace() failed");
  b->bytes[b->position] = (v >> 24) & 0xFF;
  b->bytes[b->position+1] = (v >> 16) & 0xFF;
  b->bytes[b->position+2] = (v >> 8) & 0xFF;
  b->bytes[b->position+3] = v & 0xFF;
  b->position+=4;
  return 0;
}

int ob_append_packed_ui32(struct overlay_buffer *b, uint32_t v)
{
  do{
    
    if (ob_append_byte(b, (v&0x7f) | (v>0x7f?0x80:0)))
      return -1;
    v = v>>7;
    
  }while(v!=0);
  return 0;
}

int ob_append_rfs(struct overlay_buffer *b,int l)
{
  if (l<0||l>0xffff) return -1;
  
  b->var_length_offset=b->position;
  return ob_append_ui16(b,l);
}


/*
 Functions that read / write data within the existing length limit
 */


// make sure a range of bytes is valid for reading
int test_offset(struct overlay_buffer *b,int start,int length){
  if (!b) return -1;
  if (start<0) return -1;
  if (b->sizeLimit>=0 && start+length>b->sizeLimit) return -1;
  if (start+length>b->allocSize) return -1;
  return 0;
}

int ob_getbyte(struct overlay_buffer *b, int ofs)
{
  if (test_offset(b, ofs, 1))
    return -1;
  
  return b->bytes[ofs];
}

int ob_get_bytes(struct overlay_buffer *b, unsigned char *buff, int len){
  if (test_offset(b, b->position, len))
    return -1;
  
  bcopy(b->bytes + b->position, buff, len);
  b->position+=len;
  return 0;
}

unsigned char * ob_get_bytes_ptr(struct overlay_buffer *b, int len){
  if (test_offset(b, b->position, len))
    return NULL;
  
  unsigned char *ret = b->bytes + b->position;
  b->position+=len;
  return ret;
}

uint32_t ob_get_ui32(struct overlay_buffer *b)
{
  if (test_offset(b, b->position, 4))
    return 0xFFFFFFFF; // ... unsigned

  uint32_t ret = b->bytes[b->position] << 24
	| b->bytes[b->position +1] << 16
	| b->bytes[b->position +2] << 8
	| b->bytes[b->position +3];
  b->position+=4;
  return ret;
}

uint16_t ob_get_ui16(struct overlay_buffer *b)
{
  if (test_offset(b, b->position, 2))
    return 0xFFFF; // ... unsigned
  
  uint16_t ret = b->bytes[b->position] << 8
	| b->bytes[b->position +1];
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

int ob_get(struct overlay_buffer *b){
  if (test_offset(b, b->position, 1))
    return -1;
  
  return b->bytes[b->position++];
}

int ob_set_ui16(struct overlay_buffer *b, int offset, uint16_t v)
{
  if (test_offset(b, offset, 2))
    return -1;
  
  b->bytes[offset] = (v >> 8) & 0xFF;
  b->bytes[offset+1] = v & 0xFF;
  return 0;
}

int ob_set(struct overlay_buffer *b, int ofs, unsigned char byte)
{
  if (test_offset(b, ofs, 1))
    return -1;
  b->bytes[ofs] = byte;
  return 0;
}

int ob_patch_rfs(struct overlay_buffer *b){
  return ob_set_ui16(b,b->var_length_offset,b->position - (b->var_length_offset + 2));
}


int ob_position(struct overlay_buffer *b){
  return b->position;
}
int ob_limit(struct overlay_buffer *b){
  return b->sizeLimit;
}
int ob_remaining(struct overlay_buffer *b){
  return b->sizeLimit - b->position;
}
unsigned char *ob_ptr(struct overlay_buffer *b){
  return b->bytes;
}

int asprintable(int c)
{
  if (c<' ') return '.';
  if (c>0x7e) return '.';
  return c;
}

int ob_dump(struct overlay_buffer *b,char *desc)
{
  DEBUGF("overlay_buffer '%s' at %p : position=%d, size=%d", desc, b, b->position, b->sizeLimit);
  dump(NULL, b->bytes, b->sizeLimit>b->position?b->sizeLimit:b->position);
  return 0;
}
