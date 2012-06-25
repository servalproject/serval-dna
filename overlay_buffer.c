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

overlay_buffer *ob_new(int size)
{
  overlay_buffer *ret=calloc(sizeof(overlay_buffer),1);
  if (!ret) return NULL;

  ob_unlimitsize(ret);

  return ret;
}

int ob_free(overlay_buffer *b)
{
  if (!b) return WHY("Asked to free NULL");
  if (b->bytes) free(b->bytes);
  b->bytes=NULL;
  b->allocSize=0;
  b->sizeLimit=0;
  free(b);
  return 0;
}

int ob_checkpoint(overlay_buffer *b)
{
  if (!b) return WHY("Asked to checkpoint NULL");
  b->checkpointLength=b->length;
  return 0;
}

int ob_rewind(overlay_buffer *b)
{
  if (!b) return WHY("Asked to rewind NULL");
  b->length=b->checkpointLength;
  return 0;
}

int ob_limitsize(overlay_buffer *b,int bytes)
{
  if (!b) return WHY("Asked to limit size of NULL");
  if (b->length>bytes) return WHY("Length of data in buffer already exceeds size limit");
  if (b->checkpointLength>bytes) return WHY("Checkpointed length of data in buffer already exceeds size limit");
  if (bytes<0) return WHY("Cant limit buffer to a negative size");
  b->sizeLimit=bytes;
  return 0;
}

int ob_unlimitsize(overlay_buffer *b)
{
  if (!b) return WHY("b is NULL");
  b->sizeLimit=-1;
  return 0;
}

int ob_makespace(overlay_buffer *b,int bytes)
{
  if (b->sizeLimit!=-1) {
    if (b->length+bytes>b->sizeLimit) {
      if (debug&DEBUG_PACKETFORMATS) WHY("Asked to make space beyond size limit");
      return -1; 
    }
  }

  if (0)
    printf("ob_makespace(%p,%d)\n  b->bytes=%p,b->length=%d,b->allocSize=%d\n",
	   b,bytes,b->bytes,b->length,b->allocSize);

  if (b->length+bytes>=b->allocSize)
    {
      int newSize=b->length+bytes;
      if (newSize<64) newSize=64;
      if (newSize&63) newSize+=64-(newSize&63);
      if (newSize>1024) {
	if (newSize&1023) newSize+=1024-(newSize&1023);
      }
      if (newSize>65536) {
	if (newSize&65535) newSize+=65536-(newSize&65535);
      }
      if (0) printf("  realloc(b->bytes=%p,newSize=%d)\n",
	     b->bytes,newSize);
      /* XXX OSX realloc() seems to be able to corrupt things if the heap is not happy when calling realloc(), making debugging memory corruption much harder.
	 So will do a three-stage malloc,bcopy,free to see if we can tease the bug out that way. */
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
	  printf("!!!!!! %d corrupted bytes in overrun catch tray\n",corrupt);
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
      bcopy(b->bytes,new,b->length);
      if (b->bytes) free(b->bytes);
      b->bytes=new;
      b->allocSize=newSize;
      return 0;
    }
  else
    return 0;
}

int ob_setbyte(overlay_buffer *b,int ofs,unsigned char value)
{
  if (ofs<0||ofs>=b->allocSize) {
    fprintf(stderr,"ERROR: Asked to set byte %d in overlay buffer %p, which has only %d allocated bytes.\n",
	    ofs,b,b->allocSize);
    return -1;
  }
  b->bytes[ofs]=value;
  return 0;
}

int ob_bcopy(overlay_buffer *b,int from, int to, int len)
{
  if (from<0||to<0||len<0||(from+len)>=b->allocSize||(to+len)>=b->allocSize)
    {
      fprintf(stderr,"call to ob_bcopy would corrupt memory.  Aborting.\n");
      exit(-1);
    }
  bcopy(&b->bytes[from],&b->bytes[to],len); 
  return 0;
}

int ob_append_byte(overlay_buffer *b,unsigned char byte)
{
  if (ob_makespace(b,1)) return WHY("ob_makespace() failed");
  b->bytes[b->length++] = byte;
  return 0;
}

unsigned char *ob_append_space(overlay_buffer *b,int count)
{
  if (ob_makespace(b,count)) { WHY("ob_makespace() failed"); return NULL; }
  
  unsigned char *r=&b->bytes[b->length];
  b->length+=count;
  return r;
}

int ob_append_bytes(overlay_buffer *b,unsigned char *bytes,int count)
{
  if (ob_makespace(b,count)) return WHY("ob_makespace() failed");
  
  bcopy(bytes,&b->bytes[b->length],count);
  b->length+=count;
  return 0;
}

int ob_append_short(overlay_buffer *b,unsigned short v)
{
  unsigned short s=htons(v);
  return ob_append_bytes(b,(unsigned char *)&s,sizeof(unsigned short));
}

int ob_append_int(overlay_buffer *b,unsigned int v)
{
  unsigned int s=htonl(v);
  return ob_append_bytes(b,(unsigned char *)&s,sizeof(unsigned int));
}

unsigned int ob_get_int(overlay_buffer *b,int offset)
{
  if (!b) return WHY("b is NULL");
  if (offset<0) return WHY("passed illegal offset (<0)");
  if ((offset+sizeof(unsigned int))>b->length) return WHY("passed offset too large");

  // Some platforms require alignment
  if (((uintptr_t)&b->bytes[offset])&3) {
    union { unsigned char uc[4]; uint32_t ui32; } bb;
    bcopy(&b->bytes[offset], &bb.uc[0], 4);
    return ntohl(bb.ui32);
  } else
    return ntohl(*((uint32_t*)&b->bytes[offset]));
}

int ob_append_rfs(overlay_buffer *b,int l)
{
  /* Encode the specified length and append it to the buffer */
  if (l<0||l>0xffff) return -1;

  /* First work out how long the field needs to be, then write dummy bytes
     and use ob_patch_length to set the value.  That way we have only one
     lot of code that does the encoding. */

  b->var_length_offset=b->length;
  b->var_length_bytes=rfs_length(l);

  unsigned char c[3]={0,0,0};
  if (ob_append_bytes(b,c,b->var_length_bytes)) {
    b->var_length_offset=0;
    return -1;
  }

  return ob_patch_rfs(b,l);

}

int rfs_length(int l)
{
  if (l<0) return -1;
  if (l<250) return 1;
  else if (l<(255+250+(256*4))) return 2;
  else if (l<=0xffff) return 3;
  else return -1;
}

int rfs_encode(int l, unsigned char *b)
{
  if (l<250) { b[0]=l; }
  else if (l<(255+250+(256*4))) {
    l-=250;
    int page=(l>>8);
    l&=0xff;
    b[0]=RFS_PLUS250+page;
    b[1]=l;
  } else {
    b[0]=RFS_3BYTE;
    b[1]=l>>8;
    b[2]=l&0xff;
  }
  return 0;
}

int rfs_decode(unsigned char *b,int *ofs)
{
  int rfs=b[*ofs];
  switch(rfs) {
  case RFS_PLUS250: case RFS_PLUS456: case RFS_PLUS762: case RFS_PLUS1018: case RFS_PLUS1274: 
    rfs=250+256*(rfs-RFS_PLUS250)+b[++(*ofs)]; 
    break;
  case RFS_3BYTE: rfs=(b[(*ofs)+1]<<8)+b[(*ofs)+2]; (*ofs)+=2;
  default: /* Length is natural value of field, so nothing to do */
    break;
  }
  (*ofs)++;
  return rfs;
}

int ob_indel_space(overlay_buffer *b,int offset,int shift)
{
  if (shift>0) { /* make space */ 
    if (ob_makespace(b,-shift)) return -1;
    bcopy(&b->bytes[offset],&b->bytes[offset+shift],b->length-(offset+shift));
  } else if (shift<0) { /* free up space */
    bcopy(&b->bytes[offset-shift],&b->bytes[offset],b->length-(offset-shift));
  }
  b->length+=shift;
  return 0;
}


int ob_patch_rfs(overlay_buffer *b,int l)
{
  if (l<0||l>0xffff) return -1;

  /* Adjust size of field */
  int new_size=rfs_length(l);
  int shift=new_size-b->var_length_bytes;
  if (shift) {
    if (debug&DEBUG_PACKETCONSTRUCTION) {
      fprintf(stderr,"Patching RFS for rfs_size=%d (was %d), so indel %d btyes\n",
	      new_size,b->var_length_bytes,shift);
      dump("before indel",
	   &b->bytes[b->var_length_offset],
	   b->length-b->var_length_offset);
    }
    if (ob_indel_space(b,b->var_length_offset,shift)) return -1;
    if (debug&DEBUG_PACKETCONSTRUCTION) {
      dump("after indel",
	   &b->bytes[b->var_length_offset],
	   b->length-b->var_length_offset);
    }

  }
  
  if (rfs_encode(l,&b->bytes[b->var_length_offset])) return -1;

  if (debug&DEBUG_PACKETCONSTRUCTION) {
    dump("after patch",
	 &b->bytes[b->var_length_offset],
	 b->length-b->var_length_offset);
  }

  return 0;
  
}

int asprintable(int c)
{
  if (c<' ') return '.';
  if (c>0x7e) return '.';
  return c;
}

int ob_dump(overlay_buffer *b,char *desc)
{
  fprintf(stderr,"Dumping overlay_buffer '%s' at %p : length=%d\n",desc,b,b->length);
  int i,j;

  for(i=0;i<b->length;i+=16)
    {
      fprintf(stderr,"%04x :",i);
      for(j=0;j<16&&(i+j<b->length);j++) fprintf(stderr," %02x",b->bytes[i+j]);
      for(;j<16;j++) fprintf(stderr,"   ");
      fprintf(stderr,"  ");
      for(j=0;j<16&&(i+j<b->length);j++) fprintf(stderr," %c",asprintable(b->bytes[i+j]));
      fprintf(stderr,"\n");
    }
  return 0;
}

#undef malloc
#undef calloc
#undef free
#undef realloc

#define SDM_GUARD_AFTER 16384
void *_serval_debug_malloc(unsigned int bytes,char *file,const char *func,int line)
{
  void *r=malloc(bytes+SDM_GUARD_AFTER);
  fprintf(stderr,"%s:%d:%s(): malloc(%d) -> %p\n",file,line,func,bytes,r); 
  return r;
}

void *_serval_debug_calloc(unsigned int bytes,unsigned int count,char *file,const char *func,int line)
{
  void *r=calloc((bytes*count)+SDM_GUARD_AFTER,1);
  fprintf(stderr,"%s:%d:%s(): calloc(%d,%d) -> %p\n",file,line,func,bytes,count,r);
  return r;
}

void _serval_debug_free(void *p,char *file,const char *func,int line)
{
  free(p);
  fprintf(stderr,"%s:%d:%s(): free(%p)\n",file,line,func,p);
}
