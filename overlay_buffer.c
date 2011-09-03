#include "mphlr.h"

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
    if (b->length+bytes>b->sizeLimit) return WHY("Asked to make space beyond size limit");
  }
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
      unsigned char *r=realloc(b->bytes,newSize);
      if (!r) return WHY("realloc() failed");
      b->bytes=r;
      b->allocSize=newSize;
      return 0;
    }
  else
    return 0;
}

int ob_append_byte(overlay_buffer *b,unsigned char byte)
{
  if (ob_makespace(b,1)) return WHY("ob_makespace() failed");
  
  bcopy(&byte,&b->bytes[b->length],1);
  b->length++;
  return 0;
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
    b[0]=RFS_PLUS250+(l-250)/256;
    b[1]=l-((l-250)/256);
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
    bcopy(&b->bytes[offset],&b->bytes[offset-shift],b->length-(offset-shift));
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
  if (ob_indel_space(b,b->var_length_offset,shift)) return -1;
  
  if (rfs_encode(l,&b->bytes[b->var_length_offset])) return -1;

  return 0;
  
}
