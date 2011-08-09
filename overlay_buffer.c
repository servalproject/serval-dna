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
