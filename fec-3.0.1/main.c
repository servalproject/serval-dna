#include <stdio.h>
#include "fixed.h"

void encode_rs_8(data_t *data, data_t *parity,int pad);
int decode_rs_8(data_t *data, int *eras_pos, int no_eras, int pad);


int dump(char *name,unsigned char *addr,int len)
{
  int i,j;
  fprintf(stderr,"Dump of %s\n",name);
  for(i=0;i<len;i+=16) 
    {
      fprintf(stderr,"  %04x :",i);
      for(j=0;j<16&&(i+j)<len;j++) fprintf(stderr," %02x",addr[i+j]);
      for(;j<16;j++) fprintf(stderr,"   ");
      fprintf(stderr,"    ");
      for(j=0;j<16&&(i+j)<len;j++) fprintf(stderr,"%c",addr[i+j]>=' '&&addr[i+j]<0x7f?addr[i+j]:'.');
      fprintf(stderr,"\n");
    }
  return 0;
}

int main(int argc,char **argv)
{
   unsigned char in[255];
   unsigned char out[255];
 

   srandom(getpid());  
   int i;
 
   for(i=0;i<223;i++) in[i]=i;

   encode_rs_8(&in[0],&in[223],0);
   bcopy(in,out,255);
   dump("data with parity",out,255);

   for(i=0;i<16;i++) out[random()%255]^=0xff;

   dump("data with errors added",out,255);

   decode_rs_8(out,NULL,0,0);
 
   dump("data after error correction",out,223);

   return 0; 
	
}
