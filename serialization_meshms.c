//#include <stdio.h>
//#include <ctype.h>

#include "serval.h"

// remove this once you have it in the serval source directory and
// replace it with #include "serval.h"
#define uint64_t unsigned long long

int serialize_meshms(unsigned char *buffer,int *offset,unsigned int length,char *sender_did,char *recipient_did, unsigned long long *time, char *payload)
{
  int ret = 0;
   
  encode_length_forwards(buffer,offset,length);
  pack_did(buffer,offset,sender_did);
  pack_did(buffer,offset,recipient_did);  
  pack_time(buffer,offset,time);
  
  int i=0;
  int payload_length=strlen(payload);
  for(i;i<payload_length;i++)
  {
   buffer[*offset]=payload[i];

   *offset=*offset+1;
  } 

  
  encode_length_backwards(buffer,offset,length);
  cli_printf("---------------Dump in serialization function-------------\n");
  hex_dump(buffer,*offset);
  

  return ret;
}


int encode_length_forwards(unsigned char *buffer,int *offset,
			   unsigned int length)
{
  if (length<0xff) { buffer[(*offset)++]=length; return 0; }
  buffer[(*offset)++]=0xff;
  int i;
  for(i=0;i<32;i+=8) buffer[(*offset)++]=(length>>i)&0xff;
  return 0;
}

int encode_length_backwards(unsigned char *buffer,int *offset,
			    unsigned int length)
{
  if (length<0xff) { buffer[(*offset)++]=length; return 0; }
  int i;
  for(i=0;i<32;i+=8) buffer[(*offset)++]=(length>>i)&0xff;
  buffer[(*offset)++]=0xff;
  return 0;
}

int decode_length_forwards(unsigned char *buffer,int *offset,
			    unsigned int *length)
{
  *length=0;
  switch(buffer[*offset]) {
  case 0xff:
    (*offset)++;
    int i;
    for(i=0;i<32;i+=8) (*length)|=buffer[(*offset)++]<<i;
    return 0;
  default:
    *length=buffer[(*offset)++];
    return 0;
  }
}

int decode_length_backwards(unsigned char *buffer,int offset,
			    unsigned int *length)
{
  // it is assumed that offset points to the first byte after the end
  // of the length field.
  offset--;
  *length=0;
  switch(buffer[offset]) {
  case 0xff:
    offset-=4;
    int i;
    for(i=0;i<32;i+=8) (*length)|=buffer[offset++]<<i;    
    return 0;
  default:
    *length=buffer[offset];
    return 0;
  }
}


int pack_time(unsigned char *buffer,int *offset,uint64_t time)
{
  int i;
  for(i=0;i<64;i+=8) buffer[(*offset)++]=(time>>i)&0xff;
  return 0;
}

int unpack_time(unsigned char *buffer,int *offset,uint64_t *time)
{
  int i;
  *time=0;
  for(i=0;i<64;i+=8) (*time)|=(((uint64_t)buffer[(*offset)++])<<i);
  return 0;
}


unsigned char did_chars[16]="0123456789+#*abX";

int unpack_did(unsigned char *buffer,int *offset,char *did_out)
{
  int i;
  
  for(i=0;i<64;i++)
    {
      int n=buffer[(*offset)+i/2];
      if (i&1) n=n>>4; else n=n&0xf;
      if (n!=15) did_out[i]=did_chars[n];
      else {
	did_out[i]=0;
	(*offset)+=((i+1)/2);
	if (!(i&1)) (*offset)++;
	return 0;
      }
    }
  return 0;
}

int pack_did(unsigned char *buffer,int *offset,char *did)
{
   int i;
   int highlow=0;
   for(i=0;i<64;i++) {
      int j;
      for(j=0;j<16;j++) if (did_chars[j]==tolower(did[i])) break;
      if (!did[i]) j=15;
      if (j>=16) return -1; // illegal character
      if (highlow) {
	buffer[(*offset)++]|=j<<4;
      }
      else buffer[*offset]=j;
      highlow^=1;
      if (j==15) {
	if (highlow) (*offset)++;
	return 0;
      }
   }
   return -1; // number too long
}


void hex_dump(char *data, int size)
{
	int i; // index in data...
	int j; // index in line...
	char temp[8];
	char buffer[128];
	char *ascii;

	memset(buffer, 0, 128);

	printf("---------> Dump <--------- (%d bytes from %p)\n", size, data);

	// Printing the ruler...
	printf("        +0          +4          +8          +c            0   4   8   c   \n");

	// Hex portion of the line is 8 (the padding) + 3 * 16 = 52 chars long
	// We add another four bytes padding and place the ASCII version...
	ascii = buffer + 58;
	memset(buffer, ' ', 58 + 16);
	buffer[58 + 16] = '\n';
	buffer[58 + 17] = '\0';
	buffer[0] = '+';
	buffer[1] = '0';
	buffer[2] = '0';
	buffer[3] = '0';
	buffer[4] = '0';
	for (i = 0, j = 0; i < size; i++, j++)
	{
		if (j == 16)
		{
			printf("%s", buffer);
			memset(buffer, ' ', 58 + 16);

			sprintf(temp, "+%04x", i);
			memcpy(buffer, temp, 5);

			j = 0;
		}

		sprintf(temp, "%02x", 0xff & data[i]);
		memcpy(buffer + 8 + (j * 3), temp, 2);
		if ((data[i] > 31) && (data[i] < 127))
			ascii[j] = data[i];
		else
			ascii[j] = '.';
	}

	if (j != 0)
		printf("%s", buffer);
}



#ifdef STANDALONE
int main(int argc,char **argv)
{
  unsigned char buffer[64];
  int offset=0;
  char *did=argv[1];


  printf("return value = %d\n",pack_did(buffer,&offset,did));

  int i;

  for(i=0;i<offset;i++) printf("%02x\n",buffer[i]);

  int offset_out=0;
  char did_out[64];
  
  printf("return value = %d\n",unpack_did(buffer,&offset_out,did_out));
  printf("did_out='%s', offset_out=%d (should be %d)\n",
	 did_out,offset_out,offset);

  uint64_t t=time(0)*1000LL;
  offset=0;
  pack_time(buffer,&offset,t);
  printf("stowing time = 0x%llx\n",t);
  for(i=0;i<offset;i++) printf("%02x\n",buffer[i]);
  offset-=8;
  t=0;
  unpack_time(buffer,&offset,&t);
  printf("extracted time = 0x%llx\n",t);

  offset=0;
  encode_length_backwards(buffer,&offset,123);
  for(i=0;i<offset;i++) printf("%02x\n",buffer[i]);
  unsigned int length;
  decode_length_backwards(buffer,offset,&length);
  printf("decoding reverse-encoded length=123 yields %d (offset was %d, should be 1)\n",
	 length,offset);

  offset=0;
  encode_length_backwards(buffer,&offset,0x1234567);
  for(i=0;i<offset;i++) printf("%02x\n",buffer[i]);
  decode_length_backwards(buffer,offset,&length);
  printf("decoding reverse-encoded length=0x1234567 yields 0x%x (offset was %d, should be 5)\n",
	 length,offset);

  offset=0;
  encode_length_forwards(buffer,&offset,123);
  for(i=0;i<offset;i++) printf("%02x\n",buffer[i]);
  decode_length_forwards(buffer,&offset,&length);
  offset=0;
  printf("decoding forward-encoded length=123 yields %d (offset is %d, should be 1)\n",
	 length,offset);

  offset=0;
  encode_length_forwards(buffer,&offset,0x1234567);
  for(i=0;i<offset;i++) printf("%02x\n",buffer[i]);
  offset=0;
  decode_length_forwards(buffer,&offset,&length);
  printf("decoding reverse-encoded length=0x1234567 yields 0x%x (offset is %d, should be 5)\n",
	 length,offset);


  return 0;
}


#endif
