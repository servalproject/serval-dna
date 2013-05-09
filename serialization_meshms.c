/*
Serval Mesh
Copyright (C) 2013 Alexandra Sclapari
Copyright (C) 2013 Paul Gardner-Stephen

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
#include "rhizome.h"

void hex_dump(unsigned char *data, int size)
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
			   unsigned int buffer_length,
			   unsigned int *length)
{
  *length=0;
  if (*offset>=buffer_length) return -1;
  switch(buffer[*offset]) {
  case 0xff:
    (*offset)++;
    if (*offset>=buffer_length) return -1;
    int i;
    for(i=0;i<32;i+=8) {
      (*length)|=buffer[(*offset)++]<<i;
      if (*offset>=buffer_length) return -1;
    }
    return 0;
  default:
    *length=buffer[(*offset)++];
    if (*offset>=buffer_length) return -1;
    return 0;
  }
}

int decode_length_backwards(unsigned char *buffer,int offset,
			    unsigned int *length)
{
  // it is assumed that offset points to the first byte after the end
  // of the length field.
  if (offset<=0) return -1;
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

int pack_int(unsigned char *buffer,int *offset,int32_t v)
{
  int i;
  for(i=0;i<32;i+=8) { buffer[(*offset)++]=(v>>i)&0xff; }
  return 0;
}

int unpack_int(unsigned char *buffer,int *offset,int32_t *v)
{
  int i;
  *v=0;
  for(i=0;i<32;i+=8) (*v)|=(((uint32_t)buffer[(*offset)++])<<i);
  return 0;
}

int pack_time(unsigned char *buffer,int *offset,uint64_t time)
{
  int i;
  for(i=0;i<64;i+=8) { buffer[(*offset)++]=(time>>i)&0xff; }
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

int pack_did(unsigned char *buffer,int *offset,const char *did)
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

int serialize_ack(unsigned char *buffer,int *offset, int buffer_size,
		  int ack_address)
{
  if ((*offset)+1+1+4+1>=buffer_size) return -1;
  encode_length_forwards(buffer,offset,1+1+4+1);
  buffer[(*offset)++]=RHIZOME_MESHMS_BLOCK_TYPE_MESSAGE;
  pack_int(buffer,offset,ack_address);
  encode_length_backwards(buffer,offset,1+1+4+1);
  return 0;
}

int serialize_meshms(unsigned char *buffer,int *offset,unsigned int length,const char *sender_did,const char *recipient_did, unsigned long long time, const char *payload, int payload_length)
{
  int ret = 0;
   
  encode_length_forwards(buffer,offset,length);
  buffer[(*offset)++]=RHIZOME_MESHMS_BLOCK_TYPE_MESSAGE;
  pack_did(buffer,offset,sender_did);
  pack_did(buffer,offset,recipient_did);  
  pack_time(buffer,offset,time);
  
  int i=0;
  for(i;i<payload_length;i++)
  {
   buffer[(*offset)++]=payload[i];
  }
  
  encode_length_backwards(buffer,offset,length);
  hex_dump(buffer,*offset);

  return ret;
}

int meshms_block_type(unsigned char *buffer,int offset, int blength)
{
  unsigned int length=0;
  if (offset>=blength) return -1;
  decode_length_forwards(buffer,&offset,blength,&length);
  if (offset>=blength) return -1;
  unsigned char block_type=buffer[offset];
  return block_type;
}

int deserialize_ack(unsigned char *buffer,int *offset, int buffer_size,
		    int *ack_address)
{
  unsigned int length=0;
  int length_length=*offset;
  decode_length_forwards(buffer,offset,buffer_size,&length);
  length_length=(*offset)-length_length;
  unsigned char block_type=buffer[(*offset)++];
  if (block_type!=RHIZOME_MESHMS_BLOCK_TYPE_ACK) return -1;
  unpack_int(buffer,offset,ack_address);
  (*offset)+=length_length;
  return 0;
}

int deserialize_meshms(int message_number,
		       unsigned char *buffer,int *offset, int buffer_size,
		       char *delivery_status)
{
  int ret = 0;
  int i=0;
  
  unsigned int length =0;

  unsigned int start_offset=*offset;

  cli_printf("%d",message_number); cli_delim(":");
  
  cli_printf("%d",*offset); cli_delim(":");
  
  int length_length=*offset;
  decode_length_forwards(buffer,offset,buffer_size,&length);
  length_length=(*offset)-length_length;
  cli_printf("%d",length); cli_delim(":");
  
  unsigned char block_type=buffer[(*offset)++];
  if (block_type!=RHIZOME_MESHMS_BLOCK_TYPE_MESSAGE) {
    WHYF("Corrupt meshms message block: type=0x%02x instead of 0x%02x",
	 block_type,RHIZOME_MESHMS_BLOCK_TYPE_MESSAGE);
    return -1;
  }
  
  char sender_did_out[64];
  unpack_did(buffer,offset,sender_did_out);
  cli_printf("%s",sender_did_out); cli_delim(":");
  
  char recipient_did_out[64];
  unpack_did(buffer,offset,recipient_did_out);
  cli_printf("%s",recipient_did_out); cli_delim(":");
  
  unsigned long long time = 0;
  unpack_time(buffer,offset,&time);    
  cli_printf("%lld",time); cli_delim(":");

  cli_printf("%s",delivery_status); cli_delim(":");
  cli_printf("%s","meshms"); cli_delim(":");
  
  int j=0;
  int payload_end=start_offset+length-length_length;
  for(j=*offset;j<payload_end;j++)
    {
      cli_printf("%c", buffer[(*offset)++]);
    } 
  
  cli_delim("\n");
  i = i+length;
  *offset=i;    
  
  return ret;
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
  decode_length_backwards(buffer,offset,buffer_size,&length);
  printf("decoding reverse-encoded length=123 yields %d (offset was %d, should be 1)\n",
	 length,offset);

  offset=0;
  encode_length_backwards(buffer,&offset,0x1234567);
  for(i=0;i<offset;i++) printf("%02x\n",buffer[i]);
  decode_length_backwards(buffer,offset,buffer_size,&length);
  printf("decoding reverse-encoded length=0x1234567 yields 0x%x (offset was %d, should be 5)\n",
	 length,offset);

  offset=0;
  encode_length_forwards(buffer,&offset,123);
  for(i=0;i<offset;i++) printf("%02x\n",buffer[i]);
  decode_length_forwards(buffer,&offset,buffer_size,&length);
  offset=0;
  printf("decoding forward-encoded length=123 yields %d (offset is %d, should be 1)\n",
	 length,offset);

  offset=0;
  encode_length_forwards(buffer,&offset,0x1234567);
  for(i=0;i<offset;i++) printf("%02x\n",buffer[i]);
  offset=0;
  decode_length_forwards(buffer,&offset,buffer_size,&length);
  printf("decoding reverse-encoded length=0x1234567 yields 0x%x (offset is %d, should be 5)\n",
	 length,offset);


  return 0;
}


#endif
