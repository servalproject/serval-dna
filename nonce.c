/*
Copyright (C) 2013 Paul Gardner-Stephen, Serval Project.
 
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

int nonce_initialised=0;
unsigned char nonce_buffer[128];

int generate_nonce(unsigned char *nonce,int bytes)
{
  if (bytes<1||bytes>128) return -1;
 start:
  if (!nonce_initialised) {
    if (urandombytes(nonce_buffer,128))
      return -1;
    nonce_initialised=1;
  }

  // Increment nonce
  int i;
  for(i=0;i<128;i++)
    {
      unsigned char b=nonce_buffer[i]+1;
      nonce_buffer[i]=b;
      if (b) break;
    }
  if (i>=128) {
    nonce_initialised=0;
    goto start;
  }

  bcopy(nonce_buffer,nonce,bytes);
  return 0;
}

int app_nonce_test(const struct cli_parsed *parsed, struct cli_context *context)
{
  int i,j;
  unsigned char nonces[0x10001][32];
  for(i=0;i<0x10001;i++)
    {
      if (generate_nonce(&nonces[i][0],32))
	return WHYF("Failed to generate nonce #%d\n",i);
      for(j=0;j<i;j++) {
	if (!memcmp(&nonces[i][0],&nonces[j][0],32))
	  return WHYF("Nonce #%d is the same as nonce #%d\n",i,j);
      }
      if (!(random()&0xff)) 
	cli_printf(context, "Nonce #%d = %02x%02x%02x%02x...\n",
			    i,nonces[i][0],nonces[i][1],nonces[i][2],nonces[i][3]);
    }
  cli_printf(context, "Test passed\n");
  return 0;
}
