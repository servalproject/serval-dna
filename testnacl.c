#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>

#include "crypto_box_curve25519xsalsa20poly1305.h"
#include "crypto_sign_edwards25519sha512batch.h"

struct agent {
  unsigned char box_pk[crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES];
  unsigned char box_sk[crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES];

  unsigned char sign_pk[crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES];
  unsigned char sign_sk[crypto_sign_edwards25519sha512batch_SECRETKEYBYTES];
};

struct agent *newAgent()
{
  struct agent *a;
  
  a=calloc(sizeof(struct agent),1);
  if (!a) { perror("calloc() failed"); exit(-3); }

  // Generate keys required for various crypto functions.

  if (crypto_box_curve25519xsalsa20poly1305_keypair(a->box_pk,a->box_sk))
    { fprintf(stderr,"crypto_box_curve25519xsalsa20poly1305_keypair() failed.\n"); exit(-1); }

  if (crypto_sign_edwards25519sha512batch_keypair(a->sign_pk,a->sign_sk))
    { fprintf(stderr,"crypto_box_curve25519xsalsa20poly1305_keypair() failed.\n"); exit(-1); }
  
  return a;
}

#define MESSAGE "Ketchup is a vegetable"

void dump(char *m,unsigned char *c,int l)
{
  fprintf(stderr,"%s: (%d bytes)\n",m,l);
  int i,j;

  for(i=0;i<l;i+=16)
    {
      fprintf(stderr,"%06x:",i);
      for(j=0;j<16;j++)
	if ((i+j)<l) fprintf(stderr," %02x",c[i+j]); else fprintf(stderr,"   ");
      fprintf(stderr,"  ");
      for(j=0;j<16;j++)
	if ((i+j)<l) {
	  unsigned char sanitised=c[i+j];
	  if (sanitised<' '||sanitised>0x7d) sanitised='.';
	  fprintf(stderr,"%c",sanitised);
	}
      fprintf(stderr,"\n");
    }
}

int main()
{
  int r,i;

  // Make Alice and Bob's keys
  struct agent *alice = newAgent();
  struct agent *bob = newAgent();
  fprintf(stderr,"crypto_box_keypair() and crypto_sign_keypair() succeeded.\n");

  // Make a handy nonce
  char nonce[1024];
  time_t t=time(0);
  snprintf(nonce,1024,"%s",ctime(&t));

  char plainTextIn[1024];
  char cipherText[1024];
  char plainTextOut[1024];

  long long  plainLenIn;
  long long cipherLen;
  long long plainLenOut;

  /* Crypto box test */
  bzero(&plainTextIn[0],crypto_box_curve25519xsalsa20poly1305_ZEROBYTES);
  snprintf(&plainTextIn[crypto_box_curve25519xsalsa20poly1305_ZEROBYTES],1024-crypto_box_curve25519xsalsa20poly1305_ZEROBYTES,"%s",MESSAGE);
  plainLenIn=crypto_box_curve25519xsalsa20poly1305_ZEROBYTES+strlen(MESSAGE)+1;
  r=crypto_box_curve25519xsalsa20poly1305(cipherText,plainTextIn,plainLenIn,nonce,bob->box_pk,alice->box_sk);
  dump("crypto_box plain text in",plainTextIn,plainLenIn);
  dump("crypto_box cipher text",cipherText,plainLenIn);
  if (r) { fprintf(stderr,"crypto_box() failed.\n"); exit(-1); }
  fprintf(stderr,"crypto_box() call succeeded.\n");

  bzero(&plainTextOut,1024); plainLenOut=0;
  r=crypto_box_curve25519xsalsa20poly1305_open(plainTextOut,cipherText,plainLenIn,nonce,alice->box_pk,bob->box_sk);
  dump("crypto_box recovered text",plainTextOut,plainLenIn);
  if (r) { fprintf(stderr,"crypto_box_open() failed (r=%d).\n",r); exit(-1); }
  fprintf(stderr,"crypto_box_open() call succeeded.\n");

  cipherText[33]^=1;
  bzero(&plainTextOut,1024); plainLenOut=0;
  r=crypto_box_curve25519xsalsa20poly1305_open(plainTextOut,cipherText,plainLenIn,nonce,alice->box_pk,bob->box_sk);
  if (!r) { fprintf(stderr,"crypto_box_open() failed to detect modification.\n",r); exit(-1); }
  fprintf(stderr,"crypto_box_open() call succeeded in detecting modification.\n");

  /* Crypto sign test */
  snprintf(&plainTextIn[0],1024,"%s",MESSAGE);
  plainLenIn=strlen(MESSAGE)+1;
  r=crypto_sign_edwards25519sha512batch(cipherText,&cipherLen,plainTextIn,plainLenIn,alice->sign_sk);
  dump("crypto_sign cipher text",cipherText,cipherLen);
  if (r) { fprintf(stderr,"crypto_sign() failed.\n"); exit(-1); }
  fprintf(stderr,"crypto_sign() call succeeded.\n");

  bzero(&plainTextOut,1024); plainLenOut=0;
  r=crypto_sign_edwards25519sha512batch_open(plainTextOut,&plainLenOut,cipherText,cipherLen,alice->sign_pk);
  dump("crypto_sign recovered text",plainTextOut,plainLenOut);
  if (r) { fprintf(stderr,"crypto_sign_open() failed (r=%d).\n",r); exit(-1); }
  fprintf(stderr,"crypto_sign_open() call succeeded.\n");

  cipherText[33]^=1;
  bzero(&plainTextOut,1024); plainLenOut=0;
  r=crypto_sign_edwards25519sha512batch_open(plainTextOut,&plainLenOut,cipherText,cipherLen,alice->sign_pk);
  if (!r) { fprintf(stderr,"crypto_sign_open() failed to detect modification.\n",r); exit(-1); }
  fprintf(stderr,"crypto_sign_open() call succeeded in detecting modification.\n");

  

  return 0;
}
