#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <jni.h>
#include "crypto_box_curve25519xsalsa20poly1305.h"

// Lto/yp/cr/NaCl;.moose ()I
JNIEXPORT jint JNICALL Java_to_yp_cr_NaCl_moose
  (JNIEnv *env, jobject obj)
{
  return 1;
}


static int urandomfd = -1;

int urandombytes(unsigned char *x,unsigned long long xlen)
{
  int i;
  int t=0;

  if (urandomfd == -1) {
    for (i=0;i<4;i++) {
      urandomfd = open("/dev/urandom",O_RDONLY);
      if (urandomfd != -1) break;
      sleep(1);
    }
    if (i==4) return -1;
  }

  while (xlen > 0) {
    if (xlen < 1048576) i = xlen; else i = 1048576;

    i = read(urandomfd,x,i);
    if (i < 1) {
      sleep(1);
      t++;
      if (t>4) return -1;
      continue;
    } else t=0;

    x += i;
    xlen -= i;
  }

  return 0;
}


JNIEXPORT jint JNICALL Java_to_yp_cr_NaCl_nativeRandomBytes
(JNIEnv *env, jobject obj, jbyteArray bytes)
{
  int l=(*env)->GetArrayLength(env, bytes);
  if (l<1) return -1;
  jbyte *b = (*env)->GetPrimitiveArrayCritical(env, bytes, NULL);

  urandombytes(b,l);

  if (b) (*env)->ReleasePrimitiveArrayCritical(env, bytes, b, 0);
  return 0;
}

// Lto/yp/cr/NaCl$CryptoBoxKeypair;.method ([B[B)I
JNIEXPORT jint JNICALL Java_to_yp_cr_NaCl_nativeCryptoBoxKeypair
  (JNIEnv *env, jobject obj, jbyteArray jsk, jbyteArray jpk)
{
  unsigned char pk[crypto_box_curve25519xsalsa20poly1305_ref_PUBLICKEYBYTES];
  unsigned char sk[crypto_box_curve25519xsalsa20poly1305_ref_PUBLICKEYBYTES];

  if (crypto_box_curve25519xsalsa20poly1305_ref_keypair(pk,sk)) return 1;

  /* Set java side versions of pk and sk */
  (*env)->SetByteArrayRegion(env, jpk, 0, crypto_box_curve25519xsalsa20poly1305_ref_PUBLICKEYBYTES, pk);
  (*env)->SetByteArrayRegion(env, jsk, 0, crypto_box_curve25519xsalsa20poly1305_ref_SECRETKEYBYTES, sk);

  return 0;
}

JNIEXPORT jint JNICALL Java_to_yp_cr_NaCl_nativeCryptoBox
(JNIEnv *env, jobject obj, jbyteArray jpk, jbyteArray jsk,jbyteArray jn,jbyteArray jm,jint jmlen,jbyteArray jc)
{
  /* XXX Assumes that the first 32 bytes of jm are all zeroes so that the authenticator can be written in */
  int i;
  
  if ((*env)->GetArrayLength(env, jpk)!=crypto_box_curve25519xsalsa20poly1305_ref_PUBLICKEYBYTES) return -2;
  if ((*env)->GetArrayLength(env, jsk)!=crypto_box_curve25519xsalsa20poly1305_ref_SECRETKEYBYTES) return -3;
  if ((*env)->GetArrayLength(env, jn)!=crypto_box_curve25519xsalsa20poly1305_ref_NONCEBYTES) return -4;
  if ((*env)->GetArrayLength(env, jm)!=jmlen) return -5;
  if ((*env)->GetArrayLength(env, jc)!=jmlen) return -6;

  
  /* Get inputs */
  jbyte *pk = (*env)->GetPrimitiveArrayCritical(env, jpk, NULL);
  jbyte *sk = (*env)->GetPrimitiveArrayCritical(env, jsk, NULL);
  jbyte *n = (*env)->GetPrimitiveArrayCritical(env, jn, NULL);
  jbyte *m = (*env)->GetPrimitiveArrayCritical(env, jm, NULL);
  jbyte *c = (*env)->GetPrimitiveArrayCritical(env, jc, NULL);
  
  int r=-1;
  
  if (pk&&sk&&n&&m&&c&&(jmlen>=0&&jmlen<=1048576))
    {
      /* Make sure that space for authenticator is free */
      for(i=0;i<crypto_box_curve25519xsalsa20poly1305_ref_ZEROBYTES;i++)
	{ if (m[i]) return -7; }

      r=crypto_box_curve25519xsalsa20poly1305_ref(c,m,jmlen,n,pk,sk);
    }
  
  /* do these really keep any changes made? */
  if (pk) (*env)->ReleasePrimitiveArrayCritical(env, jpk, pk, 0);
  if (sk) (*env)->ReleasePrimitiveArrayCritical(env, jsk, sk, 0);
  if (n) (*env)->ReleasePrimitiveArrayCritical(env, jn, n, 0);
  if (m) (*env)->ReleasePrimitiveArrayCritical(env, jm, m, 0);
  if (c) (*env)->ReleasePrimitiveArrayCritical(env, jc, c, 0);
  
  return r;
}

