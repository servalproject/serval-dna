#include <jni.h>
#include "crypto_box_curve25519xsalsa20poly1305.h"

// Lto/yp/cr/NaCl;.moose ()I
JNIEXPORT jint JNICALL Java_to_yp_cr_NaCl_moose
  (JNIEnv *env, jobject obj)
{
  return 1;
}

// Lto/yp/cr/NaCl$CryptoBoxKeypair;.method ([B[B)I
JNIEXPORT jint JNICALL Java_to_yp_cr_NaCl_00024CryptoBoxKeypair_method
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

