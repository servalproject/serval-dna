#include <jni.h>
#include "crypto_box_curve25519xsalsa20poly1305.h"

JNIEXPORT jobject JNICALL 
Java_to_yp_cr_nacl_crypto_box_keypair(JNIEnv * env, jobject  obj)
{
  unsigned char pk[crypto_box_curve25519xsalsa20poly1305_ref_PUBLICKEYBYTES];
  unsigned char sk[crypto_box_curve25519xsalsa20poly1305_ref_PUBLICKEYBYTES];

  if (crypto_box_curve25519xsalsa20poly1305_ref_keypair(pk,sk)) return NULL;

  jclass mapClass = (*env)->FindClass(env, "java/util/HashMap");
  if(mapClass == NULL)
    {
      return NULL;
    }

  jsize map_len = 1;
  
  jmethodID init = (*env)->GetMethodID(env, mapClass, "<init>", "(I)V");
  jobject hashMap = (*env)->NewObject(env, mapClass, init, map_len);
  
  jmethodID put = (*env)->GetMethodID(env, mapClass, "put",
				      "(ILjava/lang/Object;)Ljava/lang/Object;");

  jbyteArray jpk = (*env)->NewByteArray(env, crypto_box_curve25519xsalsa20poly1305_ref_PUBLICKEYBYTES);
  jbyteArray jsk = (*env)->NewByteArray(env, crypto_box_curve25519xsalsa20poly1305_ref_SECRETKEYBYTES);

  /* Get java side versions of pk and sk */
  (*env)->SetByteArrayRegion(env, jpk, 0, crypto_box_curve25519xsalsa20poly1305_ref_PUBLICKEYBYTES, pk);
  (*env)->SetByteArrayRegion(env, jsk, 0, crypto_box_curve25519xsalsa20poly1305_ref_SECRETKEYBYTES, sk);

  /* Store in hash map */
  jobject pkkey = (*env)->NewStringUTF(env,"public_key");
  (*env)->CallObjectMethod(env, hashMap, put, pkkey, jpk);
  jobject skkey= (*env)->NewStringUTF(env,"secret_key");
  (*env)->CallObjectMethod(env, hashMap, put, skkey, jsk);

  /* get rid of local reference counts for things we have put in the hash map */
  (*env)->DeleteLocalRef(env, pkkey);
  (*env)->DeleteLocalRef(env, skkey);
  (*env)->DeleteLocalRef(env, jpk);
  (*env)->DeleteLocalRef(env, jsk);

  return hashMap;
}

