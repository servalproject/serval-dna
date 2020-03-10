/* 
Serval DNA server main loop - JNI entry point
Copyright (C) 2015 Serval Project Inc.
Copyright (C) 2016 Flinders University

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

#include <assert.h>
#include "jni_common.h"
#include "server.h"
#include "serval.h" // for mdp_loopback_port
#include "keyring.h"
#include "conf.h"
#include "instance.h"
#include "httpd.h"
#include "feature.h"

DEFINE_FEATURE(jni_server);

static JNIEnv *server_env=NULL;
static jclass IJniServer= NULL;
static jmethodID aboutToWait, wokeUp, started;
static jobject JniCallback;

static time_ms_t waiting(time_ms_t now, time_ms_t next_run, time_ms_t next_wakeup)
{
  if (server_env && JniCallback){
    jlong r = (*server_env)->CallLongMethod(server_env, JniCallback, aboutToWait, (jlong)now, (jlong)next_run, (jlong)next_wakeup);
    // stop the server if there are any issues
    if ((*server_env)->ExceptionCheck(server_env)){
      INFO("Stopping server due to exception");
      server_close();
      return now;
    }
    return r;
  }
  return next_wakeup;
}

static void wokeup()
{
  if (server_env && JniCallback){
    (*server_env)->CallVoidMethod(server_env, JniCallback, wokeUp);
    // stop the server if there are any issues
    if ((*server_env)->ExceptionCheck(server_env)){
      INFO("Stopping server due to exception");
      server_close();
    }
  }
}

JNIEXPORT jint JNICALL Java_org_servalproject_servaldna_ServalDCommand_server(
  JNIEnv *env, jobject UNUSED(this), jobject callback, jobject keyring_pin, jobjectArray entry_pins)
{
  cf_init();
  cf_reload_strict();

  if (!IJniServer) {
    IJniServer = (*env)->FindClass(env, "org/servalproject/servaldna/IJniServer");
    if (IJniServer==NULL)
      return jni_throw(env, "java/lang/IllegalStateException", "Unable to locate class org.servalproject.servaldna.IJniServer");
    // make sure the interface class cannot be garbage collected between invocations
    IJniServer = (jclass)(*env)->NewGlobalRef(env, IJniServer);
    if (IJniServer==NULL)
      return jni_throw(env, "java/lang/IllegalStateException", "Unable to create global ref to class org.servalproject.servaldna.IJniServer");
    aboutToWait = (*env)->GetMethodID(env, IJniServer, "aboutToWait", "(JJJ)J");
    if (aboutToWait==NULL)
      return jni_throw(env, "java/lang/IllegalStateException", "Unable to locate method aboutToWait");
    wokeUp = (*env)->GetMethodID(env, IJniServer, "wokeUp", "()V");
    if (wokeUp==NULL)
      return jni_throw(env, "java/lang/IllegalStateException", "Unable to locate method wokeUp");
    started = (*env)->GetMethodID(env, IJniServer, "started", "(Ljava/lang/String;III)V");
    if (started==NULL)
      return jni_throw(env, "java/lang/IllegalStateException", "Unable to locate method started");
  }
  
  int pid = server_pid();
  if (pid < 0)
    return jni_throw(env, "java/lang/IllegalStateException", "Failed to read server pid");
  if (pid > 0)
    return jni_throw(env, "java/lang/IllegalStateException", "Server already running");
  
  int ret = -1;
  
  {
    assert(keyring == NULL);
    const char *cpin = keyring_pin?(*env)->GetStringUTFChars(env, keyring_pin, NULL):NULL;
    if (cpin != NULL){
      keyring = keyring_open_instance(cpin);
      (*env)->ReleaseStringUTFChars(env, keyring_pin, cpin);
    }else{
      keyring = keyring_open_instance("");
    }
  }
  
  // Always open all PIN-less entries.
  keyring_enter_pin(keyring, "");
  if (entry_pins){
    jsize len = (*env)->GetArrayLength(env, entry_pins);
    jsize i;
    for (i = 0; i < len; ++i) {
      const jstring pin = (jstring)(*env)->GetObjectArrayElement(env, entry_pins, i);
      if ((*env)->ExceptionCheck(env))
	goto end;
      const char *cpin = (*env)->GetStringUTFChars(env, pin, NULL);
      if (cpin != NULL){
	keyring_enter_pin(keyring, cpin);
	(*env)->ReleaseStringUTFChars(env, pin, cpin);
      }
    }
  }
  
  if (server_env){
    jni_throw(env, "java/lang/IllegalStateException", "Server java env variable already set");
    goto end;
  }
  
  server_env = env;
  JniCallback = (*env)->NewGlobalRef(env, callback);
  
  ret = server_bind();
  
  if (ret==-1){
    jni_throw(env, "java/lang/IllegalStateException", "Failed to bind sockets");
    goto end;
  }

  {
    jstring str = (jstring)(*env)->NewStringUTF(env, instance_path());
    (*env)->CallVoidMethod(env, callback, started, str, getpid(), mdp_loopback_port, httpd_server_port);
    (*env)->DeleteLocalRef(env, str);
    if ((*env)->ExceptionCheck(env)){
      ret = WHY("Not starting server due to startup exception");
      goto end;
    }
  }
  
  server_loop(waiting, wokeup);
  
end:
  
  server_env=NULL;
  if (JniCallback){
    (*env)->DeleteGlobalRef(env, JniCallback);
    JniCallback = NULL;
  }
  
  if (keyring)
    keyring_free(keyring);
  keyring = NULL;
  
  return ret;
}
