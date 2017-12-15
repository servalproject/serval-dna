/*
Serval DNA JNI command-line entry points
Copyright (C) 2016 Flinders University
Copyright (C) 2010-2013 Serval Project Inc.

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
#include "commandline.h"
#include "mem.h"
#include "os.h"
#include "str.h"
#include "strbuf_helpers.h"
#include "conf.h"
#include "debug.h"

static struct cli_vtable cli_vtable_jni;

struct jni_context {
  JNIEnv *jni_env;
  int jni_exception;
  jobject jniResults;
  char *outv_buffer;
  char *outv_current;
  char *outv_limit;
};

/* Data structures for accumulating output of a single JNI call.
*/

#define OUTV_BUFFER_ALLOCSIZE	(8192)

static jclass IJniResults = NULL;
static jmethodID putString;
static jmethodID putLong;
static jmethodID putDouble;
static jmethodID putHexValue;
static jmethodID putBlob;
static jmethodID startTable;
static jmethodID setColumnName;
static jmethodID endTable;

static int outv_growbuf(struct jni_context *context, size_t needed)
{
  assert(context->outv_current <= context->outv_limit);
  size_t remaining = (size_t)(context->outv_limit - context->outv_current);
  if (remaining < needed) {
    size_t cursize = (size_t)(context->outv_current - context->outv_buffer);
    size_t newsize = cursize + needed;
    // Round up to nearest multiple of OUTV_BUFFER_ALLOCSIZE.
    newsize = newsize + OUTV_BUFFER_ALLOCSIZE - ((newsize - 1) % OUTV_BUFFER_ALLOCSIZE + 1);
    assert(newsize > cursize);
    assert((size_t)(newsize - cursize) >= needed);
    if ((context->outv_buffer = erealloc(context->outv_buffer, newsize)) == NULL)
      return -1;
    context->outv_current = context->outv_buffer + cursize;
    context->outv_limit = context->outv_buffer + newsize;
  }
  return 0;
}

static void outv_write(struct jni_context *context, const char *buf, size_t len)
{
  // Converts NUL chars to Modified UTF-8 NUL (c0 80) so that Java's UTF String will treat it as an
  // embedded NUL.
  size_t utflen = len;
  const char *s;
  for (s = buf; s != buf + len; ++s)
    if (!*s)
      ++utflen;
  if (outv_growbuf(context, utflen) == -1)
    return;
  for (s = buf; s != buf + len; ++s)
    if (*s)
      *context->outv_current++ = *s;
    else {
      *context->outv_current++ = '\xc0';
      *context->outv_current++ = '\x80';
    }
  assert(context->outv_current <= context->outv_limit);
}

static int put_string(struct jni_context *context, const char *str)
{
  if (context->jni_exception)
    return -1;
  jstring jstr = NULL;
  if (str) {
    jstr = (jstring)(*context->jni_env)->NewStringUTF(context->jni_env, str);
    if (jstr == NULL) {
      context->jni_exception = 1;
      return WHY("Exception thrown from NewStringUTF()");
    }
  }
  (*context->jni_env)->CallVoidMethod(context->jni_env, context->jniResults, putString, jstr);
  (*context->jni_env)->DeleteLocalRef(context->jni_env, jstr);
  if ((*context->jni_env)->ExceptionCheck(context->jni_env)) {
    context->jni_exception = 1;
    return WHY("Exception thrown from CallVoidMethod(putLong)");
  }
  return 0;
}

static int put_byte_array(struct jni_context *context, const jbyte *blob, jsize length, jmethodID method, const char *method_name)
{
  jbyteArray arr = NULL;
  if (context->jni_exception)
    return -1;
  arr = (*context->jni_env)->NewByteArray(context->jni_env, length);
  if (arr == NULL || (*context->jni_env)->ExceptionCheck(context->jni_env)) {
    context->jni_exception = 1;
    return WHY("Exception thrown from NewByteArray()");
  }
  if (blob && length) {
    (*context->jni_env)->SetByteArrayRegion(context->jni_env, arr, 0, length, blob);
    if ((*context->jni_env)->ExceptionCheck(context->jni_env)) {
      context->jni_exception = 1;
      return WHY("Exception thrown from SetByteArrayRegion()");
    }
  }
  (*context->jni_env)->CallVoidMethod(context->jni_env, context->jniResults, method, arr);
  if ((*context->jni_env)->ExceptionCheck(context->jni_env)) {
    context->jni_exception = 1;
    return WHYF("Exception thrown from CallVoidMethod(%s)", method_name);
  }
  if (arr)
    (*context->jni_env)->DeleteLocalRef(context->jni_env, arr);
  return 0;
}

static int outv_end_field(struct jni_context *context)
{
  // append terminating nul
  if (outv_growbuf(context, 1) == -1)
    return -1;
  *context->outv_current++ = '\0';
  context->outv_current = context->outv_buffer;
  return put_string(context, context->outv_buffer);
}

static int initJniTypes(JNIEnv *env)
{
  if (IJniResults)
    return 0;

  cf_init();

  IJniResults = (*env)->FindClass(env, "org/servalproject/servaldna/IJniResults");
  if (IJniResults==NULL)
    return jni_throw(env, "java/lang/IllegalStateException", "Unable to locate class org.servalproject.servaldna.IJniResults");
  // make sure the interface class cannot be garbage collected between invocations in the same process
  IJniResults = (jclass)(*env)->NewGlobalRef(env, IJniResults);
  if (IJniResults==NULL)
    return jni_throw(env, "java/lang/IllegalStateException", "Unable to create global ref to class org.servalproject.servaldna.IJniResults");
  putString = (*env)->GetMethodID(env, IJniResults, "putString", "(Ljava/lang/String;)V");
  if (putString==NULL)
    return jni_throw(env, "java/lang/IllegalStateException", "Unable to locate method putString");
  putLong = (*env)->GetMethodID(env, IJniResults, "putLong", "(J)V");
  if (putLong==NULL)
    return jni_throw(env, "java/lang/IllegalStateException", "Unable to locate method putLong");
  putDouble = (*env)->GetMethodID(env, IJniResults, "putDouble", "(D)V");
  if (putDouble==NULL)
    return jni_throw(env, "java/lang/IllegalStateException", "Unable to locate method putDouble");
  putHexValue = (*env)->GetMethodID(env, IJniResults, "putHexValue", "([B)V");
  if (putHexValue==NULL)
    return jni_throw(env, "java/lang/IllegalStateException", "Unable to locate method putHexValue");
  putBlob = (*env)->GetMethodID(env, IJniResults, "putBlob", "([B)V");
  if (putBlob==NULL)
    return jni_throw(env, "java/lang/IllegalStateException", "Unable to locate method putBlob");
  startTable = (*env)->GetMethodID(env, IJniResults, "startTable", "(I)V");
  if (startTable==NULL)
    return jni_throw(env, "java/lang/IllegalStateException", "Unable to locate method startTable");
  setColumnName = (*env)->GetMethodID(env, IJniResults, "setColumnName", "(ILjava/lang/String;)V");
  if (setColumnName==NULL)
    return jni_throw(env, "java/lang/IllegalStateException", "Unable to locate method setColumnName");
  endTable = (*env)->GetMethodID(env, IJniResults, "endTable", "(I)V");
  if (endTable==NULL)
    return jni_throw(env, "java/lang/IllegalStateException", "Unable to locate method endTable");

  return 0;
}

/* JNI entry point to command line.  See org.servalproject.servald.ServalD class for the Java side.
   JNI method descriptor: "(Ljava/util/List;[Ljava/lang/String;)I"
*/
JNIEXPORT jint JNICALL Java_org_servalproject_servaldna_ServalDCommand_rawCommand(JNIEnv *env, jobject UNUSED(this), jobject outv, jobjectArray args)
{
  int r;
  // find jni results methods
  if ((r=initJniTypes(env))!=0)
    return r;

  uint8_t status = 0; // to match what the shell gets: 0..255

  // Construct argv, argc from this method's arguments.
  jsize len = (*env)->GetArrayLength(env, args);

  jstring jsv[len];
  bzero(jsv, sizeof(jsv));

  const char *argv[len + 1];
  bzero(argv, sizeof(argv));

  // From now on, in case of an exception we have to free some resources before
  // returning.
  static const char *EMPTY="";

  struct jni_context context;
  bzero(&context, sizeof(context));

  struct cli_context cli_context = {
    .vtable = &cli_vtable_jni,
    .context = &context
  };

  jsize i;
  for (i = 0; !context.jni_exception && i < len; ++i) {
    const jstring arg = jsv[i] = (jstring)(*env)->GetObjectArrayElement(env, args, i);
    if ((*env)->ExceptionCheck(env)){
      context.jni_exception = 1;
    } else if (arg == NULL) {
      argv[i] = EMPTY;
    } else {
      argv[i] = (*env)->GetStringUTFChars(env, arg, NULL);
      if (argv[i] == NULL)
	context.jni_exception = 1;
    }
  }
  if (!context.jni_exception) {
    // Set up the output buffer.
    context.jniResults = outv;
    context.outv_current = context.outv_buffer;
    // Execute the command.
    context.jni_env = env;
    status = (uint8_t)commandline_main(&cli_context, NULL, (int)len, argv);
  }

  // free any temporary output buffer
  if (context.outv_buffer)
    free(context.outv_buffer);

  // Release argv Java string buffers.
  for (i = 0; i < len; ++i) {
    if (jsv[i]) {
      assert(argv[i] != EMPTY);
      (*env)->ReleaseStringUTFChars(env, jsv[i], argv[i]);
    }
  }

  // Deal with Java exceptions: NewStringUTF out of memory in outv_end_field().
  if (context.jni_exception || (context.outv_current != context.outv_buffer && outv_end_field(&context) == -1))
    return -1;

  return (jint) status;
}

/* An instance of struct cli_vtable that passes all output fields to an IJniResults
 * interface callback.
 */

static struct jni_context *jni_context(struct cli_context *cli_context)
{
  return (struct jni_context *)(cli_context->context);
}

static void jni_delim(struct cli_context *cli_context, const char *UNUSED(opt))
{
  DEBUGF(jni, "");
  outv_end_field(jni_context(cli_context));
}

static void jni_write(struct cli_context *cli_context, const char *buf, size_t len)
{
  DEBUGF(jni, "%s", alloca_toprint(-1, buf, len));
  outv_write(jni_context(cli_context), buf, len);
}

static void jni_puts(struct cli_context *cli_context, const char *str)
{
  DEBUGF(jni, "%s", alloca_str_toprint(str));
  outv_write(jni_context(cli_context), str, strlen(str));
}

static void jni_vprintf(struct cli_context *cli_context, const char *fmt, va_list ap)
{
  DEBUGF(jni, "%s, ...", alloca_str_toprint(fmt));
  struct jni_context *context = jni_context(cli_context);
  assert(context->outv_current <= context->outv_limit);
  size_t avail = (size_t)(context->outv_limit - context->outv_current);
  va_list aq;
  va_copy(aq, ap);
  int count = vsnprintf(context->outv_current, avail, fmt, aq);
  va_end(aq);
  if (count < 0) {
    WHYF("vsnprintf(%p,%zu,%s,...) failed", context->outv_current, avail, alloca_str_toprint(fmt));
    return;
  } else if ((size_t)count < avail) {
    context->outv_current += count;
    return;
  }
  if (outv_growbuf(context, (size_t)count) == -1)
    return;
  avail = (size_t)(context->outv_limit - context->outv_current);
  va_copy(aq, ap);
  count = vsprintf(context->outv_current, fmt, aq);
  va_end(aq);
  if (count < 0) {
    WHYF("vsprintf(%p,%s,...) failed", context->outv_current, alloca_str_toprint(fmt));
    return;
  }
  assert((size_t)count < avail);
  context->outv_current += (size_t)count;
}

static void jni_put_long(struct cli_context *cli_context, int64_t value, const char *UNUSED(delim_opt))
{
  DEBUGF(jni, "%" PRId64, value);
  struct jni_context *context = jni_context(cli_context);
  if (context->jni_exception)
    return;
  (*context->jni_env)->CallVoidMethod(context->jni_env, context->jniResults, putLong, value);
  if ((*context->jni_env)->ExceptionCheck(context->jni_env)) {
    context->jni_exception = 1;
    WHY("Exception thrown from CallVoidMethod(putLong)");
  }
}

static void jni_put_string(struct cli_context *cli_context, const char *value, const char *UNUSED(delim_opt))
{
  DEBUGF(jni, "%s", alloca_str_toprint(value));
  struct jni_context *context = jni_context(cli_context);
  if (context->jni_exception)
    return;
  jstring str = NULL;
  if (value){
    str = (jstring)(*context->jni_env)->NewStringUTF(context->jni_env, value);
    if (str == NULL) {
      context->jni_exception = 1;
      WHY("Exception thrown from NewStringUTF()");
      return;
    }
  }
  (*context->jni_env)->CallVoidMethod(context->jni_env, context->jniResults, putString, str);
  (*context->jni_env)->DeleteLocalRef(context->jni_env, str);
  if ((*context->jni_env)->ExceptionCheck(context->jni_env)) {
    context->jni_exception = 1;
    WHY("Exception thrown from CallVoidMethod(putLong)");
  }
}

static void jni_put_hexvalue(struct cli_context *cli_context, const unsigned char *value, size_t length, const char *UNUSED(delim_opt))
{
  DEBUGF(jni, "%s", alloca_tohex(value, length));
  struct jni_context *context = jni_context(cli_context);
  put_byte_array(context, (const jbyte*)value, (jsize)length, putHexValue, "putHexValue");
}

static void jni_put_blob(struct cli_context *cli_context, const unsigned char *blob, size_t length, const char *UNUSED(delim_opt))
{
  DEBUGF(jni, "%s", alloca_tohex(blob, length));
  struct jni_context *context = jni_context(cli_context);
  put_byte_array(context, (const jbyte*)blob, (jsize)length, putBlob, "putBlob");
}

static void jni_start_table(struct cli_context *cli_context, size_t column_count, const char *column_names[])
{
  DEBUGF(jni, "%s", alloca_argv((int)column_count, column_names));
  struct jni_context *context = jni_context(cli_context);
  if (context->jni_exception)
    return;
  (*context->jni_env)->CallVoidMethod(context->jni_env, context->jniResults, startTable, (jint)column_count);
  if ((*context->jni_env)->ExceptionCheck(context->jni_env)) {
    context->jni_exception = 1;
    WHY("Exception thrown from CallVoidMethod(startTable)");
    return;
  }
  size_t i;
  for (i = 0; i != column_count; ++i) {
    jstring str = (jstring)(*context->jni_env)->NewStringUTF(context->jni_env, column_names[i]);
    if (str == NULL) {
      context->jni_exception = 1;
      WHY("Exception thrown from NewStringUTF()");
      return;
    }
    (*context->jni_env)->CallVoidMethod(context->jni_env, context->jniResults, setColumnName, i, str);
    (*context->jni_env)->DeleteLocalRef(context->jni_env, str);
    if ((*context->jni_env)->ExceptionCheck(context->jni_env)) {
      context->jni_exception = 1;
      WHY("Exception thrown from CallVoidMethod(setColumnName)");
      return;
    }
  }
}

static void jni_end_table(struct cli_context *cli_context, size_t row_count)
{
  DEBUGF(jni, "%zu", row_count);
  struct jni_context *context = jni_context(cli_context);
  if (context->jni_exception)
    return;
  (*context->jni_env)->CallVoidMethod(context->jni_env, context->jniResults, endTable, (jint)row_count);
  if ((*context->jni_env)->ExceptionCheck(context->jni_env)) {
    context->jni_exception = 1;
    WHY("Exception thrown from CallVoidMethod()");
  }
}

static void jni_field_name(struct cli_context *cli_context, const char *name, const char *UNUSED(delim_opt))
{
  DEBUGF(jni, "%s", name);
  struct jni_context *context = jni_context(cli_context);
  if (context->jni_exception)
    return;
  jstring str = (jstring)(*context->jni_env)->NewStringUTF(context->jni_env, name);
  if (str == NULL) {
    context->jni_exception = 1;
    WHY("Exception thrown from NewStringUTF()");
    return;
  }
  (*context->jni_env)->CallVoidMethod(context->jni_env, context->jniResults, setColumnName, -1, str);
  (*context->jni_env)->DeleteLocalRef(context->jni_env, str);
  if ((*context->jni_env)->ExceptionCheck(context->jni_env)) {
    context->jni_exception = 1;
    WHY("Exception thrown from CallVoidMethod(setColumnName)");
    return;
  }
}

static void jni_flush(struct cli_context *UNUSED(cli_context))
{
  DEBUGF(jni, "");
  // nop
}

static struct cli_vtable cli_vtable_jni = {
  .delim = jni_delim,
  .write = jni_write,
  .puts = jni_puts,
  .vprintf = jni_vprintf,
  .put_long = jni_put_long,
  .put_string = jni_put_string,
  .put_hexvalue = jni_put_hexvalue,
  .put_blob = jni_put_blob,
  .start_table = jni_start_table,
  .end_table = jni_end_table,
  .field_name = jni_field_name,
  .flush = jni_flush
};
