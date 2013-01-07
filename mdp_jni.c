/* JNI bindings for MDP protocol.
 *
 * Author(s):
 *   - Romain Vimont (®om) <rom@rom1v.com>
 */

#ifdef HAVE_JNI_H
#include <jni.h>
#include "mdp_client.h"

#define THROW_NULL_POINTER_EXCEPTION \
	(*env)->ThrowNew(env, cl_nullpointerexception, NULL);
#define THROW_OUT_OF_MEMORY_ERROR \
	(*env)->ThrowNew(env, cl_outofmemoryerror, NULL);
#define THROW_MESH_SOCKET_EXCEPTION(x) \
	(*env)->ThrowNew(env, cl_meshsocketexception, (x));

/* jfieldID and jmethodID do not need global ref. */

/* Get jfieldID ref. */
#define G_FIELD(env, cls, name, type) \
  (jfieldID) (*(env))->GetFieldID(env, cls, name, type)
/* Get jmethodID ref. */
#define G_METHOD(env, cls, name, type) \
  (jmethodID) (*(env))->GetMethodID(env, cls, name, type)
/* Get global jclass ref. */
#define GG_CLASS(env, name) \
  (jclass) (*(env))->NewGlobalRef(env,(*(env))->FindClass(env, name))

/* Classes */
static jclass cl_meshpacket;
static jclass cl_subscriberid;

/* Methods */
static jmethodID m_subscriberid_init;

/* MeshSocket fields */
static jfieldID f_meshsocket_fd;
static jfieldID f_meshsocket_rawsid;
static jfieldID f_meshsocket_port;

/* MeshPacket fields */
static jfieldID f_meshpacket_buf;
static jfieldID f_meshpacket_offset;
static jfieldID f_meshpacket_length;
static jfieldID f_meshpacket_sid;
static jfieldID f_meshpacket_port;

/* SubscriberId fields */
static jfieldID f_subscriberid_binary;

/* Throwables */
static jclass cl_meshsocketexception;
static jclass cl_nullpointerexception;
static jclass cl_outofmemoryerror;

JNIEXPORT void JNICALL
Java_org_servalproject_servald_mdp_MeshSocket_init(JNIEnv * env, jclass cls)
{
  /* Keep JNI refs of fields, methods and classes. */

  f_meshsocket_fd = G_FIELD(env, cls, "fd", "I");
  f_meshsocket_rawsid = G_FIELD(env, cls, "rawSid", "[B");
  f_meshsocket_port = G_FIELD(env, cls, "port", "I");

  cl_meshpacket = GG_CLASS(env, "org/servalproject/servald/mdp/MeshPacket");
  f_meshpacket_buf = G_FIELD(env, cl_meshpacket, "buf", "[B");
  f_meshpacket_offset = G_FIELD(env, cl_meshpacket, "offset", "I");
  f_meshpacket_length = G_FIELD(env, cl_meshpacket, "length", "I");
  f_meshpacket_sid =
    G_FIELD(env, cl_meshpacket, "sid",
            "Lorg/servalproject/servald/SubscriberId;");
  f_meshpacket_port = G_FIELD(env, cl_meshpacket, "port", "I");

  cl_subscriberid = GG_CLASS(env, "org/servalproject/servald/SubscriberId");
  f_subscriberid_binary = G_FIELD(env, cl_subscriberid, "binary", "[B");
  m_subscriberid_init = G_METHOD(env, cl_subscriberid, "<init>", "([B)V");

  cl_meshsocketexception =
    GG_CLASS(env, "org/servalproject/servald/mdp/MeshSocketException");
  cl_nullpointerexception = GG_CLASS(env, "java/lang/NullPointerException");
  cl_outofmemoryerror = GG_CLASS(env, "java/lang/OutOfMemoryError");
}

JNIEXPORT void JNICALL
Java_org_servalproject_servald_mdp_MeshSocket__1create(JNIEnv * env,
                                                       jobject this)
{
  jint fd;

  /* Create mesh socket. */

  if ((fd = overlay_mdp_client_socket()) < 0) {
    THROW_MESH_SOCKET_EXCEPTION("Cannot create socket");
    return;                     /* No resources to clean. */
  }

  /* this.fd = fd; */
  (*env)->SetIntField(env, this, f_meshsocket_fd, fd);
}

JNIEXPORT void JNICALL
Java_org_servalproject_servald_mdp_MeshSocket__1bind(JNIEnv * env,
                                                     jobject this, jint port,
                                                     jobject sid_obj)
{
  jint fd;
  jbyteArray jsid;
  jbyte *sid = NULL;
  char any[SID_SIZE];

  /* Retrieve values from java objects. */

  if (sid_obj != NULL) {
    /* jsid = sid_obj.binary; */
    if ((jsid =
         (jbyteArray) (*env)->GetObjectField(env, sid_obj,
                                             f_subscriberid_binary)) ==
        NULL) {
      THROW_NULL_POINTER_EXCEPTION;
      WHY("jsid is NULL");
      return;                   /* No resources to clean. */
    }

    /* Convert jsid array. */
    if ((sid =
         (jbyte *) (*env)->GetByteArrayElements(env, jsid, NULL)) == NULL) {
      THROW_OUT_OF_MEMORY_ERROR;
      WHY("Cannot create sid");
      goto finally;
    }
  } else {
    /* If sid_obj is NULL, then use sid = 0. */
    memset(any, 0, SID_SIZE);
    sid = any;
  }

  /* fd = this.fd; */
  fd = (*env)->GetIntField(env, this, f_meshsocket_fd);

  /* Bind. */

  if (overlay_mdp_bind(fd, sid, port)) {
    THROW_MESH_SOCKET_EXCEPTION("Cannot bind to MDP socket");
    /* fall through finally */
  }

finally:
  if (sid_obj != NULL) {
    (*env)->ReleaseByteArrayElements(env, jsid, sid, 0);
  }
}

JNIEXPORT void JNICALL
Java_org_servalproject_servald_mdp_MeshSocket__1send(JNIEnv * env,
                                                     jobject this,
                                                     jobject mdppack)
{
  jint fd, localport, offset, length, port;
  jobject sid_obj;
  jbyteArray jbuf, jsid, jlocalsid;
  jbyte *buf, *sid, *localsid = NULL;
  int src_port;
  overlay_mdp_frame mdp = { };  /* Init with zeros */

  /* Retrieve values from java objects. */

  /* length = mdppack.length; */
  length = (*env)->GetIntField(env, mdppack, f_meshpacket_length);
  if (length > MDP_MTU) {
    THROW_MESH_SOCKET_EXCEPTION("Mesh packet too big");
    WHYF("Mesh packet too big (size=%d, MTU=%d)", length, MDP_MTU);
    return;
  }

  /* fd = this.fd; */
  fd = (*env)->GetIntField(env, this, f_meshsocket_fd);

  /* jlocalsid = this.rawSid; */
  jlocalsid =
    (jbyteArray) (*env)->GetObjectField(env, this, f_meshsocket_rawsid);

  /* localport = this.port; */
  localport = (*env)->GetIntField(env, this, f_meshsocket_port);

  /* offset = mdppack.offset; */
  offset = (*env)->GetIntField(env, mdppack, f_meshpacket_offset);

  /* port = mdppack.port; */
  port = (*env)->GetIntField(env, mdppack, f_meshpacket_port);

  /* sid_obj = mdppack.sid; */
  if ((sid_obj =
       (*env)->GetObjectField(env, mdppack, f_meshpacket_sid)) == NULL) {
    THROW_NULL_POINTER_EXCEPTION;
    WHY("sid_obj is NULL");
    return;                     /* No resources to clean. */
  }

  /* jsid = mdppack.sid.binary; */
  if ((jsid =
       (jbyteArray) (*env)->GetObjectField(env, sid_obj,
                                           f_subscriberid_binary)) == NULL) {
    THROW_NULL_POINTER_EXCEPTION;
    WHY("jsid is NULL");
    return;                     /* No resources to clean. */
  }

  /* jbuf = mdppack.buf; */
  if ((jbuf =
       (jbyteArray) (*env)->GetObjectField(env, mdppack,
                                           f_meshpacket_buf)) == NULL) {
    THROW_NULL_POINTER_EXCEPTION;
    WHY("jbuf is NULL");
    return;                     /* No resources to clean. */
  };

  /* Convert arrays. */

  /* jlocalsid can be NULL: the user wants to use its own SID. */
  if (jlocalsid != NULL
      && (localsid =
          (jbyte *) (*env)->GetByteArrayElements(env, jlocalsid,
                                                 NULL)) == NULL) {
    THROW_OUT_OF_MEMORY_ERROR;
    WHY("Cannot create localsid");
    return;                     /* No resources to clean. */
  }

  if ((sid = (jbyte *) (*env)->GetByteArrayElements(env, jsid, NULL)) == NULL) {
    THROW_OUT_OF_MEMORY_ERROR;
    WHY("Cannot create sid");
    goto finally1;
  }

  if ((buf = (jbyte *) malloc(length * sizeof(jbyte))) == NULL) {
    THROW_OUT_OF_MEMORY_ERROR;
    WHY("Cannot create buf");
    goto finally2;
  }

  (*env)->GetByteArrayRegion(env, jbuf, offset, length, buf);
  if ((*env)->ExceptionCheck(env) == JNI_TRUE) {
    WHY("IndexOutOfBoundsException while filling buf");
    goto finally3;
  }

  /* Fill mdp structure. */

  mdp.packetTypeAndFlags = MDP_TX;
  mdp.out.src.port = localport;
  if (localsid != NULL) {
    memcpy(mdp.out.src.sid, localsid, SID_SIZE);
    /* else, src.sid is let to 0, so servald will automatically fill it with
       my sid. */
  }
  memcpy(mdp.out.dst.sid, sid, SID_SIZE);
  mdp.out.dst.port = port;
  mdp.out.payload_length = length;
  memcpy(mdp.out.payload, buf, length);

  /* Send data. */
  if (overlay_mdp_send(fd, &mdp, 0, 0)) {
    THROW_MESH_SOCKET_EXCEPTION("Cannot send data to servald");
    /* fall through finally */
  }

  /* Finally, release resources. */

finally3:
  free(buf);

finally2:
  (*env)->ReleaseByteArrayElements(env, jsid, sid, 0);

finally1:
  if (localsid != NULL) {
    (*env)->ReleaseByteArrayElements(env, jlocalsid, localsid, 0);
  }
}

JNIEXPORT void JNICALL
Java_org_servalproject_servald_mdp_MeshSocket__1receive(JNIEnv * env,
                                                        jobject this,
                                                        jobject mdppack)
{
  jint fd, localport, offset, length, port;
  int buf_length;
  jobject sid_obj;
  jbyteArray jbuf, jsid;
  jbyte *buf, *sid;
  overlay_mdp_frame mdp;

  /* fd = this.fd; */
  fd = (*env)->GetIntField(env, this, f_meshsocket_fd);

  /* localport = this.port; */
  localport = (*env)->GetIntField(env, this, f_meshsocket_port);

  /* length = mdppack.length; */
  length = (*env)->GetIntField(env, mdppack, f_meshpacket_length);

  /* Receive data. */
  if (overlay_mdp_recv(fd, &mdp, localport, -1)) {
    (*env)->ThrowNew(env, cl_meshsocketexception,
                     "Cannot receive data from servald");
    WHY("Cannot receive data from servald");
    return;
  }

  /* offset = mdppack.offset; */
  offset = (*env)->GetIntField(env, mdppack, f_meshpacket_offset);

  /* If payload is too big, it is truncated. */
  buf_length =
    length < mdp.in.payload_length ? length : mdp.in.payload_length;

  /* Write payload. */
  jbuf = (jbyteArray) (*env)->GetObjectField(env, mdppack, f_meshpacket_buf);
  (*env)->SetByteArrayRegion(env, jbuf, offset, buf_length, mdp.in.payload);

  /* Write payload length (received length, not truncated). */
  (*env)->SetIntField(env, mdppack, f_meshpacket_length,
                      mdp.in.payload_length);

  /* Write source sid. */
  jsid = (*env)->NewByteArray(env, SID_SIZE);
  sid = (*env)->GetByteArrayElements(env, jsid, NULL);
  memcpy(sid, mdp.in.src.sid, SID_SIZE);
  (*env)->ReleaseByteArrayElements(env, jsid, sid, 0);

  /* sid_obj = new SubscriberId(jsid); */
  sid_obj =
    (*env)->NewObject(env, cl_subscriberid, m_subscriberid_init, jsid);
  (*env)->SetObjectField(env, mdppack, f_meshpacket_sid, sid_obj);

  /* Write source port. */
  (*env)->SetIntField(env, mdppack, f_meshpacket_port, mdp.in.src.port);
}

JNIEXPORT void JNICALL
Java_org_servalproject_servald_mdp_MeshSocket__1close(JNIEnv * env,
                                                      jobject this)
{
  /* fd = this.fd; */
  jint fd = (*env)->GetIntField(env, this, f_meshsocket_fd);

  /* Close socket. */
  overlay_mdp_client_close(fd);
}
#endif
