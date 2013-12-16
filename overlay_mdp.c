/*
Serval DNA MDP overlay network
Copyright (C) 2012-2013 Serval Project Inc.
Copyright (C) 2010-2012 Paul Gardner-Stephen
 
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

/*
  Portions Copyright (C) 2013 Petter Reinholdtsen
  Some rights reserved

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
  FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
  COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.
*/

#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "serval.h"
#include "conf.h"
#include "str.h"
#include "strbuf.h"
#include "strbuf_helpers.h"
#include "overlay_buffer.h"
#include "overlay_address.h"
#include "overlay_packet.h"
#include "mdp_client.h"
#include "crypto.h"
#include "keyring.h"
#include "socket.h"

static void overlay_mdp_poll(struct sched_ent *alarm);
static void mdp_poll2(struct sched_ent *alarm);
static int overlay_mdp_releasebindings(struct socket_address *client);

static struct profile_total mdp_stats = { .name="overlay_mdp_poll" };
static struct sched_ent mdp_sock = {
  .function = overlay_mdp_poll,
  .stats = &mdp_stats,
  .poll={.fd = -1},
};

static struct profile_total mdp_stats2 = { .name="mdp_poll2" };
static struct sched_ent mdp_sock2 = {
  .function = mdp_poll2,
  .stats = &mdp_stats2,
  .poll={.fd = -1},
};

static int overlay_saw_mdp_frame(struct overlay_frame *frame, overlay_mdp_frame *mdp);
static int mdp_send2(struct socket_address *client, struct mdp_header *header, 
  const uint8_t *payload, size_t payload_len);

/* Delete all UNIX socket files in instance directory. */
static void overlay_mdp_clean_socket_files()
{
  const char *instance_path = serval_instancepath();
  DIR *dir;
  struct dirent *dp;
  if ((dir = opendir(instance_path)) == NULL) {
    WARNF_perror("opendir(%s)", alloca_str_toprint(instance_path));
    return;
  }
  while ((dp = readdir(dir)) != NULL) {
    char path[PATH_MAX];
    if (!FORM_SERVAL_INSTANCE_PATH(path, dp->d_name))
      continue;
    struct stat st;
    if (lstat(path, &st)) {
      WARNF_perror("stat(%s)", alloca_str_toprint(path));
      continue;
    }
    if (S_ISSOCK(st.st_mode))
      unlink(path);
  }
  closedir(dir);
}

static int mdp_bind_socket(const char *name)
{
  struct socket_address addr;
  int sock;
  
  if (make_local_sockaddr(&addr, "%s", name) == -1)
    return -1;
  if ((sock = esocket(addr.addr.sa_family, SOCK_DGRAM, 0)) == -1)
    return -1;
  if (socket_set_reuseaddr(sock, 1) == -1)
    WARN("Could not set socket to reuse addresses");
  if (socket_bind(sock, &addr.addr, addr.addrlen) == -1) {
    close(sock);
    return -1;
  }
  socket_set_rcvbufsize(sock, 64 * 1024);
  
  INFOF("Socket %s: fd=%d %s", name, sock, alloca_socket_address(&addr));
  return sock;
}

int overlay_mdp_setup_sockets()
{
  /* Delete stale socket files from instance directory. */
  overlay_mdp_clean_socket_files();

  if (mdp_sock.poll.fd == -1) {
    mdp_sock.poll.fd = mdp_bind_socket("mdp.socket");
    mdp_sock.poll.events = POLLIN;
    watch(&mdp_sock);
  }
  
  if (mdp_sock2.poll.fd == -1) {
    mdp_sock2.poll.fd = mdp_bind_socket("mdp.2.socket");
    mdp_sock2.poll.events = POLLIN;
    watch(&mdp_sock2);
  }
  return 0;
}

#define MDP_MAX_BINDINGS 100
#define MDP_MAX_SOCKET_NAME_LEN 110

struct mdp_binding{
  struct subscriber *subscriber;
  mdp_port_t port;
  int version;
  int (*internal)(const struct mdp_header *header, const uint8_t *payload, size_t len);
  struct socket_address client;
  time_ms_t binding_time;
};

struct mdp_binding mdp_bindings[MDP_MAX_BINDINGS];
int mdp_bindings_initialised=0;
mdp_port_t next_port_binding=256;

static int compare_client(struct socket_address *one, struct socket_address *two)
{
  if (one->addrlen==two->addrlen
    && memcmp(&one->addr, &two->addr, two->addrlen)==0)
    return 1;
  return 0;
}

static int overlay_mdp_reply(int sock, struct socket_address *client,
			  overlay_mdp_frame *mdpreply)
{
  if (!client) return WHY("No reply address");

  ssize_t replylen = overlay_mdp_relevant_bytes(mdpreply);
  if (replylen<0) return WHY("Invalid MDP frame (could not compute length)");

  ssize_t r=sendto(sock,(char *)mdpreply,replylen,0, &client->addr, client->addrlen);
  if (r == -1){
    WHYF_perror("sendto(fd=%d,len=%zu,addr=%s)", sock, (size_t)replylen, alloca_socket_address(client));
    if (errno == ENOENT){
      /* far-end of socket has died, so drop binding */
      INFOF("Closing dead MDP client '%s'", alloca_socket_address(client));
      overlay_mdp_releasebindings(client);
    }
    return -1;
  }
  if (r != replylen)
    return WHYF("sendto() sent %zu bytes of MDP reply (%zu) to %s", (size_t)r, (size_t)replylen, alloca_socket_address(client));
  return 0;  
}

static int overlay_mdp_reply_error(int sock, struct socket_address *client,
			    int error_number, char *message)
{
  overlay_mdp_frame mdpreply;

  mdpreply.packetTypeAndFlags=MDP_ERROR;
  mdpreply.error.error=error_number;
  if (error_number)
    WHYF("MDP error, code #%d %s",error_number, message);
  
  if (error_number==0||message)
    snprintf(&mdpreply.error.message[0],128,"%s",message?message:"Success");
  else{
    snprintf(&mdpreply.error.message[0],128,"Error code #%d",error_number);
  }
  mdpreply.error.message[127]=0;

  return overlay_mdp_reply(sock, client, &mdpreply);
}

static int overlay_mdp_reply_ok(int sock, struct socket_address *client, 
			 char *message)
{
  return overlay_mdp_reply_error(sock, client, 0, message);
}

static int overlay_mdp_releasebindings(struct socket_address *client)
{
  /* Free up any MDP bindings held by this client. */
  int i;
  for(i=0;i<MDP_MAX_BINDINGS;i++)
    if (compare_client(&mdp_bindings[i].client, client))
      mdp_bindings[i].port=0;

  return 0;

}

static int overlay_mdp_process_bind_request(struct subscriber *subscriber, mdp_port_t port,
				     int flags, struct socket_address *client)
{
  if (config.debug.mdprequests) 
    DEBUGF("Bind request %s:%"PRImdp_port_t, subscriber ? alloca_tohex_sid_t(subscriber->sid) : "NULL", port);
  
  if (port == 0){
    return WHYF("Port %d cannot be bound", port);
  }
  if (!mdp_bindings_initialised) {
    /* Mark all slots as unused */
    int i;
    for(i=0;i<MDP_MAX_BINDINGS;i++)
      mdp_bindings[i].port=0;
    mdp_bindings_initialised=1;
  }

  /* See if binding already exists */
  int free=-1;
  {
    int i;
    for(i=0;i<MDP_MAX_BINDINGS;i++) {
      /* Look for duplicate bindings */
      if (mdp_bindings[i].port == port && mdp_bindings[i].subscriber == subscriber) {
	if (compare_client(&mdp_bindings[i].client, client)) {
	  // this client already owns this port binding?
	  INFO("Identical binding exists");
	  return 0;
	}else if(flags&MDP_FORCE){
	  // steal the port binding
	  free=i;
	  break;
	}else{
	  return WHY("Port already in use");
	}
      }
      /* Look for free slots in case we need one */
      if ((free==-1)&&(mdp_bindings[i].port==0)) free=i;
    }
  }
 
  /* Okay, so no binding exists.  Make one, and return success.
     If we have too many bindings, we should return an error.
     XXX - We don't find out when the socket responsible for a binding has died,
     so stale bindings can hang around.  We really need a solution to this, e.g., 
     probing the sockets periodically (by sending an MDP NOOP frame perhaps?) and
     destroying any socket that reports an error.
  */
  if (free==-1) {
    /* XXX Should we probe for stale bindings here and now, since this is when
       we want the spare slots ?

       Picking one at random is as good a policy as any.
       Call listeners don't have a port binding, so are unaffected by this.
    */
    free=random()%MDP_MAX_BINDINGS;
  }
  /* Okay, record binding and report success */
  mdp_bindings[free].port=port;
  mdp_bindings[free].subscriber=subscriber;
  mdp_bindings[free].version=0;
  mdp_bindings[free].client.addrlen = client->addrlen;
  memcpy(&mdp_bindings[free].client.addr, &client->addr, client->addrlen);
  mdp_bindings[free].binding_time=gettime_ms();
  return 0;
}

int mdp_bind_internal(struct subscriber *subscriber, mdp_port_t port,
  int (*internal)(const struct mdp_header *header, const uint8_t *payload, size_t len))
{
  
  int i;
  struct mdp_binding *free_slot=NULL;
  
  for(i=0;i<MDP_MAX_BINDINGS;i++) {
    if ((!free_slot) && mdp_bindings[i].port==0)
      free_slot=&mdp_bindings[i];
    
    if (mdp_bindings[i].port == port 
      && mdp_bindings[i].subscriber == subscriber)
      return -1;
  }
  
  if (!free_slot)
    return -1;
    
  free_slot->subscriber=subscriber;
  free_slot->port=port;
  free_slot->version=1;
  free_slot->internal=internal;
  free_slot->binding_time=gettime_ms();
  return 0;
}

int mdp_unbind_internal(struct subscriber *subscriber, mdp_port_t port,
  int (*internal)(const struct mdp_header *header, const uint8_t *payload, size_t len))
{
  int i;
  for(i=0;i<MDP_MAX_BINDINGS;i++) {
    if (mdp_bindings[i].port == port
      && mdp_bindings[i].subscriber == subscriber
      && mdp_bindings[i].internal == internal){
      mdp_bindings[i].port=0;
      mdp_bindings[i].subscriber=NULL;
      mdp_bindings[i].internal=NULL;
    }
  }
  return 0;
}

static int overlay_mdp_decode_header(struct overlay_buffer *buff, overlay_mdp_frame *mdp)
{
  /* extract MDP port numbers */
  mdp_port_t port = ob_get_packed_ui32(buff);
  int same = port&1;
  port >>=1;
  mdp->in.dst.port = port;
  if (!same)
    port = ob_get_packed_ui32(buff);
  mdp->in.src.port = port;
  int len = ob_remaining(buff);
  if (len<0)
    return WHY("MDP payload is too short");
  mdp->in.payload_length=len;
  return ob_get_bytes(buff, &mdp->in.payload[0], len);
}

int overlay_mdp_decrypt(struct overlay_frame *f, overlay_mdp_frame *mdp)
{
  IN();

  /* Indicate MDP message type */
  mdp->packetTypeAndFlags=MDP_TX;
  switch(f->modifiers&(OF_CRYPTO_CIPHERED|OF_CRYPTO_SIGNED))  {
  case 0: 
    /* nothing to do, b already points to the plain text */
    mdp->packetTypeAndFlags|=MDP_NOCRYPT|MDP_NOSIGN;
    RETURN(overlay_mdp_decode_header(f->payload, mdp));
      
  case OF_CRYPTO_CIPHERED:
    RETURN(WHY("decryption not implemented"));
      
  case OF_CRYPTO_SIGNED:
    {
      int len = ob_remaining(f->payload);
      if (crypto_verify_message(f->source, ob_ptr(f->payload), &len))
	RETURN(-1);
      
      mdp->packetTypeAndFlags|=MDP_NOCRYPT; 
      ob_limitsize(f->payload, len + ob_position(f->payload));
      RETURN(overlay_mdp_decode_header(f->payload, mdp));
    }
      
  case OF_CRYPTO_CIPHERED|OF_CRYPTO_SIGNED:
    {
      if (0) DEBUGF("crypted MDP frame for %s", alloca_tohex_sid_t(f->destination->sid));

      int nm=crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES;
      int nb=crypto_box_curve25519xsalsa20poly1305_NONCEBYTES;
      int zb=crypto_box_curve25519xsalsa20poly1305_ZEROBYTES;
      int cz=crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES;
      
      unsigned char *k=keyring_get_nm_bytes(&f->destination->sid, &f->source->sid);
      if (!k) 
	RETURN(WHY("I don't have the private key required to decrypt that"));
      
      if (0)
	dump("frame",&f->payload->bytes[f->payload->position], ob_remaining(f->payload));
      
      unsigned char *nonce=ob_get_bytes_ptr(f->payload, nb);
      if (!nonce)
	RETURN(WHYF("Expected %d bytes of nonce", nb));
      
      int cipher_len=ob_remaining(f->payload);
      unsigned char *cipher_text=ob_get_bytes_ptr(f->payload, cipher_len);
      if (!cipher_text)
	RETURN(WHYF("Expected %d bytes of cipher text", cipher_len));
      
      unsigned char plain_block[cipher_len+cz];
      
      bzero(&plain_block[0],cz);
      
      bcopy(cipher_text,&plain_block[cz],cipher_len);
      
      if (0) {
	dump("nm bytes",k,nm);
	dump("nonce",nonce,nb);
	dump("cipher block",plain_block,sizeof(plain_block)); 
      }
      cipher_len+=cz;
      
      if (crypto_box_curve25519xsalsa20poly1305_open_afternm
	  (plain_block,plain_block,cipher_len,nonce,k)) {
	RETURN(WHYF("crypto_box_open_afternm() failed (from %s, to %s, len %d)",
		    alloca_tohex_sid_t(f->source->sid), alloca_tohex_sid_t(f->destination->sid), cipher_len));
      }
      
      if (0) dump("plain block",plain_block,sizeof(plain_block));
      
      cipher_len -= zb;
      struct overlay_buffer *plaintext = ob_static(&plain_block[zb], cipher_len);
      ob_limitsize(plaintext,cipher_len);
      int ret=overlay_mdp_decode_header(plaintext, mdp);
      ob_free(plaintext);
      RETURN(ret);
    }    
  }
  RETURN(WHY("Failed to decode mdp payload"));
  OUT();
}

int overlay_saw_mdp_containing_frame(struct overlay_frame *f)
{
  IN();
  /* Take frame source and destination and use them to populate mdp->in->{src,dst}
     SIDs.
     Take ports from mdp frame itself.
     Take payload from mdp frame itself.
  */
  overlay_mdp_frame mdp;
  bzero(&mdp, sizeof(overlay_mdp_frame));
  
  mdp.in.queue = f->queue;
  mdp.in.ttl = f->ttl;
  
  /* Get source and destination addresses */
  mdp.in.dst.sid = (f->destination) ? f->destination->sid : SID_BROADCAST;
  mdp.in.src.sid = f->source->sid;

  /* copy crypto flags from frame so that we know if we need to decrypt or verify it */
  if (overlay_mdp_decrypt(f,&mdp))
    RETURN(-1);

  /* and do something with it! */
  RETURN(overlay_saw_mdp_frame(f, &mdp));
  OUT();
}

int overlay_mdp_swap_src_dst(overlay_mdp_frame *mdp)
{
  sockaddr_mdp temp;
  bcopy(&mdp->out.dst,&temp,sizeof(sockaddr_mdp));
  bcopy(&mdp->out.src,&mdp->out.dst,sizeof(sockaddr_mdp));
  bcopy(&temp,&mdp->out.src,sizeof(sockaddr_mdp));
  return 0;
}

static int overlay_saw_mdp_frame(struct overlay_frame *frame, overlay_mdp_frame *mdp)
{
  IN();
  int i;
  int match=-1;

  /* Regular MDP frame addressed to us.  Look for matching port binding,
     and if available, push to client.  Else do nothing, or if we feel nice
     send back a connection refused type message? Silence is probably the
     more prudent path.
  */

  if (config.debug.mdprequests) 
    DEBUGF("Received packet with listener (MDP ports: src=%s*:%"PRImdp_port_t", dst=%"PRImdp_port_t")",
	 alloca_tohex_sid_t_trunc(mdp->out.src.sid, 14),
	 mdp->out.src.port, mdp->out.dst.port);

  // TODO pass in dest subscriber as an argument, we should know it by now
  struct subscriber *destination = NULL;
  if (frame)
    destination = frame->destination;
  else if (!is_sid_t_broadcast(mdp->out.dst.sid)){
    destination = find_subscriber(mdp->out.dst.sid.binary, SID_SIZE, 1);
  }
  
  for(i=0;i<MDP_MAX_BINDINGS;i++)
    {
      if (mdp_bindings[i].port!=mdp->out.dst.port)
	continue;
      
      if ((!destination) || mdp_bindings[i].subscriber == destination){
	/* exact match, so stop searching */
	match=i;
	break;
      }else if (!mdp_bindings[i].subscriber){
	/* If we find an "ANY" binding, remember it. But we will prefer an exact match if we find one */
	match=i;
      }
    }
  
  if (match>-1) {
    switch(mdp_bindings[match].version){
      case 0:
	{
	  ssize_t len = overlay_mdp_relevant_bytes(mdp);
	  if (len < 0)
	    RETURN(WHY("unsupported MDP packet type"));
	  struct socket_address *client = &mdp_bindings[match].client;
	  ssize_t r = sendto(mdp_sock.poll.fd,mdp,len,0, &client->addr, client->addrlen);
	  if (r == -1){
	    WHYF_perror("sendto(fd=%d,len=%zu,addr=%s)", mdp_sock.poll.fd, (size_t)len, alloca_socket_address(client));
	    if (errno == ENOENT){
	      /* far-end of socket has died, so drop binding */
	      INFOF("Closing dead MDP client '%s'", alloca_socket_address(client));
	      overlay_mdp_releasebindings(client);
	    }
	    RETURN(-1);
	  }
	  if (r != len)
	    RETURN(WHYF("sendto() sent %zu bytes of MDP reply (%zu) to %s", (size_t)r, (size_t)len, alloca_socket_address(client)));
	  RETURN(0);
	}
      case 1:
	{
	  struct mdp_header header;
	  header.local.sid=mdp->out.dst.sid;
	  header.local.port=mdp->out.dst.port;
	  header.remote.sid=mdp->out.src.sid;
	  header.remote.port=mdp->out.src.port;
	  header.qos=mdp->out.queue;
	  header.ttl=mdp->out.ttl;
	  header.flags=0;
	  if (mdp->packetTypeAndFlags & MDP_NOCRYPT)
	    header.flags|=MDP_FLAG_NO_CRYPT;
	  if (mdp->packetTypeAndFlags & MDP_NOSIGN)
	    header.flags|=MDP_FLAG_NO_SIGN;
	    
	  if (mdp_bindings[match].internal)
	    RETURN(mdp_bindings[match].internal(&header, mdp->out.payload, mdp->out.payload_length));
	    
	  RETURN(mdp_send2(&mdp_bindings[match].client, &header, mdp->out.payload, mdp->out.payload_length));
	}
    }
  } else {
    /* No socket is bound, ignore the packet ... except for magic sockets */
    RETURN(overlay_mdp_try_internal_services(frame, mdp));
  }

  RETURN(0);
  OUT();
}

int overlay_mdp_dnalookup_reply(const sockaddr_mdp *dstaddr, const sid_t *resolved_sidp, const char *uri, const char *did, const char *name)
{
  if (config.debug.mdprequests)
    DEBUGF("MDP_PORT_DNALOOKUP resolved_sid=%s uri=%s did=%s name=%s",
	  alloca_tohex_sid_t(*resolved_sidp),
	  alloca_str_toprint(uri),
	  alloca_str_toprint(did),
	  alloca_str_toprint(name)
	);
  overlay_mdp_frame mdpreply;
  bzero(&mdpreply, sizeof mdpreply);
  mdpreply.packetTypeAndFlags = MDP_TX; // outgoing MDP message
  mdpreply.out.queue=OQ_ORDINARY;
  mdpreply.out.src.sid = *resolved_sidp;
  mdpreply.out.src.port = MDP_PORT_DNALOOKUP;
  bcopy(dstaddr, &mdpreply.out.dst, sizeof(sockaddr_mdp));
  /* build reply as TOKEN|URI|DID|NAME|<NUL> */
  strbuf b = strbuf_local((char *)mdpreply.out.payload, sizeof mdpreply.out.payload);
  strbuf_tohex(b, SID_STRLEN, resolved_sidp->binary);
  strbuf_sprintf(b, "|%s|%s|%s|", uri, did, name?name:"");
  if (strbuf_overrun(b))
    return WHY("MDP payload overrun");
  mdpreply.out.payload_length = strbuf_len(b) + 1;
  /* deliver reply */
  return overlay_mdp_dispatch(&mdpreply, NULL);
}

static int overlay_mdp_check_binding(struct subscriber *subscriber, mdp_port_t port,
			      struct socket_address *client)
{
  /* System generated frames can send anything they want */
  if (!client)
    return 0;

  /* Check if the address is in the list of bound addresses,
     and that the recvaddr matches. */
  
  int i;
  for(i = 0; i < MDP_MAX_BINDINGS; ++i) {
    if (mdp_bindings[i].port != port)
      continue;
    if ((!mdp_bindings[i].subscriber) || mdp_bindings[i].subscriber == subscriber) {
      /* Binding matches, now make sure the sockets match */
      if (compare_client(&mdp_bindings[i].client, client)) {
	/* Everything matches, so this unix socket and MDP address combination is valid */
	return 0;
      }
    }
  }

  return WHYF("No matching binding: addr=%s port=%"PRImdp_port_t" -- possible spoofing attack",
	alloca_tohex_sid_t(subscriber->sid),
	port
      );
}

void overlay_mdp_encode_ports(struct overlay_buffer *plaintext, mdp_port_t dst_port, mdp_port_t src_port)
{
  mdp_port_t port = dst_port << 1;
  if (dst_port == src_port)
    port |= 1;
  ob_append_packed_ui32(plaintext, port);
  if (dst_port != src_port)
    ob_append_packed_ui32(plaintext, src_port);
}

static struct overlay_buffer * encrypt_payload(
  struct subscriber *source, 
  struct subscriber *dest, 
  const unsigned char *buffer,
  int cipher_len)
{
  int zb=crypto_box_curve25519xsalsa20poly1305_ZEROBYTES;
  int nb=crypto_box_curve25519xsalsa20poly1305_NONCEBYTES;
  int cz=crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES;
  
  // generate plain message with leading zero bytes and get ready to cipher it
  // TODO, add support for leading zero's in overlay_buffer's, so we don't need to copy the plain text
  unsigned char plain[zb+cipher_len];
  
  /* zero bytes */
  bzero(&plain[0],zb);
  bcopy(buffer,&plain[zb],cipher_len);
  
  cipher_len+=zb;
  
  struct overlay_buffer *ret = ob_new();
  if (ret == NULL)
    return NULL;
  
  unsigned char *nonce = ob_append_space(ret, nb+cipher_len);
  if (!nonce){
    ob_free(ret);
    return NULL;
  }
  unsigned char *cipher_text = nonce + nb;

  if (generate_nonce(nonce,nb)){
    ob_free(ret);
    WHY("generate_nonce() failed to generate nonce");
    return NULL;
  }
  
  // reserve the high bit of the nonce as a flag for transmitting a shorter nonce.
  nonce[0]&=0x7f;
  
  /* get pre-computed PKxSK bytes (the slow part of auth-cryption that can be
     retained and reused, and use that to do the encryption quickly. */
  unsigned char *k=keyring_get_nm_bytes(&source->sid, &dest->sid);
  if (!k) {
    ob_free(ret);
    WHY("could not compute Curve25519(NxM)");
    return NULL;
  }
  
  /* Actually authcrypt the payload */
  if (crypto_box_curve25519xsalsa20poly1305_afternm(cipher_text, plain,cipher_len, nonce, k)) {
    ob_free(ret);
    WHY("crypto_box_afternm() failed");
    return NULL;
  }
  
#if 0
  if (config.debug.crypto) {
    DEBUG("authcrypted mdp frame");
    dump("nm",k,crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES);
    dump("plain text",plain,sizeof(plain));
    dump("nonce",nonce,nb);
    dump("cipher text",cipher_text,cipher_len);
  }
#endif
  
  /* now shuffle down to get rid of the temporary space that crypto_box uses. 
   TODO extend overlay buffer so we don't need this.
   */
  bcopy(&cipher_text[cz],&cipher_text[0],cipher_len-cz);
  ret->position-=cz;
#if 0
  if (config.debug.crypto)
    dump("frame", &ret->bytes[0], ret->position);
#endif
  
  return ret;
}

// encrypt or sign the plaintext, then queue the frame for transmission.
static int overlay_send_frame(
  struct subscriber *source, mdp_port_t src_port,
  struct subscriber *destination, mdp_port_t dst_port,
  const uint8_t *payload, size_t payload_len,
  uint8_t ttl, uint8_t qos, uint8_t modifiers)
{
  if (destination && destination->reachable == REACHABLE_SELF)
    return 0;
  
  if (ttl == 0) 
    ttl = PAYLOAD_TTL_DEFAULT;
  else if (ttl > PAYLOAD_TTL_MAX)
    return WHYF("Invalid TTL");
  
  if (qos == 0)
    qos = OQ_ORDINARY;
    
  if (!source)
    return WHYF("No source specified");
  
  /* Prepare the overlay frame for dispatch */
  struct overlay_frame *frame = emalloc_zero(sizeof(struct overlay_frame));
  if (!frame)
    return -1;
  
  frame->source = source;
  frame->destination = destination;
  frame->ttl = ttl;
  frame->queue = qos;
  frame->type = OF_TYPE_DATA;
  frame->modifiers = modifiers;
  
  // copy the plain text message into a new buffer, with the wire encoded port numbers
  struct overlay_buffer *plaintext=ob_new();
  if (!plaintext){
    op_free(frame);
    return -1;
  }
  
  overlay_mdp_encode_ports(plaintext, dst_port, src_port);
  if (payload && payload_len){
    ob_append_bytes(plaintext, payload, payload_len);
  }
  
  if (ob_overrun(plaintext)) {
    if (config.debug.mdprequests) 
      DEBUGF("Frame overrun: position=%zu allocSize=%zu sizeLimit=%zu",
	  plaintext->position, plaintext->allocSize, plaintext->sizeLimit);
    op_free(frame);
    ob_free(plaintext);
    return -1;
  }
  if (config.debug.mdprequests) {
    DEBUGF("Send frame %zu bytes", ob_position(plaintext));
    dump("Frame plaintext", ob_ptr(plaintext), ob_position(plaintext));
  }
  
  /* Work out the disposition of the frame->  For now we are only worried
     about the crypto matters, and not compression that may be applied
     before encryption (since applying it after is useless as ciphered
     text should have maximum entropy). */
  switch(modifiers) {
  case OF_CRYPTO_SIGNED|OF_CRYPTO_CIPHERED:
    if (!frame->destination){
      ob_free(plaintext);
      op_free(frame);
      return WHY("Cannot encrypt to broadcast destinations");
    }
  
    /* crypted and signed (using CryptoBox authcryption primitive) */
    frame->payload = encrypt_payload(frame->source, frame->destination, ob_ptr(plaintext), ob_position(plaintext));
    if (!frame->payload){
      ob_free(plaintext);
      op_free(frame);
      return -1;
    }
#if 0
    if (config.debug.crypto)
      dump("Frame signed ciphertext", ob_ptr(frame->payload), ob_position(frame->payload));
#endif
    break;
      
  case OF_CRYPTO_SIGNED:
    // Lets just append some space into the existing payload buffer for the signature, without copying it.
    frame->payload = plaintext;
    if (   !ob_makespace(frame->payload, SIGNATURE_BYTES)
        || crypto_sign_message(frame->source, ob_ptr(frame->payload), frame->payload->allocSize, &frame->payload->position) == -1
    ) {
      op_free(frame);
      return -1;
    }
#if 0
    if (config.debug.crypto)
      dump("Frame signed plaintext", ob_ptr(frame->payload), ob_position(frame->payload));
#endif
    break;
      
  case 0:
    /* clear text and no signature */
    frame->payload = plaintext;
    break;
    
  default:
    ob_free(plaintext);
    op_free(frame);
    return WHY("Invalid encrypt / sign combination");
  }
  
  if (!frame->destination && frame->ttl>1)
    overlay_broadcast_generate_address(&frame->broadcast_id);
  
  if (overlay_payload_enqueue(frame)){
    op_free(frame);
    return -1;
  }
  
  return 0;
}

/* Construct MDP packet frame from overlay_mdp_frame structure
   (need to add return address from bindings list, and copy
   payload etc).
   This is for use by the SERVER. 
   Clients should use overlay_mdp_send()
 */
int overlay_mdp_dispatch(overlay_mdp_frame *mdp, struct socket_address *client)
{
  IN();
  unsigned __d = 0;
  if (config.debug.mdprequests) {
    __d = fd_depth();
    DEBUGF("[%u] src=%s*:%"PRImdp_port_t", dst=%s*:%"PRImdp_port_t", recv=%s",
	   __d,
	   alloca_tohex_sid_t_trunc(mdp->out.src.sid, 14), mdp->out.src.port,
	   alloca_tohex_sid_t_trunc(mdp->out.dst.sid, 14), mdp->out.dst.port,
	   client ? alloca_socket_address(client) : "NULL"
	);
  }

  if (mdp->out.payload_length > sizeof(mdp->out.payload))
    FATAL("Payload length is past the end of the buffer");

  struct subscriber *source=NULL;
  struct subscriber *destination=NULL;
  
  if (is_sid_t_any(mdp->out.src.sid)){
    /* set source to ourselves */
    source = my_subscriber;
    mdp->out.src.sid = source->sid;
  }else if (is_sid_t_broadcast(mdp->out.src.sid)){
    /* Nope, I'm sorry but we simply can't send packets from 
     * broadcast addresses. */
    RETURN(WHY("Packet had broadcast address as source address"));
  }else{
    // assume all local identities have already been unlocked and marked as SELF.
    source = find_subscriber(mdp->out.src.sid.binary, SID_SIZE, 0);
    if (!source){
      RETURN(WHYF("Possible spoofing attempt, tried to send a packet from %s, which is an unknown SID", alloca_tohex_sid_t(mdp->out.src.sid)));
    }
    if (source->reachable!=REACHABLE_SELF){
      RETURN(WHYF("Possible spoofing attempt, tried to send a packet from %s", alloca_tohex_sid_t(mdp->out.src.sid)));
    }
  }
  
  if (overlay_mdp_check_binding(source, mdp->out.src.port, client)){
    RETURN(overlay_mdp_reply_error
	   (mdp_sock.poll.fd,
	    client,8,
	    "Source address is invalid (you must bind to a source address before"
	    " you can send packets"));
  }
  
  /* Work out if destination is broadcast or not */
  if (is_sid_t_broadcast(mdp->out.dst.sid)){
    if (config.debug.mdprequests) 
      DEBUGF("[%u] Broadcast packet", __d);
    /* broadcast packets cannot be encrypted, so complain if MDP_NOCRYPT
     flag is not set. Also, MDP_NOSIGN must also be applied, until
     NaCl cryptobox keys can be used for signing. */	
    if (!(mdp->packetTypeAndFlags&MDP_NOCRYPT))
      RETURN(overlay_mdp_reply_error(mdp_sock.poll.fd,
				     client,5,
				     "Broadcast packets cannot be encrypted "));
  }else{
    destination = find_subscriber(mdp->out.dst.sid.binary, SID_SIZE, 1);
    // should we reply with an error if the destination is not currently routable?
  }
  
  if (mdp->out.ttl > PAYLOAD_TTL_MAX) {
    RETURN(overlay_mdp_reply_error(mdp_sock.poll.fd, client, 9, "TTL out of range"));
  }
  
  if (config.debug.mdprequests) 
    DEBUGF("[%u] destination->sid=%s", __d, destination ? alloca_tohex_sid_t(destination->sid) : "NULL");
  if (!destination || destination->reachable == REACHABLE_SELF){
    /* Packet is addressed to us / broadcast, we should process it first. */
    overlay_saw_mdp_frame(NULL,mdp);
    if (destination) {
      /* Is local, and is not broadcast, so shouldn't get sent out on the wire. */
      if (config.debug.mdprequests) 
	DEBUGF("[%u] Local packet, not transmitting", __d);
      RETURN(0);
    }
  }

  int modifiers=0;
  
  switch(mdp->packetTypeAndFlags&(MDP_NOCRYPT|MDP_NOSIGN)) {
  case 0:
    // default to encrypted and authenticated
    modifiers=OF_CRYPTO_SIGNED|OF_CRYPTO_CIPHERED;
    break;
  case MDP_NOCRYPT: 
    // sign it, but don't encrypt it.
    modifiers=OF_CRYPTO_SIGNED;
    break;
  case MDP_NOSIGN|MDP_NOCRYPT:
    // just send the payload unmodified
    modifiers=0; 
    break;
  case MDP_NOSIGN: 
    /* ciphered, but not signed.
     This means we don't use CryptoBox, but rather a more compact means
     of representing the ciphered stream segment.
     */
     // fall through
  default:
    RETURN(WHY("Not implemented"));
  };
  
  RETURN(overlay_send_frame(
    source, mdp->out.src.port,
    destination, mdp->out.dst.port, 
    mdp->out.payload, mdp->out.payload_length,
    mdp->out.ttl, mdp->out.queue, modifiers
  ));
  OUT();
}

static int search_subscribers(struct subscriber *subscriber, void *context){
  overlay_mdp_addrlist *response = context;
  
  if (response->mode == MDP_ADDRLIST_MODE_SELF && subscriber->reachable != REACHABLE_SELF){
    return 0;
  }
  
  if (response->mode == MDP_ADDRLIST_MODE_ROUTABLE_PEERS && 
      (!(subscriber->reachable &REACHABLE))){
    return 0;
  }
    
  if (response->mode == MDP_ADDRLIST_MODE_ALL_PEERS &&
      subscriber->reachable == REACHABLE_SELF){
    return 0;
  }
  
  if (response->server_sid_count++ >= response->first_sid && 
      response->frame_sid_count < MDP_MAX_SID_REQUEST)
    response->sids[response->frame_sid_count++] = subscriber->sid;
  
  return 0;
}

int overlay_mdp_address_list(overlay_mdp_addrlist *request, overlay_mdp_addrlist *response)
{
  if (config.debug.mdprequests)
    DEBUGF("MDP_GETADDRS first_sid=%u mode=%d", request->first_sid, request->mode);
  
  /* Prepare reply packet */
  response->mode = request->mode;
  response->first_sid = request->first_sid;
  response->frame_sid_count = 0;
  
  /* Populate with SIDs */
  enum_subscribers(NULL, search_subscribers, response);
  
  response->last_sid = response->first_sid + response->frame_sid_count - 1;
  
  if (config.debug.mdprequests)
    DEBUGF("reply MDP_ADDRLIST first_sid=%u last_sid=%u frame_sid_count=%u server_sid_count=%u",
	   response->first_sid,
	   response->last_sid,
	   response->frame_sid_count,
	   response->server_sid_count
	   );
  return 0;
}

struct routing_state{
  struct socket_address *client;
  int fd;
};

static int routing_table(struct subscriber *subscriber, void *context)
{
  struct routing_state *state = (struct routing_state *)context;
  overlay_mdp_frame reply;
  bzero(&reply, sizeof(overlay_mdp_frame));
  
  struct overlay_route_record *r=(struct overlay_route_record *)&reply.out.payload;
  reply.packetTypeAndFlags=MDP_TX;
  reply.out.payload_length=sizeof(struct overlay_route_record);
  r->sid = subscriber->sid;
  r->reachable = subscriber->reachable;
  
  if (subscriber->reachable==REACHABLE_INDIRECT && subscriber->next_hop)
    r->neighbour = subscriber->next_hop->sid;
  if (subscriber->reachable & REACHABLE_DIRECT 
    && subscriber->destination 
    && subscriber->destination->interface)
    strcpy(r->interface_name, subscriber->destination->interface->name);
  else
    r->interface_name[0]=0;
  overlay_mdp_reply(mdp_sock.poll.fd, state->client, &reply);
  return 0;
}

struct scan_state{
  struct sched_ent alarm;
  overlay_interface *interface;
  uint32_t current;
  uint32_t last;
};
struct scan_state scans[OVERLAY_MAX_INTERFACES];

static void overlay_mdp_scan(struct sched_ent *alarm)
{
  struct sockaddr_in addr={
    .sin_family=AF_INET,
    .sin_port=htons(PORT_DNA),
    .sin_addr={0},
  };
  struct scan_state *state = (struct scan_state *)alarm;
  uint32_t stop = state->last;
  if (stop - state->current > 25)
    stop = state->current+25;
  
  while(state->current <= stop){
    addr.sin_addr.s_addr=htonl(state->current);
    if (addr.sin_addr.s_addr != state->interface->address.sin_addr.s_addr){
      struct network_destination *destination = create_unicast_destination(addr, state->interface);
      if (!destination)
	break;
      int ret = overlay_send_probe(NULL, destination, OQ_ORDINARY);
      release_destination_ref(destination);
      if (ret)
	break;
    }
    state->current++;
  }
  
  if (state->current <= state->last){
    alarm->alarm=gettime_ms()+500;
    schedule(alarm);
  }else{
    DEBUG("Scan completed");
    state->interface=NULL;
    state->current=0;
    state->last=0;
  }
}

static int mdp_reply2(const struct socket_address *client, const struct mdp_header *header, 
  int flags, const unsigned char *payload, int payload_len)
{
  struct mdp_header response_header;
  bcopy(header, &response_header, sizeof(response_header));
  response_header.flags = flags;
  
  struct iovec iov[]={
    {
      .iov_base = (void *)&response_header,
      .iov_len = sizeof(struct mdp_header)
    },
    {
      .iov_base = (void *)payload,
      .iov_len = payload_len
    }
  };
  
  struct msghdr hdr={
    .msg_name=(void *)&client->addr,
    .msg_namelen=client->addrlen,
    .msg_iov=iov,
    .msg_iovlen=2,
  };
  
  if (config.debug.mdprequests)
    DEBUGF("Replying to %s with flags %d", alloca_socket_address(client), flags);
  return sendmsg(mdp_sock2.poll.fd, &hdr, 0);
}

#define mdp_reply_error(A,B)  mdp_reply2(A,B,MDP_FLAG_ERROR,NULL,0)
#define mdp_reply_ok(A,B)  mdp_reply2(A,B,MDP_FLAG_CLOSE,NULL,0)

static int mdp_process_identity_request(struct socket_address *client, struct mdp_header *header, 
  const uint8_t *payload, size_t payload_len)
{
  if (payload_len<sizeof(struct mdp_identity_request)){
    mdp_reply_error(client, header);
    return WHY("Request too small");
  }
  struct mdp_identity_request *request = (struct mdp_identity_request *)payload;
  payload += sizeof(struct mdp_identity_request);
  payload_len -= sizeof(struct mdp_identity_request);
  
  switch(request->action){
    case ACTION_LOCK:
      switch (request->type){
	case TYPE_PIN:
	  {
	    const char *pin = (char *)payload;
	    size_t ofs=0;
	    while(ofs < payload_len){
	      if (!payload[ofs++]){
		unsigned cn;
		for (cn = keyring->context_count; cn > 0;) {
		  keyring_context *cx = keyring->contexts[--cn];
		  unsigned in;
		  for (in = cx->identity_count; in > 0;) {
		    keyring_identity *id = cx->identities[--in];
		    if (id->subscriber != my_subscriber && strcmp(id->PKRPin, pin) == 0)
		      keyring_release_identity(keyring, cn, in);
		  }
		}
		pin=(char *)&payload[ofs++];
	      }
	    }
	  }
	  break;
	case TYPE_SID:
	  while(payload_len>=SID_SIZE){
	    keyring_release_subscriber(keyring, (const sid_t*)payload);
	    payload+=SID_SIZE;
	    payload_len-=SID_SIZE;
	  }
	  break;
	default:
	  mdp_reply_error(client, header);
	  return WHY("Unknown request type");
      }
      break;
    case ACTION_UNLOCK:
      {
	if (request->type!=TYPE_PIN){
	  mdp_reply_error(client, header);
	  return WHY("Unknown request type");
	}
	int unlock_count=0;
	const char *pin = (char *)payload;
	size_t ofs=0;
	while(ofs < payload_len){
	  if (!payload[ofs++]){
	    unlock_count += keyring_enter_pin(keyring, pin);
	    pin=(char *)&payload[ofs++];
	  }
	}
      }
      break;
    default:
      mdp_reply_error(client, header);
      return WHY("Unknown request action");
  }
  mdp_reply_ok(client, header);
  return 0;
}

// return one response per matching identity
static int mdp_search_identities(struct socket_address *client, struct mdp_header *header, 
  const uint8_t *payload, size_t payload_len)
{
  unsigned cn=0, in=0, kp=0;
  const char *tag=NULL;
  const unsigned char *value=NULL;
  size_t value_len=0;
  
  if (payload_len){
    if (keyring_unpack_tag(payload, payload_len, &tag, &value, &value_len)){
      mdp_reply_error(client, header);
      return -1;
    }
  }
  
  while(1){
    if (value_len){
      if (config.debug.mdprequests)
	DEBUGF("Looking for next %s tag & value", tag);
      if (!keyring_find_public_tag_value(keyring, &cn, &in, &kp, tag, value, value_len))
	break;
    }else if(tag){
      if (config.debug.mdprequests)
	DEBUGF("Looking for next %s tag", tag);
      if (!keyring_find_public_tag(keyring, &cn, &in, &kp, tag, NULL, NULL))
	break;
    }else{
      if (config.debug.mdprequests)
	DEBUGF("Looking for next identity");
      if (!keyring_next_identity(keyring, &cn, &in, &kp))
	break;
    }
    keyring_identity *id = keyring->contexts[cn]->identities[in];
    unsigned char reply_payload[1200];
    size_t ofs=0;
    
    bcopy(id->subscriber->sid.binary, &reply_payload[ofs], sizeof(id->subscriber->sid));
    ofs+=sizeof(id->subscriber->sid);
     
    // TODO return other details of this identity
     
    mdp_reply2(client, header, 0, reply_payload, ofs);
    kp++;
  }
  mdp_reply_ok(client, header);
  return 0;
}

static void mdp_process_packet(struct socket_address *client, struct mdp_header *header, 
  const uint8_t *payload, size_t payload_len)
{
  if ((header->flags & MDP_FLAG_CLOSE) && header->local.port==0){
    int i;
    for(i=0;i<MDP_MAX_BINDINGS;i++) {
      if (mdp_bindings[i].port!=0 
	&& compare_client(&mdp_bindings[i].client, client)){
	if (config.debug.mdprequests)
	  DEBUGF("Unbind MDP %s:%d from %s", 
	    mdp_bindings[i].subscriber?alloca_tohex_sid_t(mdp_bindings[i].subscriber->sid):"All",
	    mdp_bindings[i].port,
	    alloca_socket_address(client));
	mdp_bindings[i].port=0;
      }
    }
    // should we expect clients to wait for this?
    // mdp_reply_ok(client, header);
    return;
  }
  
  // find the source subscriber
  struct subscriber *source=NULL;
  
  if (is_sid_t_broadcast(header->local.sid)){
    // leave source NULL to indicate listening on all local SID's
    // note that attempting anything else will fail
  }else if (is_sid_t_any(header->local.sid)){
    // leaving the sid blank indicates that we should use our main identity
    source = my_subscriber;
    header->local.sid = source->sid;
  }else{
    // find the matching sid from our keyring
    source = find_subscriber(header->local.sid.binary, sizeof(header->local.sid), 0);
    if (!source || source->reachable != REACHABLE_SELF){
      mdp_reply_error(client, header);
      WHY("Subscriber is not local");
    }
  }
  
  struct mdp_binding *binding=NULL, *free_slot=NULL;
  
  // assign the next available port number
  if (header->local.port==0 && header->flags & MDP_FLAG_BIND){
    if (next_port_binding > 32*1024)
      next_port_binding=256;
    else
      next_port_binding++;
    header->local.port=next_port_binding;
  }
  
  // find matching binding
  {
    int i;
    for(i=0;i<MDP_MAX_BINDINGS;i++) {
      if ((!free_slot) && mdp_bindings[i].port==0)
	free_slot=&mdp_bindings[i];
      
      if (mdp_bindings[i].port == header->local.port 
	&& mdp_bindings[i].subscriber == source){
	
	binding = &mdp_bindings[i];
	break;
      }
    }
  }
  
  if (header->flags & MDP_FLAG_BIND){
    if (binding){
      mdp_reply_error(client, header);
      WHYF("Port %d already bound", header->local.port);
      return;
    }
    
    if (!free_slot){
      mdp_reply_error(client, header);
      WHY("Max supported bindings reached");
      return;
    }
    
    if (config.debug.mdprequests)
      DEBUGF("Bind MDP %s:%d to %s", 
	alloca_tohex_sid_t(header->local.sid),
	header->local.port,
	alloca_socket_address(client));
    
    // claim binding
    binding = free_slot;
    binding->port = header->local.port;
    binding->subscriber = source;
    bcopy(&client->addr, &binding->client.addr, client->addrlen);
    binding->client.addrlen = client->addrlen;
    binding->binding_time=gettime_ms();
    binding->version=1;
    
    // tell the client what we actually bound (with flags & MDP_FLAG_BIND still set)
    mdp_reply2(client, header, MDP_FLAG_BIND, NULL, 0);
  }
  
  if (is_sid_t_any(header->remote.sid)){
    // process local commands
    switch(header->remote.port){
      case MDP_LISTEN:
	// double check that this binding belongs to this connection
	if (!binding
	  || binding->internal
	  || !compare_client(&binding->client, client))
	  mdp_reply_error(client, header);
	break;
      case MDP_IDENTITY:
	if (config.debug.mdprequests)
	  DEBUGF("Processing MDP_IDENTITY from %s", alloca_socket_address(client));
	mdp_process_identity_request(client, header, payload, payload_len);
	break;
      // seach unlocked identities
      case MDP_SEARCH_IDS:
	if (config.debug.mdprequests)
	  DEBUGF("Processing MDP_SEARCH_IDS from %s", alloca_socket_address(client));
	mdp_search_identities(client, header, payload, payload_len);
	break;
      default:
	mdp_reply_error(client, header);
	WHYF("Unknown command port %d", header->remote.port);
	break;
    }
    
  }else{
    // double check that this binding belongs to this connection
    if (!binding
      || binding->internal
      || !source
      || header->local.port == 0 
      || !compare_client(&binding->client, client)){
      mdp_reply_error(client, header);
      WHY("No matching binding found");
      return;
    }
    
    struct subscriber *destination=NULL;
    if (!is_sid_t_broadcast(header->remote.sid))
      destination = find_subscriber(header->remote.sid.binary, SID_SIZE, 1);
    
    int modifiers=0;
    if ((header->flags & MDP_FLAG_NO_CRYPT) == 0)
      modifiers|=OF_CRYPTO_CIPHERED;
    if ((header->flags & MDP_FLAG_NO_SIGN) == 0)
      modifiers|=OF_CRYPTO_SIGNED;
    
    if (!destination || destination->reachable==REACHABLE_SELF){
      // TODO deprecate this mdp struct, deal with local delivery in send_frame
      overlay_mdp_frame mdp;
      mdp.out.src.sid = header->local.sid;
      mdp.out.src.port = header->local.port;
      mdp.out.dst.sid = header->remote.sid;
      mdp.out.dst.port = header->remote.port;
      bcopy(payload, mdp.out.payload, payload_len);
      mdp.out.payload_length = payload_len;
      mdp.out.ttl = header->ttl;
      mdp.out.queue = header->qos;
      mdp.packetTypeAndFlags=MDP_TX;
      if (header->flags&MDP_FLAG_NO_CRYPT)
	mdp.packetTypeAndFlags |= MDP_NOCRYPT;
      if (header->flags&MDP_FLAG_NO_SIGN)
	mdp.packetTypeAndFlags |= MDP_NOSIGN;
      
      if (config.debug.mdprequests)
	DEBUGF("Attempting to process mdp packet locally");
      overlay_saw_mdp_frame(NULL, &mdp);
    }
    
    if (config.debug.mdprequests)
      DEBUGF("Attempting to queue mdp packet");
      
    // construct, encrypt, sign and queue the packet
    if (overlay_send_frame(
      source, header->local.port,
      destination, header->remote.port, 
      payload, payload_len, 
      header->ttl, header->qos, modifiers
    )){
      mdp_reply_error(client, header);
      return;
    }
  }
  
  // remove binding
  if (binding 
    && !binding->internal
    && header->flags & MDP_FLAG_CLOSE
    && compare_client(&binding->client, client)){
    if (config.debug.mdprequests)
      DEBUGF("Unbind MDP %s:%d from %s", 
	binding->subscriber?alloca_tohex_sid_t(binding->subscriber->sid):"All",
	binding->port,
	alloca_socket_address(client));
    binding->port=0;
    binding=NULL;
  }
}

static int mdp_send2(struct socket_address *client, struct mdp_header *header, 
  const uint8_t *payload, size_t payload_len)
{
  struct iovec iov[]={
    {
      .iov_base = (void *)header,
      .iov_len = sizeof(struct mdp_header)
    },
    {
      .iov_base = (void *)payload,
      .iov_len = payload_len
    }
  };
  
  struct msghdr hdr={
    .msg_name=&client->addr,
    .msg_namelen=client->addrlen,
    .msg_iov=iov,
    .msg_iovlen=2,
  };
  
  if (sendmsg(mdp_sock2.poll.fd, &hdr, 0)<0)
    return WHY_perror("sendmsg");
  return 0;
}

static void mdp_poll2(struct sched_ent *alarm)
{
  if (alarm->poll.revents & POLLIN) {
    uint8_t payload[1200];
    struct mdp_header header;
    struct socket_address client;
    client.addrlen=sizeof(client.addr);
    
    struct iovec iov[]={
      {
	.iov_base = (void *)&header,
	.iov_len = sizeof header
      },
      {
	.iov_base = (void *)payload,
	.iov_len = sizeof payload
      }
    };
    
    struct msghdr hdr={
      .msg_name=&client.addr,
      .msg_namelen=sizeof(client.store),
      .msg_iov=iov,
      .msg_iovlen=2,
    };
    
    ssize_t len = recvmsg(alarm->poll.fd, &hdr, 0);
    if (len == -1){
      WHYF_perror("recvmsg(%d,%p,0)", alarm->poll.fd, &hdr);
      return;
    }
    if ((size_t)len < sizeof header) {
      WHYF("Expected length %zu, got %zu from %s", sizeof header, (size_t)len, alloca_socket_address(&client));
      return;
    }
    
    client.addrlen = hdr.msg_namelen;
    size_t payload_len = (size_t)(len - sizeof header);
    mdp_process_packet(&client, &header, payload, payload_len);
  }
}

static void overlay_mdp_poll(struct sched_ent *alarm)
{
  if (alarm->poll.revents & POLLIN) {
    unsigned char buffer[16384];
    int ttl;
    struct socket_address client;
    client.addrlen = sizeof client.store;

    ttl=-1;
    
    ssize_t len = recvwithttl(alarm->poll.fd,buffer,sizeof(buffer),&ttl, &client);
    if (len == -1)
      WHYF_perror("recvwithttl(%d,%p,%zu,&%d,%p(%s))",
	    alarm->poll.fd, buffer, sizeof buffer, ttl,
	    &client, alloca_socket_address(&client)
	  );

    if ((size_t)len > 0) {
      if (client.addrlen <= sizeof(sa_family_t))
	WHYF("got client.addrlen=%d too short -- ignoring frame len=%zu", (int)client.addrlen, (size_t)len);
      else {
	/* Look at overlay_mdp_frame we have received */
	overlay_mdp_frame *mdp=(overlay_mdp_frame *)&buffer[0];      
	unsigned int mdp_type = mdp->packetTypeAndFlags & MDP_TYPE_MASK;

	switch (mdp_type) {
	case MDP_GOODBYE:
	  if (config.debug.mdprequests)
	    DEBUGF("MDP_GOODBYE from %s", alloca_socket_address(&client));
	  overlay_mdp_releasebindings(&client);
	  return;
	    
	case MDP_ROUTING_TABLE:
	  if (config.debug.mdprequests)
	    DEBUGF("MDP_ROUTING_TABLE from %s", alloca_socket_address(&client));
	  {
	    struct routing_state state={
	      .client = &client,
	    };
	    
	    enum_subscribers(NULL, routing_table, &state);
	    
	  }
	  return;
	
	case MDP_GETADDRS:
	  if (config.debug.mdprequests)
	    DEBUGF("MDP_GETADDRS from %s", alloca_socket_address(&client));
	  {
	    overlay_mdp_frame mdpreply;
	    bzero(&mdpreply, sizeof(overlay_mdp_frame));
	    mdpreply.packetTypeAndFlags = MDP_ADDRLIST;
	    if (!overlay_mdp_address_list(&mdp->addrlist, &mdpreply.addrlist))
	    /* Send back to caller */
	      overlay_mdp_reply(alarm->poll.fd,
				&client,
				&mdpreply);
	      
	    return;
	  }
	  break;
	    
	case MDP_TX: /* Send payload (and don't treat it as system privileged) */
	  if (config.debug.mdprequests)
	    DEBUGF("MDP_TX from %s", alloca_socket_address(&client));
	    
	  // Dont allow mdp clients to send very high priority payloads
	  if (mdp->out.queue<=OQ_MESH_MANAGEMENT)
	    mdp->out.queue=OQ_ORDINARY;
	  overlay_mdp_dispatch(mdp, &client);
	  return;
	  break;
	    
	case MDP_BIND: /* Bind to port */
	  if (config.debug.mdprequests)
	    DEBUGF("MDP_BIND from %s", alloca_socket_address(&client));
	  {
	    struct subscriber *subscriber=NULL;
	    /* Make sure source address is either all zeros (listen on all), or a valid
	    local address */
	    
	    if (!is_sid_t_any(mdp->bind.sid)){
	      subscriber = find_subscriber(mdp->bind.sid.binary, SID_SIZE, 0);
	      if ((!subscriber) || subscriber->reachable != REACHABLE_SELF){
		WHYF("Invalid bind request for sid=%s", alloca_tohex_sid_t(mdp->bind.sid));
		/* Source address is invalid */
		overlay_mdp_reply_error(alarm->poll.fd, &client, 7,
					      "Bind address is not valid (must be a local MDP address, or all zeroes).");
		return;
	      }
	      
	    }
	    if (overlay_mdp_process_bind_request(subscriber, mdp->bind.port,
						mdp->packetTypeAndFlags, &client))
	      overlay_mdp_reply_error(alarm->poll.fd, &client, 3, "Port already in use");
	    else
	      overlay_mdp_reply_ok(alarm->poll.fd, &client, "Port bound");
	    return;
	  }
	  break;
	    
	case MDP_SCAN:
	  if (config.debug.mdprequests)
	    DEBUGF("MDP_SCAN from %s", alloca_socket_address(&client));
	  {
	    struct overlay_mdp_scan *scan = (struct overlay_mdp_scan *)&mdp->raw;
	    time_ms_t start=gettime_ms();
	    
	    if (scan->addr.s_addr==0){
	      int i=0;
	      for (i=0;i<OVERLAY_MAX_INTERFACES;i++){
		// skip any interface that is already being scanned
		if (scans[i].interface)
		  continue;
		
		struct overlay_interface *interface = &overlay_interfaces[i];
		if (interface->state!=INTERFACE_STATE_UP)
		  continue;
		
		scans[i].interface = interface;
		scans[i].current = ntohl(interface->address.sin_addr.s_addr & interface->netmask.s_addr)+1;
		scans[i].last = ntohl(interface->destination->address.sin_addr.s_addr)-1;
		if (scans[i].last - scans[i].current>0x10000){
		  INFOF("Skipping scan on interface %s as the address space is too large",interface->name);
		  continue;
		}
		scans[i].alarm.alarm=start;
		scans[i].alarm.function=overlay_mdp_scan;
		start+=100;
		schedule(&scans[i].alarm);
	      }
	    }else{
	      struct overlay_interface *interface = overlay_interface_find(scan->addr, 1);
	      if (!interface){
		overlay_mdp_reply_error(alarm->poll.fd, &client, 1, "Unable to find matching interface");
		return;
	      }
	      int i = interface - overlay_interfaces;
	      
	      if (!scans[i].interface){
		scans[i].interface = interface;
		scans[i].current = ntohl(scan->addr.s_addr);
		scans[i].last = ntohl(scan->addr.s_addr);
		scans[i].alarm.alarm=start;
		scans[i].alarm.function=overlay_mdp_scan;
		schedule(&scans[i].alarm);
	      }
	    }
	    
	    overlay_mdp_reply_ok(alarm->poll.fd, &client, "Scan initiated");
	  }
	  break;
	  
	default:
	  /* Client is not allowed to send any other frame type */
	  WARNF("Unsupported MDP frame type [%d] from %s", mdp_type, alloca_socket_address(&client));
	  overlay_mdp_reply_error(alarm->poll.fd, &client, 2, "Illegal request type.  Clients may use only MDP_TX or MDP_BIND.");
	}
      }
    }
  }
  
  if (alarm->poll.revents & (POLLHUP | POLLERR)) {
    INFO("Error on mdp socket");
  }
  return;
}
