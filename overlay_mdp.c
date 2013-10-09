/*
Copyright (C) 2010-2012 Paul Gardner-Stephen, Serval Project.
 
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

static void overlay_mdp_poll(struct sched_ent *alarm);
static void mdp_poll2(struct sched_ent *alarm);

static struct profile_total mdp_stats = { .name="overlay_mdp_poll" };
static struct sched_ent mdp_sock = {
  .function = overlay_mdp_poll,
  .stats = &mdp_stats,
  .poll.fd = -1,
};

static struct profile_total mdp_stats2 = { .name="mdp_poll2" };
static struct sched_ent mdp_sock2 = {
  .function = mdp_poll2,
  .stats = &mdp_stats2,
  .poll.fd = -1,
};

static int overlay_saw_mdp_frame(struct overlay_frame *frame, overlay_mdp_frame *mdp, time_ms_t now);

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
  struct sockaddr_un addr;
  socklen_t addrlen;
  int sock;
  
  if (make_local_sockaddr(&addr, &addrlen, "%s", name) == -1)
    return -1;
  if ((sock = esocket(AF_UNIX, SOCK_DGRAM, 0)) == -1)
    return -1;
  if (socket_set_reuseaddr(sock, 1) == -1)
    WARN("Could not set socket to reuse addresses");
  if (socket_bind(sock, (struct sockaddr *)&addr, addrlen) == -1) {
    close(sock);
    return -1;
  }
  socket_set_rcvbufsize(sock, 64 * 1024);
  
  INFOF("Socket %s: fd=%d %s", name, sock, alloca_sockaddr(&addr, addrlen));
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
  int port;
  char socket_name[MDP_MAX_SOCKET_NAME_LEN];
  int name_len;
  time_ms_t binding_time;
};

struct mdp_binding mdp_bindings[MDP_MAX_BINDINGS];
int mdp_bindings_initialised=0;

int overlay_mdp_reply_error(int sock,
			    struct sockaddr_un *recvaddr, socklen_t recvaddrlen,
			    int error_number,char *message)
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

  return overlay_mdp_reply(sock,recvaddr,recvaddrlen,&mdpreply);
}

int overlay_mdp_reply(int sock,struct sockaddr_un *recvaddr, socklen_t recvaddrlen,
			  overlay_mdp_frame *mdpreply)
{
  if (!recvaddr) return WHY("No reply address");

  ssize_t replylen = overlay_mdp_relevant_bytes(mdpreply);
  if (replylen<0) return WHY("Invalid MDP frame (could not compute length)");

  errno=0;
  int r=sendto(sock,(char *)mdpreply,replylen,0,
	       (struct sockaddr *)recvaddr,recvaddrlen);
  if (r<replylen) { 
    WHY_perror("sendto(d)"); 
    return WHYF("sendto() failed when sending MDP reply, sock=%d, r=%d", sock, r); 
  } else
    if (0) DEBUGF("reply of %d bytes sent",r);
  return 0;  
}

int overlay_mdp_reply_ok(int sock,
			 struct sockaddr_un *recvaddr, socklen_t recvaddrlen,
			 char *message)
{
  return overlay_mdp_reply_error(sock,recvaddr,recvaddrlen,0,message);
}

int overlay_mdp_releasebindings(struct sockaddr_un *recvaddr, socklen_t recvaddrlen)
{
  /* Free up any MDP bindings held by this client. */
  int i;
  for(i=0;i<MDP_MAX_BINDINGS;i++)
    if (mdp_bindings[i].name_len==recvaddrlen)
      if (!memcmp(mdp_bindings[i].socket_name,recvaddr->sun_path,recvaddrlen))
	mdp_bindings[i].port=0;

  return 0;

}

int overlay_mdp_process_bind_request(int sock, struct subscriber *subscriber, int port,
				     int flags, struct sockaddr_un *recvaddr,  socklen_t recvaddrlen)
{
  if (config.debug.mdprequests) 
    DEBUGF("Bind request %s:%d",
	subscriber ? alloca_tohex_sid(subscriber->sid) : "NULL",
	port
      );
  
  if (port<=0){
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
	if (mdp_bindings[i].name_len==recvaddrlen &&
	    !memcmp(mdp_bindings[i].socket_name,recvaddr->sun_path,recvaddrlen)) {
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
  
  mdp_bindings[free].name_len = recvaddrlen - sizeof recvaddr->sun_family;
  memcpy(mdp_bindings[free].socket_name, recvaddr->sun_path, mdp_bindings[free].name_len);
  mdp_bindings[free].binding_time=gettime_ms();
  return 0;
}

static int overlay_mdp_decode_header(struct overlay_buffer *buff, overlay_mdp_frame *mdp)
{
  /* extract MDP port numbers */
  int port = ob_get_packed_ui32(buff);
  int same = port&1;
  port >>=1;
  mdp->in.dst.port = port;
  if (!same){
    port = ob_get_packed_ui32(buff);
  }
  mdp->in.src.port = port;
  
  int len=ob_remaining(buff);
  
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
      if (0) DEBUGF("crypted MDP frame for %s", alloca_tohex_sid(f->destination->sid));

      int nm=crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES;
      int nb=crypto_box_curve25519xsalsa20poly1305_NONCEBYTES;
      int zb=crypto_box_curve25519xsalsa20poly1305_ZEROBYTES;
      int cz=crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES;
      
      unsigned char *k=keyring_get_nm_bytes(f->destination->sid, f->source->sid);
      if (!k) 
	RETURN(WHY("I don't have the private key required to decrypt that"));
      
      if (0){
	dump("frame",&f->payload->bytes[f->payload->position],
	     ob_remaining(f->payload));
      }
      
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
		    alloca_tohex_sid(f->source->sid), alloca_tohex_sid(f->destination->sid), cipher_len));
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

int overlay_saw_mdp_containing_frame(struct overlay_frame *f, time_ms_t now)
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
  if (f->destination)
    bcopy(f->destination->sid,mdp.in.dst.sid,SID_SIZE);
  else{
    // pack the broadcast address into the mdp structure, note that we no longer care about the broadcast id
    memset(mdp.in.dst.sid, 0xFF, SID_SIZE);
  }
  bcopy(f->source->sid,mdp.in.src.sid,SID_SIZE);

  /* copy crypto flags from frame so that we know if we need to decrypt or verify it */
  if (overlay_mdp_decrypt(f,&mdp))
    RETURN(-1);

  /* and do something with it! */
  RETURN(overlay_saw_mdp_frame(f, &mdp,now));
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

static int overlay_saw_mdp_frame(struct overlay_frame *frame, overlay_mdp_frame *mdp, time_ms_t now)
{
  IN();
  int i;
  int match=-1;

  switch(mdp->packetTypeAndFlags&MDP_TYPE_MASK) {
  case MDP_TX: 
    /* Regular MDP frame addressed to us.  Look for matching port binding,
       and if available, push to client.  Else do nothing, or if we feel nice
       send back a connection refused type message? Silence is probably the
       more prudent path.
    */

    if (config.debug.mdprequests) 
      DEBUGF("Received packet with listener (MDP ports: src=%s*:%d, dst=%d)",
	   alloca_tohex(mdp->out.src.sid, 7),
	   mdp->out.src.port,mdp->out.dst.port);

    // TODO pass in dest subscriber as an argument, we should know it by now
    struct subscriber *destination = NULL;
    if (frame)
      destination = frame->destination;
    else if (!is_sid_broadcast(mdp->out.dst.sid)){
      destination = find_subscriber(mdp->out.dst.sid, SID_SIZE, 1);
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
      struct sockaddr_un addr;
      addr.sun_family = AF_UNIX;
      bcopy(mdp_bindings[match].socket_name, addr.sun_path, mdp_bindings[match].name_len);
      ssize_t len = overlay_mdp_relevant_bytes(mdp);
      if (len < 0)
	RETURN(WHY("unsupported MDP packet type"));
      socklen_t addrlen = sizeof addr.sun_family + mdp_bindings[match].name_len;
      int r = sendto(mdp_sock.poll.fd,mdp,len,0,(struct sockaddr*)&addr, addrlen);
      if (r == len)
	RETURN(0);
      if (r == -1 && errno == ENOENT) {
	/* far-end of socket has died, so drop binding */
	INFOF("Closing dead MDP client '%s'",mdp_bindings[match].socket_name);
	overlay_mdp_releasebindings(&addr,mdp_bindings[match].name_len);
      }
      WHYF_perror("sendto(fd=%d,len=%zu,addr=%s)", mdp_sock.poll.fd, (size_t)len, alloca_sockaddr(&addr, addrlen));
      RETURN(WHY("Failed to pass received MDP frame to client"));
    } else {
      /* No socket is bound, ignore the packet ... except for magic sockets */
      RETURN(overlay_mdp_try_interal_services(frame, mdp));
    }
    break;
  default:
    RETURN(WHYF("We should only see MDP_TX frames here (MDP message type = 0x%x)",
		mdp->packetTypeAndFlags));
  }

  RETURN(0);
  OUT();
}

int overlay_mdp_dnalookup_reply(const sockaddr_mdp *dstaddr, const unsigned char *resolved_sid, const char *uri, const char *did, const char *name)
{
  overlay_mdp_frame mdpreply;
  bzero(&mdpreply, sizeof mdpreply);
  mdpreply.packetTypeAndFlags = MDP_TX; // outgoing MDP message
  mdpreply.out.queue=OQ_ORDINARY;
  memcpy(mdpreply.out.src.sid, resolved_sid, SID_SIZE);
  mdpreply.out.src.port = MDP_PORT_DNALOOKUP;
  bcopy(dstaddr, &mdpreply.out.dst, sizeof(sockaddr_mdp));
  /* build reply as TOKEN|URI|DID|NAME|<NUL> */
  strbuf b = strbuf_local((char *)mdpreply.out.payload, sizeof mdpreply.out.payload);
  strbuf_tohex(b, resolved_sid, SID_SIZE);
  strbuf_sprintf(b, "|%s|%s|%s|", uri, did, name?name:"");
  if (strbuf_overrun(b))
    return WHY("MDP payload overrun");
  mdpreply.out.payload_length = strbuf_len(b) + 1;
  /* deliver reply */
  return overlay_mdp_dispatch(&mdpreply, 0 /* system generated */, NULL, 0);
}

int overlay_mdp_check_binding(struct subscriber *subscriber, int port, int userGeneratedFrameP,
			      struct sockaddr_un *recvaddr,  socklen_t recvaddrlen)
{
  /* System generated frames can send anything they want */
  if (!userGeneratedFrameP)
    return 0;

  /* Check if the address is in the list of bound addresses,
     and that the recvaddr matches. */
  
  int i;
  for(i = 0; i < MDP_MAX_BINDINGS; ++i) {
    if (mdp_bindings[i].port != port)
      continue;
    if ((!mdp_bindings[i].subscriber) || mdp_bindings[i].subscriber == subscriber) {
      /* Binding matches, now make sure the sockets match */
      if (  mdp_bindings[i].name_len == recvaddrlen - sizeof(sa_family_t)
	&&  memcmp(mdp_bindings[i].socket_name, recvaddr->sun_path, recvaddrlen - sizeof(sa_family_t)) == 0
      ) {
	/* Everything matches, so this unix socket and MDP address combination is valid */
	return 0;
      }
    }
  }

  return WHYF("No such binding: recvaddr=%p %s addr=%s port=%u (0x%x) -- possible spoofing attack",
	recvaddr,
	recvaddr ? alloca_toprint(-1, recvaddr->sun_path, recvaddrlen - sizeof(sa_family_t)) : "",
	alloca_tohex_sid(subscriber->sid),
	port, port
      );
}

int overlay_mdp_encode_ports(struct overlay_buffer *plaintext, int dst_port, int src_port){
  int port=dst_port << 1;
  if (dst_port==src_port)
    port |= 1;
  if (ob_append_packed_ui32(plaintext, port))
    return -1;

  if (dst_port!=src_port){
    if (ob_append_packed_ui32(plaintext, src_port))
      return -1;
  }
  return 0;
}

static struct overlay_buffer * encrypt_payload(
  struct subscriber *source, 
  struct subscriber *dest, 
  const unsigned char *buffer, int cipher_len){
    
  int nm=crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES;
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
  
  unsigned char *nonce = ob_append_space(ret, nb+cipher_len);
  unsigned char *cipher_text = nonce + nb;
  if (!nonce){
    ob_free(ret);
    return NULL;
  }

  if (generate_nonce(nonce,nb)){
    ob_free(ret);
    WHY("generate_nonce() failed to generate nonce");
    return NULL;
  }
  
  // reserve the high bit of the nonce as a flag for transmitting a shorter nonce.
  nonce[0]&=0x7f;
  
  /* get pre-computed PKxSK bytes (the slow part of auth-cryption that can be
     retained and reused, and use that to do the encryption quickly. */
  unsigned char *k=keyring_get_nm_bytes(source->sid, dest->sid);
  if (!k) {
    ob_free(ret);
    WHY("could not compute Curve25519(NxM)");
    return NULL;
  }
  
  /* Actually authcrypt the payload */
  if (crypto_box_curve25519xsalsa20poly1305_afternm
      (cipher_text,plain,cipher_len,nonce,k)){
    ob_free(ret);
    WHY("crypto_box_afternm() failed");
    return NULL;
  }
  
  if (0) {
    DEBUG("authcrypted mdp frame");
    dump("nm",k,nm);
    dump("plain text",plain,sizeof(plain));
    dump("nonce",nonce,nb);
    dump("cipher text",cipher_text,cipher_len);
  }
  
  /* now shuffle down to get rid of the temporary space that crypto_box
   uses. 
   TODO extend overlay buffer so we don't need this.
   */
  bcopy(&cipher_text[cz],&cipher_text[0],cipher_len-cz);
  ret->position-=cz;
  if (0){
    dump("frame", &ret->bytes[0], ret->position);
  }
  
  return ret;
}

// encrypt or sign the plaintext, then queue the frame for transmission.
int overlay_send_frame(struct overlay_frame *frame, struct overlay_buffer *plaintext){
  
  if (!frame->source)
    frame->source = my_subscriber;
    
  /* Work out the disposition of the frame->  For now we are only worried
     about the crypto matters, and not compression that may be applied
     before encryption (since applying it after is useless as ciphered
     text should have maximum entropy). */
  switch(frame->modifiers) {
  default:
  case OF_CRYPTO_SIGNED|OF_CRYPTO_CIPHERED:
    /* crypted and signed (using CryptoBox authcryption primitive) */
    frame->payload = encrypt_payload(frame->source, frame->destination, ob_ptr(plaintext), ob_position(plaintext));
    if (!frame->payload){
      ob_free(plaintext);
      op_free(frame);
      return -1;
    }
    break;
      
  case OF_CRYPTO_SIGNED:
    // Lets just append some space into the existing payload buffer for the signature, without copying it.
    frame->payload = plaintext;
    ob_makespace(frame->payload,SIGNATURE_BYTES);
    if (crypto_sign_message(frame->source, ob_ptr(frame->payload), frame->payload->allocSize, &frame->payload->position)){
      op_free(frame);
      return -1;
    }
    break;
      
  case 0:
    /* clear text and no signature */
    frame->payload = plaintext;
    break;
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
int overlay_mdp_dispatch(overlay_mdp_frame *mdp,int userGeneratedFrameP,
			 struct sockaddr_un *recvaddr, socklen_t recvaddrlen)
{
  IN();

  if (mdp->out.payload_length > sizeof(mdp->out.payload))
    FATAL("Payload length is past the end of the buffer");

  struct subscriber *source=NULL;
  struct subscriber *destination=NULL;
  
  if (is_sid_any(mdp->out.src.sid)){
    /* set source to ourselves */
    source = my_subscriber;
    bcopy(source->sid, mdp->out.src.sid, SID_SIZE);
  }else if (is_sid_broadcast(mdp->out.src.sid)){
    /* Nope, I'm sorry but we simply can't send packets from 
     * broadcast addresses. */
    RETURN(WHY("Packet had broadcast address as source address"));
  }else{
    // assume all local identities have already been unlocked and marked as SELF.
    source = find_subscriber(mdp->out.src.sid, SID_SIZE, 0);
    if (!source){
      RETURN(WHYF("Possible spoofing attempt, tried to send a packet from %s, which is an unknown SID", alloca_tohex_sid(mdp->out.src.sid)));
    }
    if (source->reachable!=REACHABLE_SELF){
      RETURN(WHYF("Possible spoofing attempt, tried to send a packet from %s", alloca_tohex_sid(mdp->out.src.sid)));
    }
  }
  
  if (overlay_mdp_check_binding(source, mdp->out.src.port, userGeneratedFrameP,
				recvaddr, recvaddrlen)){
    RETURN(overlay_mdp_reply_error
	   (mdp_sock.poll.fd,
	    (struct sockaddr_un *)recvaddr,
	    recvaddrlen,8,
	    "Source address is invalid (you must bind to a source address before"
	    " you can send packets"));
  }
  
  /* Work out if destination is broadcast or not */
  if (is_sid_broadcast(mdp->out.dst.sid)){
    /* broadcast packets cannot be encrypted, so complain if MDP_NOCRYPT
     flag is not set. Also, MDP_NOSIGN must also be applied, until
     NaCl cryptobox keys can be used for signing. */	
    if (!(mdp->packetTypeAndFlags&MDP_NOCRYPT))
      RETURN(overlay_mdp_reply_error(mdp_sock.poll.fd,
				     recvaddr,recvaddrlen,5,
				     "Broadcast packets cannot be encrypted "));
  }else{
    destination = find_subscriber(mdp->out.dst.sid, SID_SIZE, 1);
    // should we reply with an error if the destination is not currently routable?
  }
  
  if (mdp->out.ttl == 0) 
    mdp->out.ttl = PAYLOAD_TTL_DEFAULT;
  else if (mdp->out.ttl > PAYLOAD_TTL_MAX) {
    RETURN(overlay_mdp_reply_error(mdp_sock.poll.fd, recvaddr,recvaddrlen,9, "TTL out of range"));
  }
  
  if (mdp->out.queue == 0)
    mdp->out.queue = OQ_ORDINARY;
    
  if (!destination || destination->reachable == REACHABLE_SELF){
    /* Packet is addressed to us / broadcast, we should process it first. */
    overlay_saw_mdp_frame(NULL,mdp,gettime_ms());
    if (destination) {
      /* Is local, and is not broadcast, so shouldn't get sent out
	 on the wire. */
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
  
  // copy the plain text message into a new buffer, with the wire encoded port numbers
  struct overlay_buffer *plaintext=ob_new();
  if (!plaintext)
    RETURN(-1);
  
  if (overlay_mdp_encode_ports(plaintext, mdp->out.dst.port, mdp->out.src.port)){
    ob_free(plaintext);
    RETURN (-1);
  }
  if (ob_append_bytes(plaintext, mdp->out.payload, mdp->out.payload_length)){
    ob_free(plaintext);
    RETURN(-1);
  }
  
  /* Prepare the overlay frame for dispatch */
  struct overlay_frame *frame = emalloc_zero(sizeof(struct overlay_frame));
  if (!frame){
    ob_free(plaintext);
    RETURN(-1);
  }
  
  frame->source = source;
  frame->destination = destination;
  frame->ttl = mdp->out.ttl;
  frame->queue = mdp->out.queue;
  frame->type=OF_TYPE_DATA;
  frame->prev=NULL;
  frame->next=NULL;
  frame->modifiers=modifiers;
  
  RETURN(overlay_send_frame(frame, plaintext));
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
      response->frame_sid_count < MDP_MAX_SID_REQUEST) {
    memcpy(response->sids[response->frame_sid_count++], subscriber->sid, SID_SIZE);
  }
  
  return 0;
}

int overlay_mdp_address_list(overlay_mdp_addrlist *request, overlay_mdp_addrlist *response){
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
  struct sockaddr_un *recvaddr_un;
  socklen_t recvaddrlen;
  int fd;
};

static int routing_table(struct subscriber *subscriber, void *context){
  struct routing_state *state = (struct routing_state *)context;
  overlay_mdp_frame reply;
  bzero(&reply, sizeof(overlay_mdp_frame));
  
  struct overlay_route_record *r=(struct overlay_route_record *)&reply.out.payload;
  reply.packetTypeAndFlags=MDP_TX;
  reply.out.payload_length=sizeof(struct overlay_route_record);
  memcpy(r->sid, subscriber->sid, SID_SIZE);
  r->reachable = subscriber->reachable;
  
  if (subscriber->reachable==REACHABLE_INDIRECT && subscriber->next_hop)
    memcpy(r->neighbour, subscriber->next_hop->sid, SID_SIZE);
  if (subscriber->reachable & REACHABLE_DIRECT 
    && subscriber->destination 
    && subscriber->destination->interface)
    strcpy(r->interface_name, subscriber->destination->interface->name);
  else
    r->interface_name[0]=0;
  overlay_mdp_reply(mdp_sock.poll.fd, state->recvaddr_un, state->recvaddrlen, &reply);
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

struct mdp_client{
  struct sockaddr_un *addr;
  socklen_t addrlen;
};

static int mdp_reply2(const struct mdp_client *client, const struct mdp_header *header, 
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
    .msg_name=client->addr,
    .msg_namelen=client->addrlen,
    .msg_iov=iov,
    .msg_iovlen=2,
  };
  
  if (config.debug.mdprequests)
    DEBUGF("Replying to %s with code %d", alloca_sockaddr(client->addr, client->addrlen), flags);
  return sendmsg(mdp_sock2.poll.fd, &hdr, 0);
}

#define mdp_reply_error(A,B,C)  mdp_reply2(A,B,MDP_FLAG_ERROR,(const unsigned char *)C,strlen(C))
#define mdp_reply_ok(A,B)  mdp_reply2(A,B,MDP_FLAG_OK,NULL,0)

static int mdp_process_identity_request(struct mdp_client *client, struct mdp_header *header, 
  const unsigned char *payload, int payload_len)
{
  if (payload_len<sizeof(struct mdp_identity_request)){
    mdp_reply_error(client, header, "Request too short");
    return -1;
  }
  struct mdp_identity_request *request = (struct mdp_identity_request *)payload;
  payload += sizeof(struct mdp_identity_request);
  payload_len -= sizeof(struct mdp_identity_request);
  
  switch(request->action){
    case ACTION_UNLOCK:
      {
	if (request->type!=TYPE_PIN){
	  mdp_reply_error(client, header, "Unknown request type");
	  return -1;
	}
	int unlock_count=0;
	const char *pin = (char *)payload;
	int ofs=0;
	while(ofs < payload_len){
	  if (!payload[ofs++]){
	    unlock_count += keyring_enter_pin(keyring, pin);
	    pin=(char *)&payload[ofs++];
	  }
	}
      }
      break;
    default:
      mdp_reply_error(client, header, "Unknown request action");
      return -1;
  }
  mdp_reply_ok(client, header);
  return 0;
}

static void mdp_poll2(struct sched_ent *alarm)
{
  if (alarm->poll.revents & POLLIN) {
    unsigned char buffer[1600];
    struct sockaddr_storage addr;
    struct mdp_client client={
      .addr = (struct sockaddr_un *)&addr,
      .addrlen = sizeof(addr)
    };
    int ttl=-1;
    
    ssize_t len = recvwithttl(alarm->poll.fd, buffer, sizeof(buffer), &ttl, (struct sockaddr *)&addr, &client.addrlen);
    
    if (len<=sizeof(struct mdp_header)){
      WHYF("Expected length %d, got %d from %s", (int)sizeof(struct mdp_header), (int)len, alloca_sockaddr(client.addr, client.addrlen));
      return;
    }
    
    struct mdp_header *header = (struct mdp_header *)buffer;
    
    unsigned char *payload = &buffer[sizeof(struct mdp_header)];
    int payload_len = len - sizeof(struct mdp_header);
    
    if (is_sid_any(header->remote.sid.binary)){
      // process local commands
      switch(header->remote.port){
	case MDP_IDENTITY:
	  if (config.debug.mdprequests)
	    DEBUGF("Processing MDP_IDENTITY from %s", alloca_sockaddr(client.addr, client.addrlen));
	  mdp_process_identity_request(&client, header, payload, payload_len);
	  break;
	default:
	  mdp_reply_error(&client, header, "Unknown port number");
	  break;
      }
    }else{
      // TODO transmit packet
      mdp_reply_error(&client, header, "Transmitting packets is not yet supported");
    }
  }
}

static void overlay_mdp_poll(struct sched_ent *alarm)
{
  if (alarm->poll.revents & POLLIN) {
    unsigned char buffer[16384];
    int ttl;
    unsigned char recvaddrbuffer[1024];
    struct sockaddr *recvaddr=(struct sockaddr *)&recvaddrbuffer[0];
    socklen_t recvaddrlen=sizeof(recvaddrbuffer);
    struct sockaddr_un *recvaddr_un=NULL;

    ttl=-1;
    bzero((void *)recvaddrbuffer,sizeof(recvaddrbuffer));
    
    ssize_t len = recvwithttl(alarm->poll.fd,buffer,sizeof(buffer),&ttl, recvaddr, &recvaddrlen);
    recvaddr_un=(struct sockaddr_un *)recvaddr;

    if (len > 0) {
      if (recvaddrlen <= sizeof(sa_family_t))
	WHYF("got recvaddrlen=%d too short -- ignoring frame len=%zu", (int)recvaddrlen, (size_t)len);
      else {
	/* Look at overlay_mdp_frame we have received */
	overlay_mdp_frame *mdp=(overlay_mdp_frame *)&buffer[0];      
	unsigned int mdp_type = mdp->packetTypeAndFlags & MDP_TYPE_MASK;

	switch (mdp_type) {
	case MDP_GOODBYE:
	  if (config.debug.mdprequests)
	    DEBUGF("MDP_GOODBYE from %s", alloca_sockaddr(recvaddr, recvaddrlen));
	  overlay_mdp_releasebindings(recvaddr_un,recvaddrlen);
	  return;
	    
	case MDP_ROUTING_TABLE:
	  if (config.debug.mdprequests)
	    DEBUGF("MDP_ROUTING_TABLE from %s", alloca_sockaddr(recvaddr, recvaddrlen));
	  {
	    struct routing_state state={
	      .recvaddr_un=recvaddr_un,
	      .recvaddrlen=recvaddrlen,
	    };
	    
	    enum_subscribers(NULL, routing_table, &state);
	    
	  }
	  return;
	
	case MDP_GETADDRS:
	  if (config.debug.mdprequests)
	    DEBUGF("MDP_GETADDRS from %s", alloca_sockaddr(recvaddr, recvaddrlen));
	  {
	    overlay_mdp_frame mdpreply;
	    bzero(&mdpreply, sizeof(overlay_mdp_frame));
	    mdpreply.packetTypeAndFlags = MDP_ADDRLIST;
	    if (!overlay_mdp_address_list(&mdp->addrlist, &mdpreply.addrlist))
	    /* Send back to caller */
	      overlay_mdp_reply(alarm->poll.fd,
				(struct sockaddr_un *)recvaddr,recvaddrlen,
				&mdpreply);
	      
	    return;
	  }
	  break;
	    
	case MDP_TX: /* Send payload (and don't treat it as system privileged) */
	  if (config.debug.mdprequests)
	    DEBUGF("MDP_TX from %s", alloca_sockaddr(recvaddr, recvaddrlen));
	    
	  // Dont allow mdp clients to send very high priority payloads
	  if (mdp->out.queue<=OQ_MESH_MANAGEMENT)
	    mdp->out.queue=OQ_ORDINARY;
	  overlay_mdp_dispatch(mdp,1,(struct sockaddr_un*)recvaddr,recvaddrlen);
	  return;
	  break;
	    
	case MDP_BIND: /* Bind to port */
	  if (config.debug.mdprequests)
	    DEBUGF("MDP_BIND from %s", alloca_sockaddr(recvaddr, recvaddrlen));
	  {
	    struct subscriber *subscriber=NULL;
	    /* Make sure source address is either all zeros (listen on all), or a valid
	    local address */
	    
	    if (!is_sid_any(mdp->bind.sid)){
	      subscriber = find_subscriber(mdp->bind.sid, SID_SIZE, 0);
	      if ((!subscriber) || subscriber->reachable != REACHABLE_SELF){
		WHYF("Invalid bind request for sid=%s", alloca_tohex_sid(mdp->bind.sid));
		/* Source address is invalid */
		overlay_mdp_reply_error(alarm->poll.fd, recvaddr_un, recvaddrlen, 7,
					      "Bind address is not valid (must be a local MDP address, or all zeroes).");
		return;
	      }
	      
	    }
	    if (overlay_mdp_process_bind_request(alarm->poll.fd, subscriber, mdp->bind.port,
						mdp->packetTypeAndFlags, recvaddr_un, recvaddrlen))
	      overlay_mdp_reply_error(alarm->poll.fd,recvaddr_un,recvaddrlen,3, "Port already in use");
	    else
	      overlay_mdp_reply_ok(alarm->poll.fd,recvaddr_un,recvaddrlen,"Port bound");
	    return;
	  }
	  break;
	    
	case MDP_SCAN:
	  if (config.debug.mdprequests)
	    DEBUGF("MDP_SCAN from %s", alloca_sockaddr(recvaddr, recvaddrlen));
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
		overlay_mdp_reply_error(alarm->poll.fd,recvaddr_un,recvaddrlen, 1, "Unable to find matching interface");
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
	    
	    overlay_mdp_reply_ok(alarm->poll.fd,recvaddr_un,recvaddrlen,"Scan initiated");
	  }
	  break;
	  
	default:
	  /* Client is not allowed to send any other frame type */
	  WARNF("Unsupported MDP frame type [%d] from %s", mdp_type, alloca_sockaddr(recvaddr, recvaddrlen));
	  mdp->packetTypeAndFlags=MDP_ERROR;
	  mdp->error.error=2;
	  snprintf(mdp->error.message,128,"Illegal request type.  Clients may use only MDP_TX or MDP_BIND.");
	  int len=4+4+strlen(mdp->error.message)+1;
	  errno=0;
	  /* We ignore the result of the following, because it is just sending an
	    error message back to the client.  If this fails, where would we report
	    the error to? My point exactly. */
	  sendto(alarm->poll.fd,mdp,len,0,(struct sockaddr *)recvaddr,recvaddrlen);
	}
      }
    }
  }
  
  if (alarm->poll.revents & (POLLHUP | POLLERR)) {
    INFO("Error on mdp socket");
  }
  return;
}
