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

#include <sys/stat.h>
#include "serval.h"
#include "conf.h"
#include "str.h"
#include "strbuf.h"
#include "overlay_buffer.h"
#include "overlay_address.h"
#include "overlay_packet.h"
#include "mdp_client.h"
#include "crypto.h"
#include "parallel.h"

struct profile_total mdp_stats={.name="overlay_mdp_poll"};

struct sched_ent mdp_abstract={
  .function = overlay_mdp_poll,
  .stats = &mdp_stats,
};

struct sched_ent mdp_named={
  .function = overlay_mdp_poll,
  .stats = &mdp_stats,
};

static int overlay_saw_mdp_frame(struct overlay_frame *frame, overlay_mdp_frame *mdp, time_ms_t now);

int overlay_mdp_setup_sockets()
{
  struct sockaddr_un name;
  int len;
  
  name.sun_family = AF_UNIX;
  
#ifndef HAVE_LINUX_IF_H
  /* Abstrack name space (i.e., non-file represented) unix domain sockets are a
     linux-only thing. */
  mdp_abstract.poll.fd = -1;
#else
  if (mdp_abstract.poll.fd<=0) {
    /* Abstract name space unix sockets is a special Linux thing, which is
       convenient for us because Android is Linux, but does not have a shared
       writable path that is on a UFS partition, so we cannot use traditional
       named unix domain sockets. So the abstract name space gives us a solution. */
    name.sun_path[0]=0;
    /* XXX The 100 should be replaced with the actual maximum allowed.
       Apparently POSIX requires it to be at least 100, but I would still feel
       more comfortable with using the appropriate constant. */
    if (!form_serval_instance_path(&name.sun_path[0], sizeof name.sun_path, "mdp.socket"))
      return WHY("Cannot construct name of unix domain socket.");
    len = 1+strlen(&name.sun_path[1]) + sizeof(name.sun_family);
    
    mdp_abstract.poll.fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (mdp_abstract.poll.fd>-1) {
      int reuseP=1;
      if (setsockopt( mdp_abstract.poll.fd, SOL_SOCKET, SO_REUSEADDR, &reuseP, sizeof(reuseP)) == -1) {
	WARN_perror("setsockopt(SO_REUSEADDR)");
	WARN("Could not set socket reuse addresses");
      }
      if (bind(mdp_abstract.poll.fd, (struct sockaddr *)&name, len) == -1) {
	WARN_perror("bind");
	close(mdp_abstract.poll.fd);
	mdp_abstract.poll.fd = -1;
	WARN("bind of abstract name space socket failed (not a problem on non-linux systems)");
      }
      int send_buffer_size=64*1024;    
      if (setsockopt(mdp_abstract.poll.fd, SOL_SOCKET, SO_SNDBUF, &send_buffer_size, sizeof(send_buffer_size)) == -1)
	WARN_perror("setsockopt(SO_SNDBUF)");
      mdp_abstract.poll.events = POLLIN;
      watch(&mdp_abstract);
    } 
  }
#endif
  if (mdp_named.poll.fd<=0) {
    if (!form_serval_instance_path(&name.sun_path[0], sizeof name.sun_path, "mdp.socket"))
      return WHY("Cannot construct name of unix domain socket.");
    unlink(&name.sun_path[0]);
    len = 0+strlen(&name.sun_path[0]) + sizeof(name.sun_family)+1;
    mdp_named.poll.fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (mdp_named.poll.fd>-1) {
      int reuseP=1;
      if(setsockopt( mdp_named.poll.fd, SOL_SOCKET, SO_REUSEADDR, &reuseP, sizeof(reuseP)) == -1) {
	WARN_perror("setsockopt(SO_REUSEADDR)");
	WARN("Could not set socket reuse addresses");
      }
      if (bind(mdp_named.poll.fd, (struct sockaddr *)&name, len) == -1) {
	WARN_perror("bind");
	close(mdp_named.poll.fd);
	mdp_named.poll.fd = -1;
	WARN("Could not bind named unix domain socket");
      }
      int send_buffer_size=64*1024;    
      if (setsockopt(mdp_named.poll.fd, SOL_SOCKET, SO_RCVBUF, &send_buffer_size, sizeof(send_buffer_size)) == -1)
	WARN_perror("setsockopt(SO_RCVBUF)");
      mdp_named.function = overlay_mdp_poll;
      mdp_named.stats = &mdp_stats;
      mdp_named.poll.events = POLLIN;
      watch(&mdp_named);
    }
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
			    struct sockaddr_un *recvaddr,int recvaddrlen,
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

int overlay_mdp_reply(int sock,struct sockaddr_un *recvaddr,int recvaddrlen,
			  overlay_mdp_frame *mdpreply)
{
  int replylen;

  if (!recvaddr) return WHY("No reply address");

  replylen=overlay_mdp_relevant_bytes(mdpreply);
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
			 struct sockaddr_un *recvaddr,int recvaddrlen,
			 char *message)
{
  return overlay_mdp_reply_error(sock,recvaddr,recvaddrlen,0,message);
}

int overlay_mdp_releasebindings(struct sockaddr_un *recvaddr,int recvaddrlen)
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
				     int flags, struct sockaddr_un *recvaddr, int recvaddrlen)
{
  int i;
  
  if (port<=0){
    return WHYF("Port %d cannot be bound", port);
  }
  if (!mdp_bindings_initialised) {
    /* Mark all slots as unused */
    for(i=0;i<MDP_MAX_BINDINGS;i++)
      mdp_bindings[i].port=0;
    mdp_bindings_initialised=1;
  }

  /* See if binding already exists */
  int free=-1;
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
  if (config.debug.mdprequests) 
    DEBUGF("Binding %s:%d", subscriber ? alloca_tohex_sid(subscriber->sid) : "NULL", port);
  /* Okay, record binding and report success */
  mdp_bindings[free].port=port;
  mdp_bindings[free].subscriber=subscriber;
  
  mdp_bindings[free].name_len=recvaddrlen-2;
  memcpy(mdp_bindings[free].socket_name,recvaddr->sun_path,
	 mdp_bindings[free].name_len);
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

      bcopy(mdp_bindings[match].socket_name,addr.sun_path,mdp_bindings[match].name_len);
      addr.sun_family=AF_UNIX;
      errno=0;
      int len=overlay_mdp_relevant_bytes(mdp);
      int r=sendto(mdp_named.poll.fd,mdp,len,0,(struct sockaddr*)&addr,sizeof(addr));
      if (r==overlay_mdp_relevant_bytes(mdp)) {	
	RETURN(0);
      }
      WHY("didn't send mdp packet");
      if (errno==ENOENT) {
	/* far-end of socket has died, so drop binding */
	INFOF("Closing dead MDP client '%s'",mdp_bindings[match].socket_name);
	overlay_mdp_releasebindings(&addr,mdp_bindings[match].name_len);
      }
      WHY_perror("sendto(e)");
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
			      struct sockaddr_un *recvaddr, int recvaddrlen)
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
      if (  mdp_bindings[i].name_len == recvaddrlen - sizeof(short)
	&&  memcmp(mdp_bindings[i].socket_name, recvaddr->sun_path, recvaddrlen - sizeof(short)) == 0
      ) {
	/* Everything matches, so this unix socket and MDP address combination is valid */
	return 0;
      }
    }
  }

  return WHYF("No such binding: recvaddr=%p %s addr=%s port=%u (0x%x) -- possible spoofing attack",
	recvaddr,
	recvaddr ? alloca_toprint(-1, recvaddr->sun_path, recvaddrlen - sizeof(short)) : "",
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

void overlay_mdp_dispatch_alarm(struct sched_ent *alarm) {
  ASSERT_THREAD(main_thread);
  overlay_mdp_frame *mdp = alarm->context;
  free(alarm);
  overlay_mdp_dispatch(mdp, 0, NULL, 0);
  free(mdp);
}

/* Construct MDP packet frame from overlay_mdp_frame structure
   (need to add return address from bindings list, and copy
   payload etc).
   This is for use by the SERVER. 
   Clients should use overlay_mdp_send()
 */
int overlay_mdp_dispatch(overlay_mdp_frame *mdp,int userGeneratedFrameP,
			 struct sockaddr_un *recvaddr,int recvaddrlen)
{
  ASSERT_THREAD(main_thread);
  IN();

  if (mdp->out.payload_length > sizeof(mdp->out.payload))
    FATAL("Payload length is past the end of the buffer");

  /* Prepare the overlay frame for dispatch */
  struct overlay_frame *frame = calloc(1,sizeof(struct overlay_frame));
  if (!frame)
    FATAL("Couldn't allocate frame buffer");
  
  if (is_sid_any(mdp->out.src.sid)){
    /* set source to ourselves */
    frame->source = my_subscriber;
    bcopy(frame->source->sid, mdp->out.src.sid, SID_SIZE);
  }else if (is_sid_broadcast(mdp->out.src.sid)){
    /* This is rather naughty if it happens, since broadcasting a
     response can lead to all manner of nasty things.
     Picture a packet with broadcast as the source address, sent
     to, say, the MDP echo port on another node, and with a source
     port also of the echo port.  Said echo will get multiplied many,
     many, many times over before the TTL finally reaches zero.
     So we just say no to any packet with a broadcast source address. 
     (Of course we have other layers of protection against such 
     shenanigens, such as using BPIs to smart-flood broadcasts, but
     security comes through depth.)
     */
    op_free(frame);
    RETURN(WHY("Packet had broadcast address as source address"));
  }else{
    // assume all local identities have already been unlocked and marked as SELF.
    frame->source = find_subscriber(mdp->out.src.sid, SID_SIZE, 0);
    if (!frame->source){
      op_free(frame);
      RETURN(WHYF("Possible spoofing attempt, tried to send a packet from %s, which is an unknown SID", alloca_tohex_sid(mdp->out.src.sid)));
    }
    if (frame->source->reachable!=REACHABLE_SELF){
      op_free(frame);
      RETURN(WHYF("Possible spoofing attempt, tried to send a packet from %s", alloca_tohex_sid(mdp->out.src.sid)));
    }
  }
  
  /* Work out if destination is broadcast or not */
  if (overlay_mdp_check_binding(frame->source, mdp->out.src.port, userGeneratedFrameP,
				recvaddr, recvaddrlen)){
    op_free(frame);
    RETURN(overlay_mdp_reply_error
	   (mdp_named.poll.fd,
	    (struct sockaddr_un *)recvaddr,
	    recvaddrlen,8,
	    "Source address is invalid (you must bind to a source address before"
	    " you can send packets"));
  }
  
  if (is_sid_broadcast(mdp->out.dst.sid)){
    /* broadcast packets cannot be encrypted, so complain if MDP_NOCRYPT
     flag is not set. Also, MDP_NOSIGN must also be applied, until
     NaCl cryptobox keys can be used for signing. */	
    if (!(mdp->packetTypeAndFlags&MDP_NOCRYPT)){
      op_free(frame);
      RETURN(overlay_mdp_reply_error(mdp_named.poll.fd,
				     recvaddr,recvaddrlen,5,
				     "Broadcast packets cannot be encrypted "));
    }
    overlay_broadcast_generate_address(&frame->broadcast_id);
    frame->destination = NULL;
  }else{
    frame->destination = find_subscriber(mdp->out.dst.sid, SID_SIZE, 1);
  }
  
  frame->ttl = mdp->out.ttl;
  if (frame->ttl == 0) 
    frame->ttl = PAYLOAD_TTL_DEFAULT;
  else if (frame->ttl > PAYLOAD_TTL_MAX) {
    op_free(frame);
    RETURN(overlay_mdp_reply_error(mdp_named.poll.fd,
				    recvaddr,recvaddrlen,9,
				    "TTL out of range"));
  }
  
  if (!frame->destination || frame->destination->reachable == REACHABLE_SELF)
    {
      /* Packet is addressed such that we should process it. */
      overlay_saw_mdp_frame(NULL,mdp,gettime_ms());
      if (frame->destination) {
	/* Is local, and is not broadcast, so shouldn't get sent out
	   on the wire. */
	op_free(frame);
	RETURN(0);
      }
    }
  
  frame->type=OF_TYPE_DATA;
  frame->prev=NULL;
  frame->next=NULL;
  struct overlay_buffer *plaintext=ob_new();
  
  if (overlay_mdp_encode_ports(plaintext, mdp->out.dst.port, mdp->out.src.port)){
    ob_free(plaintext);
    RETURN (-1);
  }
  
  if (ob_append_bytes(plaintext, mdp->out.payload, mdp->out.payload_length)){
    ob_free(plaintext);
    RETURN(-1);
  }
  
  /* Work out the disposition of the frame->  For now we are only worried
     about the crypto matters, and not compression that may be applied
     before encryption (since applying it after is useless as ciphered
     text should have maximum entropy). */
  switch(mdp->packetTypeAndFlags&(MDP_NOCRYPT|MDP_NOSIGN)) {
  case 0: /* crypted and signed (using CryptoBox authcryption primitive) */
    frame->modifiers=OF_CRYPTO_SIGNED|OF_CRYPTO_CIPHERED;
    {
      int nm=crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES;
      int zb=crypto_box_curve25519xsalsa20poly1305_ZEROBYTES;
      int nb=crypto_box_curve25519xsalsa20poly1305_NONCEBYTES;
      int cz=crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES;
      
      /* generate plain message with zero bytes and get ready to cipher it */
      int cipher_len=ob_position(plaintext);
      
      // TODO, add support for leading zero's in overlay_buffer's, then we don't need to copy the plain text again.
      unsigned char plain[zb+cipher_len];
      
      /* zero bytes */
      bzero(&plain[0],zb);
      bcopy(ob_ptr(plaintext),&plain[zb],cipher_len);
      
      cipher_len+=zb;
      
      ob_free(plaintext);
      
      frame->payload = ob_new();
      
      unsigned char *nonce = ob_append_space(frame->payload, nb+cipher_len);
      unsigned char *cipher_text = nonce + nb;
      if (!nonce)
	RETURN(-1);
      if (generate_nonce(nonce,nb)) {
	op_free(frame);
	RETURN(WHY("generate_nonce() failed to generate nonce"));
      }
      // reserve the high bit of the nonce as a flag for transmitting a shorter nonce.
      nonce[0]&=0x7f;
      
      /* get pre-computed PKxSK bytes (the slow part of auth-cryption that can be
	 retained and reused, and use that to do the encryption quickly. */
      unsigned char *k=keyring_get_nm_bytes(mdp->out.src.sid, mdp->out.dst.sid);
      if (!k) {
	op_free(frame);
	RETURN(WHY("could not compute Curve25519(NxM)")); 
      }
      /* Actually authcrypt the payload */
      if (crypto_box_curve25519xsalsa20poly1305_afternm
	  (cipher_text,plain,cipher_len,nonce,k)){
	op_free(frame);
	RETURN(WHY("crypto_box_afternm() failed")); 
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
      frame->payload->position-=cz;
      if (0){
	dump("frame",&frame->payload->bytes[0],
	     frame->payload->position);
      }
    }
    break;
      
  case MDP_NOCRYPT: 
    /* Payload is sent unencrypted, but signed. */
    frame->modifiers=OF_CRYPTO_SIGNED;
    frame->payload = plaintext;
    ob_makespace(frame->payload,SIGNATURE_BYTES);
    if (crypto_sign_message(frame->source, frame->payload->bytes, frame->payload->allocSize, &frame->payload->position)){
      op_free(frame);
      RETURN(-1);
    }
    break;
      
  case MDP_NOSIGN|MDP_NOCRYPT: /* clear text and no signature */
    frame->modifiers=0; 
    frame->payload = plaintext;
    break;
  case MDP_NOSIGN: 
  default:
    /* ciphered, but not signed.
     This means we don't use CryptoBox, but rather a more compact means
     of representing the ciphered stream segment.
     */
    op_free(frame);
    RETURN(WHY("Not implemented"));
  }
  
  frame->queue=mdp->out.queue;
  if (frame->queue==0)
    frame->queue = OQ_ORDINARY;
  
  if (overlay_payload_enqueue(frame))
    op_free(frame);
  RETURN(0);
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
  if (subscriber->reachable & REACHABLE_DIRECT && subscriber->interface)
    strcpy(r->interface_name, subscriber->interface->name);
  else
    r->interface_name[0]=0;
  overlay_mdp_reply(mdp_named.poll.fd, state->recvaddr_un, state->recvaddrlen, &reply);
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
      if (overlay_send_probe(NULL, addr, state->interface, OQ_ORDINARY))
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

void overlay_mdp_poll(struct sched_ent *alarm)
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

    if (len>0) {
      /* Look at overlay_mdp_frame we have received */
      overlay_mdp_frame *mdp=(overlay_mdp_frame *)&buffer[0];      
      unsigned int mdp_type = mdp->packetTypeAndFlags & MDP_TYPE_MASK;

      switch (mdp_type) {
      case MDP_GOODBYE:
	if (config.debug.mdprequests) DEBUG("MDP_GOODBYE");
	overlay_mdp_releasebindings(recvaddr_un,recvaddrlen);
	return;
	  
      case MDP_ROUTING_TABLE:
	{
	  struct routing_state state={
	    .recvaddr_un=recvaddr_un,
	    .recvaddrlen=recvaddrlen,
	  };
	  
	  enum_subscribers(NULL, routing_table, &state);
	  
	}
	return;
      
      case MDP_GETADDRS:
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
	if (config.debug.mdprequests) DEBUG("MDP_TX");
	  
	// Dont allow mdp clients to send very high priority payloads
	if (mdp->out.queue<=OQ_MESH_MANAGEMENT)
	  mdp->out.queue=OQ_ORDINARY;
	overlay_mdp_dispatch(mdp,1,(struct sockaddr_un*)recvaddr,recvaddrlen);
	return;
	break;
	  
      case MDP_BIND: /* Bind to port */
	{
	  if (config.debug.mdprequests) DEBUG("MDP_BIND");
	  
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
	      scans[i].last = ntohl(interface->broadcast_address.sin_addr.s_addr)-1;
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
	WARNF("Unsupported MDP frame type: %d", mdp_type);
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
  
  if (alarm->poll.revents & (POLLHUP | POLLERR)) {
    INFO("Error on mdp socket");
  }
  return;
}

