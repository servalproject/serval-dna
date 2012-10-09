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
#include "strbuf.h"
#include "overlay_buffer.h"
#include "overlay_address.h"
#include "overlay_packet.h"
#include "mdp_client.h"

struct profile_total mdp_stats={.name="overlay_mdp_poll"};

struct sched_ent mdp_abstract={
  .function = overlay_mdp_poll,
  .stats = &mdp_stats,
};

struct sched_ent mdp_named={
  .function = overlay_mdp_poll,
  .stats = &mdp_stats,
};

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
    snprintf(&name.sun_path[1],100,
	     confValueGet("mdp.socket",DEFAULT_MDP_SOCKET_NAME));
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
    if (!form_serval_instance_path(&name.sun_path[0], 100, "mdp.socket"))
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

  if (!recvaddr) return 0;

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
  if (debug & DEBUG_MDPREQUESTS) 
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

int overlay_mdp_decrypt(struct overlay_frame *f, overlay_mdp_frame *mdp)
{
  IN();

  int len=f->payload->sizeLimit - f->payload->position;
  unsigned char *b = NULL;
  unsigned char plain_block[len+16];

  /* Indicate MDP message type */
  mdp->packetTypeAndFlags=MDP_TX;
  
  switch(f->modifiers&OF_CRYPTO_BITS)  {
  case 0: 
    /* get payload */
    b=&f->payload->bytes[f->payload->position];
    mdp->packetTypeAndFlags|=MDP_NOCRYPT|MDP_NOSIGN;
    break;
  case OF_CRYPTO_CIPHERED:
    RETURN(WHY("decryption not implemented"));
  case OF_CRYPTO_SIGNED:
    {
      /* This call below will dispatch the request for the SAS if we don't
	 already have it.  In the meantime, we just drop the frame if the SAS
	 is not available. */
      if (!f->source->sas_valid){
	keyring_send_sas_request(f->source);
	RETURN(WHY("SAS key not currently on record, cannot verify"));
      }
      /* get payload and following compacted signature */
      b=&f->payload->bytes[f->payload->position];
      len=f->payload->sizeLimit - f->payload->position - crypto_sign_edwards25519sha512batch_BYTES;

      /* reconstitute signature by putting hash between two halves of signature */
      unsigned char signature[crypto_hash_sha512_BYTES
			      +crypto_sign_edwards25519sha512batch_BYTES];
      bcopy(&b[len],&signature[0],32);
      
      crypto_hash_sha512(&signature[32],b,len);
      if (0) dump("hash for verification",&signature[32],crypto_hash_sha512_BYTES);
      
      bcopy(&b[len+32],&signature[32+crypto_hash_sha512_BYTES],32);
      
      /* verify signature */
      unsigned char m[crypto_hash_sha512_BYTES];
      unsigned long long  mlen=0;
      int result
	=crypto_sign_edwards25519sha512batch_open(m,&mlen,
						  signature,sizeof(signature),
						  f->source->sas_public);
      if (result) {
	WHY("Signature verification failed");
	dump("data", b, len);
	dump("signature", signature, sizeof(signature));
	RETURN(-1);
      } else if (0) DEBUG("signature check passed");
    }    
    mdp->packetTypeAndFlags|=MDP_NOCRYPT; 
    break;
  case OF_CRYPTO_CIPHERED|OF_CRYPTO_SIGNED:
    {
      if (0) DEBUGF("crypted MDP frame for %s", alloca_tohex_sid(mdp->out.dst.sid));

      unsigned char *k=keyring_get_nm_bytes(mdp->out.dst.sid, mdp->out.src.sid);
      unsigned char *nonce=&f->payload->bytes[f->payload->position];
      int nb=crypto_box_curve25519xsalsa20poly1305_NONCEBYTES;
      int zb=crypto_box_curve25519xsalsa20poly1305_ZEROBYTES;
      if (!k) 
	RETURN(WHY("I don't have the private key required to decrypt that"));
      bzero(&plain_block[0],crypto_box_curve25519xsalsa20poly1305_ZEROBYTES-16);
      int cipher_len=f->payload->sizeLimit - f->payload->position - nb;
      bcopy(&f->payload->bytes[nb + f->payload->position],&plain_block[16],cipher_len);
      if (0) {
	dump("nm bytes",k,crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES);
	dump("nonce",nonce,crypto_box_curve25519xsalsa20poly1305_NONCEBYTES);
	dump("cipher block",&plain_block[16],cipher_len); 
      }
      if (crypto_box_curve25519xsalsa20poly1305_open_afternm
	  (plain_block,plain_block,cipher_len+16,nonce,k)) {
	RETURN(WHYF("crypto_box_open_afternm() failed (forged or corrupted packet of %d bytes)",cipher_len+16));
      }
      if (0) dump("plain block",&plain_block[zb],cipher_len-16);
      b=&plain_block[zb];
      len=cipher_len-16;
      break;
    }    
  }
  
  if (!b)
    RETURN(WHY("Failed to decode mdp payload"));
  
  int version=(b[0]<<8)+b[1];
  if (version!=0x0101) RETURN(WHY("Saw unsupported MDP frame version"));
  
  /* extract MDP port numbers */
  mdp->in.src.port=(b[2]<<24)+(b[3]<<16)+(b[4]<<8)+b[5];
  mdp->in.dst.port=(b[6]<<24)+(b[7]<<16)+(b[8]<<8)+b[9];
  if (0) DEBUGF("RX mdp dst.port=%d, src.port=%d", mdp->in.dst.port, mdp->in.src.port);  
  
  mdp->in.payload_length=len-10;
  bcopy(&b[10],&mdp->in.payload[0],mdp->in.payload_length);
  
  RETURN(0);
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
  
  /* Get source and destination addresses */
  if (f->destination)
    bcopy(f->destination->sid,mdp.in.dst.sid,SID_SIZE);
  else{
    // pack the broadcast address into the mdp structure
    memset(mdp.in.dst.sid, 0xFF, SID_SIZE - BROADCAST_LEN);
    bcopy(f->broadcast_id.id, mdp.in.dst.sid + SID_SIZE - BROADCAST_LEN, BROADCAST_LEN);
  }
  bcopy(f->source->sid,mdp.in.src.sid,SID_SIZE);

  /* copy crypto flags from frame so that we know if we need to decrypt or verify it */
  if (overlay_mdp_decrypt(f,&mdp))
    RETURN(-1);

  /* and do something with it! */
  RETURN(overlay_saw_mdp_frame(&mdp,now));
}

int overlay_mdp_swap_src_dst(overlay_mdp_frame *mdp)
{
  sockaddr_mdp temp;
  bcopy(&mdp->out.dst,&temp,sizeof(sockaddr_mdp));
  bcopy(&mdp->out.src,&mdp->out.dst,sizeof(sockaddr_mdp));
  bcopy(&temp,&mdp->out.src,sizeof(sockaddr_mdp));
  return 0;
}

int overlay_saw_mdp_frame(overlay_mdp_frame *mdp, time_ms_t now)
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

    if (debug & DEBUG_MDPREQUESTS) 
      DEBUGF("Received packet with listener (MDP ports: src=%s*:%d, dst=%d)",
	   alloca_tohex(mdp->out.src.sid, 7),
	   mdp->out.src.port,mdp->out.dst.port);

    // TODO pass in dest subscriber as an argument, we should know it by now
    struct subscriber *destination = NULL;
    if (!is_sid_broadcast(mdp->out.dst.sid)){
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
      switch(mdp->out.dst.port) {
      case MDP_PORT_VOMP:
	RETURN(vomp_mdp_received(mdp));
      case MDP_PORT_KEYMAPREQUEST:
	/* Either respond with the appropriate SAS, or record this one if it
	   verifies out okay. */
	if (debug & DEBUG_MDPREQUESTS)
	  DEBUG("MDP_PORT_KEYMAPREQUEST");
	RETURN(keyring_mapping_request(keyring,mdp));
      case MDP_PORT_DNALOOKUP: /* attempt to resolve DID to SID */
	{
	  int cn=0,in=0,kp=0;
	  char did[64+1];
	  int pll=mdp->out.payload_length;
	  if (pll>64) pll=64;
	  /* get did from the packet */
	  if (mdp->out.payload_length<1) {
	    RETURN(WHY("Empty DID in DNA resolution request")); }
	  bcopy(&mdp->out.payload[0],&did[0],pll);
	  did[pll]=0;
	  
	  if (debug & DEBUG_MDPREQUESTS)
	    DEBUG("MDP_PORT_DNALOOKUP");
	  
	  int results=0;
	  while(keyring_find_did(keyring,&cn,&in,&kp,did))
	    {
	      /* package DID and Name into reply (we include the DID because
		 it could be a wild-card DID search, but the SID is implied 
		 in the source address of our reply). */
	      if (keyring->contexts[cn]->identities[in]->keypairs[kp]->private_key_len > DID_MAXSIZE) 
		/* skip excessively long DID records */
		continue;
	      const unsigned char *packedSid = keyring->contexts[cn]->identities[in]->keypairs[0]->public_key;
	      const char *unpackedDid = (const char *) keyring->contexts[cn]->identities[in]->keypairs[kp]->private_key;
	      const char *name = (const char *)keyring->contexts[cn]->identities[in]->keypairs[kp]->public_key;
	      // URI is sid://SIDHEX/DID
	      strbuf b = strbuf_alloca(SID_STRLEN + DID_MAXSIZE + 10);
	      strbuf_puts(b, "sid://");
	      strbuf_tohex(b, packedSid, SID_SIZE);
	      strbuf_puts(b, "/local/");
	      strbuf_puts(b, unpackedDid);
	      overlay_mdp_dnalookup_reply(&mdp->out.src, packedSid, strbuf_str(b), unpackedDid, name);
	      kp++;
	      results++;
	    }
	  if (!results) {
	    /* No local results, so see if servald has been configured to use
	       a DNA-helper that can provide additional mappings.  This provides
	       a generalised interface for resolving telephone numbers into URIs.
	       The first use will be for resolving DIDs to SIP addresses for
	       OpenBTS boxes run by the OTI/Commotion project. 

	       The helper is run asynchronously, and the replies will be delivered
	       when results become available, so this function will return
	       immediately, so as not to cause blockages and delays in servald.
	    */
	    dna_helper_enqueue(mdp, did, mdp->out.src.sid);
	    monitor_tell_formatted(MONITOR_DNAHELPER, "LOOKUP:%s:%d:%s\n", alloca_tohex_sid(mdp->out.src.sid), mdp->out.src.port, did);
	  }
	  RETURN(0);
	}
	break;
      case MDP_PORT_ECHO: /* well known ECHO port for TCP/UDP and now MDP */
	{
	  /* Echo is easy: we swap the sender and receiver addresses (and thus port
	     numbers) and send the frame back. */

	  /* Swap addresses */
	  overlay_mdp_swap_src_dst(mdp);

	  /* Prevent echo:echo connections and the resulting denial of service from triggering endless pongs. */
	  if (mdp->out.dst.port==MDP_PORT_ECHO) {
	    RETURN(WHY("echo loop averted"));
	  }
	  /* If the packet was sent to broadcast, then replace broadcast address
	     with our local address. For now just responds with first local address */
	  if (is_sid_broadcast(mdp->out.src.sid))
	    {
	      if (my_subscriber)		  
		bcopy(my_subscriber->sid,
		      mdp->out.src.sid,SID_SIZE);
	      else
		/* No local addresses, so put all zeroes */
		bzero(mdp->out.src.sid,SID_SIZE);
	    }

	  /* queue frame for delivery */	  
	  overlay_mdp_dispatch(mdp,0 /* system generated */,
			       NULL,0);
	  
	  /* and switch addresses back around in case the caller was planning on
	     using MDP structure again (this happens if there is a loop-back reply
	     and the frame needs sending on, as happens with broadcasts.  MDP ping
	     is a simple application where this occurs). */
	  overlay_mdp_swap_src_dst(mdp);
	  
	}
	break;
      default:
	/* Unbound socket.  We won't be sending ICMP style connection refused
	   messages, partly because they are a waste of bandwidth. */
	RETURN(WHYF("Received packet for which no listening process exists (MDP ports: src=%d, dst=%d",
		    mdp->out.src.port,mdp->out.dst.port));
      }
    }
    break;
  default:
    RETURN(WHYF("We should only see MDP_TX frames here (MDP message type = 0x%x)",
		mdp->packetTypeAndFlags));
  }

  RETURN(0);
}

int overlay_mdp_dnalookup_reply(const sockaddr_mdp *dstaddr, const unsigned char *resolved_sid, const char *uri, const char *did, const char *name)
{
  overlay_mdp_frame mdpreply;
  bzero(&mdpreply, sizeof mdpreply);
  mdpreply.packetTypeAndFlags = MDP_TX; // outgoing MDP message
  memcpy(mdpreply.out.src.sid, resolved_sid, SID_SIZE);
  mdpreply.out.src.port = MDP_PORT_DNALOOKUP;
  bcopy(dstaddr, &mdpreply.out.dst, sizeof(sockaddr_mdp));
  /* build reply as TOKEN|URI|DID|NAME|<NUL> */
  strbuf b = strbuf_local((char *)mdpreply.out.payload, sizeof mdpreply.out.payload);
  strbuf_tohex(b, resolved_sid, SID_SIZE);
  strbuf_sprintf(b, "|%s|%s|%s|", uri, did, name);
  if (strbuf_overrun(b))
    return WHY("MDP payload overrun");
  mdpreply.out.payload_length = strbuf_len(b) + 1;
  /* deliver reply */
  return overlay_mdp_dispatch(&mdpreply, 0 /* system generated */, NULL, 0);
}

int overlay_mdp_check_binding(struct subscriber *subscriber, int port, int userGeneratedFrameP,
			      struct sockaddr_un *recvaddr, int recvaddrlen)
{

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

  /* Check for build-in port listeners */
  if (!userGeneratedFrameP){
    switch(port) {
    case MDP_PORT_NOREPLY:
    case MDP_PORT_ECHO:
    case MDP_PORT_KEYMAPREQUEST:
    case MDP_PORT_VOMP:
    case MDP_PORT_DNALOOKUP:
      return 0;
    }
  }

  return WHYF("No such binding: recvaddr=%p %s addr=%s port=%u (0x%x) -- possible spoofing attack",
	recvaddr,
	recvaddr ? alloca_toprint(-1, recvaddr->sun_path, recvaddrlen - sizeof(short)) : "",
	alloca_tohex_sid(subscriber->sid),
	port, port
      );
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
  IN();

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
  frame->ttl=64; /* normal TTL (XXX allow setting this would be a good idea) */	
  
  if (!frame->destination || frame->destination->reachable == REACHABLE_SELF)
    {
      /* Packet is addressed such that we should process it. */
      overlay_saw_mdp_frame(mdp,gettime_ms());
      if (frame->destination) {
	/* Is local, and is not broadcast, so shouldn't get sent out
	   on the wire. */
	op_free(frame);
	RETURN(0);
      }
    }
  
  /* give voice packets priority */
  if (mdp->out.dst.port==MDP_PORT_VOMP) frame->type=OF_TYPE_DATA_VOICE;
  else frame->type=OF_TYPE_DATA;
  frame->prev=NULL;
  frame->next=NULL;
  frame->payload=ob_new();
  
  int fe=0;

  /* Work out the disposition of the frame->  For now we are only worried
     about the crypto matters, and not compression that may be applied
     before encryption (since applying it after is useless as ciphered
     text should have maximum entropy). */
  switch(mdp->packetTypeAndFlags&(MDP_NOCRYPT|MDP_NOSIGN)) {
  case 0: /* crypted and signed (using CryptoBox authcryption primitive) */
    frame->modifiers=OF_CRYPTO_SIGNED|OF_CRYPTO_CIPHERED;
    /* Prepare payload */
    ob_makespace(frame->payload, 
	   1 // frame type (MDP)
	  +1 // MDP version 
	  +4 // dst port 
	  +4 // src port 
	  +crypto_box_curve25519xsalsa20poly1305_NONCEBYTES
	  +crypto_box_curve25519xsalsa20poly1305_ZEROBYTES
	  +mdp->out.payload_length);
    {
      /* write cryptobox nonce */
      unsigned char nonce[crypto_box_curve25519xsalsa20poly1305_NONCEBYTES];
      if (urandombytes(nonce,crypto_box_curve25519xsalsa20poly1305_NONCEBYTES)) {
	op_free(frame);
	RETURN(WHY("urandombytes() failed to generate nonce"));
      }
      fe|= ob_append_bytes(frame->payload,nonce,crypto_box_curve25519xsalsa20poly1305_NONCEBYTES);
      /* generate plain message with zero bytes and get ready to cipher it */
      unsigned char plain[crypto_box_curve25519xsalsa20poly1305_ZEROBYTES
			  +10+mdp->out.payload_length];
      /* zero bytes */
      int zb=crypto_box_curve25519xsalsa20poly1305_ZEROBYTES;
      bzero(&plain[0],zb);
      /* MDP version 1 */
      plain[zb+0]=0x01; 
      plain[zb+1]=0x01;
      /* Ports */
      plain[zb+2]=(mdp->out.src.port>>24)&0xff;
      plain[zb+3]=(mdp->out.src.port>>16)&0xff;
      plain[zb+4]=(mdp->out.src.port>>8)&0xff;
      plain[zb+5]=(mdp->out.src.port>>0)&0xff;
      plain[zb+6]=(mdp->out.dst.port>>24)&0xff;
      plain[zb+7]=(mdp->out.dst.port>>16)&0xff;
      plain[zb+8]=(mdp->out.dst.port>>8)&0xff;
      plain[zb+9]=(mdp->out.dst.port>>0)&0xff;
      /* payload */
      bcopy(&mdp->out.payload,&plain[zb+10],mdp->out.payload_length);
      int cipher_len=zb+10+mdp->out.payload_length;
      
      /* get pre-computed PKxSK bytes (the slow part of auth-cryption that can be
	 retained and reused, and use that to do the encryption quickly. */
      unsigned char *k=keyring_get_nm_bytes(mdp->out.src.sid, mdp->out.dst.sid);
      if (!k) {
	op_free(frame);
	RETURN(WHY("could not compute Curve25519(NxM)")); 
      }
      /* Get pointer to place in frame where the ciphered text needs to go */
      int cipher_offset=frame->payload->position;
      unsigned char *cipher_text=ob_append_space(frame->payload,cipher_len);
      if (fe||(!cipher_text)){
	op_free(frame);
	RETURN(WHY("could not make space for ciphered text")); 
      }
      /* Actually authcrypt the payload */
      if (crypto_box_curve25519xsalsa20poly1305_afternm
	  (cipher_text,plain,cipher_len,nonce,k)){
	op_free(frame);
	RETURN(WHY("crypto_box_afternm() failed")); 
      }
      /* now shuffle down 16 bytes to get rid of the temporary space that crypto_box
	 uses. */
      bcopy(&cipher_text[16],&cipher_text[0],cipher_len-16);
      frame->payload->position-=16;
      if (0) {
	DEBUG("authcrypted mdp frame");
	dump("nm bytes",k,crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES);
	dump("nonce",nonce,crypto_box_curve25519xsalsa20poly1305_NONCEBYTES);
	dump("plain text",&plain[16],cipher_len-16);
	dump("cipher text",cipher_text,cipher_len-16);	
	DEBUGF("frame->payload->length=%d,cipher_len-16=%d,cipher_offset=%d", frame->payload->position,cipher_len-16,cipher_offset);
	dump("frame",&frame->payload->bytes[0],
	     frame->payload->position);
      }
    }
    break;
  case MDP_NOCRYPT: 
    /* Payload is sent unencrypted, but signed.

       To save space we do a trick where we hash the payload, and get the 
       signature of that, but do not send the hash itself, since that can
       be reproduced (and indeed must be for verification) at the receiver's
       end.

       As the signing key is implicit, and the hash is also implicit, we can
       chop out part of the signature and thus save some bytes.
    */
    frame->modifiers=OF_CRYPTO_SIGNED; 
    /* Prepare payload */
    ob_makespace(frame->payload,
	1 // frame type (MDP) 
	+1 // MDP version 
	+4 // dst port 
	+4 // src port 
	+crypto_sign_edwards25519sha512batch_BYTES
	+mdp->out.payload_length);
    {
      unsigned char *key=keyring_find_sas_private(keyring, frame->source->sid, NULL);
      if (!key) {
	op_free(frame);
	RETURN(WHY("could not find signing key"));
      }
      
      /* Build plain-text that includes header and hash it so that
         we can sign that hash. */
      unsigned char hash[crypto_hash_sha512_BYTES];
      int plain_len = 10+mdp->out.payload_length;
      unsigned char *plain = frame->payload->bytes + frame->payload->position;
      
      if (!plain)
	return WHY("Unable to allocate space for payload and signature");
      
      /* MDP version 1 */
      ob_append_byte(frame->payload,0x01);
      ob_append_byte(frame->payload,0x01);
      /* Destination port */
      ob_append_ui32(frame->payload,mdp->out.src.port);
      ob_append_ui32(frame->payload,mdp->out.dst.port);
      ob_append_bytes(frame->payload,mdp->out.payload,mdp->out.payload_length);
      
      /* now hash it */
      crypto_hash_sha512(hash,plain,plain_len);
      
      unsigned char signature[crypto_hash_sha512_BYTES
			      +crypto_sign_edwards25519sha512batch_BYTES];
      unsigned long long  sig_len=0;
      crypto_sign_edwards25519sha512batch(signature,&sig_len,
					  hash,crypto_hash_sha512_BYTES,
					  key);
      if (!sig_len) {
	op_free(frame);
	RETURN(WHY("Signing MDP frame failed"));
      }
      
      if (0){
	dump("payload", plain, plain_len);
	dump("signature", signature, sizeof(signature));
      }
      /* chop hash out of middle of signature since it has to be recomputed
	 at the far end, anyway, and ammend the two halves of the signature. */
      ob_append_bytes(frame->payload,&signature[0],32);
      ob_append_bytes(frame->payload,&signature[32+crypto_hash_sha512_BYTES],32);
    }
    break;
  case MDP_NOSIGN|MDP_NOCRYPT: /* clear text and no signature */
    frame->modifiers=0; 
    /* Copy payload body in */
    ob_makespace(frame->payload, 
	   1 // frame type (MDP) 
	  +1 // MDP version 
	  +4 // dst port 
	  +4 // src port 
	  +mdp->out.payload_length);
    /* MDP version 1 */
    ob_append_byte(frame->payload,0x01);
    ob_append_byte(frame->payload,0x01);
    /* Destination port */
    ob_append_ui32(frame->payload,mdp->out.src.port);
    ob_append_ui32(frame->payload,mdp->out.dst.port);
    ob_append_bytes(frame->payload,mdp->out.payload,mdp->out.payload_length);
    break;
  case MDP_NOSIGN: 
  default:
    /* ciphered, but not signed.
     This means we don't use CryptoBox, but rather a more compact means
     of representing the ciphered stream segment.
     */
    op_free(frame);
    RETURN(WHY("Not implemented"));
    break;
  }
  
  // TODO include priority in packet header
  int qn=OQ_ORDINARY;
  /* Make sure voice traffic gets priority */
  if ((frame->type&OF_TYPE_BITS)==OF_TYPE_DATA_VOICE) {
    qn=OQ_ISOCHRONOUS_VOICE;
    rhizome_saw_voice_traffic();
  }
  
  frame->send_copies = mdp->out.send_copies;
  
  if (overlay_payload_enqueue(qn, frame))
    op_free(frame);
  RETURN(0);
}

static int search_subscribers(struct subscriber *subscriber, void *context){
  overlay_mdp_addrlist *response = context;
  
  if (response->mode == MDP_ADDRLIST_MODE_SELF && subscriber->reachable != REACHABLE_SELF){
    return 0;
  }
  
  if (response->mode == MDP_ADDRLIST_MODE_ROUTABLE_PEERS && 
      (subscriber->reachable != REACHABLE_DIRECT && 
       subscriber->reachable != REACHABLE_INDIRECT && 
       subscriber->reachable != REACHABLE_UNICAST)){
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
  if (debug & DEBUG_MDPREQUESTS)
    DEBUGF("MDP_GETADDRS first_sid=%u mode=%d",
	   request->first_sid,
	   request->mode
	   );
  
  /* Prepare reply packet */
  response->mode = request->mode;
  response->first_sid = request->first_sid;
  response->frame_sid_count = 0;
  
  /* ... and constrain list for sanity */
  if (response->first_sid<0) response->first_sid=0;
  
  /* Populate with SIDs */
  enum_subscribers(NULL, search_subscribers, response);
  
  response->last_sid = response->first_sid + response->frame_sid_count - 1;
  
  if (debug & DEBUG_MDPREQUESTS)
    DEBUGF("reply MDP_ADDRLIST first_sid=%u last_sid=%u frame_sid_count=%u server_sid_count=%u",
	   response->first_sid,
	   response->last_sid,
	   response->frame_sid_count,
	   response->server_sid_count
	   );
  return 0;
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
	if (debug & DEBUG_MDPREQUESTS) DEBUG("MDP_GOODBYE");
	overlay_mdp_releasebindings(recvaddr_un,recvaddrlen);
	return;
	  
      /* Deprecated. We can replace with a more generic dump of the routing table */
      case MDP_NODEINFO:
	if (debug & DEBUG_MDPREQUESTS) DEBUG("MDP_NODEINFO");
	  
	if (!overlay_route_node_info(&mdp->nodeinfo))
	  overlay_mdp_reply(mdp_named.poll.fd,recvaddr_un,recvaddrlen,mdp);
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
	if (debug & DEBUG_MDPREQUESTS) DEBUG("MDP_TX");
	overlay_mdp_dispatch(mdp,1,(struct sockaddr_un*)recvaddr,recvaddrlen);
	return;
	break;
	  
      case MDP_BIND: /* Bind to port */
	{
	  if (debug & DEBUG_MDPREQUESTS) DEBUG("MDP_BIND");
	  
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

