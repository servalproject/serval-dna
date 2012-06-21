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

#include "serval.h"
#include <sys/stat.h>

int mdp_abstract_socket=-1;
int mdp_named_socket=-1;
int overlay_mdp_setup_sockets()
{
  struct sockaddr_un name;
  int len;
  
  name.sun_family = AF_UNIX;
  
#ifndef HAVE_LINUX_IF_H
  /* Abstrack name space (i.e., non-file represented) unix domain sockets are a
     linux-only thing. */
  mdp_abstract_socket = -1;
#else
  if (mdp_abstract_socket==-1) {
    /* Abstract name space unix sockets is a special Linux thing, which is
       convenient for us because Android is Linux, but does not have a shared
       writable path that is on a UFS partition, so we cannot use traditional
       named unix domain sockets. So the abstract name space gives us a solution. */
    name.sun_path[0]=0;
    /* XXX The 100 should be replaced with the actual maximum allowed.
       Apparently POSIX requires it to be at least 100, but I would still feel
       more comfortable with using the appropriate constant. */
    snprintf(&name.sun_path[1],100,"org.servalproject.mesh.overlay.mdp");
    len = 1+strlen(&name.sun_path[1]) + sizeof(name.sun_family);
    
    mdp_abstract_socket = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (mdp_abstract_socket>-1) {
      int dud=0;
      int reuseP=1;
      if(setsockopt( mdp_abstract_socket, SOL_SOCKET, SO_REUSEADDR, 
		     &reuseP, sizeof(reuseP)) < 0)
	{
	  WARN_perror("setsockopt");
	  WARN("Could not indicate reuse addresses. Not necessarily a problem (yet)");
	}
      int r=bind(mdp_abstract_socket, (struct sockaddr *)&name, len);
      if (r) {
	WARN_perror("bind");
	dud=1;
	r=0;
	WARN("bind() of abstract name space socket failed (not an error on non-linux systems");
      }
      if (dud) {
	close(mdp_abstract_socket);
	mdp_abstract_socket=-1;
	WHY("Could not open abstract name-space socket (only a problem on Linux).");
      }
      
      int send_buffer_size=64*1024;    
      int res = setsockopt(mdp_abstract_socket, SOL_SOCKET, SO_SNDBUF, 
		       &send_buffer_size, sizeof(send_buffer_size));
    } 
  }
#endif
  if (mdp_named_socket==-1) {
    if (!form_serval_instance_path(&name.sun_path[0], 100, "mdp.socket")) {
      return WHY("Cannot construct name of unix domain socket.");
    }
    unlink(&name.sun_path[0]);
    len = 0+strlen(&name.sun_path[0]) + sizeof(name.sun_family)+1;
    mdp_named_socket = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (mdp_named_socket>-1) {
      int dud=0;
      int reuseP=1;
      if(setsockopt( mdp_named_socket, SOL_SOCKET, SO_REUSEADDR, 
		     &reuseP, sizeof(reuseP)) < 0)
	{
	  WARN_perror("setsockopt");
	  WARN("Could not indicate reuse addresses. Not necessarily a problem (yet)");
	}
      int r=bind(mdp_named_socket, (struct sockaddr *)&name, len);
      if (r) { dud=1; r=0; WHY("bind() of named unix domain socket failed"); }
      if (dud) {
	close(mdp_named_socket);
	mdp_named_socket=-1;
	WHY("Could not open named unix domain socket.");
      }

      int send_buffer_size=64*1024;    
      int res = setsockopt(mdp_named_socket, SOL_SOCKET, SO_RCVBUF, 
		       &send_buffer_size, sizeof(send_buffer_size));
      if (res)
	WHY_perror("setsockopt");
    }
  }

  return 0;
  
}

int overlay_mdp_get_fds(struct pollfd *fds,int *fdcount,int fdmax)
{
  /* Make sure sockets are open */
  overlay_mdp_setup_sockets();

  if ((*fdcount)>=fdmax) return -1;
  if (mdp_abstract_socket>-1)
    {
      if (debug&DEBUG_IO) {
	fprintf(stderr,"MDP abstract name space socket is poll() slot #%d (fd %d)\n",
		*fdcount,mdp_abstract_socket);
      }
      fds[*fdcount].fd=mdp_abstract_socket;
      fds[*fdcount].events=POLLIN;
      (*fdcount)++;
    }
  if ((*fdcount)>=fdmax) return -1;
  if (mdp_named_socket>-1)
    {
      if (debug&DEBUG_IO) {
	fprintf(stderr,"MDP named unix domain socket is poll() slot #%d (fd %d)\n",
		*fdcount,mdp_named_socket);
      }
      fds[*fdcount].fd=mdp_named_socket;
      fds[*fdcount].events=POLLIN;
      (*fdcount)++;
    }


  return 0;
}

#define MDP_MAX_BINDINGS 100
#define MDP_MAX_SOCKET_NAME_LEN 110
int mdp_bindings_initialised=0;
sockaddr_mdp mdp_bindings[MDP_MAX_BINDINGS];
char mdp_bindings_sockets[MDP_MAX_BINDINGS][MDP_MAX_SOCKET_NAME_LEN];
int mdp_bindings_socket_name_lengths[MDP_MAX_BINDINGS];
unsigned long long mdp_bindings_time[MDP_MAX_BINDINGS];

int overlay_mdp_reply_error(int sock,
			    struct sockaddr_un *recvaddr,int recvaddrlen,
			    int error_number,char *message)
{
  overlay_mdp_frame mdpreply;

  mdpreply.packetTypeAndFlags=MDP_ERROR;
  mdpreply.error.error=error_number;
  if (error_number==0||message)
    snprintf(&mdpreply.error.message[0],128,"%s",message?message:"Success");
  else
    snprintf(&mdpreply.error.message[0],128,"Error code #%d",error_number);
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
    if (mdp_bindings_socket_name_lengths[i]==recvaddrlen)
      if (!memcmp(mdp_bindings_sockets[i],recvaddr->sun_path,recvaddrlen))
	mdp_bindings[i].port=0;

  return 0;

}

int overlay_mdp_process_bind_request(int sock,overlay_mdp_frame *mdp,
				     struct sockaddr_un *recvaddr,int recvaddrlen)
{
  int i;
  if (!mdp_bindings_initialised) {
    /* Mark all slots as unused */
    for(i=0;i<MDP_MAX_BINDINGS;i++) mdp_bindings[i].port=0;
    mdp_bindings_initialised=1;
  }

//  DEBUG("Doesn't authenticate source address on multi-SID installations like an OpenBTS:mesh gateway)");
  
  /* Make sure source address is either all zeros (listen on all), or a valid
     local address */
  for(i=0;i<SID_SIZE;i++) if (mdp->bind.sid[i]) break;
  if (i<SID_SIZE) {
    /* Not all zeroes, so make sure it is a valid SID */
    int ok=0;
    if (overlay_address_is_local(mdp->bind.sid)) ok=1;
    if (!ok) {
      /* Source address is invalid */
      return overlay_mdp_reply_error(sock,recvaddr,recvaddrlen,7,
				     "Bind address is not valid (must be a local MDP address, or all zeroes).");
    }
  }

  /* See if binding already exists */
  int found=-1;
  int free=-1;
  for(i=0;i<MDP_MAX_BINDINGS;i++) {
    /* Look for duplicate bindings */
    if (mdp_bindings[i].port==mdp->bind.port_number)
      if (!memcmp(mdp_bindings[i].sid,mdp->bind.sid,SID_SIZE))
	{ found=i; break; }
    /* Look for free slots in case we need one */
    if ((free==-1)&&(mdp_bindings[i].port==0)) free=i;
  }
 
  /* Binding was found.  See if it is us, if so, then all is well,
     else we check flags to see if we should override the existing binding. */
  if (found>-1) {
    if (mdp_bindings_socket_name_lengths[found]==recvaddrlen)
      if (!memcmp(mdp_bindings_sockets[found],recvaddr->sun_path,recvaddrlen))
	{
	  INFO("Identical binding exists");
	  DEBUG("Need to return binding information to client");
	  return overlay_mdp_reply_ok(sock,recvaddr,recvaddrlen,"Port bound (actually, it was already bound to you)");
	}
    /* Okay, so there is an existing binding.  Either replace it (if requested) or
       return an error */
    if (!(mdp->packetTypeAndFlags&MDP_FORCE))
      {
	fprintf(stderr,"Port already in use.\n");
	return overlay_mdp_reply_error(sock,recvaddr,recvaddrlen,3,
				       "Port already in use");
      }
    else {
      /* Cause existing binding to be replaced.
	 XXX - We should notify the existing binding holder that their binding
	 has been snaffled. */
      DEBUG("Warn socket holder about port-snatch");
      free=found;
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
    mdp_bindings[free].port=0;
  }

  /* Okay, record binding and report success */
  mdp_bindings[free].port=mdp->bind.port_number;
  memcpy(&mdp_bindings[free].sid[0],&mdp->bind.sid[0],SID_SIZE);
  mdp_bindings_socket_name_lengths[free]=recvaddrlen-2;
  memcpy(&mdp_bindings_sockets[free][0],&recvaddr->sun_path[0],
	 mdp_bindings_socket_name_lengths[free]);
  mdp_bindings_time[free]=overlay_gettime_ms();
  return overlay_mdp_reply_ok(sock,recvaddr,recvaddrlen,"Port bound");
}

int overlay_saw_mdp_containing_frame(int interface,overlay_frame *f,long long now)
{
  /* Take frame source and destination and use them to populate mdp->in->{src,dst}
     SIDs.
     Take ports from mdp frame itself.
     Take payload from mdp frame itself.
  */
  overlay_mdp_frame mdp;

  /* Get source and destination addresses */
  bcopy(&f->destination[0],&mdp.in.dst.sid[0],SID_SIZE);
  bcopy(&f->source[0],&mdp.in.src.sid[0],SID_SIZE);

  int len=f->payload->length;
  unsigned char *b = NULL;
  unsigned char plain_block[len+16];

  if (len<10) return WHY("Invalid MDP frame");

  /* copy crypto flags from frame so that we know if we need to decrypt or verify it */
  switch(f->modifiers&OF_CRYPTO_BITS)  {
  case 0: 
    /* get payload */
    b=&f->payload->bytes[0];
    len=f->payload->length;
    mdp.packetTypeAndFlags|=MDP_NOCRYPT|MDP_NOSIGN; break;    
  case OF_CRYPTO_CIPHERED:
    return WHY("decryption not implemented");
    mdp.packetTypeAndFlags|=MDP_NOSIGN; break;
  case OF_CRYPTO_SIGNED:
    {
      /* This call below will dispatch the request for the SAS if we don't
	 already have it.  In the meantime, we just drop the frame if the SAS
	 is not available. */
      unsigned char *key=keyring_find_sas_public(keyring,mdp.out.src.sid);
      if (!key) return WHY("SAS key not currently on record, so cannot verify");

      /* get payload and following compacted signature */
      b=&f->payload->bytes[0];
      len=f->payload->length-crypto_sign_edwards25519sha512batch_BYTES;

      /* get hash */
      unsigned char hash[crypto_hash_sha512_BYTES];
      crypto_hash_sha512(hash,b,len);

      /* reconstitute signature by putting hash between two halves of signature */
      unsigned char signature[crypto_hash_sha512_BYTES
			      +crypto_sign_edwards25519sha512batch_BYTES];
      bcopy(&b[len],&signature[0],32);
      crypto_hash_sha512(&signature[32],b,len);
      if (0) dump("hash for verification",hash,crypto_hash_sha512_BYTES);
      bcopy(&b[len+32],&signature[32+crypto_hash_sha512_BYTES],32);
      
      /* verify signature */
      unsigned char m[crypto_hash_sha512_BYTES];
      unsigned long long  mlen=0;
      int result
	=crypto_sign_edwards25519sha512batch_open(m,&mlen,
						  signature,sizeof(signature),
						  key);
      if (result) return WHY("Signature verification failed: incorrect signature");
      else if (0) DEBUG("signature check passed");
    }    
    mdp.packetTypeAndFlags|=MDP_NOCRYPT; break;
  case OF_CRYPTO_CIPHERED|OF_CRYPTO_SIGNED:
    {
      if (0) {
	fflush(stderr);
	printf("crypted MDP frame for %s\n",
	       overlay_render_sid(mdp.out.dst.sid));
	fflush(stdout);
      }

      unsigned char *k=keyring_get_nm_bytes(&mdp.out.dst,&mdp.out.src);
      unsigned char *nonce=&f->payload->bytes[0];
      int nb=crypto_box_curve25519xsalsa20poly1305_NONCEBYTES;
      int zb=crypto_box_curve25519xsalsa20poly1305_ZEROBYTES;
      if (!k) return WHY("I don't have the private key required to decrypt that");
      bzero(&plain_block[0],crypto_box_curve25519xsalsa20poly1305_ZEROBYTES-16);
      int cipher_len=f->payload->length-nb;
      bcopy(&f->payload->bytes[nb],&plain_block[16],cipher_len);
      if (0) {
	dump("nm bytes",k,crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES);
	dump("nonce",nonce,crypto_box_curve25519xsalsa20poly1305_NONCEBYTES);
	dump("cipher block",&plain_block[16],cipher_len); 
      }
      if (crypto_box_curve25519xsalsa20poly1305_open_afternm
	  (plain_block,plain_block,cipher_len+16,nonce,k))
	return WHYF("crypto_box_open_afternm() failed (forged or corrupted packet of %d bytes)",cipher_len+16);
      if (0) dump("plain block",&plain_block[zb],cipher_len-16);
      b=&plain_block[zb];
      len=cipher_len-16;
      break;
    }    
  }

  int version=(b[0]<<8)+b[1];
  if (version!=0x0101) return WHY("Saw unsupported MDP frame version");

  /* Indicate MDP message type */
  mdp.packetTypeAndFlags=MDP_TX;

  /* extract MDP port numbers */
  mdp.in.src.port=(b[2]<<24)+(b[3]<<16)+(b[4]<<8)+b[5];
  mdp.in.dst.port=(b[6]<<24)+(b[7]<<16)+(b[8]<<8)+b[9];
  if (0) fprintf(stderr,
	  "RX mdp dst.port=%d, src.port=%d\n",mdp.in.dst.port,mdp.in.src.port);  

  mdp.in.payload_length=len-10;
  bcopy(&b[10],&mdp.in.payload[0],mdp.in.payload_length);

  /* and do something with it! */
  return overlay_saw_mdp_frame(interface,&mdp,now);
}

int overlay_mdp_swap_src_dst(overlay_mdp_frame *mdp)
{
  sockaddr_mdp temp;
  bcopy(&mdp->out.dst,&temp,sizeof(sockaddr_mdp));
  bcopy(&mdp->out.src,&mdp->out.dst,sizeof(sockaddr_mdp));
  bcopy(&temp,&mdp->out.src,sizeof(sockaddr_mdp));
  return 0;
}

int overlay_saw_mdp_frame(int interface, overlay_mdp_frame *mdp,long long now)
{
  int i;
  int match=-1;

  switch(mdp->packetTypeAndFlags&MDP_TYPE_MASK) {
  case MDP_TX: 
    /* Regular MDP frame addressed to us.  Look for matching port binding,
       and if available, push to client.  Else do nothing, or if we feel nice
       send back a connection refused type message? Silence is probably the
       more prudent path.
    */
    if ((!overlay_address_is_local(mdp->out.dst.sid))
	&&(!overlay_address_is_broadcast(mdp->out.dst.sid)))
      {
	return WHY("Asked to process an MDP packet that was not addressed to this node.");
      }
    
    for(i=0;i<MDP_MAX_BINDINGS;i++)
      {
	if (!memcmp(&mdp->out.dst,&mdp_bindings[i],sizeof(sockaddr_mdp)))
	  { /* exact and specific match, so stop searching */
	    match=i; break; }
	else {
	  /* No exact match, so see if the port matches, and local-side address
	     is the anonymous address (all zeroes), the destination address is
	     a local address, and the ports match.  This is to find matches to
	     the mdp equivalent of a socket bound to 0.0.0.0:port in IPv4.

	     Just as with the IPv4 situation, we prioritise ports that are listening
	     on a specific address over those with no address bound.  Thus we only
	     try to match these 0.0.0.0 style bindings if there is no specific
	     binding, and we keep looking in case there is a more specific binding.
	     
	     Because there is no concept of sub-nets in the Serval overlay mesh
	     (since addresses are randomly allocated from the entire address
	     space), we don't have to worry about a more structured heirarchy where
	     more completely specified addresses take priority over less completely
	     specified addresses.
	  */
	  if (match==-1)
	    if (mdp->out.dst.port==mdp_bindings[i].port)
		{
		  int j;
		  for(j=0;j<SID_SIZE;j++) if (mdp_bindings[i].sid[j]) break; 
		  if (j==SID_SIZE) match=i;
		}
	}
      }
    if (match>-1) {      
      struct sockaddr_un addr;
      printf("unix domain socket '%s'\n",mdp_bindings_sockets[match]);
      bcopy(mdp_bindings_sockets[match],&addr.sun_path[0],mdp_bindings_socket_name_lengths[match]);
      addr.sun_family=AF_UNIX;
      errno=0;
      int len=overlay_mdp_relevant_bytes(mdp);
      int r=sendto(mdp_named_socket,mdp,len,0,(struct sockaddr*)&addr,sizeof(addr));
      if (r==overlay_mdp_relevant_bytes(mdp)) {	
	return 0;
      }
      if (errno==ENOENT) {
	/* far-end of socket has died, so drop binding */
	printf("Closing dead MDP client '%s'\n",mdp_bindings_sockets[match]);
	overlay_mdp_releasebindings(&addr,mdp_bindings_socket_name_lengths[match]);
      }
      WHY_perror("sendto(e)");
      return WHY("Failed to pass received MDP frame to client");
    } else {
      /* No socket is bound, ignore the packet ... except for magic sockets */
      switch(mdp->out.dst.port) {
      case MDP_PORT_VOMP:
	return vomp_mdp_received(mdp);
      case MDP_PORT_KEYMAPREQUEST:
	/* Either respond with the appropriate SAS, or record this one if it
	   verfies out okay. */
	DEBUG("key mapping request");
	return keyring_mapping_request(keyring,mdp);
      case MDP_PORT_DNALOOKUP: /* attempt to resolve DID to SID */
	{
	  int cn=0,in=0,kp=0;
	  char did[64+1];
	  int pll=mdp->out.payload_length;
	  if (pll>64) pll=64;
	  /* get did from the packet */
	  if (mdp->out.payload_length<1)
	    return WHY("Empty DID in DNA resolution request");
	  bcopy(&mdp->out.payload[0],&did[0],pll);
	  /* make sure it is null terminated */
	  did[pll]=0; 
	  /* remember source sid for putting back later */
	  overlay_mdp_frame mdpreply;

	  int results=0;
	  while(keyring_find_did(keyring,&cn,&in,&kp,did))
	    {
	      bzero(&mdpreply,sizeof(mdpreply));

	      /* mark as outgoing MDP message */
	      mdpreply.packetTypeAndFlags=MDP_TX;
	      
	      /* Set source and destination addresses */
	      bcopy(&mdp->out.dst.sid,mdpreply.out.src.sid,SID_SIZE);
	      bcopy(&mdp->out.src.sid,mdpreply.out.dst.sid,SID_SIZE);
	      mdpreply.out.src.port=mdp->out.dst.port;
	      mdpreply.out.dst.port=mdp->out.src.port;

	      /* package DID and Name into reply (we include the DID because
		 it could be a wild-card DID search, but the SID is implied 
		 in the source address of our reply). */
	      if (keyring->contexts[cn]->identities[in]->keypairs[kp]
		  ->private_key_len>64) 
		/* skip excessively long DID records */
		continue;
	      /* and null-terminated DID */
	      unsigned char *unpackedDid=
		keyring->contexts[cn]->identities[in]->keypairs[kp]
		->private_key;
	      unsigned char *packedSid=
		keyring->contexts[cn]->identities[in]->keypairs[0]
		->public_key;
	      char *name=
		(char *)keyring->contexts[cn]->identities[in]->keypairs[kp]
		->public_key;
	      /* copy SID out into source address of frame */	      
	      bcopy(packedSid,&mdpreply.out.src.sid[0],SID_SIZE);
	      /* and build reply as did\nname\nURI<NUL> */
	      snprintf((char *)&mdpreply.out.payload[0],512,"%s\n%s\nsid://%s/%s",
		       unpackedDid,name,overlay_render_sid(packedSid),
		       unpackedDid);
	      mdpreply.out.payload_length=strlen((char *)mdpreply.out.payload)+1;
	      
	      /* deliver reply */
	      overlay_mdp_dispatch(&mdpreply,0 /* system generated */,NULL,0);
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
	    dna_helper_enqueue(did,mdp->out.src.sid);
	  }
	  return 0;
	}
	break;
      case MDP_PORT_ECHO: /* well known ECHO port for TCP/UDP and now MDP */
	{
	  /* Echo is easy: we swap the sender and receiver addresses (and thus port
	     numbers) and send the frame back. */

	  /* Swap addresses */
	  overlay_mdp_swap_src_dst(mdp);

	  if (mdp->out.dst.port==MDP_PORT_ECHO) return WHY("echo loop averted");
	  /* If the packet was sent to broadcast, then replace broadcast address
	     with our local address. For now just responds with first local address */
	  if (overlay_address_is_broadcast(mdp->out.src.sid))
	    {
	      if (keyring->contexts[0]->identity_count&&
		  keyring->contexts[0]->identities[0]->keypair_count&&
		  keyring->contexts[0]->identities[0]->keypairs[0]->type
		  ==KEYTYPE_CRYPTOBOX)		  
		bcopy(keyring->contexts[0]->identities[0]->keypairs[0]->public_key,
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
	return WHYF("Received packet for which no listening process exists (MDP ports: src=%d, dst=%d",
		    mdp->out.src.port,mdp->out.dst.port);
      }
    }
    break;
  default:
    return WHYF("We should only see MDP_TX frames here (MDP message type = 0x%x)",
		mdp->packetTypeAndFlags);
  }

  return WHY("Not implemented");
}

int overlay_mdp_sanitytest_sourceaddr(sockaddr_mdp *src,int userGeneratedFrameP,
				      struct sockaddr_un *recvaddr,
				      int recvaddrlen)
{
  if (overlay_address_is_broadcast(src->sid))
    {
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
      return WHY("Packet had broadcast address as source address");
    }
  
  /* Now make sure that source address is in the list of bound addresses,
     and that the recvaddr matches. */
  int i;
  for(i=0;i<MDP_MAX_BINDINGS;i++)
    {
      if (!memcmp(src,&mdp_bindings[i],sizeof(sockaddr_mdp)))
	{
	  /* Binding matches, now make sure the sockets match */
	  if (mdp_bindings_socket_name_lengths[i]==(recvaddrlen-sizeof(short)))
	      if (!memcmp(mdp_bindings_sockets[i],recvaddr->sun_path,
			  recvaddrlen-sizeof(short)))
	      {
		/* Everything matches, so this unix socket and MDP address 
		   combination is valid */
		return 0;
	      }
	}
    }

  /* Check for build-in port listeners */
  if (overlay_address_is_local(src->sid)) {
    switch(src->port) {
    case MDP_PORT_ECHO:
      /* we don't allow user/network generated packets claiming to
	 be from the echo port, largely to prevent echo:echo connections
	 and the resulting denial of service from triggering endless pongs. */
      if (!userGeneratedFrameP) return 0; 
      break;
      /* other built-in listeners */
    case MDP_PORT_KEYMAPREQUEST:
    case MDP_PORT_VOMP:
    case MDP_PORT_DNALOOKUP:
      return 0;
    default:
      break;
    }      
  } 

  printf("addr=%s port=%u (0x%x)\n",
	 overlay_render_sid(src->sid),src->port,src->port);
  if (recvaddr) printf("recvaddr='%s'\n",
	 recvaddr->sun_path);
  return WHY("No such socket binding:unix domain socket tuple exists -- someone might be trying to spoof someone else's connection");
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
  /* Work out if destination is broadcast or not */
  int broadcast=1;
  
  if (overlay_mdp_sanitytest_sourceaddr(&mdp->out.src,userGeneratedFrameP,
					recvaddr,recvaddrlen))
    return overlay_mdp_reply_error
      (mdp_named_socket,
       (struct sockaddr_un *)recvaddr,
       recvaddrlen,8,
       "Source address is invalid (you must bind to a source address before"
       " you can send packets");
  
  if (!overlay_address_is_broadcast(mdp->out.dst.sid)) broadcast=0;
  
  if (overlay_address_is_local(mdp->out.dst.sid)||broadcast)
    {
      /* Packet is addressed such that we should process it. */
      overlay_saw_mdp_frame(-1 /* not received on a network interface */,
			    mdp,overlay_gettime_ms());
      if (!broadcast) {
	/* Is local, and is not broadcast, so shouldn't get sent out
	   on the wire. */
	return 0;
      }
    }
  
  /* broadcast packets cannot be encrypted, so complain if MDP_NOCRYPT
     flag is not set. Also, MDP_NOSIGN must also be applied, until
     NaCl cryptobox keys can be used for signing. */	
  if (broadcast) {
    if (!(mdp->packetTypeAndFlags&MDP_NOCRYPT))
      return overlay_mdp_reply_error(mdp_named_socket,
				     recvaddr,recvaddrlen,5,
				     "Broadcast packets cannot be encrypted ");  }
  
  /* Prepare the overlay frame for dispatch */
  struct overlay_frame *frame;
  frame=calloc(sizeof(overlay_frame),1);
  if (!frame) return WHY_perror("calloc");
  /* give voice packets priority */
  if (mdp->out.dst.port==MDP_PORT_VOMP) frame->type=OF_TYPE_DATA_VOICE;
  else frame->type=OF_TYPE_DATA;
  frame->prev=NULL;
  frame->next=NULL;
  
  int fe=0;

  /* Work out the disposition of the frame.  For now we are only worried
     about the crypto matters, and not compression that may be applied
     before encryption (since applying it after is useless as ciphered
     text should have maximum entropy). */
  switch(mdp->packetTypeAndFlags&(MDP_NOCRYPT|MDP_NOSIGN)) {
  case 0: /* crypted and signed (using CryptoBox authcryption primitive) */
    frame->modifiers=OF_CRYPTO_SIGNED|OF_CRYPTO_CIPHERED;
    /* Prepare payload */
    frame->payload=ob_new(1 /* frame type (MDP) */
			  +1 /* MDP version */
			  +4 /* dst port */
			  +4 /* src port */
			  +crypto_box_curve25519xsalsa20poly1305_NONCEBYTES
			  +crypto_box_curve25519xsalsa20poly1305_ZEROBYTES
			  +mdp->out.payload_length);
    {
      /* write cryptobox nonce */
      unsigned char nonce[crypto_box_curve25519xsalsa20poly1305_NONCEBYTES];
      if (urandombytes(nonce,crypto_box_curve25519xsalsa20poly1305_NONCEBYTES)) {
	op_free(frame);
	return WHY("urandombytes() failed to generate nonce");
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
      unsigned char *k=keyring_get_nm_bytes(&mdp->out.src,&mdp->out.dst);
      if (!k) { op_free(frame); return WHY("could not compute Curve25519(NxM)"); }
      /* Get pointer to place in frame where the ciphered text needs to go */
      int cipher_offset=frame->payload->length;
      unsigned char *cipher_text=ob_append_space(frame->payload,cipher_len);
      if (fe||(!cipher_text))
	{ op_free(frame); return WHY("could not make space for ciphered text"); }
      /* Actually authcrypt the payload */
      if (crypto_box_curve25519xsalsa20poly1305_afternm
	  (cipher_text,plain,cipher_len,nonce,k))
	{ op_free(frame); return WHY("crypto_box_afternm() failed"); }
      /* now shuffle down 16 bytes to get rid of the temporary space that crypto_box
	 uses. */
      bcopy(&cipher_text[16],&cipher_text[0],cipher_len-16);
      frame->payload->length-=16;
      if (0) {
	DEBUG("authcrypted mdp frame");
	dump("nm bytes",k,crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES);
	dump("nonce",nonce,crypto_box_curve25519xsalsa20poly1305_NONCEBYTES);
	dump("plain text",&plain[16],cipher_len-16);
	dump("cipher text",cipher_text,cipher_len-16);	
	printf("frame->payload->length=%d,cipher_len-16=%d,cipher_offset=%d\n",
	       frame->payload->length,cipher_len-16,cipher_offset);
	dump("frame",&frame->payload->bytes[0],
	     frame->payload->length);
      }
    }
    break;
  case MDP_NOSIGN: 
    /* ciphered, but not signed.
       This means we don't use CryptoBox, but rather a more compact means
       of representing the ciphered stream segment.
    */
    frame->modifiers=OF_CRYPTO_CIPHERED; 
    op_free(frame);
    return WHY("ciphered MDP packets not implemented");
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
    frame->payload=ob_new(1 /* frame type (MDP) */
			  +1 /* MDP version */
			  +4 /* dst port */
			  +4 /* src port */
			  +crypto_sign_edwards25519sha512batch_BYTES
			  +mdp->out.payload_length);
    {
      unsigned char *key=keyring_find_sas_private(keyring,mdp->out.src.sid,NULL);
      if (!key) { op_free(frame); return WHY("could not find signing key"); }
      
      /* Build plain-text that includes header and hash it so that
         we can sign that hash. */
      unsigned char hash[crypto_hash_sha512_BYTES];
      unsigned char plain[10+mdp->out.payload_length];

      /* MDP version 1 */
      plain[0]=0x01; 
      plain[1]=0x01;
      /* Ports */
      plain[2]=(mdp->out.src.port>>24)&0xff;
      plain[3]=(mdp->out.src.port>>16)&0xff;
      plain[4]=(mdp->out.src.port>>8)&0xff;
      plain[5]=(mdp->out.src.port>>0)&0xff;
      plain[6]=(mdp->out.dst.port>>24)&0xff;
      plain[7]=(mdp->out.dst.port>>16)&0xff;
      plain[8]=(mdp->out.dst.port>>8)&0xff;
      plain[9]=(mdp->out.dst.port>>0)&0xff;
      /* payload */
      bcopy(&mdp->out.payload,&plain[10],mdp->out.payload_length);
      /* now hash it */
      crypto_hash_sha512(hash,plain,10+mdp->out.payload_length);
      
      unsigned char signature[crypto_hash_sha512_BYTES
			      +crypto_sign_edwards25519sha512batch_BYTES];
      unsigned long long  sig_len=0;
      crypto_sign_edwards25519sha512batch(signature,&sig_len,
					  hash,crypto_hash_sha512_BYTES,
					  key);
      if (!sig_len) { op_free(frame); return WHY("Signing MDP frame failed"); }
      /* chop hash out of middle of signature since it has to be recomputed
	 at the far end, anyway, as described above. */
      bcopy(&signature[32+64],&signature[32],32);
      sig_len-=crypto_hash_sha512_BYTES;
      
      /* ok, now chain plain-text with the signature at the end and send it */
      ob_append_bytes(frame->payload,plain,10+mdp->out.payload_length);
      /* chop hash out of middle of signature since it has to be recomputed
	 at the far end, anyway, as described above. */
      ob_append_bytes(frame->payload,&signature[0],32);
      ob_append_bytes(frame->payload,&signature[32+crypto_hash_sha512_BYTES],32);
    }
    break;
  case MDP_NOSIGN|MDP_NOCRYPT: /* clear text and no signature */
    frame->modifiers=0; 
    /* Copy payload body in */
    frame->payload=ob_new(1 /* frame type (MDP) */
			  +1 /* MDP version */
			  +4 /* dst port */
			  +4 /* src port */
			  +mdp->out.payload_length);
    /* MDP version 1 */
    ob_append_byte(frame->payload,0x01);
    ob_append_byte(frame->payload,0x01);
    /* Destination port */
    ob_append_int(frame->payload,mdp->out.src.port);
    ob_append_int(frame->payload,mdp->out.dst.port);
    ob_append_bytes(frame->payload,mdp->out.payload,mdp->out.payload_length);
    break;
  }
  frame->ttl=64; /* normal TTL (XXX allow setting this would be a good idea) */	  
  /* set source to ourselves 
     XXX should eventually honour binding, which should allow choosing which
     local identity.  This will be required for openbts integration/SIP:MSIP
     gateways etc. */
  overlay_frame_set_me_as_source(frame);
  
  /* Set destination address */
  if (broadcast)
    overlay_frame_set_broadcast_as_destination(frame);
  else{
    bcopy(&mdp->out.dst.sid[0],frame->destination,SID_SIZE);
    frame->destination_address_status=OA_RESOLVED;
  }
  
  int q=OQ_ORDINARY;
  if (mdp->out.src.port==MDP_PORT_VOMP) {
    q=OQ_ISOCHRONOUS_VOICE;
    rhizome_saw_voice_traffic();
  }
  if (overlay_payload_enqueue(q,frame,0))
    {
      if (frame) op_free(frame);
      return WHY("Error enqueuing frame");
    }
  else {
    if (debug&DEBUG_OVERLAYINTERFACES) DEBUG("queued frame");
    return 0;
  }
}

int overlay_mdp_poll()
{
  unsigned char buffer[16384];
  int ttl;
  unsigned char recvaddrbuffer[1024];
  struct sockaddr *recvaddr=(struct sockaddr *)&recvaddrbuffer[0];
  socklen_t recvaddrlen=sizeof(recvaddrbuffer);
  struct sockaddr_un *recvaddr_un=NULL;

  if (mdp_named_socket>-1) {
    ttl=-1;
    bzero((void *)recvaddrbuffer,sizeof(recvaddrbuffer));
    fcntl(mdp_named_socket, F_SETFL, 
	  fcntl(mdp_named_socket, F_GETFL, NULL)|O_NONBLOCK); 
    int len = recvwithttl(mdp_named_socket,buffer,sizeof(buffer),&ttl,
			  recvaddr,&recvaddrlen);
    recvaddr_un=(struct sockaddr_un *)recvaddr;

    if (len>0) {
      /* Look at overlay_mdp_frame we have received */
      overlay_mdp_frame *mdp=(overlay_mdp_frame *)&buffer[0];      

      switch(mdp->packetTypeAndFlags&MDP_TYPE_MASK) {
      case MDP_GOODBYE:
	return overlay_mdp_releasebindings(recvaddr_un,recvaddrlen);
      case MDP_VOMPEVENT:
	return vomp_mdp_event(mdp,recvaddr_un,recvaddrlen);
      case MDP_NODEINFO:
	return overlay_route_node_info(mdp,recvaddr_un,recvaddrlen);
      case MDP_GETADDRS:
	{
	  overlay_mdp_frame mdpreply;
	  
	  /* Work out which SIDs to get ... */
	  int sid_num=mdp->addrlist.first_sid;
	  int max_sid=mdp->addrlist.last_sid;
	  int max_sids=mdp->addrlist.frame_sid_count;
	  /* ... and constrain list for sanity */
	  if (sid_num<0) sid_num=0;
	  if (max_sids>MDP_MAX_SID_REQUEST) max_sids=MDP_MAX_SID_REQUEST;
	  if (max_sids<0) max_sids=0;
	  
	  /* Prepare reply packet */
	  mdpreply.packetTypeAndFlags=MDP_ADDRLIST;
	  mdpreply.addrlist.first_sid=sid_num;
	  mdpreply.addrlist.last_sid=max_sid;
	  mdpreply.addrlist.frame_sid_count=max_sids;
	  
	  /* Populate with SIDs */
	  int i=0;
	  int count=0;
	  if (mdp->addrlist.selfP) {
	    /* from self */
	    int cn=0,in=0,kp=0;
	    while(keyring_next_identity(keyring,&cn,&in,&kp)) {	    
	      if (count>=sid_num&&(i<max_sids))
		bcopy(keyring->contexts[cn]->identities[in]
		      ->keypairs[kp]->public_key,
		      mdpreply.addrlist.sids[i++],SID_SIZE);
	      in++; kp=0;
	      count++;
	      if (i>=max_sids) break;
	    }
	  } else {
	    /* from peer list */
	    int bin,slot;
	    i=0;
	    count=0;
	    for(bin=0;bin<overlay_bin_count;bin++)
	      for(slot=0;slot<overlay_bin_size;slot++)
		{
		  if ((!overlay_nodes[bin][slot].sid[0]) 
		      ||(overlay_nodes[bin][slot].best_link_score<1))
		    { 
		      continue; }
		  if ((count>=sid_num)&&(i<max_sids)) {
		    bcopy(overlay_nodes[bin][slot].sid,
			  mdpreply.addrlist.sids[i++],SID_SIZE);
		  }
		  count++;
		}
	  }
	  mdpreply.addrlist.frame_sid_count=i;
	  mdpreply.addrlist.last_sid=sid_num+i-1;
	  mdpreply.addrlist.server_sid_count=count;

	  /* Send back to caller */
	  return overlay_mdp_reply(mdp_named_socket,
				   (struct sockaddr_un *)recvaddr,recvaddrlen,
				   &mdpreply);
	}
	break;
      case MDP_TX: /* Send payload (and don't treat it as system privileged) */
	return overlay_mdp_dispatch(mdp,1,(struct sockaddr_un*)recvaddr,recvaddrlen);
	break;
      case MDP_BIND: /* Bind to port */
	return overlay_mdp_process_bind_request(mdp_named_socket,mdp,
						recvaddr_un,recvaddrlen);
	break;
      default:
	/* Client is not allowed to send any other frame type */
	WHY("Illegal frame type.");
	mdp->packetTypeAndFlags=MDP_ERROR;
	mdp->error.error=2;
	snprintf(mdp->error.message,128,"Illegal request type.  Clients may use only MDP_TX or MDP_BIND.");
	int len=4+4+strlen(mdp->error.message)+1;
	errno=0;
	/* We ignore the result of the following, because it is just sending an
	   error message back to the client.  If this fails, where would we report
	   the error to? My point exactly. */
	sendto(mdp_named_socket,mdp,len,0,(struct sockaddr *)recvaddr,recvaddrlen);
      }
    }

    fcntl(mdp_named_socket, F_SETFL, 
	  fcntl(mdp_named_socket, F_GETFL, NULL)&(~O_NONBLOCK)); 
  }

  return 0;
}

int overlay_mdp_relevant_bytes(overlay_mdp_frame *mdp) 
{
  int len=4;
  switch(mdp->packetTypeAndFlags&MDP_TYPE_MASK)
    {
    case MDP_GOODBYE:
      /* no arguments for saying goodbye */
      break;
    case MDP_ADDRLIST: 
      len=&mdp->addrlist.sids[0][0]-(unsigned char *)mdp;
      len+=mdp->addrlist.frame_sid_count*SID_SIZE;
      break;
    case MDP_GETADDRS: 
      len=&mdp->addrlist.sids[0][0]-(unsigned char *)mdp;
      break;
    case MDP_TX: 
      len=&mdp->out.payload[0]-(unsigned char *)mdp;
      len+=mdp->out.payload_length; 
      break;
    case MDP_BIND: 
      len=&mdp->bind.sid[SID_SIZE]-(unsigned char *)mdp;
      break;
    case MDP_ERROR: 
      /* This formulation is used so that we don't copy any bytes after the
	 end of the string, to avoid information leaks */
      len=&mdp->error.message[0]-(char *)mdp;
      len+=strlen(mdp->error.message)+1;      
      if (mdp->error.error) INFOF("mdp return/error code: %d:%s",mdp->error.error,mdp->error.message);
      break;
    case MDP_VOMPEVENT:
      /* XXX too hard to work out precisely for now. */
      len=sizeof(overlay_mdp_frame);
      break;
    case MDP_NODEINFO:
      /* XXX problems with calculating this due to structure padding, 
	 so doubled required space, and now it works. */
      len=sizeof(overlay_mdp_nodeinfo)*2;
      break;
    default:
      return WHY("Illegal MDP frame type.");
    }
  return len;
}

int mdp_client_socket=-1;
int overlay_mdp_send(overlay_mdp_frame *mdp,int flags,int timeout_ms)
{
  int len=4;
 
  if (mdp_client_socket==-1) 
      if (overlay_mdp_client_init() != 0)
	  return -1;

  /* Minimise frame length to save work and prevent accidental disclosure of
     memory contents. */
  len=overlay_mdp_relevant_bytes(mdp);
  if (len<0) return WHY("MDP frame invalid (could not compute length)");

  /* Construct name of socket to send to. */
  struct sockaddr_un name;
  name.sun_family = AF_UNIX;
  if (!FORM_SERVAL_INSTANCE_PATH(name.sun_path, "mdp.socket"))
    return -1;

  fcntl(mdp_client_socket, F_SETFL,
	fcntl(mdp_client_socket, F_GETFL, NULL)|O_NONBLOCK);
  int result=sendto(mdp_client_socket, mdp, len, 0,
		    (struct sockaddr *)&name, sizeof(struct sockaddr_un));
  if (result<0) {
    mdp->packetTypeAndFlags=MDP_ERROR;
    mdp->error.error=1;
    snprintf(mdp->error.message,128,"Error sending frame to MDP server.");
    return WHY_perror("sendto(f)");
  } else {
    if (!(flags&MDP_AWAITREPLY)) {       
      return 0;
    }
  }

  /* Wait for a reply until timeout */
  struct pollfd fds[1];
  int fdcount=1;
  fds[0].fd=mdp_client_socket; fds[0].events=POLLIN;
  result = poll(fds,fdcount,timeout_ms);
  if (result==0) {
    /* Timeout */
    mdp->packetTypeAndFlags=MDP_ERROR;
    mdp->error.error=1;
    snprintf(mdp->error.message,128,"Timeout waiting for reply to MDP packet (packet was successfully sent).");    
    return WHY("Timeout waiting for server response");
  }


  int ttl=-1;
  if (!overlay_mdp_recv(mdp,&ttl)) {
    /* If all is well, examine result and return error code provided */
    if ((mdp->packetTypeAndFlags&MDP_TYPE_MASK)==MDP_ERROR)
	return mdp->error.error;
    else
      /* Something other than an error has been returned */
      return 0;
  } else {
    /* poll() said that there was data, but there isn't.
       So we will abort. */
    return WHY("poll() aborted");
  }
}

char overlay_mdp_client_socket_path[1024];
int overlay_mdp_client_socket_path_len=-1;

int overlay_mdp_client_init()
{
  if (mdp_client_socket==-1) {
    /* Open socket to MDP server (thus connection is always local) */
    if (0) WHY("Use of abstract name space socket for Linux not implemented");
    
    mdp_client_socket = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (mdp_client_socket < 0) {
      WHY_perror("socket");
      return WHY("Could not open socket to MDP server");
    }

    /* We must bind to a temporary file name */
    struct sockaddr_un name;
    unsigned int random_value;
    if (urandombytes((unsigned char *)&random_value,sizeof(int)))
	return WHY("urandombytes() failed");
    name.sun_family = AF_UNIX;
    if (overlay_mdp_client_socket_path_len==-1) {
      char fmt[1024];
      if (!FORM_SERVAL_INSTANCE_PATH(fmt, "mdp-client-%d-%08x.socket"))
	return WHY("Could not form MDP client socket name");
      snprintf(overlay_mdp_client_socket_path,1024,fmt,getpid(),random_value);
      overlay_mdp_client_socket_path_len=strlen(overlay_mdp_client_socket_path)+1;
      if(debug&DEBUG_IO) DEBUGF("MDP client socket name='%s'",overlay_mdp_client_socket_path);
    }
    bcopy(overlay_mdp_client_socket_path,name.sun_path,
	  overlay_mdp_client_socket_path_len);
    unlink(name.sun_path);
    int len = 1 + strlen(name.sun_path) + sizeof(name.sun_family) + 1;
    int r=bind(mdp_client_socket, (struct sockaddr *)&name, len);
    if (r) {
      WHY_perror("bind");
      return WHY("Could not bind MDP client socket to file name");
    }

    int send_buffer_size=128*1024;
    int res = setsockopt(mdp_client_socket, SOL_SOCKET, SO_RCVBUF, 
			 &send_buffer_size, sizeof(send_buffer_size));
    if (res) WHYF("setsockopt() failed: errno=%d",errno);

  }
  
  return 0;
}

int overlay_mdp_client_done()
{
  if (mdp_client_socket!=-1) {
    /* Tell MDP server to release all our bindings */
    overlay_mdp_frame mdp;
    mdp.packetTypeAndFlags=MDP_GOODBYE;
    overlay_mdp_send(&mdp,0,0);
  }

  if (overlay_mdp_client_socket_path_len>-1)
    unlink(overlay_mdp_client_socket_path);
  if (mdp_client_socket!=-1)
    close(mdp_client_socket);
  mdp_client_socket=-1;
  return 0;
}

int overlay_mdp_client_poll(long long timeout_ms)
{
  fd_set r;
  FD_ZERO(&r);
  FD_SET(mdp_client_socket,&r);
  if (timeout_ms<0) timeout_ms=0;
  
  struct timeval tv;

  if (timeout_ms>=0) {
    tv.tv_sec=timeout_ms/1000;
    tv.tv_usec=(timeout_ms%1000)*1000;
    return select(mdp_client_socket+1,&r,NULL,&r,&tv);
  }
  else
    return select(mdp_client_socket+1,&r,NULL,&r,NULL);
}

int overlay_mdp_recv(overlay_mdp_frame *mdp,int *ttl) 
{
  char mdp_socket_name[101];
  if (!FORM_SERVAL_INSTANCE_PATH(mdp_socket_name, "mdp.socket"))
    return WHY("Could not find mdp socket");
  /* Check if reply available */
  fcntl(mdp_client_socket, F_SETFL, fcntl(mdp_client_socket, F_GETFL, NULL)|O_NONBLOCK); 
  unsigned char recvaddrbuffer[1024];
  struct sockaddr *recvaddr=(struct sockaddr *)recvaddrbuffer;
  unsigned int recvaddrlen=sizeof(recvaddrbuffer);
  struct sockaddr_un *recvaddr_un;
  mdp->packetTypeAndFlags=0;
  int len = recvwithttl(mdp_client_socket,(unsigned char *)mdp,
		    sizeof(overlay_mdp_frame),ttl,recvaddr,&recvaddrlen);
  recvaddr_un=(struct sockaddr_un *)recvaddr;
  /* Null terminate received address so that the stat() call below can succeed */
  if (recvaddrlen<1024) recvaddrbuffer[recvaddrlen]=0;
  if (len>0) {
    /* Make sure recvaddr matches who we sent it to */
    if (strncmp(mdp_socket_name, recvaddr_un->sun_path, sizeof(recvaddr_un->sun_path))) {
      /* Okay, reply was PROBABLY not from the server, but on OSX if the path
	 has a symlink in it, it is resolved in the reply path, but might not
	 be in the request path (mdp_socket_name), thus we need to stat() and
	 compare inode numbers etc */
      struct stat sb1,sb2;
      if (stat(mdp_socket_name,&sb1)) return WHY("stat(mdp_socket_name) failed, so could not verify that reply came from MDP server");
      if (stat(recvaddr_un->sun_path,&sb2)) return WHY("stat(ra->sun_path) failed, so could not verify that reply came from MDP server");
      if ((sb1.st_ino!=sb2.st_ino)||(sb1.st_dev!=sb2.st_dev))
	return WHY("Reply did not come from server");
    }
    
    int expected_len = overlay_mdp_relevant_bytes(mdp);
    
    if (len < expected_len){
      return WHYF("Expected packet length of %d, received only %d bytes", expected_len, len);
    }
    /* Valid packet received */
    return 0;
  } else 
    /* no packet received */
    return -1;

}

int overlay_mdp_bind(unsigned char *localaddr,int port) 
{
  overlay_mdp_frame mdp;
  mdp.packetTypeAndFlags=MDP_BIND|MDP_FORCE;
  bcopy(localaddr,mdp.bind.sid,SID_SIZE);
  mdp.bind.port_number=port;
  int result=overlay_mdp_send(&mdp,MDP_AWAITREPLY,5000);
  if (result) {
    if (mdp.packetTypeAndFlags==MDP_ERROR)
      fprintf(stderr,"Could not bind to MDP port %d: error=%d, message='%s'\n",
	      port,mdp.error.error,mdp.error.message);
    else
      fprintf(stderr,"Could not bind to MDP port %d (no reason given)\n",port);
    return -1;
  }
  return 0;
}

int overlay_mdp_getmyaddr(int index,unsigned char *sid)
{
  overlay_mdp_frame a;

  a.packetTypeAndFlags=MDP_GETADDRS;
  a.addrlist.selfP=1;
  a.addrlist.first_sid=index;
  a.addrlist.last_sid=0x7fffffff;
  a.addrlist.frame_sid_count=MDP_MAX_SID_REQUEST;
  int result=overlay_mdp_send(&a,MDP_AWAITREPLY,5000);
  if (result) {
    if (a.packetTypeAndFlags==MDP_ERROR)
      {
	fprintf(stderr,"Could not get list of local MDP addresses\n");
	fprintf(stderr,"  MDP Server error #%d: '%s'\n",
		a.error.error,a.error.message);
      }
    else
      fprintf(stderr,"Could not get list of local MDP addresses\n");
    return WHY("Failed to get local address list");
  }
  if ((a.packetTypeAndFlags&MDP_TYPE_MASK)!=MDP_ADDRLIST)
    return WHY("MDP Server returned something other than an address list");
  if (0) DEBUGF("local addr 0 = %s",overlay_render_sid(a.addrlist.sids[0]));
  bcopy(&a.addrlist.sids[0][0],sid,SID_SIZE);
  return 0;
}

