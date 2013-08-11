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
#include "rhizome.h"
#include "crypto.h"
#include "log.h"
#include "parallel.h"

int rhizome_mdp_send_block(struct subscriber *dest, unsigned char *id, uint64_t version, uint64_t fileOffset, uint32_t bitmap, uint16_t blockLength)
{
  IN();
  if (blockLength>1024) RETURN(-1);

  char *id_str = alloca_tohex_bid(id);

  if (config.debug.rhizome_tx)
    DEBUGF("Requested blocks for %s @%"PRIx64, id_str, fileOffset);

  /* Find manifest that corresponds to BID and version.
     If we don't have this combination, then do nothing.
     If we do have the combination, then find the associated file, 
     and open the blob so that we can send some of it.

     TODO: If we have a newer version of the manifest, and the manifest is a
     journal, then the newer version is okay to use to service this request.
  */
  
  char filehash[SHA512_DIGEST_STRING_LENGTH];
  if (rhizome_database_filehash_from_id(id_str, version, filehash)<=0)
    RETURN(-1);
  
  struct rhizome_read read;
  bzero(&read, sizeof read);
  
  int ret=rhizome_open_read(&read, filehash, 0);
  
  if (!ret){
    overlay_mdp_frame reply;
    bzero(&reply,sizeof(reply));
    // Reply is broadcast, so we cannot authcrypt, and signing is too time consuming
    // for low devices.  The result is that an attacker can prevent rhizome transfers
    // if they want to by injecting fake blocks.  The alternative is to not broadcast
    // back replies, and then we can authcrypt.
    // multiple receivers starting at different times, we really need merkle-tree hashing.
    // so multiple receivers is not realistic for now.  So use non-broadcast unicode
    // for now would seem the safest.  But that would stop us from allowing multiple
    // receivers in the special case where additional nodes begin listening in from the
    // beginning.
    reply.packetTypeAndFlags=MDP_TX|MDP_NOCRYPT|MDP_NOSIGN;
    bcopy(my_subscriber->sid,reply.out.src.sid,SID_SIZE);
    reply.out.src.port=MDP_PORT_RHIZOME_RESPONSE;
    int send_broadcast=1;
    
    if (dest){
      if (!(dest->reachable&REACHABLE_DIRECT))
	send_broadcast=0;
      if (dest->reachable&REACHABLE_UNICAST && dest->interface && dest->interface->prefer_unicast)
	send_broadcast=0;
    }
    
    if (send_broadcast){
      // send replies to broadcast so that others can hear blocks and record them
      // (not that preemptive listening is implemented yet).
      memset(reply.out.dst.sid,0xff,SID_SIZE);
      reply.out.ttl=1;
    }else{
      // if we get a request from a peer that we can only talk to via unicast, send data via unicast too.
      bcopy(dest->sid, reply.out.dst.sid, SID_SIZE);
    }
    
    reply.out.dst.port=MDP_PORT_RHIZOME_RESPONSE;
    reply.out.queue=OQ_OPPORTUNISTIC;
    reply.out.payload[0]='B'; // reply contains blocks
    // include 16 bytes of BID prefix for identification
    bcopy(id, &reply.out.payload[1], 16);
    // and version of manifest
    bcopy(&version, &reply.out.payload[1+16], sizeof(uint64_t));
    
    int i;
    for(i=0;i<32;i++){
      if (bitmap&(1<<(31-i)))
	continue;
      
      if (overlay_queue_remaining(reply.out.queue) < 10)
	break;
      
      // calculate and set offset of block
      read.offset = fileOffset+i*blockLength;
      
      // stop if we passed the length of the file
      // (but we may not know the file length until we attempt a read)
      if (read.length!=-1 && read.offset>read.length)
	break;
      
      write_uint64(&reply.out.payload[1+16+8], read.offset);
      
      int bytes_read = rhizome_read(&read, &reply.out.payload[1+16+8+8], blockLength);
      if (bytes_read<=0)
	break;
      
      reply.out.payload_length=1+16+8+8+bytes_read;
      
      // Mark the last block of the file, if required
      if (read.offset >= read.length)
	reply.out.payload[0]='T';
      
      // send packet
      if (overlay_mdp_dispatch(&reply,0 /* system generated */, NULL,0))
	break;
    }
  }
  rhizome_read_close(&read);

  RETURN(ret);
  OUT();
}

int overlay_mdp_service_rhizomerequest(overlay_mdp_frame *mdp)
{
  uint64_t version=
    read_uint64(&mdp->out.payload[RHIZOME_MANIFEST_ID_BYTES]);
  uint64_t fileOffset=
    read_uint64(&mdp->out.payload[RHIZOME_MANIFEST_ID_BYTES+8]);
  uint32_t bitmap=
    read_uint32(&mdp->out.payload[RHIZOME_MANIFEST_ID_BYTES+8+8]);
  uint16_t blockLength=
    read_uint16(&mdp->out.payload[RHIZOME_MANIFEST_ID_BYTES+8+8+4]);

  struct subscriber *source = find_subscriber(mdp->out.src.sid, SID_SIZE, 0);

  return rhizome_mdp_send_block(source, &mdp->out.payload[0], version, fileOffset, bitmap, blockLength);
}

int overlay_mdp_service_rhizomeresponse(overlay_mdp_frame *mdp)
{
  IN();
  
  if (!mdp->out.payload_length) RETURN(-1);

  int type=mdp->out.payload[0];
  switch (type) {
  case 'B': /* data block */
  case 'T': /* terminal data block */
    {
      if (mdp->out.payload_length<(1+16+8+8+1)) RETURN(-1);
      unsigned char *bidprefix=&mdp->out.payload[1];
      uint64_t version=read_uint64(&mdp->out.payload[1+16]);
      uint64_t offset=read_uint64(&mdp->out.payload[1+16+8]);
      int count=mdp->out.payload_length-(1+16+8+8);
      unsigned char *bytes=&mdp->out.payload[1+16+8+8];

      /* Now see if there is a slot that matches.  If so, then
	 see if the bytes are in the window, and write them.

	 If there is not matching slot, then consider setting 
	 a slot to capture this files as it is being requested
	 by someone else.
      */
      rhizome_received_content(bidprefix,version,offset,count,bytes,type);

      RETURN(-1);
    }
    break;
  }

  RETURN(-1);
  OUT();
}

int overlay_mdp_service_dnalookup(overlay_mdp_frame *mdp)
{
  IN();
  int cn=0,in=0,kp=0;
  char did[64+1];
  int pll=mdp->out.payload_length;
  if (pll>64) pll=64;
  /* get did from the packet */
  if (mdp->out.payload_length<1) {
    RETURN(WHY("Empty DID in DNA resolution request")); }
  bcopy(&mdp->out.payload[0],&did[0],pll);
  did[pll]=0;
  
  if (config.debug.mdprequests)
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
    monitor_tell_formatted(MONITOR_DNAHELPER, "LOOKUP:%s:%d:%s\n", 
			   alloca_tohex_sid(mdp->out.src.sid), mdp->out.src.port, 
			   did);
  }
  RETURN(0);
}

int overlay_mdp_service_echo(overlay_mdp_frame *mdp)
{
  /* Echo is easy: we swap the sender and receiver addresses (and thus port
     numbers) and send the frame back. */
  IN();

  /* Swap addresses */
  overlay_mdp_swap_src_dst(mdp);
  mdp->out.ttl=0;
  
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
  
  /* Always send PONGs auth-crypted so that the receipient knows
     that they are genuine, and so that we avoid the extra cost 
     of signing (which is slower than auth-crypting) */
  int preserved=mdp->packetTypeAndFlags;
  mdp->packetTypeAndFlags&=~(MDP_NOCRYPT|MDP_NOSIGN);
  
  /* queue frame for delivery */
  overlay_mdp_dispatch(mdp,0 /* system generated */,
		       NULL,0);
  mdp->packetTypeAndFlags=preserved;
  
  /* and switch addresses back around in case the caller was planning on
     using MDP structure again (this happens if there is a loop-back reply
     and the frame needs sending on, as happens with broadcasts.  MDP ping
     is a simple application where this occurs). */
  overlay_mdp_swap_src_dst(mdp);
  RETURN(0);
}

static int overlay_mdp_service_trace(overlay_mdp_frame *mdp){
  IN();
  int ret=0;
  
  struct overlay_buffer *b = ob_static(mdp->out.payload, sizeof(mdp->out.payload));
  ob_limitsize(b, mdp->out.payload_length);
  
  struct subscriber *src=NULL, *dst=NULL, *last=NULL, *next=NULL;
  struct decode_context context;
  bzero(&context, sizeof context);
  
  if (overlay_address_parse(&context, b, &src)){
    ret=WHYF("Invalid trace packet");
    goto end;
  }
  if (overlay_address_parse(&context, b, &dst)){
    ret=WHYF("Invalid trace packet");
    goto end;
  }
  if (context.invalid_addresses){
    ret=WHYF("Invalid address in trace packet");
    goto end;
  }

  INFOF("Trace from %s to %s", alloca_tohex_sid(src->sid), alloca_tohex_sid(dst->sid));
  
  while(ob_remaining(b)>0){
    struct subscriber *trace=NULL;
    if (overlay_address_parse(&context, b, &trace)){
      ret=WHYF("Invalid trace packet");
      goto end;
    }
    if (context.invalid_addresses){
      ret=WHYF("Invalid address in trace packet");
      goto end;
    }
    INFOF("Via %s", alloca_tohex_sid(trace->sid));
    
    if (trace->reachable==REACHABLE_SELF && !next)
      // We're already in this trace, send the next packet to the node before us in the list
      next = last;
    last = trace;
  }
  
  if (src->reachable==REACHABLE_SELF && last){
    // it came back to us, we can send the reply to our mdp client...
    next=src;
    mdp->out.dst.port=mdp->out.src.port;
    mdp->out.src.port=MDP_PORT_TRACE;
  }
  
  if (!next){
    // destination is our neighbour?
    if (dst->reachable & REACHABLE_DIRECT)
      next = dst;
    // destination is indirect?
    else if (dst->reachable & REACHABLE_INDIRECT)
      next = dst->next_hop;
    // destination is not reachable or is ourselves? bounce back to the previous node or the sender.
    else if (last)
      next = last;
    else
      next = src;
  }
  
  INFOF("Next node is %s", alloca_tohex_sid(next->sid));
  
  ob_unlimitsize(b);
  // always write a full sid into the payload
  my_subscriber->send_full=1;
  if (overlay_address_append(&context, b, my_subscriber)){
    ret = WHYF("Unable to append my address to the trace");
    goto end;
  }
  
  mdp->out.payload_length = ob_position(b);
  bcopy(my_subscriber->sid, mdp->out.src.sid, SID_SIZE);
  bcopy(next->sid, mdp->out.dst.sid, SID_SIZE);
  
  ret = overlay_mdp_dispatch(mdp, 0, NULL, 0);
end:
  ob_free(b);
  RETURN(ret);
}

static int overlay_mdp_service_manifest_response(overlay_mdp_frame *mdp){
  int offset=0;
  char id_hex[RHIZOME_MANIFEST_ID_STRLEN];
  
  while (offset<mdp->out.payload_length){
    unsigned char *bar=&mdp->out.payload[offset];
    tohex(id_hex, &bar[RHIZOME_BAR_PREFIX_OFFSET], RHIZOME_BAR_PREFIX_BYTES);
    strcat(id_hex, "%");
    rhizome_manifest *m = rhizome_new_manifest();
    if (!m)
      return WHY("Unable to allocate manifest");
    if (!rhizome_retrieve_manifest(id_hex, m)){
      rhizome_advertise_manifest(m);
    }
    rhizome_manifest_free(m);
    offset+=RHIZOME_BAR_BYTES;
  }
  
  return 0;
}

int overlay_mdp_try_interal_services(struct overlay_frame *frame, overlay_mdp_frame *mdp)
{
  IN();
  switch(mdp->out.dst.port) {
  case MDP_PORT_LINKSTATE:        RETURN(link_receive(mdp));
  case MDP_PORT_VOMP:             RETURN(vomp_mdp_received(mdp));
  case MDP_PORT_KEYMAPREQUEST:    RETURN(keyring_mapping_request(keyring,mdp));
  case MDP_PORT_DNALOOKUP:        RETURN(overlay_mdp_service_dnalookup(mdp));
  case MDP_PORT_ECHO:             RETURN(overlay_mdp_service_echo(mdp));
  case MDP_PORT_TRACE:            RETURN(overlay_mdp_service_trace(mdp));
  case MDP_PORT_PROBE:            RETURN(overlay_mdp_service_probe(mdp));
  case MDP_PORT_STUNREQ:          RETURN(overlay_mdp_service_stun_req(mdp));
  case MDP_PORT_STUN:             RETURN(overlay_mdp_service_stun(mdp));
  case MDP_PORT_RHIZOME_REQUEST: 
    if (is_rhizome_mdp_server_running()) {
      RETURN(overlay_mdp_service_rhizomerequest(mdp));
    }
    break;
  case MDP_PORT_RHIZOME_RESPONSE: RETURN(overlay_mdp_service_rhizomeresponse(mdp));    
  case MDP_PORT_RHIZOME_MANIFEST_REQUEST: RETURN(overlay_mdp_service_manifest_response(mdp));
  case MDP_PORT_RHIZOME_SYNC: RETURN(overlay_mdp_service_rhizome_sync(frame, mdp));
  }
   
  /* Unbound socket.  We won't be sending ICMP style connection refused
     messages, partly because they are a waste of bandwidth. */
  RETURN(WHYF("Received packet for which no listening process exists (MDP ports: src=%d, dst=%d",
	      mdp->out.src.port,mdp->out.dst.port));
}
