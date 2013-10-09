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

int rhizome_mdp_send_block(struct subscriber *dest, const rhizome_bid_t *bid, uint64_t version, uint64_t fileOffset, uint32_t bitmap, uint16_t blockLength)
{
  IN();
  if (!is_rhizome_mdp_server_running())
    RETURN(-1);
  if (blockLength<=0 || blockLength>1024)
    RETURN(WHYF("Invalid block length %d", blockLength));

  if (config.debug.rhizome_tx)
    DEBUGF("Requested blocks for %s @%"PRIx64" bitmap %x", alloca_tohex_rhizome_bid_t(*bid), fileOffset, bitmap);
    
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
  reply.out.src.sid = my_subscriber->sid;
  reply.out.src.port=MDP_PORT_RHIZOME_RESPONSE;
  
  if (dest && (dest->reachable==REACHABLE_UNICAST || dest->reachable==REACHABLE_INDIRECT)){
    // if we get a request from a peer that we can only talk to via unicast, send data via unicast too.
    reply.out.dst.sid = dest->sid;
  }else{
    // send replies to broadcast so that others can hear blocks and record them
    // (not that preemptive listening is implemented yet).
    reply.out.dst.sid = SID_BROADCAST;
    reply.out.ttl=1;
  }
  
  reply.out.dst.port=MDP_PORT_RHIZOME_RESPONSE;
  reply.out.queue=OQ_OPPORTUNISTIC;
  reply.out.payload[0]='B'; // reply contains blocks
  // include 16 bytes of BID prefix for identification
  bcopy(bid->binary, &reply.out.payload[1], 16);
  // and version of manifest (in the correct byte order)
  //  bcopy(&version, &reply.out.payload[1+16], sizeof(uint64_t));
  write_uint64(&reply.out.payload[1+16],version);
  
  int i;
  for(i=0;i<32;i++){
    if (bitmap&(1<<(31-i)))
      continue;
    
    if (overlay_queue_remaining(reply.out.queue) < 10)
      break;
    
    // calculate and set offset of block
    uint64_t offset = fileOffset+i*blockLength;
    
    write_uint64(&reply.out.payload[1+16+8], offset);
    
    int bytes_read = rhizome_read_cached(bid, version, gettime_ms()+5000, offset, &reply.out.payload[1+16+8+8], blockLength);
    if (bytes_read<=0)
      break;
    
    reply.out.payload_length=1+16+8+8+bytes_read;
    
    // Mark the last block of the file, if required
    if (bytes_read < blockLength)
      reply.out.payload[0]='T';
    
    // send packet
    if (overlay_mdp_dispatch(&reply,0 /* system generated */, NULL,0))
      break;
  }

  RETURN(0);
  OUT();
}

int overlay_mdp_service_rhizomerequest(struct overlay_frame *frame, overlay_mdp_frame *mdp)
{
  const rhizome_bid_t *bidp = (const rhizome_bid_t *) &mdp->out.payload[0];
  uint64_t version = read_uint64(&mdp->out.payload[sizeof bidp->binary]);
  uint64_t fileOffset = read_uint64(&mdp->out.payload[sizeof bidp->binary + 8]);
  uint32_t bitmap = read_uint32(&mdp->out.payload[sizeof bidp->binary + 8 + 8]);
  uint16_t blockLength = read_uint16(&mdp->out.payload[sizeof bidp->binary + 8 + 8 + 4]);
  return rhizome_mdp_send_block(frame->source, bidp, version, fileOffset, bitmap, blockLength);
}

int overlay_mdp_service_rhizomeresponse(overlay_mdp_frame *mdp)
{
  IN();
  
  if (!mdp->out.payload_length)
    RETURN(WHYF("No payload?"));

  int type=mdp->out.payload[0];

  if (config.debug.rhizome_mdp_rx)
    DEBUGF("Received Rhizome over MDP block, type=%02x",type);

  switch (type) {
  case 'B': /* data block */
  case 'T': /* terminal data block */
    {
      if (mdp->out.payload_length<(1+16+8+8+1)) 
	RETURN(WHYF("Payload too short"));
      unsigned char *bidprefix=&mdp->out.payload[1];
      uint64_t version=read_uint64(&mdp->out.payload[1+16]);
      uint64_t offset=read_uint64(&mdp->out.payload[1+16+8]);
      int count=mdp->out.payload_length-(1+16+8+8);
      unsigned char *bytes=&mdp->out.payload[1+16+8+8];

      if (config.debug.rhizome_mdp_rx)
	DEBUGF("bidprefix=%02x%02x%02x%02x*, offset=%"PRId64", count=%d",
	       bidprefix[0],bidprefix[1],bidprefix[2],bidprefix[3],offset,count);

      /* Now see if there is a slot that matches.  If so, then
	 see if the bytes are in the window, and write them.

	 If there is not matching slot, then consider setting 
	 a slot to capture this files as it is being requested
	 by someone else.
      */
      rhizome_received_content(bidprefix,version,offset,count,bytes,type);

      RETURN(0);
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
      const sid_t *sidp = (const sid_t *) keyring->contexts[cn]->identities[in]->keypairs[0]->public_key;
      const char *unpackedDid = (const char *) keyring->contexts[cn]->identities[in]->keypairs[kp]->private_key;
      const char *name = (const char *)keyring->contexts[cn]->identities[in]->keypairs[kp]->public_key;
      // URI is sid://SIDHEX/DID
      strbuf b = strbuf_alloca(SID_STRLEN + DID_MAXSIZE + 10);
      strbuf_puts(b, "sid://");
      strbuf_tohex(b, SID_STRLEN, sidp->binary);
      strbuf_puts(b, "/local/");
      strbuf_puts(b, unpackedDid);
      overlay_mdp_dnalookup_reply(&mdp->out.src, sidp, strbuf_str(b), unpackedDid, name);
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
    dna_helper_enqueue(mdp, did, &mdp->out.src.sid);
    monitor_tell_formatted(MONITOR_DNAHELPER, "LOOKUP:%s:%d:%s\n", 
			   alloca_tohex_sid_t(mdp->out.src.sid), mdp->out.src.port, 
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
  if (is_sid_t_broadcast(mdp->out.src.sid))
    {
      if (my_subscriber)		  
	mdp->out.src.sid = my_subscriber->sid;
      else
	/* No local addresses, so put all zeroes */
	mdp->out.src.sid = SID_ANY;
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

  INFOF("Trace from %s to %s", alloca_tohex_sid_t(src->sid), alloca_tohex_sid_t(dst->sid));
  
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
    INFOF("Via %s", alloca_tohex_sid_t(trace->sid));
    
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
  
  INFOF("Next node is %s", alloca_tohex_sid_t(next->sid));
  
  ob_unlimitsize(b);
  // always write a full sid into the payload
  my_subscriber->send_full=1;
  if (overlay_address_append(&context, b, my_subscriber)){
    ret = WHYF("Unable to append my address to the trace");
    goto end;
  }
  
  mdp->out.payload_length = ob_position(b);
  mdp->out.src.sid = my_subscriber->sid;
  mdp->out.dst.sid = next->sid;
  
  ret = overlay_mdp_dispatch(mdp, 0, NULL, 0);
end:
  ob_free(b);
  RETURN(ret);
}

static int overlay_mdp_service_manifest_requests(struct overlay_frame *frame, overlay_mdp_frame *mdp)
{
  int offset=0;
  while (offset<mdp->out.payload_length) {
    rhizome_manifest *m = rhizome_new_manifest();
    if (!m)
      return WHY("Unable to allocate manifest");
    unsigned char *bar = &mdp->out.payload[offset];
    if (!rhizome_retrieve_manifest_by_prefix(&bar[RHIZOME_BAR_PREFIX_OFFSET], RHIZOME_BAR_PREFIX_BYTES, m)){
      rhizome_advertise_manifest(frame->source, m);
      // pre-emptively send the payload if it will fit in a single packet
      if (m->fileLength > 0 && m->fileLength <= 1024)
	rhizome_mdp_send_block(frame->source, &m->cryptoSignPublic, m->version, 0, 0, m->fileLength);
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
  case MDP_PORT_LINKSTATE:        RETURN(link_receive(frame, mdp));
  case MDP_PORT_VOMP:             RETURN(vomp_mdp_received(mdp));
  case MDP_PORT_KEYMAPREQUEST:    RETURN(keyring_mapping_request(keyring,mdp));
  case MDP_PORT_DNALOOKUP:        RETURN(overlay_mdp_service_dnalookup(mdp));
  case MDP_PORT_ECHO:             RETURN(overlay_mdp_service_echo(mdp));
  case MDP_PORT_TRACE:            RETURN(overlay_mdp_service_trace(mdp));
  case MDP_PORT_PROBE:            RETURN(overlay_mdp_service_probe(frame, mdp));
  case MDP_PORT_STUNREQ:          RETURN(overlay_mdp_service_stun_req(mdp));
  case MDP_PORT_STUN:             RETURN(overlay_mdp_service_stun(mdp));
  case MDP_PORT_RHIZOME_REQUEST:  RETURN(overlay_mdp_service_rhizomerequest(frame, mdp));
  case MDP_PORT_RHIZOME_RESPONSE: RETURN(overlay_mdp_service_rhizomeresponse(mdp));    
  case MDP_PORT_RHIZOME_MANIFEST_REQUEST: RETURN(overlay_mdp_service_manifest_requests(frame, mdp));
  case MDP_PORT_RHIZOME_SYNC: RETURN(overlay_mdp_service_rhizome_sync(frame, mdp));
  }
   
  /* Unbound socket.  We won't be sending ICMP style connection refused
     messages, partly because they are a waste of bandwidth. */
  RETURN(WHYF("Received packet for which no listening process exists (MDP ports: src=%d, dst=%d",
	      mdp->out.src.port,mdp->out.dst.port));
}
