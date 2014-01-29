/*
Copyright (C) 2010-2012 Paul Gardner-Stephen
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
#include "keyring.h"
#include "dataformats.h"

int rhizome_mdp_send_block(struct subscriber *dest, const rhizome_bid_t *bid, uint64_t version, uint64_t fileOffset, uint32_t bitmap, uint16_t blockLength)
{
  IN();
  if (!is_rhizome_mdp_server_running())
    RETURN(-1);
  if (blockLength<=0 || blockLength>1024)
    RETURN(WHYF("Invalid block length %d", blockLength));

  if (config.debug.rhizome_tx)
    DEBUGF("Requested blocks for bid=%s, ver=%"PRIu64" @%"PRIx64" bitmap %x", alloca_tohex_rhizome_bid_t(*bid), version, fileOffset, bitmap);
    
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
    
    ssize_t bytes_read = rhizome_read_cached(bid, version, gettime_ms()+5000, offset, &reply.out.payload[1+16+8+8], blockLength);
    if (bytes_read<=0)
      break;
    
    reply.out.payload_length=1+16+8+8+(size_t)bytes_read;
    
    // Mark the last block of the file, if required
    if ((size_t)bytes_read < blockLength)
      reply.out.payload[0]='T';
    
    // send packet
    if (overlay_mdp_dispatch(&reply, NULL))
      break;
  }

  RETURN(0);
  OUT();
}

int overlay_mdp_service_rhizomerequest(struct internal_mdp_header *header, struct overlay_buffer *payload)
{
  const rhizome_bid_t *bidp = (const rhizome_bid_t *) ob_get_bytes_ptr(payload, sizeof bidp->binary);
  // Note, was originally built using read_uint64 which has reverse byte order of ob_get_ui64
  uint64_t version = ob_get_ui64_rv(payload);
  uint64_t fileOffset = ob_get_ui64_rv(payload);
  uint32_t bitmap = ob_get_ui32_rv(payload);
  uint16_t blockLength = ob_get_ui16_rv(payload);
  if (ob_overrun(payload))
    return -1;
  return rhizome_mdp_send_block(header->source, bidp, version, fileOffset, bitmap, blockLength);
}

int overlay_mdp_service_rhizomeresponse(struct overlay_buffer *payload)
{
  IN();
  
  int type=ob_get(payload);

  if (config.debug.rhizome_mdp_rx)
    DEBUGF("Received Rhizome over MDP block, type=%02x",type);

  switch (type) {
  case 'B': /* data block */
  case 'T': /* terminal data block */
    {
      unsigned char *bidprefix=ob_get_bytes_ptr(payload, 16);
      uint64_t version=ob_get_ui64_rv(payload);
      uint64_t offset=ob_get_ui64_rv(payload);
      if (ob_overrun(payload))
	RETURN(WHYF("Payload too short"));
      size_t count = ob_remaining(payload);
      unsigned char *bytes=ob_current_ptr(payload);
      
      if (config.debug.rhizome_mdp_rx)
	DEBUGF("bidprefix=%02x%02x%02x%02x*, offset=%"PRId64", count=%zu",
	       bidprefix[0],bidprefix[1],bidprefix[2],bidprefix[3],offset,count);

      /* Now see if there is a slot that matches.  If so, then
	 see if the bytes are in the window, and write them.

	 If there is not matching slot, then consider setting 
	 a slot to capture this files as it is being requested
	 by someone else.
      */
      rhizome_received_content(bidprefix,version,offset, count, bytes);

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
  unsigned cn=0, in=0, kp=0;
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

int overlay_mdp_service_echo(struct internal_mdp_header *header, struct overlay_buffer *payload)
{
  /* Echo is easy: we swap the sender and receiver addresses (and thus port
     numbers) and send the frame back. */
  IN();
  
  /* Prevent echo:echo connections and the resulting denial of service from triggering endless pongs. */
  if (header->source_port == MDP_PORT_ECHO)
    RETURN(WHY("echo loop averted"));
    
  struct internal_mdp_header response_header;
  bzero(&response_header, sizeof response_header);
  
  response_header.source = header->destination;
  response_header.source_port = MDP_PORT_ECHO;
  response_header.destination = header->source;
  response_header.destination_port = header->source_port;
  response_header.qos = header->qos;
  
  /* Always send PONGs auth-crypted so that the receipient knows
     that they are genuine, and so that we avoid the extra cost 
     of signing (which is slower than auth-crypting) */
  response_header.modifiers = OF_CRYPTO_CIPHERED|OF_CRYPTO_SIGNED;
  
  /* If the packet was sent to broadcast, then replace broadcast address
     with our local address. */
  if (!response_header.source)
    response_header.source = my_subscriber;
    
  RETURN(overlay_send_frame(&response_header, payload));
  OUT();
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
  overlay_address_append(&context, b, my_subscriber);
  if (ob_overrun(b)) {
    ret = WHYF("Unable to append my address to the trace");
    goto end;
  }
  mdp->out.payload_length = ob_position(b);
  mdp->out.src.sid = my_subscriber->sid;
  mdp->out.dst.sid = next->sid;
  ret = overlay_mdp_dispatch(mdp, NULL);
end:
  ob_free(b);
  RETURN(ret);
}

static int overlay_mdp_service_manifest_requests(struct internal_mdp_header *header, struct overlay_buffer *payload)
{
  while (ob_remaining(payload)) {
    const unsigned char *bar = ob_get_bytes_ptr(payload, RHIZOME_BAR_BYTES);
    if (!bar)
      break;
    rhizome_manifest *m = rhizome_new_manifest();
    if (!m)
      return WHY("Unable to allocate manifest");
    if (!rhizome_retrieve_manifest_by_prefix(&bar[RHIZOME_BAR_PREFIX_OFFSET], RHIZOME_BAR_PREFIX_BYTES, m)){
      rhizome_advertise_manifest(header->source, m);
      // pre-emptively send the payload if it will fit in a single packet
      if (m->filesize > 0 && m->filesize <= 1024)
	rhizome_mdp_send_block(header->source, &m->cryptoSignPublic, m->version, 0, 0, m->filesize);
    }
    rhizome_manifest_free(m);
  }
  return 0;
}

void overlay_mdp_bind_internal_services()
{
  mdp_bind_internal(NULL, MDP_PORT_LINKSTATE, link_receive);
  mdp_bind_internal(NULL, MDP_PORT_ECHO, overlay_mdp_service_echo);
  mdp_bind_internal(NULL, MDP_PORT_RHIZOME_REQUEST, overlay_mdp_service_rhizomerequest);
  mdp_bind_internal(NULL, MDP_PORT_RHIZOME_MANIFEST_REQUEST, overlay_mdp_service_manifest_requests);
  mdp_bind_internal(NULL, MDP_PORT_RHIZOME_SYNC, overlay_mdp_service_rhizome_sync);
}

int overlay_mdp_try_internal_services(
  struct internal_mdp_header *header, struct overlay_buffer *payload)
{
  IN();
  overlay_mdp_frame mdp;
  
  // TODO convert to internal bindings
  switch(header->destination_port) {
  case MDP_PORT_VOMP:
    overlay_mdp_fill_legacy(header, payload, &mdp);
    RETURN(vomp_mdp_received(&mdp));
  case MDP_PORT_KEYMAPREQUEST:
    overlay_mdp_fill_legacy(header, payload, &mdp);
    RETURN(keyring_mapping_request(keyring, header, &mdp));
  case MDP_PORT_DNALOOKUP:
    overlay_mdp_fill_legacy(header, payload, &mdp);
    RETURN(overlay_mdp_service_dnalookup(&mdp));
  case MDP_PORT_TRACE:
    overlay_mdp_fill_legacy(header, payload, &mdp);
    RETURN(overlay_mdp_service_trace(&mdp));
  case MDP_PORT_PROBE:
    overlay_mdp_fill_legacy(header, payload, &mdp);
    RETURN(overlay_mdp_service_probe(header, &mdp));
  case MDP_PORT_STUNREQ:
    overlay_mdp_fill_legacy(header, payload, &mdp);
    RETURN(overlay_mdp_service_stun_req(&mdp));
  case MDP_PORT_STUN:
    overlay_mdp_fill_legacy(header, payload, &mdp);
    RETURN(overlay_mdp_service_stun(&mdp));
  case MDP_PORT_RHIZOME_RESPONSE:
    RETURN(overlay_mdp_service_rhizomeresponse(payload));
  }
   
  /* Unbound socket.  We won't be sending ICMP style connection refused
     messages, partly because they are a waste of bandwidth. */
  RETURN(WHYF("Received packet for which no listening process exists (MDP ports: src=%d, dst=%d",
	      header->source_port, header->destination_port));
}
