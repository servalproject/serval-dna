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
#include "debug.h"
#include "keyring.h"
#include "dataformats.h"
#include "route_link.h"

int rhizome_mdp_send_block(struct subscriber *dest, const rhizome_bid_t *bid, uint64_t version, uint64_t fileOffset, uint32_t bitmap, uint16_t blockLength)
{
  IN();
  if (!is_rhizome_mdp_server_running())
    RETURN(-1);
  if (blockLength<=0 || blockLength>1024)
    RETURN(WHYF("Invalid block length %d", blockLength));

  DEBUGF(rhizome_tx, "Requested blocks for bid=%s, ver=%"PRIu64" @%"PRIx64" bitmap %x", alloca_tohex_rhizome_bid_t(*bid), version, fileOffset, bitmap);
    
  struct internal_mdp_header header;
  bzero(&header, sizeof header);
  
  uint8_t buff[MDP_MTU];
  struct overlay_buffer *payload = ob_static(buff, sizeof(buff));
  
  // Reply is broadcast, so we cannot authcrypt, and signing is too time consuming
  // for low devices.  The result is that an attacker can prevent rhizome transfers
  // if they want to by injecting fake blocks.  The alternative is to not broadcast
  // back replies, and then we can authcrypt.
  // multiple receivers starting at different times, we really need merkle-tree hashing.
  // so multiple receivers is not realistic for now.  So use non-broadcast unicode
  // for now would seem the safest.  But that would stop us from allowing multiple
  // receivers in the special case where additional nodes begin listening in from the
  // beginning.
  
  header.crypt_flags = MDP_FLAG_NO_CRYPT | MDP_FLAG_NO_SIGN;
  header.source = get_my_subscriber();
  header.source_port = MDP_PORT_RHIZOME_RESPONSE;
  
  if (dest && (dest->reachable==REACHABLE_UNICAST || dest->reachable==REACHABLE_INDIRECT)){
    // if we get a request from a peer that we can only talk to via unicast, send data via unicast too.
    header.destination = dest;
  }else{
    // send replies to broadcast so that others can hear blocks and record them
    // (not that preemptive listening is implemented yet).
    header.ttl = 1;
  }
  
  header.destination_port = MDP_PORT_RHIZOME_RESPONSE;
  header.qos = OQ_OPPORTUNISTIC;
  
  int i;
  for(i=0;i<32;i++){
    if (bitmap&(1u<<(31-i)))
      continue;
    
    if (overlay_queue_remaining(header.qos) < 10)
      break;
    
    // calculate and set offset of block
    uint64_t offset = fileOffset+i*blockLength;
    ob_clear(payload);
    ob_append_byte(payload, 'B'); // contains blocks
    // include 16 bytes of BID prefix for identification
    ob_append_bytes(payload, bid->binary, 16);
    // and version of manifest (in the correct byte order)
    ob_append_ui64_rv(payload, version);
    
    ob_append_ui64_rv(payload, offset);
    
    ssize_t bytes_read = rhizome_read_cached(bid, version, gettime_ms()+5000, offset, ob_current_ptr(payload), blockLength);
    if (bytes_read<=0)
      break;
    
    ob_append_space(payload, bytes_read);
    
    // Mark the last block of the file, if required
    if ((size_t)bytes_read < blockLength)
      ob_set(payload, 0, 'T');
    
    // send packet
    ob_flip(payload);
    if (overlay_send_frame(&header, payload))
      break;
  }
  ob_free(payload);
  
  RETURN(0);
  OUT();
}

DEFINE_BINDING(MDP_PORT_RHIZOME_REQUEST, overlay_mdp_service_rhizomerequest);
static int overlay_mdp_service_rhizomerequest(struct internal_mdp_header *header, struct overlay_buffer *payload)
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

DEFINE_BINDING(MDP_PORT_RHIZOME_RESPONSE, overlay_mdp_service_rhizomeresponse);
static int overlay_mdp_service_rhizomeresponse(struct internal_mdp_header *UNUSED(header), struct overlay_buffer *payload)
{
  IN();
  
  int type=ob_get(payload);

  DEBUGF(rhizome_mdp_rx, "Received Rhizome over MDP block, type=%02x",type);

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
      
      DEBUGF(rhizome_mdp_rx, "bidprefix=%02x%02x%02x%02x*, offset=%"PRId64", count=%zu",
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

DEFINE_BINDING(MDP_PORT_DNALOOKUP, overlay_mdp_service_dnalookup);
static int overlay_mdp_service_dnalookup(struct internal_mdp_header *header, struct overlay_buffer *payload)
{
  IN();
  keyring_iterator it;
  keyring_iterator_start(keyring, &it);
  char did[64+1];
  
  int pll=ob_remaining(payload);
  if (pll>64) pll=64;
  
  /* get did from the packet */
  if (pll<1)
    RETURN(WHY("Empty DID in DNA resolution request"));
  
  ob_get_bytes(payload, (unsigned char *)did, pll);
  did[pll]=0;
  
  DEBUG(mdprequests, "MDP_PORT_DNALOOKUP");
  
  int results=0;
  while(keyring_find_did(&it, did))
    {
      /* package DID and Name into reply (we include the DID because
	 it could be a wild-card DID search, but the SID is implied 
	 in the source address of our reply). */
      if (it.keypair->private_key_len > DID_MAXSIZE) 
	/* skip excessively long DID records */
	continue;
      
      struct subscriber *subscriber = it.identity->subscriber;
      const char *unpackedDid = (const char *) it.keypair->private_key;
      const char *name = (const char *)it.keypair->public_key;
      // URI is sid://SIDHEX/DID
      strbuf b = strbuf_alloca(SID_STRLEN + DID_MAXSIZE + 10);
      strbuf_puts(b, "sid://");
      strbuf_tohex(b, SID_STRLEN, subscriber->sid.binary);
      strbuf_puts(b, "/local/");
      strbuf_puts(b, unpackedDid);
      overlay_mdp_dnalookup_reply(header->source, header->source_port, subscriber, strbuf_str(b), unpackedDid, name);
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
    dna_helper_enqueue(header->source, header->source_port, did);
    monitor_tell_formatted(MONITOR_DNAHELPER, "LOOKUP:%s:%d:%s\n", 
			   alloca_tohex_sid_t(header->source->sid), header->source_port, 
			   did);
  }
  RETURN(0);
}

DEFINE_BINDING(MDP_PORT_ECHO, overlay_mdp_service_echo);
static int overlay_mdp_service_echo(struct internal_mdp_header *header, struct overlay_buffer *payload)
{
  IN();
  
  if (header->source_port == MDP_PORT_ECHO)
    RETURN(WHY("Prevented infinite echo loop"));
    
  struct internal_mdp_header response_header;
  bzero(&response_header, sizeof response_header);
  
  mdp_init_response(header, &response_header);
  // keep all defaults
  
  RETURN(overlay_send_frame(&response_header, payload));
  OUT();
}

/*
 * Trace packets are a little weird so that they can be modified by every node
 * and so they can bypass the routing table.
 * 
 * The true source and destination addresses are encoded inside the payload
 * each node that processes the packet appends their own address before forwarding it to the next hop
 * if their SID is already in the packet, the next hop is chosen from the immediately preceeding SID in the list.
 * otherwise the next SID is chosen based on the current routing table.
 * 
 * In this way the packet can follow the path defined by each node's routing table
 * Until the packet reaches the destination, the destination is unreachable, or the packet loops around the network
 * Once any of these end states occurs, the packet attempts to travel back to the source node, 
 * while using the source addresses in the trace packet for guidance instead of trusting the routing table.
 * 
 * It is hoped that this information can be useful to better understand the current network state 
 * in situations where a routing protocol is in development.
 */

DEFINE_BINDING(MDP_PORT_TRACE, overlay_mdp_service_trace);
static int overlay_mdp_service_trace(struct internal_mdp_header *header, struct overlay_buffer *payload){
  IN();
  struct overlay_buffer *next_payload = ob_new();
  if (!next_payload)
    RETURN(-1);
  ob_append_bytes(next_payload, ob_current_ptr(payload), ob_remaining(payload));
  
  int ret=0;
  struct subscriber *src=NULL, *dst=NULL, *last=NULL;
  struct decode_context context;
  bzero(&context, sizeof context);
  
  if (header->source_port == MDP_PORT_TRACE){
    ret=WHYF("Invalid source port");
    goto end;
  }
  if (overlay_address_parse(&context, payload, &src)){
    ret=WHYF("Invalid source SID");
    goto end;
  }
  if (overlay_address_parse(&context, payload, &dst)){
    ret=WHYF("Invalid destination SID");
    goto end;
  }
  if (context.flags & DECODE_FLAG_INVALID_ADDRESS){
    ret=WHYF("Unknown address in trace packet");
    goto end;
  }

  INFOF("Trace from %s to %s", alloca_tohex_sid_t(src->sid), alloca_tohex_sid_t(dst->sid));
  struct internal_mdp_header next_header;
  next_header = *header;
  next_header.source = get_my_subscriber();
  next_header.destination = NULL;
  
  while(ob_remaining(payload)>0){
    struct subscriber *trace=NULL;
    if (overlay_address_parse(&context, payload, &trace)){
      ret=WHYF("Invalid SID in packet payload");
      goto end;
    }
    if (context.flags & DECODE_FLAG_INVALID_ADDRESS){
      ret=WHYF("Unknown SID in packet payload");
      goto end;
    }
    INFOF("Via %s", alloca_tohex_sid_t(trace->sid));
    
    if (trace->reachable==REACHABLE_SELF && !next_header.destination)
      // We're already in this trace, send the next packet to the node before us in the list
      next_header.destination = last;
    last = trace;
  }
  
  if (src->reachable==REACHABLE_SELF && last){
    // it came back to us, we can send the reply to our mdp client...
    next_header.destination=src;
    next_header.destination_port = header->source_port;
    next_header.source_port = MDP_PORT_TRACE;
  }
  
  if (!next_header.destination){
    // destination is our neighbour?
    if (dst->reachable & REACHABLE_DIRECT)
      next_header.destination = dst;
    // destination is indirect?
    else if (dst->reachable & REACHABLE_INDIRECT)
      next_header.destination = dst->next_hop;
    // destination is not reachable or is ourselves? bounce back to the previous node or the sender.
    else if (last)
      next_header.destination = last;
    else
      next_header.destination = src;
  }
  
  INFOF("Next node is %s", alloca_tohex_sid_t(next_header.destination->sid));
  
  // always write a full sid into the payload
  next_header.source->send_full=1;
  overlay_address_append(&context, next_payload, next_header.source);
  if (ob_overrun(next_payload)) {
    ret = WHYF("Unable to append my address to the trace");
    goto end;
  }
  ob_flip(next_payload);
  ret = overlay_send_frame(&next_header, next_payload);
end:
  ob_free(next_payload);
  RETURN(ret);
}

DEFINE_BINDING(MDP_PORT_RHIZOME_MANIFEST_REQUEST, overlay_mdp_service_manifest_requests);
static int overlay_mdp_service_manifest_requests(struct internal_mdp_header *header, struct overlay_buffer *payload)
{
  while (ob_remaining(payload)) {
    const unsigned char *bar = ob_get_bytes_ptr(payload, RHIZOME_BAR_BYTES);
    if (!bar)
      break;
    rhizome_manifest *m = rhizome_new_manifest();
    if (!m)
      return WHY("Unable to allocate manifest");
    if (rhizome_retrieve_manifest_by_prefix(&bar[RHIZOME_BAR_PREFIX_OFFSET], RHIZOME_BAR_PREFIX_BYTES, m)==RHIZOME_BUNDLE_STATUS_SAME){
      rhizome_advertise_manifest(header->source, m);
      // pre-emptively send the payload if it will fit in a single packet
      if (m->filesize > 0 && m->filesize <= 1024)
	rhizome_mdp_send_block(header->source, &m->cryptoSignPublic, m->version, 0, 0, m->filesize);
    }
    rhizome_manifest_free(m);
  }
  return 0;
}

