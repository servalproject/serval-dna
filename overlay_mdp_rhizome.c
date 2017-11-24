/*
Serval DNA basic MDP services
Copyright (C) 2016 Flinders University
Copyright (C) 2010-2015 Serval Project Inc.
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

#include "serval.h"
#include "conf.h"
#include "overlay_buffer.h"
#include "rhizome.h"
#include "mdp_client.h"
#include "debug.h"

static int rhizome_mdp_send_block(struct subscriber *dest, const rhizome_bid_t *bid, uint64_t version, uint64_t fileOffset, uint32_t bitmap, uint16_t blockLength)
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
  header.source = get_my_subscriber(1);
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
	rhizome_mdp_send_block(header->source, &m->keypair.public_key, m->version, 0, 0, m->filesize);
    }
    rhizome_manifest_free(m);
  }
  return 0;
}
