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
#include "str.h"
#include "strbuf.h"
#include "overlay_buffer.h"
#include "overlay_address.h"
#include "overlay_packet.h"
#include "mdp_client.h"
#include "rhizome.h"
#include "crypto.h"
#include "log.h"

int overlay_mdp_service_rhizomerequest(overlay_mdp_frame *mdp)
{
  IN();

  uint64_t fileOffset=
    read_uint64(&mdp->out.payload[RHIZOME_MANIFEST_ID_BYTES+8]);
  uint32_t bitmap=
    read_uint32(&mdp->out.payload[RHIZOME_MANIFEST_ID_BYTES+8+8]);
  uint16_t blockLength=
  read_uint16(&mdp->out.payload[RHIZOME_MANIFEST_ID_BYTES+8+8+4]);
  if (blockLength>1024) RETURN(-1);

  struct subscriber *source = find_subscriber(mdp->out.src.sid, SID_SIZE, 0);
  
  if(0) {
    DEBUGF("Someone sent me a rhizome request via MDP");
    DEBUGF("requestor sid = %s",alloca_tohex_sid(mdp->out.src.sid));
    DEBUGF("bundle ID = %s",alloca_tohex_bid(&mdp->out.payload[0]));
    DEBUGF("manifest version = 0x%llx",
	   read_uint64(&mdp->out.payload[RHIZOME_MANIFEST_ID_BYTES]));
    DEBUGF("file offset = 0x%llx",fileOffset);
    DEBUGF("bitmap = 0x%08x",bitmap);
    DEBUGF("block length = %d",blockLength);
  }

  /* Find manifest that corresponds to BID and version.
     If we don't have this combination, then do nothing.
     If we do have the combination, then find the associated file, 
     and open the blob so that we can send some of it.

     TODO: If we have a newer version of the manifest, and the manifest is a
     journal, then the newer version is okay to use to service this request.
  */
  long long row_id=-1;
  if (sqlite_exec_int64(&row_id, "SELECT rowid FROM FILES WHERE id IN (SELECT filehash FROM MANIFESTS WHERE manifests.version=%lld AND manifests.id='%s');",
			read_uint64(&mdp->out.payload[RHIZOME_MANIFEST_ID_BYTES]),
			alloca_tohex_bid(&mdp->out.payload[0])) < 1)
    {
      DEBUGF("Couldn't find stored file.");
      RETURN(-1);
    }
  
  sqlite3_blob *blob=NULL; 
  int ret=sqlite3_blob_open(rhizome_db, "main", "files", "data",
				   row_id, 0 /* read only */, &blob);
  if (ret!=SQLITE_OK)
    {
      DEBUGF("Failed to open blob: %s",sqlite3_errmsg(rhizome_db));     
      RETURN(-1);
    }
  int blob_bytes=sqlite3_blob_bytes(blob);  
  if (blob_bytes<fileOffset) {
    sqlite3_blob_close(blob); blob=NULL;
    RETURN(-1);
  }

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
  reply.out.ttl=1;
  bcopy(my_subscriber->sid,reply.out.src.sid,SID_SIZE);
  reply.out.src.port=MDP_PORT_RHIZOME_RESPONSE;
  if (source && source->reachable&REACHABLE_UNICAST){
    // if we get a request from a peer that we can only talk to via unicast, send data via unicast too.
    bcopy(mdp->out.src.sid,reply.out.dst.sid,SID_SIZE);
  }else{
    // send replies to broadcast so that others can hear blocks and record them
    // (not that preemptive listening is implemented yet).
    memset(reply.out.dst.sid,0xff,SID_SIZE);
  }
  reply.out.dst.port=MDP_PORT_RHIZOME_RESPONSE;
  reply.out.queue=OQ_ORDINARY;
  reply.out.payload[0]='B'; // reply contains blocks
  // include 16 bytes of BID prefix for identification
  bcopy(&mdp->out.payload[0],&reply.out.payload[1],16);
  // and version of manifest
  bcopy(&mdp->out.payload[RHIZOME_MANIFEST_ID_BYTES],
	&reply.out.payload[1+16],8);
  
  int i;
  for(i=0;i<32;i++)
    if (!(bitmap&(1<<(31-i))))
      {	
	// calculate and set offset of block
	uint64_t blockOffset=fileOffset+i*blockLength;
	write_uint64(&reply.out.payload[1+16+8],blockOffset);
	// work out how many bytes to read
	int blockBytes=blob_bytes-blockOffset;
	if (blockBytes>blockLength) blockBytes=blockLength;
	// read data for block
	if (blob_bytes>=blockOffset) {
	  sqlite3_blob_read(blob,&reply.out.payload[1+16+8+8],
			    blockBytes,blockOffset);	  
	  reply.out.payload_length=1+16+8+8+blockBytes;

	  // Mark terminal block if required
	  if (blockOffset+blockBytes==blob_bytes) reply.out.payload[0]='T';
	  // send packet
	  overlay_mdp_dispatch(&reply,0 /* system generated */, NULL,0); 
	} else break;
      }

  sqlite3_blob_close(blob); blob=NULL;

  RETURN(-1);
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
      if (0) 
	DEBUGF("Received %d bytes @ 0x%llx for %s* version 0x%llx",
	       count,offset,alloca_tohex(bidprefix,16),version);

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

struct probe_contents{
  struct sockaddr_in addr;
  unsigned char interface;
};

/* Collection of unicast echo responses to detect working links */
static int
overlay_mdp_service_probe(overlay_mdp_frame *mdp)
{
  IN();
  if (mdp->out.src.port!=MDP_PORT_ECHO || mdp->out.payload_length != sizeof(struct probe_contents)){
    WARN("Probe packets should be returned from remote echo port");
    RETURN(-1);
  }
  
  struct subscriber *peer = find_subscriber(mdp->out.src.sid, SID_SIZE, 0);
  struct probe_contents probe;
  bcopy(&mdp->out.payload, &probe, sizeof(struct probe_contents));
  if (probe.addr.sin_family!=AF_INET)
    RETURN(WHY("Unsupported address family"));
  
  if (peer->reachable == REACHABLE_NONE || peer->reachable == REACHABLE_INDIRECT || (peer->reachable & REACHABLE_ASSUMED)){
    reachable_unicast(peer, &overlay_interfaces[probe.interface], probe.addr.sin_addr, probe.addr.sin_port);
  }
  RETURN(0);
}

int overlay_send_probe(struct subscriber *peer, struct sockaddr_in addr, overlay_interface *interface){
  if (interface==NULL)
    interface = overlay_interface_find(addr.sin_addr);
  
  if (!interface)
    return WHY("I don't know which interface to use");
  
  time_ms_t now = gettime_ms();
  
  if (peer && peer->last_probe+1000>now)
    return -1;
    
  struct overlay_frame *frame=malloc(sizeof(struct overlay_frame));
  bzero(frame,sizeof(struct overlay_frame));
  frame->type=OF_TYPE_DATA;
  frame->source = my_subscriber;
  frame->next_hop = frame->destination = peer;
  frame->ttl=1;
  frame->queue=OQ_MESH_MANAGEMENT;
  frame->destination_resolved=1;
  frame->recvaddr=addr;
  frame->flags=PACKET_UNICAST;
  frame->interface=interface;
  frame->payload = ob_new();
  frame->send_copies=3;
  
  if ((!peer) || !(peer->reachable&REACHABLE))
    my_subscriber->send_full=1;
  
  if (peer)
    peer->last_probe=gettime_ms();
  
  if (overlay_mdp_encode_ports(frame->payload, MDP_PORT_ECHO, MDP_PORT_PROBE)){
    op_free(frame);
    return -1;
  }
  // not worried about byte order here as we are the only node that should be parsing the contents.
  unsigned char *dst=ob_append_space(frame->payload, sizeof(struct probe_contents));
  if (!dst){
    op_free(frame);
    return -1;
  }
  struct probe_contents probe;
  probe.addr=addr;
  // get interface number
  probe.interface = interface - overlay_interfaces;
  bcopy(&probe, dst, sizeof(struct probe_contents));
  if (overlay_payload_enqueue(frame)){
    op_free(frame);
    return -1;
  }
  DEBUGF("Queued probe packet on interface %s to %s", interface->name, inet_ntoa(addr.sin_addr));
  return 0;
}

int overlay_mdp_try_interal_services(overlay_mdp_frame *mdp)
{
  IN();
  switch(mdp->out.dst.port) {
  case MDP_PORT_VOMP:             RETURN(vomp_mdp_received(mdp));
  case MDP_PORT_KEYMAPREQUEST:    RETURN(keyring_mapping_request(keyring,mdp));
  case MDP_PORT_DNALOOKUP:        RETURN(overlay_mdp_service_dnalookup(mdp));
  case MDP_PORT_ECHO:             RETURN(overlay_mdp_service_echo(mdp));
  case MDP_PORT_PROBE:            RETURN(overlay_mdp_service_probe(mdp));
  case MDP_PORT_RHIZOME_REQUEST: 
    if (is_rhizome_mdp_server_running()) {
      RETURN(overlay_mdp_service_rhizomerequest(mdp));
    } else break;
  case MDP_PORT_RHIZOME_RESPONSE:
    if (is_rhizome_mdp_server_running()) {
      RETURN(overlay_mdp_service_rhizomeresponse(mdp));
    } else break;
  }
   
  /* Unbound socket.  We won't be sending ICMP style connection refused
     messages, partly because they are a waste of bandwidth. */
  RETURN(WHYF("Received packet for which no listening process exists (MDP ports: src=%d, dst=%d",
	      mdp->out.src.port,mdp->out.dst.port));
}
