/*
Serval DNA MDP lookup service
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
#include "debug.h"
#include "overlay_buffer.h"

DEFINE_BINDING(MDP_PORT_DNALOOKUP, overlay_mdp_service_dnalookup);
static int overlay_mdp_service_dnalookup(struct internal_mdp_header *header, struct overlay_buffer *payload)
{
  IN();
  assert(keyring != NULL);
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
