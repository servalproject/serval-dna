/*
Serval Distributed Numbering Architecture (DNA)
Copyright (C) 2010 Paul Gardner-Stephen
 
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

/*
  We use 256bit Curve25519 addresses in the overlay mesh.  This means we have very large
  addresses to send around the place on a regular basis, which is bad.

  We allow addresses to be shortened to save bandwidth, especially for low-bandwidth links.

  For this purpose we have special address prefixes 0x00 - 0x0f which are not allowed to
  occur in unabbreviated addresses.
  
  0x00      = reserved
  0x01-0x02 = one to two byte address by index.
  0x03      = same as last address.
  0x04      = address matches sender (not currently implemented).
  0x05      = address by prefix of three bytes. 
  0x06      = address by prefix of seven bytes. 
  0x07      = address by prefix of eleven bytes.
  0x08      = full address followed by one-byte index allocation.
  0x09-0x0b = same as 0x05-0x07, but assign single byte index.
  0x0c      = reserved.
  0x0d      = same as 0x07, but assign two byte index.
  0x0e      = full address followed by two-byte index allocation.
  0x0f      = broadcast link-local.
  
  However, in this implementation we not include support for the two-byte 
  index code, as it requires 64Kx32=2MB storage, which is too much to ask
  of a mesh potato or a cheap smart phone.

  All indexed abbreviations may reference a token which is used to keep
  track of the epoch of the abbreviation table.  

  This allows us to maintain multiple abbreviation tables at the same time, so 
  that neighbours we have not spoken to for some time will not be so easily 
  confused, as any one epoch will remain valid for some time after it has 
  ceased to be ammended.

  This also allows us to effectively have multiple 256-entry pages, which will
  be more efficient than using a 16-bit index table in most instances, especially
  since we have the flexibility to reorder frames in an ensemble to minimise the
  total length.

  One table is maintained for all interfaces, as we may have neighbours who are
  reachable via multiple interfaces.  It also helps to minimise memory usage.

  A cache of recently seen addresses is also desirable for conclusively resolving
  abbreviated addresses. Failure will allow the birthday paradox to cause us problems
  and also allow an attack based on searching for private keys that yield colliding
  public key prefixes.  This would allow an attacker to mess with the routing and
  divert the traffic of other nodes to themselves.  Thus some cache or similar policy
  is strongly recommended if a node is going to accept address prefixes, especially if 
  it accepts the shorter prefixes.  Seven and eleven byte prefixes should be reasonably
  resistant to this attack. 

  There is no reason why the address abbreviation table cannot be used as the cache,
  excepting for the question of efficiency, as a naive implementation would require
  a linear search.  However, adding a simple index table can mitigate this, and thus
  presents as a sensible solution.  

  If a node receives a packet with an abbreviation that it cannot resolve an
  abbreviation can ask for clarification, including indicating if it does 
  not support the abbreviation mode specified.

  Abbreviations are link-local, but clarifications will always be requested by
  attempting to contact the abbreviator via normal mesh routing rules.

  We need to take some care so as to allow other crypto-systems, and thus storing the
  crypto-system ID byte, although we still limit addresses to 256 bits, so we always need
  no more than 33 bytes.  In any case, indicating the crypto system is not the problem of
  this section, as we are just concerned with abbreviating and expanding the addresses.

  (A simple solution to the multiple crypto-system problem is to have the receiver try each
  known crypto system when decoding a frame, and remember which addresses use which system.
  Probably a reasonable solution for now.)

  To decode abbreviations supplied by other nodes we need to try to replicate a copy of
  their abbreviation table.  This is where things get memory intensive (about 8KB per node).
  However, we only need the table of one-hop neighbours, and it is reasonable to have a
  constrained set of such tables, with a random replacement algorithm.  This allows the 
  structure to be scaled to accomodate varying memory sizes of devices. 
  
  Very memory constrained devices may elect to cache individual entries rather than tables
  of individual nodes, but we haven't implemented that here.

  If we send only a prefix, then we need to be careful to make sure that receivers
  get some chance to learn the full address if they need it. The question is whether
  abbreviation clarification is more or less efficient than sometimes sending the 
  full address.  Given that we already have need for the clarification process, let's
  go that way, and change the policy later if appropriate.

  Having had said this, on mono-directional links there is a problem with using the
  various abbreviation schemes that require state.  And this is that the receiver has
  no way to issue a please-explain.  In these situations, we need to fall-back to at
  most using the abbreviations only most of the time, and still sending the full-address
  some of the time, so that even without a feedback look to ask for explanations the
  receiver should synchronise with us fairly well.

  Also, we haven't implemented index-based lookup on the receiver side, so we need to fix
  that or disable it on the sender side.

*/

overlay_address_table *abbrs=NULL;
overlay_address_cache *cache=NULL;

sid overlay_abbreviate_previous_address={{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}};

/* The address of the sender of the current frame.
   The ID is used to lookup the abbreviation indexes.
   If the ID is -1, then this means that the sender SID has been set, but not looked up.
   This just saves some time instead of doing the *_id determination each time, when we might not need
   it on most occassions.
*/
sid overlay_abbreviate_current_sender={{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}};
int overlay_abbreviate_current_sender_set=0;
int overlay_abbreviate_current_sender_id=-1;

int overlay_abbreviate_prepare_cache()
{
  if (OVERLAY_ADDRESS_CACHE_SIZE>0x1000000) 
    exit(WHY("OVERLAY_ADDRESS_CACHE_SIZE must be no larger than 2^24."));
  if (OVERLAY_ADDRESS_CACHE_SIZE<0)
    exit(WHY("OVERLAY_ADDRESS_CACHE_SIZE must be larger than 0."));
  
  /* Allocate cache */
  cache=calloc(sizeof(overlay_address_cache),1);
  if (!cache) return 0;
  
  /* Allocate address cache */
  cache->size=OVERLAY_ADDRESS_CACHE_SIZE;
  cache->sids=calloc(sizeof(sid),cache->size);
  if (!cache->sids) { free(cache); return 0; }
  
  /* Work out the number of bits to shift */
  cache->shift=0;
  while(cache->size>>(cache->shift+1)) cache->shift++;
  
  if ((1<<cache->shift)!=cache->size)
    {
      fprintf(stderr,"cache->size=%d, shift=%d\n",cache->size,cache->shift);
      exit(WHY("OVERLAY_ADDRESS_CACHE_SIZE must be a power of two."));
    }

  cache->shift=24-cache->shift;

  return 0;
}

int overlay_abbreviate_cache_address(unsigned char *sid)
{
  if ((!cache)&&OVERLAY_ADDRESS_CACHE_SIZE>0) overlay_abbreviate_prepare_cache();
  if (!cache) return 0;

  /* Work out the index in the cache where this address would go.
     The XOR 1 is to make sure that all zeroes address doesn't live in index 0,
     which would otherwise result in it being detected as already present. */
  int index=(((sid[0]<<16)|(sid[1]<<8)|sid[2])>>cache->shift)^1;

  /* Does the stored address match the one we have been passed? */
  if (!memcmp(sid,&cache->sids[index].b[0],SID_SIZE))
    /* Address is already in cache, so return and let the caller know. */
    return 1;

  /* Not yet in cache, so store it */
  bcopy(sid,&cache->sids[index].b[0],SID_SIZE);
  if (debug&DEBUG_OVERLAYABBREVIATIONS) {
    DEBUGF("Cached address %s", alloca_tohex_sid(sid));
  }

  return 0;
}

int overlay_abbreviate_try_byindex(unsigned char *in,unsigned char *out,int *ofs,
				   int index)
{
  if(!memcmp(in,abbrs->sids[index],SID_SIZE))
    {
      /* We can encode this address with one byte */
      /* Don't always abbreviate as the receiver may not have the means to send us
	 please-explains, e.g., due to mono-directional links.  Thus we want to resend
	 the whole address sometimes. */
      if (random()&7) {
	/* Do use abbreviation */
	out[(*ofs)++]=0x01;
	out[(*ofs)++]=index;
	return 0;
      } else {
	/* Don't use the abbreviation this time, but rather repeat it again for the 
	   receiving side to cache.
	   XXX - Should we use a prefix here instead of full length?
	*/
	out[(*ofs)++]=0x08;
	bcopy(in,&out[(*ofs)],SID_SIZE);
	(*ofs)+=SID_SIZE;
	out[(*ofs)++]=index;
	return 0;
      }
    }
  else
    /* Cannot find index in our node list. */
    return 1;
}

int overlay_abbreviate_append_address(overlay_buffer *b,unsigned char *a)
{
  int count=0;
  ob_makespace(b,SID_SIZE+3);
  int r=overlay_abbreviate_address(a,&b->bytes[b->length],&count);
  if (debug&DEBUG_PACKETCONSTRUCTION) {
    fprintf(stderr,"address %s abbreviates as shown in this ",
	    alloca_tohex_sid(a));
    dump(NULL,&b->bytes[b->length],count);
  }
  if (r) return r;
  b->length+=count;
  overlay_abbreviate_set_most_recent_address(a);
  return 0;
}

int overlay_abbreviate_address(unsigned char *in,unsigned char *out,int *ofs)
{
  int i;
  int wasInCachedP=overlay_abbreviate_cache_address(in);
  
  if (!in) return WHY("in==NULL");
  if (in[0]<0x10) return WHY("Invalid address - 0x00-0x0f are reserved prefixes.");

  /* Is this the same as the current sender? */
  if (overlay_abbreviate_current_sender_set){
    for(i=0;i<SID_SIZE;i++)
      if (in[i]!=overlay_abbreviate_current_sender.b[i])
	break;
    if (i==SID_SIZE) {
      out[(*ofs)++]=OA_CODE_SELF; 
      return 0;
    } 
  }
  
  /* Try repeating previous address */
  for(i=0;i<SID_SIZE;i++)
    if (in[i]!=overlay_abbreviate_previous_address.b[i])
      break;
  if (i==SID_SIZE) { 
    out[(*ofs)++]=OA_CODE_PREVIOUS; 
    return 0;
  } 

  /* Is it a broadcast address? */
  if (overlay_address_is_broadcast(in)) {
    /* write broadcast code followed by 64bit BPI tail */
    out[(*ofs)++]=OA_CODE_BROADCAST;
    for(i=0;i<8;i++) out[(*ofs)++]=in[24+i];
    return 0;
  }

  if (!abbrs) {
    // Abbreviation table not setup, so allocate it.
    // Epoch starts at zero. 
    // XXX We have only one simultaneous epoch here, not that it is a problem.
    abbrs=calloc(sizeof(overlay_address_table),1);
    if (!abbrs)
      {
	// Could not allocate abbreviation table, so just output full-length address.
	WHY("calloc() failed.");
	bcopy(in,&out[*ofs],SID_SIZE);
	(*ofs)+=SID_SIZE;
	return 0;
      }
    abbrs->next_free=1;
  }

  /* Try abbreviating by index
     XXX should search backwards through old epochs
     XXX If we do, we need a way to indicate a reference to an old epoch */
  for(i=0;i<2;i++)
    if (abbrs->byfirstbyte[in[0]][i])
      { 
	if (0) { if (!overlay_abbreviate_try_byindex(in,out,ofs,abbrs->byfirstbyte[in[0]][i])) return 0; } 
	else {
	  if (debug&DEBUG_OVERLAYABBREVIATIONS) 
	    WHY("Abbreviation by index temporarily disabled to simplify development");
	}
      }
    else break;

  if (i<2&&abbrs->next_free) {
    // There is a spare slot to abbreviate this address by storing it in an index if we 
    // wish. So let's store it, then send the full address along with the newly allocated
    // index.

    /* Remember this address */
    bcopy(in,abbrs->sids[abbrs->next_free],SID_SIZE);
    abbrs->byfirstbyte[in[0]][i]=abbrs->next_free;

    /* Write address out with index code */
    out[(*ofs)++]=OA_CODE_FULL_INDEX1;
    bcopy(in,&out[(*ofs)],SID_SIZE);
    (*ofs)+=SID_SIZE;
    out[(*ofs)++]=abbrs->next_free;

    /* Tidy things up and return triumphant. */
    abbrs->next_free++;

    return 0;
  }

  /* No space in our table, so either send address verbatim, or send only a prefix.
     Go for prefix. Next question is length of prefix. Seven bytes is probably about
     right as an simple initial policy. */
  if (wasInCachedP) {
    /* Prefix addresses that have been seen recently */
    out[(*ofs)++]=OA_CODE_PREFIX7;
    bcopy(in,&out[(*ofs)],7);
    (*ofs)+=7;
    return 0;
  } else {
    /* But send full address for those we haven't seen before */
    bcopy(in,&out[*ofs],SID_SIZE);
    (*ofs)+=SID_SIZE;
    return 0;
  }

}

int overlay_abbreviate_expand_address(unsigned char *in,int *inofs,unsigned char *out,int *ofs)
{
  int bytes=0,r;
  if (debug&DEBUG_OVERLAYABBREVIATIONS)
    DEBUGF("Address first byte/abbreviation code=%02x (input offset=%d)\n",in[*inofs],*inofs);
  switch(in[*inofs])
    {
    case OA_CODE_02: case OA_CODE_04: case OA_CODE_0C:
      /* Unsupported codes, so tell the sender 
	 if the frame was addressed to us as next-hop */
      (*inofs)++;
      WHY("Reserved address abbreviation code");
      return OA_UNSUPPORTED;
    case OA_CODE_SELF: /* address matches the sender who produced the 
			selfannounce in this packet.  Naturally it cannot be 
			used to encode the sender's address there ;) */
      (*inofs)++;
      if (debug&DEBUG_OVERLAYABBREVIATIONS) DEBUGF("Resolving OA_CODE_SELF.\n");
      if (overlay_abbreviate_current_sender_set) {
	bcopy(&overlay_abbreviate_current_sender.b[0],&out[*ofs],SID_SIZE);
	overlay_abbreviate_set_most_recent_address(&out[*ofs]);
	(*ofs)+=SID_SIZE;
	return OA_RESOLVED;
      } else {
	WARN("Cannot resolve OA_CODE_SELF if the packet doesn't start with a self announcement.\n");
	return OA_UNINITIALISED;
      }
    case OA_CODE_INDEX: /* single byte index look up */
      /* Lookup sender's neighbour ID */
      if (overlay_abbreviate_current_sender_id==-1) if (overlay_abbreviate_lookup_sender_id()) return WHY("could not lookup neighbour ID of packet sender");
      r=overlay_abbreviate_cache_lookup(overlay_neighbours[overlay_abbreviate_current_sender_id].one_byte_index_address_prefixes[in[*inofs]],
				      out,ofs,OVERLAY_SENDER_PREFIX_LENGTH,0);
      (*inofs)++;
      if (r==OA_RESOLVED)
	overlay_abbreviate_set_most_recent_address(&out[*ofs]);
      (*inofs)++;
      return r;
    case OA_CODE_PREVIOUS: /* Same as last address */
      (*inofs)++;
      bcopy(&overlay_abbreviate_previous_address.b[0],&out[*ofs],SID_SIZE);
      overlay_abbreviate_set_most_recent_address(&out[*ofs]);
      (*ofs)+=SID_SIZE;
      return OA_RESOLVED;
    case OA_CODE_PREFIX3: case OA_CODE_PREFIX3_INDEX1: /* 3-byte prefix */
      if (in[*inofs]==0x09) bytes=1;
      r=overlay_abbreviate_cache_lookup(&in[(*inofs)+1],out,ofs,3,bytes);
      (*inofs)+=1+3+bytes;
      if (r==OA_RESOLVED)
	overlay_abbreviate_set_most_recent_address(&out[(*ofs)-SID_SIZE]);
      return r;
    case OA_CODE_PREFIX7: case OA_CODE_PREFIX7_INDEX1: /* 7-byte prefix */
      if (in[*inofs]==OA_CODE_PREFIX7_INDEX1) bytes=1;
      r=overlay_abbreviate_cache_lookup(&in[(*inofs)+1],out,ofs,7,bytes);
      (*inofs)+=1+7+bytes;
      if (r==OA_RESOLVED)
	overlay_abbreviate_set_most_recent_address(&out[(*ofs)-SID_SIZE]);
      return r;
    case OA_CODE_PREFIX11: case OA_CODE_PREFIX11_INDEX1: case OA_CODE_PREFIX11_INDEX2: /* 11-byte prefix */
      bytes=0;
      if (in[*inofs]==OA_CODE_PREFIX11_INDEX1) bytes=1;
      if (in[*inofs]==OA_CODE_PREFIX11_INDEX2) bytes=2;
      r=overlay_abbreviate_cache_lookup(&in[(*inofs)+1],out,ofs,11,bytes);
      (*inofs)+=1+11+bytes;
      if (r==OA_RESOLVED)
	overlay_abbreviate_set_most_recent_address(&out[(*ofs)-SID_SIZE]);
      return r;
    case OA_CODE_BROADCAST: /* broadcast */
      memset(&out[*ofs],0xff,SID_SIZE-8);
      (*inofs)++;
      /* Copy Broadcast Packet Identifier */
      { int i; for(i=0;i<8;i++) out[(*ofs)+24+i]=in[(*inofs)+i]; }
      if (debug&DEBUG_BROADCASTS) 
	DEBUGF("Expanded broadcast address with "
		"BPI=%02X%02X%02X%02X%02X%02X%02X%02X\n",
		in[(*inofs)+0],in[(*inofs)+1],in[(*inofs)+2],in[(*inofs)+3],
		in[(*inofs)+4],in[(*inofs)+5],in[(*inofs)+6],in[(*inofs)+7]);
      (*inofs)+=8;
      overlay_abbreviate_set_most_recent_address(&out[*ofs]);
      return OA_RESOLVED;
    case OA_CODE_FULL_INDEX1: case OA_CODE_FULL_INDEX2: 
    default: /* Full address, optionally followed by index for us to remember */
      if (in[*inofs]==OA_CODE_FULL_INDEX1) bytes=1; 
      if (in[*inofs]==OA_CODE_FULL_INDEX2) bytes=2;
      if (bytes) (*inofs)++; /* Skip leading control code if present */
      bcopy(&in[*inofs],&out[*ofs],SID_SIZE);
      if (bytes) overlay_abbreviate_remember_index(bytes,&in[*inofs],&in[(*inofs)+SID_SIZE]);
      overlay_abbreviate_cache_address(&in[*inofs]);
      overlay_abbreviate_set_most_recent_address(&in[*inofs]);
      (*inofs)+=SID_SIZE+bytes;
      return OA_RESOLVED;
    }
}

int overlay_abbreviate_lookup_sender_id()
{
  if (!overlay_abbreviate_current_sender_set)
    return WHY("Sender has not been set");
  overlay_neighbour *neh=overlay_route_get_neighbour_structure(overlay_abbreviate_current_sender.b,SID_SIZE,1 /* create if needed */);
  if (!neh) { overlay_abbreviate_current_sender_id=-1; return WHY("Could not find sender in neighbour list"); }
  /* Okay, so the following is a little tortuous in asking our parent who we are instead of just knowing, 
     but it will do for now */
  if (!neh->node) return WHY("neighbour structure has no associated node");
  overlay_abbreviate_current_sender_id=neh->node->neighbour_id;
  return 0;
}

int overlay_abbreviate_remember_index(int index_byte_count,unsigned char *sid_to_remember,unsigned char *index_bytes)
{
  int zero=0;
  char sid[SID_STRLEN+1];
  int index=index_bytes[0];
  if (index_byte_count>1) index=(index<<8)|index_bytes[1];

  /* Lookup sender's neighbour ID */
  if (overlay_abbreviate_current_sender_id==-1) overlay_abbreviate_lookup_sender_id();

  sid[0]=0; extractSid(sid_to_remember,&zero,sid);
  if (debug&DEBUG_OVERLAYABBREVIATIONS) {
    fprintf(stderr,"index=%d\n",index);
    fprintf(stderr,"We need to remember that the sender #%d has assigned index #%d to the following:\n      [%s]\n",
	  overlay_abbreviate_current_sender_id,index,sid);
  }

  bcopy(sid_to_remember,overlay_neighbours[overlay_abbreviate_current_sender_id].one_byte_index_address_prefixes[index],OVERLAY_SENDER_PREFIX_LENGTH);
  return 0;
}

int overlay_abbreviate_cache_lookup(unsigned char *in,unsigned char *out,int *ofs,
				    int prefix_bytes,int index_bytes)
{
  /* Lookup this entry from the cache, and also assign it the specified prefix */
  if ((!cache)&&OVERLAY_ADDRESS_CACHE_SIZE>0) overlay_abbreviate_prepare_cache();
  if (!cache) return OA_PLEASEEXPLAIN; /* No cache? Then ask for address in full */  

  /* Work out the index in the cache where this address would live */
  int index=(((in[0]<<16)|(in[1]<<8)|in[2])>>cache->shift)^1;

  int i;
  if (debug&DEBUG_OVERLAYABBREVIATIONS) {
    fprintf(stderr,"Looking in cache slot #%d for: ",index);
    for(i=0;i<prefix_bytes;i++) fprintf(stderr,"%02x",in[i]);
    fprintf(stderr,"*\n");
  }

  if (in[0]<0x10) {
    /* Illegal address */
    if (debug&DEBUG_OVERLAYABBREVIATIONS)
      DEBUGF("Passed an illegal address (first byte <0x10)");
    return OA_UNSUPPORTED;
  }

  /* So is it there? */
  if (memcmp(in,&cache->sids[index].b[0],prefix_bytes))
    {
      /* No, it isn't in the cache, but it might be a local address. */
      int cn=0,id=0,kp=0;
      for(cn=0;cn<keyring->context_count;cn++)
	for(id=0;id<keyring->contexts[cn]->identity_count;id++)
	  for(kp=0;kp<keyring->contexts[cn]->identities[id]->keypair_count;kp++)
	    if (keyring->contexts[cn]->identities[id]->keypairs[kp]->type
		==KEYTYPE_CRYPTOBOX)
	      {
		if (!memcmp(in,keyring->contexts[cn]->identities[id]
			  ->keypairs[kp]->public_key,prefix_bytes))
		  {
		    if (debug&DEBUG_OVERLAYABBREVIATIONS) 
		      DEBUG("Found reference to local address.");
		    bcopy(&keyring->contexts[cn]->identities[id]
			  ->keypairs[kp]->public_key[0],&out[(*ofs)],SID_SIZE);
		    (*ofs)+=SID_SIZE;
		    return OA_RESOLVED;
		  }
	      }    
      
      if (debug&DEBUG_OVERLAYABBREVIATIONS) 
	DEBUG("Encountered unresolvable address -- are we asking for explanation?");
      return OA_PLEASEEXPLAIN;
    }
  
  /* XXX We should implement associativity in the address cache so that we can spot
     colliding prefixes and ask the sender to resolve them for us, or better yet dynamically
     size the prefix length based on whether any given short prefix has collided */

  /* It is here, so let's return it */
  if (debug&DEBUG_OVERLAYABBREVIATIONS) { 
    DEBUGF("I think I looked up the following: %s", alloca_tohex_sid(cache->sids[index].b));
  }

  bcopy(&cache->sids[index].b[0],&out[(*ofs)],SID_SIZE);
  (*ofs)+=SID_SIZE;
  if (index_bytes) {
    /* We need to remember it as well, so do that.
       If this process fails, it is okay, as we can still resolve the address now.
       It will probably result in waste later though when we get asked to look it up,
       however the alternative definitely wastes bandwidth now, so let us defer the
       corrective action in case it is never required. 
    */
    overlay_abbreviate_remember_index(index_bytes,&cache->sids[index].b[0],&in[prefix_bytes]);
    (*ofs)+=index_bytes;
  }
  if (debug&DEBUG_OVERLAYABBREVIATIONS)
  {
    int i;
    fprintf(stderr,"OA_RESOLVED returned for ");
    for(i=0;i<32;i++) fprintf(stderr,"%02X",cache->sids[index].b[i]);
    fprintf(stderr,"\n");
  }
  
  return OA_RESOLVED;
}

int overlay_abbreviate_set_current_sender(unsigned char *in)
{
  bcopy(in,&overlay_abbreviate_current_sender.b[0],SID_SIZE);
  overlay_abbreviate_current_sender_id=-1;
  overlay_abbreviate_current_sender_set=1;
  return 0;
}

int overlay_abbreviate_unset_current_sender()
{
  overlay_abbreviate_current_sender_set=0;
  return 0;
}

int overlay_abbreviate_set_most_recent_address(unsigned char *in)
{
  bcopy(in,&overlay_abbreviate_previous_address.b[0],SID_SIZE);
  if (debug&DEBUG_OVERLAYABBREVIATIONS) fprintf(stderr,"Most recent address=%s\n",
		       alloca_tohex_sid(in));
  return 0;
}

int overlay_abbreviate_clear_most_recent_address()
{
  /* make previous address invalid (first byte must be >0x0f to be valid) */
  overlay_abbreviate_previous_address.b[0]=0x00;

  if (debug&DEBUG_OVERLAYABBREVIATIONS) 
    fprintf(stderr,"Cleared most recent address\n");
  return 0;
}
