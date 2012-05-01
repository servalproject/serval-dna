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
  Here we implement the actual routing algorithm which is heavily based on BATMAN.
  
  The fundamental difference is that we want to allow the mesh to grow beyond the
  size that could ordinarily be accomodated by the available bandwidth.  Some
  explanation follows.

  BATMAN operates by having nodes periodically send "hello" or originator messages,
  either with a limited distribution or with a sufficiently high TTL to spread
  over the whole network.  

  The latter results in a super-linear bandwidth requirement as the network grows 
  in size.

  What we wish to do is to implement the BATMAN concept, but using link-local traffic
  only.  To do this we need to change the high-TTL originator frames into something
  equivalent, but that does not get automatic network-wide distribution.

  What seems possible is to implement the BATMAN approach for link-local neighbours,
  and then have each node periodically announce the link-score to the peers that
  they know about, whether link-local or more distant.  If the number of reported 
  peers is left unconstrained, super-linear bandwidth consumption will still occur.

  However, if the number of peers that each node announces is limited, then bandwidth
  will be capped at a constant factor (which can be chosen based on the bandwidth
  available). The trade-off being that each node will only be able to see some number
  of "nearest" peers based on the available bandwidth.  

  This seems an entirely reasonable outcome, and at least on the surface would appear
  to solve our problem of wanting to allow a global-scale mesh, even if only local
  connectivity is possible, in contrast to existing mesh protocols that will not allow
  any connectivity once the number of nodes grows beyond a certain point.

  Remaining challenges that we have to think through are how to add a hierarchical
  element to the mesh that might allow us to route traffic beyond a nodes' 
  neighbourhood of peers.

  There is some hope to extend the effective range beyond the immediate neighbourhood
  to some degree by rotating the peers that a node reports on, so that a larger total
  set of nodes becomes known to the mesh, in return for less frequent updates on their
  link scores and optimal routes.

  This actually makes some logical sense, as the general direction in which to route 
  a frame to a distant node is less likely to change more slowly than for nearer nodes.
  So we will attempt this.

  With some careful thought, this statistical announcement of peers also serves to allow
  long-range but very low bandwidth links, e.g., satellite or dial-up, as well as long-shot
  WiFi where bandwidth is less constrained.

  Questions arise as to the possibility of introducing routing loops through the use of
  stale information.  So we will certainly need to have some idea of the freshness of 
  routing data.

  Finally, all this works only for bidirectional links.  We will need to think about how
  to handle mono-directional links.  BATMAN does this well, but I don't have the documentation
  here at 36,000 feet to digest it and think about how to incorporate it.

  Having landed and thought about this a bit more, what we will do is send link-local
  announcements which each direct neighbour Y will listen to and build up an estimated
  probability of a packet sent by X reaching them.  This information will be 
  periodically broadcast as the interface ticks, and not forwarded beyond link-local,
  this preventing super-scalar traffic growth.  When X hears that Y's P(X,Y) from 
  such a neighbour reception notice X can record P(X,Y) as its link score to Y. This
  deals with asymmetric delivery probabilities for link-local neighbours.

  So how do we efficiently distribute P(X,Y) to our second-degree neighbours, which 
  we shall call Z? We will assume that P(X,Z) = P(X,Y)*P(Y,Z).  Thus X needs to get
  Y's set of P(Y,a) values. This is easy to arrange if X and Y are bidirectionally
  link-local, as Y can periodically broadcast this information, and X can cache it.
  This process will eventually build up the entire set P(X,b), where b are all nodes
  on the mesh. However, it assumes that every link is bidirectional.  What if X can
  send directly to Y, but Y cannot send directly to X, i.e., P(X,Y)~1, P(Y,X)~0?
  Provided that there is some path P(Y,m)*P(m,X) >0, then Y will eventually learn 
  about it.  If Y knows that P(X,Y)>0, then it knows that X is a link-local neighbour
  monodirectionally, and thus should endeavour to tell X about its direct neighbours.
  This is fairly easy to arrange, and we will try this approach.

  So overall, this results in traffic at each node which is O(n^2+n*m) where n is the
  number of direct neighbours and m is the total number of nodes reachable on the 
  mesh.  As we can limit the number of nodes reachable on the mesh by having nodes
  only advertise their k highest scoring nodes, we can effectively limit the traffic
  to approximately linear with respect to reachable node count, but quadratic with
  respect to the number of immediate neighbours.  This seems a reasonable outcome.

  Related to this we need to continue thinking about how to handle intermittant links in a more
  formal sense, including getting an idea of when nodes might reappear.

  Turning to the practical side of things, we need to keep track of reachability scores for
  nodes via each of our immediate neighbours.  Recognising the statistical nature of 
  the announcments, we probably want to keep track of some that have ceased to be neighbours
  in case they become neighbours again.

  Probably it makes more sense to have a list of known nodes and the most recent and
  highest scoring nodes by which we may reach them, complete with the sequence numbers of last
  observation that they are based upon, and possibly more information down the track to
  support intermittant links.

*/


/* For fast handling we will have a number of bins that will be indexed by the
   first few bits of the peer's SIDs, and a number of entries in each bin to
   handle hash collissions while still allowing us to have static memory usage. */
int overlay_bin_count=0;
int overlay_bin_size=0; /* associativity, i.e., entries per bin */
int overlay_bin_bytes=0; /* number of bytes required to represent the range
			    [0..bin_count) */
overlay_node **overlay_nodes=NULL;

/* We also need to keep track of which nodes are our direct neighbours.
   This means we need to keep an eye on how recently we received DIRECT announcements
   from nodes, and keep a list of the most recent ones.  The challenge is to keep the
   list ordered without having to do copies or have nasty linked-list structures that
   require lots of random memory reads to resolve.

   The simplest approach is to maintain a large cache of neighbours and practise random
   replacement.  It is however succecptible to cache flushing attacks by adversaries, so
   we will need something smarter in the long term.
*/
int overlay_max_neighbours=0;
int overlay_neighbour_count=0;
overlay_neighbour *overlay_neighbours=NULL;

/* allocate structures according to memory availability.
   We size differently because some devices are very constrained,
   e.g., mesh potatoes, some are middle sized, like mobile phones, and
   some are very large, like dedicated servers, that can keep track of
   very many nodes.
   
   The memory allocation is in two main areas:
   
   1. Neighbour list, which is short, requiring just a single pointer per
   direct neighbour.  So this can probably be set to a fairly large value
   on any sized machine, certainly in the thousands, which should be more
   than sufficient for wifi-type interfaces.  1000 neighbours requires
   onlt 8KB on a 64 bit machine, which is probably a reasonable limit per
   MB allocated.  This leaves 1016KB/MB for:
   
   2. The node information (overlay_node) structures.  These take more
   space and have to be sized appropriately.  We also need to choose the
   associativity of the node table based on the size of the structure.
   The smaller the structure the greater the associativity we should have
   so that the fewer the entries the more effectively we use them.  The
   trade-off is that increased associativity results in increased search
   time as the bins are searched for matches.  This is also why for very
   large tables we want low associativity so that we are more CPU efficient.
   
   The bulk of the size ofthe overlay_node structure is the observations
   information, because each observation contains a full 32 byte SID. The
   question is whether a full SID is required, or whether a prefix is
   sufficient, or if there is some even more compact representation possible.
   
   In principle the sender of the observation should be a direct neighbour,
   and so we could just use a neighbour index. However the neighbour indices
   are liable to change or become invalid over time, and we don't want to have
   to trawl through the nodes every time that happens, as otherwise the CPU
   requirements will be crazy.  
   
   This suggests that the use of a prefix is probably more appropriate. The
   prefix must be long enough to be robust against birthday-paradox effects
   and attacks. So at least 8 bytes (64 bits) is mandatory to make it
   reasonably difficult to find a colliding public key prefix.  Prudence 
   suggests that a longer prefix is desirable to give a safety margin, perhaps
   12 bytes (96 bits) being a reasonable figure.  
   
   This approximately halves the memory requirement per node to about 4KB (i.e.
   ~250 nodes per MB), and employing shorter prefixes than 12 bytes will result
   in diminishing returns, so this gives us confidence that it is an appropriate
   figure.
   
   Four-way associativity is probably reasonable for large-memory deployments
   where we have space for many thousands of nodes to keep string comparison
   effort to low levels.
   
   For small-memory deployments where we have space for only a few hundred nodes it
   probably makes sence to go for eight-way associativity just to be on the safe
   side.  However, this is somewhat arbitrary.  Only experience will teach us.
   
   One final note on potential attacks against us is that by having a hashed structure,
   even with modest associativity, is that if an attacker knows the hash function 
   they can readily cause hash collisions and interfere with connectivity to nodes
   on the mesh.  
   
   The most robust solution to this problem would be to use a linear hash function
   that takes, say, 10 of the 32 bytes as input, as this would result in a hash function
   space of:  32!/22! which is > 2^47.  This would then require several times 2^47 
   observation injections by an adversary to cause a hash collision with confidence.
   Actually determining that such a collision had been caused would probably multiply
   the effort required by some small further constant.  
   
   Using a non-linear hash function would raise the space to 32^10 > 2^50, the factor 
   of 8 probably not being worth the CPU complexity of such a non-linear function.
   
   However the question arises as to whether such an extreme approach is required, 
   remembering that changing the hash function does not break the protocol, so 
   such strong hash functions could be employed in future if needed without breaking
   backward compatibility.
   
   So let us then think about some very simple alternatives that might be good enough
   for now, but that are very fast to calculate.
   
   The simplest is to just choose a sufficient number of bytes from the SIDs to create
   a sufficiently long index value.  This gives 32!/(32-n)! where n is the number of
   bytes required, or 32 for the worst-case situation of n.
   
   An improvement is to xor bytes to produce the index value.  Using pairs of bytes
   gets us to something along the lines of 32!/(32-2n)! for production of a single byte,
   which is a modest improvement, but possibly not good enough.  As we increase the number
   of bytes xored together the situation improves to a point. However if we go to far we 
   end up reducing the total space because once more than half of the bytes are involved in
   the xor it is equivalent to the xor of all of the bytes xored with the bytes not included
   in the xor. This means that regardless of the length of the index we need, we probably want
   to use only half of the bytes as input, a this gives a complexity of 32!/16! = 2^73,
   which is plenty.
   
   In fact, this gives us a better result than the previous concept, and can be implemented
   using a very simple algorithm.  All we need to do is get a random ordering of the numbers 
   [0..31], and round robin xor the bytes we need with the [0..15]th elements of the random
   ordering.  
*/

/* The random ordering of bytes for the hash */
int overlay_route_hash_order[16];
int overlay_route_hash_bytes=0;

int overlay_route_initP=0;
int overlay_route_init(int mb_ram)
{
  int i,j;

  /* Try to catch one observed behaviour when memory corruption has occurred. */
  if (overlay_route_initP) {
    fprintf(stderr,"ERROR: overlay_route_init() multiply called.\n");
    sleep(3600);
  }
  overlay_route_initP=1;
  
  memabuseCheck();

  srandomdev();

  /* Generate hash ordering function */
  fprintf(stderr,"Generating byte-order for hash function:");
  for(i=0;i<32;i++) {
    j=0;
    overlay_route_hash_order[i]=random()&31;
    while(j<i) {
      overlay_route_hash_order[i]=random()&31;
      for(j=0;j<i;j++) if (overlay_route_hash_order[i]==overlay_route_hash_order[j]) break;
    }
    fprintf(stderr," %d",overlay_route_hash_order[i]);
  }
  fprintf(stderr,"\n");
  overlay_route_hash_bytes=16;

  int associativity=4;
  int bin_count=1;

  /* Now fiddle it to get bin_count to be a power of two that fits and doesn't waste too much space. */
  long long space=(sizeof(overlay_neighbour*)*1024LL*mb_ram)+sizeof(overlay_node)*bin_count*associativity*1LL;
  while (space<mb_ram*1048576LL&&associativity<8)
    {
      long long space2=(sizeof(overlay_neighbour*)*1024LL*mb_ram)+sizeof(overlay_node)*(bin_count*2LL)*associativity*1LL;
      if (space2<mb_ram*1048576LL) { bin_count*=2; continue; }
      space2=(sizeof(overlay_neighbour*)*1024LL)+sizeof(overlay_node)*bin_count*(associativity+1)*1LL;
      if (space2<mb_ram*1048576LL) { associativity++; continue; }
      break;
    }

  /* Report on the space used */
  {
    space=(sizeof(overlay_neighbour*)*1024LL*mb_ram)+sizeof(overlay_node)*bin_count*associativity*1LL;
    int percent=100LL*space/(mb_ram*1048576LL);
    fprintf(stderr,"Using %d%% of %dMB RAM allows for %d bins with %d-way associativity and %d direct neighbours.\n",
	    percent,mb_ram,bin_count,associativity,1024*mb_ram);
  }

  /* Now allocate the structures */

  overlay_nodes=calloc(sizeof(overlay_node*),bin_count);
  if (!overlay_nodes) return WHY("calloc() failed.");

  overlay_neighbours=calloc(sizeof(overlay_neighbour),1024*mb_ram);
  if (!overlay_neighbours) {
    free(overlay_nodes);
    return WHY("calloc() failed.");
  }

  for(i=0;i<bin_count;i++)
    {
      overlay_nodes[i]=calloc(sizeof(overlay_node),associativity);
      if (!overlay_nodes[i]) {
	while(--i>=0) free(overlay_nodes[i]);
	free(overlay_nodes);
	free(overlay_neighbours);
	return WHY("calloc() failed.");
      }
    }

  overlay_max_neighbours=1024*mb_ram;
  overlay_bin_count=bin_count;
  overlay_bin_size=associativity;
  fprintf(stderr,"Node (%dbins) and neighbour tables allocated.\n",bin_count);

  /* Work out number of bytes required to represent the bin number.
     Used for calculation of sid hash */
  overlay_bin_bytes=1;
  while(bin_count&0xffffff00) {
    fprintf(stderr,"bin_count=0x%08x, overlay_bin_bytes=%d\n",bin_count,overlay_bin_bytes);
    overlay_bin_bytes++;
    bin_count=bin_count>>8;
  }
  fprintf(stderr,"bin_count=0x%08x, overlay_bin_bytes=%d\n",bin_count,overlay_bin_bytes);

  return 0;
}

/* Select a next hop to get to a node.
   Frist, let us consider neighbours.  These are on a local link to us, and do not require any
   intermediate nodes to transmit to us.  However, assymetric packet loss is common, so we may
   not be able to transmit back to the neighbour.  We know if we can because we will have
   received acks to our self announcements.  However, to send an ack to a self announcement we
   need a fall-back option.  This fall-back should be by sending to the broadcast address.

   The complication comes when we have multiple interfaces available.  If we send to all, then
   we need a way of keeping track which interfaces we have sent it on so far, which is a bit
   icky, and more to the point requires some revamping of code.  A bigger problem is that we might
   have cheap and expensive interfaces, and we don't want to go blabbing about our wifi or ethernet
   based peers over a $10/MB BGAN link, when we can reasonably know that it shouldn't be necessary.

   The trouble is that sometimes it might just be necessary. We then have two options, send traffic
   over multiple interfaces to try to discover such one-way links, even if internet back-haul is 
   required in between.  This is nice in the long-term.  Or, we be more conservative with the traffic
   and require that a resolution to the route be discoverable via the interface that the frame
   arrived on.

   In any case, we need to tag the nexthop address with the interface(s) on which to send it.

   Once we have this working and neighbours can communicate, then we can move on to addressing
   nodes that are only indirectly connected. Indeed, the two are somewhat interconnected as
   an indirect route may be required to get a self-announce ack back to the sender.
*/
int overlay_get_nexthop(unsigned char *d,unsigned char *nexthop,int *nexthoplen,
			int *interface)
{
  int i;
  
  if (overlay_broadcast_drop_check(d)) return WHY("I have sent that broadcast frame before");

  if (!overlay_neighbours) return WHY("I have no neighbours");

  overlay_neighbour *neh=overlay_route_get_neighbour_structure(d,0 /* don't create if 
								      missing */);

  if (neh) {
    /* Is a direct neighbour.
       So in the absence of any better indirect route, we pick the interface that
       we can hear this neighbour on the most reliably, and then send the frame 
       via that interface and directly addressed to the recipient. */
    bcopy(d,nexthop,SID_SIZE);
    (*nexthoplen)=SID_SIZE;

    *interface=0;
    for(i=1;i<OVERLAY_MAX_INTERFACES;i++) {
      if (neh->scores[i]>neh->scores[*interface]) *interface=i;
    }
    if (neh->scores[*interface]<1) {
      if (debug&DEBUG_OVERLAYROUTING)
	WHYF("No open path to %s\n",overlay_render_sid(neh->node->sid));
      return -1; 
    }
    if (0) printf("nexthop is %s\n",overlay_render_sid(nexthop));
    return 0;
  } else {
    /* Is not a direct neighbour */
    return WHY("Calculating next-hop destination for nodes that are not direct neighbours is not yet implemented");
  }
}

unsigned int overlay_route_hash_sid(unsigned char *sid)
{
  /* Calculate the bin number of an address (sid) from the sid. */
  if (!overlay_route_hash_bytes) return WHY("overlay_route_hash_bytes==0");
  unsigned int bin=0;
  int byte=0;
  int i;
  for(i=0;i<overlay_route_hash_bytes;i++) {
    bin=bin^((sid[overlay_route_hash_order[i]])<<(8*byte));
    byte++;
    if (byte>=overlay_bin_bytes) byte=0;
  }

  /* Mask out extranous bits to return only a valid bin number */
  bin&=(overlay_bin_count-1);
  if (debug&DEBUG_OVERLAYROUTING) {
    int zeroes=0;
    fprintf(stderr,"The following address resolves to bin #%d\n",bin);
    for(i=0;i<SID_SIZE;i++) { fprintf(stderr,"%02x",sid[i]); if (!sid[i]) zeroes++; }
    fprintf(stderr,"\n");
    if (zeroes>8) {
      fprintf(stderr,"Looks like corrupt memory or packet to me!\n");
    }
  }
  return bin;
}

overlay_node *overlay_route_find_node(unsigned char *sid,int createP)
{
  int bin_number=overlay_route_hash_sid(sid);
  int free_slot=-1;
  int slot;

  if (bin_number<0) { WHY("negative bin number"); return NULL; }

  for(slot=0;slot<overlay_bin_size;slot++)
    {
      if (!memcmp(sid,&overlay_nodes[bin_number][slot].sid[0],SID_SIZE))
	{
	  /* Found it */
	  return &overlay_nodes[bin_number][slot];
	}
      else if (overlay_nodes[bin_number][slot].sid[0]==0) free_slot=slot;
    }
 
  /* Didn't find it */
  if (!createP) return NULL;

  if (free_slot==-1)
    {
      /* Displace one of the others in the bin so we can go there */
      int i;
      for(i=0;i<OVERLAY_MAX_OBSERVATIONS;i++)
	overlay_nodes[bin_number][free_slot].observations[i].observed_score=0;
      overlay_nodes[bin_number][free_slot].neighbour_id=0;
      overlay_nodes[bin_number][free_slot].most_recent_observation_id=0;
      overlay_nodes[bin_number][free_slot].best_link_score=0;
      overlay_nodes[bin_number][free_slot].best_observation=0;
      for(i=0;i<OVERLAY_MAX_INTERFACES;i++) {
	overlay_nodes[bin_number][free_slot].most_recent_advertisment[i]=0;
	overlay_nodes[bin_number][free_slot].most_recent_advertised_score[i]=0;
      }
    }

  /* Ask for newly discovered node to be advertised */
  overlay_route_please_advertise(&overlay_nodes[bin_number][slot]);

  bcopy(sid,overlay_nodes[bin_number][free_slot].sid,SID_SIZE);
  return &overlay_nodes[bin_number][free_slot];
}

int overlay_route_ack_selfannounce(overlay_frame *f,
				   unsigned int s1,unsigned int s2,
				   int interface,
				   overlay_neighbour *n)
{
  /* Acknowledge the receipt of a self-announcement of an immediate neighbour.
     We could acknowledge immediately, but that requires the transmission of an
     extra packet with all the overhead that entails.  However, there is no real
     need to send the ack out immediately.  It should be entirely reasonable to 
     send the ack out with the next interface tick. 

     So we can craft the ack and submit it to the queue. As the next-hop will get
     determined at TX time, this will ensure that we send the packet out on the 
     right interface to reach the originator of the self-assessment.

     So all we need to do is craft the payload and put it onto the queue for 
     OVERLAY_MESH_MANAGEMENT messages.

     Also, we should check for older such frames on the queue and drop them.

     There is one caveat to the above:  until the first selfannounce gets returned,
     we don't have an open route.  Thus we need to just make sure that the ack
     goes out broadcast if we don't know about a return path. Once the return path
     starts getting built, it should be fine.

   */

  /* XXX Allocate overlay_frame structure and populate it */
  overlay_frame *out=NULL;
  out=calloc(sizeof(overlay_frame),1);
  if (!out) return WHY("calloc() failed to allocate an overlay frame");

  out->type=OF_TYPE_SELFANNOUNCE_ACK;
  out->modifiers=0;
  out->ttl=6; /* maximum time to live for an ack taking an indirect route back
		 to the originator.  If it were 1, then we would not be able to
		 handle mono-directional links (which WiFi is notorious for).
	         XXX 6 is quite an arbitrary selection however. */

  /* Set destination of ack to source of observed frame */
  if (overlay_frame_set_neighbour_as_destination(out,n)) {
    op_free(out);
    return WHY("overlay_frame_set_neighbour_as_source() failed");
  }
  /* set source to ourselves */
  overlay_frame_set_me_as_source(out);

  /* Next-hop will get set at TX time, so no need to set it here.
     However, if there is no known next-hop for this node (because the return path
     has not yet begun to be built), then we need to set the nexthop to broadcast. */
  out->nexthop_address_status=OA_UNINITIALISED;
  {
    unsigned char nexthop[SID_SIZE];
    int len=0;
    int next_hop_interface=-1;
    int r=overlay_get_nexthop(out->destination,nexthop,&len,
			      &next_hop_interface);
    if (r) {
      /* no open path, so convert to broadcast */
      int i;
      for(i=0;i<(SID_SIZE-8);i++) out->nexthop[i]=0xff;
      for(i=24;i<SID_SIZE;i++) out->nexthop[i]=random()&0xff;
      out->nexthop_address_status=OA_RESOLVED;
      out->ttl=2;
      out->isBroadcast=1;
      if (debug&DEBUG_OVERLAYROUTING) 
	WHY("Broadcasting ack to selfannounce for hithero unroutable node");
    } else out->isBroadcast=0;
  }

  /* Set the time in the ack. Use the last sequence number we have seen
     from this neighbour, as that may be helpful information for that neighbour
     down the track.  My policy is to communicate that information which should
     be helpful for forming and maintaining the health of the mesh, as that way
     each node can in potentially implement a different mesh routing protocol,
     without breaking the wire protocol.  This makes over-the-air software updates
     much safer.

     Combining of adjacent observation reports may mean that the most recent
     observation is not the last one in the list, also the wrapping of the sequence
     numbers means we can't just take the highest-numbered sequence number.  
     So we need to take the observation which was most recently received.
  */
  out->payload=ob_new(4+32*2+1); /* will grow if it isn't big enough, but let's try to
				    avoid a realloc() if possible */

  /* XXX - we should merge contiguous observation reports so that packet loss 
     on the return path doesn't count against the link. */
  ob_append_int(out->payload,s1);
  ob_append_int(out->payload,s2);

  /* The ack needs to contain the per-interface scores that we have built up
     for this neighbour.
     We expect that for most neighbours they will have many fewer than 32 interfaces,
     and even when they have multiple interfaces that we will only be able to hear
     them on one or a few. 

     So we will structure the format so that we use fewer bytes when fewer interfaces
     are involved.

     Probably the simplest is to put each non-zero score followed by it's interface.
     That way the whole list will be easy to parse, and as short as 3 bytes for a
     single interface.

     We could use the spare 2 bits at the top of the interface id to indicate
     multiple interfaces with same score? 
  */
#ifdef NOTDEFINED
  int i;
  for(i=0;i<OVERLAY_MAX_INTERFACES;i++)
    {
      /* Only include interfaces with score >0 */
      if (n->scores[i]) {
	ob_append_byte(out->payload,n->scores[i]);
	ob_append_byte(out->payload,i);
      }
    }
  /* Terminate list */
  ob_append_byte(out->payload,0);
#endif
  ob_append_byte(out->payload,interface);

  /* Add to queue. Keep broadcast status that we have assigned here if required to
     get ack back to sender before we have a route. */
  if (overlay_payload_enqueue(OQ_MESH_MANAGEMENT,out,out->isBroadcast))
    {
      op_free(out);
      return WHY("overlay_payload_enqueue(self-announce ack) failed");
    }
  
  /* XXX Remove any stale versions (or should we just freshen, and forget making
     a new one, since it would be more efficient). */

  return 0;
}

int overlay_route_make_neighbour(overlay_node *n)
{
  if (!n) return WHY("n is NULL");

  /* If it is already a neighbour, then return */
  if (n->neighbour_id) return 0;

  /* If address is local don't both making it a neighbour */
  if (overlay_address_is_local(n->sid)) return 0;

  /* It isn't yet a neighbour, so find or free a neighbour slot */
  /* slot 0 is reserved, so skip it */
  if (!overlay_neighbour_count) overlay_neighbour_count=1;
  if (overlay_neighbour_count<overlay_max_neighbours) {
    /* Use next free neighbour slot */
    n->neighbour_id=overlay_neighbour_count++;
  } else {
    /* Evict an old neighbour */
    int nid=1+random()%(overlay_max_neighbours-1);
    if (overlay_neighbours[nid].node) overlay_neighbours[nid].node->neighbour_id=0;
    n->neighbour_id=nid;
  }
  bzero(&overlay_neighbours[n->neighbour_id],sizeof(overlay_neighbour));
  overlay_neighbours[n->neighbour_id].node=n;

  return 0;
}

overlay_neighbour *overlay_route_get_neighbour_structure(unsigned char *packed_sid,
							 int createP)
{
  if (overlay_address_is_local(packed_sid)) {
    WHY("asked for neighbour structure for myself");
    return NULL;
  }  

  overlay_node *n=overlay_route_find_node(packed_sid,createP);
  if (!n) { WHY("Could not find node record for observed node"); return NULL; }

  /* Check if node is already a neighbour, or if not, make it one */
  if (!n->neighbour_id) if (overlay_route_make_neighbour(n)) { WHY("overlay_route_make_neighbour() failed"); return NULL; }

  /* Get neighbour structure */
  return &overlay_neighbours[n->neighbour_id];

}

int overlay_route_i_can_hear_node(unsigned char *who,int sender_interface,
				  unsigned int s1,unsigned int s2,
				  int receiver_interface,long long now)
{
  if (0) WHYF("I can hear node %s (but I really only care who can hear me)",
	      overlay_render_sid(who));
  return 0;
}


int overlay_route_node_can_hear_me(unsigned char *who,int sender_interface,
				   unsigned int s1,unsigned int s2,
				   long long now)
{
  /* 1. Find (or create) node entry for the node.
     2. Replace oldest observation with this observation.
     3. Update score of how reliably we can hear this node */

  /* Ignore traffic from ourselves. */
  if (overlay_address_is_local(who)) 
    {
      WHY("I can hear myself. How odd");
      return 0;
    }

  /* Find node, or create entry if it hasn't been seen before */
  overlay_node *n=overlay_route_find_node(who,1 /* create if necessary */);
  if (!n) return WHY("Could not find node record for observed node");

  /* Check if node is already a neighbour, or if not, make it one */
  if (!n->neighbour_id) if (overlay_route_make_neighbour(n)) return WHY("overlay_route_make_neighbour() failed");

  /* Get neighbour structure */
  if (n->neighbour_id<0||n->neighbour_id>overlay_max_neighbours)
    { WHY("n->neighbour_id set to illegal value");
      return -1;
    }
  overlay_neighbour *neh=&overlay_neighbours[n->neighbour_id];

  int obs_index=neh->most_recent_observation_id;
  int mergedP=0;

  /* See if this observation is contiguous with a previous one, if so, merge.
     This not only reduces the number of observation slots we need, but dramatically speeds up
     the scanning of recent observations when re-calculating observation scores. */
  while (neh->observations[obs_index].valid&&(neh->observations[obs_index].s2>=(s1-1)))
    {
      if (neh->observations[obs_index].sender_interface==sender_interface)
	{
	  if (0) WHYF("merging observation in slot #%d",obs_index);
	  if (!neh->observations[obs_index].s1)
	    neh->observations[obs_index].s1=neh->observations[obs_index].s2; 
	  neh->observations[obs_index].s2=s2;
	  neh->observations[obs_index].sender_interface=sender_interface;
	  neh->observations[obs_index].time_ms=now;
	  mergedP=1;
	  break;
	}

      obs_index--;
      if (obs_index<0) obs_index=OVERLAY_MAX_OBSERVATIONS-1;
    }

  if (!mergedP) {
    /* Replace oldest observation with this one */
    obs_index=neh->most_recent_observation_id+1;
    if (obs_index>=OVERLAY_MAX_OBSERVATIONS) obs_index=0;
    if (0) WHYF("storing observation in slot #%d",obs_index);
    neh->observations[obs_index].valid=0;
    neh->observations[obs_index].time_ms=now;
    neh->observations[obs_index].s1=s1;
    neh->observations[obs_index].s2=s2;
    neh->observations[obs_index].sender_interface=sender_interface;
    neh->observations[obs_index].valid=1;
  }
  neh->most_recent_observation_id=obs_index;
  neh->last_observation_time_ms=now;
  /* force updating of stats for neighbour if we have added an observation */
  neh->last_metric_update=0;

  /* Update reachability metrics for node */
  if (overlay_route_recalc_neighbour_metrics(neh,now)) WHY("overlay_route_recalc_neighbour_metrics() failed");

  if (debug&DEBUG_OVERLAYROUTEMONITOR) overlay_route_dump();
  return 0;
}

int overlay_print_address(FILE *f,char *prefix,unsigned char *s,char *suffix)
{
  int i;
  fprintf(f,"%s",prefix);
  for(i=0;i<SID_SIZE;i++) fprintf(f,"%02x",s[i]);
  fprintf(f,"%s",suffix);
  return 0;
}


int overlay_route_saw_selfannounce(int interface,overlay_frame *f,long long now)
{
  if (overlay_address_is_local(f->source)) return 0;

  unsigned int s1,s2;
  unsigned char sender_interface;
  overlay_neighbour *n=overlay_route_get_neighbour_structure(f->source,1 /* make neighbour if not yet one */);
 
  if (!n) return WHY("overlay_route_get_neighbour_structure() failed");

  /* Record current sender for reference by addresses in subsequent frames in the
     ensemble */
  overlay_abbreviate_set_current_sender(f->source);

  /* Ignore self announcements from ourselves */
  if (overlay_address_is_local(f->source)) {
    if(0) WHY("Ignoring selfannouncement from myself");
    return 0;
  }

  s1=ntohl(*((int*)&f->payload->bytes[0]));
  s2=ntohl(*((int*)&f->payload->bytes[4]));
  sender_interface=f->payload->bytes[8];
  if (debug&DEBUG_OVERLAYROUTING) {
    fprintf(stderr,"Received self-announcement for sequence range [%08x,%08x] from interface %d\n",s1,s2,sender_interface);
    dump("Payload",&f->payload->bytes[0],f->payload->length);
  }

  overlay_route_i_can_hear_node(f->source,sender_interface,s1,s2,interface,now);

  /* Ignore self-announcements from ourself. */
  if (overlay_address_is_local(&f->source[0]))
    {
      // XXX But we should make note that we have loop-back to this interface
      WHY("One or more interfaces loops back to this one, or someone is naughtily forwarding packets between interfaces.");
      return 0; 
    }

  overlay_route_ack_selfannounce(f,s1,s2,sender_interface,n);

  return 0;
}

/* XXX Think about scheduling this node's score for readvertising? */
int overlay_route_recalc_node_metrics(overlay_node *n,long long now)
{
  int o;
  int best_score=0;
  int best_observation=-1;

  for(o=0;o<OVERLAY_MAX_OBSERVATIONS;o++)
    {
      if (n->observations[o].observed_score)
	{
	  int discounted_score=n->observations[o].observed_score;
	  discounted_score-=(now-n->observations[o].rx_time)/1000;
	  if (discounted_score<0) discounted_score=0;
	  n->observations[o].corrected_score=discounted_score;
	  if (discounted_score>best_score)  {
	    best_score=discounted_score;
	    best_observation=o;
	  }
	}
    }

  if (n->neighbour_id)
    {
      /* Node is also a direct neighbour, so check score that way */
      if (n->neighbour_id>overlay_max_neighbours||n->neighbour_id<0)
	return WHY("n->neighbour_id is invalid.");
      int i;
      for(i=0;i<overlay_interface_count;i++)
	{
	  if (overlay_neighbours[n->neighbour_id].scores[i]>best_score)
	    {
	      best_score=overlay_neighbours[n->neighbour_id].scores[i];
	      best_observation=-1;
	    }
	}
    }

  /* Think about scheduling this node's score for readvertising if its score
     has changed a lot?
     Really what we probably want is to advertise when the score goes up, since
     if it goes down, we probably don't need to say anything at all.
  */
  int diff=best_score-n->best_link_score;
  if (diff>0) { 
    overlay_route_please_advertise(n);
    if (debug&DEBUG_OVERLAYROUTEMONITOR) overlay_route_dump();
  }
  
  /* Remember new reachability information */
  n->best_link_score=best_score;
  n->best_observation=best_observation;

  return 0;
}

/* Recalculate node reachability metric, but only for directly connected nodes,
   i.e., link-local neighbours.

   The scores should be calculated separately for each interface we can
   hear the node on, so that this information can get back to the sender so that
   they know the best interface to use when trying to talk to us.

   For now we will calculate a weighted sum of recent reachability over some fixed
   length time interval.
   The sequence numbers are all based on a milli-second clock.
   
   For mobile mesh networks we need this metric to be very fast adapting to new
   paths, but to have a memory of older paths in case they are still useful.

   We thus combined equally a measure of very recent reachability (in last 10
   interface ticks perhaps?) with a measure of longer-term reachability (last
   200 seconds perhaps?).  Also, if no recent observations, then we further
   limit the score.
*/
int overlay_route_recalc_neighbour_metrics(overlay_neighbour *n,long long now)
{
  int i;
  long long most_recent_observation=0;

  /* Only update every half-second */
  if ((now-n->last_metric_update)<500) {
    if (0) WHYF("refusing to update metric too often (last at %lldms, now=%lldms)",
		n->last_metric_update,now);
    return 0;
  }
  n->last_metric_update=now;

  /* Somewhere to remember how many milliseconds we have seen */
  int ms_observed_5sec[OVERLAY_MAX_INTERFACES];
  int ms_observed_200sec[OVERLAY_MAX_INTERFACES];
  for(i=0;i<OVERLAY_MAX_INTERFACES;i++) {
    ms_observed_5sec[i]=0;
    ms_observed_200sec[i]=0;
  }

  /* XXX This simple accumulation scheme does not weed out duplicates, nor weight for recency of
     communication.
     Also, we might like to take into account the interface we received 
     the announcements on. */
  for(i=0;i<OVERLAY_MAX_OBSERVATIONS;i++) {
    if (n->observations[i].valid&&n->observations[i].s1) {
      /* Work out the interval covered by the observation.
	 The times are represented as lowest 32 bits of a 64-bit 
	 millisecond clock.  This introduces modulo problems, 
	 however by using 32-bit modulo arithmatic here, we avoid
	 most of them. */
      unsigned int interval=n->observations[i].s2-n->observations[i].s1;      

      /* Check the observation age, and ignore if too old */
      int obs_age=now-n->observations[i].time_ms;
      if (0) WHYF("tallying obs: %dms old, %dms long",
	   obs_age,interval);
      if (obs_age>200000) continue;

      /* Ignore very large intervals (>1hour) as being likely to be erroneous.
	 (or perhaps a clock wrap due to the modulo arithmatic)

	 One tick per hour should be well and truly slow enough to do
	 50KB per 12 hours, which is the minimum traffic charge rate 
	 on an expensive BGAN satellite link. 	 
      */
      if (interval<3600000) {
	if (debug&DEBUG_VERBOSE_IO) 
	  fprintf(stderr,"adding %dms (interface %d '%s')\n",
		  interval,n->observations[i].sender_interface,
		  overlay_interfaces[n->observations[i].sender_interface].name);

	/* sender_interface is unsigned, so a single-sided test is sufficient for bounds checking */
	if (n->observations[i].sender_interface<OVERLAY_MAX_INTERFACES)
	  {
	    ms_observed_200sec[n->observations[i].sender_interface]+=interval;
	    if (obs_age<=5000)
	      ms_observed_5sec[n->observations[i].sender_interface]+=interval;
	  }
	else
	  {
	    WHY("Invalid interface ID in observation");
	    fprintf(stderr,"XXXXXXX adding %dms (interface %d)\n",interval,n->observations[i].sender_interface);
	  }
      }

      if (n->observations[i].time_ms>most_recent_observation) most_recent_observation=n->observations[i].time_ms;
    }
  }

  /* From the sum of observations calculate the metrics.
     We want the score to climb quickly and then plateu.
  */
  for(i=0;i<OVERLAY_MAX_INTERFACES;i++) {
    int score;
    if (ms_observed_200sec[i]>200000) ms_observed_200sec[i]=200000;
    if (ms_observed_5sec[i]>5000) ms_observed_5sec[i]=5000;
    if (ms_observed_200sec[i]==0) {
      // Not observed at all
      score=0;
    } else {
      int contrib_200=ms_observed_200sec[i]/(200000/128);
      int contrib_5=ms_observed_5sec[i]/(5000/128);

      if (contrib_5<1) score=contrib_200/2; else
      score=contrib_5+contrib_200;      

      /* Deal with invalid sequence number ranges */
      if (score<0) score=0; if (score>255) score=255;
    }

    /* Reduce score by 1 point for each second we have not seen anything from it */
    score-=(now-most_recent_observation)/1000;
    if (score<0) score=0;

    n->scores[i]=score;
    if ((debug&DEBUG_OVERLAYROUTING)&&score) fprintf(stderr,"Neighbour score on interface #%d = %d (observations for %dms)\n",i,score,ms_observed_200sec[i]);
  }
  
  return 0;
  
}

int ors_rotor=0;
char ors_out[4][SID_STRLEN+1];
char *overlay_render_sid(unsigned char *sid)
{
  int zero=0;
  ors_rotor++;
  ors_rotor&=3;
  extractSid(sid,&zero,ors_out[ors_rotor]);
  ors_out[ors_rotor][SID_STRLEN] = '\0';
  return ors_out[ors_rotor];
}

char *overlay_render_sid_prefix(unsigned char *sid,int l)
{
  int zero=0;

  if (l<0) l=0;
  if (l>SID_STRLEN) l=SID_STRLEN;
  ors_rotor++;
  ors_rotor&=3;
  extractSid(sid,&zero,ors_out[ors_rotor]);
  ors_out[ors_rotor][l]=0;
  return ors_out[ors_rotor];
}


/* 
   Self-announcement acks bounce back to the self-announcer from immediate neighbours
   who report the link score they have calculated based on listening to self-announces
   from that peer.  By acking them these scores then get to the originator, who then
   has a score for the link to their neighbour, which is measuring the correct
   direction of the link. 

   Frames consist of 32bit timestamp in seconds followed by zero or more entries
   of the format:
   
   8bits - link score
   8bits - interface number

   this is followed by a 00 byte to indicate the end.

   That way we don't waste lots of bytes on single-interface nodes.
   (But I am sure we can do better).

   These link scores should get stored in our node list as compared to our neighbour list,
   with the node itself listed as the nexthop that the score is associated with.
*/
int overlay_route_saw_selfannounce_ack(int interface,overlay_frame *f,long long now)
{
  if (0) WHYF("processing selfannounce ack (payload length=%d)",f->payload->length);
  if (!overlay_neighbours) {
    if (0) WHY("no neighbours, so returning immediately");
    return 0;
  }

  if (f->payload->length<9) 
    return WHY("FOO! selfannounce ack packet too short");

  unsigned int s1=ob_get_int(f->payload,0);
  unsigned int s2=ob_get_int(f->payload,4);
  int iface=f->payload->bytes[8];

  // Call something like the following for each link
  if (f->source_address_status==OA_RESOLVED&&
      f->destination_address_status==OA_RESOLVED) {
    if (0) WHYF("f->source=%s, f->destination=%s",
		overlay_render_sid(f->source),overlay_render_sid(f->destination));
    overlay_route_record_link(now,f->source,f->source,iface,s1,s2,
			      0 /* no associated score */,
			      0 /* no gateways in between */);
  } else WHY("address(es) not resolved");

  return 0;
}

/* if to and via are the same, then this is evidence that we can get to the
   node directly. */
int overlay_route_record_link(long long now,unsigned char *to,
			      unsigned char *via,int sender_interface,
			      unsigned int s1,unsigned int s2,int score,
			      int gateways_en_route)
{
  int i,slot=-1;

  if (0) WHYF("to=%s, via=%s, iface=%d, s1=%d, s2=%d",
	      overlay_render_sid(to),overlay_render_sid(via),
	      sender_interface,s1,s2);
 

  if (sender_interface>OVERLAY_MAX_INTERFACES) return 0;

  /* Don't record routes to ourselves */
  if (overlay_address_is_local(to)) {
    if (0) WHYF("Ignoring self announce ack addressed to me (%s).",
		overlay_render_sid(to));
    return 0;
  }
  else if (0) WHYF("Recording link to %s",overlay_render_sid(to));

  for(i=0;i<SID_SIZE;i++) if (to[i]!=via[i]) break;
  if (i==SID_SIZE)
    {
      /* It's a neighbour observation */
      if (0) WHYF("%s is my neighbour",overlay_render_sid(to));
      overlay_route_node_can_hear_me(to,sender_interface,s1,s2,now);
    }

  if (!score) {
    if (0) WHY("non-scoring report, so done");
    return 0;
  }

  fprintf(stderr,"route_record_link(0x%llx,%s*,",
	  now,overlay_render_sid_prefix(to,7));
  fprintf(stderr,"%s*,0x%08x-0x%08x,%d)\n",
	  overlay_render_sid_prefix(via,7),s1,s2,score);
  
  overlay_node *n=overlay_route_find_node(to,1 /* create node if missing */);
  if (!n) return WHY("Could not find or create entry for node");
  
  for(i=0;i<OVERLAY_MAX_OBSERVATIONS;i++)
    {
      /* Take note of where we can find space for a fresh observation */
      if ((slot==-1)&&(!n->observations[i].observed_score)) slot=i;
      
      /* If the intermediate host ("via") address and interface numbers match, 
	 then overwrite old observation with new one */
      if (!memcmp(via,n->observations[i].sender_prefix,OVERLAY_SENDER_PREFIX_LENGTH))
	{
	  /* Bingo - update this one */
	  slot=i;
	  break;
	}
    }
  /* If in doubt, replace a random slot.
     XXX - we should probably replace the lowest scoring slot instead,
     but random will work well enough for now. */
  if (slot==-1) slot=random()%OVERLAY_MAX_OBSERVATIONS;

  n->observations[slot].observed_score=0;
  n->observations[slot].gateways_en_route=gateways_en_route;
  n->observations[slot].rx_time=now;
  bcopy(via,n->observations[slot].sender_prefix,OVERLAY_SENDER_PREFIX_LENGTH);
  n->observations[slot].observed_score=score;
  n->observations[slot].interface=sender_interface;
  
  /* Remember that we have seen an observation for this node.
     XXX - This should actually be set to the time that the last first-hand
     observation of the node was made, so that stale information doesn't build
     false belief of reachability.
     This is why the timestamp field is supplied, which is just copied from the
     original selfannouncement ack.  We just have to register it against our
     local time to interpret it (XXX which comes with some risks related to
     clock-skew, but we will deal with those in due course).
  */
  n->last_observation_time_ms=now;
  if (s2>n->last_first_hand_observation_time_millisec)
    n->last_first_hand_observation_time_millisec=s2;

  overlay_route_recalc_node_metrics(n,now);
  
  if (debug&DEBUG_OVERLAYROUTEMONITOR) overlay_route_dump();
  
  return 0;
}

int overlay_address_is_local(unsigned char *s) 
{ 
  int cn=0,in=0,kp=0;
  int found=keyring_find_sid(keyring,&cn,&in,&kp,s);

  return found;
}

int overlay_route_dump()
{
  int bin,slot,o,n,i;
  long long now=overlay_gettime_ms();

  fprintf(stderr,"\nOverlay Local Identities\n------------------------\n");
  int cn,in,kp;
  for(cn=0;cn<keyring->context_count;cn++)
    for(in=0;in<keyring->contexts[cn]->identity_count;in++)
      for(kp=0;kp<keyring->contexts[cn]->identities[in]->keypair_count;kp++)
	if (keyring->contexts[cn]->identities[in]->keypairs[kp]->type
	    ==KEYTYPE_CRYPTOBOX)
	  {
	    for(i=0;i<SID_SIZE;i++)
	      fprintf(stderr,"%02x",keyring->contexts[cn]->identities[in]
		      ->keypairs[kp]->public_key[i]);
	    fprintf(stderr,"\n");
	  }

  fprintf(stderr,"\nOverlay Neighbour Table\n------------------------\n");
  for(n=0;n<overlay_neighbour_count;n++)
    if (overlay_neighbours[n].node)
      {
	fprintf(stderr,"  %s* : %lldms ago :",
		overlay_render_sid_prefix(overlay_neighbours[n].node->sid,7),
		(now-overlay_neighbours[n].last_observation_time_ms));
	for(i=0;i<OVERLAY_MAX_INTERFACES;i++)
	  if (overlay_neighbours[n].scores[i]) 
	    fprintf(stderr," %d(via #%d)",
		    overlay_neighbours[n].scores[i],i);
	fprintf(stderr,"\n");
      }
  
  fprintf(stderr,"Overlay Mesh Route Table\n------------------------\n");
  
  for(bin=0;bin<overlay_bin_count;bin++)
    for(slot=0;slot<overlay_bin_size;slot++)
      {
	if (!overlay_nodes[bin][slot].sid[0]) continue;
	
	fprintf(stderr,"  %s* : %d :",overlay_render_sid_prefix(overlay_nodes[bin][slot].sid,7),
		overlay_nodes[bin][slot].best_link_score);
	for(o=0;o<OVERLAY_MAX_OBSERVATIONS;o++)
	  {
	    if (overlay_nodes[bin][slot].observations[o].observed_score)
	      {
		overlay_node_observation *ob=&overlay_nodes[bin][slot].observations[o];
		if (ob->corrected_score)
		  fprintf(stderr," %d/%d via %s*",
			  ob->corrected_score,ob->gateways_en_route,
			  overlay_render_sid_prefix(ob->sender_prefix,7));			
	      }
	  }       
	fprintf(stderr,"\n");
      }
  return 0;
}

int max(int a,int b)
{
  if (a>b) return a; else return b;
}

/*
  We want to progressivelly update all routes as we go along, updating a few nodes
  every call, so that no one call takes too long.  This is important since we don't
  want to add any excessive delays that might upset delay-sensitive voice and video
  traffic.
*/
int overlay_route_tick_next_neighbour_id=0;
int overlay_route_tick_neighbour_bundle_size=1;
int overlay_route_tick_next_node_bin_id=0;
int overlay_route_tick_node_bundle_size=1;
int overlay_route_tick()
{
  int n;

  long long start_time=overlay_gettime_ms();

  if (debug&DEBUG_OVERLAYROUTING) 
    fprintf(stderr,"Neighbours: %d@%d, Nodes: %d@%d\n",
	    overlay_route_tick_neighbour_bundle_size,overlay_route_tick_next_neighbour_id,
	    overlay_route_tick_node_bundle_size,overlay_route_tick_next_node_bin_id);

  /* Go through some of neighbour list */
  n=overlay_route_tick_neighbour_bundle_size;
  if (n<1) n=1;
  while(n--)
    {
      overlay_route_tick_neighbour(overlay_route_tick_next_neighbour_id++,start_time);
      if (overlay_route_tick_next_neighbour_id>=overlay_neighbour_count) overlay_route_tick_next_neighbour_id=0;
    }

  /* Tweak neighbour bundle size to spread it out over the required time.
     XXX Does this behave correctly when there are no neighbours? */
  long long neighbour_time=overlay_gettime_ms()-start_time;
  if (neighbour_time>2) overlay_route_tick_neighbour_bundle_size/=neighbour_time;
  else if (neighbour_time==0) overlay_route_tick_neighbour_bundle_size*=2;
  if (overlay_route_tick_neighbour_bundle_size<1) overlay_route_tick_neighbour_bundle_size=1;
  if (overlay_route_tick_neighbour_bundle_size>overlay_neighbour_count)
    overlay_route_tick_neighbour_bundle_size=overlay_neighbour_count;

  /* Go through some of node list */
  n=overlay_route_tick_node_bundle_size;
  if (n<1) n=1;
  while(n--)
    {
      int slot;
      for(slot=0;slot<overlay_bin_size;slot++) {
	overlay_route_tick_node(overlay_route_tick_next_node_bin_id,slot,start_time);
      }
      overlay_route_tick_next_node_bin_id++;
      if (overlay_route_tick_next_node_bin_id>=overlay_bin_count) overlay_route_tick_next_node_bin_id=0;
    }

  /* Tweak neighbour bundle size to spread it out over the required time.
     Allow 2ms here instead of 1ms, as neighbour processing may have taken the
     bulk of the tick. */
  long long node_time=overlay_gettime_ms()-neighbour_time-start_time;
  if (node_time>1) overlay_route_tick_node_bundle_size/=node_time;
  else if (node_time==0) overlay_route_tick_node_bundle_size*=2;
  if (overlay_route_tick_node_bundle_size<1) overlay_route_tick_node_bundle_size=1;

  /* Limit bundle sizes to sanity */
  if (overlay_route_tick_neighbour_bundle_size>overlay_neighbour_count
      &&overlay_neighbour_count)
    overlay_route_tick_neighbour_bundle_size=overlay_neighbour_count;
  if (overlay_route_tick_node_bundle_size>overlay_bin_count)
    overlay_route_tick_node_bundle_size=overlay_bin_count;

  /* Work out how long to have between route ticks to make sure we update all route scores
     every 5 seconds. */
  int ticks=max(overlay_neighbour_count
		?overlay_neighbour_count/overlay_route_tick_neighbour_bundle_size:0,
		overlay_bin_count/overlay_route_tick_node_bundle_size);
  if (ticks<1) ticks=1;
  if (ticks>5000) ticks=5000;
  int interval=5000/ticks;

  if (debug&DEBUG_OVERLAYROUTING) fprintf(stderr,"route tick interval = %dms (%d ticks per 5sec, neigh=%lldms, node=%lldms)\n",interval,ticks,neighbour_time,node_time);
  return interval;
}

/* Ticking neighbours is easy; we just pretend we have heard from them again,
   and recalculate the score that way, which already includes a mechanism for
   taking into account the age of the most recent observation */
int overlay_route_tick_neighbour(int neighbour_id,long long now)
{
  if (overlay_route_recalc_neighbour_metrics(&overlay_neighbours[neighbour_id],now)) 
    WHY("overlay_route_recalc_neighbour_metrics() failed");
  
  return 0;
}

/* Updating the route score to get to a node it trickier, as they might not be a
   neighbour.  Even if they are a neighbour, all we have to go on is the node's
   observations.
   From these we can work out a discounted score based on their age.

   XXX This is where the discounting should be modified for nodes that are 
   updated less often as they exhibit score stability.  Actually, for the
   most part we can tolerate these without any special action, as their high
   scores will keep them reachable for longer anyway.
*/
int overlay_route_tick_node(int bin,int slot,long long now)
{
  return overlay_route_recalc_node_metrics(&overlay_nodes[bin][slot],now);
}

int overlay_route_node_info(overlay_mdp_frame *mdp,
			    struct sockaddr_un *addr,int addrlen)
{
  int bin,slot,n;
  long long now=overlay_gettime_ms();

  if (0) 
    WHYF("Looking for node %s* (prefix len=0x%x)",
	 overlay_render_sid_prefix(mdp->nodeinfo.sid,
				   mdp->nodeinfo.sid_prefix_length),
	 mdp->nodeinfo.sid_prefix_length
	 );

  /* check if it is a local identity */
  int cn,in,kp;
  for(cn=0;cn<keyring->context_count;cn++)
    for(in=0;in<keyring->contexts[cn]->identity_count;in++)
      for(kp=0;kp<keyring->contexts[cn]->identities[in]->keypair_count;kp++)
	if (keyring->contexts[cn]->identities[in]->keypairs[kp]->type
	    ==KEYTYPE_CRYPTOBOX)
	  {
	    if (!memcmp(&mdp->nodeinfo.sid[0],
			&keyring->contexts[cn]->identities[in]
			->keypairs[kp]->public_key[0],
			mdp->nodeinfo.sid_prefix_length/2))
	      {
		if (mdp->nodeinfo.count==mdp->nodeinfo.index)
		  {
		    mdp->nodeinfo.foundP=1;
		    mdp->nodeinfo.localP=1;
		    mdp->nodeinfo.neighbourP=0;
		    mdp->nodeinfo.time_since_last_observation=0;
		    mdp->nodeinfo.score=256;
		    mdp->nodeinfo.interface_number=-1;
		    bcopy(&keyring->contexts[cn]->identities[in]
			  ->keypairs[kp]->public_key[0],
			  &mdp->nodeinfo.sid[0],SID_SIZE);

		    mdp->nodeinfo.did[0]=0;
		    if (mdp->nodeinfo.resolve_did) {
		      mdp->nodeinfo.resolve_did=0;
		      int k2;
		      for(k2=0;k2<keyring->contexts[cn]->identities[in]
			    ->keypair_count;k2++)
			if (keyring->contexts[cn]->identities[in]->keypairs[k2]->type
			    ==KEYTYPE_DID)
			  {
			    /* private key field has unpacked did */
			    bcopy(&keyring->contexts[cn]->identities[in]
				  ->keypairs[k2]->private_key[0],
				  &mdp->nodeinfo.did[0],
				  keyring->contexts[cn]->identities[in]
				  ->keypairs[k2]->private_key_len);
			    /* public key has name */
			    bcopy(&keyring->contexts[cn]->identities[in]
				  ->keypairs[k2]->public_key[0],
				  &mdp->nodeinfo.name[0],
				  keyring->contexts[cn]->identities[in]
				  ->keypairs[k2]->public_key_len);
			    mdp->nodeinfo.resolve_did=1;
			  }
		    }
		  }
		mdp->nodeinfo.count++;
	      }
	  }

  /* check neighbour table, i.e., if directly connected */
  for(n=0;n<overlay_neighbour_count;n++)
    if (overlay_neighbours[n].node)
      {
	if (!memcmp(&mdp->nodeinfo.sid[0],
		    &overlay_neighbours[n].node->sid[0],
		    mdp->nodeinfo.sid_prefix_length/2))
	  {
	    if (mdp->nodeinfo.count==mdp->nodeinfo.index)
	      {
		mdp->nodeinfo.foundP=1;
		mdp->nodeinfo.localP=0;
		mdp->nodeinfo.neighbourP=1;
		mdp->nodeinfo.time_since_last_observation
		  =overlay_gettime_ms()
		  -overlay_neighbours[n].last_observation_time_ms;
		mdp->nodeinfo.score=-1;
		mdp->nodeinfo.interface_number=-1;
		mdp->nodeinfo.resolve_did=0;
		int i;
		for(i=0;i<OVERLAY_MAX_INTERFACES;i++)
		  if (overlay_neighbours[n].scores[i]>mdp->nodeinfo.score)
		    {
		      mdp->nodeinfo.score=overlay_neighbours[n].scores[i];
		      mdp->nodeinfo.interface_number=i;
		    }
		
		bcopy(&overlay_neighbours[n].node->sid[0],
		      &mdp->nodeinfo.sid[0],SID_SIZE);
	      }
	    mdp->nodeinfo.count++;
	  }
      }
  
  /* check if it is an indirectly connected node that we know about */
  for(bin=0;bin<overlay_bin_count;bin++)
    for(slot=0;slot<overlay_bin_size;slot++)
      {
	if (!overlay_nodes[bin][slot].sid[0]) continue;
	
	if (!memcmp(&mdp->nodeinfo.sid[0],
		    &overlay_nodes[bin][slot].sid[0],
		    mdp->nodeinfo.sid_prefix_length/2))
	  {
	    if (mdp->nodeinfo.count==mdp->nodeinfo.index)
	      {
		mdp->nodeinfo.foundP=1;
		mdp->nodeinfo.localP=0;
		mdp->nodeinfo.neighbourP=0;
		mdp->nodeinfo.time_since_last_observation=overlay_gettime_ms();
		mdp->nodeinfo.score=-1;
		mdp->nodeinfo.interface_number=-1;
		mdp->nodeinfo.resolve_did=0;
		int o;
		for(o=0;o<OVERLAY_MAX_OBSERVATIONS;o++)
		  if (overlay_nodes[bin][slot].observations[o].observed_score)
		    {
		      overlay_node_observation *ob
			=&overlay_nodes[bin][slot].observations[o];
		      if (ob->corrected_score>mdp->nodeinfo.score) {
			mdp->nodeinfo.score=ob->corrected_score;
		      }
		      if ((now-ob->rx_time)
			  <mdp->nodeinfo.time_since_last_observation)
			mdp->nodeinfo.time_since_last_observation=now-ob->rx_time;
		    }
		
		bcopy(&overlay_nodes[bin][slot].sid[0],
		      &mdp->nodeinfo.sid[0],SID_SIZE);
	      }
	    mdp->nodeinfo.count++;
	  }
      }

  return overlay_mdp_reply(mdp_named_socket,addr,addrlen,mdp);

  return 0;
}
