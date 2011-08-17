#include "mphlr.h"

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

typedef struct overlay_node_observation {
  int valid;
  
  /* Sequence numbers are handled as ranges because the tick
     rate can vary between interfaces, and we want to be able to
     estimate the reliability of links to nodes that may have
     several available interfaces.
     We don't want sequence numbers to wrap too often, but we
     would also like to support fairly fast ticking interfaces,
     e.g., for gigabit type links. So lets go with 1ms granularity. */
  int sequence_range_low;
  int sequence_range_high;
  long long rx_time;
  unsigned char sender[SID_SIZE];
} overlay_node_observation;

/* Keep track of last 32 observations of a node.
   Hopefully this is enough, if not, we will increase */
#define OVERLAY_MAX_OBSERVATIONS 32

typedef struct overlay_node {
  unsigned char sid[SID_SIZE];
  int neighbour_id; /* 0=not a neighbour */
  int most_recent_observation_id;
  overlay_node_observation observations[OVERLAY_MAX_OBSERVATIONS];
} overlay_node;

/* For fast handling we will have a number of bins that will be indexed by the
   first few bits of the peer's SIDs, and a number of entries in each bin to
   handle hash collissions while still allowing us to have static memory usage. */
int overlay_bin_count=0;
int overlay_bin_size=0;
overlay_node *overlay_nodes[]=NULL;

/* We also need to keep track of which nodes are our direct neighbours.
   This means we need to keep an eye on how recently we received DIRECT announcements
   from nodes, and keep a list of the most recent ones.  The challenge is to keep the
   list ordered without having to do copies or have nasty linked-list structures that
   require lots of random memory reads to resolve.

   The simplest approach is to maintain a large cache of neighbours and practise random
   replacement.  If is however succecptible to cache flushing attacks by adversaries, so
   we will need something smarter in the long term.
*/
int overlay_max_neighbours=0;
int overlay_neighbour_count=0;
overlay_node *overlay_neighbours[]=NULL;

int overlay_get_nexthop(unsigned char *d,unsigned char *nexthop,int *nexthoplen)
{
  return WHY("Not implemented");
}

int overlay_route_saw_selfannounce(overlay_frame *f)
{
  
  return WHY("Not implemented");
}

int overlay_route_saw_selfannounce_ack(overlay_frame *f)
{
  return WHY("Not implemented");  
}
