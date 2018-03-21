Route REST API
==============
[Serval Project][], September 2016

Introduction
------------

Every [Serval DNA][] daemon running on a node in the [Serval mesh network][]
maintains its own dynamic *routing table*, which it uses to choose the [network
interface][] on which to send each outgoing [MDP message][].  The mesh routing
algorithm updates the routing table whenever Serval DNA receives an [overlay
packet][] and whenever system time advances.  For more details, see [Mesh
Datagram Protocol][].

The [Serval DNA][] daemon gives applications access to its routing table via
the **Route REST API** described in this document.  Applications can use this
information to:

  * discover the current [network neighbours](#neighbour)
  * discover all currently (and recently) [reachable nodes](#reachable)
  * estimate the quality of service to any given [reachable node](#reachable)

Basic concepts
--------------

### Routing table

Every [node](#node) in the [Serval mesh network][] maintains its own *routing
table*, which identifies a single [path](#path) to every [reachable](#reachable)
[node](#node).  The mesh routing algorithm chooses the best path based on
routing information received from other nodes along the path.

Whenever a [node](#node) receives an [overlay packet][], it knows that, at the
time the packet was received, there existed a direct incoming [link](#link)
from the [transmitting node][transmitter].  It updates its routing table to
mark the transmitter's [primary SID](#primary-sid) as a [neighbour](#neighbour).

Whenever a [node](#node) receives nothing from a given neighbour for longer
than a [configured][] time interval, it presumes that the [link](#link) is
broken.  It updates its routing table to mark the neighbour's [primary
SID](#primary-sid) as no longer a neighbour.

### Tick

Every daemon ensures that all of its nearby nodes remain aware of its presence
by sending regular [overlay packet][]s to every [neighbour](#neighbour).  Every
[overlay packet][] contains its own [primary SID](#primary-sid) as the sender
address.

Every [network interface][] has a [configured][] *tick interval*, which is the
maximum time period that may elapse between messages sent to any neighbour on
that interface.  If no message has been sent to a given neighbour for a whole
tick interval, then the daemon sends an empty [overlay packet][], called a
*tick packet*, to the neighbour.

As a result, while an interface is quiescent (no traffic), depending on whether
the [link](#link) to each neighbour is *broadcast* or *unicast*, at every tick
the daemon will send either a single broadcast Wi-Fi packet, or several unicast
Wi-Fi packets, or a mixture.

### Node

A *node* in the [Serval mesh network][] is any device with its own link-layer
address (eg, a UDP/IP address or a Wi-Fi MAC address) that is running a [Serval
DNA][] daemon configured to use that network interface.

### Neighbour

A [node's](#node) *neighbour* in the [Serval mesh network][] is any node from
which its [Serval DNA][] daemon directly receives [overlay packet][]s through a
[network interface][].

Note that a neighbour is not necessarily [reachable](#reachable), because
wireless links are not always symmetrical; even though station A receives from
station B, it does not necessarily mean that B can receive from A, because of
factors like different transmitter power and antenna gain.

### Link

A *link* is a one-way connection from a [node](#node) to one of its [neighbour
nodes](#neighbour).  Links are represented in the routing table by the [primary
SID](#primary-sid) of their receiving end.

A link may be either *broadcast* or *unicast*, which is chosen by the receiver
[node](#node) during link negotiation.

Each link is characterised by a metric that represents the dynamic link quality
(eg, the proportion of recent packets successfully received).  Every
[node](#node) dynamically computes the quality of all its incoming links by
counting the gaps in the sequence numbers on received [overlay packet][]s.  It
continuously informs each [neighbour node](#neighbour) of the measured quality
of its incoming link by periodically sending a [routing
message](#routing-message) to each neighbour at a [configured][] time interval.

### Primary SID

Every [node](#node) identifies itself by its *primary SID*, which is usually
the [SID][] of the first identity that was [unlocked][] since the daemon was
started.

### Secondary SID

A [node](#node) may have more than one [SID][], ie more than one [unlocked][]
identity.  All its SIDs except the [primary SID](#primary-sid) are called
*secondary*.

A [node](#node) announces all of its secondary SIDs by representing them in its
[routing messages](#routing-message) as [reachable](#reachable)
[neighbours](#neighbour) on a private network interface (ie, not available to
other nodes) with a 100% link quality.

### Routing message

Every [node](#node) in the [Serval mesh network][] informs other nodes of the
presence and quality of all of its incoming and outgoing [links](#link) by
sending *routing messages*.  A routing message is a one-hop message that goes
to all [neighbouring](#neighbour) nodes but no further:

  * whenever a node detects the presence (received packet) or absence (timeout)
    of an incoming link, or revises the measured quality of an incoming link,
    it sends a routing message with the single link's state/quality to the
    single [neighbour](#neighbour) at the transmitting end of the link;

  * whenever a node receives a routing message from one of its neighbours, it
    incorporates the new link state (up/down) and quality information into its own
    routing table, re-evaluates its [paths](#path), and, shortly afterwards,
    sends a routing message containing the state/quality information of all its
    outgoing and incoming links to all of its [neighbours](#neighbour).

Routing messages are not forwarded directly, but the information they carry
propagates beyond the node's immediate neighbours because each neighbour, upon
receiving a routing message, updates its own [routing table](#routing-table)
and sends out its own routing messages that arise as a result of the update.

### Path

A *path* is a one-way route from a *sender* [node](#node) to a *recipient*
[node](#node), expressed as a sequence of non-repeating [links](#link).  The
first link in a path always leads to a [reachable](#reachable) [neighbour
node](#neighbour).

The routing algorithm constructs paths by choosing links whose existence and
quality has been revealed by a recently-received *routing message* from a
neighbour.

### Reachable

A [node](#node) in the [Serval mesh network][] considers another node to be
*reachable* if its own [routing table](#routing-table) contains a [path](#path)
to the second node.

REST Requests
-------------

### GET /restful/route/all.json

Returns a list of all currently known identities, in [JSON table][] format.
The table columns are:

| heading               | type             | content                                                                        |
|:--------------------- |:---------------- |:------------------------------------------------------------------------------ |
| `sid`                 | string           | the [SID][] of the identity, as 64 uppercase hex digits                        |
| `did`                 | string or `null` | the [DID][] of the identity if known (eg, for a local [keyring][] identity)    |
| `name`                | string or `null` | the [Name][] of the identity if known (eg, for a local [keyring][] identity)   |
| `is_self`             | boolean          | true if the identity is a self-identity, ie, in the local [keyring][]          |
| `reachable_broadcast` | boolean          | true if the identity is [reachable](#reachable) by broadcast [link](#link)     |
| `reachable_unicast`   | boolean          | true if the identity is [reachable](#reachable) by unicast [link](#link)       |
| `reachable_indirect`  | boolean          | true if the identity is [reachable](#reachable) only via another [node](#node) |
| `interface`           | string or `null` | the name of the local network interface on which the identity is reachable     |
| `hop_count`           | integer          | the number of hops to reach the identity                                       |
| `first_hop`           | string or `null` | if `hop_count > 1`, then the [SID][] of the first identity in the route        |
| `penultimate_hop`     | string or `null` | if `hop_count > 2`, then the [SID][] of the penultimate identity in the route  |

-----
**Copyright 2015 Serval Project Inc.**  
**Copyright 2016-2018 Flinders University**  
![CC-BY-4.0](./cc-by-4.0.png)
Available under the [Creative Commons Attribution 4.0 International licence][CC BY 4.0].


[Serval Project]: http://www.servalproject.org/
[CC BY 4.0]: ../LICENSE-DOCUMENTATION.md
[Serval Mesh network]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:mesh_network
[Serval DNA]: ../README.md
[REST-API]: ./REST-API.md
[keyring]: ./REST-API-Keyring.md
[SID]: ./REST-API-Keyring.md#serval-id
[DID]: ./REST-API-Keyring.md#did
[Name]: ./REST-API-Keyring.md#name
[unlocked]: ./REST-API-Keyring.md#identity-unlocking
[overlay packet]: ./Mesh-Datagram-Protocol.md#overlay-packet
[sender]: ./Mesh-Datagram-Protocol.md#sender
[transmitter]: ./Mesh-Datagram-Protocol.md#transmitter
[MDP message]: ./Mesh-Datagram-Protocol.md#mdp-message
[broadcast]: ./Mesh-Datagram-Protocol.md#broadcast
[Mesh Datagram Protocol]: ./Mesh-Datagram-Protocol.md
[JSON table]: ./REST-API.md#json-table
[configured]: ./Servald-Configuration.md
[network interface]: ./Servald-Configuration.md#network-interfaces
[200]: ./REST-API.md#200-ok
[201]: ./REST-API.md#201-created
[202]: ./REST-API.md#202-accepted
[400]: ./REST-API.md#400-bad-request
[404]: ./REST-API.md#404-not-found
[419]: ./REST-API.md#419-authentication-timeout
[422]: ./REST-API.md#422-unprocessable-entity
[423]: ./REST-API.md#423-locked
[500]: ./REST-API.md#500-server-error
