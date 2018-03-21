Mesh Datagram Protocol (MDP)
============================
[Serval Project], November 2017

The [Mesh Datagram Protocol][MDP] is a [layer 3][] [datagram][] network
protocol developed for the [Serval mesh network][], with characteristics that
make it particularly suitable for use in Ad Hoc wireless networks, which can
suffer high levels of packet loss due to weak signal, interference and
congestion.

MDP carries [messages](#mdp-message) from [sender](#sender) to [recipient](#recipient)
[node](#node)s, or [broadcasts](#broadcast) to all nodes.  MDP guarantees that
message contents will be correct if delivered, but does not guarantee exactly
one delivery (messages may be lost or delivered more than once), arrival time,
or message order.

MDP can be carried over any wireless or wired data link, whether a shared
medium (eg, [CSMA/CA][] used in [Wi-Fi][]) or a dedicated medium (eg, [AX.25
packet radio][], [serial cable][]).

MDP is similar to [UDP][], but it uses per-[link](#link) retransmission and
adaptive link-state routing to boost packet delivery rates, which largely
immunises it from the cumulative packet loss effect typical of multi-hop
wireless networks.  To carry a packet over **N** hops, where each hop has a
probability **P** of dropping a packet due to interference or collision, the
end-to-end loss is **1 − pow(1−P, N)**. For example, given a per-hop packet loss
of 10%, a five hop route has a net packet loss of 41%, and a ten hop route
has 75% packet loss.

The MDP retransmission scheme reduces but does not eliminate packet loss, and
sometimes produces duplicate packets.  However, it can squeeze useful packet
delivery rates from a high-loss route that would be practically useless with
[Internet protocols][], which rely on end-to-end retransmission.

Basic concepts
--------------

### Node

A **node** in the [Serval mesh network][] is a single device having one or more
[network interfaces][], running exactly one instance of the [Serval DNA][]
daemon process that is [configured][] to use those network interfaces.

If a single device were to run several [Serval DNA][] daemon processes, then
each daemon process would be treated as a separate node, and they should be
[configured][] to share the device's [network interfaces][] and communicate
with each other using device-local interfaces such as [local sockets][] or
[pipes][].

### Link

A **link** in the [Serval mesh network][] is a direct network connection
between two [node](#node)s, making it possible for a packet sent by the [Serval
DNA][] daemon on one node to be received directly by the daemon on the other
node, without traversing any other node.  In other words, a link is a direct
connection between nodes that supports [layer 2][] protocol functions.

Note that this definition does not rule out an MDP packet passing through a
non-Serval multi-hop route.  For example, if an [overlay packet](#overlay-packet)
is routed through a multi-hop [layer 3][] or [layer 4][] network service, such
as [UDP][], that is still a *single link* as far as MDP is concerned, because
the packet does not pass through a Serval [node](#node).

### MDP Address

Every [node](#node) in the [Serval mesh network][] uses a unique [Serval
ID][SID] (abbreviated to **SID**) as its **MDP address**.

The [Serval DNA][] daemon can have one or many identities in its [keyring][],
and each identity has its own unique [SID][].  The daemon chooses the first
identity that it unlocks as the *principal* identity, and that identity's SID
becomes the node's MDP Address.  If that identity is ever locked, then the
daemon will choose another currently unlocked identity and change its MDP
Address to be that SID.

Since each [SID][] identifies a distinct *user* of the network (sometimes
called a *subscriber*), then strictly speaking, the Serval mesh network could
be said to carry messages between *users* not between *devices*.  There is
nothing to prevent a [keyring][] entry from being copied from one device to
another, thus it is possible for two or more devices to have the same MDP
Address.  At present, Serval [routing][] does not handle this case, so it could
cause unwanted effects such as route flapping or dropped messages.

In practice, the “duplicate MDP Address” problem is rare for the time being,
because the [Serval Mesh app for Android][] does not provide any way for a
non-expert user to copy the [keyring][] file from one device to another, and
other Serval devices such as the [Mesh Extender][] are not operated by
end-users.

### Transmitter

Whenever an [MDP message](#mdp-message) is carried over a single [link](#link)
from one [node](#node) to another, the **transmitter** link, identified by its
[MDP address](#mdp-address), is responsible for encapsulating the message in
such a way as to guarantee its content (error detection) and possibly guarantee
or at least improve its probability of arrival (retransmission or error
correction).  The most common encapsulation is the [MDP overlay
packet](#overlay-packet).

*Transmitter* is a [layer 2][] concept because it concerns data transfer across
a single [link](#link).

### Receiver

Whenever an [MDP message](#mdp-message) is carried over a single [link](#link)
from one [node](#node) to another, the **receiver** link, identified by its
[MDP address](#mdp-address), is responsible for decoding the encapsulated
message, dealing with data corruption (error checking or correction),
cooperating with the [transmitter](#transmitter) (ACK to prevent
retransmission) and de-duplication.

*Receiver* is a [layer 2][] concept because it concerns data transfer across a
single [link](#link).

### Sender

Every [MDP message](#mdp-message) originates from a single **sender**
[node](#node), identified by its [MDP address](#mdp-address).  As the message
passes through many [nodes](#node) to reach its [recipient](#recipient), it
keeps the same sender address.

*Sender* is a [layer 3][] concept because it specifies an end point of a
multi-[link](#link) route.

### Recipient

Every [MDP message](#mdp-message) that is not a [broadcast](#broadcast) message
is destined for a single **recipient** [node](#node), identified by its [MDP
address](#mdp-address).  The message may pass through many [nodes](#node) to
reach its recipient.

*Recipient* is a [layer 3][] concept because it specifies an end point of a
multi-[link](#link) route.

### MDP message

The smallest unit of data transported by MDP is the **MDP message**.  The MDP
message is a [layer 3][], or end-to-end concept: the [Serval mesh network][]
carries each MDP message from its [sender](#sender) to its
[recipient](#recipient), routing via as many intermediate [nodes](#node) as
necessary, without the messages having to specify any intermediate nodes.

An MDP message consists of a variable-length header, followed by a
variable-length payload which may be [encrypted][] and [signed][].  Most fields
in the MDP message header are optional, depending on the initial byte of bit
flags:

| bytes  | name               | present if              | meaning                                               |
|:------:|:------------------ |:----------------------- |:----------------------------------------------------- |
| 1      | FLAGS              |                         | [message flags](#mdp-message-flags)                   |
| 1..33  | sender address     | `!SENDER_SAME`          | the [sender's](#sender) [address](#mdp-address)       |
| 1..33  | recipient address  | `!BROADCAST`            | the [recipient's](#recipient) [address](#mdp-address) |
| 8      | broadcast sequence | `BROADCAST && !ONE_HOP` | [broadcast](#broadcast) message's sequence number     |
| 1      | TTL and QoS        | `!ONE_HOP`              | time-to-live counter and service type                 |
| 2      | payload size       |                         | number of bytes in payload                            |
| 0..max | payload            |                         |                                                       |

### MDP message flags

The single FLAGS byte at the start of the [MDP message](#mdp-message) header
contains the following bits (bit numbers start with 0 = LSB):

|  bit  | symbol        | meaning                                                                                       |
|:-----:|:------------- |:--------------------------------------------------------------------------------------------- |
|   0   | `SENDER_SAME` | the [transmitter](#transmitter) is the [sender](#sender)                                      |
|   1   | `BROADCAST`   | message is [broadcast](#broadcast); has no [recipient](#recipient)                            |
|   2   | `ONE_HOP`     | message is on last [link](#link), so the [receiver](#receiver) is the [recipient](#recipient) |
|   3   | (unused)      | transmitter must set to zero; recipient must ignore                                           |
|   4   | `CIPHERED`    | payload is [encrypted][]                                                                      |
|   5   | `SIGNED`      | payload is [signed][]                                                                         |
|   6   | `ACK_SOON`    | transmitter will re-transmit very soon                                                        |
|   7   | (unused)      | transmitter must set to zero; recipient must ignore                                           |

* The `SENDER_SAME` flag is set on the first outbound [link](#link) of a message's
  trajectory if the message is encapsulated in an [overlay
  packet](#overlay-packet); ie, the [Sender SID](#sender) is identical to the
  overlay packet's [Transmitter SID](#transmitter).  In this case the *Sender
  SID* field is omitted from the message's header, to avoid unnecessary
  duplication.

* The `BROADCAST` flag indicates a [broadcast](#broadcast) message that is sent
  to all nodes.  If the `BROADCAST` flag is set, the [Recipient
  SID](#recipient) message header field is absent, and the *broadcast sequence*
  header field is present unless the `ONE_HOP` flag is also set (see below).

* The `ONE_HOP` flag is set to indicate that the message is not to be forwarded
  by the receiver; this occurs in the following cases:

  * The message is on the last [link](#link) of its trajectory to its
    [recipient](#recipient) and is encapsulated in an [overlay
    packet](#overlay-packet); ie, the [Recipient SID](#sender) is identical to
    the overlay packet's [Receiver SID](#receiver).  In this case the
    *Recipient SID* field is omitted from the message's header, to avoid
    unnecessary duplication.

  * The message is a [broadcast](#broadcast) message that need not propagate
    beyond the [receiver](#receiver); ie, it only has one [link](#link) to live
    (TTL = 1).  In this case, the *broadcast sequence* and *TTL and QoS* fields
    are omitted from the message's header to save space.

* The `CIPHERED` flag is set if the message's payload is [encrypted][] using
  the [Recipient SID](#recipient) as public key; only the recipient possesses
  the private key (secret), so only the recipient can decrypt the payload.  The
  `CIPHERED` and `BROADCAST` flags are mutually exclusive; all
  [broadcast](#broadcast) messages are unciphered.

* The `SIGNED` flag is set if the message's payload is [signed][] by the
  sender; anyone can verify the signature using the [Sender SID](#sender)
  public key, but only the sender possesses the private key (secret), so only
  the sender can produce the signature.

* The `ACK_SOON` flag is set if the [transmitter](#transmitter) will re-send
  the message unless receiving an ACK for the message within the next few
  [overlay packet](#overlay-packet)s.  This flag is typically used on
  low-latency, high quality links to maximise throughput by avoiding redundant
  re-transmissions.

### MDP address fields

The *sender* and *recipient* address fields in the [MDP message](#mdp-message)
header are encoded as a single qualifier byte **Q** followed by 0 ≤ **N** ≤ 32
bytes of data:

| **Q** | symbol     | **N** | resolves to...                                                                     |
|:-----:|:---------- |:-----:|:---------------------------------------------------------------------------------- |
| 0..31 |            | **Q** | an [abbreviated address](#abbreviated-address) in binary format                    |
|  32   |            |   32  | a complete [SID][] in binary format                                                |
| 0xFB  | `SIGNKEY`  |   32  | a complete [Signing ID][] in binary format                                         |
| 0xFC  | `P2P_ME`   |    0  | the *source* address of a [point-to-point link](#point-to-point-link)              |
| 0xFD  | `P2P_YOU`  |    0  | the *destination* address of a [point-to-point link](#point-to-point-link)         |
| 0xFE  | `PREVIOUS` |    0  | the previous resolved address                                                      |
| 0xFF  | `SELF`     |    0  | the [transmitter](#transmitter) of the enclosing [overlay packet](#overlay-packet) |

`SIGNKEY` addresses are only used for [combined IDs][], ie, where the [SID][]s
is cryptographically derived from a [Signing ID][].  Any [node](#node) running
a version of the [Serval DNA][] daemon that pre-dates the combined key upgrade
will not recognise the `SIGNKEY` address type, and will treat it as invalid.

`P2P_ME` and `P2P_YOU` addresses are only valid in MDP messages that are being
transmitted over a [point-to-point link](#point-to-point-link).  If a `P2P_ME`
address is received but the recipient [node](#node) has not yet discovered the
address of the source [node](#node) at the other end of the link, then the
recipient treats the address as invalid and initiates an address discovery
handshake, so that subsequent `P2P_ME` addresses may succeed.

A `PREVIOUS` address resolves to the previous resolved sender or recipient
address in this MDP message or in the preceding MDP message in the enclosing
[overlay packet](#overlay-packet).  This qualifier is generally not useful and
may be deprecated in future.

The `SELF` qualifier is only valid in MDP messages that are encapsulated within
an [overlay packet](#overlay-packet).

### Broadcast

**TODO**: Describe the behaviour of broadcast messages.

### Overlay Packet

MDP transmits a [MDP message](#mdp-message) over a [link](#link) by
encapsulating it into an **overlay packet** (also called **MDP packet** or
**overlay frame**).  The MDP overlay packet is a [layer 2][] concept; it is
only concerned with transporting MDP messages across a single link to a
neighbouring [peer][] node.  Once an overlay packet arrives, the receiver
unpacks all of its MDP messages, consumes those for which it (or one of its
[zero-hop][] identities) is the [recipient](#recipient) and independently
message in an overlay packet is constructed afresh when it is embedded into the
packet, setting its [flag bits](#mdp-message-flags) and re-writing the [address
fields](#mdp-address-fields) within the context of the overlay packet, in order
to conserve link bandwidth by avoiding duplication where possible.

**TODO**: Describe the structure of an overlay packet in detail.

Abbreviated address
-------------------

An *abbreviated address* is a truncated [SID][], ie, the initial **N** < 32
bytes of a whole [SID][].

Since SIDs are randomly allocated and only relatively few SIDs are in use
within a local [Serval mesh network][] at a given time, all SIDs in use are
very likely to differ within their first few bytes.  Thus, within the context
of the local mesh network, there is no need to use entire SIDs to uniquely
identify [node](#node)s.

[SID abbreviation][] allows MDP messages to identify their sender and recipient
using far fewer than 32 bytes, typically only 1 or 2 bytes.

**TODO**: Describe the the abbreviation resolution rules and the *explain*
handshake.

MDP Client Interface
--------------------

The [Serval DNA][] daemon provides an interface that allows client applications
to send and receive individual MDP packets on the [Serval mesh network][]
without having to construct and disassemble Overlay Mesh frames on their own.

MDP Client API
--------------

The *MDP Client API* is a [C language][] [API][] that an application can use to
send and receive MDP packets over the [Serval mesh network][] using the
[interface](#mdp-interface) provided by the [Serval DNA][] daemon.

History
-------

MDP was designed and first prototyped in May-June 2012 as part of the [first
New America Foundation contract][naf1] to integrate Serval security into the
OpenBTS base station, and also as part of the development of [release 0.90
“Shiny”][Batphone 0.90] of the [Serval Mesh app for Android][].

-----
**Copyright 2014 Serval Project Inc.**  
**Copyright 2016-2017 Flinders University**  
![CC-BY-4.0](./cc-by-4.0.png)
Available under the [Creative Commons Attribution 4.0 International licence][CC BY 4.0].


[Serval Project]: http://www.servalproject.org/
[CC BY 4.0]: ../LICENSE-DOCUMENTATION.md
[Serval mesh network]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:mesh_network
[Serval DNA]: ../README.md
[Serval Mesh app for Android]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:servalmesh:
[Mesh Extender]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:meshextender:
[MDP]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:mdp
[datagram]: http://en.wikipedia.org/wiki/Datagram
[CSMA/CA]: http://en.wikipedia.org/wiki/CSMA/CA
[Wi-Fi]: http://en.wikipedia.org/wiki/WiFi
[AX.25 packet radio]: http://en.wikipedia.org/wiki/Packet_radio
[serial cable]: http://en.wikipedia.org/wiki/Serial_cable
[Internet protocols]: https://en.wikipedia.org/wiki/Internet_protocol_suite
[layer 2]: https://en.wikipedia.org/wiki/Data_link_layer
[layer 3]: https://en.wikipedia.org/wiki/Network_layer
[layer 4]: https://en.wikipedia.org/wiki/Transport_layer
[peer]: ./REST-API-Route.md#peer
[UDP]: http://en.wikipedia.org/wiki/User_Datagram_Protocol
[MTU]: http://en.wikipedia.org/wiki/Maximum_transmission_unit
[SID]: ./REST-API-Keyring.md#serval-id
[Signing ID]: ./REST-API-Keyring.md#serval-signing-id
[combined IDs]: ./REST-API-Keyring.md#combined-ids
[SID abbreviation]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:sid_abbreviation
[configured]: ./Servald-Configuration.md
[network interfaces]: ./Servald-Configuration.md#network-interfaces
[keyring]: ./REST-API-Keyring.md
[routing]: ./REST-API-Route.md
[zero-hop]: ./REST-API-Route.md#zero-hop
[encrypted]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:security_framework
[signed]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:security_framework
[local sockets]: https://en.wikipedia.org/wiki/Unix_domain_socket
[pipes]: https://en.wikipedia.org/wiki/Pipeline_(Unix)
[C language]: http://en.wikipedia.org/wiki/C_(programming_language)
[API]:http://en.wikipedia.org/wiki/Application_programming_interface
[naf1]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:activity:naf1
[Batphone 0.90]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:servalmesh:releases:version_0_90
