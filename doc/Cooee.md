Cooee Service Discovery Protocol
================================
[Serval Project], May 2014

[Cooee][] is a protocol for discovering services offered by reachable nodes in
a [Serval mesh network][].  It is named after the [Australian bush shout][].

Cooee was funded by a [grant][] from the [New America Foundation][NAF]'s [Open
Technology Institute][OTI].

What is a Service?
------------------

A *service* is a program (called a *server*) running on a single network node,
that accepts spontaneous requests from other programs (called *clients*) via
the network, performs a useful function, and replies to the client via the
network.

A server may decline to respond to some clients based on their [SID][]
(typically a blacklist or whitelist) or some other criterion such as load or
some aspect of the request.  In general, however, a service is not selective
about which clients it will serve, and does not have prior knowledge of who
will contact it, or when.  In order to avoid service delays or absences, a
server must be able to handle many requests concurrently.

Service protocols and state
---------------------------

Each service has its own particular protocol, and clients wishing to use the
service must use that protocol.

A *one-shot* service protocol contains the entire request in a single [MDP][]
packet, and typically the response is a single packet sent back to the client's
originating [MDP port][] number.  A one-shot service with very rapid reply
generation may not need to be concurrent; it need only queue all incoming
requests and deal with them in turn.  In a one-shot service, it is possible for
the server to be fully *stateless*, because it need not remember any prior
requests or responses.  Service congestion can be dealt with by simply dropping
new requests when the queue is full.  The absence of a response causes the
client to re-send the request after some time-out.

More elaborate service protocols involve establishing a *session* between the
client and server, which is discarded once the service has been performed.  The
[Mesh Stream Protocol][MSP] is commonly used for this kind of service, to
provide lossless transmission of messages between client and server.
Session-based servers must retain some state per session.

Server MDP port number
----------------------

A server operates by listening for [MDP][] packets sent to a single [MDP
port][] on its node.  The port number may be reserved in advance for that
service, which means that the service can have at most one server running at a
time per node.  Alternatively, the port number may be allocated whenever the
server starts, so is not known in advance, but each node may support many
servers offering the same service.

In general, clients that wish to use a service do not know the [MDP port][]
number or [SID][] of the node that hosts the server.  They must use [Cooee][]
to discover the SID and port number.

What is Cooee?
--------------

[Cooee][] is a *one-shot* [MDP][] service available on [MDP port][] **11** of
every node, that resolves service names to port numbers and other qualifying
information.

In Cooee, every service is described by a *stanza* of `name=value` pairs, using
the same [UTF-8][] text format as the [Serval DNA configuration file][].

A Cooee request packet contains one or more *patterns* that are each matched
against the names in each service's stanza.  The request packet is typically
broadcast to all nodes in the reachable (local) Mesh network, and every service
with a name that matches any pattern sends a reply packet containing the lines
from its stanza that match.

How does a client use Cooee?
----------------------------

Client programs use Cooee by sending a broadcast packet to port 11 and
collecting all the reply packets that it provokes.  Any packet whose content
does not strictly conform to the stanza grammar should be ignored.

For example, a client searching for a [SOCKS5][]-over-[MSP][] [Internet][]
access point may send a broadcast packet containing the following pattern:

    socks5.msp.*

It may receive the following response from one node:

    socks5.msp.port=34
    socks5.msp.name.en=Filtered Internet service
    socks5.msp.rx_bps=174000
    socks5.msp.tx_bps=36000

... and the following response from another node:

    socks5.msp.port=116
    socks5.msp.name.en=Telco mobile data plan
    socks5.msp.name.es=Móvil internet de Telco

The exact meanings of the lines in the replies is defined below.

Clients may simply ignore any lines that they do not recognize, or may present
them to the human user to assist in choosing between services.  For example,
even though the `.rx_bps` and `.tx_bps` lines shown above may not be recognised
by all clients, their presence or absence will not cause any client to
disregard the service itself.

The remote (sending) [SID][] of the Cooee reply packet gives the node that
hosts the service, so a node cannot reply for services available on other
nodes.

How does a server advertise itself using Cooee?
-----------------------------------------------

Every server that wishes to make itself discoverable via Cooee must know its
own stanza, and must respond to Cooee requests on port 11 (as well as
responding to the port on which it provides its own service).  The [MDP port
sharing][] feature of [Serval DNA][] allows many servers to listen on port 11
at the same time, and all of them will receive a copy of every packet received
on port 11.

Whenever a server receives a Cooee request packet, it must match the requested
pattern against its own stanza.  If any lines match, it must construct and send
a reply packet containing the matching lines.  If a server provides many
services by listening on many ports, then it will know one stanza per service,
and if more than one of those stanzas match a Cooee request, then it must send
one reply packet per matching stanza -- it cannot combine all the matches into
a single packet.

This means that a single Cooee request may provoke more than one response
packet from one node, if more than one server running on that node provides the
service being sought.

Service description stanzas
---------------------------

A Cooee service description stanza is a block of [UTF-8][] text which conforms
to the following grammar:

    STANZA := LINE {1..}

    LINE := NAME "=" VALUE "\n"

    NAME := WORD ( "." WORD ){0..}
    WORD := WCHAR {1..}
    WCHAR := DIGIT | UPPERCASE | LOWERCASE | "_"
    DIGIT := "0".."9"      (ASCII digits)
    UPPERCASE := "A".."Z"  (ASCII uppercase)
    LOWERCASE := "a".."z"  (ASCII lowercase)

    VALUE := VCHAR {0..}
    VCHAR := any UTF-8 character except "\n" and NUL

In other words, **NAME** is a sequence of one or more alphanumeric words
separated by period characters, and **VALUE** is any sequence of characters not
containing NUL (zero) or newline `"\n"`.

**Note** that the grammar does not permit blank lines or white space before, in
or after a NAME.

### Standard service names

In general, every service description NAME must have the form:

    servicename.protocol.attribute

#### Standard `servicename` values:

 * **`socks5`** -- a SOCKS5 forward proxy that provides access to the public
   [Internet][]

 * **`http_proxy`** -- a Web forward proxy that provides access to the public
   [World Wide Web][]

#### Standard `protocol` values:

 * **`mdp`** -- [Mesh Datagram Protocol][MSP], generally only of use for
   one-shot services

 * **`msp`** -- [Mesh Stream Protocol][MSP], generally used by session-based
   services

#### Standard `attribute` values:

 * **`port`** -- the [MDP port][] number on which the service may be found, the
   value is either decimal (eg, `31`) or hexadecimal with a `0x` prefix (eg,
   `0x1f`)

 * **`name.en`** -- a textual description of the service that can be presented
   to an English-speaking human user (this is just a case of the `name.XX`
   attribute below)

 * **`name.XX`** -- a textual description of the service in a human language
   identified by the `XX` two-letter [ISO 639-1][] code, eg, `name.es` for
   Spanish, `name.ja` for Japanese, etc.

### Non-standard service names

Services may put any lines they wish into their Cooee stanza.  However, names
not defined in this standard run the risk of being incompatible with a future
expansion of the standard.

If a service wishes to publish *extra-standard* information about itself, it
must use NAME components that start with the underscore `_` character.  The
Cooee standard will never use these names, so the only risk is collision with
other services that have used the same name independently.

Service name patterns
---------------------

A Cooee request *pattern* uses a [glob][]-like syntax.  For example:

    [A-Z_]*.(ms|tc)p.(port|name.es)

will match all service names that start with an uppercase letter or underscore,
and whose protocol is either `msp` or `tcp`, and only matches the `port` and
`name.es` attributes.

 * __`text`__ -- matches exactly `text`, which may contain periods

 * __`*`__ -- matches zero or more of any character excluding period

 * __`**`__ -- matches zero or more of any character including periods

 * __`[SET]`__ -- matches any single character in SET, where SET is a
   concatenation of:
   * __`C`__ -- a single character `C`
   * __`A-B`__ -- a range of characters in [ASCII][] code order between `A` and
     `B` inclusive

 * __`[!SET]`__ -- matches any single character not in SET

 * __`(one|two|...)`__ matches either exactly `one` or `two` or any other
   alternatives separated by bars `|` and enclosed in parentheses

Some more examples:

 * Find all [MSP][] services: `*.msp.**`

 * Find only the port numbers of all [MDP][] services: `*.mdp.port`

 * Find all lines of all stanzas of all services: `**`

 * Find all non-standard lines of all stanzas of all services: `(_**|**._**)`

-----
**Copyright 2014 Serval Project Inc.**  
![CC-BY-4.0](./cc-by-4.0.png)
Available under the [Creative Commons Attribution 4.0 International licence][CC BY 4.0].


[Serval Project]: http://www.servalproject.org/
[CC BY 4.0]: ../LICENSE-DOCUMENTATION.md
[Australian bush shout]: http://en.wikipedia.org/wiki/Cooee
[Cooee]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:cooee
[grant]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:activity:naf6
[NAF]: http://www.newamerica.net/
[OTI]: http://oti.newamerica.net/
[Serval mesh network]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:mesh_network
[Serval DNA]: ../README.md
[Serval DNA configuration file]: ./Servald-Configuration.md
[SID]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:sid
[MDP]: ./Mesh-Datagram-Protocol.md
[MSP]: ./Mesh-Stream-Protocol.md
[MDP port]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:mdp_port_number
[MDP port sharing]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:mdp_port_sharing
[SOCKS5]: http://en.wikipedia.org/wiki/SOCKS
[Internet]: http://en.wikipedia.org/wiki/Internet
[World Wide Web]: http://en.wikipedia.org/wiki/World_Wide_Web
[UTF-8]: http://en.wikipedia.org/wiki/UTF-8
[ASCII]: http://en.wikipedia.org/wiki/ASCII
[ISO 639-1]: http://en.wikipedia.org/wiki/ISO_639-1
[glob]: http://en.wikipedia.org/wiki/Glob_(programming)
