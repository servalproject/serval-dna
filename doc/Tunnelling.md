Tunnelling through the Serval Mesh network
==========================================
[Serval Project][], May 2014

The [Serval Mesh network][], based on the [Mesh Datagram Protocol][MDP],
provides better packet delivery rates than conventional [UDP][] over a
multi-hop wireless network by employing per-hop retransmission (and, in future,
[linear network coding][]) to reduce the per-hop packet loss rate.  This
significantly reduces the cumulative multi-hop packet loss rate.  For this
reason, it is useful to carry [Internet Protocol][IP] traffic over the Serval
Mesh wireless network using a technique called [tunnelling][].

At present, only one tunnelling service is available for the Serval Mesh:

 * tunnelling of [TCP][] byte streams over the [Mesh Stream Protocol][MSP]
   (funded by a [grant][] from the [New America Foundation][NAF]'s [Open
   Technology Institute][OTI])

Tunnelling TCP over MSP
-----------------------

An [MSP][] tunnel can carry many [TCP][] streams simultaneously.  The tunnel
is set up by running a process on each of the two end-point nodes:

 * the “server” node's process acts as an MSP *listener*

 * the “client” node's process *connects* to the server's MSP listener once for
   each TCP stream that is to be tunnelled.

While an MSP tunnel is running, the client can initiate new TCP connections to
the server, but not vice versa.  The tunnel creates one MSP stream per TCP
stream.  Each MSP stream carries data in both directions.

When either process terminates, the tunnel is broken and all of its connections
immediately break.

### Server end - `msp listen`

    $ servald msp listen [--once] --forward=TCPPORT [--service=NAME] MDPPORT

The `msp listen` command acts as a server process which connects to the [Serval
DNA][] daemon, binds to the [MDP port][] number given by `MDPPORT`, creates an
[MSP][] *listening socket* on that port, and waits for connections from remote
MSP clients to that socket.  Whenever a connection is received, it:

 * connects to the TCP port `TCPPORT` on the local host (loopback interface),
   then:
 * writes all inbound MSP messages to the TCP stream in byte order, and
 * reads bytes from the local TCP stream and sends them as MSP messages
 * until either the local TCP stream is broken or the MSP connection is closed,
   whereupon it:
 * closes the TCP stream and the MSP connection.

If the `--once` option is given then the server process only accepts a single
MSP connection and exits as soon as the connection is closed.

If the `--service=NAME` option is given, then the server process also binds to
the standard [Serval service discovery][] [MDP port][] and responds to any
matching query with the response `NAME.mdp.port=MDPPORT`.

If the `--forward` option is omitted, then instead of connecting to a TCP port,
accepts only a single connection (the `--once` option is implied, and need not
be given explicitly) and forwards the MSP data to and from standard output and
input.

### Client end - `msp connect`

    $ servald msp connect [--once] --forward=TCPPORT SID MDPPORT

The `msp connect` command listens on TCP port `TCPPORT` of the localhost
(loopback interface) for a TCP connection from a local process.  Whenever a
connection is received, it:

 * makes an MSP connection to the given [SID][] and [MDP port][] number, then:
 * reads bytes from the local TCP stream and sends them as MSP messages, and
 * writes all inbound MSP messages to the local TCP stream in byte order
 * until either the TCP stream is broken or the MSP connection is closed,
   whereupon it:
 * closes the TCP stream and the MSP connection.

If the `--once` option is given then the server process only accepts a single
TCP connection and exits as soon as the connection is closed.

If the `--forward` option is omitted, then instead of listening on a TCP port,
makes the MSP connection immediately and forwards the MSP data to and from
standard output and input.

-----
**Copyright 2014 Serval Project Inc.**  
![CC-BY-4.0](./cc-by-4.0.png)
Available under the [Creative Commons Attribution 4.0 International licence][CC BY 4.0].


[Serval Project]: http://www.servalproject.org/
[CC BY 4.0]: http://creativecommons.org/licenses/by/4.0/
[grant]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:activity:naf6
[NAF]: http://www.newamerica.net/
[OTI]: http://oti.newamerica.net/
[Serval mesh network]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:mesh_network
[Serval DNA]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:servaldna:
[Serval service discovery]: ./Service-Discovery.md
[MDP]: ./Mesh-Datagram-Protocol.md
[MSP]: ./Mesh-Stream-Protocol.md
[UDP]: http://en.wikipedia.org/wiki/User_Datagram_Protocol
[TCP]: http://en.wikipedia.org/wiki/Transmission_Control_Protocol
[IP]: http://en.wikipedia.org/wiki/Internet_Protocol
[SID]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:sid
[MDP port]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:mdp_port_number
[linear network coding]: http://en.wikipedia.org/wiki/Linear_network_coding
[tunnelling]: http://en.wikipedia.org/wiki/Tunneling_protocol
