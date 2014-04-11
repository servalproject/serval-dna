Mesh Streaming Protocol (MSP)
=============================
[Serval Project], April 2014

The [Mesh Streaming Protocol][MSP] is a network protocol used in the [Serval
mesh network][].  It provides a two-way, reliable, ordered stream of bytes
between a pair of end points, which can be used to transfer files, conduct
an HTTP session, or carry quasi-real-time streaming data.

MSP uses the unreliable [MDP][] protocol to send datagram packets between the
two end points.  MSP uses sequence numbering, acknowledgement messages and a
sliding window to achieve eventual reliable delivery of all packets.  MSP also
uses [network coding][] to transmit redundant copies of packets in advance
without the inefficiencies of simple packet repetition.

MSP was funded by a [grant][] from the [New America Foundation][NAF]'s [Open
Technology Institute][OTI].

Protocol description
--------------------

TBC

Client API
----------

TBC


[Serval Project]: http://www.servalproject.org/
[grant]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:activity:naf6
[NAF]: http://www.newamerica.net/
[OTI]: http://oti.newamerica.net/
[MSP]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:msp
[Serval mesh network]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:mesh_network
[MDP]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:mdp
[network coding]:
