Mesh Datagram Protocol (MDP)
============================
[Serval Project], May 2014

The [Mesh Datagram Protocol][MDP] is a network protocol developed for the
[Serval mesh network][], with characteristics that make it particularly
suitable for use in Ad Hoc wireless networks, which can suffer high levels of
packet loss due to weak signal, interference and congestion.

MDP carries [datagram][] packets sent from an originating node to a single
destination node or broadcast to all nodes, guaranteeing only that packet
contents will be verbatim if delivered.  MDP is similar to [UDP][] in terms of
the service it provides to applications, but unlike UDP it uses a per-hop
[retransmission][] protocol and adaptive link-state routing to boost packet
delivery rates, which largely immunises it from the cumulative packet loss
effect typical of wireless networks.  This means that its end-to-end packet
delivery rate remains usefully high despite adverse network conditions.

**Copyright 2014 Serval Project Inc.**  All rights reserved.  Licensing terms
to be announced.

Overlay Mesh
------------

MDP packets are transmitted over a network link using the [Overlay Mesh][]
packet format, which aggregates packets into *overlay frames* which are
designed to minimise packet size.  Each overlay frame uses back references to
avoid repeating [SID][] addresses unnecessarily within the frame, and [SID
abbreviation][] to significantly shorten [SID][] addresses that have been used
in prior frames.

MDP Interface
-------------

The [Serval DNA][] daemon provides an interface that allows client applications
to send and receive individual MDP packets on the [Serval mesh network][]
without having to construct and disassemble Overlay Mesh frames on their own.

MDP API
-------

The MDP API is a [C language][] [API][] that an application can use to send and
receive MDP packets over the [Serval mesh network][] using the
[interface](#mdp-interface) provided by the [Serval DNA][] daemon.


[Serval Project]: http://www.servalproject.org/
[Serval mesh network]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:mesh_network
[Serval DNA]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:servaldna:
[MDP]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:mdp
[datagram]: http://en.wikipedia.org/wiki/Datagram
[UDP]: http://en.wikipedia.org/wiki/User_Datagram_Protocol
[Overlay Mesh]: ./Overlay-Mesh.md
[SID]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:sid
[SID abbreviation]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:sid_abbreviation
[C language]: http://en.wikipedia.org/wiki/C_(programming_language)
[API]:http://en.wikipedia.org/wiki/Application_programming_interface
