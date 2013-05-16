Serval DNA
==========

This repository contains the source code for the “core” Serval components
implemented in [GNU C][]:

 * The **[Distributed Numbering Architecture (DNA)][]** is the key
   innovation that makes mesh telephony viable in the absence of any
   infrastructure, eg, in the aftermath of a natural disaster or in remote
   locations.  It is a protocol carried over MDP (see below) that allows any
   device to ask its neighboring devices for a phone number (DID).  Such a
   request will propagate through the mesh, and any device may respond with the
   identity (SID) of a subscriber who has “claimed” that DID.

 * The **[Serval Keyring][]** is a flat file containing all the user identities on
   a single device.  Each identity is a set of elliptic curve secret
   cryptographic keys that belong to a single “mesh subscriber”, indexed by the
   subscriber's 256-bit public key, called a SID.  Each identity in the keyring is
   locked by its own user-chosen password (called a PIN in the code and
   documentation), using elliptic curve cryptography to protect locked entries
   from theft or tampering, and steganography to allow the user to plausibly
   deny the existence of any locked identity.

 * The **[Mesh Datagram Protocol (MDP)][]** is Serval's own layer 3 protocol
   designed for secure mesh networking.  It is completely independent of
   Internet protocols such as IP and UDP, but for the time being is implemented
   as an “overlay” network based on UDP/IP because that is the interface that
   Linux and other operating systems provide for sending data over WiFi.
   However, MDP could easily be implemented directly over a layer 2 data link
   such as WiFi or Ethernet MAC.  MDP uses subscribers' public keys (SID) as
   source and destination addresses, and has a 32-bit port number analogous to
   the 16-bit port number used in TCP/IP.

 * The **[Voice over Mesh Protocol (VoMP)][]** is Serval's own call negotiation
   and two-way audio streaming protocol used to implement mesh voice calls.  It
   is analogous to SIP/RTS, which is the dominant protocol used to implement
   Voice over Internet Protocol, but VoMP is designed for the variable and
   unstable conditions of wireless mesh networks.  VoMP's session state model
   and signalling can handle packet loss, mid-call re-routing and re-connection
   where SIP would fail.  VoMP's audio streaming can encapsulate many codecs
   and even DTMF (dialpad button) signalling.

 * The **[Rhizome][]** content distribution service is a storage engine implemented
   using SQLite and a content-exchange protocol based on MDP and HTTP for the
   pervasive dissemination of content like images, videos, documents, software
   upgrades, etc.  Each piece of content in Rhizome is called a “bundle”, which
   has two parts: a *manifest* that describes the content, and the *payload*,
   which is the content itself.  Each bundle has its own unique cryptographic
   identifier that allows any recipient to verify that it has not been tampered
   with.

 * The **[MeshMS][]** messaging service is implemented using Rhizome as its
   transport, with each thread represented as a pair of bundles, one for each
   direction.  At present, the MeshMS logic is implemented in Java within the
   [Serval Mesh][batphone] Android app, but is planned to be re-implemented in
   C as part of Serval DNA (see [issue #28][]).

 * **[Serval Infrastructure][]** services may optionally be deployed on any devices
   in the mesh to expose external services to mesh subscribers and vice versa
   (eg, VoIP gateways, SMS satellite links, packetised web), and to overcome
   scalability limitations of a perfectly decentralised mesh (eg, central
   telephone directory).

Most of these services are performed by a [daemon][] process called
**servald**.  Serval Infrastructure is implemented by a separate daemon called
**directory_service**.

Copyright and licensing
-----------------------

Serval DNA is [free software][] produced by the [Serval Project][] and many
[contributors][].  It is licensed to the public under the [GNU General Public
License version 2][GPL2].  All source code is freely available from the Serval
Project's [serval-dna][] Git repository on [GitHub][].

The copyright in most of the source code in Serval DNA is held by [Serval
Project Inc.][SPI], an organisation incorporated in the state of South
Australia in the Commonwealth of Australia for the purpose of developing the
Serval mesh software.

The [Serval Project][] will accept contributions from individual developers who
have agreed to the [Serval Project Developer Agreement - Individual][individ],
and from organisations that have agreed to the [Serval Project Developer
Agreement - Entity][entity].

servald
-------

The **servald** executable is a multi-purpose program designed to be invoked
directly from the command line and also via [JNI][] from within a Java program.
The following command will print a summary of all the operations that servald
offers:

    servald help

Some operations are self-contained, some start and stop the servald daemon
process, some communicate with the servald daemon as an MDP client, and others
via a two-way [pipe][] called the monitor interface.

For more detail on the purpose and usage of the servald command-line, see the
[doc](/servalproject/serval-dna/tree/master/doc/) directory.

Build and test
--------------

Instructions for building and testing Serval DNA are in
[INSTALL.md](./INSTALL.md).  (If that link is does not work, try
[INSTALL.md](/servalproject/serval-dna/blob/master/INSTALL.md).)


[Serval Project]: http://www.servalproject.org/
[SPI]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:spi
[serval-dna]: https://github.com/servalproject/serval-dna
[batphone]: https://github.com/servalproject/batphone
[issue #28]: https://github.com/servalproject/serval-dna/issues/28
[GNU C]: http://gcc.gnu.org/
[daemon]: http://en.wikipedia.org/wiki/Daemon_(computing)
[free software]: http://www.gnu.org/philosophy/free-sw.html
[contributors]: /servalproject/serval-dna/blob/master/CONTRIBUTORS.md
[GitHub]: https://github.com/servalproject
[GPL2]: http://www.gnu.org/licenses/gpl-2.0.html
[individ]: http://developer.servalproject.org/files/serval_project_inc-individual.pdf
[entity]: http://developer.servalproject.org/files/serval_project_inc-entity.pdf
[Distributed Numbering Architecture (DNA)]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:dna
[Serval Keyring]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:keyring
[Mesh Datagram Protocol (MDP)]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:mdp
[VoMP]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:vomp
[Rhizome]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:rhizome
[MeshMS]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:meshms
[Serval Infrastructure]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:serval_infrastructure
[JNI]: http://en.wikipedia.org/wiki/Java_Native_Interface
[pipe]: http://www.kernel.org/doc/man-pages/online/pages/man2/pipe.2.html
