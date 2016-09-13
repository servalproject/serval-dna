Serval DNA
==========
[Serval Project][], September 2016

[Serval DNA][] is the core component of the [Serval Mesh][] app for Android and
the [Serval Mesh Extender][] long-range mesh networking device.  It is a daemon
process that performs all the central services of the Serval mesh network
such as dynamic routing, encryption and authentication, file distribution,
messaging, and voice telephony.

Any device with Wi-Fi connectivity that runs the Serval DNA daemon can
participate in the [Serval mesh network][].

Download, build and test
------------------------

 * [INSTALL.md](./INSTALL.md) contains instructions for downloading, building
   and testing Serval DNA on Linux, Mac OS-X, and similar platforms

 * [Notes for Developers](./doc/Development.md) contains useful information for
   developers of Serval DNA, which may also help resolve build issues

Configuration
-------------

 * [doc/Servald-Configuration.md](./doc/Servald-Configuration.md) describes how
   to set up and run a Serval DNA daemon

Documentation
-------------

 * [INSTALL.md](./INSTALL.md) -- instructions to compile and install Serval DNA

 * [doc/](./doc/) -- technical documentation

 * once Serval DNA is built, its "help" command will print a summary of all the
   operations that servald offers:

        $ ./servald help

 * the following pages in the [Serval Project Wiki][]:
   * [Serval DNA overview][Serval DNA]
   * [Serval DNA development][]

 * [CONTRIBUTORS.md](./CONTRIBUTORS.md) -- individuals who have contributed to
   the software

Bugs and issues
---------------

Bugs can be reported and inspected using the [GitHub issue tracker][Serval DNA issues].

What is in this repository?
---------------------------

This repository contains the [GNU C][] source code for the **servald**
executable, a [test framework](./testframework.sh) and [test scripts](./tests/)
written in [Bash][], some [technical documentation](./doc/), and various
support files for installation and configuration on various platforms.

The **servald** executable is a multi-purpose program that can be invoked
directly from the command line, run as a daemon process, or invoked via [JNI][]
from within a Java program.  The **servald** executable is really many commands
built into one; the command-line arguments select which *command* to run.  Some
commands are stand-alone utilities, some start and stop the servald daemon
process, some communicate with the servald daemon as an MDP client, and others
via a two-way [pipe][] called the *monitor interface*.

The following protocols and services are implemented in **servald**:

 * The **[Distributed Numbering Architecture (DNA)][DNA]** is the key
   innovation that makes mesh telephony viable in the absence of any
   infrastructure, eg, in the aftermath of a natural disaster or in remote
   locations.  DNA is a protocol carried over MDP (see below) that asks many
   devices at once if they will answer a phone number (DID).  A device will
   respond with its own subscriber identity (SID) if its user has “claimed”
   that DID.   This allows phone calls to be established over the mesh using
   conventional phone numbers.

 * The **[Serval Keyring][]** is a flat file containing all the user identities
   on a single device.  Each identity is a set of elliptic curve secret
   cryptographic keys that belong to a single “mesh subscriber”, indexed by the
   subscriber's 256-bit public key, called a SID.  Each identity in the keyring
   is locked by its own user-chosen password (called a PIN in the code and
   documentation), using elliptic curve cryptography to protect locked entries
   from theft or tampering, and steganography to allow the user to plausibly
   deny the existence of locked identities.

 * The **[Mesh Datagram Protocol (MDP)][MDP]** is Serval's own layer 3 protocol
   designed for secure mesh networking.  It is completely independent of
   Internet protocols such as IP and UDP, although for the time being it is
   implemented as an “overlay” network based on UDP/IP because that is the
   interface that Linux and other operating systems provide for sending data
   over Wi-Fi.  However, MDP could easily be implemented directly over a layer
   2 data link such as Wi-Fi or Ethernet MAC.  MDP uses subscribers' public
   keys (SID) as source and destination addresses, has a 32-bit port number
   analogous to the 16-bit port number used in TCP/IP, and encrypts all packet
   contents by default, using the public key (SID) of the destination.

 * The **[Voice over Mesh Protocol (VoMP)][VoMP]** is Serval's own call
   negotiation and two-way audio streaming protocol used to implement mesh
   voice calls.  It fills the same role as SIP/RTS, the dominant protocol used
   for Voice over Internet Protocol, but VoMP is designed for the variable and
   unstable conditions of wireless mesh networks.  VoMP's session state model
   and signalling can handle packet loss, mid-call re-routing and re-connection
   where SIP would fail.  VoMP's audio streaming can encapsulate many codecs
   and even DTMF (dialpad button) signalling.

 * **[Rhizome][]** is a content storage and distribution service implemented
   using SQLite and a content-exchange protocol based on MDP.  It can be used
   to disseminate content like images, videos, documents, software upgrades,
   etc.  Each piece of content in Rhizome is called a “bundle”, which has two
   parts: a *manifest* that describes the content, and the *payload*, which is
   the content itself.  Each bundle has its own unique cryptographic identifier
   that allows any recipient to verify that it has not been tampered with.  A
   bundle's payload may be encrypted by the author so that only the designated
   recipient can read it.

 * The **[MeshMS][]** messaging service sends short text messages using Rhizome
   as its transport.  Each message thread is stored and carried in a pair of
   journal bundles, one for each direction (ply).

 * **[Serval Infrastructure][]** services may optionally be deployed on any devices
   in the mesh to expose external services to mesh subscribers and vice versa
   (eg, VoIP gateways, SMS satellite links, packetised web), and to overcome
   scalability limitations of a perfectly decentralised mesh (eg, central
   telephone directory).  Serval Infrastructure is implemented as a daemon with
   its own executable called `directory_service`.

Copyright and licensing
-----------------------

Serval DNA is [free software][] produced by the [Serval Project][] and many
[contributors][].  Its source code is licensed to the public under the [GNU
General Public License version 2][GPL2].  Its technical documentation is
licensed to the public under the [Creative Commons Attribution 4.0
International licence][CC BY 4.0].  All source code and technical documentation
is freely available from the Serval Project's [serval-dna][] Git repository on
[GitHub][].

The copyright in most of the source code in Serval DNA is held by [Serval
Project Inc.][SPI], a not-for-profit association incorporated in the state of
South Australia in the Commonwealth of Australia for the purpose of developing
the Serval mesh software.  The [COPYRIGHT][] file contains a full list of all
those who hold copyright in portions of the Serval DNA source code.

The [Serval Project][] will accept contributions for which copyright has been
assigned to [Serval Project Inc.][SPI], or which are licensed to either [Serval
Project Inc.][SPI] or to the public on terms that allow the Serval Project to
freely redistribute and re-license the code under non-restrictive terms, for
example, to release Serval DNA as part of a product distributed through the
[Apple app store][].

Individual developers may assign copyright in their contributions by signing
the [Serval Project Developer Agreement - Individual][individ], and
organisations by signing the [Serval Project Developer Agreement -
Entity][entity].

-----
**Copyright 2016 Serval Project Inc.**  
![CC-BY-4.0](./cc-by-4.0.png)
This document is available under the [Creative Commons Attribution 4.0 International licence][CC BY 4.0].


[Serval Project]: http://www.servalproject.org/
[Serval Project Wiki]: http://developer.servalproject.org/
[Serval DNA]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:servaldna:
[Serval DNA development]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:servaldna:development
[Serval Mesh]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:servalmesh:
[Serval Mesh Extender]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:meshextender:
[Serval mesh network]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:mesh_network
[SPI]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:spi
[serval-dna]: https://github.com/servalproject/serval-dna
[batphone]: https://github.com/servalproject/batphone
[Serval DNA issues]: https://github.com/servalproject/serval-dna/issues
[issue #28]: https://github.com/servalproject/serval-dna/issues/28
[GNU C]: http://gcc.gnu.org/
[daemon]: http://en.wikipedia.org/wiki/Daemon_(computing)
[free software]: http://www.gnu.org/philosophy/free-sw.html
[contributors]: /servalproject/serval-dna/blob/development/CONTRIBUTORS.md
[GitHub]: https://github.com/servalproject
[COPYRIGHT]: ./COPYRIGHT.txt
[GPL2]: ./GPL-2.0.txt
[Apple app store]: http://www.fsf.org/blogs/licensing/more-about-the-app-store-gpl-enforcement
[individ]: http://developer.servalproject.org/files/serval_project_inc-individual.pdf
[entity]: http://developer.servalproject.org/files/serval_project_inc-entity.pdf
[DNA]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:dna
[Serval Keyring]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:keyring
[MDP]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:mdp
[VoMP]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:vomp
[Rhizome]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:rhizome
[MeshMS]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:meshms
[Serval Infrastructure]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:serval_infrastructure
[JNI]: http://en.wikipedia.org/wiki/Java_Native_Interface
[Bash]: http://en.wikipedia.org/wiki/Bash_(Unix_shell)
[pipe]: http://www.kernel.org/doc/man-pages/online/pages/man2/pipe.2.html
[CC BY 4.0]: ./LICENSE-DOCUMENTATION.md
