Serval Infrastructure
=====================

Based on design discussions between Andrew Bettison and Jeremy Lakeman in
September, 2012.

In practice, these three services are built into a single daemon that can be
deployed into a mesh at many points.

Serval Directory Service (SDS)
------------------------------

SDS is a registry that associates subscriber names and phone numbers (DID) with
subscriber identities (SID).  Any subscriber may potentially register its
details with an SDS, and an SDS may also have its own source of registry
entries, such as an associated Asterisk exchange.  SDS allows the decentralised
DNA Lookup architecture to be supplemented with infrastructure, ie, mesh nodes
offering persistent services or bridges out of the mesh.

* Maps DID or Name → SID
* Responds to DNA Lookup requests
* Keeps registry of DNA entries (SID-DID-name)
* Accepts registrations and renewals of DNA entries
* Collects and caches DNA responses from local networks

Serval Internet Location Service (SILS)
---------------------------------------

* Maps SID → IP address + port number (`sockaddr_in`)
* Keeps a SIR (Subscriber Internet Registry)
* Accepts registrations (signed)
* Responds to location requests

Serval Internet Routing Service (SIRS)
--------------------------------------

* Forwards MDP packets to MDP nodes listening on IP addresses/ports
* Uses SILS to resolve destination IP addresses/ports
