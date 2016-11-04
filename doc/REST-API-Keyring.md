Keyring REST API
================
[Serval Project][], November 2016

Introduction
------------

The [Serval Mesh network][] is based on [cryptographic identities][] that can
easily be created by any node at any time.  Each [Serval DNA][] daemon that
runs on a node in the network stores its own identities in the [Keyring][], an
encrypted store protected by passwords, and gives applications access to the
Keyring via the **Keyring REST API** described in this document.  Using this
API, client applications can add, remove, unlock, lock, query, and modify
identities in the keyring.

Basic concepts
--------------

### Serval ID

Every identity in the [Serval mesh network][] is represented by its **Serval
ID**, (usually abbreviated to [SID][], and formerly known as “Subscriber ID”),
which is a unique 256-bit public key in the [Curve25519][] *crypto-box* key
space that is generated from the random *Serval ID secret* when the identity is
created.  The SID is used:

*  as the network address in the [Serval Mesh network][]
*  to encrypt [MDP][] messages
*  to identify the senders, recipients and authors of [Rhizome bundles][]
*  to identify the parties in a [MeshMS conversation][]

### Serval Signing ID

Every identity in the [Serval mesh network][] has a **Serval Signing ID**,
which is a unique 256-bit public key in the [Curve25519][] *crypto-sign* key
space that is generated at the same time as the [Serval ID](#serval-id) when
the identity is created.  The Signing ID is used:

*  to prevent forgery of [Serval Mesh network][] routing messages
*  to authenticate non-encrypted [MDP][] messages

### DID

The **DID** ([Dialled Identity][]) is a telephone number, represented as a
string of five or more digits from the set `123456789#0*`.  It is used by the
[DNA][] protocol to allow [Serval mesh network][] users to discover each other
by telephone number; the first step in establishing a mesh voice call.

### Name

The **Name** is a short, non-blank, non-empty, unstructured string assigned by
a human user to an identity.  It is used to represent the identity to human
users, as it is more recognisable than a hexadecimal [SID](#serval-id) or a
[DID](#did) (telephone number).

The name is encoded using [UTF-8][].  Since it is intended for human
consumption, it may be constrained to contain only printable characters and no
carriage-motion characters (eg, TAB U+0009 or LF U+0010), and to not start or
end with white space.

### Rhizome Secret

The *Rhizome Secret* is a secret key, separate from the [SID](#serval-id)
secret, that is generated randomly for each new identity, and stored in the
keyring as part of the identity.  The Rhizome Secret is used to securely encode
the [Bundle Secret][] of a bundle into its [manifest][], in the form of the
[Bundle Key][], thus relieving [Rhizome][] applications of the burden of having
to store and protect Bundle Secrets themselves.

### PIN

When an identity is created, it can optionally be given a PIN (passphrase).  If
the PIN is *empty* then the identity is permanently unlocked (visible).

Identities with a non-empty PIN are stored encrypted in the keyring file.
Inspection of the keyring file will not reveal their presence unless the
correct PIN is supplied, because all unused entries in the keyring file are
filled with pseudo-random content that is indistinguishable from encrypted
identities.

If a PIN is lost and forgotten, then the identity (identities) it unlocks will
remain locked and unusable forever.  There is no “master PIN” or back-door.

### Identity unlocking

All Keyring requests can supply a passphrase using the optional **pin**
parameter, which unlocks all keyring identities protected by that password,
prior to performing the request.  Serval DNA caches every PIN it receives until
the PIN is revoked using the [lock request](#get-restful-keyring-lock), so once
an identity is unlocked, it remains visible until explicitly locked.

Keyring REST API common features
--------------------------------

### Keyring JSON result

All Keyring requests relating to a single identity that do not produce a
special response content for the outcome, return the following augmented [JSON
result][] object as the HTTP response content:

    {
        "http_status_code": ...,
        "http_status_message": "...",
        "identity": {
            "sid": "<hex64>",
            "identity": "<hex64>",
            "did": "...",
            "name": "..."
        }
    }

*  the `sid` field is the [SID](#serval-id); a string containing 64 uppercase
   hexadecimal digits
*  the `identity` field is the [Signing Id](#serval-signing-id); a string
   containing 64 uppercase hexadecimal digits
*  the `did` field is the string [DID](#did); omitted if the identity has no DID
*  the `name` field is the string [Name](#name); omitted if the identity has no
   name

Keyring REST API operations
---------------------------

### GET /restful/keyring/identities.json

Returns a list of all currently unlocked identities, in [JSON table][] format.
The table columns are:

*   **sid**: the [SID](#serval-id) of the identity, a string of 64 uppercase
    hex digits
*   **identity**: the [Signing ID](#serval-signing-id) of the identity, a
    string of 64 uppercase hex digits
*   **did**: the optional [DID](#did) (telephone number) of the identity;
    `null` if none is assigned
*   **name**: the optional string [Name](#name) of the identity; `null` if none
    is assigned

### GET /restful/keyring/add

Creates a new identity with a random [SID](#serval-id).  If the **pin**
parameter is supplied, then the new identity will be protected by that
password, and the password will be cached by Serval DNA so that the new
identity is unlocked.

Returns [201 Created][201] if an identity is created; the [JSON
result](#keyring-json-result) describes the identity that was created.

### GET /restful/keyring/SID/remove

Removes an existing identity with a given [SID](#serval-id).

If there is no unlocked identity with the given SID, this request returns [404
Not Found][404].  Otherwise it returns [200 OK][200] and the [JSON
result](#keyring-json-result) describes the identity that was removed.

### GET /restful/keyring/SID/set

Sets the [DID](#did) and/or name of the unlocked identity that has the given
[SID](#serval-id).  The following parameters are recognised:

*   **did**: sets the DID (phone number); must be a string of five or more
    digits from the set `123456789#0*`
*   **name**: sets the name; must be non-empty

If there is no unlocked identity with the given SID, this request returns [404
Not Found][404].

### GET /restful/keyring/SID/lock

Locks an existing identity with a given [SID](#serval-id).

If there is no unlocked identity with the given SID, this request returns [404
Not Found][404].  Otherwise it returns [200 OK][200] and the [JSON
result](#keyring-json-result) describes the identity that was locked.


-----
**Copyright 2015 Serval Project Inc.**  
**Copyright 2016 Flinders University**  
![CC-BY-4.0](./cc-by-4.0.png)
Available under the [Creative Commons Attribution 4.0 International licence][CC BY 4.0].


[Serval Project]: http://www.servalproject.org/
[CC BY 4.0]: ../LICENSE-DOCUMENTATION.md
[Serval Mesh network]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:mesh_network
[Serval DNA]: ../README.md
[REST-API]: ./REST-API.md
[Keyring]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:keyring
[cryptographic identities]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:security_framework
[Curve25519]: https://en.wikipedia.org/wiki/Curve25519
[SID]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:sid
[Dialled Identity]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:did
[DNA]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:dna
[MDP]: ./Mesh-Datagram-Protocol.md
[Rhizome]: ./REST-API-Rhizome.md
[Rhizome bundles]: ./REST-API-Rhizome.md#bundle
[manifest]: ./REST-API-Rhizome.md#manifest
[Bundle Secret]: ./REST-API-Rhizome.md#bundle-secret
[Bundle Key]: ./REST-API-Rhizome.md#bundle-key
[MeshMS conversation]: ./REST-API-MeshMS.md#conversation
[JSON result]: ./REST-API.md#json-result
[JSON table]: ./REST-API.md#json-table
[UTF-8]: https://en.wikipedia.org/wiki/UTF-8
[200]: ./REST-API.md#200-ok
[201]: ./REST-API.md#201-created
[202]: ./REST-API.md#202-accepted
[400]: ./REST-API.md#400-bad-request
[404]: ./REST-API.md#404-not-found
[419]: ./REST-API.md#419-authentication-timeout
[422]: ./REST-API.md#422-unprocessable-entity
[423]: ./REST-API.md#423-locked
[500]: ./REST-API.md#500-server-error
