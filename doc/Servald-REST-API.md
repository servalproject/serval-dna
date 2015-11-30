Serval DNA REST API
===================
[Serval Project][], September 2015

Introduction
------------

The [Serval DNA][] daemon that runs on every node in a Serval Mesh network
gives applications access to the network through two main [API][]s:

*  the [MDP API][MDP] and [MSP API][MSP] provide "traditional" packet and
   stream transport, allowing applications to send and receive Serval network
   packets to and from nearby nodes with latencies of up to several seconds;

*  the [HTTP REST][] API provides applications with access to the following
   Serval services:
   -  [Keyring][] -- local identity management
   -  [Rhizome][] -- store-and-forward (high latency) content distribution
   -  [MeshMS][] -- secure one-to-one messaging using Rhizome as transport

This document describes the second of these, the [HTTP REST][] API.

### Protocol and port

The Serval DNA [HTTP REST][] API is an [HTTP 1.0][] server that only accepts
requests on the loopback interface (IPv4 address 127.0.0.1), TCP port 4110.  It
rejects requests that do not originate on the local host, by replying
[403](#forbidden).

### Security

The REST API uses plain HTTP *without* encryption.  REST requests and responses
are not carried over any physical network link, only local (“logical”) links
between processes, so there is no risk of remote eavesdropping.  The only
potential threat comes from hostile local processes.

Operating system kernels such as Linux (Android, Ubuntu) and Darwin (Apple)
prevent normal processes from accessing the traffic on local sockets between
other processes.  To attack Serval DNA and its clients, a local process on the
local host would have to gain super-user privilege (eg, through a privilege
escalation vulnerability).  A super-user process would have many ways to attack
Serval DNA and its clients, much more effective than intercepting their
communications, so encrypting client-server communications would offer no
protection whatsoever.

### Authentication

Clients of the HTTP REST API must authenticate themselves using [Basic
Authentication][].  This narrows the window for opportunistic attacks on the
server's HTTP port by malicious applications that scan for open local ports to
exploit.  Any process wishing to use the REST API must supply valid
authentication credentials (name/password), or will receive a [401
Unauthorized](#401-unauthorized) response.

Client applications obtain their REST API credentials via a back channel
specific to their particular platform.  This delegates the exercise of handing
out credentials to the application layer, where users can (usually) exercise
their own discretion.  For example, on Android, a client app sends an
[Intent][] to the [Serval Mesh][] app requesting a Serval REST credential, and
will receive a reply only if it possesses the right Android [Permission][].
When users install or run the client app, Android informs them that the app
requests the "Serval Network" permission, and users may allow or deny it.

As a fall-back mechanism, created primarily to facilitate testing, HTTP REST
API credentials can be [configured][] using configuration options of the form:

    api.restful.users.USERNAME.password=PASSWORD

PASSWORD is a cleartext secret, so the Serval DNA configuration file must be
protected from unauthorised access or modification by other apps.  That makes
this mechanism unsuitable for general use.

### Request

An HTTP REST request is a normal [HTTP 1.0][] [GET](#get) or [POST](#post):

#### GET

A **GET** request consists of an initial "GET" line containing the *path* and
*HTTP version*, followed by zero or more header lines, followed by a blank
line.  As usual for HTTP, all lines are terminated by an ASCII CR-LF sequence.

For example:

    GET /restful/keyring/identities.json?pin=1234 HTTP/1.0
    Authorization: Basic aGFycnk6cG90dGVy
    Accept: */*
    
GET requests only accept parameters as [query parameters][] in the *path*.

[query parameters]: http://tools.ietf.org/html/rfc3986#section-3.4

#### POST

A **POST** request is the same as a GET request except that the first word
of the first line is "POST", the blank line is followed by a request *body*,
and the following request headers are mandatory:
*   [Content-Length](#request-content-length)
*   [Content-Type](#request-content-type)

POST requests accept parameters as [query parameters][] in the *path* and also
as a request body with Content-Type: `multipart/form-data`.  These two kinds of
parameters are not exclusive; a request may contain a mixture of both.

#### Request Content-Length

In a request, the **Content-Length** header gives the exact number of bytes
(octets) in the request's body, which must be correct.  Serval DNA will not
process a request until it receives Content-Length bytes, so if Content-Length
is too large, the request will suspend and eventually time out.  Serval DNA
will ignore any bytes received after it has read Content-Length bytes, so if
Content-Length is too small, the request body will be malformed.

#### Request Content-Type

In a request, the **Content-Type** header gives the [Internet Media Type][] of
the body.  Serval DNA currently supports the following media types in requests:

*   **[multipart/form-data][]** is used to send parameters in [POST](#post)
    requests.  The **boundary** parameter must specify a string that does not
    occur anywhere within the content of any form part.

*   **text/plain; charset=utf-8** is used for [MeshMS][] message form parts.
    The only supported charset is utf-8; a missing or different charset will
    cause a [415](#unsupported-media-type) response.

*   **rhizome/manifest; format=text+binarysig** is used for [Rhizome][]
    manifests in [text+binarysig format](#textbinarysig-manifest-format).

A missing Content-Type header in a `POST` request will cause a
[400](#bad-request) response.  An unsupported content type will cause a
[415](#unsupported-media-type) response.

[multipart/form-data]: https://www.ietf.org/rfc/rfc2388.txt

#### Request Range

[HTTP 1.1 Range][] retrieval is partially supported.  In a request, the
**Range** header gives the start and end, in byte offsets, of the resource to
be returned.  The server may respond with exactly the range requested, in which
case the response status code will be [206](#partial-content), or it may ignore
the Range header and respond with the entire requested resource.

For example, the following header asks that the server omit the first 64 bytes
and send only the next 64 bytes (note that ranges are inclusive of their end
byte number):

    Range: bytes=64-127

The [specification][HTTP 1.1 Range] allows for more than one start-end range to
be supplied, separated by commas, however not all REST API operations support
multi ranges.  If a multi-range header is used in such a request, then the
response may be the entire content or [501 Not Implemented](#not-implemented).

[HTTP 1.1 Range]: http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.35

### Responses

An HTTP REST response is a normal [HTTP 1.0][] response consisting of a header
block, a blank line, and an optional body, for example: As usual, all lines are
terminated by an ASCII CR-LF sequence.  For example:

    HTTP/1.0 200 OK
    Content-Type: application/json
    Content-Length: 78

    {
     "http_status_code": 200,
     "http_status_message": "OK"
    }

The lingua franca of the HTTP REST API is [JSON][] in [UTF-8][] encoding.  All
Serval DNA HTTP REST responses have a Content-Type of **application/json**
unless otherwise documented.

Some responses contain non-standard HTTP headers as part of the result they
return to the client; for example, [Rhizome response headers](#rhizome-response-headers).

### Response status code

The HTTP REST API response uses the [HTTP status code][] to indicate the
outcome of the request as follows:

[HTTP status code]: http://www.w3.org/Protocols/HTTP/1.0/spec.html#Status-Codes

#### 200 OK

The operation was successful and no new entity was created.  Most requests
return this code to indicate success.  Requests that create a new entity only
return this code if the entity already existed, meaning that the creation was
not performed but the request can be considered a success since the desired
outcome was achieved: namely, the existence of the entity.  (If the entity was
created, then these requests return [201 Created](#created) instead.)

(Serval APIs are all [idempotent][] with respect to creation: creating the same
entity twice yields the same state as creating it once.  This is an important
property for a purely distributed network that has no central arbiter to
enforce sequencing of operations.)

#### 201 Created

The operation was successful and the entity was created.  This code is only
returned by requests that create new entities, in the case that the entity did
not exist beforehand and has been created successfully.

#### 202 Accepted

The operation was successful but the entity was not created.  This code is only
returned by requests that create new entities, in the case that the request was
valid but the entity was not created because other existing entities take
precedence.  For example, the [Rhizome REST API](#rhizome-rest-api) returns
this code when inserting a bundle to a full Rhizome store if the new bundle's
rank falls below all other bundles, so the new bundle itself would be evicted
to make room.

#### 206 Partial Content

The operation was successful and the response contains part of the requested
content.  This code is only returned by requests that fetch an entity (the
fetched entity forms the body of the response) if the request supplied a
[Range](#request-range) header that specified less than the entire entity.

#### 400 Bad Request

The HTTP request was malformed, and should not be repeated without
modifications.  This could be for several reasons:
- invalid syntax in the request header block
- a `POST` request MIME part is missing, duplicated or out of order
- a `POST` request was given an unsupported MIME part
- a `POST` request MIME part has missing or malformed content

#### 401 Unauthorized

The request did not supply an "Authorization" header with a recognised
credential.  This response contains a "WWW-Authenticate" header that describes
the missing credential:

    HTTP/1.0 401 Unauthorized
    Content-Type: application/json
    Content-Length: 88
    WWW-Authenticate: Basic "Serval RESTful API"

    {
     "http_status_code": 401
     "http_status_message": "Unauthorized"
    }

#### 403 Forbidden

The request failed because the server does not accept requests from the
originating host.

#### 404 Not Found

The request failed because the [HTTP request URI][] does not exist.  This could
be for several reasons:
- the request specified an incorrect path (typographic mistake)
- the path is unavailable because the API in question is unavailable (eg, the
  [Rhizome REST API](#rhizome-rest-api)) is currently [configured][] as
  disabled
- the path contains a reference to an entity (eg, [SID](#serval-id), [Bundle
  ID](#bundle-id)) that does not exist

[HTTP request URI]: http://www.w3.org/Protocols/HTTP/1.0/spec.html#Request-URI

#### 405 Method Not Allowed

The request failed because the [HTTP request method][] is not supported for the
given path.  Usually this means that a [GET](#get) request was attempted on a
path that only supports [POST](#post), or vice versa.

[HTTP request method]: http://www.w3.org/Protocols/HTTP/1.0/spec.html#Method

#### 411 Length Required

A `POST` request did not supply a [Content-Length](#request-content-length)
header.

#### 414 Request-URI Too Long

The request failed because the [HTTP request URI][] was too long.  The server
persists the path and a few other pieces of the request in a fixed size request
buffer, and this response is triggered if the collective size of these does not
leave enough buffer for receiving the remainder of the request.

#### 415 Unsupported Media Type

A `POST` request failed because of an unsupported content type, which could be
for several reasons:
- the request's [Content-Type](#request-content-type) header specified an
  unsupported media type
- a MIME part Content-Disposition was not “form-data”
- a MIME part Content-Type was unsupported
- a MIME part Content-Type specified an unsupported charset

#### 416 Requested Range Not Satisfiable

The [Range](#request-range) header specified a range whose start position falls
outside the size of the requested entity.

#### 419 Authentication Timeout

The request failed because the server does not possess and cannot derive the
necessary cryptographic secret or credential.  For example, updating a Rhizome
bundle without providing the bundle secret.  This code is not part of the HTTP
standard.

#### 422 Unprocessable Entity

A `POST` request supplied data that was inconsistent or violates semantic
constraints, so cannot be processed.  For example, the [Rhizome
insert](#post-restful-rhizome-insert) operation responds with 422 if the
manifest *filesize* and *filehash* fields do not match the supplied payload.

#### 423 Locked

The request cannot be performed because a necessary resource is busy for
reasons outside the control of the requester and server.

This code is returned by Rhizome requests if the Rhizome store database is
currently locked by another process.  The architecture of [Serval DNA][] is
being improved to prevent any process other than the Serval DNA daemon itself
from directly accessing the Rhizome database.  Once these improvements are
done, this code should no longer occur except during unusual testing and
development situations.

#### 429 Too Many Requests

The request cannot be performed because a necessary resource is temporarily
unavailable due to a high volume of concurrent requests.

The original use of this code was for Rhizome operations if the server's
manifest table ran out of free manifests, which would only happen if there were
many concurrent Rhizome requests holding manifest structures open in server
memory.

This code may also be used to indicate temporary exhaustion of other finite
resources.  For example, if [Serval DNA][] is ever limited to service only a
few HTTP requests at a time, then this code will be returned to new requests
that would exceed the limit.

#### 431 Request Header Fields Too Large

The request header block was too long.

Initial implementations of [Serval DNA][] allocated approximately 8 KiB of
buffer memory for each [request](#request), and the HTTP server read each
header line entirely into that buffer before parsing it.  If a single header
exceeded the size of this buffer, then the 431 response was returned.

#### 500 Internal Server Error

The request failed because of an internal error in [Serval DNA][], not an error
in the request itself.  This could be for several reasons:
- software defect (bug)
- unavailable system resource (eg, memory, disk space)
- corrupted environment (eg, bad configuration, database inconsistency)

Internal errors of this kind may persist or may resolve if the request is
re-tried, but in general they will persist because the cause is not transient.
Temporary failures that can be resolved by re-trying the request are generally
indicated by other status codes, such as [423](#locked).

#### 501 Not Implemented

The requested operation is valid but not yet implemented.  This is used for the
following cases:

- a request [Range](#request-range) header specifies a multi range

#### Cross-Origin Resource Sharing (CORS)

To support client-side JavaScript applications, Serval DNA has a limited
implementation of [Cross-Origin Resource Sharing][CORS].  If a request contains
an **Origin** header with either “null” or a single URI with scheme “http” or
“https” or “file”, hostname “localhost” or “127.0.0.1” (or empty in the case of
a “file” scheme), and optionally any port number, then the response will
contain three **Access-Control** headers granting permission for other pages on
the same site to access resources in the returned response.

For example, given the request:

    GET /restful/keyring/identities.json HTTP/1.0
    Origin: http://localhost:8080/
    ...
    
Serval DNA will respond:

    HTTP/1.0 200 OK
    Access-Control-Allow-Origin: http://localhost:8080
    Access-Control-Allow-Methods: GET, POST, OPTIONS
    Access-Control-Allow-Headers: Authorization
    ...

[CORS]: http://www.w3.org/TR/cors/

#### JSON result

All responses that convey no special content return the following *JSON result*
object:

    {
     "http_status_code": ...,
     "http_status_message": "..."
    }

The `http_status_code` field is an integer equal to the [status
code](#response-status-code) that follows the `HTTP/1.0` token in the first
line of the response.

The `http_status_message` field is usually the same as the *reason phrase* text
that follows the code in the first line of the HTTP response.  This reason
phrase may be a [standard phrase][status code], or it may be more explanatory;
for example, some *404* responses from Rhizome have phrases like, “Bundle not
found”, “Payload not found”, etc.

Some responses augment the *JSON result* object with extra fields; for example,
[Rhizome JSON result](#rhizome-json-result).

### JSON table

Many HTTP REST responses that return a list of regular objects (eg, [GET
/restful/rhizome/bundlelist.json](#get-restfulrhizomebundlelistjson)) use the
following *JSON table* format:

    {
        "header":["fieldname1","fieldname2","fieldname3", ... ],
        "rows":[
            [field1, field2, field3, ... ],
            [field1, field2, field3, ... ],
            ...
        ]
    }

The JSON table format is more compact than the most straightforward JSON
representation, an array of JSON objects, which has the overhead of redundantly
repeating all field labels in every single object:

    [
        {
            "fieldname1: field1,
            "fieldname2: field2,
            "fieldname3: field3,
            ...
        },
        {
            "fieldname1: field1,
            "fieldname2: field2,
            "fieldname3: field3,
            ...
        },
        ...
    ]



A JSON table can easily be transformed into its equivalent array of JSON
objects.  The [test scripts](./testdefs_json.sh) use the following [jq(1)][]
expression to perform the transformation:

    [
        .header as $header |
        .rows as $rows |
        $rows | keys | .[] as $index |
        [ $rows[$index] as $d | $d | keys | .[] as $i | {key:$header[$i], value:$d[$i]} ] |
        from_entries |
        .["__index"] = $index
    ]

Keyring REST API
----------------

The Keyring REST API allows client applications to query, unlock, lock, create,
and modify Serval Identities in the keyring.

### Basic concepts

#### Serval ID

The *Serval ID* (a.k.a. [SID][], a.k.a. “Subscriber ID”) is a unique 256-bit
public key in the [Curve25519][] key space, generated from the random *Serval
ID secret* when the identity is created.  The SID is used:

*  as the network address in the Serval Mesh network
*  to identify senders, recipients and authors of [Rhizome
   bundles](#concept-bundle)
*  to identify the parties in a [MeshMS conversation](#conversation)

[SID]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:sid

#### Rhizome Secret

The *Rhizome Secret* is a secret key, separate from the [SID](#serval-id)
secret, that is generated randomly for each new identity, and stored in the
keyring as part of the identity.  The Rhizome Secret is used to securely encode
the [Bundle Secrets](#bundle-secret) of bundles into the bundles themselves, in
the form of the [Bundle Key](#bundle-key).  This relieves Rhizome applications
of the burden of having to store and protect Bundle Secrets themselves.

#### PIN

When an identity is created, it can optionally be given a PIN (passphrase).  If
the PIN is *empty* then the identity is permanently unlocked (visible).

Identities with a non-empty PIN are stored encrypted in the keyring file.
Inspection of the keyring file will not reveal their presence unless the
correct PIN is supplied, because all unused entries in the keyring file are
filled with pseudo-random content that is indistinguishable from encrypted
identities.

If a PIN is lost and forgotten, then the identity (identities) it unlocks will
remain locked and unusable forever.  There is no “master PIN” or back-door.

#### Identity unlocking

All Keyring API requests can supply a passphrase using the optional **pin**
parameter, which unlocks all keyring identities protected by that password,
prior to performing the request.  Serval DNA caches every password it receives
until the password is revoked using the *lock* request, so once an identity is
unlocked, it remains visible until explicitly locked.

### GET /restful/keyring/identities.json

Returns a list of all currently unlocked identities, in [JSON
table](#json-table) format.  The table columns are:

*   **sid**: the [SID](#serval-id) of the identity, a string of 64 uppercase
    hex digits
*   **did**: the optional [DID][] (telephone number) of the identity, either
    *null* or a string of five or more digits from the set `123456789#0*`
*   **name**: the optional name of the identity, either *null* or a non-empty
    string of [UTF-8] characters

### GET /restful/keyring/add

Creates a new identity with a random [SID](#serval-id).  If the **pin**
parameter is supplied, then the new identity will be protected by that
password, and the password will be cached by Serval DNA so that the new
identity is unlocked.

### GET /restful/keyring/SID/set

Sets the [DID][] and/or name of the unlocked identity that has the given
[SID](#serval-id).  The following parameters are recognised:

*   **did**: sets the DID (phone number); must be a string of five or more
    digits from the set `123456789#0*`
*   **name**: sets the name; must be non-empty

If there is no unlocked identity with the given SID, this request returns *404
Not Found*.

Rhizome REST API
----------------

### Basic concepts

#### Rhizome storage and synchronisation

Rhizome is a [store and forward][] content distribution system that has no
central storage and relies on intermittent and ad-hoc network links between
nodes to disseminate copies of its content.

Whenever two Rhizome nodes are in direct network contact with each other (eg,
as immediate peers, or neighbours, in an ad hoc wireless network), they
spontaneously perform *Rhizome synchronisation*, during which each provides a
list of its own content to the other, and then chooses which of the other's
content to fetch.

Every Rhizome node has a *Rhizome store*, sometimes called the *Rhizome
database*, which keeps a copy of its recently received and inserted content.
Every store is limited in size, so during synchronisation, Rhizome *expires*
older items of content to make way for newer items.  Rhizome also gives
priority to smaller items, and can be made to prioritise on other criteria such
as geographical proximity to a location, sender, recipient, or content type.

The Rhizome REST API simply provides access to the contents of the local
Rhizome store.  The physical location of the store, expiry of bundles from the
store, and synchronisation with other Rhizome nodes are outside the scope of
the API.  An application wishing to share a file via Rhizome simply inserts the
file into Rhizome using this API, and lets Rhizome take care of the rest.

[store and forward]: https://en.wikipedia.org/wiki/Store_and_forward

#### Bundle

Rhizome content is organised into *bundles*.  Every bundle is an indivisible
item of content, analogous to a single file on a hard disk.  A bundle may have
any size.

A Rhizome *bundle* consists of a single [manifest](#concept-manifest) and an
optional [payload](#concept-payload).

Every Rhizome bundle is identified by its [Bundle ID](#bundle-id) and
[version](#bundle-version).

#### Bundle ID

A *Bundle ID* (a.k.a. [BID][], a.k.a. “Manifest ID”) is a unique 256-bit public
key in the [Curve25519][] key space, generated from the random [Bundle
Secret](#bundle-secret) when the the bundle is first created.

[BID]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:bid
[Curve25519]: https://en.wikipedia.org/wiki/Curve25519

#### Bundle version

A Bundle's *version* is a 64-bit unsigned integer chosen by the bundle's
author.

When presented with two or more bundles that have the same [Bundle
ID](#bundle-id), Rhizome always prefers the one with the highest version number
and discards the others.  This allows bundles to be *updated* by publishing a
new one with a larger version number than before.  As an updated bundle spreads
through the Rhizome network, it replaces all prior versions of itself.

#### Bundle Secret

A *Bundle Secret* is the [Curve25519][] cryptographic secret key that produces
a [Bundle ID](#bundle-id) public key, and is generated randomly when the bundle
is first created.

Every bundle is cryptographically signed by its own Bundle Secret, and the
signature is distributed along with the bundle's content.  This allows all
recipients to verify whether the bundle was in fact produced by the owner of
the Bundle Secret.  Bundles that do not verify are not stored or synchronised.

There is no restriction on the random generation of Bundle Secrets, so any
party may create, sign and publish as many bundles as desired.  However, only
the possessor of a Bundle Secret may publish an *update* to a bundle (same
Bundle ID, higher version).  The signature therefore prevents forgery of
updates to existing bundles.

Rhizome API operations that operate on a single bundle accept the Bundle Secret
as an optional parameter.  This allows applications to store the secrets for
the bundles they create, if desired.  However, a far easier way to remember of
a bundle's secret is to add a [Bundle Key](#bundle-key) to each bundle by
specifying a [bundle author](#bundle-author).

#### Bundle Key

The *Bundle Key* is an optional item of meta-data that may be included in a
bundle (as the [manifest](#manifest) `BK` field).  It encodes the [Bundle
Secret](#bundle-secret) in a form that only the possessor of the original
[Rhizome Secret](#rhizome-secret) can decode.  This avoids every application
having to store the secret of every bundle it may wish to update in future;
instead, it can add a `BK` field to each manifest it creates, and only the
Rhizome Secret need be stored (in the keyring).

If a bundle contains a [Bundle Key](#bundle-key), then the Bundle Secret can be
recovered as long as an unlocked keyring identity contains the originating
[Rhizome Secret](#rhizome-secret).  See [bundle author](#bundle-author) for
further information.

A bundle with no Bundle Key is truly anonymous.  If an application stores the
Bundle Secret itself (eg, in a local database indexed by Bundle ID), then it
may use that secret to update (modify) the bundle, but if the Bundle Secret is
lost, then the bundle becomes immutable.

#### Manifest

A Rhizome bundle's *manifest* consists of two parts: a meta-data section and a
signature section.

The meta-data section is a set of key-value *fields*.  A field key consists of
up to 80 alphanumeric ASCII characters, and the first character must be
alphabetic.  A field's value consists of zero or more bytes that may have any
value except ASCII NUL (0), CR (13) and NL (10).  Conventionally, numeric
values are represented using their decimal ASCII representation.

Every manifest must contain the following *core* fields, or it is *partial*:

*  `id` - the [Bundle ID](#bundle-id); 64 uppercase hexadecimal digits.

*  `version` - the [version](#bundle-version); ASCII decimal.

*  `filesize` - the number of bytes in the payload; ASCII decimal.

*  `service` - the name of the service (application) that created the bundle.

*  `date` - the date the bundle was created; an integral number of milliseconds
   since the [Unix time][] epoch, in ASCII decimal.  This field is set by the
   bundle's creator and could have any value, due either to inaccuracies in the
   system clock used to make the time stamp, or deliberate falsification.  This
   field can have values up to 2^64 − 1, so it is immune to the [Y2038
   problem][].

If the `filesize` is non-zero, then the following field must also be present:

*  `filehash` - the 512-bit cryptographic [SHA-512][] digest of the payload's
   content; 128 uppercase hexadecimal digits.

The presence of the following field indicates that the bundle is a *journal*:

*  `tail` - the byte offset within the journal at which the payload starts;
   ASCII decimal.  The bundle's creator can advance the tail whenever it
   updates the bundle, to indicate that the preceding bytes are no longer
   needed, so they can be deleted from Rhizome stores to reclaim space and need
   not be synchronised, to save network load.

The following fields are all optional:

*  `sender` - the [SID](#serval-id) of the bundle's sender; 64 uppercase
   hexadecimal digits.  Used mainly with the *MeshMS* service, for which it is
   mandatory, but can also be used by any application to suggest the bundle's
   author.

*  `recipient` - the [SID](#serval-id) of the bundle's recipient; 64 uppercase
   hexadecimal digits.  Used mainly with the *MeshMS* service, for which it is
   mandatory, but can also be used by any application to identify the bundle's
   intended destination.

*  `name` - a label that identifies the bundle to human users, and also serves
   as a file name for the *file* service.

*  `crypt` - if `1` then the payload is encrypted, so only its intended
   recipient (who may or may not be identified by the `recipient` field) can
   decrypt and read it.  If `0` or absent then the payload is clear text.

*  `BK` - the [Bundle Key](#bundle-key); 64 uppercase hexadecimal digits.

Any other field may be included in any manifest, but only those mentioned above
are given special meaning by Rhizome.

The manifest's signature section is a sequence of one or more concatenated
[Curve25519][] signature blocks.  At present, every bundle carries exactly one
signature, made using its Bundle Secret, although the manifest format allows
for the possibility of multi-signed bundles in future.

#### Bundle author

A bundle's *author* is the identity whose [Rhizome Secret](#rhizome-secret)
was used to set the manifest's `BK` field ([Bundle Key](#bundle-key)).

Manifests do not store the author [SID](#serval-id) explicitly.  Rhizome does
not support a manifest field called `author`.  Instead, the bundle author is
deduced from the `BK` field, if present.  The `BK` field relieves authors from
having to retain and protect all their Bundle Secrets, and it does so without
revealing the identity of the author.

If a bundle contains a `BK` ([Bundle Key](#bundle-key)) field, then the
author's identity can only be deduced if it is an [unlocked
identity](#get-restful-keyring-identities-json) in the local keyring.  Serval
DNA tries the [Rhizome Secret](#rhizome-secret) of every unlocked identity
until it finds one that, when used to decode the Bundle Key, yields a [Bundle
Secret](#bundle secret) that correctly generates the manifest's signature.  If
no unlocked identity is found, then the author is unknown.

Rhizome nodes that do not possess the unlocked author identity cannot derive
the [SID](#serval-id) of the author, *even if the SID is already known to them
through other means*, since they do not possess the author's Rhizome Secret.
Thus, the identity of the author is hidden even if a `BK` field is present.

If a bundle has no `BK` field, then its author can never be deduced, so the
bundle is *anonymous*.  An anonymous bundle is *immutable* if the [Bundle
Secret](#bundle-secret) is lost; without the Bundle Secret, it is impossible to
sign any change to the manifest, so no updates can be made.

The nearest thing to an “author” field is the optional `sender` field, to which
a bundle's creator can assign any SID it wishes, so it carries no guarantee of
validity.  As an optimisation, when deducing the author, Serval DNA tries the
`sender` identity first (if present and unlocked) before trying any others.  In
many cases (eg, [MeshMS conversations](#conversation)), the sender turns out to
be the author.

#### Payload

A Rhizome bundle's *payload* is a contiguous sequence of one or more bytes.

A zero-length payload is represented as "no payload" (`filesize=0`).

The interpretation of a payload's contents depends on the *service* that
created the bundle (and can therefore also deal with it), whether or not the
payload is encrypted (`crypt=1`), and other optional fields (eg, `name`) that
the creator added to the manifest.

[SHA-512]: https://en.wikipedia.org/wiki/SHA-2

#### Journal

A *journal* is a special kind of [bundle](#bundle) whose payload can only be
altered by appending new content to the end or discarding old content from the
beginning, never by changing existing content.

The presence of a `tail` field in the [manifest](#manifest) indicates that a
bundle is a journal.  The *tail* of a journal is set to zero (0) when the
journal is first created, and advanced in subsequent updates to indicate how
much of the payload has been discarded since the beginning.

The `filesize` field of a journal gives the number of bytes currently in the
payload, not counting those that have been discarded.  In other words, the
“logical length” of a journal's payload is `tail + filesize`, of which only the
most recently appended `filesize` bytes are actually stored and transported.

The `filehash` field of a journal is the digest of the `filesize` bytes
currently being stored and transported.  This allows Rhizome synchronisation
and storage to apply exactly the same manifest-payload consistency checks to
journals and non-journals alike.

Journal updates obey the following rules:

* must alter one or both of the `tail` and `filesize` fields
* do not decrease the value of the `tail` field
* do not decrease the sum of the `tail` and `filesize` fields
* do not modify any bytes of an existing payload except to remove bytes from
  the start when increasing the `tail` field or add bytes to the end when
  increasing the `filesize` field

The [Rhizome insert](#post-restful-rhizome-insert) operation enforces these
rules if it has access to a prior version of the journal, but this cannot
provide a guarantee, since an update could be performed in the absence of a
prior version, in which case the rules cannot be checked.

The Rhizome transport takes advantage of the append-only property of journals
by only transferring the newly-appended end of a payload (the “head”) during
synchronisation.  The Rhizome store reclaims space from the stored payloads of
journals by discarding bytes over which the tail has advanced.

### Rhizome-specific REST API

#### text+binarysig manifest format

The Rhizome REST API accepts and returns [manifest](#manifest)s in only one
format, denoted **text+binarysig**.  The *Content-Type* for this format is
**rhizome/manifest; format=text+binarysig**.

In future, other formats may be supported, for example, all-binary or all-text.

The TEXT part of this format lists key-value fields in arbitrary order, using
the following grammar:

    TEXT = ( KEY "=" VALUE "\n" ){0..*}
    KEY = ALPHA ( ALPHANUM ){0..79}
    VALUE = ( VALUECHAR ){0..*}
    VALUECHAR = any ASCII except NUL "\r" "\n"

Following the text is a single NUL byte, followed by the signature section in a
binary format.  If the NUL byte is missing, then the manifest is *unsigned*.

The signature section consists of one or more concatenated signature blocks.
Each block begins with a single *type* byte, followed by the bytes of the
signature itself.  The length of the signature is computed as `type × 4 + 4`.

The only supported signature type is 23 (hex 17), which is a 96-byte signature
that is verified using [Curve25519][].

#### Rhizome HTTP response headers

All Rhizome requests that fetch or insert a single bundle, whatever the
outcome, contain the following HTTP headers in the response:

    Serval-Rhizome-Result-Bundle-Status-Code: <integer>
    Serval-Rhizome-Result-Bundle-Status-Message: <text>
    Serval-Rhizome-Result-Payload-Status-Code: <integer>
    Serval-Rhizome-Result-Payload-Status-Message: <text>

*  the `Serval-Rhizome-Result-Bundle-Status-Code` header is the integer [bundle
   status code](#bundle-status-code)
*  the `Serval-Rhizome-Result-Bundle-Status-Message` header is the string
   [bundle status message](#bundle-status-message)
*  the `Serval-Rhizome-Result-Payload-Status-Code` header is the integer
   [payload status code](#payload-status-code)
*  the `Serval-Rhizome-Result-Payload-Status-Message` header is the string
   [payload status message](#payload-status-message)

#### Rhizome HTTP response bundle headers

All Rhizome requests that *successfully* fetch or insert a single bundle
contain the following HTTP headers in the response, which convey the core
manifest fields:

    Serval-Rhizome-Bundle-Id: <hex64bid>
    Serval-Rhizome-Bundle-Version: <integer>
    Serval-Rhizome-Bundle-Filesize: <integer>

If *filesize* is not zero, then the following HTTP header is present:

    Serval-Rhizome-Bundle-Filehash: <hex128>

If the bundle is a *journal*, then the following HTTP header is present:

    Serval-Rhizome-Bundle-Tail: <integer>

In addition, none, some or all of the following HTTP headers may be present, to
convey optional fields that are present in the bundle's manifest:

    Serval-Rhizome-Bundle-Sender: <hex64sid>
    Serval-Rhizome-Bundle-Recipient: <hex64sid>
    Serval-Rhizome-Bundle-BK: <hex64>
    Serval-Rhizome-Bundle-Crypt: 0 or 1
    Serval-Rhizome-Bundle-Service: <token>
    Serval-Rhizome-Bundle-Name: <quotedstring>
    Serval-Rhizome-Bundle-Date: <integer>

All single-bundle operations, unless otherwise specified, attempt to deduce the
bundle's [author](#bundle-author) by finding whether the manifest's signature
could be re-created using a [Rhizome Secret](#rhizome-secret) from a currently
unlocked identity in the keyring.  If the manifest `sender` field is present or
the author has been cached in the Rhizome database, then only that identity is
tried, otherwise every single identity in the keyring is tested.  If a signing
identity is found, then the following HTTP header is present:

    Serval-Rhizome-Bundle-Author: <hex64sid>

(In future, Serval DNA may cache the authors it discovers, to avoid redundant
re-testing of all keyring identities, but cached authors will not be
automatically treated as verified when read from the Rhizome database, because
the database could be altered by external means.)

If the bundle's [secret](#bundle-secret) is known, either because it was
supplied in the request or was deduced from the manifest's [Bundle
Key](#bundle-key) field and the author's [Rhizome Secret](#rhizome-secret),
then the following HTTP header is present:

    Serval-Rhizome-Bundle-Secret: <hex64>

The following HTTP headers might be present at the sole discretion of the
server, but they are not guaranteed, and future upgrades of [Serval DNA][] may
remove them.  They reveal internal details of the storage of the bundle:

    Serval-Rhizome-Bundle-Rowid: <integer>
    Serval-Rhizome-Bundle-Inserttime: <integer>

### Rhizome JSON result

All Rhizome requests to fetch or insert a single bundle that do not produce a
special response content for the outcome, return the following augmented [JSON
result](#json-result) object as the HTTP response content:

    {
     "http_status_code": ...,
     "http_status_message": "...",
     "rhizome_bundle_status_code": ...,
     "rhizome_bundle_status_message": "...",
     "rhizome_payload_status_code": ...,
     "rhizome_payload_status_message": "..."
    }

*  the `rhizome_bundle_status_code` field is the integer [bundle status code](#bundle-status-code)
*  the `rhizome_bundle_status_message` field is the string [bundle status message](#bundle-status-message)
*  the `rhizome_payload_status_code` field is the integer [payload status code](#payload-status-code)
*  the `rhizome_payload_status_message` field is the string [payload status message](#payload-status-message)

#### Bundle status code

All Rhizome operations that involve fetching and/or inserting a single manifest
into the Rhizome store return a *bundle status code*, which describes the
outcome of the operation.  Some codes have different meanings in the context of
a fetch or an insertion, and some codes can only be produced by insertions.
The bundle status code determines the [HTTP response code](#response-status-code).

| code | HTTP | meaning                                                                         |
|:----:|:----:|:------------------------------------------------------------------------------- |
|  -1  |  500 | internal error                                                                  |
|   0  |  201 | “new”; (fetch) bundle not found; (insert) bundle added to store                 |
|   1  |  200 | “same”; (fetch) bundle found; (insert) bundle already in store                  |
|   2  |  200 | “duplicate”; (insert only) duplicate bundle already in store                    |
|   3  |  202 | “old”; (insert only) newer version of bundle already in store                   |
|   4  |  422 | “invalid”; (insert only) manifest is malformed or invalid                       |
|   5  |  419 | “fake”; (insert only) manifest signature is invalid                             |
|   6  |  422 | “inconsistent”; (insert only) manifest filesize/filehash does not match payload |
|   7  |  202 | “no room”; (insert only) doesn't fit; store may contain more important bundles  |
|   8  |  419 | “readonly”; (insert only) cannot modify manifest because secret is unknown      |
|   9  |  423 | “busy”; Rhizome store database is currently busy (re-try)                       |
|  10  |  422 | “manifest too big”; (insert only) manifest size exceeds limit                   |

#### Bundle status message

The *bundle status message* is a short English text that explains the meaning
of its accompanying *bundle status code*, to assist with diagnosis.  The
message for a code may differ across requests and may change when [Serval
DNA][] is upgraded, so it cannot be relied upon as a means to programmatically
detect the outcome of an operation.

#### Payload status code

All Rhizome operations that involve fetching and/or inserting a single payload
into the Rhizome store return a *payload status code*, which describes the
outcome of the payload operation, and elaborates on the the reason for the
accompanying *bundle status code*.  Some codes have different meanings in the
context of a fetch or an insertion, and some codes can only be produced by
insertions.  The payload status code overrides the [HTTP response
code](#response-status-code) derived from the [bundle status
code](#bundle-status-code) if it is numerically higher.

| code | HTTP | meaning                                                               |
|:----:|:----:|:--------------------------------------------------------------------- |
|  -1  |  500 | internal error                                                        |
|   0  |  201 | empty payload (zero length)                                           |
|   1  |  201 | (fetch) payload not found; (insert) payload added to store            |
|   2  |  200 | (fetch) payload found; (insert) payload already in store              |
|   3  |  422 | payload size does not match manifest *filesize* field                 |
|   4  |  422 | payload hash does not match manifest *filehash* field                 |
|   5  |  419 | payload key unknown: (fetch) cannot decrypt; (insert) cannot encrypt  |
|   6  |  202 | (insert only) payload is too big to fit in store                      |
|   7  |  202 | (insert only) payload evicted; other payloads are ranked higher       |

#### Payload status message

The *payload status message* is short English text that explains the meaning of
its accompanying *payload status code*, to assist diagnosis.  The message for a
code may differ across requests and may change when [Serval DNA][] is upgraded,
so it cannot be relied upon as a means to programmatically detect the outcome
of an operation.

### GET /restful/rhizome/bundlelist.json

This request allows a client to discover all the bundles currently held in the
local Rhizome store.

Fetches a list of all bundles currently in [Serval DNA][]'s Rhizome store, in
order of descending insertion time starting with the most recently inserted.
The list is returned in the body of the [response](#response) in [JSON
table](#json-table) format with the following columns:

*  `.token` - either *null* or a string value that can be used as the token in
   a [newsince](#get-restful-rhizome-newsince-token-bundlelist-json) request.

*  `_id` - the Rhizome database row identifier; a unique integer per bundle
   with no guarantees of sequence or re-use after deletion.

*  `service` - the string value of the manifest's *service* field, or *null* if
   the manifest has no *service* field.

*  `id` - the [Bundle ID](#bundle-id); a string containing 64 hexadecimal digits.

*  `version` - the bundle version; a positive integer with a maximum value of
   2^64 − 1.

*  `date` - the bundle publication time; an integral number of milliseconds
   since the [Unix time][] epoch, or *null* if the manifest has no *date* field.

*  `.inserttime` - the time that the bundle was inserted into the local Rhizome
   store.  This field is created using the local system clock, so comparisons
   with the `date` field cannot be relied upon as having any meaning.

*  `.author` - the [SID](#serval-id) of the local (unlocked) identity that
   created the bundle; either a string containing 64 hexadecimal digits, or
   *null* if the [bundle author](#bundle-author) cannot be deduced.  In the
   case of *null*, the `.fromhere` field will be 0 (“not authored here”).  In
   the case of a SID, the `.fromhere` indicates whether authorship was absent,
   likely or certain.

*  `.fromhere` - an integer flag that indicates whether the bundle was authored
   on the local device:

   *  `0` (“absent”) means that the bundle was not authored by any unlocked
      identity on this device.

   *  `1` (“likely”) means that the author whose [SID](#serval-id) is given in
      the `.author` field is present in the local keyring but authorship (the
      manifest's signature) has not been cryptographically verified, so
      attempting to update this bundle may yet fail.  This is the usual value
      because cryptographic verification is not performed while listing
      bundles, since it is slow and costly in CPU and battery.

   *  `2` (“certain”) means that the author whose [SID](#serval-id) is given in
      the `.author` field is present in the local keyring and has been
      cryptographically verified as the true author of the bundle, ie, yields a
      correct [Bundle Secret](#bundle-secret).  This value will usually only be
      returned for locally-authored bundles that have recently been examined
      individually (eg, [GET /restful/rhizome/BID.rhm](#get-restful-rhizome-bid-rhm)),
      if Serval DNA has cached the result of the verification in memory.

*  `filesize` - the number of bytes in the bundle's payload; an integer zero or
   positive with a maximum value of 2^64 − 1.

*  `filehash` - if the bundle has a non-empty payload, then the [SHA-512][]
   hash of the payload content; a string containing 128 hexadecimal digits,
   otherwise *null* if the payload is empty (*filesize* = 0).

*  `sender` - the [SID](#serval-id) of the bundle's sender; either a string
   containing 64 hexadecimal digits, or *null* if the manifest has no *sender*
   field.

*  `recipient` - the [SID](#serval-id) of the bundle's recipient; either a
   string containing 64 hexadecimal digits, or *null* if the manifest has no
   *recipient* field.

*  `name` - the string value of the manifest's *name* field, or *null* if the
   manifest has no *name* field.

### GET /restful/rhizome/newsince/TOKEN/bundlelist.json

This request allows a client to receive near-real-time notification of
newly-arriving Rhizome bundles.

Fetches a list of all bundles currently in [Serval DNA][]'s Rhizome store, in
order of ascending insertion time, since (but not including) the bundle
identified by TOKEN.  TOKEN must be a value taken from the non-null `.token`
field of any previous *bundlelist.json* request.

The list is returned in the body of the [response](#response) in [JSON
table](#json-table) format, exactly the same as [GET
/restful/rhizome/bundlelist.json](#get-restful-rhizome-bundlelist-json), but
with the following differences:

*  Bundles are listed in order of *ascending*, not *descending*, insertion
   time, ie, the most recent last.

*  Once all bundles have been listed, the response does not finish immediately,
   but blocks for approximately 60 seconds while waiting for new bundles to
   appear (get added to the Rhizome store).

*  The final “]}” of the [JSON table](#json-table) “rows” array and top-level
   object are not sent until the response finishes, so in order to make proper
   use of this request, the client must be able to incrementally parse partial
   JSON as it arrives.

### GET /restful/rhizome/BID.rhm

Fetches the manifest for the bundle whose id is `BID` (64 hex digits), eg:

    /restful/rhizome/1702BD647D614DB72C36BD634B6870CA31040C2EEC5069AEC0C0841D0CC671BE.rhm

If the **manifest is found** in the local Rhizome store, then the response will
be *200 OK* and:

*  the [bundle status code](#bundle-status-code) will be 1
*  the [payload status code](#payload-status-code), if present in the response,
   is not relevant, so must be ignored
*  the [Rhizome response bundle headers](#rhizome-response-bundle-headers) give
   information about the found bundle, some of which is duplicated from the
   manifest
*  the response's Content-Type is **rhizome/manifest; format=text+binarysig**
*  the response's Content-Length is the size, in bytes, of the manifest with
   its binary signature appended
*  the response's content is the Rhizome manifest in [text+binarysig
   format](#textbinarysig-manifest-format)

If the **manifest is not found** in the local Rhizome store, then the response
will be *404 Bundle not found* and:

*  the [bundle status code](#bundle-status-code) will be 0
*  the [payload status code](#payload-status-code), if present in the response,
   is not relevant, so must be ignored
*  the [Rhizome response bundle headers](#rhizome-response-bundle-headers) are
   absent from the response
*  the response's content is the [Rhizome JSON result](#rhizome-json-result)
   object

### GET /restful/rhizome/BID/raw.bin

Fetches the "raw" (encrypted) payload for the bundle whose id is `BID` (64 hex
digits), eg:

    /restful/rhizome/1702BD647D614DB72C36BD634B6870CA31040C2EEC5069AEC0C0841D0CC671BE/raw.bin

If the **manifest and the payload are both found** in the local Rhizome store,
then the response will be *200 OK* and:

*  the [bundle status code](#bundle-status-code) will be 1
*  the [payload status code](#payload-status-code) will be 0 if the payload has
   zero length, otherwise 2
*  the [Rhizome response bundle headers](#rhizome-response-bundle-headers) give
   information about the found bundle, some of which is duplicated from the
   manifest
*  the response's Content-Type is **application/octet-stream**
*  the response's Content-Length is the size, in bytes, of the raw payload
*  the response's content is the bundle's payload exactly as stored in Rhizome;
   if the payload is encrypted (the manifest's `crypt` field is 1) then the
   payload is not decrypted

If the **manifest is not found** in the local Rhizome store, then the response
will be *404 Bundle not found* and:

*  the [bundle status code](#bundle-status-code) will be 0
*  the [payload status code](#payload-status-code), if present in the response,
   is not relevant, so must be ignored
*  the [Rhizome response bundle headers](#rhizome-response-bundle-headers) are
   absent from the response
*  the response's content is the [Rhizome JSON result](#rhizome-json-result)
   object

If the **manifest is found** in the local Rhizome store but the **payload is
not found**, then the response will be *404 Payload not found* and:

*  the [bundle status code](#bundle-status-code) will be 1
*  the [payload status code](#payload-status-code) will be 1
*  the [Rhizome response bundle headers](#rhizome-response-bundle-headers) give
   information about the found manifest
*  the response's content is the [Rhizome JSON result](#rhizome-json-result)
   object

### GET /restful/rhizome/BID/decrypted.bin

Fetches the decrypted payload for the bundle whose id is `BID` (64 hex digits),
eg:

    /restful/rhizome/1702BD647D614DB72C36BD634B6870CA31040C2EEC5069AEC0C0841D0CC671BE/decrypted.bin

The responses are identical to those for [GET /restful/rhizome/BID/raw.bin](get-restful-rhizome-bid-raw-bin),
with the following additional case:

If the **manifest and payload are both found** and the payload is **encrypted**
(the manifest's `crypt` field is 1), but the **payload secret is not known**,
then:

*  the [bundle status code](#bundle-status-code) will be 0
*  the [payload status code](#payload-status-code) will be 5
*  the [Rhizome response bundle headers](#rhizome-response-bundle-headers) give
   information about the found manifest
*  the response's content is the [Rhizome JSON result](#rhizome-json-result)
   object

For a bundle that has a *sender* and a *recipient*, the payload secret is
determined as follows:

*  if the recipient's identity is found (unlocked) in the keyring, then the
   secret is derived from the recipient's [Serval ID](#serval-id) secret;
   otherwise
*  if the recipient's identity is not found in the keyring (locked or missing)
   but the sender's identity is found (unlocked) in the keyring, then the
   secret is derived from the sender's [Serval ID](#serval-id) secret;
   otherwise
*  neither identity is found in the keyring (both are locked or missing), so
   the payload secret is unknown.

For all other bundles, the payload secret is derived directly from the [Bundle
Secret](#bundle-secret), whether supplied as a query parameter or deduced from
the bundle's [Bundle Key](#bundle-key).  If the Bundle Secret is unknown, then
the payload secret is unknown.

### POST /restful/rhizome/insert

This request allows a client to add a new bundle to the Rhizome store, or
update an existing bundle in the store.  This request cannot be used to create
or update [journals](#journal); use the [append](#post-restful-rhizome-append)
request instead.

Takes the following parameters, all optional under various conditions:

*  **bundle-id**  The [Bundle ID](#bundle-id) of an existing bundle to update;
   64 hexadecimal digits.  If the bundle currently exists in the Rhizome store
   then a copy of its manifest is used as the basis of the new bundle, omitting
   its `version`, `filesize`, `filehash` fields (which must be supplied or
   inferred anew).

*  **bundle-author**  The [SID](#serval-id) of the bundle's
   [author](#bundle-author):
   *  64 hexadecimal digits;
   *  the bundle author sets (or removes) the bundle's `BK` field, overriding
      any `BK` field in the partial manifest supplied in the *manifest*
      parameter or in the existing bundle nominated by the *bundle-id*
      parameter;
   *  if there is no unlocked identity in the keyring with the given SID, then
      the new bundle will be an *anonymous* bundle with no `BK` field;
   *  this parameter must come before the *manifest* parameter, otherwise the
      request fails with status [400](#bad-request) and the message ‘Spurious
      "bundle-id" form part’.

*  **bundle-secret**  The [Bundle Secret](#bundle-secret); 64 hexadecimal
   digits.  This is needed in order to create a bundle with a specific [Bundle
   ID](#bundle-id) (supplied in the **manifest** parameter), or to update an
   existing bundle that is anonymous or the author is not a currently unlocked
   identity in the keyring.

*  **manifest**  A partial, unsigned manifest in [text+binarysig
   format](#textbinarysig-manifest-format), with a correct *Content-Type*
   header.  The fields in this manifest are used to form the new bundle's
   manifest, overwriting the fields of any existing manifest specified by the
   *bundle-id* parameter, if given.

*  **payload**  The content of the new bundle's payload:
   *  the form part's *Content-Type* header is currently ignored, but in future
      it may be used to determine the default values of some manifest fields;
   *  this parameter must occur after the *manifest* parameter, otherwise the
      request fails with status [400](#bad-request) and the message ‘Missing
      "manifest" form part’;
   *  the *payload* parameter must not be supplied if the `filesize` field in
      the *manifest* parameter is zero.

The insertion logic proceeds in the following steps:

1.  If the partial manifest supplied in the *manifest* parameter is malformed
    (syntax error) or contains a core field with an invalid value, then the
    request fails with status [422](#unprocessable-entity) and the [bundle
    status code](#bundle-status-code) for “invalid”.

2.  If a *bundle-id* parameter was supplied and the given bundle exists in the
    Rhizome store, then the new bundle's manifest is initialised by copying all
    the fields from the existing manifest.

3.  If a partial manifest was supplied in the *manifest* parameter, then its
    fields are copied into the new manifest, overwriting any that were copied
    in step 2.

4.  If the `tail` field is present in the new manifest then the new bundle is a
    [journal](#journal), so the request fails with status
    [422](#unprocessable-entity) and the [bundle status
    code](#bundle-status-code) for “invalid”.  Journals can only be created and
    updated using the [append](#post-restful-rhizome-append) request.

5.  If the *bundle-secret* parameter was supplied, then a public key ([Bundle
    ID](#bundle-id)) is derived from the [Bundle Secret](#bundle-secret), and:

    * if the new manifest has no `id` field, then the `id` field is set to the
      derived public key;

    * otherwise, if the new manifest's `id` field is not equal to the derived
      public key, then the supplied secret is wrong, so the request fails with
      status [419](#authentication-timeout) and the [bundle status
      code](#bundle-status-code) for “readonly”;

    Otherwise, if no *bundle-secret* parameter was supplied:

    * if the new manifest has no `id` field, then a new [Bundle
      Secret](#bundle-secret) is generated randomly, the [Bundle
      ID](#bundle-id) is derived from the new Bundle Secret, and the `id` field
      set to that Bundle ID;

    * if the new manifest already has an `id` field but no `BK` field ([Bundle
      Key](#bundle-key)) (ie, the bundle is *anonymous*), then the [Bundle
      Secret](#bundle-secret) cannot be discovered, so the request fails with
      status [419](#authentication-timeout) and the [bundle status
      code](#bundle-status-code) for “readonly”.

    * otherwise, if the *bundle-author* parameter was given, then that
      [SID](#serval-id) is looked up in the keyring.  If the identity is found,
      then the [Bundle Secret](#bundle-secret) is derived from the combination
      of the `BK` field ([Bundle Key](#bundle-key)) with the identity's
      [Rhizome Secret](#rhizome-secret), and the [Bundle ID](#bundle-id) is
      derived from the Bundle Secret.  If the identity was not found or the
      derived Bundle ID does not equal the `id` field then the request fails
      with status [419](#authentication-timeout) and the [bundle status
      code](#bundle-status-code) for “readonly”.

    * otherwise, if no *bundle-author* parameter was given, then the keyring is
      searched for an identity whose [Rhizome Secret](#rhizome-secret) combined
      with the `BK` field ([Bundle Key](#bundle-key)) produces a [Bundle
      Secret](#bundle-secret) whose derived [Bundle ID](#bundle-id) matches the
      `id` field.  The search starts with the identity given by the `sender`
      field, if present.  If none is found, then the request fails with status
      [419](#authentication-timeout) and the [bundle status
      code](#bundle-status-code) for “readonly”, otherwise the author is
      deduced to be the found identity.

6.  If the *bundle-author* parameter was given and step 5 set the `id` field
    (either derived from the *bundle-secret* parameter or randomly generated),
    then the *bundle-author* [SID](#serval-id) is looked up in the keyring.  If
    not found, then the request fails with status
    [419](#authentication-timeout) and the [bundle status
    code](#bundle-status-code) for “readonly”.  If found, then the author's
    [Rhizome Secret](#rhizome-secret) is used to calculate the [Bundle
    Key](#bundle-key) and set the `BK` field.

7.  The following fields are initialised if they are missing:

    *  `service` to the value `file`
    *  `version` to the current [Unix time][] in milliseconds since the epoch
    *  `date` to the current [Unix time][] in milliseconds since the epoch
    *  `crypt` to `1` if the `sender` and `recipient` fields are both set

8.  If the *payload* parameter is given and is non-empty, then its value is
    stored in the store, and its size and [SHA-512][] digest computed.  If the
    manifest is missing either or both of the `filesize` and `filehash` fields,
    then the missing ones are filled in from the computed values.  If the
    manifest had a `filesize` or `filehash` field that does not match the
    computed value, then the request fails with status
    [422](#unprocessable-entity) and the [bundle status
    code](#bundle-status-code) for “inconsistent”.

9.  The manifest is *validated* to ensure that:

    *  the `id` field is present
    *  the `version` field is present
    *  the `filesize` field is present
    *  if `filesize` is zero then there is no `filehash` field
    *  if `filesize` is non-zero then the `filehash` field is present
    *  if `service` is `file` then a `name` field is present
    *  if `service` is `MeshMS1` or `MeshMS2` then the `sender` and `recipient`
       fields are both present
    *  the `service` field contains no invalid characters
    *  the `date` field is present

    If validation fails, the request fails with status
    [422](#unprocessable-entity) and the [bundle status
    code](#bundle-status-code) for “invalid”.

10. If step 5 set the `id` field (either derived from the *bundle-secret*
    parameter or randomly generated) and the bundle is a *duplicate* of a
    bundle that is already in the store, then the request finishes with status
    [200](#ok) and the [bundle status code](#bundle-status-code) for
    “duplicate”.  Bundles are considered duplicates if they have:

    *  an identical payload (identical `filesize` and `filehash` fields), and
    *  the same `service` field, and
    *  the same `name` field, and
    *  the same `sender` field, and
    *  the same `recipient` field.

11. The manifest is signed using the [Bundle Secret](#bundle-secret), and the
    signature appended to the manifest after a single ASCII NUL (0) separator
    byte.  If the result exceeds the maximum manifest size (8 KiB) then the
    request fails with status [422](#unprocessable-entity) and the [bundle
    status code](#bundle-status-code) for “manifest too big”.

12. If the Rhizome store already contains a manifest with the same [Bundle
    ID](#bundle-id), then its version is compared with the new manifest's
    version.

    *  If they have the same version, then the new manifest is not stored, and
       the request returns status [200](#ok) and the [bundle status
       code](#bundle-status-code) for “same”.

    *  If the new manifest's version is less than the stored manifest's, then
       the new manifest is not stored, and the request returns status
       [202](#accepted) and the [bundle status code](#bundle-status-code) for
       “old”.

13. The new manifest is stored in the Rhizome store, replacing any existing
    manifest with the same [Bundle ID](#bundle-id).  The request returns status
    [201](#created) and the [bundle status code](#bundle-status-code) for
    “new”.

### POST /restful/rhizome/append

This request allows a client to add a new [journal bundle](#journal) to the
Rhizome store, or update an existing one.  It takes exactly the same parameters
as the [insert](#post-restful-rhizome-insert) operation, to which it is
identical in all respects except as follows:

The steps of the insertion logic have these variations:

1.  The validity checks on any partial manifest given in the *manifest*
    parameter will also fail if the partial manifest contains a `version`,
    `filesize` or `filehash` field.

2.  If the *bundle-id* parameter specifies an existing manifest, then the
    `version`, `filesize` and `filehash` fields are not copied from the
    existing manifest to the new manifest.

3.  After the partial manifest has been copied into the new manifest, if the
    *bundle-id* parameter was not given or specified a bundle that was not
    found in the store (step 2), then the `filesize` and `tail` fields are
    initialised to zero (0) if they are missing.

4.  If the `tail` field is missing from the new manifest then the bundle is not
    a [journal](#journal), so the request fails with status
    [422](#unprocessable-entity) and the [bundle status
    code](#bundle-status-code) for “invalid”.

5.  No change.

6.  No change.

7.  No change.

8.  After the payload has been stored, the `filesize` and `filehash` fields are
    always set, overriding any that were already present.  Also, the `version`
    is always set to `tail + filesize`.

9.  No change.

10. No change.

11. No change.

12. No change.

13. No change.

MeshMS REST API
---------------

### Basic concepts

#### Conversation

TBC

#### Ply

### GET /restful/meshms/RECIPIENTSID/conversationlist.json

TBC

### GET /restful/meshms/SENDERSID/RECIPIENTSID/messagelist.json

TBC

### GET /restful/meshms/SENDERSID/RECIPIENTSID/newsince/TOKEN/messagelist.json

TBC

### POST /restful/meshms/SENDERSID/RECIPIENTSID/sendmessage

TBC


-----
**Copyright 2015 Serval Project Inc.**  
![CC-BY-4.0](./cc-by-4.0.png)
Available under the [Creative Commons Attribution 4.0 International licence][CC BY 4.0].


[Serval Project]: http://www.servalproject.org/
[CC BY 4.0]: ../LICENSE-DOCUMENTATION.md
[Serval DNA]: ../README.md
[Serval Mesh]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:servalmesh:development
[Keyring]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:keyring
[Rhizome]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:rhizome
[MeshMS]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:meshms
[MDP]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:mdp
[MSP]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:msp
[DID]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:did
[Basic Authentication]: https://en.wikipedia.org/wiki/Basic_access_authentication
[API]: https://en.wikipedia.org/wiki/Application_programming_interface
[HTTP REST]: https://en.wikipedia.org/wiki/Representational_state_transfer
[HTTP 1.0]: http://www.w3.org/Protocols/HTTP/1.0/spec.html
[Intent]: http://developer.android.com/reference/android/content/Intent.html
[Permission]: https://developer.android.com/preview/features/runtime-permissions.html
[configured]: ./Servald-Configuration.md
[Internet Media Type]: https://www.iana.org/assignments/media-types/media-types.xhtml
[JSON]: https://en.wikipedia.org/wiki/JSON
[UTF-8]: https://en.wikipedia.org/wiki/UTF-8
[jq(1)]: https://stedolan.github.io/jq/
[idempotent]: https://en.wikipedia.org/wiki/Idempotence
[Unix time]: https://en.wikipedia.org/wiki/Unix_time
[Y2038 problem]: https://en.wikipedia.org/wiki/Year_2038_problem
