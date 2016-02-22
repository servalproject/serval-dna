REST API
========
[Serval Project][], February 2016

Introduction
------------

The [Serval DNA][] daemon that runs on every node in a [Serval Mesh network][]
gives applications access to the network through two main classes of [API][]:

*  the [MDP API][MDP] and [MSP API][MSP] provide "traditional" packet and
   stream transport, allowing applications to send and receive Serval network
   packets to and from nearby nodes with latencies of up to several seconds;

*  the various [HTTP REST][] APIs provide applications with access to Serval
   services:

   -  [Keyring REST API][] -- local identity management by querying and
      modifying the [Keyring][]

   -  [Rhizome REST API][] -- store-and-forward (high latency) content
      distribution by extracting and inserting content in the local [Rhizome][]
      store

   -  [MeshMS REST API][] -- secure one-to-one messaging by reading and writing
      the local cache of [MeshMS][] messages

This document describes the features in common to all the [HTTP REST][] APIs.

### Protocol and port

The Serval DNA [HTTP REST][] API is an [HTTP 1.0][] server that only accepts
requests on the loopback interface (IPv4 address 127.0.0.1), TCP port 4110.  It
rejects requests that do not originate on the local host, by replying
[403 Forbidden](#403-forbidden).

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
as a request body with a [Content-Type](#request-content-type) of
[multipart/form-data][].  These two kinds of parameters are not exclusive; a
request may contain a mixture of both.

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
    cause a [415 Unsupported Media Type](#415-unsupported-media-type) response.

*   **rhizome/manifest; format=text+binarysig** is used for [Rhizome
    manifest][]s in [text+binarysig format][].

A missing Content-Type header in a `POST` request will cause a [400 Bad
Request](#400-bad-request) response.  An unsupported content type will cause a
[415 Unsupported Media Type](#415-unsupported-media-type) response.

The following media types are *not supported*:

*  [application/x-www-form-urlencoded][] is commonly used to send parameters in
   [POST](#post) requests, and is the predecessor web standard to
   [multipart/form-data][].  It has the benefit of being simpler than
   [multipart/form-data][] for requests that take short, mainly textual
   parameters, but is very inefficient for encoding large binary values and
   does not provide any means to associate metadata such as content-type and
   encoding with individual parameters.  In future, some REST API requests may
   support [application/x-www-form-urlencoded][].

[multipart/form-data]: https://www.ietf.org/rfc/rfc2388.txt
[application/x-www-form-urlencoded]: https://tools.ietf.org/html/rfc1866#section-8.2.1

#### Request Range

[HTTP 1.1 Range][] retrieval is partially supported.  In a request, the
**Range** header gives the start and end, in byte offsets, of the resource to
be returned.  The server may respond with exactly the range requested, in which
case the response status code will be [206 Partial Content](#206-partial-content),
or it may ignore the Range header and respond with the entire requested
resource.

For example, the following header asks that the server omit the first 64 bytes
and send only the next 64 bytes (note that ranges are inclusive of their end
byte number):

    Range: bytes=64-127

The [specification][HTTP 1.1 Range] allows for more than one start-end range to
be supplied, separated by commas, however not all REST API operations support
multi ranges.  If a multi-range header is used in such a request, then the
response may be the entire content or [501 Not Implemented](#501-not-implemented).

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
Serval DNA HTTP REST responses have a Content-Type of **[application/json][]**
unless otherwise documented.

Some responses contain non-standard HTTP headers as part of the result they
return to the client; for example, [Rhizome response headers](#rhizome-response-headers).

[application/json]: https://tools.ietf.org/html/rfc4627

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
created, then these requests return [201 Created](#201-created) instead.)

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
- the path contains a reference to an entity (eg, [SID][], [Bundle ID][]) that
  does not exist

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
- a part of a [multipart/form-data][] request body has:
  - a missing `Content-Disposition` header, or
  - a `Content-Disposition` header that is not of type `form-data`, or
  - a missing or unsupported `Content-Type` header (including a missing or
    unsupported `charset` parameter)

#### 416 Requested Range Not Satisfiable

The [Range](#request-range) header specified a range whose start position falls
outside the size of the requested entity.

#### 419 Authentication Timeout

The request failed because the server does not possess and cannot derive the
necessary cryptographic secret or credential.  For example, updating a [Rhizome
bundle][] without providing the [bundle secret][].  This code is not part of
the HTTP standard.

#### 422 Unprocessable Entity

A `POST` request supplied data that was inconsistent or violates semantic
constraints, so cannot be processed.  For example, the [Rhizome
insert](./REST-API-Rhizome.md#post-restfulrhizomeinsert) operation responds
with 422 if the manifest *filesize* and *filehash* fields do not match the
supplied payload.

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
indicated by other status codes, such as [423 Locked](#423-locked).

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
/restful/rhizome/bundlelist.json](./REST-API-Rhizome.md#get-restfulrhizomebundlelistjson))
use the following *JSON table* format:

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
objects.  The [test scripts](../testdefs_json.sh) use the following [jq(1)][]
expression to perform the transformation:

    [
        .header as $header |
        .rows as $rows |
        $rows | keys | .[] as $index |
        [ $rows[$index] as $d | $d | keys | .[] as $i | {key:$header[$i], value:$d[$i]} ] |
        from_entries |
        .["__index"] = $index
    ]

-----
**Copyright 2015 Serval Project Inc.**  
![CC-BY-4.0](./cc-by-4.0.png)
Available under the [Creative Commons Attribution 4.0 International licence][CC BY 4.0].


[Serval Project]: http://www.servalproject.org/
[CC BY 4.0]: ../LICENSE-DOCUMENTATION.md
[API]: https://en.wikipedia.org/wiki/Application_programming_interface
[Serval DNA]: ../README.md
[Serval Mesh network]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:mesh_network
[HTTP REST]: https://en.wikipedia.org/wiki/Representational_state_transfer
[HTTP 1.0]: http://www.w3.org/Protocols/HTTP/1.0/spec.html
[MDP]: ./Mesh-Datagram-Protocol.md
[MSP]: ./Mesh-Stream-Protocol.md
[Keyring REST API]: ./REST-API-Keyring.md
[Keyring]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:keyring
[Rhizome REST API]: ./REST-API-Rhizome.md
[Rhizome]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:rhizome
[MeshMS REST API]: ./REST-API-MeshMS.md
[MeshMS]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:meshms
[Basic Authentication]: https://en.wikipedia.org/wiki/Basic_access_authentication
[Serval Mesh]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:servalmesh:development
[Intent]: http://developer.android.com/reference/android/content/Intent.html
[Permission]: https://developer.android.com/preview/features/runtime-permissions.html
[configured]: ./Servald-Configuration.md
[Internet Media Type]: https://www.iana.org/assignments/media-types/media-types.xhtml
[Rhizome bundle]: ./REST-API-Rhizome.md#bundle
[Rhizome manifest]: ./REST-API-Rhizome.md#manifest
[bundle secret]: ./REST-API-Rhizome.md#bundle-secret
[text+binarysig format]: ./REST-API-Rhizome.md#textbinarysig-manifest-format
[JSON]: https://en.wikipedia.org/wiki/JSON
[UTF-8]: https://en.wikipedia.org/wiki/UTF-8
[jq(1)]: https://stedolan.github.io/jq/
[idempotent]: https://en.wikipedia.org/wiki/Idempotence
[SID]: ./REST-API-Keyring.md#serval-id
[Bundle ID]: ./REST-API-Rhizome.md#bundle-id
