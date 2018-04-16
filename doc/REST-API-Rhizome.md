Rhizome REST API
================
[Serval Project][], October 2017

Introduction
------------

[Rhizome][] is a service in the [Serval Mesh network][] that provides secure,
distributed [store and forward][] content distribution without a central
storage, using intermittent and ad-hoc network links between nodes to
disseminate copies of its content.

The [Serval DNA][] daemon that runs on every node gives applications access to
the [Rhizome][] service via the **Rhizome REST API** described in this
document.

Basic concepts
--------------

### Rhizome store

Unlike conventional Internet cloud storage services like Dropbox, Rhizome has
no central storage server.  Instead, Rhizome stores its content on every device
in the [Serval mesh network][], which provides a high degree of redundance and
resilience.

Every Rhizome node has its own *Rhizome store*, sometimes called the *Rhizome
database*, which keeps a copy of all recently received and inserted content.

The Rhizome REST API provides its client applications with access to the
contents of the local Rhizome store.  The internal format of the store, expiry
of bundles from the store, and synchronisation with other Rhizome nodes are
outside the scope of the API.  An application wishing to share a file via
Rhizome simply inserts the file into Rhizome using this API, and lets Rhizome
take care of the rest.

### Rhizome synchronisation

Whenever two Rhizome nodes are in direct network contact with each other (eg,
as immediate peers, or neighbours, in an ad hoc wireless network), they
spontaneously perform *Rhizome synchronisation*, during which each provides a
list of its own content to the other, and then chooses which of the other's
content to fetch.

Every [Rhizome store](#rhizome-store) is limited in size, so during
synchronisation, Rhizome *expires* older items of content to make way for newer
items.  Rhizome gives priority to smaller items, and can be made to prioritise
on other criteria such as geographical proximity to a location, sender,
recipient, or content type.

### Rhizome Secret

Every identity in the [Serval mesh network][] has its own [Rhizome
Secret](./REST-API-Keyring.md#rhizome-secret), which is a cryptographic secret
key generated at random when the identity is first created, and stored in the
[Keyring][].

### Bundle

Rhizome content is organised into *bundles*.  Every bundle is an indivisible
item of content, analogous to a single file on a hard disk.  A bundle may have
any size.

A Rhizome *bundle* consists of a single [manifest](#manifest) and an optional
[payload](#payload).

Every Rhizome bundle is uniquely identified by its [Bundle ID](#bundle-id) and
[version](#bundle-version).

### Bundle ID

Every [Bundle](#bundle) in Rhizome is identified by its *Bundle ID*
(abbreviated to [BID][], sometimes known as “Manifest ID”), which is a unique
256-bit public key in the [Curve25519][] key space, generated from the random
[Bundle Secret](#bundle-secret) when the the bundle is first created.

### Bundle version

A Bundle's *version* is a 64-bit unsigned integer chosen by the bundle's
author.

When presented with two or more bundles that have the same [Bundle
ID](#bundle-id), Rhizome always prefers the one with the highest version number
and discards the others.  This allows bundles to be *updated* by publishing a
new one with a larger version number than before.  As an updated bundle spreads
through the Rhizome network, it replaces all prior versions of itself.

### Bundle Secret

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

### Bundle Key

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

### Manifest

A Rhizome bundle's *manifest* consists of two parts: a meta-data section and a
signature section, separated by a NUL (zero) byte:

    MANIFEST = METADATA NUL SIGNATURE

If the NUL byte is missing, then the manifest is *unsigned*.

The meta-data section consists of a set of key-value *fields* in arbitrary
order, conforming to the following grammar:

    METADATA = ( KEY "=" VALUE LF ){0..*}
    KEY = ALPHA ( ALPHANUM ){0..79}
    VALUE = ( VALUECHAR ){0..*}
    ALPHA = octet in set ASCII A..F or a..f
    ALPHANUM = ALPHA or octet in set ASCII 0..9
    VALUECHAR = any ASCII octet except NUL CR or LF
    ASCII = any octet in range 0..127
    NUL = octet with value 0
    LF = octet with value 10
    CR = octet with value 13

The signature section uses a binary format, and consists of one or more
concatenated signature blocks.  Each block begins with a single *type* byte,
followed by the bytes of the signature itself.  The length of the signature is
computed as `type × 4 + 4`, not counting the type byte:

    SIGNATURE = ( BLOCK ){1..*}
    BLOCK = TYPE ( ANY ){TYPE * 4 + 4}
    TYPE = octet with value 23
    ANY = any octet in range 0..255

The only supported signature type is 23 (hex 17), which is a 96-byte signature
that is verified using [Curve25519][].

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

*  `sender` - the [SID][] of the bundle's sender; 64 uppercase hexadecimal
   digits.  Used mainly with the [MeshMS][] service, for which it is mandatory,
   but can also be used by any application to suggest the bundle's author.

*  `recipient` - the [SID][] of the bundle's recipient; 64 uppercase
   hexadecimal digits.  Used mainly with the [MeshMS][] service, for which it
   is mandatory, but can also be used by any application to identify the
   bundle's intended destination.

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

### Valid manifest

A [manifest](#manifest) is *valid* if:

*  the `id` field is present and valid
*  the `version` field is present and valid
*  the `filesize` field is present and valid
*  the `service` field is present and valid
*  the `date` field is present and valid
*  if `filesize` is zero then there is no `filehash` field, otherwise the
   `filehash` field is present and valid
*  if `service` is `file` then a `name` field is present
*  if `service` is `MeshMS1` or `MeshMS2` then the `sender` and `recipient`
   fields are both present and valid

Note that *validity* does not require that the manifest's signature be
*verified*.  A manifest with an unverified or missing signature may still be
*valid*.

### Bundle author

A bundle's *author* is the identity whose [Rhizome Secret](#rhizome-secret)
was used to set the manifest's `BK` field ([Bundle Key](#bundle-key)).

Manifests do not store the author [SID][] explicitly.  Rhizome does not support
a manifest field called `author`.  Instead, the bundle author is deduced from
the `BK` field, if present.  The `BK` field relieves authors from having to
retain and protect all their Bundle Secrets, and it does so without revealing
the identity of the author.

If a bundle contains a `BK` ([Bundle Key](#bundle-key)) field, then the
author's identity can only be deduced if it is an [unlocked
identity](#get-restfulkeyringidentitiesjson) in the local keyring.  Serval
DNA tries the [Rhizome Secret](#rhizome-secret) of every unlocked identity
until it finds one that, when used to decode the Bundle Key, yields a [Bundle
Secret](#bundle-secret) that correctly generates the manifest's signature.  If
no unlocked identity is found, then the author is unknown.

Rhizome nodes that do not possess the unlocked author identity cannot derive
the [SID][] of the author, *even if the SID is already known to them through
other means*, since they do not possess the author's Rhizome Secret.  Thus, the
identity of the author is hidden even if a `BK` field is present.

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

### Payload

A Rhizome bundle's *payload* is a contiguous sequence of one or more bytes.

A zero-length payload is represented as "no payload" (`filesize=0`).

The interpretation of a payload's contents depends on the *service* that
created the bundle (and can therefore also deal with it), whether or not the
payload is encrypted (`crypt=1`), and other optional fields (eg, `name`) that
the creator added to the manifest.

[SHA-512]: https://en.wikipedia.org/wiki/SHA-2

### Journal

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

The [Rhizome insert](#post-restfulrhizomeinsert) operation enforces these
rules if it has access to a prior version of the journal, but this cannot
provide a guarantee, since an update could be performed in the absence of a
prior version, in which case the rules cannot be checked.

The Rhizome transport takes advantage of the append-only property of journals
by only transferring the newly-appended end of a payload (the “head”) during
synchronisation.  The Rhizome store reclaims space from the stored payloads of
journals by discarding bytes over which the tail has advanced.

Rhizome REST API common features
--------------------------------

### Rhizome HTTP content types

#### rhizome/manifest

Serval DNA [POST][] requests that take [Rhizome manifest](#manifest) parameters
use the non-standard **rhizome/manifest** content type in the parameter's [form
part][].  See the [insert request](#post-restfulrhizomeinsert) for an example.

Serval DNA also uses this content type when it returns a manifest in an HTTP
response.  See the [get manifest request](#get-restfulrhizomebidrhm) for an
example.

Currently only one format is supported, denoted **text+binarysig**, which must
be explicitly specified, so the correct [Content-Type][] header is:

    Content-Type: rhizome/manifest; format=text+binarysig

This format is described in detail in the [manifest](#manifest) section.

In future, other formats may be supported, for example, all-binary or all-text.

#### rhizome/bid

Serval DNA [POST](#post) requests that take [Bundle ID](#bundle-id) parameters
use the non-standard **rhizome/bid** content type in the parameter's [form
part](#multipart-form-data).  See the [insert request](#post-restfulrhizomeinsert)
for an example.

At present only the **hex** format is supported, and must be explicitly
specified.  A missing or different format will cause a [415 Unsupported Media
Type][415] response.  The correct [Content-Type][] header is:

    Content-Type: rhizome/bid; format=hex

Hex format parameter values may only contain ASCII characters from the set
`0123456789ABCDEFabcdef`; any other character (such as a trailing newline) will
cause a [400 Bad Request][400] response.

In future other formats may be supported, such as Base-64, 7-bit binary, or
8-bit binary.

#### rhizome/bundlesecret

Serval DNA [POST](#post) requests that take [bundle secret](#bundle-secret)
parameters use the non-standard **rhizome/bundlesecret; format=hex** content
type in the parameter's [form part](#multipart-form-data).  See the [insert
request](#post-restfulrhizomeinsert) for an example.

At present only the **hex** format is supported, and must be explicitly
specified.  A missing or different format will cause a [415 Unsupported Media
Type][415] response.  The correct [Content-Type][] header is:

    Content-Type: rhizome/bundlesecret; format=hex

Hex format parameter values may only contain ASCII characters from the set
`0123456789ABCDEFabcdef`; any other character (such as a trailing newline) will
cause a [400 Bad Request][400] response.

In future other formats may be supported, such as Base-64, 7-bit binary, or
8-bit binary.

### Rhizome HTTP response headers

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

### Rhizome HTTP response bundle headers

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
result][] object as the HTTP response content:

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

### Bundle status code

All Rhizome operations that involve fetching and/or inserting a single manifest
into the Rhizome store return a *bundle status code*, which describes the
outcome of the operation.  Some codes have different meanings in the context of
a fetch or an insertion, and some codes can only be produced by insertions.
The bundle status code determines the [HTTP response code](#response-status-code).

| code |   HTTP  | meaning                                                                         |
|:----:|:-------:|:------------------------------------------------------------------------------- |
|  -1  | [500][] | internal error                                                                  |
|   0  | [201][] | “new”; (fetch) bundle not found; (insert) bundle added to store                 |
|   1  | [200][] | “same”; (fetch) bundle found; (insert) bundle already in store                  |
|   2  | [200][] | “duplicate”; (insert only) duplicate bundle already in store                    |
|   3  | [202][] | “old”; (insert only) newer version of bundle already in store                   |
|   4  | [422][] | “invalid”; (insert only) manifest is malformed or invalid                       |
|   5  | [419][] | “fake”; (insert only) manifest signature is invalid                             |
|   6  | [422][] | “inconsistent”; (insert only) manifest filesize/filehash does not match payload |
|   7  | [202][] | “no room”; (insert only) doesn't fit; store may contain more important bundles  |
|   8  | [419][] | “readonly”; (insert only) cannot modify manifest because secret is unknown      |
|   9  | [423][] | “busy”; Rhizome store database is currently busy (re-try)                       |
|  10  | [422][] | “manifest too big”; (insert only) manifest size exceeds limit                   |

### Bundle status message

The *bundle status message* is a short English text that explains the meaning
of its accompanying *bundle status code*, to assist with diagnosis.  The
message for a code may differ across requests and may change when [Serval
DNA][] is upgraded, so it cannot be relied upon as a means to programmatically
detect the outcome of an operation.

### Payload status code

All Rhizome operations that involve fetching and/or inserting a single payload
into the Rhizome store return a *payload status code*, which describes the
outcome of the payload operation, and elaborates on the the reason for the
accompanying *bundle status code*.  Some codes have different meanings in the
context of a fetch or an insertion, and some codes can only be produced by
insertions.  The payload status code overrides the [HTTP response
code](#response-status-code) derived from the [bundle status
code](#bundle-status-code) if it is numerically higher.

| code |   HTTP  | meaning                                                                    |
|:----:|:-------:|:-------------------------------------------------------------------------- |
|  -1  | [500][] | internal error                                                             |
|   0  | [201][] | "empty"; zero length payload                                               |
|   1  | [201][] | "new"; (fetch) payload not found; (insert) payload added to store          |
|   2  | [200][] | "found"; (fetch) payload found; (insert) payload already in store          |
|   3  | [422][] | "wrong size"; payload size does not match manifest *filesize* field        |
|   4  | [422][] | "wrong hash"; payload hash does not match manifest *filehash* field        |
|   5  | [419][] | "key unknown"; (fetch) cannot decrypt; (insert) cannot encrypt             |
|   6  | [202][] | "too big"; (insert only) payload is too big to fit in store                |
|   7  | [202][] | "evicted"; (insert only) payload evicted; other payloads are ranked higher |
|   8  | [423][] | "busy"; Rhizome store database is currently busy (re-try)                  |

### Payload status message

The *payload status message* is short English text that explains the meaning of
its accompanying *payload status code*, to assist diagnosis.  The message for a
code may differ across requests and may change when [Serval DNA][] is upgraded,
so it cannot be relied upon as a means to programmatically detect the outcome
of an operation.

Rhizome REST API operations
---------------------------

### GET /restful/rhizome/bundlelist.json

This request allows a client to discover all the bundles currently held in the
local Rhizome store.

Fetches a list of all bundles currently in [Serval DNA][]'s Rhizome store, in
order of descending insertion time starting with the most recently inserted.
The list is returned in the body of the [response](#response) in [JSON table][]
format with the following columns:

*  `.token` - either *null* or a string value that can be used as the token in
   a [newsince](#get-restfulrhizomenewsincetokenbundlelistjson) request.

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

*  `.author` - the [SID][] of the local (unlocked) identity that created the
   bundle; either a string containing 64 hexadecimal digits, or *null* if the
   [bundle author](#bundle-author) cannot be deduced.  In the case of *null*,
   the `.fromhere` field will be 0 (“not authored here”).  In the case of a
   SID, the `.fromhere` indicates whether authorship was absent, likely or
   certain.

*  `.fromhere` - an integer flag that indicates whether the bundle was authored
   on the local device:

   *  `0` (“absent”) means that the bundle was not authored by any unlocked
      identity on this device.

   *  `1` (“likely”) means that the author whose [SID][] is given in the
      `.author` field is present in the local keyring but authorship (the
      manifest's signature) has not been cryptographically verified, so
      attempting to update this bundle may yet fail.  This is the usual value
      because cryptographic verification is not performed while listing
      bundles, since it is slow and costly in CPU and battery.

   *  `2` (“certain”) means that the author whose [SID][] is given in the
      `.author` field is present in the local keyring and has been
      cryptographically verified as the true author of the bundle, ie, yields a
      correct [Bundle Secret](#bundle-secret).  This value will usually only be
      returned for locally-authored bundles that have recently been examined
      individually (eg, [GET /restful/rhizome/BID.rhm](#get-restfulrhizomebidrhm)),
      if Serval DNA has cached the result of the verification in memory.

*  `filesize` - the number of bytes in the bundle's payload; an integer zero or
   positive with a maximum value of 2^64 − 1.

*  `filehash` - if the bundle has a non-empty payload, then the [SHA-512][]
   hash of the payload content; a string containing 128 hexadecimal digits,
   otherwise *null* if the payload is empty (*filesize* = 0).

*  `sender` - the [SID][] of the bundle's sender; either a string containing 64
   hexadecimal digits, or *null* if the manifest has no *sender* field.

*  `recipient` - the [SID][] of the bundle's recipient; either a string
   containing 64 hexadecimal digits, or *null* if the manifest has no
   *recipient* field.

*  `name` - the string value of the manifest's *name* field, or *null* if the
   manifest has no *name* field.

### GET /restful/rhizome/newsince[/TOKEN]/bundlelist.json

This request allows a client to receive near-real-time notification of
newly-arriving Rhizome bundles.

Fetches a list of all bundles currently in [Serval DNA][]'s Rhizome store, in
order of ascending insertion time, since (but not including) the bundle
identified by TOKEN. If present, TOKEN must be a value taken from the non-null `.token`
field of any previous *bundlelist.json* request.

The list is returned in the body of the [response](#response) in [JSON table][]
format, exactly the same as [GET /restful/rhizome/bundlelist.json](#get-restfulrhizomebundlelistjson),
but with the following differences:

*  Bundles are listed in order of *ascending*, not *descending*, insertion
   time, ie, the most recent last.

*  Once all bundles have been listed, the response does not finish immediately,
   but blocks for approximately 60 seconds while waiting for new bundles to
   appear (get added to the Rhizome store).

*  The final “]}” of the [JSON table][] “rows” array and top-level object are
   not sent until the response finishes, so in order to make proper use of this
   request, the client must be able to incrementally parse partial JSON as it
   arrives.

### GET /restful/rhizome/BID.rhm

Fetches the manifest for the bundle whose id is `BID` (64 hex digits), eg:

    /restful/rhizome/1702BD647D614DB72C36BD634B6870CA31040C2EEC5069AEC0C0841D0CC671BE.rhm

If the **manifest is found** in the local Rhizome store, then the response will
be [200 OK][200] and:

*  the [bundle status code](#bundle-status-code) for "same"
*  the [payload status code](#payload-status-code), if present in the response,
   is not relevant, so must be ignored
*  the [bundle headers](#rhizome-http-response-bundle-headers) give information
   about the found bundle, some of which is duplicated from the manifest
*  the response's Content-Type is [rhizome/manifest](#rihzomemanifest)
*  the response's Content-Length is the size, in bytes, of the entire manifest,
   including its binary signature
*  the response's content is the Rhizome [manifest](#manifest)

If the **manifest is not found** in the local Rhizome store, then the response
will be [404 Not Found][404] and:

*  the [bundle status code](#bundle-status-code) for "new"
*  the [payload status code](#payload-status-code), if present in the response,
   is not relevant, so must be ignored
*  the [bundle headers](#rhizome-http-response-bundle-headers) are absent from
   the response
*  the response's content is the [Rhizome JSON result](#rhizome-json-result)
   object

### GET /restful/rhizome/BID/raw.bin

Fetches the "raw" (encrypted) payload for the bundle whose id is `BID` (64 hex
digits), eg:

    /restful/rhizome/1702BD647D614DB72C36BD634B6870CA31040C2EEC5069AEC0C0841D0CC671BE/raw.bin

If the **manifest and the payload are both found** in the local Rhizome store,
then the response will be [200 OK][200] and:

*  the [bundle status code](#bundle-status-code) for "same"
*  the [payload status code](#payload-status-code) for "empty" if the payload
   has zero length, otherwise "found"
*  the [bundle headers](#rhizome-http-response-bundle-headers) give information
   about the found bundle, some of which is duplicated from
   the manifest
*  the response's Content-Type is **application/octet-stream**
*  the response's Content-Length is the size, in bytes, of the raw payload
*  the response's content is the bundle's payload exactly as stored in Rhizome;
   if the payload is encrypted (the manifest's `crypt` field is 1) then the
   payload is not decrypted

If the **manifest is not found** in the local Rhizome store, then the response
will be [404 Not Found][404] and:

*  the [bundle status code](#bundle-status-code) for "new"
*  the [payload status code](#payload-status-code), if present in the response,
   is not relevant, so must be ignored
*  the [bundle headers](#rhizome-http-response-bundle-headers) are absent from
   the response
*  the response's content is the [Rhizome JSON result](#rhizome-json-result)
   object

If the **manifest is found** in the local Rhizome store but the **payload is
not found**, then the response will be [404 Not Found][404] and:

*  the [bundle status code](#bundle-status-code) for "same"
*  the [payload status code](#payload-status-code) for "new"
*  the [bundle headers](#rhizome-http-response-bundle-headers) give information
   about the found manifest
*  the response's content is the [Rhizome JSON result](#rhizome-json-result)
   object

### GET /restful/rhizome/BID/decrypted.bin

Fetches the decrypted payload for the bundle whose id is `BID` (64 hex digits),
eg:

    /restful/rhizome/1702BD647D614DB72C36BD634B6870CA31040C2EEC5069AEC0C0841D0CC671BE/decrypted.bin

If the **manifest and payload are both found** and the payload is **encrypted**
(the manifest's `crypt` field is 1), then the *payload secret* is determined as
follows:

*  if the manifest has both *sender* and *recipient* [SID][]s:

   *  if the recipient's identity is found (unlocked) in the keyring, then the
      secret is derived from the recipient's [Serval ID](#serval-id) secret;
      otherwise
   *  if the recipient's identity is not found in the keyring (locked or missing)
      but the sender's identity is found (unlocked) in the keyring, then the
      secret is derived from the sender's [Serval ID](#serval-id) secret;
      otherwise
   *  if neither identity is found in the keyring (both are locked or missing),
      then the the payload secret is unknown.

*  otherwise, the payload secret is derived directly from the [Bundle
   Secret](#bundle-secret), which in turn is deduced from the `BK` [Bundle
   Key](#bundle-key) field in the manifest, if present, as long as the bundle's
   author can be found (unlocked) in the keyring.  If there is no `BK` field,
   or if no unlocked identity in the keyring can provide the necessary [Rhizome
   Secret](#rhizome-secret), then the payload secret is unknown.

The responses are identical to [GET /restful/rhizome/BID/raw.bin](get-restfulrhizomebidrawbin),
with the following variations:

If the **payload is encrypted** and the **payload secret is known**, then
the response will be [200 OK][200] and:

*  the [bundle status code](#bundle-status-code) for "same"
*  the [payload status code](#payload-status-code) for "empty" if the decrypted
   payload has zero length, otherwise "found"
*  the [bundle headers](#rhizome-http-response-bundle-headers) give information
   about the found bundle, some of which is duplicated from the manifest
*  the response's Content-Type is **application/octet-stream**
*  the response's Content-Length is the size, in bytes, of the decrypted
   payload
*  the response's content is the bundle's decrypted payload

If the **payload is encrypted** and the **payload secret is not known** then:

*  the request will fail with status [419 Authentication Timeout][419]
*  the [bundle headers](#rhizome-http-response-bundle-headers) give information
   about the found manifest
*  the response body is a [Rhizome JSON result](#rhizome-json-result) object,
   in which:
   *  the [bundle status code](#bundle-status-code) is for "new"
   *  the [payload status code](#payload-status-code) is for "key unknown"

### POST /restful/rhizome/insert

The Rhizome insert [POST][] request allows a client to add a new bundle to the
Rhizome store, or update an existing bundle in the store.  This request cannot
be used to create or update [journals](#journal); use the
[append](#post-restfulrhizomeappend) request instead.

This request does not accept any [query parameters][] in the *path*, but does
accept parameters using a [Content-Type][] of [multipart/form-data][], in which
each parameter has its own content type.  For example:

        POST /restful/rhizome/insert HTTP/1.0
        Content-Type: multipart/form-data;boundary=OoOoOoOo
        
        --OoOoOoOo
        Content-Disposition: form-data; name=bundle-author
        Content-Type: serval/sid;format=hex
        
        3DA7BA5E97DF4918DB5528450875EC9F788F0C37BC2603FD1BA7FF276C575018
        --OoOoOoOo
        Content-Disposition: form-data; name=manifest
        Content-Type: rhizome/manifest;format=text+binarysig
        
        service=file
        name=helloworld.txt
        
        --OoOoOoOo
        Content-Disposition: form-data; name=payload; filename="helloworld.txt"
        Content-Type: application/octet-stream
        
        Hello world!
        
        --OoOoOoOo--

The parameters are all optional under various conditions:

*  **bundle-id** = the [Bundle ID](#bundle-id) of an existing bundle to update:
   *  64 hexadecimal digits
   *  [Content-Type][] must be [rhizome/bid](#rhizomebid)
   *  if the bundle currently exists in the Rhizome store then a copy of its
      manifest is used as the basis of the new bundle, omitting its `version`,
      `filesize`, `filehash` fields (which must be supplied or inferred anew).

*  **bundle-author** = the [SID][] of the bundle's [author](#bundle-author):
   *  64 hexadecimal digits;
   *  [Content-Type][] must be [serval/sid][]
   *  the bundle author sets (or removes) the bundle's `BK` field, overriding
      any `BK` field in the partial manifest supplied in the *manifest*
      parameter or in the existing bundle nominated by the *bundle-id*
      parameter;
   *  if there is no unlocked identity in the keyring with the given SID, then
      the new bundle will be an *anonymous* bundle with no `BK` field;
   *  this parameter must come before the *manifest* parameter, otherwise the
      request fails with status [400 Bad Request][400] and the message
      ‘Spurious "bundle-id" form part’.

*  **bundle-secret** = the [Bundle Secret](#bundle-secret):
   *  64 hexadecimal digits
   *  [Content-Type][] must be [rhizome/bundlesecret](#rhizomebundlesecret)
   *  is needed in order to create a bundle with a specific [Bundle ID](#bundle-id)
      (supplied in the *manifest* parameter), or to update an existing bundle
      that is anonymous or the author is not a currently unlocked identity in
      the keyring.

*  **manifest** = a partial, unsigned [manifest](#manifest):
   *  [Content-Type][] must be [rhizome/manifest](#rhizomemanifest)
   *  the fields in this manifest are used to form the new bundle's manifest,
      overwriting the fields of any existing manifest specified by the
      *bundle-id* parameter, if given.

*  **payload** = the content of the new bundle's payload:
   *  [Content-Type][] is currently ignored, but in future it may be used to
      determine the default values of some manifest fields;
   *  this parameter must come after the *manifest* parameter, otherwise the
      request fails with status [400 Bad Request][400] and the message ‘Missing
      "manifest" form part’;
   *  the *payload* parameter must not be supplied if the `filesize` field in
      the *manifest* parameter is zero.

The response body is always a [Rhizome JSON result](#rhizome-json-result)
object, and the [bundle headers](#rhizome-http-response-bundle-headers) give
information about the manifest.

The insertion logic proceeds in the following steps:

1.  If a *bundle-id* parameter was supplied and the given bundle exists in the
    Rhizome store, then the new bundle's manifest is initialised by copying all
    the fields from the existing manifest.

2.  If a partial manifest was supplied in the *manifest* parameter, then its
    fields are copied into the new manifest, overwriting any that were copied
    in step 1.  If the partial manifest is malformed (syntax error) or contains
    a core field with an invalid value, then the request fails with status [422
    Unprocessable Entity][422] and the [bundle status code](#bundle-status-code)
    for “invalid”.

3.  If the `tail` field is present in the new manifest then the new bundle is a
    [journal](#journal), so the request fails with status [422 Unprocessable
    Entity][422] and the [bundle status code](#bundle-status-code) for
    “invalid”.  Journals can only be created and updated using the
    [append](#post-restfulrhizomeappend) request.

4.  If the *bundle-secret* parameter was supplied, then a public key
    ([Bundle ID](#bundle-id)) is derived from the [Bundle Secret](#bundle-secret),
    and:

    * if the new manifest has no `id` field, then the `id` field is set to the
      derived public key;

    * otherwise, if the new manifest's `id` field is not equal to the derived
      public key, then the supplied secret is wrong, so the request fails with
      status [419 Authentication Timeout][419] and the [bundle status
      code](#bundle-status-code) for “readonly”;

    Otherwise, if no *bundle-secret* parameter was supplied:

    * if the new manifest has no `id` field, then a new [Bundle Secret](#bundle-secret)
      is generated randomly, the [Bundle ID](#bundle-id) is derived from the
      new Bundle Secret, and the `id` field set to that Bundle ID;

    * if the new manifest already has an `id` field but no `BK` field
      ([Bundle Key](#bundle-key)) (ie, the bundle is *anonymous*), then the
      [Bundle Secret](#bundle-secret) cannot be discovered, so the request
      fails with status [419 Authentication Timeout][419] and the [bundle
      status code](#bundle-status-code) for “readonly”.

    * otherwise, if the *bundle-author* parameter was given, then that [SID][]
      is looked up in the keyring.  If the identity is found, then the [Bundle
      Secret](#bundle-secret) is derived from the combination of the `BK` field
      ([Bundle Key](#bundle-key)) with the identity's [Rhizome
      Secret](#rhizome-secret), and the [Bundle ID](#bundle-id) is derived from
      the Bundle Secret.  If the identity was not found or the derived Bundle
      ID does not equal the `id` field then the request fails with status [419
      Authentication Timeout][419] and the [bundle status
      code](#bundle-status-code) for “readonly”.

    * otherwise, if no *bundle-author* parameter was given but the manifest has
      a `BK` field, then the keyring is searched for an identity whose [Rhizome
      Secret](#rhizome-secret) combined with the `BK` field ([Bundle
      Key](#bundle-key)) produces a [Bundle Secret](#bundle-secret) whose
      derived [Bundle ID](#bundle-id) matches the `id` field.  The search
      starts with the identity given by the `sender` field, if present.  If
      none is found, then the request fails with status [419 Authentication
      Timeout][419] and the [bundle status code](#bundle-status-code) for
      “readonly”, otherwise the author is deduced to be the found identity.

    * otherwise, if no *bundle-author* parameter was given and the manifest has
      no `BK` field, then an *anonymous* bundle is produced, ie, with no `BK`
      key.

5.  If the *bundle-author* parameter was given and step 4 set the `id` field
    (either derived from the *bundle-secret* parameter or randomly generated),
    then the *bundle-author* [SID][] is looked up in the keyring.  If not
    found, then the request fails with status [419 Authentication Timeout][419]
    and the [bundle status code](#bundle-status-code) for “readonly”.  If
    found, then the author's [Rhizome Secret](#rhizome-secret) is used to
    calculate the [Bundle Key](#bundle-key) and set the `BK` field.

6.  The following fields are initialised if they are missing:

    *  `service` to the value `file`
    *  `version` to the current [Unix time][] in milliseconds since the epoch
    *  `date` to the current [Unix time][] in milliseconds since the epoch
    *  `crypt` to `1` if the `sender` and `recipient` fields are both set

7.  If the *payload* parameter is given and is non-empty, then its value is
    stored in the store, and its size and [SHA-512][] digest computed.  If the
    manifest is missing either or both of the `filesize` and `filehash` fields,
    then the missing ones are filled in from the computed values.  If the
    manifest `filesize` or `filehash` fields do not match the computed values,
    then the request fails with status [422 Unprocessable Entity][422] and the
    [bundle status code](#bundle-status-code) for “inconsistent”.

8.  If the manifest is not [valid](#valid-manifest) then the request fails with
    status [422 Unprocessable Entity][422] and the [bundle status
    code](#bundle-status-code) for “invalid”.

9.  If step 4 set the `id` field (either derived from the *bundle-secret*
    parameter or randomly generated) and the bundle is a *duplicate* of a
    bundle that is already in the store, then the request finishes with status
    [200 OK][200] and the [bundle status code](#bundle-status-code) for
    “duplicate”.  Bundles are considered duplicates if they have:

    *  an identical payload (identical `filesize` and `filehash` fields), and
    *  the same `service` field, and
    *  the same `name` field, and
    *  the same `sender` field, and
    *  the same `recipient` field.

10. The manifest is signed using the [Bundle Secret](#bundle-secret), and the
    signature appended to the manifest after a single ASCII NUL (0) separator
    byte.  If the result exceeds the maximum manifest size (8 KiB) then the
    request fails with status [422 Unprocessable Entity][422] and the [bundle
    status code](#bundle-status-code) for “manifest too big”.

11. If the Rhizome store already contains a manifest with the same
    [Bundle ID](#bundle-id), then its version is compared with the new
    manifest's version.

    *  If they have the same version, then the new manifest is not stored, and
       the request returns status [200 OK][200] and the [bundle status
       code](#bundle-status-code) for “same”.

    *  If the new manifest's version is less than the stored manifest's, then
       the new manifest is not stored, and the request returns status [202
       Accepted][202] and the [bundle status code](#bundle-status-code) for
       “old”.

12. Otherwise, the new manifest is stored in the Rhizome store, replacing any
    existing manifest with the same [Bundle ID](#bundle-id).  The request
    returns status [201 Created][201] and the [bundle status
    code](#bundle-status-code) for “new”.

### POST /restful/rhizome/append

This request allows a client to add a new [journal bundle](#journal) to the
Rhizome store, or update an existing one.  It takes exactly the same parameters
as the [insert](#post-restfulrhizomeinsert) operation, to which it is
identical in all respects except as follows:

The steps of the insertion logic have these variations:

1.  If the *bundle-id* parameter specifies an existing manifest, then the
    `version`, `filesize` and `filehash` fields are not copied from the
    existing manifest to the new manifest.

2.  The validity checks on any partial manifest given in the *manifest*
    parameter will also fail if the partial manifest contains a `version`,
    `filesize` or `filehash` field.  After the partial manifest has been copied
    into the new manifest, if the *bundle-id* parameter was not given or
    specified a bundle that was not found in the store (step 1), then the
    `filesize` and `tail` fields are initialised to zero (0) if they are
    missing.

3.  If the `tail` field is missing from the new manifest then the bundle is not
    a [journal](#journal), so the request fails with status [422 Unprocessable
    Entity][422] and the [bundle status code](#bundle-status-code) for
    “invalid”.

4.  No change.

5.  No change.

6.  No change.

7.  After the payload has been stored, the `filesize` and `filehash` fields are
    always set, overriding any that were already present.  Also, the `version`
    is always set to `tail + filesize`.

8.  No change.

9.  No change.

10. No change.

11. No change.

12. No change.

### POST /restful/rhizome/import

The import [POST](#post) request allows the client to store a valid bundle
(manifest and payload) in the store that may have been obtained through some
other means, such as exporting from another store using the [manifest
request](#get-restfulrhizomebidrhm) and the [raw payload
request](#get-restfulrhizomebidrawbin).

The response body is always a [Rhizome JSON result](#rhizome-json-result)
object, and the [bundle headers](#rhizome-http-response-bundle-headers) give
information about the imported manifest, whether or not it was already present
in the store.

This request accepts the following optional [query parameters][] in the *path*:

*  **id** = the [ID](#bundle-id) of the bundle
*  **version** = the [version](#bundle-version) of the bundle

Both query parameters must be supplied together, or neither.  If only one is
supplied, or has an invalid value, then then the request fails with status [400
Bad request][400] and a message like ‘Missing "id" parameter’ or ‘Invalid
"version" parameter’.

This request also accepts the following parameters using a [Content-Type][] of
[multipart/form-data][], in which each parameter has its own content type:

*  **manifest** (required) = a signed [manifest](#manifest):
   *  [Content-Type][] must be [rhizome/manifest](#rhizomemanifest);
   *  if the **id** and **version** query parameters were supplied, then their
      values must match the corresponding manifest fields.

*  **payload** = the content of the bundle's payload:
   *  the *payload* parameter must be supplied if the `filesize` field in the
      *manifest* parameter is non-zero, otherwise it must not be supplied;
   *  this parameter must come after the *manifest* parameter, otherwise the
      request fails with status [400 Bad Request][400] and the message ‘Missing
      "manifest" form part’;
   *  [Content-Type][] is currently ignored, but in future it may be used to
      determine the default values of some manifest fields;
   *  if the bundle is encrypted (the manifest `crypt` field is 1) then the
      payload must be in encrypted form, not plain text.

The import logic proceeds in the following steps:

1.  If the `id` and `version` [query parameters][] were given, then check if the
    store already contains a bundle with that [Bundle ID](#bundle-id) and
    [Bundle version](#bundle-version).  If so, then the request succeeds with
    status [200 OK][200] and:
    *  the remaining body of the request will not be read
    *  the [bundle status code](#bundle-status-code) is "same"
    *  the [payload status code](#payload-status-code) is "empty" if the
       payload has zero length, otherwise "found"
    *  the only [bundle headers](#rhizome-http-response-bundle-headers) in the
       response are:
       *  `Serval-Rhizome-Bundle-Id`
       *  `Serval-Rhizome-Bundle-Version`
       *  `Serval-Rhizome-Bundle-Filesize`

2.  As soon as the `manifest` form part is received, if the manifest is not
    [valid](#valid-manifest) or if the `id` and `version` query parameters were
    supplied but do not match the `id` and `version` fields of the manifest,
    then the request fails with status [422 Unprocessable Entity][422] and the
    [bundle status code](#bundle-status-code) for “invalid”.

3.  If the manifest's signature does not verify, then the request fails with
    status [419 Authentication Timeout][419] and the  [bundle status
    code](#bundle-status-code) for “fake”.

4.  If the *payload* form part is provided and is non-empty, then its content
    is stored in the store, and its size and [SHA-512][] digest computed.  If
    the manifest `filesize` and `filehash` fields do not match the computed
    values, then the request fails with status [422 Unprocessable Entity][422]
    and the [bundle status code](#bundle-status-code) for “inconsistent”.

5.  If the Rhizome store already contains a manifest with the same
    [Bundle ID](#bundle-id), then its version is compared with the new
    manifest's version.

    *  If they have the same version, then the new manifest is not stored, and
       the request returns status [200 OK][200] and the [bundle status
       code](#bundle-status-code) for “same”.

    *  If the new manifest's version is less than the stored manifest's, then
       the new manifest is not stored, and the request returns status [202
       Accepted][202] and the [bundle status code](#bundle-status-code) for
       “old”.

6.  Otherwise, the new manifest is stored in the Rhizome store, replacing any
    existing manifest with the same [Bundle ID](#bundle-id).  The request
    returns status [201 Created][201] and the [bundle status
    code](#bundle-status-code) for “new”.

### GET /restful/rhizome/storestatus.json

Fetch on the current disk usage of the rhizome store.

The results will be a single json object with the following fields;

* `external_bytes` - the total size of all payloads larger than
  rhizome.max_blob_size, that have been stored outside of sqlite, in the
  rhizome blob folder.

* `db_page_size` - the size of disk pages returned by sqlite.

* `db_total_pages` - the number of disk pages in the sqlite database file.

* `db_available_pages` - the number of disk pages in the sqlite database file
  that have been allocated but are not currently in use.

* `content_bytes` - the total bytes of space used in the sqlite database, and
  in payloads stored outside of sqlite. This should be equal to;
  db_page_size * (db_total_pages - db_available_pages) + external_bytes

* `content_limit_bytes` - the calculated storage limit that is being applied.
  This will be the smallest of the configured rhizome.database_size or the
  maximum we can store while keeping rhizome.min_free_space available for
  other uses.

* `filesystem_bytes` - the measured total size of the filesystem where the
  rhizome store is located.

* `filesystem_free_bytes` - the measured free space of the filesystem.

-----
**Copyright 2015-2017 Serval Project Inc.**  
![CC-BY-4.0](./cc-by-4.0.png)
Available under the [Creative Commons Attribution 4.0 International licence][CC BY 4.0].


[Serval Project]: http://www.servalproject.org/
[CC BY 4.0]: ../LICENSE-DOCUMENTATION.md
[Rhizome]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:rhizome
[BID]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:bid
[Serval Mesh network]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:mesh_network
[Serval DNA]: ../README.md
[REST-API]: ./REST-API.md
[form part]: ./REST-API.md#multipart-form-data
[POST]: ./REST-API.md#post
[JSON result]: ./REST-API.md#json-result
[store and forward]: https://en.wikipedia.org/wiki/Store_and_forward
[SID]: ./REST-API-Keyring.md#serval-id
[Keyring]: ./REST-API-Keyring.md
[MeshMS]: ./REST-API-MeshMS.md
[MeshMS conversations]: ./REST-API-MeshMS.md#conversation
[JSON table]: ./REST-API.md#json-table
[Curve25519]: https://en.wikipedia.org/wiki/Curve25519
[Unix time]: https://en.wikipedia.org/wiki/Unix_time
[Y2038 problem]: https://en.wikipedia.org/wiki/Year_2038_problem
[query parameters]: https://en.wikipedia.org/wiki/Query_string
[Content-Type]: ./REST-API.md#content-type-header
[multipart/form-data]: ./REST-API.md#multipartform-data
[serval/sid]: ./REST-API.md#servalsid
[200]: ./REST-API.md#200-ok
[201]: ./REST-API.md#201-created
[202]: ./REST-API.md#202-accepted
[400]: ./REST-API.md#400-bad-request
[404]: ./REST-API.md#404-not-found
[415]: ./REST-API.md#415-unsupported-media-type
[419]: ./REST-API.md#419-authentication-timeout
[422]: ./REST-API.md#422-unprocessable-entity
[423]: ./REST-API.md#423-locked
[500]: ./REST-API.md#500-server-error
