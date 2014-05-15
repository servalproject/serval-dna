Mesh Streaming Protocol (MSP)
=============================
[Serval Project], May 2014

The [Mesh Streaming Protocol][MSP] is a network protocol developed for the
[Serval mesh network][], with characteristics that make it particularly
suitable for use in Ad Hoc wireless networks, which can suffer high levels of
packet loss due to weak signal, interference and congestion.

MSP provides a two-way, reliable, ordered stream of messages between a pair of
end points, which can be used to transfer files, conduct an HTTP session, or
carry quasi-real-time streaming data, similar to [TCP][].

MSP was funded by a [grant][] from the [New America Foundation][NAF]'s [Open
Technology Institute][OTI].

**Copyright 2014 Serval Project Inc.**  All rights reserved.

Caveat
------

MSP is a work in progress, and has not been subjected to rigorous testing, so
expect speed humps and sub-optimal performance depending on your operating
conditions.  Please report any issues that you may encounter so that MSP can be
improved for all users.

Protocol description
--------------------

An MSP connection is a two-way ordered stream of messages between a pair of end
points in the [Serval mesh network][].  Each node is identified by its [SID][],
and each end point is an [MDP port][] on its node.  A message is a sequence of
bytes with a minimum length of 1 and a maximum length which is several bytes
short of the underlying [MDP][] [MTU][].  Zero-length messages are not carried.

Every single *send* operation on one end point produces a single *receive* on
the other.  In other words, an MSP message stream is a stream of bytes that
preserves write boundaries as read boundaries.  Any application can easily use
an MSP connection as a simple ordered byte stream, like [TCP][], by ignoring
incoming message boundaries and buffering all input and output.  (In future, an
MSP *buffered* mode may be provided to facilitate this.)

[MSP][] is built on the [Mesh Datagram Protocol][MDP] which carries packets
unreliably between the two end points.  MSP uses a combination of [sliding
window][], [ACK][], [timeout][] and retransmission to achieve reliable delivery
despite dropped MDP packets.

MSP does not have any broadcast or multicast mode, so all data is always
encrypted end-to-end and the originating address ([SID][]) is always
authenticated. Since encryption doesn't depend on negotiating a session token,
the first few packets of data can be sent without waiting to discover whether
the connection attempt has been successful.

In future, MSP may use [linear network coding][] to reduce timeouts and
retransmissions, thereby keeping end-to-end latency down, even under conditions
that would typically cause [TCP][] to time out, retransmit and thereby increase
latency and drive up congestion.  Linear network coding works by dedicating a
certain proportion of bandwidth to redundant re-transmissions up front, which
keeps the probability of first-time packet arrival relatively high.

MSP API
-------

**Note**: The MSP protocol and its API are currently provisional, and will
evolve as development continues.  Provisional versions of MSP may not be
compatible with successive versions, so applications developed using a
provisional version MSP may have to be re-written, re-compiled and/or re-linked
against a newer version of the API in order to remain interoperable.

MSP applications can operate in two modes:
 * *client* applications are started occasionally, and *connect* to remote
 * *server* applications, which typically run continuously, *listening* for
   clients to connect.

Synopses of client and server source code are shown separately below, but there
is nothing to prevent a single application acting as both a server and a
client, by listening on one [MDP port][] while also making outbound connections
to other server applications.  An example of this would be a distributed chat
room app, which allowed users to host their own chat rooms (server) and also
join in others hosted nearby (client).

### Including MSP in your program

The MSP API will eventually be available as a library which can be linked
either statically (at compile time) or dynamically (at run time) into an
executable.  For the time being, the MSP API is only available as an
intermediate object file, `msp_client.o`, produced by the [Serval DNA
build](../INSTALL.md), and hence is only available to programs that have access
to the built [Serval DNA source code][] at build time.

The entry points (functions), global variables and constants provided by and
required by the MSP client library are defined in the `msp_client.h` C header
file, which is also available as part of the [Serval DNA source code][].

The MSP API builds on the underlying [MDP API][].  All compile-time and
run-time requirements for that API also apply.

### Threading and asychronous i/o

The MSP client library is not [thread safe][] and does not create or use
threads internally.  The calling application must either not be multi threaded,
or the programmer must ensure that the MSP client library is never invoked by
more than one thread at the same time; typically this is achieved by avoiding
thread [preemption][] or using a [mutual exclusion][] mechanism.

The MSP client library depends on timed events to handle retransmissions and
detect connection failures.  The caller must schedule calls to handle these
events.  Although the MSP library could create a helper thread to generate
these calls automatically, it does not do this, and relies instead on the
programmer to invoke the *processing* function at appropriate times.  This
gives greater flexibility to developers by not forcing them to use
multi-threading, and it fits well into any mature, [event driven][]
[application framework][].

### “Undefined results”

If the MSP API is misused, *undefined results* may occur.  These may be
immediate or delayed, and may include but are not limited to: heap or stack
corruption, writing to standard error, creating, opening and writing a file,
invoking and waiting for a child process (typically to execute [gdb(1)][] to
obtain a stack trace), immediate termination of the calling process using
[abort(3)][], [exit(3)][] or [_exit(2)][], a segmentation or bus violation
signal, or any combination of the above.

### Synopsis - client application (connect)

An **MSP client** application connects to an MSP server at a known remote
address ([SID][] and [MDP port][]).  The following example illustrates a
rudimentary MSP client, showing when and how all the MSP API primitives must be
called.  The example's main loop is not [event driven][] and, for brevity,
omits details of how the remote address is obtained and omits error handling,
so should not be used as production code:

```
#include "msp_client.h"

static int quit = 0;
size_t outlen;
uint8_t outbuf[MSP_MESSAGE_SIZE];

size_t io_handler(MSP_SOCKET sock, msp_state_t state, const uint8_t *payload, size_t len, void *context) {
    int ret = 0;
    if (payload && len) {
        // ... process 'len' incoming bytes at 'payload' ...
        ret = ... number of bytes consumed ...
    }
    if (ret == len && (state & MSP_STATE_SHUTDOWN_REMOTE)) {
        // ... process incoming EOF ...
    }
    // ... produce 'outlen' outgoing bytes in 'outbuf' ...
    if ( outlen == 0 && ... no more data to send ... )
        msp_shutdown(sock);
    else if (state & MSP_STATE_DATA_OUT) {
        ssize_t sent = msp_send(sock, outbuf, outlen);
        if (sent == -1)
            msp_shutdown(sock); // premature end
        else {
            assert((size_t)sent <= outlen);
            // ... keep any unsent data to send again in next call ...
        }
    }
    if (state & (MSP_STATE_CLOSED | MSP_STATE_ERROR)) {
        // ... release resources ...
        quit = 1;
    }
    assert(ret <= len);
    return ret;
}

main() {
    int mdp_fd = mdp_socket();
    if (mdp_fd == -1)
        exit(1);
    MSP_SOCKET sock = msp_socket(mdp_fd, 0);
    if (!msp_socket_is_open(sock))
        exit(1);
    struct mdp_sockaddr addr;
    addr.sid = ... ;
    addr.port = ... ;
    msp_connect(sock, &addr);
    msp_set_handler(sock, io_handler, NULL);
    time_ms_t next_time = TIME_MS_NEVER_HAS;
    while (!quit) {
        time_ms_t now = gettime_ms();
        if (now < next_time) {
            struct timeval timeout = time_ms_to_timeval(next_time - now);
            setsockopt(mdp_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout);
            msp_recv(mdp_fd);
        }
        msp_processing(&next_time);
    }
    msp_close_all(mdp_fd);
    mdp_close(mdp_fd);
    exit(0);
}
```

### Synopsis - server application (listen)

An **MSP server** listens for and accepts connections from MSP client
applications, and in most respects has the same structure as a client
application.  The `main()` function differs only in how it sets up the
listening MSP socket: it sets the *local* address instead of the remote, and
sets a *listener* handler function that is called whenever a connection request
is received.  The listener handler creates a new MSP socket for the new inbound
connection and sets its i/o handler which is identical in structure to the
client example shown above, so is not shown below:

```
#include "msp_client.h"

// ... see "client" example above for io_handler() ...

size_t listen_handler(MSP_SOCKET sock, msp_state_t state, const uint8_t *payload, size_t len, void *context) {
    if (state & (MSP_STATE_ERROR | MSP_STATE_CLOSED))
        quit = 1;
    else {
        // ... set up resources needed for the new connection ...
        msp_set_handler(sock, io_handler, NULL);
        if (payload && len)
            return io_handler(sock, state, payload, len, NULL);
    }
    assert(len == 0);
    return 0;
}

main() {
    // ... as for "client" example above ...
    struct mdp_sockaddr addr;
    addr.sid = BIND_ALL;
    addr.port = ... ; // known by clients
    msp_set_local(sock, &addr);
    msp_set_handler(sock, listen_handler, NULL);
    msp_listen(sock);
    // ... as for "client" example above ...
}
```

### `MSP_SOCKET` - MSP socket handle
```
MSP_SOCKET sock = MSP_SOCKET_NULL;
int msp_socket_is_null(MSP_SOCKET sock);
int msp_socket_is_valid(MSP_SOCKET sock);
```

Each MSP socket is represented by a [handle][] of type `MSP_SOCKET`, which can
be assigned and copied freely, and is analagous to the [POSIX file
descriptor][] or the [standard C i/o][] [FILE pointer][].

The *null socket*, `MSP_SOCKET_NULL` is the same as all bytes zero, and is a
special MSP socket handle that does not refer to any socket.  This is analagous
to a file descriptor of -1 or a FILE pointer of `NULL`.

The implementation of `MSP_SOCKET` is specific to the platform, and is exposed
in the `msp_client.h` header.  Applications must only depend on the operations
and semantics described in this document, and must not rely on other specifics
of implementation.  In particular, the C comparison operators `==` and `!=` are
not supported for MSP socket handles, but assignment is supported.

The `msp_socket_is_null(sock)` function tests whether a socket handle is the
special `MSP_SOCKET_NULL` value, and can be applied at any time to any variable
of type `MSP_SOCKET`.

The `msp_socket_is_valid(sock)` function tests whether a socket handle refers
to a socket that has been created.  If a handle is null or has not been
initialised, then it is *invalid*.

Passing an invalid handle to an MSP primitive function will produce *undefined
results* unless otherwise stated.

### MSP socket life cycle

#### Initial state

Every newly-created MSP socket begins in the *initialising* state.

#### Opening

`msp_listen()` turns an *initialising* socket into an *open listening* socket.
`msp_connect()` turns an *initialising* socket into a *open data* socket.  Once
open, sockets cannot be changed; they remain *listening* or *data* for the
remainder of their lifetimes.  Every open socket remains open until *closed*.

#### Connecting

An *open data* socket is marked as *connected* when the first MDP packet is
received from its remote end.

*Listening* sockets do not connect, but instead create a new, *connected*,
*open data* socket each time a new connection is received from a remote node.

#### Shut down

An application may *locally shut down* an open data socket by calling
`msp_shutdown()`, which queues a *shutdown* message to the remote end, prevents
the socket from queueing more messages to send, and once all outbound messages
have been transmitted, stops the outbound direction of the connection.  The
inbound directon may continue.

When MSP receives a *shutdown* message from the remote end, it marks an open
data socket as *remotely shut down*, which means that the inbound direction of
the connection has been stopped and no more messages will be received, but the
outbound direction may continue.

The only way to shut down an open listening socket is to close it.

#### Closing

The `msp_processing()` function will close a data socket automatically once
both directions of the connection are shut down and all queued messages have
been delivered.  In this case, `msp_processing()` will invoke the socket's
handler function one last time with the CLOSED flag set.

The `msp_processing()` function will never close a listening socket
automatically; that must be done explicitly by the application.

An application may close any open socket at any time by calling `msp_close()`.
This will cause `msp_processing()` to stop both directions of an open data
socket without alerting the remote end point, discard all queued messages
locally, and invoke the socket's handler function one last time with the CLOSED
flag set.

#### Finalisation

Once a socket is closed, all handles to that socket may become invalid during
any subsequent call to `msp_processing()`, as it releases resources associated
with the socket.  Thus, a test for whether a socket is closed yet must test for
an invalid handle first (the `msp_socket_is_closed()` predicate does this).

#### No re-use

Sockets cannot be re-used.  Passing a closed or invalid socket to an MSP
primitive function which requires a valid socket will produce *undefined
results*.

### MSP socket predicates

The following *predicate* functions can all safely be called on any MSP socket
handle, even null and invalid handles.

#### State
```
int msp_socket_is_initialising(MSP_SOCKET sock);
int msp_socket_is_open(MSP_SOCKET sock);
int msp_socket_is_closed(MSP_SOCKET sock);
```
These functions are the safest way for an application to test a socket's state
particularly when outside a handler function.  At any given time, at least one
of the first three predicate functions above will return true on a given
socket.  `msp_socket_is_closed()` returns 1 on an invalid socket handle,
whereas the others all return 0.

#### Listening vs data
```
int msp_socket_is_listening(MSP_SOCKET sock);
int msp_socket_is_data(MSP_SOCKET sock);
```
`msp_socket_is_listening()` returns 1 on an *open listening* socket, 0 otherwise.
`msp_socket_is_data()` returns 1 on an *open data* socket, 0 otherwise.

#### Connection
```
int msp_socket_is_connected(MSP_SOCKET sock);
```
`msp_socket_is_connected()` returns 1 on an open data socket which has received
at least one MDP packet from the remote end, 0 otherwise.

#### Shut down
```
int msp_socket_is_shutdown_local(MSP_SOCKET sock);
int msp_socket_is_shutdown_remote(MSP_SOCKET sock);
```
These functions can only return true on a valid data socket; once a socket is
closed and the socket's handle invalidated, they return 0.  Note that a socket
may go into closed state without either of the shutdown predicates ever
becoming true, because a socket can be forcefully closed before both sides of
the connection are shut down.

### Socket initialisation primitives

#### `msp_socket()` - Create an MSP socket
```
MSP_SOCKET msp_socket(int mdp_fd, int flags);
```
Creates an MSP that uses the given MDP socket, which must remain open for at
least the lifetime of the MSP socket.  An MDP socket cannot be used by more
than one MSP socket, so each call to `msp_socket()` must be preceded by a call
to `mdp_socket()`.  See the [MDP API][] for information about the
`mdp_socket()` function.

The second argument to `msp_socket()` is a bit mask of flags.  At present no
flags are supported, and this argument must be zero.  If any unsupported bit is
set, then `mdp_socket()` will log an error and return a null handle.

If the MSP socket is successfully created, returns a handle for a new,
*initialising* socket.  If unsuccessful, then `mdp_socket()` will log an error
and return a null handle.

#### `msp_set_local()` - Bind local identity and port
```
void msp_set_local(MSP_SOCKET sock, const struct msp_sockaddr *addr);
```
Sets the address of the local end point.

**``sock``** must be the handle of an *initialising* socket.  Calling
`msp_set_local()` on an open, closed or invalid socket will produce *undefined
results*.

**`addr->sid`** specifies the identity to use as the local end point:
 * the [SID][] of an active (unlocked) identity on the local node, or
 * **`BIND_PRIMARY`** to use the primary active (unlocked) identity, or
 * **`BIND_ALL`** to use all active (unlocked) identities.

**`addr->port`** specifies the [MDP port][] number of the local end point, or
zero to allow MSP to choose any available local port.

A server application must call `msp_set_local()` with a non-zero port number on
a socket before calling `msp_listen()`.

A client application may optionally call `msp_set_local()` to set the
originating port and [SID][] of its connection before calling `msp_connect()`;
by default the originating identity is the primary SID (`BIND_PRIMARY`) and the
next available port number will be allocated.

When the socket is *opened*, its address is resolved and remains unchanged for
the remainder of the socket's lifetime: `BIND_PRIMARY` or `BIND_ALL` resolve to
the actual [SID][] used, and a zero port number resolves to the real, non-zero
port number used.  The `msp_get_local()` function reveals the resolved local
address of an open socket, once the socket is open.

#### `msp_connect()` - Connect to remote port
```
void msp_connect(MSP_SOCKET sock, const struct msp_sockaddr *addr);
```
Turns the given *initialising* socket into an *open data* socket and sets the
remote address to which it will connect.  An open data socket is not marked as
*connected* until `msp_processing()` processes the first MDP packet from the
remote end.

**``sock``** must be the handle of an *initialising* socket.  Calling
`msp_connect()` on an open, closed or invalid socket will produce *undefined
results*.

**`addr->sid`** specifies the node of the remote end point, which must be the
valid [SID][] of an active (unlocked) identity on the remote node.  It may not
be **`BIND_PRIMARY`** or **`BIND_ALL`**.

**`addr->port`** specifies the [MDP port][] number of the local end point, which
must be non-zero.

By default, the originating identity of the outgoing connection is the local
node's primary SID (`BIND_PRIMARY`) and the next available port number will be
allocated.  A client application may override the default by calling
`msp_set_local()` to set the originating port and [SID][] of its connection
before calling `msp_connect()`.

When the socket is opened, its local address is resolved and remains unchanged
for the remainder of the socket's lifetime: `BIND_PRIMARY` or `BIND_ALL`
resolve to the actual [SID][] used, and a zero port number resolves to the
real, non-zero port number used.  The `msp_get_local()` function reveals the
resolved local address of an open socket, once the socket is open.

While the socket is open, the `msp_get_remote()` function returns the address
that was passed to `msp_connect()`.

The `msp_connect()` call performs no i/o itself, it merely alters the state of
the socket and returns immediately.  You must call `msp_processing()` to start
sending and receiving packets and to mark the socket as *connected*.  An
application may queue a few messages on a new open data socket using
`msp_send()` before calling `msp_processing()`.

#### `msp_listen()` - Listen for incoming MSP connections
```
int msp_listen(MSP_SOCKET sock);
```
Turns the given *initialising* socket into an *open listening* socket.

**``sock``** must be the handle of an *initialising* socket.  Calling
`msp_listen()` on an open, closed or invalid socket will produce *undefined
results*.

A single listening socket can handle any number of incoming connections.  MSP
will create a new, *connected*, *open data* socket whenever it receives a new
incoming connection, with the local and remote addresses of the connection
resolved, and the same handler function as the listening socket.

A listening socket's handler function will be invoked on the new *open data*
socket whenever a new connection request is received.  The handler function's
main responsibility is to set up another handler function for the data socket's
i/o and to allocate any other, application-specific resources needed by the new
connection.

`msp_listen()` calls `mdp_send()` internally to bind the address of the MDP
socket, and returns returns 0 if successul, or -1 if the MDP bind returns an
error.

### Socket main loop primitives

The following MSP primitives may be applied to *open* sockets, and are used
identically in the main loop of an MSP server or client (or mixed) application.

#### `msp_get_mdp_socket()` - MDP socket number
```
int msp_get_mdp_socket(MSP_SOCKET);
```
Returns the MDP socket number that was used to create the given socket.

**`sock`** must be a valid socket handle.

*Data* sockets created by a *listening* socket inherit the listening socket's
MDP socket.

#### `msp_get_local()` - Local address
```
void msp_get_local(MSP_SOCKET sock, struct mdp_sockaddr *addr);
```
Returns the local address of the given socket.

**`sock`** must be a valid socket handle.

**`addr`** must point to an MDP socket address structure into which the
local address will be written.

If `msp_set_local()` has been called on the socket and the socket is not yet
*open*, then `msp_get_local()` will return the same address that was set.  If
`msp_set_local()` has not yet been called on the socket and the socket is not
yet *open*, then `msp_get_local()` will return the default local address, which
may contain a `BIND_PRIMARY` or `BIND_ALL` value for the [SID][], and/or a zero
[MDP port][] number.

Once a data socket is *open*, its local address is resolved to a real SID and
non-zero port number, and `msp_get_local()` will henceforward return the
resolved local address.

#### `msp_get_remote()` - Remote address
```
void msp_get_remote(MSP_SOCKET sock, struct mdp_sockaddr *addr);
```
Returns the remote address of the given socket.

**`sock`** must be the valid handle of an *open data* socket.
`msp_get_remote()` will return an undefined address on a socket which is not an
*open data* socket.

**`addr`** must point to an MDP socket address structure into which the
remote address will be written.

If the application opened the socket by calling `msp_connect()`, then
`msp_get_remote()` will return the address that was passed to `msp_connect()`.
If the socket was created by a listening socket that received an incoming
connection, then `msp_get_remote()` will return the address of the remote end
that initiated the connection.

#### `msp_set_handler()` - Register MSP handler function
```
void msp_set_handler(MSP_SOCKET sock, MSP_HANDLER *handler, void *context);
```

**``sock``** must be a valid socket handle.

**``handler``** must be a pointer to the caller-supplied handler function (see
below).

**``context``** is saved and passed to the supplied handler function whenever
MSP invokes it.

Sets the *handler* function and its context argument for the given socket.  The
application must call `msp_set_handler()` to set the handler function before
`msp_processing()` is first called, and may call it again between calls to
`msp_processing()` if desired, to change the handler function.

#### `msp_get_state()` - Socket state
```
msp_state_t msp_get_state(MSP_SOCKET sock);
```
Returns the same bit mask that is passed as the **`state`** parameter to the
handler function.

**``sock``** must be a valid socket handle.

`msp_get_state()` may be invoked inside or outside a handler function.  Passing
an invalid socket handle will produce an *undefined result*.  Since a
socket's handle becomes invalid once the socket is closed and its handler
function has been called for the last time with the CLOSED flag set, care must
be taken when invoking this function outside a handler function.

A safer way to check whether a socket has been closed is to call
`msp_socket_is_closed()`, which will return true on an invalid handle as well
as a valid, closed socket.

#### MSP handler function

The handler function is responsible for handling new incoming connections,
processing incoming messages, and responding to other MSP state changes related
to the connection.  MSP invokes the handler function as a callback, during
invocation of the `msp_processing()` function, on the following events:

 * on a *listening* socket, whenever a new connection is received

 * on a *data* socket, for every message that has been received and whenever
   there is space in the transmit queue for another outbound message

 * on all sockets, if there is an error condition

 * on all sockets, exactly once after the socket has closed

```
size_t handler_function(MSP_SOCKET sock,
                        msp_state_t state,
                        const uint8_t *payload,
                        size_t len,
                        void *context
                       )
{
    size_t ret = 0;
    if (state & MSP_STATE_ERROR) {
        // Connection is no longer working and cannot be recovered.  Do not
        // release resources here; that will be done in the MSP_STATE_CLOSED case
        // below.
        msp_close(sock);
    }
    if (payload && len) {
        // Process incoming message and return the number of bytes processed.
        ret = ... ;
    }
    if (state & MSP_STATE_DATA_OUT) {
        msp_send( ... );
    }
    if (state & MSP_STATE_SHUTDOWN_REMOTE) {
        // Remote party has closed the connection; no more messages will arrive.
    }
    if (state & MSP_STATE_CLOSED) {
        // Release all resources associated with this connection.
    }
    assert(ret <= len);
    return ret;
}
```

**`sock`** is the handle of a *valid* MSP socket, which is always *open* except
on the last invocation of a socket's handler, when it is *closed* and the
CLOSED flag is set (see below).  This argument allows the same handler function
to be used for more than one socket, and the handler function should pass it to
all MSP primitives which it invokes.  The handler function of a *listening*
socket is passed the handle of the newly-created, open *data* socket for the
connection unless either of the ERROR or CLOSED flags are set, in which case
`sock` refers to the listening socket itself.

**`context`** is the argument that was passed to the `msp_set_handler()` call
which set this function handler on the socket **`sock`**.  This mechanism allows
the caller to specialise a single handler function to different connections
without having to store a mapping from socket handle to context.

**`state`** is a bit mask of flags, which can also be obtained by calling
`mdp_get_state(sock)` or tested using the socket state predicate functions:

  * **`MSP_STATE_DATA_OUT`** is set if there is space in the MSP transmit queue
    for an outgoing packet, so the next call to `msp_send()` will succeed
    without blocking.  The handler function should only call (or cause the main
    loop to call) `msp_send()` once.  This flag will remain set in subsequent
    calls of the handler function, as long there is still space, so if the
    application has many messages to send, it should send them one by one in
    successive invocations of the handler function.

  * **`MSP_STATE_SHUTDOWN_LOCAL`** is set if the `msp_shutdown()` function has
    been called on this socket and there are no more outgoing messages queued.
    The outgoing connection is now shut, but if the incoming connection is not
    shut down yet then messages can still be received from the remote end.

  * **`MSP_STATE_SHUTDOWN_REMOTE`** is set if the remote end has sent a
    *shutdown* message and there are no queued incoming messages after the one
    currently given in `payload` and `len`.  The incoming connection is now
    shut, but if the outgoing connection is not shut down yet then messages can
    still be sent to the remote end.

  * **`MSP_STATE_CLOSED`**.  The handler function is called exactly once with
    this flag set, after the socket is closed (for whatever reason, including
    error) and after all incoming data has been consumed (`len` will always be
    zero if the CLOSED flag is set).  The handler function will never be called
    again on the same socket, so this is the point at which the application
    should release all resources associated with the connection.

  * **`MSP_STATE_ERROR`** is set if something went wrong with the connection,
    eg, a timeout, or an unrecoverable error communicating with the Serval DNA
    daemon, or an error condition returned by the Serval DNA daemon.  This flag
    may be set simultaneously with the CLOSED flag unless there is received
    data yet to be consumed (`len` is non-zero).

**`payload`** and **`len`** give the bytes of a message which has been received
in full, if `len` is non-zero.  If `len` is zero, there is no message.
Listening sockets never receive messages, only data sockets.

The handler function may consume the entire message by returning the value
`len` or may consume part of the message by returning a value less than `len`,
which gives the number of bytes consumed from the start of the message.  In
this case, the bytes not processed will remain in the MSP queue and be passed
to the next call of the handler function, the next time `msp_processing()` is
invoked, with `payload` and `len`.

No bytes from the next message will be passed to the handler function until the
current message is fully consumed.  If the handler function does not consume
messages rapidly enough, further incoming messages may fill MSP's receive queue
and be silently dropped, causing retransmission.

#### `msp_recv()` - Receive inbound message
```
int msp_recv(int mdp_fd);
```
Receives the next packet from the given MDP socket, and queues it on the
appropriate MSP socket for processing.

**`mdp_fd`** must be an MDP socket number.

Note: after calling `msp_recv()` an application should call `msp_processing()`
immediately, to ensure that timeouts are performed correctly.

If there are no packets available to receive, then `msp_recv(mdp_fd)` will
block until the next packet arrives, unless `mdp_fd` has been put into
non-blocking mode, in which case `msp_recv()` will return -1 with errno =
EAGAIN (EWOULDBLOCK on some systems).

If a [poll(2)][] or [select(2)][] system call previously identified the file
descriptor `mdp_fd` as available to read, then the next call to
`msp_recv(mdp_fd)` will not block, because it only reads a single packet.

`msp_recv()` returns 0 if it receives a packet and successfully queues it.

The `msp_recv()` function uses `mdp_recv()` internally, which in turn uses the
[recvmsg(2)][] system call.  If this call returns an error, then `msp_recv()`
will log the error and return -1 with the value of errno as set by the system
call.  The errors EINTR and EAGAIN (EWOULDBLOCK on some systems) are not
logged.

If there is an internal error receiving the packet, such as a failed connection
to the Serval DNA daemon, or if the received packet has an illegal size, an
unrecognised originating address, or malformed contents, then `msp_recv()` sets
errno = EBADMSG, logs an error and returns -1.  It does not set the *error*
state on any MSP socket.

If a packet is received from a local source other than the Serval daemon, then
`msp_recv()` will set errno = EBADMSG, log a warning and return -1.  This could
occur if another process on the local node were attempting to impersonate the
Serval daemon.

If the local Serval daemon cannot be contacted because its local socket name is
too long, then `msp_recv()` sets errno = EOVERFLOW, logs an error and returns
-1.  This can occur if the value of the `SERVALINSTANCE_PATH` environment
variable is too long.

#### `msp_send()` - Queue outbound message for transmission
```
uint8_t payload[MSP_MESSAGE_SIZE];
int msp_send(MSP_SOCKET sock, const uint8_t *payload, size_t len);
```
Queues a single message for transmission.  The message is not actually sent
until the next call to `msp_processing()`.

**`sock`** must be the handle of an *open data* socket which is not in the
*local shutdown* condition.

**`payload`** must point to **`len`** bytes of data that constitute the
message.

Message boundaries are preserved at the receiving end: the receiver will be
passed the message in a single call to its MSP handler function with the `len`
parameter equal to the `len` value that the sender passed to `msp_send()`.

Zero length messages are not sent, but do not cause `msp_send()` to return an
error.  (In future, a zero-length send may cause a flush if a buffered mode is
implemented, so it is best not to call `msp_send()` with `len = 0`.)

The message must not be longer than `MSP_MESSAGE_SIZE` bytes.  A value of `len`
greater than this will cause `msp_send()` to return -1 with errno = EBADMSG.
(In future, if a buffered mode is implemented, this restriction may be
relaxed.)

If MSP has insufficient memory to queue the message, `msp_send()` will return
-1 with an errno = EAGAIN.  If this occurs, the caller should wait until the
next time the MSP handler function is called with the `MSP_STATE_DATAOUT` flag
set in the `state` argument, before re-trying the send.

#### `msp_processing()` - Transmit outgoing messages, handle incoming messages
```
int msp_processing(ms_time_t *next_time);
```
Performs all pending MSP protocol logic on all open MSP connections, transmits
queued outgoing packets using `mdp_send()`, and handles all received incoming
packets by calling the handler function once per message.

`msp_processing()` sets `*next_time` to the latest time at which the caller
should invoke it again.  The caller may invoke it at any time before then, for
example immediately after calling `msp_recv()` or `msp_send()`, but must not
fail to call it before the indicated time, otherwise MSP timeout and keep-alive
logic may fail.

This is typically done by passing a suitable time-out parameter to [poll(2)][]
or [select(2)][], or setting a receive time-out on the MDP socket using
[setsockopt(2)][], so that if no input events occur before `*next_time`, the
system call will return and the application's main loop will iterate, calling
`msp_processing()` on the way around.

### Socket finalisation primitives

There are three ways that an MSP socket gets closed, described below from most
orderly to most drastic.

#### `msp_shutdown()` - End of outgoing message stream
```
int msp_shutdown(MSP_SOCKET sock);
```
Queues a *shutdown* message and sets the socket's *local shutdown* condition.

**``sock``** must be the handle of an *open* socket which is not in *local
shutdown* condition.

The *shutdown* message is not actually sent to the remote end until the next
call to `msp_processing()`.  If called from within a handler function, the
shutdown takes effect as soon as the handler function returns.

After calling `msp_shutdown()`, no more messages can be sent, so calling
`msp_send()` or `msp_shutdown()` will produce *undefined results*.  The
inbound side of the connection remains active, so messages will still be
received until the socket is closed.

When the remote party shuts down the socket at its end and all remaining data
has been transferred, including the *shutdown* packet from the remote end, the
socket will close automatically during `msp_processing()`.

#### `msp_close()` - Close a single MSP connection
```
void msp_close(MSP_SOCKET sock);
```
Marks the given socket as closed.  The socket is not actually cleaned up until
the next call to `msp_processing()`.  If called from within a handler function,
the close takes effect as soon as the function returns.

The next call to `msp_processing()` will immediately terminate all i/o activity
for the socket without negotiating with or notifying the remote end, will
discard all locally queued incoming and outgoing messages, and will make the
final invocation to the socket's handler function with the CLOSED flag set.
The remote end will have to rely on its MSP timeout logic to detect that the
MSP connection is finished.  The effect is as though the local end point had
lost contact with the remote end with no warning.

#### `msp_close_all()` - Close all MSP connections on a given MDP socket
```
msp_close_all(mdp_fd);
```
Immediately closes and frees all MSP sockets associated with the given MDP
socket.  This function is intended to be used after an application's main loop
has terminated, and just before the application itself terminates, so it does
not require any subsequent call to `mdp_processing()`.

Calling `msp_close_all()` from within a handler function will have *undefined
results*.


[Serval Project]: http://www.servalproject.org/
[grant]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:activity:naf6
[NAF]: http://www.newamerica.net/
[OTI]: http://oti.newamerica.net/
[MSP]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:msp
[Serval mesh network]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:mesh_network
[MDP]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:mdp
[TCP]: http://en.wikipedia.org/wiki/Transmission_Control_Protocol
[SID]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:sid
[MDP port]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:mdp_port_number
[MTU]: http://en.wikipedia.org/wiki/Maximum_transmission_unit
[sliding window]: http://en.wikipedia.org/wiki/Sliding_window_protocol
[linear network coding]: http://en.wikipedia.org/wiki/Linear_network_coding
[ACK]: http://en.wikipedia.org/wiki/Acknowledgement_(data_networks)
[timeout]: http://en.wikipedia.org/wiki/Timeout_(computing)
[poll(2)]: http://man7.org/linux/man-pages/man2/poll.2.html
[select(2)]: http://man7.org/linux/man-pages/man2/select.2.html
[recvmsg(2)]: http://man7.org/linux/man-pages/man2/recvmsg.2.html
[setsockopt(2)]: http://man7.org/linux/man-pages/man2/setsockopt.2.html
[_exit(2)]: http://man7.org/linux/man-pages/man2/_exit.2.html
[abort(3)]: http://linux.die.net/man/3/abort
[exit(3)]: http://linux.die.net/man/3/exit
[gdb(1)]: http://www.gnu.org/software/gdb/documentation/
[thread safe]: http://en.wikipedia.org/wiki/Thread_safety
[preemption]: http://en.wikipedia.org/wiki/Preemption_(computing)
[mutual exclusion]: http://en.wikipedia.org/wiki/Mutual_exclusion
[application framework]: http://en.wikipedia.org/wiki/Application_framework
[event driven]: http://en.wikipedia.org/wiki/Event-driven_programming
[handle]: http://en.wikipedia.org/wiki/Handle_(computing)
[POSIX file descriptor]: http://en.wikipedia.org/wiki/File_handle
[standard C i/o]: http://en.wikipedia.org/wiki/C_file_input/output
[FILE pointer]: http://code-reference.com/c/keywords/file
[MDP API]: ./Mesh-Datagram-Protocol.md
[Serval DNA source code]: https://github.com/servalproject/serval-dna
