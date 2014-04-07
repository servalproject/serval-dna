Mesh Streaming Protocol (MSP)
=============================
[Serval Project], April 2014

The [Mesh Streaming Protocol][MSP] is a network protocol used in the [Serval
mesh network][].  It provides a two-way, reliable, ordered stream of bytes
between a pair of end points, which can be used to transfer files, conduct
an HTTP session, or carry quasi-real-time streaming data.

MSP uses the unreliable [MDP][] protocol to send datagram packets between the
two end points.  MSP uses sequence numbering, acknowledgement messages and a
sliding window to achieve eventual reliable delivery of all packets.

MSP was funded by a [grant][] from the [New America Foundation][NAF]'s [Open
Technology Institute][OTI].

Protocol description
--------------------

Mesh Streaming Protocol (MSP) is a TCP-like protocol for providing reliable, 
in-order delivery of messages via the Mesh Datagram Protocol (MDP).

Being based on MDP all data will be encrypted end-to-end, and authentication 
is implicit. Since encryption doesn't depend on negotiating a session token,
the first few packets of data can be sent before knowing if the connection
attempt is successful.

The MSP protocol requires processing timed events for handling retransmission or 
connection failures. It is necessary for the programmer to manually schedule 
calls to handle these events.  It would be possible to have this happen 
automatically from a helper-thread, however the existing manual mode will 
likely be retained in the long-term as it allows for greater flexibility.

MSP is a work in progress, and has not been subjected to rigorous testing, so 
expect speed humps and sub-optimal performance depending on your operating 
conditions.  Please report any issues that you may encounter so that MSP can 
be improved for all users.

Client API
----------

The MSP API builds on the underlying MDP API.

See `msp_client.h` for full function prototypes and pre-processor definitions.

The provisional API is as follows.  Expect this to evolve as MSP development 
continues.

#### Create an MSP socket
```
int mdp_fd = mdp_socket();
struct msp_sock *sock = msp_socket(mdp_fd);
```

#### Receive any queued inbound events on an MSP socket

For example, if the file descriptor is identified as having waiting input using `poll()` or `select()`
```
msp_recv(mdp_fd);
```

After calling `msp_recv()` you should then call `msp_processing()` as soon as possible, 
so that it can schedule any necessary alarms for asynchronous processing in a timely manner.

#### Handle any asynchronous processing alarms that are due 
```
time_ms_t next_time;
msp_processing(&next_time);
```

This will set `next_time` to the next time at which `msp_processing()` should be called.
You should attempt to call `msp_processing()` again at or before the time indicated.  
Typically, this might be done with a `poll()` or `select()` with an appropriate time out, 
so that if no input events occur before `next_time`, it can be called. 


#### To listen for incoming MSP connections

The socket can be bound to listen on all local SIDs (`BIND_ALL`), 
only the primary SID of the node (`BIND_PRIMARY`), 
or to any particular SID passed in via `addr.sid`.

Any number of incoming connections can be handled by a single mdp socket.  
An MSP socket will be allocated for each incoming connection with the local 
and remote addresses of the connection. Each socket will initially be given 
the same call-back handler as the original listen socket.

```
struct mdp_sockaddr addr;
addr.port = <port number | 0 = ANY >;
addr.sid = <local Subscriber Id | BIND_PRIMARY | BIND_ALL >;
msp_set_local(sock, addr);
msp_listen(sock);
```

#### To connect to a remote socket;

Only one outgoing connection is supported on a single mdp socket. You may call 
`msp_set_local()` before `msp_set_remote()` to manually bind to a specific source address.
If you do not call set_local, the connection will be bound to the Primary 
address on the next available port.


```
struct mdp_sockaddr addr;
addr.port = <port number | 0 = ANY>;
addr.sid = <remote Subscriber Id>;
msp_set_remote(sock, addr);
```

You may start sending data immediately. A small number of data packets can 
be sent before we know that the connection has been accepted.
You must call `msp_processing()` to establish the connection.

#### Queue a message for transmission;

Use `msp_send()` to send messages.

```
int msp_send(struct msp_sock *sock, const uint8_t *payload, size_t len);
```

Data is not actually sent until the next call to `msp_processing()`, which 
should be triggered as soon as possible.
Message boundaries are preserved from end to end. Zero length messages are not currently supported.

In the event that there is insufficient buffer space to send the message, `msp_send()` 
will return -1. If this occurs, you should wait until the next time your handler 
function is called with the `MSP_STATE_DATAOUT` flag set in the `state` argument.

#### Handling asynchronous events;

The handler is specified by calling `msp_set_handler()` similar to the following:
```
msp_set_handler(sock, handler_function, context);
```

The handler function should process incoming data and deal with other state changes related to the connection, as indicated in the example below.

```
int handler_function(struct msp_sock *sock, msp_state_t state, const uint8_t *payload, size_t len, void *context){

 if (state & MSP_STATE_ERROR){
    // something went wrong, eg connection timeout or an unspecified error was returned from serval's daemon.
  }

  if (payload && len){
    // process incoming message bytes and return 0
    // all incoming messages will be delivered in the same order they were sent

    // if you can't process the whole message now, return 1
    // later when you believe you will be able to process this message, call msp_processing again
  }

  if (state & MSP_STATE_DATA_OUT){
    // a call to msp_send() should now succeed.
  }

  if (state & MSP_STATE_SHUTDOWN_REMOTE){
    // the remote party has stopped sending data and would like to close.
    // you may keep your end of the connection open and continue to send data. 
    // When both ends have shutdown the connection will be closed.
  }

  if (state & MSP_STATE_CLOSED){
    // No matter how the socket it closed, this function should always be called exactly once with a closed state before the struct msp_sock* is free'd
    // Any other resources associated with the socket should now be released.
  }

  // if you return -1, the socket will be flagged a closed
}
```

#### Graceful shutdown of MSP handling on a socket

Simply call `msp_shutdown(sock);`, replacing `sock` with the MSP socket in question.

After calling shutdown, you can no longer queue any messages to send. Once both parties have 
shutdown the socket and all remaining data has been transferred, the socket will be closed.


#### Closing an MSP connection/socket.

Call `msp_close()` on the socket in question.  

Note that calling `msp_close()` immediately destroys all socket state on the local side, without negotiating with or notifying the remote side.

This can be called at anytime, because it only marks the socket for cleanup, which will not occur until the next time `msp_processing()` is called.

#### Free all sockets immediately;

```
msp_close_all(mdp_fd);
```

This immediately frees all MSP sockets.  It cannot be called from within a handler function.



[Serval Project]: http://www.servalproject.org/
[grant]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:activity:naf6
[NAF]: http://www.newamerica.net/
[OTI]: http://oti.newamerica.net/
[MSP]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:msp
[Serval mesh network]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:mesh_network
[MDP]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:mdp
[network coding]:
