Configuring servald
===================

The examples in this document are [Bourne shell][] commands, using standard
quoting and variable expansion.  Commands issued by the user are prefixed with
the shell prompt `$` to distinguish them from the output of the command.
Single and double quotes around arguments are part of the shell syntax, not
part of the argument itself.

Instance path
-------------

By default, **servald** keeps its configuration, keyring, and other temporary
files in its *instance directory*.  The default instance directory depends on
the target platform:

* on Android `/data/data/org.servalproject/var/serval-node`
* on other platforms `/var/serval-node`

The default instance directory is overridden by the `SERVALINSTANCE_PATH`
environment variable.

Configuration options
---------------------

The **servald** configuration is a set of label-value pairs called *options*.
A label is a sequence of one or more alphanumeric words separated by period
characters `.`.  A value is a string of characters.  If an option is given an
invalid value, eg, an option that requires a positive decimal integer value is
given a non-decimal string, then **servald** will log an error or warning and
use the option's default setting instead.

To set a configuration option:

    $ servald config set name.of.option 'value'
    $

To examine an option's current setting:

    $ servald config get name.of.option
    name.of.option=value
    $

To examine all configuration option settings:

    $ servald config get
    interfaces=+eth0,+wifi0
    name.of.option=value
    name.of.other_option=value2
    $

**servald** stores its configuration option settings in a file called `config`
in its instance directory, which it reads upon every invocation.  This means
that each instance's own option settings persist until changed or until the
`config` file is altered or removed.

Running many daemons
--------------------

To run more than one **servald** daemon process on the same device, each daemon
must have its own instance path.  Set the `SERVALINSTANCE_PATH` environment
variable to a different directory path before starting each daemon.  Each
**servald** daemon will create its own instance directory (and all enclosing
parent directories) if it does not already exist.

Network interfaces
------------------

The **servald** daemon periodically scans its operating system's network
interfaces and uses its `interfaces` configuration option to select which to
ignore and which to use.

Eg, to use two interfaces, `eth0` a 230 MiB/s ethernet on port 7333 and `wifi0`
a 1 MB/s WiFi device:

    $ servald config set interfaces '+eth0=ethernet:7333:230M,+wifi0=wifi'

Eg, to use all available interfaces, treating all as WiFi 1 MB/s

    $ servald config set interfaces '+'

The `interfaces` configuration option accepts a comma-separated list of
interface specifications, each having one of the following forms:

    +
    -name
    +name=type
    +name=type:port
    +name=type:port:speed
    +>path

where:
 * `name` is the operating system's label for a network interface,
 * `type` is one of `wifi`, `ethernet`, `other`, `catear` (default is `wifi`)
 * `port` is a TCP port number (default is 4110)
 * `speed` is the interface's bytes per second capacity (default 1 MB/s),
   expressed in the form ***Nu*** where ***N*** is a decimal integer and
   ***u*** is a unit, one of `k` (10³), `K` (2¹⁰), `m` (10⁶), `M` (2²⁰), `g`
   (10⁹) or `G` (2³⁰)

Interface specifications are applied in the order they appear.  The form `+`
matches all interfaces.  The form `-name` rejects any interfaces called *name*.
The forms beginning with `+name` match any interface called *name*.  The
`+>path` form specifies a dummy interface (see below).  For example, an
interfaces list of `+,-eth0` will not reject the *eth0* interface because the
leading `+` will match it first, but `-eth0,+` will reject *eth0*.

Dummy Network Interface
-----------------------

Sometimes it is helpful to run an isolated group of several intercommunicating
**servald** instances on a single machine for testing purposes.  To make this
possible, **servald** supports a *dummy* network interface.

A dummy interface is simply a regular file to which all instances append their
network packets.  The file grows without limit.  Each instance advances its own
read pointer through the file, packet by packet.  This simulates a lossless
mesh network with 100% connectivity, ie, all nodes are neighbours.

To use a dummy interface, first create an empty file, eg, `/tmp/dummy`, and for
each servald instance, include the dummy file in its *interfaces* list, eg:

    $ servald config set interfaces '+>/tmp/dummy'

NOTE: Because dummynets are files, not sockets, the *poll*(2) system call does
not work on them.  As a result the **servald** daemon main loop has slightly
different behaviour and timing characteristics when a dummynet is in use.


[Bourne shell]: http://en.wikipedia.org/wiki/Bourne_shell
