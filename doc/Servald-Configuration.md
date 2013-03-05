Configuring servald
===================

The examples in this document are [Bourne shell][] commands, using standard
quoting and variable expansion.  Commands issued by the user are prefixed with
the shell prompt `$` to distinguish them from the output of the command.
Single and double quotes around arguments are part of the shell syntax, so are
not seen by the command.  Lines ending in backslash `\` continue the command on
the next line.

Instance path
-------------

By default, **servald** keeps its configuration, keyring, and other temporary
files in its *instance directory*.  The instance directory is set at run time
by the `SERVALINSTANCE_PATH` environment variable.  If this is not set, then
**servald** uses a built-in default path which depends on its build-time option
and target platform:

* as specified by the `./configure --enable-instance-path=PATH` option when
  **servald** was built from source
* on Android `/data/data/org.servalproject/var/serval-node`
* on other platforms `/var/serval-node`

Running many daemons
--------------------

To run more than one **servald** daemon process on the same device, each daemon
must have its own instance path (and hence its own `serval.conf`).  Set the
`SERVALINSTANCE_PATH` environment variable to a different directory path before
starting each daemon.  Each **servald** daemon will create its own instance
directory (and all enclosing parent directories) if it does not already exist.

Configuration options
---------------------

The **servald** configuration is a set of label-value pairs called *options*.
A label is a sequence of one or more alphanumeric words separated by period
characters `.`.  A value is a string of characters which is parsed according
to the option's type, for example a decimal integer, a boolean, or an internet
address.

To set a configuration option:

    $ servald config set name.of.option 'value'
    $

To unset a configuration option, returning it to its default value:

    $ servald config del name.of.option
    $

To examine an option's current value:

    $ servald config get name.of.option
    name.of.option=value
    $

To examine all configuration option settings:

    $ servald config get
    interfaces=+eth0,+wifi0
    name.of.option=value
    name.of.other_option=value2
    $

To list all supported configuration options:

    $ servald config schema
    debug.broadcasts=(boolean)
    debug.dnahelper=(boolean)
    debug.dnaresponses=(boolean)
    ...
    server.chdir=(absolute_path)
    server.dummy_interface_dir=(str_nonempty)
    server.respawn_on_crash=(boolean)
    $

The configuration schema is defined in the [conf_schema.h](../conf_schema.h)
source header file.

Configuration persistence
-------------------------

**servald** stores its configuration option settings in a file called
`serval.conf` in its instance directory, which it reads upon every invocation.
This means that each instance's own option settings persist until changed or
until its `serval.conf` file is altered or removed.

Invalid configuration
---------------------

If `serval.conf` is syntactically malformed or refers to an unsupported option
or contains an invalid value or inconsistency, then every invocation of
**servald** will log explanatory warnings and reject the file, failing with an
error instead of performing the command.  The warnings will be logged according
to any valid logging options found in `serval.conf`.

The only exceptions to this rule are the `help` and `stop` commands and the
various `config` commands described above.  Those commands will proceed instead
of failing by omitting the offending config options and using built-in defaults
in their place.  This means that despite an invalid `serval.conf`, **servald**
may still be used to inspect and correct the configuration, and to stop a
running daemon.

Configuration of daemons
------------------------

As described above, an invalid `serval.conf` will prevent the **servald**
`start` command from starting a daemon process.  Once the daemon is running, it
periodically checks whether `serval.conf` has changed (by comparing size and
modification time) and attempts to re-load it if it detects a change.  If the
re-loaded file is invalid, the daemon rejects it, logs an error, and continues
execution with unchanged configuration.  However, if the daemon is stopped or
killed, it cannot be re-started while the invalid `serval.conf` persists.

Logging configuration
---------------------

**servald** logging is controlled by the following config options:

    log.file=PATH
    log.show_pid=BOOLEAN
    log.show_time=BOOLEAN

The `log.file` option names a file to which log messages are appended using the
O\_APPEND option of [open(2)][].  If the file does not exist, **servald** will
create it.  If the `log.file` PATH is not absolute (ie, does not start with
`/`) then it is relative to the instance directory.  If `log.file` is not set
then log messages are sent to standard error.  This will mean that background
**servald** daemons will not log anything, since the standard input, output and
error streams of all background daemon processes are closed.

The `log.show_pid` option, if true, causes all log lines to be prefixed with
the process ID of the logging process.  This can help distinguish between log
messages from different daemon processes sharing the same log file, or, more
commonly, between a daemon process and other **servald** invocations.  The
`log.show_pid` option is true by default.

The `log.show_time` option, if true, causes all log lines to be prefixed with
the date and time, to millisecond resolution if available, of the log message.
The `log.show_time` option is true by default.

Network interfaces
------------------

The **servald** daemon periodically scans its operating system's network
interfaces and uses its `interfaces` configuration option to select which to
ignore and which to use.

For example, the following configuration will use any interface whose name
starts with `eth` (eg, `eth0`, `eth1`) as a 230 MiB/s Ethernet on port 7333,
and any interface whose name starts with `wifi` or `wlan` but is not `wifi0` or
`wlan0` as a 1,000,000 B/s WiFi on the default port number:

    $ servald config set interfaces.0.match 'eth*' \
                     set interfaces.0.type ethernet \
                     set interfaces.0.port 7333 \
                     set interfaces.0.speed 230M \
                     set interfaces.1.match 'wifi0,wlan0' \
                     set interfaces.1.exclude true \
                     set interfaces.2.match 'wifi*,wlan*' \
                     set interfaces.2.type wifi \
                     set interfaces.2.speed 1m

The following configuration is equivalent to the above example, but uses the
“legacy”, single-option syntax (see below):

    $ servald config set interfaces '+eth=ethernet:7333:230M,-wifi0,-wlan0,+wifi=wifi::1m,+wlan=wifi::1m'

The following two equivalent configurations use all available interfaces,
treating all as WiFi 1 MB/s (the default type and speed):

    $ servald config set interfaces.0.match '*'
    $ servald config set interfaces '+'

Network interface rules
-----------------------

As shown in the first example above, the `interfaces` config option contains a
numbered list of *rules* that are applied to all detected system interfaces in
order of ascending number.  The general form of an interface rule is:

    interfaces.UINT.match=PATTERN[, PATTERN ...]
    interfaces.UINT.exclude=BOOLEAN
    interfaces.UINT.type=IFTYPE
    interfaces.UINT.port=PORT
    interfaces.UINT.speed=SPEED
    interfaces.UINT.mdp_tick_ms=UINT_NONZERO
    interfaces.UINT.default_route=BOOLEAN
    interfaces.UINT.dummy=PATH
    interfaces.UINT.dummy_address=IN_ADDR
    interfaces.UINT.dummy_netmask=IN_ADDR
    interfaces.UINT.dummy_filter_broadcasts=BOOLEAN

where:

 * `BOOLEAN` is one of `true`, `false`, `1`, `0`, `yes`, `no`, `on` or `off`
 * `UINT` is an unsigned decimal integer (with no `+` or `-` prefix)
 * `UINT_NONZERO` is an unsigned decimal integer ≥ 1
 * `PATTERN` is a [shell wildcard][] pattern that is matched against the
   interface name using the [fnmatch(3)][] standard library function
 * `PATH` is an absolute or relative file path
 * `IFTYPE` is one of `wifi`, `ethernet`, `catear` or `other`
 * `PORT` is an unsigned decimal integer in the range 1 to 65535
 * `SPEED` is `UINT[SCALE]`, where `SCALE` is a single-letter multiplying
   factor, one of `k` (10^3), `K` (2^10), `m` (10^6), `M` (2^20), `g` (10^9) or
   `G` (2^30)
 * `IN_ADDR` is an Internet address as accepted by [inet_aton(3)][], ie,
   `N.N.N.N` where `N` is an integer in the range 0 to 255.

The `match` and `dummy` options are mutually incompatible.  If both are
specified, it is an error; the rule is omitted from the configuration and
`serval.conf` is treated as invalid (see above).

If a rule specifies a `match` option, then it is used to match real system
interfaces, and if any PATTERN matches, the rule is applied and the interface
is used (or excluded if the rule has a true `exclude` option).

If a rule specifies a `dummy` path, then a dummy interface (see below) is
created if the given file exists.

If the `type` option is given, it sets the IFTYPE of the interface, which will
affect the default settings of the other options, such as `speed` and
`mdp_tick_ms`.  In future it may also change the way the interface behaves, for
example, an `ethernet` interface may automatically assume that broadcast
packets will be filtered out, so will start using MDP unicast protocols
immediately rather than waiting to detect that broadcast packets are not
acknowledged.

The `mdp_tick_ms` option, if set, controls the time interval in milliseconds
between MDB broadcast announcements on the interface.  If set to zero, it
disables MDP announcements altogether on the interface (called “tickless”
mode).  If not set, then the value of the `mdp.iftype.IFTYPE.tick_ms` option is
used.  If that is not set, then **servald** uses a built-in interval that
depends on the IFTYPE.

Network interface “legacy” syntax
---------------------------------

Instead of using the multi-option schema described above, the `interfaces`
configuration option can be set using a less capable “legacy” format, for
compatibility with older config files.  The “legacy” interfaces syntax is a
single text string consisting of a comma-separated list of rule stanzas, each
stanza having one of the following forms:

    +
    -
    +PREFIX=IFTYPE
    +PREFIX=IFTYPE:PORT
    +PREFIX=IFTYPE:PORT:SPEED
    -PREFIX
    +>PATH

The rule `+` matches all interfaces.

The rule `-` excludes all interfaces.

Rules beginning with `+PREFIX` match any interface whose name starts with
`PREFIX`; so for example a rule starting with `+foo` is equivalent to a `match`
option with a single PATTERN of `foo*`

The rule `-PREFIX` excludes interfaces whose name starts with `PREFIX`.

The rule `+>PATH` specifies a dummy interface (see below) with no address or
netmask or broadcast filter.

Interface rules are numbered in the order they appear, and hence applied in
that order.  For example, an `interfaces` option of `+,-eth0` will not reject
the *eth0* interface because the leading `+` will match it first, but `-eth0,+`
will reject *eth0* and accept all others.

The “legacy” format is only provided for backward compatibility and will
eventually be deprecated and removed.  The “legacy” interfaces configuration is
incompatible with the modern form; an instance that uses one cannot use the
other.

Dummy network interface
-----------------------

Sometimes it is helpful to run an isolated group of connected **servald**
instances on a single machine for testing purposes.  To make this possible,
**servald** supports a *dummy* network interface.

A dummy interface is simply a regular file to which all instances append their
network packets.  The file grows without limit.  Each instance advances its own
read pointer through the file, packet by packet.  This simulates a lossless
mesh network with 100% connectivity, ie, all nodes are neighbours.

To use a dummy interface, first create an empty file, eg, `/tmp/dummy`, and for
each servald instance, include the dummy file in its *interfaces* list, eg:

    $ servald config set interfaces.0.dummy '/tmp/dummy'

NOTE: Because dummynets are files, not sockets, the [poll(2)][] system call
does not work on them.  As a result the **servald** daemon main loop has
slightly different behaviour and timing characteristics when a dummynet is in
use.

If a dummy interface's PATH is not absolute (ie, does not start with `/`) then
the PATH is relative to the `server.dummy_interface_dir` config option if set,
otherwise relative to the instance directory.

The following config options adorn a dummy interface with properties that real
interfaces normally obtain directly from the operating system:

    interfaces.UINT.dummy_address=IN_ADDR
    interfaces.UINT.dummy_netmask=IN_ADDR
    interfaces.UINT.dummy_filter_broadcasts=BOOLEAN

If the `dummy_filter_broadcasts` option is true, then the dummy interface will
not carry broadcast packets, to simulate the effect of the WiFi drivers on some
Android devices which filter out broadcast packets.

[Bourne shell]: http://en.wikipedia.org/wiki/Bourne_shell
[open(2)]: http://www.kernel.org/doc/man-pages/online/pages/man2/open.2.html
[shell wildcard]: http://www.kernel.org/doc/man-pages/online/pages/man7/glob.7.html
[fnmatch(3)]: http://www.kernel.org/doc/man-pages/online/pages/man3/fnmatch.3.html
[inet_aton(3)]: http://www.manpagez.com/man/3/inet_aton
[poll(2)]: http://www.kernel.org/doc/man-pages/online/pages/man2/poll.2.html
