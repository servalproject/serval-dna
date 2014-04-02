Configuring Serval DNA
======================
[Serval Project][], April 2013


Configuration options
---------------------

The **servald** configuration is an unordered set of LABEL=VALUE pairs called
*options*.  For example:

    debug.verbose=true
    interfaces.0.file=/var/tmp/serval/dummy
    interfaces.0.socket_type=file
    log.file.directory_path=/var/tmp/serval-logs
    log.file.duration=20m
    log.file.rotate=10
    rhizome.direct.peer.0.host=129.96.12.91
    server.respawn_on_crash=true

An option **LABEL** is a sequence of one or more [US-ASCII][] alphanumeric
words separated by period characters, eg, `log.file.directory_path`.  If a
LABEL is not recognised, it is *unsupported*.

An option **VALUE** is a string of [US-ASCII][] characters, excluding newline
(character 10), which is parsed according to the option's *type*:

  * decimal integer, eg: `10`, `0`, `-1000000`
  * boolean, eg: `true`, `false`, `on`, `off`, `1`, `0`, `yes`, `no`
  * internet address (in\_addr), eg: `192.168.1.1`
  * time interval, eg: `12h`, `1w3d`, `2h15m30s`
  * absolute path, eg: `/var/lib/serval`
  * relative path, eg: `../lib/hostlist`
  * Serval ID (SID), eg: `EEBF3AC19E7EE58722A0F6D4A4D5894A72F5C71030C3399FE75808DCF6C6254B`
  * scaled decimal integer with optional suffix **k** (10^3), **K** (2^10),
    **m** (10^6), **M** (2^20), **g** (10^9) or **G** (2^30), eg:
    `1M` = 1,048,576

If a VALUE does not parse correctly, it is *invalid*.

Configuration persistence
-------------------------

**servald** stores its configuration option settings in a file called
`serval.conf` in its instance directory.  It reads this file upon every
invocation.  This means that each instance's option settings persist until
changed or until its `serval.conf` file is altered or removed.

The format of the file is as shown in the example above: each option is
represented by a single line in the file.  Each line may have one of the forms:

    [ WHITE ] LABEL "=" VALUE "\n"
    [ WHITE ] "#" COMMENT "\n"
    [ WHITE ] "\n"

where WHITE is any sequence of zero or more space or tab characters (as
classified by [isspace(3)][]), COMMENT is any sequence of characters except
newline, and LABEL and VALUE are as defined above.

Blank lines are ignored, as are lines beginning with the comment character `#`.
VALUE is parsed very strictly: all spaces are significant.  A leading or
trailing space in VALUE can cause a numerical option to be invalid.

Invalid configuration
---------------------

Although `serval.conf` is usually written and read only by **servald**, in fact
it is an external file which may be modified, so **servald** has no control
over its contents.  The semantics of the configuration loading anticipate the
possibility of encountering a *defective* file:

 * If `serval.conf` is syntactically malformed, then **servald** will log a
   warning, skip the malformed line and continue parsing;

 * If the same LABEL appears more than once, then **servald** will log a
   warning and ignore the second and all subsequent lines with the *duplicate*
   LABEL;

 * If an *unsupported* LABEL is encountered (which could be a mis-spelling of a
   supported option), then **servald** will log a warning and ignore the line;

 * If a configuration option has an *invalid* VALUE, then **servald** will log
   a warning and leave the option with its built-in default value;

 * If a logical relation, such as mutually incompatible or mandatory options,
   is violated, then **servald** will log a warning and ignore the *illogical*
   options or use default values.

In all the above cases, most **servald** commands will reject the defective
file by logging an error and exiting with error status (255).  In this case,
logging is done using options salvaged from the defective file (see the [config
dump](#config-dump) command, described below).

Some “permissive” commands, such as `help`, `stop`, and the various `config`
commands described below, will not fail on a defective configuration file.
Instead they will log a warning and carry on using options salvaged from the
defective file.  This means that **servald** may always be used to inspect and
correct the configuration, and to stop a running daemon, despite a defective
configuration file.

Configuration reloading
-----------------------

A running daemon re-loads its configuration whenever the `serval.conf` file is
changed.  It does this by periodically checking the file's size and
modification time, and if they have changed, parses the file and updates its
own internal copy of the configuration settings.

As described above, the **servald** `start` command will not start a daemon
process if the `serval.conf` file is defective.  However, the file may become
defective *after* the daemon has started.

In this case, the daemon will not terminate, nor load the defective file, but
will log an error and continue execution with its internal configuration
unchanged.  The daemon's internal configuration will no longer be consistent
with the contents of the file.  If the daemon is stopped or killed, it cannot
be re-started while `serval.conf` remains defective.

Despite detecting a defective configuration file, the daemon continues to check
for changes to the file, and attempts to re-load whenever it changes.  As soon
as the defective `serval.conf` is fixed, the running daemon will load it
successfully and continue execution with the new configuration.  The internal
configuration and the file contents will once again be consistent.

Daemon instances
----------------

It order to support more than one daemon running on the same host, each daemon
can be configured to use its own *instance directory*, as follows:

  * A daemon's instance directory can be set at run time by setting the
    `SERVALINSTANCE_PATH` environment variable prior to starting the daemon.
    This overrides all default paths.  Once a daemon is running, the only way
    to change its instance directory is to stop it and start another daemon
    with a different value for the environment variable.

  * If the instance directory is not set at run time, then if **servald** was
    built with the `./configure INSTANCE_PATH=DIR` option, then the **servald**
    executable will use the instance directory in `DIR` by default.  The FHS
    paths will never be used.

  * On an Android system, if none of the above are used, then **servald** will
    use the instance directory `/data/data/org.servalproject/var/serval-node`
    by default.  The FHS paths will never be used.

  * If none of the above apply, then there is no *instance directory*.
    Instead, [FHS][] paths are used (see below).  Only one daemon can run in
    this situation on the same host, since the single, common PID file will
    prevent more than one being started.

The main use for multiple instances on a single host is for testing, and this
is used extensively in the automated test suite.  Deployments other than
Android are unlikely to use an instance path, so the FHS paths are most likely
to be used in practice.

FHS paths
---------

By default, **servald** locates its files such as configuration, logs, Rhizome
storage, etc.  in accordance with the [Filesystem Heirarchy Standard][FHS] 2.3:

  * the **servald** executable is installed in `/usr/local/bin/servald`
  * the configuration is stored in `/etc/serval/serval.conf`
  * the keyring is stored in `/etc/serval/serval.keyring`
  * the PID file is `/var/run/serval/servald.pid`
  * the daemon creates its process information files under
    `/var/run/serval/proc/`
  * the daemon creates and rotates log files files under
    `/var/log/serval/`
  * the daemon creates and updates a symbolic link to the latest log file in
    `/var/log/servald.log`
  * the Rhizome store is in `/var/cache/serval/` (unless overridden by
    configuration):
    * the SQLite database is `/var/cache/serval/rhizome.db`
    * large payloads are stored under `/var/cache/serval/blob/`
  * the SQLite temporary directory is `/tmp/serval/sqlite3tmp/`
  * dummy interface files are created under `/tmp/serval/` (unless overridden
    by configuration)

The **servald** `start` command will create all sub-directories within the
standard FHS paths as needed, and any failure will cause the daemon not to
start.

The following build-time configuration options are available to alter the paths
described above, which can help adapt **servald** to systems which use a
different software installation convention (eg, all packages are installed
under `/opt/packagename`) or which have a volatile `/var` directory (eg, on
OpenWRT, `/var` is a symlink to `/tmp`):

  * If **servald** is built with the `./configure --prefix=DIR` option, then
    the executable is installed in `DIR/bin` instead of `/usr/local/bin`

  * If **servald** is built with the `./configure --sysconfdir=DIR` option,
    then it will use `DIR` in place of `/etc`

  * If **servald** is built with the `./configure --localstatedir=DIR` option,
    then it will use `DIR` in place of `/var`

  * If **servald** is built with the `./configure SERVAL_ETC_PATH=DIR` option,
    then it will use `DIR` in place of `/etc/serval`

  * If **servald** is built with the `./configure SERVAL_RUN_PATH=DIR` option,
    then it will use `DIR` in place of `/var/run/serval`

  * If **servald** is built with the `./configure SYSTEM_LOG_PATH=DIR` option,
    then it will use `DIR` in place of `/var/log`

  * If **servald** is built with the `./configure SERVAL_LOG_PATH=DIR` option,
    then it will use `DIR` in place of `/var/log/serval`

  * If **servald** is built with the `./configure RHIZOME_STORE_PATH=DIR`
    option, then it will use `DIR` in place of `/var/cache/serval` for the
    Rhizome store

  * If **servald** is built with the `./configure SERVAL_TMP_PATH=DIR` option,
    then it will use `DIR` in place of `/tmp/serval`

The **servald** `config paths` command will display all the paths in use, based
on the built-in defaults as overridden by configuration settings and run-time
environment variables available to the command.  This command will work even if
configuration is defective, so is a useful diagnostic tool.

Instance directory paths
------------------------

If **servald** is started with an *instance directory*, then all configuration,
state, and temporary files are stored in or beneath that directory, denoted
`IDIR`:

  * the configuration is stored in `IDIR/serval.conf`
  * the keyring is stored in `IDIR/serval.keyring`
  * the PID file is `IDIR/servald.pid`
  * the daemon creates its process information files under `IDIR/proc/`
  * the daemon creates and rotates log files files under `IDIR/log/`
  * the daemon creates and updates a symbolic link to the latest log file in
    `IDIR/servald.log`
  * the Rhizome store is in `IDIR/` (unless overridden by configuration):
    * the SQLite database is `IDIR/rhizome.db`
    * large payloads are stored under `IDIR/blob/`
  * the SQLite temporary directory is `IDIR/sqlite3tmp/`
  * dummy interface files are created under `IDIR/` (unless overridden by
    configuration)

The **servald** `start` command will create its instance directory (and all
enclosing parent directories) if it does not already exist.  Failure will cause
the daemon not to start.

About the examples
------------------

The examples in this document are [Bourne shell][] commands, using standard
quoting and variable expansion.  Commands issued by the user are prefixed with
the shell prompt `$` to distinguish them from the output of the command.
Single and double quotes around arguments are part of the shell syntax, so are
not seen by the command.  Lines ending in backslash `\` continue the command on
the next line.

Configuration commands
----------------------

### config set

To set a configuration option:

    $ servald config set name.of.option 'value'
    $

### config del

To unset (remove) a configuration option, returning it to its default value:

    $ servald config del name.of.option
    $

### config set del

Several **set** and **del** commands can be chained together in a single
command:

    $ servald config set debug.verbose 1 \
                     del debug.dnahelper \
                     set log.file.path /tmp/log.txt
    $

### config get

To examine a single option's current value as defined in the `serval.conf` file
(invalid, unsupported and illogical options may be examined, but not duplicate
options):

    $ servald config get name.of.option
    name.of.option=value
    $

To examine all option settings defined in the `serval.conf` file, including
invalid, unsupported and illogical options, but not duplicate options:

    $ servald config get
    interfaces=+eth0,+wifi0
    name.of.option=value
    name.of.other_option=value2
    $

### config schema

To list the names and types of all supported configuration options (the
“configuration schema”):

    $ servald config schema
    debug.broadcasts=(boolean)
    debug.dnahelper=(boolean)
    debug.dnaresponses=(boolean)
    ...
    server.chdir=(absolute_path)
    server.interface_path=(str_nonempty)
    server.respawn_on_crash=(boolean)
    $

The configuration schema, with its default values, is defined in the
[conf_schema.h](../conf_schema.h) source header file.

### config dump

To examine all current *valid* configuration option settings, as produced by
parsing `serval.conf` and omitting invalid, unsupported, duplicate and
illogical options (ie, the configuration used by permissive commands and for
logging):

    $ servald config dump --full
    debug.broadcasts=false
    debug.dnahelper=false
    debug.dnaresponses=false
    ...
    rhizome.rhizome_mdp_block_size=512
    server.chdir=/
    server.respawn_on_crash=true
    $

Omitting the `--full` argument omits all options which have their default
value, leaving only the minimal settings that need be present in `serval.conf`
to produce the current configuration:

    $ servald config dump
    debug.rhizome=true
    interfaces.0.file=/var/serval-node/dummy
    interfaces.0.socket_type=file
    rhizome.direct.peer.0.host=129.128.127.126
    server.respawn_on_crash=true
    $

Logging configuration
---------------------

**servald** logging is controlled by the following config options:

    log.console.level=debug|info|hint|warn|error|none
    log.console.dump_config=BOOLEAN
    log.console.show_pid=BOOLEAN
    log.console.show_time=BOOLEAN

    log.android.level=debug|info|hint|warn|error|none
    log.android.dump_config=BOOLEAN
    log.android.show_pid=BOOLEAN
    log.android.show_time=BOOLEAN

    log.file.level=debug|info|hint|warn|error|none
    log.file.dump_config=BOOLEAN
    log.file.show_pid=BOOLEAN
    log.file.show_time=BOOLEAN
    log.file.path=PATH
    log.file.directory_path=PATH
    log.file.duration=INTERVAL
    log.file.rotate=UINT

There are three log output destinations, each of which can be configured
independently of the others:

  * The *console* log destination is the standard error of the **servald**
    process, which is available in all command invocations of **servald**, but
    not in the background daemon process (the daemon closes all its standard IO
    streams when started in background mode).

  * The *android* log destination is available in **servald** executables built
    for the Android platform, and sends to the Android Log buffer that is
    accessible via the `adb logcat` command.  On non-Android platforms, the
    `log.android` configuration options are supported but have no effect.

  * The *file* log destination is a log file created and appended directly by
    the **servald** process using the O\_APPEND option of [open(2)][] and a
    single [write(2)][] system call per log line (so concurrent **servald**
    processes will not corrupt each others' log lines).  If the file does not
    exist, **servald** will create it and all its enclosing directories as
    needed.

All log destinations support the following configuration options:

  * `log.DESTINATION.level`  Log messages below this level are not sent to the
    destination.  The lowest level is `debug`, and the highest is `error`.
    Setting this option to `none` suppresses all log messages.

  * `log.DESTINATION.dump_config`  If true, then the current configuration is
    written to the destination (in `servald config dump` format), prior to
    other messages.

  * `log.DESTINATION.show_pid`  If true, then every line written to this
    destination is prefixed with the Process ID of the process that produced
    it.

  * `log.DESTINATION.show_time`  If true, then every line written to this
    destination is prefixed with the system time in millisecond resolution
    (if available) in the format `HH:MM:SS.mmm`.

In addition, the *file* destination has these extra configuration options:

  * `log.file.directory_path`  If set, log files are created in this directory,
    which is created if it does not exist.  Relative paths are interpreted
    relative to the `log` sub-directory of the instance directory.  The default
    setting (empty string) causes log files to be created within the `log`
    sub-directory of the instance directory.

  * `log.file.path`  If set, all log messages are appended directly to the file
    at the given path.  If the path is not absolute, it is interpreted relative
    the `log.file.directory_path` option.  If `log.file.path` is not set, then
    log files have names of the form `serval-YYYYMMDDHHMMSS.log`, using the
    date/time of creation of the file.

  * `log.file.duration`  If non zero, then a new log file is created every new
    interval.  Interval boundaries are measured from the Unix epoch, so if the
    interval is an integral divisor of one day then a new file will always
    start at midnight.  The interval can be given as a plain number of seconds,
    but a convenient scaled notation is supported: `[Nw][Nd][Nh][Nm][N[s]]`,
    eg, `2h40m20s` means two hours plus 40 minutes plis 20 seconds.

  * `log.file.rotate`  If non zero, then old log files are deleted so that no
    more than this many files exist at one time.

Every log message is written to all destinations according to their
configuration.

Network interfaces
------------------

The **servald** daemon periodically scans its operating system's network
interfaces and uses its `interfaces` configuration option to select which to
ignore and which to use.

For example, the following configuration will use any interface whose name
starts with `eth` (eg, `eth0`, `eth1`) on port 7333 and any interface whose
name starts with `wifi` or `wlan` but is not `wifi0` or `wlan0` as a [Wi-Fi][]
on the default port number:

    $ servald config set interfaces.0.match 'eth*' \
                     set interfaces.0.type ethernet \
                     set interfaces.0.port 7333 \
                     set interfaces.1.match 'wifi0,wlan0' \
                     set interfaces.1.exclude true \
                     set interfaces.2.match 'wifi*,wlan*' \
                     set interfaces.2.type wifi

The following configuration is equivalent to the above example, but uses the
“legacy”, single-option syntax (see below):

    $ servald config set interfaces \
        '+eth=ethernet:7333,-wifi0,-wlan0,+wifi=wifi,+wlan=wifi'

The following two equivalent configurations will use all available interfaces,
treating all as Wi-Fi (the default type) with a 400 µs inter-packet delay (the
default packet interval for Wi-Fi):

    $ servald config set interfaces.0.match '*'
    $ servald config set interfaces '+'

Network interface rules
-----------------------

As shown in the first example above, the `interfaces` config option contains a
numbered list of *rules* that are applied to all detected system interfaces in
order of ascending number.  The general form of an interface rule is:

    interfaces.UINT.match=PATTERN[, PATTERN ...]
    interfaces.UINT.file=PATH
    interfaces.UINT.exclude=BOOLEAN
    interfaces.UINT.socket_type=SOCKTYPE
    interfaces.UINT.port=PORT
    interfaces.UINT.encapsulation=ENCAPSULATION
    interfaces.UINT.default_route=BOOLEAN
    interfaces.UINT.prefer_unicast=BOOLEAN
    interfaces.UINT.send_broadcasts=BOOLEAN
    interfaces.UINT.type=IFTYPE
    interfaces.UINT.mdp_tick_ms=UINT_NONZERO
    interfaces.UINT.packet_interval=UINT_NONZERO

where:

 * PATTERN is a [shell wildcard][] pattern
 * BOOLEAN is `true`, `false`, `1`, `0`, `yes`, `no`, `on` or `off`
 * SOCKTYPE is `dgram`, `stream` or `file`
 * ENCAPSULATION is `overlay` or `single`
 * IFTYPE is `wifi`, `ethernet`, `catear` or `other`
 * PORT is an unsigned decimal integer in the range 1 to 65535
 * UINT is any unsigned decimal integer (with no `+` or `-` prefix)
 * UINT\_NONZERO is an unsigned decimal integer ≥ 1
 * PATH is an absolute or relative file path
 * IN\_ADDR is an Internet address as accepted by [inet_aton(3)][], ie,
   `N.N.N.N` where `N` is an integer in the range 0 to 255.

The `match` and `file` options are mutually incompatible.  If both are set, it
is an error; the interface rule is omitted from the configuration and
`serval.conf` is treated as defective (see above).  If neither are set, it is
also an error.

If a rule specifies a `match` option, then each PATTERN is applied to the names
of the real system interfaces using the [fnmatch(3)][] standard library
function.  If any PATTERN matches, then the rule's `exclude` option is checked:
if true, then the interface is not activated, otherwise a socket on that system
interface is opened and the interface's `socket_type` is set to `dgram`.  (It
is invalid to explicitly set `socket_type` to other than `dgram` for a match
interface.)

If a rule specifies a `file` path, then an interface is created *if the given
file exists*.  The interface's `socket_type` determines how the file is written
and read:

  * `file` (the default) creates a “dummy” interface for closed communication
    with other **servald** daemons on the same host -- see below.  If the file
    does not exist, a warning is logged and the interface is not activated.

  * `stream` reads and writes the file as though it were a [character special
    device][].  If the file does not exist, an error is logged and the
    interface is not activated.

  * `dgram` is not valid for a file interface.

The `type` option only affects the default settings the `packet_interval` and
`mdp_tick_ms` options, for convenience.  In future it may also change the way
the interface behaves, for example, an `ethernet` interface may automatically
assume that broadcast packets will be filtered out, so will start using MDP
unicast protocols immediately rather than waiting to detect that broadcast
packets are not acknowledged.

The `packet_interval` option controls the maximum rate at which packets are
tramsmitted on the interface.  It sets the *average* interval, in microseconds,
between individual packets.  If the interval is less than the time it takes to
transmit a packet, then packets will be sent at maximum speed with no
intervening delay.  Otherwise, delays are inserted between packets as needed to
keep to the average.

The `mdp_tick_ms` option controls the time interval, in milliseconds, between
MDB broadcast announcements on the interface.  If set to zero, it disables MDP
announcements altogether on the interface (called “tickless” mode).  If not
set, then the value of the `mdp.iftype.IFTYPE.tick_ms` option is used.  If that
is not set, then **servald** uses a built-in interval that depends on the
IFTYPE.

The `encapsulation` option controls how MDP packets are written to the
interface's socket:
  * `overlay` (the default) stuffs as many MDP packets as it can into each
    [UDP][] frame, to avoid wasting bandwidth on conventional [Wi-Fi][]
    interfaces which have a fixed packet size (the [IEEE 802.11][] [MTU][])
    over the air;
  * `single` sends each MDP packet on its own to the socket using [SLIP][]
    encoding, and is suited to data links with a variable packet size on the
    air (eg, a serial connection to a [packet radio][] modem).

The `default_route` option, if true, causes all MDP packets with an unresolved
recipient address (SID) to be sent to this interface instead of just dropped.
This will allow the node to use [Serval Infrastructure][] to route its packets.
Many interfaces may have the `default_route` set to true, but only the first
one will be used as the default route.

The `prefer_unicast` option, if true, causes the interface to send to unicast
IP addresses instead of the broadcast IP address if both have been observed to
reach the destination.

The `send_broadcasts` option, if false, prevents the interface from sending any
broadcast packets whenever a recipient address (SID) cannot be resolved to an
interface.  Normally, any MDP packet to an unresolvable recipient gets
broadcast on all active interfaces.

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
    +PREFIX=IFTYPE:PORT:IGNORED
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

Interface rules are numbered in the order they appear, and are applied in that
order.  For example, an `interfaces` option of `+,-eth0` will not reject the
*eth0* interface because the leading `+` will match it first, but `-eth0,+`
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
read pointer through the file, packet by packet, skipping packets which are not
addressed to it.  A single dummy file simulates a lossless mesh network with
total connectivity, ie, all nodes that read and write the file are neighbours.

To use a dummy interface, first create an empty file, eg, `/tmp/dummy`, and for
each servald instance, include the dummy file in its *interfaces* list, eg:

    $ servald config set interfaces.0.file '/tmp/dummy'

NOTE: Because dummynets are files, not sockets, the [poll(2)][] system call
does not work on them.  As a result the **servald** daemon main loop has
slightly different behaviour and timing characteristics when a dummynet is in
use.

If a dummy interface's `file` PATH is not absolute (ie, does not start with
`/`) then it is interpreted relative to the instance directory.

The following config options adorn a dummy interface with properties that real
interfaces normally obtain directly from the operating system:

    interfaces.UINT.dummy_address=IN_ADDR
    interfaces.UINT.dummy_netmask=IN_ADDR
    interfaces.UINT.drop_unicasts=BOOLEAN
    interfaces.UINT.drop_broadcasts=BOOLEAN

The `dummy_address` option sets the interface's unicast (receive) IP address.

The `dummy_netmask` option sets the interface's unicast (receive) IP network
mask, which together with `dummy_address` determines the interface's IP
broadcast address.

The `drop_unicasts`, option, if true, will drop overlay frames addressed to the
interface's unicast IP address, so that only broadcast packets will be read.

The `drop_broadcasts`, option, if true, will drop overlay frames addressed to
the interface's broadcast IP address, so that only unicast packets will be
read.  This can simulate the effects of the Fi-Fi drivers on some Android
devices that filter out broadcast packets (to prevent the device from waking up
unless there is traffic explicitly sent to it).


[Serval Project]: http://www.servalproject.org/
[Serval Infrastructure]: ./Serval-Infrastructure.md
[US-ASCII]: http://en.wikipedia.org/wiki/ASCII
[Bourne shell]: http://en.wikipedia.org/wiki/Bourne_shell
[isspace(3)]: http://linux.die.net/man/3/isspace
[shell wildcard]: http://www.kernel.org/doc/man-pages/online/pages/man7/glob.7.html
[open(2)]: http://www.kernel.org/doc/man-pages/online/pages/man2/open.2.html
[write(2)]: http://www.kernel.org/doc/man-pages/online/pages/man2/write.2.html
[poll(2)]: http://www.kernel.org/doc/man-pages/online/pages/man2/poll.2.html
[fnmatch(3)]: http://www.kernel.org/doc/man-pages/online/pages/man3/fnmatch.3.html
[inet_aton(3)]: http://www.manpagez.com/man/3/inet_aton
[Wi-Fi]: http://en.wikipedia.org/wiki/Wi-fi
[IEEE 802.11]: http://en.wikipedia.org/wiki/IEEE_802.11
[UDP]: http://en.wikipedia.org/wiki/User_Datagram_Protocol
[MTU]: http://en.wikipedia.org/wiki/Maximum_transmission_unit
[SLIP]: http://en.wikipedia.org/wiki/Serial_Line_Internet_Protocol
[packet radio]: http://en.wikipedia.org/wiki/Packet_radio
[character special device]: http://en.wikipedia.org/wiki/Device_file#Character_devices
