Serval DNA Build and Test
=========================
[Serval Project][], March 2013

Supported Architectures
-----------------------

These instructions will build [Serval DNA][] successfully for the following platforms:

 * Debian Linux, ix86 and x86\_64, kernels 2.6.x and 3.x, using [gcc 4.4][] to
   [gcc 4.8][]
 * Mac OS X x86\_64, releases 10.7 “Lion” to 10.11 “El Capitan”, using [gcc
   4.2][] available in [Xcode][] versions 3.2 to 7.2, and GNU tools available
   from [homebrew][]
 * Oracle SunOs 5.10 (Solaris), Sparc, using [gcc 4.4][] and GNU tools
   installed

[Serval DNA][] also runs on the following platforms, to which these build
instructions do not apply:

 * [Android 2.2 “Froyo”][], Arm, Linux kernels 2.6.x and 3.x, using [gcc 4.4][]
   supplied as part of [Android NDK][] Revision 7b
 * [OpenWRT][] (as used by the [Serval Mesh Extender][], the [Mesh Potato][],
   and the [Commotion Wireless][] project)

Download
--------

Serval DNA source code is available from the [serval-dna][] repository on
GitHub.  You can use [Git][] to download the latest version:

    $ cd $HOME/src
    $ git clone -q git://github.com/servalproject/serval-dna.git
    $ cd serval-dna
    $

Dependencies
------------

The dependencies for build are expressed in [configure.in](./configure.in).
Most mandatory dependencies are present in the standard Linux development
environment.

Mandatory dependencies:

 * standard C library `libc` and standard headers
 * standard math library `libm` and headers `<math.h>` `<float.h>`
 * network services library `libnsl` and headers
 * socket library `libsocket` and headers
 * dynamic link library `libdl` and header `<dlfcn.h>`
 * Native Posix Threads Library `libpthread` and header `<pthread.h>`
 * on Solaris, the realtime library `librt` (for the `nanosleep()` function)
 * Autoconf 2.67-2.69 (2.70 may work but has not been tested)
 * Automake 1.15

Optional:

 * Java compiler and SDK (mandatory for Android's **libservald.so**)
 * ALSA sound library and headers (only present on Linux not Android)

Test dependencies:

 * bash 3.2.48 or later
 * GNU grep, sed and awk (on OSX and Solaris, as ggrep, gsed and gawk)
 * jq 1.3 or later
 * curl

The GNU grep, sed and awk programs can be installed on OSX using the
[homebrew][] package manager.  The [Notes for Developers](./doc/Development.md)
give more details.

Build
-----

To compile a native (ie, not cross-compiled) Serval DNA from source, run the
following commands:

    $ cd $HOME/src/serval-dna
    $ autoreconf -f -i -I m4
    $ ./configure
    $ make
    $

A successful session should appear something like:

    $ cd $HOME/src/serval-dna
    $ autoreconf -f -i -I m4
    aclocal: warning: autoconf input should be named 'configure.ac', not 'configure.in'
    $ ./configure
    checking build system type... i686-pc-linux-gnu
    checking host system type... i686-pc-linux-gnu
    checking target system type... i686-pc-linux-gnu
    checking for pkg-config... /usr/bin/pkg-config
    checking pkg-config is at least version 0.9.0... yes
    checking for gcc... gcc
    ...
    checking for library containing strlcpy... no
    configure: creating ./config.status
    config.status: creating Makefile
    config.status: creating testconfig.sh
    $ make
    SERVALD CC conf.c
    SERVALD CC cli.c
    ...
    CC cli.c
    CC commandline.c
    ...
    CC xprintf.c
    LINK servald
    LINK libmonitorclient.so
    AR libmonitorclient.a
    CC tfw_createfile.c
    LINK tfw_createfile
    $

On Solaris, the system `make` command may not be GNU Make, and the system
`cc` command may not be GNU Gcc.  The following may work:

    $ cd $HOME/src/serval-dna
    $ autoreconf -f -i -I m4
    $ CC=gcc
    $ export CC
    $ ./configure
    $ gmake
    $

In the event of a build failure, first consult the [Notes for
Developers](./doc/Development.md), then [contact the Serval Project][].

Built artifacts
---------------

The build process produces the following artifacts:

* **servald** is the main Serval DNA executable.

* **libservald.so** is a shared library built only for Android, which is linked
  into the [batphone][] Java executable at run time to provide the [JNI][]
  entry points to servald.

* **directory_service** is the executable for the Serval Infrastructure daemon.

* **libmonitorclient.a** and **libmonitorclient.so** are libraries implementing
  the client end of the monitor interface with the servald daemon.  They are
  linked into the [batphone][] Java executable at run time and contain [JNI][]
  entry points to functions for managing the client end of a monitor connection
  with the servald daemon.

* **fakeradio** is a utility used by test scripts to simulate the serial
  interface to the [RFD900][] packet radio used in the [Serval Mesh Extender][]

* **simulator** is a utility used by test scripts for simulating wireless
  packet transmission under different conditions.

* **tfw_createfile** is a utility needed by test scripts for creating large
  data files with unique, non-repeating content.

* **config_test** is a utility that will fail to link if any external
  dependencies creep into the configuration subsystem.

Test scripts
------------

After building the native `servald` executable, run all the tests with the
following command:

    $ ./tests/all
    1 [PASS.] (logging) By default, only errors and warnings are logged to stderr
    2 [PASS.] (logging) Configure all messages logged to stderr
    3 [PASS.] (logging) Configure no messages logged to stderr
    4 [PASS.] (logging) By Default, all messages are appended to a configured file
    ...
    158 [PASS.] (rhizomeprotocol) One way direct pull bundle from configured peer
    159 [PASS.] (rhizomeprotocol) Two-way direct sync bundles with configured peer
    160 [PASS.] (directory_service) Publish and retrieve a directory entry
    161 [PASS.] (directory_service) Ping via relay node
    161 tests, 161 pass, 0 fail, 0 error
    $

Every test run writes log files into the [testlog/all](./testlog/all/)
directory (relative to the current working directory), deleting any logs from
the previous run.

See [Serval DNA Testing](./doc/Testing.md) for more information on running and
developing test scripts.

Configure
---------

Before running `servald`, it must be configured correctly.  The
[doc/Servald-Configuration](./doc/Servald-Configuration.md) document describes
the configuration of Serval DNA in detail.

About the examples
------------------

The examples in this document are [Bourne shell][] commands, using standard
quoting and variable expansion.  Commands issued by the user are prefixed with
the shell prompt `$` to distinguish them from the output of the command.
Single and double quotes around arguments are part of the shell syntax, so are
not seen by the command.  Lines ending in backslash `\` continue the command on
the next line.

The directory paths used in the examples are for illustrative purposes only,
and may need to be changed for your particular circumstances.

-----
**Copyright 2013 Serval Project Inc.**  
![CC-BY-4.0](./cc-by-4.0.png)
This document is available under the [Creative Commons Attribution 4.0 International licence][CC BY 4.0].


[Serval Project]: http://www.servalproject.org/
[Serval DNA]: ./README.md
[serval-dna]: https://github.com/servalproject/serval-dna
[batphone]: https://github.com/servalproject/batphone
[Android 2.2 “Froyo”]: http://developer.android.com/about/versions/android-2.2-highlights.html
[Android NDK]: http://developer.android.com/tools/sdk/ndk/index.html
[gcc 4.2]: http://gcc.gnu.org/gcc-4.2/
[Xcode]: https://developer.apple.com/xcode/
[gcc 4.4]: http://gcc.gnu.org/gcc-4.4/
[gcc 4.7]: http://gcc.gnu.org/gcc-4.7/
[OpenWRT]: ./doc/OpenWRT.md
[Serval Mesh Extender]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:meshextender:
[contact the Serval Project]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:contact
[RFD900]: http://rfdesign.com.au/index.php/rfd900
[Mesh Potato]: http://villagetelco.org/mesh-potato/
[Commotion Wireless]: http://commotionwireless.net/
[JNI]: http://en.wikipedia.org/wiki/Java_Native_Interface
[Bash]: http://en.wikipedia.org/wiki/Bash_(Unix_shell)
[GNU make]: http://www.gnu.org/software/make/
[Git]: http://git-scm.com/
[Subversion]: http://subversion.apache.org/
[Bourne shell]: http://en.wikipedia.org/wiki/Bourne_shell
[homebrew]: http://brew.sh/
[CC BY 4.0]: ./LICENSE-DOCUMENTATION.md
