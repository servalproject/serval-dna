Serval DNA Build and Test
=========================
[Serval Project][], October 2016

Supported Architectures
-----------------------

These instructions will build [Serval DNA][] successfully for the following platforms:

 * Debian Linux, ix86 and x86\_64, kernel versions 2.6 to 4.6, using [gcc
   4.4][] and later, [gcc 5][] and [gcc 6][]
 * Mac OS-X x86\_64, releases 10.7 “Lion” to 10.11 “El Capitan”, using
   [Xcode][] versions 3.2 to 8, and GNU tools available from [homebrew][]
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

The dependencies for build are expressed in [configure.ac](./configure.ac).
Most mandatory dependencies are present in the standard Linux development
environment.

Mandatory dependencies:

 * standard C library **libc** and standard headers
 * standard math library **libm** and headers `<math.h>` `<float.h>`
 * network services library **libnsl** and headers
 * dynamic link library **libdl** and header `<dlfcn.h>`
 * Native Posix Threads Library **libpthread** and header `<pthread.h>`
 * elliptic curve encryption library **libsodium** and header `<sodium.h>`,
   version 1.0.2 or greater
 * on Solaris, the realtime library **librt** (for the `nanosleep()` function)
 * **autoconf** 2.67-2.69 (2.70 may work but has not been tested)
 * **automake** 1.15

The **libsodium** development files are available on Debian/Ubuntu systems in
the `libsodium-dev` package.  On other systems, like Mac OS-X, it must be
compiled from source.  The [Notes for Developers][] give more details.

Optional:

 * Java compiler and SDK
 * ALSA sound library and headers (present on Linux, not on Android)

Test dependencies:

 * bash 3.2.48 or later
 * GNU grep, sed and awk (on Mac OS-X and Solaris, as ggrep, gsed and gawk)
 * jq 1.3 or later
 * curl

**Bash** and **curl** are both provided by the [XCode][] package for Mac OS X.
**GNU grep**, **GNU sed**, **GNU awk** and **jq** can all be installed on Mac
OS-X using the [homebrew][] package manager.  The [Notes for Developers][] give
more details.

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
    LINK simulator
    SERVALD CC test_cli.c
    SERVALD CC log_context.c
    SERVALD CC log_stderr.c
    SERVALD CC context1.c
    LINK serval-tests
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

In the event of a build failure:

 * ensure that all the [dependencies](#dependencies) are present
 * consult the [Notes for Developers][]
 * as a last resort, [contact the Serval Project][]

Built artifacts
---------------

The build process produces the following artifacts:

* **servald** is the main Serval DNA daemon executable.  All the Serval DNA
  daemon code is statically linked into this executable, so it does not depend
  on any built Serval libraries.  However, it is dynamically linked with the
  system libraries and with `libsodium.so`.

* **servaldwrap** is a Serval DNA executable identical to *servald*, but
  dynamically linked with `libservald.so` instead of statically linked.  This
  executable mainly exists to ensure that the shared library is always
  linkable.

* **serval-tests** is an executable utility that performs various system tests
  such as memory speed, cryptographic speed, byte ordering, and configuration
  parsing.  These tests are not normally required in a deployed system, so are
  provided in a separate executable in order to keep the size of the *servald*
  executable to a minimum.

* **libservald.a** is a static library containing the complete executable code
  of the Serval DNA daemon.  An executable (such as *servald*) can be built
  with any desired subset of Serval functions by linking in only the required
  parts of this library using the *features* mechanism described in
  [feature.h](./feature.h).

* **libservald.so** is a dynamic library containing the complete executable
  code of the Serval DNA daemon, including [JNI][] entry points.  The Serval
  DNA Java API, which is used by [batphone][], and the *servaldwrap* executable
  both use this dynamic library.

* **directory_service** is the executable for the [Serval Infrastructure][]
  daemon.

* **libservalclient.a** and **libservalclient.so** are static and dynamic
  libraries implementing the client end of the interface with the servald
  daemon, which includes the [MDP API][], a subset of the [CLI API][], and
  functions for starting and stopping the daemon.  The dynamic library is
  linked into the [batphone][] Java executable at run time and contains [JNI][]
  entry points to these APIs.

* **libmonitorclient.a** and **libmonitorclient.so** are static and dynamic
  libraries implementing the client end of the monitor interface with the
  servald daemon.  The dynamic library is linked into the [batphone][] Java
  executable at run time and contains [JNI][] entry points to functions for
  managing the client end of a monitor connection with the servald daemon.
  *The monitor interface is deprecated and will eventually be replaced by a set
  of equivalent [MDP][] services that can be accessed using libservalclient.*

* **fakeradio** is an executable utility used by test scripts to simulate the
  serial interface to the [RFD900][] packet radio used in the [Serval Mesh
  Extender][]

* **simulator** is an executable utility used by test scripts for simulating
  wireless packet transmission under different conditions.

* **tfw_createfile** is an executable utility needed by test scripts for
  creating large data files with unique, non-repeating content.

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
    375 [PASS.] (meshmsjava) Java API send MeshMS message from unknown identity
    376 [PASS.] (meshmsjava) Java API MeshMS mark all conversations read
    377 [PASS.] (meshmsjava) Java API MeshMS mark all conversations read
    378 [PASS.] (meshmsjava) Java API MeshMS mark a message as read
    378 tests, 378 pass, 0 fail, 0 error
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
**Copyright 2013-2015 Serval Project Inc.**  
**Copyright 2016 Flinders University**  
![CC-BY-4.0](./cc-by-4.0.png)
This document is available under the [Creative Commons Attribution 4.0 International licence][CC BY 4.0].


[Serval Project]: http://www.servalproject.org/
[Serval DNA]: ./README.md
[serval-dna]: https://github.com/servalproject/serval-dna
[batphone]: https://github.com/servalproject/batphone
[Android 2.2 “Froyo”]: http://developer.android.com/about/versions/android-2.2-highlights.html
[Android NDK]: http://developer.android.com/tools/sdk/ndk/index.html
[Xcode]: https://developer.apple.com/xcode/
[gcc 4.4]: http://gcc.gnu.org/gcc-4.4/
[gcc 5]: http://gcc.gnu.org/gcc-5/
[gcc 6]: http://gcc.gnu.org/gcc-6/
[Notes for Developers]: ./doc/Development.md
[OpenWRT]: ./doc/OpenWRT.md
[Serval Infrastructure]: ./doc/Serval-Infrastructure.md
[Serval Mesh Extender]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:meshextender:
[contact the Serval Project]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:contact
[RFD900]: http://rfdesign.com.au/index.php/rfd900
[Mesh Potato]: http://villagetelco.org/mesh-potato/
[Commotion Wireless]: http://commotionwireless.net/
[MDP]: ./doc/Mesh-Datagram-Protocol.md
[MDP API]: ./doc/Mesh-Datagram-Protocol.md#mdp-api
[CLI API]: ./doc/CLI-API.md
[JNI]: http://en.wikipedia.org/wiki/Java_Native_Interface
[Bash]: http://en.wikipedia.org/wiki/Bash_(Unix_shell)
[GNU make]: http://www.gnu.org/software/make/
[Git]: http://git-scm.com/
[Subversion]: http://subversion.apache.org/
[Bourne shell]: http://en.wikipedia.org/wiki/Bourne_shell
[XCode]: https://developer.apple.com/xcode/
[homebrew]: http://brew.sh/
[CC BY 4.0]: ./LICENSE-DOCUMENTATION.md
