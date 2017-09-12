Serval DNA Build and Test
=========================
[Serval Project][], September 2017

Supported Architectures
-----------------------

These instructions will build [Serval DNA][] successfully for the following platforms:

 * Debian Linux, ix86 and x86\_64, kernel versions 2.6 to 4.12, using [gcc
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
 * on Solaris, the realtime library **librt** (for the `nanosleep()` function)
 * **autoconf** 2.67-2.69 (2.70 may work but has not been tested)
 * **automake** 1.15

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
    SERVALD CC servald_features.c
    MAKE libsodium-dev
    make[1]: Entering directory '/home/username/src/serval-dna/libsodium'
    Making install in contrib
    make[2]: Entering directory '/home/username/src/serval-dna/libsodium/contrib'
    ...
    make[4]: Leaving directory '/home/username/src/serval-dna/libsodium/src/libsodium/include'
    make[4]: Entering directory '/home/username/src/serval-dna/libsodium/src/libsodium'
      CC       crypto_aead/chacha20poly1305/sodium/libsodium_la-aead_chacha20poly1305.lo
      CC       crypto_aead/xchacha20poly1305/sodium/libsodium_la-aead_xchacha20poly1305.lo
      CC       crypto_auth/libsodium_la-crypto_auth.lo
    ...
    ----------------------------------------------------------------------
    Libraries have been installed in:
       /home/username/src/serval-dna/libsodium-dev/lib
    ...
    make[1]: Leaving directory '/home/username/src/serval-dna/libsodium'
    SERVALD CC jni_common.c
    SERVALD CC jni_commandline.c
    SERVALD CC jni_instance.c
    ...
    CC version_servald.c
    AR _servald.a
    LINK libservaldaemon.so
    LIB CC base64.c
    LIB CC cli.c
    LIB CC cli_stdio.c
    ...
    LINK simulator
    SERVALD CC test_features.c
    LINK serval-tests
    make[1]: Entering directory '/home/username/src/serval-dna/java-api'
    JAVAC classes
    JAVAC testclasses
    Note: Some input files use or override a deprecated API.
    Note: Recompile with -Xlint:deprecation for details.
    make[1]: Leaving directory '/home/username/src/serval-dna/java-api'
    rm _servalclient.a _monitorclient.a _servald.a
    $

On some systems, the system `make` command may not be GNU Make, and the system
`cc` command may not be GNU gcc.  The following may work:

    $ cd $HOME/src/serval-dna
    $ autoreconf -f -i -I m4
    $ ./configure CC=gcc
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
  daemon, SQLite and libsodium code is statically linked into this executable,
  so it does not need to load any Serval or libsodium shared libraries at
  run-time.  Its unstripped size is about 9.5 MB on a typical 64-bit system, of
  which about 7 MB is SQLite.  Its stripped size is about 3 MB.

* **servaldwrap** is a Serval DNA executable identical to *servald*, but
  it loads `libservaldaemon.so` at run-time using [dlopen(3)][] instead of
  being statically linked, so it is only a dozen KB in size.  This executable
  mainly exists to test that the shared library is loadable.

* **serval-tests** is an executable utility that performs various system tests
  such as memory speed, cryptographic speed, byte ordering, and configuration
  parsing.  These tests are not normally required in a deployed system, so are
  provided in a separate executable in order to keep the size of the *servald*
  executable to a minimum.

* **libservaldaemon.a** is a static library containing the complete executable
  code of the Serval DNA daemon, including SQLite and libsodium cryptographic
  functions.  An executable (such as *servald*) can be built with any desired
  subset of Serval functions by linking in only the required parts of this
  library using the *features* mechanism described in [feature.h](./feature.h).

* **libservaldaemon.so** is a dynamic library containing the complete executable
  code of the Serval DNA daemon, including [JNI][] entry points, SQLite and
  libsodium cryptographic functions.  The Serval DNA Java API, which is used by
  [batphone][], and the *servaldwrap* executable both use this dynamic library.

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
**Copyright 2016-2017 Flinders University**  
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
