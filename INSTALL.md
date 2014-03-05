Serval DNA Build and Test
=========================
[Serval Project], March 2013

Supported Architectures
-----------------------

These instructions will build [Serval DNA][] successfully for the following platforms:

 * Debian Linux, ix86 and x86\_64, kernels 2.6.x and 3.x, using [gcc 4.4][] to
   [gcc 4.8][]
 * Mac OS X 10.7 “Lion”, x86\_64, using [gcc 4.2][] available in [Xcode 4][]
   3.2.6
 * Oracle SunOs 5.10 (Solaris), Sparc, using [gcc 4.4][]

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
 * Autoconf 2.67 or later
 * on Solaris, the realtime library `librt` (for the `nanosleep()` function)

Optional:

 * Java compiler and SDK (mandatory for Android's **libservald.so**)
 * ALSA sound library and headers (only present on Linux not Android)

Test dependencies:

 * bash 3.2.48 or later
 * jq 1.3 or later
 * curl

Build
-----

To compile Serval DNA from source, run the following commands:

    $ cd $HOME/src/serval-dna
    $ autoreconf -f -i
    $ ./configure
    $ make
    $

A successful session should appear something like:

    $ cd $HOME/src/serval-dna
    $ autoreconf -f -i
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
    CC nacl/src/crypto_auth_hmacsha256_ref/hmac.c
    CC nacl/src/crypto_auth_hmacsha256_ref/verify.c
    CC nacl/src/crypto_auth_hmacsha512256_ref/hmac.c
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
    $ autoreconf -f -i
    $ CC=gcc
    $ export CC
    $ ./configure
    $ gmake
    $

Built artifacts
---------------

The build process produces the following artifacts:

* **servald** is the main executable.

* **libservald.so** is a shared library built only for Android, which is linked
  into the [batphone][] Java executable at run time to provide the [JNI][]
  entry points to servald.

* **directory_service** is the executable for the Serval Infrastructure daemon.

* **libmonitorclient.a** and **libmonitorclient.so** are libraries implementing
  the client end of the monitor interface with the servald daemon.  They are
  linked into the [batphone][] Java executable at run time and contain [JNI][]
  entry points to functions for managing the client end of a monitor connection
  with the servald daemon.

Test scripts
------------

The scripts in the [tests](./tests/) directory require [Bash][] version 3.2.48
or later.  To run tests, simply build a native `servald` executable then invoke
the test script.  Each test case is executed in its own self-contained
temporary directory with its own set-up and configuration, so there is no need
to configure anything or clean up afterwards.

For example, the following command runs all the tests except long-running,
resource-hungry “stress” tests:

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

There are options to run tests concurrently for faster results, and to select
subsets of test cases.  To see the options, give the `--help` option:

    $ ./tests/all --help

Every test run writes its log files into the [testlog/all](./testlog/all/)
directory, deleting all logs from the previous run.

Configure
---------

The [doc/Servald-Configuration](./doc/Servald-Configuration.md) document
describes the configuration of Serval DNA in detail.

Voice call test
---------------

If the following packages are present then `./configure` will set the
`HAVE_VOIPTEST` macro and build **servald** with its `phone` command available
for performing voice call testing:

 * [Port audio](http://www.portaudio.com)
 * [Secret Rabbit Code](http://www.mega-nerd.com/SRC/) (a.k.a. Sample Rate
   Convert) by Erik de Castro Lopo
 * [SpanDSP](http://www.soft-switch.org/) by Steve Underwood
 * [Codec2](http://www.rowetel.com/blog/?page_id=452) by Dave Rowe of Rowetel

The Codec2 source code can be fetched using [Subversion][]:

    $ cd $HOME/src
    $ svn checkout https://freetel.svn.sourceforge.net/svnroot/freetel/codec2 codec2
    $

There are command-line options to control the `HAVE_VOIPTEST` macro:

 * To force `HAVE_VOIPTEST` to be set, and fail if the necessary packages are
   not present, use:

        $ ./configure --enable-voiptest

 * To force `HAVE_VOIPTEST` to be un-set (and not check for the presence of the
   above packages), use:

        $ ./configure --disable-voiptest

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


[Serval Project]: http://www.servalproject.org/
[Serval DNA]: ./README.md
[serval-dna]: https://github.com/servalproject/serval-dna
[batphone]: https://github.com/servalproject/batphone
[Android 2.2 “Froyo”]: http://developer.android.com/about/versions/android-2.2-highlights.html
[Android NDK]: http://developer.android.com/tools/sdk/ndk/index.html
[gcc 4.2]: http://gcc.gnu.org/gcc-4.2/
[Xcode 4]: https://developer.apple.com/xcode/
[gcc 4.4]: http://gcc.gnu.org/gcc-4.4/
[gcc 4.7]: http://gcc.gnu.org/gcc-4.7/
[OpenWRT]: ./doc/OpenWRT.md
[Serval Mesh Extender]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:meshextender:
[Mesh Potato]: http://villagetelco.org/mesh-potato/
[Commotion Wireless]: http://commotionwireless.net/
[JNI]: http://en.wikipedia.org/wiki/Java_Native_Interface
[Bash]: http://en.wikipedia.org/wiki/Bash_(Unix_shell)
[GNU make]: http://www.gnu.org/software/make/
[Git]: http://git-scm.com/
[Subversion]: http://subversion.apache.org/
[Bourne shell]: http://en.wikipedia.org/wiki/Bourne_shell
