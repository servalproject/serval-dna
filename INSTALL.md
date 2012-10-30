Serval DNA Build and Test
=========================

To build
--------

Run the following commands:

    autoreconf -f -i
    ./configure
    make

Supported Targets
-----------------

The Serval DNA code successfully builds for the following platforms:

 * Debian Linux, ix86 and x86\_64, kernels 2.6.x and 3.x, [gcc 4.4][] to [gcc 4.7][]
 * [Android 2.2 “Froyo”][], Arm, Linux kernels 2.6.x and 3.x, [gcc 4.4][] supplied as
   part of [Android NDK][] Revision 7b
 * Mac OS X 10.7 “Lion”, x86\_64, [gcc 4.2][] available in [Xcode 4][] 3.2.6
 * Oracle SunOs 5.10 (Solaris), Sparc, [gcc 4.4][]

Dependencies
------------

The dependencies for build are expressed in [configure.in](./configure.in).
Most mandatory dependencies are present by default in a conventional Linux
development environment.

Mandatory dependencies:

 * standard C library `libc` and standard headers
 * standard math library `libm` and headers `<math.h>` `<float.h>`
 * network services library `libnsl` and headers
 * socket library `libsocket` and headers
 * dynamic link library `libdl` and header `<dlfcn.h>`
 * Native Posix Threads Library `libpthread` and header `<pthread.h>`
 * on Solaris, the realtime library `librt` (for the `nanosleep()` function)

Optional:

 * Java compiler and SDK (mandatory for Android's **libservald.so**)
 * ALSA sound library and headers (only present on Linux not Android)

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

Voice call test
---------------

If the following packages are present then `./configure` will set the
`HAVE_VOIPTEST` macro and build **servald** with its `phone` command available
for performing voice call testing:

 * [Port audio](http://www.portaudio.com)
 * [Secret Rabbit Code](http://www.mega-nerd.com/SRC/) (a.k.a. Sample Rate
   Convert) by Erik de Castor Lopo
 * [SpanDSP](http://www.soft-switch.org/) by Steve Underwood
 * [Codec2](http://www.rowetel.com/blog/?page_id=452) by Dave Rowe of Rowetel

The Codec2 source code can be fetched using [Subversion][]:

    svn checkout https://freetel.svn.sourceforge.net/svnroot/freetel/codec2 codec2

The following options can be used to control the `HAVE_VOIPTEST` macro:

 * `./configure --enable-voiptest` will set `HAVE_VOIPTEST` and fail if the
   necessary packages are not present

 * `./configure --disable-voiptest` will unset `HAVE_VOIPTEST` and will not
   check for presence of the above packages

Test scripts
------------

The scripts in the [tests](./tests/) directory require [Bash][] version 3.2.48
or later.  To run the tests, build the `servald` executable natively using [GNU
make][], then invoke them manually:

    ./tests/config
    ./tests/directory_service
    ./tests/dnahelper
    ./tests/dnaprotocol
    ./tests/jni
    ./tests/rhizomeops
    ./tests/rhizomeprotocol
    ./tests/rhizomestress
    ./tests/routing
    ./tests/server

There are options to run tests concurrently for faster results, and to select
subsets of test cases within each script.  To see the options, give the
`--help` option to any script:

    ./tests/server --help

The logs of the most recent test runs are under the [testlog](./testlog/)
directory.


[batphone]: https://github.com/servalproject/batphone
[Android 2.2 “Froyo”]: http://developer.android.com/about/versions/android-2.2-highlights.html
[Android NDK]: http://developer.android.com/tools/sdk/ndk/index.html
[gcc 4.2]: http://gcc.gnu.org/gcc-4.2/
[Xcode 4]: https://developer.apple.com/xcode/
[gcc 4.4]: http://gcc.gnu.org/gcc-4.4/
[gcc 4.7]: http://gcc.gnu.org/gcc-4.7/
[JNI]: http://en.wikipedia.org/wiki/Java_Native_Interface
[Bash]: http://en.wikipedia.org/wiki/Bash_(Unix_shell)
[GNU make]: http://www.gnu.org/software/make/
[Subversion]: http://subversion.apache.org/
