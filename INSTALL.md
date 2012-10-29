Serval DNA Build and Test
=========================

To build
--------

    autoconf
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

Built artefacts
---------------

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

Testing
-------

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
