Notes for Serval DNA Developers
===============================
[Serval Project][], May 2018

This document is intended for all developers of [Serval DNA][], and also for
non-developers who are experiencing errors in the [build][] process.

Introduction
------------

The [Serval DNA][] development and [build][] toolchain is completely oriented
around the [Bash shell][] command-line on [Unix][] platforms such as
[GNU][]/[Linux][] and [Darwin][], and uses [GNU autoconf][] achieve portability
between different platforms.

To date, the [Serval Project][] has not dedicated effort to integrating with
[IDE][]s such as [Android Studio][] or supporting non-Unix platforms such as
[Microsoft Windows][], because the ongoing effort of maintaining compatibility
with so many platforms would detract from the development of core features.
Anybody is welcome to contribute support for more platforms, but at this stage,
the Serval Project cannot commit to maintaining any contributed integrations.

Autotools
---------

The [configure.ac][] file is a [GNU autoconf][] script that contains
instructions for adapting the build of Serval DNA to different platforms and
CPU architectures.  This script makes use of many [GNU M4][] macros, each of
which tests an aspect of the build environment, such as the make and version of
the C compiler (eg, [GCC][], [Clang][]), the availability of headers, functions
and system calls in the standard library, and so forth.

Most of these M4 macros are standard, either supplied with [GNU autoconf][] or
from the [autoconf macro archive][].  Some macros are specific to Serval DNA,
either to improve on a standard macro or perform a test for which no standard
macro exists.  These extra macros are locally defined in files within the
[m4](../m4) sub-directory.

The [autoreconf][] command used in the [build][] instructions generates an
`aclocal.m4` file that includes all the necessary files from the [m4](../m4)
directory.  In turn, it then includes this `aclocal.m4` file when invoking [GNU
M4][] to convert the [configure.ac][] file into the `./configure` script.

When invoked without arguments, all [autoreconf][] versions up to 2.69 will
emit warning messages like this:

    $ cd serval-dna
    $ aclocal
    configure.ac:19: warning: Unsupported attribute section, the test may fail
    ../../lib/autoconf/lang.m4:224: AC_LANG_SOURCE is expanded from...
    ../../lib/autoconf/lang.m4:241: AC_LANG_PROGRAM is expanded from...
    ../../lib/autoconf/lang.m4:193: AC_LANG_CONFTEST is expanded from...
    ../../lib/autoconf/general.m4:2672: _AC_LINK_IFELSE is expanded from...
    ../../lib/autoconf/general.m4:2689: AC_LINK_IFELSE is expanded from...
    ../../lib/m4sugar/m4sh.m4:639: AS_IF is expanded from...
    ../../lib/autoconf/general.m4:2042: AC_CACHE_VAL is expanded from...
    ../../lib/autoconf/general.m4:2063: AC_CACHE_CHECK is expanded from...
    /usr/share/aclocal/ax_gcc_var_attribute.m4:57: AX_GCC_VAR_ATTRIBUTE is expanded from...
    configure.ac:19: the top level
    $

These messages mean that the generated `aclocal.m4` file does not contain the
M4 macros provided by Serval DNA, but instead contains the default ones that
from the [autoconf macro archive][].  As a consequence, the `./configure`
script may not test for certain features correctly, leading to compilation
failure or subtle bugs.

The correct way to invoke [autoreconf][] versions 2.69 or earlier is to give
the `-I m4` option, which will eliminate the warnings:

    $ cd serval-dna
    $ autoreconf -f -i -I m4
    $

The `-I m4` option should be unnecessary in [autoreconf][] versions 2.70 and
later, because they will deduce it from the `AC_CONFIG_MACRO_DIR([m4])`
directive near the top of [configure.ac][].

Linker
------

The default GNU linker (based on the BFD library) does not support relocation
of some symbols produced by the Swift compiler:

    relocation R_X86_64_PC32 against protected symbol `...' can not be used when making a shared object

The Serval DNA dynamic library is linked using the GNU [gold][] linker
(available in GNU binutils since 2008), which does not have this problem.

libsodium
---------

[Serval DNA][] uses the [libsodium][] cryptographic library for elliptic curve
encryption, authentication and secure hashing.

[libsodium][] is a portable, cross-compilable fork of [NaCl][], with a
compatible API.  The design choices in NaCl-libsodium, particularly in regard
to the [Curve25519][] Diffie-Hellman function, emphasise security, and the
“magic constants" in NaCl-libsodium have clear rationales.  By contrast, the
[NIST][] standard curves emphasise “performance" at the cost of security and do
not describe the specific origins of certain constants.  Despite the emphasis
on higher security, NaCl-libsodium primitives are faster across-the-board than
most implementations of the NIST standards.

A copy of the libsodium source code is embedded within the Serval DNA source
code under the `libsodium` subdirectory, using [git subtree][].  Developers do
not need to take any special steps to compile or install this libsodium source
code, because Serval DNA does it automatically:

* the [autoreconf][] command automatically recurses into the libsodium
  subdirectory;
* [Autotools](#autotools) `./configure` script automatically runs the
  `libsodium/configure` script;
* the `make` command automatically recurses into the libsodium directory *the
  first time that it is run*.

The Serval DNA build system has not been set up to facilitate development of
the libsodium source code itself.  The Serval DNA `make` command will only
recurse into the libsodium directory the first time it runs.  If a developer
subsequently alters a libsodium source file, he/she must run `cd libsodium;
make` manually to compile it, then run the Serval DNA `make`, which will
recompile the entire Serval DNA source code.

Upgrading libsodium
-------------------

To upgrade the embedded [libsodium](#libsodium) source code to a later version,
for example to its (hypothetical) tag `1.0.77`:

    $ cd serval-dna
    $ git subtree pull --prefix libsodium git@github.com:jedisct1/libsodium.git \
          --squash 1.0.77 --message 'Merge libsodium 1.0.77'
    $

Beware: Git does not support rebasing of subtree merge commits.

Debian/Ubuntu
-------------

A single [apt-get][] command will install all mandatory and testing
dependencies before building on [Debian][] and [Ubuntu][] systems:

    $ sudo apt-get --yes install libc6-dev jq curl
    Reading package lists... Done
    Building dependency tree
    Reading state information... Done
    libc6-dev is already the newest version (2.23-5).
    The following NEW packages will be installed:
      curl jq
    0 upgraded, 2 newly installed, 0 to remove and 0 not upgraded.
    Need to get 544 kB of archives.
    After this operation, 1,683 kB of additional disk space will be used.
    Get:1 http://ftp.us.debian.org/debian testing/main amd64 curl amd64 7.50.1-1 [218 kB]
    Get:2 http://ftp.us.debian.org/debian testing/main amd64 jq amd64 1.5+dfsg-1 [156 kB]
    Fetched 374 kB in 1s (304 kB/s)
    Selecting previously unselected package curl.
    (Reading database ... 205089 files and directories currently installed.)
    Preparing to unpack .../0-curl_7.50.1-1_amd64.deb ...
    Unpacking curl (7.50.1-1) ...
    Selecting previously unselected package jq.
    Preparing to unpack .../1-jq_1.5+dfsg-1_amd64.deb ...
    Unpacking jq (1.5+dfsg-1) ...
    Setting up jq (1.5+dfsg-1) ...
    Setting up curl (7.50.1-1) ...
    Processing triggers for man-db (2.7.5-1) ...
    $

Apple Mac OS-X
--------------

### Test utilities

The [OS X grep(1)][] , [OS X sed(1)][] and [OS X awk(1)][] tools provided by
Apple Mac OS X are the BSD variants.  The [test scripts][] require the GNU
variants with the names *ggrep*, *gsed* and *gawk*, which can be installed on
Mac OS X using the [homebrew][] package manager:

    $ brew tap homebrew/dupes
    ==> Tapping homebrew/dupes
    Cloning into '/usr/local/Library/Taps/homebrew/homebrew-dupes'...
    remote: Counting objects: 42, done.
    remote: Compressing objects: 100% (42/42), done.
    remote: Total 42 (delta 0), reused 3 (delta 0), pack-reused 0
    Unpacking objects: 100% (42/42), done.
    Checking connectivity... done.
    Tapped 38 formulae (103 files, 120.0K)
    
    $ brew install grep
    ==> Installing grep from homebrew/dupes
    ==> Installing dependencies for homebrew/dupes/grep: pcre
    ==> Installing homebrew/dupes/grep dependency: pcre
    ==> Downloading https://homebrew.bintray.com/bottles/pcre-8.38.el_capitan.bottle.tar.gz
    ==> Pouring pcre-8.38.el_capitan.bottle.tar.gz
    /usr/local/Cellar/pcre/8.38: 146 files, 5.4M
    ==> Installing homebrew/dupes/grep
    ==> Downloading https://homebrew.bintray.com/bottles-dupes/grep-2.22.el_capitan.bottle.tar.gz
    ==> Pouring grep-2.22.el_capitan.bottle.tar.gz
    ==> Caveats
    The command has been installed with the prefix "g".
    If you do not want the prefix, install using the "with-default-names" option.
    ==> Summary
    /usr/local/Cellar/grep/2.22: 14 files, 756.5K

    $ brew install gnu-sed
    ==> Downloading https://homebrew.bintray.com/bottles/gnu-sed-4.2.2.el_capitan.bottle.2.tar.gz
    ==> Pouring gnu-sed-4.2.2.el_capitan.bottle.2.tar.gz
    tar: Failed to set default locale
    ==> Caveats
    The command has been installed with the prefix "g".
    If you do not want the prefix, install using the "with-default-names" option.
    If you need to use these commands with their normal names, you
    can add a "gnubin" directory to your PATH from your bashrc like:
    PATH="/usr/local/opt/gnu-sed/libexec/gnubin:$PATH"
    Additionally, you can access their man pages with normal names if you add
    the "gnuman" directory to your MANPATH from your bashrc as well:
    MANPATH="/usr/local/opt/gnu-sed/libexec/gnuman:$MANPATH"
    ==> Summary
    /usr/local/Cellar/gnu-sed/4.2.2: 9 files, 452K

    $ brew install gawk
    ==> Downloading https://homebrew.bintray.com/bottles/gawk-4.1.3.el_capitan.bottle.tar.gz
    ==> Pouring gawk-4.1.3.el_capitan.bottle.tar.gz
    /usr/local/Cellar/gawk/4.1.3: 63 files, 3.2M

    $

The [jq(1)][] tool is not provided by Apple Mac OS X, so it must be installed
using the [homebrew][] package manager:

    $ brew install jq
    ==> Installing dependencies for jq: oniguruma
    ==> Installing jq dependency: oniguruma
    ==> Downloading https://homebrew.bintray.com/bottles/oniguruma-6.1.1.el_capitan.bottle.tag.gz
    ==> Pouring oniguruma-6.1.1.el_capitan.bottle.tag.gz
    /usr/local/Cellar/oniguruma/6.1.1: 16 files, 1.3M
    ==> Installing jq
    ==> Downloading https://homebrew.bintray.com/bottles/jq-1.5_2.el_capitan.bottle.tag.gz
    ==> Pouring jq-1.5_2.el_capitan.bottle.tag.gz
    /usr/local/Cellar/jq/1.5_2: 18 files, 958K
    $

Java
----

The Serval DNA *libservaldeamon* static and dynamic libraries provide a [JNI][]
API so that the Serval [command line][CLI] can be called from Java programs,
and the daemon server can be run in a Java thread.

Swift
-----

Serval DNA supports [Swift][], the language that Apple recommend for developing
iOS apps for their mobile devices such as phones and tablets.  The
`./configure` script [generated from configure.ac](#autotools) detects whether
a [Swift 4.1][] compiler is present, and if so, then produces a Makefile that
will compile [servaldswift.swift][] into the *servaldswift* executable, to
prove that the Swift [module map](../module.modulemap) allows Swift source code
to invoke internal Serval DNA functions.

The `./configure` script can be passed the following variables, either as
environment variables or using the `VARNAME=value` syntax on its command line:

* `SWIFTC` the path name of the Swift compiler to use; by default the configure
  script searches `$PATH` for `swiftc`

* `SWIFTCFLAGS` extra command-line arguments to pass to the Swift compiler;
  analogous to `CFLAGS` for the C compiler

Swift Daemon API
----------------

Serval DNA provides a *Swift Daemon API* as a [Swift module][] called
**ServalDNA**, which provides access to some of the internal APIs of the Serval
DNA daemon by wrapping direct function invocations in Swift classes.

The Swift daemon API is written as a set of [Swift][] "wrappers" around
internal functions and constants that are declared in C header files.  Those
internals are exposed to Swift by the Swift [module map](../module.modulemap),
which defines a [Swift module][] called **servald** that has the following
submodules:

* **servald.log** the Serval DNA logging API, including the log output API

* **servald.cli** the Serval DNA [CLI API][] and the daemon's command-line
  entry point

The [CliContext][] Swift class provides an object-oriented interface to the
[CLI API][].  To capture the output from any CLI command, a Swift program can
simply subclass [CliContext][] and override its `write()` method and any other
methods as needed, then pass an instance of that subclass to the
[serval\_commandline\_main][] function.  An example of how to do this is in
[servaldswift.swift][], which uses an instance of the [CliContextFile][]
subclass to print its output on standard output via a buffer.

[servaldswift.swift][] shows how to capture Serval DNA log output in Swift
code, by providing an implementation of the delegate log output `print()`
function.  This works because [Makefile.in][] includes `log_output_delegate.o`
in the link for the *servaldswift* executable, and omits the other log outputs.

Swift Client API
----------------

Serval DNA provides a *Swift Client API* as a [Swift module][] called
**ServalClient**, which provides access to the services of the Serval DNA
daemon through its [REST API][].  Once an iOS app has started a thread that is
running the daemon (invoked via the [Swift Daemon API](#swift-daemon-api)), the
client API can be used to communicate with the running daemon thread.

The Swift client API is written entirely in [Swift][] using the [URLSession][]
Foundation class and related classes as the HTTP client.  The API is covered
by its own [test scripts][].  To date only the following parts of the [REST
API][] are supported:

* [Keyring REST API][], test script is [keyringswift](../tests/keyringswift)

Using Swift modules
-------------------

To use a [Swift module][] in your Swift program:

* add the directory containing the *ModuleName.swiftmodule* and
  *ModuleName.swiftdoc* files to your Swift import path, so the Swift source
  code can use `import ModuleName` to access the API definition;

* include the `libModuleName.a` static library in the link command line, either
  by giving its path explicitly as an argument, or by adding its containing
  directory to the link search path with the `-L` option and giving the
  `-lModuleName` option on the link command line.

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
**Copyright 2015 Serval Project Inc.**  
**Copyright 2016-2018 Flinders University**  
![CC-BY-4.0](./cc-by-4.0.png)
Available under the [Creative Commons Attribution 4.0 International licence][CC BY 4.0].


[Serval Project]: http://www.servalproject.org/
[CC BY 4.0]: ../LICENSE-DOCUMENTATION.md
[Serval DNA]: ../README.md
[build]: ../INSTALL.md
[CLI API]: ./CLI-API.md
[REST API]: ./REST-API.md
[Keyring REST API]: ./REST-API-Keyring.md
[test scripts]: ./Testing.md
[configure.ac]: ../configure.ac
[Makefile.in]: ../Makefile.in
[servaldswift.swift]: ../servaldswift.swift
[CliContext]: ../swift-daemon-api/Sources/CliContext.swift
[CliContextFile]: ../swift-daemon-api/Sources/CliContextFile.swift
[serval\_commandline\_main]: ../swift-daemon-api/Sources/commandline.swift
[GNU autoconf]: http://www.gnu.org/software/autoconf/autoconf.html
[Bash shell]: http://en.wikipedia.org/wiki/Bash_(Unix_shell)
[Unix]: https://en.wikipedia.org/wiki/Unix
[GNU]: https://en.wikipedia.org/wiki/GNU
[Linux]: https://en.wikipedia.org/wiki/Linux
[Darwin]: https://en.wikipedia.org/wiki/Darwin_(operating_system)
[autoconf macro archive]: http://www.gnu.org/software/autoconf-archive/
[GNU M4]: http://www.gnu.org/software/m4/m4.html
[GCC]: https://gcc.gnu.org/
[Clang]: http://clang.llvm.org/
[libsodium]: https://libsodium.org/
[NaCl]: https://nacl.cr.yp.to/
[NIST]: https://en.wikipedia.org/wiki/National_Institute_of_Standards_and_Technology
[Curve25519]: https://en.wikipedia.org/wiki/Curve25519
[build]: ../INSTALL.md
[aclocal]: https://www.gnu.org/software/automake/manual/html_node/aclocal-Invocation.html
[autoreconf]: https://www.gnu.org/savannah-checkouts/gnu/autoconf/manual/autoconf.html#autoreconf-Invocation
[git subtree]: http://git-memo.readthedocs.io/en/latest/subtree.html
[Debian]: http://www.debian.org/
[Ubuntu]: http://www.ubuntu.com/
[apt-get]: https://www.debian.org/doc/manuals/apt-guide/ch2.en.html
[OS X grep(1)]: https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man1/grep.1.html
[OS X sed(1)]: https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man1/sed.1.html
[OS X awk(1)]: https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man1/awk.1.html
[jq(1)]: https://stedolan.github.io/jq/
[homebrew]: http://brew.sh/
[CLI]: ./CLI-API.md
[JNI]: http://en.wikipedia.org/wiki/Java_Native_Interface
[Swift]: https://en.wikipedia.org/wiki/Swift_(programming_language)
[Swift module]: https://swift.org/package-manager/#modules
[Swift 4.1]: https://swift.org/blog/swift-4-1-released/
[URLSession]: https://developer.apple.com/documentation/foundation/urlsession
[gold]: https://en.wikipedia.org/wiki/Gold_(linker)
[IDE]: https://en.wikipedia.org/wiki/Integrated_development_environment
[Android Studio]: https://en.wikipedia.org/wiki/Android_Studio
[Microsoft Windows]: https://en.wikipedia.org/wiki/Microsoft_Windows
[Bourne shell]: http://en.wikipedia.org/wiki/Bourne_shell
