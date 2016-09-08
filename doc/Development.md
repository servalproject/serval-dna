Notes for Serval DNA Developers
===============================
[Serval Project][], January 2016

Introduction
------------

This document is intended for all developers of [Serval DNA][], and also for
non-developers who are experiencing errors in the [build][] process.

Autoconf
--------

The [configure.in](../configure.in) file is an [autoconf][] script that
contains instructions for adapting the build of Serval DNA to different
platforms and CPU architectures.  This script makes use of many [GNU M4][]
macros, each of which tests an aspect of the build environment, such as the
make and version of the C compiler (eg, [GCC][], [Clang][]), the availability
of headers, functions and system calls in the standard library, and so forth.

Most of these M4 macros are standard, either supplied with [autoconf][] or from
the [autoconf macro archive][].  Some macros are specific to Serval DNA, either
to improve on a standard macro or perform a test for which no standard macro
exists.  These extra macros are locally defined in files within the [m4](../m4)
sub-directory.

The [autoreconf][] command used in the [build][] instructions generates an
`aclocal.m4` file that includes all the necessary files from the [m4](../m4)
directory.  In turn, it then includes this `aclocal.m4` file when invoking [GNU
M4][] to convert the [configure.in](../configure.in) file into the
`./configure` script.

Internally, [autoconf][] generates the `aclocal.m4` file by invoking the
[aclocal][] utility.  Used without arguments, [aclocal][] may emit some warning
messages that look like this:

    $ cd serval-dna
    $ aclocal
    aclocal: warning: autoconf input should be named 'configure.ac', not 'configure.in'
    configure.in:18: warning: Unsupported attribute section, the test may fail
    ../../lib/autoconf/lang.m4:224: AC_LANG_SOURCE is expanded from...
    ../../lib/autoconf/lang.m4:241: AC_LANG_PROGRAM is expanded from...
    ../../lib/autoconf/lang.m4:193: AC_LANG_CONFTEST is expanded from...
    ../../lib/autoconf/general.m4:2672: _AC_LINK_IFELSE is expanded from...
    ../../lib/autoconf/general.m4:2689: AC_LINK_IFELSE is expanded from...
    ../../lib/m4sugar/m4sh.m4:639: AS_IF is expanded from...
    ../../lib/autoconf/general.m4:2042: AC_CACHE_VAL is expanded from...
    ../../lib/autoconf/general.m4:2063: AC_CACHE_CHECK is expanded from...
    /usr/share/aclocal/ax_gcc_var_attribute.m4:57: AX_GCC_VAR_ATTRIBUTE is expanded from...
    configure.in:18: the top level
    $

These messages are harmless; the correct `aclocal.m4` is still generated.  To
suppress most of these messages from the output of [aclocal][] and
[autoreconf][], give the `-I m4` option:

    $ cd serval-dna
    $ autoreconf -f -i -I m4
    aclocal: warning: autoconf input should be named 'configure.ac', not 'configure.in'
    $

Debian/Ubuntu
-------------

A single [apt-get][] command will install all mandatory and testing
dependencies before building on [Debian][] and [Ubuntu][] systems:

    $ sudo apt-get --yes install libc6-dev libsodium-dev jq curl
    Reading package lists... Done
    Building dependency tree
    Reading state information... Done
    libc6-dev is already the newest version (2.23-5).
    The following NEW packages will be installed:
      curl jq libsodium-dev
    0 upgraded, 3 newly installed, 0 to remove and 0 not upgraded.
    Need to get 544 kB of archives.
    After this operation, 1,683 kB of additional disk space will be used.
    Get:1 http://ftp.us.debian.org/debian testing/main amd64 curl amd64 7.50.1-1 [218 kB]
    Get:2 http://ftp.us.debian.org/debian testing/main amd64 jq amd64 1.5+dfsg-1 [156 kB]
    Get:3 http://ftp.us.debian.org/debian testing/main amd64 libsodium-dev amd64 1.0.11-1 [170 kB]
    Fetched 544 kB in 1s (304 kB/s)
    Selecting previously unselected package curl.
    (Reading database ... 205089 files and directories currently installed.)
    Preparing to unpack .../0-curl_7.50.1-1_amd64.deb ...
    Unpacking curl (7.50.1-1) ...
    Selecting previously unselected package jq.
    Preparing to unpack .../1-jq_1.5+dfsg-1_amd64.deb ...
    Unpacking jq (1.5+dfsg-1) ...
    Selecting previously unselected package libsodium-dev:amd64.
    Preparing to unpack .../2-libsodium-dev_1.0.11-1_amd64.deb ...
    Unpacking libsodium-dev:amd64 (1.0.11-1) ...
    Setting up jq (1.5+dfsg-1) ...
    Setting up curl (7.50.1-1) ...
    Setting up libsodium-dev:amd64 (1.0.11-1) ...
    Processing triggers for man-db (2.7.5-1) ...
    $

Apple Mac OS X
--------------

### libsodium

Although the [libsodium][] package is available for Mac OS X using the
[homebrew][] package manager, that package only provides the run-time library,
not the development files; for example, it does not provide the `#include
<sodium.h>` header.

Before building Serval DNA on Mac OS X, the libsodium development files can be
locally installed by downloading the [libsodium source code][] and building it.
The [build-libsodium.sh](../build-libsodium.sh) script will do this:

    $ ./build-libsodium.sh
    ...
    The libsodium run-time and development files have been installed in:
    /absolute/path/name/serval-dna/libsodium
    
    To use this installation of libsodium, set up the environment using the
    shell's "dot" command to source its settings.sh script, for example:
    
       . libsodium/settings.sh ; ./configure
    
    $

In the event of failure, check that:

* the [github.com][libsodium source code] web site can be reached
* there is at least 60 MB of available disk space
* there is no other libsodium development package already installed

For more information, refer to the [libsodium installation documentation][]
and the script's help message:

    $ ./build-libsodium.sh --help
    ...
    $

### Test utilities

The [OS X grep(1)][] , [OS X sed(1)][] and [OS X awk(1)][] tools provided by
Apple Mac OS X are the BSD variants.  The test scripts require the GNU variants
with the names *ggrep*, *gsed* and *gawk*, which can be installed on Mac OS X
using the [homebrew][] package manager:

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
![CC-BY-4.0](./cc-by-4.0.png)
Available under the [Creative Commons Attribution 4.0 International licence][CC BY 4.0].


[Serval Project]: http://www.servalproject.org/
[CC BY 4.0]: ../LICENSE-DOCUMENTATION.md
[Serval DNA]: ../README.md
[autoconf]: http://www.gnu.org/software/autoconf/autoconf.html
[autoconf macro archive]: http://www.gnu.org/software/autoconf-archive/
[GNU M4]: http://www.gnu.org/software/m4/m4.html
[GCC]: https://gcc.gnu.org/
[Clang]: http://clang.llvm.org/
[build]: ../INSTALL.md
[aclocal]: https://www.gnu.org/software/automake/manual/html_node/aclocal-Invocation.html
[autoreconf]: https://www.gnu.org/savannah-checkouts/gnu/autoconf/manual/autoconf.html#autoreconf-Invocation
[Debian]: http://www.debian.org/
[Ubuntu]: http://www.ubuntu.com/
[libsodium]: https://download.libsodium.org/doc/
[libsodium source code]: https://github.com/jedisct1/libsodium
[libsodium installation documentation]: https://download.libsodium.org/libsodium/content/installation/
[apt-get]: https://www.debian.org/doc/manuals/apt-guide/ch2.en.html
[OS X grep(1)]: https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man1/grep.1.html
[OS X sed(1)]: https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man1/sed.1.html
[OS X awk(1)]: https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man1/awk.1.html
[jq(1)]: https://stedolan.github.io/jq/
[homebrew]: http://brew.sh/
[Bourne shell]: http://en.wikipedia.org/wiki/Bourne_shell
