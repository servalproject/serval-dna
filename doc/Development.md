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

Apple OSX
---------

The [OSX grep(1)][] , [OSX sed(1)][] and [OSX awk(1)][] tools provided by Apple
OSX are the BSD variants.  The test scripts require the GNU variants with the
names *ggrep*, *gsed* and *gawk*, which can be installed on OSX using the
[homebrew][] package manager:

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
[OSX grep(1)]: https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man1/grep.1.html
[OSX sed(1)]: https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man1/sed.1.html
[OSX awk(1)]: https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man1/awk.1.html
[homebrew]: http://brew.sh/
[Bourne shell]: http://en.wikipedia.org/wiki/Bourne_shell
