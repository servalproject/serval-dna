Building Serval DNA for OpenWRT
===============================
[Serval Project], February 2014

These are instructions for building [Serval DNA][] for [OpenWRT][] 12.09
“Attitude Adjustment” released in April, 2013 (the same release used to make
firmware for the [Serval Mesh Extender][]).

The OpenWRT build system
------------------------

The [OpenWRT 12.09 Buildroot][] package itself contains almost no code that
ends up as an executable on the target hardware.  Instead, it is an elaborate
menu-based configuration and build system that downloads and cross-compiles a
chosen set of *packages* from source code and aggregates the compiled binaries
into a firmware image.

Buildroot must be configured with a list of package providers called *feeds*.
Each [OpenWRT feed][] contains a directory tree with a structure like
`$category_name/$package_name/Makefile` that contains one [OpenWRT Makefile][]
per package (plus optionally some OpenWRT-specific config files and patches).
For example, a feed containing the following files provides sixteen packages:

    utils/vim/Makefile
    utils/more/Makefile
    utils/sed/Makefile
    devel/oprofile/Makefile
    devel/cppunit/Makefile
    libs/sqlite3/Makefile
    libs/gpgme/Makefile
    libs/openldap/Makefile
    admin/sudo/Makefile
    admin/gtop/Makefile
    lang/python/Makefile
    lang/erlang/Makefile
    lang/ghc/Makefile
    net/curl/Makefile
    net/iftop/Makefile
    net/nmap/Makefile

Each [OpenWRT Makefile][] contains commands for downloading and compiling a
single package from source.

Before building OpenWRT, its list of feeds must be configured, and each feed
updated by downloading copies of its contents.  Once this is done, the OpenWRT
build is invoked by running the `make` command in the OpenWRT source directory,
which progresses through the following steps:

 - checks that all software tools and libraries it depends on are present,
 - on the first invocation only, runs a manual component selection and
   configuration dialog called *menuconfig*
 - for each selected package, invokes its [OpenWRT Makefile][], which downloads
   the package's source code and cross-compiles it for the selected target
   architecture
 - aggregates all compiled components into a firmware image

During the build, continuous Internet access is required to allow downloading
of packages.

OpenWRT Dependencies
--------------------

You will need to install the following development tools and packages before
running an OpenWRT build:

 * [GNU make][] -- dependency-driven software build utility
 * [getopt][] -- command-line option parsing utility, available in the
   [util-linux][] package
 * [GNU coreutils][] -- file manipulation utilities like [cp(1)][], etc.
 * [gcc][] and [g++][]-- GNU C and C++ compilers
 * [binutils][] -- GNU assembler, linker and binary executable utilities
 * [C standard library][] development -- headers and linkage binaries
 * [ncurses][] -- terminal-mode user interface headers and library
 * [zlib][] -- compression library headers and library
 * [GNU awk][] -- programmable text processing utility
 * [flex][] -- fast lexical analyzer generator
 * [unzip][] -- file de-archive and de-compression utility
 * [bzip2][] -- file compression utility
 * [patch][] -- source code diff-style patch applicator
 * [Perl 5][] -- scripting language
 * [Python][] -- scripting language
 * [GNU wget][] -- command-line HTTP client utility
 * [Git][] -- distributed source code version control
 * [GNU tar][] -- directory tree archiver utility
 * [Subversion][] -- source code version control
 * [GNU findutils][] -- directory tree traversal and search utility
 * [pkg-config][] -- package installation metadata utility
 * [gettext][] -- GNU language localisation tool

[Debian][] uses [eglibc][] as its [C standard library][], but other platforms
may use [GNU libc][].

The following command will install and/or upgrade all the necessary packages on
[Debian][] and on derivatives like [Ubuntu][]:

    $ sudo apt-get install make util-linux coreutils gcc g++ binutils libc6-dev \
                           libncurses5-dev zlib1g-dev gawk flex unzip bzip2 \
                           patch perl python wget git tar subversion \
                           pkg-config gettext
    $

Download OpenWRT
----------------

The [OpenWRT 12.09 Buildroot][] package is available as a [Git][] repository,
which is the recommended way to download it:

    $ mkdir -p 12.09
    $ cd 12.09
    $ git clone -q git://git.openwrt.org/12.09/openwrt.git
    $ cd openwrt
    $

If this does not work, see the [OpenWRT Buildroot installation HOWTO][], which
may have changed since this was written.

Update OpenWRT package feeds
----------------------------

Make sure that the feeds you want are configured, by creating a `feeds.conf`
file.  If this file is missing, the `feeds.conf.default` file is used, which,
in the [OpenWRT 12.09 Buildroot][] repository is:

    src-svn packages svn://svn.openwrt.org/openwrt/branches/packages_12.09
    src-svn xwrt http://x-wrt.googlecode.com/svn/trunk/package
    src-svn luci http://svn.luci.subsignal.org/luci/branches/luci-0.11/contrib/package
    src-git routing git://github.com/openwrt-routing/packages.git;for-12.09.x
    #src-svn phone svn://svn.openwrt.org/openwrt/feeds/phone
    #src-svn efl svn://svn.openwrt.org/openwrt/feeds/efl
    #src-svn xorg svn://svn.openwrt.org/openwrt/feeds/xorg
    #src-svn desktop svn://svn.openwrt.org/openwrt/feeds/desktop
    #src-svn xfce svn://svn.openwrt.org/openwrt/feeds/xfce
    #src-svn lxde svn://svn.openwrt.org/openwrt/feeds/lxde
    #src-link custom /usr/src/openwrt/custom-feed

Lines beginning with `#` are comments.  Once the feeds are configured, fetch
them all:

    $ cd 12.09/openwrt
    $ ./scripts/feeds update
    Updating feed 'packages' from 'svn://svn.openwrt.org/openwrt/branches/packages_12.09' ...
    Updating '.':
    At revision 39583.
    Create index file './feeds/packages.index' 
    Updating feed 'xwrt' from 'http://x-wrt.googlecode.com/svn/trunk/package' ...
    Updating '.':
    At revision 4987.
    Create index file './feeds/xwrt.index' 
    Updating feed 'luci' from 'http://svn.luci.subsignal.org/luci/branches/luci-0.11/contrib/package' ...
    Updating '.':
    At revision 9955.
    Create index file './feeds/luci.index' 
    Updating feed 'routing' from 'git://github.com/openwrt-routing/packages.git;for-12.09.x' ...
    Already up-to-date.
    Create index file './feeds/routing.index' 
    $

Build OpenWRT without Serval DNA
--------------------------------

Before building OpenWRT with a Serval feed, build OpenWRT out of the box, to
ensure that all dependencies are met and to resolve any other build issues:

    $ cd 12.09/openwrt
    $ make
    Collecting package info: done
    Collecting target info: done
    Checking 'working-make'... ok.
    Checking 'case-sensitive-fs'... ok.
    Checking 'getopt'... ok.
    Checking 'fileutils'... ok.
    Checking 'working-gcc'... ok.
    Checking 'working-g++'... ok.
    Checking 'ncurses'... ok.
    Checking 'zlib'... ok.
    Checking 'gawk'... ok.
    Checking 'unzip'... ok.
    Checking 'bzip2'... ok.
    Checking 'patch'... ok.
    Checking 'perl'... ok.
    Checking 'python'... ok.
    Checking 'wget'... ok.
    Checking 'git'... ok.
    Checking 'gnutar'... ok.
    Checking 'svn'... ok.
    Checking 'gnu-find'... ok.
    Checking 'getopt-extended'... ok.
    Checking 'non-root'... ok.
    make[2]: Entering directory `/home/andrewb/serval/src/openwrt/12.09/openwrt/scripts/config'
    ...

If all dependencies are ok, OpenWRT's interactive *menuconfig* screen will
appear.  (This only happens the first time that a build has been run.  On all
subsequent builds, the *menuconfig* step will be skipped, but can be run
manually with the `make menuconfig` command.)

The following example *meniconfig* configuration chooses the target system of
the [Serval Mesh Extender][] which is based on the [TP-LINK TL-MR3020][]
wireless router, models 1.7 and 1.8 (for more information, see the [OpenWRT
TP-LINK TL-MR3020][] page).  The remaining settings are taken from the
[config.ar71xx.generic][] file in the pre-build binary supplied by OpenWRT.
Alter these settings to suit your needs:

 * Target System: Atheros AR7xxx/AR9xxx
 * Subtarget: Generic
 * Target Profile: TP-LINK LP-MR3020
 * Target Images: (default)
 * Global build settings:
   * Compile with support for patented functionality
   * Enable shadow password support
   * Collect kernel debug information
   * Compile the kernel with SysRq support
   * Enable process core dump support
   * Enable printk timestamps
   * Enable IPv6 support in packages
   * Compile certain packages parallelized
   * Use top-level make jobserver for packages
   * Binary stripping method: sstrip
   * Preferred standard C++ library: uClibc++
 * Advanced configuration options (for developers):
   * Automatic rebuild of packages
   * Enable log files during build process
     * Toolchain options:
       * Binutils version: binutils 2.22
       * GCC compiler Version: gcc 4.6.x with Linaro enhancements
       * Build/install c++ compiler and libstdc++?
       * C Library implementation: Use uClibc
       * uClibc Version: uClibc 0.9.33.2
       * Build gdb
 * Build the OpenWrt Image Builder
 * Build the OpenWrt SDK
 * Build the OpenWrt based Toolchain
 * Image configuration:
   * Preinit configuration options:
     * Suppress stderr messages during preinit
     * Failsafe wait timeout: 2
     * IP address for preinit network messages: 192.168.1.1
     * Netmask for preinit network messages: 255.255.255.0
     * Broadcast address for preinit network messages: 192.168.1.255
   * Init configuration options:
     * PATH for regular boot: /bin:/sbin:/usr/bin:/usr/sbin
     * Init command: /sbin/init
     * Suppress stderr messages of init
   * Version configuration options:
     * Release distribution: OpenWrt
     * Release version nickname: Attitude Adjustment
     * Release version number: 12.09
     * Release repository: http://downloads.openwrt.org/attitude_adjustment/12.09.1/%S/packages
 * Base system:
   * base-files: Y
   * block-mount: M
   * bridge: M
   * busybox: Y
   * dnsmasq: Y
   * dnsmasq-dhcpv6: M
   * dropbear: Y
   * ead: M
   * firewall: Y
   * hotplug2: Y
   * libc: ---
   * libgcc: ---
   * libpthread: M
   * librt: M
   * libstdcpp: M
   * mtd: Y
   * netifd: ---
   * nvram: M
   * om: M
   * opkg: Y
   * qos: M
   * resolveip: M
   * swconfig: Y
   * ubus: ---
   * ubusd: ---
   * uci: Y
   * udev: M
   * wireless: Y

Exit *autoconfig*, saving the OpenWRT configuration file.  The
download-and-build phase will commence, and can take the better part of an
hour, depending on Internet download speeds and CPU/memory performance:

    *** End of OpenWrt configuration.
    ...
     make[1] world
     make[2] tools/install
     make[3] -C tools/m4 compile
     make[3] -C tools/m4 install
     make[3] -C tools/sed compile
    ...
     make[3] -C target/sdk install
     make[3] -C target/imagebuilder install
     make[3] -C target/toolchain install
     make[2] package/index
    $

The built firmware images are in the `bin` directory:

    $ ls -s -h -1 bin
    total 182M
    5.0M kernel-debug.tar.bz2
    4.0K md5sums
    1.8M openwrt-ar71xx-generic-rootfs.tar.gz
    2.2M openwrt-ar71xx-generic-root.jffs2-128k
    2.2M openwrt-ar71xx-generic-root.jffs2-256k
    2.2M openwrt-ar71xx-generic-root.jffs2-64k
    1.7M openwrt-ar71xx-generic-root.squashfs
    1.4M openwrt-ar71xx-generic-root.squashfs-64k
    3.8M openwrt-ar71xx-generic-tl-mr3020-v1-jffs2-factory.bin
    3.1M openwrt-ar71xx-generic-tl-mr3020-v1-jffs2-sysupgrade.bin
    3.8M openwrt-ar71xx-generic-tl-mr3020-v1-squashfs-factory.bin
    2.3M openwrt-ar71xx-generic-tl-mr3020-v1-squashfs-sysupgrade.bin
    1.3M openwrt-ar71xx-generic-uImage-gzip.bin
    916K openwrt-ar71xx-generic-uImage-lzma.bin
    2.7M openwrt-ar71xx-generic-vmlinux.bin
    2.7M openwrt-ar71xx-generic-vmlinux.elf
    1.3M openwrt-ar71xx-generic-vmlinux.gz
    964K openwrt-ar71xx-generic-vmlinux.lzma
    924K openwrt-ar71xx-generic-vmlinux-lzma.elf
     36M OpenWrt-ImageBuilder-ar71xx_generic-for-linux-i486.tar.bz2
     67M OpenWrt-SDK-ar71xx-for-linux-i486-gcc-4.6-linaro_uClibc-0.9.33.2.tar.bz2
     40M OpenWrt-Toolchain-ar71xx-for-mips_r2-gcc-4.6-linaro_uClibc-0.9.33.2.tar.bz2
    4.0K packages
    $

Add the Serval feed to OpenWRT
------------------------------

Once an out-of-the-box build has succeeded, add the Serval feed by creating a
`feeds.conf` file that contains a line for downloading the *master* branch of
the [Serval OpenWRT feed][] from GitHub:

    $ cp feeds.conf.default feeds.conf
    $ cat >>feeds.conf <<EOF
    src-git serval git://github.com/servalproject/openwrt-packages.git;master
    EOF
    $

(Other branches of the [Serval OpenWRT feed][] are available; see the
[README][Serval OpenWRT feed] for more information.)

Download the Serval feed:

    $ ./scripts/feeds update serval
    Updating feed 'serval' from 'git://github.com/servalproject/openwrt-packages.git;master' ...
    Cloning into './feeds/serval'...
    remote: Counting objects: 6, done.
    remote: Compressing objects: 100% (4/4), done.
    remote: Total 6 (delta 0), reused 4 (delta 0)
    Receiving objects: 100% (6/6), done.
    Checking connectivity... done.
    Create index file './feeds/serval.index' 
    Collecting package info: done
    $

Add all the packages from the Serval feed to the OpenWRT package menu:

    $ ./scripts/feeds install -a -p serval
    Installing all packages from feed serval.
    $

Run *menuconfig* and select the Serval packages for building:

    $ make menuconfig
    ...

 * Network
   * Mesh networking
     * Serval DNA: Y

Exit *menuconfig*, saving the OpenWRT configuration file, then build:

    *** End of OpenWrt configuration.
    *** Execute 'make' to build the OpenWrt or try 'make help'.
    $ make
     make[1] world
     make[2] target/compile
     make[3] -C target/linux compile
    ...
     make[3] -C feeds/serval/net/serval-dna compile
    ...
     make[2] package/install
    ...
     make[3] -C feeds/serval/net/serval-dna install
    ...
     make[3] -C target/toolchain install
     make[2] package/index
    $

The [Serval DNA][] daemon is now included in the firmware image.

Appendix A - Adding a package to OpenWRT
----------------------------------------

The [OpenWRT feed][] page gives complete instructions for adding a new package
to OpenWRT.  In summary:

 - the package's source code must be accessible in some conventional form such
   as a directory on the local file system, or a directory tree that can be
   downloaded, such as a tarball, a [Subversion][] or [Git][] repository, or
   even a few files on an FTP server;
 - choose a unique name for the package, that is not already used in any of the
   existing feeds;
 - an [OpenWRT Makefile][] must be created for the package, that contains
   the package's name and commands for downloading, unpacking and compiling the
   package's source code;
 - the package's [OpenWRT Makefile][] must be added to an [OpenWRT feed][];
   either one which is already configured by default into OpenWRT, or a new
   one;
 - the URL of the [OpenWRT feed][] must be added to the OpenWRT `feeds.conf`
   file, along with a simple name chosen to identify the feed;
 - the package must be installed:

    $ ./scripts/feeds install $package_name
    $

Appendix B - Developing an OpenWRT package
------------------------------------------

The instructions above are not ideal for a developer who wishes to compile the
locally-edited source code of a package, because every time the developer
wished to build the package, first the latest changes would have to be
committed and pushed to the package's repository, and the package's [OpenWRT
Makefile][] updated (with a new Git commit id) and pushed to its feed.

The solution is to use a local feed which contains an [OpenWRT Makefile][] that
uses a local directory for the package's source code (instead of a remote Git
repository or tarball).  The Serval DNA source contains a [development OpenWRT
Makefile](../openwrt/packages/net/serval-dna/Makefile) which contains
instructions for its use in the header comment.

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
[Serval DNA]: ../README.md
[OpenWRT]: http://openwrt.org/
[OpenWRT 12.09 Buildroot]: https://dev.openwrt.org/browser/tags/attitude_adjustment_12.09
[Serval Mesh Extender]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:meshextender:
[OpenWRT build system]: http://wiki.openwrt.org/about/toolchain
[OpenWRT feed]: http://wiki.openwrt.org/doc/devel/feeds
[OpenWRT Buildroot installation HOWTO]:http://wiki.openwrt.org/doc/howto/buildroot.exigence
[OpenWRT Makefile]: http://wiki.openwrt.org/doc/devel/packages
[Serval OpenWRT feed]: https://github.com/servalproject/openwrt-packages
[Serval OpenWRT feed README]: https://github.com/servalproject/openwrt-packages
[make]: http://www.gnu.org/software/make/
[getopt]: http://en.wikipedia.org/wiki/Getopt
[util-linux]: http://en.wikipedia.org/wiki/Util-linux
[GNU coreutils]: http://www.gnu.org/software/coreutils/
[cp(1)]: http://man.cx/cp(1)
[gcc]: http://gcc.gnu.org/
[g++]: http://gcc.gnu.org/
[binutils]: http://www.gnu.org/software/binutils/
[C standard library]: http://en.wikipedia.org/wiki/C_standard_library
[ncurses]: http://www.gnu.org/software/ncurses/
[zlib]: http://www.zlib.net/
[GNU awk]: http://www.gnu.org/software/gawk/
[flex]: http://flex.sourceforge.net/
[unzip]: http://www.info-zip.org/UnZip.html
[bzip2]: http://www.bzip.org/
[patch]: http://en.wikipedia.org/wiki/Patch_(Unix)
[Perl 5]: http://www.perl.org/
[Python]: http://www.python.org/
[GNU wget]: http://www.gnu.org/software/wget/
[Git]: http://git-scm.com/
[GNU tar]: http://www.gnu.org/software/tar/
[Subversion]: http://subversion.apache.org/
[GNU findutils]: http://www.gnu.org/software/findutils/
[pkg-config]: http://www.freedesktop.org/wiki/Software/pkg-config/
[gettext]: http://www.gnu.org/software/gettext/
[eglibc]: http://www.eglibc.org
[GNU libc]: http://www.gnu.org/software/libc/
[Debian]: http://www.debian.org/
[Ubuntu]: http://www.ubuntu.com/desktop
[TP-LINK TL-MR3020]: http://www.tp-link.com/en/products/details/?model=TL-MR3020
[OpenWRT TP-LINK TL-MR3020]: http://wiki.openwrt.org/toh/tp-link/tl-mr3020
[config.ar71xx.generic]: http://downloads.openwrt.org/attitude_adjustment/12.09/ar71xx/generic/config.ar71xx_generic
[Bourne shell]: http://en.wikipedia.org/wiki/Bourne_shell
