Serval DNA on iOS
=================
[Serval Project][], May 2018

These instructions describe how to embed [Serval DNA][] into an [Apple iOS][]
app.

This work was funded by a grant from the [NLnet Foundation][].

Introduction
------------

The [build instructions][build] and [Notes for Developers][develop] introduce
[Serval DNA][]'s build and development environment.  To summarise:

 * the build toolchain is completely oriented around the [Bash shell][]
   command-line on [Unix][] platforms such as [GNU][]/[Linux][] and [Darwin][]

 * [GNU autoconf][] is used to achieve portability between different platforms

Serval DNA does not support building by [IDE][]s, however the only platform
available for developing iOS apps is the [Xcode][] IDE from Apple.  Xcode is
only available for Mac OS-X, and it builds iOS apps by [cross compiling][] to
the selected target.

Overview
--------

To use Serval DNA in an iOS app, a developer must use the Mac OSX command line
to configure and build Serval DNA into a multi-target [Framework Bundle][] for
iOS.  This framework allows an app to call all entry points of the Serval DNA
Swift API, and also to call any public C function in the Serval DNA source
code.

Once the Serval DNA framework bundle is built, the developer may then import it
into any Xcode project.

The scripts for building the Serval DNA framework bundle are in the
[ios](../ios/) sub-directory.  [Serval DNA][]'s iOS support is based on recent
versions of the [Darwin][]/[Xcode][] environment, so these scripts are not
complicated by the kinds of portability issues that plague other environments,
like GNU/Linux and POSIX.

Supported targets
-----------------

The supported target operating systems are:

 * [iOS 10][] or later (iPhoneOS and iPhoneSimulator)

running on any of the following devices:

 * [iPhone 5][] and [iPhone 5C][] (ARMv7s 32-bit dual-core CPU)
 * [iPhone 5S][] (ARMv8 64-bit dual-core CPU)
 * [iPhone 6 and 6 Plus][] (ARMv8 64-bit dual-core CPU)
 * [iPhone 6S and 6S Plus][] (ARMv8-A 64-bit dual-core CPU)
 * [iPhone SE][] (ARMv8-A 64-bit dual-core CPU)
 * [iPhone 7 and 7 Plus][] (ARM 64-bit quad-core CPU)
 * [iPhone 8 and 8 Plus][] (ARM 64-bit hexa-core CPU)
 * [iPhone X][] (ARM 64-bit hexa-core CPU)
 * iPhone Simulator (Intel 32-bit CPU)
 * iPhone Simulator (Intel 64-bit CPU)

In Apple terminology, a CPU architecture is called a *slice*.

In this document, *target* means an operating system and a slice, so, based on
the above list, the supported targets are:

 * iPhoneOS ARMv7s (32-bit)
 * iPhoneOS ARMv8 (64-bit)
 * iPhoneSimulator i386 (32-bit)
 * iPhoneSimulator x86\_64 (64-bit)

Dependencies
------------

[Serval DNA][] exposes its API using the [Swift 4.1][] programming language, so
building it for iOS requires:

 * [Xcode version 9.3][Xcode 9] or later (which introduced Swift 4.1), which in turn requires
 * [Mac OS 10.13 “High Sierra”][] or later.

[Xcode 9][] provides the following command-line utilities:

 * [Bash shell][] version 3.2
 * [GNU make][] version 3.81
 * [Clang][] compiler for [C11][] based on LLVM version 8
 * [Swift 4.1][] compiler based on LLVM version 8
 * standard BSD utilities such as [sed][], [tr][], and [mkdir][]

These are adequate for cross-compiling for iOS as described below, but may not
be enough for native development; see [Notes for Developers][develop].

Build the Serval DNA Framework Bundle
-------------------------------------

In a [working copy of the Serval DNA source code](../INSTALL.md#download), use
the following commands:

    $ cd serval-dna
    $ autoreconf -f -i -I m4
    $ cd ios
    $ ./configure
    $ make
    $

See below for a description of the [built artifacts](#built-artifacts).

Once the `ios/configure` script has been run once, it only needs to be run
again if the main configure script [configure.ac](../configure.ac) has been
changed (and `autoreconf` has been re-run) or if [Makefile.in](../Makefile.in)
or any other `.in` files have been changed.

After any change to Serval DNA source or header file, to re-compile and re-link
the framework bundle, simply run `make` again:

    $ cd ios
    $ make
    $

Built artifacts
---------------

The `make` command above produces the following files:

 * `ios/frameworks/ServalDNA.framework/` contains a static iOS [Framework
   Bundle][] that consists of the following pieces:

   * `Resources/` (symbolic link) contains all “resource” files that accompany
     the shared library:

      * `Info.plist` is the bundle's property list in XML format; this allows
        Xcode to recognise the bundle and import it correctly

   * `ServalDNA` (symbolic link) is a multi-slice static library for all
     [supported targets](#supported-targets)

   * `Headers/` (symbolic link) contains all the Serval DNA C header files, and
     subdirectories for all [supported targets](#supported-targets):

     * `iphoneos-armv7` contains the C header files specific to the iPhone
       ARMv7 target

     * `iphoneos-arm64` contains the C header files for the iPhone ARMv8 target

     * `iphonesimulator-i386` contains the C header files for the 32-bit
       simulator target

     * `iphonesimulator-x86_64` contains the C header files for the 64-bit
       simulator target

   * `module.modulemap` (symbolic link) is a file that defines the [Clang module][]
     for the bundle; this is what gives Swift code access to the Serval DNA
     headers and entry points

 * `ios/frameworks/ServalDNA.xcconfig` is an Xcode configuration file that
   contains all the settings needed to use the `ServalDNA.framework` bundle in
   an Xcode project

Import ServalDNA.framework into Xcode
-------------------------------------

To use the Serval DNA iOS [Framework Bundle][] in an Xcode iOS project:

1. Open the Xcode application

2. Create a new iOS project or open an existing one, called “Sample App” for
   example

1. Add the bundle's config file to the Xcode project:

   * menu **File** → **Add Files to “Sample App”...**
   * a file chooser dialog window pops up
   * navigate to the Xcode config file, eg: *Home* → **src** → **serval-dna** →
     **ios** → **frameworks** → **ServalDNA.xcconfig**
   * press the **Add** button at the lower right of the dialog window
   * the file chooser dialog window closes
   * the **ServalDNA.xcconfig file** should now appear in the “Project
     navigator” pane on the left side of the Xcode main window

2. Include the bundle's config file in the project's settings:

   * in the “Project navigator” pane, click on the topmost row, which should be
     labelled with the project name, eg: **Sample App**
   * in the second row of the centre pane, click on **Info**
   * in the left column of the centre pane, click on the row immediately
     beneath the **PROJECT** line, which should be labelled with the project
     name, eg: **Sample App**
   * in the main area of the centre pane, under the **Configurations** heading,
     for each of the “Debug” and “Release” sub-headings:
     * click on the triangle to expand the sub-heading
     * on the line immediately beneath the sub-heading, which should be
       labelled with the project name, eg: **Sample App**, click on the widget
       in the “Based on Configuration File” column
     * a selection box should pop up, containing the options “None” and “ServalDNA”
     * choose **ServalDNA**

3. Write some simple code that invokes a Serval DNA function:

   * TODO

4. Run the simulator to test that the bundle links correctly:

   * menu **Product** → **Run**
   * the message “Build succeeded” should pop up, and the Simulator window
     should appear shortly afterwards

How it works
------------

The `ios/configure` script takes advantage of [GNU autoconf][]'s support for
out-of-tree builds: if an autoconf-generated `configure` script (such as the
one used by Serval DNA's [build][]) is invoked from within a different working
directory than the source directory that contains the `configure` script
itself, then it places all resulting configuration files such as `config.h`,
`config.state` and `Makefile` under the working directory, not the source
directory.  Invoking the `make` command in that working directory will then
place all built artifacts under the same working directory, without altering
the source directory; ie,  the build is completely contained within the working
directory.  Because of this, many differently-configured builds can be
preformed from a single copy of the source code, without interfering with each
other.

The `ios/configure` script creates one working directory per target, under the
`ios/build` directory, and invokes the main Serval DNA `configure` script in
each target subdirectory, with appropriate options to produce the respective
cross-compilation, eg:

    cd build/armv7-iphoneos
    ../../../configure --host="armv7-apple-darwin" --enable-xcode-sdk=iphoneos
    cd -
    cd build/arm64-iphoneos
    ../../../configure --host="aarch64-apple-darwin" --enable-xcode-sdk=iphoneos
    cd -
    cd build/i386-iphonesimulator
    ../../../configure --host="i386-apple-darwin" --enable-xcode-sdk=iphonesimulator
    cd -
    cd build/x86_64-iphonesimulator
    ../../../configure --host="x86_64-apple-darwin" --enable-xcode-sdk=iphonesimulator
    cd -

The `ios/configure` script then creates `ios/Makefile`, which, when invoked
by the `make` command:

 * for each target, runs `cd build/TARGET; make libservaldaemon.a`

 * creates the `ios/frameworks/ServalDNA.framework` destination directory

 * combines the all the built static libraries into a single, multi-slice
   static library in the framework directory using the [lipo(1)][] utility

 * copies all the Serval DNA C header files into the framework's `Headers`
   subdirectory

 * for each target, copies all the target-specific C header files (config.h and
   libsodium headers) into the framework's `Headers/TARGET` subdirectory

 * creates the framework's `Resources/Info.plist` file

 * creates the framework's `modules.modulemap` file

 * creates all framework's internal symbolic links

 * creates the `ServalDNA.xcconfig` file to accompany the framework

If any Serval DNA source (or header) file is subsequently modified, it is only
necessary to re-run the `make` command to recompile for all the targets and
update the framework.  Just like in normal development, only the affected
object files will be re-compiled as determined by each target's Makefile
dependency rules.  This makes it possible to carry out development of the
Serval DNA source code itself and test it using an Xcode iOS project, with a
relatively quick turn-around.

-----
**Copyright 2017 Flinders University**  
![CC-BY-4.0](./cc-by-4.0.png)
This document is available under the [Creative Commons Attribution 4.0 International licence][CC BY 4.0].


[Serval Project]: http://www.servalproject.org/
[Serval DNA]: ../README.md
[Apple iOS]: https://en.wikipedia.org/wiki/IOS
[NLnet Foundation]: https://nlnet.nl/
[Bash shell]: http://en.wikipedia.org/wiki/Bash_(Unix_shell)
[Unix]: https://en.wikipedia.org/wiki/Unix
[GNU]: https://en.wikipedia.org/wiki/GNU
[Linux]: https://en.wikipedia.org/wiki/Linux
[Darwin]: https://en.wikipedia.org/wiki/Darwin_(operating_system)
[GNU autoconf]: http://www.gnu.org/software/autoconf/autoconf.html
[GNU make]: https://www.gnu.org/software/make/
[Clang]: https://en.wikipedia.org/wiki/Clang
[build]: ../INSTALL.md
[develop]: ./Development.md
[IDE]: https://en.wikipedia.org/wiki/Integrated_development_environment
[Xcode]: https://en.wikipedia.org/wiki/Xcode
[Xcode 9]: https://developer.apple.com/library/content/releasenotes/DeveloperTools/RN-Xcode/Chapters/Introduction.html
[C11]: https://en.wikipedia.org/wiki/C11_(C_standard_revision)
[Swift 4.1]: https://swift.org/blog/swift-4-1-released/
[cross compiling]: https://en.wikipedia.org/wiki/Cross_compiler
[Mac OS 10.13 “High Sierra”]: https://en.wikipedia.org/wiki/MacOS_High_Sierra
[iOS 10]: https://en.wikipedia.org/wiki/IOS_10
[iPhone 5]: https://en.wikipedia.org/wiki/IPhone_5
[iPhone 5C]: https://en.wikipedia.org/wiki/IPhone_5C
[iPhone 5S]: https://en.wikipedia.org/wiki/IPhone_5S
[iPhone 6 and 6 Plus]: https://en.wikipedia.org/wiki/IPhone_6
[iPhone 6S and 6S Plus]: https://en.wikipedia.org/wiki/IPhone_6S
[iPhone SE]: https://en.wikipedia.org/wiki/IPhone_SE
[iPhone 7 and 7 Plus]: https://en.wikipedia.org/wiki/IPhone_7
[iPhone 8 and 8 Plus]: https://en.wikipedia.org/wiki/IPhone_8
[iPhone X]: https://en.wikipedia.org/wiki/IPhone_X
[sed]: https://developer.apple.com/legacy/library/documentation/Darwin/Reference/ManPages/man1/sed.1.html
[tr]: https://developer.apple.com/legacy/library/documentation/Darwin/Reference/ManPages/man1/tr.1.html
[mkdir]: https://developer.apple.com/legacy/library/documentation/Darwin/Reference/ManPages/man1/mkdir.1.html
[Framework Bundle]: https://developer.apple.com/library/content/documentation/MacOSX/Conceptual/BPFrameworks/Frameworks.html
[Clang module]: https://clang.llvm.org/docs/Modules.html
[lipo(1)]: http://www.manpages.info/macosx/lipo.1.html
[CC BY 4.0]: ../LICENSE-DOCUMENTATION.md
