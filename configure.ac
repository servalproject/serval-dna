dnl Process this file with autoconf to produce a configure script.
dnl vim:filetype=m4
AC_INIT(servald, 0.9)
AC_CONFIG_SRCDIR([serval_types.h])
AC_CONFIG_MACRO_DIR([m4])

AC_ARG_VAR([AR], [Library archiver])
AC_ARG_VAR([RANLIB], [Archive indexer])

dnl Specify Swift compiler
AC_ARG_VAR([SWIFTC], [Swift compiler])
AC_ARG_VAR([SWIFTCFLAGS], [Swift compiler flags])

dnl Specify default instance path
AC_ARG_VAR([INSTANCE_PATH], [default instance path for servald])
AS_IF([test "x$INSTANCE_PATH" != x], [AC_DEFINE_UNQUOTED([INSTANCE_PATH], ["$INSTANCE_PATH"], [default instance path])])

dnl Specify default Serval config directory
AC_ARG_VAR([SERVAL_ETC_PATH], [default Serval config directory])
AS_IF([test "x$SERVAL_ETC_PATH" != x], [AC_DEFINE_UNQUOTED([SERVAL_ETC_PATH], ["$SERVAL_ETC_PATH"], [default config directory])])

dnl Specify default Serval run directory
AC_ARG_VAR([SERVAL_RUN_PATH], [default Serval run directory])
AS_IF([test "x$SERVAL_RUN_PATH" != x], [AC_DEFINE_UNQUOTED([SERVAL_RUN_PATH], ["$SERVAL_RUN_PATH"], [default run directory])])

dnl Specify default Serval log directory
AC_ARG_VAR([SERVAL_LOG_PATH], [default Serval log directory])
AS_IF([test "x$SERVAL_LOG_PATH" != x], [AC_DEFINE_UNQUOTED([SERVAL_LOG_PATH], ["$SERVAL_LOG_PATH"], [default log directory])])

dnl Specify default system log directory
AC_ARG_VAR([SYSTEM_LOG_PATH], [default system log directory])
AS_IF([test "x$SYSTEM_LOG_PATH" != x], [AC_DEFINE_UNQUOTED([SYSTEM_LOG_PATH], ["$SYSTEM_LOG_PATH"], [default system log directory])])

dnl Specify default Serval tmp directory
AC_ARG_VAR([SERVAL_TMP_PATH], [default Serval tmp directory])
AS_IF([test "x$SERVAL_TMP_PATH" != x], [AC_DEFINE_UNQUOTED([SERVAL_TMP_PATH], ["$SERVAL_TMP_PATH"], [default Serval tmp directory])])

dnl Specify default Rhizome store directory
AC_ARG_VAR([RHIZOME_STORE_PATH], [default Rhizome store directory])
AS_IF([test "x$RHIZOME_STORE_PATH" != x], [AC_DEFINE_UNQUOTED([RHIZOME_STORE_PATH], ["$RHIZOME_STORE_PATH"], [default Rhizome store directory])])

dnl Set $build, $build_cpu, $build_vendor, $build_os to reflect the native
dnl platform (the one on which the build is being performed), either from the
dnl --build option, or by running config.guess.
AC_CANONICAL_BUILD

dnl Set $host, $host_cpu, $host_vendor, $host_os, either from --host option
dnl (cross compilation), or falling back to $build (native compilation).
AC_CANONICAL_HOST

dnl $CFLAGS_TARGET is used in the Serval DNA Makefile and also passed in CFLAGS to all
dnl sub-Makefiles, such as libsodium.
CFLAGS_TARGET=''

dnl Check for C99 compiler, preprocessor and assembler.
AC_PROG_CC_C99
AC_PROG_CPP
AM_PROG_AS

dnl Check for library creation tools.
AC_CHECK_TOOL([AR], [ar], [:])
AS_IF([test "x$AR" = x:], [AC_MSG_ERROR([Library archiver not found: ar])])
AC_CHECK_TOOL([RANLIB], [ranlib], [:])
AS_IF([test "x$RANLIB" = x:], [AC_MSG_ERROR([Archive indexer not found: ranlib])])

dnl C preprocessor option to support cross-compiling.
AX_APPEND_COMPILE_FLAGS(["-arch $host_cpu"], [CPPFLAGS])

dnl Check for a Swift 3 or 4 compiler; set SWIFTC if found.
AC_PROG_SWIFTC

AS_IF([test "x$SWIFTC" != x], [ dnl
    dnl Discover the Swift compiler's target, which is determined by the --host option
    dnl in an Xcode cross build, and is its default target for a native build (which
    dnl may be affected by $SWIFTCFLAGS).
    AC_MSG_CHECKING([Swift target])

    dnl Swift SDK names differ a little from Xcode names: iPhoneOS and iPhoneSimulator
    dnl are both represented as ios.
    swiftc_target=`$SWIFTC $SWIFTCFLAGS -version 2>&1 | sed -n -e 's/^Target:  *//p'`
    AS_IF([test "x$swiftc_target" = x], [AC_MSG_ERROR([Swift compiler does not report its target: $SWIFTC $SWIFTCFLAGS -version])])

    dnl In a build for Mac OSX (native or cross), ensure that the Swift target is high
    dnl enough to create a Swift package, which were not supported before Mac OSX 10.10.
    macosx_min_version=10.10
    AS_CASE([$swiftc_target],
        [[*-apple-macosx*]], [ dnl
            swiftc_target_version=[`echo "$swiftc_target" | sed -n -e 's/^.*-macosx//p'`]
            AS_VERSION_COMPARE([$swiftc_target_version], [$macosx_min_version], [ dnl
                CFLAGS_TARGET="-mmacosx-version-min=$macosx_min_version"
                swiftc_target=[`echo "$swiftc_target" | sed -n -e 's/-macosx.*$//p'`-macosx$macosx_min_version]
            ])
        ]
    )
    AC_MSG_RESULT([$swiftc_target])

    dnl Check whether the Swift compiler will compile a simple Swift 4 program with the supplied flags.
    dnl If not, report failure but keep going.
    AC_PROG_SWIFTC_IS_SWIFT4
    AS_IF([test "x$ac_cv_prog_swiftc_is_swift4" = xyes], [SWIFT_VERSION=4], [ dnl
        AC_PROG_SWIFTC_IS_SWIFT3
        AS_IF([test "x$ac_cv_prog_swiftc_is_swift3" = xyes], [SWIFT_VERSION=3], [ dnl
            AC_MSG_WARN([$SWIFTC version is too old; omitting Swift API])
            SWIFT_VERSION=
            SWIFTC=
        ])
    ])

    dnl Add the -target option to SWIFTCFLAGS (if the user has already supplied a -target option in
    dnl SWIFTCFLAGS, then this prepended one will take precedence).
    SWIFTCFLAGS="-target $swiftc_target $SWIFTCFLAGS"
])

dnl Check for a working Swift package manager, keep going if unsuccessful.
AS_IF([test "x$SWIFTC" != x && test "x$SWIFT_BUILD" = x], [
    AC_PROG_SWIFT_PACKAGE_MANAGER
])

dnl The C compilation flags used in all Serval-DNA Makefiles.
CPPFLAGS="$CPPFLAGS -D_GNU_SOURCE"
CFLAGS_TARGET="$CFLAGS_TARGET"
CFLAGS="$CFLAGS_TARGET $CFLAGS"

export CPPFLAGS
export CFLAGS

AC_SUBST([WRAPPER])
AC_SUBST([CFLAGS_TARGET])
AC_SUBST([SWIFTC])
AC_SUBST([SWIFTCFLAGS])
AC_SUBST([SWIFT_VERSION])
AC_SUBST([SWIFT_BUILD])

dnl Various GCC function and variable attributes
AX_GCC_FUNC_ATTRIBUTE(aligned)
AX_GCC_FUNC_ATTRIBUTE(alloc_size)
AX_GCC_FUNC_ATTRIBUTE(error)
AX_GCC_FUNC_ATTRIBUTE(format)
AX_GCC_FUNC_ATTRIBUTE(malloc)
AX_GCC_FUNC_ATTRIBUTE(unused)
AX_GCC_FUNC_ATTRIBUTE(used)
AX_GCC_VAR_ATTRIBUTE(section)
AX_GCC_VAR_ATTRIBUTE(section_seg)
AX_GCC_STMT_ATTRIBUTE(fallthrough)

dnl The default GNU linker (BFD) cannot relocate some symbols produced by the
dnl Swift compiler, so the gold linker is used to create dynamic libraries.
dnl See doc/Development.md for details.
AX_APPEND_LINK_FLAGS(-fuse-ld=gold)

dnl Early versions of GCC on Mac OS-X would fail without this flag, which soon
dnl became deprecated and eventually removed some time around 2015.
AX_APPEND_COMPILE_FLAGS([-no-cpp-precomp], [CFLAGS])

dnl Cause GCC to use pipes to connect the compilation stages using pipes instead
dnl of temporary files.
AX_APPEND_COMPILE_FLAGS([-pipe], [CFLAGS])

dnl Suppress certain compiler warnings when compiling SQLite.
AX_APPEND_COMPILE_FLAGS([ \
    -Wno-empty-body \
    -Wno-unused-value \
    -Wno-unused-function \
    -Wno-unused-parameter \
    -Wno-unused-variable \
    -Wno-unused-but-set-variable \
    -Wno-missing-field-initializers \
    -Wno-deprecated-declarations \
    '-Wno-#warnings' \
    ],
    [CFLAGS_SQLITE], [-Werror])
dnl Put a backslash before any '#' characters so it expands correctly in Makefile.in.
CFLAGS_SQLITE="`echo "$CFLAGS_SQLITE" | sed 's/#/\\\\#/g'`"
AC_SUBST([CFLAGS_SQLITE])

dnl Math library functions for spandsp
AC_CHECK_HEADERS([math.h], [INSERT_MATH_HEADER="#include <math.h>"])
AC_CHECK_HEADERS([float.h])

dnl Check for a working Java compiler, keep going if unsuccessful.
dnl *** Kludge: override AC_MSG_ERROR because AC_PROG_JAVAC does not have
dnl *** [if-found] and [if-not-found] action parameters.
pushdef([AC_MSG_ERROR], defn([AC_MSG_WARN]))
AC_PROG_JAVAC
popdef([AC_MSG_ERROR])
AC_SUBST([JAVAC])

dnl Check Java version, ditch Java if not adequate
AS_IF([test -n "$JAVAC"], [ dnl
    dnl Discover the version of the Java compiler
    AC_PROG_JAVAC_VERSION
    dnl Check that the Java compiler is modern enough
    AS_CASE($ax_cv_prog_javac_version,
            [[1.[6-9].*|1.[1-9][0-9].*|2.*]], [],
            [''], [ dnl
                AC_MSG_WARN([Java version not detected; omitting Java API])
                JAVAC=""
            ], [ dnl
                AC_MSG_WARN([Java version $ax_cv_prog_javac_version is too old; omitting Java API])
                JAVAC=""
            ])
])

AS_IF([test -n "$JAVAC"], [ dnl
    dnl Discover the locations of JNI header files
    dnl *** Kludge: override AC_MSG_ERROR because AC_JNI_INCLUDE_DIR does not have
    dnl *** [if-found] and [if-not-found] action parameters.
    pushdef([AC_MSG_ERROR], defn([AC_MSG_WARN]))
    AC_JNI_INCLUDE_DIR
    for JNI_INCLUDE_DIR in $JNI_INCLUDE_DIRS; do
        CPPFLAGS="$CPPFLAGS -I$JNI_INCLUDE_DIR"
    done
    popdef([AC_MSG_ERROR])
])

dnl XXX Isn't this pointless? we are always linked against libc
AC_CHECK_LIB(c,srandomdev)

AC_CHECK_LIB(m,sqrtf,[LDFLAGS="$LDFLAGS -lm"])
AC_CHECK_LIB(nsl,callrpc,[LDFLAGS="$LDFLAGS -lnsl"])
AC_CHECK_LIB(dl,dlopen,[LDFLAGS="$LDFLAGS -ldl"])

dnl Solaris hides nanosleep here
AC_CHECK_LIB(rt,nanosleep)

AC_CHECK_FUNCS([getpeereid bcopy bzero bcmp lseek64])
AC_CHECK_TYPES([off64_t], [have_off64_t=1], [have_off64_t=0])
AC_CHECK_SIZEOF([off_t])

dnl There must be a 64-bit seek(2) system call of some kind
AS_IF([test "x$have_lseek64_t" = "xno" && test "x$ac_cv_sizeof_off_t" != x8 ], [
    AC_MSG_ERROR([Missing lseek64(2) system call])
])

AC_CHECK_HEADERS(
    stdio.h \
    errno.h \
    stdlib.h \
    strings.h \
    unistd.h \
    string.h \
    arpa/inet.h \
    sys/socket.h \
    sys/mman.h \
    sys/time.h \
    sys/ucred.h \
    sys/statvfs.h \
    sys/stat.h \
    sys/vfs.h \
    poll.h \
    netdb.h \
    linux/ioctl.h \
    linux/netlink.h \
    linux/rtnetlink.h \
    net/if.h \
    netinet/in.h \
    ifaddrs.h \
    net/route.h \
    signal.h \
    jni.h \
    ucred.h \
    sys/filio.h \
    sys/endian.h \
    sys/byteorder.h \
    sys/sockio.h \
    sys/socket.h
)
AC_CHECK_HEADERS(
    linux/if.h
,,, [
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
])

AC_SUBST([HAVE_JNI_H], [$ac_cv_header_jni_h])

dnl Check if the Linux gettid() and tgkill() system calls are supported.
AC_CHECK_FUNCS([gettid tgkill])
AC_CACHE_CHECK([Linux thread system calls], ac_cv_have_linux_threads, [
    ac_cv_have_linux_threads=no
    AC_COMPILE_IFELSE(
        [AC_LANG_PROGRAM([
                #include <unistd.h>
                #include <sys/syscall.h>
                #include <signal.h>
            ],
            [syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGHUP)]
        )],
        [ac_cv_have_linux_threads=yes]
    )
])
AS_IF([test "x$ac_cv_have_linux_threads" = xyes],
      [AC_DEFINE([HAVE_LINUX_THREADS], 1, [Linux threads are supported - gettid(2) and tgkill(2).])])

dnl Lazy way of checking for Linux
AS_IF([test "x$ac_cv_header_linux_if_h" = xyes],
      [AC_DEFINE([USE_ABSTRACT_NAMESPACE], 1, [Use abstract namespace sockets for local communication.])])

AC_CACHE_CHECK([linker -z relro option], libc_cv_z_relro, [dnl
  libc_cv_z_relro=no
  AS_IF([AC_TRY_COMMAND([${CC-cc} -v --help 2>&1 | grep "z relro" 1>&AS_MESSAGE_LOG_FD])], [
    AS_IF([AC_TRY_COMMAND([${CC-cc} -Wl,--verbose 2>&1 | grep DATA_SEGMENT_RELRO_END 1>&AS_MESSAGE_LOG_FD])], [
      libc_cv_z_relro=yes
      LDFLAGS="$LDFLAGS -Wl,-z,relro"
    ])
  ])
])

dnl Stack smashing protection is not available on all platforms
AC_MSG_CHECKING([for SSP support])
have_ssp=0
save_cflags="$CFLAGS"
CFLAGS="$CFLAGS -fstack-protector --param=ssp-buffer-size=4"
AC_LANG([C])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])], [
    AC_LINK_IFELSE([AC_LANG_PROGRAM([])], [
        have_ssp=1
    ])
])
AS_IF([test x"$have_ssp" = "x1"], [
    AC_MSG_RESULT([yes])
    AC_SUBST([HAVE_SSP],1)
], [
    AC_MSG_RESULT([no])
    CFLAGS="$save_cflags"
])

dnl Some platforms still seem to lack the basic single precision trig and power related function.
AC_SEARCH_LIBS([sinf], [m], AC_DEFINE([HAVE_SINF], [1], [Define to 1 if the sinf() function is available.]))
AC_SEARCH_LIBS([cosf], [m], AC_DEFINE([HAVE_COSF], [1], [Define to 1 if the cosf() function is available.]))
AC_SEARCH_LIBS([tanf], [m], AC_DEFINE([HAVE_TANF], [1], [Define to 1 if the tanf() function is available.]))
AC_SEARCH_LIBS([asinf], [m], AC_DEFINE([HAVE_ASINF], [1], [Define to 1 if the asinf() function is available.]))
AC_SEARCH_LIBS([acosf], [m], AC_DEFINE([HAVE_ACOSF], [1], [Define to 1 if the acosf() function is available.]))
AC_SEARCH_LIBS([atanf], [m], AC_DEFINE([HAVE_ATANF], [1], [Define to 1 if the atanf() function is available.]))
AC_SEARCH_LIBS([atan2f], [m], AC_DEFINE([HAVE_ATAN2F], [1], [Define to 1 if the atan2f() function is available.]))
AC_SEARCH_LIBS([ceilf], [m], AC_DEFINE([HAVE_CEILF], [1], [Define to 1 if the ceilf() function is available.]))
AC_SEARCH_LIBS([floorf], [m], AC_DEFINE([HAVE_FLOORF], [1], [Define to 1 if the floorf() function is available.]))
AC_SEARCH_LIBS([powf], [m], AC_DEFINE([HAVE_POWF], [1], [Define to 1 if the powf() function is available.]))
AC_SEARCH_LIBS([expf], [m], AC_DEFINE([HAVE_EXPF], [1], [Define to 1 if the expf() function is available.]))
AC_SEARCH_LIBS([logf], [m], AC_DEFINE([HAVE_LOGF], [1], [Define to 1 if the logf() function is available.]))
AC_SEARCH_LIBS([log10f], [m], AC_DEFINE([HAVE_LOG10F], [1], [Define to 1 if the log10f() function is available.]))

dnl Check for strlcpy (eg Ubuntu)
AC_SEARCH_LIBS([strlcpy], [], AC_DEFINE([HAVE_STRLCPY], [1], [Define to 1 if the strlcpy() function is available.]))

dnl Put all the -DHAVE_BLAH=1 definitions into config.h instead of expanding
dnl them in @DEFS@ on the command-line of every compilation invoked by make.
AC_CONFIG_HEADERS([config.h])
AC_SUBST([CONFIG_H], [config.h])

dnl The entire libsodium source is in a subdirectory, and has its own configure
dnl script.

AC_CONFIG_SUBDIRS([libsodium])

ac_configure_args="$ac_configure_args CC='$CC' CCAS='$CCAS' LD='$LD'"

AC_OUTPUT([
    Makefile
    testconfig.sh
    java-api/Makefile
    swift-client-api/Makefile
])
