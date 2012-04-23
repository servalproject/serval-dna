# ===========================================================================
#    http://www.gnu.org/software/autoconf-archive/ax_jni_include_dir.html
# ===========================================================================
#
# SYNOPSIS
#
#   AX_JNI_INCLUDE_DIR
#
# DESCRIPTION
#
#   AX_JNI_INCLUDE_DIR finds include directories needed for compiling
#   programs using the JNI interface.
#
#   JNI include directories are usually in the java distribution This is
#   deduced from the value of JAVAC. When this macro completes, a list of
#   directories is left in the variable JNI_INCLUDE_DIRS.
#
#   Example usage follows:
#
#     AX_JNI_INCLUDE_DIR
#
#     for JNI_INCLUDE_DIR in $JNI_INCLUDE_DIRS
#     do
#             CPPFLAGS="$CPPFLAGS -I$JNI_INCLUDE_DIR"
#     done
#
#   If you want to force a specific compiler:
#
#   - at the configure.in level, set JAVAC=yourcompiler before calling
#   AX_JNI_INCLUDE_DIR
#
#   - at the configure level, setenv JAVAC
#
#   Note: This macro can work with the autoconf M4 macros for Java programs.
#   This particular macro is not part of the original set of macros.
#
# LICENSE
#
#   Copyright (c) 2008 Don Anderson <dda@sleepycat.com>
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

#serial 7

AU_ALIAS([AC_JNI_INCLUDE_DIR], [AX_JNI_INCLUDE_DIR])
AC_DEFUN([AX_JNI_INCLUDE_DIR],[

JNI_INCLUDE_DIRS=""

test "x$JAVAC" = x && AC_MSG_ERROR(['\$JAVAC' undefined])
AC_PATH_PROG([_ACJNI_JAVAC], [$JAVAC], [no])
test "x$_ACJNI_JAVAC" = xno && AC_MSG_ERROR([$JAVAC could not be found in path])

_ACJNI_FOLLOW_SYMLINKS("$_ACJNI_JAVAC")
_JTOPDIR=`echo "$_ACJNI_FOLLOWED" | sed -e 's://*:/:g' -e 's:/[[^/]]*$::'`
case "$host_os" in
        darwin*)        _JTOPDIR=`echo "$_JTOPDIR" | sed -e 's:/[[^/]]*$::'`
                        _JINC="$_JTOPDIR/Headers";;
        *)              _JINC="$_JTOPDIR/include";;
esac
_AS_ECHO_LOG([_JTOPDIR=$_JTOPDIR])
_AS_ECHO_LOG([_JINC=$_JINC])

# On Mac OS X 10.6.4, jni.h is a symlink:
# /System/Library/Frameworks/JavaVM.framework/Versions/Current/Headers/jni.h
# -> ../../CurrentJDK/Headers/jni.h.
if test -f "$_JINC/jni.h" || test -L "$_JINC/jni.h"; then
        JNI_INCLUDE_DIRS="$JNI_INCLUDE_DIRS $_JINC"
else
        _JTOPDIR=`echo "$_JTOPDIR" | sed -e 's:/[[^/]]*$::'`
        if test -f "$_JTOPDIR/include/jni.h"; then
                JNI_INCLUDE_DIRS="$JNI_INCLUDE_DIRS $_JTOPDIR/include"
        else
                AC_MSG_ERROR([cannot find java include files])
        fi
fi

# get the likely subdirectories for system specific java includes
case "$host_os" in
bsdi*)          _JNI_INC_SUBDIRS="bsdos";;
linux*)         _JNI_INC_SUBDIRS="linux genunix";;
osf*)           _JNI_INC_SUBDIRS="alpha";;
solaris*)       _JNI_INC_SUBDIRS="solaris";;
mingw*)		_JNI_INC_SUBDIRS="win32";;
cygwin*)	_JNI_INC_SUBDIRS="win32";;
*)              _JNI_INC_SUBDIRS="genunix";;
esac

# add any subdirectories that are present
for JINCSUBDIR in $_JNI_INC_SUBDIRS
do
    if test -d "$_JTOPDIR/include/$JINCSUBDIR"; then
         JNI_INCLUDE_DIRS="$JNI_INCLUDE_DIRS $_JTOPDIR/include/$JINCSUBDIR"
    fi
done
])

# _ACJNI_FOLLOW_SYMLINKS <path>
# Follows symbolic links on <path>,
# finally setting variable _ACJNI_FOLLOWED
# ----------------------------------------
AC_DEFUN([_ACJNI_FOLLOW_SYMLINKS],[
# find the include directory relative to the javac executable
_cur="$1"
while ls -ld "$_cur" 2>/dev/null | grep " -> " >/dev/null; do
        AC_MSG_CHECKING([symlink for $_cur])
        _slink=`ls -ld "$_cur" | sed 's/.* -> //'`
        case "$_slink" in
        /*) _cur="$_slink";;
        # 'X' avoids triggering unwanted echo options.
        *) _cur=`echo "X$_cur" | sed -e 's/^X//' -e 's:[[^/]]*$::'`"$_slink";;
        esac
        AC_MSG_RESULT([$_cur])
done
_ACJNI_FOLLOWED="$_cur"
])# _ACJNI
# ===========================================================================
#       http://www.gnu.org/software/autoconf-archive/ax_prog_javac.html
# ===========================================================================
#
# SYNOPSIS
#
#   AX_PROG_JAVAC
#
# DESCRIPTION
#
#   AX_PROG_JAVAC tests an existing Java compiler. It uses the environment
#   variable JAVAC then tests in sequence various common Java compilers. For
#   political reasons, it starts with the free ones.
#
#   If you want to force a specific compiler:
#
#   - at the configure.in level, set JAVAC=yourcompiler before calling
#   AX_PROG_JAVAC
#
#   - at the configure level, setenv JAVAC
#
#   You can use the JAVAC variable in your Makefile.in, with @JAVAC@.
#
#   *Warning*: its success or failure can depend on a proper setting of the
#   CLASSPATH env. variable.
#
#   TODO: allow to exclude compilers (rationale: most Java programs cannot
#   compile with some compilers like guavac).
#
#   Note: This is part of the set of autoconf M4 macros for Java programs.
#   It is VERY IMPORTANT that you download the whole set, some macros depend
#   on other. Unfortunately, the autoconf archive does not support the
#   concept of set of macros, so I had to break it for submission. The
#   general documentation, as well as the sample configure.in, is included
#   in the AX_PROG_JAVA macro.
#
# LICENSE
#
#   Copyright (c) 2008 Stephane Bortzmeyer <bortzmeyer@pasteur.fr>
#
#   This program is free software; you can redistribute it and/or modify it
#   under the terms of the GNU General Public License as published by the
#   Free Software Foundation; either version 2 of the License, or (at your
#   option) any later version.
#
#   This program is distributed in the hope that it will be useful, but
#   WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
#   Public License for more details.
#
#   You should have received a copy of the GNU General Public License along
#   with this program. If not, see <http://www.gnu.org/licenses/>.
#
#   As a special exception, the respective Autoconf Macro's copyright owner
#   gives unlimited permission to copy, distribute and modify the configure
#   scripts that are the output of Autoconf when processing the Macro. You
#   need not follow the terms of the GNU General Public License when using
#   or distributing such scripts, even though portions of the text of the
#   Macro appear in them. The GNU General Public License (GPL) does govern
#   all other use of the material that constitutes the Autoconf Macro.
#
#   This special exception to the GPL applies to versions of the Autoconf
#   Macro released by the Autoconf Archive. When you make and distribute a
#   modified version of the Autoconf Macro, you may extend this special
#   exception to the GPL to apply to your modified version as well.

#serial 6

AU_ALIAS([AC_PROG_JAVAC], [AX_PROG_JAVAC])
AC_DEFUN([AX_PROG_JAVAC],[
if test "x$JAVAPREFIX" = x; then
        test "x$JAVAC" = x && AC_CHECK_PROGS(JAVAC, "gcj -C" guavac jikes javac)
else
        test "x$JAVAC" = x && AC_CHECK_PROGS(JAVAC, "gcj -C" guavac jikes javac, $JAVAPREFIX)
fi
test "x$JAVAC" = x && AC_MSG_ERROR([no acceptable Java compiler found in \$PATH])
AX_PROG_JAVAC_WORKS
AC_PROVIDE([$0])dnl
])
# ===========================================================================
#    http://www.gnu.org/software/autoconf-archive/ax_prog_javac_works.html
# ===========================================================================
#
# SYNOPSIS
#
#   AX_PROG_JAVAC_WORKS
#
# DESCRIPTION
#
#   Internal use ONLY.
#
#   Note: This is part of the set of autoconf M4 macros for Java programs.
#   It is VERY IMPORTANT that you download the whole set, some macros depend
#   on other. Unfortunately, the autoconf archive does not support the
#   concept of set of macros, so I had to break it for submission. The
#   general documentation, as well as the sample configure.in, is included
#   in the AX_PROG_JAVA macro.
#
# LICENSE
#
#   Copyright (c) 2008 Stephane Bortzmeyer <bortzmeyer@pasteur.fr>
#
#   This program is free software; you can redistribute it and/or modify it
#   under the terms of the GNU General Public License as published by the
#   Free Software Foundation; either version 2 of the License, or (at your
#   option) any later version.
#
#   This program is distributed in the hope that it will be useful, but
#   WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
#   Public License for more details.
#
#   You should have received a copy of the GNU General Public License along
#   with this program. If not, see <http://www.gnu.org/licenses/>.
#
#   As a special exception, the respective Autoconf Macro's copyright owner
#   gives unlimited permission to copy, distribute and modify the configure
#   scripts that are the output of Autoconf when processing the Macro. You
#   need not follow the terms of the GNU General Public License when using
#   or distributing such scripts, even though portions of the text of the
#   Macro appear in them. The GNU General Public License (GPL) does govern
#   all other use of the material that constitutes the Autoconf Macro.
#
#   This special exception to the GPL applies to versions of the Autoconf
#   Macro released by the Autoconf Archive. When you make and distribute a
#   modified version of the Autoconf Macro, you may extend this special
#   exception to the GPL to apply to your modified version as well.

#serial 5

AU_ALIAS([AC_PROG_JAVAC_WORKS], [AX_PROG_JAVAC_WORKS])
AC_DEFUN([AX_PROG_JAVAC_WORKS],[
AC_CACHE_CHECK([if $JAVAC works], ac_cv_prog_javac_works, [
JAVA_TEST=Test.java
CLASS_TEST=Test.class
cat << \EOF > $JAVA_TEST
/* [#]line __oline__ "configure" */
public class Test {
}
EOF
if AC_TRY_COMMAND($JAVAC $JAVACFLAGS $JAVA_TEST) >/dev/null 2>&1; then
  ac_cv_prog_javac_works=yes
else
  AC_MSG_ERROR([The Java compiler $JAVAC failed (see config.log, check the CLASSPATH?)])
  echo "configure: failed program was:" >&AC_FD_CC
  cat $JAVA_TEST >&AC_FD_CC
  ac_cv_prog_javac_works=no
fi
rm -f $JAVA_TEST $CLASS_TEST
])
AC_PROVIDE([$0])dnl
])
# ===========================================================================
#        http://www.gnu.org/software/autoconf-archive/ax_pthread.html
# ===========================================================================
#
# SYNOPSIS
#
#   AX_PTHREAD([ACTION-IF-FOUND[, ACTION-IF-NOT-FOUND]])
#
# DESCRIPTION
#
#   This macro figures out how to build C programs using POSIX threads. It
#   sets the PTHREAD_LIBS output variable to the threads library and linker
#   flags, and the PTHREAD_CFLAGS output variable to any special C compiler
#   flags that are needed. (The user can also force certain compiler
#   flags/libs to be tested by setting these environment variables.)
#
#   Also sets PTHREAD_CC to any special C compiler that is needed for
#   multi-threaded programs (defaults to the value of CC otherwise). (This
#   is necessary on AIX to use the special cc_r compiler alias.)
#
#   NOTE: You are assumed to not only compile your program with these flags,
#   but also link it with them as well. e.g. you should link with
#   $PTHREAD_CC $CFLAGS $PTHREAD_CFLAGS $LDFLAGS ... $PTHREAD_LIBS $LIBS
#
#   If you are only building threads programs, you may wish to use these
#   variables in your default LIBS, CFLAGS, and CC:
#
#     LIBS="$PTHREAD_LIBS $LIBS"
#     CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
#     CC="$PTHREAD_CC"
#
#   In addition, if the PTHREAD_CREATE_JOINABLE thread-attribute constant
#   has a nonstandard name, defines PTHREAD_CREATE_JOINABLE to that name
#   (e.g. PTHREAD_CREATE_UNDETACHED on AIX).
#
#   Also HAVE_PTHREAD_PRIO_INHERIT is defined if pthread is found and the
#   PTHREAD_PRIO_INHERIT symbol is defined when compiling with
#   PTHREAD_CFLAGS.
#
#   ACTION-IF-FOUND is a list of shell commands to run if a threads library
#   is found, and ACTION-IF-NOT-FOUND is a list of commands to run it if it
#   is not found. If ACTION-IF-FOUND is not specified, the default action
#   will define HAVE_PTHREAD.
#
#   Please let the authors know if this macro fails on any platform, or if
#   you have any other suggestions or comments. This macro was based on work
#   by SGJ on autoconf scripts for FFTW (http://www.fftw.org/) (with help
#   from M. Frigo), as well as ac_pthread and hb_pthread macros posted by
#   Alejandro Forero Cuervo to the autoconf macro repository. We are also
#   grateful for the helpful feedback of numerous users.
#
#   Updated for Autoconf 2.68 by Daniel Richard G.
#
# LICENSE
#
#   Copyright (c) 2008 Steven G. Johnson <stevenj@alum.mit.edu>
#   Copyright (c) 2011 Daniel Richard G. <skunk@iSKUNK.ORG>
#
#   This program is free software: you can redistribute it and/or modify it
#   under the terms of the GNU General Public License as published by the
#   Free Software Foundation, either version 3 of the License, or (at your
#   option) any later version.
#
#   This program is distributed in the hope that it will be useful, but
#   WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
#   Public License for more details.
#
#   You should have received a copy of the GNU General Public License along
#   with this program. If not, see <http://www.gnu.org/licenses/>.
#
#   As a special exception, the respective Autoconf Macro's copyright owner
#   gives unlimited permission to copy, distribute and modify the configure
#   scripts that are the output of Autoconf when processing the Macro. You
#   need not follow the terms of the GNU General Public License when using
#   or distributing such scripts, even though portions of the text of the
#   Macro appear in them. The GNU General Public License (GPL) does govern
#   all other use of the material that constitutes the Autoconf Macro.
#
#   This special exception to the GPL applies to versions of the Autoconf
#   Macro released by the Autoconf Archive. When you make and distribute a
#   modified version of the Autoconf Macro, you may extend this special
#   exception to the GPL to apply to your modified version as well.

#serial 18

AU_ALIAS([ACX_PTHREAD], [AX_PTHREAD])
AC_DEFUN([AX_PTHREAD], [
AC_REQUIRE([AC_CANONICAL_HOST])
AC_LANG_PUSH([C])
ax_pthread_ok=no

# We used to check for pthread.h first, but this fails if pthread.h
# requires special compiler flags (e.g. on True64 or Sequent).
# It gets checked for in the link test anyway.

# First of all, check if the user has set any of the PTHREAD_LIBS,
# etcetera environment variables, and if threads linking works using
# them:
if test x"$PTHREAD_LIBS$PTHREAD_CFLAGS" != x; then
        save_CFLAGS="$CFLAGS"
        CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
        save_LIBS="$LIBS"
        LIBS="$PTHREAD_LIBS $LIBS"
        AC_MSG_CHECKING([for pthread_join in LIBS=$PTHREAD_LIBS with CFLAGS=$PTHREAD_CFLAGS])
        AC_TRY_LINK_FUNC(pthread_join, ax_pthread_ok=yes)
        AC_MSG_RESULT($ax_pthread_ok)
        if test x"$ax_pthread_ok" = xno; then
                PTHREAD_LIBS=""
                PTHREAD_CFLAGS=""
        fi
        LIBS="$save_LIBS"
        CFLAGS="$save_CFLAGS"
fi

# We must check for the threads library under a number of different
# names; the ordering is very important because some systems
# (e.g. DEC) have both -lpthread and -lpthreads, where one of the
# libraries is broken (non-POSIX).

# Create a list of thread flags to try.  Items starting with a "-" are
# C compiler flags, and other items are library names, except for "none"
# which indicates that we try without any flags at all, and "pthread-config"
# which is a program returning the flags for the Pth emulation library.

ax_pthread_flags="pthreads none -Kthread -kthread lthread -pthread -pthreads -mthreads pthread --thread-safe -mt pthread-config"

# The ordering *is* (sometimes) important.  Some notes on the
# individual items follow:

# pthreads: AIX (must check this before -lpthread)
# none: in case threads are in libc; should be tried before -Kthread and
#       other compiler flags to prevent continual compiler warnings
# -Kthread: Sequent (threads in libc, but -Kthread needed for pthread.h)
# -kthread: FreeBSD kernel threads (preferred to -pthread since SMP-able)
# lthread: LinuxThreads port on FreeBSD (also preferred to -pthread)
# -pthread: Linux/gcc (kernel threads), BSD/gcc (userland threads)
# -pthreads: Solaris/gcc
# -mthreads: Mingw32/gcc, Lynx/gcc
# -mt: Sun Workshop C (may only link SunOS threads [-lthread], but it
#      doesn't hurt to check since this sometimes defines pthreads too;
#      also defines -D_REENTRANT)
#      ... -mt is also the pthreads flag for HP/aCC
# pthread: Linux, etcetera
# --thread-safe: KAI C++
# pthread-config: use pthread-config program (for GNU Pth library)

case ${host_os} in
        solaris*)

        # On Solaris (at least, for some versions), libc contains stubbed
        # (non-functional) versions of the pthreads routines, so link-based
        # tests will erroneously succeed.  (We need to link with -pthreads/-mt/
        # -lpthread.)  (The stubs are missing pthread_cleanup_push, or rather
        # a function called by this macro, so we could check for that, but
        # who knows whether they'll stub that too in a future libc.)  So,
        # we'll just look for -pthreads and -lpthread first:

        ax_pthread_flags="-pthreads pthread -mt -pthread $ax_pthread_flags"
        ;;

        darwin*)
        ax_pthread_flags="-pthread $ax_pthread_flags"
        ;;
esac

if test x"$ax_pthread_ok" = xno; then
for flag in $ax_pthread_flags; do

        case $flag in
                none)
                AC_MSG_CHECKING([whether pthreads work without any flags])
                ;;

                -*)
                AC_MSG_CHECKING([whether pthreads work with $flag])
                PTHREAD_CFLAGS="$flag"
                ;;

                pthread-config)
                AC_CHECK_PROG(ax_pthread_config, pthread-config, yes, no)
                if test x"$ax_pthread_config" = xno; then continue; fi
                PTHREAD_CFLAGS="`pthread-config --cflags`"
                PTHREAD_LIBS="`pthread-config --ldflags` `pthread-config --libs`"
                ;;

                *)
                AC_MSG_CHECKING([for the pthreads library -l$flag])
                PTHREAD_LIBS="-l$flag"
                ;;
        esac

        save_LIBS="$LIBS"
        save_CFLAGS="$CFLAGS"
        LIBS="$PTHREAD_LIBS $LIBS"
        CFLAGS="$CFLAGS $PTHREAD_CFLAGS"

        # Check for various functions.  We must include pthread.h,
        # since some functions may be macros.  (On the Sequent, we
        # need a special flag -Kthread to make this header compile.)
        # We check for pthread_join because it is in -lpthread on IRIX
        # while pthread_create is in libc.  We check for pthread_attr_init
        # due to DEC craziness with -lpthreads.  We check for
        # pthread_cleanup_push because it is one of the few pthread
        # functions on Solaris that doesn't have a non-functional libc stub.
        # We try pthread_create on general principles.
        AC_LINK_IFELSE([AC_LANG_PROGRAM([#include <pthread.h>
                        static void routine(void *a) { a = 0; }
                        static void *start_routine(void *a) { return a; }],
                       [pthread_t th; pthread_attr_t attr;
                        pthread_create(&th, 0, start_routine, 0);
                        pthread_join(th, 0);
                        pthread_attr_init(&attr);
                        pthread_cleanup_push(routine, 0);
                        pthread_cleanup_pop(0) /* ; */])],
                [ax_pthread_ok=yes],
                [])

        LIBS="$save_LIBS"
        CFLAGS="$save_CFLAGS"

        AC_MSG_RESULT($ax_pthread_ok)
        if test "x$ax_pthread_ok" = xyes; then
                break;
        fi

        PTHREAD_LIBS=""
        PTHREAD_CFLAGS=""
done
fi

# Various other checks:
if test "x$ax_pthread_ok" = xyes; then
        save_LIBS="$LIBS"
        LIBS="$PTHREAD_LIBS $LIBS"
        save_CFLAGS="$CFLAGS"
        CFLAGS="$CFLAGS $PTHREAD_CFLAGS"

        # Detect AIX lossage: JOINABLE attribute is called UNDETACHED.
        AC_MSG_CHECKING([for joinable pthread attribute])
        attr_name=unknown
        for attr in PTHREAD_CREATE_JOINABLE PTHREAD_CREATE_UNDETACHED; do
            AC_LINK_IFELSE([AC_LANG_PROGRAM([#include <pthread.h>],
                           [int attr = $attr; return attr /* ; */])],
                [attr_name=$attr; break],
                [])
        done
        AC_MSG_RESULT($attr_name)
        if test "$attr_name" != PTHREAD_CREATE_JOINABLE; then
            AC_DEFINE_UNQUOTED(PTHREAD_CREATE_JOINABLE, $attr_name,
                               [Define to necessary symbol if this constant
                                uses a non-standard name on your system.])
        fi

        AC_MSG_CHECKING([if more special flags are required for pthreads])
        flag=no
        case ${host_os} in
            aix* | freebsd* | darwin*) flag="-D_THREAD_SAFE";;
            osf* | hpux*) flag="-D_REENTRANT";;
            solaris*)
            if test "$GCC" = "yes"; then
                flag="-D_REENTRANT"
            else
                flag="-mt -D_REENTRANT"
            fi
            ;;
        esac
        AC_MSG_RESULT(${flag})
        if test "x$flag" != xno; then
            PTHREAD_CFLAGS="$flag $PTHREAD_CFLAGS"
        fi

        AC_CACHE_CHECK([for PTHREAD_PRIO_INHERIT],
            ax_cv_PTHREAD_PRIO_INHERIT, [
                AC_LINK_IFELSE([
                    AC_LANG_PROGRAM([[#include <pthread.h>]], [[int i = PTHREAD_PRIO_INHERIT;]])],
                    [ax_cv_PTHREAD_PRIO_INHERIT=yes],
                    [ax_cv_PTHREAD_PRIO_INHERIT=no])
            ])
        AS_IF([test "x$ax_cv_PTHREAD_PRIO_INHERIT" = "xyes"],
            AC_DEFINE([HAVE_PTHREAD_PRIO_INHERIT], 1, [Have PTHREAD_PRIO_INHERIT.]))

        LIBS="$save_LIBS"
        CFLAGS="$save_CFLAGS"

        # More AIX lossage: must compile with xlc_r or cc_r
        if test x"$GCC" != xyes; then
          AC_CHECK_PROGS(PTHREAD_CC, xlc_r cc_r, ${CC})
        else
          PTHREAD_CC=$CC
        fi
else
        PTHREAD_CC="$CC"
fi

AC_SUBST(PTHREAD_LIBS)
AC_SUBST(PTHREAD_CFLAGS)
AC_SUBST(PTHREAD_CC)

# Finally, execute ACTION-IF-FOUND/ACTION-IF-NOT-FOUND:
if test x"$ax_pthread_ok" = xyes; then
        ifelse([$1],,AC_DEFINE(HAVE_PTHREAD,1,[Define if you have POSIX threads libraries and header files.]),[$1])
        :
else
        ax_pthread_ok=no
        $2
fi
AC_LANG_POP
])dnl AX_PTHREAD
# pkg.m4 - Macros to locate and utilise pkg-config.            -*- Autoconf -*-
# serial 1 (pkg-config-0.24)
# 
# Copyright © 2004 Scott James Remnant <scott@netsplit.com>.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#
# As a special exception to the GNU General Public License, if you
# distribute this file as part of a program that contains a
# configuration script generated by Autoconf, you may include it under
# the same distribution terms that you use for the rest of that program.

# PKG_PROG_PKG_CONFIG([MIN-VERSION])
# ----------------------------------
AC_DEFUN([PKG_PROG_PKG_CONFIG],
[m4_pattern_forbid([^_?PKG_[A-Z_]+$])
m4_pattern_allow([^PKG_CONFIG(_(PATH|LIBDIR|SYSROOT_DIR|ALLOW_SYSTEM_(CFLAGS|LIBS)))?$])
m4_pattern_allow([^PKG_CONFIG_(DISABLE_UNINSTALLED|TOP_BUILD_DIR|DEBUG_SPEW)$])
AC_ARG_VAR([PKG_CONFIG], [path to pkg-config utility])
AC_ARG_VAR([PKG_CONFIG_PATH], [directories to add to pkg-config's search path])
AC_ARG_VAR([PKG_CONFIG_LIBDIR], [path overriding pkg-config's built-in search path])

if test "x$ac_cv_env_PKG_CONFIG_set" != "xset"; then
	AC_PATH_TOOL([PKG_CONFIG], [pkg-config])
fi
if test -n "$PKG_CONFIG"; then
	_pkg_min_version=m4_default([$1], [0.9.0])
	AC_MSG_CHECKING([pkg-config is at least version $_pkg_min_version])
	if $PKG_CONFIG --atleast-pkgconfig-version $_pkg_min_version; then
		AC_MSG_RESULT([yes])
	else
		AC_MSG_RESULT([no])
		PKG_CONFIG=""
	fi
fi[]dnl
])# PKG_PROG_PKG_CONFIG

# PKG_CHECK_EXISTS(MODULES, [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
#
# Check to see whether a particular set of modules exists.  Similar
# to PKG_CHECK_MODULES(), but does not set variables or print errors.
#
# Please remember that m4 expands AC_REQUIRE([PKG_PROG_PKG_CONFIG])
# only at the first occurence in configure.ac, so if the first place
# it's called might be skipped (such as if it is within an "if", you
# have to call PKG_CHECK_EXISTS manually
# --------------------------------------------------------------
AC_DEFUN([PKG_CHECK_EXISTS],
[AC_REQUIRE([PKG_PROG_PKG_CONFIG])dnl
if test -n "$PKG_CONFIG" && \
    AC_RUN_LOG([$PKG_CONFIG --exists --print-errors "$1"]); then
  m4_default([$2], [:])
m4_ifvaln([$3], [else
  $3])dnl
fi])

# _PKG_CONFIG([VARIABLE], [COMMAND], [MODULES])
# ---------------------------------------------
m4_define([_PKG_CONFIG],
[if test -n "$$1"; then
    pkg_cv_[]$1="$$1"
 elif test -n "$PKG_CONFIG"; then
    PKG_CHECK_EXISTS([$3],
                     [pkg_cv_[]$1=`$PKG_CONFIG --[]$2 "$3" 2>/dev/null`
		      test "x$?" != "x0" && pkg_failed=yes ],
		     [pkg_failed=yes])
 else
    pkg_failed=untried
fi[]dnl
])# _PKG_CONFIG

# _PKG_SHORT_ERRORS_SUPPORTED
# -----------------------------
AC_DEFUN([_PKG_SHORT_ERRORS_SUPPORTED],
[AC_REQUIRE([PKG_PROG_PKG_CONFIG])
if $PKG_CONFIG --atleast-pkgconfig-version 0.20; then
        _pkg_short_errors_supported=yes
else
        _pkg_short_errors_supported=no
fi[]dnl
])# _PKG_SHORT_ERRORS_SUPPORTED


# PKG_CHECK_MODULES(VARIABLE-PREFIX, MODULES, [ACTION-IF-FOUND],
# [ACTION-IF-NOT-FOUND])
#
#
# Note that if there is a possibility the first call to
# PKG_CHECK_MODULES might not happen, you should be sure to include an
# explicit call to PKG_PROG_PKG_CONFIG in your configure.ac
#
#
# --------------------------------------------------------------
AC_DEFUN([PKG_CHECK_MODULES],
[AC_REQUIRE([PKG_PROG_PKG_CONFIG])dnl
AC_ARG_VAR([$1][_CFLAGS], [C compiler flags for $1, overriding pkg-config])dnl
AC_ARG_VAR([$1][_LIBS], [linker flags for $1, overriding pkg-config])dnl

pkg_failed=no
AC_MSG_CHECKING([for $1])

_PKG_CONFIG([$1][_CFLAGS], [cflags], [$2])
_PKG_CONFIG([$1][_LIBS], [libs], [$2])

m4_define([_PKG_TEXT], [Alternatively, you may set the environment variables $1[]_CFLAGS
and $1[]_LIBS to avoid the need to call pkg-config.
See the pkg-config man page for more details.])

if test $pkg_failed = yes; then
   	AC_MSG_RESULT([no])
        _PKG_SHORT_ERRORS_SUPPORTED
        if test $_pkg_short_errors_supported = yes; then
	        $1[]_PKG_ERRORS=`$PKG_CONFIG --short-errors --print-errors --cflags --libs "$2" 2>&1`
        else 
	        $1[]_PKG_ERRORS=`$PKG_CONFIG --print-errors --cflags --libs "$2" 2>&1`
        fi
	# Put the nasty error message in config.log where it belongs
	echo "$$1[]_PKG_ERRORS" >&AS_MESSAGE_LOG_FD

	m4_default([$4], [AC_MSG_ERROR(
[Package requirements ($2) were not met:

$$1_PKG_ERRORS

Consider adjusting the PKG_CONFIG_PATH environment variable if you
installed software in a non-standard prefix.

_PKG_TEXT])[]dnl
        ])
elif test $pkg_failed = untried; then
     	AC_MSG_RESULT([no])
	m4_default([$4], [AC_MSG_FAILURE(
[The pkg-config script could not be found or is too old.  Make sure it
is in your PATH or set the PKG_CONFIG environment variable to the full
path to pkg-config.

_PKG_TEXT

To get pkg-config, see <http://pkg-config.freedesktop.org/>.])[]dnl
        ])
else
	$1[]_CFLAGS=$pkg_cv_[]$1[]_CFLAGS
	$1[]_LIBS=$pkg_cv_[]$1[]_LIBS
        AC_MSG_RESULT([yes])
	$3
fi[]dnl
])# PKG_CHECK_MODULES
