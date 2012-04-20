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
fi
rm -f $JAVA_TEST $CLASS_TEST
])
AC_PROVIDE([$0])dnl
])
