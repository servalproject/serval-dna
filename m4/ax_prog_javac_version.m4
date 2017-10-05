# SYNOPSIS
#
#   AX_PROG_JAVAC_VERSION
#
# DESCRIPTION
#
#   Discover the version of the java compiler by invoking it with the -version
#   option and stripping off any leading "javac " word.  Cache the result in
#   $ac_cv_prog_javac_version
#
# LICENSE
#
#   Copyright (C) 2017 Flinders University
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
#   As a special exception, Flinders University gives unlimited permission to
#   copy, distribute and modify the configure scripts that are the output of
#   Autoconf when processing the Macro. You need not follow the terms of the
#   GNU General Public License when using or distributing such scripts, even
#   though portions of the text of the Macro appear in them. The GNU General
#   Public License (GPL) does govern all other use of the material that
#   constitutes the Autoconf Macro.
#
#   This special exception to the GPL applies to versions of the Autoconf
#   Macro released by Flinders University. When you make and distribute a
#   modified version of the Autoconf Macro, you may extend this special
#   exception to the GPL to apply to your modified version as well.

#serial 1

AU_ALIAS([AC_PROG_JAVAC_VERSION], [AX_PROG_JAVAC_VERSION])
AC_DEFUN([AX_PROG_JAVAC_VERSION],[
    AC_REQUIRE([AC_PROG_SED])
    AC_PROG_SED
    AC_CACHE_CHECK([Java compiler version],
                   ax_cv_prog_javac_version,
                   [ dnl
        dnl Many javac print their version number on standard output
        if AC_TRY_COMMAND([$JAVAC -version >java_version 2>&1]); then
            ax_cv_prog_javac_version=`$SED -n 's/^javac //p' java_version`
        else
            AC_MSG_ERROR([The Java compiler $JAVAC failed (see config.log)])
            ax_cv_prog_javac_version=""
        fi
        rm -f java_version
    ])
    AC_PROVIDE([$0])dnl
])
