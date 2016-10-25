# Serval Project Swift language support
#
# SYNOPSIS
#
#   AX_PROG_SWIFT_PACKAGE_MANAGER
#
# DESCRIPTION
#
#   AX_PROG_SWIFT_PACKAGE_MANAGER tests for the presence of a Swift package
#   manager, ie, a "swift" executable that supports the "swift build" and
#   "swift package" commands.
#
#   Sets the SWIFT shell variable to the name of the Swift executable (not the
#   Swift compiler!) either relative to $PATH or an absolute path if necessary;
#   this is usually just "swift".
#
#   Sets the SWIFT_BUILD shell variable to the command to invoke the
#   build-package command, usually "$SWIFT build".
#
#   Sets the SWIFT_PACKAGE variable to the command to invoke the package
#   management command, usually "$SWIFT package".
#
#   To force a specific swift executable, either:
#
#   - in configure.ac, set SWIFT=yourswift before calling
#     AX_PROG_SWIFT_PACKAGE_MANAGER, or
#
#   - before invoking ./configure, export SWIFT=yourswift
#
# LICENSE
#
#   Copyright (C) 2016 Flinders University
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

AU_ALIAS([AC_PROG_SWIFT_PACKAGE_MANAGER], [AX_PROG_SWIFT_PACKAGE_MANAGER])
AC_DEFUN([AX_PROG_SWIFT_PACKAGE_MANAGER],[
    AS_IF([test "x$SWIFT" = x], [AC_CHECK_PROGS([SWIFT], [swift])])
    AS_IF([test "x$SWIFT" = x], [
        echo "no Swift executable found in \$PATH" >&AS_MESSAGE_LOG_FD
    ], [
        AX_PROG_SWIFT_BUILD_WORKS
        AX_PROG_SWIFT_PACKAGE_WORKS
    ])
    AC_PROVIDE([$0])dnl
])
