# Serval Project Swift language support
#
# SYNOPSIS
#
#   AX_PROG_SWIFT_PACKAGE_WORKS
#
# DESCRIPTION
#
#   AX_PROG_SWIFT_BUILD_WORKS tests whether the Swift package manager "package"
#   command works.
#
#   Requires the SWIFT shell variable to contain the path of the Swift package
#   manager executable (not the Swift compiler!), either relative to $PATH or
#   absolute; this will usually be just "swift".
#
#   Sets the SWIFT_PACKAGE variable to the command to invoke the manage-package
#   command, usually "swift package".
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

AU_ALIAS([AC_PROG_SWIFT_PACKAGE_WORKS], [AX_PROG_SWIFT_PACKAGE_WORKS])
AC_DEFUN([AX_PROG_SWIFT_PACKAGE_WORKS],[
    AC_REQUIRE([AC_PROG_SED])
    AC_REQUIRE([AX_TMPDIR_SWIFT])
    SWIFT_PACKAGE="$SWIFT package"
    AC_CACHE_CHECK([if $SWIFT_PACKAGE works], ac_cv_prog_swift_package_works, [
        AS_MKDIR_P(["$ax_tmpdir_swift/swift_package/Sources"])
        cat << \EOF > "$ax_tmpdir_swift/swift_package/Package.swift"
/* [#]line __oline__ "configure" */
import PackageDescription
let package = Package(name: "test")
EOF
        ac_cv_prog_swift_package_works=no
        AS_IF([AC_TRY_COMMAND(cd "$ax_tmpdir_swift/swift_package" >/dev/null && $SWIFT_PACKAGE dump-package) > "$ax_tmpdir_swift/swift_package_info.json"], [
            ac_swift_package_info=`$SED -e ':a;$!N;s/\n//;ta;s/ //g' "$ax_tmpdir_swift/swift_package_info.json"`
            AS_IF([test "x$ac_swift_package_info" = ['x{"dependencies":[],"exclude":[],"name":"test","targets":[]}']], [
                ac_cv_prog_swift_package_works=yes
            ])
        ])
        AS_IF([test "x$ac_cv_prog_swift_package_works" != xyes], [
          echo "Package.swift:" >&AS_MESSAGE_LOG_FD
          cat "$ax_tmpdir_swift/swift_package/Package.swift" >&AS_MESSAGE_LOG_FD
          echo "failed output was:" >&AS_MESSAGE_LOG_FD
          echo "$ac_swift_package_info" >&AS_MESSAGE_LOG_FD
        ])
    ])
    AS_IF([test "x$ac_cv_prog_swift_package_works" != xyes], [
        AS_UNSET([SWIFT_PACKAGE])
    ])
    AC_PROVIDE([$0])dnl
])
