# Serval Project Swift language support
#
# SYNOPSIS
#
#   AX_PROG_SWIFTC_IS_SWIFT4_1
#
# DESCRIPTION
#
#   AX_PROG_SWIFTC_IS_SWIFT4_1 tests whether the Swift compiler in the SWIFTC
#   variable (eg, as detected by the AX_PROG_SWIFTC macro) can compile a Swift
#   4.1 program to a working native executable, with the given SWIFTCFLAGS
#   compiler options.
#
# LICENSE
#
#   Copyright (C) 2017-2018 Flinders University
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

AU_ALIAS([AC_PROG_SWIFTC_IS_SWIFT4_1], [AX_PROG_SWIFTC_IS_SWIFT4_1])
AC_DEFUN([AX_PROG_SWIFTC_IS_SWIFT4_1],[
    AC_REQUIRE([AX_TMPDIR_SWIFT])
    AC_CACHE_CHECK([if $SWIFTC supports Swift 4.1], ac_cv_prog_swiftc_is_swift4_1, [
        [
        cat <<EOF > "$ax_tmpdir_swift/Test.swift"
/* canImport() was introduced in Swift 4.1 */
#if canImport(os)
import os
#endif
/* Substring was introduced in Swift 4 */
let a = "test"
let b : Substring = a[a.startIndex ... a.index(a.startIndex, offsetBy: 2)]
precondition(b == "tes")
/* Swift 2 uses Process.arguments, so this only compiles in Swift 3 and later */
print(CommandLine.arguments)
EOF
        ]
        if AC_TRY_COMMAND($SWIFTC $SWIFTCFLAGS -emit-executable -o "$ax_tmpdir_swift/Test" "$ax_tmpdir_swift/Test.swift") >/dev/null 2>&1; then
            if AC_TRY_COMMAND("$ax_tmpdir_swift/Test" one two three) > "$ax_tmpdir_swift/Test.out" 2>&1; then
                ac_swift_test_out=`cat "$ax_tmpdir_swift/Test.out"`
                if test "x$ac_swift_test_out" = ['x["'"$ax_tmpdir_swift"'/Test", "one", "two", "three"]']; then
                    ac_cv_prog_swiftc_is_swift4_1=yes
                else
                    echo "incorrect output was: $ac_swift_test_out" >&AS_MESSAGE_LOG_FD
                    ac_cv_prog_swiftc_is_swift4_1=no
                fi
            else
                echo "failed "$ax_tmpdir_swift/Test" execution produced output:" >&AS_MESSAGE_LOG_FD
                cat "$ax_tmpdir_swift/Test.out" >&AS_MESSAGE_LOG_FD
                ac_cv_prog_swiftc_is_swift4_1=no
            fi
        else
            echo "compilation failed for:" >&AS_MESSAGE_LOG_FD
            cat "$ax_tmpdir_swift/Test.swift" >&AS_MESSAGE_LOG_FD
            ac_cv_prog_swiftc_is_swift4_1=no
        fi
        rm -f Test.swift Test Test.out
    ])
    AC_PROVIDE([$0])dnl
])
