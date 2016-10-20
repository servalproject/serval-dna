# Serval Project Swift language support
#
# SYNOPSIS
#
#   AX_TMPDIR_SWIFT
#
# DESCRIPTION
#
#   AX_TMPDIR_SWIFT creates a temporary directory prefixed with "swft" that
#   will be deleted when the shell exits.  It sets the ax_tmpdir_swift shell
#   variable to the absolute path of the created directory.
#
#   Uses AS_TMPDIR() internally but preserves the value of the 'tmp' shell
#   variable.
#

AC_DEFUN([AX_TMPDIR_SWIFT],[
    AS_VAR_COPY([_swift_tmp], [tmp])
    AS_TMPDIR([swft])
    ax_tmpdir_swift="$tmp"
    AS_VAR_COPY([tmp], [_swift_tmp])
])
