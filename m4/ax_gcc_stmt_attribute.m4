# SYNOPSIS
#
#   AX_GCC_STMT_ATTRIBUTE(ATTRIBUTE)
#
# DESCRIPTION
#
#   This macro checks if the compiler supports one of GCC's statement
#   attributes; many other compilers also provide statement attributes with the
#   same syntax. Compiler warnings are used to detect supported attributes as
#   unsupported ones are ignored by default so quieting warnings when using
#   this macro will yield false positives.
#
#   The ATTRIBUTE parameter holds the name of the attribute to be checked.
#
#   If ATTRIBUTE is supported define HAVE_STMT_ATTRIBUTE_<ATTRIBUTE>.
#
#   The macro caches its result in the ax_cv_have_stmt_attribute_<attribute>
#   variable.
#
#   The macro currently supports the following variable attributes:
#
#    fallthrough  (added 11 Sep 2017, Serval Project)
#
# LICENSE
#
#   Copyright (c) 2017 Flinders University
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved.  This file is offered as-is, without any
#   warranty.

#serial 3

AC_DEFUN([AX_GCC_STMT_ATTRIBUTE], [
    AS_VAR_PUSHDEF([ac_var], [ax_cv_have_stmt_attribute_$1])

    AC_CACHE_CHECK([for __attribute__(($1))], [ac_var], [
        AC_LINK_IFELSE([AC_LANG_PROGRAM([], [
            m4_case([$1],
                [fallthrough], [
                    int x = 1;
                    switch (x) {
                    case 0: __attribute__(($1));
                    case 1: break;
                    }
                ], [
                    m4_warn([syntax], [Unsupported attribute "$1", the test may fail])
                    int x = 1;
                    ++x __attribute__(($1));
                ]
            )])
            ],
            dnl GCC doesn't exit with an error if an unknown attribute is
            dnl provided but only outputs a warning, so accept the attribute
            dnl only if no warning were issued.
            [AS_IF([test -s conftest.err],
                [AS_VAR_SET([ac_var], [no])],
                [AS_VAR_SET([ac_var], [yes])])],
            [AS_VAR_SET([ac_var], [no])
        ])
    ])

    AS_IF([test yes = AS_VAR_GET([ac_var])],
        [AC_DEFINE_UNQUOTED(AS_TR_CPP(HAVE_STMT_ATTRIBUTE_$1), 1,
            [Define to 1 if the system has the `$1' statement attribute])], [])

    AS_VAR_POPDEF([ac_var])
])
