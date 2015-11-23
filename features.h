/*
Copyright (C) 2015 Serval Project Inc.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#ifndef __SERVAL_DNA__FEATURES_H
#define __SERVAL_DNA__FEATURES_H

/* Useful macros not specific to Serval DNA
 */

// Number of elements in an array (Warning: does not work if A is a pointer!).
#define NELS(A) (sizeof (A) / sizeof *(A))

// Support for various GCC attributes.

#ifdef HAVE_FUNC_ATTRIBUTE_ERROR
#   define __ATTRIBUTE_error(m)  __error__(m)
#else
#   define __ATTRIBUTE_error(m)
#endif

#ifdef HAVE_FUNC_ATTRIBUTE_FORMAT
#   define __ATTRIBUTE_format(a,b,c)  __format__(a,b,c)
#else
#   define __ATTRIBUTE_format(a,b,c)
#endif

#ifdef HAVE_FUNC_ATTRIBUTE_MALLOC
#   define __ATTRIBUTE_malloc  __malloc__
#else
#   define __ATTRIBUTE_malloc
#endif

#ifdef HAVE_FUNC_ATTRIBUTE_ALLOC_SIZE
#   define __ATTRIBUTE_alloc_size(n)  __alloc_size__(n)
#else
#   define __ATTRIBUTE_alloc_size(n)
#endif

// To suppress the "unused parameter" warning from -Wunused-parameter.
#ifdef HAVE_FUNC_ATTRIBUTE_UNUSED
#   define __ATTRIBUTE_unused  __unused__
#   define UNUSED(x) x __attribute__((__unused__))
#else
#   define __ATTRIBUTE_unused
#   define UNUSED(x) x
#endif

#endif // __SERVAL_DNA__FEATURES_H
