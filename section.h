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

#ifndef __SERVAL_DNA__SECTION_H
#define __SERVAL_DNA__SECTION_H

#include "lang.h"

/* Macros for creating named linkage sections.
 */

#define SECTION_START(X) __start_##X
#define SECTION_END(X) __stop_##X

#if defined(HAVE_VAR_ATTRIBUTE_SECTION)
#   define _SECTION_ATTRIBUTE(X) __section__(#X)
#   define DECLARE_SECTION(TYPE, X) \
        extern TYPE SECTION_START(X)[];\
        extern TYPE SECTION_END(X)[]
#elif defined(HAVE_VAR_ATTRIBUTE_SECTION_SEG)
#   define _SECTION_ATTRIBUTE(X) __section__("__DATA,__"#X)
#   define DECLARE_SECTION(TYPE, X) \
        extern TYPE SECTION_START(X)[] __asm("section$start$__DATA$__" #X);\
        extern TYPE SECTION_END(X)[] __asm("section$end$__DATA$__" #X)
#else
#error "Compiler does not support __attribute__(section())"
#endif

#if !defined(HAVE_FUNC_ATTRIBUTE_ALIGNED)
#error "Compiler does not support __attribute__(aligned())"
#elif !defined(HAVE_FUNC_ATTRIBUTE_USED)
#error "Compiler does not support __attribute__(used)"
#else
#define IN_SECTION(name) __attribute__((__used__, __aligned__(sizeof(void *)), _SECTION_ATTRIBUTE(name)))
#endif

#endif // __SERVAL_DNA__SECTION_H

