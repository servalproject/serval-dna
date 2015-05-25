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

/* Macros for creating named linkage sections.
 */

#ifdef __APPLE__
#define _SECTION_ATTRIBUTE(X) section("__DATA,__" #X )
#define SECTION_START(X) __asm("section$start$__DATA$__" #X)
#define SECTION_STOP(X) __asm("section$end$__DATA$__" #X)
#else
#define _SECTION_ATTRIBUTE(X) section(#X)
#define SECTION_START(X)
#define SECTION_STOP(X)
#endif

#define IN_SECTION(name) __attribute__((used,aligned(sizeof(void *)),_SECTION_ATTRIBUTE(name)))

#endif // __SERVAL_DNA__SECTION_H

