/*
Copyright (C) 2017 Flinders University
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

#ifndef __SERVAL_DNA__IDEBUG_H
#define __SERVAL_DNA__IDEBUG_H

#include "lang.h" // for bool_t

/* An "indirect debug flag" is a struct that contains a pointer to a flag and a
 * string constant with the name of the flag.
 */

struct idebug {
    bool_t *flagp;
    const char *flagname;
};

#endif // __SERVAL_DNA__IDEBUG_H
