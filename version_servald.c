/* 
Serval DNA version and copyright strings
Copyright (C) 2013 Serval Project Inc.

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

#include "version_servald.h"

#ifndef SERVALD_VERSION
#error "SERVALD_VERSION is not defined"
#endif

#ifndef SERVALD_COPYRIGHT
#error "SERVALD_COPYRIGHT is not defined"
#endif

const char version_servald[] = SERVALD_VERSION;
const char copyright_servald[] = SERVALD_COPYRIGHT;
