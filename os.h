/*
Serval DNA native Operating System interface
Copyright (C) 2012 Serval Project Inc.
 
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#ifndef __SERVALDNA_OS_H
#define __SERVALDNA_OS_H

/* All wall clock times in the Serval daemon are represented in milliseconds
 * since the Unix epoch.  The gettime_ms() function uses gettimeofday(2) to
 * return this value when called.  The time_ms_t typedef should be used
 * wherever this time value is handled or stored.
 *
 * This type could perfectly well be unsigned, but is defined as signed to
 * avoid the need to cast or define a special signed timedelta_ms_t type at **
 * (1):
 *
 *      static time_ms_t then = 0;
 *      time_ms_t now = gettime_ms();
 *      time_ms_t ago = now - then;  // ** (1)
 *      if (then && ago < 0) {
 *          ... time going backwards ...
 *      } else {
 *          ... time has advanced ...
 *          then = now;
 *      }
 */
typedef long long time_ms_t;

time_ms_t gettime_ms();
time_ms_t sleep_ms(time_ms_t milliseconds);

/* bzero(3) is deprecated in favour of memset(3). */
#define bzero(addr,len) memset((addr), 0, (len))

/* OpenWRT libc doesn't have bcopy, but has memmove */
#define bcopy(A,B,C) memmove(B,A,C)

int mkdirs(const char *path, mode_t mode);
int mkdirsn(const char *path, size_t len, mode_t mode);

void srandomdev();
int urandombytes(unsigned char *buf, unsigned long long len);

#endif //__SERVALDNA_OS_H
