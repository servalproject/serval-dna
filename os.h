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

#ifndef __SERVALDNA_OS_H
#define __SERVALDNA_OS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>

#ifndef __SERVALDNA_OS_INLINE
# if __GNUC__ && !__GNUC_STDC_INLINE__
#  define __SERVALDNA_OS_INLINE extern inline
# else
#  define __SERVALDNA_OS_INLINE inline
# endif
#endif

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
typedef int64_t time_ms_t;
#define PRItime_ms_t PRId64

time_ms_t gettime_ms();
time_ms_t sleep_ms(time_ms_t milliseconds);

#ifndef HAVE_BZERO
__SERVALDNA_OS_INLINE void bzero(void *buf, size_t len) {
    memset(buf, 0, len);
}
#endif

#ifndef HAVE_BCOPY
__SERVALDNA_OS_INLINE void bcopy(void *src, void *dst, size_t len) {
    memcpy(dst, src, len);
}
#endif

#ifndef HAVE_BCMP
__SERVALDNA_OS_INLINE int bcmp(const void *s1, const void *s2, size_t n) {
    // bcmp() is only an equality test, not an order test, so its return value
    // is not specified as negative or positive, only non-zero.  Hoewver
    // memcmp() is an order test.  We deliberately discard negative return
    // values from memcmp(), to avoid misleading developers into assuming that
    // bcmp() is an ordering operator and writing code that depends on that,
    // which of course would fail on platforms with a native bcmp() function.
    return memcmp(s1, s2, n) != 0;
}
#endif

/* The "e" variants log the error before returning -1.
 */
int mkdirs(const char *path, mode_t mode);
int emkdirs(const char *path, mode_t mode);
int mkdirsn(const char *path, size_t len, mode_t mode);
int emkdirsn(const char *path, size_t len, mode_t mode);

void srandomdev();
int urandombytes(unsigned char *buf, size_t len);

/* Read the symbolic link into the supplied buffer and add a terminating nul.
 * Logs an ERROR and returns -1 if the buffer is too short to hold the link
 * content and the terminating nul.  If readlink(2) returns an error, then logs
 * an ERROR and returns -1.  Otherwise, returns the number of bytes read,
 * including the terminating nul, ie, returns what readlink(2) returns plus
 * one.  If the 'len' argument is given as zero, then returns the number of
 * bytes that would be read, by calling lstat(2) instead of readlink(2), plus
 * one for the terminating nul.  Beware of the following race condition: a
 * symbolic link may be altered between calling the lstat(2) and readlink(2),
 * so the following apparently overflow-proof code may still fail from a buffer
 * overflow in the second call to read_symlink():
 *
 *    char *readlink_malloc(const char *path) {
 *	ssize_t len = read_symlink(path, NULL, 0);
 *	if (len == -1)
 *	  return NULL;
 *	char *buf = malloc(len);
 *	if (buf == NULL)
 *	  return NULL;
 *	if (read_symlink(path, buf, len) == -1) {
 *	  free(buf);
 *	  return NULL;
 *	}
 *	return buf;
 *    }
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
ssize_t read_symlink(const char *path, char *buf, size_t len);

#endif //__SERVALDNA_OS_H
