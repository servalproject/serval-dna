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

#ifndef __SERVAL_DNA__OS_H
#define __SERVAL_DNA__OS_H

#include <sys/types.h> // for off64_t
#include <stdio.h> // for NULL
#include <stdlib.h>
#include <stdint.h> // for int64_t
#include <unistd.h> // for lseek()
#ifdef HAVE_STRINGS_H
#include <strings.h> // for bcopy()
#endif
#include <string.h> // for memcmp()
#include "log.h"

#ifndef __SERVAL_DNA__OS_INLINE
# if __GNUC__ && !__GNUC_STDC_INLINE__
#  define __SERVAL_DNA__OS_INLINE extern inline
# else
#  define __SERVAL_DNA__OS_INLINE inline
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
typedef uint32_t time_s_t;
#define PRItime_ms_t PRId64
#define TIME_MS_NEVER_WILL INT64_MAX
#define TIME_MS_NEVER_HAS INT64_MIN

time_ms_t gettime_ms();
time_s_t gettime();
time_ms_t sleep_ms(time_ms_t milliseconds);
struct timeval time_ms_to_timeval(time_ms_t);

#ifndef HAVE_BZERO
__SERVAL_DNA__OS_INLINE void bzero(void *buf, size_t len) {
    memset(buf, 0, len);
}
#endif

#ifndef HAVE_BCOPY
__SERVAL_DNA__OS_INLINE void bcopy(const void *src, void *dst, size_t len) {
    memcpy(dst, src, len);
}
#endif

#ifndef HAVE_BCMP
__SERVAL_DNA__OS_INLINE int bcmp(const void *s1, const void *s2, size_t n) {
    // bcmp() is only an equality test, not an order test, so its return value
    // is not specified as negative or positive, only non-zero.  Hoewver
    // memcmp() is an order test.  We deliberately discard negative return
    // values from memcmp(), to avoid misleading developers into assuming that
    // bcmp() is an ordering operator and writing code that depends on that,
    // which of course would fail on platforms with a native bcmp() function.
    return memcmp(s1, s2, n) != 0;
}
#endif

/* If there is no lseek64(2) system call but off_t is 64 bits, then we can use
 * lseek(2) instead.
 */
#ifndef HAVE_LSEEK64
# if SIZEOF_OFF_T != 8
#  error "lseek64(2) system call is not available and `sizeof(off_t) is not 8"
# endif
# ifndef HAVE_OFF64_T
typedef off_t off64_t;
__SERVAL_DNA__OS_INLINE off64_t lseek64(int fd, off64_t offset, int whence) {
    return lseek(fd, offset, whence);
}
# endif
#endif

/* The "e" variants log the error before returning -1.
 */
typedef void MKDIR_LOG_FUNC(struct __sourceloc, const char *, mode_t);
MKDIR_LOG_FUNC log_info_mkdir;
int _mkdirs(struct __sourceloc, const char *path, mode_t mode, MKDIR_LOG_FUNC *);
int _mkdirsn(struct __sourceloc, const char *path, size_t len, mode_t mode, MKDIR_LOG_FUNC *);
int _emkdirs(struct __sourceloc, const char *path, mode_t mode, MKDIR_LOG_FUNC *);
int _emkdirsn(struct __sourceloc, const char *path, size_t len, mode_t mode, MKDIR_LOG_FUNC *);

#define mkdirs_log(path, mode, func)        _mkdirs(__WHENCE__, (path), (mode), (func))
#define mkdirsn_log(path, len, mode, func)  _mkdirsn(__WHENCE__, (path), (len), (mode), (func))
#define emkdirs_log(path, mode, func)       _emkdirs(__WHENCE__, (path), (mode), (func))
#define emkdirsn_log(path, len, mode, func) _emkdirsn(__WHENCE__, (path), (len), (mode), (func))

#define mkdirs(path, mode)              mkdirs_log((path), (mode), NULL)
#define mkdirsn(path, len, mode)        mkdirsn_log((path), (len), (mode), NULL)
#define emkdirs(path, mode)             emkdirs_log((path), (mode), NULL)
#define emkdirsn(path, len, mode)       emkdirsn_log((path), (len), (mode), NULL)

#define mkdirs_info(path, mode)         mkdirs_log((path), (mode), log_info_mkdir)
#define mkdirsn_info(path, len, mode)   mkdirsn_log((path), (len), (mode), log_info_mkdir)
#define emkdirs_info(path, mode)        emkdirs_log((path), (mode), log_info_mkdir)
#define emkdirsn_info(path, len, mode)  emkdirsn_log((path), (len), (mode), log_info_mkdir)

/* Read the symbolic link into the supplied buffer and add a terminating nul.
 * Logs an ERROR and returns -1 if the buffer is too short to hold the link
 * content and the terminating nul.  If readlink(2) returns an error, then logs
 * an ERROR and returns -1.  Otherwise, returns the number of bytes read,
 * including the terminating nul, ie, returns what readlink(2) returns plus
 * one.  If the 'len' argument is given as zero, then ignores 'buf' and returns
 * the number of bytes that would be read, by calling lstat(2) instead of
 * readlink(2), plus one for the terminating nul.  Beware of the following race
 * condition: a symbolic link may be altered between calling the lstat(2) and
 * readlink(2), so the following apparently overflow-proof code may still fail
 * from a buffer overflow in the second call to read_symlink():
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

/* Read the whole file into the given buffer.  If the file will not fit into
 * the buffer or if there is an error opening or reading the file, logs an
 * error and returns -1.  Otherwise, returns the number of bytes read.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
ssize_t read_whole_file(const char *path, unsigned char *buffer, size_t buffer_size);

/* Read the whole file into a buffer.  If *bufp is NULL then uses malloc(3) to
 * create a buffer first, the size of the file (up to a maximum of *sizp if
 * *sizp is not zero), and assigns the address to *bufp.  If the file will not
 * fit into the buffer or if there is an error from malloc(3) or opening or
 * reading the file, logs an error and returns -1.  Otherwise, returns 0.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int malloc_read_whole_file(const char *path, unsigned char **bufp, size_t *sizp);

/* File metadata primitives, used for detecting when a file has changed.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
struct file_meta {
  struct timespec mtime;
  off_t size;
};

#define FILE_META_UNKNOWN ((struct file_meta){ .mtime = { .tv_sec = -1, .tv_nsec = -1 }, .size = -1 })

// A non-existent file is treated as size == 0 and an impossible modification
// time, so that cmp_file_meta() will not compare it as equal with any existing
// file.
#define FILE_META_NONEXIST ((struct file_meta){ .mtime = { .tv_sec = -1, .tv_nsec = -1 }, .size = 0 })

__SERVAL_DNA__OS_INLINE int is_file_meta_nonexist(const struct file_meta *m) {
    return m->mtime.tv_sec == -1 && m->mtime.tv_nsec == -1 && m->size == 0;
}

int get_file_meta(const char *path, struct file_meta *metap);
int cmp_file_meta(const struct file_meta *a, const struct file_meta *b);

// Ensure that the metadata of a file differs from a given original metadata,
// by bumping the file's modification time or altering its inode.
int alter_file_meta(const char *path, const struct file_meta *origp, struct file_meta *metap);

/* Fill the given buffer with the nul-terminated absolute path of the calling
 * process's executable.  Logs an error and returns -1 if the executable cannot
 * be determined or the supplied buffer is too short.  Otherwise returns the
 * number of bytes placed in the buffer, including the terminating nul (ie,
 * returns strlen(buf) + 1).
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
ssize_t get_self_executable_path(char *buf, size_t len);

#endif //__SERVAL_DNA__OS_H

