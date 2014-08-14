/* 
Serval Distributed Numbering Architecture (DNA)
Copyright (C) 2010 Paul Gardner-Stephen 

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

#define __SERVAL_DNA__OS_INLINE
#include "constants.h"
#include "os.h"
#include "mem.h"
#include "str.h"
#include "log.h"
#include "strbuf_helpers.h"

#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <alloca.h>
#include <dirent.h>
#include <time.h>
#include <string.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

void log_info_mkdir(struct __sourceloc __whence, const char *path, mode_t mode)
{
  INFOF("mkdir %s (mode %04o)", alloca_str_toprint(path), mode);
}

int _mkdirs(struct __sourceloc __whence, const char *path, mode_t mode, MKDIR_LOG_FUNC *logger)
{
  return _mkdirsn(__whence, path, strlen(path), mode, logger);
}

int _emkdirs(struct __sourceloc __whence, const char *path, mode_t mode, MKDIR_LOG_FUNC *logger)
{
  if (_mkdirs(__whence, path, mode, logger) == -1)
    return WHYF_perror("mkdirs(%s,%o)", alloca_str_toprint(path), mode);
  return 0;
}

int _emkdirsn(struct __sourceloc __whence, const char *path, size_t len, mode_t mode, MKDIR_LOG_FUNC *logger)
{
  if (_mkdirsn(__whence, path, len, mode, logger) == -1)
    return WHYF_perror("mkdirsn(%s,%lu,%o)", alloca_toprint(-1, path, len), (unsigned long)len, mode);
  return 0;
}

/* This variant must not log anything itself, because it is called by the logging subsystem, and
 * that would cause infinite recursion!
 *
 * The path need not be NUL terminated.
 *
 * The logger function pointer is usually NULL, for no logging, but may be any function the caller
 * supplies (for example, log_info_mkdir).
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int _mkdirsn(struct __sourceloc whence, const char *path, size_t len, mode_t mode, MKDIR_LOG_FUNC *logger)
{
  if (len == 0)
    errno = EINVAL;
  else {
    char *pathfrag = alloca(len + 1);
    strncpy(pathfrag, path, len)[len] = '\0';
    if (mkdir(pathfrag, mode) != -1) {
      if (logger)
	logger(whence, pathfrag, mode);
      return 0;
    }
    if (errno == EEXIST) {
      DIR *d = opendir(pathfrag);
      if (d) {
	closedir(d);
	return 0;
      }
    }
    else if (errno == ENOENT) {
      const char *lastsep = path + len - 1;
      while (lastsep != path && *--lastsep != '/')
	;
      while (lastsep != path && *--lastsep == '/')
	;
      if (lastsep != path) {
	if (_mkdirsn(whence, path, lastsep - path + 1, mode, logger) == -1)
	  return -1;
	if (mkdir(pathfrag, mode) != -1) {
	  if (logger)
	    logger(whence, pathfrag, mode);
	  return 0;
	}
      }
    }
  }
  return -1;
}

int urandombytes(unsigned char *buf, size_t len)
{
  static int urandomfd = -1;
  int tries = 0;
  if (urandomfd == -1) {
    for (tries = 0; tries < 4; ++tries) {
      urandomfd = open("/dev/urandom",O_RDONLY);
      if (urandomfd != -1) break;
      sleep_ms(1000);
    }
    if (urandomfd == -1) {
      WHY_perror("open(/dev/urandom)");
      return -1;
    }
  }
  tries = 0;
  while (len > 0) {
    ssize_t i = read(urandomfd, buf, (len < 1048576) ? len : 1048576);
    if (i == -1) {
      if (++tries > 4) {
	WHY_perror("read(/dev/urandom)");
	if (errno==EBADF) urandomfd=-1;
	return -1;
      }
    } else {
      tries = 0;
      buf += i;
      len -= i;
    }
  }
  return 0;
}

time_ms_t gettime_ms()
{
  struct timeval nowtv;
  // If gettimeofday() fails or returns an invalid value, all else is lost!
  if (gettimeofday(&nowtv, NULL) == -1)
    FATAL_perror("gettimeofday");
  if (nowtv.tv_sec < 0 || nowtv.tv_usec < 0 || nowtv.tv_usec >= 1000000)
    FATALF("gettimeofday returned tv_sec=%ld tv_usec=%ld", (long)nowtv.tv_sec, (long)nowtv.tv_usec);
  return nowtv.tv_sec * 1000LL + nowtv.tv_usec / 1000;
}

time_s_t gettime()
{
  struct timeval nowtv;
  // If gettimeofday() fails or returns an invalid value, all else is lost!
  if (gettimeofday(&nowtv, NULL) == -1)
    FATAL_perror("gettimeofday");
  if (nowtv.tv_sec < 0 || nowtv.tv_usec < 0 || nowtv.tv_usec >= 1000000)
    FATALF("gettimeofday returned tv_sec=%ld tv_usec=%ld", (long)nowtv.tv_sec, (long)nowtv.tv_usec);
  return nowtv.tv_sec;
}

// Returns sleep time remaining.
time_ms_t sleep_ms(time_ms_t milliseconds)
{
  if (milliseconds <= 0)
    return 0;
  struct timespec delay;
  struct timespec remain;
  delay.tv_sec = milliseconds / 1000;
  delay.tv_nsec = (milliseconds % 1000) * 1000000;
  if (nanosleep(&delay, &remain) == -1 && errno != EINTR)
    FATALF_perror("nanosleep(tv_sec=%ld, tv_nsec=%ld)", delay.tv_sec, delay.tv_nsec);
  return remain.tv_sec * 1000 + remain.tv_nsec / 1000000;
}

struct timeval time_ms_to_timeval(time_ms_t milliseconds)
{
  struct timeval tv;
  tv.tv_sec = milliseconds / 1000;
  tv.tv_usec = (milliseconds % 1000) * 1000;
  return tv;
}

ssize_t read_symlink(const char *path, char *buf, size_t len)
{
  if (len == 0) {
    struct stat stat;
    if (lstat(path, &stat) == -1)
      return WHYF_perror("lstat(%s)", alloca_str_toprint(path));
    return stat.st_size + 1; // allow for terminating nul
  }
  ssize_t nr = readlink(path, buf, len);
  if (nr == -1)
    return WHYF_perror("readlink(%s,%p,%zu)", alloca_str_toprint(path), buf, len);
  if ((size_t)nr >= len)
    return WHYF("buffer overrun from readlink(%s, len=%zu)", alloca_str_toprint(path), len);
  buf[nr] = '\0';
  return nr;
}

ssize_t read_whole_file(const char *path, unsigned char *buffer, size_t buffer_size)
{
  assert(buffer != NULL);
  assert(buffer_size != 0);
  if (malloc_read_whole_file(path, &buffer, &buffer_size) == -1)
    return -1;
  return buffer_size;
}

int malloc_read_whole_file(const char *path, unsigned char **bufp, size_t *sizp)
{
  int fd = open(path, O_RDONLY);
  if (fd == -1)
    return WHYF_perror("open(%d,%s,O_RDONLY)", fd, alloca_str_toprint(path));
  ssize_t ret;
  struct stat stat;
  if (fstat(fd, &stat) == -1)
    ret = WHYF_perror("fstat(%d)", fd);
  else if (*bufp != NULL && (size_t)stat.st_size > *sizp)
    ret = WHYF("file %s (size %zu) is larger than available buffer (%zu)", alloca_str_toprint(path), (size_t)stat.st_size, *sizp);
  else if (*bufp == NULL && *sizp && (size_t)stat.st_size > *sizp)
    ret = WHYF("file %s (size %zu) is larger than maximum buffer (%zu)", alloca_str_toprint(path), (size_t)stat.st_size, *sizp);
  else {
    *sizp = (size_t)stat.st_size;
    if (*bufp == NULL && (*bufp = emalloc(*sizp)) == NULL)
      ret = WHYF("file %s (size %zu) does not fit into memory", alloca_str_toprint(path), *sizp);
    else {
      assert(*bufp != NULL);
      ret = read(fd, *bufp, *sizp);
      if (ret == -1)
	ret = WHYF_perror("read(%d,%s,%zu)", fd, alloca_str_toprint(path), *sizp);
    }
  }
  if (close(fd) == -1)
    ret = WHYF_perror("close(%d)", fd);
  return ret;
}

int get_file_meta(const char *path, struct file_meta *metap)
{
  struct stat st;
  if (stat(path, &st) == -1) {
    if (errno != ENOENT)
      return WHYF_perror("stat(%s)", path);
    *metap = FILE_META_NONEXIST;
  } else {
    metap->size = st.st_size;
    metap->mtime.tv_sec = st.st_mtime;
    // Truncate to whole seconds to ensure that this code will work on file systems that only have
    // whole-second time stamp resolution.
    metap->mtime.tv_nsec = 0;
  }
  return 0;
}

static int cmp_timespec(const struct timespec *a, const struct timespec *b)
{
  return a->tv_sec < b->tv_sec ? -1 : a->tv_sec > b->tv_sec ? 1 : a->tv_nsec < b->tv_nsec ? -1 : a->tv_nsec > b->tv_nsec ? 1 : 0;
}

static void add_timespec(struct timespec *tv, long sec, long nsec)
{
  const long NANO = 1000000000;
  tv->tv_sec += sec;
  // Bring nsec into range -NANO < nsec < NANO.
  if (nsec >= NANO) {
    sec = nsec / NANO;
    tv->tv_sec += sec;
    nsec -= sec * NANO;
  } else if (nsec <= -NANO) {
    // The C standard does not define whether negative integer division truncates towards negative
    // infinity or rounds towards zero.  So we have to use positive integer division, which always
    // truncates towards zero.
    sec = -nsec / NANO;
    tv->tv_sec -= sec;
    nsec += sec * NANO;
  }
  assert(nsec > -NANO);
  assert(nsec < NANO);
  tv->tv_nsec += nsec;
  // Bring tv_nsec into range 0 <= tv_nsec < NANO.
  if (tv->tv_nsec >= NANO) {
    sec = tv->tv_nsec / NANO;
    tv->tv_sec += sec;
    tv->tv_nsec -= sec * NANO;
  } else if (tv->tv_nsec < 0) {
    sec = (-tv->tv_nsec + NANO - 1) / NANO;
    tv->tv_sec -= sec;
    tv->tv_nsec += sec * NANO;
  }
  assert(tv->tv_nsec >= 0);
  assert(tv->tv_nsec < NANO);
}

int cmp_file_meta(const struct file_meta *a, const struct file_meta *b)
{
  int c = cmp_timespec(&a->mtime, &b->mtime);
  return c ? c : a->size < b->size ? -1 : a->size > b->size ? 1 : 0;
}

/* Post-update file meta adjustment.
 *
 * If a file's meta information is used to detect changes to the file by polling at regular
 * intervals, then every update to the file must guarantee to never produce the same meta
 * information as any prior update.  The typical case is several updates in rapid succession during
 * one second that do not change the size of the file.  The second and subsequent of these will not
 * change the file's meta information (size or last-modified time stamp) on file systems that only
 * have one-second timestamp resolution.
 *
 * This function can be called immediately after updating such a file, supplying the meta
 * information from just prior to the update.  It will alter the file's meta information (last
 * modified time stamp) to ensure that it differs from the prior meta information.  This typically
 * involves advancing the file's last-modification time stamp.
 *
 * Returns -1 if an error occurs, 1 if it alters the file's meta information, 0 if the current meta
 * information is already different and did not need alteration.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int alter_file_meta(const char *path, const struct file_meta *origp, struct file_meta *metap)
{
  long nsec = 1;
  long sec = 0;
  // If the file's current last-modified timestamp is not greater than its original, try bumping the
  // original timestamp by one nanosecond, and if that does not alter the timestamp, the file system
  // does not support nanosecond timestamps, so try bumping it by one second.
  while (sec <= 1) {
    struct file_meta meta;
    if (get_file_meta(path, &meta) == -1)
      return -1;
    if (metap)
      *metap = meta;
    if (is_file_meta_nonexist(&meta) || cmp_timespec(&origp->mtime, &meta.mtime) < 0)
      return 0;
    meta.mtime = origp->mtime;
    add_timespec(&meta.mtime, sec, nsec);
    struct timeval times[2];
    times[0] = time_ms_to_timeval(gettime_ms());
    times[1].tv_sec = meta.mtime.tv_sec;
    times[1].tv_usec = meta.mtime.tv_nsec / 1000;
    if (utimes(path, times) == -1)
      return WHYF_perror("utimes(%s,[%s,%s])", alloca_str_toprint(path), alloca_timeval(&times[0]), alloca_timeval(&times[1]));
    nsec = 0;
    ++sec;
  }
  return 1;
}

ssize_t get_self_executable_path(char *buf, size_t len)
{
#if defined(linux)
  return read_symlink("/proc/self/exe", buf, len);
#elif defined (__sun__)
  return read_symlink("/proc/self/path/a.out", buf, len);
#elif defined (__APPLE__)
  uint32_t bufsize = len;
  return _NSGetExecutablePath(buf, &bufsize) || len == 0 ? bufsize : -1;
#else
#error Unable to find executable path
#endif
}
