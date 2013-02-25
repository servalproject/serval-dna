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

#define __SERVALDNA_OS_INLINE
#include "os.h"
#include "log.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <alloca.h>
#include <dirent.h>
#include <time.h>
#include <string.h>

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

int mkdirs(const char *path, mode_t mode)
{
  return mkdirsn(path, strlen(path), mode);
}

int mkdirsn(const char *path, size_t len, mode_t mode)
{
  if (len == 0)
    return WHY("Bug: empty path");
  char *pathfrag = alloca(len + 1);
  strncpy(pathfrag, path, len);
  pathfrag[len] = '\0';
  if (mkdir(pathfrag, mode) != -1)
    return 0;
  if (errno == EEXIST) {
    DIR *d = opendir(pathfrag);
    if (!d) {
      WHY_perror("opendir");
      return WHYF("cannot access %s", pathfrag);
    }
    closedir(d);
    return 0;
  }
  if (errno == ENOENT) {
    const char *lastsep = path + len - 1;
    while (lastsep != path && *--lastsep != '/')
      ;
    while (lastsep != path && *--lastsep == '/')
      ;
    if (lastsep != path) {
      if (mkdirsn(path, lastsep - path + 1, mode) == -1)
	return -1;
      if (mkdir(pathfrag, mode) != -1)
	return 0;
    }
  }
  WHY_perror("mkdir");
  return WHYF("cannot mkdir %s", pathfrag);
}

int urandombytes(unsigned char *buf, unsigned long long len)
{
  static int urandomfd = -1;
  int tries = 0;
  if (urandomfd == -1) {
    for (tries = 0; tries < 4; ++tries) {
      urandomfd = open("/dev/urandom",O_RDONLY);
      if (urandomfd != -1) break;
      sleep(1);
    }
    if (urandomfd == -1) {
      WHY_perror("open(/dev/urandom)");
      return -1;
    }
  }
  tries = 0;
  while (len > 0) {
    int i = (len < 1048576) ? len : 1048576;
    i = read(urandomfd, buf, i);
    if (i == -1) {
      if (++tries > 4) {
	WHY_perror("read(/dev/urandom)");
	return -1;
      }
      sleep(1);
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
    FATALF("gettimeofday returned tv_sec=%ld tv_usec=%ld", nowtv.tv_sec, nowtv.tv_usec);
  return nowtv.tv_sec * 1000LL + nowtv.tv_usec / 1000;
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

ssize_t read_symlink(const char *path, char *buf, size_t len)
{
  if (len == 0) {
    struct stat stat;
    if (lstat(path, &stat) == -1)
      return WHYF_perror("lstat(%s)", path);
    return stat.st_size;
  }
  ssize_t nr = readlink(path, buf, len);
  if (nr == -1)
    return WHYF_perror("readlink(%s)", path);
  if (nr >= len)
    return WHYF("buffer overrun from readlink(%s, len=%lu)", path, (unsigned long) len);
  buf[nr] = '\0';
  return nr;
}
