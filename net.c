/*
Serval Distributed Numbering Architecture (DNA)
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

#include "serval.h"

int _set_nonblock(int fd, const char *file, unsigned int line, const char *function)
{
  int flags;
  if ((flags = fcntl(fd, F_GETFL, NULL)) == -1) {
    logMessage_perror(LOG_LEVEL_ERROR, file, line, function, "set_nonblock: fcntl(%d,F_GETFL,NULL)", fd);
    return -1;
  }
  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
    logMessage_perror(LOG_LEVEL_ERROR, file, line, function, "set_nonblock: fcntl(%d,F_SETFL,0x%x|O_NONBLOCK)", fd, flags);
    return -1;
  }
  return 0;
}

int _set_block(int fd, const char *file, unsigned int line, const char *function)
{
  int flags;
  if ((flags = fcntl(fd, F_GETFL, NULL)) == -1) {
    logMessage_perror(LOG_LEVEL_ERROR, file, line, function, "set_block: fcntl(%d,F_GETFL,NULL)", fd);
    return -1;
  }
  if (fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) == -1) {
    logMessage_perror(LOG_LEVEL_ERROR, file, line, function, "set_block: fcntl(%d,F_SETFL,0x%x&~O_NONBLOCK)", fd, flags);
    return -1;
  }
  return 0;
}

int _read_nonblock(int fd, void *buf, size_t len, const char *file, unsigned int line, const char *function)
{
  ssize_t nread = read(fd, buf, len);
  if (nread == -1) {
    switch (errno) {
      case EINTR:
      case EAGAIN:
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
      case EWOULDBLOCK:
#endif
	return 0;
    }
    logMessage_perror(LOG_LEVEL_ERROR, file, line, function, "read_nonblock: read(%d,%p,%lu)",
	fd, buf, (unsigned long)len);
    return -1;
  }
  return nread;
}

int _write_all(int fd, const void *buf, size_t len, const char *file, unsigned int line, const char *function)
{
  ssize_t written = write(fd, buf, len);
  if (written == -1) {
    logMessage_perror(LOG_LEVEL_ERROR, file, line, function, "write_all: write(%d,%p %s,%lu)",
	fd, buf, alloca_toprint(30, buf, len), (unsigned long)len);
    return -1;
  }
  if (written != len) {
    logMessage(LOG_LEVEL_ERROR, file, line, function, "write_all: write(%d,%p %s,%lu) returned %ld",
	fd, buf, alloca_toprint(30, buf, len), (unsigned long)len, (long)written);
    return -1;
  }
  return written;
}

int _write_nonblock(int fd, const void *buf, size_t len, const char *file, unsigned int line, const char *function)
{
  ssize_t written = write(fd, buf, len);
  if (written == -1) {
    switch (errno) {
      case EINTR:
      case EAGAIN:
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
      case EWOULDBLOCK:
#endif
	return 0;
    }
    logMessage_perror(LOG_LEVEL_ERROR, file, line, function, "write_nonblock: write(%d,%p %s,%lu)",
	fd, buf, alloca_toprint(30, buf, len), (unsigned long)len);
    return -1;
  }
  return written;
}

int _write_all_nonblock(int fd, const void *buf, size_t len, const char *file, unsigned int line, const char *function)
{
  ssize_t written = _write_nonblock(fd, buf, len, file, line, function);
  if (written != -1 && written != len) {
    logMessage(LOG_LEVEL_ERROR, file, line, function, "write_all_nonblock: write(%d,%p %s,%lu) returned %ld",
	fd, buf, alloca_toprint(30, buf, len), (unsigned long)len, (long)written);
    return -1;
  }
  return written;
}

int _write_str(int fd, const char *str, const char *file, unsigned int line, const char *function)
{
  return _write_all(fd, str, strlen(str), file, line, function);
}

int _write_str_nonblock(int fd, const char *str, const char *file, unsigned int line, const char *function)
{
  return _write_all_nonblock(fd, str, strlen(str), file, line, function);
}
