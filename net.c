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

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <time.h>

#include "serval.h"
#include "conf.h"
#include "net.h"
#include "socket.h"
#include "str.h"
#include "strbuf_helpers.h"

struct in_addr hton_in_addr(in_addr_t addr)
{
  struct in_addr a;
  a.s_addr = htonl(addr);
  return a;
}

int _set_nonblock(int fd, struct __sourceloc __whence)
{
  int flags;
  if ((flags = fcntl(fd, F_GETFL, NULL)) == -1)
    return WHYF_perror("set_nonblock: fcntl(%d,F_GETFL,NULL)", fd);
  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
    return WHYF_perror("set_nonblock: fcntl(%d,F_SETFL,0x%x|O_NONBLOCK)", fd, flags);
  return 0;
}

int _set_block(int fd, struct __sourceloc __whence)
{
  int flags;
  if ((flags = fcntl(fd, F_GETFL, NULL)) == -1)
    return WHYF_perror("set_block: fcntl(%d,F_GETFL,NULL)", fd);
  if (fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) == -1)
    return WHYF_perror("set_block: fcntl(%d,F_SETFL,0x%x&~O_NONBLOCK)", fd, flags);
  return 0;
}

ssize_t _read_nonblock(int fd, void *buf, size_t len, struct __sourceloc __whence)
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
    return WHYF_perror("read_nonblock: read(%d,%p,%lu)", fd, buf, (unsigned long)len);
  }
  return nread;
}

ssize_t _write_all(int fd, const void *buf, size_t len, struct __sourceloc __whence)
{
  ssize_t written = write(fd, buf, len);
  if (written == -1)
    return WHYF_perror("write_all: write(%d,%p %s,%zu)",
	fd, buf, alloca_toprint(30, buf, len), len);
  if ((size_t)written != len)
    return WHYF_perror("write_all: write(%d,%p %s,%zu) returned %zd",
	fd, buf, alloca_toprint(30, buf, len), len, (size_t)written);
  return written;
}

ssize_t _writev_all(int fd, const struct iovec *iov, int iovcnt, struct __sourceloc __whence)
{
  size_t len = 0;
  int i;
  for (i = 0; i < iovcnt; ++i)
    len += iov[i].iov_len;
  ssize_t written = writev(fd, iov, iovcnt);
  if (written == -1)
    return WHYF_perror("writev_all: writev(%d,%s len=%zu)", fd, alloca_iovec(iov, iovcnt), len);
  if ((size_t)written != len)
    return WHYF_perror("writev_all: writev(%d,%s len=%zu) returned %zd", fd, alloca_iovec(iov, iovcnt), len, (size_t)written);
  return written;
}

ssize_t _write_nonblock(int fd, const void *buf, size_t len, struct __sourceloc __whence)
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
    return WHYF_perror("write_nonblock: write(%d,%p %s,%lu)",
	fd, buf, alloca_toprint(30, buf, len), (unsigned long)len);
    return -1;
  }
  return written;
}

ssize_t _write_all_nonblock(int fd, const void *buf, size_t len, struct __sourceloc __whence)
{
  ssize_t written = _write_nonblock(fd, buf, len, __whence);
  if (written != -1 && (size_t)written != len)
    return WHYF("write_all_nonblock: write(%d,%p %s,%zu) returned %zd",
	fd, buf, alloca_toprint(30, buf, len), len, (size_t)written);
  return written;
}

ssize_t _write_str(int fd, const char *str, struct __sourceloc __whence)
{
  return _write_all(fd, str, strlen(str), __whence);
}

ssize_t _write_str_nonblock(int fd, const char *str, struct __sourceloc __whence)
{
  return _write_all_nonblock(fd, str, strlen(str), __whence);
}
