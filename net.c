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

int set_nonblock(int fd)
{
  int flags;
  if ((flags = fcntl(fd, F_GETFL, NULL)) == -1)
    return WHY_perror("fcntl(F_GETFL)");
  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
    return WHY_perror("fcntl(F_SETFL)");
  return 0;
}

int set_block(int fd)
{
  int flags;
  if ((flags = fcntl(fd, F_GETFL, NULL)) == -1)
    return WHY_perror("fcntl(F_GETFL)");
  if (fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) == -1)
    return WHY_perror("fcntl(F_SETFL)");
  return 0;
}

int write_all(int fd, const char *buf, size_t len)
{
  ssize_t written = write(fd, buf, len);
  if (written == -1)
    return WHY_perror("write");
  if (written != len)
    return WHYF("write(%u bytes) returned %d", len, written);
  return written;
}

int write_nonblock(int fd, const char *buf, size_t len)
{
  ssize_t written = write(fd, buf, len);
  if (written == -1) {
    switch (errno) {
      case EAGAIN:
      case EINTR:
	return 0;
    }
    return WHY_perror("write");
  }
  return written;
}

int write_all_nonblock(int fd, const char *buf, size_t len)
{
  ssize_t written = write_nonblock(fd, buf, len);
  if (written != -1 && written != len)
    return WHYF("write(%u bytes) returned %d", len, written);
  return written;
}

int write_str(int fd, const char *str)
{
  return write_all(fd, str, strlen(str));
}

int write_str_nonblock(int fd, const char *str)
{
  return write_all_nonblock(fd, str, strlen(str));
}
