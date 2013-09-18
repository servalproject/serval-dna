/*
Serval DNA named sockets
Copyright 2013 Serval Project Inc.

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
#include "conf.h"
#include "log.h"
#include "strbuf_helpers.h"

/* Under Linux, create a socket name in the abstract namespace.  This permits us to use local
 * sockets on Android despite its lack of a shared writeable directory on a UFS partition.
 *
 * On non-Linux systems, create a conventional named local socket in the $SERVALINSTANCE_PATH
 * directory.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 * @author Daniel O'Connor <daniel@servalproject.com>
 */
int socket_setname(struct sockaddr_un *addr, const char *name, socklen_t *addrlen)
{
  bzero(addr, sizeof(*addr));
  addr->sun_family = AF_UNIX;
#ifdef USE_ABSTRACT_NAMESPACE
  addr->sun_path[0] = '\0'; // mark as Linux abstract socket
  int len = snprintf(addr->sun_path + 1, sizeof addr->sun_path - 1, "%s.%s", DEFAULT_ABSTRACT_PREFIX, name);
  if (len > sizeof addr->sun_path - 1)
    return WHYF("abstract socket name overflow (%d bytes exceeds maximum %u): %s.%s", DEFAULT_ABSTRACT_PREFIX, name, len, sizeof addr->sun_path - 1);
  *addrlen = sizeof(addr->sun_family) + 1 + len; // abstract socket names do not have a trailing nul
#else // !USE_ABSTRACT_NAMESPACE
  if (!FORM_SERVAL_INSTANCE_PATH(addr->sun_path, name))
    return WHYF("local socket name overflow: %s", name);
  *addrlen = sizeof(addr->sun_family) + strlen(addr->sun_path) + 1;
#endif // !USE_ABSTRACT_NAMESPACE
  return 0;
}

int esocket(int domain, int type, int protocol)
{
  int fd;
  if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
    return WHYF_perror("socket(%s, %s, 0)", alloca_socket_domain(domain), alloca_socket_type(type));
  if (config.debug.io || config.debug.verbose_io)
    DEBUGF("socket(%s, %s, 0) -> %d", alloca_socket_domain(domain), alloca_socket_type(type), fd);
  return fd;
}

int socket_connect(int sock, const struct sockaddr *addr, socklen_t addrlen)
{
  if (connect(sock, (struct sockaddr *)addr, addrlen) == -1)
    return WHYF_perror("connect(%d,%s,%lu)", sock, alloca_sockaddr(addr, addrlen), (unsigned long)addrlen);
  if (config.debug.io || config.debug.verbose_io)
    DEBUGF("connect(%d, %s, %lu)", sock, alloca_sockaddr(addr, addrlen), (unsigned long)addrlen);
  return 0;
}

int socket_bind(int sock, const struct sockaddr *addr, socklen_t addrlen)
{
  if (addr->sa_family == AF_UNIX && ((struct sockaddr_un *)addr)->sun_path[0]) {
    if (unlink(((struct sockaddr_un *)addr)->sun_path) == -1 && errno != ENOENT)
      WARNF_perror("unlink(%s)", alloca_str_toprint(((struct sockaddr_un *)addr)->sun_path));
    if (config.debug.io || config.debug.verbose_io)
      DEBUGF("unlink(%s)", alloca_str_toprint(((struct sockaddr_un *)addr)->sun_path));
  }
  if (bind(sock, (struct sockaddr *)addr, addrlen) == -1)
    return WHYF_perror("bind(%d,%s,%lu)", sock, alloca_sockaddr(addr, addrlen), (unsigned long)addrlen);
  if (config.debug.io || config.debug.verbose_io)
    DEBUGF("bind(%d, %s, %lu)", sock, alloca_sockaddr(addr, addrlen), (unsigned long)addrlen);
  return 0;
}

int socket_listen(int sock, int backlog)
{
  if (listen(sock, backlog) == -1)
    return WHYF_perror("listen(%d,%d)", sock, backlog);
  if (config.debug.io || config.debug.verbose_io)
    DEBUGF("listen(%d, %d)", sock, backlog);
  return 0;
}

int socket_set_reuseaddr(int sock, int reuseP)
{
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuseP, sizeof reuseP) == -1) {
    WARNF_perror("setsockopt(%d,SOL_SOCKET,SO_REUSEADDR,&%d,%u)", sock, reuseP, (unsigned)sizeof reuseP);
    return -1;
  }
  if (config.debug.io || config.debug.verbose_io)
    DEBUGF("setsockopt(%d, SOL_SOCKET, SO_REUSEADDR, &%d, %u)", sock, reuseP, (unsigned)sizeof reuseP);
  return 0;
}

int socket_set_rcvbufsize(int sock, unsigned buffer_size)
{
  if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &buffer_size, sizeof buffer_size) == -1) {
    WARNF_perror("setsockopt(%d,SOL_SOCKET,SO_RCVBUF,&%u,%u)", sock, buffer_size, (unsigned)sizeof buffer_size);
    return -1;
  }
  if (config.debug.io || config.debug.verbose_io)
    DEBUGF("setsockopt(%d, SOL_SOCKET, SO_RCVBUF, &%u, %u)", sock, buffer_size, (unsigned)sizeof buffer_size);
  return 0;
}
