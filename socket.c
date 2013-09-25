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

#include <limits.h>
#include <stdlib.h>
#include <assert.h>

#include "serval.h"
#include "conf.h"
#include "log.h"
#include "strbuf_helpers.h"

/* Form the name of an AF_UNIX (local) socket in the instance directory as an absolute path.
 * Under Linux, this will create a socket name in the abstract namespace.  This permits us to use
 * local sockets on Android despite its lack of a shared writeable directory on a UFS partition.
 *
 * The absolute file name is resolved to its real path using realpath(3), to ensure that name
 * comparisons of addresses returned by recvmsg(2) can reliably be used on systems where the
 * instance path may have a symbolic link in it.
 *
 * Returns -1 if the path name overruns the size of a sockaddr_un structure, or if realpath(3) fails
 * with an error.  The contents of *addr and *addrlen are undefined in this case.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 * @author Daniel O'Connor <daniel@servalproject.com>
 */
int _make_local_sockaddr(struct __sourceloc __whence, struct sockaddr_un *addr, socklen_t *addrlen, const char *fmt, ...)
{
  bzero(addr, sizeof(*addr));
  va_list ap;
  va_start(ap, fmt);
  int r = vformf_serval_instance_path(__WHENCE__, addr->sun_path, sizeof addr->sun_path, fmt, ap);
  va_end(ap);
  if (!r)
    return WHY("socket name overflow");
  if (real_sockaddr(addr, sizeof addr->sun_family + strlen(addr->sun_path) + 1, addr, addrlen) == -1)
    return -1;
#ifdef USE_ABSTRACT_NAMESPACE
  // For the abstract name we use the absolute path name with the initial '/' replaced by the
  // leading nul.  This ensures that different instances of the Serval daemon have different socket
  // names.
  addr->sun_path[0] = '\0'; // mark as Linux abstract socket
  --*addrlen; // do not count trailing nul in abstract socket name
#endif // USE_ABSTRACT_NAMESPACE
  addr->sun_family = AF_UNIX;
  return 0;
}

/* Converts an AF_UNIX local socket file name to contain a real path name using realpath(3), leaves
 * all other socket types intact, including abstract local socket names.  Returns -1 in case of an
 * error from realpath(3) or a buffer overflow, without modifying *dst_addr or *dst_addrlen.
 * Returns 1 if the path is changed and puts the modified path in *dst_addr and *dst_addrlen.
 * Returns 0 if not the path is not changed and copies from *src_addr to *dst_addr, src_addrlen to
 * *dst_addrlen.
 *
 * Can safely be used to perform an in-place conversion by using src_addr == dst_addr and
 * dst_addrlen == &src_addrlen.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int real_sockaddr(const struct sockaddr_un *src_addr, socklen_t src_addrlen, struct sockaddr_un *dst_addr, socklen_t *dst_addrlen)
{
  int src_path_len = src_addrlen - sizeof src_addr->sun_family;
  if (	 src_addrlen >= sizeof src_addr->sun_family + 1
      && src_addr->sun_family == AF_UNIX
      && src_addr->sun_path[0] != '\0'
      && src_addr->sun_path[src_path_len - 1] == '\0'
  ) {
    char real_path[PATH_MAX];
    size_t real_path_len;
    if (realpath(src_addr->sun_path, real_path) == NULL)
      return WHYF_perror("realpath(%s)", alloca_str_toprint(src_addr->sun_path));
    else if ((real_path_len = strlen(real_path) + 1) > sizeof dst_addr->sun_path)
      return WHYF("sockaddr overrun: realpath(%s) returned %s", alloca_str_toprint(src_addr->sun_path), alloca_str_toprint(real_path));
    else if (   real_path_len != src_path_len
	     || memcmp(real_path, src_addr->sun_path, src_path_len) != 0
    ) {
      memcpy(dst_addr->sun_path, real_path, real_path_len);
      *dst_addrlen = real_path_len + sizeof dst_addr->sun_family;
      return 1;
    }
  }
  if (dst_addr != src_addr)
    memcpy(dst_addr, src_addr, src_addrlen);
  *dst_addrlen = src_addrlen;
  return 0;
}

/* Compare any two struct sockaddr.  Return -1, 0 or 1.  Copes with invalid and truncated sockaddr
 * structures.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int cmp_sockaddr(const struct sockaddr *addrA, socklen_t addrlenA, const struct sockaddr *addrB, socklen_t addrlenB)
{
  // Two zero-length sockaddrs are equal.
  if (addrlenA == 0 && addrlenB == 0)
    return 0;
  // If either sockaddr is truncated, then we compare the bytes we have.
  if (addrlenA < sizeof addrA->sa_family || addrlenB < sizeof addrB->sa_family) {
    int c = memcmp(addrA, addrB, addrlenA < addrlenB ? addrlenA : addrlenB);
    if (c == 0)
      c = addrlenA < addrlenB ? -1 : addrlenA > addrlenB ? 1 : 0;
    return c;
  }
  // Order first by address family.
  if (addrA->sa_family < addrB->sa_family)
    return -1;
  if (addrA->sa_family > addrB->sa_family)
    return 1;
  // Both addresses are in the same family...
  switch (addrA->sa_family) {
  case AF_UNIX: {
      unsigned pathlenA = addrlenA - sizeof ((const struct sockaddr_un *)addrA)->sun_family;
      unsigned pathlenB = addrlenB - sizeof ((const struct sockaddr_un *)addrB)->sun_family;
      int c;
      if (   pathlenA > 1 && pathlenB > 1
	  && ((const struct sockaddr_un *)addrA)->sun_path[0] == '\0'
	  && ((const struct sockaddr_un *)addrB)->sun_path[0] == '\0'
      ) {
	// Both abstract sockets - just compare names, nul bytes are not terminators.
	c = memcmp(&((const struct sockaddr_un *)addrA)->sun_path[1],
		   &((const struct sockaddr_un *)addrB)->sun_path[1],
		   (pathlenA < pathlenB ? pathlenA : pathlenB) - 1);
      } else {
	// Either or both are named local file sockets.  If the file names are identical up to the
	// first nul, then the addresses are equal.  This collates abstract socket names, whose first
	// character is a nul, ahead of all non-empty file socket names.
	c = strncmp(((const struct sockaddr_un *)addrA)->sun_path,
		    ((const struct sockaddr_un *)addrB)->sun_path,
		    (pathlenA < pathlenB ? pathlenA : pathlenB));
      }
      if (c == 0)
	c = pathlenA < pathlenB ? -1 : pathlenA > pathlenB ? 1 : 0;
      return c;
    }
    break;
  }
  // Fall back to comparing raw data bytes.
  int c = memcmp(addrA->sa_data, addrB->sa_data, (addrlenA < addrlenB ? addrlenA : addrlenB) - sizeof addrA->sa_family);
  if (c == 0)
    c = addrlenA < addrlenB ? -1 : addrlenA > addrlenB ? 1 : 0;
  return c;
}

int _esocket(struct __sourceloc __whence, int domain, int type, int protocol)
{
  int fd;
  if ((fd = socket(domain, type, protocol)) == -1)
    return WHYF_perror("socket(%s, %s, 0)", alloca_socket_domain(domain), alloca_socket_type(type));
  if (config.debug.io || config.debug.verbose_io)
    DEBUGF("socket(%s, %s, 0) -> %d", alloca_socket_domain(domain), alloca_socket_type(type), fd);
  return fd;
}

int _socket_connect(struct __sourceloc __whence, int sock, const struct sockaddr *addr, socklen_t addrlen)
{
  if (connect(sock, (struct sockaddr *)addr, addrlen) == -1)
    return WHYF_perror("connect(%d,%s,%lu)", sock, alloca_sockaddr(addr, addrlen), (unsigned long)addrlen);
  if (config.debug.io || config.debug.verbose_io)
    DEBUGF("connect(%d, %s, %lu)", sock, alloca_sockaddr(addr, addrlen), (unsigned long)addrlen);
  return 0;
}

int _socket_bind(struct __sourceloc __whence, int sock, const struct sockaddr *addr, socklen_t addrlen)
{
  assert(addrlen > sizeof addr->sa_family);
  if (addr->sa_family == AF_UNIX && ((struct sockaddr_un *)addr)->sun_path[0] != '\0') {
    assert(((struct sockaddr_un *)addr)->sun_path[addrlen - sizeof ((struct sockaddr_un *)addr)->sun_family - 1] == '\0');
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

int _socket_listen(struct __sourceloc __whence, int sock, int backlog)
{
  if (listen(sock, backlog) == -1)
    return WHYF_perror("listen(%d,%d)", sock, backlog);
  if (config.debug.io || config.debug.verbose_io)
    DEBUGF("listen(%d, %d)", sock, backlog);
  return 0;
}

int _socket_set_reuseaddr(struct __sourceloc __whence, int sock, int reuseP)
{
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuseP, sizeof reuseP) == -1) {
    WARNF_perror("setsockopt(%d,SOL_SOCKET,SO_REUSEADDR,&%d,%u)", sock, reuseP, (unsigned)sizeof reuseP);
    return -1;
  }
  if (config.debug.io || config.debug.verbose_io)
    DEBUGF("setsockopt(%d, SOL_SOCKET, SO_REUSEADDR, &%d, %u)", sock, reuseP, (unsigned)sizeof reuseP);
  return 0;
}

int _socket_set_rcvbufsize(struct __sourceloc __whence, int sock, unsigned buffer_size)
{
  if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &buffer_size, sizeof buffer_size) == -1) {
    WARNF_perror("setsockopt(%d,SOL_SOCKET,SO_RCVBUF,&%u,%u)", sock, buffer_size, (unsigned)sizeof buffer_size);
    return -1;
  }
  if (config.debug.io || config.debug.verbose_io)
    DEBUGF("setsockopt(%d, SOL_SOCKET, SO_RCVBUF, &%u, %u)", sock, buffer_size, (unsigned)sizeof buffer_size);
  return 0;
}
