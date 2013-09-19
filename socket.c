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
int _socket_setname(struct __sourceloc __whence, struct sockaddr_un *addr, socklen_t *addrlen, const char *fmt, ...)
{
  bzero(addr, sizeof(*addr));
  addr->sun_family = AF_UNIX;
  va_list ap;
  va_start(ap, fmt);
  int r = vformf_serval_instance_path(__WHENCE__, addr->sun_path, sizeof addr->sun_path, fmt, ap);
  va_end(ap);
  if (r == -1)
    return WHY("local socket name overflow");
  *addrlen = sizeof(addr->sun_family) + strlen(addr->sun_path) + 1;
#ifdef USE_ABSTRACT_NAMESPACE
  // For the abstract name we use the absolute path name with the initial '/' replaced by the
  // leading nul.  This ensures that different instances of the Serval daemon have different socket
  // names.
  addr->sun_path[0] = '\0'; // mark as Linux abstract socket
  --*addrlen; // do not count trailing nul in abstract socket name
#endif // USE_ABSTRACT_NAMESPACE
  return 0;
}

/* Compare any two struct sockaddr.  Return -1, 0 or 1.  Cope with invalid and truncated sockaddr
 * structures.  Uses inode number comparison to resolve symbolic links in AF_UNIX path names so is
 * not suitable for sorting, because comparison results are inconsistent (eg, if A is a symlink to
 * C, then A == C but A < B and B < C).
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
      if (   pathlenA > 1 && pathlenB > 1
	  && ((const struct sockaddr_un *)addrA)->sun_path[0] == '\0'
	  && ((const struct sockaddr_un *)addrB)->sun_path[0] == '\0'
      ) {
	// Both abstract sockets - just compare names, nul bytes are not terminators.
	int c = memcmp(&((const struct sockaddr_un *)addrA)->sun_path[1],
		       &((const struct sockaddr_un *)addrB)->sun_path[1],
		       (pathlenA < pathlenB ? pathlenA : pathlenB) - 1);
	if (c == 0)
	  c = pathlenA < pathlenB ? -1 : pathlenA > pathlenB ? 1 : 0;
	return c;
      }
      // Either or both are named local file sockets.  If the file names are identical up to the
      // first nul, then the addresses are equal.  Otherwise, if both are nul terminated file names
      // (not abstract) then compare for equality by using the inode numbers to factor out symbolic
      // links.  Otherwise, simply compare the nul-terminated names (abstract names start with a nul
      // so will always collate ahead of non-empty file names).
      int c = strncmp(((const struct sockaddr_un *)addrA)->sun_path,
		      ((const struct sockaddr_un *)addrB)->sun_path,
		      (pathlenA < pathlenB ? pathlenA : pathlenB));
      if (c == 0 && pathlenA == pathlenB)
	return 0;
      if (   pathlenA && pathlenB
	  && ((const struct sockaddr_un *)addrA)->sun_path[0]
	  && ((const struct sockaddr_un *)addrB)->sun_path[0]
	  && ((const struct sockaddr_un *)addrA)->sun_path[pathlenA - 1] == '\0'
	  && ((const struct sockaddr_un *)addrB)->sun_path[pathlenB - 1] == '\0'
      ) {
	struct stat statA, statB;
	if (   stat(((const struct sockaddr_un *)addrA)->sun_path, &statA) == 0
	    && stat(((const struct sockaddr_un *)addrB)->sun_path, &statB) == 0
	    && statA.st_dev == statB.st_dev
	    && statA.st_ino == statB.st_ino
	)
	    return 0;
      }
      if (c == 0)
	c = pathlenA < pathlenB ? -1 : pathlenA > pathlenB ? 1 : 0;
      return c;
    }
    break;
  }
  // Fall back to comparing the data bytes.
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
