/* 
Serval DNA header file for socket operations
Copyright (C) 2012-2013 Serval Project Inc.

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

#ifndef __SERVAL_DNA___SOCKET_H
#define __SERVAL_DNA___SOCKET_H

#ifdef WIN32
#   include "win32/win32.h"
#else
#   include <sys/un.h>
#   ifdef HAVE_SYS_SOCKET_H
#     include <sys/socket.h>
#   endif
#   ifdef HAVE_NETINET_IN_H
#     include <netinet/in.h>
#   endif
#endif

#include "features.h"
#include "whence.h"

struct socket_address{
  socklen_t addrlen;
  union{
    struct sockaddr addr;
    struct sockaddr_un local; // name "unix" is a predefined macro
    struct sockaddr_in inet;
    struct sockaddr_storage store;
    uint8_t raw[255];
  };
};

/* Basic socket operations.
 */
int _make_local_sockaddr(struct __sourceloc, struct socket_address *addr, const char *fmt, ...)
    __attribute__((__ATTRIBUTE_format(printf, 3, 4)));
int _esocket(struct __sourceloc, int domain, int type, int protocol);
int _socket_bind(struct __sourceloc, int sock, const struct socket_address *addr);
int _socket_connect(struct __sourceloc, int sock, const struct socket_address *addr);
int _socket_listen(struct __sourceloc, int sock, int backlog);
int _socket_set_reuseaddr(struct __sourceloc, int sock, int reuseP);
int _socket_set_rcvbufsize(struct __sourceloc, int sock, unsigned buffer_size);
int socket_unlink_close(int sock);

#define make_local_sockaddr(sockname, fmt,...) _make_local_sockaddr(__WHENCE__, (sockname), (fmt), ##__VA_ARGS__)
#define esocket(domain, type, protocol)             _esocket(__WHENCE__, (domain), (type), (protocol))
#define socket_bind(sock, addr)                     _socket_bind(__WHENCE__, (sock), (addr))
#define socket_connect(sock, addr)                  _socket_connect(__WHENCE__, (sock), (addr))
#define socket_listen(sock, backlog)                _socket_listen(__WHENCE__, (sock), (backlog))
#define socket_set_reuseaddr(sock, reuseP)          _socket_set_reuseaddr(__WHENCE__, (sock), (reuseP))
#define socket_set_rcvbufsize(sock, buffer_size)    _socket_set_rcvbufsize(__WHENCE__, (sock), (buffer_size))

int real_sockaddr(const struct socket_address *src_addr, struct socket_address *dst_addr);
int cmp_sockaddr(const struct socket_address *addrA, const struct socket_address *addrB);

// helper functions for manipulating fragmented packet data
#define MAX_FRAGMENTS 8
struct fragmented_data{
  int fragment_count;
  struct iovec iov[MAX_FRAGMENTS];
};

int prepend_fragment(struct fragmented_data *data, const uint8_t *payload, size_t len);
int append_fragment(struct fragmented_data *data, const uint8_t *payload, size_t len);
size_t copy_fragment(struct fragmented_data *src, uint8_t *dest, size_t length);

ssize_t _send_message(struct __sourceloc, int fd, const struct socket_address *address, const struct fragmented_data *data);
ssize_t _recv_message_frag(struct __sourceloc, int fd, struct socket_address *address, int *ttl, struct fragmented_data *data);
ssize_t _recv_message(struct __sourceloc __whence, int fd, struct socket_address *address, int *ttl, unsigned char *buffer, size_t buflen);

#define send_message(fd, address, data)      _send_message(__WHENCE__, (fd), (address), (data))
#define recv_message_frag(fd, address, ttl, data) _recv_message(__WHENCE__, (fd), (address), (ttl), (data))
#define recv_message(fd, address, ttl, buf, len) _recv_message(__WHENCE__, (fd), (address), (ttl), (buf), (len))

#endif // __SERVAL_DNA___SOCKET_H
