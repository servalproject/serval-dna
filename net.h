/*
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

#ifndef __SERVALD_NET_H
#define __SERVALD_NET_H

#include <sys/types.h> // for size_t, ssize_t
#include <sys/socket.h> // for struct sockaddr, socklen_t
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h> // for struct in_addr
#endif
#include <arpa/inet.h> // for in_addr_t
#include "log.h" // for __WHENCE__ and struct __sourceloc

/* Build a struct in_addr from a host-byte-order integer.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
struct in_addr hton_in_addr(in_addr_t);

#define set_nonblock(fd)                (_set_nonblock(fd, __WHENCE__))
#define set_block(fd)                   (_set_block(fd, __WHENCE__))
#define read_nonblock(fd,buf,len)       (_read_nonblock(fd, buf, len, __WHENCE__))
#define write_all(fd,buf,len)           (_write_all(fd, buf, len, __WHENCE__))
#define writev_all(fd,iov,cnt)          (_writev_all(fd, (iov), (cnt), __WHENCE__))
#define write_nonblock(fd,buf,len)      (_write_nonblock(fd, buf, len, __WHENCE__))
#define write_all_nonblock(fd,buf,len)  (_write_all_nonblock(fd, buf, len, __WHENCE__))
#define write_str(fd,str)               (_write_str(fd, str, __WHENCE__))
#define write_str_nonblock(fd,str)      (_write_str_nonblock(fd, str, __WHENCE__))

int _set_nonblock(int fd, struct __sourceloc __whence);
int _set_block(int fd, struct __sourceloc __whence);
ssize_t _read_nonblock(int fd, void *buf, size_t len, struct __sourceloc __whence);
ssize_t _write_all(int fd, const void *buf, size_t len, struct __sourceloc __whence);
ssize_t _write_nonblock(int fd, const void *buf, size_t len, struct __sourceloc __whence);
ssize_t _write_all_nonblock(int fd, const void *buf, size_t len, struct __sourceloc __whence);
ssize_t _writev_all(int fd, const struct iovec *iov, int iovcnt, struct __sourceloc __whence);
ssize_t _write_str(int fd, const char *str, struct __sourceloc __whence);
ssize_t _write_str_nonblock(int fd, const char *str, struct __sourceloc __whence);

struct socket_address;
ssize_t recvwithttl(int sock, unsigned char *buffer, size_t bufferlen, int *ttl, struct socket_address *);

#endif // __SERVALD_NET_H
