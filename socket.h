#ifndef __SERVALD_SOCKET_H
#define __SERVALD_SOCKET_H

#ifndef WIN32
#include <sys/un.h>
#endif

struct socket_address{
  socklen_t addrlen;
  union{
    struct sockaddr addr;
    struct sockaddr_un addr_un;
    struct sockaddr_storage store;
  };
};

/* Basic socket operations.
 */
int _make_local_sockaddr(struct __sourceloc, struct socket_address *addr, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
int _esocket(struct __sourceloc, int domain, int type, int protocol);
int _socket_bind(struct __sourceloc, int sock, const struct sockaddr *addr, socklen_t addrlen);
int _socket_connect(struct __sourceloc, int sock, const struct sockaddr *addr, socklen_t addrlen);
int _socket_listen(struct __sourceloc, int sock, int backlog);
int _socket_set_reuseaddr(struct __sourceloc, int sock, int reuseP);
int _socket_set_rcvbufsize(struct __sourceloc, int sock, unsigned buffer_size);

#define make_local_sockaddr(sockname, fmt,...) _make_local_sockaddr(__WHENCE__, (sockname), (fmt), ##__VA_ARGS__)
#define esocket(domain, type, protocol)             _esocket(__WHENCE__, (domain), (type), (protocol))
#define socket_bind(sock, addr, addrlen)            _socket_bind(__WHENCE__, (sock), (addr), (addrlen))
#define socket_connect(sock, addr, addrlen)         _socket_connect(__WHENCE__, (sock), (addr), (addrlen))
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
ssize_t _recv_message(struct __sourceloc, int fd, struct socket_address *address, struct fragmented_data *data);

#define send_message(fd, address, data)    _send_message(__WHENCE__, (fd), (address), (data))
#define recv_message(fd, address, data)    _recv_message(__WHENCE__, (fd), (address), (data))

#endif