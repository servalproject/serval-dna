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
#include "log.h" // for __HERE__ and struct __sourceloc

#define set_nonblock(fd)                (_set_nonblock(fd, __HERE__))
#define set_block(fd)                   (_set_block(fd, __HERE__))
#define read_nonblock(fd,buf,len)       (_read_nonblock(fd, buf, len, __HERE__))
#define write_all(fd,buf,len)           (_write_all(fd, buf, len, __HERE__))
#define write_nonblock(fd,buf,len)      (_write_nonblock(fd, buf, len, __HERE__))
#define write_all_nonblock(fd,buf,len)  (_write_all_nonblock(fd, buf, len, __HERE__))
#define write_str(fd,str)               (_write_str(fd, str, __HERE__))
#define write_str_nonblock(fd,str)      (_write_str_nonblock(fd, str, __HERE__))

int _set_nonblock(int fd, struct __sourceloc where);
int _set_block(int fd, struct __sourceloc where);
ssize_t _read_nonblock(int fd, void *buf, size_t len, struct __sourceloc where);
ssize_t _write_all(int fd, const void *buf, size_t len, struct __sourceloc where);
ssize_t _write_nonblock(int fd, const void *buf, size_t len, struct __sourceloc where);
ssize_t _write_all_nonblock(int fd, const void *buf, size_t len, struct __sourceloc where);
ssize_t _write_str(int fd, const char *str, struct __sourceloc where);
ssize_t _write_str_nonblock(int fd, const char *str, struct __sourceloc where);

#endif // __SERVALD_NET_H
