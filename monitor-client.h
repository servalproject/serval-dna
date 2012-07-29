/*
Copyright (C) 2012 Paul Gardner-Stephen, Serval Project.
 
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

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <string.h>
#include <signal.h>
#include <sys/types.h>

#ifdef WIN32
#include "win32/win32.h"
#endif
#include <unistd.h>
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#include <sys/un.h>
#include <fcntl.h>

#include "constants.h"
#include "conf.h"
#include "log.h"

#define MONITOR_CLIENT_BUFFER_SIZE 8192
typedef struct monitor_result {
  char line[MONITOR_CLIENT_BUFFER_SIZE];
  unsigned char data[MONITOR_CLIENT_BUFFER_SIZE];
  int dataBytes;
} monitor_result;
