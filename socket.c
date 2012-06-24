/*
  Copyright (C) 2012 Daniel O'Connor, Serval Project.
 
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

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#include <stdio.h>
#include <strings.h>
#include <sys/errno.h>
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#include <sys/un.h>
#include <unistd.h>

#include "serval.h"
#include "socket.h"

/* Create a socket and bind it to name in the abstract namespace for android or
 * $SERVALINSTANCE_PATH/name for everything else.
 * 
 * Use abstract namespace as Android has no writable FS which supports sockets.
 * Don't use it for anything else because it makes testing harder (as we can't run
 * more than one servald on a given system.
*/
int
socket_bind(const char *name, int reuse) {
    int			s, oerrno, reuseP;
  struct sockaddr_un	sockname;
  socklen_t		len;
  
  if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
    return -1;

  if (reuse) {
      reuseP = 1;
      if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, 
		    &reuseP, sizeof(reuseP)) < 0) {
	  close(s);
	  return -1;
      }
  }
      
  socket_setname(&sockname, name, &len);
  unlink(sockname.sun_path);

  if (bind(s, (struct sockaddr *)&sockname, len) == -1) {
    oerrno = errno;
    close(s);
    errno = oerrno;
    return -1;
  }

  return s;
}

/* Set sockname to name handling abstract name space sockets etc. */
void
socket_setname(struct sockaddr_un *sockname, const char *name, socklen_t *len) {
  bzero(sockname, sizeof(*sockname));
  sockname->sun_family = AF_UNIX;
  
#ifdef USE_ABSTRACT_NAMESPACE
  sockname->sun_path[0] = 0;
  /* Note: -2 here not -1 because sprintf will put the trailling nul in */
  *len = snprintf(sockname->sun_path + 1, sizeof(sockname->sun_path) - 2, "%s.%s", 
		  DEFAULT_ABSTRACT_PREFIX, name);
  if (*len > sizeof(sockname->sun_path) - 2)
    FATALF("Socket path too long (%d > %d)", *len, sizeof(sockname->sun_path) - 2);

  /* Doesn't include trailing nul */
  *len = 1 + strlen(sockname->sun_path + 1) + sizeof(sockname->sun_family);
#else
  *len = snprintf(sockname->sun_path, sizeof(sockname->sun_path) - 1, "%s/%s",
		  serval_instancepath(), name);
  if (*len > sizeof(sockname->sun_path) - 1)
    FATALF("Socket path too long (%d > %d)", *len, sizeof(sockname->sun_path) - 1);
  
#ifdef SUN_LEN
  *len = SUN_LEN(sockname);
#else
  /* Includes trailing nul */
  *len = 1 + strlen(sockname->sun_path) + sizeof(sockname->sun_family);
#endif
#endif
}

/* Cleanup socket opened by socket_bind */
void
socket_done(const char *name) {
#ifndef USE_ABSTRACT_NAMESPACE
  struct sockaddr_un	sockname;
  socklen_t		len;
  
  socket_setname(&sockname, name, &len);
  unlink(sockname.sun_path);
  
#endif
}
