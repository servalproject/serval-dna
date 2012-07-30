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

#include "conf.h"
#include "log.h"
#include "socket.h"

/* Set the socket name in the abstract namespace for linux or
 * $SERVALINSTANCE_PATH/name for everything else.
 */
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
