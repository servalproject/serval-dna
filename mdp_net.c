/*
Copyright (C) 2013 Serval Project, Inc.
 
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

#include "socket.h"
#include "conf.h"
#include "log.h"

ssize_t recvwithttl(int sock,unsigned char *buffer, size_t bufferlen,int *ttl, struct socket_address *recvaddr)
{
  struct msghdr msg;
  struct iovec iov[1];
  struct cmsghdr cmsgcmsg[16];
  iov[0].iov_base=buffer;
  iov[0].iov_len=bufferlen;
  bzero(&msg,sizeof(msg));
  msg.msg_name = &recvaddr->store;
  msg.msg_namelen = recvaddr->addrlen;
  msg.msg_iov = &iov[0];
  msg.msg_iovlen = 1;
  msg.msg_control = cmsgcmsg;
  msg.msg_controllen = sizeof cmsgcmsg;
  msg.msg_flags = 0;
  
  ssize_t len = recvmsg(sock,&msg,0);
  if (len == -1 && errno != EAGAIN && errno != EWOULDBLOCK)
    return WHYF_perror("recvmsg(%d,%p,0)", sock, &msg);
  
#if 0
  if (config.debug.packetrx) {
    DEBUGF("recvmsg returned %d (flags=%d, msg_controllen=%d)", (int) len, msg.msg_flags, (int)msg.msg_controllen);
    dump("received data", buffer, len);
  }
#endif
  
  if (len > 0) {
    struct cmsghdr *cmsg;
    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
      if (   cmsg->cmsg_level == IPPROTO_IP
	  && ((cmsg->cmsg_type == IP_RECVTTL) || (cmsg->cmsg_type == IP_TTL))
	  && cmsg->cmsg_len
      ) {
	if (config.debug.packetrx)
	  DEBUGF("  TTL (%p) data location resolves to %p", ttl,CMSG_DATA(cmsg));
	if (CMSG_DATA(cmsg)) {
	  *ttl = *(unsigned char *) CMSG_DATA(cmsg);
	  if (config.debug.packetrx)
	    DEBUGF("  TTL of packet is %d", *ttl);
	} 
      } else {
	if (config.debug.packetrx)
	  DEBUGF("I didn't expect to see level=%02x, type=%02x",
		 cmsg->cmsg_level,cmsg->cmsg_type);
      }	 
    }
  }
  recvaddr->addrlen = msg.msg_namelen;
  
  return len;
}
