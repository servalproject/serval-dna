/*
 Copyright (C) 2010-2012 Paul Gardner-Stephen
 Copyright (C) 2010-2013 Serval Project Inc.
 
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

#include <inttypes.h> // for PRIx64 on Android
#include <sys/stat.h>
#include "conf.h"
#include "log.h"
#include "str.h"
#include "strbuf.h"
#include "strbuf_helpers.h"
#include "overlay_buffer.h"
#include "overlay_address.h"
#include "overlay_interface.h"
#include "overlay_packet.h"
#include "mdp_client.h"
#include "socket.h"

int _mdp_socket(struct __sourceloc UNUSED(__whence))
{
  // for now use the same process for creating sockets
  // TODO make overlay_mdp_client_socket() take __whence arg
  return overlay_mdp_client_socket();
}

int _mdp_close(struct __sourceloc __whence, int socket)
{
  // tell the daemon to drop all bindings
  struct mdp_header header={
    .flags = MDP_FLAG_CLOSE,
    .local.port = 0,
  };
  
  mdp_send(socket, &header, NULL, 0);
  
  // remove socket
  socket_unlink_close(socket);
  return 0;
}

int _mdp_send(struct __sourceloc __whence, int socket, const struct mdp_header *header, const uint8_t *payload, size_t len)
{
  struct socket_address addr;
  if (make_local_sockaddr(&addr, "mdp.2.socket") == -1)
    return -1;
  struct fragmented_data data={
    .fragment_count = len ? 2 : 1,
    .iov={
      {
	.iov_base = (void*)header,
	.iov_len = sizeof(struct mdp_header)
      },
      {
	.iov_base = (void*)payload,
	.iov_len = len
      }
    }
  };
  ssize_t sent = send_message(socket, &addr, &data);
  if (sent == -1)
    return -1;
  if ((size_t)sent != sizeof *header + len) {
    errno = EMSGSIZE;
    return WHYF("send_message(%d,%s,%s) returned %zd, expecting %zd -- setting errno = EMSGSIZE",
	socket,
	alloca_socket_address(&addr),
	alloca_fragmented_data(&data),
	(size_t)sent,
	sizeof *header + len
      );
  }
  return 0;
}

/* This function is designed to be used a bit like a system or library call, because it always sets
 * errno before returning -1.  Some errno values arise from system calls, and some are synthetic,
 * eg, to report buffer overflow or an MDP protocol error.
 */
ssize_t _mdp_recv(struct __sourceloc __whence, int socket, struct mdp_header *header, uint8_t *payload, size_t max_len)
{
  /* Construct name of socket to receive from. */
  struct socket_address mdp_addr;
  if (make_local_sockaddr(&mdp_addr, "mdp.2.socket") == -1) {
    errno = EOVERFLOW;
    WHY_perror("Failed to build socket address, setting errno=EOVERFLOW");
    return -1;
  }
  
  struct socket_address addr;
  bzero(&addr, sizeof addr);
  struct iovec iov[]={
    {
      .iov_base = (void *)header,
      .iov_len = sizeof(struct mdp_header)
    },
    {
      .iov_base = (void *)payload,
      .iov_len = max_len
    }
  };
  
  struct msghdr hdr={
    .msg_name=&addr.addr,
    .msg_namelen=sizeof(addr.store),
    .msg_iov=iov,
    .msg_iovlen= max_len ? 2 : 1,
  };
  
  ssize_t len = recvmsg(socket, &hdr, 0);
  if (len == -1) {
    // Do not log errors that are part of normal operation.
    if (   errno != EAGAIN
#ifdef EWOULDBLOCK
	&& errno != EWOULDBLOCK
#endif
	&& errno != EINTR
    )
      WHYF_perror("recvmsg(%d,%p,0)", socket, &hdr);
    return -1;
  }
  if ((size_t)len < sizeof(struct mdp_header)) {
    errno = EBADMSG;
    WHYF_perror("received message too short (%zu), setting errno=EBADMSG", (size_t)len);
    return -1;
  }
  addr.addrlen=hdr.msg_namelen;
  // double check that the incoming address matches the servald daemon
  if (cmp_sockaddr(&addr, &mdp_addr) != 0
      && (   addr.local.sun_family != AF_UNIX
	  || real_sockaddr(&addr, &addr) <= 0
	  || cmp_sockaddr(&addr, &mdp_addr) != 0
	 )
  ) {
    errno = EBADMSG;
    WARNF_perror("dropped message from %s (expecting %s), setting errno=EBADMSG",
      alloca_socket_address(&addr),
      alloca_socket_address(&mdp_addr));
    return -1;
  }
  return len - sizeof(struct mdp_header);
}

int _mdp_poll(struct __sourceloc UNUSED(__whence), int socket, time_ms_t timeout_ms)
{
  // TODO make overlay_mdp_client_poll() take __whence arg
  return overlay_mdp_client_poll(socket, timeout_ms);
}

// returns -1 on error, -2 on timeout, packet length on success.
ssize_t mdp_poll_recv(int mdp_sock, time_ms_t deadline, struct mdp_header *rev_header, unsigned char *payload, size_t buffer_size)
{
  time_ms_t now = gettime_ms();
  if (now > deadline)
    return -2;
  int p = mdp_poll(mdp_sock, deadline - now);
  if (p == -1)
    return WHY_perror("mdp_poll");
  if (p == 0)
    return -2;
  ssize_t len = mdp_recv(mdp_sock, rev_header, payload, buffer_size);
  if (len == -1)
    return -1;
  if (rev_header->flags & MDP_FLAG_ERROR)
    return WHY("Operation failed, check the daemon log for more information");
  return len;
}

int overlay_mdp_send(int mdp_sockfd, overlay_mdp_frame *mdp, int flags, int timeout_ms)
{
  if (mdp_sockfd == -1)
    return -1;
  // Minimise frame length to save work and prevent accidental disclosure of memory contents.
  ssize_t len = overlay_mdp_relevant_bytes(mdp);
  if (len == -1)
    return WHY("MDP frame invalid (could not compute length)");
  /* Construct name of socket to send to. */
  struct socket_address addr;
  if (make_local_sockaddr(&addr, "mdp.socket") == -1)
    return -1;
  // Send to that socket
  set_nonblock(mdp_sockfd);
  ssize_t result = sendto(mdp_sockfd, mdp, (size_t)len, 0, &addr.addr, addr.addrlen);
  set_block(mdp_sockfd);
  if ((size_t)result != (size_t)len) {
    if (result == -1)
      WHYF_perror("sendto(fd=%d,len=%zu,addr=%s)", mdp_sockfd, (size_t)len, alloca_socket_address(&addr));
    else
      WHYF("sendto() sent %zu bytes of MDP reply (%zu) to %s", (size_t)result, (size_t)len, alloca_socket_address(&addr)); 
    mdp->packetTypeAndFlags=MDP_ERROR;
    mdp->error.error=1;
    snprintf(mdp->error.message,128,"Error sending frame to MDP server.");
    return -1;
  } else {
    if (!(flags&MDP_AWAITREPLY)) {       
      return 0;
    }
  }
  
  mdp_port_t port=0;
  if ((mdp->packetTypeAndFlags&MDP_TYPE_MASK) == MDP_TX)
      port = mdp->out.src.port;
      
  time_ms_t started = gettime_ms();
  while(timeout_ms>=0 && overlay_mdp_client_poll(mdp_sockfd, timeout_ms)>0){
    int ttl=-1;
    if (!overlay_mdp_recv(mdp_sockfd, mdp, port, &ttl)) {
      /* If all is well, examine result and return error code provided */
      if ((mdp->packetTypeAndFlags&MDP_TYPE_MASK)==MDP_ERROR)
	return mdp->error.error;
      else
      /* Something other than an error has been returned */
	return 0;
    }
    
    // work out how much longer we can wait for a valid response
    time_ms_t now = gettime_ms();
    timeout_ms -= (now - started);
  }
  
  /* Timeout */
  mdp->packetTypeAndFlags=MDP_ERROR;
  mdp->error.error=1;
  snprintf(mdp->error.message,128,"Timeout waiting for reply to MDP packet (packet was successfully sent).");    
  return -1; /* WHY("Timeout waiting for server response"); */
}

/** Create a new MDP socket and return its descriptor (-1 on error). */
int overlay_mdp_client_socket(void)
{
  /* Create local per-client socket to MDP server (connection is always local) */
  int mdp_sockfd;
  struct socket_address addr;
  uint32_t random_value;
  if (urandombytes((unsigned char *)&random_value, sizeof random_value) == -1)
    return WHY("urandombytes() failed");
  if (make_local_sockaddr(&addr, "mdp.client.%u.%08lx.socket", getpid(), (unsigned long)random_value) == -1)
    return -1;
  if ((mdp_sockfd = esocket(AF_UNIX, SOCK_DGRAM, 0)) == -1)
    return -1;
  if (socket_bind(mdp_sockfd, &addr) == -1) {
    close(mdp_sockfd);
    return -1;
  }
  socket_set_rcvbufsize(mdp_sockfd, 128 * 1024);
  return mdp_sockfd;
}

int overlay_mdp_client_close(int mdp_sockfd)
{
  /* Tell MDP server to release all our bindings */
  overlay_mdp_frame mdp;
  mdp.packetTypeAndFlags = MDP_GOODBYE;
  overlay_mdp_send(mdp_sockfd, &mdp, 0, 0);
  
  socket_unlink_close(mdp_sockfd);
  return 0;
}

int overlay_mdp_client_poll(int mdp_sockfd, time_ms_t timeout_ms)
{
  fd_set r;
  FD_ZERO(&r);
  FD_SET(mdp_sockfd, &r);
  if (timeout_ms<0) timeout_ms=0;
  
  struct pollfd fds[]={
    {
      .fd = mdp_sockfd,
      .events = POLLIN|POLLERR,
    }
  };
  return poll(fds, 1, timeout_ms);
}

int overlay_mdp_recv(int mdp_sockfd, overlay_mdp_frame *mdp, mdp_port_t port, int *ttl)
{
  /* Construct name of socket to receive from. */
  struct socket_address mdp_addr;
  if (make_local_sockaddr(&mdp_addr, "mdp.socket") == -1)
    return -1;
  
  /* Check if reply available */
  struct socket_address recvaddr;
  recvaddr.addrlen = sizeof recvaddr.store;
  ssize_t len;
  mdp->packetTypeAndFlags = 0;
  set_nonblock(mdp_sockfd);
  len = recvwithttl(mdp_sockfd, (unsigned char *)mdp, sizeof(overlay_mdp_frame), ttl, &recvaddr);
  if (len == -1)
    WHYF_perror("recvwithttl(%d,%p,%zu,&%d,%p(%s))",
	  mdp_sockfd, mdp, sizeof(overlay_mdp_frame), *ttl,
	  &recvaddr, alloca_socket_address(&recvaddr)
	);
  set_block(mdp_sockfd);
  if (len <= 0)
    return -1; // no packet received

  // If the received address overflowed the buffer, then it cannot have come from the server, whose
  // address must always fit within a struct sockaddr_un.
  if (recvaddr.addrlen > sizeof recvaddr.store)
    return WHY("reply did not come from server: address overrun");

  // Compare the address of the sender with the address of our server, to ensure they are the same.
  // If the comparison fails, then try using realpath(3) on the sender address and compare again.
  if (	cmp_sockaddr(&recvaddr, &mdp_addr) != 0
      && (   recvaddr.local.sun_family != AF_UNIX
	  || real_sockaddr(&recvaddr, &recvaddr) <= 0
	  || cmp_sockaddr(&recvaddr, &mdp_addr) != 0
	 )
  )
    return WHYF("reply did not come from server: %s", alloca_socket_address(&recvaddr));
  
  // silently drop incoming packets for the wrong port number
  if (port>0 && port != mdp->out.dst.port){
    WARNF("Ignoring packet for port %"PRImdp_port_t,mdp->out.dst.port);
    return -1;
  }

  ssize_t expected_len = overlay_mdp_relevant_bytes(mdp);
  if (expected_len < 0)
    return WHY("unsupported MDP packet type");
  if ((size_t)len < (size_t)expected_len)
    return WHYF("Expected packet length of %zu, received only %zd bytes", (size_t) expected_len, (size_t) len);
  
  /* Valid packet received */
  return 0;
}

// send a request to servald deamon to add a port binding
int overlay_mdp_bind(int mdp_sockfd, const sid_t *localaddr, mdp_port_t port) 
{
  overlay_mdp_frame mdp;
  mdp.packetTypeAndFlags=MDP_BIND|MDP_FORCE;
  mdp.bind.sid = *localaddr;
  mdp.bind.port=port;
  int result=overlay_mdp_send(mdp_sockfd, &mdp,MDP_AWAITREPLY,5000);
  if (result) {
    if (mdp.packetTypeAndFlags==MDP_ERROR)
      WHYF("Could not bind to MDP port %"PRImdp_port_t": error=%d, message='%s'",
	   port,mdp.error.error,mdp.error.message);
    else
      WHYF("Could not bind to MDP port %"PRImdp_port_t" (no reason given)",port);
    return -1;
  }
  return 0;
}

int overlay_mdp_getmyaddr(int mdp_sockfd, unsigned index, sid_t *sidp)
{
  overlay_mdp_frame a;
  memset(&a, 0, sizeof(a));
  
  a.packetTypeAndFlags=MDP_GETADDRS;
  a.addrlist.mode = MDP_ADDRLIST_MODE_SELF;
  a.addrlist.first_sid=index;
  a.addrlist.last_sid=OVERLAY_MDP_ADDRLIST_MAX_SID_COUNT;
  a.addrlist.frame_sid_count=MDP_MAX_SID_REQUEST;
  int result=overlay_mdp_send(mdp_sockfd,&a,MDP_AWAITREPLY,5000);
  if (result) {
    if (a.packetTypeAndFlags == MDP_ERROR)
      DEBUGF("MDP Server error #%d: '%s'", a.error.error, a.error.message);
    return WHY("Failed to get local address list");
  }
  if ((a.packetTypeAndFlags&MDP_TYPE_MASK)!=MDP_ADDRLIST)
    return WHY("MDP Server returned something other than an address list");
  if (0) DEBUGF("local addr 0 = %s",alloca_tohex_sid_t(a.addrlist.sids[0]));
  *sidp = a.addrlist.sids[0];
  return 0;
}

ssize_t overlay_mdp_relevant_bytes(overlay_mdp_frame *mdp) 
{
  size_t len;
  switch(mdp->packetTypeAndFlags&MDP_TYPE_MASK)
  {
    case MDP_ROUTING_TABLE:
    case MDP_GOODBYE:
      /* no arguments for saying goodbye */
      len=&mdp->raw[0]-(char *)mdp;
      break;
    case MDP_ADDRLIST: 
      len = mdp->addrlist.sids[mdp->addrlist.frame_sid_count].binary - (unsigned char *)mdp;
      break;
    case MDP_GETADDRS: 
      len = mdp->addrlist.sids[0].binary - (unsigned char *)mdp;
      break;
    case MDP_TX: 
      len=(&mdp->out.payload[0]-(unsigned char *)mdp) + mdp->out.payload_length; 
      break;
    case MDP_BIND:
      // make sure that the compiler has actually given these two structures the same address
      // I've seen gcc 4.8.1 on x64 fail to give elements the same address once
      assert((void *)mdp->raw == (void *)&mdp->bind);
      len=(&mdp->raw[0] - (char *)mdp) + sizeof(struct mdp_sockaddr);
      break;
    case MDP_SCAN:
      len=(&mdp->raw[0] - (char *)mdp) + sizeof(struct overlay_mdp_scan);
      break;
    case MDP_ERROR: 
      /* This formulation is used so that we don't copy any bytes after the
       end of the string, to avoid information leaks */
      len=(&mdp->error.message[0]-(char *)mdp) + strlen(mdp->error.message)+1;      
      if (mdp->error.error) INFOF("mdp return/error code: %d:%s",mdp->error.error,mdp->error.message);
      break;
    default:
      return WHY("Illegal MDP frame type.");
  }
  return len;
}
