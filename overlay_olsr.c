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

/*
  Portions Copyright (C) 2013 Petter Reinholdtsen
  Some rights reserved

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
  FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
  COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.
*/

/*
 
 Integration with olsr routing.
 
 - requires olsrd to be running on the same machine with plugin X loaded with the following configuration;
 LoadPlugin "name..."{
   PlParam  "BindPort"	"4130" 
   PlParam  "DestPort"	"4131"
   PlParam  "MagicNumber" "123"
 }
 
 This plugin will be used to forward broadcast mdp payloads to other instances of servald running on the network.

*/

#include "serval.h"
#include "conf.h"
#include "overlay_interface.h"
#include "overlay_packet.h"
#include "overlay_buffer.h"
#include "overlay_address.h"
#include "route_link.h"

#define PACKET_FORMAT_NUMBER 123

static void olsr_read(struct sched_ent *alarm);

static struct profile_total read_timing={
  .name="olsr_read",
};

static struct sched_ent read_watch={
  .function=olsr_read,
  .stats=&read_timing,
  .poll={.fd=-1,.events=POLLIN},
};

int olsr_init_socket(void){
  int fd;
  int reuseP = 1;
  
  if (read_watch.poll.fd>=0)
    return 0;
  
  if (!config.olsr.enable)
    return 0;
  
  INFOF("Initialising olsr broadcast forwarding via ports %d-%d", config.olsr.local_port, config.olsr.remote_port);
  struct sockaddr_in addr = {
    .sin_family = AF_INET,
    .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    .sin_port = htons(config.olsr.local_port),
    .sin_zero = {0},
  };
  
  fd = socket(AF_INET,SOCK_DGRAM,0);
  if (fd < 0) {
    return WHY_perror("Error creating socket");
  } 
  
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseP, sizeof(reuseP)) < 0) {
    WHY_perror("setsockopt(SO_REUSEADR)");
    close(fd);
    return -1;
  }
  
#ifdef SO_REUSEPORT
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &reuseP, sizeof(reuseP)) < 0) {
    WHY_perror("setsockopt(SO_REUSEPORT)");
    close(fd);
    return -1;
  }
#endif
  
  /* Automatically close socket on calls to exec().
   This makes life easier when we restart with an exec after receiving
   a bad signal. */
  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, NULL) |
#ifdef FD_CLOEXEC
 FD_CLOEXEC
#else
 O_CLOEXEC
#endif
);
  
  if (bind(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in))) {
    WHY_perror("Bind failed");
    close(fd);
    return -1;
  }
  
  read_watch.poll.fd = fd;
  
  watch(&read_watch);
  return 0;
}

static void parse_frame(struct overlay_buffer *buff){
  struct overlay_frame frame;
  uint8_t addr_len;
  struct in_addr *addr;
  struct decode_context context={
    .please_explain=NULL,
  };
  
  memset(&frame,0,sizeof(struct overlay_frame));
  // parse the incoming olsr header
  int magic = ob_get(buff);
  if ((PACKET_FORMAT_NUMBER & 0xFF) != magic){
    WHYF("Unexpected magic number %d", magic);
    return;
  }
  
  frame.ttl = ob_get(buff);
  addr_len = ob_get(buff);
  
  // Note IP6 not yet supported
  if (addr_len!=4)
    return;
  
  addr = (struct in_addr *)ob_get_bytes_ptr(buff, addr_len);
  
  // read subscriber id of transmitter
  if (overlay_address_parse(&context, buff, &context.sender))
    goto end;
  
  if (context.flags & DECODE_FLAG_INVALID_ADDRESS)
    goto end;
  
  // locate the interface we should send outgoing unicast packets to
  context.interface = overlay_interface_find(*addr, 1);
  if (context.interface){
    link_received_packet(&context, -1, 0);
  }
  
  // read subscriber id of payload origin
  if (overlay_address_parse(&context, buff, &frame.source))
    goto end;
  
  if (context.flags & DECODE_FLAG_INVALID_ADDRESS)
    goto end;
  
  // read source broadcast id
  // assume each packet may arrive multiple times due to routing loops between servald overlay and olsr.
  if (overlay_broadcast_parse(buff, &frame.broadcast_id))
    goto end;
  
  if (context.flags & DECODE_FLAG_INVALID_ADDRESS)
    goto end;
  
  frame.modifiers=ob_get(buff);
  
  DEBUGF(overlayinterfaces, "Received %zu byte payload via olsr", buff->sizeLimit - buff->position);
  
  // the remaining bytes are an mdp payload, process it
  frame.payload = buff;
  
  overlay_saw_mdp_containing_frame(&frame);
  
  // TODO relay this packet to other non-olsr networks.
  
end:
  // if we didn't understand one of the address abreviations, ask for explanation
  send_please_explain(&context, get_my_subscriber(), context.sender);
}

static void olsr_read(struct sched_ent *alarm){
  if (alarm->poll.revents & POLLIN) {
    unsigned char buff[1600];
    struct sockaddr_in addr;
    socklen_t size = sizeof(struct sockaddr_in);
    
    int msg_len = recvfrom(read_watch.poll.fd, buff, sizeof(buff), 0, (struct sockaddr *)&addr, &size);
    if (msg_len<3)
      return;
    
    // drop packets from other port numbers
    if (ntohs(addr.sin_port)!= config.olsr.remote_port){
      WHYF("Dropping unexpected packet from port %d", ntohs(addr.sin_port));
      return;
    }
    
    struct overlay_buffer *b = ob_static(buff, msg_len);
    ob_limitsize(b, msg_len);
    parse_frame(b);
    
    ob_free(b);
  }
  
  if (alarm->poll.revents & (POLLHUP | POLLERR)) {
    unwatch(alarm);
    close(alarm->poll.fd);
    alarm->poll.fd=-1;
    WHY("Olsr socket closed due to error");
  }
}

static int send_packet(unsigned char *header, int header_len, unsigned char *payload, int payload_len){
  struct sockaddr_in addr={
    .sin_family=AF_INET,
    .sin_addr.s_addr=htonl(INADDR_LOOPBACK),
    .sin_port=htons(config.olsr.remote_port),
    .sin_zero = {0},
  };
  
  struct iovec iov[]={
    {
      .iov_base=header,
      .iov_len=header_len,
    },
    {
      .iov_base=payload,
      .iov_len=payload_len,
    },
  };
  
  struct msghdr msg={
    .msg_name=&addr,
    .msg_namelen=sizeof(struct sockaddr_in),
    .msg_iov=iov,
    .msg_iovlen=2,
  };
  
  if (sendmsg(read_watch.poll.fd, &msg, 0)<0){
    return WHY_perror("Sending packet");
  }
  return 0;
}

int olsr_send(struct overlay_frame *frame){
  if (read_watch.poll.fd<0)
    return 0;
  // only send broadcasts
  if (frame->destination)
    return 0;
  
  struct decode_context context;
  bzero(&context, sizeof context);
  struct overlay_buffer *b=ob_new();
  if (b == NULL)
    return 0;
  
  // build olsr specific frame header
  ob_append_byte(b, PACKET_FORMAT_NUMBER);
  ob_append_byte(b, frame->ttl);
  
  // address the packet as transmitted by me
  overlay_address_append(&context, b, get_my_subscriber());
  overlay_address_append(&context, b, frame->source);
  overlay_broadcast_append(b, &frame->broadcast_id);
  ob_append_byte(b, frame->modifiers);
  
  DEBUGF(overlayinterfaces, "Sending %zu byte payload via olsr", frame->payload->sizeLimit);
  
  // send the packet
  int ret = send_packet(b->bytes, b->position, frame->payload->bytes, frame->payload->sizeLimit);
  ob_free(b);
  return ret;
}
