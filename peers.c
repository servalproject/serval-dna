/* 
Serval Distributed Numbering Architecture (DNA)
Copyright (C) 2010 Paul Gardner-Stephen 

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

#include "mphlr.h"

char *batman_socket=NULL;
char *batman_peerfile=NULL;

int peer_count=0;
struct in_addr peers[MAX_PEERS];

struct in_addr nominated_peers[256];
int nom_peer_count=0;

int additionalPeer(char *peer)
{
  struct in_addr pa;

  if (nom_peer_count>255) return setReason("Too many peers.  You can only nominate 255 peers in this version.");

  pa.s_addr=inet_addr(peer);
  if (pa.s_addr==INADDR_NONE) return setReason("Invalid peer address specified.");
  nominated_peers[nom_peer_count++]=pa;

  return 0;
}

int getBroadcastAddresses(struct in_addr peers[],int *peer_count,int peer_max){
  /* The Android ndk doesn't have ifaddrs.h, so we have to use the netlink interface.
     However, netlink is only available on Linux, so for BSD systems, e.g., Mac, we
     need to use the ifaddrs method.

     Also, ifaddrs will work on non-linux systems which is considered critical.
  */
#ifdef HAVE_LINUX_NETLINK_H
  
  // Ask for the address information.
  struct {
    struct nlmsghdr netlinkHeader;
    struct ifaddrmsg msg;
  }addrRequest;
  char buff[16384];
  int netsock;
  size_t bytesRead;
  struct nlmsghdr *hdr;
  
  if (debug>1) fprintf(stderr,"Reading broadcast addresses (linux style)\n");
  
  netsock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
  
  memset(&addrRequest, 0, sizeof(addrRequest));
  
  addrRequest.netlinkHeader.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;
  addrRequest.netlinkHeader.nlmsg_type = RTM_GETADDR;
  addrRequest.netlinkHeader.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(addrRequest)));
  addrRequest.msg.ifa_family = AF_INET;
  addrRequest.msg.ifa_index = 0; // All interfaces.
  
  while (send(netsock, &addrRequest, addrRequest.netlinkHeader.nlmsg_len, 0)==EINTR);
  
  while(1){
    while((bytesRead = recv(netsock, buff, sizeof(buff), 0))==EINTR);
    if (bytesRead<=0) break;
    
    for (hdr = (struct nlmsghdr*)buff; 
	 NLMSG_OK(hdr, (size_t)bytesRead); 
	 hdr = NLMSG_NEXT(hdr, bytesRead)) {
      
      switch (hdr->nlmsg_type) {
	case NLMSG_DONE:
	  return 0;
	case NLMSG_ERROR:
	  return -1;
	case RTM_NEWADDR:
	{
	  struct ifaddrmsg* address = (struct ifaddrmsg*)(NLMSG_DATA(hdr));
	  struct rtattr* rta = IFA_RTA(address);
	  size_t ifaPayloadLength = IFA_PAYLOAD(hdr);
	  
	  while (RTA_OK(rta, ifaPayloadLength)) {
	    if (rta->rta_type == IFA_BROADCAST && address->ifa_family == AF_INET) {
	      struct in_addr *addr=(struct in_addr *)RTA_DATA(rta);
	      peers[(*peer_count)++].s_addr=addr->s_addr;
	    }
	    rta = RTA_NEXT(rta, ifaPayloadLength);
	  }
	}
	  break;
      }
    }
  }
#else
#ifdef HAVE_IFADDRS_H
  struct ifaddrs *ifaddr,*ifa;
  int family;
    
  if (debug>1) fprintf(stderr,"Reading broadcast addresses (posix style)\n");

  if (getifaddrs(&ifaddr) == -1)  {
    perror("getifaddr()");
    return WHY("getifaddrs() failed");
  }

  for (ifa=ifaddr;ifa!=NULL;ifa=ifa->ifa_next) {
    family=ifa->ifa_addr->sa_family;
    switch(family) {
    case AF_INET: 
      /* Add our local address and computed broadcast address to the list of peers.
	 XXX - ifa->ifa_broadaddr should give us the broadcast address, but doesn't seem to
	 on mac osx.  So we have resorted computing the normal (ceiling) broadcast address.
       */
      peers[(*peer_count)++].s_addr=((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
      {
	unsigned int local=(((struct sockaddr_in *)(ifa->ifa_addr))->sin_addr.s_addr);
	unsigned int netmask=(((struct sockaddr_in *)(ifa->ifa_netmask))->sin_addr.s_addr);
	peers[(*peer_count)++].s_addr=local|~netmask;
      }
      break;
    }
  }
#else
 if (debug>1) fprintf(stderr,"Don't know how to read broadcast addresses :(\n");
#endif
#endif
  return 0;
}

int getPeerList()
{
  /* Generate the list of known peers.
     If using BATMAN layer 3, this needs to be the list of exact IP addresses of the peers,
     as we cannot reliably broadcast.
     Once BATMAN Advanced is available, we will be able to do that.
     In the mean time, we need to query BATMANd to find the known list of peers.  This is not
     quite as easy as we might wish.
  */
  int i;

  peer_count=0;
  
  /* Add user specified peers */
  for(i=0;i<nom_peer_count;i++) peers[peer_count++]=nominated_peers[i];

  /* Add ourselves as a peer */
  peers[peer_count++].s_addr=inet_addr("127.0.0.1");

  /* Add broadcast address of every running interface */
  getBroadcastAddresses(peers,&peer_count,MAX_PEERS);

  /* XXX Query BATMANd for other peers */
  if (batman_peerfile) 
    readBatmanPeerFile(batman_peerfile,peers,&peer_count,MAX_PEERS);
  else if (batman_socket)
    getBatmanPeerList(batman_socket,peers,&peer_count,MAX_PEERS);
  else
    readRoutingTable(peers,&peer_count,MAX_PEERS);
  /* Read ARP table for good measure as a defence against transient loss of broadcast reception,
   e.g., when screens go off on phones. */
  readArpTable(peers,&peer_count,MAX_PEERS);

  return 0;
}

int sendToPeers(unsigned char *packet,int packet_len,int method,int peerId,struct response_set *r)
{
  /* The normal version of BATMAN works at layer 3, so we cannot simply use an ethernet broadcast
     to get the message out.  BATMAN Advanced might solve this, though.

     So, in the mean time, we need to explicitly send the request to each peer.
     We don't want to bother the peers who have already responded.
  */
  int i;
  int maxPeer=peer_count-1;
  int n=0;
  int ret;
  struct sockaddr_in peer_addr;

  bzero(&peer_addr, sizeof(peer_addr));
  peer_addr.sin_family=AF_INET;
  peer_addr.sin_port = htons(4110);

  if (method==REQ_PARALLEL) i=0; else { i=peerId; maxPeer=i; }
  for(;i<=maxPeer;i++)
    if (!responseFromPeerP(r,i))
      {
	peer_addr.sin_addr=peers[i];

	if (debug>1) fprintf(stderr,"Sending packet to peer #%d\n",i);
	
	ret=sendto(sock,packet,packet_len,0,(struct sockaddr *)&peer_addr,sizeof(peer_addr));
	if (ret<packet_len)
	  {
	    /* XXX something bad happened */
	    if (debug) fprintf(stderr,"Could not send to peer %s\n",inet_ntoa(peer_addr.sin_addr));
	  }
	else
	  {
	    if (debug>1) fprintf(stderr,"Sent request to peer %s\n",inet_ntoa(peer_addr.sin_addr));
	    n++;
	    /* If sending to only one peer, return now */ 
	    if (method==i) break;
	  }
      }
    else
      if (debug>1) fprintf(stderr,"Peer %s has already replied, so not sending again.\n",
			   inet_ntoa(peer_addr.sin_addr));

  if (debug) fprintf(stderr,"Sent request to %d peers.\n",n);

  return 0;

}
