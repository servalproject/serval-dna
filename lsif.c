/*
 * Derived from https://github.com/ajrisi/lsif/blob/master/lsif.c
 * No copyright information in the file, and published publicly, 
 * so presume no rights reserved. 
 *
 * This method doesn't work properly on OSX, but is for Android where no other
 * option seems to work.  Should work on any linux system.
 * ********************************
 *
 * Updated code to obtain IP and MAC address for all "up" network
 * interfaces on a linux system. Now IPv6 friendly and updated to use
 * inet_ntop instead of the deprecated inet_ntoa function. This version
 * should not seg fault on newer linux systems
 *
 * Version 2.0
 *
 * Authors: 
 *   Adam Pierce
 *   Adam Risi
 *   William Schaub
 *
 * Date: 11/11/2009
 * http://www.adamrisi.com
 * http://www.doctort.org/adam/
 * http://teotwawki.steubentech.com/
 *
 */

#include "serval.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/ioctl.h>
#if __MACH__ || __NetBSD__ || __OpenBSD__ || __FreeBSD__
#include <sys/sysctl.h>
#endif
/* Include sockio.h if needed */
#ifndef SIOCGIFCONF
#include <sys/sockio.h>
#endif
#include <netinet/in.h>
#include <netinet/if_ether.h>
#if __MACH__
#include <net/if_dl.h>
#endif
#include <net/if.h>

/* On platforms that have variable length 
   ifreq use the old fixed length interface instead */
#ifdef OSIOCGIFCONF
#undef SIOCGIFCONF
#define SIOCGIFCONF OSIOCGIFCONF
#undef SIOCGIFADDR
#define SIOCGIFADDR OSIOCGIFADDR
#undef SIOCGIFBRDADDR
#define SIOCGIFBRDADDR OSIOCGIFBRDADDR
#endif

#ifdef linux
/* for when all other options fail, as can happen on Android,
   if the permissions for the socket-based method are broken.
   Down side is that it while it gets the interface name and
   broadcast, it doesn't get the local address for that
   interface. 
*/
int scrapeProcNetRoute()
{
  if (debug & DEBUG_OVERLAYINTERFACES) DEBUG("called");

  FILE *f=fopen("/proc/net/route","r");
  if (!f) return fprintf(stderr,"Can't read from /proc/net/route\n");

  char line[1024],name[1024],dest[1024],mask[1024];

  /* skip header line */
  line[0]=0; fgets(line,1024,f);

  line[0]=0; fgets(line,1024,f);
  while(line[0]) {
    int r;
    if ((r=sscanf(line,"%s %s %*s %*s %*s %*s %*s %s",name,dest,mask))==3)
      {
	unsigned int d = strtol(dest,NULL,16);
	unsigned int m = strtol(mask,NULL,16);
	struct sockaddr_in local,broadcast;
	if (!(d&(~m))) {
	  local.sin_addr.s_addr=d;
	  broadcast.sin_addr.s_addr=d|~m;
	  overlay_interface_register(name,&local,&broadcast);
	}
      }

    line[0]=0; fgets(line,1024,f);    
  }
  fclose(f);
  return 0;
}
#endif

#ifdef SIOCGIFCONF

/* Not present in Linux */
#ifndef _SIZEOF_ADDR_IFREQ
#define _SIZEOF_ADDR_IFREQ(x) sizeof(struct ifreq)
#endif

int
lsif(void) {
  char            buf[8192];
  struct ifconf   ifc;
  int             sck, nInterfaces, ofs;
  struct ifreq    *ifr;
  struct sockaddr_in local, *broadcast;

  if (debug & DEBUG_OVERLAYINTERFACES) DEBUG("called");

  /* Get a socket handle. */
  sck = socket(PF_INET, SOCK_DGRAM, 0);
  if(sck < 0) {
    WHY_perror("socket");
    return 1;
  }
 
  /* Query available interfaces. */
  ifc.ifc_len = sizeof(buf);
  ifc.ifc_buf = buf;
  if(ioctl(sck, SIOCGIFCONF, &ifc) < 0) {
    WHY_perror("ioctl(SIOCGIFCONF)");
    close(sck);
    return 1;
  }

  /* Iterate through the list of interfaces. */
  nInterfaces = 0;
  ofs = 0;
  
  while (ofs < ifc.ifc_len && ofs < sizeof(buf)) {
    ifr = (struct ifreq *)(ifc.ifc_ifcu.ifcu_buf + ofs);
    ofs += _SIZEOF_ADDR_IFREQ(*ifr);

    /* We're only interested in IPv4 addresses */
    if (ifr->ifr_ifru.ifru_addr.sa_family != AF_INET) {
      if (debug & DEBUG_OVERLAYINTERFACES) DEBUGF("Skipping non-AF_INET address on %s", ifr->ifr_name);
      continue;
    }
  
    bcopy(&ifr->ifr_ifru.ifru_addr, &local, sizeof(struct sockaddr_in));
    
    /* Get interface flags */
    if (ioctl(sck, SIOCGIFFLAGS, ifr) == -1)
      FATAL_perror("ioctl(SIOCGIFFLAGS)");
    
    /* Not broadcast? Not interested.. */
    if ((ifr->ifr_ifru.ifru_flags & IFF_BROADCAST) == 0) {
      if (debug & DEBUG_OVERLAYINTERFACES) DEBUGF("Skipping non-broadcast address on %s", ifr->ifr_name);
      continue;
    }
    
    /* Get broadcast address */
    if (ioctl(sck, SIOCGIFBRDADDR, ifr, sizeof(*ifr)) == -1){
      WHY_perror("ioctl(SIOCGIFBRDADDR)");
      continue;
    }

    broadcast = (struct sockaddr_in *)&ifr->ifr_ifru.ifru_broadaddr;

    if (debug & DEBUG_OVERLAYINTERFACES) {
      // note, inet_ntop doesn't seem to behave on android
      DEBUGF("%s address: %s", ifr->ifr_name, inet_ntoa(local.sin_addr));
      DEBUGF("%s broadcast address: %s", ifr->ifr_name, inet_ntoa(broadcast->sin_addr));
    }
    overlay_interface_register(ifr->ifr_name, &local, broadcast);
    nInterfaces++;
  }
  
  if (debug & DEBUG_OVERLAYINTERFACES) DEBUGF("Examined %d interface addresses", nInterfaces);

  close(sck); 
  return 0;
}

#endif

#ifdef HAVE_IFADDRS_H
int
doifaddrs(void) {
  struct ifaddrs	*ifaddr, *ifa;
  char 			*name;
  struct sockaddr_in	local, netmask, broadcast;
  
  if (debug & DEBUG_OVERLAYINTERFACES) DEBUGF("called");
  
  if (getifaddrs(&ifaddr) == -1)
    return WHY_perror("getifaddr()");

  for (ifa = ifaddr; ifa != NULL ; ifa = ifa->ifa_next) {
    /* We're only interested in IPv4 addresses */
    if (ifa->ifa_addr->sa_family != AF_INET) {
      if (debug & DEBUG_OVERLAYINTERFACES) DEBUGF("Skipping non-AF_INET address on %s", ifa->ifa_name);
      continue;
    }
    
    /* Not broadcast? Not interested.. */
    if ((ifa->ifa_flags & IFF_BROADCAST) == 0) {
      if (debug & DEBUG_OVERLAYINTERFACES) DEBUGF("Skipping non-broadcast address on %s", ifa->ifa_name);
      continue;
    }

    name = ifa->ifa_name;
    local = *(struct sockaddr_in *)ifa->ifa_addr;
    netmask = *(struct sockaddr_in *)ifa->ifa_netmask;
    broadcast = local;
  
    /* Compute broadcast address */
    broadcast.sin_addr.s_addr |= (~netmask.sin_addr.s_addr);

    if (debug & DEBUG_OVERLAYINTERFACES){
      char			addrtxt[INET_ADDRSTRLEN], bcasttxt[INET_ADDRSTRLEN];
      assert(inet_ntop(AF_INET, (const void *)&local.sin_addr, addrtxt, INET_ADDRSTRLEN) != NULL);
      assert(inet_ntop(AF_INET, (const void *)&broadcast.sin_addr, bcasttxt, INET_ADDRSTRLEN) != NULL);
      DEBUGF("name=%s addr=%s broad=%s", name, addrtxt, bcasttxt);
    }

    overlay_interface_register(name,&local,&broadcast);
  }
  freeifaddrs(ifaddr);

  return 0;
}
#endif

