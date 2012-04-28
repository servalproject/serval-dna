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
#include <net/if.h>
#include <netinet/if_ether.h>
#if __MACH__
#include <net/if_dl.h>
#endif

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

#ifdef HAVE_LINUX_IF_H
int lsif(void)
{
  char            buf[8192] = {0};
  struct ifconf   ifc = {0};
  struct ifreq   *ifr = NULL;
  int             sck = 0;
  int             nInterfaces = 0;
  int             i = 0;
  struct ifreq    *item;
  struct sockaddr_in local,broadcast;

  /* Get a socket handle. */
  sck = socket(PF_INET, SOCK_DGRAM, 0);
  if(sck < 0) {
    return 1;
  }
 
  /* Query available interfaces. */
  ifc.ifc_len = sizeof(buf);
  ifc.ifc_buf = buf;
  if(ioctl(sck, SIOCGIFCONF, &ifc) < 0) {
    return 1;
  }

  /* Iterate through the list of interfaces. */
  ifr = ifc.ifc_req;
  nInterfaces = ifc.ifc_len / sizeof(struct ifreq); 
  for(i = 0; i < nInterfaces; i++) {
    item = &ifr[i];
    
    bcopy(&item->ifr_addr,&local,sizeof(local));      

    /* get broadcast address */
    if(ioctl(sck, SIOCGIFBRDADDR, item)== 0) {
      bcopy(&item->ifr_broadaddr,&broadcast,sizeof(broadcast));
    } else continue;

    printf("name=%s addr=%08x, broad=%08x\n",	   
	   item->ifr_name,
	   local.sin_addr,
	   broadcast.sin_addr);
    overlay_interface_register(item->ifr_name,local,broadcast);
  }
 
  return 0;
}
#endif
