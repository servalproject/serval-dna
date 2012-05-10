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

/* for when all other options fail, as can happen on Android,
   if the permissions for the socket-based method are broken.
   Down side is that it while it gets the interface name and
   broadcast, it doesn't get the local address for that
   interface. 
*/
int scrapeProcNetRoute()
{
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
	  overlay_interface_register((unsigned char *)name,local,broadcast);
	}
      }

    line[0]=0; fgets(line,1024,f);    
  }
  fclose(f);
  return 0;
}

#ifdef ANDROID
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
    fprintf(stderr,"Failed to gt socket handle to list addresses, errno=%d\n",
	    errno);
    return 1;
  }
 
  /* Query available interfaces. */
  ifc.ifc_len = sizeof(buf);
  ifc.ifc_buf = buf;
  if(ioctl(sck, SIOCGIFCONF, &ifc) < 0) {
    fprintf(stderr,"Failed to read interface list\n");
    return 1;
  }

  /* Iterate through the list of interfaces. */
  ifr = ifc.ifc_req;
  nInterfaces = ifc.ifc_len / sizeof(struct ifreq); 
  fprintf(stderr,"Examining %d interfaces\n",nInterfaces);
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
  close(sck); 
  return 0;
}
#endif
