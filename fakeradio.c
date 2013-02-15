#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>

int main(int argc,char **argv)
{
  int left=posix_openpt(O_RDWR|O_NOCTTY);
  grantpt(left); unlockpt(left);
  int right=posix_openpt(O_RDWR|O_NOCTTY);
  grantpt(right); unlockpt(right);
  fprintf(stdout,"%s\n",ptsname(left));
  fprintf(stdout,"%s\n",ptsname(right));

  fcntl(left,F_SETFL,fcntl(left, F_GETFL, NULL)|O_NONBLOCK);
  fcntl(right,F_SETFL,fcntl(right, F_GETFL, NULL)|O_NONBLOCK);

  struct pollfd fds[2];
  int i;
  char buffer[8192];

  fds[0].fd=left;
  fds[0].events=POLLIN;
  fds[1].fd=right;
  fds[1].events=POLLIN;

  while(1) {
    poll(fds,2,1000);
    for(i=0;i<2;i++) {
      if (fds[i].revents&POLLIN) {
	int bytes=read(fds[i].fd,buffer,sizeof(buffer));
	if (bytes>0) {
	  // every write operation consumes "air time" and adds delay to the next read
	  usleep(100000);
	  int fd = i^1;
	  
	  // set blocking
	  fcntl(fd,F_SETFL,fcntl(fd, F_GETFL, NULL)&~O_NONBLOCK);
	  
	  int offset=0;
	  while(offset < bytes){
	    int written = write(fds[i^1].fd,buffer+offset,bytes - offset);
	    if (written >0)
	      offset+=written;
	    else{
	      printf("Write returned %d, errno=%d\n",written,errno);
	      usleep(10000);
	    }
	  }
	  
	  // set non-blocking
	  fcntl(fd,F_SETFL,fcntl(fd, F_GETFL, NULL)|O_NONBLOCK);
	  
	  printf("reading from %d, read %d, written %d, errno=%d\n",i,bytes,offset,errno);
	}       
	fds[i].revents=0;
      }
      if (fds[i].revents&~POLLIN)
	printf("revents %x\n", fds[i].revents);
    }
  }

  return 0;
}
