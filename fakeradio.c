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
  fds[2].events=POLLIN;

  while(1) {
    poll(fds,2,1000);
    for(i=0;i<2;i++) {
      if (1||fds[i].revents&POLLIN) {
	int bytes=read(fds[i].fd,buffer,8192);
	if (bytes>0) {
	  write(fds[i^1].fd,buffer,bytes);
	  printf("reading from %d, read %d, errno=%d\n",i,bytes,errno);
	}       
	fds[i].revents=0;
      }
    }
    usleep(100000);

  }

  return 0;
}
