#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>

int main(int argc, char *argv[]) {
  struct sockaddr_un addr;
  int fd;

  if ( (fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
    perror("socket error");
    exit(-1);
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  addr.sun_path[0]=0;
  snprintf(&addr.sun_path[1],100,"org.servalproject.servald.monitor.socket");
  int len = 1+strlen(&addr.sun_path[1]) + sizeof(addr.sun_family);
  char *p=(char *)&addr;
  printf("last char='%c' %02x\n",p[len-1],p[len-1]);

  if (connect(fd, (struct sockaddr*)&addr, len) == -1) {
    perror("connect error");
    exit(-1);
  }

  fcntl(fd,F_SETFL,
	fcntl(fd, F_GETFL, NULL)|O_NONBLOCK);
  fcntl(STDIN_FILENO,F_SETFL,
	fcntl(STDIN_FILENO, F_GETFL, NULL)|O_NONBLOCK);

  struct pollfd fds[128];
  int fdcount=0;

  fds[fdcount].fd=fd;
  fds[fdcount].events=POLLIN;
  fdcount++;
  fds[fdcount].fd=STDIN_FILENO;
  fds[fdcount].events=POLLIN;
  fdcount++;

  while(1) {
    poll(fds,fdcount,1000);

    char line[1024];
    int bytes;
    bytes=read(fd,line,1024);
    if (bytes>0)
      write(STDOUT_FILENO,line,bytes);
    bytes=read(STDIN_FILENO,line,1024);
    if (bytes>0) {
      write(STDOUT_FILENO,line,bytes);
      write(fd,line,bytes);
    }
  }
  
  return 0;
}
