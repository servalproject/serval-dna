#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>

int fd;
int writeLine(char *msg)
{
  write(fd,msg,strlen(msg));
}

int main(int argc, char *argv[]) {
  struct sockaddr_un addr;

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

  writeLine("monitor vomp\n");
  writeLine("monitor rhizome\n");

  if (argc>1) {
    char msg[1024];
    snprintf(msg,1024,"call %s 5551 5552\n",argv[1]);
    writeLine(msg);
  }

  while(1) {
    poll(fds,fdcount,1000);

    char line[1024];
    int bytes;
    int i;
    bytes=read(fd,line,1024);
    if (bytes>0)
      for(i=0;i<bytes;i++) processChar(line[i]);
    bytes=read(STDIN_FILENO,line,1024);
    if (bytes>0) {
      line[bytes]=0;
      printf("< %s",line);
      write(fd,line,bytes);
    }
  }
  
  return 0;
}

int callState=0;
int processLine(char *cmd,unsigned char *data,int dataLen)
{
  int l_id,r_id,l_state,r_state;
  printf("> %s\n",cmd);
  if (data) {
    int i,j;
    for(i=0;i<dataLen;i+=16) {
      printf("   %04x :",i);
      for(j=0;j<16;j++) 
	if (i+j<dataLen) printf(" %02x",data[i+j]); else printf("   ");
      printf("  ");
      for(j=0;j<16;j++) 
	if (i+j<dataLen) {
	  if (data[i+j]>=0x20&&data[i+j]<0x7e)
	    printf("%c",data[i+j]); else printf(".");
	}
      printf("\n");
    }
  }
  if (sscanf(cmd,"CALLSTATUS:%x:%x:%d:%d",
	     &l_id,&r_id,&l_state,&r_state)==4)
    {
      if (l_state==4) {
	// We are ringing, so pickup
	char msg[1024];
	sprintf(msg,"pickup %x\n",l_id);
	writeLine(msg);
      }
      callState=l_state;
    }
  if (sscanf(cmd,"KEEPALIVE:%x",&l_id)==1) {
    if (callState==5) {
      /* Send synthetic audio packet */
      char buffer[1024];
      sprintf(buffer,"*320:AUDIO:%x:8\n"
	      "qwertyuiopasdfghjklzxcvbnm123456"
	      "qwertyuiopasdfghjklzxcvbnm123456"
	      "qwertyuiopasdfghjklzxcvbnm123456"
	      "qwertyuiopasdfghjklzxcvbnm123456"
	      "qwertyuiopasdfghjklzxcvbnm123456"
	      "qwertyuiopasdfghjklzxcvbnm123456"
	      "qwertyuiopasdfghjklzxcvbnm123456"
	      "qwertyuiopasdfghjklzxcvbnm123456"
	      "qwertyuiopasdfghjklzxcvbnm123456"
	      "qwertyuiopasdfghjklzxcvbnm123456",l_id);
      writeLine(buffer);
      printf("< *320:AUDIO:%x:8\\n<320 bytes>\n",l_id);
    }
  }

}

char cmd[1024];
int cmdLen=0;
int cmdOfs=0;
int dataBytesExpected=0;
unsigned char data[65536];
int dataBytes=0;

#define STATE_CMD 1
#define STATE_DATA 2
int state=STATE_CMD;
int processChar(int c)
{
  switch(state) {
  case STATE_CMD:
    if (c!='\n') {
      if (cmdLen<1000) {
	cmd[cmdLen++]=c;
      }
    } else {
      if (!cmdLen) return 0;
      cmd[cmdLen]=0;
      if (sscanf(cmd,"*%d:%n",&dataBytesExpected,&cmdOfs)==1) {
	if (dataBytesExpected<0) dataBytesExpected=0;
	if (dataBytesExpected>65535) dataBytesExpected=65535;
	state=STATE_DATA;
      } else {
	processLine(cmd,NULL,0);
	cmdLen=0;
      }
    }
    break;
  case STATE_DATA:
    if (dataBytes<dataBytesExpected)
      data[dataBytes++]=c;
    if (dataBytes>=dataBytesExpected) {
      processLine(&cmd[cmdOfs],data,dataBytes);
      cmdLen=0;
    }
  }      
}
