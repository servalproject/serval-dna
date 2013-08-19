#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <strings.h>
#include <string.h>
#include <unistd.h>

struct radio_state {
  int state;
  char commandbuffer[128];
  int cb_len;
  unsigned char txbuffer[1024];
  int txb_len;
  long long last_char_ms;
  long long last_tx_ms;
  long long last_rssi_time_ms;
  int rssi_output;
  int tx_rate;
};

#define STATE_ONLINE 0
#define STATE_PLUS 1
#define STATE_PLUSPLUS 2
#define STATE_PLUSPLUSPLUS 3
#define STATE_COMMAND 4

long long gettime_ms()
{
  struct timeval nowtv;
  // If gettimeofday() fails or returns an invalid value, all else is lost!
  if (gettimeofday(&nowtv, NULL) == -1)
    perror("gettimeofday");
  return nowtv.tv_sec * 1000LL + nowtv.tv_usec / 1000;
}

int emit(int fd,char *s)
{
  return write(fd,s,strlen(s));
}

int processCommand(int fd,struct radio_state *s,int out_fd)
{
  if (!s->cb_len) return 0;
  s->commandbuffer[s->cb_len]=0;
  char *cmd=s->commandbuffer;
  if (!strcasecmp(cmd,"ATO")) {
    emit(fd,"OK\r");
    s->state=STATE_ONLINE;
    return 0;
  }
  if (!strcasecmp(cmd,"AT&T")) {
    emit(fd,"OK\r");
    s->rssi_output=0;
    return 0;
  }
  if (!strcasecmp(cmd,"AT&T=RSSI")) {
    emit(fd,"OK\r");
    s->rssi_output=1;
    return 0;
  }
  if (!strcasecmp(cmd,"ATI")) {
    emit(fd,"RFD900a SIMULATOR 1.6\r");
    emit(fd,"OK\r");
    return 0;
  }
  emit(fd,"ERROR\r");
  return 1;
}

int print_report=0;

int updateState(int fd,struct radio_state *s,int out_fd)
{
  int i;

  print_report=0;

  // Read bytes from stdin
  int bytes=read(fd,&s->txbuffer[s->txb_len],sizeof(s->txbuffer)-s->txb_len);
  if (bytes>0) { s->txb_len+=bytes; print_report=1; }

  // Switch to command mode if required
  if (bytes<1&&s->state==STATE_PLUSPLUSPLUS&&
      (gettime_ms()-s->last_char_ms)>=1000) {
    s->state=STATE_COMMAND;
    print_report=1;
    emit(fd,"OK\r\n");
  } else
    if (bytes>0) 
      s->last_char_ms=gettime_ms();

  if (bytes>0) { 
    fprintf(stderr,"Received %d bytes: ",bytes);
    for(i=0;i<bytes&&i<32;i++) {
      unsigned char c=s->txbuffer[s->txb_len-bytes+i];
      if (c>=' '&&c<0x7d) fprintf(stderr,"%c",c); else fprintf(stderr,"?");      
    }
    if (bytes>20) fprintf(stderr,"...");
    fprintf(stderr,"\n");
  }

  // work out how many bytes we can dispatch
  long long tx_count_allowed=gettime_ms()-s->last_tx_ms;

  // now go through the TX buffer and dispatch them
  // (or change state as appropriate)
  for(i=0;i<tx_count_allowed;i++) {
    if (s->txb_len<1) break;
    switch(s->state) {
    case STATE_ONLINE:
      if (s->txbuffer[0]!='+') { 
	s->state=STATE_ONLINE;
	char c[2]; c[0]=s->txbuffer[0]; c[1]=0;
	emit(out_fd,c);
      } else { s->state=STATE_PLUS; i--; }
      break;
    case STATE_PLUS:
      if (s->txbuffer[0]!='+') { 
	s->state=STATE_ONLINE;
	emit(out_fd,"+"); i+=1;
      } else { s->state=STATE_PLUSPLUS; i--; }
      break;
    case STATE_PLUSPLUS:
      if (s->txbuffer[0]!='+') { 
	s->state=STATE_ONLINE;
	emit(out_fd,"++"); i+=2;
      } else { s->state=STATE_PLUSPLUSPLUS; i--; }
      break;
    case STATE_PLUSPLUSPLUS: 
      if (s->txbuffer[0]!='+') { 
	s->state=STATE_ONLINE;
	emit(out_fd,"+++"); i+=3;
      } else { 
	// more than 3 pluses, so start outputting the
	// extras
	emit(out_fd,"+"); i+=1;
	s->state=STATE_PLUSPLUSPLUS; i--; 
      }
      break;
    case STATE_COMMAND:
      {
	char c[2];
	c[0]=s->txbuffer[0]; c[1]=0;
	emit(fd,c);
	if (s->txbuffer[0]=='\r'||s->txbuffer[0]=='\n') {
	  // end of command
	  processCommand(fd,s,out_fd);
	  s->cb_len=0;
	} else {
	  if (s->cb_len<127) {
	    s->commandbuffer[s->cb_len++]=s->txbuffer[0];
	  }
	}
      }
    }
    // Remove processed character
    if (s->txb_len>0) {
      bcopy(&s->txbuffer[1],&s->txbuffer[0],s->txb_len);
      s->txb_len--;
    }
  }
  
  // Remember the current time for TX throttling
  s->last_tx_ms=gettime_ms();

  // Output radio link status if requested
  if (s->rssi_output&&(gettime_ms()-s->last_rssi_time_ms)>=1000) {
    emit(fd,"L/R RSSI: 200/190  L/R noise: 80/70 pkts: 10  txe=0 rxe=0 stx=0 srx=0 ecc=0/0 temp=42 dco=0\r\n");
    s->last_rssi_time_ms=gettime_ms();
  }

  if (print_report) {
    s->commandbuffer[s->cb_len]=0;
    fprintf(stderr,"Radio #%d state: %d rssi_output=%d cbuf='%s', txb_len=%d\n",
	    fd,s->state,s->rssi_output,s->commandbuffer,s->txb_len);
  }
  return 0;
}

int main(int argc,char **argv)
{
  struct radio_state left_state,right_state;
  bzero(&left_state,sizeof left_state);
  bzero(&right_state,sizeof right_state);
  // set actual throughput to match real RFD900 radios running at 128kbit with golay encoding
  // (assumes 70% efficiency for TDMA)
  left_state.tx_rate=128000/2*0.7;
  right_state.tx_rate=128000/2*0.7;

  int left=posix_openpt(O_RDWR|O_NOCTTY);
  grantpt(left); unlockpt(left);
  int right=posix_openpt(O_RDWR|O_NOCTTY);
  grantpt(right); unlockpt(right);
  fprintf(stdout,"%s\n",ptsname(left));
  fprintf(stdout,"%s\n",ptsname(right));
  fflush(stdout);

  fcntl(left,F_SETFL,fcntl(left, F_GETFL, NULL)|O_NONBLOCK);
  fcntl(right,F_SETFL,fcntl(right, F_GETFL, NULL)|O_NONBLOCK);

  struct pollfd fds[2];
  int i;

  fds[0].fd=left;
  fds[0].events=POLLIN;
  fds[1].fd=right;
  fds[1].events=POLLIN;

  while(1) {
    poll(fds,2,10);
    updateState(left,&left_state,right);
    updateState(right,&right_state,left);
    for(i=0;i<2;i++) {
      fds[i].revents=0;
      if (fds[i].revents&~POLLIN)
	printf("revents %x\n", fds[i].revents);
    }
  }
  
  return 0;
}
