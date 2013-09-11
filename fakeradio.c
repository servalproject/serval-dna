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

int radio_packet_size=256;
int chars_per_ms=1;
long ber=0;

struct radio_state {
  int fd;
  int state;
  const char *name;
  char commandbuffer[128];
  int cb_len;
  unsigned char txbuffer[1024];
  int txb_len;
  unsigned char rxbuffer[1024];
  int rxb_len;
  long long last_char_ms;
  long long next_rssi_time_ms;
  int rssi_output;
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

void log_time(){
  struct timeval tv;
  struct tm tm;
  gettimeofday(&tv, NULL);
  localtime_r(&tv.tv_sec, &tm);
  char buf[50];
  if (strftime(buf, sizeof buf, "%T", &tm) == 0)
    fprintf(stderr, "EMPTYTIME___ ");
  else
    fprintf(stderr, "%s.%03u ", buf, (unsigned int)tv.tv_usec / 1000);
}

int append_bytes(struct radio_state *s, const char *bytes, int len)
{
  if (len==-1)
    len = strlen(bytes);
  if (len + s->rxb_len > sizeof(s->rxbuffer))
    return -1;
  bcopy(bytes, &s->rxbuffer[s->rxb_len], len);
  s->rxb_len+=len;
  return len;
}

int processCommand(struct radio_state *s)
{
  if (!s->cb_len) return 0;
  s->commandbuffer[s->cb_len]=0;
  char *cmd=s->commandbuffer;
  
  log_time();
  fprintf(stderr, "Processing command from %s \"%s\"\n", s->name, cmd);
  
  if (!strcasecmp(cmd,"ATO")) {
    append_bytes(s, "OK\r", -1);
    s->state=STATE_ONLINE;
    return 0;
  }
  if (!strcasecmp(cmd,"AT&T")) {
    append_bytes(s, "OK\r", -1);
    s->rssi_output=0;
    return 0;
  }
  if (!strcasecmp(cmd,"AT&T=RSSI")) {
    append_bytes(s, "OK\r", -1);
    s->rssi_output=1;
    return 0;
  }
  if (!strcasecmp(cmd,"ATI")) {
    append_bytes(s, "RFD900a SIMULATOR 1.6\rOK\r", -1);
    return 0;
  }
  append_bytes(s, "ERROR\r", -1);
  return 1;
}

int dump(char *name, unsigned char *addr, int len)
{
  int i,j;
  if (name)
    fprintf(stderr,"Dump of %s\n",name);
  for(i=0;i<len;i+=16){
    fprintf(stderr,"  %04x :",i);
    for(j=0;j<16&&(i+j)<len;j++) 
      fprintf(stderr," %02x",addr[i+j]);
    for(;j<16;j++) 
      fprintf(stderr,"   ");
    fprintf(stderr,"    ");
    for(j=0;j<16&&(i+j)<len;j++)
      fprintf(stderr,"%c",addr[i+j]>=' '&&addr[i+j]<0x7f?addr[i+j]:'.');
    fprintf(stderr,"\n");
  }
  return 0;
}

int read_bytes(struct radio_state *s)
{
  unsigned char buff[256];
  int i;
  int bytes=read(s->fd,buff,sizeof(buff));
  if (bytes<=0)
    return bytes;
  log_time();
  fprintf(stderr, "Read from %s\n", s->name);
  dump(NULL,buff,bytes);
  s->last_char_ms = gettime_ms();
  
  // process incoming bytes
  for (i=0;i<bytes;i++){
    
    // either append to a command buffer
    if (s->state==STATE_COMMAND){
      if (buff[i]=='\r'||buff[i]=='\n'){
	// and process the commend on EOL
	processCommand(s);
	s->cb_len=0;
      }else if (s->cb_len<127)
	s->commandbuffer[s->cb_len++]=buff[i];
      continue;
    }
    
    // or watch for "+++"
    if (buff[i]=='+'){
      // consume 3 +'s
      if (s->state < STATE_PLUSPLUSPLUS){
	s->state++;
      }else if(s->txb_len<sizeof(s->txbuffer)){
	s->txbuffer[s->txb_len++]=buff[i];
      }
      continue;
    }
    
    // regenerate any +'s we consumed
    while(s->state > STATE_ONLINE){
      if(s->txb_len<sizeof(s->txbuffer))
	s->txbuffer[s->txb_len++]='+';
      s->state--;
    }
    
    // or append to the transmit buffer if there's room
    if(s->txb_len<sizeof(s->txbuffer))
      s->txbuffer[s->txb_len++]=buff[i];
  }
  return bytes;
}

int write_bytes(struct radio_state *s)
{
  int wrote = write(s->fd, s->rxbuffer, s->rxb_len);
  if (wrote>0){
    log_time();
    fprintf(stderr, "Wrote to %s\n", s->name);
    dump(NULL, s->rxbuffer, wrote);
    if (wrote < s->rxb_len)
      bcopy(&s->rxbuffer[wrote], s->rxbuffer, s->rxb_len - wrote);
    s->rxb_len -= wrote;
  }
  return wrote;
}

int transmitter=0;
long long next_transmit_time=0;

int transfer_bytes(struct radio_state *radios)
{
  // if there's data to transmit, copy a radio packet from one device to the other
  int receiver = transmitter^1;
  struct radio_state *r = &radios[receiver];
  struct radio_state *t = &radios[transmitter];
  int bytes=t->txb_len;
  
  // TODO detect MAVLINK frame header
  // respond to heartbeats?
  // only transmit if we have read the entire mavlink packet
  
  if (bytes > radio_packet_size)
    bytes = radio_packet_size;
    
  if (bytes>0){
    log_time();
    fprintf(stderr, "Transferring %d byte packet from %s to %s\n", bytes, t->name, r->name);
  }
  int i, j;
  for (i=0;i<bytes && r->rxb_len<sizeof(r->rxbuffer);i++){
    char byte = t->txbuffer[i];
    // introduce bit errors
    for(j=0;j<8;j++) {
      if (random()<ber) {
	byte^=(1<<j);
	fprintf(stderr,"Flipped a bit\n");
      }
    }
    r->rxbuffer[r->rxb_len++]=byte;
  }
  
  if (bytes>0 && bytes < t->txb_len)
    bcopy(&t->txbuffer[bytes], t->txbuffer, t->txb_len - bytes);
  t->txb_len-=bytes;
  
  // swap who's turn it is to transmit
  transmitter = receiver;
  
  // set the wait time for the next transmission
  next_transmit_time = gettime_ms() + (bytes+10)/chars_per_ms;
  return bytes;
}

int main(int argc,char **argv)
{
  if (argv[1]) {
    chars_per_ms=atol(argv[1]);
    if (argv[2]) 
      ber=atol(argv[2]);
  }
  fprintf(stderr, "Sending %d bytes per ms\n", chars_per_ms);
  fprintf(stderr, "Introducing %f%% bit errors\n", (ber * 100.0) / 0xFFFFFFFF);

  struct pollfd fds[2];
  struct radio_state radios[2];
  
  bzero(&radios,sizeof radios);
  
  int i;
  for (i=0;i<2;i++){
    radios[i].fd=posix_openpt(O_RDWR|O_NOCTTY);
    grantpt(radios[i].fd);
    unlockpt(radios[i].fd);
    fcntl(radios[i].fd,F_SETFL,fcntl(radios[i].fd, F_GETFL, NULL)|O_NONBLOCK);
    fprintf(stdout,"%s\n",ptsname(radios[i].fd));
    fds[i].fd = radios[i].fd;
  }
  radios[0].name="left";
  radios[1].name="right";
  fflush(stdout);

  while(1) {
    // what events do we need to poll for? how long can we block?
    long long now = gettime_ms();
    long long next_event = now+10000;
    
    for (i=0;i<2;i++){
      // always watch for incoming data, though we will throw it away if we run out of buffer space
      fds[i].events = POLLIN;
      // if we have data to write data, watch for POLLOUT too.
      if (radios[i].rxb_len)
	fds[i].events |= POLLOUT;
      
      if (radios[i].rssi_output && next_event > radios[i].next_rssi_time_ms)
	next_event = radios[i].next_rssi_time_ms;
      
      if (radios[i].state==STATE_PLUSPLUSPLUS && next_event > radios[i].last_char_ms+1000)
	next_event = radios[i].last_char_ms+1000;
      
      if (radios[i].txb_len && next_event > next_transmit_time)
	next_event = next_transmit_time;
    }
    
    int delay = next_event - now;
    if (delay<0)
      delay=0;
    
    poll(fds,2,delay);
    
    for (i=0;i<2;i++){
      
      if (fds[i].revents & POLLIN)
	read_bytes(&radios[i]);
	
      if (fds[i].revents & POLLOUT)
	write_bytes(&radios[i]);
      
      now = gettime_ms();
      if (radios[i].rssi_output && now >= radios[i].next_rssi_time_ms){
	if (append_bytes(&radios[i], "L/R RSSI: 200/190  L/R noise: 80/70 pkts: 10  txe=0 rxe=0 stx=0 srx=0 ecc=0/0 temp=42 dco=0\r\n", -1)>0)
	  radios[i].next_rssi_time_ms=now+1000;
      }
      
      if (radios[i].state==STATE_PLUSPLUSPLUS && now >= radios[i].last_char_ms+1000){
	fprintf(stderr, "Detected +++ from %s\n",radios[i].name);
	if (append_bytes(&radios[i], "OK\r\n", -1)>0)
	  radios[i].state=STATE_COMMAND;
      }
    }
    
    if (now >= next_transmit_time)
      transfer_bytes(radios);
  }
  
  return 0;
}
