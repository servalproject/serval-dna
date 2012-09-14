
#include "constants.h"
#include "mdp_client.h"
#include <poll.h>
#include <stdio.h>
#include <unistd.h>

char last_add[256]="dummy";

void store(char *key, char *value){
  // used by tests
  INFOF("PUBLISHED \"%s\" = \"%s\"", key, value);
  strncpy(value, last_add, sizeof(last_add));
  last_add[255]=0;
}

const char *retrieve(char *key){
  INFOF("RESOLVING \"%s\"", key);
  
  // dummy code, just reply with the last record we've heard
  return last_add;
}

void add_record(){
  int ttl;
  overlay_mdp_frame mdp;
  
  if (!overlay_mdp_recv(&mdp, &ttl))
    return;
  
  if (mdp.packetTypeAndFlags|=MDP_NOCRYPT)
    return WHY("Only encrypted packets will be considered for publishing");
  
  // make sure the payload is a NULL terminated string
  mdp.in.payload[mdp.in.payload_length]=0;
  
  char *did=(char *)mdp.in.payload;
  int i=0;
  while(i<mdp.in.payload_length && mdp.in.payload[i] && mdp.in.payload[i]!='|')
    i++;
  mdp.in.payload[i]=0;
  char *name = mdp.in.payload+i+1;
  char *sid = alloca_to_hex_sid(mdp.in.src.sid);
  
  // TODO check that did is a valid phone number
  
  char url[256];
  snprintf(url, sizeof(url), "sid://%s/%s|%s|%s", sid, did, did, name);
  store(did, url);
}

void process_line(char *line){
  char *token=line;
  char *p=line;
  while(*p && *p!='|') p++;
  *p++=0;
  char *did = p;
  while(*p && *p!='|') p++;
  *p++=0;
  
  const char *response = retrieve(did);
  if (response)
    printf("%s|%s|\n",token,response);
}

void resolve_request(){
  static char line_buff[1024];
  static int line_pos=0;
  
  int bytes = read(STDIN_FILENO, line_buff + line_pos, sizeof(line_buff) - line_pos);
  int i = line_pos;
  int processed=0;
  line_pos+=bytes;
  char *line_start=line_buff;
  
  for (;i<line_pos;i++){
    if (line_buff[i]=='\n'){
      line_buff[i]=0;
      if (*line_start)
	process_line(line_start);
      processed=i+1;
      line_start = line_buff + processed;
    }
  }
  
  if (processed){
    // squash unprocessed data back to the start of the buffer
    line_pos -= processed;
    bcopy(line_buff, line_start, line_pos);
  }
}

int main(int argc, char **argv){
  struct pollfd fds[2];

  // bind for incoming directory updates
  unsigned char srcsid[SID_SIZE];
  if (overlay_mdp_getmyaddr(0,srcsid)) return WHY("Could not get local address");
  if (overlay_mdp_bind(srcsid,MDP_PORT_DIRECTORY)) return WHY("Could not bind to MDP socket");
  
  set_nonblock(STDIN_FILENO);
  
  fds[0].fd = STDIN_FILENO;
  fds[0].events = POLLIN;
  fds[1].fd = mdp_client_socket;
  fds[1].events = POLLIN;
  
  fprintf(stderr, "Hello\n");
  
  while(1){
    int r = poll(fds, 2, 10000);
    if (r>0){
      if (fds[0].revents & POLLIN)
	resolve_request();
      if (fds[1].revents & POLLIN)
	add_record();
      
      if (fds[0].revents & (POLLHUP | POLLERR))
	break;
    }
    fprintf(stderr,".");
  }
  
  fprintf(stderr, "Bye\n");
  overlay_mdp_client_done();
  return 0;
}