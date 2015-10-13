/* 
Serval DNA directory service
Copyright (C) 2013 Serval Project Inc.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#ifdef HAVE_POLL_H
#include <poll.h>
#endif
#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include "serval.h"
#include "constants.h"
#include "mdp_client.h"
#include "str.h"

struct item{
  // simple tree structure
  struct item *_left;
  struct item *_right;
  char key[32];
  char value[128];
  time_ms_t expires;
};

struct item *root=NULL;
static uint8_t allow_duplicates = 1;

static struct item *create_item(const char *key){
  struct item *ret=calloc(1,sizeof(struct item));
  buf_strncpy_nul(ret->key, key);
  return ret;
}

static struct item *find_item(const char *key){
  struct item *item = root;
  
  while(item){
    int c=strcmp(item->key, key);
    if (c==0)
      return item;
    if (c<0){
      item = item->_left;
    }else{
      item = item->_right;
    }
  }
  return NULL;
}

static int add_item(const char *key, const char *value){
  struct item *item = root, **last_ptr=&root;
  while(item){
    int c=strcmp(item->key, key);
    if (c==0){
      c=strcmp(item->value, value);
      if (c==0){
	item->expires = gettime_ms()+1200000;
	return 1;
      }else if(!allow_duplicates)
	return -1;
    }
    if (c<0){
      last_ptr = &item->_left;
    }else{
      last_ptr = &item->_right;
    }
    item = *last_ptr;
  }
  
  *last_ptr = item = create_item(key);
  
  buf_strncpy_nul(item->value, value);

  // expire after 20 minutes
  item->expires = gettime_ms()+1200000;
  return 0;
}

static int add_record(int mdp_sockfd){
  struct mdp_header header;
  uint8_t payload[MDP_MTU];
  
  ssize_t len = mdp_recv(mdp_sockfd, &header, payload, sizeof payload);
  if (len == -1)
    return WHY_perror("mdp_recv");
  
  if (header.flags & (MDP_FLAG_NO_CRYPT|MDP_FLAG_NO_SIGN))
    return WHY("Only encrypted packets will be considered for publishing\n");
  
  // make sure the payload is a NULL terminated string
  assert((size_t)len < sizeof payload);
  payload[(size_t)len]=0;
  
  const char *did=(const char *)payload;
  unsigned i=0;
  while (i<(size_t)len && payload[i] && payload[i]!='|')
    i++;
  payload[i]=0;
  const char *name = (const char *)payload+i+1;
  const char *sid = alloca_tohex_sid_t(header.remote.sid);
  
  // TODO check that did is a valid phone number
  
  char url[256];
  snprintf(url, sizeof(url), "sid://%s/local/%s|%s|%s", sid, did, did, name);
  
  // TODO only add whitelisted entries
  
  int r=add_item(did, url);
  if (r==0){
    // used by tests
    fprintf(stderr, "PUBLISHED \"%s\" = \"%s\"\n", did, url);
  }
  uint8_t response = (r==-1 ? 0:1);
  if (mdp_send(mdp_sockfd, &header, &response, sizeof response)==-1)
    return WHY_perror("mdp_send");
  return 0;
}

static void respond(char *token, struct item *item, char *key){
  if (!item)
    return;
  
  int c = strcmp(item->key, key);
  if (c<=0)
    respond(token, item->_left, key);
  if (c==0 && item->expires > gettime_ms())
    printf("%s|%s|\n",token,item->value);
  if (c>=0)
    respond(token, item->_right, key);
}

static void process_line(char *line){
  char *token=line;
  char *p=line;
  while(*p && *p!='|') p++;
  *p++=0;
  char *did = p;
  while(*p && *p!='|') p++;
  *p++=0;
  
  respond(token, find_item(did), did);
  printf("DONE\n");
  fflush(stdout);
}

static void resolve_request(){
  static char line_buff[1024];
  static int line_pos=0;
  
  set_nonblock(STDIN_FILENO);
  
  int bytes = read(STDIN_FILENO, line_buff + line_pos, sizeof(line_buff) - line_pos);
  
  set_block(STDIN_FILENO);
  
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

void cf_on_config_change()
{
}

int main(void){
  struct pollfd fds[2];
  int mdp_sockfd;

  if ((mdp_sockfd = mdp_socket()) < 0)
    return WHY("Cannot create MDP socket");

  // bind for incoming directory updates
  struct mdp_sockaddr local_addr = {.sid = BIND_PRIMARY, .port = MDP_PORT_DIRECTORY};
  
  if (mdp_bind(mdp_sockfd, &local_addr)==-1)
    return WHY_perror("mdp_bind");
  
  fds[0].fd = STDIN_FILENO;
  fds[0].events = POLLIN;
  fds[1].fd = mdp_sockfd;
  fds[1].events = POLLIN;
  
  printf("STARTED\n");
  fflush(stdout);
  
  while(1){
    int r = poll(fds, 2, 100);
    if (r>0){
      if (fds[0].revents & POLLIN)
        resolve_request();
      if (fds[1].revents & POLLIN)
	add_record(mdp_sockfd);
      
      if (fds[0].revents & (POLLHUP | POLLERR))
	break;
    }
  }
  
  mdp_close(mdp_sockfd);
  return 0;
}
