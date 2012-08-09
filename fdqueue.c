/*
Serval Distributed Numbering Architecture (DNA)
Copyright (C) 2012 Paul Gardner-Stephen
 
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

#include "serval.h"
#include "strbuf.h"
#include "strbuf_helpers.h"
#include <poll.h>

#define MAX_WATCHED_FDS 128
struct pollfd fds[MAX_WATCHED_FDS];
int fdcount=0;
struct sched_ent *fd_callbacks[MAX_WATCHED_FDS];
struct sched_ent *next_alarm=NULL;
struct sched_ent *next_deadline=NULL;
struct profile_total poll_stats={NULL,0,"Idle (in poll)",0,0,0};

void list_alarms() {
  DEBUG("Alarms;");
  time_ms_t now = gettime_ms();
  struct sched_ent *alarm;
  for (alarm = next_alarm; alarm; alarm = alarm->_next)
    DEBUGF("%s in %lldms", (alarm->stats ? alarm->stats->name : "Unnamed"), alarm->alarm - now);
  DEBUG("File handles;");
  int i;
  for (i = 0; i < fdcount; ++i)
    DEBUGF("%s watching #%d", (fd_callbacks[i]->stats ? fd_callbacks[i]->stats->name : "Unnamed"), fds[i].fd);
}

int deadline(struct sched_ent *alarm){
  struct sched_ent *node = next_deadline, *last = NULL;
  if (alarm->deadline < alarm->alarm)
    alarm->deadline = alarm->alarm;
  
  while(node!=NULL){
    if (node->alarm > alarm->alarm)
      break;
    last = node;
    node = node->_next;
  }
  if (last == NULL){
    next_deadline = alarm;
  }else{
    last->_next=alarm;
  }
  alarm->_prev = last;
  if(node!=NULL)
    node->_prev = alarm;
  alarm->_next = node;
  return 0;
}


// add an alarm to the list of scheduled function calls.
// simply populate .alarm with the absolute time, and .function with the method to call.
// on calling .poll.revents will be zero.
int schedule(struct sched_ent *alarm){
  struct sched_ent *node = next_alarm, *last = NULL;
  
  if (!alarm->function)
    return WHY("Can't schedule if you haven't set the function pointer");
  
  if (alarm->deadline < alarm->alarm)
    alarm->deadline = alarm->alarm;
  
  // if the alarm has already expired, move straight to the deadline queue
  if (alarm->alarm <= gettime_ms())
    return deadline(alarm);
  
  while(node!=NULL){
    if (node->alarm > alarm->alarm)
      break;
    last = node;
    node = node->_next;
  }
  if (last == NULL){
    next_alarm = alarm;
  }else{
    last->_next=alarm;
  }
  alarm->_prev = last;
  if(node!=NULL)
    node->_prev = alarm;
  alarm->_next = node;
  
  return 0;
}

// remove a function from the schedule before it has fired
// safe to unschedule twice...
int unschedule(struct sched_ent *alarm){
  struct sched_ent *prev = alarm->_prev;
  struct sched_ent *next = alarm->_next;
  
  if (prev)
    prev->_next = next;
  else if(next_alarm==alarm)
    next_alarm = next;
  else if(next_deadline==alarm)
    next_deadline = next;
  
  if (next)
    next->_prev = prev;
  
  alarm->_prev = NULL;
  alarm->_next = NULL;
  return 0;
}

// start watching a file handle, call this function again if you wish to change the event mask
int watch(struct sched_ent *alarm){
  if (!alarm->function)
    return WHY("Can't watch if you haven't set the function pointer");
  
  if (alarm->_poll_index>=0 && fd_callbacks[alarm->_poll_index]==alarm){
    // updating event flags
    if (debug & DEBUG_IO)
      DEBUGF("Updating watch %s, #%d for %d", (alarm->stats?alarm->stats->name:"Unnamed"), alarm->poll.fd, alarm->poll.events);
  }else{
    if (debug & DEBUG_IO)
      DEBUGF("Adding watch %s, #%d for %d", (alarm->stats?alarm->stats->name:"Unnamed"), alarm->poll.fd, alarm->poll.events);
    if (fdcount>=MAX_WATCHED_FDS)
      return WHY("Too many file handles to watch");
    fd_callbacks[fdcount]=alarm;
    alarm->poll.revents = 0;
    alarm->_poll_index=fdcount;
    fdcount++;
  }
  fds[alarm->_poll_index]=alarm->poll;
  return 0;
}

// stop watching a file handle
int unwatch(struct sched_ent *alarm){
  int index = alarm->_poll_index;
  if (index <0 || fds[index].fd!=alarm->poll.fd)
    return WHY("Attempted to unwatch a handle that is not being watched");
  
  fdcount--;
  if (index!=fdcount){
    // squash fds
    fds[index] = fds[fdcount];
    fd_callbacks[index] = fd_callbacks[fdcount];
    fd_callbacks[index]->_poll_index=index;
  }
  fds[fdcount].fd=-1;
  fd_callbacks[fdcount]=NULL;
  alarm->_poll_index=-1;
  if (debug & DEBUG_IO)
    DEBUGF("%s stopped watching #%d for %d", (alarm->stats?alarm->stats->name:"Unnamed"), alarm->poll.fd, alarm->poll.events);
  return 0;
}

void call_alarm(struct sched_ent *alarm, int revents){
  struct call_stats call_stats;
  call_stats.totals = alarm->stats;
  
  if (call_stats.totals)
    fd_func_enter(&call_stats);
  
  alarm->poll.revents = revents;
  alarm->function(alarm);
  
  if (call_stats.totals)
    fd_func_exit(&call_stats);
}

int fd_poll()
{
  int i, r;
  int ms=60000;
  time_ms_t now = gettime_ms();
  
  /* move alarms that have elapsed to the deadline queue */
  while (next_alarm!=NULL&&next_alarm->alarm <=now){
    struct sched_ent *alarm = next_alarm;
    unschedule(alarm);
    deadline(alarm);
  }
  
  /* work out how long we can block in poll */
  if (next_deadline)
    ms = 0;
  else if (next_alarm){
    ms = next_alarm->alarm - now;
  }
  
  /* Make sure we don't have any silly timeouts that will make us wait forever. */
  if (ms<0) ms=0;
  
  /* check if any file handles have activity */
  {
    struct call_stats call_stats;
    call_stats.totals=&poll_stats;
    fd_func_enter(&call_stats);
    r = poll(fds, fdcount, ms);
    if (debug & DEBUG_IO) {
      strbuf b = strbuf_alloca(1024);
      int i;
      for (i = 0; i < fdcount; ++i) {
	if (i)
	  strbuf_puts(b, ", ");
	strbuf_sprintf(b, "%d:", fds[i].fd);
	strbuf_append_poll_events(b, fds[i].events);
	strbuf_putc(b, ':');
	strbuf_append_poll_events(b, fds[i].revents);
      }
      DEBUGF("poll(fds=(%s), fdcount=%d, ms=%d) = %d", strbuf_str(b), fdcount, ms, r);
    }
    fd_func_exit(&call_stats);
    now=gettime_ms();
  }
  
  /* call one alarm function, but only if its deadline time has elapsed OR there is no file activity */
  if (next_deadline && (next_deadline->deadline <=now || (r==0))){
    struct sched_ent *alarm = next_deadline;
    unschedule(alarm);
    call_alarm(alarm, 0);
    now=gettime_ms();
  }
  
  /* If file descriptors are ready, then call the appropriate functions */
  if (r>0) {
    for(i=0;i<fdcount;i++)
      if (fds[i].revents) {
	/* Call the alarm callback with the socket in non-blocking mode */
	set_nonblock(fds[i].fd);
	call_alarm(fd_callbacks[i], fds[i].revents);
	if (fds[i].fd != -1)
	  set_block(fds[i].fd);
      }
  }
  return 0;
}
