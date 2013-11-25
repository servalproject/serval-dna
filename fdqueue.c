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

#include "fdqueue.h"
#include "conf.h"
#include "str.h"
#include "strbuf.h"
#include "strbuf_helpers.h"

#define MAX_WATCHED_FDS 128
struct pollfd fds[MAX_WATCHED_FDS];
int fdcount=0;
struct sched_ent *fd_callbacks[MAX_WATCHED_FDS];
struct sched_ent *next_alarm=NULL;
struct sched_ent *next_deadline=NULL;
struct profile_total poll_stats={NULL,0,"Idle (in poll)",0,0,0};

#define alloca_alarm_name(alarm) ((alarm)->stats ? alloca_str_toprint((alarm)->stats->name) : "Unnamed")

void list_alarms()
{
  DEBUG("Alarms;");
  time_ms_t now = gettime_ms();
  struct sched_ent *alarm;
  
  for (alarm = next_deadline; alarm; alarm = alarm->_next)
    DEBUGF("%p %s deadline in %"PRId64"ms", alarm->function, alloca_alarm_name(alarm), alarm->deadline - now);
  
  for (alarm = next_alarm; alarm; alarm = alarm->_next)
    DEBUGF("%p %s in %"PRId64"ms, deadline in %"PRId64"ms", alarm->function, alloca_alarm_name(alarm), alarm->alarm - now, alarm->deadline - now);
  
  DEBUG("File handles;");
  int i;
  for (i = 0; i < fdcount; ++i)
    DEBUGF("%s watching #%d", alloca_alarm_name(fd_callbacks[i]), fds[i].fd);
}

int deadline(struct sched_ent *alarm)
{
  struct sched_ent *node = next_deadline, *last = NULL;
  if (alarm->deadline < alarm->alarm)
    alarm->deadline = alarm->alarm;
  
  while(node!=NULL){
    if (node->deadline > alarm->deadline)
      break;
    last = node;
    node = node->_next;
  }
  if (last == NULL){
    next_deadline = alarm;
  }else{
    last->_next = alarm;
  }
  alarm->_prev = last;
  if(node!=NULL)
    node->_prev = alarm;
  alarm->_next = node;
  return 0;
}

int is_scheduled(const struct sched_ent *alarm)
{
  return alarm->_next || alarm->_prev || alarm == next_alarm || alarm == next_deadline;
}

// add an alarm to the list of scheduled function calls.
// simply populate .alarm with the absolute time, and .function with the method to call.
// on calling .poll.revents will be zero.
int _schedule(struct __sourceloc __whence, struct sched_ent *alarm)
{
  time_ms_t now = gettime_ms();
  if (config.debug.io)
    DEBUGF("schedule(alarm=%s) alarm=%.3f deadline=%.3f",
	  alloca_alarm_name(alarm),
	  (double)(alarm->alarm - now) / 1000,
	  (double)(alarm->deadline - now) / 1000
	);
  if (!alarm->stats)
    WARN("schedule() called without supplying an alarm name");

  struct sched_ent *node = next_alarm, *last = NULL;
  
  if (is_scheduled(alarm))
    FATAL("Scheduling an alarm that is already scheduled");
  
  if (!alarm->function)
    return WHY("Can't schedule if you haven't set the function pointer");

  if (alarm->deadline < alarm->alarm)
    alarm->deadline = alarm->alarm;
  
  if (now - alarm->deadline > 1000){
    // 1000ms ago? thats silly, if you keep doing it noone else will get a turn.
    FATALF("Alarm %s tried to schedule a deadline %"PRId64"ms ago",
	   alloca_alarm_name(alarm),
           (now - alarm->deadline)
	);
  }

  // if the alarm has already expired, move straight to the deadline queue
  if (alarm->alarm <= now)
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
int _unschedule(struct __sourceloc __whence, struct sched_ent *alarm)
{
  if (config.debug.io)
    DEBUGF("unschedule(alarm=%s)", alloca_alarm_name(alarm));

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
int _watch(struct __sourceloc __whence, struct sched_ent *alarm)
{
  if (config.debug.io)
    DEBUGF("watch(alarm=%s)", alloca_alarm_name(alarm));
  if (!alarm->stats)
    WARN("watch() called without supplying an alarm name");

  if (!alarm->function)
    return WHY("Can't watch if you haven't set the function pointer");
  
  if (alarm->_poll_index>=0 && fd_callbacks[alarm->_poll_index]==alarm){
    // updating event flags
    if (config.debug.io)
      DEBUGF("Updating watch %s, #%d for %s", alloca_alarm_name(alarm), alarm->poll.fd, alloca_poll_events(alarm->poll.events));
  }else{
    if (config.debug.io)
      DEBUGF("Adding watch %s, #%d for %s", alloca_alarm_name(alarm), alarm->poll.fd, alloca_poll_events(alarm->poll.events));
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
int _unwatch(struct __sourceloc __whence, struct sched_ent *alarm)
{
  if (config.debug.io)
    DEBUGF("unwatch(alarm=%s)", alloca_alarm_name(alarm));

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
  if (config.debug.io)
    DEBUGF("%s stopped watching #%d for %s", alloca_alarm_name(alarm), alarm->poll.fd, alloca_poll_events(alarm->poll.events));
  return 0;
}

static void call_alarm(struct sched_ent *alarm, int revents)
{
  IN();
  if (!alarm)
    FATAL("Attempted to call with no alarm");
  struct call_stats call_stats;
  call_stats.totals = alarm->stats;
  
  if (config.debug.io)
    DEBUGF("Calling alarm/callback %p %s", alarm, alloca_alarm_name(alarm));

  if (call_stats.totals)
    fd_func_enter(__HERE__, &call_stats);
  
  alarm->poll.revents = revents;
  alarm->function(alarm);
  
  if (call_stats.totals)
    fd_func_exit(__HERE__, &call_stats);

  if (config.debug.io)
    DEBUGF("Alarm %p returned",alarm);

  OUT();
}

int fd_poll()
{
  IN();
  int i, r=0;
  int ms=60000;
  time_ms_t now = gettime_ms();
  
  if (!next_alarm && !next_deadline && fdcount==0)
    RETURN(0);
  
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
    fd_func_enter(__HERE__, &call_stats);
    if (fdcount==0){
      sleep_ms(ms);
    }else{
      r = poll(fds, fdcount, ms);
      if (config.debug.io) {
	strbuf b = strbuf_alloca(1024);
	int i;
	for (i = 0; i < fdcount; ++i) {
	  if (i)
	    strbuf_puts(b, ", ");
	  strbuf_sprintf(b, "%d:", fds[i].fd);
	  strbuf_append_poll_events(b, fds[i].events);
	  strbuf_puts(b, "->");
	  strbuf_append_poll_events(b, fds[i].revents);
	}
	DEBUGF("poll(fds=(%s), fdcount=%d, ms=%d) -> %d", strbuf_str(b), fdcount, ms, r);
      }
    }
    fd_func_exit(__HERE__, &call_stats);
    now=gettime_ms();
  }

  // Reading new data takes priority over everything else
  // Are any handles marked with POLLIN?
  int in_count=0;
  if (r>0){
    for (i=0;i<fdcount;i++)
      if (fds[i].revents & POLLIN)
        in_count++;
  }

  /* call one alarm function, but only if its deadline time has elapsed OR there is no incoming file activity */
  if (next_deadline && (next_deadline->deadline <=now || (in_count==0))){
    struct sched_ent *alarm = next_deadline;
    unschedule(alarm);
    call_alarm(alarm, 0);
    now=gettime_ms();

    // after running a timed alarm, unless we already know there is data to read we want to check for more incoming IO before we send more outgoing.
    if (in_count==0)
      RETURN(1);
  }
  
  /* If file descriptors are ready, then call the appropriate functions */
  if (r>0) {
    for(i=fdcount -1;i>=0;i--){
      if (fds[i].revents) {
        // if any handles have POLLIN set, don't process any other handles
        if (!(fds[i].revents&POLLIN || in_count==0))
          continue;

	int fd = fds[i].fd;
	/* Call the alarm callback with the socket in non-blocking mode */
	errno=0;
	set_nonblock(fd);
	// Work around OSX behaviour that doesn't set POLLERR on 
	// devices that have been deconfigured, e.g., a USB serial adapter
	// that has been removed.
	if (errno == ENXIO) fds[i].revents|=POLLERR;
	call_alarm(fd_callbacks[i], fds[i].revents);
	/* The alarm may have closed and unwatched the descriptor, make sure this descriptor still matches */
	if (i<fdcount && fds[i].fd == fd){
	  if (set_block(fds[i].fd))
	    FATALF("Alarm %p %s has a bad descriptor that wasn't closed!", fd_callbacks[i], alloca_alarm_name(fd_callbacks[i]));
	}
      }
    }
  }
  RETURN(1);
  OUT();
}
