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

/*
  Portions Copyright (C) 2013 Petter Reinholdtsen
  Some rights reserved

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
  FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
  COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.
*/

#include <inttypes.h> // for PRIu64 on Android
#include "fdqueue.h"
#include "conf.h"
#include "net.h"
#include "str.h"
#include "strbuf.h"
#include "strbuf_helpers.h"

#define MAX_WATCHED_FDS 128
__thread struct pollfd fds[MAX_WATCHED_FDS];
__thread int fdcount=0;
__thread struct sched_ent *fd_callbacks[MAX_WATCHED_FDS];

__thread struct sched_ent *wake_list=NULL;
__thread struct sched_ent *run_soon=NULL;
__thread struct sched_ent *run_now=NULL;

struct profile_total poll_stats={NULL,0,"Idle (in poll)",0,0,0,0};

#define alloca_alarm_name(alarm) ((alarm)->stats ? alloca_str_toprint((alarm)->stats->name) : "Unnamed")

void list_alarms()
{
  time_ms_t now = gettime_ms();
  struct sched_ent *alarm;
  
  DEBUG("Run now;");
  for (alarm = run_now; alarm; alarm=alarm->_next_run)
    DEBUGF("%p %s deadline in %"PRId64"ms", alarm->function, alloca_alarm_name(alarm), alarm->run_before - now);
    
  DEBUG("Run soon;");
  for (alarm = run_soon; alarm; alarm=alarm->_next_run)
    DEBUGF("%p %s run in %"PRId64"ms", alarm->function, alloca_alarm_name(alarm), alarm->run_after - now);
  
  DEBUG("Wake at;");
  for (alarm = wake_list; alarm; alarm = alarm->_next_wake)
    DEBUGF("%p %s wake in %"PRId64"ms", alarm->function, alloca_alarm_name(alarm), alarm->wake_at - now);
  
  DEBUG("File handles;");
  int i;
  for (i = 0; i < fdcount; ++i)
    DEBUGF("%s watching #%d for %x", alloca_alarm_name(fd_callbacks[i]), fds[i].fd, fds[i].events);
}

static void insert_run_now(struct sched_ent *alarm)
{
  struct sched_ent **list = &run_now;
  
  while(*list){
    if ((*list)->run_before > alarm->run_before)
      break;
    list = &(*list)->_next_run;
  }
  alarm->_next_run = *list;
  *list = alarm;
}

static void insert_run_soon(struct sched_ent *alarm)
{
  struct sched_ent **list = &run_soon;
  
  while(*list){
    if ((*list)->run_after > alarm->run_after)
      break;
    list = &(*list)->_next_run;
  }
  alarm->_next_run = *list;
  *list = alarm;
}

static void remove_run_list(struct sched_ent *alarm, struct sched_ent **list)
{
  while(*list){
    if (*list==alarm){
      *list = alarm->_next_run;
      list = &alarm->_next_run;
      alarm->_next_run=NULL;
      return;
    }else{
      list = &(*list)->_next_run;
    }
  }
}

static void insert_wake_list(struct sched_ent *alarm)
{
  if (alarm->wake_at == TIME_MS_NEVER_WILL)
    return;
  struct sched_ent **list = &wake_list, *last = NULL;
  while(*list){
    if ((*list)->wake_at > alarm->wake_at)
      break;
    last = (*list);
    list = &last->_next_wake;
  }
  alarm->_next_wake = *list;
  if (*list)
    (*list)->_prev_wake = alarm;
  alarm->_prev_wake = last;
  *list = alarm;
}

static void remove_wake_list(struct sched_ent *alarm)
{
  struct sched_ent *prev = alarm->_prev_wake;
  struct sched_ent *next = alarm->_next_wake;
  
  if (prev)
    prev->_next_wake = next;
  else if(wake_list==alarm)
    wake_list = next;
    
  if (next)
    next->_prev_wake = prev;
  
  alarm->_prev_wake = NULL;
  alarm->_next_wake = NULL;
}

// move alarms from run_soon to run_now
static void move_run_list(){
  time_ms_t now = gettime_ms();
  while(run_soon && run_soon->run_after <= now){
    struct sched_ent *alarm = run_soon;
    run_soon = run_soon->_next_run;
    remove_wake_list(alarm);
    insert_run_now(alarm);
    if (config.debug.io)
      DEBUGF("Moved %s from run_soon to run_now", alloca_alarm_name(alarm));
  }
}

// add an alarm to the list of scheduled function calls.
// simply populate .alarm with the absolute time, and .function with the method to call.
// on calling .poll.revents will be zero.
void _schedule(struct __sourceloc __whence, struct sched_ent *alarm)
{
  // TODO deprecate alarm and deadline, rename all uses to wake_at, run_before
  alarm->wake_at = alarm->alarm;
  alarm->run_before = alarm->deadline;
  if (alarm->run_after == TIME_MS_NEVER_WILL || alarm->run_after==0)
    alarm->run_after = alarm->wake_at;
  
  if (config.debug.io){
    time_ms_t now = gettime_ms();
    DEBUGF("schedule(alarm=%s) run_after=%.3f wake_at=%.3f run_before=%.3f",
	  alloca_alarm_name(alarm),
	  (double)(alarm->run_after - now) / 1000,
	  (double)(alarm->wake_at - now) / 1000,
	  (double)(alarm->run_before - now) / 1000
	);
  }
  
  if (!alarm->stats)
    WARN("schedule() called without supplying an alarm stats");
  
  assert(alarm->wake_at >= alarm->run_after);
  assert(alarm->run_before >= alarm->run_after);
  assert(!is_scheduled(alarm));
  assert(alarm->function);
  
  // TODO assert if the alarm times look odd? eg >1s ago or >1hr from now?
  
  // don't bother to schedule an alarm that will (by definition) never run
  // not an error as it simplifies calling API use
  if (alarm->run_after != TIME_MS_NEVER_WILL){
    insert_wake_list(alarm);
    insert_run_soon(alarm);
    alarm->_scheduled=1;
  }
}

// remove a function from the schedule before it has fired
// safe to unschedule twice...
void _unschedule(struct __sourceloc __whence, struct sched_ent *alarm)
{
  if (!is_scheduled(alarm))
    return;
    
  if (config.debug.io)
    DEBUGF("unschedule(alarm=%s)", alloca_alarm_name(alarm));

  remove_run_list(alarm, &run_now);
  remove_run_list(alarm, &run_soon);
  remove_wake_list(alarm);
  alarm->_scheduled=0;
  alarm->run_after = TIME_MS_NEVER_WILL;
}

// start watching a file handle, call this function again if you wish to change the event mask
int _watch(struct __sourceloc __whence, struct sched_ent *alarm)
{
  if (config.debug.io)
    DEBUGF("watch(alarm=%s)", alloca_alarm_name(alarm));
  if (!alarm->stats)
    WARN("watch() called without supplying an alarm name");

  if (!alarm->function)
    FATAL("Can't watch if you haven't set the function pointer");
  if (!alarm->poll.events)
    FATAL("Can't watch if you haven't set any poll flags");
  
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

int is_watching(struct sched_ent *alarm)
{
  if (alarm->_poll_index <0 || fds[alarm->_poll_index].fd!=alarm->poll.fd)
    return 0;
  return 1;
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


int fd_poll2(time_ms_t (*waiting)(time_ms_t, time_ms_t, time_ms_t), void (*wokeup)())
{
  IN();
  
  // clear the run now list of any alarms that are overdue
  if (run_now && run_now->run_before <= gettime_ms()){
    struct sched_ent *alarm = run_now;
    run_now = alarm->_next_run;
    alarm->_scheduled=0;
    alarm->run_after = TIME_MS_NEVER_WILL;
    call_alarm(alarm, 0);
    RETURN(1);
  }
  
  // return 0 when there's nothing to do, it doesn't make sense to wait for infinity
  if (!run_now && !wake_list && fdcount==0)
    RETURN(0);
  
  time_ms_t now = gettime_ms();
  time_ms_t wait_until=TIME_MS_NEVER_WILL;
  uint8_t called_waiting = 0;
  
  if (run_now){
    wait_until = now;
  }else{
    time_ms_t next_run=TIME_MS_NEVER_WILL;
    if(run_soon)
      next_run = run_soon->run_after;
    
    if (wake_list)
      wait_until = wake_list->wake_at;
      
    if (waiting && wait_until > now){
      wait_until = waiting(now, next_run, wait_until);
      now = gettime_ms();
      called_waiting = 1;
    }
  }
  
  // check for IO and/or wait for the next wake_at
  int wait=0;
  int r=0;
  
  {
    struct call_stats call_stats;
    call_stats.totals=&poll_stats;
    
    if (wait_until==TIME_MS_NEVER_WILL)
      wait = -1;
    else if (wait_until <= now)
      wait = 0;
    else
      wait = wait_until - now;
    
    if (fdcount){
      if (config.debug.io)
	DEBUGF("Calling poll with %dms wait", wait);
	
      fd_func_enter(__HERE__, &call_stats);
      r = poll(fds, fdcount, wait);
      fd_func_exit(__HERE__, &call_stats);
      
      if (r==-1 && errno!=EINTR)
	WHY_perror("poll");
      
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
	DEBUGF("poll(fds=(%s), fdcount=%d, ms=%d) -> %d", strbuf_str(b), fdcount, wait, r);
      }
      
    }else if(wait>0){
      fd_func_enter(__HERE__, &call_stats);
      sleep_ms(wait);
      fd_func_exit(__HERE__, &call_stats);
      
    }
  }
  
  if (wokeup && called_waiting)
    wokeup();
  
  move_run_list();
  
  // We don't want a single alarm to be able to reschedule itself and starve all IO
  // So we only check for new overdue alarms if we attempted to sleep
  if (wait && run_now && run_now->run_before <= gettime_ms())
    RETURN(1);
  
  // process all watched IO handles once (we need to be fair)
  if (r>0) {
    int i;
    for(i=fdcount -1;i>=0;i--){
      if (fd_callbacks[i] && fd_callbacks[i]->poll.fd == fds[i].fd && fds[i].revents) {
	errno=0;
	int fd = fds[i].fd;
	set_nonblock(fd);
	// Work around OSX behaviour that doesn't set POLLERR on 
	// devices that have been deconfigured, e.g., a USB serial adapter
	// that has been removed.
	if (errno == ENXIO) fds[i].revents|=POLLERR;
	call_alarm(fd_callbacks[i], fds[i].revents);
	// The alarm may have closed and unwatched the descriptor, make sure this descriptor still matches
	if (i<fdcount && fds[i].fd == fd){
	  if (set_block(fds[i].fd))
	    FATALF("Alarm %p %s has a bad descriptor that wasn't closed!", fd_callbacks[i], alloca_alarm_name(fd_callbacks[i]));
	}
      }
    }
    // time may have passed while processing IO, or processing IO could trigger a new overdue alarm
    move_run_list();
    
  }else if (run_now){
    // No IO, no overdue alarms but another alarm is runnable? run a single alarm before polling again
    struct sched_ent *alarm = run_now;
    run_now = alarm->_next_run;
    alarm->_scheduled=0;
    alarm->run_after = TIME_MS_NEVER_WILL;
    call_alarm(alarm, 0);
  }
  
  RETURN(1);
  OUT();
}
