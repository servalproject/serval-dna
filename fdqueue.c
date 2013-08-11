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

#include <poll.h>
#include <pthread.h>
#include <unistd.h>
#include "serval.h"
#include "conf.h"
#include "str.h"
#include "strbuf.h"
#include "strbuf_helpers.h"
#include "fdqueue.h"

#ifndef PTHREAD_RECURSIVE_MUTEX_INITIALIZER
#define PTHREAD_RECURSIVE_MUTEX_INITIALIZER \
  PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP
#endif

fdqueue main_fdqueue = {
  .poll_stats = { .name = "Main fdqueue" },
  .mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER,
  .cond_is_active = PTHREAD_COND_INITIALIZER,
  .cond_change = PTHREAD_COND_INITIALIZER
};

fdqueue rhizome_fdqueue = {
  .poll_stats = { .name = "Rhizome fdqueue" },
  .mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER,
  .cond_is_active = PTHREAD_COND_INITIALIZER,
  .cond_change = PTHREAD_COND_INITIALIZER
};

static inline int is_active(fdqueue *fdq) {
  return fdq->next_alarm || fdq->next_deadline || fdq->fdcount > 0;
}

static void fdqueue_init(fdqueue *fdq) {
  fdq->fds = fdq->intfds + 1;
  if (pipe(fdq->pipefd)) {
    FATAL("pipe failed");
  }
  fdq->intfds[0].fd = fdq->pipefd[0];
  fdq->intfds[0].events = POLLIN;
}

void fdqueues_init(void) {
  fdqueue_init(&main_fdqueue);
  fdqueue_init(&rhizome_fdqueue);
}

static void fdqueue_free(fdqueue *fdq) {
  close(fdq->pipefd[0]);
  close(fdq->pipefd[1]);
  fdq->intfds[0].fd = 0;
}

void fdqueues_free(void) {
  fdqueue_free(&main_fdqueue);
  fdqueue_free(&rhizome_fdqueue);
}

/* write 1 char to pipe fd for poll() to always be non-blocking */
static inline void add_poll_nonblock(fdqueue *fdq) {
  char c = 0;
  write(fdq->pipefd[1], &c, 1);
}

/* read 1 char from pipe fd */
static inline void remove_poll_nonblock(fdqueue *fdq) {
  char c;
  read(fdq->pipefd[0], &c, 1);
}

#define alloca_alarm_name(alarm) ((alarm)->stats ? alloca_str_toprint((alarm)->stats->name) : "Unnamed")

void list_alarms(fdqueue *fdq)
{
  DEBUG("Alarms;");

  add_poll_nonblock(fdq);
  pthread_mutex_lock(&fdq->mutex);
  remove_poll_nonblock(fdq);

  time_ms_t now = gettime_ms();
  struct sched_ent *alarm;
  
  for (alarm = fdq->next_deadline; alarm; alarm = alarm->_next)
    DEBUGF("%p %s deadline in %lldms", alarm->function, alloca_alarm_name(alarm), alarm->deadline - now);
  
  for (alarm = fdq->next_alarm; alarm; alarm = alarm->_next)
    DEBUGF("%p %s in %lldms, deadline in %lldms", alarm->function, alloca_alarm_name(alarm), alarm->alarm - now, alarm->deadline - now);
  
  DEBUG("File handles;");
  int i;
  for (i = 0; i < fdq->fdcount; ++i)
    DEBUGF("%s watching #%d", alloca_alarm_name(fdq->fd_callbacks[i]), fdq->fds[i].fd);
  pthread_mutex_unlock(&fdq->mutex);
}

static int deadline(struct sched_ent *alarm)
{
  fdqueue *fdq = alarm->fdqueue;
  struct sched_ent *node = fdq->next_deadline, *last = NULL;
  if (alarm->deadline < alarm->alarm)
    alarm->deadline = alarm->alarm;
  
  while(node!=NULL){
    if (node->deadline > alarm->deadline)
      break;
    last = node;
    node = node->_next;
  }
  if (last == NULL){
    fdq->next_deadline = alarm;
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
  fdqueue *fdq = alarm->fdqueue;
  if (!fdq) {
    return 0;
  }
  int res;

  add_poll_nonblock(fdq);
  pthread_mutex_lock(&fdq->mutex);
  remove_poll_nonblock(fdq);

  res = alarm->_next || alarm->_prev || alarm == fdq->next_alarm
    || alarm == fdq->next_deadline;
  pthread_mutex_unlock(&fdq->mutex);
  return res;
}

// add an alarm to the list of scheduled function calls.
// simply populate .alarm with the absolute time, and .function with the method to call.
// on calling .poll.revents will be zero.
int _schedule(struct __sourceloc __whence, struct sched_ent *alarm)
{
  if (config.debug.io)
    DEBUGF("schedule(alarm=%s) called from %s() %s:%d", 
	   alloca_alarm_name(alarm),
	   __whence.function,__whence.file,__whence.line);
  if (!alarm->stats)
    WARNF("schedule() called from %s() %s:%d without supplying an alarm name", 
	  __whence.function,__whence.file,__whence.line);

  if (!alarm->function)
    return WHY("Can't schedule if you haven't set the function pointer");

  fdqueue *fdq = alarm->fdqueue;
  if (!fdq) {
    fdq = alarm->fdqueue = &main_fdqueue;
  }

  add_poll_nonblock(fdq);
  pthread_mutex_lock(&fdq->mutex);
  remove_poll_nonblock(fdq);

  struct sched_ent *node = fdq->next_alarm, *last = NULL;

  if (is_scheduled(alarm)) {
    pthread_mutex_unlock(&fdq->mutex);
    FATAL("Scheduling an alarm that is already scheduled");
  }

  if (!is_active(fdq)) {
    /* it will become active before releasing the mutex */
    pthread_cond_signal(&fdq->cond_is_active);
  }

  time_ms_t now = gettime_ms();

  if (alarm->deadline < alarm->alarm)
    alarm->deadline = alarm->alarm;
  
  if (now - alarm->deadline > 1000){
    // 1000ms ago? thats silly, if you keep doing it noone else will get a turn.
    WHYF("Alarm %s tried to schedule a deadline %lldms ago, from %s() %s:%d",
	   alloca_alarm_name(alarm),
           (now - alarm->deadline),
	   __whence.function,__whence.file,__whence.line);
  }

  // if the alarm has already expired, move straight to the deadline queue
  if (alarm->alarm <= now) {
    int res = deadline(alarm);
    pthread_cond_signal(&fdq->cond_change);
    pthread_mutex_unlock(&fdq->mutex);
    return res;
  }

  while(node!=NULL){
    if (node->alarm > alarm->alarm)
      break;
    last = node;
    node = node->_next;
  }
  if (last == NULL){
    fdq->next_alarm = alarm;
    pthread_cond_signal(&fdq->cond_change);
  }else{
    last->_next=alarm;
  }
  alarm->_prev = last;
  if(node!=NULL)
    node->_prev = alarm;
  alarm->_next = node;

  pthread_mutex_unlock(&fdq->mutex);

  return 0;
}

// remove a function from the schedule before it has fired
// safe to unschedule twice...
int _unschedule(struct __sourceloc __whence, struct sched_ent *alarm)
{
  if (config.debug.io)
    DEBUGF("unschedule(alarm=%s)", alloca_alarm_name(alarm));

  fdqueue *fdq = alarm->fdqueue;
  if (!fdq) {
    /* was never scheduled */
    return 0;
  }

  add_poll_nonblock(fdq);
  pthread_mutex_lock(&fdq->mutex);
  remove_poll_nonblock(fdq);

  struct sched_ent *prev = alarm->_prev;
  struct sched_ent *next = alarm->_next;
  
  if (prev) {
    prev->_next = next;
  } else if (fdq->next_alarm == alarm) {
    fdq->next_alarm = next;
    pthread_cond_signal(&fdq->cond_change);
  } else if (fdq->next_deadline == alarm) {
    fdq->next_deadline = next;
    pthread_cond_signal(&fdq->cond_change);
  }
  
  if (next)
    next->_prev = prev;
  
  alarm->_prev = NULL;
  alarm->_next = NULL;

  pthread_mutex_unlock(&fdq->mutex);

  return 0;
}

// start watching a file handle, call this function again if you wish to change the event mask
int _watch(struct __sourceloc __whence, struct sched_ent *alarm)
{
  if (config.debug.io)
    DEBUGF("watch(alarm=%s)", alloca_alarm_name(alarm));
  if (!alarm->stats)
    WARNF("watch() called from %s() %s:%d without supplying an alarm name", 
	  __whence.function,__whence.file,__whence.line);

  if (!alarm->function)
    return WHY("Can't watch if you haven't set the function pointer");

  fdqueue *fdq = alarm->fdqueue;
  if (!fdq) {
    fdq = alarm->fdqueue = &main_fdqueue;
  }

  add_poll_nonblock(fdq);
  pthread_mutex_lock(&fdq->mutex);
  remove_poll_nonblock(fdq);

  if (!is_active(fdq)) {
    /* it will become active before releasing the mutex */
    pthread_cond_signal(&fdq->cond_is_active);
  }
  pthread_cond_signal(&fdq->cond_change);

  if (alarm->_poll_index >= 0 && fdq->fd_callbacks[alarm->_poll_index] == alarm) {
    // updating event flags
    if (config.debug.io)
      DEBUGF("Updating watch %s, #%d for %d", alloca_alarm_name(alarm), alarm->poll.fd, alarm->poll.events);
  }else{
    if (config.debug.io)
      DEBUGF("Adding watch %s, #%d for %d", alloca_alarm_name(alarm), alarm->poll.fd, alarm->poll.events);
    if (fdq->fdcount >= MAX_WATCHED_FDS) {
      pthread_mutex_unlock(&fdq->mutex);
      return WHY("Too many file handles to watch");
    }
    fdq->fd_callbacks[fdq->fdcount] = alarm;
    alarm->poll.revents = 0;
    alarm->_poll_index = fdq->fdcount;
    fdq->fdcount++;
  }
  fdq->fds[alarm->_poll_index] = alarm->poll;

  pthread_mutex_unlock(&fdq->mutex);

  return 0;
}

// stop watching a file handle
int _unwatch(struct __sourceloc __whence, struct sched_ent *alarm)
{
  if (config.debug.io)
    DEBUGF("unwatch(alarm=%s)", alloca_alarm_name(alarm));

  fdqueue *fdq = alarm->fdqueue;

  add_poll_nonblock(fdq);
  pthread_mutex_lock(&fdq->mutex);
  remove_poll_nonblock(fdq);

  int index = alarm->_poll_index;
  if (index < 0 || fdq->fds[index].fd != alarm->poll.fd) {
    pthread_mutex_unlock(&fdq->mutex);
    return WHY("Attempted to unwatch a handle that is not being watched");
  }

  fdq->fdcount--;
  if (index != fdq->fdcount) {
    // squash fds
    fdq->fds[index] = fdq->fds[fdq->fdcount];
    fdq->fd_callbacks[index] = fdq->fd_callbacks[fdq->fdcount];
    fdq->fd_callbacks[index]->_poll_index = index;
  }
  fdq->fds[fdq->fdcount].fd = -1;
  fdq->fd_callbacks[fdq->fdcount] = NULL;
  alarm->_poll_index=-1;
  if (config.debug.io)
    DEBUGF("%s stopped watching #%d for %d", alloca_alarm_name(alarm), alarm->poll.fd, alarm->poll.events);

  pthread_mutex_unlock(&fdq->mutex);

  return 0;
}

static void call_alarm(struct sched_ent *alarm, int revents)
{
  IN();
  if (!alarm)
    FATAL("Attempted to call with no alarm");
  fdqueue *fdq = alarm->fdqueue;
  struct call_stats call_stats;
  call_stats.totals = alarm->stats;
  
  if (config.debug.io) DEBUGF("Calling alarm/callback %p ('%s')",
			      alarm, alloca_alarm_name(alarm));

  if (call_stats.totals)
    fd_func_enter(__HERE__, &call_stats);
  
  alarm->poll.revents = revents;
  pthread_mutex_unlock(&fdq->mutex);
  alarm->function(alarm);
  pthread_mutex_lock(&fdq->mutex);
  
  if (call_stats.totals)
    fd_func_exit(__HERE__, &call_stats);

  if (config.debug.io) DEBUGF("Alarm %p returned",alarm);

  OUT();
}

int fd_poll(fdqueue *fdq, int wait)
{
  IN();
  pthread_mutex_lock(&fdq->mutex);
  int i, r=0;
  int invalidated;
  int ms;
  time_ms_t now;

  do {
    invalidated = 0;
    if (wait) {
      while (!is_active(fdq)) {
        pthread_cond_wait(&fdq->cond_is_active, &fdq->mutex);
      }
    } else {
      if (!is_active(fdq)) {
        pthread_mutex_unlock(&fdq->mutex);
        RETURN(0);
      }
    }

    now = gettime_ms();

    /* move alarms that have elapsed to the deadline queue */
    while (fdq->next_alarm && fdq->next_alarm->alarm <= now) {
      struct sched_ent *alarm = fdq->next_alarm;
      unschedule(alarm);
      deadline(alarm);
    }

    /* check if any file handles have activity */
    struct call_stats call_stats;
    call_stats.totals = &fdq->poll_stats;
    fd_func_enter(__HERE__, &call_stats);
    if (fdq->fdcount == 0) {
      if (fdq->fdcount == 0 && !fdq->next_deadline) {
        /* wait for the next alarm or the next change */
        struct timespec timeout;
        MS_TO_TIMESPEC(fdq->next_alarm->alarm, &timeout);
        int retcode =
          pthread_cond_timedwait(&fdq->cond_change, &fdq->mutex, &timeout);
        invalidated = retcode != ETIMEDOUT;
      }
    } else {
      if (fdq->next_deadline) {
        ms = 0;
      } else if (fdq->next_alarm) {
        ms = fdq->next_alarm->alarm - now;
        if (ms < 0) {
          ms = 0;
        }
      } else {
        /* infinite timeout */
        ms = -1;
      }

      if (config.debug.io) DEBUGF("poll(X,%d,%d)", fdq->fdcount, ms);

      /* poll on fdq->intdfs which contains fds + the interrupt fd */
      r = poll(fdq->intfds, fdq->fdcount + 1, ms);

      if (fdq->intfds[0].revents) {
        /* interrupted (another thread wants the mutex) */
        invalidated = 1;
        pthread_mutex_unlock(&fdq->mutex);
        usleep(1000); /* release the lock for 1 ms */
        pthread_mutex_lock(&fdq->mutex);
      } else {
        if (config.debug.io) {
          strbuf b = strbuf_alloca(1024);
          int i;
          for (i = 0; i < fdq->fdcount; ++i) {
            if (i)
              strbuf_puts(b, ", ");
            strbuf_sprintf(b, "%d:", fdq->fds[i].fd);
            strbuf_append_poll_events(b, fdq->fds[i].events);
            strbuf_putc(b, ':');
            strbuf_append_poll_events(b, fdq->fds[i].revents);
          }
          DEBUGF("poll(fds=(%s), fdcount=%d, ms=%d) = %d", strbuf_str(b), fdq->fdcount, ms, r);
        }
      }
    }
    fd_func_exit(__HERE__, &call_stats);
    now=gettime_ms();
  } while (invalidated);

  // Reading new data takes priority over everything else
  // Are any handles marked with POLLIN?
  int in_count = 0;
  if (r > 0) {
    for (i = 0; i < fdq->fdcount; i++)
      if (fdq->fds[i].revents & POLLIN)
        in_count++;
  }

  /* call one alarm function, but only if its deadline time has elapsed OR there is no incoming file activity */
  if (fdq->next_deadline && (fdq->next_deadline->deadline <= now || in_count == 0)) {
    struct sched_ent *alarm = fdq->next_deadline;
    unschedule(alarm);
    call_alarm(alarm, 0);
    now=gettime_ms();

    // after running a timed alarm, unless we already know there is data to read we want to check for more incoming IO before we send more outgoing.
    if (in_count==0) {
      pthread_mutex_unlock(&fdq->mutex);
      RETURN(1);
    }
  }
  
  /* If file descriptors are ready, then call the appropriate functions */
  if (r > 0) {
    for (i = fdq->fdcount -1; i >= 0; i--){
      if (fdq->fds[i].revents) {
        // if any handles have POLLIN set, don't process any other handles
        if (!(fdq->fds[i].revents & POLLIN || in_count == 0))
          continue;
        int fd = fdq->fds[i].fd;
        /* Call the alarm callback with the socket in non-blocking mode */
        errno=0;
        set_nonblock(fd);
        // Work around OSX behaviour that doesn't set POLLERR on
        // devices that have been deconfigured, e.g., a USB serial adapter
        // that has been removed.
        if (errno == ENXIO) fdq->fds[i].revents|=POLLERR;
        call_alarm(fdq->fd_callbacks[i], fdq->fds[i].revents);
        /* The alarm may have closed and unwatched the descriptor, make sure this descriptor still matches */
        if (i < fdq->fdcount && fdq->fds[i].fd == fd){
          if (set_block(fdq->fds[i].fd))
            FATALF("Alarm %p %s has a bad descriptor that wasn't closed!", fdq->fd_callbacks[i], alloca_alarm_name(fdq->fd_callbacks[i]));
        }
      }
    }
  }

  pthread_mutex_unlock(&fdq->mutex);

  RETURN(1);
  OUT();
}
