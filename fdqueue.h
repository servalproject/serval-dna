/*
 Copyright (C) 2012 Serval Project.

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
 Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 02110-1301, USA.
 */

#ifndef __SERVALD_FDQUEUE_H
#define __SERVALD_FDQUEUE_H

#include <pthread.h>
#include "serval.h"

#define MAX_WATCHED_FDS 128

/* fdqueue used for all actions (including MDP) except Rhizome */
extern struct fdqueue main_fdqueue;

/* fdqueue used for Rhizome actions */
extern struct fdqueue rhizome_fdqueue;

typedef struct fdqueue {

  struct pollfd fds[MAX_WATCHED_FDS];
  int fdcount;
  struct sched_ent *fd_callbacks[MAX_WATCHED_FDS];
  struct sched_ent *next_alarm;
  struct sched_ent *next_deadline;
  struct profile_total poll_stats;

  /* thread associated with the fdqueue */
  pthread_t thread;

  /* mutex to be acquired for every fdqueue items access */
  pthread_mutex_t mutex;

  /* signaled when the queue state changes from inactive to active (see
   * is_active(fdqueue *) in fdqueue.c) */
  pthread_cond_t cond_is_active;

  /* signaled when next_alarm or next_deadline is changed or when a new
   * fd is being watched */
  pthread_cond_t cond_change;

} fdqueue;

#endif
