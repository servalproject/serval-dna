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

#include <pthread.h>
#include "parallel.h"
#include "serval.h"

pthread_t main_thread;
pthread_t rhizome_thread;

/* thread function, must have type: void *f(void *) */
void *rhizome_run(void *arg) {
  rhizome_fdqueue.thread = rhizome_thread = pthread_self();
  while (fd_poll(&rhizome_fdqueue, 1));
  return NULL;
}

void post_runnable(ALARM_FUNCP function, void *arg, fdqueue *fdq) {
  time_ms_t now = gettime_ms();
  static struct profile_total stats = { .name = "post_runnable/generic" };
  struct sched_ent *alarm = malloc(sizeof(struct sched_ent));
  if (!alarm) OUT_OF_MEMORY;
  *alarm = (struct sched_ent) {
    .function = function,
    .alarm = now,
    .deadline = now + 2000,
    .stats = &stats,
    .context = arg,
    .fdqueue = fdq,
  };
  schedule(alarm);
}
