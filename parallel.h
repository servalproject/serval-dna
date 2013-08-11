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

#ifndef __SERVALD_PARALLEL_H
#define __SERVALD_PARALLEL_H

#include <pthread.h>
#include "serval.h"

extern int multithread;

extern pthread_t main_thread;
extern pthread_t rhizome_thread;

#define ASSERT_THREAD(P)\
  if (multithread && pthread_self() != (P)) {\
    FATAL("Not called from the expected thread");\
  }

/* rhizome thread function */
void *rhizome_run(void *arg);

/* schedule a function call with the specified arguments on fdq */
void post_runnable(ALARM_FUNCP function, void *arg, fdqueue *fdq);

#endif
