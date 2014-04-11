/* 
Serval DNA file descriptor queue
Copyright (C) 2012-2013 Serval Project Inc.

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

#ifndef __SERVAL_DNA__FDQUEUE_H
#define __SERVAL_DNA__FDQUEUE_H

#ifdef HAVE_POLL_H
#include <poll.h>
#endif
#include "os.h"
#include "log.h"

struct profile_total {
  struct profile_total *_next;
  int _initialised;
  const char *name;
  time_ms_t max_time;
  time_ms_t total_time;
  time_ms_t child_time;
  int calls;
};

struct call_stats{
  time_ms_t enter_time;
  time_ms_t child_time;
  struct profile_total *totals;
  struct call_stats *prev;
};

struct sched_ent;

typedef void (*ALARM_FUNCP) (struct sched_ent *alarm);

struct sched_ent{
  struct sched_ent *_next;
  struct sched_ent *_prev;
  
  ALARM_FUNCP function;
  void *context;
  struct pollfd poll;
  // when we should first consider the alarm
  time_ms_t alarm;
  // the order we will prioritise the alarm
  time_ms_t deadline;
  struct profile_total *stats;
  int _poll_index;
};

#define STRUCT_SCHED_ENT_UNUSED {.poll={.fd=-1}, ._poll_index=-1,}

int is_scheduled(const struct sched_ent *alarm);
int is_watching(struct sched_ent *alarm);
int _schedule(struct __sourceloc, struct sched_ent *alarm);
int _unschedule(struct __sourceloc, struct sched_ent *alarm);
int _watch(struct __sourceloc, struct sched_ent *alarm);
int _unwatch(struct __sourceloc, struct sched_ent *alarm);
#define schedule(alarm)   _schedule(__WHENCE__, alarm)
#define unschedule(alarm) _unschedule(__WHENCE__, alarm)
#define watch(alarm)      _watch(__WHENCE__, alarm)
#define unwatch(alarm)    _unwatch(__WHENCE__, alarm)
int fd_poll();

/* function timing routines */
int fd_clearstats();
int fd_showstats();
int fd_checkalarms();
int fd_func_enter(struct __sourceloc, struct call_stats *this_call);
int fd_func_exit(struct __sourceloc, struct call_stats *this_call);
void dump_stack(int log_level);
unsigned fd_depth();

#define IN() static struct profile_total _aggregate_stats={NULL,0,__FUNCTION__,0,0,0,0}; \
    struct call_stats _this_call={.totals=&_aggregate_stats}; \
    fd_func_enter(__HERE__, &_this_call);

#define OUT() fd_func_exit(__HERE__, &_this_call)
#define RETURN(X) do { OUT(); return (X); } while (0)
#define RETURNNULL(X) do { X; OUT(); return (NULL); } while (0)
#define RETURNVOID do { OUT(); return; } while (0)

#endif // __SERVAL_DNA__FDQUEUE_H
