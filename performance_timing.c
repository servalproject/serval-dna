/*
 Serval Distributed Numbering Architecture (DNA)
 Copyright (C) 2012 Serval Project, Inc.
 
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
#include "conf.h"

void fd_clearstat(struct profile_total *s){
  s->max_time = 0;
  s->total_time = 0;
  s->child_time = 0;
  s->calls = 0;
}

int fd_tallystats(struct profile_total *total,struct profile_total *a)
{
  total->total_time+=a->total_time;
  total->calls+=a->calls;
  if (a->max_time>total->max_time) total->max_time=a->max_time;
  return 0;
}

int fd_showstat(struct profile_total *total, struct profile_total *a)
{
  INFOF("%lldms (%2.1f%%) in %d calls (max %lldms, avg %.1fms, +child avg %.1fms) : %s",
       (long long) a->total_time,
       a->total_time*100.0/total->total_time,
       a->calls,
       (long long) a->max_time,
       a->total_time*1.00/a->calls,
       (a->total_time+a->child_time)*1.00/a->calls,
       a->name);
  return 0;
}

// sort the list of call times
struct profile_total *sort(struct profile_total *list){
  struct profile_total *first = list;
  // the left hand list will contain all items that took longer than the first item
  struct profile_total *left_head = NULL;
  struct profile_total *left_tail = NULL;
  // the right hand list will contain all items that took less time than the first item
  struct profile_total *right_head = NULL;
  struct profile_total *right_tail = NULL;
  
  // most of the cpu time is likely to be the same offenders
  // don't sort a list that's already sorted
  int left_already_sorted = 1;
  int right_already_sorted = 1;
  
  if (!list)
    return NULL;
  
  list = list->_next;
  first->_next = NULL;
  
  // split the list into two sub-lists based on the time of the first entry
  while(list){
    if (list->total_time > first->total_time){
      if (left_tail){
	left_tail->_next = list;
	if (list->total_time > left_tail->total_time)
	  left_already_sorted = 0;
      }else
	left_head=list;
      left_tail=list;
    }else{
      if (right_tail){
	right_tail->_next = list;
	if (list->total_time > right_tail->total_time)
	  right_already_sorted = 0;
      }else
	right_head=list;
      right_tail=list;
    }
    list = list->_next;
  }
  
  // sort the left sub-list
  if (left_tail){
    left_tail->_next=NULL;
    
    if (!left_already_sorted){
      left_head = sort(left_head);
      
      // find the tail again
      left_tail = left_head;
      while(left_tail->_next)
	left_tail = left_tail->_next;
    }
    
    // add the first item after the left list
    left_tail->_next = first;
  }else
    left_head = first;
  
  left_tail = first;
    
  // sort the right sub-list
  if (right_tail){
    right_tail->_next=NULL;
    
    if (!right_already_sorted)
      right_head = sort(right_head);
    left_tail->_next = right_head;
  }
  
  return left_head;
}

int fd_clearstats(fdqueue *fdq)
{
  struct profile_total *stats = fdq->stats_head;
  while(stats!=NULL){
    fd_clearstat(stats);
    stats = stats->_next;
  }
  return 0;
}

int fd_showstats(fdqueue *fdq)
{
  struct profile_total total={NULL, 0, "Total", 0,0,0};
  
  fdq->stats_head = sort(fdq->stats_head);
  
  struct profile_total *stats = fdq->stats_head;
  while(stats!=NULL){
    /* Get total time spent doing everything */
    fd_tallystats(&total,stats);
    stats = stats->_next;
  }

  // Show periodic rhizome transfer information, but only
  // if there are some active rhizome transfers.
  if (fdq == &rhizome_fdqueue && rhizome_active_fetch_count()!=0)
    INFOF("Rhizome transfer progress: %d,%d,%d,%d,%d,%d (remaining %d)",
	  rhizome_active_fetch_bytes_received(0),
	  rhizome_active_fetch_bytes_received(1),
	  rhizome_active_fetch_bytes_received(2),
	  rhizome_active_fetch_bytes_received(3),
	  rhizome_active_fetch_bytes_received(4),
	  rhizome_active_fetch_bytes_received(5),
          rhizome_fetch_queue_bytes());

  // Report any functions that take too much time
  if (!config.debug.timing)
    {
      stats = fdq->stats_head;
      while(stats!=NULL){
	/* If a function spends more than 1 second in any 
	   notionally 3 second period, then dob on it */
	if (stats->total_time>1000
	    &&strcmp(stats->name,"Idle (in poll)"))
	  fd_showstat(&total,stats);
	stats = stats->_next;
      }
    }
  else {
    INFOF("servald time usage stats:");
    stats = fdq->stats_head;
    while(stats!=NULL){
      /* Get total time spent doing everything */
      if (stats->calls)
	fd_showstat(&total,stats);
      stats = stats->_next;
    }    
    fd_showstat(&total,&total);
  }
  
  return 0;
}

void fd_periodicstats(struct sched_ent *alarm)
{
  fd_showstats(alarm->fdqueue);
  fd_clearstats(alarm->fdqueue);
  alarm->alarm = gettime_ms()+3000;
  alarm->deadline = alarm->alarm+1000;
  schedule(alarm);
}

void dump_stack(fdqueue *fdq, int log_level)
{
  struct call_stats *call = fdq->current_call;
  while(call){
    if (call->totals)
      LOGF(log_level, "%s",call->totals->name);
    call=call->prev;
  }
}

void dump_stacks(int log_level)
{
  INFOF("Main thread stack:");
  dump_stack(&main_fdqueue, log_level);
  INFOF("Rhizome thread stack:");
  dump_stack(&rhizome_fdqueue, log_level);
}

int fd_func_enter(struct __sourceloc __whence, fdqueue * fdq,
                  struct call_stats *this_call)
{
  if (config.debug.profiling)
    DEBUGF("%s called from %s() %s:%d",
	   __FUNCTION__,__whence.function,__whence.file,__whence.line); 
 
  this_call->enter_time=gettime_ms();
  this_call->child_time=0;
  this_call->prev = fdq->current_call;
  fdq->current_call = this_call;
  return 0;
}

int fd_func_exit(struct __sourceloc __whence, fdqueue * fdq,
                 struct call_stats *this_call)
{
  // If current_call does not match this_call, then all bets are off as to where it points.  It
  // probably points to somewhere on the stack (see the IN() macro) that has since been overwritten,
  // so no sense in trying to print its contents in a diagnostic message; that would just cause
  // a SEGV.
  if (config.debug.profiling)
    DEBUGF("%s called from %s() %s:%d",
	   __FUNCTION__,__whence.function,__whence.file,__whence.line); 

  if (fdq->current_call != this_call)
    FATAL("performance timing stack trace corrupted");
  
  time_ms_t now = gettime_ms();
  time_ms_t elapsed = now - this_call->enter_time;
  fdq->current_call = this_call->prev;
  
  if (this_call->totals && !this_call->totals->_initialised){
    this_call->totals->_initialised=1;
    this_call->totals->_next = fdq->stats_head;
    fd_clearstat(this_call->totals);
    fdq->stats_head = this_call->totals;
  }
  
  if (fdq->current_call)
    fdq->current_call->child_time+=elapsed;
  
  elapsed-=this_call->child_time;
  
  if (this_call->totals){
    this_call->totals->total_time+=elapsed;
    this_call->totals->child_time+=this_call->child_time;
    this_call->totals->calls++;
    
    if (elapsed>this_call->totals->max_time) this_call->totals->max_time=elapsed;
  }
  
  return 0;
}
