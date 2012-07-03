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

struct profile_total *stats_head=NULL;
struct call_stats *current_call=NULL;

void fd_clearstat(struct profile_total *s){
  s->max_time = 0;
  s->total_time = 0;
  s->calls = 0;
}

void fd_update_stats(struct profile_total *s,long long elapsed)
{
  s->total_time+=elapsed;
  if (elapsed>s->max_time) s->max_time=elapsed;
  s->calls++;
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
  INFOF("%lldms (%2.1f%%) in %d calls (max %lldms, avg %.1fms) : %s",
       a->total_time,a->total_time*100.0/total->total_time,
       a->calls,
       a->max_time,a->total_time*1.00/a->calls,
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

int fd_clearstats()
{
  struct profile_total *stats = stats_head;
  while(stats!=NULL){
    fd_clearstat(stats);
    stats = stats->_next;
  }
  return 0;
}

int fd_showstats()
{
  struct profile_total total={NULL, 0, "Total", 0,0,0};
  
  stats_head = sort(stats_head);
  
  struct profile_total *stats = stats_head;
  while(stats!=NULL){
    /* Get total time spent doing everything */
    fd_tallystats(&total,stats);
    stats = stats->_next;
  }
  
  INFOF("servald time usage stats:");
  stats = stats_head;
  while(stats!=NULL){
    /* Get total time spent doing everything */
    if (stats->calls)
      fd_showstat(&total,stats);
    stats = stats->_next;
  }
  
  fd_showstat(&total,&total);
  
  return 0;
}

void fd_periodicstats(struct sched_ent *alarm)
{
  fd_showstats();
  fd_clearstats();  
  alarm->alarm = overlay_gettime_ms()+3000;
  schedule(alarm);
}

int fd_func_enter(struct call_stats *this_call)
{
  this_call->enter_time=overlay_gettime_ms();
  this_call->child_time=0;
  this_call->prev = current_call;
  current_call = this_call;
  return 0;
}

int fd_func_exit(struct call_stats *this_call, struct profile_total *aggregate_stats)
{
  if (current_call != this_call)
    WHYF("stack mismatch, exited through %s()",aggregate_stats->name);
  
  long long now = overlay_gettime_ms();
  long long elapsed=now - this_call->enter_time;
  current_call = this_call->prev;
  
  if (!aggregate_stats->_initialised){
    aggregate_stats->_initialised=1;
    aggregate_stats->_next = stats_head;
    fd_clearstat(aggregate_stats);
    stats_head = aggregate_stats;
  }
  
  if (current_call)
    current_call->child_time+=elapsed;
  
  fd_update_stats(aggregate_stats, (elapsed - this_call->child_time));
  
  return 0;
}

