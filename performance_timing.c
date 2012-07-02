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

struct callback_stats *stats_head=NULL;
struct call_stats *current_call=NULL;

void fd_clearstat(struct callback_stats *s){
  s->max_time = 0;
  s->total_time = 0;
  s->calls = 0;
}

void fd_update_stats(struct callback_stats *s,long long elapsed)
{
  s->total_time+=elapsed;
  if (elapsed>s->max_time) s->max_time=elapsed;
  s->calls++;
}

int fd_tallystats(struct callback_stats *total,struct callback_stats *a)
{
  total->total_time+=a->total_time;
  total->calls+=a->calls;
  if (a->max_time>total->max_time) total->max_time=a->max_time;
  return 0;
}

int fd_showstat(struct callback_stats *total, struct callback_stats *a)
{
  INFOF("%lldms (%2.1f%%) in %d calls (max %lldms, avg %.1fms) : %s",
       a->total_time,a->total_time*100.0/total->total_time,
       a->calls,
       a->max_time,a->total_time*1.00/a->calls,
       a->name);
  return 0;
}

int fd_clearstats()
{
  struct callback_stats *stats = stats_head;
  while(stats!=NULL){
    fd_clearstat(stats);
    stats = stats->_next;
  }
  return 0;
}

int fd_showstats()
{
  struct callback_stats total={NULL, 0, "Total", 0,0,0};
  
  struct callback_stats *stats = stats_head;
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

int fd_func_exit(struct call_stats *this_call, struct callback_stats *aggregate_stats)
{
  if (current_call != this_call)
    WHYF("stack mismatch, exited through %s()",aggregate_stats->name);
  
  long long now = overlay_gettime_ms();
  long long elapsed=now - this_call->enter_time;
  current_call = this_call->prev;
  
  if (current_call)
    current_call->child_time+=elapsed;
  
  fd_update_stats(aggregate_stats, (elapsed - this_call->child_time));
  
  if (!aggregate_stats->_initialised){
    aggregate_stats->_initialised=1;
    aggregate_stats->_next = stats_head;
    stats_head = aggregate_stats;
  }
  
  return 0;
}

