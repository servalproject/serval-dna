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
#include <poll.h>

struct callback_stats {
  long long max_time;
  long long total_time;
  int calls;
};

#define MAX_ALARMS 128
typedef struct callback_alarm {
  void (*func)();
  long long next_alarm;
  long long repeat_every;

  struct callback_stats stats;
} callback_alarm;

callback_alarm alarms[MAX_ALARMS];
int alarmcount=0;

#define MAX_WATCHED_FDS 128
struct pollfd fds[MAX_WATCHED_FDS];
int fdcount=0;
void(*fd_functions[MAX_WATCHED_FDS])(int fd);  
struct callback_stats fd_stats[MAX_WATCHED_FDS];

struct callback_stats poll_stats={0,0,0};

/* @PGS/20120615 */
int last_valid=0;
int last_line;
const char *last_file;
const char *last_func;
long long last_time;

/* @PGS/20120615 */
void TIMING_PAUSE()
{
  last_valid=0;
}

/* @PGS/20120615 */
void _TIMING_CHECK(const char *file,const char *func,int line)
{
  long long now=overlay_gettime_ms();
  if (last_valid) {
    if (now-last_time>5) {
      // More than 5ms spent in a given task, complain
      char msg[1024];
      snprintf(msg,1024,"Spent %lldms between %s:%d in %s() and here",
	       now-last_time,last_file,last_line,last_func);
      logMessage(LOG_LEVEL_WARN,file,line,func,"%s",msg);
    }
  }

  last_valid=1;
  last_file=file;
  last_func=func;
  last_line=line;
  last_time=now;
}

int fd_watch(int fd,void (*func)(int fd),int events)
{
  if (fd<0||fd>=MAX_WATCHED_FDS) 
    return WHYF("Invalid file descriptor (%d) - must be between 0 and %d",
		MAX_WATCHED_FDS-1);
  if (fdcount>=MAX_WATCHED_FDS)
    return WHYF("Currently watching too many file descriptors.  This should never happen; report a bug.");
  
  fds[fdcount].fd=fd;
  fds[fdcount++].events=events;
  if (func!=fd_functions[fd]) {
    fd_stats[fd].max_time=0;
    fd_stats[fd].total_time=0;
    fd_stats[fd].calls=0;
  }
  fd_functions[fd]=func;

  return 0;
}

int fd_teardown(int fd)
{
  int i;
  for(i=0;i<fdcount;i++)
    if (fds[i].fd==fd) {
      if (i<(fdcount-1)) {
	/* Move last entry in list to this position, and wipe last entry in list */
	fds[i]=fds[fdcount-1];
	fds[fdcount-1].fd=-1;
	fds[fdcount-1].events=0;
      } else {
	/* We are last entry in list, so just wipe */
	fds[i].events=0;
	fds[i].fd=-1;
      }
      fdcount--; i--;
    }
  close(fd);
  return 0;
}

/* Automatically call a function every this many milli-seconds.
   If repeat_every is zero, then the alarm will be a one-shot */
int fd_setalarm(void (*func),long long first_alarm_in,int repeat_every)
{
  int i;
  if (!func) return -1;
  if (first_alarm_in<=0) first_alarm_in=repeat_every;
  if (repeat_every<0) return -1;

  for(i=0;i<alarmcount;i++)
    {
      if (func==alarms[i].func) break;
    }
  if (i>=MAX_ALARMS) return WHY("Too many alarms");

  if (!first_alarm_in) {
    /* remove old alarm */
    alarms[i]=alarms[--alarmcount];
    return 0;
  } else {
    /* Create new alarm, or update existing one */
    if (alarms[i].func!=func) {      
      alarms[i].stats.calls=0;
      alarms[i].stats.max_time=0;
      alarms[i].stats.total_time=0;
    }
    alarms[i].func=func;
    alarms[i].next_alarm=overlay_gettime_ms()+first_alarm_in;
    alarms[i].repeat_every=repeat_every;
    if (i>=alarmcount) alarmcount=i+1;
    return 0;
  }
}

void fd_update_stats(struct callback_stats *s,long long elapsed)
{
  s->total_time+=elapsed;
  if (elapsed>s->max_time) s->max_time=elapsed;
  s->calls++;
}

int fd_checkalarms()
{
  long long now=overlay_gettime_ms();
  int i;

  long long next_alarm_in=15000;

  TIMING_PAUSE(); 
  for(i=0;i<alarmcount;i++)
    {

      if (alarms[i].next_alarm&&alarms[i].next_alarm<=now) {
	now=overlay_gettime_ms();
	alarms[i].func();
	long long elapsed=overlay_gettime_ms()-now;
	fd_update_stats(&alarms[i].stats,elapsed);
	if (!alarms[i].repeat_every) {
	  /* Alarm was one-shot, so erase alarm */
	  fd_setalarm(alarms[i].func,0,0);
	  i--;
	  continue;
	} else
	  /* Alarm is repeating, so set next call */
	  alarms[i].next_alarm=now+alarms[i].repeat_every;
      }
      /* Work out if this alarm is next */
      if (next_alarm_in>(alarms[i].next_alarm-now))
	next_alarm_in=(alarms[i].next_alarm-now);
    }
  return next_alarm_in;
}

int fd_poll()
{
  int i;

  /* See if any alarms have expired before we do anything.
     This also returns the time to the next alarm that is due. */
  int ms=fd_checkalarms();
  /* Make sure we don't have any silly timeouts that will make us wait for ever. */
  if (ms<1) ms=1;
  
  /* Wait for action or timeout */
  long long now=overlay_gettime_ms();
  int r=poll(fds, fdcount, ms);
  long long elapsed=overlay_gettime_ms()-now;
  fd_update_stats(&poll_stats,elapsed);

  /* If file descriptors are ready, then call the appropriate functions */
  if (r>0) {
    for(i=0;i<fdcount;i++)
      if (fds[i].revents) {
	long long now=overlay_gettime_ms();
	fd_functions[fds[i].fd](fds[i].fd);
	long long elapsed=overlay_gettime_ms()-now;
	fd_update_stats(&fd_stats[fds[i].fd],elapsed);
      }
  }

  /* After all that action, we might have an alarm expire, so check the alarms
     again */
  fd_checkalarms();

  return 0;
}

typedef struct func_descriptions {
  void *addr;
  char *description;
} func_descriptions;

func_descriptions func_names[]={
  {overlay_check_ticks,"overlay_check_ticks"},
  {overlay_dummy_poll,"overlay_dummy_poll"},
  {overlay_interface_discover,"overlay_interface_discover"},
  {overlay_route_tick,"overlay_route_tick"},
  {rhizome_enqueue_suggestions,"rhizome_enqueue_suggestions"},
  {server_shutdown_check,"server_shutdown_check"},
  {monitor_client_poll,"monitor_client_poll"},
  {monitor_poll,"monitor_poll"},
  {overlay_interface_poll,"overlay_interface_poll"},
  {overlay_mdp_poll,"overlay_mdp_poll"},
  {rhizome_client_poll,"rhizome_client_poll"},
  {rhizome_fetch_poll,"rhizome_fetch_poll"},
  {rhizome_server_poll,"rhizome_server_poll"},
  {fd_periodicstats,"fd_periodicstats"},
  {vomp_tick,"vomp_tick"},
  {NULL,NULL}
};

#define MAX_FUNCS 1024
struct callback_stats called_funcs[MAX_FUNCS];
const char *called_func_names[MAX_FUNCS];
int func_count=0;

#define MAX_CALL_DEPTH 128
struct {
  int func_id;
  int enter_time;
  int child_time;
} call_stack[MAX_CALL_DEPTH];
int call_stack_depth=0;

char *fd_funcname(void *addr)
{
  int j;
  char *funcname="unknown";
  for(j=0;func_names[j].addr;j++)
    if (func_names[j].addr==addr)
      funcname=func_names[j].description;
  return funcname;
}

int fd_list()
{
  long long now=overlay_gettime_ms();
  int i;
  INFOF("List of timed callbacks:");
  INFOF("------------------------");
  for(i=0;i<alarmcount;i++) {
    INFOF(alarms[i].repeat_every?"() in %lldms and every %lldms":"%s() in %lldms%*",
	  fd_funcname(alarms[i].func),
	  alarms[i].next_alarm-now,alarms[i].repeat_every);
  }

  INFOF("List of watched file descriptors:");
  INFOF("---------------------------------");
  for(i=0;i<fdcount;i++) {
    char *eventdesc="<somethinged>";
    if ((fds[i].events&POLL_IN)&&(fds[i].events&POLL_OUT)) 
      eventdesc="read or written";
    else if (fds[i].events&POLL_IN)
      eventdesc="read";
    else if (fds[i].events&POLL_OUT)
      eventdesc="written";

    INFOF("%s() when fd#%d can be %s",
	  fd_funcname(fd_functions[fds[i].fd]),fds[i].fd,eventdesc);
  }
  return 0;
}

int fd_tallystats(struct callback_stats *total,struct callback_stats *a)
{
  total->total_time+=a->total_time;
  total->calls+=a->calls;
  if (a->max_time>total->max_time) total->max_time=a->max_time;
  return 0;
}

int fd_showstat(struct callback_stats *total, struct callback_stats *a, const char *msg)
{
  WHYF("%lldms (%2.1f%%) in %d calls (max %lldms, avg %.1fms) : %s",
       a->total_time,a->total_time*100.0/total->total_time,
       a->calls,
       a->max_time,a->total_time*1.00/a->calls,
       msg);
  return 0;
}

int fd_clearstat(struct callback_stats *s)
{
  s->calls=0;
  s->max_time=0;
  s->total_time=0;
  return 0;
}

int fd_clearstats()
{
  int i;
  fd_clearstat(&poll_stats);
  for(i=0;i<alarmcount;i++)
    fd_clearstat(&alarms[i].stats);
  for(i=0;i<fdcount;i++)
    fd_clearstat(&fd_stats[fds[i].fd]);
  for(i=0;i<func_count;i++)
    fd_clearstat(&called_funcs[i]);

  return 0;
}

int fd_showstats()
{
  int i;
  struct callback_stats total={0,0,0};

  /* Get total time spent doing everything */
  fd_tallystats(&total,&poll_stats);
  for(i=0;i<alarmcount;i++)
    fd_tallystats(&total,&alarms[i].stats);
  for(i=0;i<fdcount;i++)
    fd_tallystats(&total,&fd_stats[fds[i].fd]);

  /* Now show stats */
  INFOF("servald time usage stats:");
  fd_showstat(&total,&poll_stats,"Idle (in poll)");
  for(i=0;i<alarmcount;i++) {
    char desc[1024];
    snprintf(desc,1024,"%s() alarm callback",fd_funcname(alarms[i].func));
    fd_showstat(&total,&alarms[i].stats,desc);
  }
  for(i=0;i<fdcount;i++) {
    char desc[1024];
    snprintf(desc,1024,"%s() fd#%d callback",
	     fd_funcname(fd_functions[fds[i].fd]),fds[i].fd);
    fd_showstat(&total,&fd_stats[fds[i].fd],desc);
  }
  fd_showstat(&total,&total,"TOTAL");
  INFOF("servald function time statistics:");
  for(i=0;i<func_count;i++)
    if (called_funcs[i].calls)
      fd_showstat(&total,&called_funcs[i],called_func_names[i]);

  return 0;
}

void fd_periodicstats()
{
  fd_showstats();
  fd_clearstats();  
}

int fd_next_funcid(const char *funcname)
{
  if (func_count>=MAX_FUNCS) return MAX_FUNCS-1;
  fd_clearstat(&called_funcs[func_count]);
  called_func_names[func_count]=funcname;
  return func_count++;
}

int fd_func_enter(int funcid)
{
  if (call_stack_depth>=MAX_CALL_DEPTH) return 0;
  call_stack[call_stack_depth].func_id=funcid;
  call_stack[call_stack_depth].enter_time=overlay_gettime_ms();
  call_stack[call_stack_depth].child_time=0;
  call_stack_depth++;
  return 0;
}

int fd_func_exit(int funcid)
{
  if (funcid!=call_stack[call_stack_depth-1].func_id)
    exit(WHYF("func_id mismatch: entered through %s(), but exited through %s()",
	      called_func_names[call_stack[call_stack_depth-1].func_id],
	      called_func_names[funcid]));

  long long elapsed=overlay_gettime_ms()-call_stack[call_stack_depth-1].enter_time;
  long long self_elapsed=elapsed-call_stack[call_stack_depth-1].child_time;
  if (call_stack_depth>1) {
    int d=call_stack_depth-2;
    call_stack[d].child_time+=elapsed;
  }
  fd_update_stats(&called_funcs[funcid],self_elapsed);
  call_stack_depth--;
  return 0;
}

