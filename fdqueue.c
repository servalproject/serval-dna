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

#define MAX_ALARMS 128
typedef struct callback_alarm {
  void (*func)();
  long long next_alarm;
  long long repeat_every;
} callback_alarm;

callback_alarm alarms[MAX_ALARMS];
int alarmcount=0;

#define MAX_WATCHED_FDS 128
struct pollfd fds[MAX_WATCHED_FDS];
int fdcount=0;
void(*fd_functions[MAX_WATCHED_FDS])(int fd);  

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
    alarms[i].func=func;
    alarms[i].next_alarm=overlay_gettime_ms()+first_alarm_in;
    alarms[i].repeat_every=repeat_every;
    if (i>=alarmcount) alarmcount=i+1;
    return 0;
  }
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
	_TIMING_CHECK(__FILE__,fd_funcname(alarms[i].func),-1);
	alarms[i].func();
	TIMING_CHECK();
	TIMING_PAUSE();
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

  TIMING_PAUSE();
    /* Wait for action or timeout */
  int r=poll(fds, fdcount, ms);

  /* If file descriptors are ready, then call the appropriate functions */
  if (r>0) {
    for(i=0;i<fdcount;i++)
      if (fds[i].revents) {
	_TIMING_CHECK(__FILE__,fd_funcname(fd_functions[fds[i].fd]),-1);
	fd_functions[fds[i].fd](fds[i].fd);
	TIMING_CHECK();
	TIMING_PAUSE();
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
  {NULL,NULL}
};

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
  fprintf(stderr,"\n");
  fprintf(stderr,"List of timed callbacks:\n");
  fprintf(stderr,"------------------------\n");
  for(i=0;i<alarmcount;i++) {
    fprintf(stderr,"%s() in %lldms ",fd_funcname(alarms[i].func),
	    alarms[i].next_alarm-now);
    if (alarms[i].repeat_every) fprintf(stderr,"and every %lldms",
					alarms[i].repeat_every);
    fprintf(stderr,"\n");
  }

  fprintf(stderr,"List of watched file descriptors:\n");
  fprintf(stderr,"---------------------------------\n");
  for(i=0;i<fdcount;i++) {
    char *eventdesc="<somethinged>";
    if ((fds[i].events&POLL_IN)&&(fds[i].events&POLL_OUT)) 
      eventdesc="read or written";
    else if (fds[i].events&POLL_IN)
      eventdesc="read";
    else if (fds[i].events&POLL_OUT)
      eventdesc="written";

    fprintf(stderr,"%s() when fd#%d can be %s\n",
	    fd_funcname(fd_functions[fds[i].fd]),fds[i].fd,eventdesc);
  }
  return 0;
}
