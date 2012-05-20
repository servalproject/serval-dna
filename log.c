/* 
Serval Distributed Numbering Architecture (DNA)
Copyright (C) 2010 Paul Gardner-Stephen 

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

int debug = 0;

#ifdef ANDROID
#include <android/log.h> 
#endif

void logMessage(int level, char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  vlogMessage(level, fmt, ap);
  va_end(ap);
}

void vlogMessage(int level, char *fmt, va_list ap)
{
  va_list ap2;
  char buf[8192];
  va_copy(ap2, ap);
  vsnprintf(buf, sizeof buf, fmt, ap2);
  va_end(ap2);
  buf[sizeof buf - 1] = '\0';
#ifdef ANDROID
  int alevel = ANDROID_LOG_UNKNOWN;
  switch (level) {
    case LOG_LEVEL_FATAL: alevel = ANDROID_LOG_FATAL; break;
    case LOG_LEVEL_ERROR: alevel = ANDROID_LOG_ERROR; break;
    case LOG_LEVEL_INFO:  alevel = ANDROID_LOG_INFO; break;
    case LOG_LEVEL_WARN:  alevel = ANDROID_LOG_WARN; break;
    case LOG_LEVEL_DEBUG: alevel = ANDROID_LOG_DEBUG; break;
  }
  __android_log_print(alevel, "servald", "%s", buf);
#endif
  const char *levelstr = "UNKNOWN";
  switch (level) {
    case LOG_LEVEL_FATAL: levelstr = "FATAL"; break;
    case LOG_LEVEL_ERROR: levelstr = "ERROR"; break;
    case LOG_LEVEL_INFO:  levelstr = "INFO"; break;
    case LOG_LEVEL_WARN:  levelstr = "WARN"; break;
    case LOG_LEVEL_DEBUG: levelstr = "DEBUG"; break;
  }
  fprintf(stderr, "%s: %s\n", levelstr, buf);
}

int setReason(char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  vlogMessage(LOG_LEVEL_ERROR, fmt, ap);
  va_end(ap);
  return -1;
}

int dump(char *name, unsigned char *addr, int len)
{
  int i,j;
  fprintf(stderr,"Dump of %s\n",name);
  for(i=0;i<len;i+=16) 
    {
      fprintf(stderr,"  %04x :",i);
      for(j=0;j<16&&(i+j)<len;j++) fprintf(stderr," %02x",addr[i+j]);
      for(;j<16;j++) fprintf(stderr,"   ");
      fprintf(stderr,"    ");
      for(j=0;j<16&&(i+j)<len;j++) fprintf(stderr,"%c",addr[i+j]>=' '&&addr[i+j]<0x7f?addr[i+j]:'.');
      fprintf(stderr,"\n");
    }
  return 0;
}

int dumpResponses(struct response_set *responses)
{
  struct response *r;
  if (!responses) {fprintf(stderr,"Response set is NULL\n"); return 0; }
  fprintf(stderr,"Response set claims to contain %d entries.\n",responses->response_count);
  r=responses->responses;
  while(r)
    {
      fprintf(stderr,"  response code 0x%02x\n",r->code);
      if (r->next)
	if (r->next->prev!=r) fprintf(stderr,"    !! response chain is broken\n");
      r=r->next;
    }
  return 0;
}

long long debugFlagMask(const char *flagname) {
  if	  (!strcasecmp(flagname,"all"))			return -1;
  else if (!strcasecmp(flagname,"interfaces"))		return DEBUG_OVERLAYINTERFACES;
  else if (!strcasecmp(flagname,"rx"))			return DEBUG_PACKETRX;
  else if (!strcasecmp(flagname,"tx"))			return DEBUG_PACKETTX;
  else if (!strcasecmp(flagname,"verbose"))		return DEBUG_VERBOSE;
  else if (!strcasecmp(flagname,"verbio"))		return DEBUG_VERBOSE_IO;
  else if (!strcasecmp(flagname,"peers"))		return DEBUG_PEERS;
  else if (!strcasecmp(flagname,"dnaresponses"))	return DEBUG_DNARESPONSES;
  else if (!strcasecmp(flagname,"dnarequests"))		return DEBUG_DNAREQUESTS;
  else if (!strcasecmp(flagname,"simulation"))		return DEBUG_SIMULATION;
  else if (!strcasecmp(flagname,"dnavars"))		return DEBUG_DNAVARS;
  else if (!strcasecmp(flagname,"packetformats"))	return DEBUG_PACKETFORMATS;
  else if (!strcasecmp(flagname,"packetconstruction"))	return DEBUG_PACKETCONSTRUCTION;
  else if (!strcasecmp(flagname,"gateway"))		return DEBUG_GATEWAY;
  else if (!strcasecmp(flagname,"hlr"))			return DEBUG_HLR;
  else if (!strcasecmp(flagname,"sockio"))		return DEBUG_IO;
  else if (!strcasecmp(flagname,"frames"))		return DEBUG_OVERLAYFRAMES;
  else if (!strcasecmp(flagname,"abbreviations"))	return DEBUG_OVERLAYABBREVIATIONS;
  else if (!strcasecmp(flagname,"routing"))		return DEBUG_OVERLAYROUTING;
  else if (!strcasecmp(flagname,"security"))		return DEBUG_SECURITY;
  else if (!strcasecmp(flagname,"rhizome"))	        return DEBUG_RHIZOME;
  else if (!strcasecmp(flagname,"filesync"))		return DEBUG_RHIZOMESYNC;
  else if (!strcasecmp(flagname,"monitorroutes"))	return DEBUG_OVERLAYROUTEMONITOR;
  else if (!strcasecmp(flagname,"queues"))		return DEBUG_QUEUES;
  else if (!strcasecmp(flagname,"broadcasts"))		return DEBUG_BROADCASTS;
  WARNF("Unsupported debug flag '%s'", flagname);
  return 0;
}

