/* 
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

int audio_reflector_null() { return 0; }
int audio_reflector_pollfds(struct pollfd *fd,int slots) { return 0; }

unsigned char reflectBuffer[8192];
int reflectBufferLen=0;

int audio_reflector_write(unsigned char *buffer,int len)
{
  if (reflectBufferLen+len>=8192) 
    len=8192-reflectBufferLen;
  bcopy(&buffer[0],&reflectBuffer[reflectBufferLen],len);
  reflectBufferLen+=len;
  return len;
}

int audio_reflector_read(unsigned char *buffer,int maximum_count)
{
  int count=reflectBufferLen;
  if (count>maximum_count) count=maximum_count;
  bcopy(&reflectBuffer[0],&buffer[0],count);
  bcopy(&reflectBuffer[count],&reflectBuffer[0],
	reflectBufferLen-count);
  reflectBufferLen-=count;
  return count;
}

monitor_audio *audio_reflector_detect()
{
  monitor_audio *au=calloc(sizeof(monitor_audio),1);
  strcpy(au->name,"Echo Reflector");
  au->start=audio_reflector_null;
  au->stop=audio_reflector_null;
  au->poll_fds=audio_reflector_pollfds;
  au->read=audio_reflector_read;
  au->write=audio_reflector_write;
  return au;
}
