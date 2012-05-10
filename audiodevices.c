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

#define AUDIO_MSM_G1_ETC 1
#define AUDIO_MSM_N1_ETC 2
monitor_audio *audev=NULL;

int playFd=-1;
int recordFd=-1;
int playBufferSize=0;
int recordBufferSize=0;

int detectAudioDevice()
{
  if (!audev) audev=audio_msm_g1_detect();
  if (!audev) audev=audio_alsa_detect();
  if (audev) {
    WHYF("Detected audio device '%s'",audev->name);
    return 0;
  }
  return -1;
}

int getAudioPlayFd() 
{
  return playFd;
}

int getAudioRecordFd() 
{
  return recordFd;
}

/* read some audio, but not more than bufferSize-offset bytes.
 */
int getAudioBytes(unsigned char *buffer,
		  int offset,
		  int bufferSize) 
{
  if (audev&&audev->write) {
    return audev->write(&buffer[offset],bufferSize-offset);    
  }
  return -1;
}

int stopAudio()
{
  if (audev&&audev->stop) return audev->stop();
  return -1;
}

int startAudio()
{
  if (audev&&audev->start) return audev->start();
  return -1;
}
