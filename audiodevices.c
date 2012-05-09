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
int detectedAudioDevice=-1;
char *detectedAudioDeviceName=NULL;

int playFd=-1;
int recordFd=-1;
int playBufferSize=0;
int recordBufferSize=0;

int detectAudioDevice()
{
  detectedAudioDeviceName=audio_msm_g1_detect();
  if (detectedAudioDeviceName) {
    detectedAudioDevice=AUDIO_MSM_G1_ETC;
    WHYF("Detected audio device '%s'",detectedAudioDeviceName);
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
  switch(detectedAudioDevice) {
    /* some devices require reading a whole buffer in one go */
  case AUDIO_MSM_G1_ETC:
    {
      if (bufferSize-offset<recordBufferSize) {
	return WHY("Supplied buffer has no space for new samples");
      }
      int b=read(recordFd,&buffer[offset],recordBufferSize);
      if (b>0) offset+=b;
      return offset;
    }
    break;
    /* while others allow reading an arbitrary amount */
  default:
    {
      int b=read(recordFd,&buffer[offset],bufferSize-offset);
      if (b>0) offset+=b;
      return offset;
    }
    break;
  }
  return WHYF("Reading audio for device class #%d not implemented",
	      detectedAudioDevice);
}

/* as with recording, some of the devices have a fixed buffer size that
   we must completely fill. 
*/
int playBufferBytes=0;
unsigned char playBuffer[65536];
int playAudio(unsigned char *data,int bytes)
{
  switch(detectedAudioDevice) {
    /* some devices require reading a whole buffer in one go */
  case AUDIO_MSM_G1_ETC:
    if (bytes+playBufferBytes>65536)
      return WHY("Play marshalling buffer full");
    bcopy(&data[0],&playBuffer[playBufferBytes],bytes);
    playBufferBytes+=bytes;
    int i;
    for(i=0;i<playBufferBytes;i+=playBufferSize)
      {
	if (write(playFd,&playBuffer[i],playBufferSize)<
	    playBufferSize) 
	  break;	  
      }
    bcopy(&playBuffer[i],&playBuffer[0],playBufferBytes-i);
    playBufferBytes-=i;
    break;
    /* the rest we can just write() to */
  default:
    if (write(playFd,data,bytes)<bytes) 
      return WHY("short write() when playing audio");
    return 0;
  }

  return WHYF("Playing audio for device class #%d not implemented",
	      detectedAudioDevice);
}

int stopAudio()
{
  switch(detectedAudioDevice) {
  case AUDIO_MSM_G1_ETC:
    return audio_msm_g1_stop();
    break;
  default:
    break;
  }
  return WHYF("Stopping audio for device class #%d not implemented",
	      detectedAudioDevice);
}

int startAudio()
{
  switch(detectedAudioDevice) {
  case AUDIO_MSM_G1_ETC:
    return audio_msm_g1_start();
    break;
  default:
    break;
  }
  return WHYF("Starting audio for device class #%d not implemented",
	      detectedAudioDevice);
}
