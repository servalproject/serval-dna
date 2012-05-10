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

int encodeAndDispatchRecordedAudio(int fd,int callSessionToken,
				   int recordCodec,
				   unsigned char *sampleData,
				   int sampleBytes)
{
  switch (recordCodec) {
  case VOMP_CODEC_PCM:
    /* leave data raw, so need to rewrite sampleData or sampleBytes */
    break;
  default:
    WHYF("Codec not yet supported");
    return -1;
  }

  char msg[128+MAX_AUDIO_BYTES];
  snprintf(msg,128,"\n*%d:AUDIO:%x:%d\n",sampleBytes,callSessionToken,recordCodec);
  int len=strlen(msg);
  bcopy(&sampleData[0],&msg[len],sampleBytes);
  len+=sampleBytes;
  write(fd,msg,len);
  return 0;
}

int bufferAudioForPlayback(int codec,long long start_time,long long end_time,
		unsigned char *data,int dataLen)
{
  /* XXX We need to buffer and reorder out-of-order sample blocks and
     decode codecs etc here. */

  /* send audio to device */
  int bytesWritten=audev->write(&data[0],dataLen);
  return 0;
}
