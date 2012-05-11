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
   
   Contains code derived from playwav2.c, which has the following notice:
   
   Copyright (C) 2008 The Android Open Source Project
*/

extern int playFd;
extern int recordFd;
extern int playBufferSize;
extern int recordBufferSize;

#include "serval.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <errno.h>

#include <linux/ioctl.h>

#if 0
#include <linux/msm_audio.h>
#else
/* ---------- linux/msm_audio.h -------- */

#define AUDIO_IOCTL_MAGIC 'a'

#define AUDIO_START        _IOW(AUDIO_IOCTL_MAGIC, 0, unsigned)
#define AUDIO_STOP         _IOW(AUDIO_IOCTL_MAGIC, 1, unsigned)
#define AUDIO_FLUSH        _IOW(AUDIO_IOCTL_MAGIC, 2, unsigned)
#define AUDIO_GET_CONFIG   _IOR(AUDIO_IOCTL_MAGIC, 3, unsigned)
#define AUDIO_SET_CONFIG   _IOW(AUDIO_IOCTL_MAGIC, 4, unsigned)
#define AUDIO_GET_STATS    _IOR(AUDIO_IOCTL_MAGIC, 5, unsigned)
#define AUDIO_ENABLE_AUDPP _IOW(AUDIO_IOCTL_MAGIC, 6, unsigned)
#define AUDIO_SET_ADRC     _IOW(AUDIO_IOCTL_MAGIC, 7, unsigned)
#define AUDIO_SET_EQ       _IOW(AUDIO_IOCTL_MAGIC, 8, unsigned)
#define AUDIO_SET_RX_IIR   _IOW(AUDIO_IOCTL_MAGIC, 9, unsigned)

#define EQ_MAX_BAND_NUM	12

#define ADRC_ENABLE  0x0001
#define ADRC_DISABLE 0x0000
#define EQ_ENABLE    0x0002
#define EQ_DISABLE   0x0000
#define IIR_ENABLE   0x0004
#define IIR_DISABLE  0x0000

struct eq_filter_type
{
  int16_t gain;
  uint16_t freq;
  uint16_t type;
  uint16_t qf;
};

struct eqalizer
{
  uint16_t bands;
  uint16_t params[132];
};

struct rx_iir_filter
{
  uint16_t num_bands;
  uint16_t iir_params[48];
};


struct msm_audio_config
{
  uint32_t buffer_size;
  uint32_t buffer_count;
  uint32_t channel_count;
  uint32_t sample_rate;
  uint32_t codec_type;
  uint32_t unused[3];
};

struct msm_audio_stats
{
  uint32_t out_bytes;
  uint32_t unused[3];
};

/* Audio routing */

#define SND_IOCTL_MAGIC 's'

#define SND_MUTE_UNMUTED 0
#define SND_MUTE_MUTED   1

struct msm_snd_device_config
{
  uint32_t device;
  uint32_t ear_mute;
  uint32_t mic_mute;
};

#define SND_SET_DEVICE _IOW(SND_IOCTL_MAGIC, 2, struct msm_device_config *)

#define SND_METHOD_VOICE 0

#define SND_METHOD_VOICE_1 1

struct msm_snd_volume_config
{
  uint32_t device;
  uint32_t method;
  uint32_t volume;
};

#define SND_SET_VOLUME _IOW(SND_IOCTL_MAGIC, 3, struct msm_snd_volume_config *)

/* Returns the number of SND endpoints supported. */

#define SND_GET_NUM_ENDPOINTS _IOR(SND_IOCTL_MAGIC, 4, unsigned *)

struct msm_snd_endpoint
{
  int id;			/* input and output */
  char name[64];		/* output only */
};

/* Takes an index between 0 and one less than the number returned by
 * SND_GET_NUM_ENDPOINTS, and returns the SND index and name of a
 * SND endpoint.  On input, the .id field contains the number of the
 * endpoint, and on exit it contains the SND index, while .name contains
 * the description of the endpoint.
 */

#define SND_GET_ENDPOINT _IOWR(SND_IOCTL_MAGIC, 5, struct msm_snd_endpoint *)

#endif

static int
do_route_audio_rpc (uint32_t device, int ear_mute, int mic_mute)
{
  if (device == -1UL)
    return 0;

  int fd;

  printf ("rpc_snd_set_device(%d, %d, %d)\n", device, ear_mute, mic_mute);

  fd = open ("/dev/msm_snd", O_RDWR);
  if (fd < 0)
    {
      perror ("Can not open snd device");
      return -1;
    }
  // RPC call to switch audio path
  /* rpc_snd_set_device(
   *     device,            # Hardware device enum to use
   *     ear_mute,          # Set mute for outgoing voice audio
   *                        # this should only be unmuted when in-call
   *     mic_mute,          # Set mute for incoming voice audio
   *                        # this should only be unmuted when in-call or
   *                        # recording.
   *  )
   */
  struct msm_snd_device_config args;
  args.device = device;
  args.ear_mute = ear_mute ? SND_MUTE_MUTED : SND_MUTE_UNMUTED;
  args.mic_mute = mic_mute ? SND_MUTE_MUTED : SND_MUTE_UNMUTED;

  if (ioctl (fd, SND_SET_DEVICE, &args) < 0)
    {
      perror ("snd_set_device error.");
      close (fd);
      return -1;
    }

  close (fd);
  return 0;
}

static int
set_volume_rpc (uint32_t device, uint32_t method, uint32_t volume)
{
  int fd;

  printf ("rpc_snd_set_volume(%d, %d, %d)\n", device, method, volume);

  if (device == -1UL)
    return 0;

  fd = open ("/dev/msm_snd", O_RDWR);
  if (fd < 0)
    {
      perror ("Can not open snd device");
      return -1;
    }
  /* rpc_snd_set_volume(
   *     device,            # Any hardware device enum, including
   *                        # SND_DEVICE_CURRENT
   *     method,            # must be SND_METHOD_VOICE to do anything useful
   *     volume,            # integer volume level, in range [0,5].
   *                        # note that 0 is audible (not quite muted)
   *  )
   * rpc_snd_set_volume only works for in-call sound volume.
   */
  struct msm_snd_volume_config args;
  args.device = device;
  args.method = method;
  args.volume = volume;

  if (ioctl (fd, SND_SET_VOLUME, &args) < 0)
    {
      perror ("snd_set_volume error.");
      close (fd);
      return -1;
    }
  close (fd);
  return 0;
}

/* Prepare audio path, volume etc, and then open play and
   record file descriptors. 
*/
int audio_msm_g1_start_play()
{
  if (playFd>-1) return 0;

  /* Get audio control device */
  int fd = open ("/dev/msm_snd", O_RDWR);
  if (fd<0) return -1;

  /* Look through endpoints for the regular in-call endpoint */
  int endpoints=0;
  ioctl(fd,SND_GET_NUM_ENDPOINTS,&endpoints);
  int endpoint=-1;
  int i;
  for(i=0;i<endpoints;i++) {
    struct msm_snd_endpoint ep;
    ep.id=i;
    ep.name[0]=0;
    ioctl(fd,SND_GET_ENDPOINT,&ep);
    if (!strcasecmp(ep.name,"HANDSET"))  
      /* should this be i, or ep.id ? */
      endpoint=i;
  }
  close(fd);

  /* Set the specified endpoint and unmute microphone and speaker */
  do_route_audio_rpc(endpoint,SND_MUTE_UNMUTED,SND_MUTE_UNMUTED);

  /* Set the volume (somewhat arbitrarily for now) */
  int vol=5;
  int dev=0xd; /* no one seems to know what this magic value means */
  set_volume_rpc(dev,SND_METHOD_VOICE_1, vol);

  playFd=open("/dev/msm_pcm_out",O_RDWR);
  struct msm_audio_config config;
  if (ioctl(playFd, AUDIO_GET_CONFIG,&config))
    {
      close(playFd);
      playFd=-1;
      return WHY("Could not read audio device configuration");
    }
  config.channel_count=1;
  config.sample_rate=8000;
  playBufferSize=config.buffer_size;
  if (ioctl(playFd, AUDIO_SET_CONFIG,&config))
    {
      close(playFd);
      playFd=-1;
      return WHY("Could not set audio device configuration");
    }
  
  fcntl(playFd,F_SETFL,
	fcntl(playFd, F_GETFL, NULL)|O_NONBLOCK);

  /*
    If playBufferSize equates to too long an interval,
    then try to reduce it in various ways.
  */    
  float bufferTime=playBufferSize/2*1.0/config.sample_rate;
  if (bufferTime>0.02) {
    WHYF("PLAY buf=%.3fsecs, which is too long. Trying to reduce it.",
	 bufferTime);

    /* 64 bytes = 32 samples = ~4ms */
    config.buffer_size=64*8;
    config.buffer_count=2;
    if (!ioctl(playFd, AUDIO_SET_CONFIG,&config))
      {
	if (!ioctl(playFd, AUDIO_GET_CONFIG,&config)) {
	  playBufferSize=config.buffer_size;
	  bufferTime=playBufferSize/2*1.0/config.sample_rate;
	  WHYF("Succeeded in reducing play buffer to %d bytes (%.3fsecs)",
	       playBufferSize,bufferTime);
	  goto fixedBufferSize;
	}
      }
  }
 fixedBufferSize:
 
  /* tell hardware to start playing */
  ioctl(playFd,AUDIO_START,0);
  
  WHYF("G1/IDEOS style MSM audio device initialised and ready to play");
  WHYF("Play buffer size = %d bytes",playBufferSize);
  return 0;
}

int audio_msm_g1_stop_play()
{
  WHY("stopping audio play");
  if (playFd>-1) close(playFd);
  playFd=-1;
  return 0;
}

int audio_msm_g1_start_record()
{
  if (recordFd>-1) return 0;

  recordFd=open("/dev/msm_pcm_in",O_RDWR);
  struct msm_audio_config config;
  if (ioctl(recordFd, AUDIO_GET_CONFIG,&config))
    {
      close(recordFd);
      recordFd=-1;
      return WHY("Could not read audio device configuration");
    }
  config.channel_count=1;
  config.sample_rate=8000;
  if (ioctl(recordFd, AUDIO_SET_CONFIG,&config))
    {
      close(recordFd);
      recordFd=-1;
      return WHY("Could not set audio device configuration");
    }

  /*
    If recordBufferSize equates to too long an interval,
    then try to reduce it in various ways.
  */  
  recordBufferSize=config.buffer_size;
  float bufferTime=recordBufferSize/2*1.0/config.sample_rate;
  if (bufferTime>0.02) {
    WHYF("REC buf=%.3fsecs, which is too long. Trying to reduce it.",
	 bufferTime);

    /* 64 bytes = 32 samples = ~4ms */
    config.buffer_size=64*8;
    config.buffer_count=2;
    if (!ioctl(recordFd, AUDIO_SET_CONFIG,&config))
      {
	if (!ioctl(playFd, AUDIO_GET_CONFIG,&config)) {
	  recordBufferSize=config.buffer_size;
	  bufferTime=recordBufferSize/2*1.0/config.sample_rate;
	  WHYF("Succeeded in reducing record buffer to %d bytes (%.3fsecs)",
	       recordBufferSize,bufferTime);
	  goto fixedBufferSize;
	}
      }

#if 0
    /* Ask for 2x speed and 2x channels, to divide effective buffer size by 4.
     */
    config.sample_rate=16000;
    config.channel_count=2;
#endif
  }
 fixedBufferSize:

  fcntl(recordFd,F_SETFL,
	fcntl(recordFd, F_GETFL, NULL)|O_NONBLOCK);
  
  /* tell hardware to start playing */
  ioctl(recordFd,AUDIO_START,0);

  WHY("G1/IDEOS style MSM audio device initialised and ready to record");  
  return 0;
}

int audio_msm_g1_stop_record()
{
  WHY("stopping recording");
  if (recordFd>-1) close(recordFd);
  recordFd=-1;
  return 0;
}

int audio_msm_g1_stop()
{
  audio_msm_g1_stop_play();
  audio_msm_g1_stop_record();
  return 0;
}

int audio_msm_g1_start()
{
  if (audio_msm_g1_start_play()) return -1;
  if (audio_msm_g1_start_record()) {
    audio_msm_g1_stop_play();
    return -1;
  }
  return 0;
}

int audio_msm_g1_poll_fds(struct pollfd *fds,int slots)
{
  int count=0;
  if (playFd>-1&&slots>0) {
    fds[count].fd=playFd;
    fds[count].events=POLL_IN;
    count++; slots--;
  }
  return count;
}

int audio_msm_g1_read(unsigned char *buffer,int maximum_count)
{
  if (recordFd==-1) return 0;

  /* Regardless of the maximum, we must read exactly buffer sized pieces
     on this audio device */
  if (maximum_count<recordBufferSize) {
    return WHY("Supplied buffer has no space for sample quanta");
  }
  fcntl(recordFd,F_SETFL,fcntl(recordFd, F_GETFL, NULL)|O_NONBLOCK);
  int b=read(recordFd,&buffer[0],recordBufferSize);
  if (b<1) 
    WHYF("read failed: b=%d, err=%s",b,strerror(errno));
  else 
    WHYF("read %d bytes",b);
  if (errno=EBADF) recordFd=-1;
  return b;
}

int playBufferBytes=0;
unsigned char playBuffer[65536];
int audio_msm_g1_write(unsigned char *data,int bytes) 
{
  if (playFd==-1) return 0;
  fcntl(playFd,F_SETFL,fcntl(playFd, F_GETFL, NULL)|O_NONBLOCK);
  if (bytes+playBufferBytes>65536)
    { WHY("Play marshalling buffer full");
      return 0; }
  bcopy(&data[0],&playBuffer[playBufferBytes],bytes);
  playBufferBytes+=bytes;
  int i;
  for(i=0;i<playBufferBytes;)
    {
      struct msm_audio_stats stats;
      if (ioctl (playFd, AUDIO_GET_STATS, &stats) == 0)
	WHYF("stats.out_bytes = %10d", stats.out_bytes);

      int bytes=playBufferSize;
      if (i+bytes>playBufferBytes) bytes=playBufferBytes-i;
      WHYF("Trying to write %d bytes of audio",bytes);
      ioctl(playFd,AUDIO_START,0);
      fcntl(playFd,F_SETFL,fcntl(playFd, F_GETFL, NULL)|O_NONBLOCK);
      int w=0;
      WHYF("write(%d,&pb[%d],%d) (playBufferBytes=%d)",
	   playFd,i,bytes,playBufferBytes);
      if ((w=write(playFd,&playBuffer[i],bytes))<
	  1)
	{
	  WHYF("Failed to write, returned %d (errno=%s)",
	       w,strerror(errno));
	  if (errno==EBADF) playFd=-1;
	  break;
	} else {
	WHYF("Wrote %d bytes of audio",w);
	i+=w;
      }
      WHY("after write");
    }
  bcopy(&playBuffer[i],&playBuffer[0],playBufferBytes-i);
  playBufferBytes-=i;

  WHY("done writing");
  return bytes;
}

/* See if we can query end-points for this device.
   If so, assume we have detected it. 
*/
monitor_audio *audio_msm_g1_detect()
{
   int fd = open ("/dev/msm_snd", O_RDWR);
   if (fd<0) {
     WHYF("Could not open /dev/msm_snd (err=%s)",strerror(errno));
     return NULL;
   }
   int endpoints=0;
   ioctl(fd,SND_GET_NUM_ENDPOINTS,&endpoints);
   close(fd);
   if (endpoints>0)  {
     monitor_audio *au=calloc(sizeof(monitor_audio),1);
     strcpy(au->name,"G1/IDEOS style MSM audio");
     au->start=audio_msm_g1_start;
     au->stop=audio_msm_g1_stop;
     au->poll_fds=audio_msm_g1_poll_fds;
     au->read=audio_msm_g1_read;
     au->write=audio_msm_g1_write;
     return au;
   } else {
     WHY("zero end points, so assuming not compatibile audio device");
     return NULL;
   }
}
