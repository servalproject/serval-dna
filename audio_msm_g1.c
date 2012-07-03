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

/*
  We ask the driver to reduce it's buffer size, but it doesn't listen.
  This is very strange, as looking in pcm_out.c of kernel source it appears
  that it should work just fine.

  What does work, however, is increasing the sample rate, so that the buffers
  empty sooner. So we use 32000Hz instead of 8000Hz so that the 2KB record buffer
  holds only 1/32nd of a second instead of 1/8th of a second.

  We may need to introduce a low-pass filter to prevent aliasing, assuming that
  the microphone and ACD in these phones responds to requencies above 4KHz.

  Added fun with this device is that we must read/write exactly one buffer full
  at a time.
 */
#define DESIRED_BUFFER_SIZE 256
#define DESIRED_SAMPLE_RATE 32000
#define RESAMPLE_FACTOR (DESIRED_SAMPLE_RATE/8000)
int resamplingBufferSize=0;
unsigned char *playMarshallBuffer=0;
unsigned char *recordMarshallBuffer=0;

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

#if HAVE_LINUX_IOCTL_H
#include <linux/ioctl.h>
#endif

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
  config.sample_rate=DESIRED_SAMPLE_RATE;
  config.buffer_size=DESIRED_BUFFER_SIZE;
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
  ioctl(playFd, AUDIO_GET_CONFIG,&config);
  playBufferSize=config.buffer_size;
  float bufferTime=playBufferSize/2*1.0/config.sample_rate;
  WHYF("PLAY buf=%.3fsecs.",bufferTime);

  playMarshallBuffer=malloc(playBufferSize);

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
  if (playMarshallBuffer) free(playMarshallBuffer);
  playFd=-1; playMarshallBuffer=NULL;
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
  config.sample_rate=DESIRED_SAMPLE_RATE;
  config.buffer_size=DESIRED_BUFFER_SIZE;
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
  ioctl(recordFd, AUDIO_GET_CONFIG,&config);
  recordBufferSize=config.buffer_size;
  float bufferTime=recordBufferSize/2*1.0/config.sample_rate;
  WHYF("REC buf=%.3fsecs.",bufferTime);

  if (!recordMarshallBuffer)
    recordMarshallBuffer=malloc(recordBufferSize);

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
  if (recordMarshallBuffer) free(recordMarshallBuffer);
  recordMarshallBuffer=NULL;
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
    fds[count].events=POLLIN;
    count++; slots--;
  }
  return count;
}

int recordMarshallBufferOffset=0;
int audio_msm_g1_read(unsigned char *buffer,int maximum_count)
{
  if (recordFd==-1) return 0;
  if (!recordMarshallBuffer) return 0;

  int supplied=0;  

  /* read new samples if we don't have any lingering around */  
  if (!recordMarshallBufferOffset) {
    fcntl(recordFd,F_SETFL,fcntl(recordFd, F_GETFL, NULL)|O_NONBLOCK);      
    ioctl(recordFd,AUDIO_START,0);
    WHY("calling read()");
    int b=read(recordFd,&recordMarshallBuffer[0],recordBufferSize);
    if (b<1)
      WHYF("read failed: b=%d, err=%s",b,strerror(errno));
    if (errno==EBADF) recordFd=-1;
    WHYF("read %d raw (upsampled) bytes",b);
    recordMarshallBufferOffset=b;
  } 

  /* supply audio from marshalling buffer if it has anything.
     Don't forget to downsample first. */
  int marshall_offset=0;
  while(marshall_offset<recordMarshallBufferOffset
	&&supplied<maximum_count) {
    buffer[supplied+0]=recordMarshallBuffer[marshall_offset];
    buffer[supplied+1]=recordMarshallBuffer[marshall_offset+1];
    supplied+=2;
    marshall_offset+=2*RESAMPLE_FACTOR;
  }
  bcopy(&recordMarshallBuffer[marshall_offset],
	&recordMarshallBuffer[0],
	recordMarshallBufferOffset-marshall_offset);
  recordMarshallBufferOffset-=marshall_offset;
  
  /* Else we read exactly one buffer full into the marshalling buffer */

  WHYF("Read %d samples.",supplied/2);

  return supplied;
}

int playMarshallBufferOffset=0;
int audio_msm_g1_write(unsigned char *data,int bytes) 
{
  if (playFd==-1) return 0;
  fcntl(playFd,F_SETFL,fcntl(playFd, F_GETFL, NULL)|O_NONBLOCK);
 
  WHYF("Writing %d bytes of 8KHz audio",bytes);

  int i,played=0;

  while(played<bytes)
    {
      if (playMarshallBufferOffset==playBufferSize) {
	/* we have a buffer full of samples, so play it */
	struct msm_audio_stats stats;
	if (ioctl (playFd, AUDIO_GET_STATS, &stats) == 0)
	  WHYF("stats.out_bytes = %10d", stats.out_bytes);
	
	/* even if set non-blocking the following write can block 
	   if we don't call this ioctl first */
	ioctl(playFd,AUDIO_START,0); 
	int w=write(playFd,&playMarshallBuffer[0],playBufferSize);
	if (w<1)
	  {
	    WHYF("Failed to write, returned %d (errno=%s)",
		 w,strerror(errno));
	    if (errno==EBADF) playFd=-1;      
	  } else {
	  if (w<=playBufferSize) {
	    /* short write, so update buffer status and inform caller */
	    bcopy(&playMarshallBuffer[w],&playMarshallBuffer[0],
		  playBufferSize-w);
	    playMarshallBufferOffset-=w;
	    WHYF("short write: %d of %d raw bytes written",
		 w,playBufferSize);
	    return w/RESAMPLE_FACTOR;
	  }
	}
	playMarshallBufferOffset=0;
      }

      /* upsample for playing back */
      for(i=0;i<RESAMPLE_FACTOR;i++) {
	playMarshallBuffer[playMarshallBufferOffset++]
	  =data[played];
	playMarshallBuffer[playMarshallBufferOffset++]
	  =data[played+1];
      }
      played+=2;     
    }

  WHYF("done writing %d audio bytes",played);
  return played;
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
