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

#ifdef HAVE_ALSA_ASOUNDLIB_H

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <alsa/asoundlib.h>

#ifndef ANDROID
#define ALSA_LIB_PATH "/lib/libasound.so.2"
#else
// XXX Verify on a SGS2 ?
#define ALSA_LIB_PATH "/system/lib/libasound.so.2"
#endif

/* 
   For Android systems we have the fun that this binary (not just the source code)
   needs to be able to run on systems that lack the alsa library.

   This means it is time for some more dlopen() and dlsym() fun to get the
   necessary symbols we need.
*/
typedef struct alsa_functions {
  int (*snd_pcm_open)(snd_pcm_t **,char *,int,int);
  int (*snd_pcm_close)(snd_pcm_t *);
  int (*snd_pcm_hw_params_malloc)(snd_pcm_hw_params_t **);
  int (*snd_pcm_hw_params_any)(snd_pcm_t *,snd_pcm_hw_params_t *);
  int (*snd_pcm_hw_params_set_access)(snd_pcm_t *,snd_pcm_hw_params_t *,int);
  int (*snd_pcm_hw_params_set_format)(snd_pcm_t *,snd_pcm_hw_params_t *,int);
  int (*snd_pcm_hw_params_set_rate_near)(snd_pcm_t *,snd_pcm_hw_params_t *,int,int);
  int (*snd_pcm_hw_params_set_channels)(snd_pcm_t *,snd_pcm_hw_params_t *,int);
  int (*snd_pcm_hw_params)(snd_pcm_t *,snd_pcm_hw_params_t *);
  void (*snd_pcm_hw_params_free)(snd_pcm_hw_params_t *);
  int (*snd_pcm_prepare)(snd_pcm_t *);
  int (*snd_pcm_writei)(snd_pcm_t *,short *,int);
  int (*snd_pcm_readi)(snd_pcm_t *,short *,int);
  int (*snd_pcm_poll_descriptors)(snd_pcm_t *,struct pollfd *,unsigned int);
} alsa_functions;

#define S(X) #X
#define GETSYM(X) {a->X = dlsym(h,S(X)); if (!a->X) { dlclose(h); free(a); return -1; }}

alsa_functions *alsa = NULL;

int alsa_load()
{
  void *h = dlopen(ALSA_LIB_PATH,RTLD_LAZY);
  if (!h) return -1;
  alsa_functions *a=calloc(sizeof(alsa_functions),1);
  GETSYM(snd_pcm_open);
  GETSYM(snd_pcm_hw_params_malloc);
  GETSYM(snd_pcm_hw_params_any);
  GETSYM(snd_pcm_hw_params_set_access);
  GETSYM(snd_pcm_hw_params_set_format);
  GETSYM(snd_pcm_hw_params_set_rate_near);
  GETSYM(snd_pcm_hw_params_set_channels);
  GETSYM(snd_pcm_hw_params);
  GETSYM(snd_pcm_hw_params_free);
  GETSYM(snd_pcm_writei);
  GETSYM(snd_pcm_readi);
  GETSYM(snd_pcm_close);
  GETSYM(snd_pcm_poll_descriptors);
  alsa=a;
  dlclose(h);
  
  return 0;
}


int alsa_handles_initialised=0;
snd_pcm_t *play_handle;
snd_pcm_t *record_handle;
snd_pcm_hw_params_t *play_params;
snd_pcm_hw_params_t *record_params;

int audio_alsa_stop_play()
{
  if (!alsa) return 0;
  alsa->snd_pcm_hw_params_free(play_params); play_params=NULL;
  alsa->snd_pcm_close(play_handle);
  return 0;
}

int audio_alsa_stop_record()
{
  if (!alsa) return 0;
  alsa->snd_pcm_hw_params_free(record_params); record_params=NULL;
  alsa->snd_pcm_close(record_handle);
  return 0;
}

int audio_alsa_start_play()
{
  int r;

  /* if already playing, then return. */
  if (alsa_handles_initialised) return 0;
  
  if (!alsa) return -1;
  record_handle=NULL; play_handle=NULL;
  record_params=NULL; play_params=NULL;

  /* Open playback device */
  r = alsa->snd_pcm_open (&play_handle,"default",SND_PCM_STREAM_PLAYBACK,
			  SND_PCM_NONBLOCK);
  if (r) { WHYF("ALSA pcm_open() failed"); goto error; }

  /* Configure playback device for 8000Hz, 16 bit, mono */
  r=alsa->snd_pcm_hw_params_malloc(&play_params);
  if (r) { WHYF("ALSA hw_params_malloc() failed"); goto error; }
  r=alsa->snd_pcm_hw_params_any(play_handle,play_params);
  if (r) { WHYF("ALSA hw_params_any() failed"); goto error; }
  r=alsa->snd_pcm_hw_params_set_access(play_handle,play_params,
				       SND_PCM_ACCESS_RW_INTERLEAVED);
  if (r) { WHYF("ALSA hw_params_set_access() failed"); goto error; }
  r=alsa->snd_pcm_hw_params_set_format(play_handle,play_params,
				       SND_PCM_FORMAT_S16_LE);
  if (r) { WHYF("ALSA hw_params_set_format() failed"); goto error; }
  r=alsa->snd_pcm_hw_params_set_rate_near(play_handle,play_params,8000,0);
  if (r) { WHYF("ALSA hw_params_set_rate_near() failed"); goto error; }
  r=alsa->snd_pcm_hw_params_set_channels(play_handle,play_params,1);
  if (r) { WHYF("ALSA hw_params_set_channels() failed"); goto error; }
  r=alsa->snd_pcm_hw_params(play_handle,play_params);
  if (r) { WHYF("ALSA snd_pcm_hw_params() failed"); goto error; }
  alsa->snd_pcm_hw_params_free(play_params); play_params=NULL;

  r=alsa->snd_pcm_prepare(play_handle);
  if (r) { WHYF("ALSA snd_pcm_prepare() failed"); goto error; }

  WHY("Playback device configured");

 error:
  /* close handles and generally cleanup after ourselves */
  audio_alsa_stop_play();
  return -1;
}

int audio_alsa_start_record()
{
  /* Open recording device non-blocking */
  int r = alsa->snd_pcm_open (&record_handle,"default",SND_PCM_STREAM_CAPTURE,
			      SND_PCM_NONBLOCK);
  if (r) { WHYF("ALSA pcm_open() failed"); goto error; }

  /* Configure playback device for 8000Hz, 16 bit, mono */
  r=alsa->snd_pcm_hw_params_malloc(&record_params);
  if (r) { WHYF("ALSA hw_params_malloc() failed"); goto error; }
  r=alsa->snd_pcm_hw_params_any(record_handle,record_params);
  if (r) { WHYF("ALSA hw_params_any() failed"); goto error; }
  r=alsa->snd_pcm_hw_params_set_access(record_handle,record_params,
				       SND_PCM_ACCESS_RW_INTERLEAVED);
  if (r) { WHYF("ALSA hw_params_set_access() failed"); goto error; }
  r=alsa->snd_pcm_hw_params_set_format(record_handle,record_params,
				       SND_PCM_FORMAT_S16_LE);
  if (r) { WHYF("ALSA hw_params_set_format() failed"); goto error; }
  r=alsa->snd_pcm_hw_params_set_rate_near(record_handle,record_params,8000,0);
  if (r) { WHYF("ALSA hw_params_set_rate_near() failed"); goto error; }
  r=alsa->snd_pcm_hw_params_set_channels(record_handle,record_params,1);
  if (r) { WHYF("ALSA hw_params_set_channels() failed"); goto error; }
  r=alsa->snd_pcm_hw_params(record_handle,record_params);
  if (r) { WHYF("ALSA snd_pcm_hw_params() failed"); goto error; }
  alsa->snd_pcm_hw_params_free(record_params); record_params=NULL;

  r=alsa->snd_pcm_prepare(record_handle);
  if (r) { WHYF("ALSA snd_pcm_prepare() failed"); goto error; }

  WHY("Record device configured");
  return 0;
 
 error:
  /* close handles and generally cleanup after ourselves */
  audio_alsa_stop_record();
  return -1;
}

int audio_alsa_stop()
{
  audio_alsa_stop_play();
  audio_alsa_stop_record();
  return 0;
}

int audio_alsa_start()
{
  if (audio_alsa_start_play()) return -1;
  if (audio_alsa_start_record()) {
    audio_alsa_stop();
    return -1;
  }
  return 0;
}

int audio_alsa_pollfds(struct pollfd *fds,int slots)
{
  int used_play
    =alsa->snd_pcm_poll_descriptors(play_handle,fds,slots);
  int used_record
    =alsa->snd_pcm_poll_descriptors(record_handle,&fds[used_play],slots);
  return used_play+used_record;
}

int audio_alsa_read(unsigned char *buffer,int maximum_bytes)
{
  int frames_read=0;
  if ((frames_read=
       alsa->snd_pcm_readi(record_handle, (short *)buffer, maximum_bytes/2))<0)
    {
      alsa->snd_pcm_prepare(record_handle);
      frames_read
	=alsa->snd_pcm_readi(play_handle, (short *)buffer, maximum_bytes/2);
    }
  return frames_read*2;
}

int audio_alsa_write(unsigned char *buffer,int bytes)
{
  /* 16 bits per sample, so frames = bytes/2 */
  int frames_written=0;
  if ((frames_written=alsa->snd_pcm_writei(play_handle, (short *)buffer, bytes/2))<0)
    {
      alsa->snd_pcm_prepare(play_handle);
      return alsa->snd_pcm_writei(play_handle, (short *)buffer, bytes/2)*2;
    }
  else return 0;
}

#endif // HAVE_ALSA_ASOUNDLIB_H

monitor_audio *audio_alsa_detect()
{
#ifdef HAVE_ALSA_ASOUNDLIB_H
  if (!alsa) alsa_load();
  if (!alsa) return NULL;
  snd_pcm_t *handle;
  if (alsa->snd_pcm_open (&handle, "default", SND_PCM_STREAM_PLAYBACK, 0) != -1) {
    alsa->snd_pcm_close(handle);
    monitor_audio *au=calloc(sizeof(monitor_audio),1);
    strcpy(au->name,"ALSA compatible");
    au->start=audio_alsa_start;
    au->stop=audio_alsa_stop;
    au->poll_fds=audio_alsa_pollfds;
    au->read=audio_alsa_read;
    au->write=audio_alsa_write;
    return au;
  }
#endif // HAVE_ALSA_ASOUNDLIB_H
  return NULL;
}
