/* 
Serval DNA Portaudio phone interface
Copyright (C) 2012 Serval Project Inc.

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

#include <codec2.h>
#include <spandsp.h>
#include "fifo.h"
#include <portaudio.h>
#include <pthread.h>
#include <samplerate.h>
#include "serval.h"

/* Defines */
#define IN_FRAMES 128
#define NUM_BUFS	(8)
#define ECHO_LEN	(128)
#define ADAPT_MODE	(ECHO_CAN_USE_ADAPTION | ECHO_CAN_USE_NLP | ECHO_CAN_USE_CNG)

#define CODEC2_BYTES_PER_FRAME ((CODEC2_BITS_PER_FRAME + 7) / 8)

/* Prototypes */
typedef struct {
  PaStream			*stream;
  
  SRC_STATE			*src;

  pthread_mutex_t		mtx;		/* Mutex for frobbing queues */
    
  /* Incoming samples after decompression
   * Written with result of  recvfrom + codec2_decode
   * Read by sample rate converter
   */
  struct fifo			*incoming;
  int				incoverflow;
    
  /* Samples after rate conversion
   * Written by sample rate converter
   * Read by PA callback
   */
  struct fifo			*incrate;
  int				underrun;

  /* Outgoing samples
   * Written by PA callback
   * Read by codec2_encode + sendto
   */
  struct fifo			*outgoing;

  int				overrun;

  echo_can_state_t 		*echocan;	/* Echo canceller state */
  void				*codec2;	/* Codec2 state */
    
} PaCtx;

static void	freectx(PaCtx *ctx);
static int	patestCallback(const void *inputBuffer, void *outputBuffer, unsigned long framesPerBuffer,
			       const PaStreamCallbackTimeInfo* timeInfo, PaStreamCallbackFlags statusFlags,
			       void *userData);
static PaCtx	*pa_phone_setup(void);

/* Declarations */

int app_pa_phone(const struct cli_parsed *parsed, void *context)
{
  PaCtx	 	*ctx;
  
  if ((ctx = pa_phone_setup()) == NULL)
    return -1;

  freectx(ctx);

  return 0;
}

/* This routine will be called by the PortAudio engine when audio is needed.
** It may called at interrupt level on some machines so don't do anything
** that could mess up the system like calling malloc() or free().
*/
static int
patestCallback(const void *inputBuffer, void *outputBuffer,
	       unsigned long framesPerBuffer,
	       const PaStreamCallbackTimeInfo* timeInfo,
	       PaStreamCallbackFlags statusFlags,
	       void *userData) {
  PaCtx			*ctx;
  int16_t			*in, *out;
  int				avail, amt;
    
  ctx = (PaCtx *)userData;
  out = (int16_t *)outputBuffer;
  in = (int16_t *)inputBuffer;

  pthread_mutex_lock(&ctx->mtx);
    
  amt = framesPerBuffer * sizeof(out[0]);
    
  /* Copy out samples to be played */
  if ((avail = fifo_get(ctx->incrate, (uint8_t *)out, amt)) < amt) {
    /* Zero out samples there are no data for */
    bzero(out + (avail / sizeof(out[0])), amt - avail);
    ctx->underrun += (amt - avail) / sizeof(out[0]);
  }
    
  /* Copy in samples to be recorded */
  if ((avail = fifo_put(ctx->outgoing, (uint8_t *)in, amt)) < amt) {
    /* Zero out samples there are no data for */
    bzero(in + (avail / sizeof(out[0])), amt - avail);
    ctx->overrun += (amt - avail) / sizeof(out[0]);
  }

#if 1
  /* Run the echo canceller */
  for (int ofs = 0; ofs < framesPerBuffer; ofs++)
    out[ofs] = echo_can_update(ctx->echocan, in[ofs], out[ofs]);
#endif
  pthread_mutex_unlock(&ctx->mtx);

  return paContinue;
}

static PaCtx *
pa_phone_setup(void) {
  PaCtx		*ctx;
  int		err, i, srcerr;
  PaError	err2;

  err = paNoError;
  err2 = 0;
  
  if ((ctx = calloc(1, sizeof(PaCtx))) == NULL) {
    WHY("Unable to allocate PA context");
    err2 = 1;
    goto error;
  }

  /* Init mutex */
  if (pthread_mutex_init(&ctx->mtx, NULL) != 0) {
    WHYF("Unable to init mutex: %s\n", strerror(errno));
    err2 = 1;
    goto error;
  }
  
  /* Allocate FIFOs */
  i = IN_FRAMES * 10 * sizeof(int16_t);
  printf("Allocating %d byte FIFOs\n", i);
    
  if ((ctx->incoming = fifo_alloc(i)) == NULL) {
    WHY("Unable to allocate incoming FIFO\n");
    err2 = 1;
    goto error;    
  }

  if ((ctx->incrate = fifo_alloc(i)) == NULL) {
    WHY("Unable to allocate incoming SRC FIFO\n");
    err2 = 1;
    goto error;
  }

  if ((ctx->outgoing = fifo_alloc(i)) == NULL) {
    WHY("Unable to allocate outgoing FIFO\n");
    err2 = 1;
    goto error;
  }    


  /* Init sample rate converter */
  if ((ctx->src = src_new(SRC_SINC_BEST_QUALITY, 1, &srcerr)) == NULL) {
    WHYF("Unable to init sample rate converter: %d\n", srcerr);
    err2 = 1;
    goto error;
  }

  /* Init echo canceller */
  if ((ctx->echocan = echo_can_init(ECHO_LEN, ADAPT_MODE)) == NULL) {
    WHY("Unable to init echo canceller\n");
    err2 = 1;
    goto error;
  }

  /* Init codec2 */
  if ((ctx->codec2 = codec2_create()) == NULL) {
    WHY("Unable to init codec2\n");
    err2 = 1;
    goto error;
  }
    
  /* Initialize Port Audio library */
  if ((err = Pa_Initialize()) != paNoError)
    goto error;
     
  /* Open an audio I/O stream. */
  if ((err = Pa_OpenDefaultStream(&ctx->stream,
				  1,          /* input channels */
				  1,          /* output channels */
				  paInt16,
				  SAMPLE_RATE,
				  IN_FRAMES, /* frames per buffer */
				  patestCallback,
				  &ctx)) != paNoError)
    goto error;
 
  /* Start stream */
  if ((err = Pa_StartStream(ctx->stream)) != paNoError)
    goto error;

  /* Close down stream, PA, etc */
/* XXX: hangs in pthread_join on Ubuntu 10.04 */
#ifndef linux
  if ((err = Pa_StopStream(ctx->stream)) != paNoError)
    goto error;
#endif

  /* Do stuff */

  if ((err = Pa_CloseStream(ctx->stream)) != paNoError)
    goto error;

  error:
  Pa_Terminate();
    
  /* Free things */
  freectx(ctx);
    
  if (err != paNoError)
    WHYF("Port audio error: %s\n", Pa_GetErrorText(err));

  return NULL;
}

static void
freectx(PaCtx *ctx) {
    /* Destroy mutex */
    pthread_mutex_destroy(&ctx->mtx);
    
    /* Free SRC resources */
    if (ctx->src != NULL)
	src_delete(ctx->src);

    /* Free echo caneller */
    if (ctx->echocan != NULL)
	echo_can_free(ctx->echocan);

    /* Free codec2 */
    if (ctx->codec2 != NULL)
	codec2_destroy(ctx->codec2);

    /* Free FIFOs */
    if (ctx->incoming != NULL)
	fifo_free(ctx->incoming);
    if (ctx->incrate != NULL)
	fifo_free(ctx->incrate);
    if (ctx->outgoing != NULL)
	fifo_free(ctx->outgoing);
}

/*
 * Local variables:
 * c-basic-offset: 2
 * End:
 */

