#if 0
#ifdef WITH_PORTAUDIO

#include "codec2.h"
#define SPAN_DECLARE(x)	x
#include "echo.h"
#include "fifo.h"
#include <portaudio.h>
#include <samplerate.h>
#include "serval.h"

/* Defines */
#define MIN(x, y)	((x) > (y) ? y : x)
#define MAX(x, y)	((x) < (y) ? y : x)

#define CODEC2_BYTES_PER_FRAME ((CODEC2_BITS_PER_FRAME + 7) / 8)

/* Prototypes */
typedef struct {
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

/* Declarations */

/* Prototypes */
void		runstream(PaCtx *ctx, int netfd, struct sockaddr *send_addr, socklen_t addrlen);
void		freectx(PaCtx *ctx);

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

PaCtx *
pa_phone_setup(void) {
  PaCtx	*ctx;
  int	err, err2;

  err = paNoError;
  err2 = 0;
  
  if ((ctx = calloc(1, sizeof(PaCtx))) == NULL) {
    WHY("Unable to allocate PA context");
    err2 = 1;
    goto error;
  }

  /* Init mutex */
  if (pthread_mutex_init(&ctx->mtx, NULL) != 0) {
    WHY("Unable to init mutex: %s\n", strerror(errno));
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
    WHY("Unable to init sample rate converter: %d\n", srcerr);
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
  if ((err = Pa_OpenDefaultStream(&stream,
				  1,          /* input channels */
				  1,          /* output channels */
				  paInt16,
				  SAMPLE_RATE,
				  IN_FRAMES, /* frames per buffer */
				  patestCallback,
				  &ctx)) != paNoError)
    goto error;
 
  /* Start stream */
  if ((err = Pa_StartStream(stream)) != paNoError)
    goto error;

  /* Close down stream, PA, etc */
/* XXX: hangs in pthread_join on Ubuntu 10.04 */
#ifndef linux
  if ((err = Pa_StopStream(stream)) != paNoError)
    goto error;
#endif

  /* Do stuff */

  if ((err = Pa_CloseStream(stream)) != paNoError)
    goto error;

  error:
  Pa_Terminate();
    
  /* Free things */
  freectx(&ctx);
  if (netfd != -1)
    close(netfd);
    
  if (err != paNoError)
    WHY("Port audio error: %s\n", Pa_GetErrorText(err));

  return NULL;
}

#endif
#endif


/*
 * Local variables:
 * c-basic-offset: 2
 * End:
 */

