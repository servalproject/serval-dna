#ifdef WITH_PORTAUDIO
#include "serval.h"
#include <portaudio.h>

struct private_data {
  int foo;
};

struct private_data pd;
PaStream *stream=NULL;

/* This routine will be called by the PortAudio engine when audio is needed.
 It may called at interrupt level on some machines so don't do anything
 that could mess up the system like calling malloc() or free().
*/ 
static int paphoneCallback( const void *inputBuffer, void *outputBuffer,
                           unsigned long framesPerBuffer,
                           const PaStreamCallbackTimeInfo* timeInfo,
                           PaStreamCallbackFlags statusFlags,
                           void *userData )
{
    /* Cast data passed through stream to our structure. */
    struct private_data *data = (struct private_data*)userData; 
    uint16_t *out = (uint16_t*)outputBuffer;
    uint16_t *in = (uint16_t*)inputBuffer;
    unsigned int i;

    /* Add recorded audio to ring buffer */
    /* Play audio from ring buffer.
       XXX - Special case for DTMF tones.
       DTMF is:
          1209 1336 1477 1633
       697  1    2    3    A
       770  4    5    6    B
       852  7    8    9    C
       941  *    0    #    D
    */

    return 0;
}

int paphone_setup()
{
 PaError err;
 err = Pa_Initialize();
 if( err != paNoError ) goto error;  

 
 /* Open an audio I/O stream. */
 err = Pa_OpenDefaultStream( &stream,
			     1,          /* one input channel */
			     1,          /* one output channel */
			     paInt16,  /* sample format */
			     8000,
			     8000/40,    /* frames per buffer, i.e. the number
					    of sample frames that PortAudio will
					    request from the callback. Many apps
					    may want to use
					    paFramesPerBufferUnspecified, which
					    tells PortAudio to pick the best,
					    possibly changing, buffer size.*/
			     paphoneCallback, /* this is your callback function */
			     &pd ); /*This is a pointer that will be passed to
					your callback*/
 if( err != paNoError ) goto error;

 err = Pa_StartStream( stream );
 if( err != paNoError ) goto error;

  return 0;
 error:
  return WHYF(  "PortAudio error: %s\n", Pa_GetErrorText( err ) );
}

int paphone_cleanup()
{
  PaError err;
 err = Pa_StopStream( stream );
    if( err != paNoError ) goto error;
 err = Pa_CloseStream( stream );
    if( err != paNoError ) goto error;

 error:
  err = Pa_Terminate();
  if( err != paNoError )
    return WHYF(  "PortAudio error: %s\n", Pa_GetErrorText( err ) );
  return 0;
}

#endif
