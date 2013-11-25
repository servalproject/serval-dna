/* 
Serval Voice Over Mesh Protocol (VoMP)
Copyright (C) 2012 Paul Gardner-Stephen
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

/*
  VoMP works using a 6-state model of a phone call, and relies on MDP for 
  auth-cryption of frames. VoMP provides it's own replay protection.

*/

#include "serval.h"
#include "str.h"
#include "conf.h"
#include "strbuf.h"
#include "strlcpy.h"
#include "overlay_address.h"

/*
 Typical call state lifecycle between 2 parties.
 Legend;
  # incoming command from monitor client
  $ outgoing monitor status
  <> vomp packet with state change sent across the network
 
  Monitor Init
  # MONITOR VOMP [supported codec list]
 
  Dialing
  // client requests an outgoing call
  # CALL [sid] [myDid] [TheirDid]
  > CALLPREP + codecs + phone numbers
  // let the client know what token we are going to use for the remainder of the call
  $ CALLTO [token] [mySid] [myDid] [TheirSid] [TheirDid]
      // allocate a session number and tell them our codecs,
      // but we don't need to do anything else yet, 
      // this might be a replay attack
      < NOCALL + codecs
  // Ok, we have a network path, lets try to establish the call
  $ CODECS [token] [their supported codec list]
  > RINGOUT
      $ CODECS [token] [their supported codec list]
      // (Note that if both parties are trying to dial each other, 
      // the call should jump straight to INCALL)
      // inform client about the call request
      $ CALLFROM [token] [mySid] [myDid] [TheirSid] [TheirDid]
      // Note that we may need to wait for other external processes
      // before a phone is actually ringing 
      # RING [token]
      < RINGIN
  // All good, there's a phone out there ringing, you can indicate that to the user
  $ RINGING [token]
 
  Answering
      # PICKUP [token]
      < INCALL
      // The client can now start sending audio
  > INCALL
  $ INCALL [token]
  // The client can now start sending audio
      $ INCALL [token]

  Tell any clients that the call hasn't timed out yet
  (if servald is behaving this should be redundant, if it isn't behaving how do we hangup?)
  $ KEEPALIVE [token]
 
  Hanging up (may also be triggered on network or call establishment timeout)
  # HANGUP [token]
  > CALLENDED
  $ HANGUP [token]
      < CALLENDED
      $ HANGUP [token]
 */


/*
 Minimum network format requirements;
 - your call session, packed integer
 - my call state
 - my sequence number
 
 Pre-ring call setup;
 - my call session
 - my supported codec list
 - your number
 - my number
 - my name
 
 In call audio;
 - codec
 - elapsed time from call start
 - audio duration
 - audio data (remainder of payload)
 
 Assuming minimum audio duration per packet is 20ms, 1 byte sequence should let us deal with ~2.5s of jitter.
 If we have >2.5s of jitter, the network is obviously too crappy to support a voice call anyway.
 
 If we can assume constant duration per codec, and I believe we can, 
 we can use the sequence number to derive the other audio timing information.
 
 We need to resume a call even with large periods of zero traffic (eg >10s), 
 we should be able to use our own wall clock to estimate which 5s interval the audio belongs to.
 */


// ideally these id's should only be used on the network, with monitor events to inform clients of state changes
#define VOMP_STATE_NOCALL 1
#define VOMP_STATE_CALLPREP 2
#define VOMP_STATE_RINGINGOUT 3
#define VOMP_STATE_RINGINGIN 4
#define VOMP_STATE_INCALL 5
#define VOMP_STATE_CALLENDED 6

#define VOMP_REJECT_HANGUP 0
#define VOMP_REJECT_NOPHONE 1
#define VOMP_REJECT_NOCODEC 2
#define VOMP_REJECT_BUSY 3
#define VOMP_REJECT_TIMEOUT 4

#define VOMP_SESSION_MASK 0xffff
#define VOMP_MAX_CALLS 16

#define VOMP_VERSION 0x02

struct vomp_call_half {
  struct subscriber *subscriber;
  char did[64];
  unsigned char state;
  unsigned int session;
  unsigned int sequence;
};

struct jitter_sample{
  int sample_clock;
  int local_clock;
  int delta;
  int sort_index;
};

#define JITTER_SAMPLES 128
struct jitter_measurements{
  struct jitter_sample samples[JITTER_SAMPLES];
  struct jitter_sample *sorted_samples[JITTER_SAMPLES];
  int next_sample;
  int max_sample_clock;
  int sample_count;
};

#define SEEN_SAMPLES 16

struct vomp_call_state {
  struct sched_ent alarm;
  struct vomp_call_half local;
  struct vomp_call_half remote;
  int initiated_call;
  time_ms_t create_time;
  time_ms_t last_activity;
  time_ms_t audio_clock;
  int remote_audio_clock;
  
  // last local & remote status we sent to all interested parties
  int last_sent_status;
  int rejection_reason;
  unsigned char remote_codec_flags[CODEC_FLAGS_LENGTH];
  struct jitter_measurements jitter;
};

/* Some clients may only support one call at a time, even then we allow for multiple call states.
 This is partly to deal with denial of service attacks that might occur by causing
 the ejection of newly allocated session numbers before the caller has had a chance
 to progress the call to a further state. */
int vomp_call_count=0;
// TODO allocate call structures dynamically
struct vomp_call_state vomp_call_states[VOMP_MAX_CALLS];
struct profile_total vomp_stats;

static void vomp_process_tick(struct sched_ent *alarm);
strbuf strbuf_append_vomp_supported_codecs(strbuf sb, const unsigned char supported_codecs[256]);


static int vomp_codec_timespan(int c, int data_size)
{
  switch(c) {
    case VOMP_CODEC_16SIGNED: return data_size/16;
    case VOMP_CODEC_ULAW: return data_size/8;
    case VOMP_CODEC_ALAW: return data_size/8;
  }
  return -1;
}

int vomp_parse_dtmf_digit(char c)
{
  if (c>='0'&&c<='9') return c-0x30;
  switch (c) {
    case 'a': case 'A': return 0xa;
    case 'b': case 'B': return 0xb;
    case 'c': case 'C': return 0xc;
    case 'd': case 'D': return 0xd;
    case '*': return 0xe;
    case '#': return 0xf;
  }
  return -1;
}

char vomp_dtmf_digit_to_char(int digit)
{
  if (digit<0) return '?';
  if (digit<10) return '0'+digit;
  if (digit<0xe) return 'A'+digit-0xa;
  if (digit==0xe) return '*';
  if (digit==0xf) return '#';
  return '?';
}

static int store_jitter_sample(struct jitter_measurements *measurements, int sample_clock, int local_clock, int *delay){
  IN();
  int i, count=0;
  
  // have a quick look through recent samples, drop if already seen
  if (measurements->sample_count>0){
    i=measurements->next_sample -1;
    while(count<SEEN_SAMPLES && count<=measurements->sample_count){
      if (i<0)
	i=measurements->sample_count -1;
      if (measurements->samples[i].sample_clock == sample_clock)
	RETURN(-1);
      i--;
      count++;
    }
  }
  
  struct jitter_sample *sample = &measurements->samples[measurements->next_sample];

  measurements->next_sample++;
  if (measurements->next_sample>=JITTER_SAMPLES)
    measurements->next_sample=0;
  
  int delta=(local_clock - sample_clock);
  
  int pos=0;
  if (measurements->sample_count>0){
    int old_index = measurements->sample_count;
    if (measurements->sample_count>=JITTER_SAMPLES){
      old_index = sample->sort_index;
    }
      
    // binary search to find insert position
    int min=0;
    int max=measurements->sample_count -1;
    while(min<=max){
      pos = (max+min) / 2;
      if (delta <= measurements->sorted_samples[pos]->delta){
	max = pos-1;
      }else{
	pos++;
	min = pos;
      }
    }
    
    if (pos>=measurements->sample_count)
      pos=measurements->sample_count -1;
    
    // shuffle the sorted array elements
    for (i=old_index;i>pos;i--){
      measurements->sorted_samples[i]=measurements->sorted_samples[i-1];
      measurements->sorted_samples[i]->sort_index=i;
    }
    for (i=old_index;i<pos;i++){
      measurements->sorted_samples[i]=measurements->sorted_samples[i+1];
      measurements->sorted_samples[i]->sort_index=i;
    }
  }
  measurements->sorted_samples[pos]=sample;
  
  if (measurements->sample_count<JITTER_SAMPLES)
    measurements->sample_count++;
  
  sample->sample_clock = sample_clock;
  sample->local_clock = local_clock;
  sample->delta = delta;
  sample->sort_index = pos;
  
  if (sample_clock > measurements->max_sample_clock)
    measurements->max_sample_clock=sample_clock;
  
  *delay=sample->delta - measurements->sorted_samples[0]->delta;

  RETURN(0);
  OUT();
}

static int get_jitter_size(struct jitter_measurements *measurements){
  IN();
  int i=JITTER_SAMPLES -4;
  int jitter;
  if (i>=measurements->sample_count)
    i=measurements->sample_count -1;
  jitter=measurements->sorted_samples[i]->delta - measurements->sorted_samples[0]->delta;
  if (jitter < 60)
    jitter=60;
  RETURN(jitter);
  OUT();
}

void set_codec_flag(int codec, unsigned char *flags){
  if (codec<0 || codec>255)
    return;
  flags[codec >> 3] |= 1<<(codec & 7);
}

int is_codec_set(int codec, unsigned char *flags){
  if (codec<0 || codec>255)
    return 0;
  return flags[codec >> 3] & (1<<(codec & 7));
}

struct vomp_call_state *vomp_find_call_by_session(int session_token)
{
  int i;
  for(i=0;i<vomp_call_count;i++)
    if (session_token==vomp_call_states[i].local.session)
      return &vomp_call_states[i];
  return NULL;
}

static int vomp_generate_session_id()
{
  int session_id=0;
  while (!session_id)
  {
    if (urandombytes((unsigned char *)&session_id,sizeof(int)))
      return WHY("Insufficient entropy");
    session_id&=VOMP_SESSION_MASK;
    if (config.debug.vomp) DEBUGF("session=0x%08x",session_id);
    int i;
    /* reject duplicate call session numbers */
    for(i=0;i<vomp_call_count;i++)
      if (session_id==vomp_call_states[i].local.session
	  ||session_id==vomp_call_states[i].local.session){
	session_id=0;
	break;
      }
  }
  return session_id;
}

static struct vomp_call_state *vomp_create_call(struct subscriber *remote,
				  struct subscriber *local,
				  unsigned int remote_session,
				  unsigned int local_session)
{
  if (!local_session)
    local_session=vomp_generate_session_id();
  
  struct vomp_call_state *call = &vomp_call_states[vomp_call_count];
  vomp_call_count++;
  
  /* prepare slot */
  bzero(call,sizeof(struct vomp_call_state));
  call->local.subscriber=local;
  call->remote.subscriber=remote;
  call->local.session=local_session;
  call->remote.session=remote_session;
  call->local.state=VOMP_STATE_NOCALL;
  call->remote.state=VOMP_STATE_NOCALL;
  call->last_sent_status=-1;
  call->create_time=gettime_ms();
  call->last_activity=call->create_time;
  
  call->alarm.alarm = call->create_time+VOMP_CALL_STATUS_INTERVAL;
  call->alarm.function = vomp_process_tick;
  vomp_stats.name="vomp_process_tick";
  call->alarm.stats=&vomp_stats;
  schedule(&call->alarm);
  if (config.debug.vomp)
    DEBUGF("Returning new call #%d",local_session);
  return call;
}

static struct vomp_call_state *vomp_find_or_create_call(struct subscriber *remote,
					  struct subscriber *local,
					  unsigned int sender_session,
					  unsigned int recvr_session,
					  int sender_state,
					  int recvr_state)
{
  int i;
  struct vomp_call_state *call;
  
  if (config.debug.vomp)
    DEBUGF("%d calls already in progress.",vomp_call_count);
  for(i=0;i<vomp_call_count;i++)
    {
      call = &vomp_call_states[i];
      
      /* do the fast comparison first, and only if that matches proceed to
	 the slower SID comparisons */
      if (config.debug.vomp)
	DEBUGF("asking for %06x:%06x, this call %06x:%06x",
		sender_session,recvr_session,
		call->remote.session,
		call->local.session);

      int checked=0;
      if (call->remote.session&&sender_session) { 
	checked++;
	if(sender_session!=call->remote.session)
	  continue;
      }
      if (call->local.session&&recvr_session) {
	checked++;
	if(recvr_session!=call->local.session)
	  continue;
      }
      if (!checked) continue;
      if (remote!=call->remote.subscriber || local!=call->local.subscriber)
	continue;

      /* it matches. */

      /* Record session number if required */
      if (!call->remote.session) 
	call->remote.session=sender_session;

      if (config.debug.vomp) {
	DEBUGF("%06x:%06x matches call #%d %06x:%06x",
		sender_session,recvr_session,i,
		call->remote.session,
		call->local.session);
      }
      
      return call;
    }
  
  /* Don't create a call record if either party has already ended it */
  if (sender_state==VOMP_STATE_CALLENDED || recvr_state==VOMP_STATE_CALLENDED){
    WHYF("Not creating a call record when the call has already ended");
    return NULL;
  }

  /* Only create a call record if the remote party is trying to prepare a call */
  if (sender_state==VOMP_STATE_CALLPREP && recvr_state==VOMP_STATE_NOCALL && recvr_session==0)
    return vomp_create_call(remote, local, sender_session, recvr_session);
  
  WHYF("Not creating a call record for state %d %d", sender_state, recvr_state);
  return NULL;
}

static void prepare_vomp_header(struct vomp_call_state *call, overlay_mdp_frame *mdp){
  mdp->packetTypeAndFlags=MDP_TX;
  mdp->out.src.sid = call->local.subscriber->sid;
  mdp->out.src.port=MDP_PORT_VOMP;
  mdp->out.dst.sid = call->remote.subscriber->sid;
  mdp->out.dst.port=MDP_PORT_VOMP;
  
  mdp->out.payload[0]=VOMP_VERSION;
  mdp->out.payload[1]=(call->local.session>>8)&0xff;
  mdp->out.payload[2]=(call->local.session>>0)&0xff;
  mdp->out.payload[3]=(call->remote.session>>8)&0xff;
  mdp->out.payload[4]=(call->remote.session>>0)&0xff;
  mdp->out.payload[5]=(call->remote.state<<4)|call->local.state;
  mdp->out.payload_length=6;
  
  // keep trying to punch a NAT tunnel for 10s
  // note that requests are rate limited internally to one packet per second
  time_ms_t now = gettime_ms();
  if (call->local.state < VOMP_STATE_CALLENDED && call->create_time + 10000 >now)
    overlay_send_stun_request(directory_service, call->remote.subscriber);
}

/* send updated call status to end-point and to any interested listeners as
   appropriate */

static int vomp_send_status_remote(struct vomp_call_state *call)
{
  overlay_mdp_frame mdp;
  unsigned short  *len=&mdp.out.payload_length;
  
  bzero(&mdp,sizeof(mdp));
  prepare_vomp_header(call, &mdp);
  mdp.out.queue=OQ_ORDINARY;
  if (call->local.state < VOMP_STATE_RINGINGOUT && call->remote.state < VOMP_STATE_RINGINGOUT) {
    int didLen;
    unsigned char codecs[CODEC_FLAGS_LENGTH];
    
    /* Include the list of supported codecs */
    monitor_get_all_supported_codecs(codecs);
    
    int i;
    for (i = 0; i < 256; ++i)
      if (is_codec_set(i,codecs)) {
	mdp.out.payload[(*len)++]=i;
      }
    mdp.out.payload[(*len)++]=0;
    
    /* Include src and dst phone numbers */
    if (call->initiated_call){
      DEBUGF("Sending phone numbers %s, %s",call->local.did,call->remote.did);
      didLen = snprintf((char *)(mdp.out.payload + *len), sizeof(mdp.out.payload) - *len, "%s", call->local.did);
      *len+=didLen+1;
      didLen = snprintf((char *)(mdp.out.payload + *len), sizeof(mdp.out.payload) - *len, "%s", call->remote.did);
      *len+=didLen+1;
    }
    
    if (config.debug.vomp)
      DEBUGF("mdp frame with codec list is %d bytes", mdp.out.payload_length);
  }

  call->local.sequence++;
  
  overlay_mdp_dispatch(&mdp, NULL);
  
  return 0;
}

int vomp_received_audio(struct vomp_call_state *call, int audio_codec, int time, int sequence,
			const unsigned char *audio, int audio_length)
{
  if (call->local.state!=VOMP_STATE_INCALL)
    return -1;
  
  // note we assume the caller will be consistent about providing time and sequence info
  if (time==-1){
    time = call->audio_clock;
    call->audio_clock+=vomp_codec_timespan(audio_codec, audio_length);
  }
  
  if (sequence==-1)
    sequence = call->local.sequence++;
  
  overlay_mdp_frame mdp;
  unsigned short  *len=&mdp.out.payload_length;
  
  bzero(&mdp,sizeof(mdp));
  prepare_vomp_header(call, &mdp);
  
  mdp.out.payload[(*len)++]=audio_codec;
  time = time / 20;
  mdp.out.payload[(*len)++]=(time>>8)&0xff;
  mdp.out.payload[(*len)++]=(time>>0)&0xff;
  mdp.out.payload[(*len)++]=(sequence>>8)&0xff;
  mdp.out.payload[(*len)++]=(sequence>>0)&0xff;
  
  bcopy(audio,&mdp.out.payload[(*len)],audio_length);
  (*len)+=audio_length;
    
  mdp.out.queue=OQ_ISOCHRONOUS_VOICE;
  
  overlay_mdp_dispatch(&mdp, NULL);
  
  return 0;
}

static int monitor_call_status(struct vomp_call_state *call)
{
  char msg[1024];
  int n = snprintf(msg,1024,"\nCALLSTATUS:%06x:%06x:%d:%d:%d:%s:%s:%s:%s\n",
	   call->local.session,call->remote.session,
	   call->local.state,call->remote.state,
	   0,
	   alloca_tohex_sid_t(call->local.subscriber->sid),
	   alloca_tohex_sid_t(call->remote.subscriber->sid),
	   call->local.did,call->remote.did);
  
  monitor_tell_clients(msg, n, MONITOR_VOMP);
  return 0;
}

static int monitor_send_audio(struct vomp_call_state *call, int audio_codec, int time, int sequence, 
		       const unsigned char *audio, int audio_length, int delay)
{
  if (0) DEBUGF("Tell call monitor about audio for call %06x:%06x",
		call->local.session,call->remote.session);
  char msg[1024 + MAX_AUDIO_BYTES];
  /* All commands followed by binary data start with *len:, so that 
   they can be easily parsed at the far end, even if not supported.
   Put newline at start of these so that receiving data in command
   mode doesn't confuse the parser.  */
  
  int jitter_delay = get_jitter_size(&call->jitter);
  
  int msglen = snprintf(msg, 1024,
			"\n*%d:AUDIO:%x:%d:%d:%d:%d:%d\n",
			audio_length,
			call->local.session,
			audio_codec, time, sequence, 
			jitter_delay, delay);
  
  bcopy(audio, &msg[msglen], audio_length);
  msglen+=audio_length;
  msg[msglen++]='\n';
  monitor_tell_clients(msg, msglen, MONITOR_VOMP);
  return 0;
}

// update local state and notify interested clients with the correct message
static int vomp_update_local_state(struct vomp_call_state *call, int new_state){
  if (call->local.state>=new_state)
    return 0;
  
  if (new_state > VOMP_STATE_CALLPREP && new_state <= VOMP_STATE_INCALL && call->local.state<=VOMP_STATE_CALLPREP){
    // tell clients about the remote codec list 
    int i;
    unsigned char our_codecs[CODEC_FLAGS_LENGTH];
    char msg[256];
    monitor_get_all_supported_codecs(our_codecs);
    strbuf b = strbuf_local(msg, sizeof msg);
    strbuf_sprintf(b, "\nCODECS:%06x", call->local.session);
    
    for (i = 0; i < 256; ++i){
      if (is_codec_set(i,call->remote_codec_flags) && is_codec_set(i,our_codecs)) {
	strbuf_sprintf(b, ":%d", i);
      }
    }
    strbuf_putc(b, '\n');
    monitor_tell_clients(strbuf_str(b), strbuf_len(b), MONITOR_VOMP);
  }
  
  switch(new_state){
    case VOMP_STATE_CALLPREP:
      // tell client our session id.
      monitor_tell_formatted(MONITOR_VOMP, "\nCALLTO:%06x:%s:%s:%s:%s\n", 
			     call->local.session, 
			     alloca_tohex_sid_t(call->local.subscriber->sid), call->local.did,
			     alloca_tohex_sid_t(call->remote.subscriber->sid), call->remote.did);
      break;
    case VOMP_STATE_CALLENDED:
      monitor_tell_formatted(MONITOR_VOMP, "\nHANGUP:%06x\n", call->local.session);
      break;
  }
  
  call->local.state=new_state;
  return 0;
}

// update remote state and notify interested clients with the correct message
static int vomp_update_remote_state(struct vomp_call_state *call, int new_state){
  if (call->remote.state>=new_state)
    return 0;
  
  switch(new_state){
    case VOMP_STATE_RINGINGOUT:
      monitor_tell_formatted(MONITOR_VOMP, "\nCALLFROM:%06x:%s:%s:%s:%s\n", 
			     call->local.session, 
			     alloca_tohex_sid_t(call->local.subscriber->sid), call->local.did,
			     alloca_tohex_sid_t(call->remote.subscriber->sid), call->remote.did);
      break;
    case VOMP_STATE_RINGINGIN:
      monitor_tell_formatted(MONITOR_VOMP, "\nRINGING:%06x\n", call->local.session);
      break;
    case VOMP_STATE_INCALL:
      if (call->remote.state==VOMP_STATE_RINGINGIN){
	monitor_tell_formatted(MONITOR_VOMP, "\nANSWERED:%06x\n", call->local.session);
      }
      break;
  }
  
  call->remote.state=new_state;
  return 0;
}

// send call state updates if required.
static int vomp_update(struct vomp_call_state *call)
{
  int combined_status=(call->remote.state<<4)|call->local.state;
  
  if (call->last_sent_status==combined_status)
    return 0;
  
  if (config.debug.vomp)
    DEBUGF("Call state changed to %d %d, sending updates",call->local.state, call->remote.state);
  
  call->last_sent_status=combined_status;
  
  // tell the remote party
  vomp_send_status_remote(call);
  
  // tell monitor clients
  if (monitor_socket_count && monitor_client_interested(MONITOR_VOMP))
    monitor_call_status(call);
  
  return 0;
}

static int to_absolute_value(int short_value, int reference_value){
  short_value = (reference_value & 0xFFFF0000) | short_value;
  
  if (short_value + 0x8000 < reference_value)
    short_value+=0x10000;
  
  if (short_value > reference_value + 0x8000)
    short_value-=0x10000;
  
  return short_value;
}

static int vomp_process_audio(struct vomp_call_state *call, overlay_mdp_frame *mdp, time_ms_t now)
{
  int ofs=6;

  if(ofs>=mdp->in.payload_length)
    return 0;
  
  int codec=mdp->in.payload[ofs++];
  
  int time = mdp->in.payload[ofs]<<8 | mdp->in.payload[ofs+1]<<0;
  ofs+=2;
  int sequence = mdp->in.payload[ofs]<<8 | mdp->in.payload[ofs+1]<<0;
  ofs+=2;
  
  // rebuild absolute time value from short relative time.
  int decoded_time = to_absolute_value(time, call->remote_audio_clock);
  int decoded_sequence = to_absolute_value(sequence, call->remote.sequence);
  
  if (call->remote_audio_clock < decoded_time &&
    call->remote.sequence < decoded_sequence){
    call->remote_audio_clock = decoded_time;
    call->remote.sequence = decoded_sequence;
  }else if (call->remote_audio_clock < decoded_time ||
    call->remote.sequence < decoded_sequence){
    WARNF("Mismatch while decoding sequence and time offset (%d, %d) + (%d, %d) = (%d, %d)",
	time, sequence,
	call->remote_audio_clock, call->remote.sequence,
	decoded_time, decoded_sequence);
  }

  decoded_time=decoded_time * 20;
  
  int audio_len = mdp->in.payload_length - ofs;
  int delay=0;
  
  if (store_jitter_sample(&call->jitter, decoded_time, now, &delay))
    return 0;
  
  /* Pass audio frame to all registered listeners */
  if (monitor_socket_count)
    monitor_send_audio(call, codec, decoded_time, decoded_sequence,
		       &mdp->in.payload[ofs],
		       audio_len, delay);
  return 0;
}

int vomp_ringing(struct vomp_call_state *call){
  if (call){
    if ((!call->initiated_call) && call->local.state<VOMP_STATE_RINGINGIN && call->remote.state==VOMP_STATE_RINGINGOUT){
      if (config.debug.vomp)
	DEBUGF("RING RING!");
      vomp_update_local_state(call, VOMP_STATE_RINGINGIN);
      vomp_update(call);
    }else
      return WHY("Can't ring, call is not being dialled");
  }
  return 0;
}

static int vomp_call_destroy(struct vomp_call_state *call)
{
  if (config.debug.vomp)
    DEBUGF("Destroying call %06x:%06x [%s,%s]", call->local.session, call->remote.session, call->local.did,call->remote.did);
  
  /* now release the call structure */
  int i = (call - vomp_call_states);
  unschedule(&call->alarm);
  call->local.session=0;
  call->remote.session=0;
  
  vomp_call_count--;
  if (i!=vomp_call_count){
    unschedule(&vomp_call_states[vomp_call_count].alarm);
    bcopy(&vomp_call_states[vomp_call_count],
	  call,
	  sizeof(struct vomp_call_state));
    schedule(&call->alarm);
  }
  return 0;
}

int vomp_dial(struct subscriber *local, struct subscriber *remote, const char *local_did, const char *remote_did)
{
  /* TODO use local_did and remote_did start putting the call together.
   These need to be passed to the node being called to provide caller id,
   and potentially handle call-routing, e.g., if it is a gateway.
   */
  if (config.debug.vomp)
    DEBUG("Dialing");
  
  if (vomp_call_count>=VOMP_MAX_CALLS)
    return WHY("All call slots in use");
  
  /* allocate unique call session token, which is how the client will
   refer to this call during its life */
  struct vomp_call_state *call=vomp_create_call(
					 remote,
					 local,
					 0,
					 0);
  
  /* Copy local / remote phone numbers */
  strlcpy(call->local.did, local_did, sizeof(call->local.did));
  strlcpy(call->remote.did, remote_did, sizeof(call->remote.did));
  
  vomp_update_local_state(call, VOMP_STATE_CALLPREP);
  // remember that we initiated this call, not the other party
  call->initiated_call = 1;
  
  /* send status update to remote, thus causing call to be created
   (hopefully) at far end. */
  vomp_update(call);
  
  return 0;
}

int vomp_pickup(struct vomp_call_state *call)
{
  if (call){
    if (config.debug.vomp)
      DEBUG("Picking up");
    if (call->local.state<=VOMP_STATE_RINGINGIN && call->remote.state==VOMP_STATE_RINGINGOUT){
      vomp_update_local_state(call, VOMP_STATE_INCALL);
      call->create_time=gettime_ms();
      /* state machine does job of starting audio stream, just tell everyone about
       the changed state. */
      vomp_update(call);
    }else
      return WHY("Can't pickup, call is not ringing");
  }
  return 0;
}

int vomp_hangup(struct vomp_call_state *call)
{
  if (call){
    if (config.debug.vomp)
      DEBUG("Hanging up");
    vomp_update_local_state(call, VOMP_STATE_CALLENDED);
    vomp_update(call);
  }
  return 0;
}

static int vomp_extract_remote_codec_list(struct vomp_call_state *call,overlay_mdp_frame *mdp)
{
  int ofs=6;
  
  if (config.debug.vomp)
    dump("codec list mdp frame", (unsigned char *)&mdp->in.payload[0],mdp->in.payload_length);
  
  for (;ofs<mdp->in.payload_length && mdp->in.payload[ofs];ofs++){
    int codec = mdp->in.payload[ofs];
    set_codec_flag(codec, call->remote_codec_flags);
  }
  if (!call->initiated_call){
    ofs++;
    if (ofs<mdp->in.payload_length)
      ofs+=strlcpy(call->remote.did, (char *)(mdp->in.payload+ofs), sizeof(call->remote.did))+1;
    if (ofs<mdp->in.payload_length)
      ofs+=strlcpy(call->local.did, (char *)(mdp->in.payload+ofs), sizeof(call->local.did));
  }
  return 0;
}

/* At this point we know the MDP frame is addressed to the VoMP port, but 
   we have not inspected the contents. As these frames are wire-format, we
   must pay attention to endianness. */
int vomp_mdp_received(overlay_mdp_frame *mdp)
{
  time_ms_t now = gettime_ms();
  
  if (mdp->packetTypeAndFlags&(MDP_NOCRYPT|MDP_NOSIGN))
    {
      /* stream-crypted audio frame */
      return WHY("not implemented");
    }

  /* only auth-crypted frames make it this far */

  struct vomp_call_state *call=NULL;

  switch(mdp->in.payload[0]) {
  case VOMP_VERSION:
    {
      unsigned int sender_session=(mdp->in.payload[1]<<8)|mdp->in.payload[2];
      unsigned int recvr_session=(mdp->in.payload[3]<<8)|mdp->in.payload[4];
      int recvr_state=mdp->in.payload[5]>>4;
      int sender_state=mdp->in.payload[5]&0xf;
      
      /* wants to create a call session.
       Main aim here: replay protection. An adversary should not be able to
       replay previous VoMP packets to cause any action.  We do this by
       allocating a new session number for each call.  As an adversary may be
       trying to use such replays to cause a denial of service attack we need
       to be able to track multiple potential session numbers even from the
       same SID. */
      struct subscriber *local=find_subscriber(mdp->in.dst.sid.binary, SID_SIZE, 0);
      struct subscriber *remote=find_subscriber(mdp->in.src.sid.binary, SID_SIZE, 0);
      
      call=vomp_find_or_create_call(remote,local,
				    sender_session,recvr_session,
				    sender_state,recvr_state);
      
      if (!call)
	return WHY("Unable to find or create call");
      
      if (!recvr_session && (config.debug.vomp))
	DEBUG("recvr_session==0, created call");
      
      // stale packet or forgery attempt? Should we just drop it?
      if (sender_state < call->remote.state)
	sender_state = call->remote.state;
      
      // we don't really care what state they think we are in. 
      // Though we could use this information to indicate a network error.
      recvr_state = call->local.state;
      
      if ((!monitor_socket_count)
	  &&(!monitor_client_interested(MONITOR_VOMP)))
      {
	/* No registered listener, so we cannot answer the call, so just reject
	   it. */
	WHY("Rejecting call, no listening clients");
	call->rejection_reason=VOMP_REJECT_NOPHONE;
	recvr_state=VOMP_STATE_CALLENDED;
	/* now let the state machine progress to destroy the call */
      }

      if (recvr_state < VOMP_STATE_RINGINGOUT && sender_state < VOMP_STATE_RINGINGOUT){
	
	// TODO, pass codec list to connected clients, let them pick a codec they can use first?
	
	unsigned char supported_codecs[CODEC_FLAGS_LENGTH];
	int i, found=0;
	
	// the other party should have given us their list of supported codecs
	vomp_extract_remote_codec_list(call,mdp);
	
	// make sure we have at least one codec in common
	monitor_get_all_supported_codecs(supported_codecs);
	
	// look for a matching bit
	for (i=0;i<CODEC_FLAGS_LENGTH;i++){
	  if (supported_codecs[i] & call->remote_codec_flags[i]){
	    found=1;
	    break;
	  }
	}
	
	// nope, we can't speak the same language.
	if (!found){
	  WHY("Rejecting call, no matching codecs found");
	  call->rejection_reason=VOMP_REJECT_NOCODEC;
	  recvr_state=VOMP_STATE_CALLENDED;
	}
      }
      
      if (sender_state==VOMP_STATE_CALLENDED){
	/* For whatever reason, the far end has given up on the call, 
	   so we must also move to CALLENDED no matter what state we were in */
	recvr_state=VOMP_STATE_CALLENDED;
      }
      
      /* Consider states: our actual state, sender state, what the sender thinks
	 our state is, and what we think the sender's state is.  But largely it
	 breaks down to what we think our state is, and what they think their 
	 state is.  That leaves us with just 6X6=36 cases. 
       */
      int combined_state=recvr_state<<3 | sender_state;
      
      switch(combined_state) {
      case (VOMP_STATE_NOCALL<<3)|VOMP_STATE_CALLPREP:
	/* The remote party is in the call-prep state tryng to dial us. 
	   We'll send them our codec list, then they can tell us to ring.
	*/
	break;
	  
      case (VOMP_STATE_RINGINGIN<<3)|VOMP_STATE_RINGINGOUT:
	/* they are ringing us and we are ringing.  Lets keep doing that. */
      case (VOMP_STATE_NOCALL<<3)|VOMP_STATE_RINGINGOUT:
	/* We have have issued a session, the remote party is now indicating 
	   that they would like us to start ringing.
	   So change our state to RINGINGIN. */
	  
	if (call->initiated_call){
	  // hey, quit it, we were trying to call you.
	  call->rejection_reason=VOMP_REJECT_BUSY;
	  recvr_state=VOMP_STATE_CALLENDED;
	}else{
	  // Don't automatically transition to RINGIN, wait for a client to tell us when.
	}
	break;
	  
      case (VOMP_STATE_CALLPREP<<3)|VOMP_STATE_NOCALL:
      case (VOMP_STATE_CALLPREP<<3)|VOMP_STATE_CALLPREP:
	/* We are getting ready to ring, and the other end has issued a session
	   number, (and may be calling us at the same time).  
	   Now is the time to ring out.
	   However, until the remote party has acknowledged with RINGIN, 
	   don't indicate their ringing state to the user.
	 */
	if (call->initiated_call){
	  recvr_state=VOMP_STATE_RINGINGOUT;
	}else{
	  recvr_state=VOMP_STATE_CALLENDED;
	}
	break;
	  
      case (VOMP_STATE_RINGINGOUT<<3)|VOMP_STATE_NOCALL:
      case (VOMP_STATE_RINGINGOUT<<3)|VOMP_STATE_CALLPREP:
	/* We are calling them, and they have not yet answered, just wait */
	break;
	  
      case (VOMP_STATE_RINGINGOUT<<3)|VOMP_STATE_RINGINGIN:
	/* we are calling them and they have acknowledged it. 
	   Now we can play a tone to indicate they are ringing */
	break;
	  
      case (VOMP_STATE_RINGINGOUT<<3)|VOMP_STATE_RINGINGOUT:
	/* Woah, we're trying to dial each other?? That must have been well timed. 
	 Jump to INCALL and start audio */
	recvr_state=VOMP_STATE_INCALL;
	// reset create time when call is established
	call->create_time=gettime_ms();
	break;
	  
      case (VOMP_STATE_INCALL<<3)|VOMP_STATE_RINGINGOUT:
	/* we think the call is in progress, but the far end hasn't replied yet
	 Just wait. */
	break;
	  
      case (VOMP_STATE_RINGINGOUT<<3)|VOMP_STATE_INCALL:
	/* They have answered, we can jump to incall as well */
	recvr_state=VOMP_STATE_INCALL;
	// reset create time when call is established
	call->create_time=gettime_ms();
	// Fall through
      case (VOMP_STATE_INCALL<<3)|VOMP_STATE_INCALL:
	/* play any audio that they have sent us. */
	vomp_process_audio(call,mdp,now);
	break;
	  
      case (VOMP_STATE_CALLENDED<<3)|VOMP_STATE_NOCALL:
      case (VOMP_STATE_CALLENDED<<3)|VOMP_STATE_CALLPREP:
      case (VOMP_STATE_CALLENDED<<3)|VOMP_STATE_RINGINGOUT:
      case (VOMP_STATE_CALLENDED<<3)|VOMP_STATE_RINGINGIN:
      case (VOMP_STATE_CALLENDED<<3)|VOMP_STATE_INCALL:
      case (VOMP_STATE_CALLENDED<<3)|VOMP_STATE_CALLENDED:
	/* If we ended the call, we'll wait for the far end to reply before destroying it */
	break;
	  
      default:
	/*
	  Any state not explicitly listed above is considered invalid and possibly stale, 
	  the packet will be completely ignored.
	*/
	WHYF("Ignoring invalid call state %d.%d",sender_state,recvr_state);
	return 0;
      }
      
      vomp_update_remote_state(call, sender_state);
      vomp_update_local_state(call, recvr_state);
      call->last_activity=gettime_ms();
      
      // TODO if we hear a stale echo of our state should we force another outgoing packet now?
      // will that always cause 2 outgoing packets?
      
      /* send an update to the call status if required */
      vomp_update(call);
    }
    return 0;
    break;
  default:
    /* unsupported VoMP frame */
    WHYF("Unsupported VoMP frame type = 0x%02x",mdp->in.payload[0]);
    break;
  }

  return WHY("Malformed VoMP MDP packet?");
}

static void vomp_process_tick(struct sched_ent *alarm)
{
  char msg[32];
  int len;
  time_ms_t now = gettime_ms();
  
  struct vomp_call_state *call = (struct vomp_call_state *)alarm;

  /* See if any calls need to be expired.
     Allow VOMP_CALL_DIAL_TIMEOUT ms for the other party to ring / request ringing
     Allow VOMP_CALL_RING_TIMEOUT ms for the ringing party to answer
     Allow VOMP_CALL_NETWORK_TIMEOUT ms between received packets
   */
  
  if ((call->remote.state < VOMP_STATE_RINGINGOUT && call->create_time + VOMP_CALL_DIAL_TIMEOUT < now) ||
      (call->local.state < VOMP_STATE_INCALL && call->create_time + VOMP_CALL_RING_TIMEOUT < now) ||
      (call->last_activity+VOMP_CALL_NETWORK_TIMEOUT<now) ){
    
    /* tell any local clients that call has died */
    call->rejection_reason=VOMP_REJECT_TIMEOUT;
    vomp_update_local_state(call, VOMP_STATE_CALLENDED);
    vomp_update_remote_state(call, VOMP_STATE_CALLENDED);
    vomp_update(call);
  }
  
  /*
   If we are calling ourselves, mdp packets are processed as soon as they are sent.
   So we can't risk moving call entries around at that time as that will change pointers that are still on the stack.
   So instead we wait for the next vomp tick to destroy the structure
   */
  if (call->local.state==VOMP_STATE_CALLENDED
      &&call->remote.state==VOMP_STATE_CALLENDED){
    vomp_call_destroy(call);
    return;
  }
  
  /* update everyone if the state has changed */
  vomp_update(call);
  /* force a packet to the other party. We are still here */
  vomp_send_status_remote(call);
  
  /* tell local monitor clients the call is still alive */
  len = snprintf(msg,sizeof(msg) -1,"\nKEEPALIVE:%06x\n", call->local.session);
  monitor_tell_clients(msg, len, MONITOR_VOMP);
  
  alarm->alarm = gettime_ms() + VOMP_CALL_STATUS_INTERVAL;
  alarm->deadline = alarm->alarm + VOMP_CALL_STATUS_INTERVAL/2;
  schedule(alarm);
}
