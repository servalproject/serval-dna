/* 
Serval Voice Over Mesh Protocol (VoMP)
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

/*
  VoMP works using a 6-state model of a phone call, and relies on MDP for 
  auth-cryption of frames. VoMP provides it's own replay protection.

*/

#include "serval.h"

/* Although we only support one call at a time, we allow for multiple call states.
   This is partly to deal with denial of service attacks that might occur by causing
   the ejection of newly allocated session numbers before the caller has had a chance
   to progress the call to a further state. */
int vomp_call_count=0;
int vomp_active_call=-1;
vomp_call_state vomp_call_states[VOMP_MAX_CALLS];
struct profile_total vomp_stats;

int dump_vomp_status();
void vomp_process_tick(struct sched_ent *alarm);

/* which codecs we support (set by registered listener) */
unsigned char vomp_local_codec_list[256];

/* Now keep track of who wants to know what we are up to */
int vomp_interested_usock_count=0;
#define VOMP_MAX_INTERESTED 128
struct sockaddr_un *vomp_interested_usocks[VOMP_MAX_INTERESTED];
int vomp_interested_usock_lengths[VOMP_MAX_INTERESTED];
unsigned long long vomp_interested_expiries[VOMP_MAX_INTERESTED];

vomp_call_state *vomp_find_call_by_session(int session_token)
{
  int i;
  for(i=0;i<vomp_call_count;i++)
    if (session_token==vomp_call_states[i].local.session)
      return &vomp_call_states[i];
  return NULL;
}

int vomp_generate_session_id(){
  int session_id=0;
  while (!session_id)
  {
    if (urandombytes((unsigned char *)&session_id,sizeof(int)))
      return WHY("Insufficient entropy");
    session_id&=VOMP_SESSION_MASK;
    DEBUGF("session=0x%08x\n",session_id);
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

vomp_call_state *vomp_create_call(unsigned char *remote_sid,
				  unsigned char *local_sid,
				  unsigned int remote_session,
				  unsigned int local_session,
				  int remote_state,
				  int local_state){
  
  int i;
  if (!local_session)
    local_session=vomp_generate_session_id();
  
  vomp_call_state *call = &vomp_call_states[vomp_call_count];
  vomp_call_count++;
  
  /* prepare slot */
  bzero(call,sizeof(vomp_call_state));
  bcopy(local_sid,call->local.sid,SID_SIZE);
  bcopy(remote_sid,call->remote.sid,SID_SIZE);
  call->local.session=local_session;
  call->remote.session=remote_session;
  call->local.state=local_state;
  call->remote.state=remote_state;
  call->last_sent_status=-1;
  call->create_time=overlay_gettime_ms();
  call->last_activity=call->create_time;
  
  // fill sample cache with invalid times
  for (i=0;i<VOMP_MAX_RECENT_SAMPLES *4;i++)
    call->seen_samples[i]=0xFFFFFFFF;
  
  call->alarm.alarm = call->create_time+VOMP_CALL_STATUS_INTERVAL;
  call->alarm.function = vomp_process_tick;
  vomp_stats.name="vomp_process_tick";
  call->alarm.stats=&vomp_stats;
  schedule(&call->alarm);
  WHYF("Returning new call #%d",local_session);
  return call;
}

vomp_call_state *vomp_find_or_create_call(unsigned char *remote_sid,
					  unsigned char *local_sid,
					  unsigned int sender_session,
					  unsigned int recvr_session,
					  int sender_state,
					  int recvr_state)
{
  int i;
  vomp_call_state *call;
  
  if (0) printf("%d calls already in progress.\n",vomp_call_count);
  for(i=0;i<vomp_call_count;i++)
    {
      call = &vomp_call_states[i];
      
      /* do the fast comparison first, and only if that matches proceed to
	 the slower SID comparisons */
      if (0)
	fprintf(stderr,"asking for %06x:%06x, this call %06x:%06x\n",
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
      if (memcmp(remote_sid,call->remote.sid,SID_SIZE)) continue;
      if (memcmp(local_sid,call->local.sid,SID_SIZE)) continue;

      /* it matches. */

      /* Record session number if required */
      if (!call->remote.session) 
	call->remote.session=sender_session;

      if (0) {
	WHYF("Returning existing call #%d",i);
	fprintf(stderr,"%06x:%06x matches call #%d %06x:%06x\n",
		sender_session,recvr_session,i,
		call->remote.session,
		call->local.session);
      }
      
      return call;
    }
  
  /* Don't create a call record if either party has ended it */
  if (sender_state==VOMP_STATE_CALLENDED || recvr_state==VOMP_STATE_CALLENDED)
    return NULL;

  /* Only create a call record if either party is in CALLPREP state */
  if (sender_state==VOMP_STATE_CALLPREP || recvr_state==VOMP_STATE_CALLPREP)
    return vomp_create_call(remote_sid, local_sid, sender_session, recvr_session, VOMP_STATE_NOCALL, VOMP_STATE_NOCALL);
  
  return NULL;
}

/* send updated call status to end-point and to any interested listeners as
   appropriate */

int vomp_send_status_remote_audio(vomp_call_state *call, int audio_codec, char *audio, int audio_length)
{
  overlay_mdp_frame mdp;
  
  bzero(&mdp,sizeof(mdp));
  mdp.packetTypeAndFlags=MDP_TX;
  bcopy(call->local.sid,mdp.out.src.sid,SID_SIZE);
  mdp.out.src.port=MDP_PORT_VOMP;
  bcopy(call->remote.sid,mdp.out.dst.sid,SID_SIZE);
  mdp.out.dst.port=MDP_PORT_VOMP;
  
  mdp.out.payload[0]=0x01; /* Normal VoMP frame */
  mdp.out.payload[1]=(call->remote.state<<4)|call->local.state;
  mdp.out.payload[2]=(call->remote.sequence>>8)&0xff;
  mdp.out.payload[3]=(call->remote.sequence>>0)&0xff;
  mdp.out.payload[4]=(call->local.sequence>>8)&0xff;
  mdp.out.payload[5]=(call->local.sequence>>0)&0xff;
  unsigned long long call_millis=overlay_gettime_ms()-call->create_time;
  mdp.out.payload[6]=(call_millis>>8)&0xff;
  mdp.out.payload[7]=(call_millis>>0)&0xff;
  mdp.out.payload[8]=(call->remote.session>>16)&0xff;
  mdp.out.payload[9]=(call->remote.session>>8)&0xff;
  mdp.out.payload[10]=(call->remote.session>>0)&0xff;
  mdp.out.payload[11]=(call->local.session>>16)&0xff;
  mdp.out.payload[12]=(call->local.session>>8)&0xff;
  mdp.out.payload[13]=(call->local.session>>0)&0xff;
  
  mdp.out.payload_length=14;
  
  if (call->local.state<VOMP_STATE_RINGINGOUT
      &&call->remote.state<VOMP_STATE_RINGINGOUT){
    /* Also include list of supported codecs */
    if (0) WHY("Including codec list");
    int i;
    for(i=0;i<256;i++)
      if (vomp_local_codec_list[i]) {
	mdp.out.payload[mdp.out.payload_length++]=i;
	if (0) WHYF("  I support the %s codec",vomp_describe_codec(i));
      }
    mdp.out.payload[mdp.out.payload_length++]=0;
    if (0) WHYF("mdp frame with codec list is %d bytes",mdp.out.payload_length);
  }

  if (call->local.state==VOMP_STATE_INCALL && audio && audio_length && vomp_sample_size(audio_codec)==audio_length) {
    unsigned short  *len=&mdp.out.payload_length;
    unsigned char *p=&mdp.out.payload[0];

    // WHY("Including audio sample block");

    /* record sample in recent list.
       XXX - What timestamp to attach to the sample?
       Two obvious choices:
       1. The sample is for the most recent n milliseconds; or
       2. The sample is for the next n milliseconds following the
       last sample.

       Option 1 introduces all sorts of problems with sample production
       jitter, where as option 2 has no such problems, but simply requires the
       producer of audio to ensure that they provide exactly the right amount
       of audio, or risk the call getting out of sync.  This is a fairly
       reasonable expectation, or else things go to pot.

       Note that in-call slew is the responsibility of the player, not the
       recorder of audio.  Basically if the audio queue starts to bank up,
       then the player needs to drop samples.
    */
    vomp_sample_block *sb=call->recent_samples;
    int rotor=call->recent_sample_rotor%VOMP_MAX_RECENT_SAMPLES;
    sb[rotor].codec=audio_codec;
    sb[rotor].endtime=call->audio_clock+vomp_codec_timespan(sb[rotor].codec)-1;
    sb[rotor].starttime=call->audio_clock;
    call->audio_clock=sb[rotor].endtime+1;
    bcopy(audio,&sb[rotor].bytes[0],audio_length);
    
    /* write the sample end-time in milliseconds since call establishment */
    p[(*len)++]=(call->audio_clock>>24)&0xff;
    p[(*len)++]=(call->audio_clock>>16)&0xff;
    p[(*len)++]=(call->audio_clock>>8)&0xff;
    p[(*len)++]=(call->audio_clock>>0)&0xff;	

    /* stuff frame with most recent sample blocks as a form of preemptive
       retransmission. But don't make the packets too large. */
    while (((*len)+1+audio_length)
	   <VOMP_STUFF_BYTES) {
      p[(*len)++]=sb[rotor].codec;
      bcopy(&sb[rotor].bytes[0],&p[*len],vomp_sample_size(sb[rotor].codec));
      (*len)+=vomp_sample_size(sb[rotor].codec);
      
      rotor--; if (rotor<0) rotor+=VOMP_MAX_RECENT_SAMPLES;
      rotor%=VOMP_MAX_RECENT_SAMPLES;
      
      // stop if we've run out of samples before we ran out of bytes
      if ((!sb[rotor].endtime)||(sb[rotor].endtime+1==call->audio_clock)) break;
    }
    call->recent_sample_rotor++;
    call->recent_sample_rotor%=VOMP_MAX_RECENT_SAMPLES;
  }
  
  /* XXX Here we act as our own client. This used to be able to block.
     We should really refactor overlay_mdp_poll() so that we can deliver
     the frame directly.
     Make sure that we don't want (just drop the message if there is
     congestion) */
  
  overlay_mdp_dispatch(&mdp,1,NULL,0);
  
  call->local.sequence++;
  return 0;
}

int vomp_send_status_remote(vomp_call_state *call){
  return vomp_send_status_remote_audio(call, 0, NULL, 0);
}

int vomp_send_mdp_status_audio(vomp_call_state *call, int audio_codec, unsigned int start_time, unsigned int end_time, char *audio, int audio_length){
  if (audio && audio_length && vomp_sample_size(audio_codec)!=audio_length)
    return WHY("Audio frame is the wrong length");
  
  overlay_mdp_frame mdp;
  
  DEBUG("Sending mdp client packet");
  
  bzero(&mdp,sizeof(mdp));
  mdp.packetTypeAndFlags=MDP_VOMPEVENT;
  mdp.vompevent.call_session_token=call->local.session;
  mdp.vompevent.last_activity=call->last_activity;
  if (call->ringing) mdp.vompevent.flags|=VOMPEVENT_RINGING;
  if (call->local.state==VOMP_STATE_CALLENDED) 
    mdp.vompevent.flags|=VOMPEVENT_CALLENDED;
  if (call->remote.state==VOMPEVENT_CALLENDED)
    mdp.vompevent.flags|=VOMPEVENT_CALLREJECT;
  if (call->audio_started) 
    mdp.vompevent.flags|=VOMPEVENT_AUDIOSTREAMING;
  // TODO ???
  //mdp.vompevent.flags|=VOMPEVENT_CALLCREATED;
  mdp.vompevent.local_state=call->local.state;
  mdp.vompevent.remote_state=call->remote.state;

  bcopy(&call->remote_codec_list[0],&mdp.vompevent.supported_codecs[0],256);

  if (audio && audio_length) {
    if (0) WHYF("Frame contains audio (codec=%s)",
		vomp_describe_codec(audio_codec));
    bcopy(audio,
	  &mdp.vompevent.audio_bytes[0],
	  audio_length);
    mdp.vompevent.audio_sample_codec=audio_codec;
    mdp.vompevent.audio_sample_bytes=audio_length;
    mdp.vompevent.audio_sample_starttime=start_time;
    mdp.vompevent.audio_sample_endtime=end_time;
  }
  
  int i;
  long long now=overlay_gettime_ms();
  for(i=0;i<vomp_interested_usock_count;i++)
    if (vomp_interested_expiries[i]>=now) {
      overlay_mdp_reply(mdp_named.poll.fd,
			vomp_interested_usocks[i],
			vomp_interested_usock_lengths[i],
			&mdp);
    }   
  return 0;
}

int vomp_send_mdp_status(vomp_call_state *call){
  return vomp_send_mdp_status_audio(call,0,0,0,NULL,0);
}

// send call state updates if required.
int vomp_update(vomp_call_state *call){
  int combined_status=(call->remote.state<<4)|call->local.state;
  
  if (call->last_sent_status==combined_status)
    return 0;
  
  DEBUGF("Call state changed to %d %d, sending updates",call->local.state, call->remote.state);
  
  call->last_sent_status=combined_status;
  
  // tell the remote party
  vomp_send_status_remote(call);
  
  // tell monitor clients
  if (monitor_socket_count)
    monitor_call_status(call);
  
  // tell mdp clients
  if (vomp_interested_usock_count)
    vomp_send_mdp_status(call);

  return 0;
}

int vomp_call_start_audio(vomp_call_state *call)
{
  call->audio_started=1;
  return WHY("Not implemented");
}

// check a small circular buffer of recently seen audio
// we're not trying to be perfect here, we still expect all clients to reorder and filter duplicates
int vomp_audio_already_seen(vomp_call_state *call, unsigned int end_time){
  int i;
  for(i=0;i<VOMP_MAX_RECENT_SAMPLES *4;i++)
    if (call->seen_samples[i]==end_time)
      return 1;
  call->seen_samples[call->sample_pos]=end_time;
  call->sample_pos++;
  if (call->sample_pos>=VOMP_MAX_RECENT_SAMPLES *4)
    call->sample_pos=0;
  return 0;
}

int vomp_process_audio(vomp_call_state *call,unsigned int sender_duration,overlay_mdp_frame *mdp)
{
  int ofs=14;
  // if (mdp->in.payload_length>14)
  //  WHYF("got here (payload has %d bytes)",mdp->in.payload_length);

  /* Get end time marker for sample block collection */
  unsigned int e=0, s=0, duration;
  e=mdp->in.payload[ofs++]<<24;
  e|=mdp->in.payload[ofs++]<<16;
  e|=mdp->in.payload[ofs++]<<8;
  e|=mdp->in.payload[ofs++]<<0;
  
  sender_duration = (e&0xFFFF0000)|sender_duration;
  if (0)
    DEBUGF("Jitter %d, %d",sender_duration -e,(overlay_gettime_ms()-call->create_time)-e);
  
  while(ofs<mdp->in.payload_length)
    {
      int codec=mdp->in.payload[ofs];
      // WHYF("Spotted a %s sample block",vomp_describe_codec(codec));
      if (!codec||vomp_sample_size(codec)<0) break;
      if ((ofs+1+vomp_sample_size(codec))>mdp->in.payload_length) break;

      /* work out start-time from end-time less duration of included sample(s).
         XXX - Assumes only non-adaptive codecs. */
      s = e-vomp_codec_timespan(codec)+1;

      /* Pass audio frame to all registered listeners */
      if (!vomp_audio_already_seen(call, e)){
	if (vomp_interested_usock_count)
	  vomp_send_mdp_status_audio(call, codec, s, e,
			       &mdp->in.payload[ofs+1],
			       vomp_sample_size(codec)
			       );
	
	if (monitor_socket_count)
	  monitor_send_audio(call, codec, s, e,
			     &mdp->in.payload[ofs+1],
			     vomp_sample_size(codec)
			     );
      }
      ofs+=1+vomp_sample_size(codec);
      e=s-1;
    }
  return 0;
}

int vomp_call_stop_audio(vomp_call_state *call)
{
  call->audio_started=0;
  return WHY("Not implemented");
}

int vomp_call_start_ringing(vomp_call_state *call)
{
  /* We just need to set the flag to say that we are ringing.
     Interested listeners and far end will be informed via vomp_send_status() */
  call->ringing=1;
  fprintf(stderr,"RING RING!\n");
  return 0;
}

int vomp_call_destroy(vomp_call_state *call)
{
  /* do some general clean ups */
  if (call->audio_started) vomp_call_stop_audio(call);
  if (call->ringing) call->ringing=0;

  fprintf(stderr,"Destroying call %s <--> %s\n",
	  call->local.did,call->remote.did);

  /* tell everyone the call has died */
  call->local.state=VOMP_STATE_CALLENDED; call->remote.state=VOMP_STATE_CALLENDED;
  
  vomp_update(call);

  /* now release the call structure */
  int i = (call - vomp_call_states);
  unschedule(&call->alarm);
  
  vomp_call_count--;
  if (i!=vomp_call_count){
    unschedule(&vomp_call_states[vomp_call_count].alarm);
    bcopy(&vomp_call_states[vomp_call_count],
	  call,
	  sizeof(vomp_call_state));
    schedule(&call->alarm);
  }
  return 0;
}

int vomp_dial(unsigned char *local_sid, unsigned char *remote_sid, char *local_did, char *remote_did){
  /* TODO use local_did and remote_did start putting the call together.
   These need to be passed to the node being called to provide caller id,
   and potentially handle call-routing, e.g., if it is a gateway.
   */
  DEBUG("Dialing\n");
  
  if (vomp_call_count>=VOMP_MAX_CALLS)
    return WHY("All call slots in use");
  
  /* allocate unique call session token, which is how the client will
   refer to this call during its life */
  vomp_call_state *call=vomp_create_call(
					 remote_sid,
					 local_sid,
					 0,
					 0,
					 VOMP_STATE_NOCALL,
					 VOMP_STATE_CALLPREP
					 );
  
  // remember that we initiated this call, not the other party
  call->initiated_call = 1;
  
  /* send status update to remote, thus causing call to be created
   (hopefully) at far end. */
  vomp_update(call);
  
  return 0;
}

int vomp_pickup(vomp_call_state *call){
  if (call){
    WHY("Picking up");
    if (call->local.state!=VOMP_STATE_RINGINGIN)
      return WHY("Call is not ringing");
    
    call->local.state=VOMP_STATE_INCALL;
    call->create_time=overlay_gettime_ms();
    call->ringing=0;
    /* state machine does job of starting audio stream, just tell everyone about
     the changed state. */
    vomp_update(call);
  }
  return 0;
}

int vomp_hangup(vomp_call_state *call){
  if (call){
    WHY("Hanging up");
    if (call->local.state==VOMP_STATE_INCALL) vomp_call_stop_audio(call);
    call->local.state=VOMP_STATE_CALLENDED;
    vomp_update(call);
  }
  return 0;
}

/* An MDP message of type MDP_VOMPEVENT received from the unix domain socket.
   This is how user tasks request telephone calls and receive updated status
   and audio from the call. We need the receiver socket so that we can 
   route the events back to wherever they should be going. 
   XXX - We should have some means of authenticating/protecting this interface
   so that any old process cannot request a mesh call. Although, in fairness,
   the user will know about the call because the call display will come up.
*/

int vomp_mdp_event(overlay_mdp_frame *mdp,
		   struct sockaddr_un *recvaddr,int recvaddrlen)
{
  /* Frames from the user can take only a few forms:
     - announce interest in call state.
     - withdraw interest in call state.
     - place a call (SID+DID combination)
     - deliver audio for sending
     - indicate pickup, hangup or call reject

     We then send back all sorts of relevant call state information as well as
     transported audio.  In particular we inform when the call state changes,
     including if any error has occurred.
  */
  if (0)
    DEBUGF("Flags=0x%x\n",mdp->vompevent.flags);
  
  switch(mdp->vompevent.flags)
    {
    case VOMPEVENT_REGISTERINTEREST:
      WHY("Request to register interest");
      /* put unix domain socket on record to send call state event and audio to. */
      {
	int i;
	int candidate=-1;
	long long now=overlay_gettime_ms();
	for(i=0;i<vomp_interested_usock_count;i++)
	  {
	    if (vomp_interested_usock_lengths[i]==recvaddrlen)
	      if (!memcmp(recvaddr->sun_path,
			  vomp_interested_usocks[i],recvaddrlen))
		/* found it -- so we are already monitoring this one */
		return overlay_mdp_reply_error(mdp_named.poll.fd,recvaddr,recvaddrlen,
					       0,"Success");
	    if (vomp_interested_expiries[i]<now) candidate=i;
	  }
	if (i>=vomp_interested_usock_count&&(candidate>-1)) i=candidate;
	/* not currently on the list, so add */
	if (i<VOMP_MAX_INTERESTED) {
	  if (vomp_interested_usocks[i]) {
	    free(vomp_interested_usocks[i]);
	    vomp_interested_usocks[i]=NULL;
	  }
	  vomp_interested_usocks[i]=malloc(recvaddrlen);
	  if (!vomp_interested_usocks[i])
	    return overlay_mdp_reply_error(mdp_named.poll.fd, recvaddr,recvaddrlen,
					   4002,"Out of memory");
	  bcopy(recvaddr,vomp_interested_usocks[i],
		recvaddrlen);
	  vomp_interested_usock_lengths[i]=recvaddrlen;
	  vomp_interested_expiries[i]=overlay_gettime_ms()+60000;
	  if (i==vomp_interested_usock_count) vomp_interested_usock_count++;

	  if (mdp->vompevent.supported_codecs[0]) {
	    /* Replace set of locally supported codecs */
	    for(i=0;i<256;i++) vomp_local_codec_list[i]=0;
	    for(i=0;(i<256)&&mdp->vompevent.supported_codecs[i];i++)
	      {
		vomp_local_codec_list[mdp->vompevent.supported_codecs[i]]=1;
	      }
	  }
		
	  return overlay_mdp_reply_error
	    (mdp_named.poll.fd,recvaddr,recvaddrlen,0,"Success");	     
	} else {
	  return overlay_mdp_reply_error
	    (mdp_named.poll.fd,recvaddr,recvaddrlen,
	     4003,"Too many listeners (try again in a minute?)");
	}
      }
      break;
    case VOMPEVENT_WITHDRAWINTEREST:
      /* opposite of above */
      WHY("Request to withdraw interest");
      {
	int i;
	for(i=0;i<vomp_interested_usock_count;i++)
	  {
	    if (vomp_interested_usock_lengths[i]==recvaddrlen)
	      if (!memcmp(recvaddr->sun_path,
			  vomp_interested_usocks[i],recvaddrlen))
		{
		  /* found it -- so we are already monitoring this one */
		  free(vomp_interested_usocks[i]);
		  if (i<vomp_interested_usock_count-1)
		    {
		      int swap=vomp_interested_usock_count-1;
		      vomp_interested_usock_lengths[i]
			=vomp_interested_usock_lengths[swap];
		      vomp_interested_usocks[i]=vomp_interested_usocks[swap];
		      vomp_interested_expiries[i]=vomp_interested_expiries[swap];
		    }
		  vomp_interested_usock_count--;
		  return overlay_mdp_reply_error
		    (mdp_named.poll.fd,recvaddr,recvaddrlen,
		     0,"Success. You have been removed.");
		}
	  }
	return overlay_mdp_reply_error
	  (mdp_named.poll.fd,recvaddr,recvaddrlen,
	   0,"Success. You were never listening.");
      }
      break;
    case VOMPEVENT_CALLINFO:
      {
	/* provide call endpoint info to user */
	vomp_call_state *call
	  =vomp_find_call_by_session(mdp->vompevent.call_session_token);

	/* collect call info and send to requestor */
	overlay_mdp_frame mdpreply;
	bzero(&mdpreply,sizeof(mdpreply));
	mdpreply.packetTypeAndFlags=MDP_VOMPEVENT;
	mdpreply.vompevent.flags=VOMPEVENT_CALLINFO;
	mdpreply.vompevent.call_session_token=mdp->vompevent.call_session_token;
	if (call) {
	  if (call->ringing) mdpreply.vompevent.flags|=VOMPEVENT_RINGING;
	  if (call->audio_started) 
	    mdpreply.vompevent.flags|=VOMPEVENT_AUDIOSTREAMING;
	  if (call->remote.state==VOMP_STATE_CALLENDED) 
	    mdpreply.vompevent.flags|=VOMPEVENT_CALLENDED;
	  bcopy(call->local.sid,mdpreply.vompevent.local_sid,SID_SIZE);
	  bcopy(call->remote.sid,mdpreply.vompevent.remote_sid,SID_SIZE);
	  bcopy(call->local.did,mdpreply.vompevent.local_did,64);
	  bcopy(call->remote.did,mdpreply.vompevent.remote_did,64);
	  dump_vomp_status();
	} else 
	  if (mdp->vompevent.call_session_token)
	    /* let the requestor know that the requested call doesn't exist */
	    mdpreply.vompevent.flags|=VOMPEVENT_ERROR;

	/* and provide a quick summary of all calls in progress */
	int i;
	for(i=0;i<vomp_call_count;i++)
	  {
	    mdpreply.vompevent.other_calls_sessions[i]
	      =vomp_call_states[i].local.session;
	    mdpreply.vompevent.other_calls_states[i]
	      =vomp_call_states[i].local.state;
	  }
	
	return overlay_mdp_reply(mdp_named.poll.fd,recvaddr,recvaddrlen,&mdpreply);
      }
      break;
    case VOMPEVENT_DIAL:
      if (vomp_dial(
	mdp->vompevent.local_sid,
	mdp->vompevent.remote_sid,
	NULL,
	NULL))
	return overlay_mdp_reply_error
	      (mdp_named.poll.fd,recvaddr,recvaddrlen,4004,
	       "Unable to place call");
      else{
	int result= overlay_mdp_reply_error 
	  (mdp_named.poll.fd,recvaddr,recvaddrlen,0, "Success");
	if (result) WHY("Failed to send MDP reply");
	return result;
      }
      break;
    case VOMPEVENT_CALLREJECT: /* hangup is the same */
      {
	vomp_call_state *call
	  =vomp_find_call_by_session(mdp->vompevent.call_session_token);
	if (!call) 
	  return overlay_mdp_reply_error
	    (mdp_named.poll.fd,recvaddr,recvaddrlen,4006,
	     "No such call");
	
	vomp_hangup(call);
	
	return overlay_mdp_reply_error(mdp_named.poll.fd,
				recvaddr,recvaddrlen,0,"Success");
      }
      break;
    case VOMPEVENT_PICKUP: 
      {
	vomp_call_state *call
	  =vomp_find_call_by_session(mdp->vompevent.call_session_token);
	if (!call) 
	  return overlay_mdp_reply_error
	    (mdp_named.poll.fd,recvaddr,recvaddrlen,4006,
	     "No such call");
	
	if (vomp_pickup(call))
	  return overlay_mdp_reply_error(mdp_named.poll.fd,
					 recvaddr,recvaddrlen,4009,
					 "Call is not RINGINGIN, so cannot be picked up");
	else
	  return overlay_mdp_reply_error(mdp_named.poll.fd,
				  recvaddr,recvaddrlen,0,"Success");
      }
      break;
    case VOMPEVENT_AUDIOPACKET: /* user supplying audio */
      {
	// WHY("Audio packet arrived");
	vomp_call_state *call
	  =vomp_find_call_by_session(mdp->vompevent.call_session_token);
	if (call) {
	  return vomp_send_status_remote_audio(call, 
					       mdp->vompevent.audio_sample_codec,
					       &mdp->vompevent.audio_bytes[0],
					       vomp_sample_size(mdp->vompevent.audio_sample_codec));
	}
	else WHY("audio packet had invalid call session token");
      }
      break;
    default:
      /* didn't understand it, so respond with an error */
      return overlay_mdp_reply_error(mdp_named.poll.fd,
				     recvaddr,recvaddrlen,4001,
				     "Invalid VOMPEVENT request (use DIAL,HANGUP,CALLREJECT,AUDIOSTREAMING,REGISTERINTERST,WITHDRAWINTERST only)"); 

    }

  return WHY("Not implemented");
}

int vomp_extract_remote_codec_list(vomp_call_state *call,overlay_mdp_frame *mdp)
{
  int i;
  if (0) {
    WHY("Receiving list of remote codecs");
    dump("codec list mdp frame",
	 (unsigned char *)&mdp->in.payload[0],mdp->in.payload_length);
  }
  for(i=0;mdp->in.payload[14+i]&&(i<256)
	&&((14+i)<mdp->in.payload_length);i++)
    {
      if (0) WHYF("populating remote codec list with %s",
		  vomp_describe_codec(mdp->in.payload[14+i]));
      call->remote_codec_list[mdp->in.payload[14+i]]=1;
    }  
  // TODO send codec list to monitor clients
  return 0;
}

/*
Simplified call state lifecycle;
 
 (we dial)
 > CALLPREP + codecs
 < NOCALL + codecs
 > RINGOUT
 < RINGIN (they start ringing)
   (we start "they are ringing" tone)
 (they pickup)
 < INCALL
 > INCALL
 (either hangup, or state error)
 > CALLENDED
 < CALLENDED
 */

/* At this point we know the MDP frame is addressed to the VoMP port, but 
   we have not inspected the contents. As these frames are wire-format, we
   must pay attention to endianness. */
int vomp_mdp_received(overlay_mdp_frame *mdp)
{
  if (mdp->packetTypeAndFlags&(MDP_NOCRYPT|MDP_NOSIGN))
    {
      /* stream-crypted audio frame */
      return WHY("not implemented");
    }

  /* only auth-crypted frames make it this far */

  vomp_call_state *call=NULL;

  switch(mdp->in.payload[0]) {
  case 0x01: /* Ordinary VoMP state+optional audio frame */
    {
      int recvr_state=mdp->in.payload[1]>>4;
      int sender_state=mdp->in.payload[1]&0xf;
      unsigned int recvr_session=
	(mdp->in.payload[8]<<16)|(mdp->in.payload[9]<<8)|mdp->in.payload[10];
      unsigned int sender_session=
	(mdp->in.payload[11]<<16)|(mdp->in.payload[12]<<8)|mdp->in.payload[13];
      int sender_seq=(mdp->in.payload[4]<<8)+mdp->in.payload[5];
      
      // cyclic ~1 minute timer...
      unsigned int sender_duration = (mdp->in.payload[6]<<8) | mdp->in.payload[7];
      
      /* wants to create a call session.
       Main aim here: replay protection. An adversary should not be able to
       replay previous VoMP packets to cause any action.  We do this by
       allocating a new session number for each call.  As an adversary may be
       trying to use such replays to cause a denial of service attack we need
       to be able to track multiple potential session numbers even from the
       same SID. */
      
      call=vomp_find_or_create_call(mdp->in.src.sid,mdp->in.dst.sid,
				    sender_session,recvr_session,
				    sender_state,recvr_state);
      
      if (!call)
	return WHY("Unable to find or create call");
      
      if (!recvr_session)
	WHY("recvr_session==0, created call.");
      
      
      // TODO ignore state changes if sequence is stale?
      // TODO ignore state changes that seem to go backwards?
      
      if ((!vomp_interested_usock_count)
	  &&(!monitor_socket_count))
	{
	/* No registered listener, so we cannot answer the call, so just reject
	   it. */
	  if (0) WHYF("Rejecting call due to lack of a listener: states=%d,%d",
	       call->local.state,sender_state);

	call->local.state=VOMP_STATE_CALLENDED;
	/* now let the state machine progress to destroy the call */
      }

      if (call->local.state < VOMP_STATE_RINGINGOUT && sender_state < VOMP_STATE_RINGINGOUT){
	// the other party should have given us their list of supported codecs
	vomp_extract_remote_codec_list(call,mdp);
      }
      
      if (sender_state==VOMP_STATE_CALLENDED){
	/* For whatever reason, the far end has given up on the call, 
	   so we must also move to CALLENDED no matter what state we were in */
	
	if (call->audio_started) vomp_call_stop_audio(call);
	if (call->ringing) call->ringing=0;
	call->local.state=VOMP_STATE_CALLENDED;
      }
      
      /* Consider states: our actual state, sender state, what the sender thinks
	 our state is, and what we think the sender's state is.  But largely it
	 breaks down to what we think our state is, and what they think their 
	 state is.  That leaves us with just 6X6=36 cases. 
       */
      int combined_state=call->local.state<<3 | sender_state;
      
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
	  
	if (call->initiated_call)
	  // hey, quit it, we were trying to call you.
	  call->local.state=VOMP_STATE_CALLENDED;
	else{
	  // TODO fail the call if we can't find a codec you know
	  call->local.state=VOMP_STATE_RINGINGIN;
	  if (!call->ringing) vomp_call_start_ringing(call);
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
	  // TODO fail the call if we can't agree on codec's
	  call->local.state=VOMP_STATE_RINGINGOUT;
	}else{
	  call->local.state=VOMP_STATE_CALLENDED;
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
	call->local.state=VOMP_STATE_INCALL;
	// reset create time when call is established
	call->create_time=overlay_gettime_ms();
	break;
	  
      case (VOMP_STATE_INCALL<<3)|VOMP_STATE_RINGINGOUT:
	/* we think the call is in progress, but the far end hasn't replied yet
	 Just wait. */
	break;
	  
      case (VOMP_STATE_RINGINGOUT<<3)|VOMP_STATE_INCALL:
	/* They have answered, we can jump to incall as well */
	call->local.state=VOMP_STATE_INCALL;
	// reset create time when call is established
	call->create_time=overlay_gettime_ms();
	call->ringing=0;
	// Fall through
      case (VOMP_STATE_INCALL<<3)|VOMP_STATE_INCALL:
	/* play any audio that they have sent us. */
	if (!call->audio_started) {
	  if (vomp_call_start_audio(call)) call->local.codec=VOMP_CODEC_ENGAGED;
	}
	vomp_process_audio(call,sender_duration,mdp);
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
	return 0;
      }
      
      call->remote.sequence=sender_seq;
      call->remote.state=sender_state;
      call->last_activity=overlay_gettime_ms();
      
      // TODO if we hear a stale echo of our state should we force another outgoing packet now?
      // will that always cause 2 outgoing packets?
      
      /* send an update to the call status if required */
      vomp_update(call);
      
      if (call->remote.state==VOMP_STATE_CALLENDED
	  &&call->local.state==VOMP_STATE_CALLENDED)
	return vomp_call_destroy(call);
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

char *vomp_describe_state(int state)
{
  switch(state) {
  case VOMP_STATE_CALLENDED: return "CALLENDED";
  case VOMP_STATE_INCALL: return "INCALL";
  case VOMP_STATE_RINGINGIN: return "RINGINGIN";
  case VOMP_STATE_RINGINGOUT: return "RINGINGOUT";
  case VOMP_STATE_CALLPREP: return "CALLPREP";
  case VOMP_STATE_NOCALL: return "NOCALL";
  }
  return "UNKNOWN";
}

int dump_vomp_status()
{
  int i;
  printf(">>> Active VoMP call states:\n");
  for(i=0;i<vomp_call_count;i++)
    {
      printf("%s/%06x\n-> %s/%06x\n   (%s -> %s)\n",
	     alloca_tohex_sid(vomp_call_states[i].local.sid),
	     vomp_call_states[i].local.session,
	     alloca_tohex_sid(vomp_call_states[i].remote.sid),
	     vomp_call_states[i].remote.session,
	     vomp_call_states[i].local.did,
	     vomp_call_states[i].remote.did);
      printf("   local state=%s, remote state=%s\n",
	     vomp_describe_state(vomp_call_states[i].local.state),
	     vomp_describe_state(vomp_call_states[i].remote.state));
    }
  if (!vomp_call_count) printf("No active calls\n");
  return 0;
}

char *vomp_describe_codec(int c)
{
  switch(c) {
  case VOMP_CODEC_NONE: return "none";
  case VOMP_CODEC_CODEC2_2400: return "CODEC2@1400";
  case VOMP_CODEC_CODEC2_1400: return "CODEC2@2400";
  case VOMP_CODEC_GSMHALF: return "GSM-half-rate";
  case VOMP_CODEC_GSMFULL: return "GSM-full-rate";
  case VOMP_CODEC_16SIGNED: return "16bit-raw";
  case VOMP_CODEC_8ULAW: return "8bit-uLaw";
  case VOMP_CODEC_8ALAW: return "8bit-aLaw";
  case VOMP_CODEC_PCM: return "PCM@8KHz";
  case VOMP_CODEC_DTMF: return "DTMF";
  case VOMP_CODEC_ENGAGED: return "Engaged-tone";
  case VOMP_CODEC_ONHOLD: return "On-Hold";
  case VOMP_CODEC_CALLERID: return "CallerID";
  }
  return "unknown";
}

int vomp_sample_size(int c)
{
  switch(c) {
  case VOMP_CODEC_NONE: return 0;
  case VOMP_CODEC_CODEC2_2400: return 7; /* actually 2550bps, 51 bits per 20ms, 
					    but using whole byte here, so 2800bps */
  case VOMP_CODEC_CODEC2_1400: return 7; /* per 40ms */
  case VOMP_CODEC_GSMHALF: return 14; /* check. 5.6kbits */
  case VOMP_CODEC_GSMFULL: return 33; /* padded to 13.2kbit/sec */
  case VOMP_CODEC_16SIGNED: return 320; /* 8000x2bytes*0.02sec */
  case VOMP_CODEC_8ULAW: return 160;
  case VOMP_CODEC_8ALAW: return 160;
  case VOMP_CODEC_PCM: return 320;
  case VOMP_CODEC_DTMF: return 1;
  case VOMP_CODEC_ENGAGED: return 0;
  case VOMP_CODEC_ONHOLD: return 0;
  case VOMP_CODEC_CALLERID: return 32;
  }
  return -1;
}

int vomp_codec_timespan(int c)
{
  switch(c) {
  case VOMP_CODEC_NONE: return 1;
  case VOMP_CODEC_CODEC2_2400: return 20;
  case VOMP_CODEC_CODEC2_1400: return 40;
  case VOMP_CODEC_GSMHALF: return 20;
  case VOMP_CODEC_GSMFULL: return 20;
  case VOMP_CODEC_16SIGNED: return 20; 
  case VOMP_CODEC_8ULAW: return 20;
  case VOMP_CODEC_8ALAW: return 20;
  case VOMP_CODEC_PCM: return 20;
  case VOMP_CODEC_DTMF: return 80;
  case VOMP_CODEC_ENGAGED: return 20;
  case VOMP_CODEC_ONHOLD: return 20;
  case VOMP_CODEC_CALLERID: return 0;
  }
  return -1;
}


int app_vomp_status(int argc, const char *const *argv, struct command_line_option *o)
{ 
  overlay_mdp_frame mdp;
  bzero(&mdp,sizeof(mdp));

  mdp.packetTypeAndFlags=MDP_VOMPEVENT;
  mdp.vompevent.flags=VOMPEVENT_CALLINFO;
  if (overlay_mdp_send(&mdp,MDP_AWAITREPLY,5000))
    {
      WHY("Current call state information request failed.");
      if (mdp.packetTypeAndFlags==MDP_ERROR&&mdp.error.error)
	fprintf(stderr,"MDP: error=%d, message='%s'\n",
		mdp.error.error,mdp.error.message);
      overlay_mdp_client_done();
      return -1;
    }
  if (mdp.packetTypeAndFlags!=MDP_VOMPEVENT) {
    WHYF("Received incorrect reply type from server (received MDP message type 0x%04x)\n",mdp.packetTypeAndFlags);
    overlay_mdp_client_done();
    return -1;
  }
  if (mdp.vompevent.flags!=VOMPEVENT_CALLINFO) {
    WHYF("Received incorrect reply type from server (received VoMP message type 0x%04x)\n",mdp.vompevent.flags);
    overlay_mdp_client_done();
    return -1;
  }
  int i;
  int count=0;
  overlay_mdp_frame mdp2;
  bzero(&mdp2,sizeof(mdp2));
  for(i=0;i<VOMP_MAX_CALLS;i++)
    if (mdp.vompevent.other_calls_sessions[i])
      {
	count++;
	fprintf(stderr,"%06x:%s:",
		mdp.vompevent.other_calls_sessions[i],
		vomp_describe_state(mdp.vompevent.other_calls_states[i]));
	mdp2.packetTypeAndFlags=MDP_VOMPEVENT;
	mdp2.vompevent.flags=VOMPEVENT_CALLINFO;
	mdp2.vompevent.call_session_token=mdp.vompevent.other_calls_sessions[i];
	if (overlay_mdp_send(&mdp2,MDP_AWAITREPLY,5000))
	  fprintf(stderr,"<server failed to provide detail>");
	else
	  {
	    if (mdp2.vompevent.call_session_token!=mdp.vompevent.other_calls_sessions[i])
	      fprintf(stderr,"<strange reply from server (%04x, %04x, token %06x)>",
		      mdp.packetTypeAndFlags,mdp.vompevent.flags,
		      mdp2.vompevent.call_session_token);
	    else {
	      fprintf(stderr,"%s* -> %s* (%s -> %s)",
		      alloca_tohex(mdp2.vompevent.local_sid, 6),
		      alloca_tohex(mdp2.vompevent.remote_sid, 6),
		      strlen(mdp2.vompevent.local_did)
		      ?mdp2.vompevent.local_did:"<no local number>",
		      strlen(mdp2.vompevent.remote_did)
		      ?mdp2.vompevent.remote_did:"<no remote number>");
	    }
	    int i;
	    fprintf(stderr," supports");
	    for(i=0;i<256;i++) 
	      if (mdp2.vompevent.supported_codecs[i])
		fprintf(stderr," %s",vomp_describe_codec(i));	    
	  }
	fprintf(stderr,"\n");	
      }
  fprintf(stderr,"%d live call descriptors.\n",count);
  return overlay_mdp_client_done();
}

int app_vomp_dial(int argc, const char *const *argv, struct command_line_option *o)
{
  const char *sid,*did,*callerid;
  cli_arg(argc, argv, o, "sid", &sid, NULL, "");
  cli_arg(argc, argv, o, "did", &did, NULL, "");
  cli_arg(argc, argv, o, "callerid", &callerid, NULL, NULL);

  overlay_mdp_frame mdp;
  bzero(&mdp,sizeof(mdp));

  mdp.packetTypeAndFlags=MDP_VOMPEVENT;
  mdp.vompevent.flags=VOMPEVENT_DIAL;
  if (overlay_mdp_getmyaddr(0,&mdp.vompevent.local_sid[0])) return -1;
  stowSid(&mdp.vompevent.remote_sid[0],0,sid);
  printf("local_sid=%s\n",alloca_tohex_sid(mdp.vompevent.local_sid));
  printf("remote_sid=%s from %s\n", alloca_tohex_sid(mdp.vompevent.remote_sid),sid);

  if (overlay_mdp_send(&mdp,MDP_AWAITREPLY,5000))
    {
      WHY("Dial request failed.");
    }
  if (mdp.packetTypeAndFlags==MDP_ERROR&&mdp.error.error)
    fprintf(stderr,"Dial request failed: error=%d, message='%s'\n",
	    mdp.error.error,mdp.error.message);
  else 
    printf("Dial request accepted.\n");
  
  return overlay_mdp_client_done();
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

int app_vomp_dtmf(int argc, const char *const *argv, struct command_line_option *o)
{
  const char *call_token;
  const char *digits;
  cli_arg(argc, argv, o, "call", &call_token, NULL, "");
  cli_arg(argc, argv, o, "digits", &digits,NULL,"");

  overlay_mdp_frame mdp;
  bzero(&mdp,sizeof(mdp));

  mdp.packetTypeAndFlags=MDP_VOMPEVENT;
  mdp.vompevent.flags=VOMPEVENT_AUDIOPACKET;
  mdp.vompevent.call_session_token=strtol(call_token,NULL,16);

  /* One digit per sample block. */
  mdp.vompevent.audio_sample_codec=VOMP_CODEC_DTMF;
  mdp.vompevent.audio_sample_bytes=1;

  int i;
  for(i=0;i<strlen(digits);i++) {
    int digit=vomp_parse_dtmf_digit(digits[i]);
    if (digit<0) return WHYF("'%c' is not a DTMF digit.",digits[i]);    
    mdp.vompevent.audio_bytes[mdp.vompevent.audio_sample_bytes]
      =(digit<<4); /* 80ms standard tone duration, so that it is a multiple
		      of the majority of codec time units (70ms is the nominal
		      DTMF tone length for most systems). */
    if (overlay_mdp_send(&mdp,0,0)) WHY("Send DTMF failed.");
  }

  printf("DTMF digit(s) sent.\n");
  
  return overlay_mdp_client_done();
} 


int app_vomp_pickup(int argc, const char *const *argv, struct command_line_option *o)
{
  const char *call_token;
  cli_arg(argc, argv, o, "call", &call_token, NULL, "");

  overlay_mdp_frame mdp;
  bzero(&mdp,sizeof(mdp));

  mdp.packetTypeAndFlags=MDP_VOMPEVENT;
  mdp.vompevent.flags=VOMPEVENT_PICKUP;
  mdp.vompevent.call_session_token=strtol(call_token,NULL,16);

  if (overlay_mdp_send(&mdp,MDP_AWAITREPLY,5000))
    {
      WHY("Pickup request failed.");
    }
  if (mdp.packetTypeAndFlags==MDP_ERROR&&mdp.error.error)
    fprintf(stderr,"Pickup request failed: error=%d, message='%s'\n",
	    mdp.error.error,mdp.error.message);
  else 
    printf("Pickup request accepted.\n");
  
  return overlay_mdp_client_done();
} 

int app_vomp_hangup(int argc, const char *const *argv, struct command_line_option *o)
{
  const char *call_token;
  cli_arg(argc, argv, o, "call", &call_token, NULL, "");

  overlay_mdp_frame mdp;
  bzero(&mdp,sizeof(mdp));

  mdp.packetTypeAndFlags=MDP_VOMPEVENT;
  mdp.vompevent.flags=VOMPEVENT_HANGUP;
  mdp.vompevent.call_session_token=strtol(call_token,NULL,16);

  if (overlay_mdp_send(&mdp,MDP_AWAITREPLY,5000))
    {
      WHY("Hangup/reject request failed.");
    }
  if (mdp.packetTypeAndFlags==MDP_ERROR&&mdp.error.error)
    fprintf(stderr,"Hangup/reject request failed: error=%d, message='%s'\n",
	    mdp.error.error,mdp.error.message);
  else 
    printf("Hangup/reject request accepted.\n");
  
  return overlay_mdp_client_done();
} 

int app_vomp_monitor(int argc, const char *const *argv, struct command_line_option *o)
{
  overlay_mdp_frame mdp;
  bzero(&mdp,sizeof(mdp));

  mdp.packetTypeAndFlags=MDP_VOMPEVENT;
  mdp.vompevent.flags=VOMPEVENT_REGISTERINTEREST;
  mdp.vompevent.supported_codecs[0]=VOMP_CODEC_DTMF;
  mdp.vompevent.supported_codecs[1]=VOMP_CODEC_NONE;

  if (overlay_mdp_send(&mdp,MDP_AWAITREPLY,5000))
    { WHY("Failed to register interest in telephony events.");
      overlay_mdp_client_done(); 
      if (mdp.packetTypeAndFlags==MDP_ERROR&&mdp.error.error) 
	fprintf(stderr,"  MDP Server error #%d: '%s'\n",
		mdp.error.error,mdp.error.message);
      return -1; 
    }

  while(!servalShutdown) {
    overlay_mdp_frame rx;
    int ttl;
    /* In theory we should be able to ask for a timeout of -1 for
       infinity, but broken poll() and select() implementations on OSX
       make this impossible.  So one unnecessary check per second is 
       probably tolerable.  */
    if (overlay_mdp_client_poll(1000)>0)
      if (!overlay_mdp_recv(&rx,&ttl))
	{
	  switch(rx.packetTypeAndFlags) {
	  case MDP_ERROR:
	    fprintf(stderr,"MDP Server error #%d: '%s'\n",
		    rx.error.error,rx.error.message);
	    break;
	  case MDP_VOMPEVENT:
	    fprintf(stderr,"VoMP call descriptor %06x %s:%s",
		    rx.vompevent.call_session_token,
		    vomp_describe_state(rx.vompevent.local_state),
		    vomp_describe_state(rx.vompevent.remote_state));
	    if (rx.vompevent.flags&VOMPEVENT_RINGING) 
	      fprintf(stderr," RINGING");
	    if (rx.vompevent.flags&VOMPEVENT_CALLENDED) 
	      fprintf(stderr," CALLENDED");
	    if (rx.vompevent.flags&VOMPEVENT_CALLREJECT) 
	      fprintf(stderr," CALLREJECTED");
	    if (rx.vompevent.flags&VOMPEVENT_CALLCREATED) 
	      fprintf(stderr," CREATED");
	    if (rx.vompevent.flags&VOMPEVENT_AUDIOSTREAMING) 
	      fprintf(stderr," AUDIOSTREAMING");
	    int i;
	    fprintf(stderr," codecs:");
	    for(i=0;i<256;i++) 
	      if (rx.vompevent.supported_codecs[i])
		fprintf(stderr," %s",vomp_describe_codec(i));	    

	    fprintf(stderr,"\n");
	    if (rx.vompevent.audio_sample_codec) {
	      fprintf(stderr,"    attached audio sample: codec=%s, len=%d\n",
		      vomp_describe_codec(rx.vompevent.audio_sample_codec),
		      rx.vompevent.audio_sample_bytes);
	      fprintf(stderr,"    sample covers %lldms - %lldms of call.\n",
		      rx.vompevent.audio_sample_starttime,
		      rx.vompevent.audio_sample_endtime);
	    }
	    break;
	  default:
	    fprintf(stderr,"Unknown message (type=0x%02x)\n",rx.packetTypeAndFlags);
	  }
	}
    
  }

  mdp.packetTypeAndFlags=MDP_VOMPEVENT;
  mdp.vompevent.flags=VOMPEVENT_WITHDRAWINTEREST;
  if (overlay_mdp_send(&mdp,MDP_AWAITREPLY,5000))
    { WHY("Failed to deregister interest in telephony events.");
      overlay_mdp_client_done(); return -1; }
  if (mdp.packetTypeAndFlags==MDP_ERROR&&mdp.error.error) {
    fprintf(stderr,"  MDP Server error #%d: '%s'\n",
	    mdp.error.error,mdp.error.message);
     }

  return overlay_mdp_client_done();
}

void vomp_process_tick(struct sched_ent *alarm){
  char msg[32];
  int len;
  unsigned long long now = overlay_gettime_ms();
  
  vomp_call_state *call = (vomp_call_state *)alarm;
  
  /* See if any calls need to begin expiring
   (current timeout is set at 2 minutes) */
  if (call->local.state<VOMP_STATE_INCALL
      &&((call->create_time+VOMP_CALL_TIMEOUT)<now))
  {
    /* timeout calls that haven't reached INCALL status, e.g.,
     ringing. As well as sensible UX, it also prevents our call
     slots getting full of cruft. */
    vomp_call_destroy(call);
    return;
  } else if (call->last_activity+VOMP_CALL_TIMEOUT<now)
    switch(call->local.state)	  
  {
    case VOMP_STATE_INCALL:
      /* Timeout while call in progress, so end call.
       Keep call structure hanging around for a bit so that we can
       synchonrise with the far end if possible. */
      call->local.state=VOMP_STATE_CALLENDED;
      vomp_call_stop_audio(call);
      call->last_activity=now;
      break;
    default:	    
      /* Call timed out while not actually in progress, so just immmediately
       tear the call down */
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
  
  alarm->alarm = overlay_gettime_ms() + VOMP_CALL_STATUS_INTERVAL;
  schedule(alarm);
}
