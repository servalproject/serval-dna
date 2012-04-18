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
  VoMP works using a 5-state model of a phone call, and relies on MDP for 
  auth-cryption of frames. VoMP provides it's own replay protection.

*/

#include "serval.h"

typedef struct vomp_call_half {
  unsigned char sid[SID_SIZE];
  unsigned char state;
  unsigned char codec;
  unsigned int session;
#define VOMP_SESSION_MASK 0xffffff
  unsigned int sequence;
  /* the following is from call creation, not start of audio flow */
  unsigned long long milliseconds_since_call_start;
} vomp_call_half;

typedef struct vomp_call_state {
  vomp_call_half local;
  vomp_call_half remote;
  int ringing;
  unsigned long long last_activity;
  int audio_started;
} vomp_call_state;

#define VOMP_CODEC_CODEC2_2400 0x01
#define VOMP_CODEC_CODEC2_1400 0x02
#define VOMP_CODEC_GSM 0x03
#define VOMP_CODEC_DTMF 0x04
#define VOMP_CODEC_ENGAGED 0x05
#define VOMP_CODEC_CODECSISUPPORT 0xfe
#define VOMP_CODEC_CHANGEYOURCODECTO 0xff

#define VOMP_STATE_NOCALL 1
#define VOMP_STATE_CALLPREP 2
#define VOMP_STATE_RINGINGOUT 3
#define VOMP_STATE_RINGINGIN 4
#define VOMP_STATE_INCALL 5
#define VOMP_STATE_CALLENDED 6

/* Although we only support one call at a time, we allow for multiple call states.
   This is partly to deal with denial of service attacks that might occur by causing
   the ejection of newly allocated session numbers before the caller has had a chance
   to progress the call to a further state. */
int vomp_call_count=0;
#define VOMP_MAX_CALLS 16
vomp_call_state vomp_call_states[VOMP_MAX_CALLS];

vomp_call_state *vomp_find_or_create_call(unsigned char *remote_sid,
					  unsigned char *local_sid,
					  unsigned int sender_session,
					  unsigned int recvr_session)
{
  int expired_slot=-1;
  int i;
  for(i=0;i<vomp_call_count;i++)
    {
      /* do the fast comparison first, and only if that matches proceed to
	 the slower SID comparisons */
      if (sender_session&(sender_session!=vomp_call_states[i].remote.session))
	continue;
      if (recvr_session&(recvr_session!=vomp_call_states[i].local.session))
	continue;
      if (bcmp(remote_sid,vomp_call_states[i].remote.sid,SID_SIZE)) continue;
      if (bcmp(local_sid,vomp_call_states[i].local.sid,SID_SIZE)) continue;

      /* it matches.  but has it expired (no activity in 120 seconds)? */
      if (vomp_call_states[i].last_activity<(overlay_gettime_ms()-120000))
	{
	  expired_slot=i;
	  continue;
	}

      return &vomp_call_states[i];
    }

  /* not in the list.  So allocate a slot. */
  if (expired_slot>-1) i=expired_slot;
  else if ((i<VOMP_MAX_CALLS)&&(i==vomp_call_count)) {
    /* there is room to allocate another, so do that */
    vomp_call_count++;
  } else {
    /* no room, either reallocate an existing slot, or fail.
       We try to reuse slots that either mark ended calls, or 
       */
    int candidates[VOMP_MAX_CALLS];
    int candidate_count=0;
    for(i=0;i<VOMP_MAX_CALLS;i++)
      if ((vomp_call_states[i].local.state==VOMP_STATE_NOCALL)||
	  (vomp_call_states[i].local.state==VOMP_STATE_CALLENDED))
	candidates[candidate_count++]=i;
    i=candidates[random()%candidate_count];
  }
  
  /* prepare slot */
  bzero(&vomp_call_states[i],sizeof(vomp_call_state));
  bcopy(local_sid,&vomp_call_states[i].local.sid,SID_SIZE);
  bcopy(remote_sid,&vomp_call_states[i].remote.sid,SID_SIZE);
  if (!recvr_session) {
    urandombytes((unsigned char *)&recvr_session,sizeof(int));
    recvr_session&=VOMP_SESSION_MASK;
  }
  if (!sender_session) {
    urandombytes((unsigned char *)&sender_session,sizeof(int));
    sender_session&=VOMP_SESSION_MASK;
  }
  vomp_call_states[i].local.session=recvr_session;
  vomp_call_states[i].remote.session=sender_session;
  vomp_call_states[i].local.state=VOMP_STATE_NOCALL;
  vomp_call_states[i].remote.state=VOMP_STATE_NOCALL;
  return &vomp_call_states[i];
}

int vomp_send_status(vomp_call_state *call)
{
  return WHY("Not implemented");
}

int vomp_call_start_audio(vomp_call_state *call)
{
  return WHY("Not implemented");
}

int vomp_process_audio(vomp_call_state *call,overlay_mdp_frame *mdp)
{
  // int first_frame_codec=mdp->in.payload[3];
  // int recvr_seq=(mdp->in.payload[4]<<8)+mdp->in.payload[5];
  // int sender_seq=(mdp->in.payload[4]<<8)+mdp->in.payload[5];
  // unsigned int sender_millis=
  //   (mdp->in.payload[12]<<16)+(mdp->in.payload[13]<<8)+mdp->in.payload[14];

  return WHY("Not implemented");
}

int vomp_call_stop_audio(vomp_call_state *call)
{
  return WHY("Not implemented");
}

int vomp_call_start_ringing(vomp_call_state *call)
{
  return WHY("Not implemented");
}

int vomp_call_rejected(vomp_call_state *call)
{
  return WHY("Not implemented");
}

int vomp_call_error(vomp_call_state *call)
{
  if (call->audio_started) vomp_call_stop_audio(call);
  return WHY("Not implemented");
}

int vomp_call_destroy(vomp_call_state *call)
{
  if (call->audio_started) vomp_call_stop_audio(call);
  return WHY("Not implemented");
}

/* At this point we know the MDP frame is addressed to the VoMP port, but 
   we have not inspected the contents. As these frames are wire-format, we
   must pay attention to endianness. */
void vomp_mdp_received(overlay_mdp_frame *mdp)
{
  if (mdp->packetTypeAndFlags&(MDP_NOCRYPT|MDP_NOSIGN))
    {
      /* stream-crypted audio frame */
      WHY("not implemented");
      return;
    }

  /* only auth-crypted frames make it this far */

  vomp_call_state *call=NULL;

  switch(mdp->in.payload[0]) {
  case 0x01: /* Ordinary VoMP state+optional audio frame */
    {
      // int recvr_state=mdp->in.payload[2];
      int sender_state=mdp->in.payload[2];
      unsigned int recvr_session=
	(mdp->in.payload[6]<<16)+(mdp->in.payload[7]<<8)+mdp->in.payload[8];
      unsigned int sender_session=
	(mdp->in.payload[9]<<16)+(mdp->in.payload[10]<<8)+mdp->in.payload[11];
      
      if (!recvr_session) {
	/* wants to create a call session.
	   Main aim here: replay protection. An adversary should not be able to
	   replay previous VoMP packets to cause any action.  We do this by
	   allocating a new session number for each call.  As an adversary may be
	   trying to use such replays to cause a denial of service attack we need
	   to be able to track multiple potential session numbers even from the
	   same SID. */
	call=vomp_find_or_create_call(mdp->in.src.sid,mdp->in.dst.sid,
				      sender_session,recvr_session);
	if (!call) {
	  /* could not allocate a call slot, so do nothing */
	  WHY("No free call slots");
	  return;
	}

	/* We have a session number.  Send a status update back to sender */
	call->last_activity=overlay_gettime_ms();
	vomp_send_status(call);
	return;
      } else {
	/* A VoMP packet for a call apparently already in progress */
	call=vomp_find_or_create_call(mdp->in.src.sid,mdp->in.dst.sid,
				      sender_session,recvr_session);
	if (!call) {
	  WHY("VoMP frame does not correspond to an active call - stale traffic or replay attack?");
	  return;
	}
	/* Consider states: our actual state, sender state, what the sender thinks
	   our state is, and what we think the sender's state is.  But largely it
	   breaks down to what we think our state is, and what they think their 
	   state is.  That leaves us with just 6X6=36 cases. */
	int combined_state=call->local.state<<3;
	combined_state|=sender_state;
	switch(combined_state) {
	case (VOMP_STATE_NOCALL<<3)|VOMP_STATE_NOCALL:
	  /* We both think that we are not yet in a call, and we have session numbers
	     at each end. Presumably waiting for further state synchronisation */
	  break;
	case (VOMP_STATE_NOCALL<<3)|VOMP_STATE_CALLPREP:
	  /* The remote party is in the call-prep state, while we think no call
	     is in progress.  Yet we have supplied them with a session number.
	     This is probably a state that should not occur, since when they 
	     received the session # they should have moved to RINGINGOUT. 
	     No action is required, but we probably shouldn't count it towards
	     valid call activity, so don't touch the recent activity timer.
	     Just return. */
	  return;
	case (VOMP_STATE_NOCALL<<3)|VOMP_STATE_RINGINGOUT:
	  /* We have have issued a session, but think that no call is in progress.
	     The remote party is now indicating that they are trying to ring us.
	     So change our state to RINGINGIN, but don't yet flag this to the user
	     until we both have acknowledged this (when I am RINGINGIN and they are
	     RINGINGOUT). */
	  call->local.state=VOMP_STATE_RINGINGIN;
	  break;
	case (VOMP_STATE_NOCALL<<3)|VOMP_STATE_RINGINGIN:
	  /* We think there is no call, while the remote end thinks that we are
	     ringing them. This could be because we hung the call up.  That's okay.
	     We just keep persisting, because once they acknowledge this, we will
	     both move to CALLENDED and hang up */
	  call->local.state=VOMP_STATE_CALLENDED;
	  break;
	case (VOMP_STATE_NOCALL<<3)|VOMP_STATE_INCALL:
	  /* As above, a call has probably been hung up by us, but the far end has
	     not yet realised.  Nothing to do here, except wait for states to
	     synchronise. */
	  break;
	case (VOMP_STATE_NOCALL<<3)|VOMP_STATE_CALLENDED:
	  /* Far end has given up on the call, so also move to CALLENDED */
	  call->local.state=VOMP_STATE_CALLENDED;
	  break;
	case (VOMP_STATE_CALLPREP<<3)|VOMP_STATE_NOCALL:
	  /* We are getting ready to ring, and the other end has issued a session
	     number, but nothing else.  This means that we can now proceed to 
	     the RINGINGOUT state, and wait for acknowledgement of that from the
	     far end. But we don't start ringing until the far end acknowledges
	     the state change. */
	  call->local.state=VOMP_STATE_RINGINGOUT;
	  break;
	case (VOMP_STATE_CALLPREP<<3)|VOMP_STATE_CALLPREP:
	  /* we are both in callprep stage, so we are both trying to ring each 
	     other!  This would take some pretty special timing to happen, but
	     let's not prevent it.  We move to RINGINGOUT (as they probably will
	     as well). */
	  call->local.state=VOMP_STATE_RINGINGOUT;
	  break;
	case (VOMP_STATE_CALLPREP<<3)|VOMP_STATE_RINGINGOUT:
	  /* We are trying to call them, and they are trying to call us, again
	     this seems a very unlikely situation.  But the appropriate action is
	     clear: get ready to start ringing. */
	  call->local.state=VOMP_STATE_RINGINGIN;
	  break;
	case (VOMP_STATE_CALLPREP<<3)|VOMP_STATE_RINGINGIN:
	  /* We are trying to call them, and they think we are trying to call them.
	     They seem to have guessed our next move, which is fine.  We move to
	     RINGINGOUT. */
	  call->local.state=VOMP_STATE_RINGINGOUT;
	  break;
	case (VOMP_STATE_CALLPREP<<3)|VOMP_STATE_INCALL:
	  /* We are trying to call them, and they think we are already in a call.
	     This shouldn't happen either, but appropriate action is that we move
	     to in-call, and start handling audio. If audio is not available, we
	     can switch to engaged tone by sending a single VOMP_CODEC_ENGAGED
	     audio frame. Call-waiting not currently supported. */
	  call->local.state=VOMP_STATE_INCALL;
	  if (vomp_call_start_audio(call)) call->local.codec=VOMP_CODEC_ENGAGED;  
	  break;
	case (VOMP_STATE_CALLPREP<<3)|VOMP_STATE_CALLENDED:
	  /* far end says no call */
	  call->local.state=VOMP_STATE_CALLENDED;
	  break;
	case (VOMP_STATE_RINGINGOUT<<3)|VOMP_STATE_NOCALL:
	  /* We are calling them, and they have not yet answered, wait for
	     synchronisation. */
	  call->local.state=VOMP_STATE_RINGINGOUT;
	  break;
	case (VOMP_STATE_RINGINGOUT<<3)|VOMP_STATE_CALLPREP:
	  /* we are calling them, and they are getting ready to call us, so wait
	     for synchronisation */
	  break;
	case (VOMP_STATE_RINGINGOUT<<3)|VOMP_STATE_RINGINGOUT:
	  /* we are each calling each other, so move to INCALL and start audio */
	  call->local.state=VOMP_STATE_INCALL;
	  if (vomp_call_start_audio(call)) call->local.codec=VOMP_CODEC_ENGAGED;  
	  break;
	case (VOMP_STATE_RINGINGOUT<<3)|VOMP_STATE_RINGINGIN:
	  /* we are calling them and they are calling us, so keep on ringing.
	     Or if we haven't started making noise, then do so. */
	  if (!call->ringing) vomp_call_start_ringing(call);
	  break;   
	case (VOMP_STATE_RINGINGOUT<<3)|VOMP_STATE_INCALL:
	  /* we are calling them, and they have entered the call, so we should enter
	     the call as well. */
	  call->local.state=VOMP_STATE_INCALL;
	  if (vomp_call_start_audio(call)) call->local.codec=VOMP_CODEC_ENGAGED;  
	  break;
	case (VOMP_STATE_RINGINGOUT<<3)|VOMP_STATE_CALLENDED:
	  /* Other end has rejected call */
	  vomp_call_rejected(call);
	  call->local.state=VOMP_STATE_CALLENDED;
	  break;
	case (VOMP_STATE_RINGINGIN<<3)|VOMP_STATE_NOCALL:
	  /* we are ringing and they think there is no call, so move to CALLENDED */
	  call->local.state=VOMP_STATE_CALLENDED;
	  vomp_call_error(call);
	  break;
	case (VOMP_STATE_RINGINGIN<<3)|VOMP_STATE_CALLPREP:
	  /* er, causaility loop here.  We are ringing before they have started 
	     ringing us.  I guess we should stop ringing. Should we also abort the
	     call? */
	  call->local.state=VOMP_STATE_CALLENDED;
	  vomp_call_error(call);
	  break;
	case (VOMP_STATE_RINGINGIN<<3)|VOMP_STATE_RINGINGOUT:
	  /* we are ringing and they are ringing us.  Make sure we are ringing. */
	  if (!call->ringing) vomp_call_start_ringing(call);
	  break;
	case (VOMP_STATE_RINGINGIN<<3)|VOMP_STATE_RINGINGIN:
	  /* er, we both think that the other is calling us. */
	  call->local.state=VOMP_STATE_CALLENDED;
	  vomp_call_error(call);
	  break;
	case (VOMP_STATE_RINGINGIN<<3)|VOMP_STATE_INCALL:
	  /* we think they are ringing us, but they think the call has
	     started. I guess we just keep ringing. */
	  if (!call->ringing) vomp_call_start_ringing(call);
	  break;
	case (VOMP_STATE_RINGINGIN<<3)|VOMP_STATE_CALLENDED:
	  /* the far end has rejected our attempt to call them */
	  vomp_call_rejected(call);
	  call->local.state=VOMP_STATE_CALLENDED;
	  break;
	case (VOMP_STATE_INCALL<<3)|VOMP_STATE_NOCALL:
	  /* this shouldn't happen */
	  call->local.state=VOMP_STATE_CALLENDED;
	  vomp_call_error(call);
	  break;
	case (VOMP_STATE_INCALL<<3)|VOMP_STATE_CALLPREP:
	  /* this shouldn't happen either */
	  call->local.state=VOMP_STATE_CALLENDED;
	  vomp_call_error(call);
	  break;
	case (VOMP_STATE_INCALL<<3)|VOMP_STATE_RINGINGOUT:
	  /* we think the call is in progress, but the far end hasn't realised
	     we have picked up yet.  Nothing to do here. */
	  break;
	case (VOMP_STATE_INCALL<<3)|VOMP_STATE_RINGINGIN:
	case (VOMP_STATE_INCALL<<3)|VOMP_STATE_INCALL:
	  /* play any audio that they have sent us. */
	  if (!call->audio_started) {
	    if (vomp_call_start_audio(call)) call->local.codec=VOMP_CODEC_ENGAGED;
	  }
	  vomp_process_audio(call,mdp);
	  break;
	case (VOMP_STATE_INCALL<<3)|VOMP_STATE_CALLENDED:
	  /* far end hung up */
	  vomp_call_stop_audio(call);
	  call->local.state=VOMP_STATE_CALLENDED;
	  break;
	case (VOMP_STATE_CALLENDED<<3)|VOMP_STATE_NOCALL:
	case (VOMP_STATE_CALLENDED<<3)|VOMP_STATE_CALLPREP:
	case (VOMP_STATE_CALLENDED<<3)|VOMP_STATE_RINGINGOUT:
	case (VOMP_STATE_CALLENDED<<3)|VOMP_STATE_RINGINGIN:
	case (VOMP_STATE_CALLENDED<<3)|VOMP_STATE_INCALL:
	  /* For all of these states wait for the far end to synchronise,
	     but don't touch the call timer */
	  return;
	case (VOMP_STATE_CALLENDED<<3)|VOMP_STATE_CALLENDED:
	  /* We both agree the call is done.  Destroy call. */
	  vomp_call_destroy(call);
	  return;
	}
	
	/* touch call timer if the current state has not vetoed by returning */
	call->last_activity=overlay_gettime_ms();
	/* and then send an update to the call status */
	vomp_send_status(call);
      }
    }
    break;
  case 0x02: /* codec selection, lists set of acceptable codec formats,
		and may thus cause change of codec, including during the call */
    break;
  default:
    /* unsupported VoMP frame */
    break;
  }

}
