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

vomp_call_state *vomp_find_or_create_call(unsigned char *remote_sid,
					  unsigned char *local_sid,
					  unsigned int sender_session,
					  unsigned int recvr_session,
					  int sender_state,int recvr_state)
{
  int expired_slot=-1;
  int i;
  printf("%d calls already in progress.\n",vomp_call_count);
  for(i=0;i<vomp_call_count;i++)
    {
      /* do the fast comparison first, and only if that matches proceed to
	 the slower SID comparisons */
      fprintf(stderr,"asking for %06x:%06x, this call %06x:%06x\n",
	      sender_session,recvr_session,
	      vomp_call_states[i].remote.session,
	      vomp_call_states[i].local.session);

      int checked=0;
      if (vomp_call_states[i].remote.session&&sender_session) { 
	checked++;
	if(sender_session!=vomp_call_states[i].remote.session)
	  continue;
      }
      if (vomp_call_states[i].local.session&&recvr_session) {
	checked++;
	if(recvr_session!=vomp_call_states[i].local.session)
	  continue;
      }
      if (!checked) continue;
      if (memcmp(remote_sid,vomp_call_states[i].remote.sid,SID_SIZE)) continue;
      if (memcmp(local_sid,vomp_call_states[i].local.sid,SID_SIZE)) continue;

      /* it matches.  but has it expired (no activity in 120 seconds)?
         NOTE: as these time calculations are unsigned, we must add to
	 the last activity time rather than subtract from the current time
	 when calculating the timeout.
      */
      if (vomp_call_states[i].last_activity+VOMP_CALL_TIMEOUT<(overlay_gettime_ms()))
	{
	  WHYF("slot %d has expired.",i);
	  WHYF("  last_activity=%lld, now=%lld",
	       vomp_call_states[i].last_activity,overlay_gettime_ms());
	  expired_slot=i;
	  continue;
	}

      /* Record session number if required */
      if (!vomp_call_states[i].remote.session) 
	vomp_call_states[i].remote.session=sender_session;

      WHYF("Returning existing call #%d",i);
      fprintf(stderr,"%06x:%06x matches call #%d %06x:%06x\n",
	     sender_session,recvr_session,i,
	     vomp_call_states[i].remote.session,
	     vomp_call_states[i].local.session);
      
      return &vomp_call_states[i];
    }

  /* not in the list.  So allocate a slot, but only if the call is in progress. */
  if (recvr_state==VOMP_STATE_CALLENDED&&sender_state==VOMP_STATE_CALLENDED)
    return NULL;

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
  vomp_call_states[i].create_time=overlay_gettime_ms();
  vomp_call_states[i].last_activity=vomp_call_states[i].create_time;
  WHYF("Returning new call #%d",i);
  return &vomp_call_states[i];
}

/* send updated call status to end-point and to any interested listeners as
   appropriate */
#define VOMP_TELLINTERESTED (1<<0)
#define VOMP_TELLREMOTE (1<<1)
#define VOMP_NEWCALL (1<<2)
#define VOMP_FORCETELLREMOTE ((1<<3)|VOMP_TELLREMOTE)
#define VOMP_TELLCODECS (1<<4)

int vomp_send_status(vomp_call_state *call,int flags)
{
  if (flags&VOMP_TELLREMOTE) {
    int combined_status=(call->remote.state<<4)|call->local.state;
    if (call->last_sent_status!=combined_status||
	(flags&VOMP_FORCETELLREMOTE)==VOMP_FORCETELLREMOTE) {
      call->last_sent_status=combined_status;

      overlay_mdp_frame mdp;
      bzero(&mdp,sizeof(mdp));
      mdp.packetTypeAndFlags=MDP_TX;
      bcopy(call->local.sid,mdp.out.src.sid,SID_SIZE);
      mdp.out.src.port=MDP_PORT_VOMP;
      bcopy(call->remote.sid,mdp.out.dst.sid,SID_SIZE);
      mdp.out.dst.port=MDP_PORT_VOMP;
      
      mdp.out.payload[0]=0x01; /* Normal VoMP frame */
      mdp.out.payload[1]=combined_status;
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
      
      if ((!call->remote.session)||(flags&VOMP_TELLCODECS)) {
	/* Also include list of supported codecs */
	int i;
	for(i=0;i<256;i++)
	  if (vomp_local_codec_list[i]) mdp.out.payload[mdp.out.payload_length++]=i;
	mdp.out.payload[mdp.out.payload_length++]=0;
      }

      overlay_mdp_send(&mdp,0,0);
      
      call->local.sequence++;
    }
  }
  if (flags&VOMP_TELLINTERESTED) {
    overlay_mdp_frame mdp;
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
    if (flags&VOMP_NEWCALL)
      mdp.vompevent.flags|=VOMPEVENT_CALLCREATED;
    mdp.vompevent.local_state=call->local.state;
    mdp.vompevent.remote_state=call->remote.state;

    int i;
    long long now=overlay_gettime_ms();
    for(i=0;i<vomp_interested_usock_count;i++)
      if (vomp_interested_expiries[i]>=now) {
	overlay_mdp_reply(mdp_named_socket,
			  vomp_interested_usocks[i],
			  vomp_interested_usock_lengths[i],
			  &mdp);
      }
    bcopy(&call->remote_codec_list[0],&mdp.vompevent.supported_codecs[0],256);
  }
  return 0;
}

int vomp_call_start_audio(vomp_call_state *call)
{
  call->audio_started=1;
  return WHY("Not implemented");
}

int vomp_process_audio(vomp_call_state *call,overlay_mdp_frame *mdp)
{

  return WHY("Not implemented");
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

int vomp_call_rejected(vomp_call_state *call)
{  
  /* state number change is handled elsewhere, we just need to make sure
     that things are tidy. */
  if (call->audio_started) vomp_call_stop_audio(call);
  if (call->ringing) call->ringing=0;
  return 0;
}

int vomp_call_error(vomp_call_state *call)
{
  if (call->audio_started) vomp_call_stop_audio(call);
  if (call->ringing) call->ringing=0;
  return 0;
}

int vomp_call_destroy(vomp_call_state *call)
{
  /* do some general clean ups */
  if (call->audio_started) vomp_call_stop_audio(call);

  fprintf(stderr,"Destroying call %s <--> %s\n",
	  call->local.did,call->remote.did);

  /* tell everyone the call has died */
  vomp_send_status(call,VOMP_TELLREMOTE|VOMP_TELLINTERESTED);

  /* now release the call structure */
  int i;
  for(i=0;i<VOMP_MAX_CALLS;i++)
    if (call==&vomp_call_states[i]) break;
  if (i>=VOMP_MAX_CALLS) return WHY("supplied call handle looks invalid");

  if (i==vomp_call_count-1)
    vomp_call_count--;
  else
    {
      bcopy(&vomp_call_states[vomp_call_count-1],
	    &vomp_call_states[i],
	    sizeof(vomp_call_state));
      vomp_call_count--;
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
  dump("vomp frame",(unsigned char *)mdp,256);
  fprintf(stderr,"Flags=0x%x\n",mdp->vompevent.flags);
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
		return overlay_mdp_reply_error(mdp_named_socket,recvaddr,recvaddrlen,
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
	    return overlay_mdp_reply_error(mdp_named_socket, recvaddr,recvaddrlen,
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
	      vomp_local_codec_list[mdp->vompevent.supported_codecs[i]]=1;
	  }
		
	  return overlay_mdp_reply_error
	    (mdp_named_socket,recvaddr,recvaddrlen,0,"Success");	     
	} else {
	  return overlay_mdp_reply_error
	    (mdp_named_socket,recvaddr,recvaddrlen,
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
		    (mdp_named_socket,recvaddr,recvaddrlen,
		     0,"Success. You have been removed.");
		}
	  }
	return overlay_mdp_reply_error
	  (mdp_named_socket,recvaddr,recvaddrlen,
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
	} else 
	  if (mdp->vompevent.call_session_token)
	    /* let the requestor know that the requested call doesn't exist */
	    mdpreply.vompevent.flags|=VOMPEVENT_ERROR;

	/* and provide a quick summary of all calls in progress */
	int i;
	for(i=0;i<VOMP_MAX_CALLS;i++)
	  {
	    if (i<vomp_call_count) {
	      mdpreply.vompevent.other_calls_sessions[i]
		=vomp_call_states[i].local.session;
	      mdpreply.vompevent.other_calls_states[i]
		=vomp_call_states[i].local.state;
	    }
	  }

	return overlay_mdp_reply(mdp_named_socket,recvaddr,recvaddrlen,&mdpreply);
      }
      break;
    case VOMPEVENT_DIAL: 
      /* pull local_did and remote_did and start putting the call together.
	 These need to be passed to the node being called to provide caller id,
	 and potentially handle call-routing, e.g., if it is a gateway.
         */
      fprintf(stderr,"DIAL Request!\n");
      {
	/* Populate call structure */
	if (vomp_call_count>=VOMP_MAX_CALLS) 
	  return overlay_mdp_reply_error
	    (mdp_named_socket,recvaddr,recvaddrlen,4004,
	     "All call slots in use");
	int slot=vomp_call_count++;
	vomp_call_state *call=&vomp_call_states[slot];
	bzero(call,sizeof(vomp_call_state));
	bcopy(mdp->vompevent.local_sid,call->local.sid,SID_SIZE);
	bcopy(mdp->vompevent.remote_sid,call->remote.sid,SID_SIZE);
	bcopy(mdp->vompevent.local_did,call->local.did,64);
	bcopy(mdp->vompevent.remote_did,call->remote.did,64);
	call->local.state=VOMP_STATE_CALLPREP;
	call->remote.state=VOMP_STATE_NOCALL; /* far end has yet to agree that a call is happening */
	/* allocate unique call session token, which is how the client will
	   refer to this call during its life */
	while (!call->local.session)
	  {
	    if (urandombytes((unsigned char *)&call->local.session,sizeof(int)))
	      return overlay_mdp_reply_error
		(mdp_named_socket,recvaddr,recvaddrlen,4005,
		 "Insufficient entropy");
	    call->local.session&=VOMP_SESSION_MASK;
	    printf("session=0x%08x\n",call->local.session);
	    int i;
	    for(i=0;i<vomp_call_count;i++)
	      if (i!=slot) 
		if (call->local.session==vomp_call_states[i].local.session) break;
	    /* reject duplicate call session numbers */
	    if (i<vomp_call_count) call->local.session=0;
	  }
	call->local.session&=VOMP_SESSION_MASK;
	call->last_activity=overlay_gettime_ms();

	/* send status update to remote, thus causing call to be created
	   (hopefully) at far end. */
	vomp_send_status(call,VOMP_TELLREMOTE|VOMP_TELLINTERESTED);
	WHY("sending MDP reply back");
	dump("recvaddr",(unsigned char *)recvaddr,recvaddrlen);
	int result= overlay_mdp_reply_error 
	  (mdp_named_socket,recvaddr,recvaddrlen,0, "Success");
	if (result) WHY("Failed to send MDP reply");
	return result;
      }
      break;
    case VOMPEVENT_CALLREJECT: /* hangup is the same */
      {
	WHY("Hanging up");
	vomp_call_state *call
	  =vomp_find_call_by_session(mdp->vompevent.call_session_token);
	if (!call) 
	  return overlay_mdp_reply_error
	    (mdp_named_socket,recvaddr,recvaddrlen,4006,
	     "No such call");
	if (call->local.state==VOMP_STATE_INCALL) vomp_call_stop_audio(call);
	call->local.state=VOMP_STATE_CALLENDED;
	overlay_mdp_reply_error(mdp_named_socket,
				recvaddr,recvaddrlen,0,"Success");
	return vomp_send_status(call,VOMP_TELLREMOTE|VOMP_TELLINTERESTED);
      }
      break;
    case VOMPEVENT_PICKUP: 
      {
	WHY("Picking up");
	vomp_call_state *call
	  =vomp_find_call_by_session(mdp->vompevent.call_session_token);
	if (!call) 
	  return overlay_mdp_reply_error
	    (mdp_named_socket,recvaddr,recvaddrlen,4006,
	     "No such call");
	if (call->local.state==VOMP_STATE_RINGINGIN) {
	  call->local.state=VOMP_STATE_INCALL;
	  call->ringing=0;
	  /* state machine does job of starting audio stream, just tell everyone about
	     the changed state. */
	  overlay_mdp_reply_error(mdp_named_socket,
				  recvaddr,recvaddrlen,0,"Success");
	  return vomp_send_status(call,VOMP_TELLREMOTE|VOMP_TELLINTERESTED);
	} else {
	  overlay_mdp_reply_error(mdp_named_socket,
				  recvaddr,recvaddrlen,4009,
				  "Call is not RINGINGIN, so cannot be picked up");
	}
      }
      break;
    case VOMPEVENT_AUDIOSTREAMING: /* user supplying audio */
      WHY("Handling of in-call audio not yet implemented");
      break;
    default:
      /* didn't understand it, so respond with an error */
      return overlay_mdp_reply_error(mdp_named_socket,
				     recvaddr,recvaddrlen,4001,
				     "Invalid VOMPEVENT request (use DIAL,HANGUP,CALLREJECT,AUDIOSTREAMING,REGISTERINTERST,WITHDRAWINTERST only)"); 

    }

  return WHY("Not implemented");
}

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
	(mdp->in.payload[8]<<16)+(mdp->in.payload[9]<<8)+mdp->in.payload[10];
      unsigned int sender_session=
	(mdp->in.payload[11]<<16)+(mdp->in.payload[12]<<8)+mdp->in.payload[13];
      int sender_seq=(mdp->in.payload[4]<<8)+mdp->in.payload[5];
      
      if (!recvr_session) {
	/* wants to create a call session.
	   Main aim here: replay protection. An adversary should not be able to
	   replay previous VoMP packets to cause any action.  We do this by
	   allocating a new session number for each call.  As an adversary may be
	   trying to use such replays to cause a denial of service attack we need
	   to be able to track multiple potential session numbers even from the
	   same SID. */
	WHY("recvr_session==0, creating call.");

	call=vomp_find_or_create_call(mdp->in.src.sid,mdp->in.dst.sid,
				      sender_session,recvr_session,
				      sender_state,recvr_state);
	if (!call) {
	  /* could not allocate a call slot, so do nothing */
	  return WHY("No free call slots");
	}
	WHYF("Far end is in state %s",vomp_describe_state(sender_state));
	WHYF("I am in state %s",vomp_describe_state(call->local.state));

	/* We have a session number.  Send a status update back to sender */
	call->last_activity=overlay_gettime_ms();
	call->remote.sequence=sender_seq;
	call->remote.state=sender_state;
	return vomp_send_status(call,VOMP_TELLREMOTE|VOMP_TELLCODECS);
      } else {
	WHY("recvr_session!=0, looking for existing call");
	/* A VoMP packet for a call apparently already in progress */
	call=vomp_find_or_create_call(mdp->in.src.sid,mdp->in.dst.sid,
				      sender_session,recvr_session,
				      sender_state,recvr_state);
	if (!call) {
	  return WHY("VoMP frame does not correspond to an active call - stale traffic or replay attack?");
	}

	if (!vomp_interested_usock_count) {
	  /* No registered listener, so we cannot answer the call, so just reject
	     it. */
	  call->local.state=VOMP_STATE_CALLENDED;
	  return vomp_send_status(call,VOMP_TELLREMOTE);
	}

	/* Consider states: our actual state, sender state, what the sender thinks
	   our state is, and what we think the sender's state is.  But largely it
	   breaks down to what we think our state is, and what they think their 
	   state is.  That leaves us with just 6X6=36 cases. */
	int combined_state=call->local.state<<3;
	combined_state|=sender_state;
	call->remote.state=sender_state;
	WHYF("Far end is in state %s",vomp_describe_state(call->remote.state));
	WHYF("I am in state %s",vomp_describe_state(call->local.state));
	switch(combined_state) {
	case (VOMP_STATE_NOCALL<<3)|VOMP_STATE_NOCALL:
	  /* We both think that we are not yet in a call, and we have session numbers
	     at each end. Presumably waiting for further state synchronisation.
	     Do nothing (not even send anything back, as that results in the peer 
	     doing the same, as they are in the same state as us) */
	  return 0;
	  break;
	case (VOMP_STATE_NOCALL<<3)|VOMP_STATE_CALLPREP:
	  /* The remote party is in the call-prep state, while we think no call
	     is in progress.  Yet we have supplied them with a session number.
	     This is probably a state that should not occur, since when they 
	     received the session # they should have moved to RINGINGOUT. 
	     No action is required, but we probably shouldn't count it towards
	     valid call activity, so don't touch the recent activity timer.
	     Just return.

	     What we do need to do is decode the list of offered codecs, and tell
	     any registered listener.
	  */
	  {
	    int i;
	    for(i=0;mdp->in.payload[14+i]&&(i<256);i++)
	      call->remote_codec_list[mdp->in.payload[14+i]]=1;	    
	  }
	  return 0;
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
	  call->ringing=0;
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
	  return 0;
	case (VOMP_STATE_CALLENDED<<3)|VOMP_STATE_CALLENDED:
	  /* We both agree the call is done.  Destroy call.
	     But make sure that we have confidence that the end of the call
	     has propagated to both ends before destroying */
	  if (call->remote.state==VOMP_STATE_CALLENDED
	      &&call->local.state==VOMP_STATE_CALLENDED)
	    return vomp_call_destroy(call);
	}
	
	/* touch call timer if the current state has not vetoed by returning */
	call->last_activity=overlay_gettime_ms();
	/* and then send an update to the call status */
	vomp_send_status(call,VOMP_TELLREMOTE|VOMP_TELLINTERESTED);
      }
    }
    return 0;
    break;
  case 0x02: /* codec selection, lists set of acceptable codec formats,
		and may thus cause change of codec, including during the call */
    return WHY("Codec selection not implemented");
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
	     overlay_render_sid(vomp_call_states[i].local.sid),
	     vomp_call_states[i].local.session,
	     overlay_render_sid(vomp_call_states[i].remote.sid),
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
  case VOMP_CODEC_DTMF: return "DTMF";
  case VOMP_CODEC_ENGAGED: return "Engaged-tone";
  case VOMP_CODEC_ONHOLD: return "On-Hold";
  case VOMP_CODEC_CALLERID: return "CallerID";
  }
  return "unknown";
}

int app_vomp_status(int argc, char **argv, struct command_line_option *o)
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
		      overlay_render_sid_prefix(mdp2.vompevent.local_sid,6),
		      overlay_render_sid_prefix(mdp2.vompevent.remote_sid,6),
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

int app_vomp_dial(int argc, char **argv, struct command_line_option *o)
{
  char *sid,*did,*callerid;
  cli_arg(argc, argv, o, "sid", &sid, NULL, "");
  cli_arg(argc, argv, o, "did", &did, NULL, "");
  cli_arg(argc, argv, o, "callerid", &callerid, NULL, NULL);

  overlay_mdp_frame mdp;
  bzero(&mdp,sizeof(mdp));

  mdp.packetTypeAndFlags=MDP_VOMPEVENT;
  mdp.vompevent.flags=VOMPEVENT_DIAL;
  if (overlay_mdp_getmyaddr(0,&mdp.vompevent.local_sid[0])) return -1;
  stowSid(&mdp.vompevent.remote_sid[0],0,sid);
  printf("local_sid=%s\n",overlay_render_sid(mdp.vompevent.local_sid));
  printf("remote_sid=%s from %s\n",
	 overlay_render_sid(mdp.vompevent.remote_sid),sid);

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


int app_vomp_pickup(int argc, char **argv, struct command_line_option *o)
{
  char *call_token;
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

int app_vomp_hangup(int argc, char **argv, struct command_line_option *o)
{
  char *call_token;
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

int app_vomp_monitor(int argc, char **argv, struct command_line_option *o)
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
	    fprintf(stderr,"\n");
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

int overlay_mdp_getmyaddr(int index,unsigned char *sid)
{
  overlay_mdp_frame a;

  a.packetTypeAndFlags=MDP_GETADDRS;
  a.addrlist.first_sid=index;
  a.addrlist.last_sid=0x7fffffff;
  a.addrlist.frame_sid_count=MDP_MAX_SID_REQUEST;
  int result=overlay_mdp_send(&a,MDP_AWAITREPLY,5000);
  if (result) {
    if (a.packetTypeAndFlags==MDP_ERROR)
      {
	fprintf(stderr,"Could not get list of local MDP addresses\n");
	fprintf(stderr,"  MDP Server error #%d: '%s'\n",
		a.error.error,a.error.message);
      }
    else
      fprintf(stderr,"Could not get list of local MDP addresses\n");
    return -1;
  }
  if ((a.packetTypeAndFlags&MDP_TYPE_MASK)!=MDP_ADDRLIST)
    return WHY("MDP Server returned something other than an address list");
  bcopy(&a.addrlist.sids[0][0],sid,SID_SIZE);
  return 0;
}

int vomp_tick()
{
  /* Send any reminder packets for call state, and also process any audio. */
  unsigned long long now=overlay_gettime_ms();
  int i;

  for(i=0;i<vomp_call_count;i++)
    {
      if (now>vomp_call_states[i].next_status_time)
	{
	  vomp_send_status(&vomp_call_states[i],VOMP_FORCETELLREMOTE);
	  vomp_call_states[i].next_status_time=now+VOMP_CALL_STATUS_INTERVAL;
	}
      /* See if any calls need to begin expiring */
      if (vomp_call_states[i].last_activity+VOMP_CALL_TIMEOUT<now)
	switch(vomp_call_states[i].local.state)	  
	  {
	  case VOMP_STATE_INCALL:
	    /* Timeout while call in progress, so end call.
	       Keep call structure hanging around for a bit so that we can
	       synchonrise with the far end if possible. */
	    vomp_call_states[i].local.state=VOMP_STATE_CALLENDED;
	    vomp_send_status(&vomp_call_states[i],
			     VOMP_TELLREMOTE|VOMP_TELLINTERESTED);
	    vomp_call_states[i].last_activity=now;
	    vomp_call_stop_audio(&vomp_call_states[i]);
	    break;
	  default:	    
	  /* Call timed out while not actually in progress, so just immmediately
	     tear the call down */
	    vomp_call_destroy(&vomp_call_states[i]);
	    /* since this slot will get reclaimed, we need to wind back one in
	       the iteration of the list of slots */
	    i--;
	    break;
	  }
    }    
  return 0;
}

int vomp_tick_interval()
{
  /* Work out the number of milliseconds until the next vomp tick is required. */
  return 1000;
}
