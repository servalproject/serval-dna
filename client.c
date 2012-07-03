/* 
Serval Distributed Numbering Architecture (DNA)
Copyright (C) 2010 Paul Gardner-Stephen 

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

int sock = -1;
char *outputtemplate = NULL;
int returnMultiVars = 0;
int dnatimeout = 3000; /* default 3000 ms request timeout */

/* Now that we are using the keyring, we only support a small subset of variables.
   (VAR_NAME is not properly supported yet) 
*/
struct mphlr_variable vars[]={
    {VAR_NAME, "name", "Published name of this subscriber"},
    {VAR_DIDS,"dids","Numbers claimed by this subscriber"},
    {VAR_LOCATIONS,"locations","Network address of telephone end point"},
    {0x00,NULL,NULL}
};


int packetSendFollowup(struct in_addr destination,
		       unsigned char *packet,int packet_len)
{
  struct sockaddr_in peer_addr;
  int r;
  
  bzero(&peer_addr, sizeof(peer_addr));
  peer_addr.sin_family=AF_INET;
  peer_addr.sin_port = htons( PORT_DNA );
  peer_addr.sin_addr.s_addr=destination.s_addr;

  if (!serverMode) {
    sock=socket(PF_INET,SOCK_DGRAM,0);
    if (sock == -1) {
      WHY_perror("socket");
      FATAL("Could not create UDP socket");
    }
    r=1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &r, sizeof(r));
  }
  
  r=sendto(sock,packet,packet_len,0,(struct sockaddr *)&peer_addr,sizeof(peer_addr));
  if (r<packet_len)	{
    if (debug&DEBUG_PACKETTX) DEBUGF("Could not send to %s (r=%d, packet_len=%d)",inet_ntoa(destination),r,packet_len);
    perror("sendto(a)");
  } else {
    if (debug&DEBUG_PACKETTX) DEBUGF("Sent request to client %s",inet_ntoa(destination));
  }
  return 0;
}

int packetSendRequest(int method,unsigned char *packet,int packet_len,int batchP,
		      unsigned char *transaction_id,struct sockaddr *recvaddr,
		      struct response_set *responses)
{
  int i;
  int cumulative_timeout=0; /* ms */
  int this_timeout=125; /* ms */
  int peer_low,peer_high;
  int timeout_remaining;

  struct timeval time_in,now;
 
  /* Prepare ephemeral UDP socket (hence no binding)
     If in server mode, then we already have a socket available to us and appropriately bound */
  if (!serverMode) {
    sock=socket(PF_INET,SOCK_DGRAM,0);
    if (sock == -1) {
      WHY_perror("socket");
      FATAL("Could not create UDP socket");
    }
    i=1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &i, sizeof(i));
  }
  
  /* Deal with special case */
  if (method==REQ_REPLY)
    {
      int r;
      if (overlayMode) 
	r=overlay_sendto((struct sockaddr_in *)recvaddr,packet,packet_len);
      else
	r=sendto(sock,packet,packet_len,0,recvaddr,sizeof(struct sockaddr_in));
      if (r<packet_len)	{
	if (debug&DEBUG_PACKETTX) DEBUGF("Could not send to client %s (packet=%p,len=%d,sock=%d)",
			   inet_ntoa(client_addr),packet,packet_len,sock);
	perror("sendto(b)");
      } else {
	if (debug&DEBUG_PACKETTX) DEBUGF("Sent request to client %s",inet_ntoa(client_addr));
      }
      return 0;
    }

  if (!peer_count) getPeerList();

  gettimeofday(&time_in,NULL);

  /* REQ_SERIAL & REQ_PARALLEL work in fundamentally different ways, 
     but it turns out the retry/timeout code is the dominant part.
     So we do a bit of fiddling around to make one loop that can handle both */
  if (method==REQ_SERIAL) {
    peer_low=0; peer_high=peer_count-1;
    /* If there are too many peers to allow sending to each three times, then we should 
       adjust our incremental timeout accordingly, so far as is practicable */
    if (this_timeout*peer_count*3>dnatimeout)
      {
	this_timeout=dnatimeout/(3*peer_count);
	if (this_timeout<10) this_timeout=10; /* 10ms minimum sending interval */
      }
  } else 
    { peer_low=-1; peer_high=-1;}

  while(cumulative_timeout<=dnatimeout)
    {
      /* If not in serial mode, then send request to everyone immediately.
         Make sure we only ask once in parallel mode, since it will always ask everyone */
      if (method==REQ_PARALLEL) sendToPeers(packet,packet_len,method,0,responses);
      else if (method!=REQ_SERIAL)
	for(i=0;i<peer_count;i++) sendToPeers(packet,packet_len,method,i,responses);

      /* If in serial mode, send request to peers in turn until one responds positively, 
	 otherwise just deal with the reply fetching loop to listen to as many or few reply. */
      for(i=peer_low;i<=peer_high;i++) {
	struct response *rr;
	if (i>-1) sendToPeers(packet,packet_len,REQ_SERIAL,i,responses);
	
	/* Placing the timeout calculation here means that the total timeout is shared among
	   all peers in a serial request, but round-robining after each time-step.
	   We adjust this_timeout if there are many peers to allow 3 sends to each peer where possible.
	*/
	cumulative_timeout+=this_timeout;
	timeout_remaining=this_timeout;

	while(1)
	  {
	    /* Wait for response */
	    int r=getReplyPackets(method,i,batchP,responses,transaction_id,recvaddr,timeout_remaining);
	    if (r && (debug & DEBUG_DNARESPONSES)) DEBUG("returned on timeout");
	    
	    switch(method)
	      {
	      case REQ_PARALLEL:
		/* XXX We could stop once all peers have replied.
		   (need to update the test script if we do that, so that it tests with multiple
		    peers and so tests that we wait if not all peers have responded) */
		break;
	      case REQ_FIRSTREPLY:
		if (debug&DEBUG_DNARESPONSES) DEBUGF("Returning with first reply (REQ_FIRSTREPLY)");
		if (!r) return 0;
		break;
	      case REQ_SERIAL:
		if (!r) {
		  /* Stop if we have an affirmative response.
		     XXX - doesn't allow for out of order replies. */
		  if (debug&DEBUG_DNARESPONSES) dumpResponses(responses);
		  rr=responses->last_response;
		  while (rr)
		    {
		      if (rr->checked) break;
		      if (debug&DEBUG_DNARESPONSES) 
			DEBUGF("Got a response code 0x%02x, checking if that is what we need",rr->code);
		      switch (rr->code)
			{
			case ACTION_OKAY: case ACTION_DATA:
			  /* bingo */
			  if (!batchP) return 0;
			  break;
			}
		      rr->checked=1;
		      rr=rr->prev;
		    }
		  
		  /* not what we are after, so clear response and try with next peer */
		  clearResponses(responses);
		}
		break;
	      }
	    
	    /* Wait for the previous timeout to really expire,
	       (this is for the case where all peers have replied) */
	    {
	      int elapsed_usecs=0;
	      int cumulative_usecs=cumulative_timeout*1000;
	      int remaining_usecs;
	      
	      gettimeofday(&now,NULL);
	      elapsed_usecs=(now.tv_sec-time_in.tv_sec)*1000000;
	      elapsed_usecs+=(now.tv_usec-time_in.tv_usec);
	      
	      remaining_usecs=cumulative_usecs-elapsed_usecs;
	      
	      if (remaining_usecs<=0) break;
	      else timeout_remaining=remaining_usecs/1000;		    
	    }
	    
	  }
      }
      cumulative_timeout+=this_timeout;
    }
  if ((debug&DEBUG_DNARESPONSES) && cumulative_timeout>=dnatimeout) 
    DEBUGF("Request timed out after retries (timeout=%d, elapsed=%d)",
	    dnatimeout,cumulative_timeout);

  return 0;
}

/* Some data types can end in @ if they require the address of the sender to be appended for correct local interpretation */
int fixResponses(struct response_set *responses)
{
  struct response *rr;

  if (debug&DEBUG_DNARESPONSES) DEBUG("Fixing response set");

  if (!responses) return -1;

  rr=responses->responses;
  while(rr)
    {
      if (debug&DEBUG_DNARESPONSES)
	DEBUGF("  len=%d, rr->code=%02x, rr->var_id=%02x",
		rr->value_bytes,rr->code,rr->var_id);
      if (rr->value_bytes>0&&rr->code==ACTION_DATA&&rr->var_id==VAR_LOCATIONS)
	{
	  if (debug&DEBUG_DNARESPONSES) 
	    DEBUGF("  response='%s'",rr->response);
	  if (rr->response[rr->value_bytes-1]=='@')
	    {
	      /* Append response with IP address of sender */
	      char *addr=inet_ntoa(rr->sender);
	      int alen=strlen(addr);
	      char *new = malloc(rr->value_bytes+alen+1);
	      if (debug&DEBUG_DNARESPONSES) 
		DEBUGF("Fixing LOCATIONS response '%s' received from '%s (0x%08x)'",
				   rr->response,addr,(unsigned int)rr->sender.s_addr);
	      if (!new) return -1;
	      bcopy(rr->response,new,rr->value_bytes);
	      bcopy(addr,&new[rr->value_bytes],alen+1);
	      free(rr->response); rr->response=NULL;
	      rr->response=(unsigned char *)new;
	      rr->value_len+=alen;
	      rr->value_bytes+=alen;
	      new[rr->value_len]=0; /* Make sure it is null terminated */
	      if (debug&DEBUG_DNARESPONSES) DEBUGF("Response string now '%s'",rr->response);
	    }
	}
      rr=rr->next;
    }
  return 0;
}

int getReplyPackets(int method,int peer,int batchP,struct response_set *responses,
		    unsigned char *transaction_id,struct sockaddr *recvaddr,int timeout)
{
  /* set timeout alarm */
  
  /* get packets until timeout, or until we get a packet from the specified peer
     if method==REQ_SERIAL.  If REQ_SERIAL we also reject packets from other 
     senders as they must be spoofs.
  */
  struct timeval t;
  int timeout_secs;
  int timeout_usecs;
  int to=timeout;
  int len;
  
  if (debug&DEBUG_DNARESPONSES) DEBUGF("getReplyPackets(policy=%d)",method);
  
  /* Work out when the timeout will expire */
  gettimeofday(&t,NULL); 
  timeout_secs=t.tv_sec; timeout_usecs=t.tv_usec;
  if (to>1000) { timeout_secs+=(to/1000); to=to%1000; }
  timeout_usecs+=to*1000; if (timeout_usecs>1000000) { timeout_secs++; timeout_usecs-=1000000; }
  
  while(1) {
    unsigned char buffer[16384];
    struct sockaddr sender;
    socklen_t recvaddrlen=sizeof(struct sockaddr);
    struct pollfd fds;
    
    if (recvaddr) bzero((void *)recvaddr,sizeof(struct sockaddr));
    fds.fd=sock; fds.events=POLLIN; fds.revents=0;
    
    while (poll(&fds,1,10 /* wait for 10ms at a time */)==0)
      {
	gettimeofday(&t,NULL);
	if (t.tv_sec>timeout_secs) return 1;
	if (t.tv_sec==timeout_secs&&t.tv_usec>=timeout_usecs) return 1;
      }

    /* Use this temporary socket address structure if one was not supplied */
    struct sockaddr reply_recvaddr;
    int ttl=-1;
    if (!recvaddr) recvaddr=&reply_recvaddr;

    len=recvwithttl(sock,buffer,sizeof(buffer),&ttl,recvaddr,&recvaddrlen);
    if (len<=0) return WHY("Unable to receive packet.");

    if (recvaddr) {
      client_port=((struct sockaddr_in *)recvaddr)->sin_port;
      client_addr=((struct sockaddr_in *)recvaddr)->sin_addr;
      
      if (debug&DEBUG_DNARESPONSES) DEBUGF("Received reply from %s (len=%d)",inet_ntoa(client_addr),len);
      if (debug&DEBUG_DNARESPONSES) dump("recvaddr",(unsigned char *)&sender,recvaddrlen);
      if (debug&DEBUG_DNARESPONSES) dump("packet",(unsigned char *)buffer,len);
    }

    if (dropPacketP(len)) {
      if (debug&DEBUG_SIMULATION) DEBUGF("Simulation mode: Dropped packet due to simulated link parameters");
      continue;
    }
    if (!packetOk(NULL,buffer,len,transaction_id,ttl,recvaddr,recvaddrlen,0)) {
      /* Packet passes tests - extract responses and append them to the end of the response list */
      if (extractResponses(client_addr,buffer,len,responses)) 
	return WHY("Problem extracting response fields from reply packets");
      if (method==REQ_SERIAL||method==REQ_FIRSTREPLY) {
	if (!batchP) return 0;
	/* In batch mode we need ACTION_DONE to mark end of transmission. 
	   While it gets sent last, out-of-order delivery means we can't rely on
	   such a nice arrangement. */
	{
	  /* XXX inefficient for long lists.
	     XXX can be made better by working backwards from end using double-linked list and 
	     remembering the previous length of the list */
	  struct response *r=responses->responses;
	  while(r)
	    {
	      if (r->code==ACTION_DONE) return 0;
	      r=r->next;
	    }
	}
      }
      else {
	if (debug&DEBUG_DNARESPONSES) DEBUGF("Waiting for more packets, since called with policy %d",method);
      }
    } else {
      if (debug&(DEBUG_PACKETRX|DEBUG_DNARESPONSES)) DEBUG("Ignoring invalid packet");
    }      
  }
}
