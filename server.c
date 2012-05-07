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

#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "serval.h"

unsigned char *hlr=NULL;
int hlr_size=0;

FILE *i_f=NULL;

struct in_addr client_addr;
int client_port;

int getKeyring(char *s);
int createServerSocket();
int simpleServerMode();

int recvwithttl(int sock,unsigned char *buffer,int bufferlen,int *ttl,
		struct sockaddr *recvaddr,unsigned int *recvaddrlen)
{
  struct msghdr msg;
  struct iovec iov[1];
  
  iov[0].iov_base=buffer;
  iov[0].iov_len=bufferlen;
  bzero(&msg,sizeof(msg));
  msg.msg_name = recvaddr;
  msg.msg_namelen = *recvaddrlen;
  msg.msg_iov = &iov[0];
  msg.msg_iovlen = 1;
  // setting the following makes the data end up in the wrong place
  //  msg.msg_iov->iov_base=iov_buffer;
  // msg.msg_iov->iov_len=sizeof(iov_buffer);

  struct cmsghdr cmsgcmsg[16];
  msg.msg_control = &cmsgcmsg[0];
  msg.msg_controllen = sizeof(struct cmsghdr)*16;
  msg.msg_flags = 0;

  fcntl(sock,F_SETFL, O_NONBLOCK);

  int len = recvmsg(sock,&msg,0);

  if (0&&debug&DEBUG_PACKETRX) {
    fprintf(stderr,"recvmsg returned %d bytes (flags=%d,msg_controllen=%d)\n",
	    len,msg.msg_flags,msg.msg_controllen);
    dump("received data",buffer,len);
  }
  
  struct cmsghdr *cmsg;
  if (len>0)
    {
      for (cmsg = CMSG_FIRSTHDR(&msg); 
	   cmsg != NULL; 
	   cmsg = CMSG_NXTHDR(&msg,cmsg)) {
	
	if ((cmsg->cmsg_level == IPPROTO_IP) && 
	    ((cmsg->cmsg_type == IP_RECVTTL) ||(cmsg->cmsg_type == IP_TTL))
	    &&(cmsg->cmsg_len) ){
	  if (debug&DEBUG_PACKETRX)
	    fprintf(stderr,"  TTL (%p) data location resolves to %p\n",
		    ttl,CMSG_DATA(cmsg));
	  if (CMSG_DATA(cmsg)) {
	    *ttl = *(unsigned char *) CMSG_DATA(cmsg);
	    if (debug&DEBUG_PACKETRX)
	      fprintf(stderr,"  TTL of packet is %d\n",*ttl);
	  } 
	} else {
	  if (debug&DEBUG_PACKETRX)
	    fprintf(stderr,"I didn't expect to see level=%02x, type=%02x\n",
		    cmsg->cmsg_level,cmsg->cmsg_type);
	}	 
      }
  }
  *recvaddrlen=msg.msg_namelen;

  return len;
}


int server(char *backing_file,int foregroundMode)
{
  if (overlayMode)
    {
      /* Now find and initialise all the suitable network interfaces, i.e., 
	 those running IPv4.
	 Packet radio dongles will get discovered later as the interfaces get probed.

	 This will setup the sockets for the server to communicate on each interface.
	 
	 XXX - Problems may persist where the same address is used on multiple interfaces,
	 but otherwise hopefully it will allow us to bridge multiple networks.
      */
      overlay_interface_discover();
    }
  else
    {
      /* Create a simple socket for listening on if we are not in overlay mesh mode. */
      createServerSocket();     

      /* Get backing store for keyring (overlay sets it up itself) */
      getKeyring(backing_file);
    }
  
  /* Detach from the console */
  if (!foregroundMode) daemon(0,0);

  /* Record PID */
  char filename[1024];
  if (!FORM_SERVAL_INSTANCE_PATH(filename, "serval.pid"))
    return -1;
  FILE *f=fopen(filename,"w");
  if (!f) {
    WHYF("Could not write to PID file %s", filename);
    perror("fopen");
    return -1;
  }
  fprintf(f,"%d\n",getpid());
  fclose(f);

  if (!overlayMode) simpleServerMode();
  else overlayServerMode();

  return 0;
}

int getKeyring(char *backing_file)
{
 if (!backing_file)
    {     
      exit(WHY("Keyring requires a backing file"));
    }
  else
    {
      if (keyring) 
	exit(WHY("Keyring being opened twice"));
      keyring=keyring_open(backing_file);
      /* unlock all entries with blank pins */
      keyring_enter_pins(keyring,"");
    }
 keyring_seed(keyring);

 return 0;
}

int processRequest(unsigned char *packet,int len,
		   struct sockaddr *sender,int sender_len,
		   unsigned char *transaction_id,int recvttl, char *did,char *sid)
{
  /* Find HLR entry by DID or SID, unless creating */
  int ofs;
  int records_searched=0;
  
  int prev_pofs=0;
  int pofs=OFS_PAYLOAD;

  while(pofs<len)
    {
      if (debug&DEBUG_DNAREQUESTS) fprintf(stderr,"  processRequest: len=%d, pofs=%d, pofs_prev=%d\n",len,pofs,prev_pofs);
      /* Avoid infinite loops */
      if (pofs<=prev_pofs) break;
      prev_pofs=pofs;

      if (packet[pofs]==ACTION_CREATEHLR)
	{
	  /* Creating an HLR requires an initial DID number and definitely no SID -
	     you can't choose a SID. */
	  if (debug&DEBUG_HLR) fprintf(stderr,"Creating a new HLR record. did='%s', sid='%s'\n",did,sid);
	  if (!did[0]) return respondSimple(NULL,ACTION_DECLINED,NULL,0,transaction_id,recvttl,sender,CRYPT_CIPHERED|CRYPT_SIGNED);
	  if (sid[0])  
	    return respondSimple(NULL,ACTION_DECLINED,NULL,0,transaction_id,
				 recvttl,sender,CRYPT_CIPHERED|CRYPT_SIGNED);
	  if (debug&DEBUG_HLR) fprintf(stderr,"Verified that create request supplies DID but not SID\n");
	  
	  /* Creating an identity is nice and easy now with the new keyring */
	  keyring_identity *id=keyring_create_identity(keyring,keyring->contexts[0],
						       "");
	  if (id) keyring_set_did(id,did,"Mr. Smith");
	  if (id==NULL||keyring_commit(keyring))
	    return respondSimple(NULL,ACTION_DECLINED,NULL,0,transaction_id,recvttl,
				 sender,CRYPT_CIPHERED|CRYPT_SIGNED);
	  else
	    return respondSimple(id,ACTION_OKAY,NULL,0,transaction_id,recvttl,
				 sender,CRYPT_CIPHERED|CRYPT_SIGNED);	
	  	  
	  pofs+=1;
	  pofs+=1+SID_SIZE;
	}
      else
	{
	  if (debug&DEBUG_DNAREQUESTS) fprintf(stderr,"Looking at action code 0x%02x @ packet offset 0x%x\n",
			       packet[pofs],pofs);
	  switch(packet[pofs])
	    {
	    case ACTION_PAD: /* Skip padding */
	      pofs++;
	      pofs+=1+packet[pofs];
	      break;
	    case ACTION_EOT:  /* EOT */
	      pofs=len;
	      break;
	    case ACTION_STATS:
	      /* short16 variable id,
		 int32 value */
	      {
		pofs++;
		short field=packet[pofs+1]+(packet[pofs]<<8);
		int value=packet[pofs+5]+(packet[pofs+4]<<8)+(packet[pofs+3]<<16)+(packet[pofs+2]<<24);
		pofs+=6;
		if (instrumentation_file)
		  {
		    if (!i_f) { if (strcmp(instrumentation_file,"-")) i_f=fopen(instrumentation_file,"a"); else i_f=stdout; }
		    if (i_f) fprintf(i_f,"%ld:%08x:%d:%d\n",time(0),*(unsigned int *)&sender->sa_data[0],field,value);
		    if (i_f) fflush(i_f);
		  }
	      }
	      break;
	    case ACTION_SET:
	      setReason("You can only set keyring variables locally");
	      return respondSimple(NULL,ACTION_ERROR,
				   (unsigned char *)"Would be insecure",
				   0,transaction_id,recvttl,
				   sender,CRYPT_CIPHERED|CRYPT_SIGNED);
	      
	      break;
	    case ACTION_GET:
	      {
		/* Limit transfer size to MAX_DATA_BYTES, plus an allowance for variable packing. */
		unsigned char data[MAX_DATA_BYTES+16];
		int dlen=0;
		int sendDone=0;

		if (debug&DEBUG_HLR) dump("Request bytes",&packet[pofs],8);

		pofs++;
		int var_id=packet[pofs];
		int instance=-1;
		if (var_id&0x80) instance=packet[++pofs];
		if (instance==0xff) instance=-1;
		pofs++;
		int offset=(packet[pofs]<<8)+packet[pofs+1]; pofs+=2;
		keyring_identity *responding_id=NULL;

		pofs+=2;

		if (debug&DEBUG_DNAREQUESTS) fprintf(stderr,"Processing ACTION_GET (var_id=%02x, instance=%02x, pofs=0x%x, len=%d)\n",var_id,instance,pofs,len);

		ofs=0;
		if (debug&DEBUG_HLR) fprintf(stderr,"Looking for identities with sid='%s' / did='%s'\n",(sid&&sid[0])?sid:"null",did?did:"null");
		  
		/* Keyring only has DIDs in it for now.
		   Location is implied, so we allow that */
		switch(var_id) {
		case VAR_DIDS:
		case VAR_LOCATIONS:
		  break;
		default:
		  return respondSimple(NULL,ACTION_ERROR,
				       (unsigned char *)"Unsupported variable",
				       0,transaction_id,recvttl,
				       sender,CRYPT_CIPHERED|CRYPT_SIGNED);

		}

		{		  
		  int cn=0,in=0,kp=0;
		  int found=0;
		  int count=0;
		  while(cn<keyring->context_count) {
		    found=0;
		    if (sid&&sid[0]) {
		      unsigned char packedSid[SID_SIZE];
		      stowSid(packedSid,0,sid);
		      found=keyring_find_sid(keyring,&cn,&in,&kp,packedSid);
		    } else {
		      found=keyring_find_did(keyring,&cn,&in,&kp,did);
		    }

		    struct response r;
		    unsigned char packedDid[64];

		    if (found&&(instance==-1||instance==count)) {
		      /* We have a matching identity/DID, now see what variable
			 they want.
			 VAR_DIDS and VAR_LOCATIONS are the only ones we support
			 with the new keyring file format for now. */
		      r.var_id=var_id;
		      r.var_instance=instance;
		      switch(var_id) {
		      case VAR_DIDS:
			/* We need to pack the DID before sending off */
			r.value_len=0;
			stowDid(packedDid,&r.value_len,
				(char *)keyring->contexts[cn]->identities[in]
				->keypairs[kp]->private_key);
			r.response=packedDid;
			break;
		      case VAR_LOCATIONS:
			r.response=(unsigned char *)"4000@";
			r.value_len=strlen((char *)r.response);		      
			break;
		      }

		      /* For multiple packet responses, we want to tag only the
			 last one with DONE, so we queue up the most recently generated
			 packet, and only dispatch it when we are about to produce 
			 another.  Then at the end of the loop, if we have a packet
			 waiting we simply mark that with with DONE, and everything
			 falls into place. */
		      if (sendDone>0)
			/* Send previous packet */
			respondSimple(responding_id,ACTION_DATA,data,dlen,
				      transaction_id,recvttl,sender,
				      CRYPT_CIPHERED|CRYPT_SIGNED);		      
		      /* Prepare new packet */
		      dlen=0;		      
		      if (packageVariableSegment(data,&dlen,&r,offset,
						 MAX_DATA_BYTES+16))
			return setReason("packageVariableSegment() failed.");
		      responding_id = keyring->contexts[cn]->identities[in];

		      /* Remember that we need to send this new packet */
		      sendDone++;

		      count++;
		    }
		    
		    /* look for next record.
		       Here the placing of DONE at the end of the response stream 
		       becomes challenging, as we may be responding as multiple
		       identities.  This means we have to DONE after each identity. */
		    int lastin=in,lastcn=cn;		    
		    kp++;
		    keyring_sanitise_position(keyring,&cn,&in,&kp);
		    if (lastin!=in||lastcn!=cn) {
		      /* moved off last identity, so send waiting packet if there is
			 one. */
		      if (sendDone)
			{
			  data[dlen++]=ACTION_DONE;
			  data[dlen++]=sendDone&0xff;
			  respondSimple(responding_id,ACTION_DATA,data,dlen,
					transaction_id,
					recvttl,sender,CRYPT_CIPHERED|CRYPT_SIGNED);
			}
		      sendDone=0;
		      
		    }
		    
		  }
		}

		/* Now, see if we have a final queued packet which needs marking with
		   DONE and then sending. */
		if (sendDone)
		  {
		    data[dlen++]=ACTION_DONE;
		    data[dlen++]=sendDone&0xff;
		    respondSimple(responding_id,ACTION_DATA,data,dlen,transaction_id,
				  recvttl,sender,CRYPT_CIPHERED|CRYPT_SIGNED);
		  }
		
		if (gatewayspec&&(var_id==VAR_LOCATIONS)&&did&&strlen(did))
		  {
		    /* We are a gateway, so offer connection via the gateway as well */
		    unsigned char data[MAX_DATA_BYTES+16];
		    int dlen=0;
		    struct response fake;
		    unsigned char uri[1024];
		    
		    /* We use asterisk to provide the gateway service,
		       so we need to create a temporary extension in extensions.conf,
		       ask asterisk to re-read extensions.conf, and then make sure it has
		       a functional SIP gateway.
		    */
		    if (!asteriskObtainGateway(sid,did,(char *)uri))
		      {
			
			fake.value_len=strlen((char *)uri);
			fake.var_id=var_id;
			fake.response=uri;
			
			if (packageVariableSegment(data,&dlen,&fake,offset,MAX_DATA_BYTES+16))
			  return setReason("packageVariableSegment() of gateway URI failed.");
			
			WHY("Gateway claims to be 1st identity, when it should probably have its own identity");
			respondSimple(keyring->contexts[0]->identities[0],
				      ACTION_DATA,data,dlen,
				      transaction_id,recvttl,sender,
				      CRYPT_CIPHERED|CRYPT_SIGNED);
		      }
		    else
		      {
			  /* Should we indicate the gateway is not available? */
			}
		    }
	      
	      }
	      break;
	    default:
	      setReason("Asked to perform unsupported action");
	      if (debug&DEBUG_PACKETFORMATS) fprintf(stderr,"Asked to perform unsipported action at Packet offset = 0x%x\n",pofs);
	      if (debug&DEBUG_PACKETFORMATS) dump("Packet",packet,len);
	      return WHY("Asked to perform unsupported action.");
	    }	   
	}
    }
  
  if (debug&DEBUG_HLR) fprintf(stderr,"Searched %d HLR entries.\n",records_searched);

  return 0;
}

int respondSimple(keyring_identity *id,
		  int action,unsigned char *action_text,int action_len,
		  unsigned char *transaction_id,int recvttl,
		  struct sockaddr *recvaddr,int cryptoFlags)
{
  unsigned char packet[8000];
  int pl=0;
  int *packet_len=&pl;
  int packet_maxlen=8000;
  int i;

  /* XXX Complain about invalid crypto flags.
     XXX We don't do anything with the crypto flags right now
     XXX Other packet sending routines need this as well. */
  if (!cryptoFlags) return WHY("Crypto-flags not set.");

  /* ACTION_ERROR is associated with an error message.
     For syntactic simplicity, we do not require the respondSimple() call to provide
     the length of the error message. */
  if (action==ACTION_ERROR) {
    action_len=strlen((char *)action_text);
    /* Make sure the error text isn't too long.
       IF it is, trim it, as we still need to communicate the error */
    if (action_len>255) action_len=255;
  }

  /* Prepare the request packet */
  if (packetMakeHeader(packet,8000,packet_len,transaction_id,cryptoFlags)) 
    return WHY("packetMakeHeader() failed.");
  if (id)
    { if (packetSetSidFromId(packet,8000,packet_len,id)) 
	return setReason("invalid SID in reply"); }
  else 
    { if (packetSetDid(packet,8000,packet_len,"")) 
	return setReason("Could not set empty DID in reply"); }  

  CHECK_PACKET_LEN(1+1+action_len);
  packet[(*packet_len)++]=action;
  if (action==ACTION_ERROR) packet[(*packet_len)++]=action_len;
  for(i=0;i<action_len;i++) packet[(*packet_len)++]=action_text[i];

  if (debug&DEBUG_DNARESPONSES) dump("Simple response octets",action_text,action_len);

  if (packetFinalise(packet,8000,recvttl,packet_len,cryptoFlags))
    return WHY("packetFinalise() failed.");

  if (debug&DEBUG_DNARESPONSES) fprintf(stderr,"Sending response of %d bytes.\n",*packet_len);

  if (packetSendRequest(REQ_REPLY,packet,*packet_len,NONBATCH,transaction_id,recvaddr,NULL)) 
    return WHY("packetSendRequest() failed.");
  
  return 0;
}

int createServerSocket() 
{
  struct sockaddr_in bind_addr;
  
  sock=socket(PF_INET,SOCK_DGRAM,0);
  if (sock<0) {
    fprintf(stderr,"Could not create UDP socket.\n");
    perror("socket");
    exit(-3);
  }
  
  /* Automatically close socket on calls to exec().
     This makes life easier when we restart with an exec after receiving
     a bad signal. */
  fcntl(sock, F_SETFL,
	fcntl(sock, F_GETFL, NULL)|O_CLOEXEC);

  int TRUE=1;
  setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &TRUE, sizeof(TRUE));

  errno=0;
  if(setsockopt(sock, IPPROTO_IP, IP_RECVTTL, &TRUE,sizeof(TRUE))<0)
    perror("setsockopt(IP_RECVTTL)");  

  bind_addr.sin_family = AF_INET;
  bind_addr.sin_port = htons( PORT_DNA );
  bind_addr.sin_addr.s_addr = htonl( INADDR_ANY );
  if(bind(sock,(struct sockaddr *)&bind_addr,sizeof(bind_addr))) {
    fprintf(stderr,"MP HLR server could not bind to UDP port %d\n", PORT_DNA);
    perror("bind");
    exit(-3);
  }
  return 0;
}

extern int sigIoFlag;
extern int rhizome_server_socket;
int simpleServerMode()
{
  while(1) {
    struct sockaddr recvaddr;
    socklen_t recvaddrlen=sizeof(recvaddr);
    struct pollfd fds[128];
    int fdcount;
    int len;
    int r;

    if (servalShutdown) {
      serverCleanUp();
      exit(0);
    }

    bzero((void *)&recvaddr,sizeof(recvaddr));

    /* Get rhizome server started BEFORE populating fd list so that
       the server's listen socket is in the list for poll() */
    if (rhizome_datastore_path) rhizome_server_poll();

    /* Get list of file descripters to watch */
    fds[0].fd=sock; fds[0].events=POLLIN;
    fdcount=1;
    rhizome_server_get_fds(fds,&fdcount,128);
    if (debug&DEBUG_IO) {
      printf("poll()ing file descriptors:");
      { int i;
	for(i=0;i<fdcount;i++) { printf(" %d",fds[i].fd); } }
      printf("\n");
    }
    
    /* Wait patiently for packets to arrive. */
    if (rhizome_datastore_path) rhizome_server_poll();
    while ((r=poll(fds,fdcount,100000))<1) {
      if (sigIoFlag) { sigIoFlag=0; break; }
      sleep(0);
    }
    if (rhizome_datastore_path) rhizome_server_poll();

    unsigned char buffer[16384];
    int ttl=-1; // unknown

    if (fds[0].revents&POLLIN) {
      
      len=recvwithttl(sock,buffer,sizeof(buffer),&ttl,&recvaddr,&recvaddrlen);


      client_port=((struct sockaddr_in*)&recvaddr)->sin_port;
      client_addr=((struct sockaddr_in*)&recvaddr)->sin_addr;
      
      if (debug&DEBUG_DNAREQUESTS) fprintf(stderr,"Received packet from %s:%d (len=%d).\n",inet_ntoa(client_addr),client_port,len);
      if (debug&DEBUG_PACKETRX) dump("recvaddr",(unsigned char *)&recvaddr,recvaddrlen);
      if (debug&DEBUG_PACKETRX) dump("packet",(unsigned char *)buffer,len);
      if (dropPacketP(len)) {
	if (debug&DEBUG_SIMULATION) fprintf(stderr,"Simulation mode: Dropped packet due to simulated link parameters.\n");
	continue;
      }
      /* Simple server mode doesn't really use interface numbers, so lie and say interface -1 */
      if (packetOk(-1,buffer,len,NULL,ttl,&recvaddr,recvaddrlen,1)) { 
	if (debug&DEBUG_PACKETFORMATS) setReason("Ignoring invalid packet");
      }
      if (debug&DEBUG_PACKETRX) fprintf(stderr,"Finished processing packet, waiting for next one.\n");
    }
  }
  return 0;
}

#ifdef DEBUG_MEM_ABUSE
unsigned char groundzero[65536];
int memabuseInitP=0;

int memabuseInit()
{
  if (memabuseInitP) {
    fprintf(stderr,"WARNING: memabuseInit() called more than once.\n");
    return memabuseCheck();
  }

  unsigned char *zero=(unsigned char *)0;
  int i;
  for(i=0;i<65536;i++) {
    groundzero[i]=zero[i];
    printf("%04x\n",i);
  }
  memabuseInitP=1;
  return 0;
}

int _memabuseCheck(const char *func,const char *file,const int line)
{
  unsigned char *zero=(unsigned char *)0;
  int firstAddr=-1;
  int lastAddr=-1;
  int i;
  for(i=0;i<65536;i++) if (groundzero[i]!=zero[i]) {
      lastAddr=i;
      if (firstAddr==-1) firstAddr=i;
    }
  
  if (lastAddr>0) {
    fprintf(stderr,"WARNING: Memory corruption in first 64KB of RAM detected.\n");
    fprintf(stderr,"         Changed bytes exist in range 0x%04x - 0x%04x\n",firstAddr,lastAddr);
    dump("Changed memory content",&zero[firstAddr],lastAddr-firstAddr+1);
    dump("Initial memory content",&groundzero[firstAddr],lastAddr-firstAddr+1);
    sleep(1);
  } else {
    fprintf(stderr,"All's well at %s() %s:%d\n",func,file,line);
  }
  
  return 0;
}
#endif
