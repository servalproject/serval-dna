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

#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>

#include "serval.h"

static char cmd[1024];
static int cmdLen=0;
static int cmdOfs=0;
static int dataBytesExpected=0;
static unsigned char data[65536];
static int dataBytes=0;

#define STATE_CMD 1
#define STATE_DATA 2
static int state=STATE_CMD;

static int fd;

static int processChar(int c);

static int autoAnswerP=1;
static int pipeAudio=1;
static int reflectAudio=0;
static int syntheticAudio=0;
static int showReceived=1;
static int interactiveP=1;
static int recordCodec=VOMP_CODEC_PCM;
static int recordCodecTimespan=20;
static int callSessionToken=0;
static int fast_audio=0;

int app_monitor_cli(int argc, const char *const *argv, struct command_line_option *o)
{
  const char *sid=NULL;
  cli_arg(argc, argv, o, "sid", &sid, NULL, "");
  struct sockaddr_un addr;

  if (!strcasecmp(sid,"reflect")) {
    pipeAudio=1; reflectAudio=1;
    sid="";
  }

  if ( (fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
    perror("socket");
    exit(-1);
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  addr.sun_path[0]=0;
  snprintf(&addr.sun_path[1],100,"%s",
	   confValueGet("monitor.socket",DEFAULT_MONITOR_SOCKET_NAME));
  int len = 1+strlen(&addr.sun_path[1]) + sizeof(addr.sun_family);
  char *p=(char *)&addr;
  printf("last char='%c' %02x\n",p[len-1],p[len-1]);

  if (connect(fd, (struct sockaddr*)&addr, len) == -1) {
    perror("connect");
    exit(-1);
  }

  if (pipeAudio) {
    if (reflectAudio)
      audev=audio_reflector_detect();
    else 
      detectAudioDevice();
    char *name=audev?audev->name:NULL;
    if (!name) {
      WHY("Could not detect any audio device. Will not pipe audio.");
      pipeAudio=0;
    }
  }

  struct pollfd fds[128];
  int fdcount=0;

  fds[fdcount].fd=fd;
  fds[fdcount].events=POLLIN;
  fdcount++;
  if (interactiveP) {
    fds[fdcount].fd=STDIN_FILENO;
    fds[fdcount].events=POLLIN;
    fdcount++;
  }  

  WRITE_STR(fd, "monitor vomp\n");
  WRITE_STR(fd, "monitor rhizome\n");

  if (sid!=NULL&&sid[0]) {
    char msg[1024];
    snprintf(msg,1024,"call %s 5551 5552\n",argv[1]);
    WRITE_STR(fd, msg);
  }

  char line[1024];
  /* Allow for up to one second of audio read from the microphone
     to be buffered. This is probably more than we will ever need.
     The primary purpose of the buffer is in fact to handle the fact
     that we are unlikely to ever read exaclty the number of samples
     we need, so we need to keep any left over ones from the previous
     read. */
  int audioRecordBufferBytes=0;
  int audioRecordBufferSize=8000*2;
  unsigned char audioRecordBuffer[8000*2];

  int base_fd_count=fdcount;
  while(1) {
    fdcount=base_fd_count;
    if (audev&&audev->poll_fds) fdcount+=audev->poll_fds(&fds[fdcount],128-fdcount);
    poll(fds,fdcount,1000);

    SET_NONBLOCKING(fd);
    if (interactiveP) 
      SET_NONBLOCKING(STDIN_FILENO);
    
    int bytes;
    int i;
    line[0]=0;
    bytes=read(fd,line,1024);
    if (bytes>0)
      for(i=0;i<bytes;i++) processChar(line[i]);
    if (interactiveP) {
      bytes=read(STDIN_FILENO,line,1024);
      if (bytes>0) {
	line[bytes]=0;
	printf("< %s",line);
	write(fd,line,bytes);
      }
    }

    if (audev&&audev->read)
      {
	WHY("about to read");
	int bytesRead=audev->read(&audioRecordBuffer[audioRecordBufferBytes],
				  audioRecordBufferSize-audioRecordBufferBytes);
	WHY("read");
	if (bytesRead>0) audioRecordBufferBytes+=bytesRead;
	
	/* 8KHz 16 bit samples = 16000 bytes per second.
	   Thus one 1ms of audio = 16 bytes. */
	int audioRecordBufferOffset=0;
	while ((audioRecordBufferBytes-audioRecordBufferOffset)
	       >recordCodecTimespan*16) {
	  /* encode and deliver audio block to servald via monitor interface */
	  encodeAndDispatchRecordedAudio(fd,callSessionToken,recordCodec,
					 &audioRecordBuffer[audioRecordBufferOffset],
					 recordCodecTimespan*16);
	  WHY("sample block sent");
	  /* skip over the samples we have already processed */
	  audioRecordBufferOffset+=recordCodecTimespan*16;
	}
	/* copy the remaining buffered bytes down and correct buffer length */
	if (audioRecordBufferOffset<0) audioRecordBufferOffset=0;
	if (audioRecordBufferOffset>audioRecordBufferBytes)
	  audioRecordBufferOffset=audioRecordBufferBytes;
	bcopy(&audioRecordBuffer[audioRecordBufferOffset],
	      &audioRecordBuffer[0],
	      audioRecordBufferBytes-audioRecordBufferOffset);
	audioRecordBufferBytes-=audioRecordBufferOffset;
      }
    
    SET_BLOCKING(fd);
    SET_BLOCKING(STDIN_FILENO);
  }
  
  return 0;
}

int counter=0;
int callState=0;
int processLine(char *cmd,unsigned char *data,int dataLen)
{
  int l_id,r_id,l_state,r_state,codec;
  long long start_time,end_time;
  if (showReceived) {
    printf("> %s\n",cmd);
    if (data) {
      int i,j;
      for(i=0;i<dataLen;i+=16) {
	printf("   %04x :",i);
	for(j=0;j<16;j++) 
	  if (i+j<dataLen) printf(" %02x",data[i+j]); else printf("   ");
	printf("  ");
	for(j=0;j<16;j++) 
	  if (i+j<dataLen) {
	    if (data[i+j]>=0x20&&data[i+j]<0x7e)
	      printf("%c",data[i+j]); else printf(".");
	  }
	printf("\n");
      }
    }
  }
  if (sscanf(cmd,"AUDIOPACKET:%x:%x:%d:%d:%d:%lld:%lld",
	     &l_id,&r_id,&l_state,&r_state,
	     &codec,&start_time,&end_time)==7)
    {
      if (pipeAudio&&audev&&fast_audio) {
	bufferAudioForPlayback(codec,start_time,end_time,data,dataLen);	
      }
    }
  char msg[1024];
  if (sscanf(cmd,"CALLSTATUS:%x:%x:%d:%d:%d",
	     &l_id,&r_id,&l_state,&r_state,&fast_audio)==5)
    {
      if (l_state<5&&l_id&&pipeAudio) {
	// Take control of audio for this call, and let the java side know
	snprintf(msg,1024,"FASTAUDIO:%x:1\n",l_id);
	WRITE_STR(fd, msg);
      }
      if (l_state==4&&autoAnswerP) {
	// We are ringing, so pickup
	sprintf(msg,"pickup %x\n",l_id);
	WRITE_STR(fd, msg);
      }
      if (l_state==5) {
	if (fast_audio) {	  
	  startAudio();
	}
	callSessionToken=l_id;
      } else {
	stopAudio();
	callSessionToken=0;
      }
      callState=l_state;
    }
  if (sscanf(cmd,"KEEPALIVE:%x",&l_id)==1) {
    if (callState==5&&syntheticAudio) {
	/* Send synthetic audio packet */
	char buffer[1024];
	sprintf(buffer,"*320:AUDIO:%x:8\n"
		"%08d pasdfghjklzxcvbnm123456"
		"qwertyuiopasdfghjklzxcvbnm123456"
		"qwertyuiopasdfghjklzxcvbnm123456"
		"qwertyuiopasdfghjklzxcvbnm123456"
		"qwertyuiopasdfghjklzxcvbnm123456"
		"qwertyuiopasdfghjklzxcvbnm123456"
		"qwertyuiopasdfghjklzxcvbnm123456"
		"qwertyuiopasdfghjklzxcvbnm123456"
		"qwertyuiopasdfghjklzxcvbnm123456"
		"qwertyuiopasdfghjklzxcvbnm123456",l_id,counter++);
	WRITE_STR(fd, buffer);
	printf("< *320:AUDIO:%x:8\\n<320 bytes>\n",l_id);
      }
  }
  cmd[0]=0;
  cmdLen=0;
  dataBytes=0;
  dataBytesExpected=0;
  state=STATE_CMD;
  return 0;
}

int processChar(int c)
{
  switch(state) {
  case STATE_CMD:
    if (c!='\n') {
      if (cmdLen<1000) {
	cmd[cmdLen++]=c;
      }
    } else {
      if (!cmdLen) return 0;
      cmd[cmdLen]=0;
      if (sscanf(cmd,"*%d:%n",&dataBytesExpected,&cmdOfs)==1) {
	if (dataBytesExpected<0) dataBytesExpected=0;
	if (dataBytesExpected>65535) dataBytesExpected=65535;
	state=STATE_DATA;
      } else {
	processLine(cmd,NULL,0);
	cmdLen=0;
      }
    }
    break;
  case STATE_DATA:
    if (dataBytes<dataBytesExpected)
      data[dataBytes++]=c;
    if (dataBytes>=dataBytesExpected) {
      processLine(&cmd[cmdOfs],data,dataBytes);
      cmdLen=0;
    }
  }      
  return 0;
}
