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

#include "mphlr.h"
#include "rhizome.h"

extern int sigPipeFlag;
extern int sigIoFlag;


typedef struct rhizome_file_fetch_record {
  int socket; /* if non-zero this is the socket to read from */
  rhizome_manifest *manifest;
  char fileid[SHA512_DIGEST_STRING_LENGTH];
  FILE *file;
  
  int close;

  char request[1024];
  int request_len;
  int request_ofs;
  
  int file_len;
  int file_ofs;

  int state;
  int last_action;
#define RHIZOME_FETCH_SENDINGHTTPREQUEST 1
#define RHIZOME_FETCH_RXHTTPHEADERS 2
#define RHIZOME_FETCH_RXFILE 3
} rhizome_file_fetch_record;

/* List of queued transfers */
#define MAX_QUEUED_FILES 4
int rhizome_file_fetch_queue_count=0;
rhizome_file_fetch_record file_fetch_queue[MAX_QUEUED_FILES];
/* 
   Queue a manifest for importing.

   There are three main cases that can occur here:

   1. The manifest has no associated file (filesize=0);
   2. The associated file is already in our database; or
   3. The associated file is not already in our database, and so we need
   to fetch it before we can import it.

   Cases (1) and (2) are more or less identical, and all we need to do is to
   import the manifest into the database.

   Case (3) requires that we fetch the associated file.

   This is where life gets interesting.
   
   First, we need to make sure that we can free up enough space in the database
   for the file.

   Second, we need to work out how we are going to get the file. 
   If we are on an IPv4 wifi network, then HTTP is probably the way to go.
   If we are not on an IPv4 wifi network, then HTTP is not an option, and we need
   to use a Rhizome/Overlay protocol to fetch it.  It might even be HTTP over MDP
   (Serval Mesh Datagram Protocol) or MTCP (Serval Mesh Transmission Control Protocol
   -- yet to be specified).

   For efficiency, the MDP transfer protocol should allow multiple listeners to
   receive the data. In contrast, it would be nice to have the data auth-crypted, if
   only to deal with packet errors (but also naughty people who might want to mess
   with the transfer.

   For HTTP over IPv4, the biggest problem is that we don't know the IPv4 address of
   the sender, or in fact that the link is over IPv4 and thus that HTTP over IPv4 is
   an option.  We probably need to be passed this information.
*/
   
int rhizome_queue_manifest_import(rhizome_manifest *m,
				  struct sockaddr_in *peerip)
{
  if (rhizome_file_fetch_queue_count>=MAX_QUEUED_FILES) {
    if (debug&DEBUG_RHIZOME) fprintf(stderr,"Already busy fetching files");
    return -1;
  }

  char *filehash=rhizome_manifest_get(m,"filehash",NULL,0);
  long long filesize=rhizome_manifest_get_ll(m,"filesize");

  if (debug&DEBUG_RHIZOME) fprintf(stderr,"Getting ready to fetch file %s\n",filehash);

  if (filesize>0&&(filehash!=NULL))
    {  
      if (strlen(filehash)!=SHA512_DIGEST_STRING_LENGTH-1)
	{
	  return WHY("File hash is wrong length");
	}

      int gotfile=
	sqlite_exec_int64("SELECT COUNT(*) FROM FILES WHERE ID='%s';",
			  rhizome_safe_encode((unsigned char *)filehash,
					      strlen(filehash)));
			    
      if (gotfile!=1) {
	/* We need to get the file */
	
	/* Discard request if the same manifest is already queued for reception.   
	 */
	int i,j;
	for(i=0;i<rhizome_file_fetch_queue_count;i++)
	  {
	    for(j=0;j<crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES;j++)
	      if (m->cryptoSignPublic[j]
		  !=file_fetch_queue[i].manifest->cryptoSignPublic[j]) break;
	    if (j==crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES)
	      {
		/* We are already fetching this manifest */
		if (debug&DEBUG_RHIZOME) fprintf(stderr,"Already fetching manifest\n");
		return -1;
	      }
	    for(j=0;j<SHA512_DIGEST_STRING_LENGTH;j++)
	      if (filehash[j]!=file_fetch_queue[i].fileid[j]) break;
	    if (j==SHA512_DIGEST_STRING_LENGTH)
	      {
		/* We are already fetching this file */
		if (debug&DEBUG_RHIZOME) fprintf(stderr,"Already fetching file %s\n",
						 filehash);
		return -1;
	      }
	  }

	if (peerip)
	  {
	    /* Transfer via HTTP over IPv4 */
	    int sock = socket(AF_INET,SOCK_STREAM,0);
	    fcntl(sock,F_SETFL, O_NONBLOCK);
	    struct sockaddr_in peeraddr;
	    bcopy(peerip,&peeraddr,sizeof(peeraddr));
	    peeraddr.sin_port=htons(RHIZOME_HTTP_PORT);
	    int r=connect(sock,(struct sockaddr*)&peeraddr,sizeof(peeraddr));
	    if ((errno!=EINPROGRESS)&&(r!=0)) {	      
	      close (sock);
	      if (debug&DEBUG_RHIZOME) {
		WHY("Failed to open socket to peer's rhizome web server");
		perror("connect");
	      }
	      return -1;
	    }
	    
	    rhizome_file_fetch_record 
	      *q=&file_fetch_queue[rhizome_file_fetch_queue_count];
	    q->manifest=m;
	    q->socket=sock;
	    strncpy(q->fileid,
		    filehash,SHA512_DIGEST_STRING_LENGTH);
	    snprintf(q->request,1024,"GET /rhizome/file/%s HTTP/1.0\r\n\r\n",
		     q->fileid);
	    q->request_len=strlen(q->request);
	    q->request_ofs=0;
	    q->state=RHIZOME_FETCH_SENDINGHTTPREQUEST;
	    q->file_len=-1;
	    q->file_ofs=0;
	    q->close=0;
	    q->last_action=time(0);
	    /* XXX Don't forget to implement resume */
#define RHIZOME_IDLE_TIMEOUT 10
	    /* XXX We should stream file straight into the database */
	    char filename[1024];
	    snprintf(filename,1024,"%s/import/file.%s",rhizome_datastore_path,
		     rhizome_manifest_get(q->manifest,"id",NULL,0));
	    q->manifest->dataFileName=strdup(filename);
	    q->file=fopen(filename,"w");
	    if (!q->file) {
	      if (debug&DEBUG_RHIZOME)
		fprintf(stderr,"Could not open '%s' to write received file.\n",
			filename);
	    }
	    rhizome_file_fetch_queue_count++;
	    if (debug&DEBUG_RHIZOME) fprintf(stderr,"Queued file for fetching\n");
	    return 0;
	  }
	else
	  {
	    /* Transfer via overlay */
	    return WHY("Rhizome fetching via overlay not implemented");
	  }
      }
    }
  
  return 0;
}

int rhizome_fetching_get_fds(struct pollfd *fds,int *fdcount,int fdmax)
{
  int i;
  if ((*fdcount)>=fdmax) return -1;

  for(i=0;i<rhizome_file_fetch_queue_count;i++)
    {
      if ((*fdcount)>=fdmax) return -1;
      if (debug&DEBUG_IO) {
	fprintf(stderr,"rhizome file fetch request #%d is poll() slot #%d (fd %d)\n",
		i,*fdcount,file_fetch_queue[i].socket); }
      fds[*fdcount].fd=file_fetch_queue[i].socket;
      switch(file_fetch_queue[i].state) {
      case RHIZOME_FETCH_SENDINGHTTPREQUEST:
	fds[*fdcount].events=POLLOUT; break;
      case RHIZOME_FETCH_RXHTTPHEADERS:
      case RHIZOME_FETCH_RXFILE:      
      default:
	fds[*fdcount].events=POLLIN; break;
      }
      (*fdcount)++;    
    }
   return 0;
}


int rhizome_fetch_poll()
{
  int rn;
  if (debug&DEBUG_RHIZOME) printf("Checking %d active fetch requests\n",
		    rhizome_file_fetch_queue_count);
  for(rn=0;rn<rhizome_file_fetch_queue_count;rn++)
    {
      rhizome_file_fetch_record *q=&file_fetch_queue[rn];
      int action=0;
      int bytes;
	  
      /* Make socket non-blocking */
      fcntl(q->socket,F_SETFL,fcntl(q->socket, F_GETFL, NULL)|O_NONBLOCK);

      switch(q->state) 
	{
	case RHIZOME_FETCH_SENDINGHTTPREQUEST:
	  bytes=write(q->socket,&q->request[q->request_ofs],
			  q->request_len-q->request_ofs);
	  if (bytes>0) {
	    action=1;
	    q->request_ofs+=bytes;
	    if (q->request_ofs>=q->request_len) {
	      /* Sent all of request.  Switch to listening for HTTP response headers.
	       */
	      if (debug&DEBUG_RHIZOME) {
		fprintf(stderr,"Sent http request to fetch file. (%d of %d bytes)\n",q->request_ofs,q->request_len);	      
		fprintf(stderr,"sent [%s]\n",q->request);
	      }
	      q->request_len=0; q->request_ofs=0;
	      q->state=RHIZOME_FETCH_RXHTTPHEADERS;
	    }
	  }
	  break;
	case RHIZOME_FETCH_RXFILE:
	  /* Keep reading until we have the promised amount of data */
	  if (debug&DEBUG_RHIZOME) 
	    fprintf(stderr,"receiving rhizome fetch file body (current offset=%d)\n",
		    q->file_ofs);
	  
	  sigPipeFlag=0;
	  
	  errno=0;
	  char buffer[8192];

	  int bytes=read(q->socket,buffer,8192);
	  
	  /* If we got some data, see if we have found the end of the HTTP request */
	  if (bytes>0) {
	    action=1;

	    if (debug&DEBUG_RHIZOME) 
	      fprintf(stderr,"Read %d bytes; we now have %d of %d bytes.\n",
		      bytes,q->file_ofs+bytes,q->file_len);

	    if (bytes>(q->file_len-q->file_ofs))
	      bytes=q->file_len-q->file_ofs;
	    if (fwrite(buffer,bytes,1,q->file)!=1)
	      {
		if (debug&DEBUG_RHIZOME) fprintf(stderr,"Failed writing %d bytes to file. @ offset %d\n",bytes,q->file_ofs);
		q->close=1;
		continue;
	      }
	    q->file_ofs+=bytes;
	  }	  
	  if (q->file_ofs>=q->file_len)
	    {
	      /* got all of file */
	      q->close=1;
	      if (debug&DEBUG_RHIZOME) fprintf(stderr,"Received all of file via rhizome -- now to import it\n");
	      {
		fclose(q->file);
		char filename[1024];
		snprintf(filename,1024,"%s/import/manifest.%s",
			 rhizome_datastore_path,
			 rhizome_manifest_get(q->manifest,"id",NULL,0));
		/* Do really write the manifest unchanged */
		if (debug&DEBUG_RHIZOME) {
		  fprintf(stderr,"manifest has %d signatories\n",q->manifest->sig_count);
		  fprintf(stderr,"manifest id = %s, len=%d\n",
			  rhizome_manifest_get(q->manifest,"id",NULL,0),
			  q->manifest->manifest_bytes);
		  dump("manifest",&q->manifest->manifestdata[0],
		       q->manifest->manifest_all_bytes);
		}
		q->manifest->finalised=1;
		q->manifest->manifest_bytes=q->manifest->manifest_all_bytes;
		if (!rhizome_write_manifest_file(q->manifest,filename)) {
		    rhizome_bundle_import(rhizome_manifest_get(q->manifest,
							       "id",NULL,0),
					  NULL /* no additional groups */,
					  q->manifest->ttl-1 /* TTL */,
					  1 /* do verify */,
					  1 /* do check hash of file */,
					  0 /* do not sign it, just keep existing
					       signatures */);		  
		  }
	      }
	    }
	  break;
	case RHIZOME_FETCH_RXHTTPHEADERS:
	  /* Keep reading until we have two CR/LFs in a row */
	  if (debug&DEBUG_RHIZOME) WHY("receiving rhizome fetch http headers");
	  
	  sigPipeFlag=0;
	  
	  errno=0;
	  bytes=read(q->socket,&q->request[q->request_len],
			 1024-q->request_len-1);

	  /* If we got some data, see if we have found the end of the HTTP request */
	  if (bytes>0) {
	    action=1;
	    int lfcount=0;
	    int i=q->request_len-160;
	    if (i<0) i=0;
	    q->request_len+=bytes;
	    if (q->request_len<1024)
	      q->request[q->request_len]=0;
	    if (debug&DEBUG_RHIZOME)
	      dump("http reply headers",(unsigned char *)q->request,q->request_len);
	    for(;i<(q->request_len+bytes);i++)
	      {
		switch(q->request[i]) {
		case '\n': lfcount++; break;
		case '\r': /* ignore CR */ break;
		case 0: /* ignore NUL (telnet inserts them) */ break;
		default: lfcount=0; break;
		}
		if (lfcount==2) break;
	      }
	    if (lfcount==2) {
	      /* We have the response headers, so parse.
	         (we may also have some extra bytes, so we need to be a little
	          careful) */

	      /* Terminate string at end of headers */
	      q->request[i]=0;

	      /* Get HTTP result code */
	      char *s=strstr(q->request,"HTTP/1.0 ");
	      if (!s) { 
		if (debug&DEBUG_RHIZOME) fprintf(stderr,"HTTP response lacked HTTP/1.0 response code.\n");
		q->close=1; continue; }
	      int http_response_code=strtoll(&s[9],NULL,10);
	      if (http_response_code!=200) {
		if (debug&DEBUG_RHIZOME) fprintf(stderr,"Rhizome web server returned %d != 200 OK\n",http_response_code);
		q->close=1; continue;
	      }
	      /* Get content length */
	      s=strstr(q->request,"Content-length: ");
	      if (!s) {
		if (debug&DEBUG_RHIZOME) 
		  fprintf(stderr,"Missing Content-Length: header.\n");
		q->close=1; continue; }
	      q->file_len=strtoll(&s[16],NULL,10);
	      if (q->file_len<0) {
		if (debug&DEBUG_RHIZOME) 
		  fprintf(stderr,"Illegal file size (%d).\n",q->file_len);
		q->close=1; continue; }

	      /* Okay, we have both, and are all set.
		 File is already open, so just write out any initial bytes of the
		 file we read, and update state flag.
	      */
	      int fileRxBytes=q->request_len-(i+1);
	      if (fileRxBytes>0)
		if (fwrite(&q->request[i+1],fileRxBytes,1,q->file)!=1)
		  {
		    if (debug&DEBUG_RHIZOME) 
		      fprintf(stderr,"Failed writing initial %d bytes to file.\n",
			      fileRxBytes);	       
		    q->close=1;
		    continue;
		  }
	      q->file_ofs=fileRxBytes;
	      if (debug&DEBUG_RHIZOME) 
		fprintf(stderr,"Read %d initial bytes of %d total\n",
			q->file_ofs,q->file_len);
	      q->state=RHIZOME_FETCH_RXFILE;
	    }
	    
	    q->request_len+=bytes;
	  } 
	  
	  /* Give up fairly quickly if there is no action, because the peer may
	     have moved out of range. */
	  if (!action) {
	    if (time(0)-q->last_action>RHIZOME_IDLE_TIMEOUT) {
	      if (debug&DEBUG_RHIZOME) 
		WHY("Closing connection due to inactivity timeout.");
	      q->close=1;
	      continue;
	    }
	  } else q->last_action=time(0);
	  
	  if (sigPipeFlag||((bytes==0)&&(errno==0))) {
	    /* broken pipe, so close connection */
	    if (debug&DEBUG_RHIZOME) 
	      WHY("Closing rhizome fetch connection due to sigpipe");
	    q->close=1;
	    continue;
	  }	 
	  break;
	default:
	  if (debug&DEBUG_RHIZOME) 
	    WHY("Closing rhizome fetch connection due to illegal/unimplemented state.");
	  q->close=1;
	  break;
	}
      
      /* Make socket blocking again for poll()/select() */
      fcntl(q->socket,F_SETFL,fcntl(q->socket, F_GETFL, NULL)&(~O_NONBLOCK));
    }
  
  int i;
  for(i=rhizome_file_fetch_queue_count-1;i>=0;i--)
    {
      if (file_fetch_queue[i].close) {
	/* Free ephemeral data */
	if (file_fetch_queue[i].file) fclose(file_fetch_queue[i].file);
	file_fetch_queue[i].file=NULL;
	if (file_fetch_queue[i].manifest) 
	  rhizome_manifest_free(file_fetch_queue[i].manifest);
	file_fetch_queue[i].manifest=NULL;
	
	/* reshuffle higher numbered slot down if required */
	if (i<(rhizome_file_fetch_queue_count-1))
	  bcopy(&file_fetch_queue[rhizome_file_fetch_queue_count-1],
		&file_fetch_queue[i],sizeof(rhizome_file_fetch_record));
	
	/* Reduce count of open connections */
	rhizome_file_fetch_queue_count--;
      }
    }


  return 0;
}
