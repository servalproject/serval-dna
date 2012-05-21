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
#include "serval.h"
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
   an option.  We probably need to be passed this information.  This has since been
   incorporated.
*/

/* As defined below uses 64KB */
#define RHIZOME_VERSION_CACHE_NYBLS 2 /* 256=2^8=2nybls */
#define RHIZOME_VERSION_CACHE_SHIFT 1
#define RHIZOME_VERSION_CACHE_SIZE 128
#define RHIZOME_VERSION_CACHE_ASSOCIATIVITY 16
unsigned char rhizome_manifest_version_cache
[RHIZOME_VERSION_CACHE_SIZE][RHIZOME_VERSION_CACHE_ASSOCIATIVITY][32];

int rhizome_manifest_version_cache_store(rhizome_manifest *m)
{
  int bin=0;
  int slot;
  int i;

  char *id=rhizome_manifest_get(m,"id",NULL,0);
  if (!id) return 1; // dodgy manifest, so don't suggest that we want to RX it.

  /* Work out bin number in cache */
  for(i=0;i<RHIZOME_VERSION_CACHE_NYBLS;i++)
    {
      int nybl=chartonybl(id[i]);
      bin=(bin<<4)|nybl;
    }
  bin=bin>>RHIZOME_VERSION_CACHE_SHIFT;

  slot=random()%RHIZOME_VERSION_CACHE_ASSOCIATIVITY;
  unsigned char *entry=rhizome_manifest_version_cache[bin][slot];
  unsigned long long *cached_version=(unsigned long long *)&entry[24];
  unsigned long long manifest_version = rhizome_manifest_get_ll(m,"version");

  *cached_version=manifest_version;
  for(i=0;i<24;i++)
    {
      int byte=(chartonybl(id[(i*2)])<<4)|chartonybl(id[(i*2)+1]);
      entry[i]=byte;
    }

  return 0;
}

int rhizome_manifest_version_cache_lookup(rhizome_manifest *m)
{
  int bin=0;
  int slot;
  int i;

  char *id=rhizome_manifest_get(m,"id",NULL,0);
  if (!id) return 1; // dodgy manifest, so don't suggest that we want to RX it.

  /* Work out bin number in cache */
  for(i=0;i<RHIZOME_VERSION_CACHE_NYBLS;i++)
    {
      int nybl=chartonybl(id[i]);
      bin=(bin<<4)|nybl;
    }
  bin=bin>>RHIZOME_VERSION_CACHE_SHIFT;
  
  for(slot=0;slot<RHIZOME_VERSION_CACHE_ASSOCIATIVITY;slot++)
    {
      unsigned char *entry=rhizome_manifest_version_cache[bin][slot];
      for(i=0;i<24;i++)
	{
	  int byte=
	    (chartonybl(id[(i*2)+RHIZOME_VERSION_CACHE_NYBLS])<<4)
	    |chartonybl(id[(i*2)+RHIZOME_VERSION_CACHE_NYBLS+1]);
	  if (byte!=entry[i]) break;
	}
      if (i==24) {
	/* Entries match -- so check version */
	unsigned long long rev = rhizome_manifest_get_ll(m,"version");
	unsigned long long *cached_rev=(unsigned long long *)&entry[24];
	if (rev<*cached_rev) {
	  /* the presented manifest is older than we have.
	     This allows the caller to know that they can tell whoever gave them the
	     manifest it's time to get with the times.  May or not every be
	     implemented, but it would be nice. XXX */
	  return -2;
	} else if (rev<=*cached_rev) {
	  /* the presented manifest is already stored. */	   
	  return -1;
	} else {
	  /* the presented manifest is newer than we have */
	  return 0;
	}	  
      }
    }

  /* Not in cache, so all is well, well, maybe.
     What we do know is that it is unlikely to be in the database, so it probably
     doesn't hurt to try to receive it.  

     Of course, we can just ask the database if it is there already, and populate
     the cache in the process if we find it.  The tradeoff is that the whole point
     of the cache is to AVOID database lookups, not incurr them whenever the cache
     has a negative result.  But if we don't ask the database, then we can waste
     more effort fetching the file associated with the manifest, and will ultimately
     incurr a database lookup (and more), so while it seems a little false economy
     we need to do the lookup now.

     What this all suggests is that we need fairly high associativity so that misses
     are rare events. But high associativity then introduces a linear search cost,
     although that is unlikely to be nearly as much cost as even thinking about a
     database query.

     It also says that on a busy network that things will eventually go pear-shaped
     and require regular database queries, and that memory allowing, we should use
     a fairly large cache here.
 */
  unsigned long long manifest_version=rhizome_manifest_get_ll(m,"version");
  if (sqlite_exec_int64("select count(*) from manifests"
			" where id='%s' and version>=%lld",
			id,manifest_version)>0) {
    /* Okay, so we have a stored version which is newer, so update the cache
       using a random replacement strategy. */
    unsigned long long stored_version
      =sqlite_exec_int64("select version from manifests where id='%s'",
			 id);

    slot=random()%RHIZOME_VERSION_CACHE_ASSOCIATIVITY;
    unsigned char *entry=rhizome_manifest_version_cache[bin][slot];
    unsigned long long *cached_version=(unsigned long long *)&entry[24];
    *cached_version=stored_version;
    for(i=0;i<24;i++)
      {
	int byte=(chartonybl(id[(i*2)])<<4)|chartonybl(id[(i*2)+1]);
	entry[i]=byte;
      }
    
    /* Finally, say that it isn't worth RXing this manifest */
    if (stored_version>manifest_version) return -2; else return -1;
  } else {
    /* At best we hold an older version of this manifest */
    return 0;
  }

}

int rhizome_queue_manifest_import(rhizome_manifest *m,
				  struct sockaddr_in *peerip)
{
  int i;

  /* Do the quick rejection tests first, before the more expensive once,
     like querying the database for manifests. 

     We probably need a cache of recently rejected manifestid:versionid
     pairs so that we can avoid database lookups in most cases.  Probably
     the first 64bits of manifestid is sufficient to make it resistant to
     collission attacks, but using 128bits or the full 256 bits would be safer.
     Let's make the cache use 256 bit (32byte) entries for power of two
     efficiency, and so use the last 64bits for version id, thus using 192 bits
     for collission avoidance --- probably sufficient for many years yet (from
     time of writing in 2012).  We get a little more than 192 bits by using
     the cache slot number to implicitly store the first bits.
  */

  if (rhizome_manifest_version_cache_lookup(m)) {
    /* We already have this version or newer */
    if (debug&DEBUG_RHIZOMESYNC) {
      fprintf(stderr,"manifest id=%s, version=%lld\n",
	      rhizome_manifest_get(m,"id",NULL,0),
	      rhizome_manifest_get_ll(m,"version"));
      WHY("We already have that manifest or newer.\n");
    }
    return -1;
  } else {
    if (debug&DEBUG_RHIZOMESYNC) {
      fprintf(stderr,"manifest id=%s, version=%lld is new to us.\n",
	      rhizome_manifest_get(m,"id",NULL,0),
	      rhizome_manifest_get_ll(m,"version"));
    }
  }

  /* Don't queue if queue slots already full */
  if (rhizome_file_fetch_queue_count>=MAX_QUEUED_FILES) {
    if (debug&DEBUG_RHIZOME) WHY("Already busy fetching files");
    return -1;
  }
  /* Don't queue if already queued */
  char *id=rhizome_manifest_get(m,"id",NULL,0);
  for(i=0;i<rhizome_file_fetch_queue_count;i++) {
    rhizome_file_fetch_record 
      *q=&file_fetch_queue[i];
    if (!strcasecmp(id,rhizome_manifest_get(q->manifest,"id",NULL,0))) {
	if (debug&DEBUG_RHIZOMESYNC)
	  fprintf(stderr,"Already have %s in the queue.\n",id);
	return -1;
      }
  }

  char *filehash=rhizome_manifest_get(m,"filehash",NULL,0);
  long long filesize=rhizome_manifest_get_ll(m,"filesize");

  if (debug&DEBUG_RHIZOMESYNC) 
    fprintf(stderr,"Getting ready to fetch file %s for manifest %s\n",filehash,rhizome_manifest_get(m,"id",NULL,0));

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
	      WHY_perror("connect");
	      close (sock);
	      if (debug&DEBUG_RHIZOME) WHY("Failed to open socket to peer's rhizome web server");
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
	    const char *id = rhizome_manifest_get(q->manifest, "id", NULL, 0);
	    if (id == NULL) {
	      close(sock);
	      return WHY("Manifest missing ID");
	    }
	    char filename[1024];
	    if (!FORM_RHIZOME_DATASTORE_PATH(filename, "import/file.%s", id)) {
	      close(sock);
	      return -1;
	    }
	    q->manifest->dataFileName = strdup(filename);
	    q->file=fopen(filename,"w");
	    if (!q->file) {
	      WHY_perror("fopen");
	      if (debug&DEBUG_RHIZOME)
		DEBUGF("Could not open '%s' to write received file.", filename);
	      close(sock);
	      return -1;
	    }
	    rhizome_file_fetch_queue_count++;
	    if (debug&DEBUG_RHIZOME) DEBUGF("Queued file for fetching");
	    return 0;
	  }
	else
	  {
	    /* Transfer via overlay */
	    return WHY("Rhizome fetching via overlay not implemented");
	  }
      }
      else
	{
	  if (debug&DEBUG_RHIZOMESYNC) 
	    fprintf(stderr,"We already have the file for this manifest; importing from manifest alone.\n");
	  m->finalised=1;
	  m->fileHashedP=1;
	  m->manifest_bytes=m->manifest_all_bytes;
	  const char *id = rhizome_manifest_get(m, "id", NULL, 0);
	  if (id == NULL)
	    return WHY("Manifest missing ID");
	  char filename[1024];
	  if (!FORM_RHIZOME_DATASTORE_PATH(filename, "import/manifest.%s", id))
	    return -1;
	  if (!rhizome_write_manifest_file(m, filename)) {
	    rhizome_bundle_import(m, NULL, id,
				  NULL /* no additional groups */,
				  m->ttl-1 /* TTL */,
				  1 /* do verify */,
				  0 /* don't check hash of file (since we are using the databse stored copy) */,
				  0 /* do not sign it, just keep existing
				       signatures */);		  
	    
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
		fclose(q->file); q->file=NULL;
		const char *id = rhizome_manifest_get(q->manifest, "id", NULL, 0);
		if (id == NULL)
		  return WHY("Manifest missing ID");
		char filename[1024];
		if (!FORM_RHIZOME_DATASTORE_PATH(filename,"import/manifest.%s", id))
		  return -1;
		snprintf(filename,1024,"%s/manifest.%s",rhizome_datastore_path(),id);
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
		  rhizome_bundle_import(q->manifest, NULL, id,
					NULL /* no additional groups */,
					q->manifest->ttl - 1 /* TTL */,
					1 /* do verify */,
					1 /* do check hash of file */,
					0 /* do not sign it, just keep existing signatures */);
		  q->manifest=NULL;
		} else {
		  WHY("rhizome_write_manifest_file() failed");
		  rhizome_manifest_free(q->manifest);
		  q->manifest=NULL;
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
