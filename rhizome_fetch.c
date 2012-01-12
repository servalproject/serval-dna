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

typedef struct rhizome_file_fetch_record {
  int sock; /* if non-zero this is the socket to read from */
  rhizome_manifest *manifest;
  char fileid[SHA512_DIGEST_STRING_LENGTH];
  FILE *file;
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
	    file_fetch_queue[rhizome_file_fetch_queue_count].manifest=m;
	    strncpy(file_fetch_queue[rhizome_file_fetch_queue_count].fileid,
		    filehash,SHA512_DIGEST_STRING_LENGTH);
	    rhizome_file_fetch_queue_count++;
	    if (debug&DEBUG_RHIZOME) fprintf(stderr,"Queued file for fetching\n");
	    WHY("Fetch preparation incomplete (socket state recording is needed)");
	    return 0;
	  }
	else
	  {
	    /* Transfer via overlay */
	    return WHY("Rhizome fetching via overlay not implemented");
	  }
      }
    }

  /* got file, so now import */
  WHY("Actual importing not implemented");

  return WHY("Not implemented.");
}
