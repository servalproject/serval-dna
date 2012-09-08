/*
Serval Mesh Software
Copyright (C) 2010-2012 Paul Gardner-Stephen

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
  Rhizome Direct (github issue #9)
  @author Paul Gardner-Stephen <paul@servalproject.org>

  The base rhizome protocol allows the automatic and progressive transfer of data
  bundles (typically files and their associated meta-data) between devices sharing
  a common network interface.

  There are several use-cases where that is insufficient, e.g.:

  1. User wishes to cause two near-by devices to completely synchronise, e.g., as
  part of a regular data courier activity, or a field operation centre wishing to
  extract all field-collected data from a device, and possibly provide the field
  device with updated operational information and software.

  2. Two remote devices wish to synchronise, e.g., redundant Serval Rhizome servers
  forming part of a humanitarian or governmental emergency/disaster response
  capability.

  3. As (2), but with regular synchronisation.

  In all cases what is required is a mechanism for one Serval daemon instance to
  communicate via another Serval daemon instance, and determine the bundles that
  need to be transfered in each direction, and effect those transfers.

  Several challenges complicate this objective:

  1. Network Address Translation (NAT) or some other barrier may make it impossible
  for one of the devices to initiate a TCP connection to the other device.  Thus
  the protocol must be able to operate "one-sided", yet be able to synchronise
  bundles in both directions.

  2. The protocol must not impair the real-time requirements of the Serval daemon
  at either end. Therefore the protocol must be implemented in a separate thread
  or process.  As the Serval design is for single-threaded processes to improve
  portability and reliability, a separate process will be used.  That separate
  process will be another instance of the Serval daemon that will be run from the
  command line, and terminate when the synchronisation has completed, or when it
  receives an appropriate signal.  This approach also ensures that the Rhizome 
  databases at each end will always be consistent (or more properly, not become
  inconsistent due to the operation of this protocol).

  The test suites to exercise this protocol are located in "tests/rhizomeprotocol".

  The above functionality resolves down to several specific functions:

  1. Ability to enquire running servald and generate a list of BARs that it has
  stored, and present that list of "IHAVE"'s to the far end for examination.

  2. Ability to respond to such a list of BAR's, compare the list to the local
  servald instance's Rhizome database, and send back a list of "IHAVE"'s for any
  bundles that are newer than those presented in the list, or that were not present
  in the list.

  3. Ability to parse such a list of "IHAVE"'s, and from that determine the set of
  bundles to synchronise in each direction.

  4. As each server may have very many bundles, the above transactions must be able
  to operate on a limited range of bundle-IDs.  Each request shall therefore include
  the lowest and highest bundle-ID covered by the list.

  Note that the above actions are between the two Rhizome Direct processes, and not
  the Serval daemon processes (although each Rhizome Direct process will necessarily
  need to communicate with their local Serval daemon instances).

  5. Ability to present a BAR to the remote end Serval daemon instance and fetch the
  associated data bundle, and then present it to the local Serval daemon instance
  for adding to the local Rhizome database.

  It is recognised that the Serval daemon's real-time behaviour is compromised by
  the current mechanism for importing bundles into the Rhizome database.  This will
  be addressed as part of the on-going development of the main Rhizome protocol, and
  its rectification is beyond the scope of Rhizome Direct.

  6. Ability to present manifest and associated data for a bundle to the remote
  Rhizome Direct process for that process to schedule its insertion into the Rhizome
  database.

  As with the existing Rhizome protocol, it seems reasonable to use HTTP as the
  basis. The interactions will be M2M, so we do not need a fully-fledged HTTP
  server at this stage, but can make use of our own spartan HTTP server already
  integrated into servald.

  In light of the above, the Rhizome Direct process will need to have it's own TCP
  port number.  It is also necessary to have a Rhizome Direct process running to
  accept Rhizome Direct requests from clients.
  
*/

#include "serval.h"
#include "rhizome.h"
#include "str.h"
#include <assert.h>

int rhizome_direct_clear_temporary_files(rhizome_http_request *r)
{
  char filename[1024];
  char *fields[]={"manifest","data","unknown",NULL};
  int i;

  for(i=0;fields[i];i++) {
    snprintf(filename,1024,"rhizomedirect.%d.%s",r->alarm.poll.fd,fields[i]);
    filename[1023]=0;
    DEBUGF("Unlinking '%s'",filename);
  }
  return 0;
}

int rhizome_direct_form_received(rhizome_http_request *r)
{
  /* XXX This needs to be implemented.
     For now we just put out a "no content" response that makes testing convenient
  */

  /* XXX process completed form based on the set of fields seen */
  switch(r->fields_seen) {
  case RD_MIME_STATE_MANIFESTHEADERS
    |RD_MIME_STATE_DATAHEADERS:
    /* A bundle to import */
    DEBUGF("Call bundle import for rhizomedata.%d.{data,file}",
	   r->alarm.poll.fd);
    char cmd[1024];
    snprintf(cmd,1024,
	     "servald rhizome import bundle rhizomedirect.%d.data rhizomedirect.%d.manifest",
	     r->alarm.poll.fd,r->alarm.poll.fd);
    cmd[1023]=0;
    int rv=system(cmd);
    int status=-1;

    if (rv!=-1) status=WEXITSTATUS(rv);

    DEBUGF("Import returned %d",status);

    /* clean up after ourselves */
    rhizome_direct_clear_temporary_files(r);
    /* and report back to caller.
       201 = content created, which is probably appropriate for when we successfully
       import a bundle (or if we already have it).
       403 = forbidden, which might be appropriate if we refuse to accept it, e.g.,
       the import fails due to malformed data etc.

       For now we are just returning "no content" as a place-holder while debugging.
    */       
    rhizome_server_simple_http_response(r, 204, "Move along. Nothing to see.");
    break;     
  default:
    /* Clean up after ourselves */
    rhizome_direct_clear_temporary_files(r);
    
    
  }

  return rhizome_server_simple_http_response(r, 204, "Move along. Nothing to see.");

}


int rhizome_direct_process_mime_line(rhizome_http_request *r,char *buffer,int count)
{
  /* Check for boundary line at start of buffer.
     Boundary line = CRLF + "--" + boundary_string + optional whitespace + CRLF
     EXCEPT end of form boundary, which is:
     CRLF + "--" + boundary_string + "--" + CRLF

     NOTE: We attach the "--" to boundary_string when setting things up so that
     we don't have to keep manually checking for it here.

     NOTE: The parser eats the CRLF from the front, and attaches it to the end
     of the previous line.  This means we need to rewind 2 bytes from whatever
     file we were writing to whenever we encounter a boundary line, at least
     if those last two bytes were CRLF. That can be safely assumed if we
     assume that the boundary string has been chosen to be a string never appearing
     anywhere in the contents of the form.  In practice, that is only "almost
     certain" (according to the mathematical meaning of that phrase) if boundary
     strings are randomly selected and are of sufficient length.
   
     NOTE: We are not supporting nested/mixed parts, as that would considerably
     complicate the parser.  If the need arises in future, we will deal with it
     then.  In the meantime, we will have something that meets our immediate
     needs for Rhizome Direct and a variety of use cases.
  */

  /* Regardless of the state of the parser, the presence of boundary lines
     is significant, so lets just check once, and remember the result.
     Similarly check a few other conditions. */
  int boundaryLine=0;
  if (!bcmp(buffer,r->boundary_string,r->boundary_string_length))
    boundaryLine=1;

  int endOfForm=0;
  if (boundaryLine&&
      buffer[r->boundary_string_length]=='-'&&
      buffer[r->boundary_string_length+1]=='-')
    endOfForm=1;
  int blankLine=0;
  if (!strcmp(buffer,"\r\n")) blankLine=1;

  DEBUGF("mime state: 0x%x, blankLine=%d, boundary=%d, EOF=%d, bytes=%d",
	 r->source_flags,blankLine,boundaryLine,endOfForm,count);
  switch(r->source_flags) {
  case RD_MIME_STATE_INITIAL:
    if (boundaryLine) r->source_flags=RD_MIME_STATE_PARTHEADERS;
    break;
  case RD_MIME_STATE_PARTHEADERS:
  case RD_MIME_STATE_MANIFESTHEADERS:
  case RD_MIME_STATE_DATAHEADERS:
    DEBUGF("mime line: %s",r->request);
    if (blankLine) {
      /* End of headers */
      if (r->source_flags==RD_MIME_STATE_PARTHEADERS)
	{
	  /* Multiple content-disposition lines.  This is very naughty. */
	  rhizome_server_simple_http_response
	    (r, 400, "<html><h1>Malformed multi-part form POST: Missing content-disposition lines in MIME encoded part.</h1></html>\r\n");
	  return -1;
	}
      
      /* Prepare to write to file for field.
	 We may have multiple rhizome direct transactions running at the same
	 time on different TCP connections.  So serialise using file descriptor.
	 We could use the boundary string or some other random thing, but using
	 the file descriptor places a reasonable upper limit on the clutter that
	 is possible, while still preventing collisions -- provided that we don't
	 close the file descriptor until we have completed processing the 
	 request. */
      r->field_file=NULL;
      char filename[1024];
      char *field="unknown";
      switch(r->source_flags) {
      case RD_MIME_STATE_DATAHEADERS: field="data"; break;
      case RD_MIME_STATE_MANIFESTHEADERS: field="manifest"; break;
      }
      snprintf(filename,1024,"rhizomedirect.%d.%s",r->alarm.poll.fd,field);
      filename[1023]=0;
      DEBUGF("Writing to '%s'",filename);
      r->field_file=fopen(filename,"w");
      if (!r->field_file) {
	rhizome_direct_clear_temporary_files(r);
	rhizome_server_simple_http_response
	  (r, 500, "<html><h1>Sorry, couldn't complete your request, reasonable as it was.  Perhaps try again later.</h1></html>\r\n");
	return -1;
      }
      r->source_flags=RD_MIME_STATE_BODY;
    } else {
      char name[1024];
      char field[1024];
      if (sscanf(buffer,
		 "Content-Disposition: form-data; name=\"%[^\"]\";"
		 " filename=\"%[^\"]\"",field,name)==2)
	{
	  if (r->source_flags!=RD_MIME_STATE_PARTHEADERS)
	    {
	      /* Multiple content-disposition lines.  This is very naughty. */
	      rhizome_server_simple_http_response
		(r, 400, "<html><h1>Malformed multi-part form POST: Multiple content-disposition lines in single MIME encoded part.</h1></html>\r\n");
	      return -1;
	    }
	  DEBUGF("Found form part '%s' name '%s'",field,name);
	  if (!strcasecmp(field,"manifest")) 
	    r->source_flags=RD_MIME_STATE_MANIFESTHEADERS;
	  if (!strcasecmp(field,"data")) 
	    r->source_flags=RD_MIME_STATE_DATAHEADERS;
	  if (r->source_flags!=RD_MIME_STATE_PARTHEADERS)
	    r->fields_seen|=r->source_flags;
	} 
    }
    break;
  case RD_MIME_STATE_BODY:
    if (boundaryLine) {
      r->source_flags=RD_MIME_STATE_PARTHEADERS;

      /* We will have written an extra CRLF to the end of the file,
	 so prune that off. */
      fflush(r->field_file);
      int fd=fileno(r->field_file);
      off_t correct_size=ftell(r->field_file)-2;
      ftruncate(fd,correct_size);
      fclose(r->field_file);
      r->field_file=NULL;
    }
    else {
      int written=fwrite(r->request,count,1,r->field_file);
      DEBUGF("wrote %d lump of %d bytes",written,count);
    }
    break;
  }

  if (endOfForm) {
    /* End of form marker found. 
       Pass it to function that deals with what has been received,
       and will also send response or close the http request if required. */

    /* XXX Rewind last two bytes from file if open, and close file */

    DEBUGF("Found end of form");
    return rhizome_direct_form_received(r);
  }
  return 0;
}

int rhizome_direct_process_post_multipart_bytes
(rhizome_http_request *r,const char *bytes,int count)
{
  {
    DEBUGF("Saw %d multi-part form bytes",count);
    FILE *f=fopen("post.log","a"); 
    if (f) fwrite(bytes,count,1,f);
    if (f) fclose(f);
  }

  /* This function looks for multi-part form separators and descriptor lines,
     and streams any "manifest" or "data" blocks to respectively named files.

     The challenge is that we might only get a partial boundary string passed
     to us.  So we need to remember the last KB or so of data and glue it to
     the front of the current set of bytes.

     In multi-part form parsing we don't need r->request for anything, so if
     we are not in a form part already, then we can stow the bytes there
     for reexamination when more bytes arrive.
     
     Side effect will be that the entire boundary string and associated bits will
     need to be <=1KB, the size of r->request.  This seems quite reasonable.

     Example of such a block is:

     ------WebKitFormBoundaryEoJwSoSVW4qsrBZW
     Content-Disposition: form-data; name="manifest"; filename="spleen"
     Content-Type: application/octet-stream     
  */

  int o;

  /* Split into lines and process each line separately using a
     simple state machine. 
     Lines containing binary are truncated into arbitrarily length pieces, but
     a newline will ALWAYS break the line.
  */

  for(o=0;o<count;o++)
    {
      int newline=0;
      if (bytes[o]=='\n')
	if (r->request_length>0&&r->request[r->request_length-1]=='\r')
	  { newline=1; r->request_length--; }
      if (r->request_length>1020) newline=2;
      if (newline) {	
	/* Found end of line, so process it */
	if (newline==1) {
	  /* Put the real new line onto the end if it was present, so that
	     we don't go doing anything silly, like joining lines in files
	     that really were separated by CRLF, or similarly inserting CRLF
	     in the middle of slabs of bytes that were not CRLF terminated.
	  */
	  r->request[r->request_length++]='\r';
	  r->request[r->request_length++]='\n';
	}
	r->request[r->request_length]=0;
	if (rhizome_direct_process_mime_line(r,r->request,r->request_length)) 
	  return -1;
	r->request_length=0;
	/* If a real new line was detected, then
	   don't include the \n as part of the next line.
	   But if it wasn't a real new line, then make sure we
	   don't loose the byte. */
	if (newline==1) continue;
      }

      r->request[r->request_length++]=bytes[o];
    }

  r->source_count-=count;
  if (r->source_count<=0) {
    DEBUGF("Got to end of multi-part form data");

    /* If the form is still being processed, then flush things through */
    if (r->request_type<0) {
      /* Flush out any remaining data */
      if (r->request_length) {
	DEBUGF("Flushing last %d bytes",r->request_length);
	r->request[r->request_length]=0;
	rhizome_direct_process_mime_line(r,r->request,r->request_length);
      }      
      return rhizome_direct_form_received(r);
    } else {
      /* Form has already been processed, so do nothing */
    }
  }
  return 0;
}

int rhizome_direct_parse_http_request(rhizome_http_request *r)
{
  /* Switching to writing, so update the call-back */
  r->alarm.poll.events=POLLOUT;
  watch(&r->alarm);
  // Start building up a response.
  r->request_type = 0;
  // Parse the HTTP "GET" line.
  char *path = NULL;
  size_t pathlen = 0;
  if (str_startswith(r->request, "GET ", &path)) {
    char *p;
    // This loop is guaranteed to terminate before the end of the buffer, because we know that the
    // buffer contains at least "\n\n" and maybe "\r\n\r\n" at the end of the header block.
    for (p = path; !isspace(*p); ++p)
      ;
    pathlen = p - path;
    if ( str_startswith(p, " HTTP/1.", &p)
      && (str_startswith(p, "0", &p) || str_startswith(p, "1", &p))
      && (str_startswith(p, "\r\n", &p) || str_startswith(p, "\n", &p))
    )
      path[pathlen] = '\0';
    else
      path = NULL;
 
    if (path) {
      char *id = NULL;
      INFOF("RHIZOME HTTP SERVER, GET %s", alloca_toprint(1024, path, pathlen));
      if (strcmp(path, "/favicon.ico") == 0) {
	r->request_type = RHIZOME_HTTP_REQUEST_FAVICON;
	rhizome_server_http_response_header(r, 200, "image/vnd.microsoft.icon", favicon_len);
      } else {
	rhizome_server_simple_http_response(r, 404, "<html><h1>Not found</h1></html>\r\n");
      }
    }
  } else   if (str_startswith(r->request, "POST ", &path)) {
    char *p;
        
    // This loop is guaranteed to terminate before the end of the buffer, because we know that the
    // buffer contains at least "\n\n" and maybe "\r\n\r\n" at the end of the header block.
    for (p = path; !isspace(*p); ++p)
      ;
    pathlen = p - path;
    if ( str_startswith(p, " HTTP/1.", &p)
      && (str_startswith(p, "0", &p) || str_startswith(p, "1", &p))
      && (str_startswith(p, "\r\n", &p) || str_startswith(p, "\n", &p))
    )
	path[pathlen] = '\0';
    else
      path = NULL;
 
    if (path) {
      char *id = NULL;
      INFOF("RHIZOME HTTP SERVER, POST %s", alloca_toprint(1024, path, pathlen));
      if (strcmp(path, "/bundle") == 0) {
	/*
	  We know we have the complete header, so get the content length and content type
	  fields. From those we work out what to do with the body. */
	char *headers=&path[pathlen+1];
	int headerlen=r->request_length-(headers-r->request);
	const char *cl_str=str_str(headers,"Content-Length: ",headerlen);
	const char *ct_str=str_str(headers,"Content-Type: multipart/form-data; boundary=",headerlen);
	if (!cl_str)
	  return 
	    rhizome_server_simple_http_response(r,400,"<html><h1>POST without content-length</h1></html>\r\n");
	if (!ct_str)
	  return 
	    rhizome_server_simple_http_response(r,400,"<html><h1>POST without content-type (or unsupported content-type)</h1></html>\r\n");
	/* ok, we have content-type and content-length, now make sure they are
	   well formed. */
	long long cl;
	if (sscanf(cl_str,"Content-Length: %lld",&cl)!=1)
	  return 
	    rhizome_server_simple_http_response(r,400,"<html><h1>malformed Content-Length: header</h1></html>\r\n");
	char boundary_string[1024];
	int i;
	ct_str+=strlen("Content-Type: multipart/form-data; boundary=");
	for(i=0;i<1023&&*ct_str&&*ct_str!='\n'&&*ct_str!='\r';i++,ct_str++)
	  boundary_string[i]=*ct_str;
	boundary_string[i]=0;
	if (i<4||i>128)
	  return 
	    rhizome_server_simple_http_response(r,400,"<html><h1>malformed Content-Type: header</h1></html>\r\n");

	DEBUGF("HTTP POST content-length=%lld, boundary string='%s'",
	       cl,boundary_string);

	/* Now start receiving and parsing multi-part data.
	   We may have already received some of the post-header data, so 
	   rewind that if necessary. Need to start by finding actual end of
	   headers, and passing any body bytes to the parser.
	   Also need to tell the HTTP request that it has moved to multipart
	   form data parsing, and what the actual requested action is.
	*/

	/* Remember boundary string and source path.
	   Put the preceeding -- on the front to make our life easier when
	   parsing the rest later. */
	snprintf(&r->boundary_string[0],1023,"--%s",boundary_string);
	r->boundary_string[1023]=0;
	r->boundary_string_length=strlen(r->boundary_string);
	r->source_index=0;
	r->source_count=cl;
	snprintf(&r->path[0],1023,"%s",path);
	r->path[1023]=0;
	r->request_type=RHIZOME_HTTP_REQUEST_RECEIVING_MULTIPART;

	/* Find the end of the headers and start of any body bytes that we
	   have read so far. */
	{
	  const char *eoh="\r\n\r\n";
	  int i=0;
	  for(i=0;i<r->request_length;i++) {
	    if (!strncmp(eoh,&r->request[i],strlen(eoh)))
	      break;
	  }
	  if (i>=r->request_length) {
	    /* Couldn't find the end of the headers, but this routine should
	       not be called if the end of headers has not been found.
	       Complain and go home. */
	    return 
	      rhizome_server_simple_http_response(r, 404, "<html><h1>End of headers seems to have gone missing</h1></html>\r\n");
	  }

	  /* Process any outstanding bytes.
	     We need to copy the bytes to a separate buffer, because 
	     r->request and r->request_length get used internally in the 
	     parser, which is also why we need to zero r->request_length.
	     We also zero r->source_flags, which is used as the state
	     counter for parsing the multi-part form data.
	   */
	  int count=r->request_length-i;
	  char buffer[count];
	  bcopy(&r->request[i],&buffer[0],count);
	  r->request_length=0;
	  r->source_flags=0;
	  rhizome_direct_process_post_multipart_bytes(r,buffer,count);
	}

	/* Handle the rest of the transfer asynchronously. */
	return 0;
      } else {
	rhizome_server_simple_http_response(r, 404, "<html><h1>Not found</h1></html>\r\n");
      }
    }
  } else {
    if (debug & DEBUG_RHIZOME_TX)
      DEBUGF("Received malformed HTTP request: %s", alloca_toprint(120, (const char *)r->request, r->request_length));
    rhizome_server_simple_http_response(r, 400, "<html><h1>Malformed request</h1></html>\r\n");
  }
  
  /* Try sending data immediately. */
  rhizome_server_http_send_bytes(r);

  return 0;
}

int app_rhizome_direct_sync(int argc, const char *const *argv, 
			    struct command_line_option *o)
{
  /* Attempt to connect with a remote Rhizome Direct instance,
     and negotiate which BARs to synchronise. */
  const char *modeName = (argc >= 3 ? argv[2] : "sync");
  int mode=3; /* two-way sync */
  if (!strcasecmp(modeName,"push")) mode=1; /* push only */
  if (!strcasecmp(modeName,"pull")) mode=2; /* pull only */

  DEBUGF("sync direction = %d",mode);

  /* Get iterator capable of 64KB buffering */
  rhizome_direct_bundle_cursor *c=rhizome_direct_bundle_iterator(0x10000);
  int count;
  while((count=rhizome_direct_bundle_iterator_fill(c,-1)))
    {
      DEBUGF("Got %d BARs",count);
      dump("BARs",c->buffer,c->buffer_used+c->buffer_offset_bytes);

      /* Build HTTP POST to send to far end presenting these BARs and seeking
	 feedback from the far end as to which are new, or if the far end has
	 new content that we do not.

	 The iterator prepares the buffer entirely, including putting the cursor
	 range covered, so that the far end can unpack it, search their corresponding
	 space and return their results.
      */
      rhizome_direct_bundle_cursor *t=rhizome_direct_bundle_iterator(0x10000);
      rhizome_direct_bundle_iterator_unpickle_range(t,c->buffer,10);      
      DEBUGF("Unpickled: size bins=%lld..%lld, %08x - %08x",
	     t->size_high,t->limit_size_high,
	     *(int*)&t->bid_low[0],
	     *(int*)&t->limit_bid_high[0]);
      rhizome_direct_bundle_iterator_free(&t);
    }
  rhizome_direct_bundle_iterator_free(&c);

  return -1;
}
 
rhizome_direct_bundle_cursor *rhizome_direct_bundle_iterator(int buffer_size)
{
  rhizome_direct_bundle_cursor *r=calloc(sizeof(rhizome_direct_bundle_cursor),1);
  assert(r!=NULL);
  r->buffer=malloc(buffer_size);
  assert(r->buffer);
  r->buffer_size=buffer_size;

  r->size_low=0;
  r->size_high=1024;

  /* Make cursor initially unlimited in range */
  rhizome_direct_bundle_iterator_unlimit(r);

  return r;
}

void rhizome_direct_bundle_iterator_unlimit(rhizome_direct_bundle_cursor *r)
{
  assert(r!=NULL);

  r->limit_size_high=1LL<<48LL;
  memset(r->limit_bid_high,0xff,RHIZOME_MANIFEST_ID_BYTES);
  return;
}

int rhizome_direct_bundle_iterator_pickle_range(rhizome_direct_bundle_cursor *r,
						unsigned char *pickled,
						int pickle_buffer_size)
{
  assert(r);
  assert(pickle_buffer_size>=(1+4+1+4));

  /* Pickled cursor ranges use the format:

     byte - log2(start_size_high)
     4 bytes - first eight bytes of start_bid_low.

     byte - log2(size_high)
     4 bytes - first eight bytes of bid_high.

     For a total of 10 bytes.

     We can get away with the short prefixes for the BIDs, because the worst case
     scenario is that we include a small part of the BID address space that we
     don't need to.  That will happen MUCH less often than transferring cursor
     ranges, which will happen with every rhizome direct sync.
  */

  long long v;
  int ltwov=0;

  v=r->start_size_high;
  while(v>1) { ltwov++; v=v>>1; }
  pickled[0]=ltwov;
  for(v=0;v<4;v++) pickled[1+v]=r->start_bid_low[v];
  v=r->size_high;
  DEBUGF("pickling size_high=%lld",r->size_high);
  while(v>1) { ltwov++; v=v>>1; }
  pickled[1+4]=ltwov;
  for(v=0;v<4;v++) pickled[1+4+1+v]=r->bid_high[v];

  return 1+4+1+4;
}

int rhizome_direct_bundle_iterator_unpickle_range(rhizome_direct_bundle_cursor *r,
						  const unsigned char *pickled,
						  int pickle_buffer_size)
{
  assert(r);
  if (pickle_buffer_size!=10) {
    DEBUGF("pickled rhizome direct cursor ranges should be 10 bytes.");
    return -1;
  }

  int v;

  /* Get start of range */
  r->size_high=1LL<<pickled[0];
  r->size_low=(r->size_high/2)+1;
  for(v=0;v<4;v++) r->bid_low[v]=pickled[1+v];
  for(;v<RHIZOME_MANIFEST_ID_BYTES;v++) r->bid_low[v]=0x00;

  /* Get end of range */
  r->limit_size_high=1LL<<pickled[1+4];
  for(v=0;v<4;v++) r->limit_bid_high[v]=pickled[1+4+1+v];
  for(;v<RHIZOME_MANIFEST_ID_BYTES;v++) r->limit_bid_high[v]=0xff;

  return 0;
}

int rhizome_direct_bundle_iterator_fill(rhizome_direct_bundle_cursor *c,int max_bars)
{
  int bundles_stuffed=0;
  c->buffer_used=0;

  /* Note where we are starting the cursor fill from, so that the caller can easily
     communicate the range of interest to the far end.  We will eventually have a 
     cursor set function that will allow that information to be loaded back in at
     the far end.  We will similarly need to have a mechanism to limit the end of
     the range that the cursor will cover, so that responses to the exact range
     covered can be provided.. But first things first, remembering where the cursor
     started.
     We keep the space for the pickled cursor range at the start of the buffer,
     and fill it in at the end.
  */
  /* This is the only information required to remember where we started: */
  c->start_size_high=c->size_high;
  bcopy(c->bid_low,c->start_bid_low,RHIZOME_MANIFEST_ID_BYTES);
  c->buffer_offset_bytes=1+4+1+4; /* space for pickled cursor range */

  /* -1 is magic value for fill right up */
  if (max_bars==-1) max_bars=c->buffer_size/RHIZOME_BAR_BYTES;

  while (bundles_stuffed<max_bars&&c->size_high<=c->limit_size_high) 
    {
      /* Don't overrun the cursor's buffer */
      int stuffable
	=(c->buffer_size-c->buffer_used-c->buffer_offset_bytes)/RHIZOME_BAR_BYTES;
      if (stuffable<=0) break;

      /* Make sure we only get the range of BIDs allowed by the cursor limit.
	 If we are not yet at the bundle data size limit, then any bundle is okay.
	 If we are at the bundle data size limit, then we need to honour
	 c->limit_bid_high. */
      unsigned char bid_max[RHIZOME_MANIFEST_ID_BYTES];
      if (c->size_high==c->limit_size_high)
	bcopy(c->limit_bid_high,bid_max,RHIZOME_MANIFEST_ID_BYTES);
      else
	memset(bid_max,0xff,RHIZOME_MANIFEST_ID_BYTES);

      int stuffed_now=rhizome_direct_get_bars(c->bid_low,c->bid_high,
					      c->size_low,c->size_high,
					      bid_max,
					      &c->buffer[c->buffer_used
							 +c->buffer_offset_bytes],
					      stuffable);
      bundles_stuffed+=stuffed_now;
      c->buffer_used+=RHIZOME_BAR_BYTES*stuffed_now;
      if (!stuffed_now) {
	/* no more matches in this size bin, so move up a size bin */
	c->size_low=c->size_high+1;
	c->size_high*=2;
	/* Record that we covered to the end of that size bin */
	memset(c->bid_high,0xff,RHIZOME_MANIFEST_ID_BYTES);
      } else {      
	/* Continue from next BID */
	bcopy(c->bid_high,c->bid_low,RHIZOME_MANIFEST_ID_BYTES);
	int i;
	for(i=RHIZOME_BAR_BYTES-1;i>=0;i--)
	  {
	    c->bid_low[i]++;
	    if (c->bid_low[i]) break;
	  }
	if (i<0) break;
      }
    }  

  /* Record range of cursor that this call covered. */
  rhizome_direct_bundle_iterator_pickle_range(c,c->buffer,c->buffer_offset_bytes);

  return bundles_stuffed;
}

void rhizome_direct_bundle_iterator_free(rhizome_direct_bundle_cursor **c)
{
  free((*c)->buffer); (*c)->buffer=NULL;
  bzero(*c,sizeof(rhizome_direct_bundle_cursor));
  *c=NULL;
}

/* Read upto the <bars_requested> next BARs from the Rhizome database,
   beginning from the first BAR that corresponds to a manifest with 
   BID>=<bid_low>.
   Sets <bid_high> to the highest BID for which a BAR was returned.
   Return value is the number of BARs written into <bars_out>.

   Only returns BARs for bundles within the specified size range.
   This is used by the cursor wrapper function that passes over all of the
   BARs in prioritised order.

   XXX Once the rhizome database gets big, we will need to make sure
   that we have suitable indexes.  It is tempting to just pack BARs
   by row_id, but the far end needs them in an orderly manner so that
   it is possible to make provably complete comparison of the contents
   of the respective rhizome databases.
*/
int rhizome_direct_get_bars(const unsigned char bid_low[RHIZOME_MANIFEST_ID_BYTES],
			    unsigned char bid_high[RHIZOME_MANIFEST_ID_BYTES],
			    long long size_low,long long size_high,
			    const unsigned char bid_max[RHIZOME_MANIFEST_ID_BYTES],
			    unsigned char *bars_out,
			    int bars_requested)
{
  sqlite_retry_state retry = SQLITE_RETRY_STATE_DEFAULT;
  char query[1024];

  snprintf(query,1024,
	   "SELECT BAR,ROWID,ID FROM MANIFESTS"
	   " WHERE ID>='%s' AND ID<='%s' AND FILESIZE BETWEEN %lld AND %lld"
	   " ORDER BY BAR LIMIT %d;",
	   alloca_tohex(bid_low,RHIZOME_MANIFEST_ID_BYTES),
	   alloca_tohex(bid_max,RHIZOME_MANIFEST_ID_BYTES),
	   size_low,size_high,
	   bars_requested);

  sqlite3_stmt *statement=sqlite_prepare(query);
  sqlite3_blob *blob=NULL;  

  int bars_written=0;

  while(bars_written<bars_requested
	&&  sqlite_step_retry(&retry, statement) == SQLITE_ROW)
    {
      int column_type=sqlite3_column_type(statement, 0);
      switch(column_type) {
      case SQLITE_BLOB:
	if (blob)
	  sqlite3_blob_close(blob);
	blob = NULL;
	int ret;
	int64_t rowid = sqlite3_column_int64(statement, 1);
	do ret = sqlite3_blob_open(rhizome_db, "main", "manifests", "bar",
				   rowid, 0 /* read only */, &blob);
	while (sqlite_code_busy(ret) && sqlite_retry(&retry, "sqlite3_blob_open"));
	if (!sqlite_code_ok(ret)) {
	  WHYF("sqlite3_blob_open() failed, %s", sqlite3_errmsg(rhizome_db));
	  continue;
	}
	sqlite_retry_done(&retry, "sqlite3_blob_open");
	
	int blob_bytes=sqlite3_blob_bytes(blob);
	if (blob_bytes!=RHIZOME_BAR_BYTES) {
	  if (debug&DEBUG_RHIZOME)
	    DEBUG("Found a BAR that is the wrong size - ignoring");
	  sqlite3_blob_close(blob);
	  blob=NULL;
	  continue;
	}	
	sqlite3_blob_read(blob,&bars_out[bars_written*RHIZOME_BAR_BYTES],
			  RHIZOME_BAR_BYTES,0);
	sqlite3_blob_close(blob);
	blob=NULL;

	/* Remember the BID so that we cant write it into bid_high so that the
	   caller knows how far we got. */
	fromhex(bid_high,
		(const char *)sqlite3_column_text(statement, 2),
		RHIZOME_MANIFEST_ID_BYTES);

	bars_written++;
	break;
      default:
	/* non-BLOB field.  This is an error, but we will persevere with subsequent
	   rows, becuase they might be fine. */
	break;
      }
    }
  if (statement)
    sqlite3_finalize(statement);
  statement = NULL;
  
  return bars_written;
}
  
