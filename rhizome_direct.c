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

int rhizome_direct_form_received(rhizome_http_request *r)
{
  /* XXX This needs to be implemented.
     For now we just put out a "no content" response that makes testing convenient
  */

  return rhizome_server_simple_http_response(r, 204, "Move along. Nothing to see.");
}


int rhizome_direct_process_mime_line(rhizome_http_request *r,char *buffer)
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
  if (!strncmp(buffer,r->boundary_string,r->boundary_string_length))
    boundaryLine=1;
  int endOfForm=0;
  if (boundaryLine&&
      buffer[r->boundary_string_length]=='-'&&
      buffer[r->boundary_string_length+1]=='-')
    endOfForm=1;
  int blankLine=0;
  if (!strcmp(buffer,"\r\n")) blankLine=1;

  DEBUGF("mime state: 0x%x, blankLine=%d, EOF=%d",
	 r->source_flags,blankLine,endOfForm);
  switch(r->source_flags) {
  case RD_MIME_STATE_INITIAL:
    DEBUGF("mime line: %s",r->request);
    if (boundaryLine) r->source_flags=RD_MIME_STATE_PARTHEADERS;
    break;
  case RD_MIME_STATE_PARTHEADERS:
  case RD_MIME_STATE_MANIFESTHEADERS:
  case RD_MIME_STATE_DATAHEADERS:
    DEBUGF("mime line: %s",r->request);
    if (blankLine) {
      /* End of headers */
      if (r->source_flags!=RD_MIME_STATE_PARTHEADERS) {
	/* Open manifest or data file handle, and begin writing to
	   it. */
	/* XXX not implemented */
	r->source_flags=RD_MIME_STATE_BODY;
      } else {
	/* unknown part: complain */
	rhizome_server_simple_http_response
	  (r, 400, "<html><h1>Unsupported form field or missing content-disposition line in mime part</h1></html>\r\n");
	return -1;
      }
    } else {
      char field[1024];
      char name[1024];
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
	} else if (blankLine) {
	  if (r->source_flags==RD_MIME_STATE_PARTHEADERS)
	    {
	      /* Multiple content-disposition lines.  This is very naughty. */
	      rhizome_server_simple_http_response
		(r, 400, "<html><h1>Malformed multi-part form POST: Missing content-disposition lines in MIME encoded part.</h1></html>\r\n");
	      return -1;
	    }
	  r->source_flags=RD_MIME_STATE_BODY;
      }	
    }
    break;
  case RD_MIME_STATE_BODY:
    if (boundaryLine) r->source_flags=RD_MIME_STATE_PARTHEADERS;
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
	if (rhizome_direct_process_mime_line(r,r->request)) return -1;
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
    /* return "no content" for now. */
    return rhizome_direct_form_received(r);
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
	for(i=0;i<1023&&*ct_str&&*ct_str!='\n';i++,ct_str++)
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

int app_rhizome_direct_server(int argc, const char *const *argv, 
			      struct command_line_option *o)
{
  /* Start Rhizome Direct server on configured port.
     We re-use the Rhizome HTTP server code as much as possible here,
     just replacing the server and client poll functions with our own.
  */  

  int port_low=confValueGetInt64Range("rhizome.direct.port",RHIZOME_DIRECT_PORT,
					 0,65535);
  int port_high=confValueGetInt64Range("rhizome.direct.port_max",RHIZOME_DIRECT_PORT_MAX,
					 port_low,65535);

  /* Rhizome direct mode doesn't need all of the normal servald preparation, because
     rhizome direct just needs to listen on its port, talk to other rhizome direct
     daemons, and query the rhizome database directly.  So we probably just need to
     read configuration settings so that we can access the rhizome sqlite database.
  */
 
  /* Start rhizome direct http server */
  rhizome_http_server_start(rhizome_direct_parse_http_request,
			    "rhizome_direct_parse_http_request",
			    port_low,port_high);
  
  /* Respond to events */
  while(1) {
    /* Check for activitiy and respond to it */
    fd_poll();
  }

  return 0;
}

int app_rhizome_direct_sync(int argc, const char *const *argv, 
			    struct command_line_option *o)
{
  /* Attempt to connect with a remote Rhizome Direct instance,
     and negotiate which BARs to synchronise. */
  return -1;
}
  
  
