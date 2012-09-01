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

int rhizome_direct_process_post_multipart_bytes
(rhizome_http_request *r,const char *bytes,int count)
{
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

	/* Remember boundary string and source path */
	snprintf(&r->boundarystring[0],1023,"%s",boundary_string);
	r->boundarystring[1023]=0;
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

	  /* Process any outstanding bytes */
	  rhizome_direct_process_post_multipart_bytes(r,&r->request[i],r->request_length-i);
	  r->request_length=0;
	}

	return rhizome_server_simple_http_response(r, 200, "<html><h1>Not implemented</h1></html>\r\n");
	
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
  
  
