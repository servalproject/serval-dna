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

#include "serval.h"
#include "rhizome.h"
#include "str.h"
#include "strbuf.h"
#include "strbuf_helpers.h"
#include <assert.h>
#include <sys/stat.h>
#include <sys/wait.h>

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
  if (!strcmp(r->path,"/rhizome/import")) {
    switch(r->fields_seen) {
    case RD_MIME_STATE_MANIFESTHEADERS | RD_MIME_STATE_DATAHEADERS: {
	/* Got a bundle to import */
	strbuf manifest_path = strbuf_alloca(50);
	strbuf payload_path = strbuf_alloca(50);
	strbuf_sprintf(manifest_path, "rhizomedirect.%d.manifest", r->alarm.poll.fd);
	strbuf_sprintf(payload_path, "rhizomedirect.%d.data", r->alarm.poll.fd);
	int ret = rhizome_bundle_import_files(strbuf_str(manifest_path), strbuf_str(payload_path), 1); // ttl = 1

	rhizome_direct_clear_temporary_files(r);
	/* report back to caller.
	  200 = ok, which is probably appropriate for when we already had the bundle.
	  201 = content created, which is probably appropriate for when we successfully
	  import a bundle (or if we already have it).
	  403 = forbidden, which might be appropriate if we refuse to accept it, e.g.,
	  the import fails due to malformed data etc.
	  (should probably also indicate if we have a newer version if possible)
	*/
	switch (ret) {
	case 0:
	  return rhizome_server_simple_http_response(r, 201, "Bundle succesfully imported.");
	case 2:
	  return rhizome_server_simple_http_response(r, 200, "Bundle already imported.");
	}
	return rhizome_server_simple_http_response(r, 500, "Server error: Rhizome import command failed.");
      }
      break;     
    default:
      /* Clean up after ourselves */
      rhizome_direct_clear_temporary_files(r);	     
    }
  } else if (!strcmp(r->path,"/rhizome/enquiry")) {
    int fd=-1;
    char file[1024];
    switch(r->fields_seen) {
    case RD_MIME_STATE_DATAHEADERS:
      /* Read data buffer in, pass to rhizome direct for comparison with local
	 rhizome database, and send back responses. */
      snprintf(file,1024,"rhizomedirect.%d.%s",r->alarm.poll.fd,"data");
      fd=open(file,O_RDONLY);
      if (fd == -1) {
	WHYF_perror("open(%s, O_RDONLY)", alloca_str_toprint(file));
	/* Clean up after ourselves */
	rhizome_direct_clear_temporary_files(r);	     
	return rhizome_server_simple_http_response(r,500,"Couldn't read a file");
      }
      struct stat stat;
      if (fstat(fd, &stat) == -1) {
	WHYF_perror("stat(%d)", fd);
	/* Clean up after ourselves */
	close(fd);
	rhizome_direct_clear_temporary_files(r);	     
	return rhizome_server_simple_http_response(r,500,"Couldn't stat a file");
      }
      unsigned char *addr = mmap(NULL, stat.st_size, PROT_READ, MAP_SHARED, fd, 0);
      if (addr==MAP_FAILED) {
	WHYF_perror("mmap(NULL, %lld, PROT_READ, MAP_SHARED, %d, 0)", (long long) stat.st_size, fd);
	/* Clean up after ourselves */
	close(fd);
	rhizome_direct_clear_temporary_files(r);	     
	return rhizome_server_simple_http_response(r,500,"Couldn't mmap() a file");
      }
      /* Ask for a fill response.  Regardless of the size of the set of BARs passed
	 to us, we will allow up to 64KB of response. */
      rhizome_direct_bundle_cursor 
	*c=rhizome_direct_get_fill_response(addr,stat.st_size,10+18);
      munmap(addr,stat.st_size);
      close(fd);

      if (c)
	{
	  /* TODO: Write out_buffer as the body of the response.
	     We should be able to do this using the async framework fairly easily.
	  */
	  
	  int bytes=c->buffer_offset_bytes+c->buffer_used;
	  r->buffer=malloc(bytes+1024);
	  r->buffer_size=bytes+1024;
	  r->buffer_offset=0;
	  assert(r->buffer);

	  /* Write HTTP response header */
	  struct http_response hr;
	  hr.result_code=200;
	  hr.content_type="binary/octet-stream";
	  hr.content_length=bytes;
	  hr.body=NULL;
	  r->request_type=0;
	  rhizome_server_set_response(r,&hr);
	  assert(r->buffer_offset<1024);

	  /* Now append body and send it back. */
	  bcopy(c->buffer,&r->buffer[r->buffer_length],bytes);
	  r->buffer_length+=bytes;
	  r->buffer_offset=0;

	  /* Clean up cursor after sending response */
	  rhizome_direct_bundle_iterator_free(&c);
	  /* Clean up after ourselves */
	  rhizome_direct_clear_temporary_files(r);	     

	  return 0;
	}
      else
	{
	  return rhizome_server_simple_http_response(r,500,"Could not get response to enquiry");
	}

      /* Clean up after ourselves */
      rhizome_direct_clear_temporary_files(r);	     
      break;
    default:
      /* Clean up after ourselves */
      rhizome_direct_clear_temporary_files(r);	     

      return rhizome_server_simple_http_response(r, 404, "/rhizome/enquiry requires 'data' field");
    }

  }

  /* Clean up after ourselves */
  rhizome_direct_clear_temporary_files(r);	     
  /* Report error */
  return rhizome_server_simple_http_response(r, 500, "Something went wrong.  Probably a missing data or manifest part, or invalid combination of URI and data/manifest provision.");

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
  if (!memcmp(buffer,r->boundary_string,r->boundary_string_length))
    boundaryLine=1;

  int endOfForm=0;
  if (boundaryLine&&
      buffer[r->boundary_string_length]=='-'&&
      buffer[r->boundary_string_length+1]=='-')
    endOfForm=1;
  int blankLine=0;
  if (!strcmp(buffer,"\r\n")) blankLine=1;

  DEBUGF("mime state 0x%x, blankLine=%d, boundary=%d, EOF=%d, bytes=%d",
	 r->source_flags,blankLine,boundaryLine,endOfForm,count);
  switch(r->source_flags) {
  case RD_MIME_STATE_INITIAL:
    if (boundaryLine) r->source_flags=RD_MIME_STATE_PARTHEADERS;
    break;
  case RD_MIME_STATE_PARTHEADERS:
  case RD_MIME_STATE_MANIFESTHEADERS:
  case RD_MIME_STATE_DATAHEADERS:
    DEBUGF("mime line %s", alloca_str_toprint(r->request));
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

int rhizome_direct_process_post_multipart_bytes(rhizome_http_request *r,const char *bytes,int count)
{
  DEBUG(alloca_toprint(-1, bytes, count));
  {
    DEBUGF("Saw %d multi-part form bytes",count);
    char logname[128];
    snprintf(logname,128,"post-%08x.log",r->uuid);
    FILE *f=fopen(logname,"a"); 
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
  // Parse the HTTP request into verb, path, protocol, headers and content.
  char *const request_end = r->request + r->request_length;
  char *verb = r->request;
  char *path = NULL;
  char *proto = NULL;
  size_t pathlen = 0;
  char *headers = NULL;
  int headerlen = 0;
  char *content = NULL;
  int contentlen = 0;
  char *p;
  if ((str_startswith(verb, "GET", &p) || str_startswith(verb, "POST", &p)) && isspace(*p)) {
    *p++ = '\0';
    path = p;
    while (p < request_end && !isspace(*p))
      ++p;
    if (p < request_end) {
      pathlen = p - path;
      *p++ = '\0';
      proto = p;
      if ( str_startswith(p, "HTTP/1.", &p)
	&& (str_startswith(p, "0", &p) || str_startswith(p, "1", &p))
	&& (str_startswith(p, "\r\n", &headers) || str_startswith(p, "\n", &headers))
      ) {
	*p = '\0';
	char *eoh = str_str(headers, "\r\n\r\n", request_end - p);
	if (eoh) {
	  content = eoh + 4;
	  headerlen = content - headers;
	  contentlen = request_end - content;
	}
      }
    }
  }
  if (content == NULL) {
    if (debug & DEBUG_RHIZOME_TX)
      DEBUGF("Received malformed HTTP request %s", alloca_toprint(160, (const char *)r->request, r->request_length));
    return rhizome_server_simple_http_response(r, 400, "<html><h1>Malformed request</h1></html>\r\n");
  }
  INFOF("RHIZOME HTTP SERVER, %s %s %s", verb, alloca_toprint(-1, path, pathlen), proto);
  if (debug & DEBUG_RHIZOME_TX)
    DEBUGF("headers %s", alloca_toprint(-1, headers, headerlen));
  if (strcmp(verb, "GET") == 0) {
    if (strcmp(path, "/favicon.ico") == 0) {
      r->request_type = RHIZOME_HTTP_REQUEST_FAVICON;
      rhizome_server_http_response_header(r, 200, "image/vnd.microsoft.icon", favicon_len);
    } else {
      rhizome_server_simple_http_response(r, 404, "<html><h1>Not found</h1></html>\r\n");
    }
  } else if (strcmp(verb, "POST") == 0) {
    if (strcmp(path, "/rhizome/import") == 0 || strcmp(path, "/rhizome/enquiry") == 0) {
      const char *cl_str=str_str(headers,"Content-Length: ",headerlen);
      const char *ct_str=str_str(headers,"Content-Type: multipart/form-data; boundary=",headerlen);
      if (!cl_str)
	return rhizome_server_simple_http_response(r,400,"<html><h1>Missing Content-Length header</h1></html>\r\n");
      if (!ct_str)
	return rhizome_server_simple_http_response(r,400,"<html><h1>Missing or unsupported Content-Type header</h1></html>\r\n");
      /* ok, we have content-type and content-length, now make sure they are well formed. */
      long long content_length;
      if (sscanf(cl_str,"Content-Length: %lld",&content_length)!=1)
	return rhizome_server_simple_http_response(r,400,"<html><h1>Malformed Content-Length header</h1></html>\r\n");
      char boundary_string[1024];
      int i;
      ct_str+=strlen("Content-Type: multipart/form-data; boundary=");
      for(i=0;i<1023&&*ct_str&&*ct_str!='\n'&&*ct_str!='\r';i++,ct_str++)
	boundary_string[i]=*ct_str;
      boundary_string[i] = '\0';
      if (i<4||i>128)
	return rhizome_server_simple_http_response(r,400,"<html><h1>Malformed Content-Type header</h1></html>\r\n");

      DEBUGF("content_length=%lld, boundary_string=%s contentlen=%d", (long long) content_length, alloca_str_toprint(boundary_string), contentlen);

      /* Now start receiving and parsing multi-part data.  If we already received some of the
	 post-header data, process that first.  Tell the HTTP request that it has moved to multipart
	 form data parsing, and what the actual requested action is.
      */

      /* Remember boundary string and source path.
	  Put the preceeding -- on the front to make our life easier when
	  parsing the rest later. */
      strbuf bs = strbuf_local(r->boundary_string, sizeof r->boundary_string);
      strbuf_puts(bs, "--");
      strbuf_puts(bs, boundary_string);
      if (strbuf_overrun(bs))
	return rhizome_server_simple_http_response(r,500,"<html><h1>Server error: Multipart boundary string too long</h1></html>\r\n");
      strbuf ps = strbuf_local(r->path, sizeof r->path);
      strbuf_puts(ps, path);
      if (strbuf_overrun(ps))
	return rhizome_server_simple_http_response(r,500,"<html><h1>Server error: Path too long</h1></html>\r\n");
      r->boundary_string_length = strbuf_len(bs);
      r->source_index = 0;
      r->source_count = content_length;
      r->request_type = RHIZOME_HTTP_REQUEST_RECEIVING_MULTIPART;
      r->request_length = 0;
      r->source_flags = 0;

      /* Find the end of the headers and start of any body bytes that we have read
	 so far. Copy the bytes to a separate buffer, because r->request and 
	 r->request_length get used internally in the parser.
	*/
      if (contentlen) {
	char buffer[contentlen];
	bcopy(content, buffer, contentlen);
	rhizome_direct_process_post_multipart_bytes(r, buffer, contentlen);
      }

      /* Handle the rest of the transfer asynchronously. */
      return 0;
    } else {
      rhizome_server_simple_http_response(r, 404, "<html><h1>Not found</h1></html>\r\n");
    }
  } else {
    rhizome_server_simple_http_response(r, 404, "<html><h1>Not found</h1></html>\r\n");
  }
  
  /* Try sending data immediately. */
  rhizome_server_http_send_bytes(r);

  return 0;
}

void rhizome_direct_http_dispatch(rhizome_direct_sync_request *r)
{
  DEBUGF("Dispatch size_high=%lld",r->cursor->size_high);
  rhizome_direct_transport_state_http *state = r->transport_specific_state;

  int sock=socket(AF_INET, SOCK_STREAM, 0);
  if (sock==-1) {
    WHY_perror("socket");    
    goto end;
  } 

  struct hostent *hostent;
  hostent = gethostbyname(state->host);
  if (!hostent) {
    DEBUGF("could not resolve hostname");
    goto end;
  }

  struct sockaddr_in addr;  
  addr.sin_family = AF_INET;     
  addr.sin_port = htons(state->port);   
  addr.sin_addr = *((struct in_addr *)hostent->h_addr);
  bzero(&(addr.sin_zero),8);     

  if (connect(sock,(struct sockaddr *)&addr,sizeof(struct sockaddr)) == -1) {
    WHY_perror("connect");
    close(sock);
    goto end;
  }
 
  char boundary[20];
  char buffer[8192];

  strbuf bb = strbuf_local(boundary, sizeof boundary);
  strbuf_sprintf(bb, "%08lx%08lx", random(), random());
  assert(!strbuf_overrun(bb));
  strbuf content_preamble = strbuf_alloca(200);
  strbuf content_postamble = strbuf_alloca(40);
  strbuf_sprintf(content_preamble,
      "--%s\r\n"
      "Content-Disposition: form-data; name=\"data\"; filename=\"IHAVEs\"\r\n"
      "Content-Type: application/octet-stream\r\n"
      "\r\n",
      boundary
    );
  strbuf_sprintf(content_postamble, "\r\n--%s--\r\n", boundary);
  assert(!strbuf_overrun(content_preamble));
  assert(!strbuf_overrun(content_postamble));
  int content_length = strbuf_len(content_preamble)
		     + r->cursor->buffer_offset_bytes
		     + r->cursor->buffer_used
		     + strbuf_len(content_postamble);
  strbuf request = strbuf_local(buffer, sizeof buffer);
  strbuf_sprintf(request,
      "POST /rhizome/enquiry HTTP/1.0\r\n"
      "Content-Length: %d\r\n"
      "Content-Type: multipart/form-data; boundary=%s\r\n"
      "\r\n%s",
      content_length, boundary, strbuf_str(content_preamble)
    );
  assert(!strbuf_overrun(request));

  /* TODO: Refactor this code so that it uses our asynchronous framework.
   */
  int len = strbuf_len(request);
  int sent=0;
  while(sent<len) {
    DEBUGF("write(%d, %s, %d)", sock, alloca_toprint(-1, &buffer[sent], len-sent), len-sent);
    int count=write(sock,&buffer[sent],len-sent);
    if (count == -1) {
      if (errno==EPIPE) goto rx;
      WHYF_perror("write(%d)", len - sent);
      close(sock);
      goto end;
    }
    sent+=count;
  }

  len=r->cursor->buffer_offset_bytes+r->cursor->buffer_used;
  sent=0;
  while(sent<len) {
    DEBUGF("write(%d, %s, %d)", sock, alloca_toprint(-1, (const char*)&r->cursor->buffer[sent], len-sent), len-sent);
    int count=write(sock,&r->cursor->buffer[sent],len-sent);
    if (count == -1) {
      if (errno == EPIPE)
	goto rx;
      WHYF_perror("write(%d)", count);
      close(sock);
      goto end;
    }
    sent+=count;
  }

  strbuf_reset(request);
  strbuf_puts(request, strbuf_str(content_postamble));
  len = strbuf_len(request);
  sent=0;
  while(sent<len) {
    DEBUGF("write(%d, %s, %d)", sock, alloca_toprint(-1, &buffer[sent], len-sent), len-sent);
    int count=write(sock,&buffer[sent],len-sent);
    if (count == -1) {
      if (errno==EPIPE) goto rx;
      WHYF_perror("write(%d)", len - sent);
      close(sock);
      goto end;
    }
    sent+=count;
  }

 rx:
  /* request sent, now get response back. */
  buffer[0]=0; len=0;
  while(!http_header_complete(buffer,len,len)&&(len<8192))
    {
      int count=read(sock,&buffer[len],8192-len);
      if (count==0) break;
      if (count == -1) {
	WHYF_perror("read(%d)", 8192-len);
	close(sock);
	goto end;
      }
      len+=count;
      if (len>=8000) {
	DEBUGF("reply header too long");
	close(sock);
	goto end;
      }
    }

  DEBUGF("Got HTTP header");
  dump("reply",(unsigned char *)buffer,len);

  char *p = NULL;
  if (!str_startswith(buffer, "HTTP/1.0 ", &p)) {
    DEBUGF("Malformed HTTP reply: missing HTTP/1.0 preamble");
    close(sock); goto end;
  }
  int http_response_code = 0;
  char *nump;
  for (nump = p; isdigit(*p); ++p)
    http_response_code = http_response_code * 10 + *p - '0';
  if (p == nump || *p != ' ') {
      DEBUGF("Malformed HTTP reply: missing decimal status code");
    close(sock); goto end;
  }
  if (http_response_code != 200) {
    DEBUGF("Failed HTTP request: rhizome server returned %d != 200 OK", http_response_code);
    close(sock); goto end;
  }
  // This loop will terminate, because http_header_complete() above found at least
  // "\n\n" at the end of the header, and probably "\r\n\r\n".
  while (*p++ != '\n')
    ;
  // Iterate over header lines until the last blank line.
  while (*p != '\r' && *p != '\n') {
    if (strcase_startswith(p, "Content-Length:", &p)) {
      while (*p == ' ')
	++p;
      content_length = 0;
      for (nump = p; isdigit(*p); ++p)
	content_length = content_length * 10 + *p - '0';
      if (p == nump || (*p != '\r' && *p != '\n')) {
	DEBUGF("Invalid HTTP reply: malformed Content-Length header");
	close(sock); goto end;	
      }
    }
    while (*p++ != '\n')
      ;
  }
  if (*p == '\r')
    ++p;
  ++p; // skip '\n' at end of blank line
  if (content_length == -1) {
    DEBUGF("Invalid HTTP reply: missing Content-Length header");
    close(sock); goto end;
  }

  DEBUGF("content_length=%d",content_length);
  dump("response",(unsigned char *)p,content_length);

  /* We now have the list of (1+RHIZOME_BAR_PREFIX_BYTES)-byte records that indicate
     the list of BAR prefixes that differ between the two nodes.  We can now action
     those which are relevant, i.e., based on whether we are pushing, pulling or 
     synchronising (both).

     I am currently undecided as to whether it is cleaner to have some general
     rhizome direct function for doing that, or whether it just adds unnecessary
     complication, and the responses should just be handled in here.

     For now, I am just going to implement it in here, and we can generalise later.
  */
  DEBUGF("XXX Need to parse responses into actions");
  int i;
  for(i=10;i<content_length;i+=(1+RHIZOME_BAR_PREFIX_BYTES))
    {
      int type=p[i];
      // unsigned char *bid_prefix=(unsigned char *)&p[i+1];
      unsigned long long 
	bid_prefix_ll=rhizome_bar_bidprefix_ll((unsigned char *)&p[i+1]);
      DEBUGF("%s %016llx*",type==1?"push":"pull",bid_prefix_ll);
      if (type==2&&r->pullP) {
	WARN("XXX Rhizome direct http pull yet implemented");
	/* Need to fetch manifest.  Once we have the manifest, then we can
	   use our normal bundle fetch routines from rhizome_fetch.c	 

	   Generate a request like: GET /rhizome/manifestbybar/<hex of bar>
	   and add it to our list of HTTP fetch requests, then watch
	   until the request is finished.  That will give us the manifest.
	   Then as noted above, we can use that to pull the file down using
	   existing routines.
	*/
	if (!rhizome_fetch_request_manifest_by_prefix
	    (&addr,(unsigned char *)&p[i+1],RHIZOME_BAR_PREFIX_BYTES,
	     1 /* import, getting file if needed */))
	  {
	    /* Fetching the manifest, and then using it to see if we want to 
	       fetch the file for import is all handled asynchronously, so just
	       wait for it to finish. */
	    while(rhizome_file_fetch_queue_count) fd_poll();
	  }
	
      } else if (type==1&&r->pushP) {
	/* Form up the POST request to submit the appropriate bundle. */

	/* Start by getting the manifest, which is the main thing we need, and also
	   gives us the information we need for sending any associated file. */
	rhizome_manifest 
	  *m=rhizome_direct_get_manifest((unsigned char *)&p[i+1],
					 RHIZOME_BAR_PREFIX_BYTES);
	if (!m) {
	  WHY("This should never happen.  The manifest exists, but when I went looking for it, it doesn't appear to be there.");
	  goto next_item;
	}

	/* Get filehash and size from manifest if present */
	const char *id = rhizome_manifest_get(m, "id", NULL, 0);
	DEBUGF("bundle id = '%s'",id);
	const char *hash = rhizome_manifest_get(m, "filehash", NULL, 0);
	DEBUGF("bundle file hash = '%s'",hash);
	long long filesize = rhizome_manifest_get_ll(m, "filesize");
	DEBUGF("file size = %lld",filesize);

	/* We now have everything we need to compose the POST request and send it.
	 */
	char *template="POST /rhizome/import HTTP/1.0\r\n"
	  "Content-Length: %d\r\n"
	  "Content-Type: multipart/form-data; boundary=%s\r\n"
	  "\r\n";
	char *template2="--%s\r\n"
	  "Content-Disposition: form-data; name=\"manifest\"; filename=\"m\"\r\n"
	  "Content-Type: application/octet-stream\r\n"
	  "\r\n";
	char *template3=
	  "\r\n--%s\r\n"
	  "Content-Disposition: form-data; name=\"data\"; filename=\"d\"\r\n"
	  "Content-Type: application/octet-stream\r\n"
	  "\r\n";
	/* Work out what the content length should be */
	DEBUGF("manifest_all_bytes=%d, manifest_bytes=%d",
	       m->manifest_all_bytes,m->manifest_bytes);
	int content_length
	  =strlen(template2)-2 /* minus 2 for the "%s" that gets replaced */
	  +strlen(boundary)
	  +m->manifest_all_bytes
	  +strlen(template3)-2 /* minus 2 for the "%s" that gets replaced */
	  +strlen(boundary)
	  +filesize
	  +strlen("\r\n--")+strlen(boundary)+strlen("--\r\n");

	/* XXX For some reason the above is four bytes out, so fix that */
	content_length+=4;

	int len=snprintf(buffer,8192,template,content_length,boundary);
	len+=snprintf(&buffer[len],8192-len,template2,boundary);
	memcpy(&buffer[len],m->manifestdata,m->manifest_all_bytes);
	len+=m->manifest_all_bytes;
	len+=snprintf(&buffer[len],8192-len,template3,boundary);

	addr.sin_family = AF_INET;     
	addr.sin_port = htons(state->port);   
	addr.sin_addr = *((struct in_addr *)hostent->h_addr);
	bzero(&(addr.sin_zero),8);     
	
	sock=socket(AF_INET, SOCK_STREAM, 0);
	if (sock==-1) {
	  DEBUGF("could not open socket");    
	  goto closeit;
	} 
	if (connect(sock,(struct sockaddr *)&addr,sizeof(struct sockaddr)) == -1)
	  {
	    DEBUGF("Could not connect to remote");
	    goto closeit;
	  }

	int sent=0;
	/* Send buffer now */
	while(sent<len) {
	  DEBUGF("write(%d, %s, %d)", sock, alloca_toprint(-1, &buffer[sent], len-sent), len-sent);
	  int r=write(sock,&buffer[sent],len-sent);
	  if (r>0) sent+=r;
	  if (r<0) goto closeit;
	}

	/* send file contents now */
	long long rowid = -1;
	sqlite3_blob *blob=NULL;
	sqlite_exec_int64(&rowid, "select rowid from files where id='%s';", hash);
	DEBUGF("Reading from rowid #%d filehash='%s'",rowid,hash?hash:"(null)");
	if (rowid >= 0 && sqlite3_blob_open(rhizome_db, "main", "files", "data", 
					    rowid, 0, &blob) != SQLITE_OK)
	  goto closeit;
	int i;
	for(i=0;i<filesize;)
	  {
	    int count=4096;
	    if (filesize-i<count) count=filesize-i;
	    unsigned char buffer[4096];
	    DEBUGF("reading %d bytes @ %d from blob",count,i);
	    int sr=sqlite3_blob_read(blob,buffer,count,i);
	    if (sr==SQLITE_OK||sr==SQLITE_DONE)
	      {
		DEBUGF("write(%d, %s, %d)", sock, alloca_toprint(-1, (char *)buffer, count), count);
		count=write(sock,buffer,count);
		if (count<0) {
		  WHY_perror("write");
		  sqlite3_blob_close(blob);
		  goto closeit;
		} else { 
		  i+=count;
		  DEBUGF("Wrote %d bytes of file",count);
		}
	      } else {
	      WHYF("sqlite error #%d occurred reading from the blob: %s",sr, sqlite3_errmsg(rhizome_db));
	      sqlite3_blob_close(blob);
	      goto closeit;
	    }

	  }

	/* Send final mime boundary */
	len=snprintf(buffer,8192,"\r\n--%s--\r\n",boundary);
	sent=0;
	while(sent<len) {
	  DEBUGF("write(%d, %s, %d)", sock, alloca_toprint(-1, &buffer[sent], len-sent), len-sent);
	  int r=write(sock,&buffer[sent],len-sent);
	  if (r>0) sent+=r;
	  if (r<0) goto closeit;
	}	

	/* send buffer now */
	DEBUGF("XXX check HTTP response");

      closeit:
	close(sock);

	if (m) rhizome_manifest_free(m);
      }
    next_item:
      continue;
    }

  /* now update cursor according to what range was covered in the response.
     We set our current position to just past the high limit of the returned
     cursor.

     XXX - This introduces potential problems with the returned cursor range.
     If the far end returns an earlier cursor position than we are in, we could
     end up in an infinite loop.  We could also end up in a very long finite loop
     if the cursor doesn't advance far.  A simple solution is to not adjust the
     cursor position, and simply re-attempt the sync until no actions result.
     That will do for now.     
 */
#ifdef FANCY_CURSOR_POSITION_HANDLING
  rhizome_direct_bundle_cursor *c=rhizome_direct_bundle_iterator(10);
  assert(c!=NULL);
  if (rhizome_direct_bundle_iterator_unpickle_range(c,(unsigned char *)&p[0],10))
    {
      DEBUGF("Couldn't unpickle range. This should never happen.  Assuming near and far cursor ranges match.");
    }
  else {
    DEBUGF("unpickled size_high=%lld, limit_size_high=%lld",
	   c->size_high,c->limit_size_high);
    DEBUGF("c->buffer_size=%d",c->buffer_size);
    r->cursor->size_low=c->limit_size_high;
    bcopy(c->limit_bid_high,r->cursor->bid_low,4);
    /* Set tail of BID to all high, as we assume the far end has returned all
       BIDs with the specified prefix. */
    memset(&r->cursor->bid_low[4],0xff,RHIZOME_MANIFEST_ID_BYTES);
  }
  rhizome_direct_bundle_iterator_free(&c);
#endif

  end:
  /* Warning: tail recursion when done this way. 
     Should be triggered by an asynchronous event.
     But this will do for now. */
  rhizome_direct_continue_sync_request(r);
}
