/*
Serval DNA Rhizome HTTP external interface
Copyright (C) 2013,2014 Serval Project Inc.
 
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
#include "conf.h"
#include "httpd.h"
#include "str.h"
#include "strbuf.h"

DECLARE_HANDLER("/rhizome/status", rhizome_status_page);
DECLARE_HANDLER("/rhizome/file/", rhizome_file_page);
DECLARE_HANDLER("/rhizome/manifestbyprefix/", manifest_by_prefix_page);

static int rhizome_file_page(httpd_request *r, const char *remainder)
{
  /* Stream the specified payload */
  if (!is_rhizome_http_enabled())
    return 403;
  if (r->http.verb != HTTP_VERB_GET)
    return 405;
  if (r->http.request_header.content_range_count > 1) {
    // To support byte range sets, eg, Range: bytes=0-100,200-300,400- we would have
    // to reply with a multipart/byteranges MIME content.
    http_request_simple_response(&r->http, 501, "Not Implemented: Byte range sets");
    return 1;
  }
  rhizome_filehash_t filehash;
  if (str_to_rhizome_filehash_t(&filehash, remainder) == -1)
    return 1;
  int ret = rhizome_response_content_init_filehash(r, &filehash);
  if (ret)
    return ret;
  http_request_response_generated(&r->http, 200, CONTENT_TYPE_BLOB, rhizome_payload_content);
  return 1;
}

static int manifest_by_prefix_page(httpd_request *r, const char *remainder)
{
  if (!is_rhizome_http_enabled())
    return 403;
  if (r->http.verb != HTTP_VERB_GET)
    return 405;
  rhizome_bid_t prefix;
  const char *endp = NULL;
  unsigned prefix_len = strn_fromhex(prefix.binary, sizeof prefix.binary, remainder, &endp);
  if (endp == NULL || *endp != '\0' || prefix_len < 1)
    return 404; // not found
  if ((r->manifest = rhizome_new_manifest()) == NULL)
    return 500;
  switch(rhizome_retrieve_manifest_by_prefix(prefix.binary, prefix_len, r->manifest)){
    case RHIZOME_BUNDLE_STATUS_SAME:
      http_request_response_static(&r->http, 200, CONTENT_TYPE_BLOB, (const char *)r->manifest->manifestdata, r->manifest->manifest_all_bytes);
      return 1;
    case RHIZOME_BUNDLE_STATUS_NEW:
      return 404;
    default:
      return 500;
  }
}

static int rhizome_status_page(httpd_request *r, const char *remainder)
{
  if (!is_rhizome_http_enabled())
    return 403;
  if (*remainder)
    return 404;
  if (r->http.verb != HTTP_VERB_GET)
    return 405;
  char buf[32*1024];
  strbuf b = strbuf_local_buf(buf);
  strbuf_puts(b, "<html><head><meta http-equiv=\"refresh\" content=\"5\" ></head><body>");
  strbuf_sprintf(b, "%d HTTP requests<br>", current_httpd_request_count);
  strbuf_sprintf(b, "%d Bundles transferring via MDP<br>", rhizome_cache_count());
  rhizome_fetch_status_html(b);
  strbuf_puts(b, "</body></html>");
  if (strbuf_overrun(b))
    return -1;
  http_request_response_static(&r->http, 200, CONTENT_TYPE_HTML, buf, strbuf_len(b));
  return 1;
}
