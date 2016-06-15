
#include "serval.h"
#include "httpd.h"
#include "conf.h"
#include "overlay_address.h"
#include "overlay_interface.h"
#include "os.h"
#include "route_link.h"

DECLARE_HANDLER("/static/", static_page);
DECLARE_HANDLER("/interface/", interface_page);
DECLARE_HANDLER("/neighbour/", neighbour_page);
DECLARE_HANDLER("/favicon.ico", fav_icon_header);
DECLARE_HANDLER("/", root_page);


static int root_page(httpd_request *r, const char *remainder)
{
  if (*remainder)
    return 404;
  if (r->http.verb != HTTP_VERB_GET)
    return 405;
  char temp[8192];
  strbuf b = strbuf_local_buf(temp);
  strbuf_sprintf(b, "<html><head><meta http-equiv=\"refresh\" content=\"5\" ></head><body>"
	   "<h1>Hello, I'm %s*</h1>",
	   alloca_tohex_sid_t_trunc(get_my_subscriber()->sid, 16));
  if (config.server.motd[0]) {
      strbuf_puts(b, "<p>");
      strbuf_html_escape(b, config.server.motd, strlen(config.server.motd));
      strbuf_puts(b, "</p>");
  }
  strbuf_puts(b, "Interfaces;<br />");
  int i;
  for (i=0;i<OVERLAY_MAX_INTERFACES;i++){
    if (overlay_interfaces[i].state==INTERFACE_STATE_UP)
      strbuf_sprintf(b, "<a href=\"/interface/%d\">%d: %s, TX: %d, RX: %d</a><br />",
	i, i, overlay_interfaces[i].name, overlay_interfaces[i].tx_count, overlay_interfaces[i].recv_count);
  }
  strbuf_puts(b, "Neighbours;<br />");
  link_neighbour_short_status_html(b, "/neighbour");
  if (is_rhizome_http_enabled()){
    strbuf_puts(b, "<a href=\"/rhizome/status\">Rhizome Status</a><br />");
  }
  strbuf_puts(b, "</body></html>");
  if (strbuf_overrun(b)) {
    WHY("HTTP Root page buffer overrun");
    return 500;
  }
  http_request_response_static(&r->http, 200, CONTENT_TYPE_HTML, temp, strbuf_len(b));
  return 1;
}

static int fav_icon_header(httpd_request *r, const char *remainder)
{
  if (*remainder)
    return 404;
  http_request_response_static(&r->http, 200, "image/vnd.microsoft.icon", (const char *)favicon_bytes, favicon_len);
  return 1;
}

static int neighbour_page(httpd_request *r, const char *remainder)
{
  if (r->http.verb != HTTP_VERB_GET)
    return 405;
  char buf[8*1024];
  strbuf b = strbuf_local_buf(buf);
  sid_t neighbour_sid;
  if (str_to_sid_t(&neighbour_sid, remainder) == -1)
    return 404;
  struct subscriber *neighbour = find_subscriber(neighbour_sid.binary, sizeof(neighbour_sid.binary), 0);
  if (!neighbour)
    return 404;
  strbuf_puts(b, "<html><head><meta http-equiv=\"refresh\" content=\"5\" ></head><body>");
  link_neighbour_status_html(b, neighbour);
  strbuf_puts(b, "</body></html>");
  if (strbuf_overrun(b))
    return -1;
  http_request_response_static(&r->http, 200, CONTENT_TYPE_HTML, buf, strbuf_len(b));
  return 1;
}

static int interface_page(httpd_request *r, const char *remainder)
{
  if (r->http.verb != HTTP_VERB_GET)
    return 405;
  char buf[8*1024];
  strbuf b=strbuf_local_buf(buf);
  int index=atoi(remainder);
  if (index<0 || index>=OVERLAY_MAX_INTERFACES)
    return 404;
  strbuf_puts(b, "<html><head><meta http-equiv=\"refresh\" content=\"5\" ></head><body>");
  interface_state_html(b, &overlay_interfaces[index]);
  strbuf_puts(b, "</body></html>");
  if (strbuf_overrun(b))
    return -1;
  http_request_response_static(&r->http, 200, CONTENT_TYPE_HTML, buf, strbuf_len(b));
  return 1;
}


static int static_file_generator(struct http_request *hr, unsigned char *buf, size_t bufsz, struct http_content_generator_result *result)
{
  struct httpd_request *r=(struct httpd_request *)hr;
  uint64_t remain = r->http.response.header.content_length + r->http.response.header.content_range_start - r->u.file.offset;
  if (bufsz < remain)
    remain = bufsz;
  ssize_t bytes = read(r->u.file.fd, buf, remain);
  if (bytes == -1)
    return -1;
  r->u.file.offset+=bytes;
  result->generated = bytes;
  return (r->u.file.offset >= r->http.response.header.content_length + r->http.response.header.content_range_start)?0:1;
}

static void finalise_union_close_file(httpd_request *r)
{
  if (r->u.file.fd==-1)
    return;
  close(r->u.file.fd);
  r->u.file.fd=-1;
}

static int static_page(httpd_request *r, const char *remainder)
{
  if (r->http.verb != HTTP_VERB_GET)
    return 405;
  char path[PATH_MAX];
  
  if (!*remainder)
    remainder="index.html";
  if (FORMF_SERVAL_ETC_PATH(path, "static/%s", remainder)==0)
    return 500;
  struct stat stat;
  if (lstat(path, &stat))
    return 404;
  
  r->u.file.fd = open(path, O_RDONLY);
  if (r->u.file.fd==-1)
    return 404;
  
  r->finalise_union=finalise_union_close_file;
  
  // TODO find extension and set content type properly
  http_response_init_content_range(r, stat.st_size);
  if (r->http.response.header.content_range_start){
    if (lseek64(r->u.file.fd, r->http.response.header.content_range_start, SEEK_SET)){
      WARNF_perror("lseek(%s)", path);
      return 500;
    }
  }
  r->u.file.offset=r->http.response.header.content_range_start;
  http_request_response_generated(&r->http, 200, CONTENT_TYPE_HTML, static_file_generator);
  return 1;
}
