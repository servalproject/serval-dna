/*
Serval DNA Rhizome HTTP interface
Copyright (C) 2013-2014 Serval Project Inc.
 
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

#ifndef __SERVAL_DNA__HTTPD_H
#define __SERVAL_DNA__HTTPD_H

#include "rhizome.h"
#include "keyring.h"
#include "meshms.h"
#include "http_server.h"

int is_httpd_server_running();

#define HTTPD_PORT 4110
#define HTTPD_PORT_MAX 4210

extern uint16_t httpd_server_port;
extern unsigned int current_httpd_request_count;

enum list_phase { LIST_HEADER = 0, LIST_FIRST, LIST_ROWS, LIST_END, LIST_DONE };

struct form_buf_malloc {
  char *buffer;
  size_t size_limit; // == 0 means no limit
  size_t buffer_alloc_size;
  size_t length;
};

struct httpd_request;

int form_buf_malloc_init(struct form_buf_malloc *, size_t size_limit);
int form_buf_malloc_accumulate(struct httpd_request *, const char *partname, struct form_buf_malloc *, const char *, size_t);
void form_buf_malloc_release(struct form_buf_malloc *);

typedef struct httpd_request
{
  struct http_request http; // MUST BE FIRST ELEMENT

  /* Doubly-linked list of current requests.  Used to pass triggers to requests.
   */
  struct httpd_request *next;
  struct httpd_request *prev;

  /* For requests/responses that pertain to a single manifest.
   */
  rhizome_manifest *manifest;
  enum rhizome_payload_status payload_status;
  enum rhizome_bundle_status bundle_status;

  /* For requests/responses that contain one or two SIDs.
   */
  sid_t sid1;
  sid_t sid2;

  /* For requests/responses that contain a Rhizome Bundle ID.
   */
  rhizome_bid_t bid;

  /* For requests/responses that contain a 64-bit unsigned integer (eg, SQLite ROWID, byte offset).
   */
  uint64_t ui64;

  /* Trigger function for Rhizome bundle added.
   */
  void (*trigger_rhizome_bundle_added)(struct httpd_request *, rhizome_manifest *);

  /* Finaliser for union contents (below).
   */
  void (*finalise_union)(struct httpd_request *);

  /* Mutually exclusive response arguments.
   */
  union {

    /* For receiving Rhizome Direct import request
     */
    struct {
      // Which part is currently being received
      const char *current_part;
      // Temporary file currently current part is being written to
      int part_fd;
      // Which parts have already been received
      bool_t received_manifest;
      bool_t received_data;
      // Name of data file supplied in part's Content-Disposition header, filename
      // parameter (if any)
      char data_file_name[MIME_FILENAME_MAXLEN + 1];
    }
      direct_import;

    /* For receiving RESTful Rhizome insert request
     */
    struct {
      // If this is really a (journal) append request
      bool_t appending;
      // Which part is currently being received
      const char *current_part;
      // Which parts have already been received
      bool_t received_author;
      bool_t received_secret;
      bool_t received_bundleid;
      bool_t received_manifest;
      bool_t received_payload;
      // For storing the "bundle-author" hex SID as we receive it
      char author_hex[SID_STRLEN];
      size_t author_hex_len;
      sid_t author;
      // For storing the "bundle-secret" hex as we receive it
      char secret_text[RHIZOME_BUNDLE_SECRET_MAX_STRLEN];
      size_t secret_text_len;
      rhizome_bk_t bundle_secret;
      // For storing the "bundle-id" hex as we receive it
      char bid_text[RHIZOME_BUNDLE_ID_STRLEN];
      size_t bid_text_len;
      // The "force-new" parameter
      char force_new_text[5]; // enough for "false"
      size_t force_new_text_len;
      bool_t force_new;
      // For storing the manifest text (malloc/realloc) as we receive it
      struct form_buf_malloc manifest;
      // For receiving the payload
      uint64_t payload_size;
      struct rhizome_write write;
    }
      insert;

    /* For responses that send part or all of a payload.
    */
    struct rhizome_read read_state;

    /* For responses that list SIDs.
    */
    struct {
      enum list_phase phase;
      keyring_iterator it;
    }
      sidlist;

    /* For responses that list manifests.
    */
    struct {
      enum list_phase phase;
      uint64_t rowid_highest;
      size_t rowcount;
      time_ms_t end_time;
      struct rhizome_list_cursor cursor;
    }
      rhlist;

    /* For responses that list MeshMS conversations.
    */
    struct {
      enum list_phase phase;
      size_t rowcount;
      struct meshms_conversations *conv;
      struct meshms_conversation_iterator iter;
    }
      mclist;

    /* For responses that list MeshMS messages in a single conversation.
    */
    struct {
      struct newsince_position {
        enum meshms_which_ply which_ply;
        uint64_t offset;
      }
        token,
        current,
        latest;
      time_ms_t end_time;
      uint64_t highest_ack_offset;
      enum list_phase phase;
      size_t rowcount;
      struct meshms_message_iterator iter;
      unsigned dirty;
      int finished;
    }
      msglist;

    /* For responses that send a MeshMS message.
    */
    struct {
      // Which part is currently being received
      const char *current_part;
      // Which parts have already been received
      bool_t received_message;
      // The text of the message to send
      struct form_buf_malloc message;
    }
      sendmsg;
      
    
    struct {
      int fd;
      size_t offset;
    }
      file;
  } u;

} httpd_request;

int httpd_server_start(uint16_t port_low, uint16_t port_high);

typedef int HTTP_HANDLER(httpd_request *r, const char *remainder);

struct http_handler {
  const char *path;
  HTTP_HANDLER *parser;
};

DECLARE_SECTION(struct http_handler, httpd);

#define DECLARE_HANDLER(PATH, FUNC) \
  static HTTP_HANDLER FUNC;\
  static struct http_handler __##FUNC IN_SECTION(httpd) = {\
    .path=PATH,\
    .parser=FUNC\
  }

int is_http_header_complete(const char *buf, size_t len, size_t read_since_last_call);
int authorize_restful(struct http_request *r);
int http_response_content_type(httpd_request *r, const char *what, const struct mime_content_type *ct);
int http_response_content_disposition(httpd_request *r, const char *what, const char *type);
int http_response_form_part(httpd_request *r, const char *what, const char *partname, const char *text, size_t textlen);
int http_response_init_content_range(httpd_request *r, size_t resource_length);
int accumulate_text(httpd_request *r, const char *partname, char *textbuf, size_t textsiz, size_t *textlenp, const char *buf, size_t len);

int rhizome_response_content_init_filehash(httpd_request *r, const rhizome_filehash_t *hash);
int rhizome_response_content_init_payload(httpd_request *r, rhizome_manifest *);
HTTP_CONTENT_GENERATOR rhizome_payload_content;

struct http_response_parts {
  uint16_t code;
  char *reason;
  uint64_t range_start;
  uint64_t content_length;
  char *content_start;
};

#define HTTP_RESPONSE_CONTENT_LENGTH_UNSET UINT64_MAX

int unpack_http_response(char *response, struct http_response_parts *parts);

#endif // __SERVAL_DNA__HTTPD_H
