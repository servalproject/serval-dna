/*
Serval Distributed Numbering Architecture (DNA)
Copyright (C) 2013 Paul Gardner-Stephen
Copyright (C) 2013 Alexandra Sclapari

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
#include "log.h"
#include "conf.h"

rhizome_manifest *meshms_find_or_create_manifestid
(const char *sender_sid_hex,const char *recipient_sid_hex)
{
  sid_t authorSid;
  if (str_to_sid_t(&authorSid, sender_sid_hex)==-1)
    { WHYF("invalid sender_sid: %s", sender_sid_hex); return NULL; }

  // Get manifest structure to hold the manifest we find or create
  rhizome_manifest *m = rhizome_new_manifest();
  if (!m) {
    WHY("Manifest struct could not be allocated -- not added to rhizome"); 
    return NULL;
  }

  // Check if there is an existing one, if so, read it and return it.
  char manifestid_hex[RHIZOME_MANIFEST_ID_STRLEN+1];
  if (!rhizome_meshms_find_conversation(sender_sid_hex, recipient_sid_hex, 
					manifestid_hex,
					0 /* get first matching manifestid */)) {
    // Found manifest, so nothing more to do right now.
    int ret = rhizome_retrieve_manifest(manifestid_hex, m);
    if (!ret) {
      rhizome_find_bundle_author(m);
      return m; 
    }
    else {
      WHYF("rhizome_retreive_manifest(%s) failed",manifestid_hex);
      rhizome_manifest_free(m);
      return NULL;
    }
  } 

  // No existing manifest, so create one:

  // Populate with the fields we know
  rhizome_manifest_set(m, "service", RHIZOME_SERVICE_MESHMS);
  rhizome_manifest_set(m,"sender",sender_sid_hex);
  rhizome_manifest_set(m,"recipient",recipient_sid_hex);

  // Ask rhizome to prepare the missing parts (this will automatically determine
  // whether to encrypt based on whether receipient was set to broadcast or not)
  if (rhizome_fill_manifest(m,NULL,&authorSid,NULL)) {
    WHY("rhizome_fill_manifest() failed");
      rhizome_manifest_free(m);
      return NULL;
  }

  return m;
}

// meshms add message <sender SID> <recipient SID> <sender DID> <recipient DID> <message text>
int app_meshms_add_message(const struct cli_parsed *parsed, void *context)
{
 int ret = 0;
 
 if (create_serval_instance_dir() == -1)
   return -1;
 if (!(keyring = keyring_open_instance_cli(parsed)))
   return -1;
 if (rhizome_opendb() == -1)
   return -1; 

 if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
 //sender_sid = author_sid
 const char *sender_did, *recipient_did, *payload, *sender_sid, *recipient_sid;

 // Parse mandatory arguments
 cli_arg(parsed, "sender_sid", &sender_sid, cli_optional_sid, "");
 cli_arg(parsed, "recipient_sid", &recipient_sid, cli_optional_sid, "");
 cli_arg(parsed, "sender_did", &sender_did, cli_optional_did, "");
 cli_arg(parsed, "recipient_did", &recipient_did, cli_optional_did, "");
 cli_arg(parsed, "payload", &payload, NULL, "");
 // Sanity check passed arguments
 if ( (strcmp(sender_did,"") == 0) || (strcmp(recipient_did,"") == 0) || (strcmp(sender_sid,"") == 0) || (strcmp(recipient_sid,"" ) == 0) )
   { 
     cli_puts("One or more missing arguments"); cli_delim("\n");
   } 
 sid_t aSid;
 if (sender_sid[0] && str_to_sid_t(&aSid, sender_sid) == -1)
   return WHYF("invalid sender_sid: %s", sender_sid);
 if (recipient_sid[0] && str_to_sid_t(&aSid, recipient_sid) == -1)
   return WHYF("invalid recipient_sid: %s", recipient_sid);

 // Parse optional arguments
 const char *name, *offset, *limit;
 cli_arg(parsed, "name", &name, NULL, "");
 cli_arg(parsed, "offset", &offset, cli_uint, "0");
 cli_arg(parsed, "limit", &limit, cli_uint, "0");

 // Create serialised meshms message for appending to the conversation ply
 unsigned int length_int = 1;
 int offset_buf=0;
 unsigned long long send_date_ll=gettime_ms();
 unsigned char *buffer_serialize;
 buffer_serialize=malloc(strlen(payload)+100); // make sure we have plenty of space
 
 // encode twice: first to work out the final length, then once more to write it correctly
 ret = serialize_meshms(buffer_serialize,&offset_buf,length_int,sender_did, recipient_did, send_date_ll, payload, strlen(payload)+1);
 while(length_int!=offset_buf) {
   length_int=offset_buf;
   offset_buf=0;
   ret = serialize_meshms(buffer_serialize,&offset_buf,length_int,sender_did, recipient_did, send_date_ll, payload, strlen(payload)+1);
 }
 
 // Find the manifest (or create it if it doesn't yet exist)
 rhizome_manifest *m=meshms_find_or_create_manifestid(sender_sid,recipient_sid);
 if (!m) return -1;
 
 // Read the bundle file containing the meshms messages
 // (and keep enough space to append the new message
 unsigned char *buffer_file=malloc(m->fileLength+length_int);  
 if (!buffer_file) {
   WHYF("malloc(%d) failed when reading existing MeshMS log.",m->fileLength);
   rhizome_manifest_free(m);
   return -1;
 }
 ret = meshms_read_message(m,buffer_file);
 if (ret) {
   WHYF("meshms_read_message() failed.");
   rhizome_manifest_free(m);
   return -1;   
 }
 // Append the serialised message, and update file length
 bcopy(buffer_serialize,&buffer_file[m->fileLength],length_int);
 m->fileLength += length_int;
 // MeshMS bundles are journalled, so filesize and version are synonymous
 rhizome_manifest_set_ll(m, "filesize", m->fileLength);  
 rhizome_manifest_set_ll(m,"version",m->fileLength);
 // Write enlarged message log to bundle
 rhizome_add_file(m,(char *)buffer_file,1,m->fileLength);

 free(buffer_file); 
 free(buffer_serialize);
 
 rhizome_manifest *mout = NULL;
 ret=rhizome_manifest_finalise(m,&mout);
 if (ret<0){
   cli_printf("Error in manifest finalise");
   rhizome_manifest_free(m);
   if (mout&&mout!=m) rhizome_manifest_free(mout);
   return -1;
 } 
  
 {
   char bid[RHIZOME_MANIFEST_ID_STRLEN + 1];
   rhizome_bytes_to_hex_upper(mout->cryptoSignPublic, bid, RHIZOME_MANIFEST_ID_BYTES);
   cli_puts("manifestid");
   cli_delim(":");
   cli_puts(bid);
   cli_delim("\n");
 }
 {
   char secret[RHIZOME_BUNDLE_KEY_STRLEN + 1];
   rhizome_bytes_to_hex_upper(mout->cryptoSignSecret, secret, RHIZOME_BUNDLE_KEY_BYTES);
   cli_puts("secret");
   cli_delim(":");
   cli_puts(secret);
   cli_delim("\n");
 }
 cli_puts("version");    cli_delim(":"); cli_printf("%lld", m->version);    cli_delim("\n");
 cli_puts("filesize");
 cli_delim(":");
 cli_printf("%lld", mout->fileLength);
 cli_delim("\n");
 if (mout->fileLength != 0) {
   cli_puts("filehash");
   cli_delim(":");
   cli_puts(mout->fileHexHash);
   cli_delim("\n");
 }
 const char *name_manifest = rhizome_manifest_get(mout, "name", NULL, 0);
 if (name_manifest) {
   cli_puts("name");
   cli_delim(":");
   cli_puts(name_manifest);
   cli_delim("\n");
 }
 
 if (mout != m)
   rhizome_manifest_free(mout);
 rhizome_manifest_free(m); 
 
  return ret ; 
}

int app_meshms_read_messagelog(const struct cli_parsed *parsed, void *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  
  int ret;
  const char *manifestid=NULL;
  
  if (cli_arg(parsed, "manifestid", &manifestid, cli_manifestid, "") == -1 )
     return -1;
  
  if (create_serval_instance_dir() == -1)
   return -1;
  if (!(keyring = keyring_open_instance_cli(parsed)))
   return -1;
  if (rhizome_opendb() == -1)
   return -1; 
  
  ret=0;
  
  unsigned char manifest_id[RHIZOME_MANIFEST_ID_BYTES];
  if (fromhexstr(manifest_id, manifestid, RHIZOME_MANIFEST_ID_BYTES) == -1)
    return WHY("Invalid manifest ID");
  
  char manifestIdUpper[RHIZOME_MANIFEST_ID_STRLEN + 1];
  tohex(manifestIdUpper, manifest_id, RHIZOME_MANIFEST_ID_BYTES);
 
  rhizome_manifest *m = rhizome_new_manifest();
  if (!m)
   return WHY("Manifest struct could not be allocated -- not added to rhizome"); 
    
  ret = rhizome_retrieve_manifest(manifestIdUpper, m);
  
  if (ret==0){
    // ignore errors
    rhizome_extract_privatekey(m, NULL);
    const char *blob_service = rhizome_manifest_get(m, "service", NULL, 0);
    cli_puts("service");    cli_delim(":"); cli_puts(blob_service); cli_delim("\n");
    cli_puts("manifestid"); cli_delim(":"); cli_puts(manifestIdUpper); cli_delim("\n");
    cli_puts("version");    cli_delim(":"); cli_printf("%lld", m->version); cli_delim("\n");
    cli_puts("inserttime"); cli_delim(":"); cli_printf("%lld", m->inserttime); cli_delim("\n");
    if (m->haveSecret) {
      cli_puts(".author");  cli_delim(":"); cli_puts(alloca_tohex_sid(m->author)); cli_delim("\n");
    }
    cli_puts(".readonly");  cli_delim(":"); cli_printf("%d", m->haveSecret?0:1); cli_delim("\n");
    cli_puts("filesize");   cli_delim(":"); cli_printf("%lld", (long long) m->fileLength); cli_delim("\n");
    if (m->fileLength != 0) {
      cli_puts("filehash"); cli_delim(":"); cli_puts(m->fileHexHash); cli_delim("\n");
    }
   }
  
  unsigned char *buffer_file;
  buffer_file=malloc(m->fileLength);
  int buffer_length=m->fileLength;  

  ret = meshms_read_message(m,buffer_file);
  //hex_dump(buffer_file,buffer_length);
  int offset_buffer = 0;
  ret = deserialize_meshms(buffer_file,&offset_buffer,buffer_length);
  


  free(buffer_file);
  return ret;
  
}

