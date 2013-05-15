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
(const char *sender_sid_hex,const char *recipient_sid_hex, int createP)
{
  sid_t authorSid;
  if (str_to_sid_t(&authorSid, sender_sid_hex)==-1)
    { WHYF("invalid sender_sid: '%s'", sender_sid_hex); return NULL; }

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
    // Found manifest, so read it in, and set secret if we know it, or can work
    // it out.
    int ret = rhizome_retrieve_manifest(manifestid_hex, m);
    if (!ret) {
      if (rhizome_obfuscated_manifest_generate_outgoing_bid
	  (m,authorSid.binary,recipient_sid_hex))   
	rhizome_find_bundle_author(m);
      return m; 
    }
    else {
      // The manifest can't be read. This is normal for the first message in an
      // outgoing plys of meshms threads, because we compute the BID
      // deterministically.
      // So we can just ignore this.
    }
  } else {
    if (!createP) {
      rhizome_manifest_free(m);
      return NULL;
    }
  }

  // No existing manifest, so create one:

  // Generate the deterministic BID for this sender recipient pair
  sid_t sender_sid; 
  if (cf_opt_sid(&sender_sid,sender_sid_hex)) {
    WHY("Could not parse sender SID");
    rhizome_manifest_free(m);
    return NULL;
  }
  if (rhizome_obfuscated_manifest_generate_outgoing_bid
      (m,sender_sid.binary,recipient_sid_hex)) {
    WHY("meshms_generate_outgoing_bid() failed");
    rhizome_manifest_free(m);
    return NULL;
  }  

  // Populate with the fields we know
  rhizome_manifest_set(m, "service", RHIZOME_SERVICE_MESHMS);
  rhizome_manifest_set(m,"recipient",recipient_sid_hex);
  // DO NOT put the real sender in, because that would reveal people's social
  // graph to everyone trivially.  
  // See github.com/servalproject/serval-docs/securing-meshms/ for more info.
  // Instead, according to the above scheme, we:
  // 1. Set sender=<a disposable sid> and 
  // 2. ssender=<mechanism to retrieve real sender if you are the recipient>
  // This is done by the following function
  if (rhizome_manifest_set_obfuscated_sender(m,sender_sid_hex,recipient_sid_hex)) {
    WHY("meshms_set_obfuscated_sender() failed");
    rhizome_manifest_free(m);
    return NULL;
  }

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

  ret=meshms_append_messageblock(sender_sid,recipient_sid,
				 buffer_serialize,length_int);
  free(buffer_serialize);
  return ret;
}

int meshms_read_conversation_log(const char *sender_sid_hex,
				 rhizome_manifest *l,
				 unsigned char **buffer_file)
{
  // Check if there is an existing one, if so, read it and return it.
  if (rhizome_meshms_derive_conversation_log_bid(sender_sid_hex,l))
    return WHYF("Could not derive conversation log bid for sid: %s",sender_sid_hex);
  char manifestid_hex[crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES*2+1];
  tohex(manifestid_hex,l->cryptoSignPublic,
	crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES);
  
  int ret = rhizome_retrieve_manifest(manifestid_hex, l);
  if (!ret) {
    // Manifest already exists, nothing to do just yet.
  } else {
    // Create new manifest
    if (rhizome_meshms_derive_conversation_log_bid(sender_sid_hex,l))
      return WHYF("Could not derive conversation log bid for sid: %s",sender_sid_hex);
    
    rhizome_manifest_set(l, "service", RHIZOME_SERVICE_FILE);
    rhizome_manifest_set(l, "crypt", "1");

    // Ask rhizome to prepare the missing parts
    if (rhizome_fill_manifest(l,NULL,NULL,NULL)) {
      rhizome_manifest_free(l);
      return WHY("rhizome_fill_manifest() failed");
    }

    rhizome_manifest_del(l,"author");
    rhizome_manifest_del(l,"sender");
    rhizome_manifest_del(l,"recipient");

    uint64_t initial_version=0;
    urandombytes((unsigned char *)&initial_version,sizeof(uint64_t));
    rhizome_manifest_set_ll(l,"version",initial_version);
  }

  // We now have the manifest, so read the associated file, if any,
  // store the new record if necessary, and write back updated bundle if
  // the record was stored.

  // We allow space for 256 more records, because we add a random number of 
  // empty records onto the end when it fills up, and allocate 256 entries
  // initially. The idea is to make it harder for an adversary to estimate the
  // size of your social graph.
  *buffer_file=malloc(l->fileLength+(SID_SIZE+crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES)*256);  
  if (!*buffer_file) {
    rhizome_manifest_free(l);
    return WHYF("malloc(%d) failed when reading existing conversation index.",
		l->fileLength);
  }
  if (l->fileLength) {
    int ret = meshms_read_message(l,*buffer_file);
    if (ret) {
      rhizome_manifest_free(l);
      return WHYF("meshms_read_message() failed.");
    }
  }
return 0;
}


int meshms_remember_conversation(const char *sender_sid_hex,
				 rhizome_manifest *m)
{
  // Check if the BID:recipient pair exists in the meshms conversation log
  // bundle.

  char *recipient_hex=rhizome_manifest_get(m,"recipient",NULL,0);
  sid_t rxSid,txSid;
  if (!recipient_hex||!recipient_hex[0]
      ||cf_opt_sid(&rxSid,recipient_hex)||cf_opt_sid(&txSid,sender_sid_hex))
    return WHY("sender or recipient SID could not be parsed.");

  // Generate conversation row for remembering
  unsigned char row[SID_SIZE+crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES];
  bcopy(&rxSid.binary,&row[0],SID_SIZE);
  bcopy(m->cryptoSignPublic,&row[SID_SIZE],
	crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES);

  rhizome_manifest *l = rhizome_new_manifest();
  if (!l) {
    return WHY("Manifest struct could not be allocated -- not added to rhizome"); 
  }

  unsigned char *buffer_file=NULL;
  
  if (meshms_read_conversation_log(sender_sid_hex,l,&buffer_file)) {
    rhizome_manifest_free(l);
    if (buffer_file) free(buffer_file);
    return WHYF("meshms_read_conversation_log() failed");
  }

  int i;
  for(i=0;i<l->fileLength;i+=sizeof(row)) {
    if (!bcmp(row,&buffer_file[i],sizeof(row))) {
      // Conversation has already been remembered
      rhizome_manifest_free(l);
      return 0;
    }
    int j;
    for(j=0;j<sizeof(row);j++) if (buffer_file[i+j]) break;
    if (j==sizeof(row)) {
      // Found an empty row -- we can store it here
      bcopy(row,&buffer_file[i],sizeof(row));
      break;
    }
  }
  if (i==l->fileLength) {
    // There were no empty rows in the file.
    // Write to next slot, and then decide how many empty slots to add.
    bcopy(row,&buffer_file[i],sizeof(row));

    // Make large initial allocation so that it is not easy to estimate the size
    // of someone's social graph.  In particular, we don't want an adversary to 
    // be able to easily pick people with many contacts from those with few
    // contacts.
    // For simplicity we will just add 256 records at a time.
    l->fileLength+=256*sizeof(row);
    // zero the unused slots so that we know we can use them later.
    // XXX - This does create a very big crib. Will have to think about a better
    // solution later.
    bzero(&buffer_file[i+sizeof(row)],l->fileLength-i-sizeof(row));
    rhizome_manifest_set_ll(l, "filesize", l->fileLength);  
  }
  // Update the version. Advance by a random amount so that it is not as easy to
  // guess how many times it has been advanced (this doesn't help greatly, but there
  // is no point making life easier than necessary for an adversary).
  unsigned short advance;
  urandombytes((unsigned char *)&advance,2);
  uint64_t old_version=rhizome_manifest_get_ll(l,"version");
  uint64_t new_version=old_version+advance;
  rhizome_manifest_set_ll(l,"version",new_version);

  rhizome_add_file(l,(char *)buffer_file,1,l->fileLength);
  free(buffer_file);

  rhizome_manifest *mout = NULL;
  int ret=rhizome_manifest_finalise(l,&mout);
  if (ret<0){
    cli_printf("Error in manifest finalise");
    rhizome_manifest_free(l);
    if (mout&&mout!=l) rhizome_manifest_free(mout);
    return -1;
  }
  
  rhizome_manifest_free(l);

  return 0;
}

int meshms_append_messageblock(const char *sender_sid_hex,
			       const char *recipient_sid_hex,
			       const unsigned char *buffer_serialize,
			       int length_int)
{
  // Find the manifest (or create it if it doesn't yet exist)
  rhizome_manifest *m=meshms_find_or_create_manifestid(sender_sid_hex,
						       recipient_sid_hex,1);
  if (!m) return WHYF("Could not read manifest");
 
 // Read the bundle file containing the meshms messages
 // (and keep enough space to append the new message
 unsigned char *buffer_file=malloc(m->fileLength+length_int);  
 if (!buffer_file) {
   WHYF("malloc(%d) failed when reading existing MeshMS log.",m->fileLength);
   rhizome_manifest_free(m);
   return -1;
 }
 int ret = meshms_read_message(m,buffer_file);
 if (ret) {
   WHYF("meshms_read_message() failed.");
   rhizome_manifest_free(m);
   return -1;   
 }
 // If this is the first message sent, remember the conversation for later
 // recall.
 if (!m->fileLength) meshms_remember_conversation(sender_sid_hex,m);

 // Append the serialised message, and update file length
 bcopy(buffer_serialize,&buffer_file[m->fileLength],length_int);
 m->fileLength += length_int;
 // MeshMS bundles are journalled, so filesize and version are synonymous
 rhizome_manifest_set_ll(m, "filesize", m->fileLength);  
 rhizome_manifest_set_ll(m,"version",m->fileLength);
 // Write enlarged message log to bundle
 rhizome_add_file(m,(char *)buffer_file,1,m->fileLength);

 free(buffer_file); 
 
 rhizome_manifest *mout = NULL;
 ret|=rhizome_manifest_finalise(m,&mout);
 if (ret<0){  
   cli_printf("Error in manifest finalise");
   rhizome_manifest_free(m);
   if (mout&&mout!=m) rhizome_manifest_free(mout);
   return -1;
 } 
   
 if (mout != m)
   rhizome_manifest_free(mout);
 rhizome_manifest_free(m); 
 
 return ret ; 
}

int app_meshms_list_messages(const struct cli_parsed *parsed, void *context)
{
 if (create_serval_instance_dir() == -1)
   return -1;
 if (!(keyring = keyring_open_instance_cli(parsed)))
   return -1;
 if (rhizome_opendb() == -1)
   return -1; 

 if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
 //left_sid = author_sid
 const char *left_sid, *right_sid;

 // Parse mandatory arguments
 cli_arg(parsed, "sender_sid", &left_sid, cli_optional_sid, "");
 cli_arg(parsed, "recipient_sid", &right_sid, cli_optional_sid, "");
 // Sanity check passed arguments
 if ( (strcmp(left_sid,"") == 0) || (strcmp(right_sid,"" ) == 0) )
   { 
     cli_puts("One or more missing arguments"); cli_delim("\n");
   } 
 sid_t aSid;
 if (left_sid[0] && str_to_sid_t(&aSid, left_sid) == -1)
   return WHYF("invalid left_sid: %s", left_sid);
 if (right_sid[0] && str_to_sid_t(&aSid, right_sid) == -1)
   return WHYF("invalid right_sid: %s", right_sid);

 // Obtain message logs for both sides of the conversation, if available
 rhizome_manifest *m_left=NULL,*m_right=NULL;
 m_left=meshms_find_or_create_manifestid(left_sid,right_sid,0);
 m_right=meshms_find_or_create_manifestid(right_sid,left_sid,0);
 int left_len=0, right_len=0;
 unsigned char *left_messages=NULL, *right_messages=NULL;
 if (m_left) {
   left_messages=malloc(m_left->fileLength);
   if (!left_messages) {
     WHYF("malloc(%d) failed while reading meshms logs",m_left->fileLength);
     return -1;
   }
   if (!meshms_read_message(m_left,left_messages))
     left_len=m_left->fileLength;
 }
 if (m_right) {
   right_messages=malloc(m_right->fileLength);
   if (!right_messages) {
     WHYF("malloc(%d) failed while reading meshms logs",m_right->fileLength);
     return -1;
   }
   if (!meshms_read_message(m_right,right_messages))
     right_len=m_right->fileLength;
 }
 rhizome_manifest_free(m_left); m_left=NULL;
 rhizome_manifest_free(m_right); m_right=NULL;

#define MAX_MESSAGES_IN_THREAD 16384
 int offsets[MAX_MESSAGES_IN_THREAD];
 int sides[MAX_MESSAGES_IN_THREAD];
 int message_count=0;

 // Scan through messages and acks to generate forward-ordered list, and determine
 // last message from left that has been ack'd by right.  We will then traverse the
 // list in reverse order to display the messages.
 int right_ack_limit=0;
 int left_ack=0, left_offset=0, right_offset=0;
 for(left_offset=0;left_offset<left_len;)
   {
     for(;right_offset<left_ack;)
       {
	 unsigned int right_block_len;
	 int o=right_offset;
	 if (decode_length_forwards(right_messages,&o,right_len,
				    &right_block_len)) break;
	 int block_type=meshms_block_type(right_messages,right_offset,right_len);
	 switch(block_type) {
	 case RHIZOME_MESHMS_BLOCK_TYPE_BID_REFERENCE:
	 case RHIZOME_MESHMS_BLOCK_TYPE_MESSAGE:
	   offsets[message_count]=right_offset;
	   sides[message_count++]=1;
	   break;
	 case RHIZOME_MESHMS_BLOCK_TYPE_ACK:
	   {
	     int o=right_offset;
	     deserialize_ack(right_messages,&o,right_len,&right_ack_limit);
	   }
	   break;
	 }
	 right_offset+=right_block_len;
	 if (message_count>=MAX_MESSAGES_IN_THREAD) break;
       }
     if (message_count>=MAX_MESSAGES_IN_THREAD) break;
     int block_type=meshms_block_type(left_messages,left_offset,left_len);
	 switch(block_type) {
	 case RHIZOME_MESHMS_BLOCK_TYPE_BID_REFERENCE:
	 case RHIZOME_MESHMS_BLOCK_TYPE_MESSAGE:
	   offsets[message_count]=left_offset;
	   sides[message_count++]=0;
	   break;
	 case RHIZOME_MESHMS_BLOCK_TYPE_ACK:
	   {
	     int o=right_offset;
	     deserialize_ack(right_messages,&o,right_len,&right_ack_limit);
	   }
	   break;
	 }
     unsigned int left_block_len;
     int o=left_offset;
     if (decode_length_forwards(left_messages,&o,left_len,&left_block_len)) break;     
     left_offset+=left_block_len;
   }
 // Process any outstanding messages from the right side
 for(;right_offset<=right_len;)
   {
     unsigned int right_block_len;
     int o=right_offset;
     if (decode_length_forwards(right_messages,&o,right_len,
				&right_block_len)) {
       break;
     }
     int block_type=meshms_block_type(right_messages,right_offset,right_len);
     switch(block_type) {
     case RHIZOME_MESHMS_BLOCK_TYPE_BID_REFERENCE:
     case RHIZOME_MESHMS_BLOCK_TYPE_MESSAGE:
       offsets[message_count]=right_offset;
       sides[message_count++]=1;
       break;
     case RHIZOME_MESHMS_BLOCK_TYPE_ACK:
       {
	 int o=right_offset;
	 deserialize_ack(right_messages,&o,right_len,&right_ack_limit);
       }
       break;
     }
     right_offset+=right_block_len;
     if (message_count>=MAX_MESSAGES_IN_THREAD) break;
   }
 
 // Display list of messages in reverse order
  const char *names[]={
    "number",
    "offset",
    "length",
    "sender",
    "recipient",
    "date",
    "delivery_status",
    "type",
    "message"
  };
  cli_columns(9, names);

 int i;
 for(i=message_count-1;i>=0;i--) 
   {
     char *delivery_status
       =sides[i]?"received":
       ((offsets[i]<right_ack_limit)?"delivered":"unacknowledged");
     int boffset=offsets[i];
     deserialize_meshms(message_count-1-i,
			sides[i]?right_messages:left_messages,&boffset,
			sides[i]?right_len:left_len,delivery_status);
   }

 return 0;
}


int meshms_get_last_ack_offset(const char *left_sid,const char *right_sid)
{
  rhizome_manifest *m_left=NULL;
  m_left=meshms_find_or_create_manifestid(left_sid,right_sid,0);
  if (!m_left) {
    DEBUGF("Couldn't find manifest for thread ply");
    return 0;
  }
  unsigned char *left_messages=malloc(m_left->fileLength);
  if (!left_messages) {
    WHYF("malloc(%d) failed while reading meshms logs",m_left->fileLength);
    return 0;
  }
  if (meshms_read_message(m_left,left_messages)) {
    DEBUGF("Couldn't read message log for thread ply");
    rhizome_manifest_free(m_left); return 0;
  }

  int left_len=m_left->fileLength;
  rhizome_manifest_free(m_left); m_left=NULL;
  
  // Scan through messages and look for acks
  int left_ack_limit=0;
  int left_offset=0;
  for(left_offset=0;left_offset<left_len;)
    {
      int block_type=meshms_block_type(left_messages,left_offset,left_len);
      switch(block_type) {
      case RHIZOME_MESHMS_BLOCK_TYPE_ACK:
	{
	  int o=left_offset;
	  deserialize_ack(left_messages,&o,left_len,&left_ack_limit);
	}
	break;
      }
      unsigned int left_block_len;
      int o=left_offset;
      if (decode_length_forwards(left_messages,&o,left_len,&left_block_len)) break;     
      left_offset+=left_block_len;
    }
  free(left_messages);
  return left_ack_limit;
}

int app_meshms_ack_messages(const struct cli_parsed *parsed, void *context)
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
 const char *sender_sid, *recipient_sid;

 const char *message_offset_str;
 uint message_offset=0;

 // Parse mandatory arguments
 cli_arg(parsed, "sender_sid", &sender_sid, cli_optional_sid, "");
 cli_arg(parsed, "recipient_sid", &recipient_sid, cli_optional_sid, "");
 cli_arg(parsed, "message_offset", &message_offset_str, NULL, "0");
 message_offset=atoi(message_offset_str);
 // Sanity check passed arguments
 if ( (strcmp(sender_sid,"") == 0) || (strcmp(recipient_sid,"" ) == 0) )
   { 
     cli_puts("One or more missing arguments"); cli_delim("\n");
   } 
 sid_t aSid;
 if (sender_sid[0] && str_to_sid_t(&aSid, sender_sid) == -1)
   return WHYF("invalid sender_sid: %s", sender_sid);
 if (recipient_sid[0] && str_to_sid_t(&aSid, recipient_sid) == -1)
   return WHYF("invalid recipient_sid: %s", recipient_sid);

 DEBUGF("Message log previously acknowledged to %d",
	meshms_get_last_ack_offset(sender_sid,recipient_sid));
 if (meshms_get_last_ack_offset(sender_sid,recipient_sid)>=message_offset) {
   INFO("Already acknowledged.");
   return 0;
 }

 // Create serialised ack message for appending to the conversation ply
 int length_int = 0;
 unsigned char buffer_serialize[100];

 ret|=serialize_ack(buffer_serialize,&length_int,100,message_offset);

 if (!ret)
   ret|=meshms_append_messageblock(sender_sid,recipient_sid,
				   buffer_serialize,length_int);

 if (!ret) INFO("Acknowledged.");

 return ret;
}

int app_meshms_list_conversations(const struct cli_parsed *parsed, void *context)
{
  if (create_serval_instance_dir() == -1)
   return -1;
 if (!(keyring = keyring_open_instance_cli(parsed)))
   return -1;
 if (rhizome_opendb() == -1)
   return -1; 

 if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
 const char *sid,*offset_str,*count_str;

 // Parse mandatory arguments
 cli_arg(parsed, "sid", &sid, cli_optional_sid, "");
 cli_arg(parsed, "offset", &offset_str, NULL, "0");
 cli_arg(parsed, "count", &count_str, NULL, "9999");
 int offset=atoi(offset_str);
 int count=atoi(count_str);
 // Sanity check passed arguments
 if ( strcmp(sid,"") == 0  )
   { 
     cli_puts("One or more missing arguments"); cli_delim("\n");
   } 
 sid_t aSid;
 if (sid[0] && str_to_sid_t(&aSid, sid) == -1)
   return WHYF("invalid sid: %s", sid);

 return rhizome_meshms_find_conversations(sid,offset,count);
}
