/*
 Serval keyring command line functions
 Copyright (C) 2014 Serval Project Inc.
 
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

#include <stdio.h>
#include "cli.h"
#include "serval_types.h"
#include "dataformats.h"
#include "os.h"
#include "conf.h"
#include "mdp_client.h"
#include "commandline.h"
#include "keyring.h"

DEFINE_CMD(app_keyring_create, 0,
  "Create a new keyring file.",
  "keyring","create");
static int app_keyring_create(const struct cli_parsed *parsed, struct cli_context *UNUSED(context))
{
  DEBUG_cli_parsed(verbose, parsed);
  keyring_file *k = keyring_create_instance();
  if (!k)
    return -1;
  keyring_free(k);
  return 0;
}

DEFINE_CMD(app_keyring_dump, 0,
  "Dump all keyring identities that can be accessed using the specified PINs",
  "keyring","dump" KEYRING_PIN_OPTIONS,"[--secret]","[<file>]");
static int app_keyring_dump(const struct cli_parsed *parsed, struct cli_context *UNUSED(context))
{
  DEBUG_cli_parsed(verbose, parsed);
  const char *path;
  if (cli_arg(parsed, "file", &path, cli_path_regular, NULL) == -1)
    return -1;
  int include_secret = 0 == cli_arg(parsed, "--secret", NULL, NULL, NULL);
  keyring_file *k = keyring_open_instance_cli(parsed);
  if (!k)
    return -1;
  FILE *fp = path ? fopen(path, "w") : stdout;
  if (fp == NULL) {
    WHYF_perror("fopen(%s, \"w\")", alloca_str_toprint(path));
    keyring_free(k);
    return -1;
  }
  int ret = keyring_dump(k, XPRINTF_STDIO(fp), include_secret);
  if (fp != stdout && fclose(fp) == EOF) {
    WHYF_perror("fclose(%s)", alloca_str_toprint(path));
    keyring_free(k);
    return -1;
  }
  keyring_free(k);
  return ret;
}

DEFINE_CMD(app_keyring_load, 0,
  "Load identities from the given dump text and insert them into the keyring using the specified entry PINs",
  "keyring","load" KEYRING_PIN_OPTIONS,"<file>","[<entry-pin>]...");
static int app_keyring_load(const struct cli_parsed *parsed, struct cli_context *UNUSED(context))
{
  DEBUG_cli_parsed(verbose, parsed);
  const char *path;
  if (cli_arg(parsed, "file", &path, cli_path_regular, NULL) == -1)
    return -1;
  unsigned pinc = 0;
  unsigned i;
  for (i = 0; i < parsed->labelc; ++i)
    if (strn_str_cmp(parsed->labelv[i].label, parsed->labelv[i].len, "entry-pin") == 0)
      ++pinc;
  const char *pinv[pinc];
  unsigned pc = 0;
  for (i = 0; i < parsed->labelc; ++i)
    if (strn_str_cmp(parsed->labelv[i].label, parsed->labelv[i].len, "entry-pin") == 0) {
      assert(pc < pinc);
      pinv[pc++] = parsed->labelv[i].text;
    }
  keyring_file *k = keyring_open_instance_cli(parsed);
  if (!k)
    return -1;
  FILE *fp = path && strcmp(path, "-") != 0 ? fopen(path, "r") : stdin;
  if (fp == NULL) {
    WHYF_perror("fopen(%s, \"r\")", alloca_str_toprint(path));
    keyring_free(k);
    return -1;
  }
  if (keyring_load_from_dump(k, pinc, pinv, fp) == -1) {
    keyring_free(k);
    return -1;
  }
  if (keyring_commit(k) == -1) {
    keyring_free(k);
    return WHY("Could not write new identity");
  }
  keyring_free(k);
  return 0;
}

DEFINE_CMD(app_keyring_list, 0,
  "List identities that can be accessed using the supplied PINs",
  "keyring","list" KEYRING_PIN_OPTIONS);
static int app_keyring_list(const struct cli_parsed *parsed, struct cli_context *context)
{
  DEBUG_cli_parsed(verbose, parsed);
  keyring_file *k = keyring_open_instance_cli(parsed);
  if (!k)
    return -1;
    
  const char *names[]={
    "sid",
    "did",
    "name"
  };
  cli_columns(context, 3, names);
  size_t rowcount = 0;
  
  keyring_iterator it;
  keyring_iterator_start(k, &it);
  const keyring_identity *id;
  while((id = keyring_next_identity(&it))){
    const sid_t *sidp = NULL;
    const char *did = NULL;
    const char *name = NULL;
    keyring_identity_extract(id, &sidp, &did, &name);
    if (sidp || did) {
      cli_put_string(context, alloca_tohex_sid_t(*sidp), ":");
      cli_put_string(context, did, ":");
      cli_put_string(context, name, "\n");
      rowcount++;
    }
  }
  keyring_free(k);
  cli_row_count(context, rowcount);
  return 0;
}

static void cli_output_identity(struct cli_context *context, const keyring_identity *id)
{
  if (id->box_pk){
      cli_field_name(context, "sid", ":");
      cli_put_string(context, alloca_tohex_sid_t(*id->box_pk), "\n");
  }
  keypair *kp=id->keypairs;
  while(kp){
    switch(kp->type){
      case KEYTYPE_DID:
	{
	  char *str = (char*)kp->private_key;
	  int l = strlen(str);
	  if (l){
	    cli_field_name(context, "did", ":");
	    cli_put_string(context, str, "\n");
	  }
	  str = (char*)kp->public_key;
	  l=strlen(str);
	  if (l){
	    cli_field_name(context, "name", ":");
	    cli_put_string(context, str, "\n");
	  }
	}
	break;
      case KEYTYPE_PUBLIC_TAG:
	{
	  const char *name;
	  const unsigned char *value;
	  size_t length;
	  if (keyring_unpack_tag(kp->public_key, kp->public_key_len, &name, &value, &length)==0){
	    cli_field_name(context, name, ":");
	    cli_put_string(context, alloca_toprint_quoted(-1, value, length, NULL), "\n");
	  }
	}
	break;
    }
    kp=kp->next;
  }
}

DEFINE_CMD(app_keyring_list2, 0, "List the full details of identities that can be accessed using the supplied PINs", 
  "keyring", "list", "--full" KEYRING_PIN_OPTIONS);
static int app_keyring_list2(const struct cli_parsed *parsed, struct cli_context *context)
{
  keyring_file *k = keyring_open_instance_cli(parsed);
  if (!k)
    return -1;
    
  keyring_iterator it;
  keyring_iterator_start(k, &it);
  const keyring_identity *id;
  while((id = keyring_next_identity(&it))){
    unsigned fields=0;
    // count the number of fields that we will output
    keypair *kp=it.identity->keypairs;
    while(kp){
      if (kp->type==KEYTYPE_CRYPTOBOX || kp->type==KEYTYPE_PUBLIC_TAG)
	fields++;
      if (kp->type==KEYTYPE_DID){
	if (strlen((char*)kp->private_key))
	  fields++;
	if (strlen((char*)kp->public_key))
	  fields++;
      }
      kp=kp->next;
    }
    cli_field_name(context, "fields", ":");
    cli_put_long(context, fields, "\n");
    cli_output_identity(context, id);
  }
  keyring_free(k);
  return 0;
}

DEFINE_CMD(app_keyring_add, 0,
  "Create a new identity in the keyring protected by the supplied PIN (empty PIN if not given)",
  "keyring","add" KEYRING_PIN_OPTIONS,"[<pin>]");
static int app_keyring_add(const struct cli_parsed *parsed, struct cli_context *context)
{
  DEBUG_cli_parsed(verbose, parsed);
  const char *pin;
  cli_arg(parsed, "pin", &pin, NULL, "");
  keyring_file *k = keyring_open_instance_cli(parsed);
  if (!k)
    return -1;
  keyring_enter_pin(k, pin);
  
  const keyring_identity *id = keyring_create_identity(k, pin);
  if (id == NULL) {
    keyring_free(k);
    return WHY("Could not create new identity");
  }
  const sid_t *sidp = NULL;
  const char *did = "";
  const char *name = "";
  keyring_identity_extract(id, &sidp, &did, &name);
  if (!sidp) {
    keyring_free(k);
    return WHY("New identity has no SID");
  }
  if (keyring_commit(k) == -1) {
    keyring_free(k);
    return WHY("Could not write new identity");
  }
  cli_output_identity(context, id);
  keyring_free(k);
  return 0;
}

DEFINE_CMD(app_keyring_set_did, 0,
  "Set the DID for the specified SID (must supply PIN to unlock the SID record in the keyring)",
  "keyring", "set","did" KEYRING_PIN_OPTIONS,"<sid>","<did>","<name>");
static int app_keyring_set_did(const struct cli_parsed *parsed, struct cli_context *context)
{
  DEBUG_cli_parsed(verbose, parsed);
  const char *sidhex, *did, *name;
  
  if (cli_arg(parsed, "sid", &sidhex, str_is_subscriber_id, "") == -1 ||
      cli_arg(parsed, "did", &did, cli_optional_did, "") == -1 ||
      cli_arg(parsed, "name", &name, NULL, "") == -1)
    return -1;

  if (strlen(name)>63)
    return WHY("Name too long (31 char max)");

  sid_t sid;
  if (str_to_sid_t(&sid, sidhex) == -1){
    keyring_free(keyring);
    keyring = NULL;
    return WHY("str_to_sid_t() failed");
  }

  if (!(keyring = keyring_open_instance_cli(parsed)))
    return -1;
  
  keyring_iterator it;
  keyring_iterator_start(keyring, &it);
  
  int r=0;
  if (!keyring_find_sid(&it, &sid))
    r=WHY("No matching SID");
  else{
    if (keyring_set_did(it.identity, did, name))
      r=WHY("Could not set DID");
    else{
      if (keyring_commit(keyring))
	r=WHY("Could not write updated keyring record");
      else{
	cli_output_identity(context, it.identity);
      }
    }
  }

  keyring_free(keyring);
  keyring = NULL;
  return r;
}

DEFINE_CMD(app_keyring_set_tag, 0,
  "Set a named tag for the specified SID (must supply PIN to unlock the SID record in the keyring)",
  "keyring", "set","tag" KEYRING_PIN_OPTIONS,"<sid>","<tag>","<value>");
static int app_keyring_set_tag(const struct cli_parsed *parsed, struct cli_context *context)
{
  const char *sidhex, *tag, *value;
  if (cli_arg(parsed, "sid", &sidhex, str_is_subscriber_id, "") == -1 ||
      cli_arg(parsed, "tag", &tag, NULL, "") == -1 ||
      cli_arg(parsed, "value", &value, NULL, "") == -1 )
    return -1;
  
  if (!(keyring = keyring_open_instance_cli(parsed)))
    return -1;

  sid_t sid;
  if (str_to_sid_t(&sid, sidhex) == -1)
    return WHY("str_to_sid_t() failed");

  keyring_iterator it;
  keyring_iterator_start(keyring, &it);
  int r=0;
  if (!keyring_find_sid(&it, &sid))
    r=WHY("No matching SID");
  else{
    int length = strlen(value);
    if (keyring_set_public_tag(it.identity, tag, (const unsigned char*)value, length))
      r=WHY("Could not set tag value");
    else{
      if (keyring_commit(keyring))
	r=WHY("Could not write updated keyring record");
      else{
	cli_output_identity(context, it.identity);
      }
    }
  }
  
  keyring_free(keyring);
  keyring = NULL;
  return r;
}

static int handle_pins(const struct cli_parsed *parsed, struct cli_context *UNUSED(context), int revoke)
{
  const char *pin, *sid_hex;
  if (cli_arg(parsed, "entry-pin", &pin, NULL, "") == -1 ||
      cli_arg(parsed, "sid", &sid_hex, str_is_subscriber_id, "") == -1)
    return -1;

  int ret=1;
  struct mdp_header header={
    .remote.port=MDP_IDENTITY,
  };
  int mdp_sock = mdp_socket();
  set_nonblock(mdp_sock);
  
  unsigned char request_payload[1200];
  struct mdp_identity_request *request = (struct mdp_identity_request *)request_payload;
  
  if (revoke){
    request->action=ACTION_LOCK;
  }else{
    request->action=ACTION_UNLOCK;
  }
  size_t len = sizeof(struct mdp_identity_request);
  if (pin && *pin) {
    request->type=TYPE_PIN;
    size_t pin_siz = strlen(pin) + 1;
    if (pin_siz + len > sizeof(request_payload))
      return WHY("Supplied pin is too long");
    bcopy(pin, &request_payload[len], pin_siz);
    len += pin_siz;
  }else if(sid_hex && *sid_hex){
    request->type=TYPE_SID;
    sid_t sid;
    if (str_to_sid_t(&sid, sid_hex) == -1)
      return WHY("str_to_sid_t() failed");
    bcopy(sid.binary, &request_payload[len], sizeof(sid));
    len += sizeof(sid);
  }
  
  if (mdp_send(mdp_sock, &header, request_payload, len) == -1)
    goto end;
  
  time_ms_t timeout=gettime_ms()+5000;
  while(1){
    struct mdp_header rev_header;
    unsigned char response_payload[1600];
    ssize_t len = mdp_poll_recv(mdp_sock, timeout, &rev_header, response_payload, sizeof(response_payload));
    if (len==-1)
      break;
    if (len==-2){
      WHYF("Timeout while waiting for response");
      break;
    }
    if (rev_header.flags & MDP_FLAG_CLOSE){
      ret=0;
      break;
    }
  }
end:
  mdp_close(mdp_sock);
  return ret;
}

DEFINE_CMD(app_revoke_pin, 0,
  "Unload any identities protected by this pin and drop all routes to them",
  "id", "relinquish", "pin", "<entry-pin>");
DEFINE_CMD(app_revoke_pin, 0,
  "Unload a specific identity and drop all routes to it",
  "id", "relinquish", "sid", "<sid>");
int app_revoke_pin(const struct cli_parsed *parsed, struct cli_context *context)
{
  return handle_pins(parsed, context, 1);
}

DEFINE_CMD(app_id_pin, 0,
  "Unlock any pin protected identities and enable routing packets to them",
  "id", "enter", "pin", "<entry-pin>");
static int app_id_pin(const struct cli_parsed *parsed, struct cli_context *context)
{
  return handle_pins(parsed, context, 0);
}

DEFINE_CMD(app_id_list, 0, 
  "Search unlocked identities based on an optional tag and value",
  "id", "list", "[<tag>]", "[<value>]");
static int app_id_list(const struct cli_parsed *parsed, struct cli_context *context)
{
  const char *tag, *value;
  if (cli_arg(parsed, "tag", &tag, NULL, "") == -1 ||
      cli_arg(parsed, "value", &value, NULL, "") == -1 )
    return -1;
  
  int ret=-1;
  struct mdp_header header={
    .remote.port=MDP_SEARCH_IDS,
  };
  int mdp_sock = mdp_socket();
  set_nonblock(mdp_sock);
  
  unsigned char request_payload[1200];
  size_t len=0;
  
  if (tag && *tag){
    size_t value_len=0;
    if (value && *value)
      value_len = strlen(value);
    len = sizeof(request_payload);
    if (keyring_pack_tag(request_payload, &len, tag, (unsigned char*)value, value_len))
      goto end;
  }
  
  if (mdp_send(mdp_sock, &header, request_payload, len) == -1)
    goto end;
  
  const char *names[]={
    "sid"
  };
  cli_columns(context, 1, names);
  size_t rowcount=0;
  
  time_ms_t timeout=gettime_ms()+5000;
  while(1){
    struct mdp_header rev_header;
    unsigned char response_payload[1600];
    ssize_t len = mdp_poll_recv(mdp_sock, timeout, &rev_header, response_payload, sizeof(response_payload));
    if (len==-1)
      break;
    if (len==-2){
      WHYF("Timeout while waiting for response");
      break;
    }
    
    if (len>=SID_SIZE){
      rowcount++;
      sid_t *id = (sid_t*)response_payload;
      cli_put_hexvalue(context, id->binary, sizeof(sid_t), "\n");
      // TODO receive and decode other details about this identity
    }
    
    if (rev_header.flags & MDP_FLAG_CLOSE){
      ret=0;
      break;
    }
  }
  cli_row_count(context, rowcount);
end:
  mdp_close(mdp_sock);
  return ret;
}

