/*
Serval Distributed Numbering Architecture (DNA)
Copyright (C) 2010 Paul Gardner-Stephen
 
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
#include "str.h"
#include "rhizome.h"
#include <stdlib.h>

int is_rhizome_enabled()
{
  return config.rhizome.enable;
}

int is_rhizome_http_enabled()
{
  return config.rhizome.enable
    &&   config.rhizome.http.enable
    &&   rhizome_db;
}

int is_rhizome_mdp_enabled()
{
  return config.rhizome.enable
    &&   config.rhizome.mdp.enable
    &&   rhizome_db;
}

int is_rhizome_mdp_server_running()
{
  return is_rhizome_mdp_enabled();
}

int is_rhizome_advertise_enabled()
{
  return config.rhizome.enable
    &&   config.rhizome.advertise.enable
    &&   rhizome_db
    &&   (is_rhizome_http_server_running() || is_rhizome_mdp_server_running());
}

int rhizome_fetch_delay_ms()
{
  return config.rhizome.fetch_delay_ms;
}

/* Import a bundle from a pair of files, one containing the manifest and the optional other
   containing the payload.  The logic is all in rhizome_bundle_import().  This function just wraps
   that function and manages file and object buffers and lifetimes.
*/

int rhizome_bundle_import_files(rhizome_manifest *m, const char *manifest_path, const char *filepath)
{
  if (config.debug.rhizome)
    DEBUGF("(manifest_path=%s, filepath=%s)",
	manifest_path ? alloca_str_toprint(manifest_path) : "NULL",
	filepath ? alloca_str_toprint(filepath) : "NULL");
  
  if (rhizome_read_manifest_file(m, manifest_path, 0) == -1)
    return WHY("could not read manifest file");
  if (rhizome_manifest_verify(m))
    return WHY("could not verify manifest");
  
  /* Make sure we store signatures */
  // TODO, why do we need this? Why isn't the state correct from rhizome_read_manifest_file? 
  // This feels like a hack...
  m->manifest_bytes=m->manifest_all_bytes;
  
  int status = rhizome_import_file(m, filepath);
  if (status<0)
    return status;
  
  status = rhizome_manifest_check_duplicate(m, NULL);
  if (status<0)
    return status;
  
  if (status==0){
    if (rhizome_add_manifest(m, 1) == -1) { // ttl = 1
      return WHY("rhizome_add_manifest() failed");
    }
  }else
    INFO("Duplicate found in store");
  
  return status;
}

/* Import a bundle from a finalised manifest struct.  The dataFileName element must give the path
   of a readable file containing the payload unless the payload is null (zero length).  The logic is
   all in rhizome_add_manifest().  This function just wraps that function and manages object buffers
   and lifetimes.
*/

int rhizome_bundle_import(rhizome_manifest *m, int ttl)
{
  if (config.debug.rhizome)
    DEBUGF("(m=%p, ttl=%d)", m, ttl);
  int ret = rhizome_manifest_check_duplicate(m, NULL);
  if (ret == 0) {
    ret = rhizome_add_manifest(m, ttl);
    if (ret == -1)
      WHY("rhizome_add_manifest() failed");
  }
  return ret;
}

int rhizome_manifest_check_sanity(rhizome_manifest *m_in)
{
  /* Ensure manifest meets basic sanity checks. */
  const char *service = rhizome_manifest_get(m_in, "service", NULL, 0);
  const char *sender = rhizome_manifest_get(m_in, "sender", NULL, 0);
  const char *recipient = rhizome_manifest_get(m_in, "recipient", NULL, 0);
  
  if (service == NULL || !service[0])
      return WHY("Manifest missing 'service' field");
  if (rhizome_manifest_get_ll(m_in, "date") == -1)
      return WHY("Manifest missing 'date' field");
  if (strcasecmp(service, RHIZOME_SERVICE_FILE) == 0) {
    const char *name = rhizome_manifest_get(m_in, "name", NULL, 0);
    if (name == NULL)
      return WHY("Manifest missing 'name' field");
  } else if (strcasecmp(service, RHIZOME_SERVICE_MESHMS) == 0) {
    if (sender == NULL || !sender[0])
      return WHY("MeshMS Manifest missing 'sender' field");
    if (!str_is_subscriber_id(sender))
      return WHYF("MeshMS Manifest contains invalid 'sender' field: %s", sender);
    if (recipient == NULL || !recipient[0])
      return WHY("MeshMS Manifest missing 'recipient' field");
    if (!str_is_subscriber_id(recipient))
      return WHYF("MeshMS Manifest contains invalid 'recipient' field: %s", recipient);
  } else {
    return WHY("Invalid service type");
  }
  if (config.debug.rhizome)
    DEBUGF("sender='%s'", sender ? sender : "(null)");

  /* passes all sanity checks */
  return 0;
}


/*
  A bundle can either be an ordinary manifest-payload pair, or a group description.
  
  - Group descriptions are manifests with no payload that have the "isagroup" variable set.  They
    get stored in the manifests table AND a reference is added to the grouplist table.  Any
    manifest, including any group manifest, may be a member of zero or one group.  This allows a
    nested, i.e., multi-level group hierarchy where sub-groups will only typically be discovered
    by joining the parent group.
*/

int rhizome_manifest_bind_id(rhizome_manifest *m_in)
{
  if (rhizome_manifest_createid(m_in) == -1)
    return -1;
  /* The ID is implicit in transit, but we need to store it in the file, so that reimporting
     manifests on receiver nodes works easily.  We might implement something that strips the id
     variable out of the manifest when sending it, or some other scheme to avoid sending all the
     extra bytes. */
  rhizome_manifest_set(m_in, "id", alloca_tohex_bid(m_in->cryptoSignPublic));
  if (!is_sid_any(m_in->author)) {
    /* Set the BK using the provided authorship information.
       Serval Security Framework defines BK as being:
       BK = privateKey XOR sha512(RS##BID), where BID = cryptoSignPublic, 
       and RS is the rhizome secret for the specified author. 
       The nice thing about this specification is that:
       privateKey = BK XOR sha512(RS##BID), so the same function can be used
       to encrypt and decrypt the BK field. */
    const unsigned char *rs;
    int rs_len=0;
    unsigned char bkbytes[RHIZOME_BUNDLE_KEY_BYTES];

    if (rhizome_find_secret(m_in->author,&rs_len,&rs)) {
      return WHYF("Failed to obtain RS for %s to calculate BK",
		 alloca_tohex_sid(m_in->author));
    }
    if (!rhizome_secret2bk(m_in->cryptoSignPublic,rs,rs_len,bkbytes,m_in->cryptoSignSecret)) {
      char bkhex[RHIZOME_BUNDLE_KEY_STRLEN + 1];
      (void) tohex(bkhex, bkbytes, RHIZOME_BUNDLE_KEY_BYTES);
      if (config.debug.rhizome) DEBUGF("set BK=%s", bkhex);
      rhizome_manifest_set(m_in, "BK", bkhex);
    } else {
      return WHY("Failed to set BK");
    }
  }
  return 0;
}

/* Check if a manifest is already stored for the same payload with the same details.
   This catches the case of "dna rhizome add file <filename>" on the same file more than once.
   (Debounce!) */
int rhizome_manifest_check_duplicate(rhizome_manifest *m_in, rhizome_manifest **m_out)
{
  if (config.debug.rhizome) DEBUG("Checking for duplicate");
  if (m_out) *m_out = NULL; 
  rhizome_manifest *dupm = NULL;
  if (rhizome_find_duplicate(m_in, &dupm,0 /* version doesn't matter */) == -1)
    return WHY("Errors encountered searching for duplicate manifest");
  if (dupm) {
    /* If the caller wants the duplicate manifest, it must be finalised, otherwise discarded. */
    if (m_out) {
      *m_out = dupm;
    }
    else
      rhizome_manifest_free(dupm);
    if (config.debug.rhizome) DEBUG("Found a duplicate");
    return 2;
  }
  if (config.debug.rhizome) DEBUG("No duplicate found");
  return 0;
}

int rhizome_add_manifest(rhizome_manifest *m_in,int ttl)
{
  if (config.debug.rhizome)
    DEBUGF("rhizome_add_manifest(m_in=%p, ttl=%d)",m_in, ttl);

  if (m_in->finalised==0)
    return WHY("Manifest must be finalised before being stored");

  /* Store time to live, clamped to within legal range */
  m_in->ttl = ttl < 0 ? 0 : ttl > 254 ? 254 : ttl;

  if (rhizome_manifest_check_sanity(m_in))
    return WHY("Sanity checks on manifest failed");

  if (m_in->fileLength){
    if (!rhizome_exists(m_in->fileHexHash))
      return WHY("File has not been imported");
  }

  /* Get manifest version number. */
  m_in->version = rhizome_manifest_get_ll(m_in, "version");
  if (m_in->version==-1)
    return WHY("Manifest must have a version number");

  /* Supply manifest version number if missing, so we can do the version check below */
  if (m_in->version == -1) {
    m_in->version = gettime_ms();
    rhizome_manifest_set_ll(m_in, "version", m_in->version);
  }

  /* If the manifest already has an ID */
  char id[SID_STRLEN + 1];
  if (rhizome_manifest_get(m_in, "id", id, SID_STRLEN + 1)) {
    str_toupper_inplace(id);
    /* Discard the new manifest unless it is newer than the most recent known version with the same ID */
    long long storedversion = -1;
    switch (sqlite_exec_int64(&storedversion, "SELECT version from manifests where id='%s';", id)) {
      case -1:
	return WHY("Select failed");
      case 0:
	if (config.debug.rhizome) DEBUG("No existing manifest");
	break;
      case 1:
	if (config.debug.rhizome) DEBUGF("Found existing version=%lld, new version=%lld", storedversion, m_in->version);
	if (m_in->version < storedversion)
	  return WHY("Newer version exists");
	if (m_in->version == storedversion)
	  return WHY("Same version of manifest exists, not adding");
	break;
      default:
	return WHY("Select found too many rows!");
    }
  } else {
    /* no manifest ID */
    return WHY("Manifest does not have an ID");   
  }

  /* Okay, it is written, and can be put directly into the rhizome database now */
  int64_t insertionTime=0;
  if ((insertionTime=rhizome_store_bundle(m_in)) == -1)
    return WHY("rhizome_store_bundle() failed.");

  // This message used in tests; do not modify or remove.
  const char *service = rhizome_manifest_get(m_in, "service", NULL, 0);
  INFOF("RHIZOME ADD MANIFEST service=%s bid=%s version=%lld",
      service ? service : "NULL",
      alloca_tohex_sid(m_in->cryptoSignPublic),
      m_in->version
      );
  if (serverMode) monitor_announce_bundle(m_in,insertionTime);
  return 0;
}

/* Update an existing Rhizome bundle */
int rhizome_bundle_push_update(char *id,long long version,unsigned char *data,int appendP)
{
  return WHY("Not implemented");
}

/* When voice traffic is being carried, we need to throttle Rhizome down
   to a more sensible level.  Or possibly even supress it entirely.
 */
time_ms_t rhizome_voice_timeout = -1;
int rhizome_saw_voice_traffic()
{
  /* We are in "voice mode" for a second after sending a voice frame */
  rhizome_voice_timeout=gettime_ms()+1000;
  return 0;
}
