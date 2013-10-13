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
  
  unsigned char buffer[MAX_MANIFEST_BYTES];
  size_t buffer_len = 0;
  
  // manifest has been appended to the end of the file.
  if (strcmp(manifest_path, filepath)==0){
    unsigned char marker[4];
    int ret=0;
    FILE *f = fopen(filepath, "r");
    
    if (f == NULL)
      return WHYF_perror("Could not open manifest file %s for reading.", filepath);
    
    if (fseek(f, -sizeof(marker), SEEK_END))
      ret=WHY_perror("Unable to seek to end of file");
    
    if (ret==0){
      ret = fread(marker, 1, sizeof(marker), f);
      if (ret==sizeof(marker))
	ret=0;
      else
	ret=WHY_perror("Unable to read end of manifest marker");
    }
    
    if (ret==0){
      if (marker[2]!=0x41 || marker[3]!=0x10)
	ret=WHYF("Expected 0x4110 marker at end of file");
    }
    
    if (ret==0){
      buffer_len = read_uint16(marker);
      if (buffer_len < 1 || buffer_len > MAX_MANIFEST_BYTES)
	ret=WHYF("Invalid manifest length %zu", buffer_len);
    }
    
    if (ret==0){
      if (fseek(f, -(buffer_len+sizeof(marker)), SEEK_END))
	ret=WHY_perror("Unable to seek to end of file");
    }
    
    if (ret==0){
      ret = fread(buffer, 1, buffer_len, f);
      if (ret==buffer_len)
	ret=0;
      else
	ret=WHY_perror("Unable to read manifest contents");
    }
    
    fclose(f);
    
    if (ret)
      return ret;
    
    manifest_path=(char*)buffer;
  }
  
  if (rhizome_read_manifest_file(m, manifest_path, buffer_len) == -1)
    return WHY("could not read manifest file");
  if (rhizome_manifest_verify(m))
    return WHY("could not verify manifest");
  
  /* Make sure we store signatures */
  // TODO, why do we need this? Why isn't the state correct from rhizome_read_manifest_file? 
  // This feels like a hack...
  m->manifest_bytes=m->manifest_all_bytes;
  
  /* Do we already have this manifest or newer? */
  int64_t dbVersion = -1;
  if (sqlite_exec_int64(&dbVersion, "SELECT version FROM MANIFESTS WHERE id = ?;", RHIZOME_BID_T, &m->cryptoSignPublic, END) == -1)
    return WHY("Select failure");

  if (dbVersion>=m->version)
    return 2;

  int status = rhizome_import_file(m, filepath);
  if (status<0)
    return status;
  
  return rhizome_add_manifest(m, 1);
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
  
  /* Get manifest version number. */
  m_in->version = rhizome_manifest_get_ll(m_in, "version");
  if (m_in->version==-1)
    return WHY("Manifest must have a version number");
  
  if (strcasecmp(service, RHIZOME_SERVICE_FILE) == 0) {
    const char *name = rhizome_manifest_get(m_in, "name", NULL, 0);
    if (name == NULL)
      return WHY("Manifest missing 'name' field");
  } else if (strcasecmp(service, RHIZOME_SERVICE_MESHMS) == 0 
    || strcasecmp(service, RHIZOME_SERVICE_MESHMS2) == 0) {
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
  if (!is_sid_t_any(m_in->author)) {
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

    if (rhizome_find_secret(&m_in->author, &rs_len, &rs))
      return WHYF("Failed to obtain RS for %s to calculate BK", alloca_tohex_sid_t(m_in->author));
    if (!rhizome_secret2bk(&m_in->cryptoSignPublic, rs, rs_len, bkbytes, m_in->cryptoSignSecret)) {
      char bkhex[RHIZOME_BUNDLE_KEY_STRLEN + 1];
      (void) tohex(bkhex, RHIZOME_BUNDLE_KEY_STRLEN, bkbytes);
      if (config.debug.rhizome) DEBUGF("set BK=%s", bkhex);
      rhizome_manifest_set(m_in, "BK", bkhex);
    } else
      return WHY("Failed to set BK");
  }
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
    return -1;

  if (m_in->fileLength && !rhizome_exists(&m_in->filehash))
    return WHY("File has not been imported");

  /* If the manifest already has an ID */
  if (rhizome_bid_t_is_zero(m_in->cryptoSignPublic))
    return WHY("Manifest does not have an ID");   
  
  /* Discard the new manifest unless it is newer than the most recent known version with the same ID */
  int64_t storedversion = -1;
  switch (sqlite_exec_int64(&storedversion, "SELECT version FROM MANIFESTS WHERE id = ?;", RHIZOME_BID_T, &m_in->cryptoSignPublic, END)) {
    case -1:
      return WHY("Select failed");
    case 0:
      if (config.debug.rhizome) DEBUG("No existing manifest");
      break;
    case 1:
      if (config.debug.rhizome) 
	DEBUGF("Found existing version=%"PRId64", new version=%"PRId64, storedversion, m_in->version);
      if (m_in->version < storedversion)
	return WHY("Newer version exists");
      if (m_in->version == storedversion)
	return WHYF("Already have %s:%"PRId64", not adding", alloca_tohex_rhizome_bid_t(m_in->cryptoSignPublic), m_in->version);
      break;
    default:
      return WHY("Select found too many rows!");
  }

  /* Okay, it is written, and can be put directly into the rhizome database now */
  return rhizome_store_bundle(m_in);
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
