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

#include <stdlib.h>
#include <assert.h>
#include "serval.h"
#include "conf.h"
#include "str.h"
#include "rhizome.h"

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
	ret=WHYF("Invalid manifest length %zd", buffer_len);
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

int rhizome_manifest_check_sanity(rhizome_manifest *m)
{
  /* Ensure manifest meets basic sanity checks. */
  int ret = 0;
  if (m->version == 0)
    ret = WHY("Manifest must have a version number");
  if (m->filesize == RHIZOME_SIZE_UNSET)
    ret = WHY("Manifest missing 'filesize' field");
  else if (m->filesize && rhizome_filehash_t_is_zero(m->filehash))
    ret = WHY("Manifest 'filehash' field has not been set");
  if (m->service == NULL)
    ret = WHY("Manifest missing 'service' field");
  else if (strcasecmp(m->service, RHIZOME_SERVICE_FILE) == 0) {
    if (m->name == NULL)
      ret = WHY("Manifest with service='" RHIZOME_SERVICE_FILE "' missing 'name' field");
  } else if (strcasecmp(m->service, RHIZOME_SERVICE_MESHMS) == 0 
	  || strcasecmp(m->service, RHIZOME_SERVICE_MESHMS2) == 0) {
    if (!m->has_sender)
      ret = WHYF("Manifest with service='%s' missing 'sender' field", m->service);
    if (!m->has_recipient)
      ret = WHYF("Manifest with service='%s' missing 'recipient' field", m->service);
  }
  else if (!rhizome_str_is_manifest_service(m->service))
    ret = WHYF("Manifest invalid 'service' field %s", alloca_str_toprint(m->service));
  if (!m->has_date)
    ret = WHY("Manifest missing 'date' field");
  return ret;
}

/* Sets the bundle key "BK" field of a manifest.  Returns 1 if the field was set, 0 if not.
 *
 * This function must not be called unless the bundle secret is known.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int rhizome_manifest_add_bundle_key(rhizome_manifest *m)
{
  IN();
  assert(m->haveSecret);
  switch (m->authorship) {
    case ANONYMOUS: // there can be no BK field without an author
    case AUTHOR_UNKNOWN: // we already know the author is not in the keyring
    case AUTHENTICATION_ERROR: // already tried and failed to get Rhizome Secret
      break;
    case AUTHOR_NOT_CHECKED:
    case AUTHOR_LOCAL:
    case AUTHOR_AUTHENTIC:
    case AUTHOR_IMPOSTOR: {
	/* Set the BK using the provided author.  Serval Security Framework defines BK as being:
	*    BK = privateKey XOR sha512(RS##BID)
	* where BID = cryptoSignPublic, 
	*       RS is the rhizome secret for the specified author. 
	* The nice thing about this specification is that:
	*    privateKey = BK XOR sha512(RS##BID)
	* so the same function can be used to encrypt and decrypt the BK field.
	*/
	const unsigned char *rs;
	size_t rs_len = 0;
	enum rhizome_secret_disposition d = find_rhizome_secret(&m->author, &rs_len, &rs);
	switch (d) {
	  case FOUND_RHIZOME_SECRET: {
	      rhizome_bk_t bkey;
	      if (rhizome_secret2bk(&m->cryptoSignPublic, rs, rs_len, bkey.binary, m->cryptoSignSecret) == 0) {
		rhizome_manifest_set_bundle_key(m, &bkey);
		m->authorship = AUTHOR_AUTHENTIC;
		RETURN(1);
	      } else
		m->authorship = AUTHENTICATION_ERROR;
	    }
	    break;
	  case IDENTITY_NOT_FOUND:
	    m->authorship = AUTHOR_UNKNOWN;
	    break;
	  case IDENTITY_HAS_NO_RHIZOME_SECRET:
	    m->authorship = AUTHENTICATION_ERROR;
	    break;
	  default:
	    FATALF("find_rhizome_secret() returned unknown code %d", (int)d);
	    break;
	}
      }
      break;
    default:
      FATALF("m->authorship = %d", (int)m->authorship);
  }
  rhizome_manifest_del_bundle_key(m);
  switch (m->authorship) {
    case AUTHOR_UNKNOWN:
      WHYF("Cannot set BK because author=%s is not in keyring", alloca_tohex_sid_t(m->author));
      break;
    case AUTHENTICATION_ERROR:
      WHY("Cannot set BK due to error");
      break;
    default:
      break;
  }
  RETURN(0);
}

int rhizome_add_manifest(rhizome_manifest *m, int ttl)
{
  if (config.debug.rhizome)
    DEBUGF("rhizome_add_manifest(m=%p, ttl=%d)",m, ttl);

  if (m->finalised==0)
    return WHY("Manifest must be finalised before being stored");

  /* Store time to live, clamped to within legal range */
  m->ttl = ttl < 0 ? 0 : ttl > 254 ? 254 : ttl;

  if (rhizome_manifest_check_sanity(m))
    return -1;

  assert(m->filesize != RHIZOME_SIZE_UNSET);
  if (m->filesize > 0 && !rhizome_exists(&m->filehash))
    return WHY("File has not been imported");

  /* If the manifest already has an ID */
  if (rhizome_bid_t_is_zero(m->cryptoSignPublic))
    return WHY("Manifest does not have an ID");   
  
  /* Discard the new manifest unless it is newer than the most recent known version with the same ID */
  int64_t storedversion = -1;
  switch (sqlite_exec_int64(&storedversion, "SELECT version FROM MANIFESTS WHERE id = ?;", RHIZOME_BID_T, &m->cryptoSignPublic, END)) {
    case -1:
      return WHY("Select failed");
    case 0:
      if (config.debug.rhizome) DEBUG("No existing manifest");
      break;
    case 1:
      if (config.debug.rhizome) 
	DEBUGF("Found existing version=%"PRId64", new version=%"PRId64, storedversion, m->version);
      if (m->version < storedversion)
	return WHY("Newer version exists");
      if (m->version == storedversion)
	return WHYF("Already have %s:%"PRId64", not adding", alloca_tohex_rhizome_bid_t(m->cryptoSignPublic), m->version);
      break;
    default:
      return WHY("Select found too many rows!");
  }

  /* Okay, it is written, and can be put directly into the rhizome database now */
  return rhizome_store_bundle(m);
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
