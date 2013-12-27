/*
Serval DNA Rhizome file distribution
Copyright (C) 2012-2013 Serval Project Inc.
Copyright (C) 2011-2012 Paul Gardner-Stephen
 
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

/*
  Portions Copyright (C) 2013 Petter Reinholdtsen
  Some rights reserved

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
  FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
  COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdlib.h>
#include <assert.h>
#include "serval.h"
#include "conf.h"
#include "str.h"
#include "rhizome.h"
#include "dataformats.h"

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
 * containing the payload.  The work is all done by rhizome_bundle_import() and
 * rhizome_store_manifest().
 */
enum rhizome_bundle_status rhizome_bundle_import_files(rhizome_manifest *m, rhizome_manifest **mout, const char *manifest_path, const char *filepath)
{
  if (config.debug.rhizome)
    DEBUGF("(manifest_path=%s, filepath=%s)",
	manifest_path ? alloca_str_toprint(manifest_path) : "NULL",
	filepath ? alloca_str_toprint(filepath) : "NULL");
  
  size_t buffer_len = 0;
  int ret = 0;
  
  // manifest has been appended to the end of the file.
  if (strcmp(manifest_path, filepath)==0){
    unsigned char marker[4];
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
    if (ret == 0 && fread(m->manifestdata, buffer_len, 1, f) != 1) {
      if (ferror(f))
	ret = WHYF("fread(%p,%zu,1,%s) error", m->manifestdata, buffer_len, alloca_str_toprint(filepath));
      else if (feof(f))
	ret = WHYF("fread(%p,%zu,1,%s) hit end of file", m->manifestdata, buffer_len, alloca_str_toprint(filepath));
    }
    fclose(f);
  } else {
    ssize_t size = read_whole_file(manifest_path, m->manifestdata, sizeof m->manifestdata);
    if (size == -1)
      ret = -1;
    buffer_len = (size_t) size;
  }
  if (ret)
    return ret;
  m->manifest_all_bytes = buffer_len;
  if (   rhizome_manifest_parse(m) == -1
      || !rhizome_manifest_validate(m)
      || !rhizome_manifest_verify(m)
  )
    return RHIZOME_BUNDLE_STATUS_INVALID;
  enum rhizome_bundle_status status = rhizome_manifest_check_stored(m, mout);
  if (status == RHIZOME_BUNDLE_STATUS_NEW) {
    enum rhizome_payload_status pstatus = rhizome_import_payload_from_file(m, filepath);
    switch (pstatus) {
      case RHIZOME_PAYLOAD_STATUS_EMPTY:
      case RHIZOME_PAYLOAD_STATUS_STORED:
      case RHIZOME_PAYLOAD_STATUS_NEW:
	if (rhizome_store_manifest(m) == -1)
	  return -1;
	break;
      case RHIZOME_PAYLOAD_STATUS_ERROR:
      case RHIZOME_PAYLOAD_STATUS_CRYPTO_FAIL:
	return -1;
      case RHIZOME_PAYLOAD_STATUS_WRONG_SIZE:
      case RHIZOME_PAYLOAD_STATUS_WRONG_HASH:
	status = RHIZOME_BUNDLE_STATUS_INCONSISTENT;
	break;
      default:
	FATALF("pstatus = %d", pstatus);
    }
  }
  return status;
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

/* Test the status of a given manifest 'm' (id, version) with respect to the Rhizome store, and
 * return a code which indicates whether 'm' should be stored or not, setting *mout to 'm' or
 * to point to a newly allocated manifest.  The caller is responsible for freeing *mout if *mout !=
 * m.  If the caller passes mout==NULL then no new manifest is allocated.
 *
 *  - If the store contains no manifest with the given id, sets *mout = m and returns
 *    RHIZOME_BUNDLE_STATUS_NEW, ie, the manifest 'm' should be stored.
 *
 *  - If the store contains a manifest with the same id and an older version, sets *mout to the
 *    stored manifest and returns RHIZOME_BUNDLE_STATUS_NEW, ie, the manifest 'm' should be
 *    stored.
 *
 *  - If the store contains a manifest with the same id and version, sets *mout to the stored
 *    manifest and returns RHIZOME_BUNDLE_STATUS_SAME.  The caller must compare *m and *mout, and
 *    if they are not identical, must decide what to do.
 *
 *  - If the store contains a manifest with the same id and a later version, sets *mout to the
 *    stored manifest and returns RHIZOME_BUNDLE_STATUS_OLD, ie, the manifest 'm' should NOT be
 *    stored.
 *
 *  - If there is an error querying the Rhizome store or allocating a new manifest structure, logs
 *    an error and returns -1.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
enum rhizome_bundle_status rhizome_manifest_check_stored(rhizome_manifest *m, rhizome_manifest **mout)
{
  assert(m->has_id);
  assert(m->version != 0);
  rhizome_manifest *stored_m = rhizome_new_manifest();
  if (stored_m == NULL)
    return -1;
  int n = rhizome_retrieve_manifest(&m->cryptoSignPublic, stored_m);
  switch (n) {
    case -1:
      rhizome_manifest_free(stored_m);
      return -1;
    case 1:
      if (config.debug.rhizome)
	DEBUGF("No stored manifest with id=%s", alloca_tohex_rhizome_bid_t(m->cryptoSignPublic));
      rhizome_manifest_free(stored_m);
      if (mout)
	*mout = m;
      return RHIZOME_BUNDLE_STATUS_NEW;
    case 0:
      break;
    default:
      FATALF("rhizome_retrieve_manifest() returned %d", n);
  }
  if (mout)
    *mout = stored_m;
  else
    rhizome_manifest_free(stored_m);
  enum rhizome_bundle_status result = RHIZOME_BUNDLE_STATUS_NEW;
  const char *what = "newer than";
  if (m->version < stored_m->version) {
    result = RHIZOME_BUNDLE_STATUS_OLD;
    what = "older than";
  }
  if (m->version == stored_m->version) {
    return RHIZOME_BUNDLE_STATUS_SAME;
    what = "same as";
  }
  if (config.debug.rhizome)
    DEBUGF("Bundle %s:%"PRIu64" is %s stored version %"PRIu64, alloca_tohex_rhizome_bid_t(m->cryptoSignPublic), m->version, what, stored_m->version);
  return result;
}

enum rhizome_bundle_status rhizome_add_manifest(rhizome_manifest *m, rhizome_manifest **mout)
{
  if (config.debug.rhizome)
    DEBUGF("rhizome_add_manifest(m=manifest[%d](%p), mout=%p)", m->manifest_record_number, m, mout);
  if (!m->finalised && !rhizome_manifest_validate(m))
    return RHIZOME_BUNDLE_STATUS_INVALID;
  assert(m->finalised);
  if (!m->selfSigned && !rhizome_manifest_verify(m))
    return RHIZOME_BUNDLE_STATUS_FAKE;
  assert(m->filesize != RHIZOME_SIZE_UNSET);
  if (m->filesize > 0 && !rhizome_exists(&m->filehash))
    return WHY("Payload has not been stored");
  enum rhizome_bundle_status status = rhizome_manifest_check_stored(m, mout);
  if (status == RHIZOME_BUNDLE_STATUS_NEW && rhizome_store_manifest(m) == -1)
    return -1;
  return status;
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
