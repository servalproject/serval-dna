/*
Serval DNA - Rhizome entry points
Copyright (C) 2012-2015 Serval Project Inc.
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
#include "strbuf_helpers.h"
#include "mem.h"
#include "rhizome.h"
#include "httpd.h"
#include "dataformats.h"
#include "log.h"
#include "debug.h"

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
    &&   (is_httpd_server_running() || is_rhizome_mdp_server_running());
}

int rhizome_fetch_delay_ms()
{
  return config.rhizome.fetch_delay_ms;
}

int rhizome_add_field_assignment(struct rhizome_manifest_field_assignment *field, const char *arg, size_t arglen)
{
  const char *eq;
  if (arglen > 0 && arg[0] == '!') {
    field->label = arg + 1;
    field->labellen = arglen - 1;
    field->value = NULL;
  } else if ((eq = strnchr(arg, arglen, '='))) {
    field->label = arg;
    field->labellen = eq - arg;
    field->value = eq + 1;
    field->valuelen = (arg + arglen) - field->value;
  } else
    return WHYF("invalid manifest field argument: %s", alloca_str_toprint(arg));
  if (!rhizome_manifest_field_label_is_valid(field->label, field->labellen))
    return WHYF("invalid manifest field label: %s", alloca_toprint(-1, field->label, field->labellen));
  if (field->value && !rhizome_manifest_field_value_is_valid(field->value, field->valuelen))
    return WHYF("invalid manifest field value: %s", alloca_toprint(-1, field->value, field->valuelen));
  return 0;
}

int rhizome_parse_field_assignments(struct rhizome_manifest_field_assignment *fields, unsigned argc, const char *const *args)
{
  unsigned i;
  for (i = 0; i < argc; ++i) {
    struct rhizome_manifest_field_assignment *field = &fields[i];
    const char *arg = args[i];
    size_t arglen = strlen(arg);
    if (rhizome_add_field_assignment(field, arg, arglen)==-1)
      return -1;
  }
  return argc;
}

struct rhizome_bundle_result rhizome_apply_assignments(rhizome_manifest *m,
  unsigned nassignments, const struct rhizome_manifest_field_assignment *assignments)
{
  // Apply the field assignments, overriding the existing manifest fields.
  unsigned i;
  for (i = 0; i != nassignments; ++i) {
    const struct rhizome_manifest_field_assignment *asg = &assignments[i];
    rhizome_manifest_remove_field(m, asg->label, asg->labellen);
    if (asg->value) {
      const char *label = alloca_strndup(asg->label, asg->labellen);
      enum rhizome_manifest_parse_status status = rhizome_manifest_parse_field(m, asg->label, asg->labellen, asg->value, asg->valuelen);
      switch (status) {
      case RHIZOME_MANIFEST_ERROR:
	return rhizome_bundle_result_sprintf(RHIZOME_BUNDLE_STATUS_ERROR,
						"Error updating manifest field: %s=%s",
						label, alloca_toprint(-1, asg->value, asg->valuelen));
      case RHIZOME_MANIFEST_OK:
	break;
      case RHIZOME_MANIFEST_SYNTAX_ERROR:
	return rhizome_bundle_result_sprintf(RHIZOME_BUNDLE_STATUS_INVALID,
						"Manifest syntax error: %s=%s",
						label, alloca_toprint(-1, asg->value, asg->valuelen));
      case RHIZOME_MANIFEST_DUPLICATE_FIELD:
	// We already deleted the field, so if this happens, its a logic bug.
	FATALF("Duplicate field should not occur: %s=%s", label, alloca_toprint(-1, asg->value, asg->valuelen));
      case RHIZOME_MANIFEST_INVALID:
	return rhizome_bundle_result_sprintf(RHIZOME_BUNDLE_STATUS_INVALID,
						"Manifest invalid field: %s=%s",
						label, alloca_toprint(-1, asg->value, asg->valuelen));
      case RHIZOME_MANIFEST_MALFORMED:
	return rhizome_bundle_result_sprintf(RHIZOME_BUNDLE_STATUS_INVALID,
						"Manifest malformed field: %s=%s",
						label, alloca_toprint(-1, asg->value, asg->valuelen));
      case RHIZOME_MANIFEST_OVERFLOW:
	return rhizome_bundle_result_sprintf(RHIZOME_BUNDLE_STATUS_INVALID,
						"Too many fields in manifest at: %s=%s",
						label, alloca_toprint(-1, asg->value, asg->valuelen));
      default:
	FATALF("status = %d", status);
      }
    }
  }
  return rhizome_bundle_result(RHIZOME_BUNDLE_STATUS_NEW);
}

/* Create a manifest structure to accompany adding a file to Rhizome or appending to a journal.
 * This function is used by all application-facing APIs (eg, CLI, RESTful HTTP).  It differs from
 * the import operation in that if the caller does not supply a complete, signed manifest then this
 * operation will create it using the fields supplied.  Also, the caller can supply a clear-text
 * payload with the 'crypt=1' field to cause it to be stored encrypted.
 *
 * - if 'appending' is true then the new bundle will be a journal bundle, otherwise it will be a
 *   normal bundle.  Any existing manifest must be consistent; eg, an append will fail if a bundle
 *   with the same Bundle Id already exists in the store and is not a journal.
 *
 * - 'm' must point to a manifest structure into which any supplied partial manifest has already
 *   been parsed.  If the caller supplied no (partial) manifest at all, then the manifest 'm' will
 *   be blank.
 *
 * - 'mout' must point to a manifest pointer which is updated to hold the constructed manifest.
 *
 * - 'bid' must point to a supplied bundle id parameter, or NULL if none was supplied.
 *
 * - 'bsk' must point to a supplied bundle secret parameter, or NULL if none was supplied.
 *
 * - 'author' must point to a supplied author parameter, or NULL if none was supplied.
 *
 * - 'file_path' can point to a supplied payload file name (eg, if the payload was read from a named
 *   file), or can be NULL.  If not NULL, then the file's name will be used to fill in the 'name'
 *   field of the manifest if it was not explicitly supplied in 'm' or in the existing manifest.
 *
 * - 'nassignments' and 'assignments' describe an array of field assignments that override the
 *   fields supplied in 'm' and also the fields in any existing manifest with the same Bundle Id.
 *
 * - 'reason' may either be NULL or points to a strbuf to which descriptive text is appended if the
 *   manifest creation fails.
 *
 * If the add is successful, modifies '*mout' to point to the constructed Manifest, which might be
 * 'm' or might be another manifest, and returns 0.  It is the caller's responsibility to free
 * '*mout'.
 *
 * If the add fails because of invalid field settings that violate Rhizome semantics (eg, a missing
 * mandatory field, a malformed field name or value), then if 'reason' is not NULL, appends a text
 * string to the 'reason' strbuf that describes the cause of the failure, does not alter '*mout',
 * and returns 1.
 *
 * If the add fails because of a recoverable error (eg, database locking) then if 'reason' is not
 * NULL, appends a text string to the 'reason' strbuf that describes the cause of the failure, does
 * not alter '*mout', and returns 2.
 *
 * If the add fails because of an unrecoverable error (eg, out of memory, i/o failure)
 * then if 'reason' is not NULL, appends a text string to the 'reason' strbuf that describes the
 * cause of the failure, does not alter '*mout', and returns -1.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
struct rhizome_bundle_result rhizome_manifest_add_file(int appending,
                                                       rhizome_manifest *m,
                                                       rhizome_manifest **mout,
                                                       const rhizome_bid_t *bid,
                                                       const rhizome_bk_t *bsk,
                                                       const sid_t *author,
                                                       const char *file_path,
                                                       unsigned nassignments,
                                                       const struct rhizome_manifest_field_assignment *assignments)
{
  struct rhizome_bundle_result result = INVALID_RHIZOME_BUNDLE_RESULT; // must be set before returning
  rhizome_manifest *existing_manifest = NULL;
  rhizome_manifest *new_manifest = NULL;
  assert(m != NULL);
  // Caller must not supply a malformed manifest (but an invalid one is okay because missing
  // fields will be filled in, so we don't check validity here).
  assert(!m->malformed);
  // If appending to a journal, caller must not supply 'version', 'filesize' or 'filehash' fields,
  // because these will be calculated by the journal append logic.
  if (appending) {
    if (m->version) {
      result = rhizome_bundle_result_static(RHIZOME_BUNDLE_STATUS_INVALID, "Cannot set 'version' field in journal append");
      goto error;
    }
    else if (m->filesize != RHIZOME_SIZE_UNSET) {
      result = rhizome_bundle_result_static(RHIZOME_BUNDLE_STATUS_INVALID, "Cannot set 'filesize' field in journal append");
      goto error;
    }
    else if (m->has_filehash) {
      result = rhizome_bundle_result_static(RHIZOME_BUNDLE_STATUS_INVALID, "Cannot set 'filehash' field in journal append");
      goto error;
    }
  }
  if (bid) {
    DEBUGF(rhizome, "Reading manifest from database: id=%s", alloca_tohex_rhizome_bid_t(*bid));
    if ((existing_manifest = rhizome_new_manifest()) == NULL) {
      result = rhizome_bundle_result_static(RHIZOME_BUNDLE_STATUS_ERROR, "Manifest struct could not be allocated");
      goto error;
    }
    result.status = rhizome_retrieve_manifest(bid, existing_manifest);
    switch (result.status) {
    case RHIZOME_BUNDLE_STATUS_NEW:
      // No manifest with that bundle ID exists in the store, so we are building a bundle from
      // scratch.
      rhizome_manifest_free(existing_manifest);
      existing_manifest = NULL;
      break;
    case RHIZOME_BUNDLE_STATUS_SAME:
      // Found a manifest with the same bundle ID.  If appending to a journal, then keep the
      // existing 'version', 'filesize' and 'filehash' (so they can be verified when the existing
      // payload is copied) and don't allow the supplied manifest to overwrite them.  If not a
      // journal, then unset the 'version', 'filesize' and 'filehash' fields, then overwrite the
      // existing manifest with the supplied manifest.
      if (!appending) {
        rhizome_manifest_del_version(existing_manifest);
        rhizome_manifest_del_filesize(existing_manifest);
        rhizome_manifest_del_filehash(existing_manifest);
      }
      if (rhizome_manifest_overwrite(existing_manifest, m) == -1) {
	result = rhizome_bundle_result_static(RHIZOME_BUNDLE_STATUS_ERROR,
					      "Existing manifest could not be overwritten");
        goto error;
      }
      new_manifest = existing_manifest;
      existing_manifest = NULL;
      break;
    case RHIZOME_BUNDLE_STATUS_BUSY:
      result = rhizome_bundle_result_static(RHIZOME_BUNDLE_STATUS_BUSY,
					    "Existing manifest not retrieved due to Rhizome store locking");
      goto error;
    case RHIZOME_BUNDLE_STATUS_ERROR:
      result = rhizome_bundle_result_static(RHIZOME_BUNDLE_STATUS_BUSY,
					    "Error retrieving existing manifest from Rhizome store");
      goto error;
    case RHIZOME_BUNDLE_STATUS_DUPLICATE:
    case RHIZOME_BUNDLE_STATUS_OLD:
    case RHIZOME_BUNDLE_STATUS_INVALID:
    case RHIZOME_BUNDLE_STATUS_FAKE:
    case RHIZOME_BUNDLE_STATUS_INCONSISTENT:
    case RHIZOME_BUNDLE_STATUS_NO_ROOM:
    case RHIZOME_BUNDLE_STATUS_READONLY:
    case RHIZOME_BUNDLE_STATUS_MANIFEST_TOO_BIG:
      FATALF("rhizome_retrieve_manifest() returned %s", rhizome_bundle_status_message(result.status));
    }
  }
  // If no existing bundle has been identified, we are building a bundle from scratch.
  if (!new_manifest) {
    new_manifest = m;
    // A new journal manifest needs the 'filesize' and 'tail' fields set so that the first append can
    // succeed.
    if (appending) {
      if (new_manifest->filesize == RHIZOME_SIZE_UNSET)
        rhizome_manifest_set_filesize(new_manifest, 0);
      if (new_manifest->tail == RHIZOME_SIZE_UNSET)
        rhizome_manifest_set_tail(new_manifest, 0);
    }
  }
  // Apply the field assignments, overriding the existing manifest fields.
  if (nassignments) {
    result = rhizome_apply_assignments(new_manifest, nassignments, assignments);
    if (result.status != RHIZOME_BUNDLE_STATUS_NEW)
      goto error;
  }
  if (appending && !new_manifest->is_journal) {
    result = rhizome_bundle_result_static(RHIZOME_BUNDLE_STATUS_INVALID,
					  "Cannot append to a non-journal");
    goto error;
  }
  if (!appending && new_manifest->is_journal) {
    result = rhizome_bundle_result_static(RHIZOME_BUNDLE_STATUS_INVALID,
					  "Cannot add a journal bundle (use append instead)");
    goto error;
  }
  if (bsk) {
    if (new_manifest->has_id) {
      if (!rhizome_apply_bundle_secret(new_manifest, bsk)) {
	result = rhizome_bundle_result_static(RHIZOME_BUNDLE_STATUS_READONLY,
					      "Supplied bundle secret does not match Bundle Id");
        goto error;
      }
    } else {
      rhizome_new_bundle_from_secret(new_manifest, bsk);
    }
  }
  // TODO: one day there will be no default service, but for now if no service
  // is specified, it defaults to 'file' (file sharing).
  if (new_manifest->service == NULL) {
    WARNF("Manifest 'service' field not supplied - setting to '%s'", RHIZOME_SERVICE_FILE);
    rhizome_manifest_set_service(new_manifest, RHIZOME_SERVICE_FILE);
  }

  if (author)
    rhizome_manifest_set_author(m, author);

  result = rhizome_fill_manifest(new_manifest, file_path);
error:
  switch (result.status) {
  case RHIZOME_BUNDLE_STATUS_NEW:
    *mout = new_manifest;
    return result;
  default:
    if (new_manifest && new_manifest != m && new_manifest != existing_manifest)
      rhizome_manifest_free(new_manifest);
    if (existing_manifest)
      rhizome_manifest_free(existing_manifest);
    return result;
  }
  FATALF("result.status = %d", (int)result.status);
}

/* Import a bundle from a pair of files, one containing the manifest and the optional other
 * containing the payload.
 */
enum rhizome_bundle_status rhizome_bundle_import_files(rhizome_manifest *m, rhizome_manifest **mout, const char *manifest_path, const char *filepath, int zip_comment)
{
  DEBUGF(rhizome, "(manifest_path=%s, filepath=%s, zip_comment=%d)",
	 manifest_path ? alloca_str_toprint(manifest_path) : "NULL",
	 filepath ? alloca_str_toprint(filepath) : "NULL",
	 zip_comment);
  
  enum rhizome_bundle_status ret;
  int single_file = strcmp(manifest_path, filepath)==0;

  int fd = open(manifest_path, O_RDONLY);
  if (fd == -1)
    return WHYF_perror("Could not open manifest file %s for reading.", filepath);

  off_t file_len = lseek(fd, 0, SEEK_END);
  if (file_len==-1){
    ret=WHY_perror("Unable to determine file length");
    goto end;
  }

  uint8_t buff[MAX_MANIFEST_BYTES + 22];
  off_t read_len = sizeof buff;

  if (read_len > file_len)
    read_len = file_len;

  if (lseek(fd, -read_len, SEEK_END)==-1){
    ret=WHYF_perror("lseek(%d, %d, SEEK_END) - Failed to seek to near the end of %s, len %u", fd, (int)-read_len, manifest_path, (int)file_len);
    goto end;
  }

  if (read(fd, buff, read_len)!=read_len){
    ret=WHYF_perror("Failed to read %u bytes of the manifest", (int)read_len);
    goto end;
  }
  uint8_t *manifest_ptr;

  // manifest has been appended to the end of the file.
  if (single_file){
    if (zip_comment){
      // scan backwards for EOCD marker 0x504b0506
      uint8_t *EOCD = &buff[read_len - 22];
      while(EOCD){
	if (EOCD[0]==0x50 && EOCD[1]==0x4b && EOCD[2]==0x05 && EOCD[3]==0x06)
	  break;
	EOCD--;
      }

      if (!EOCD){
	WHY("Expected zip EOCD marker 0x504b0506 near end of file");
	ret = RHIZOME_BUNDLE_STATUS_INVALID;
	goto end;
      }

      m->manifest_all_bytes = EOCD[20] | (EOCD[21]<<8);
      manifest_ptr = &EOCD[22];

    }else{
      if (buff[read_len-2]!=0x41 || buff[read_len-1]!=0x10){
	WHYF("Expected 0x4110 marker at end of file");
	ret = RHIZOME_BUNDLE_STATUS_INVALID;
	goto end;
      }
      m->manifest_all_bytes = read_uint16(&buff[read_len-4]);
      manifest_ptr = &buff[read_len - m->manifest_all_bytes - 4];
    }
  }else{
    manifest_ptr = buff;
    m->manifest_all_bytes = read_len;
  }

  if (m->manifest_all_bytes < 1 || m->manifest_all_bytes > MAX_MANIFEST_BYTES){
    WHYF("Invalid manifest length %zu", m->manifest_all_bytes);
    ret = RHIZOME_BUNDLE_STATUS_INVALID;
    goto end;
  }
  if (manifest_ptr < buff || manifest_ptr + m->manifest_all_bytes > buff + read_len){
    WHY("Invalid manifest offset");
    ret = RHIZOME_BUNDLE_STATUS_INVALID;
    goto end;
  }
  bcopy(manifest_ptr, m->manifestdata, m->manifest_all_bytes);

  if (   rhizome_manifest_parse(m) == -1
      || !rhizome_manifest_validate(m)
      || !rhizome_manifest_verify(m)
  ){
    ret = RHIZOME_BUNDLE_STATUS_INVALID;
    goto end;
  }

  ret = rhizome_manifest_check_stored(m, mout);
  if (ret != RHIZOME_BUNDLE_STATUS_NEW)
    goto end;

  enum rhizome_payload_status pstatus = RHIZOME_PAYLOAD_STATUS_EMPTY;
  if (m->filesize > 0){

    if (single_file){
      if (lseek(fd, 0, SEEK_SET)==-1){
	ret=WHY_perror("Unable to seek to start of file");
	goto end;
      }
    }else{
      close(fd);
      fd = open(filepath, O_RDONLY);
      if (fd==-1)
	return WHYF_perror("Could not open payload file %s for reading.", filepath);
    }

    /* Import the file, checking the hash as we go */
    struct rhizome_write write;
    bzero(&write, sizeof(write));

    pstatus = rhizome_open_write(&write, &m->filehash, m->filesize);
    if (pstatus == RHIZOME_PAYLOAD_STATUS_NEW){
      off_t read_len = m->filesize;
      uint8_t payload_buffer[RHIZOME_CRYPT_PAGE_SIZE];
      if (zip_comment)
	read_len -=2;
      while(write.file_offset < (uint64_t)read_len){
	size_t size = sizeof payload_buffer;
	if (write.file_offset + size > (uint64_t)read_len)
	  size = read_len - write.file_offset;
	ssize_t r = read(fd, payload_buffer, size);
	if (r == -1) {
	  ret = WHYF_perror("read(%d,%p,%zu)", fd, payload_buffer, size);
	  rhizome_fail_write(&write);
	  goto end;
	}
	if ((size_t) r != size) {
	  ret = WHYF("file truncated - read(%d,%p,%zu) returned %zu", fd, payload_buffer, size, (size_t) r);
	  rhizome_fail_write(&write);
	  goto end;
	}
	if (r && rhizome_write_buffer(&write, payload_buffer, (size_t) r)) {
	  ret = -1;
	  rhizome_fail_write(&write);
	  goto end;
	}
      }

      if (zip_comment){
	uint8_t comment_len[2] = {0,0};
	if (rhizome_write_buffer(&write, comment_len, sizeof comment_len)){
	  ret = -1;
	  rhizome_fail_write(&write);
	  goto end;
	}
      }

      pstatus = rhizome_finish_write(&write);
      if (pstatus == RHIZOME_PAYLOAD_STATUS_BUSY)
	rhizome_fail_write(&write);
    }

  }

  switch (pstatus) {
    case RHIZOME_PAYLOAD_STATUS_EMPTY:
    case RHIZOME_PAYLOAD_STATUS_STORED:
    case RHIZOME_PAYLOAD_STATUS_NEW:
      ret = rhizome_add_manifest_to_store(m, mout);
      break;
    case RHIZOME_PAYLOAD_STATUS_TOO_BIG:
    case RHIZOME_PAYLOAD_STATUS_EVICTED:
      ret = RHIZOME_BUNDLE_STATUS_NO_ROOM;
      break;
    case RHIZOME_PAYLOAD_STATUS_ERROR:
    case RHIZOME_PAYLOAD_STATUS_CRYPTO_FAIL:
      ret = -1;
      break;
    case RHIZOME_PAYLOAD_STATUS_WRONG_SIZE:
    case RHIZOME_PAYLOAD_STATUS_WRONG_HASH:
      ret = RHIZOME_BUNDLE_STATUS_INCONSISTENT;
      break;
    default:
      FATALF("rhizome_import_payload_from_file() returned status = %d", pstatus);
  }

end:
  close(fd);
  return ret;
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
  enum rhizome_bundle_status result = rhizome_retrieve_manifest(&m->keypair.public_key, stored_m);
  if (result==RHIZOME_BUNDLE_STATUS_SAME){
    const char *what = "same as";
    if (m->version < stored_m->version) {
      result = RHIZOME_BUNDLE_STATUS_OLD;
      what = "older than";
    }
    if (m->version > stored_m->version) {
      what = "newer than";
      result = RHIZOME_BUNDLE_STATUS_NEW;
    }
    DEBUGF(rhizome, "Bundle %s:%"PRIu64" is %s stored version %"PRIu64, alloca_tohex_rhizome_bid_t(m->keypair.public_key), m->version, what, stored_m->version);
    if (mout)
      *mout = stored_m;
    else
      rhizome_manifest_free(stored_m);
  }else{
    rhizome_manifest_free(stored_m);
    DEBUGF(rhizome, "No stored manifest with id=%s", alloca_tohex_rhizome_bid_t(m->keypair.public_key));
    if (mout)
      *mout = m;
  }
  return result;
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

const char *rhizome_bundle_status_message(enum rhizome_bundle_status status)
{
  switch (status) {
    case RHIZOME_BUNDLE_STATUS_NEW:		 return "Bundle new to store";
    case RHIZOME_BUNDLE_STATUS_SAME:		 return "Bundle already in store";
    case RHIZOME_BUNDLE_STATUS_DUPLICATE:	 return "Duplicate bundle already in store";
    case RHIZOME_BUNDLE_STATUS_OLD:		 return "Newer bundle already in store";
    case RHIZOME_BUNDLE_STATUS_INVALID:		 return "Invalid manifest";
    case RHIZOME_BUNDLE_STATUS_FAKE:		 return "Manifest signature does not verify";
    case RHIZOME_BUNDLE_STATUS_INCONSISTENT:	 return "Manifest inconsistent with supplied payload";
    case RHIZOME_BUNDLE_STATUS_NO_ROOM:		 return "No room in store for bundle";
    case RHIZOME_BUNDLE_STATUS_READONLY:	 return "Bundle is read-only";
    case RHIZOME_BUNDLE_STATUS_BUSY:		 return "Database is busy";
    case RHIZOME_BUNDLE_STATUS_ERROR:		 return "Internal error";
    case RHIZOME_BUNDLE_STATUS_MANIFEST_TOO_BIG: return "Manifest too big";
  }
  return NULL;
}

const char *rhizome_bundle_status_message_nonnull(enum rhizome_bundle_status status)
{
  const char *message = rhizome_bundle_status_message(status);
  return message ? message : "Invalid";
}

const char *rhizome_payload_status_message(enum rhizome_payload_status status)
{
  switch (status) {
    case RHIZOME_PAYLOAD_STATUS_NEW:         return "Payload new to store";
    case RHIZOME_PAYLOAD_STATUS_STORED:      return "Payload already in store";
    case RHIZOME_PAYLOAD_STATUS_EMPTY:       return "Payload empty";
    case RHIZOME_PAYLOAD_STATUS_TOO_BIG:     return "Payload size exceeds store";
    case RHIZOME_PAYLOAD_STATUS_EVICTED:     return "Payload evicted";
    case RHIZOME_PAYLOAD_STATUS_WRONG_SIZE:  return "Payload size contradicts manifest";
    case RHIZOME_PAYLOAD_STATUS_WRONG_HASH:  return "Payload hash contradicts manifest";
    case RHIZOME_PAYLOAD_STATUS_CRYPTO_FAIL: return "Incorrect bundle secret";
    case RHIZOME_PAYLOAD_STATUS_ERROR:       return "Internal error";
    case RHIZOME_PAYLOAD_STATUS_BUSY:        return "busy storage";
  }
  return NULL;
}

const char *rhizome_payload_status_message_nonnull(enum rhizome_payload_status status)
{
  const char *message = rhizome_payload_status_message(status);
  return message ? message : "Invalid";
}

void rhizome_bundle_result_free(struct rhizome_bundle_result *resultp)
{
  if (resultp->release) {
    resultp->release((void *)resultp->message);
  }
  *resultp = INVALID_RHIZOME_BUNDLE_RESULT;
}

static const char *rhizome_bundle_status_symbol(enum rhizome_bundle_status status)
{
  switch (status) {
    case RHIZOME_BUNDLE_STATUS_NEW:		 return "NEW";
    case RHIZOME_BUNDLE_STATUS_SAME:		 return "SAME";
    case RHIZOME_BUNDLE_STATUS_DUPLICATE:	 return "DUPLICATE";
    case RHIZOME_BUNDLE_STATUS_OLD:		 return "OLD";
    case RHIZOME_BUNDLE_STATUS_INVALID:		 return "INVALID";
    case RHIZOME_BUNDLE_STATUS_FAKE:		 return "FAKE";
    case RHIZOME_BUNDLE_STATUS_INCONSISTENT:	 return "INCONSISTENT";
    case RHIZOME_BUNDLE_STATUS_NO_ROOM:		 return "NO_ROOM";
    case RHIZOME_BUNDLE_STATUS_READONLY:	 return "READONLY";
    case RHIZOME_BUNDLE_STATUS_BUSY:		 return "BUSY";
    case RHIZOME_BUNDLE_STATUS_MANIFEST_TOO_BIG: return "MANIFEST_TOO_BIG";
    case RHIZOME_BUNDLE_STATUS_ERROR:		 return "ERROR";
  }
  FATALF("status=%d", (int)status);
}

static void log_rhizome_bundle_result(struct __sourceloc __whence, struct rhizome_bundle_result result)
{
  switch (result.status) {
    case RHIZOME_BUNDLE_STATUS_NEW:
    case RHIZOME_BUNDLE_STATUS_SAME:
    case RHIZOME_BUNDLE_STATUS_DUPLICATE:
    case RHIZOME_BUNDLE_STATUS_OLD:
    case RHIZOME_BUNDLE_STATUS_INVALID:
    case RHIZOME_BUNDLE_STATUS_FAKE:
    case RHIZOME_BUNDLE_STATUS_INCONSISTENT:
    case RHIZOME_BUNDLE_STATUS_NO_ROOM:
    case RHIZOME_BUNDLE_STATUS_READONLY:
    case RHIZOME_BUNDLE_STATUS_MANIFEST_TOO_BIG:
      DEBUG(rhizome, alloca_rhizome_bundle_result(result));
      return;
    case RHIZOME_BUNDLE_STATUS_BUSY:
      WARN(alloca_rhizome_bundle_result(result));
      return;
    case RHIZOME_BUNDLE_STATUS_ERROR:
      WHY(alloca_rhizome_bundle_result(result));
      return;
  }
  FATAL(alloca_rhizome_bundle_result(result));
}


struct rhizome_bundle_result _rhizome_bundle_result(struct __sourceloc __whence, enum rhizome_bundle_status status)
{
  struct rhizome_bundle_result result = INVALID_RHIZOME_BUNDLE_RESULT;
  result.status = status;
  log_rhizome_bundle_result(__whence, result);
  return result;
}

struct rhizome_bundle_result _rhizome_bundle_result_static(struct __sourceloc __whence, enum rhizome_bundle_status status, const char *message)
{
  struct rhizome_bundle_result result = INVALID_RHIZOME_BUNDLE_RESULT;
  result.status = status;
  result.message = message;
  log_rhizome_bundle_result(__whence, result);
  return result;
}

struct rhizome_bundle_result _rhizome_bundle_result_strdup(struct __sourceloc __whence, enum rhizome_bundle_status status, const char *message)
{
  assert(message != NULL);
  struct rhizome_bundle_result result = INVALID_RHIZOME_BUNDLE_RESULT;
  result.status = status;
  result.message = str_edup(message);
  result.release = free;
  log_rhizome_bundle_result(__whence, result);
  return result;
}

struct rhizome_bundle_result _rhizome_bundle_result_sprintf(struct __sourceloc __whence, enum rhizome_bundle_status status, const char *fmt, ...)
{
  struct rhizome_bundle_result result = INVALID_RHIZOME_BUNDLE_RESULT;
  result.status = status;
  strbuf sb;
  STRBUF_ALLOCA_FIT(sb, 200, strbuf_va_printf(sb, fmt));
  result.message = str_edup(strbuf_str(sb));
  result.release = free;
  log_rhizome_bundle_result(__whence, result);
  return result;
}

const char *rhizome_bundle_result_message(struct rhizome_bundle_result result)
{
  return result.message ? result.message : rhizome_bundle_status_message(result.status);
}

const char *rhizome_bundle_result_message_nonnull(struct rhizome_bundle_result result)
{
  return result.message ? result.message : rhizome_bundle_status_message_nonnull(result.status);
}

strbuf strbuf_append_rhizome_bundle_result(strbuf sb, struct rhizome_bundle_result result)
{
  switch (result.status) {
  case RHIZOME_BUNDLE_STATUS_NEW:
  case RHIZOME_BUNDLE_STATUS_SAME:
  case RHIZOME_BUNDLE_STATUS_DUPLICATE:
  case RHIZOME_BUNDLE_STATUS_OLD:
  case RHIZOME_BUNDLE_STATUS_INVALID:
  case RHIZOME_BUNDLE_STATUS_FAKE:
  case RHIZOME_BUNDLE_STATUS_INCONSISTENT:
  case RHIZOME_BUNDLE_STATUS_NO_ROOM:
  case RHIZOME_BUNDLE_STATUS_READONLY:
  case RHIZOME_BUNDLE_STATUS_BUSY:
  case RHIZOME_BUNDLE_STATUS_MANIFEST_TOO_BIG:
  case RHIZOME_BUNDLE_STATUS_ERROR:
    strbuf_puts(sb, "RHIZOME_BUNDLE_STATUS_");
    strbuf_puts(sb, rhizome_bundle_status_symbol(result.status));
    if (result.message) {
      strbuf_puts(sb, " ");
      strbuf_toprint_quoted(sb, "``", result.message);
    }
    return sb;
  }
  strbuf_sprintf(sb, "Invalid rhizome_bundle_status (%d)", (int)result.status);
  return sb;
}
