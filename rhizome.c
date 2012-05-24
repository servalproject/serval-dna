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
#include "rhizome.h"
#include <stdlib.h>

/* Import a bundle from the inbox folder.  The bundle is contained a pair of files, one containing
   the manifest and the optional other containing the payload.

   The logic is all in rhizome_add_manifest().  This function just wraps that function and manages
   file and object buffers and lifetimes.
*/

int rhizome_bundle_import(rhizome_manifest *m_in, rhizome_manifest **m_out, 
			  const char *bundle,
			  char *groups[], int ttl,
			  int verifyP, int checkFileP, int signP)
{
  if (debug&DEBUG_RHIZOMESYNC)
    DEBUGF("rhizome_bundle_import(m_in=%p, m_out=%p, bundle=%s, groups=%p, ttl=%d, verifyP=%d, checkFileP=%d, signP=%d)",
	  m_in, m_out, bundle ? bundle : "(null)", groups, ttl, verifyP, checkFileP, signP);
  if (m_out) *m_out = NULL;

  char filename[1024];
  char manifestname[1024];

  /* make sure import path exists */
  if (create_rhizome_import_dir() == -1)
    return -1;

  if (!FORM_RHIZOME_IMPORT_PATH(filename, "file.%s", bundle)
   || !FORM_RHIZOME_IMPORT_PATH(manifestname, "manifest.%s", bundle))
    return WHY("Manifest bundle name too long");

  /* Read manifest file if no manifest was given */
  rhizome_manifest *m = m_in;
  if (!m_in)  {
    m = rhizome_read_manifest_file(manifestname, 0 /* file not buffer */, RHIZOME_VERIFY);
    if (!m)
      return WHY("Could not read manifest file.");
  } else {
    if (debug&DEBUG_RHIZOMESYNC)
      DEBUGF("Importing direct from manifest structure fileHashedP=%d", m->fileHashedP);
  }

  /* Add the manifest and its associated file to the Rhizome database. */
  rhizome_manifest *dupm;
  int ret = rhizome_add_manifest(m, &dupm, filename, groups, ttl, 
				 verifyP, checkFileP, signP,
				 NULL /* don't specify author for manifests received via mesh */
				);
  unlink(filename);
  if (ret == -1) {
    WHY("rhizome_add_manifest() failed");
    unlink(manifestname);
  } else {
    /* >>> For testing, write manifest file back to disk and leave it there */
    // unlink(manifestname);
    if (rhizome_write_manifest_file(m, manifestname))
      ret = WHY("Could not write manifest file.");
  }

  /* If the manifest structure was allocated in this function, and it is not being returned to the
     caller, then this function is responsible for freeing it */
  if (m_out)
    *m_out = m;
  else if (!m_in)
    rhizome_manifest_free(m);

  return ret;
}

/* Add a manifest/payload pair ("bundle") to the rhizome data store.

   Returns:
     0 if successful
     2 if a duplicate is already in the store (same name, version and filehash)
     -1 on error or failure

   Fills in any missing manifest fields (generating a new, random manifest ID if necessary),
   optionally performs consistency checks (see below), adds the manifest to the given groups (for
   which private keys must be held), optionally signs it, and inserts the manifest and payload into
   the rhizome store unless the store already contains a manifest with the same ID and a higher
   version number or an identical manifest (in which case the stored version number is bumped to the
   maximum of the two).

   This function is called in three different situations:
    (a) when the user injects a file (with or without a complete manifest) into rhizome,
    (b) when a manifest is received via the mesh and the file is already present in the rhizome store,
    (c) when a file is received via the mesh for a manifest that was received previously.

   The following arguments distinguish these situations:

    ttl
      - In case (a) ttl will be typically set to the initial (maximum?) TTL for a manifest.  In
	cases (b) and (c) ttl will be the TTL of the received manifest decremented by one.  This
	function clamps the supplied value into the legal range 0..255, so callers need not perform
	range checking after decrement.

    verifyP
      - If set, then checks that no signature verifications failed when the manifest was loaded.
	(If checkFileP is given, then also checks that the payload and manifest are consistent.)
	This is used in case (a) if the user provided a manifest file, and always for cases (b) and
	(c).  It ensures the integrity of the received/provided manifest, and ensures that the
	received/provided payload is actually the one that the manifest belongs to.  If verifyP is
	false, then the new manifest will be overwritten with the correct values for the payload.

    checkFileP
      - If set then checks that the payload file is readable, and will cause verifyP to also check
	that the payload matches the values in the manifest, specifically length and content hash.
	This is always used in cases (a) and (c), but not in case (b) because in that case, the
	file's contents with the given file hash are known to be already in the database.

    signP
      - If set, then signs the manifest after all its fields have been filled in.  Only used in case
	(a), because in cases (b) and (c) the manifest has already been signed, since it is already
	on the air.

   A bundle can either be an ordinary manifest-payload pair, or a group description.
   
    - Group descriptions are manifests with no payload that have the "isagroup" variable set.  They
      get stored in the manifests table AND a reference is added to the grouplist table.  Any
      manifest, including any group manifest, may be a member of zero or one group.  This allows a
      nested, i.e., multi-level group hierarchy where sub-groups will only typically be discovered
      by joining the parent group.

*/

int rhizome_add_manifest(rhizome_manifest *m_in,
			 rhizome_manifest **m_out,
			 const char *filename,
			 char *groups[],
			 int ttl,
			 int verifyP, // verify that file's hash is consistent with manifest
			 int checkFileP,
			 int signP,
			 const char *author // NULL or zero-length to make an unauthored manifest
			)
{
  if (debug&DEBUG_RHIZOMESYNC)
    DEBUGF("rhizome_add_manifest(m_in=%p, m_out=%p, filename=%s, groups=%p, ttl=%d, verifyP=%d, checkFileP=%d, signP=%d, author=%s)",
	  m_in, m_out,
	  filename ? filename : "NULL",
	  groups, ttl, verifyP, checkFileP, signP,
	  author ? author : "NULL"
	);
  if (m_out) *m_out = NULL;
  if (author && !author[0]) author = NULL;

  /* Ensure manifest meets basic sanity checks. */
  const char *service = rhizome_manifest_get(m_in, "service", NULL, 0);
  if (service == NULL || !service[0])
      return WHY("Manifest missing 'service' field");
  if (rhizome_manifest_get_ll(m_in, "date") == -1)
      return WHY("Manifest missing 'date' field");
  if (strcasecmp(service, RHIZOME_SERVICE_FILE) == 0) {
    const char *name = rhizome_manifest_get(m_in, "name", NULL, 0);
    if (name == NULL || !name[0])
      return WHY("Manifest missing 'name' field");
  } else if (strcasecmp(service, RHIZOME_SERVICE_MESHMS) == 0) {
    const char *sender = rhizome_manifest_get(m_in, "sender", NULL, 0);
    const char *recipient = rhizome_manifest_get(m_in, "recipient", NULL, 0);
    if (sender == NULL || !sender[0])
      return WHY("Manifest missing 'sender' field");
    if (!validateSid(sender))
      return WHY("Manifest contains invalid 'sender' field");
    /* If the author was not specified, use the 'sender' as the author, otherwise ensure that they
       match. */
    if (!author)
      author = sender;
    else if (strcasecmp(author, sender))
      return WHYF("Author inconsistent with sender: author=%s, sender=%s", author, sender);
    if (recipient == NULL || !recipient[0])
      return WHY("Manifest missing 'recipient' field");
    if (!validateSid(recipient))
      return WHY("Manifest contains invalid 'recipient' field");
  }
  if (debug & DEBUG_RHIZOME) DEBUGF("author='%s'", author ? author : "(null)");

  /* Keep payload file name handy for later */
  m_in->dataFileName = strdup(filename);

  /* Store time to live, clamped to within legal range */
  m_in->ttl = ttl < 0 ? 0 : ttl > 254 ? 254 : ttl;

  /* Check payload file is accessible and discover its length, then check that it matches
     the file size stored in the manifest */
  if (checkFileP) {
    struct stat stat;
    if (lstat(filename,&stat))
      return WHYF("Could not stat() payload file '%s'",filename);
    m_in->fileLength = stat.st_size;
    if (debug & DEBUG_RHIZOME)
      DEBUGF("filename=%s, fileLength=%lld", filename, m_in->fileLength);
    long long mfilesize = rhizome_manifest_get_ll(m_in, "filesize");
    if (mfilesize != -1 && mfilesize != m_in->fileLength) {
      WHYF("Manifest.filesize (%lld) != actual file size (%lld)", mfilesize, m_in->fileLength);
      if (verifyP)
	return -1;
    }
  }

  /* Bail out now if errors occurred loading the manifest file, eg signature failed to validate */
  if (verifyP && m_in->errors)
      return WHYF("Manifest.errors (%d) is non-zero", m_in->errors);

  /* Compute hash of payload unless we know verification has already failed */
  if (checkFileP || signP) {
    char hexhashbuf[RHIZOME_FILEHASH_STRLEN + 1];
    if (rhizome_hash_file(filename, hexhashbuf))
      return WHY("Could not hash file.");
    memcpy(&m_in->fileHexHash[0], &hexhashbuf[0], sizeof hexhashbuf);
    m_in->fileHashedP = 1;
  }

  /* Check that payload hash matches manifest */
  if (checkFileP) {
    const char *mhexhash = rhizome_manifest_get(m_in, "filehash", NULL, 0);
    if (mhexhash && strcmp(m_in->fileHexHash, mhexhash)) {
      WHYF("Manifest.filehash (%s) does not match payload hash (%s)", mhexhash, m_in->fileHexHash);
      if (verifyP)
	return -1;
    }
  }

  /* Fill in the manifest so that duplicate detection can be performed, and to avoid redundant work
     by rhizome_manifest_finalise() below. */
  if (checkFileP&&m_in->finalised==0) {
    rhizome_manifest_set(m_in, "filehash", m_in->fileHexHash);
  }

  /* Make sure the manifest structure contains the version number, which may legitimately be -1 if
     the caller did not provide a version. */
  m_in->version = rhizome_manifest_get_ll(m_in, "version");

  /* Check if a manifest is already stored for the same payload with the same details.
     This catches the case of "dna rhizome add file <filename>" on the same file more than once.
     (Debounce!) */
  rhizome_manifest *dupm = NULL;
  if (rhizome_find_duplicate(m_in, &dupm) == -1)
    return WHY("Errors encountered searching for duplicate manifest");
  if (dupm) {
    /* If the caller wants the duplicate manifest, it must be finalised, otherwise discarded. */
    if (m_out) {
      if (rhizome_manifest_finalise(dupm, 0,NULL))
	return WHY("Failed to finalise manifest.\n");
      *m_out = dupm;
    }
    else
      rhizome_manifest_free(dupm);
    return 2;
  }

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
    long long storedversion = sqlite_exec_int64("SELECT version from manifests where id='%s';", id);
    if (debug & DEBUG_RHIZOME)
      DEBUGF("Found existing version=%lld, new version=%lld", storedversion, m_in->version);
    if (m_in->version < storedversion) {
      return WHY("Newer version exists");
    }
    if (m_in->version == storedversion) {
      return WHY("Same version exists");
    }
    /* Check if we know its private key */
    rhizome_hex_to_bytes(id, m_in->cryptoSignPublic, crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES*2); 
    if (rhizome_extract_privatekey(m_in, author) == 0)
      m_in->haveSecret=1;
  } else {
    /* The manifest had no ID (256 bit random string being a public key in the NaCl CryptoSign
       crypto system), so create one. */
    rhizome_manifest_createid(m_in);
    /* The ID is implicit in transit, but we need to store it in the file, so that reimporting
       manifests on receiver nodes works easily.  We might implement something that strips the id
       variable out of the manifest when sending it, or some other scheme to avoid sending all the
       extra bytes. */
    rhizome_bytes_to_hex_upper(m_in->cryptoSignPublic, id, crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES);
    rhizome_manifest_set(m_in, "id", id);
    if (author) {
      /* Set the BK using the provided authorship information.
         Serval Security Framework defines BK as being:
         BK = privateKey XOR sha512(RS##BID), where BID = cryptoSignPublic, 
	 and RS is the rhizome secret for the specified author. 
         The nice thing about this specification is that:
         privateKey = BK XOR sha512(RS##BID), so the same function can be used
	 to encrypt and decrypt the BK field. */
      unsigned char bkbytes[RHIZOME_BUNDLE_KEY_BYTES];
      if (rhizome_bk_xor(author, m_in->cryptoSignPublic, m_in->cryptoSignSecret, bkbytes) == 0) {
	char bkhex[RHIZOME_BUNDLE_KEY_STRLEN + 1];
	rhizome_bytes_to_hex_upper(bkbytes, bkhex, RHIZOME_BUNDLE_KEY_BYTES);
	if (debug&DEBUG_RHIZOME) DEBUGF("set BK=%s", bkhex);
	rhizome_manifest_set(m_in, "BK", bkhex);
      } else {
	return WHY("Failed to set BK");
      }
    }   
  }

  /* Add group memberships */
  if (groups) {
    int i;
    for(i = 0; groups[i]; i++)
      rhizome_manifest_add_group(m_in, groups[i]);
  }

  /* Finish completing the manifest */
  if (m_in->finalised==0)
    if (rhizome_manifest_finalise(m_in, signP, author))
      return WHY("Failed to finalise manifest.\n");

  /* Okay, it is written, and can be put directly into the rhizome database now */
  if (rhizome_store_bundle(m_in, filename) == -1)
    return WHY("rhizome_store_bundle() failed.");

  monitor_announce_bundle(m_in);
  if (m_out) *m_out = m_in;
  return 0;
}

/* Update an existing Rhizome bundle */
int rhizome_bundle_push_update(char *id,long long version,unsigned char *data,int appendP)
{
  return WHY("Not implemented");
}

/** Return the uppercase hex digit for a given nybble value 0..15.
 */
char nybltochar_upper(int nybl)
{
  if (nybl<0) return '?';
  if (nybl>15) return '?';
  if (nybl<10) return '0'+nybl;
  return 'A'+nybl-10;
}

int chartonybl(int c)
{
  if (c>='A'&&c<='F') return 0x0a+(c-'A');
  if (c>='a'&&c<='f') return 0x0a+(c-'a');
  if (c>='0'&&c<='9') return 0x00+(c-'0');
  return 0;
}

int rhizome_hex_to_bytes(const char *in,unsigned char *out,int hexChars)
{
  int i;

  for(i=0;i<hexChars;i++)
    {
      int byte=i>>1;
      int nybl=chartonybl(in[i]);
      out[byte]=out[byte]<<4;
      out[byte]|=nybl;
    }
  return 0;
}

/* When voice traffic is being carried, we need to throttle Rhizome down
   to a more sensible level.  Or possibly even supress it entirely.
 */
long long rhizome_voice_timeout=0;
int rhizome_saw_voice_traffic()
{
  /* We are in "voice mode" for a second after sending a voice frame */
  if (rhizome_voice_timeout<overlay_gettime_ms()) {
    WHY("Suppressing Rhizome due to voice traffic");
    rhizome_voice_timeout=overlay_gettime_ms()+1000;
  }
    
  return 0;
}
