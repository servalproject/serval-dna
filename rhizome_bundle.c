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
#include "rhizome.h"
#include "str.h"

int rhizome_manifest_verify(rhizome_manifest *m)
{
  int end_of_text=0;

  /* find end of manifest body and start of signatures */
  while(m->manifestdata[end_of_text]&&end_of_text<m->manifest_all_bytes)
    end_of_text++;
  end_of_text++; /* include null byte in body for verification purposes */

  /* Calculate hash of the text part of the file, as we need to couple this with
     each signature block to */
  crypto_hash_sha512(m->manifesthash,m->manifestdata,end_of_text);
  
  /* Read signature blocks from file. */
  int ofs=end_of_text;  
  while(ofs<m->manifest_all_bytes) {
    if (config.debug.rhizome) DEBUGF("ofs=0x%x, m->manifest_bytes=0x%x", ofs,m->manifest_all_bytes);
    if (rhizome_manifest_extract_signature(m,&ofs)) break;
  }
  
  if (m->sig_count==0) {
    WHYF("Manifest has zero valid signatures");
    m->errors++;
  }
  
  /* Make sure that id variable is correct */
  {
    rhizome_bid_t bid;
    char *id = rhizome_manifest_get(m,"id",NULL,0);
    if (!id) {
      WARN("Manifest lacks 'id' field");
      m->errors++;
    } else if (str_to_rhizome_bid_t(&bid, id) == -1) {
      WARN("Invalid manifest 'id' field");
      m->errors++;
    } else if (m->sig_count == 0 || memcmp(m->signatories[0], bid.binary, sizeof bid.binary) != 0) {
      if (config.debug.rhizome) {
	if (m->sig_count>0) {
	  DEBUGF("Manifest id variable does not match first signature block (signature key is %s)",
		  alloca_tohex(m->signatories[0], crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES)
		  );
	} else {
	  DEBUG("Manifest has no signature blocks, but should have self-signature block");
	}
      }
      m->errors++;
      m->selfSigned=0;
    } else {
      m->selfSigned=1;
    }
  }

  /* Mark as finalised, as it is all read and intact,
     unless of course it has errors, or is lacking a self-signature. */
  if (!m->errors) m->finalised=1;
  else WHY("Verified a manifest that has errors, so marking as not finalised");

  if (m->errors) return WHY("Manifest verification failed");
  else return 0;
}

ssize_t read_whole_file(const char *path, unsigned char *buffer, size_t buffer_size)
{
  int fd = open(path, O_RDONLY);
  if (fd == -1)
    return WHYF_perror("open(%s,O_RDONLY)", alloca_str_toprint(path));
  ssize_t ret = read(fd, buffer, buffer_size);
  if (ret == -1)
    ret = WHYF_perror("read(%s,%u)", alloca_str_toprint(path), buffer_size);
  if (close(fd) == -1)
    ret = WHY_perror("close");
  return ret;
}

int rhizome_manifest_parse(rhizome_manifest *m)
{
  IN();
  m->manifest_all_bytes=m->manifest_bytes;
  m->var_count=0;
  m->journalTail=-1;

  /* Parse out variables, signature etc */
  int have_service = 0;
  int have_id = 0;
  int have_version = 0;
  int have_date = 0;
  int have_filesize = 0;
  int have_filehash = 0;
  
  int ofs = 0;
  while (ofs < m->manifest_bytes && m->manifestdata[ofs]) {
    char line[1024];
    int limit = ofs + sizeof line - 1;
    if (limit > m->manifest_bytes)
      limit = m->manifest_bytes;
    char *p = line;
    while (ofs < limit && !(m->manifestdata[ofs] == '\0' || m->manifestdata[ofs] == '\n' || m->manifestdata[ofs] == '\r'))
	  *p++ = m->manifestdata[ofs++];
    *p = '\0';
    if (m->manifestdata[ofs] == '\r')
      ++ofs;
    if (m->manifestdata[ofs] == '\n')
      ++ofs;
    /* Ignore blank lines */
    if (line[0] == '\0')
      continue;
    /* Ignore comment lines */
    if (line[0] == '#' || line[0] == '!')
      continue;
    /* Parse field=value lines */
    size_t linelen = p - line;
    p = strchr(line, '=');
    if (p == NULL || p == line) {
      m->errors++;
      WARNF("Malformed manifest line: %s", alloca_toprint(80, line, linelen));
    } else {
      *p++ = '\0';
      char *var = line;
      char *value = p;
      if (rhizome_manifest_get(m, var, NULL, 0)) {
	if (config.debug.rejecteddata)
	  WARNF("Ill formed manifest file, duplicate variable \"%s\"", var);
	m->errors++;
      } else if (m->var_count >= MAX_MANIFEST_VARS) {
	if (config.debug.rejecteddata)
	  WARN("Ill formed manifest file, too many variables");
	m->errors++;
      } else {
	m->vars[m->var_count] = strdup(var);
	m->values[m->var_count] = strdup(value);
	
	// if any of these fields are not well formed, the manifest is invalid and cannot be imported
	
	if (strcasecmp(var, "id") == 0) {
	  have_id = 1;
	  if (str_to_rhizome_bid_t(&m->cryptoSignPublic, value) == -1) {
	    if (config.debug.rejecteddata)
	      WARNF("Invalid manifest id: %s", value);
	    m->errors++;
	  } else {
	    /* Force to upper case to avoid case sensitive comparison problems later. */
	    str_toupper_inplace(m->values[m->var_count]);
	  }
	} else if (strcasecmp(var, "filehash") == 0) {
	  have_filehash = 1;
	  if (str_to_rhizome_filehash_t(&m->filehash, value) == -1) {
	    if (config.debug.rejecteddata)
	      WARNF("Invalid filehash: %s", value);
	    m->errors++;
	  } else {
	    /* Force to upper case to avoid case sensitive comparison problems later. */
	    str_toupper_inplace(m->values[m->var_count]);
	  }
	} else if (strcasecmp(var, "filesize") == 0) {
	  have_filesize = 1;
	  uint64_t filesize;
	  if (!str_to_uint64(value, 10, &filesize, NULL)) {
	    if (config.debug.rejecteddata)
	      WARNF("Invalid filesize: %s", value);
	    m->errors++;
	  } else {
	    m->fileLength = filesize;
	  }
	} else if (strcasecmp(var, "version") == 0) {
	  have_version = 1;
	  uint64_t version;
	  if (!str_to_uint64(value, 10, &version, NULL)) {
	    if (config.debug.rejecteddata)
	      WARNF("Invalid version: %s", value);
	    m->errors++;
	  } else {
	    m->version = version;
	  }
	// since rhizome *MUST* be able to carry future manifest versions
	// if any of these fields are not well formed, the manifest can still be imported and exported
	// but the bundle should not be added or exported
	} else if (strcasecmp(var, "tail") == 0) {
	  uint64_t tail;
	  if (!str_to_uint64(value, 10, &tail, NULL)) {
	    if (config.debug.rejecteddata)
	      WARNF("Invalid tail: %s", value);
	    m->warnings++;
	  } else {
	    m->journalTail = tail;
	  }
	} else if (strcasecmp(var, "BK") == 0) {
	  if (!rhizome_str_is_bundle_key(value)) {
	    if (config.debug.rejecteddata)
	      WARNF("Invalid BK: %s", value);
	    m->warnings++;
	  } else {
	    /* Force to upper case to avoid case sensitive comparison problems later. */
	    str_toupper_inplace(m->values[m->var_count]);
	  }
	} else if (strcasecmp(var, "service") == 0) {
	  have_service = 1;
	  if ( strcasecmp(value, RHIZOME_SERVICE_FILE) == 0
	    || strcasecmp(value, RHIZOME_SERVICE_MESHMS) == 0
	    || strcasecmp(value, RHIZOME_SERVICE_MESHMS2) == 0) {
	  } else {
	    if (config.debug.rejecteddata)
	      WARNF("Unsupported service: %s", value);
	    m->warnings++;
	  }
	} else if (strcasecmp(var, "date") == 0) {
	  have_date = 1;
	  int64_t date;
	  if (!str_to_int64(value, 10, &date, NULL)) {
	    if (config.debug.rejecteddata)
	      WARNF("Invalid date: %s", value);
	    m->warnings++;
	  }
	  // TODO: store date in manifest struct
	} else if (strcasecmp(var, "sender") == 0 || strcasecmp(var, "recipient") == 0) {
	  if (!str_is_subscriber_id(value)) {
	    if (config.debug.rejecteddata)
	      WARNF("Invalid %s: %s", var, value);
	    m->warnings++;
	  } else {
	    /* Force to upper case to avoid case sensitive comparison problems later. */
	    str_toupper_inplace(m->values[m->var_count]);
	  }
	} else if (strcasecmp(var, "name") == 0) {
	  if (value[0] == '\0') {
	    if (config.debug.rejecteddata)
	      WARN("Empty name");
	    m->warnings++;
	  }
	} else if (strcasecmp(var, "crypt") == 0) {
	  if (!(strcmp(value, "0") == 0 || strcmp(value, "1") == 0)) {
	    if (config.debug.rejecteddata)
	      WARNF("Invalid crypt: %s", value);
	    m->warnings++;
	  } else {
	    m->payloadEncryption = atoi(value);
	  }
	} else {
	  // An unknown field is not an error... older rhizome nodes must carry newer manifests.
	}
	m->var_count++;
      }
    }
  }
  /* The null byte gets included in the check sum */
  if (ofs < m->manifest_bytes)
    ++ofs;

  /* Remember where the text ends */
  int end_of_text=ofs;
  m->manifest_bytes = end_of_text;

  // verify that all required fields are consistent.
  if (!have_id) {
    if (config.debug.rejecteddata)
      WARNF("Missing manifest id field");
    m->errors++;
  }
  if (!have_version) {
    if (config.debug.rejecteddata)
      WARNF("Missing version field");
    m->errors++;
  }
  if (!have_filesize) {
    if (config.debug.rejecteddata)
      WARNF("Missing filesize field");
    m->errors++;
  }
  if (!have_filehash && m->fileLength != 0) {
    if (config.debug.rejecteddata)
      WARNF("Missing filehash field");
    m->errors++;
  }
  if (have_filehash && m->fileLength == 0) {
    if (config.debug.rejecteddata)
      WARNF("Spurious filehash field");
    m->errors++;
  }

  // warn if expected fields are missing
  if (!have_service) {
    if (config.debug.rejecteddata)
      WARNF("Missing service field");
    m->warnings++;
  }
  if (!have_date) {
    if (config.debug.rejecteddata)
      WARNF("Missing date field");
    m->warnings++;
  }
  
  // TODO Determine group membership here.

  if (m->errors || m->warnings) {
    if (config.debug.rejecteddata)
      dump("manifest body",m->manifestdata,m->manifest_bytes);
  }

  RETURN(0);
  OUT();
}

int rhizome_read_manifest_file(rhizome_manifest *m, const char *filename, size_t bufferP)
{
  if (!m)
    return WHY("Null manifest");
  if (bufferP>sizeof(m->manifestdata))
    return WHY("Buffer too big");

  if (bufferP) {
    m->manifest_bytes=bufferP;
    memcpy(m->manifestdata, filename, m->manifest_bytes);
  } else {
    ssize_t bytes = read_whole_file(filename, m->manifestdata, sizeof m->manifestdata);
    if (bytes == -1)
      return -1;
    m->manifest_bytes = bytes;
  }
  return rhizome_manifest_parse(m);
}

int rhizome_hash_file(rhizome_manifest *m, const char *path, rhizome_filehash_t *hash_out, uint64_t *size_out)
{
  /* Gnarf! NaCl's crypto_hash() function needs the whole file passed in in one
     go.  Trouble is, we need to run Serval DNA on filesystems that lack mmap(),
     and may be very resource constrained. Thus we need a streamable SHA-512
     implementation.
  */
  // TODO encrypted payloads
  if (m && m->payloadEncryption) 
    return WHY("Encryption of payloads not implemented");

  uint64_t filesize = 0;
  SHA512_CTX context;
  SHA512_Init(&context);
  if (path[0]) {
    int fd = open(path, O_RDONLY);
    if (fd == -1)
      return WHYF_perror("open(%s,O_RDONLY)", alloca_str_toprint(path));
    unsigned char buffer[8192];
    ssize_t r;
    while ((r = read(fd, buffer, sizeof buffer))) {
      if (r == -1) {
	WHYF_perror("read(%s,%u)", alloca_str_toprint(path), sizeof buffer);
	close(fd);
	return -1;
      }
      SHA512_Update(&context, buffer, (size_t) r);
      filesize += (size_t) r;
    }
    close(fd);
  }
  // Empty files (including empty path) have no hash.
  if (hash_out) {
    if (filesize > 0)
      SHA512_Final(hash_out->binary, &context);
    else
      *hash_out = RHIZOME_FILEHASH_NONE;
  }
  if (size_out)
    *size_out = filesize;
  SHA512_End(&context, NULL);
  return 0;
}

char *rhizome_manifest_get(const rhizome_manifest *m, const char *var, char *out, int maxlen)
{
  int i,j;

  if (!m) return NULL;

  for(i=0;i<m->var_count;i++)
    if (!strcmp(m->vars[i],var)) {
      if (out) {
	for(j=0;(j<maxlen);j++) {
	  out[j]=m->values[i][j];
	  if (!out[j]) break;
	}
      }
      return m->values[i];
    }
  return NULL;
}

int64_t rhizome_manifest_get_ll(rhizome_manifest *m, const char *var)
{
  if (!m)
    return -1;
  int i;
  for (i = 0; i < m->var_count; ++i)
    if (!strcmp(m->vars[i], var)) {
      int64_t val;
      return str_to_int64(m->values[i], 10, &val, NULL) ? val : -1;
    }
  return -1;
}

double rhizome_manifest_get_double(rhizome_manifest *m,char *var,double default_value)
{
  int i;

  if (!m) return default_value;

  for(i=0;i<m->var_count;i++)
    if (!strcmp(m->vars[i],var))
      return strtod(m->values[i],NULL);
  return default_value;
}

/* @author Andrew Bettison <andrew@servalproject.com>
 */
int rhizome_manifest_del(rhizome_manifest *m, const char *var)
{
  int ret = 0;
  int i;
  for (i = 0; i < m->var_count; ++i)
    if (strcmp(m->vars[i], var) == 0) {
      free(m->vars[i]); 
      free(m->values[i]); 
      --m->var_count;
      m->finalised = 0;
      ret = 1;
      break;
    }
  for (; i < m->var_count; ++i) {
    m->vars[i] = m->vars[i + 1];
    m->values[i] = m->values[i + 1];
  }
  return ret;
}

int rhizome_manifest_set(rhizome_manifest *m, const char *var, const char *value)
{
  if (!m)
    return WHY("m == NULL");
  int i;
  for(i=0;i<m->var_count;i++)
    if (!strcmp(m->vars[i],var)) {
      free(m->values[i]); 
      m->values[i]=strdup(value);
      m->finalised=0;
      return 0;
    }
  if (m->var_count >= MAX_MANIFEST_VARS)
    return WHY("no more manifest vars");
  m->vars[m->var_count]=strdup(var);
  m->values[m->var_count]=strdup(value);
  m->var_count++;
  m->finalised=0;
  return 0;
}

int rhizome_manifest_set_ll(rhizome_manifest *m, char *var, int64_t value)
{
  char str[50];
  snprintf(str, sizeof str, "%" PRId64, value);
  return rhizome_manifest_set(m, var, str);
}

rhizome_manifest manifests[MAX_RHIZOME_MANIFESTS];
char manifest_free[MAX_RHIZOME_MANIFESTS];
int manifest_first_free=-1;
struct __sourceloc manifest_alloc_whence[MAX_RHIZOME_MANIFESTS];
struct __sourceloc manifest_free_whence[MAX_RHIZOME_MANIFESTS];

static void _log_manifest_trace(struct __sourceloc __whence, const char *operation)
{
  int count_free = 0;
  int i;
  for (i = 0; i != MAX_RHIZOME_MANIFESTS; ++i)
    if (manifest_free[i])
      ++count_free;
  DEBUGF("%s(): count_free = %d", operation, count_free);
}

rhizome_manifest *_rhizome_new_manifest(struct __sourceloc __whence)
{
  if (manifest_first_free<0) {
    /* Setup structures */
    int i;
    for(i=0;i<MAX_RHIZOME_MANIFESTS;i++) {
      manifest_alloc_whence[i]=__NOWHERE__;
      manifest_free_whence[i]=__NOWHERE__;
      manifest_free[i]=1;
    }
    manifest_first_free=0;
  }

  /* No free manifests */
  if (manifest_first_free>=MAX_RHIZOME_MANIFESTS)
    {
      int i;
      WHYF("%s(): no free manifest records, this probably indicates a memory leak", __FUNCTION__);
      WHYF("   Slot# | Last allocated by");
      for(i=0;i<MAX_RHIZOME_MANIFESTS;i++) {
	WHYF("   %-5d | %s:%d in %s()",
		i,
		manifest_alloc_whence[i].file,
		manifest_alloc_whence[i].line,
		manifest_alloc_whence[i].function
	    );
      }     
      return NULL;
    }

  rhizome_manifest *m=&manifests[manifest_first_free];
  bzero(m,sizeof(rhizome_manifest));
  m->manifest_record_number=manifest_first_free;

  /* Indicate where manifest was allocated, and that it is no longer
     free. */
  manifest_alloc_whence[manifest_first_free]=__whence;
  manifest_free[manifest_first_free]=0;
  manifest_free_whence[manifest_first_free]=__NOWHERE__;

  /* Work out where next free manifest record lives */
  for (; manifest_first_free < MAX_RHIZOME_MANIFESTS && !manifest_free[manifest_first_free]; ++manifest_first_free)
    ;

  if (config.debug.manifests) _log_manifest_trace(__whence, __FUNCTION__);

  // Set global defaults for a manifest
  m->journalTail = -1;

  return m;
}

void _rhizome_manifest_free(struct __sourceloc __whence, rhizome_manifest *m)
{
  if (!m) return;
  int i;
  int mid=m->manifest_record_number;

  if (m!=&manifests[mid]) {
    WHYF("%s(): asked to free manifest %p, which claims to be manifest slot #%d (%p), but isn't",
	__FUNCTION__, m, mid, &manifests[mid]
      );
    exit(-1);
  }

  if (manifest_free[mid]) {
    WHYF("%s(): asked to free manifest slot #%d (%p), which was already freed at %s:%d:%s()",
	__FUNCTION__, mid, m,
	manifest_free_whence[mid].file,
	manifest_free_whence[mid].line,
	manifest_free_whence[mid].function
      );
    exit(-1);
  }

  /* Free variable and signature blocks.
     XXX These should be moved to malloc-free storage eventually */
  for(i=0;i<m->var_count;i++)
    { free(m->vars[i]); free(m->values[i]); 
      m->vars[i]=NULL; m->values[i]=NULL; }
  for(i=0;i<m->sig_count;i++)
    { free(m->signatories[i]);
      m->signatories[i]=NULL;
    }

  if (m->dataFileName) {
    if (m->dataFileUnlinkOnFree && unlink(m->dataFileName) == -1)
      WARNF_perror("unlink(%s)", alloca_str_toprint(m->dataFileName));
    free(m->dataFileName);
    m->dataFileName = NULL;
  }

  manifest_free[mid]=1;
  manifest_free_whence[mid]=__whence;
  if (mid<manifest_first_free) manifest_first_free=mid;

  if (config.debug.manifests) _log_manifest_trace(__whence, __FUNCTION__);

  return;
}

/* Convert variable list to string, complaining if it ends up
   too long. 
   Signatures etc will be added later. */
int rhizome_manifest_pack_variables(rhizome_manifest *m)
{
  int i,ofs=0;

  for(i=0;i<m->var_count;i++)
    {
      if ((ofs+strlen(m->vars[i])+1+strlen(m->values[i])+1+1)>MAX_MANIFEST_BYTES)
	return WHY("Manifest variables too long in total to fit in MAX_MANIFEST_BYTES");
      snprintf((char *)&m->manifestdata[ofs],MAX_MANIFEST_BYTES-ofs,"%s=%s\n",
	       m->vars[i],m->values[i]);
      ofs+=strlen((char *)&m->manifestdata[ofs]);
    }
  m->manifestdata[ofs++]=0x00;
  m->manifest_bytes=ofs;
  if (config.debug.rhizome) DEBUG("Repacked variables in manifest.");
  m->manifest_all_bytes=ofs;

  /* Recalculate hash */
  crypto_hash_sha512(m->manifesthash,m->manifestdata,m->manifest_bytes);

  return 0;
}

/* Sign this manifest using our it's own BID secret key.
   TODO: need a third-party signing primitive, eg, to support signing with SAS.
 */
int rhizome_manifest_selfsign(rhizome_manifest *m)
{
  if (!m->haveSecret)
    return WHY("Need private key to sign manifest");
  rhizome_signature sig;
  if (rhizome_sign_hash(m, &sig) == -1)
    return WHY("rhizome_sign_hash() failed");
  /* Append signature to end of manifest data */
  if (sig.signatureLength + m->manifest_bytes > MAX_MANIFEST_BYTES)
    return WHY("Manifest plus signatures is too long");
  bcopy(&sig.signature[0], &m->manifestdata[m->manifest_bytes], sig.signatureLength);
  m->manifest_bytes += sig.signatureLength;
  m->manifest_all_bytes = m->manifest_bytes;
  return 0;
}

int rhizome_write_manifest_file(rhizome_manifest *m, const char *path, char append)
{
  if (config.debug.rhizome)
    DEBUGF("write manifest (%d bytes) to %s", m->manifest_all_bytes, path);
  if (!m)
    return WHY("Manifest is null.");
  if (!m->finalised)
    return WHY("Manifest must be finalised before it can be written.");
  int fd = open(path, O_WRONLY | O_CREAT | (append ? O_APPEND : 0), 0666);
  if (fd == -1)
    return WHYF_perror("open(%s,O_WRONLY|O_CREAT%s,0666)", alloca_str_toprint(path), append ? "|O_APPEND" : "");
  int ret = 0;
  if (write_all(fd, m->manifestdata, m->manifest_all_bytes) == -1)
    ret = -1;
  else if (append) {
    unsigned char marker[4];
    write_uint16(marker, m->manifest_all_bytes);
    marker[2]=0x41;
    marker[3]=0x10;
    if (write_all(fd, marker, sizeof marker) == -1)
      ret = -1;
  }
  if (close(fd) == -1)
    ret = WHY_perror("close");
  return ret;
}

/*
  Adds a group that this bundle should be present in.  If we have the means to sign
  the bundle as a member of that group, then we create the appropriate signature block.
  The group signature blocks, like all signature blocks, will be appended to the
  manifest data during the finalisation process.
 */
int rhizome_manifest_add_group(rhizome_manifest *m,char *groupid)
{
  return WHY("Not implemented.");
}

int rhizome_manifest_dump(rhizome_manifest *m, const char *msg)
{
  int i;
  WHYF("Dumping manifest %s:", msg);
  for(i=0;i<m->var_count;i++)
    WHYF("[%s]=[%s]\n", m->vars[i], m->values[i]);
  return 0;
}

int rhizome_manifest_finalise(rhizome_manifest *m, rhizome_manifest **mout, int deduplicate)
{
  IN();
  int ret=0;
  
  // if a manifest was supplied with an ID, don't bother to check for a duplicate.
  // we only want to filter out added files with no existing manifest.
  if (deduplicate && m->haveSecret != EXISTING_BUNDLE_ID && rhizome_find_duplicate(m, mout) == 1)
    RETURN(2);
  
  *mout=m;
  
  /* Convert to final form for signing and writing to disk */
  if (rhizome_manifest_pack_variables(m))
    RETURN(WHY("Could not convert manifest to wire format"));
  
  /* Sign it */
  if (rhizome_manifest_selfsign(m))
    RETURN(WHY("Could not sign manifest"));
  
  /* mark manifest as finalised */
  m->finalised=1;
  ret=rhizome_add_manifest(m, 255 /* TTL */);
  
  RETURN(ret);
  OUT();
}

int rhizome_fill_manifest(rhizome_manifest *m, const char *filepath, const sid_t *authorSidp, rhizome_bk_t *bsk){
  /* Fill in a few missing manifest fields, to make it easier to use when adding new files:
   - the default service is FILE
   - use the current time for "date"
   - if service is file, then use the payload file's basename for "name"
   */
  const char *service = rhizome_manifest_get(m, "service", NULL, 0);
  if (service == NULL)
    return WHYF("missing 'service'");
  if (config.debug.rhizome)
    DEBUGF("manifest service=%s", service);
  if (rhizome_manifest_get(m, "date", NULL, 0) == NULL) {
    rhizome_manifest_set_ll(m, "date", (int64_t) gettime_ms());
    if (config.debug.rhizome) DEBUGF("missing 'date', set default date=%s", rhizome_manifest_get(m, "date", NULL, 0));
  }
  
  if (strcasecmp(RHIZOME_SERVICE_FILE, service) == 0) {
    const char *name = rhizome_manifest_get(m, "name", NULL, 0);
    if (name == NULL) {
      if (filepath && *filepath){
	name = strrchr(filepath, '/');
	name = name ? name + 1 : filepath;
      }else
	name="";
      rhizome_manifest_set(m, "name", name);
      if (config.debug.rhizome) DEBUGF("missing 'name', set default name=\"%s\"", name);
    } else {
      if (config.debug.rhizome) DEBUGF("manifest contains name=\"%s\"", name);
    }
  }
  
  /* If the author was not specified, then the manifest's "sender"
   field is used, if present. */
  if (authorSidp)
    m->author = *authorSidp;
  else{
    const char *sender = rhizome_manifest_get(m, "sender", NULL, 0);
    if (sender){
      if (str_to_sid_t(&m->author, sender) == -1)
	return WHYF("invalid sender: %s", sender);
    }
  }

  /* set version of manifest, either from version variable, or using current time */
  if (rhizome_manifest_get(m,"version",NULL,0)==NULL)
  {
    /* No version set, default to the current time */
    m->version = gettime_ms();
    rhizome_manifest_set_ll(m,"version",m->version);
  }
  
  if (!m->haveSecret){
    const char *id = rhizome_manifest_get(m, "id", NULL, 0);
    if (id == NULL) {
      if (config.debug.rhizome) DEBUG("creating new bundle");
      if (rhizome_manifest_bind_id(m) == -1) {
	return WHY("Could not bind manifest to an ID");
      }
    } else {
      if (config.debug.rhizome) DEBUGF("modifying existing bundle bid=%s", id);
      
      // Modifying an existing bundle.  Make sure we can find the bundle secret.
      if (rhizome_extract_privatekey_required(m, bsk))
	return -1;
      
      // TODO assert that new version > old version?
    }
  }
  assert(m->haveSecret);
  
  int crypt = rhizome_manifest_get_ll(m,"crypt"); 
  if (crypt==-1){
    // no explicit crypt flag, should we encrypt this bundle?
    char *sender = rhizome_manifest_get(m, "sender", NULL, 0);
    char *recipient = rhizome_manifest_get(m, "recipient", NULL, 0);
    
    // anything sent from one person to another should be considered private and encrypted by default
    if (sender && recipient){
      sid_t s_sender, s_recipient;
      if (cf_opt_sid(&s_sender, sender)==CFOK 
	&& cf_opt_sid(&s_recipient, recipient)==CFOK
	&& !is_sid_t_broadcast(s_recipient)){
	if (config.debug.rhizome)
	  DEBUGF("Implicitly adding payload encryption due to presense of sender & recipient fields");
	m->payloadEncryption=1;
	rhizome_manifest_set_ll(m,"crypt",1LL); 
      }
    }
  }
  
  return 0;
}
