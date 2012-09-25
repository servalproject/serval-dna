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
#include "serval.h"
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
    if (debug & DEBUG_RHIZOME) DEBUGF("ofs=0x%x, m->manifest_bytes=0x%x", ofs,m->manifest_all_bytes);
    if (rhizome_manifest_extract_signature(m,&ofs)) break;
  }
  
  if (m->sig_count==0) {
    WHYF("Manifest has zero valid signatures");
    m->errors++;
  }
  
  /* Make sure that id variable is correct */
  {
    unsigned char manifest_id[RHIZOME_MANIFEST_ID_BYTES];
    char *id = rhizome_manifest_get(m,"id",NULL,0);
    if (!id) {
      WARN("Manifest lacks 'id' field");
      m->errors++;
    } else if (fromhexstr(manifest_id, id, RHIZOME_MANIFEST_ID_BYTES) == -1) {
      WARN("Invalid manifest 'id' field");
      m->errors++;
    } else if (m->sig_count == 0 || memcmp(m->signatories[0], manifest_id, RHIZOME_MANIFEST_ID_BYTES) != 0) {
      if (debug&DEBUG_RHIZOME) {
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

int rhizome_read_manifest_file(rhizome_manifest *m, const char *filename, int bufferP)
{
  IN();
  if (bufferP>MAX_MANIFEST_BYTES) RETURN(WHY("Buffer too big"));
  if (!m) RETURN(WHY("Null manifest"));

  if (bufferP) {
    m->manifest_bytes=bufferP;
    memcpy(m->manifestdata, filename, m->manifest_bytes);
  } else {
    FILE *f = fopen(filename, "r");
    if (f == NULL)
      RETURN(WHYF("Could not open manifest file %s for reading.", filename)); 
    m->manifest_bytes = fread(m->manifestdata, 1, MAX_MANIFEST_BYTES, f);
    int ret = 0;
    if (m->manifest_bytes == -1)
      ret = WHY_perror("fread");
    if (fclose(f) == EOF)
      ret = WHY_perror("fclose");
    if (ret == -1)
      RETURN(-1);
  }

  m->manifest_all_bytes=m->manifest_bytes;

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
      WARNF(bufferP ? "Malformed manifest line in buffer %p: %s"
		    : "Malformed manifest line in file %s: %s",
	  filename, alloca_toprint(80, line, linelen));
    } else {
      *p++ = '\0';
      char *var = line;
      char *value = p;
      if (rhizome_manifest_get(m, var, NULL, 0)) {
	WARNF("Ill formed manifest file, duplicate variable \"%s\"", var);
	m->errors++;
      } else if (m->var_count >= MAX_MANIFEST_VARS) {
	WARN("Ill formed manifest file, too many variables");
	m->errors++;
      } else {
	m->vars[m->var_count] = strdup(var);
	m->values[m->var_count] = strdup(value);
	if (strcasecmp(var, "id") == 0) {
	  have_id = 1;
	  if (fromhexstr(m->cryptoSignPublic, value, RHIZOME_MANIFEST_ID_BYTES) == -1) {
	    WARNF("Invalid manifest id: %s", value);
	    m->errors++;
	  } else {
	    /* Force to upper case to avoid case sensitive comparison problems later. */
	    str_toupper_inplace(m->values[m->var_count]);
	  }
	} else if (strcasecmp(var, "filehash") == 0) {
	  have_filehash = 1;
	  if (!rhizome_str_is_file_hash(value)) {
	    WARNF("Invalid filehash: %s", value);
	    m->errors++;
	  } else {
	    /* Force to upper case to avoid case sensitive comparison problems later. */
	    str_toupper_inplace(m->values[m->var_count]);
	    strcpy(m->fileHexHash, m->values[m->var_count]);
	    m->fileHashedP = 1;
	  }
	} else if (strcasecmp(var, "BK") == 0) {
	  if (!rhizome_str_is_bundle_key(value)) {
	    WARNF("Invalid BK: %s", value);
	    m->errors++;
	  } else {
	    /* Force to upper case to avoid case sensitive comparison problems later. */
	    str_toupper_inplace(m->values[m->var_count]);
	  }
	} else if (strcasecmp(var, "filesize") == 0) {
	  have_filesize = 1;
	  char *ep = value;
	  long long filesize = strtoll(value, &ep, 10);
	  if (ep == value || *ep || filesize < 0) {
	    WARNF("Invalid filesize: %s", value);
	    m->errors++;
	  } else {
	    m->fileLength = filesize;
	  }
	} else if (strcasecmp(var, "service") == 0) {
	  have_service = 1;
	  if ( strcasecmp(value, RHIZOME_SERVICE_FILE) == 0
	    || strcasecmp(value, RHIZOME_SERVICE_MESHMS) == 0) {
	  } else {
	    INFOF("Unsupported service: %s", value);
	    // This is not an error... older rhizome nodes must carry newer manifests.
	  }
	} else if (strcasecmp(var, "version") == 0) {
	  have_version = 1;
	  char *ep = value;
	  long long version = strtoll(value, &ep, 10);
	  if (ep == value || *ep || version < 0) {
	    WARNF("Invalid version: %s", value);
	    m->errors++;
	  } else {
	    m->version = version;
	  }
	} else if (strcasecmp(var, "date") == 0) {
	  have_date = 1;
	  char *ep = value;
	  long long date = strtoll(value, &ep, 10);
	  if (ep == value || *ep || date < 0) {
	    WARNF("Invalid date: %s", value);
	    m->errors++;
	  }
	  // TODO: store date in manifest struct
	} else if (strcasecmp(var, "sender") == 0 || strcasecmp(var, "recipient") == 0) {
	  if (!str_is_subscriber_id(value)) {
	    WARNF("Invalid %s: %s", var, value);
	    m->errors++;
	  } else {
	    /* Force to upper case to avoid case sensitive comparison problems later. */
	    str_toupper_inplace(m->values[m->var_count]);
	  }
	} else if (strcasecmp(var, "name") == 0) {
	  if (value[0] == '\0') {
	    WARNF("Empty name", value);
	    m->errors++;
	  }
	  // TODO: complain if service is not MeshMS
	} else if (strcasecmp(var, "crypt") == 0) {
	  if (!(strcmp(value, "0") == 0 || strcmp(value, "1") == 0)) {
	    WARNF("Invalid crypt: %s", value);
	    m->errors++;
	  } else {
	    m->payloadEncryption = atoi(value);
	  }
	} else {
	  INFOF("Unsupported field: %s=%s", var, value);
	  // This is not an error... older rhizome nodes must carry newer manifests.
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

  if (!have_service) {
    WARNF("Missing service field");
    m->errors++;
  }
  if (!have_id) {
    WARNF("Missing manifest id field");
    m->errors++;
  }
  if (!have_version) {
    WARNF("Missing version field");
    m->errors++;
  }
  if (!have_date) {
    WARNF("Missing date field");
    m->errors++;
  }
  if (!have_filesize) {
    WARNF("Missing filesize field");
    m->errors++;
  }
  if (!have_filehash && m->fileLength != 0) {
    WARNF("Missing filehash field");
    m->errors++;
  }
  if (have_filehash && m->fileLength == 0) {
    WARNF("Spurious filehash field");
    m->errors++;
  }

  // TODO Determine group membership here.

  RETURN(0);
}

int rhizome_hash_file(rhizome_manifest *m,const char *filename,char *hash_out)
{
  /* Gnarf! NaCl's crypto_hash() function needs the whole file passed in in one
     go.  Trouble is, we need to run Serval DNA on filesystems that lack mmap(),
     and may be very resource constrained. Thus we need a streamable SHA-512
     implementation.
  */
  // TODO encrypted payloads
  if (m && m->payloadEncryption) 
    return WHY("Encryption of payloads not implemented");

  SHA512_CTX context;
  SHA512_Init(&context);
  if (filename[0]) {
    FILE *f = fopen(filename, "r");
    if (!f) {
      WHY_perror("fopen");
      return WHYF("Could not open %s to calculate SHA512 hash.", filename);
    }
    while (!feof(f)) {
      unsigned char buffer[8192];
      int r = fread(buffer, 1, 8192, f);
      if (r == -1) {
	WHY_perror("fread");
	fclose(f);
	return WHYF("Error reading %s to calculate SHA512 hash", filename);
      }
      if (r > 0)
	SHA512_Update(&context, buffer, r);
    }
    fclose(f);
  }
  SHA512_End(&context, (char *)hash_out);
  str_toupper_inplace(hash_out);
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

long long rhizome_manifest_get_ll(rhizome_manifest *m, const char *var)
{
  if (!m)
    return -1;
  int i;
  for (i = 0;i != m->var_count; ++i)
    if (!strcmp(m->vars[i], var)) {
      char *vp = m->values[i];
      char *ep = vp;
      long long val = strtoll(vp, &ep, 10);
      return (ep != vp && *ep == '\0') ? val : -1;
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

int rhizome_manifest_set_ll(rhizome_manifest *m,char *var,long long value)
{
  char svalue[100];

  snprintf(svalue,100,"%lld",value);

  return rhizome_manifest_set(m,var,svalue);
}

rhizome_manifest manifests[MAX_RHIZOME_MANIFESTS];
char manifest_free[MAX_RHIZOME_MANIFESTS];
int manifest_first_free=-1;
struct __sourceloc manifest_alloc_where[MAX_RHIZOME_MANIFESTS];
struct __sourceloc manifest_free_where[MAX_RHIZOME_MANIFESTS];

static void _log_manifest_trace(struct __sourceloc where, const char *operation)
{
  int count_free = 0;
  int i;
  for (i = 0; i != MAX_RHIZOME_MANIFESTS; ++i)
    if (manifest_free[i])
      ++count_free;
  logMessage(LOG_LEVEL_DEBUG, where, "%s(): count_free = %d", operation, count_free);
}

rhizome_manifest *_rhizome_new_manifest(struct __sourceloc where)
{
  if (manifest_first_free<0) {
    /* Setup structures */
    int i;
    for(i=0;i<MAX_RHIZOME_MANIFESTS;i++) {
      manifest_alloc_where[i]=__NOWHERE__;
      manifest_free_where[i]=__NOWHERE__;
      manifest_free[i]=1;
    }
    manifest_first_free=0;
  }

  /* No free manifests */
  if (manifest_first_free>=MAX_RHIZOME_MANIFESTS)
    {
      int i;
      logMessage(LOG_LEVEL_ERROR, where, "%s(): no free manifest records, this probably indicates a memory leak", __FUNCTION__);
      WHYF("   Slot# | Last allocated by");
      for(i=0;i<MAX_RHIZOME_MANIFESTS;i++) {
	WHYF("   %-5d | %s:%d in %s()",
		i,
		manifest_alloc_where[i].file,
		manifest_alloc_where[i].line,
		manifest_alloc_where[i].function
	    );
      }     
      return NULL;
    }

  rhizome_manifest *m=&manifests[manifest_first_free];
  bzero(m,sizeof(rhizome_manifest));
  m->manifest_record_number=manifest_first_free;

  /* Indicate where manifest was allocated, and that it is no longer
     free. */
  manifest_alloc_where[manifest_first_free]=where;
  manifest_free[manifest_first_free]=0;
  manifest_free_where[manifest_first_free]=__NOWHERE__;

  /* Work out where next free manifest record lives */
  for (; manifest_first_free < MAX_RHIZOME_MANIFESTS && !manifest_free[manifest_first_free]; ++manifest_first_free)
    ;

  if (debug & DEBUG_MANIFESTS) _log_manifest_trace(where, __FUNCTION__);

  return m;
}

void _rhizome_manifest_free(struct __sourceloc where, rhizome_manifest *m)
{
  if (!m) return;
  int i;
  int mid=m->manifest_record_number;

  if (m!=&manifests[mid]) {
    logMessage(LOG_LEVEL_ERROR, where,
	"%s(): asked to free manifest %p, which claims to be manifest slot #%d (%p), but isn't",
	__FUNCTION__, m, mid, &manifests[mid]
      );
    exit(-1);
  }

  if (manifest_free[mid]) {
    logMessage(LOG_LEVEL_ERROR, where,
	"%s(): asked to free manifest slot #%d (%p), which was already freed at %s:%d:%s()",
	__FUNCTION__, mid, m,
	manifest_free_where[mid].file,
	manifest_free_where[mid].line,
	manifest_free_where[mid].function
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

  if (m->dataFileName) free(m->dataFileName);
  m->dataFileName=NULL;

  manifest_free[mid]=1;
  manifest_free_where[mid]=where;
  if (mid<manifest_first_free) manifest_first_free=mid;

  if (debug & DEBUG_MANIFESTS) _log_manifest_trace(where, __FUNCTION__);

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
  if (debug&DEBUG_RHIZOME) DEBUG("Repacked variables in manifest.");
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
  if (!m->haveSecret) return WHY("Need private key to sign manifest");
  rhizome_signature *sig = rhizome_sign_hash(m, m->cryptoSignSecret);
  if (!sig) return WHY("rhizome_sign_hash() failed.");

  /* Append signature to end of manifest data */
  if (sig->signatureLength+m->manifest_bytes>MAX_MANIFEST_BYTES) {
    free(sig); 
    return WHY("Manifest plus signatures is too long.");
  }

  bcopy(&sig->signature[0],&m->manifestdata[m->manifest_bytes],sig->signatureLength);

  m->manifest_bytes+=sig->signatureLength;
  m->manifest_all_bytes=m->manifest_bytes;

  free(sig);
  return 0;
}

int rhizome_write_manifest_file(rhizome_manifest *m, const char *filename)
{
  if (debug & DEBUG_RHIZOME) DEBUGF("write manifest (%d bytes) to %s", m->manifest_all_bytes, filename);
  if (!m) return WHY("Manifest is null.");
  if (!m->finalised) return WHY("Manifest must be finalised before it can be written.");
  FILE *f = fopen(filename, "w");
  if (f == NULL) {
    WHY_perror("fopen");
    return WHYF("Cannot write manifest to %s", filename);
  }
  int r1 = fwrite(m->manifestdata, m->manifest_all_bytes, 1, f);
  int r2 = fclose(f);
  if (r1 != 1)
    return WHYF("fwrite(%s) returned %d", filename, r1);
  if (r2 == EOF)
    return WHYF("fclose(%s) returned %d", filename, r2);
  return 0;
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

int rhizome_manifest_finalise(rhizome_manifest *m)
{
  /* set fileLength and "filesize" var */
  if (m->dataFileName[0]) {
    struct stat stat;
    if (lstat(m->dataFileName, &stat)) {
      WHY_perror("lstat");
      return WHY("Could not stat() associated file");
    }
    m->fileLength = stat.st_size;
  } else
    m->fileLength = 0;
  rhizome_manifest_set_ll(m, "filesize", m->fileLength);

  /* set fileHexHash and "filehash" var */
  if (m->fileLength != 0) {
    if (!m->fileHashedP) {
      if (rhizome_hash_file(m, m->dataFileName, m->fileHexHash))
	return WHY("rhizome_hash_file() failed during finalisation of manifest.");
      m->fileHashedP = 1;
    }
    rhizome_manifest_set(m, "filehash", m->fileHexHash);
  } else {
    m->fileHexHash[0] = '\0';
    m->fileHashedP = 0;
    rhizome_manifest_del(m, "filehash");
  }

  /* set fileHighestPriority based on group associations.
     XXX - Should probably be set as groups are added */

  /* set version of manifest, either from version variable, or using current time */
  if (rhizome_manifest_get(m,"version",NULL,0)==NULL)
    {
      /* No version set */
      m->version = gettime_ms();
      rhizome_manifest_set_ll(m,"version",m->version);
    }
  else
    m->version = rhizome_manifest_get_ll(m,"version");

  /* Convert to final form for signing and writing to disk */
  if (rhizome_manifest_pack_variables(m))
    return WHY("Could not convert manifest to wire format");

  /* Sign it */
  if (rhizome_manifest_selfsign(m))
    return WHY("Could not sign manifest");

  /* mark manifest as finalised */
  m->finalised=1;

  return 0;
}
