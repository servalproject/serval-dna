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
  if (bufferP>MAX_MANIFEST_BYTES) return WHY("Buffer too big");
  if (!m) return WHY("Null manifest");

  if (bufferP) {
    m->manifest_bytes=bufferP;
    memcpy(m->manifestdata, filename, m->manifest_bytes);
  } else {
    FILE *f = fopen(filename, "r");
    if (f == NULL)
      return WHYF("Could not open manifest file %s for reading.", filename); 
    m->manifest_bytes = fread(m->manifestdata, 1, MAX_MANIFEST_BYTES, f);
    int ret = 0;
    if (m->manifest_bytes == -1)
      ret = WHY_perror("fread");
    if (fclose(f) == EOF)
      ret = WHY_perror("fclose");
    if (ret == -1)
      return -1;
  }

  m->manifest_all_bytes=m->manifest_bytes;

  /* Parse out variables, signature etc */
  int ofs=0;
  while((ofs<m->manifest_bytes)&&(m->manifestdata[ofs]))
    {
      int i;
      char line[1024],var[1024],value[1024];
      while((ofs<m->manifest_bytes)&&
	    (m->manifestdata[ofs]==0x0a||
	     m->manifestdata[ofs]==0x09||
	     m->manifestdata[ofs]==0x20||
	     m->manifestdata[ofs]==0x0d)) ofs++;
      for(i=0;(i<(m->manifest_bytes-ofs))
	    &&(i<1023)
	    &&(m->manifestdata[ofs+i]!=0x00)
	    &&(m->manifestdata[ofs+i]!=0x0d)
	    &&(m->manifestdata[ofs+i]!=0x0a);i++)
	    line[i]=m->manifestdata[ofs+i];
      ofs+=i;
      line[i]=0;
      /* Ignore blank lines */
      if (line[0]==0) continue;
      /* Ignore comment lines */
      if (line[0] == '#' || line[0] == '!') continue;
      /* Parse property lines */
      /* This could be improved to parse Java's Properties.store() output, by handling backlash
         escapes and continuation lines */
      if (sscanf(line,"%[^=]=%[^\n\r]", var, value)==2) {
	if (rhizome_manifest_get(m,var,NULL,0)) {
	  WARNF("Ill formed manifest file, duplicate variable \"%s\"-- keeping first value)", var);
	  m->errors++;
	} else if (m->var_count<MAX_MANIFEST_VARS) {
	  /*`
	  if (debug & DEBUG_RHIZOME) {
	    char buf[80];
	    DEBUGF("read manifest line: %s=%s", var, catv(value, buf, sizeof buf));
	  }
	  */
	  m->vars[m->var_count] = strdup(var);
	  m->values[m->var_count] = strdup(value);
	  if (strcasecmp(var,"id") == 0) {
	    str_toupper_inplace(m->values[m->var_count]);
	    /* Parse hex string of ID into public key, and force to upper case. */
	    if (fromhexstr(m->cryptoSignPublic, value, RHIZOME_MANIFEST_ID_BYTES) == -1) {
	      WARNF("Invalid manifest id: %s", value);
	      m->errors++;
	    }
	  } else if (strcasecmp(var,"filehash") == 0 || strcasecmp(var,"BK") == 0) {
	    /* Force to upper case to avoid case sensitive comparison problems later. */
	    str_toupper_inplace(m->values[m->var_count]);
	  }
	  m->var_count++;
	}
      } else {
	if (debug & DEBUG_RHIZOME) {
	  char buf[80];
	  DEBUGF("Skipping malformed line in manifest file %s: %s", bufferP ? "<buffer>" : filename, catv(line, buf, sizeof buf));
	}
      }
    }
  /* The null byte gets included in the check sum */
  if (ofs<m->manifest_bytes) ofs++;

  /* Remember where the text ends */
  int end_of_text=ofs;

  // TODO Determine group membership here.

  m->manifest_bytes=end_of_text;

  return 0;
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


int rhizome_manifest_set(rhizome_manifest *m, const char *var, const char *value)
{
  int i;

  if (!m) return -1;

  for(i=0;i<m->var_count;i++)
    if (!strcmp(m->vars[i],var)) {
      free(m->values[i]); 
      m->values[i]=strdup(value);
      m->finalised=0;
      return 0;
    }

  if (m->var_count>=MAX_MANIFEST_VARS) return -1;
  
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
const char *manifest_alloc_sourcefiles[MAX_RHIZOME_MANIFESTS];
const char *manifest_alloc_functions[MAX_RHIZOME_MANIFESTS];
int manifest_alloc_lines[MAX_RHIZOME_MANIFESTS];
const char *manifest_free_sourcefiles[MAX_RHIZOME_MANIFESTS];
const char *manifest_free_functions[MAX_RHIZOME_MANIFESTS];
int manifest_free_lines[MAX_RHIZOME_MANIFESTS];

static void _log_manifest_trace(const char *filename, const char *funcname, int line, const char *operation)
{
  int count_free = 0;
  int i;
  for (i = 0; i != MAX_RHIZOME_MANIFESTS; ++i)
    if (manifest_free[i])
      ++count_free;
  logMessage(LOG_LEVEL_DEBUG, filename, line, funcname, "%s(): count_free = %d", operation, count_free);
}

rhizome_manifest *_rhizome_new_manifest(const char *filename, const char *funcname, int line)
{
  if (manifest_first_free<0) {
    /* Setup structures */
    int i;
    for(i=0;i<MAX_RHIZOME_MANIFESTS;i++) {
      manifest_alloc_sourcefiles[i]="<never allocated>";
      manifest_alloc_functions[i]="<never allocated>";
      manifest_alloc_lines[i]=-1;
      manifest_free_sourcefiles[i]="<never freed>";
      manifest_free_functions[i]="<never freed>";
      manifest_free_lines[i]=-1;
      manifest_free[i]=1;
    }
    manifest_first_free=0;
  }

  /* No free manifests */
  if (manifest_first_free>=MAX_RHIZOME_MANIFESTS)
    {
      int i;
      logMessage(LOG_LEVEL_ERROR, filename, line, funcname, "%s(): no free manifest records, this probably indicates a memory leak", __FUNCTION__);
      WHYF("   Slot# | Last allocated by");
      for(i=0;i<MAX_RHIZOME_MANIFESTS;i++) {
	WHYF("   %-5d | %s:%d in %s()",
		i,
		manifest_alloc_sourcefiles[i],
		manifest_alloc_lines[i],
		manifest_alloc_functions[i]
	    );
      }     
      return NULL;
    }

  rhizome_manifest *m=&manifests[manifest_first_free];
  bzero(m,sizeof(rhizome_manifest));
  m->manifest_record_number=manifest_first_free;

  /* Indicate where manifest was allocated, and that it is no longer
     free. */
  manifest_alloc_sourcefiles[manifest_first_free]=filename;
  manifest_alloc_lines[manifest_first_free]=line;
  manifest_alloc_functions[manifest_first_free]=funcname;
  manifest_free[manifest_first_free]=0;
  manifest_free_sourcefiles[manifest_first_free]="<not freed>";
  manifest_free_functions[manifest_first_free]="<not freed>";
  manifest_free_lines[manifest_first_free]=-1;

  /* Work out where next free manifest record lives */
  for (; manifest_first_free < MAX_RHIZOME_MANIFESTS && !manifest_free[manifest_first_free]; ++manifest_first_free)
    ;

  if (debug & DEBUG_MANIFESTS) _log_manifest_trace(filename, funcname, line, __FUNCTION__);

  return m;
}

void _rhizome_manifest_free(const char *sourcefile,const char *funcname,int line,
			    rhizome_manifest *m)
{
  if (!m) return;
  int i;
  int mid=m->manifest_record_number;

  if (m!=&manifests[mid]) {
    logMessage(LOG_LEVEL_ERROR, sourcefile, line, funcname,
	"%s(): asked to free manifest %p, which claims to be manifest slot #%d (%p), but isn't",
	__FUNCTION__, m, mid, &manifests[mid]
      );
    exit(-1);
  }

  if (manifest_free[mid]) {
    logMessage(LOG_LEVEL_ERROR, sourcefile, line, funcname,
	"%s(): asked to free manifest slot #%d (%p), which was already freed at %s:%d:%s()",
	__FUNCTION__, mid, m,
	manifest_free_sourcefiles[mid],
	manifest_free_lines[mid],
	manifest_free_functions[mid]
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
  manifest_free_sourcefiles[mid]=sourcefile;
  manifest_free_functions[mid]=funcname;
  manifest_free_lines[mid]=line;
  if (mid<manifest_first_free) manifest_first_free=mid;

  if (debug & DEBUG_MANIFESTS) _log_manifest_trace(sourcefile, funcname, line, __FUNCTION__);

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
  /* set fileHexHash */
  if (!m->fileHashedP) {
    if (rhizome_hash_file(m,m->dataFileName,m->fileHexHash))
      return WHY("rhizome_hash_file() failed during finalisation of manifest.");
    m->fileHashedP=1;

    /* set fileLength */
    if (m->dataFileName[0]) {
      struct stat stat;
      if (lstat(m->dataFileName, &stat)) {
	WHY_perror("lstat");
	return WHY("Could not stat() associated file");
      }
      m->fileLength = stat.st_size;
    } else
      m->fileLength = 0;
  }
  
  /* Set file hash and size information */
  rhizome_manifest_set(m,"filehash",m->fileHexHash);
  rhizome_manifest_set_ll(m,"filesize",m->fileLength);

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
