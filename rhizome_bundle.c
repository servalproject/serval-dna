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

rhizome_manifest *rhizome_read_manifest_file(const char *filename, int bufferP, int flags)
{
  if (bufferP>MAX_MANIFEST_BYTES) return NULL;

  rhizome_manifest *m = rhizome_new_manifest();
  if (!m) return NULL;

  if (bufferP) {
    m->manifest_bytes=bufferP;
    memcpy(m->manifestdata, filename, m->manifest_bytes);
  }
  else {
    FILE *f=fopen(filename,"r");
    if (!f) {
      WHYF("Could not open manifest file %s for reading.", filename); 
      rhizome_manifest_free(m);
      return NULL;
    }
    m->manifest_bytes = fread(m->manifestdata,1,MAX_MANIFEST_BYTES,f);
    fclose(f);
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
      if (sscanf(line,"%[^=]=%[^\n\r]",var,value)==2)
	{
	  if (rhizome_manifest_get(m,var,NULL,0)!=NULL) {
	    if (debug&DEBUG_RHIZOME) fprintf(stderr, "Error in manifest file (duplicate variable \"%s\"-- keeping first value)\n", var);
	    m->errors++;
	  }
	  if (m->var_count<MAX_MANIFEST_VARS)
	    {
	      m->vars[m->var_count]=strdup(var);
	      m->values[m->var_count]=strdup(value);
	      m->var_count++;
	    }
	}
      else
	{
	  /* Error in manifest file.
	     Silently ignore for now. */
	  WHY("Error in manifest file (badly formatted line).");
	}
    }
  /* The null byte gets included in the check sum */
  if (ofs<m->manifest_bytes) ofs++;

  /* Remember where the text ends */
  int end_of_text=ofs;

  if (flags&RHIZOME_VERIFY) {
    /* Calculate hash of the text part of the file, as we need to couple this with
       each signature block to */
    crypto_hash_sha512(m->manifesthash,m->manifestdata,end_of_text);
    
    /* Read signature blocks from file. */
    while(ofs<m->manifest_bytes) {
      if (debug&DEBUG_RHIZOME)
	fprintf(stderr,"ofs=0x%x, m->manifest_bytes=0x%x\n",
		ofs,m->manifest_bytes);
      rhizome_manifest_extract_signature(m,&ofs);
    }
    
    if (m->sig_count==0) {
      m->errors++;
    }

    /* Make sure that id variable is correct */
    {
      char *id=rhizome_manifest_get(m,"id",NULL,0);

      if (!id) { 
	if (debug&DEBUG_RHIZOME) fprintf(stderr,"Manifest lacks id variable.\n");
	m->errors++; }
      else {
	unsigned char manifest_bytes[crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES];
	rhizome_hex_to_bytes(id,manifest_bytes,
			     crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES*2); 
	if ((m->sig_count==0)||
	    memcmp(&m->signatories[0][0],manifest_bytes,
		   crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES))
	  {
	    if (debug&DEBUG_RHIZOME) 
	      fprintf(stderr,
		      "Manifest id variable does not match first signature block.\n");
	    m->errors++;
	    m->selfSigned=0;
	  } else m->selfSigned=1;
      }
    }

    if (debug&DEBUG_RHIZOME) 
      fprintf(stderr, "Group membership determination not implemented (see which signatories are groups? what about manifests signed by groups we don't yet know about?)\n");
  }
  
  m->manifest_bytes=end_of_text;

  return m;
}

int rhizome_strn_is_file_hash(const char *text)
{
  int i;
  for (i = 0; i != SHA512_DIGEST_LENGTH * 2; ++i)
    if (!isxdigit(text[i]))
      return 0;
  return 1;
}

int rhizome_str_is_file_hash(const char *text)
{
  size_t len = strlen(text);
  return len == SHA512_DIGEST_LENGTH * 2 && rhizome_strn_is_file_hash(text);
}

int rhizome_hash_file(const char *filename,char *hash_out)
{
  /* Gnarf! NaCl's crypto_hash() function needs the whole file passed in in one
     go.  Trouble is, we need to run Serval DNA on filesystems that lack mmap(),
     and may be very resource constrained. Thus we need a streamable SHA-512
     implementation.
  */
  FILE *f = fopen(filename, "r");
  if (!f)
    return WHYF("Could not read %s to calculate SHA512 hash.", filename);
  SHA512_CTX context;
  SHA512_Init(&context);
  while (!feof(f)) {
    unsigned char buffer[8192];
    int r = fread(buffer, 1, 8192, f);
    if (r > 0)
      SHA512_Update(&context, buffer, r);
  }
  SHA512_End(&context, (char *)hash_out);
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

#define MAX_RHIZOME_MANIFESTS 16
rhizome_manifest manifests[MAX_RHIZOME_MANIFESTS];
char manifest_free[MAX_RHIZOME_MANIFESTS];
int manifest_first_free=-1;
const char *manifest_alloc_sourcefiles[MAX_RHIZOME_MANIFESTS];
const char *manifest_alloc_functions[MAX_RHIZOME_MANIFESTS];
int manifest_alloc_lines[MAX_RHIZOME_MANIFESTS];
const char *manifest_free_sourcefiles[MAX_RHIZOME_MANIFESTS];
const char *manifest_free_functions[MAX_RHIZOME_MANIFESTS];
int manifest_free_lines[MAX_RHIZOME_MANIFESTS];

rhizome_manifest *_rhizome_new_manifest(const char *filename,const char *funcname,
					int line)
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
      fprintf(stderr,"%s:%d:%s() call to rhizome_new_manifest() could not be serviced.\n   (no free manifest records, this probably indicates a memory leak.)\n",
	      filename,line,funcname);
      fprintf(stderr,"   Manifest Slot# | Last allocated by\n");
      for(i=0;i<MAX_RHIZOME_MANIFESTS;i++) {
	fprintf(stderr,"   %-14d | %s:%d in %s()\n",
		i,
		manifest_alloc_sourcefiles[i],
		manifest_alloc_lines[i],
		manifest_alloc_functions[i]);
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
  for(;manifest_first_free<MAX_RHIZOME_MANIFESTS
	&&(!manifest_free[manifest_first_free]);
      manifest_first_free++)
    continue;

  return m;
}

void _rhizome_manifest_free(const char *sourcefile,const char *funcname,int line,
			    rhizome_manifest *m)
{
  if (!m) return;
  int i;
  int mid=m->manifest_record_number;

  if (m!=&manifests[mid]) {
    fprintf(stderr,"%s:%d:%s() called rhizome_manifest_free() and asked to free"
	    " manifest %p, which claims to be manifest slot #%d (%p), but isn't.\n",
	    sourcefile,line,funcname,m,mid,&manifests[mid]);
    exit(-1);
  }

  if (manifest_free[mid]) {
    fprintf(stderr,"%s:%d:%s() called rhizome_manifest_free() and asked to free"
	    " manifest slot #%d (%p), which has already been freed at %s:%d:%s().\n",
	    sourcefile,line,funcname,mid,m,
	    manifest_free_sourcefiles[mid],
	    manifest_free_lines[mid],
	    manifest_free_functions[mid]);
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
  if (debug&DEBUG_RHIZOME) fprintf(stderr, "Repacked variables in manifest.\n");
  m->manifest_all_bytes=ofs;

  /* Recalculate hash */
  crypto_hash_sha512(m->manifesthash,m->manifestdata,m->manifest_bytes);

  return 0;
}

/* Sign this manifest using our own private CryptoSign key */
int rhizome_manifest_sign(rhizome_manifest *m)
{
  rhizome_signature *sig=rhizome_sign_hash(m->manifesthash,m->cryptoSignPublic);

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
  if (!m) return WHY("Manifest is null.");
  if (!m->finalised) return WHY("Manifest must be finalised before it can be written.");
  FILE *f=fopen(filename,"w");
  int r=fwrite(m->manifestdata,m->manifest_all_bytes,1,f);
  fclose(f);
  if (r!=1) return WHY("Failed to fwrite() manifest file.");
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

int rhizome_manifest_dump(rhizome_manifest *m,char *msg)
{
  int i;
  fprintf(stderr,"Dumping manifest %s:\n",msg);
  for(i=0;i<m->var_count;i++)
    fprintf(stderr,"[%s]=[%s]\n",m->vars[i],m->values[i]);
  return 0;
}

int rhizome_manifest_finalise(rhizome_manifest *m,int signP)
{
  /* set fileHexHash */
  if (!m->fileHashedP) {
    if (rhizome_hash_file(m->dataFileName,m->fileHexHash))
      return WHY("rhizome_hash_file() failed during finalisation of manifest.");
    m->fileHashedP=1;

    /* set fileLength */
    struct stat stat;
    if (lstat(m->dataFileName,&stat)) {
      return WHY("Could not stat() associated file");
    }
    m->fileLength=stat.st_size;
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
  rhizome_manifest_pack_variables(m);

  /* Sign it */
  if (signP) rhizome_manifest_sign(m);

  /* mark manifest as finalised */
  m->finalised=1;

  return 0;
}
