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

#include "mphlr.h"
#include "rhizome.h"
#include <stdlib.h>

rhizome_manifest *rhizome_read_manifest_file(char *filename,int bufferP,int flags)
{
  if (bufferP>MAX_MANIFEST_BYTES) return NULL;

  rhizome_manifest *m = calloc(sizeof(rhizome_manifest),1);
  if (!m) return NULL;

  if (bufferP) {
    m->manifest_bytes=bufferP;
    bcopy(filename,m->manifestdata,m->manifest_bytes);
  }
  else {
    FILE *f=fopen(filename,"r");
    if (!f) { WHY("Could not open manifest file for reading."); 
      rhizome_manifest_free(m); return NULL; }
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
      if (sscanf(line,"%[^=]=%[^\n\r]",var,value)==2)
	{
	  if (rhizome_manifest_get(m,var,NULL,0)!=NULL) {
	    WHY("Error in manifest file (duplicate variable -- keeping first value).");
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
	if (debug&DEBUG_RHIZOME) fprintf(stderr,"Manifest lacks id variable.");
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

    WHY("Group membership determination not implemented (see which signatories are groups? what about manifests signed by groups we don't yet know about?)");
  }
  
  m->manifest_bytes=end_of_text;

  return m;
}

int rhizome_hash_file(char *filename,char *hash_out)
{
  /* Gnarf! NaCl's crypto_hash() function needs the whole file passed in in one
     go.  Trouble is, we need to run Serval DNA on filesystems that lack mmap(),
     and may be very resource constrained. Thus we need a streamable SHA-512
     implementation.
  */
  FILE *f=fopen(filename,"r");
  if (!f) return WHY("Could not open file for reading to calculage SHA512 hash.");
  unsigned char buffer[8192];
  int r;

  SHA512_CTX context;
  SHA512_Init(&context);

  while(!feof(f)) {
    r=fread(buffer,1,8192,f);
    if (r>0) SHA512_Update(&context,buffer,r);
  }

  SHA512_End(&context,(char *)hash_out);
  return 0;
}

char *rhizome_manifest_get(rhizome_manifest *m,char *var,char *out,int maxlen)
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

long long rhizome_manifest_get_ll(rhizome_manifest *m,char *var)
{
  int i;

  if (!m) return -1;

  for(i=0;i<m->var_count;i++)
    if (!strcmp(m->vars[i],var))
      return strtoll(m->values[i],NULL,10);
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


int rhizome_manifest_set(rhizome_manifest *m,char *var,char *value)
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

long long rhizome_file_size(char *filename)
{
  FILE *f;

  /* XXX really should just use stat instead of opening the file */
  f=fopen(filename,"r");
  fseek(f,0,SEEK_END);
  long long size=ftello(f);
  fclose(f);
  return size;
}

void rhizome_manifest_free(rhizome_manifest *m)
{
  if (!m) return;

  int i;
  for(i=0;i<m->var_count;i++)
    { free(m->vars[i]); free(m->values[i]); 
      m->vars[i]=NULL; m->values[i]=NULL; }

  for(i=0;i<m->sig_count;i++)
    { free(m->signatories[i]);
      m->signatories[i]=NULL;
    }

  if (m->dataFileName) free(m->dataFileName);
  m->dataFileName=NULL;

  free(m);

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
  if (debug&DEBUG_RHIZOME) WHY("Repacked variables in manifest.");
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

int rhizome_write_manifest_file(rhizome_manifest *m,char *filename)
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
  }

  /* set fileLength */
  struct stat stat;
  if (lstat(m->dataFileName,&stat)) {
    return WHY("Could not stat() associated file");
  }
  m->fileLength=stat.st_size;
  
  /* Set file hash and size information */
  rhizome_manifest_set(m,"filehash",m->fileHexHash);
  rhizome_manifest_set_ll(m,"filesize",m->fileLength);

  /* set fileHighestPriority based on group associations.
     XXX - Should probably be set as groups are added */

  /* set version of manifest, either from version variable, or using current time */
  if (rhizome_manifest_get(m,"version",NULL,0)==NULL)
    {
      /* No version set */
      m->version = overlay_gettime_ms();
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
