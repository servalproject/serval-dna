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

/* Import a bundle from the inbox folder.
   Check that the manifest prototype is valid, and if so, complete it, and sign it if required and possible.

   Note that bundles can either be an ordinary bundle, or a group description.
   Group specifications are simply manifests that have the "isagroup" variable set.
   Groups get stored in the manifests table AND a reference included in the 
   grouplist table.
   Groups are allowed to be listed as being members of other groups.
   This allows a nested, i.e., multi-level group heirarchy where sub-groups will only
   typically be discovered by joining the parent group.  Probably not a bad way to do
   things.

   The file should be included in the specified rhizome groups, if possible.
   (some groups may be closed groups that we do not have the private key for.)
*/
int rhizome_bundle_import(rhizome_manifest *m_in,char *bundle,char *groups[], int ttl,
			  int verifyP, int checkFileP, int signP)
{
  char filename[1024];
  char manifestname[1024];
  char *buffer;
 

  snprintf(filename,1024,"%s/import/file.%s",rhizome_datastore_path,bundle); filename[1023]=0;
  snprintf(manifestname,1024,"%s/import/manifest.%s",rhizome_datastore_path,bundle); manifestname[1023]=0;

  /* Open files */
  rhizome_manifest *m=m_in;
  if (!m_in) 
    m=rhizome_read_manifest_file(manifestname,0 /* file not buffer */,RHIZOME_VERIFY);
  else
    if (debug&DEBUG_RHIZOMESYNC) fprintf(stderr,"Importing direct from manifest structure hashP=%d\n",m->fileHashedP);

  if (!m) return WHY("Could not read manifest file.");
  char hexhash[SHA512_DIGEST_STRING_LENGTH];

  /* work out time to live */
  if (ttl<0) ttl=0; if (ttl>254) ttl=254; m->ttl=ttl;

  /* Keep associated file name handy for later */
  m->dataFileName=strdup(filename);
  if (checkFileP) {
    struct stat stat;
    if (lstat(filename,&stat)) {
      return WHY("Could not stat() associated file");
      m->fileLength=stat.st_size;
    }
  }

  if (checkFileP||signP) {
    if (rhizome_hash_file(filename,hexhash)) {
      rhizome_manifest_free(m);
      return WHY("Could not hash file.");
    }
    memcpy(&m->fileHexHash[0],&hexhash[0],SHA512_DIGEST_STRING_LENGTH);
    m->fileHashedP=1;
  }

  if (verifyP)
    {
      /* Make sure hashes match.
	 Make sure that no signature verification errors were spotted on loading. */
      int verifyErrors=0;
      char *mhexhash;
      if (checkFileP) {
	if ((mhexhash=rhizome_manifest_get(m,"filehash",NULL,0))!=NULL)
	  if (strcmp(hexhash,mhexhash))
	    verifyErrors++;
      }
      if (m->errors)
	verifyErrors+=m->errors;
      if (verifyErrors) {
	rhizome_manifest_free(m);
	unlink(manifestname);
	unlink(filename);
	return WHY("Errors encountered verifying bundle manifest");
      }
    }

  if (!verifyP) {
    if ((buffer=rhizome_manifest_get(m,"id",NULL,0))!=NULL) {
      /* No bundle id (256 bit random string being a public key in the NaCl CryptoSign crypto system),
	 so create one, and keep the private key handy. */
      printf("manifest does not have an id\n");
      rhizome_manifest_createid(m);
      /* The ID is implicit in transit, but we need to store it in the file,
	 so that reimporting manifests on receiver nodes works easily.
	 We might implement something that strips the id variable out of the
	 manifest when sending it, or some other scheme to avoid sending all 
	 the extra bytes. */	
      rhizome_manifest_set(m,"id",rhizome_bytes_to_hex(m->cryptoSignPublic,crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES));
    } else {
      /* An ID was specified, so remember it, and look for the private key if
	 we have it stowed away */
      rhizome_hex_to_bytes(buffer,m->cryptoSignPublic,
			   crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES*2); 
      if (!rhizome_find_keypair_bytes(m->cryptoSignPublic,m->cryptoSignSecret))
	m->haveSecret=1;
    }

    rhizome_manifest_set(m,"filehash",hexhash);
    if (rhizome_manifest_get(m,"version",NULL,0)==NULL)
      /* Version not set, so set one */
      rhizome_manifest_set_ll(m,"version",overlay_gettime_ms());
    rhizome_manifest_set_ll(m,"first_byte",0);
    rhizome_manifest_set_ll(m,"last_byte",rhizome_file_size(filename));
  }
   
  /* Discard if it is older than the most recent known version */
  long long storedversion = sqlite_exec_int64("SELECT version from manifests where id='%s';",rhizome_bytes_to_hex(m->cryptoSignPublic,crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES));
  if (storedversion>rhizome_manifest_get_ll(m,"version"))
    {
      rhizome_manifest_free(m);
      return WHY("Newer version exists");
    }
					      
  /* Add group memberships */
					      
int i;
  if (groups) for(i=0;groups[i];i++) rhizome_manifest_add_group(m,groups[i]);

  if (rhizome_manifest_finalise(m,signP)) {
    return WHY("Failed to finalise manifest.\n");
  }

  /* Write manifest back to disk */
  if (rhizome_write_manifest_file(m,manifestname)) {
    rhizome_manifest_free(m);
    return WHY("Could not write manifest file.");
  }

  /* Okay, it is written, and can be put directly into the rhizome database now */
  int r=rhizome_store_bundle(m,filename);
  if (!r) {
    // XXX For testing   unlink(manifestname);
    unlink(filename);
    return 0;
  }

  return WHY("rhizome_store_bundle() failed.");
}

/* Update an existing Rhizome bundle */
int rhizome_bundle_push_update(char *id,long long version,unsigned char *data,int appendP)
{
  return WHY("Not implemented");
}

char nybltochar(int nybl)
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

int rhizome_hex_to_bytes(char *in,unsigned char *out,int hexChars)
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

