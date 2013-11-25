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
#include <sys/uio.h>
#include "serval.h"
#include "conf.h"
#include "rhizome.h"
#include "str.h"
#include "mem.h"
#include "keyring.h"
#include "dataformats.h"

static const char *rhizome_manifest_get(const rhizome_manifest *m, const char *var)
{
  unsigned i;
  for (i = 0; i < m->var_count; ++i)
    if (strcmp(m->vars[i], var) == 0)
      return m->values[i];
  return NULL;
}

#if 0
static int64_t rhizome_manifest_get_ll(rhizome_manifest *m, const char *var)
{
  unsigned i;
  for (i = 0; i < m->var_count; ++i)
    if (strcmp(m->vars[i], var) == 0) {
      int64_t val;
      return str_to_int64(m->values[i], 10, &val, NULL) ? val : -1;
    }
  return -1;
}
#endif

/* @author Andrew Bettison <andrew@servalproject.com>
 */
static int _rhizome_manifest_del(struct __sourceloc __whence, rhizome_manifest *m, const char *var)
{
  if (config.debug.rhizome_manifest)
    DEBUGF("DEL manifest[%d].%s", m->manifest_record_number, var);
  int ret = 0;
  unsigned i;
  for (i = 0; i < m->var_count; ++i)
    if (strcmp(m->vars[i], var) == 0) {
      free((char *) m->vars[i]);
      free((char *) m->values[i]);
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

#define rhizome_manifest_set(m,var,value) _rhizome_manifest_set(__WHENCE__, (m), (var), (value))
#define rhizome_manifest_set_ll(m,var,value) _rhizome_manifest_set_ll(__WHENCE__, (m), (var), (value))
#define rhizome_manifest_del(m,var) _rhizome_manifest_del(__WHENCE__, (m), (var))

static const char *_rhizome_manifest_set(struct __sourceloc __whence, rhizome_manifest *m, const char *var, const char *value)
{
  if (config.debug.rhizome_manifest)
    DEBUGF("SET manifest[%d].%s = %s", m->manifest_record_number, var, alloca_str_toprint(value));
  unsigned i;
  for(i=0;i<m->var_count;i++)
    if (strcmp(m->vars[i],var) == 0) {
      const char *ret = str_edup(value);
      if (ret == NULL)
	return NULL;
      free((char *)m->values[i]);
      m->values[i] = ret;
      m->finalised = 0;
      return ret;
    }
  if (m->var_count >= MAX_MANIFEST_VARS)
    return WHYNULL("no more manifest vars");
  if ((m->vars[m->var_count] = str_edup(var)) == NULL)
    return NULL;
  const char *ret = m->values[m->var_count] = str_edup(value);
  if (ret == NULL) {
    free((char *)m->vars[i]);
    m->vars[i] = NULL;
    return NULL;
  }
  m->var_count++;
  m->finalised = 0;
  return ret;
}

static const char *_rhizome_manifest_set_ll(struct __sourceloc __whence, rhizome_manifest *m, char *var, int64_t value)
{
  char str[50];
  snprintf(str, sizeof str, "%" PRId64, value);
  return rhizome_manifest_set(m, var, str);
}

void _rhizome_manifest_set_id(struct __sourceloc __whence, rhizome_manifest *m, const rhizome_bid_t *bidp)
{
  const char *v = rhizome_manifest_set(m, "id", alloca_tohex_rhizome_bid_t(*bidp));
  assert(v); // TODO: remove known manifest fields from vars[]
  if (bidp != &m->cryptoSignPublic && cmp_rhizome_bid_t(&m->cryptoSignPublic, bidp) != 0) {
    m->cryptoSignPublic = *bidp;
    // The BID just changed, so the secret key and bundle key are no longer valid.
    if (m->haveSecret) {
      m->haveSecret = SECRET_UNKNOWN;
      bzero(m->cryptoSignSecret, sizeof m->cryptoSignSecret); // not strictly necessary but aids debugging
    }
    if (m->has_bundle_key) {
      m->has_bundle_key = 0;
      m->bundle_key = RHIZOME_BK_NONE; // not strictly necessary but aids debugging
    }
    // Any authenticated author is no longer authenticated, but is still known to be in the keyring.
    if (m->authorship == AUTHOR_AUTHENTIC)
      m->authorship = AUTHOR_LOCAL;
  }
}

void _rhizome_manifest_set_version(struct __sourceloc __whence, rhizome_manifest *m, int64_t version)
{
  const char *v = rhizome_manifest_set_ll(m, "version", version);
  assert(v); // TODO: remove known manifest fields from vars[]
  m->version = version;
}

void _rhizome_manifest_set_filesize(struct __sourceloc __whence, rhizome_manifest *m, uint64_t size)
{
  const char *v = rhizome_manifest_set_ll(m, "filesize", size);
  assert(v); // TODO: remove known manifest fields from vars[]
  m->filesize = size;
  if (m->filesize == 0)
    rhizome_manifest_set_filehash(m, NULL);
}

/* Must always set file size before setting the file hash, to avoid assertion failures.
 */
void _rhizome_manifest_set_filehash(struct __sourceloc __whence, rhizome_manifest *m, const rhizome_filehash_t *hash)
{
  assert(m->filesize != RHIZOME_SIZE_UNSET);
  if (hash) {
    assert(m->filesize > 0);
    const char *v = rhizome_manifest_set(m, "filehash", alloca_tohex_rhizome_filehash_t(*hash));
    assert(v); // TODO: remove known manifest fields from vars[]
    m->filehash = *hash;
  } else {
    assert(m->filesize == 0);
    rhizome_manifest_del(m, "filehash");
    m->filehash = RHIZOME_FILEHASH_NONE;
  }
}

void _rhizome_manifest_set_tail(struct __sourceloc __whence, rhizome_manifest *m, uint64_t tail)
{
  const char *v = rhizome_manifest_set_ll(m, "tail", tail);
  assert(v); // TODO: remove known manifest fields from vars[]
  m->tail = tail;
  m->is_journal = (tail != RHIZOME_SIZE_UNSET);
}

void _rhizome_manifest_set_bundle_key(struct __sourceloc __whence, rhizome_manifest *m, const rhizome_bk_t *bkp)
{
  if (bkp) {
    const char *v = rhizome_manifest_set(m, "BK", alloca_tohex_rhizome_bk_t(*bkp));
    assert(v); // TODO: remove known manifest fields from vars[]
    m->bundle_key = *bkp;
    m->has_bundle_key = 1;
  } else
    _rhizome_manifest_del_bundle_key(__whence, m);
}

void _rhizome_manifest_del_bundle_key(struct __sourceloc __whence, rhizome_manifest *m)
{
  if (m->has_bundle_key) {
    rhizome_manifest_del(m, "BK");
    m->has_bundle_key = 0;
    m->bundle_key = RHIZOME_BK_NONE; // not strictly necessary, but aids debugging
  } else
    assert(rhizome_manifest_get(m, "BK") == NULL);
  // Once there is no BK field, any authenticated authorship is no longer.
  if (m->authorship == AUTHOR_AUTHENTIC)
    m->authorship = AUTHOR_LOCAL;
}

void _rhizome_manifest_set_service(struct __sourceloc __whence, rhizome_manifest *m, const char *service)
{
  if (service) {
    const char *v = rhizome_manifest_set(m, "service", service);
    assert(v); // TODO: remove known manifest fields from vars[]
    m->service = v;
  } else
    _rhizome_manifest_del_service(__whence, m);
}

void _rhizome_manifest_del_service(struct __sourceloc __whence, rhizome_manifest *m)
{
  if (m->service) {
    m->service = NULL;
    rhizome_manifest_del(m, "service");
  } else
    assert(rhizome_manifest_get(m, "service") == NULL);
}

void _rhizome_manifest_set_name(struct __sourceloc __whence, rhizome_manifest *m, const char *name)
{
  if (name) {
    const char *v = rhizome_manifest_set(m, "name", name);
    assert(v); // TODO: remove known manifest fields from vars[]
    m->name = v;
  } else {
    rhizome_manifest_del(m, "name");
    m->name = NULL;
  }
}

void _rhizome_manifest_del_name(struct __sourceloc __whence, rhizome_manifest *m)
{
  if (m->name) {
    m->name = NULL;
    rhizome_manifest_del(m, "name");
  } else
    assert(rhizome_manifest_get(m, "name") == NULL);
}

void _rhizome_manifest_set_date(struct __sourceloc __whence, rhizome_manifest *m, time_ms_t date)
{
  const char *v = rhizome_manifest_set_ll(m, "date", date);
  assert(v); // TODO: remove known manifest fields from vars[]
  m->date = date;
  m->has_date = 1;
}

void _rhizome_manifest_set_sender(struct __sourceloc __whence, rhizome_manifest *m, const sid_t *sidp)
{
  if (sidp) {
    const char *v = rhizome_manifest_set(m, "sender", alloca_tohex_sid_t(*sidp));
    assert(v); // TODO: remove known manifest fields from vars[]
    m->sender = *sidp;
    m->has_sender = 1;
  } else
    _rhizome_manifest_del_sender(__whence, m);
}

void _rhizome_manifest_del_sender(struct __sourceloc __whence, rhizome_manifest *m)
{
  if (m->has_sender) {
    rhizome_manifest_del(m, "sender");
    m->sender = SID_ANY;
    m->has_sender = 0;
  } else
    assert(rhizome_manifest_get(m, "sender") == NULL);
}

void _rhizome_manifest_set_recipient(struct __sourceloc __whence, rhizome_manifest *m, const sid_t *sidp)
{
  if (sidp) {
    const char *v = rhizome_manifest_set(m, "recipient", alloca_tohex_sid_t(*sidp));
    assert(v); // TODO: remove known manifest fields from vars[]
    m->recipient = *sidp;
    m->has_recipient = 1;
  } else
    _rhizome_manifest_del_recipient(__whence, m);
}

void _rhizome_manifest_del_recipient(struct __sourceloc __whence, rhizome_manifest *m)
{
  if (m->has_recipient) {
    rhizome_manifest_del(m, "recipient");
    m->recipient = SID_ANY;
    m->has_recipient = 0;
  } else
    assert(rhizome_manifest_get(m, "recipient") == NULL);
}

void _rhizome_manifest_set_crypt(struct __sourceloc __whence, rhizome_manifest *m, enum rhizome_manifest_crypt flag)
{
  switch (flag) {
    case PAYLOAD_CRYPT_UNKNOWN:
      rhizome_manifest_del(m, "crypt");
      break;
    case PAYLOAD_CLEAR: {
      const char *v = rhizome_manifest_set(m, "crypt", "0");
      assert(v); // TODO: remove known manifest fields from vars[]
      break;
    }
    case PAYLOAD_ENCRYPTED: {
      const char *v = rhizome_manifest_set(m, "crypt", "1");
      assert(v); // TODO: remove known manifest fields from vars[]
      break;
    }
    default: abort();
  }
  m->payloadEncryption = flag;
}

void _rhizome_manifest_set_rowid(struct __sourceloc __whence, rhizome_manifest *m, uint64_t rowid)
{
  m->rowid = rowid;
}

void _rhizome_manifest_set_inserttime(struct __sourceloc __whence, rhizome_manifest *m, time_ms_t time)
{
  m->inserttime = time;
}

void _rhizome_manifest_set_author(struct __sourceloc __whence, rhizome_manifest *m, const sid_t *sidp)
{
  if (sidp) {
    if (m->authorship == ANONYMOUS || cmp_sid_t(&m->author, sidp) != 0) {
      if (config.debug.rhizome_manifest)
	DEBUGF("SET manifest[%d] author = %s", m->manifest_record_number, alloca_tohex_sid_t(*sidp));
      m->author = *sidp;
      m->authorship = AUTHOR_NOT_CHECKED;
    }
  } else
    _rhizome_manifest_del_author(__whence, m);
}

void _rhizome_manifest_del_author(struct __sourceloc __whence, rhizome_manifest *m)
{
  if (m->authorship != ANONYMOUS) {
    if (config.debug.rhizome_manifest)
      DEBUGF("DEL manifest[%d] author", m->manifest_record_number);
    m->author = SID_ANY;
    m->authorship = ANONYMOUS;
  }
}

int rhizome_manifest_verify(rhizome_manifest *m)
{
  unsigned end_of_text=0;

  /* find end of manifest body and start of signatures */
  while(m->manifestdata[end_of_text]&&end_of_text<m->manifest_all_bytes)
    end_of_text++;
  end_of_text++; /* include null byte in body for verification purposes */

  /* Calculate hash of the text part of the file, as we need to couple this with
     each signature block to */
  crypto_hash_sha512(m->manifesthash,m->manifestdata,end_of_text);

  /* Read signature blocks from file. */
  unsigned ofs = end_of_text;
  while(ofs<m->manifest_all_bytes) {
    if (config.debug.rhizome)
      DEBUGF("ofs=0x%x, m->manifest_bytes=0x%x", ofs,m->manifest_all_bytes);
    if (rhizome_manifest_extract_signature(m, &ofs))
      break;
  }

  if (m->sig_count==0) {
    WHYF("Manifest has zero valid signatures");
    m->errors++;
  }

  /* Make sure that id variable is correct */
  {
    rhizome_bid_t bid;
    const char *id = rhizome_manifest_get(m,"id");
    if (!id) {
      WHY("Manifest lacks 'id' field");
      m->errors++;
    } else if (str_to_rhizome_bid_t(&bid, id) == -1) {
      WHY("Invalid manifest 'id' field");
      m->errors++;
    } else if (cmp_rhizome_bid_t(&bid, &m->cryptoSignPublic) != 0) {
      WHYF("Manifest id field does not match cryptoSignPublic: id=%s, cryptoSignPublic=%s",
	  alloca_tohex_rhizome_bid_t(bid),
	  alloca_tohex_rhizome_bid_t(m->cryptoSignPublic)
	);
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
      m->selfSigned = 0;
    } else
      m->selfSigned = 1;
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
    ret = WHYF_perror("read(%s,%zu)", alloca_str_toprint(path), buffer_size);
  if (close(fd) == -1)
    ret = WHY_perror("close");
  return ret;
}

int rhizome_manifest_parse(rhizome_manifest *m)
{
  IN();
  m->manifest_all_bytes=m->manifest_bytes;
  m->var_count = 0;
  m->filesize = RHIZOME_SIZE_UNSET;
  m->tail = RHIZOME_SIZE_UNSET;

  /* Parse out variables, signature etc */
  int have_id = 0;
  int have_version = 0;
  int have_filehash = 0;

  unsigned ofs = 0;
  while (ofs < m->manifest_bytes && m->manifestdata[ofs]) {
    char line[1024];
    unsigned limit = ofs + sizeof line - 1;
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
      if (rhizome_manifest_get(m, var)) {
	if (config.debug.rejecteddata)
	  DEBUGF("Ill formed manifest file, duplicate variable \"%s\"", var);
	m->errors++;
      } else if (m->var_count >= MAX_MANIFEST_VARS) {
	if (config.debug.rejecteddata)
	  WARN("Ill formed manifest file, too many variables");
	m->errors++;
      } else {
	m->vars[m->var_count] = strdup(var);
	m->values[m->var_count] = strdup(value);
	/* The bundle ID is implicit in transit, but we need to store it in the manifest, so that
	 * reimporting manifests on receiver nodes works easily.  We might implement something that
	 * strips the id variable out of the manifest when sending it, or some other scheme to avoid
	 * sending all the extra bytes.
	 */
	if (strcasecmp(var, "id") == 0) {
	  have_id = 1;
	  if (str_to_rhizome_bid_t(&m->cryptoSignPublic, value) == -1) {
	    if (config.debug.rejecteddata)
	      DEBUGF("Invalid manifest id: %s", value);
	    m->errors++;
	  } else {
	    if (config.debug.rhizome_manifest)
	      DEBUGF("PARSE manifest[%d].id = %s", m->manifest_record_number, alloca_tohex_sid_t(m->cryptoSignPublic));
	  }
	} else if (strcasecmp(var, "filehash") == 0) {
	  have_filehash = 1;
	  if (str_to_rhizome_filehash_t(&m->filehash, value) == -1) {
	    if (config.debug.rejecteddata)
	      DEBUGF("Invalid filehash: %s", value);
	    m->errors++;
	  } else {
	    if (config.debug.rhizome_manifest)
	      DEBUGF("PARSE manifest[%d].filehash = %s", m->manifest_record_number, alloca_tohex_rhizome_filehash_t(m->filehash));
	  }
	} else if (strcasecmp(var, "filesize") == 0) {
	  uint64_t filesize;
	  if (!str_to_uint64(value, 10, &filesize, NULL) || filesize == RHIZOME_SIZE_UNSET) {
	    if (config.debug.rejecteddata)
	      DEBUGF("Invalid filesize: %s", value);
	    m->errors++;
	  } else {
	    m->filesize = filesize;
	    if (config.debug.rhizome_manifest)
	      DEBUGF("PARSE manifest[%d].filesize = %"PRIu64, m->manifest_record_number, m->filesize);
	  }
	} else if (strcasecmp(var, "version") == 0) {
	  have_version = 1;
	  uint64_t version;
	  if (!str_to_uint64(value, 10, &version, NULL)) {
	    if (config.debug.rejecteddata)
	      DEBUGF("Invalid version: %s", value);
	    m->errors++;
	  } else {
	    m->version = version;
	    if (config.debug.rhizome_manifest)
	      DEBUGF("PARSE manifest[%d].version = %"PRIu64, m->manifest_record_number, m->version);
	  }
	// since rhizome *MUST* be able to carry future manifest versions
	// if any of these fields are not well formed, the manifest can still be imported and exported
	// but the bundle should not be added or exported
	} else if (strcasecmp(var, "tail") == 0) {
	  uint64_t tail;
	  if (!str_to_uint64(value, 10, &tail, NULL) || tail == RHIZOME_SIZE_UNSET) {
	    if (config.debug.rejecteddata)
	      DEBUGF("Invalid tail: %s", value);
	    m->errors++;
	  } else {
	    m->tail = tail;
	    m->is_journal = 1;
	    if (config.debug.rhizome_manifest)
	      DEBUGF("PARSE manifest[%d].tail = %"PRIu64, m->manifest_record_number, m->tail);
	  }
	} else if (strcasecmp(var, "BK") == 0) {
	  if (str_to_rhizome_bk_t(&m->bundle_key, value) == -1) {
	    if (config.debug.rejecteddata)
	      DEBUGF("Invalid BK: %s", value);
	    m->warnings++;
	  } else {
	    m->has_bundle_key = 1;
	    if (config.debug.rhizome_manifest)
	      DEBUGF("PARSE manifest[%d].BK = %s", m->manifest_record_number, alloca_tohex_rhizome_bk_t(m->bundle_key));
	  }
	} else if (strcasecmp(var, "service") == 0) {
	  if (rhizome_str_is_manifest_service(value)) {
	    m->service = m->values[m->var_count]; // will be free()d when vars[] and values[] are free()d
	    if (config.debug.rhizome_manifest)
	      DEBUGF("PARSE manifest[%d].service = %s", m->manifest_record_number, alloca_str_toprint(m->service));
	  } else {
	    if (config.debug.rejecteddata)
	      DEBUGF("Invalid service: %s", value);
	    m->warnings++;
	  }
	} else if (strcasecmp(var, "date") == 0) {
	  int64_t date;
	  if (!str_to_int64(value, 10, &date, NULL)) {
	    if (config.debug.rejecteddata)
	      DEBUGF("Invalid date: %s", value);
	    m->warnings++;
	  } else {
	    m->date = date;
	    m->has_date = 1;
	    if (config.debug.rhizome_manifest)
	      DEBUGF("PARSE manifest[%d].date = %"PRItime_ms_t, m->manifest_record_number, m->date);
	  }
	} else if (strcasecmp(var, "sender") == 0) {
	  if (str_to_sid_t(&m->sender, value) == -1) {
	    if (config.debug.rejecteddata)
	      DEBUGF("Invalid sender: %s", value);
	    m->warnings++;
	  } else {
	    m->has_sender = 1;
	    if (config.debug.rhizome_manifest)
	      DEBUGF("PARSE manifest[%d].sender = %s", m->manifest_record_number, alloca_tohex_sid_t(m->sender));
	  }
	} else if (strcasecmp(var, "recipient") == 0) {
	  if (str_to_sid_t(&m->recipient, value) == -1) {
	    if (config.debug.rejecteddata)
	      DEBUGF("Invalid recipient: %s", value);
	    m->warnings++;
	  } else {
	    m->has_recipient = 1;
	    if (config.debug.rhizome_manifest)
	      DEBUGF("PARSE manifest[%d].recipient = %s", m->manifest_record_number, alloca_tohex_sid_t(m->recipient));
	  }
	} else if (strcasecmp(var, "name") == 0) {
	  if (value[0] == '\0') {
	    if (config.debug.rejecteddata)
	      WARN("Empty name");
	    //m->warnings++;  TODO Meshms code should set a name for its "conversations" bundle
	  }
	  m->name = m->values[m->var_count]; // will be free()d when vars[] and values[] are free()d
	  if (config.debug.rhizome_manifest)
	    DEBUGF("PARSE manifest[%d].name = %s", m->manifest_record_number, alloca_str_toprint(m->name));
	} else if (strcasecmp(var, "crypt") == 0) {
	  if (!(strcmp(value, "0") == 0 || strcmp(value, "1") == 0)) {
	    if (config.debug.rejecteddata)
	      DEBUGF("Invalid crypt: %s", value);
	    m->warnings++;
	  } else {
	    m->payloadEncryption = (value[0] == '1') ? PAYLOAD_ENCRYPTED : PAYLOAD_CLEAR;
	    if (config.debug.rhizome_manifest)
	      DEBUGF("PARSE manifest[%d].crypt = %u", m->manifest_record_number, m->payloadEncryption == PAYLOAD_ENCRYPTED ? 1 : 0);
	  }
	} else {
	  // An unknown field is not an error... older rhizome nodes must carry newer manifests.
	  if (config.debug.rhizome_manifest)
	    DEBUGF("SKIP manifest[%d].%s = %s", m->manifest_record_number, var, alloca_str_toprint(value));
	}
	m->var_count++;
      }
    }
  }
  /* The null byte gets included in the check sum */
  if (ofs < m->manifest_bytes)
    ++ofs;

  /* Remember where the text ends */
  unsigned end_of_text = ofs;
  m->manifest_bytes = end_of_text;

  // verify that all required fields are consistent.
  if (!have_id) {
    if (config.debug.rejecteddata)
      DEBUG("Missing manifest id field");
    m->errors++;
  }
  if (!have_version) {
    if (config.debug.rejecteddata)
      DEBUG("Missing version field");
    m->errors++;
  }
  if (m->filesize == RHIZOME_SIZE_UNSET) {
    if (config.debug.rejecteddata)
      DEBUG("Missing filesize field");
    m->errors++;
  }
  if (!have_filehash && m->filesize > 0) {
    if (config.debug.rejecteddata)
      DEBUG("Missing filehash field");
    m->errors++;
  }
  if (have_filehash && m->filesize == 0) {
    if (config.debug.rejecteddata)
      DEBUG("Spurious filehash field");
    m->errors++;
  }

  // warn if expected fields are missing
  if (m->service == NULL) {
    if (config.debug.rejecteddata)
      DEBUG("Missing service field");
    m->warnings++;
  }
  if (!m->has_date) {
    if (config.debug.rejecteddata)
      DEBUG("Missing date field");
    m->warnings++;
  }

  if (m->errors || m->warnings) {
    if (config.debug.rejecteddata)
      dump("manifest body", m->manifestdata, (size_t) m->manifest_bytes);
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
  if (m && m->payloadEncryption == PAYLOAD_ENCRYPTED)
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
	WHYF_perror("read(%s,%zu)", alloca_str_toprint(path), sizeof buffer);
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

rhizome_manifest manifests[MAX_RHIZOME_MANIFESTS];
char manifest_free[MAX_RHIZOME_MANIFESTS];
int manifest_first_free=-1;
struct __sourceloc manifest_alloc_whence[MAX_RHIZOME_MANIFESTS];
struct __sourceloc manifest_free_whence[MAX_RHIZOME_MANIFESTS];

static void _log_manifest_trace(struct __sourceloc __whence, const char *operation)
{
  int count_free = 0;
  unsigned i;
  for (i = 0; i != MAX_RHIZOME_MANIFESTS; ++i)
    if (manifest_free[i])
      ++count_free;
  DEBUGF("%s(): count_free = %d", operation, count_free);
}

rhizome_manifest *_rhizome_new_manifest(struct __sourceloc __whence)
{
  if (manifest_first_free<0) {
    /* Setup structures */
    unsigned i;
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
      unsigned i;
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

  // Set global defaults for a manifest (which are not zero)
  m->filesize = RHIZOME_SIZE_UNSET;
  m->tail = RHIZOME_SIZE_UNSET;

  return m;
}

void _rhizome_manifest_free(struct __sourceloc __whence, rhizome_manifest *m)
{
  if (!m) return;
  int mid=m->manifest_record_number;

  if (m!=&manifests[mid])
    FATALF("%s(): asked to free manifest %p, which claims to be manifest slot #%d (%p), but isn't",
	  __FUNCTION__, m, mid, &manifests[mid]
      );

  if (manifest_free[mid])
    FATALF("%s(): asked to free manifest slot #%d (%p), which was already freed at %s:%d:%s()",
	  __FUNCTION__, mid, m,
	  manifest_free_whence[mid].file,
	  manifest_free_whence[mid].line,
	  manifest_free_whence[mid].function
	);

  /* Free variable and signature blocks. */
  unsigned i;
  for(i=0;i<m->var_count;i++) {
    free((char *) m->vars[i]);
    free((char *) m->values[i]);
    m->vars[i] = m->values[i] = NULL;
  }
  for(i=0;i<m->sig_count;i++) {
    free(m->signatories[i]);
    m->signatories[i] = NULL;
  }

  if (m->dataFileName) {
    if (m->dataFileUnlinkOnFree && unlink(m->dataFileName) == -1)
      WARNF_perror("unlink(%s)", alloca_str_toprint(m->dataFileName));
    free((char *) m->dataFileName);
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
  unsigned i;
  unsigned ofs = 0;
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
  unsigned char marker[4];
  struct iovec iov[2];
  int iovcnt = 1;
  iov[0].iov_base = m->manifestdata;
  iov[0].iov_len = m->manifest_all_bytes;
  if (append) {
    write_uint16(marker, m->manifest_all_bytes);
    marker[2] = 0x41;
    marker[3] = 0x10;
    iov[1].iov_base = marker;
    iov[1].iov_len = sizeof marker;
    iovcnt = 2;
  }
  if (writev_all(fd, iov, iovcnt) == -1)
    ret = -1;
  if (close(fd) == -1)
    ret = WHY_perror("close");
  return ret;
}

int rhizome_manifest_dump(rhizome_manifest *m, const char *msg)
{
  unsigned i;
  WHYF("Dumping manifest %s:", msg);
  for(i=0;i<m->var_count;i++)
    WHYF("[%s]=[%s]\n", m->vars[i], m->values[i]);
  return 0;
}

int rhizome_manifest_finalise(rhizome_manifest *m, rhizome_manifest **mout, int deduplicate)
{
  IN();
  int ret=0;

  if (m->filesize == RHIZOME_SIZE_UNSET)
    RETURN(WHY("Manifest filesize unknown"));

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
  ret = rhizome_add_manifest(m, 255 /* TTL */);

  RETURN(ret);
  OUT();
}

int rhizome_fill_manifest(rhizome_manifest *m, const char *filepath, const sid_t *authorSidp)
{
  /* Fill in a few missing manifest fields, to make it easier to use when adding new files:
   - use the current time for "date" and "version"
   - if service is file, then use the payload file's basename for "name"
   */

  /* Set version of manifest from current time if not already set. */
  if (m->version == 0)
    rhizome_manifest_set_version(m, gettime_ms());

  /* Set the manifest's author.  This must be done before binding to a new ID (below).  If no author
   * was specified, then the manifest's "sender" field is used, if present.
   */
  if (authorSidp)
    rhizome_manifest_set_author(m, authorSidp);
  else if (m->has_sender)
    rhizome_manifest_set_author(m, &m->sender);

  /* Set the bundle ID (public key) and secret key.
   */
  if (!m->haveSecret && rhizome_bid_t_is_zero(m->cryptoSignPublic)) {
    if (config.debug.rhizome)
      DEBUG("creating new bundle");
    if (rhizome_manifest_createid(m) == -1)
      return WHY("Could not bind manifest to an ID");
    if (m->authorship != ANONYMOUS)
      rhizome_manifest_add_bundle_key(m); // set the BK field
  } else {
    if (config.debug.rhizome)
      DEBUGF("modifying existing bundle bid=%s", alloca_tohex_rhizome_bid_t(m->cryptoSignPublic));
    // Modifying an existing bundle.  Try to discover the bundle secret key and the author.
    rhizome_authenticate_author(m);
    // TODO assert that new version > old version?
  }

  if (m->service == NULL)
    return WHYF("missing 'service'");
  if (config.debug.rhizome)
    DEBUGF("manifest service=%s", m->service);

  if (!m->has_date) {
    rhizome_manifest_set_date(m, (int64_t) gettime_ms());
    if (config.debug.rhizome)
      DEBUGF("missing 'date', set default date=%"PRItime_ms_t, m->date);
  }

  if (strcasecmp(RHIZOME_SERVICE_FILE, m->service) == 0) {
    if (m->name == NULL) {
      if (filepath && *filepath) {
	const char *name = strrchr(filepath, '/');
	rhizome_manifest_set_name(m, name ? name + 1 : filepath);
      } else
	rhizome_manifest_set_name(m, "");
      if (config.debug.rhizome)
	DEBUGF("missing 'name', set default name=%s", alloca_str_toprint(m->name));
    } else {
      if (config.debug.rhizome)
	DEBUGF("manifest contains name=%s", alloca_str_toprint(m->name));
    }
  }

  // Anything sent from one person to another should be considered private and encrypted by default.
  if (   m->payloadEncryption == PAYLOAD_CRYPT_UNKNOWN
      && m->has_sender
      && m->has_recipient
      && !is_sid_t_broadcast(m->recipient)
  ) {
    if (config.debug.rhizome)
      DEBUGF("Implicitly adding payload encryption due to presense of sender & recipient fields");
    rhizome_manifest_set_crypt(m, PAYLOAD_ENCRYPTED);
  }

  return 0;
}

/* Work out the authorship status of the bundle without performing any cryptographic checks.
 * Sets the 'authorship' element and returns 1 if an author was found, 0 if not.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int rhizome_lookup_author(rhizome_manifest *m)
{
  IN();
  int cn, in, kp;
  switch (m->authorship) {
    case AUTHOR_NOT_CHECKED:
      if (config.debug.rhizome)
	DEBUGF("manifest[%d] lookup author=%s", m->manifest_record_number, alloca_tohex_sid_t(m->author));
      cn = 0, in = 0, kp = 0;
      if (keyring_find_sid(keyring, &cn, &in, &kp, &m->author)) {
	if (config.debug.rhizome)
	  DEBUGF("found author");
	m->authorship = AUTHOR_LOCAL;
	RETURN(1);
      }
      // fall through
    case ANONYMOUS:
      if (m->has_sender) {
	if (config.debug.rhizome)
	  DEBUGF("manifest[%d] lookup sender=%s", m->manifest_record_number, alloca_tohex_sid_t(m->sender));
	cn = 0, in = 0, kp = 0;
	if (keyring_find_sid(keyring, &cn, &in, &kp, &m->sender)) {
	  if (config.debug.rhizome)
	    DEBUGF("found sender");
	  rhizome_manifest_set_author(m, &m->sender);
	  m->authorship = AUTHOR_LOCAL;
	  RETURN(1);
	}
      }
    case AUTHENTICATION_ERROR:
    case AUTHOR_UNKNOWN:
    case AUTHOR_IMPOSTOR:
      RETURN(0);
    case AUTHOR_LOCAL:
    case AUTHOR_AUTHENTIC:
      RETURN(1);
  }
  FATALF("m->authorship = %d", m->authorship);
  RETURN(0);
  OUT();
}
