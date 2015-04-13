/*
Serval DNA - Rhizome manifest operations
Copyright (C) 2010 Paul Gardner-Stephen
Copyright (C) 2013-2014 Serval Project Inc.
 
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
static uint64_t rhizome_manifest_get_ui64(rhizome_manifest *m, const char *var)
{
  unsigned i;
  for (i = 0; i < m->var_count; ++i)
    if (strcmp(m->vars[i], var) == 0) {
      uint64_t val;
      return str_to_uint64(m->values[i], 10, &val, NULL) ? val : -1;
    }
  return -1;
}
#endif

/* Remove the field with the given label from the manifest
 *
 * @author Andrew Bettison <andrew@servalproject.com>
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
#define rhizome_manifest_set_ui64(m,var,value) _rhizome_manifest_set_ui64(__WHENCE__, (m), (var), (value))
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
      return ret;
    }
  if (m->var_count >= NELS(m->vars))
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
  return ret;
}

static const char *_rhizome_manifest_set_ui64(struct __sourceloc __whence, rhizome_manifest *m, char *var, uint64_t value)
{
  char str[50];
  snprintf(str, sizeof str, "%" PRIu64, value);
  return rhizome_manifest_set(m, var, str);
}

void _rhizome_manifest_set_id(struct __sourceloc __whence, rhizome_manifest *m, const rhizome_bid_t *bidp)
{
  if (bidp) {
    if (m->has_id && (bidp == &m->cryptoSignPublic || cmp_rhizome_bid_t(&m->cryptoSignPublic, bidp) == 0))
      return; // unchanged
    const char *v = rhizome_manifest_set(m, "id", alloca_tohex_rhizome_bid_t(*bidp));
    assert(v); // TODO: remove known manifest fields from vars[]
    m->cryptoSignPublic = *bidp;
    m->has_id = 1;
  } else if (m->has_id) {
    bzero(&m->cryptoSignPublic, sizeof m->cryptoSignPublic); // not strictly necessary but aids debugging
    m->has_id = 0;
  } else
    return; // unchanged
  // The BID has changed.
  m->finalised = 0;
  // Any existing secret key and bundle key are no longer valid.
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

void _rhizome_manifest_set_version(struct __sourceloc __whence, rhizome_manifest *m, uint64_t version)
{
  if (version) {
    const char *v = rhizome_manifest_set_ui64(m, "version", version);
    assert(v); // TODO: remove known manifest fields from vars[]
  } else
    rhizome_manifest_del(m, "version");
  m->version = version;
  m->finalised = 0;
}

void _rhizome_manifest_del_version(struct __sourceloc __whence, rhizome_manifest *m)
{
  _rhizome_manifest_set_version(__whence, m, 0);
}

void _rhizome_manifest_set_filesize(struct __sourceloc __whence, rhizome_manifest *m, uint64_t size)
{
  if (size == RHIZOME_SIZE_UNSET) {
    rhizome_manifest_del(m, "filesize");
  } else {
    const char *v = rhizome_manifest_set_ui64(m, "filesize", size);
    assert(v); // TODO: remove known manifest fields from vars[]
  }
  m->filesize = size;
  m->finalised = 0;
}

void _rhizome_manifest_del_filesize(struct __sourceloc __whence, rhizome_manifest *m)
{
  _rhizome_manifest_set_filesize(__whence, m, RHIZOME_SIZE_UNSET);
}

/* Must always set file size before setting the file hash, to avoid assertion failures.
 */
void _rhizome_manifest_set_filehash(struct __sourceloc __whence, rhizome_manifest *m, const rhizome_filehash_t *hash)
{
  if (hash) {
    const char *v = rhizome_manifest_set(m, "filehash", alloca_tohex_rhizome_filehash_t(*hash));
    assert(v); // TODO: remove known manifest fields from vars[]
    m->filehash = *hash;
    m->has_filehash = 1;
  } else {
    rhizome_manifest_del(m, "filehash");
    m->filehash = RHIZOME_FILEHASH_NONE;
    m->has_filehash = 0;
  }
  m->finalised = 0;
}

void _rhizome_manifest_del_filehash(struct __sourceloc __whence, rhizome_manifest *m)
{
  _rhizome_manifest_set_filehash(__whence, m, NULL);
}

void _rhizome_manifest_set_tail(struct __sourceloc __whence, rhizome_manifest *m, uint64_t tail)
{
  if (tail == RHIZOME_SIZE_UNSET) {
    rhizome_manifest_del(m, "tail");
    m->is_journal = 0;
  } else {
    const char *v = rhizome_manifest_set_ui64(m, "tail", tail);
    assert(v); // TODO: remove known manifest fields from vars[]
    m->is_journal = 1;
  }
  m->tail = tail;
  m->finalised = 0;
}

void _rhizome_manifest_set_bundle_key(struct __sourceloc __whence, rhizome_manifest *m, const rhizome_bk_t *bkp)
{
  if (bkp) {
    const char *v = rhizome_manifest_set(m, "BK", alloca_tohex_rhizome_bk_t(*bkp));
    assert(v); // TODO: remove known manifest fields from vars[]
    m->bundle_key = *bkp;
    m->has_bundle_key = 1;
    m->finalised = 0;
  } else
    _rhizome_manifest_del_bundle_key(__whence, m);
}

void _rhizome_manifest_del_bundle_key(struct __sourceloc __whence, rhizome_manifest *m)
{
  if (m->has_bundle_key) {
    rhizome_manifest_del(m, "BK");
    m->has_bundle_key = 0;
    m->bundle_key = RHIZOME_BK_NONE; // not strictly necessary, but aids debugging
    m->finalised = 0;
  } else
    assert(rhizome_manifest_get(m, "BK") == NULL);
  // Once there is no BK field, any authenticated authorship is no longer.
  if (m->authorship == AUTHOR_AUTHENTIC)
    m->authorship = AUTHOR_LOCAL;
}

void _rhizome_manifest_set_service(struct __sourceloc __whence, rhizome_manifest *m, const char *service)
{
  if (service) {
    assert(rhizome_str_is_manifest_service(service));
    const char *v = rhizome_manifest_set(m, "service", service);
    assert(v); // TODO: remove known manifest fields from vars[]
    m->service = v;
    m->finalised = 0;
  } else
    _rhizome_manifest_del_service(__whence, m);
}

void _rhizome_manifest_del_service(struct __sourceloc __whence, rhizome_manifest *m)
{
  if (m->service) {
    m->service = NULL;
    m->finalised = 0;
    rhizome_manifest_del(m, "service");
  } else
    assert(rhizome_manifest_get(m, "service") == NULL);
}

void _rhizome_manifest_set_name(struct __sourceloc __whence, rhizome_manifest *m, const char *name)
{
  m->finalised = 0;
  if (name) {
    assert(rhizome_str_is_manifest_name(name));
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
    m->finalised = 0;
    rhizome_manifest_del(m, "name");
  } else
    assert(rhizome_manifest_get(m, "name") == NULL);
}

void _rhizome_manifest_set_date(struct __sourceloc __whence, rhizome_manifest *m, time_ms_t date)
{
  const char *v = rhizome_manifest_set_ui64(m, "date", (uint64_t)date);
  assert(v); // TODO: remove known manifest fields from vars[]
  m->date = date;
  m->has_date = 1;
  m->finalised = 0;
}

void _rhizome_manifest_del_date(struct __sourceloc __whence, rhizome_manifest *m)
{
  if (m->has_date) {
    m->has_date = 0;
    m->finalised = 0;
    rhizome_manifest_del(m, "date");
  } else
    assert(rhizome_manifest_get(m, "date") == NULL);
}

void _rhizome_manifest_set_sender(struct __sourceloc __whence, rhizome_manifest *m, const sid_t *sidp)
{
  if (sidp) {
    const char *v = rhizome_manifest_set(m, "sender", alloca_tohex_sid_t(*sidp));
    assert(v); // TODO: remove known manifest fields from vars[]
    m->sender = *sidp;
    m->has_sender = 1;
    m->finalised = 0;
  } else
    _rhizome_manifest_del_sender(__whence, m);
}

void _rhizome_manifest_del_sender(struct __sourceloc __whence, rhizome_manifest *m)
{
  if (m->has_sender) {
    rhizome_manifest_del(m, "sender");
    m->sender = SID_ANY;
    m->has_sender = 0;
    m->finalised = 0;
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
    m->finalised = 0;
  } else
    _rhizome_manifest_del_recipient(__whence, m);
}

void _rhizome_manifest_del_recipient(struct __sourceloc __whence, rhizome_manifest *m)
{
  if (m->has_recipient) {
    rhizome_manifest_del(m, "recipient");
    m->recipient = SID_ANY;
    m->has_recipient = 0;
    m->finalised = 0;
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
  m->finalised = 0;
}

void _rhizome_manifest_set_rowid(struct __sourceloc __whence, rhizome_manifest *m, uint64_t rowid)
{
  if (config.debug.rhizome_manifest)
    DEBUGF("SET manifest[%d].rowid = %"PRIu64, m->manifest_record_number, rowid);
  m->rowid = rowid;
}

void _rhizome_manifest_set_inserttime(struct __sourceloc __whence, rhizome_manifest *m, time_ms_t time)
{
  if (config.debug.rhizome_manifest)
    DEBUGF("SET manifest[%d].inserttime = %"PRItime_ms_t, m->manifest_record_number, time);
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

/* Compute the hash of the manifest's body, including the NUL byte that separates the body from
 * the signature block, and verify that a signature is present and is correct.
 *
 * If the manifest signature is valid, ie, the signature is a self-signature using the
 * manifest's own private key, then sets the m->selfSigned flag and returns 1.
 *
 * If there are no signatures or if the signature block does not verify, then clears the
 * m->selfSigned flag and returns 0.
 *
 * Only call this function on manifests for which rhizome_manifest_validate(m) has returned true
 * (ie, m->finalised is set).
 */
int rhizome_manifest_verify(rhizome_manifest *m)
{
  assert(m->finalised);
  assert(m->manifest_body_bytes > 0);
  assert(m->manifest_all_bytes > 0);
  assert(m->manifest_body_bytes <= m->manifest_all_bytes);
  assert(m->sig_count == 0);
  if (m->manifest_body_bytes == m->manifest_all_bytes)
    assert(m->manifestdata[m->manifest_body_bytes - 1] == '\0');
  // Hash the body
  crypto_hash_sha512(m->manifesthash, m->manifestdata, m->manifest_body_bytes);
  // Read signature blocks
  unsigned ofs = m->manifest_body_bytes;
  while (ofs < m->manifest_all_bytes) {
    if (rhizome_manifest_extract_signature(m, &ofs) == -1)
      break;
  }
  assert(ofs <= m->manifest_all_bytes);
  // Make sure the first signatory's public key is the bundle ID
  assert(m->has_id);
  if (m->sig_count == 0) {
    if (config.debug.rhizome)
      DEBUG("Manifest has no signature blocks, but should have self-signature block");
    m->selfSigned = 0;
    return 0;
  }
  if (memcmp(m->signatories[0], m->cryptoSignPublic.binary, sizeof m->cryptoSignPublic.binary) != 0) {
    if (config.debug.rhizome)
      DEBUGF("Manifest id does not match first signature block (signature key is %s)",
	      alloca_tohex(m->signatories[0], crypto_sign_edwards25519sha512batch_PUBLICKEYBYTES)
	    );
    m->selfSigned = 0;
    return 0;
  }
  m->selfSigned = 1;
  return 1;
}

static void rhizome_manifest_clear(rhizome_manifest *m)
{
  while (m->var_count) {
    --m->var_count;
    free((char *) m->vars[m->var_count]);
    free((char *) m->values[m->var_count]);
    m->vars[m->var_count] = m->values[m->var_count] = NULL;
  }
  while (m->sig_count) {
    --m->sig_count;
    free(m->signatories[m->sig_count]);
    m->signatories[m->sig_count] = NULL;
  }
  m->malformed = NULL;
  m->has_id = 0;
  m->has_filehash = 0;
  m->is_journal = 0;
  m->filesize = RHIZOME_SIZE_UNSET;
  m->tail = RHIZOME_SIZE_UNSET;
  m->version = 0;
  // TODO initialise more fields
}

int rhizome_manifest_inspect(const char *buf, size_t len, struct rhizome_manifest_summary *summ)
{
  const char *const end = buf + len;
  int has_bid = 0;
  int has_version = 0;
  const char *begin = buf;
  const char *eol = NULL;
  enum { Label, Value, Error } state = Label;
  const char *p;
  for (p = buf; state != Error && p < end && *p; ++p)
    switch (state) {
      case Label:
	if (*p == '=') {
	  if (!rhizome_manifest_field_label_is_valid(begin, p - begin))
	    state = Error; // bad field name
	  else {
	    int *has = NULL;
	    if (p == begin + 2 && strncmp(begin, "id", 2) == 0)
	      has = &has_bid;
	    else if (p == begin + 7 && strncmp(begin, "version", 7) == 0)
	      has = &has_version;
	    state = Value;
	    if (has) {
	      if (*has)
		state = Error; // duplicate
	      else {
		*has = 1;
		begin = p + 1;
	      }
	    }
	  }
	}
	break;
      case Value:
	if (*p == '\r' && !eol)
	  eol = p;
	else if (*p == '\n') {
	  if (!eol)
	    eol = p;
	  if (has_bid == 1) {
	    const char *e;
	    if (parse_rhizome_bid_t(&summ->bid, begin, eol - begin, &e) == 0 && e == eol)
	      has_bid = 2;
	    else
	      state = Error; // invalid "id" field
	  } else if (has_version == 1) {
	    const char *e;
	    if (str_to_uint64(begin, 10, &summ->version, &e) && e == eol)
	      has_version = 2;
	    else
	      state = Error; // invalid "version" field
	  }
	  if (state == Value) {
	    state = Label;
	    begin = p + 1;
	    eol = NULL;
	  }
	} else if (eol)
	  state = Error; // CR not followed by LF
	break;
      default:
	abort();
    }
  if (p < end && *p == '\0')
    ++p;
  summ->body_len = p - buf;
  return state == Label && has_bid == 2 && has_version == 2;
}

/* Parse a Rhizome text manifest from its internal buffer up to and including the terminating NUL
 * character which marks the start of the signature block.
 *
 * Prior to calling, the caller must set up m->manifest_all_bytes to the length of the manifest
 * text, including the signature block, and set m->manifestdata[0..m->manifest_all_bytes-1] to
 * contain the manifest text and signature block to be parsed.
 *
 * A "well formed" manifest consists of a series of zero or more lines with the form:
 *
 *	LABEL "=" VALUE [ CR ] LF
 *
 * where LABEL matches the regular expression [A-Za-z][A-Za-z0-9]* (identifier without underscore)
 *       VALUE is any value that does not contain NUL, CR or LF (leading and trailing spaces are
 *	       not stripped from VALUE)
 *       NUL is ASCII 0
 *       CR is ASCII 13
 *       LF is ASCII 10
 *
 * Unpacks all parsed field labels and string values into the m->vars[] and m->values[] arrays, as
 * pointers to malloc(3)ed NUL terminated strings, in the order they appear, and sets m->var_count
 * to the number of fields unpacked.  Sets m->manifest_body_bytes to the number of bytes in the text
 * portion up to and including the optional NUL that starts the signature block (if present).
 *
 * Returns 1 if the manifest is not well formed (syntax violation), any essential field is
 * malformed, or if there are any duplicate fields.  In this case the m->vars[] and m->values[]
 * arrays are not set and the manifest is returned to the state it was in prior to calling.
 *
 * Returns 0 if the manifest is well formed, if there are no duplicate fields, and if all essential
 * fields are valid.  Counts invalid non-essential fields and unrecognised fields in m->malformed.
 *
 * Returns -1 if there is an unrecoverable error (eg, malloc(3) returns NULL, out of memory).
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int rhizome_manifest_parse(rhizome_manifest *m)
{
  IN();
  assert(m->manifest_all_bytes <= sizeof m->manifestdata);
  assert(m->manifest_body_bytes == 0);
  assert(m->var_count == 0);
  assert(!m->finalised);
  assert(m->malformed == NULL);
  assert(!m->has_id);
  assert(!m->has_filehash);
  assert(!m->is_journal);
  assert(m->filesize == RHIZOME_SIZE_UNSET);
  assert(m->tail == RHIZOME_SIZE_UNSET);
  assert(m->version == 0);
  assert(!m->has_date);
  assert(!m->has_sender);
  assert(!m->has_recipient);
  assert(m->payloadEncryption == PAYLOAD_CRYPT_UNKNOWN);
  unsigned invalid = 0;
  unsigned has_invalid_core = 0;
  unsigned has_duplicate = 0;
  const char *const end = (const char *)m->manifestdata + m->manifest_all_bytes;
  const char *p;
  unsigned line_number = 0;
  for (p = (const char *)m->manifestdata; !invalid && p < end && *p; ++p) {
    ++line_number;
    const char *const plabel = p++;
    while (p < end && *p && *p != '=' && *p != '\n')
      ++p;
    if (p == end || *p != '=') {
      if (config.debug.rhizome_manifest)
	DEBUGF("Invalid manifest line %u: %s", line_number, alloca_toprint(-1, plabel, p - plabel + 1));
      break;
    }
    assert(p < end);
    assert(*p == '=');
    const char *const pvalue = ++p;
    while (p < end && *p && *p != '\n')
      ++p;
    if (p >= end || *p != '\n') {
      if (config.debug.rhizome_manifest)
	DEBUGF("Missing manifest newline at line %u: %s", line_number, alloca_toprint(-1, plabel, p - plabel));
      break;
    }
    const char *const eol = (p > pvalue && p[-1] == '\r') ? p - 1 : p;
    enum rhizome_manifest_parse_status status = rhizome_manifest_parse_field(m, plabel, pvalue - plabel - 1, pvalue, eol - pvalue);
    int status_ok = 0;
    switch (status) {
      case RHIZOME_MANIFEST_ERROR:
	RETURN(-1);
      case RHIZOME_MANIFEST_OK:
	status_ok = 1;
	break;
      case RHIZOME_MANIFEST_SYNTAX_ERROR:
	status_ok = 1;
	++invalid;
	break;
      case RHIZOME_MANIFEST_DUPLICATE_FIELD:
	status_ok = 1;
	++has_duplicate;
	break;
      case RHIZOME_MANIFEST_INVALID:
	status_ok = 1;
	++has_invalid_core;
	break;
      case RHIZOME_MANIFEST_MALFORMED:
	status_ok = 1;
	m->malformed = "Invalid field";
	break;
      case RHIZOME_MANIFEST_OVERFLOW:
	status_ok = 1;
	++invalid;
	break;
    }
    if (!status_ok)
      FATALF("status = %d", status);
    assert(p < end);
    assert(*p == '\n');
  }
  if ((p < end && *p) || has_invalid_core || has_duplicate) {
    rhizome_manifest_clear(m);
    RETURN(1);
  }
  // The null byte is included in the body (and checksum), not the signature block
  if (p < end) {
    assert(*p == '\0');
    ++p;
  }
  m->manifest_body_bytes = p - (const char *)m->manifestdata;
  RETURN(0);
  OUT();
}

typedef int MANIFEST_FIELD_TESTER(const rhizome_manifest *);
typedef void MANIFEST_FIELD_UNSETTER(struct __sourceloc, rhizome_manifest *);
typedef void MANIFEST_FIELD_COPIER(struct __sourceloc, rhizome_manifest *, const rhizome_manifest *);
typedef int MANIFEST_FIELD_PARSER(rhizome_manifest *, const char *);

static int _rhizome_manifest_test_id(const rhizome_manifest *m)
{
  return m->has_id;
}
static void _rhizome_manifest_unset_id(struct __sourceloc __whence, rhizome_manifest *m)
{
  rhizome_manifest_set_id(m, NULL);
}
static void _rhizome_manifest_copy_id(struct __sourceloc __whence, rhizome_manifest *m, const rhizome_manifest *srcm)
{
  rhizome_manifest_set_id(m, srcm->has_id ? &srcm->cryptoSignPublic : NULL);
}
static int _rhizome_manifest_parse_id(rhizome_manifest *m, const char *text)
{
  rhizome_bid_t bid;
  if (str_to_rhizome_bid_t(&bid, text) == -1)
    return 0;
  rhizome_manifest_set_id(m, &bid);
  return 1;
}

static int _rhizome_manifest_test_version(const rhizome_manifest *m)
{
  return m->version != 0;
}
static void _rhizome_manifest_unset_version(struct __sourceloc __whence, rhizome_manifest *m)
{
  rhizome_manifest_del_version(m);
}
static void _rhizome_manifest_copy_version(struct __sourceloc __whence, rhizome_manifest *m, const rhizome_manifest *srcm)
{
  rhizome_manifest_set_version(m, srcm->version);
}
static int _rhizome_manifest_parse_version(rhizome_manifest *m, const char *text)
{
  uint64_t version;
  if (!str_to_uint64(text, 10, &version, NULL) || version == 0)
    return 0;
  rhizome_manifest_set_version(m, version);
  return 1;
}

static int _rhizome_manifest_test_filehash(const rhizome_manifest *m)
{
  return m->has_filehash;
}
static void _rhizome_manifest_unset_filehash(struct __sourceloc __whence, rhizome_manifest *m)
{
  rhizome_manifest_set_filehash(m, NULL);
}
static void _rhizome_manifest_copy_filehash(struct __sourceloc __whence, rhizome_manifest *m, const rhizome_manifest *srcm)
{
  rhizome_manifest_set_filehash(m, srcm->has_filehash ? &srcm->filehash : NULL);
}
static int _rhizome_manifest_parse_filehash(rhizome_manifest *m, const char *text)
{
  rhizome_filehash_t hash;
  if (str_to_rhizome_filehash_t(&hash, text) == -1)
    return 0;
  rhizome_manifest_set_filehash(m, &hash);
  return 1;
}

static int _rhizome_manifest_test_filesize(const rhizome_manifest *m)
{
  return m->filesize != RHIZOME_SIZE_UNSET;
}
static void _rhizome_manifest_unset_filesize(struct __sourceloc __whence, rhizome_manifest *m)
{
  rhizome_manifest_set_filesize(m, RHIZOME_SIZE_UNSET);
}
static void _rhizome_manifest_copy_filesize(struct __sourceloc __whence, rhizome_manifest *m, const rhizome_manifest *srcm)
{
  rhizome_manifest_set_filesize(m, srcm->filesize);
}
static int _rhizome_manifest_parse_filesize(rhizome_manifest *m, const char *text)
{
  uint64_t size;
  if (!str_to_uint64(text, 10, &size, NULL) || size == RHIZOME_SIZE_UNSET)
    return 0;
  rhizome_manifest_set_filesize(m, size);
  return 1;
}

static int _rhizome_manifest_test_tail(const rhizome_manifest *m)
{
  return m->is_journal;
}
static void _rhizome_manifest_unset_tail(struct __sourceloc __whence, rhizome_manifest *m)
{
  rhizome_manifest_set_tail(m, RHIZOME_SIZE_UNSET);
}
static void _rhizome_manifest_copy_tail(struct __sourceloc __whence, rhizome_manifest *m, const rhizome_manifest *srcm)
{
  rhizome_manifest_set_tail(m, srcm->tail);
}
static int _rhizome_manifest_parse_tail(rhizome_manifest *m, const char *text)
{
  uint64_t tail;
  if (!str_to_uint64(text, 10, &tail, NULL) || tail == RHIZOME_SIZE_UNSET)
    return 0;
  rhizome_manifest_set_tail(m, tail);
  return 1;
}

static int _rhizome_manifest_test_BK(const rhizome_manifest *m)
{
  return m->has_bundle_key;
}
static void _rhizome_manifest_unset_BK(struct __sourceloc __whence, rhizome_manifest *m)
{
  rhizome_manifest_del_bundle_key(m);
}
static void _rhizome_manifest_copy_BK(struct __sourceloc __whence, rhizome_manifest *m, const rhizome_manifest *srcm)
{
  rhizome_manifest_set_bundle_key(m, srcm->has_bundle_key ? &srcm->bundle_key : NULL);
}
static int _rhizome_manifest_parse_BK(rhizome_manifest *m, const char *text)
{
  rhizome_bk_t bk;
  if (str_to_rhizome_bk_t(&bk, text) == -1)
    return 0;
  rhizome_manifest_set_bundle_key(m, &bk);
  return 1;
}

static int _rhizome_manifest_test_service(const rhizome_manifest *m)
{
  return m->service != NULL;
}
static void _rhizome_manifest_unset_service(struct __sourceloc __whence, rhizome_manifest *m)
{
  rhizome_manifest_del_service(m);
}
static void _rhizome_manifest_copy_service(struct __sourceloc __whence, rhizome_manifest *m, const rhizome_manifest *srcm)
{
  rhizome_manifest_set_service(m, srcm->service);
}
static int _rhizome_manifest_parse_service(rhizome_manifest *m, const char *text)
{
  if (!rhizome_str_is_manifest_service(text))
    return 0;
  rhizome_manifest_set_service(m, text);
  return 1;
}

static int _rhizome_manifest_test_date(const rhizome_manifest *m)
{
  return m->has_date;
}
static void _rhizome_manifest_unset_date(struct __sourceloc __whence, rhizome_manifest *m)
{
  rhizome_manifest_del_date(m);
}
static void _rhizome_manifest_copy_date(struct __sourceloc __whence, rhizome_manifest *m, const rhizome_manifest *srcm)
{
  if (srcm->has_date)
    rhizome_manifest_set_date(m, srcm->date);
  else
    rhizome_manifest_del_date(m);
}
static int _rhizome_manifest_parse_date(rhizome_manifest *m, const char *text)
{
  int64_t date;
  if (!str_to_int64(text, 10, &date, NULL))
    return 0;
  rhizome_manifest_set_date(m, date);
  return 1;
}

static int _rhizome_manifest_test_sender(const rhizome_manifest *m)
{
  return m->has_sender;
}
static void _rhizome_manifest_unset_sender(struct __sourceloc __whence, rhizome_manifest *m)
{
  rhizome_manifest_set_sender(m, NULL);
}
static void _rhizome_manifest_copy_sender(struct __sourceloc __whence, rhizome_manifest *m, const rhizome_manifest *srcm)
{
  rhizome_manifest_set_sender(m, srcm->has_sender ? &srcm->sender : NULL);
}
static int _rhizome_manifest_parse_sender(rhizome_manifest *m, const char *text)
{
  sid_t sid;
  if (str_to_sid_t(&sid, text) == -1)
    return 0;
  rhizome_manifest_set_sender(m, &sid);
  return 1;
}

static int _rhizome_manifest_test_recipient(const rhizome_manifest *m)
{
  return m->has_recipient;
}
static void _rhizome_manifest_unset_recipient(struct __sourceloc __whence, rhizome_manifest *m)
{
  rhizome_manifest_set_recipient(m, NULL);
}
static void _rhizome_manifest_copy_recipient(struct __sourceloc __whence, rhizome_manifest *m, const rhizome_manifest *srcm)
{
  rhizome_manifest_set_recipient(m, srcm->has_recipient ? &srcm->recipient : NULL);
}
static int _rhizome_manifest_parse_recipient(rhizome_manifest *m, const char *text)
{
  sid_t sid;
  if (str_to_sid_t(&sid, text) == -1)
    return 0;
  rhizome_manifest_set_recipient(m, &sid);
  return 1;
}

static int _rhizome_manifest_test_name(const rhizome_manifest *m)
{
  return m->name != NULL;
}
static void _rhizome_manifest_unset_name(struct __sourceloc __whence, rhizome_manifest *m)
{
  rhizome_manifest_del_name(m);
}
static void _rhizome_manifest_copy_name(struct __sourceloc __whence, rhizome_manifest *m, const rhizome_manifest *srcm)
{
  rhizome_manifest_set_name(m, srcm->name);
}
static int _rhizome_manifest_parse_name(rhizome_manifest *m, const char *text)
{
  rhizome_manifest_set_name(m, text);
  return 1;
}

static int _rhizome_manifest_test_crypt(const rhizome_manifest *m)
{
  return m->payloadEncryption != PAYLOAD_CRYPT_UNKNOWN;
}
static void _rhizome_manifest_unset_crypt(struct __sourceloc __whence, rhizome_manifest *m)
{
  rhizome_manifest_set_crypt(m, PAYLOAD_CRYPT_UNKNOWN);
}
static void _rhizome_manifest_copy_crypt(struct __sourceloc __whence, rhizome_manifest *m, const rhizome_manifest *srcm)
{
  rhizome_manifest_set_crypt(m, srcm->payloadEncryption);
}
static int _rhizome_manifest_parse_crypt(rhizome_manifest *m, const char *text)
{
  if (!(strcmp(text, "0") == 0 || strcmp(text, "1") == 0))
    return 0;
  rhizome_manifest_set_crypt(m, (text[0] == '1') ? PAYLOAD_ENCRYPTED : PAYLOAD_CLEAR);
  return 1;
}

static struct rhizome_manifest_field_descriptor {
    const char *label;
    int core;
    MANIFEST_FIELD_TESTER *test;
    MANIFEST_FIELD_UNSETTER *unset;
    MANIFEST_FIELD_COPIER *copy;
    MANIFEST_FIELD_PARSER *parse;
}
    rhizome_manifest_fields[] = {
#define FIELD(CORE, NAME) \
        { #NAME, CORE, _rhizome_manifest_test_ ## NAME, _rhizome_manifest_unset_ ## NAME, _rhizome_manifest_copy_ ## NAME, _rhizome_manifest_parse_ ## NAME }
	FIELD(1, id),
	FIELD(1, version),
	FIELD(1, filehash),
	FIELD(1, filesize),
	FIELD(1, tail),
	FIELD(0, BK),
	FIELD(0, service),
	FIELD(0, date),
	FIELD(0, sender),
	FIELD(0, recipient),
	FIELD(0, name),
	FIELD(0, crypt),
#undef FIELD
    };

static struct rhizome_manifest_field_descriptor *get_rhizome_manifest_field_descriptor(const char *label)
{
  unsigned i;
  for (i = 0; i < NELS(rhizome_manifest_fields); ++i)
    if (strcasecmp(label, rhizome_manifest_fields[i].label) == 0)
      return &rhizome_manifest_fields[i];
  return NULL;
}

/* Overwrite a Rhizome manifest with fields from another.  Used in the "add bundle" application API
 * when the application supplies a partial manifest to override or add to existing manifest fields.
 *
 * Returns -1 if a field in the destination manifest cannot be overwritten for an unrecoverable
 * reason, eg, out of memory or too many variables, leaving the destination manifest in an undefined
 * state.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int _rhizome_manifest_overwrite(struct __sourceloc __whence, rhizome_manifest *m, const rhizome_manifest *srcm)
{
  unsigned i;
  for (i = 0; i < NELS(rhizome_manifest_fields); ++i) {
      struct rhizome_manifest_field_descriptor *desc = &rhizome_manifest_fields[i];
      if (desc->test(srcm)) {
	if (config.debug.rhizome_manifest)
	  DEBUGF("COPY manifest[%d].%s to:", srcm->manifest_record_number, desc->label);
	desc->copy(__whence, m, srcm);
      }
  }
  for (i = 0; i < srcm->var_count; ++i) {
    struct rhizome_manifest_field_descriptor *desc = get_rhizome_manifest_field_descriptor(srcm->vars[i]);
    if (!desc)
      if (_rhizome_manifest_set(__whence, m, srcm->vars[i], srcm->values[i]) == NULL)
	return -1;
  }
  return 0;
}

int rhizome_manifest_field_label_is_valid(const char *field_label, size_t field_label_len)
{
  if (field_label_len == 0 || field_label_len > MAX_MANIFEST_FIELD_LABEL_LEN)
    return 0;
  if (!isalpha(field_label[0]))
    return 0;
  unsigned i;
  for (i = 1; i != field_label_len; ++i)
    if (!isalnum(field_label[i]))
      return 0;
  return 1;
}

int rhizome_manifest_field_value_is_valid(const char *field_value, size_t field_value_len)
{
  if (field_value_len >= MAX_MANIFEST_BYTES)
    return 0;
  unsigned i;
  for (i = 0; i < field_value_len; ++i)
    if (field_value[i] == '\0' || field_value[i] == '\r' || field_value[i] == '\n')
      return 0;
  return 1;
}

/* Parse a single Rhizome manifest field.  Used for incremental construction or modification of
 * manifests.
 *
 * If the supplied field_label is invalid (does not conform to the syntax for field names) or the
 * field_value string is too long or contains a NUL (ASCII 0), CR (ASCII 13) or LF (ASCII 10), then
 * returns RHIZOME_MANIFEST_SYNTAX_ERROR and leaves the manifest unchanged.
 *
 * If a field with the given label already exists in the manifest, then returns
 * RHIZOME_MANIFEST_DUPLICATE_FIELD without modifying the manifest.  (To overwrite an existing
 * field, first remove it by calling rhizome_manifest_remove_field() then call
 * rhizome_manifest_parse_field().)
 *
 * If the maximum number of fields are already occupied in the manifest, then returns
 * RHIZOME_MANIFEST_OVERFLOW and leaves the manifest unchanged.
 *
 * If the supplied field_value is invalid (does not parse according to the field's syntax, eg,
 * unsigned integer) then returns RHIZOME_MANIFEST_INVALID if it is a core field, otherwise returns
 * RHIZOME_MANIFEST_MALFORMED and leaves the manifest unchanged.  Unsupported fields are not parsed;
 * their value string is simply stored, so they cannot evoke a MALFORMED result.
 *
 * Otherwise, sets the relevant element(s) of the manifest structure and appends the field_label and
 * field_value strings into the m->vars[] and m->values[] arrays, as pointers to malloc(3)ed NUL
 * terminated strings, and increments m->var_count.  Returns RHIZOME_MANIFEST_OK.
 *
 * Returns -1 (RHIZOME_MANIFEST_ERROR) if there is an unrecoverable error (eg, malloc(3) returns
 * NULL, out of memory).
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
enum rhizome_manifest_parse_status
rhizome_manifest_parse_field(rhizome_manifest *m, const char *field_label, size_t field_label_len, const char *field_value, size_t field_value_len)
{
  // Syntax check on field label.
  if (!rhizome_manifest_field_label_is_valid(field_label, field_label_len)) {
    if (config.debug.rhizome_manifest)
      DEBUGF("Invalid manifest field name: %s", alloca_toprint(100, field_label, field_label_len));
    return RHIZOME_MANIFEST_SYNTAX_ERROR;
  }
  const char *label = alloca_strndup(field_label, field_label_len);
  // Sanity and syntax check on field value.
  if (!rhizome_manifest_field_value_is_valid(field_value, field_value_len)) {
    if (config.debug.rhizome_manifest)
      DEBUGF("Invalid manifest field value: %s=%s", label, alloca_toprint(100, field_value, field_value_len));
    return RHIZOME_MANIFEST_SYNTAX_ERROR;
  }
  const char *value = alloca_strndup(field_value, field_value_len);
  struct rhizome_manifest_field_descriptor *desc = get_rhizome_manifest_field_descriptor(label);
  enum rhizome_manifest_parse_status status = RHIZOME_MANIFEST_OK;
  assert(m->var_count <= NELS(m->vars));
  if (desc ? desc->test(m) : rhizome_manifest_get(m, label) != NULL) {
    if (config.debug.rhizome_manifest)
      DEBUGF("Duplicate field at %s=%s", label, alloca_toprint(100, field_value, field_value_len));
    status = RHIZOME_MANIFEST_DUPLICATE_FIELD;
  } else if (m->var_count == NELS(m->vars)) {
    if (config.debug.rhizome_manifest)
      DEBUGF("Manifest field limit reached at %s=%s", label, alloca_toprint(100, field_value, field_value_len));
    status = RHIZOME_MANIFEST_OVERFLOW;
  } else if (desc) {
    if (!desc->parse(m, value)) {
      if (config.debug.rhizome_manifest)
	DEBUGF("Manifest field parse failed at %s=%s", label, alloca_toprint(100, field_value, field_value_len));
      status = desc->core ? RHIZOME_MANIFEST_INVALID : RHIZOME_MANIFEST_MALFORMED;
    }
  } else if (rhizome_manifest_set(m, label, value) == NULL)
    status = RHIZOME_MANIFEST_ERROR;
  if (status != RHIZOME_MANIFEST_OK) {
    if (config.debug.rhizome_manifest)
      DEBUGF("SKIP manifest[%d].%s = %s (status=%d)", m->manifest_record_number, label, alloca_str_toprint(value), status);
  }
  return status;
}

/* Remove the field with the given label from the manifest.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int rhizome_manifest_remove_field(rhizome_manifest *m, const char *field_label, size_t field_label_len)
{
  if (!rhizome_manifest_field_label_is_valid(field_label, field_label_len)) {
    if (config.debug.rhizome_manifest)
      DEBUGF("Invalid manifest field name: %s", alloca_toprint(100, field_label, field_label_len));
    return 0;
  }
  const char *label = alloca_strndup(field_label, field_label_len);
  struct rhizome_manifest_field_descriptor *desc = NULL;
  unsigned i;
  for (i = 0; desc == NULL && i < NELS(rhizome_manifest_fields); ++i)
    if (strcasecmp(label, rhizome_manifest_fields[i].label) == 0)
      desc = &rhizome_manifest_fields[i];
  if (!desc)
    return rhizome_manifest_del(m, label);
  if (!desc->test(m))
    return 0;
  desc->unset(__WHENCE__, m);
  return 1;
}

/* If all essential (transport) fields are present and well formed then sets the m->finalised field
 * and returns 1, otherwise returns 0.
 *
 * Sets m->malformed if any non-essential fields are missing or invalid.  It is up to the caller to
 * check m->malformed and decide whether or not to process a malformed manifest.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int rhizome_manifest_validate(rhizome_manifest *m)
{
  return rhizome_manifest_validate_reason(m) == NULL ? 1 : 0;
}

/* If all essential (transport) fields are present and well formed then sets the m->finalised field
 * and returns NULL, otherwise returns a pointer to a static string (not malloc(3)ed) describing the
 * problem.
 *
 * If any non-essential fields are missing or invalid, then sets m->malformed to point to a static
 * string describing the problem.  It is up to the caller to check m->malformed and decide whether
 * or not to process a malformed manifest.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
const char *rhizome_manifest_validate_reason(rhizome_manifest *m)
{
  const char *reason = NULL;
  if (!m->has_id)
    reason = "Missing 'id' field";
  else if (m->version == 0)
    reason = "Missing 'version' field";
  else if (m->filesize == RHIZOME_SIZE_UNSET)
    reason = "Missing 'filesize' field";
  else if (m->filesize == 0 && m->has_filehash)
    reason = "Spurious 'filehash' field";
  else if (m->filesize != 0 && !m->has_filehash)
    reason = "Missing 'filehash' field";
  if (reason && config.debug.rhizome_manifest)
    DEBUG(reason);
  if (m->service == NULL)
    m->malformed = "Missing 'service' field";
  else if (strcmp(m->service, RHIZOME_SERVICE_FILE) == 0) {
    if (m->name == NULL)
      m->malformed = "Manifest with service='" RHIZOME_SERVICE_FILE "' missing 'name' field";
  } else if (strcmp(m->service, RHIZOME_SERVICE_MESHMS) == 0
          || strcmp(m->service, RHIZOME_SERVICE_MESHMS2) == 0
  ) {
    if (!m->has_recipient)
      m->malformed = "Manifest missing 'recipient' field";
    else if (!m->has_sender)
      m->malformed = "Manifest missing 'sender' field";
  }
  else if (!rhizome_str_is_manifest_service(m->service))
    m->malformed = "Manifest invalid 'service' field";
  else if (!m->has_date)
    m->malformed = "Missing 'date' field";
  if (m->malformed && config.debug.rhizome_manifest)
    DEBUG(m->malformed);
  m->finalised = (reason == NULL);
  return reason;
}

int rhizome_read_manifest_from_file(rhizome_manifest *m, const char *filename)
{
  ssize_t bytes = read_whole_file(filename, m->manifestdata, sizeof m->manifestdata);
  if (bytes == -1)
    return -1;
  m->manifest_all_bytes = (size_t) bytes;
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

static unsigned _count_free_manifests()
{
  unsigned count_free = 0;
  unsigned i;
  for (i = 0; i != MAX_RHIZOME_MANIFESTS; ++i)
    if (manifest_free[i])
      ++count_free;
  return count_free;
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

  if (config.debug.rhizome_manifest)
    DEBUGF("NEW manifest[%d], count_free=%u", m->manifest_record_number, _count_free_manifests());

  // Set global defaults for a manifest (which are not zero)
  rhizome_manifest_clear(m);

  return m;
}

void _rhizome_manifest_free(struct __sourceloc __whence, rhizome_manifest *m)
{
  if (!m) return;
  int mid=m->manifest_record_number;

  if (m!=&manifests[mid])
    FATALF("%s(): manifest at %p claims to be manifest[%d] (%p) but isn't",
	  __FUNCTION__, m, mid, &manifests[mid]
      );

  if (manifest_free[mid])
    FATALF("%s(): manifest[%d] (%p) was already freed at %s:%d:%s()",
	  __FUNCTION__, mid, m,
	  manifest_free_whence[mid].file,
	  manifest_free_whence[mid].line,
	  manifest_free_whence[mid].function
	);

  /* Free variable and signature blocks. */
  rhizome_manifest_clear(m);
  if (m->dataFileName) {
    if (m->dataFileUnlinkOnFree && unlink(m->dataFileName) == -1)
      WARNF_perror("unlink(%s)", alloca_str_toprint(m->dataFileName));
    free((char *) m->dataFileName);
    m->dataFileName = NULL;
  }

  manifest_free[mid]=1;
  manifest_free_whence[mid]=__whence;
  if (mid<manifest_first_free) manifest_first_free=mid;

  if (config.debug.rhizome_manifest)
    DEBUGF("FREE manifest[%d], count_free=%u", m->manifest_record_number, _count_free_manifests());

  return;
}

/* Convert variable list into manifest text body and compute the hash.  Do not sign.
 */
static int rhizome_manifest_pack_variables(rhizome_manifest *m)
{
  assert(m->var_count <= NELS(m->vars));
  strbuf sb = strbuf_local((char*)m->manifestdata, sizeof m->manifestdata);
  unsigned i;
  for (i = 0; i < m->var_count; ++i) {
    strbuf_puts(sb, m->vars[i]);
    strbuf_putc(sb, '=');
    strbuf_puts(sb, m->values[i]);
    strbuf_putc(sb, '\n');
  }
  if (strbuf_overrun(sb))
    return WHYF("Manifest overflow: body of %zu bytes exceeds limit of %zu", strbuf_count(sb) + 1, sizeof m->manifestdata);
  m->manifest_body_bytes = strbuf_len(sb) + 1;
  if (config.debug.rhizome)
    DEBUGF("Repacked variables into manifest: %zu bytes", m->manifest_body_bytes);
  m->manifest_all_bytes = m->manifest_body_bytes;
  m->selfSigned = 0;
  return 0;
}

/* Sign this manifest using it's own BID secret key.  Manifest must not already be signed.
 * Manifest body hash must already be computed.
 */
int rhizome_manifest_selfsign(rhizome_manifest *m)
{
  assert(m->manifest_body_bytes > 0);
  assert(m->manifest_body_bytes <= sizeof m->manifestdata);
  assert(m->manifestdata[m->manifest_body_bytes - 1] == '\0');
  assert(m->manifest_body_bytes == m->manifest_all_bytes); // no signature yet
  if (!m->haveSecret)
    return WHY("Need private key to sign manifest");
  crypto_hash_sha512(m->manifesthash, m->manifestdata, m->manifest_body_bytes);
  rhizome_signature sig;
  if (rhizome_sign_hash(m, &sig) == -1)
    return WHY("rhizome_sign_hash() failed");
  assert(sig.signatureLength > 0);
  /* Append signature to end of manifest data */
  if (sig.signatureLength + m->manifest_body_bytes > sizeof m->manifestdata)
    return WHYF("Manifest overflow: body %zu + signature %zu bytes exceeds limit of %zu",
		m->manifest_body_bytes,
		sig.signatureLength,
		sizeof m->manifestdata
	      );
  bcopy(sig.signature, m->manifestdata + m->manifest_body_bytes, sig.signatureLength);
  m->manifest_all_bytes = m->manifest_body_bytes + sig.signatureLength;
  m->selfSigned = 1;
  return 0;
}

int rhizome_write_manifest_file(rhizome_manifest *m, const char *path, char append)
{
  if (config.debug.rhizome)
    DEBUGF("write manifest (%zd bytes) to %s", m->manifest_all_bytes, path);
  assert(m->finalised);
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

enum rhizome_bundle_status rhizome_manifest_finalise(rhizome_manifest *m, rhizome_manifest **mout, int deduplicate)
{
  IN();
  assert(*mout == NULL);
  if (!m->finalised && !rhizome_manifest_validate(m))
    RETURN(RHIZOME_BUNDLE_STATUS_INVALID);
  // The duplicate detection logic exists to filter out files repeatedly added with no existing
  // manifest (ie, "de-bounce" for the "Add File" user interface action).
  // 1. If a manifest was supplied with a bundle ID, don't check for a duplicate.
  // 2. Never perform duplicate detection on journals (the first append does not supply a bundle ID,
  //    but all subsequent appends supply a bundle ID, so are caught by case (1)).
  if (deduplicate && m->haveSecret != EXISTING_BUNDLE_ID && !m->is_journal) {
    enum rhizome_bundle_status status = rhizome_find_duplicate(m, mout);
    switch (status) {
      case RHIZOME_BUNDLE_STATUS_DUPLICATE:
	assert(*mout != NULL);
	assert(*mout != m);
	RETURN(status);
      case RHIZOME_BUNDLE_STATUS_ERROR:
	if (*mout != NULL && *mout != m) {
	  rhizome_manifest_free(*mout);
	  *mout = NULL;
	}
	RETURN(status);
      case RHIZOME_BUNDLE_STATUS_NEW:
	break;
      default:
	FATALF("rhizome_find_duplicate() returned %d", status);
    }
  }
  assert(*mout == NULL);
  *mout = m;

  /* Convert to final form for signing and writing to disk */
  if (rhizome_manifest_pack_variables(m))
    RETURN(WHY("Could not convert manifest to wire format"));

  /* Sign it */
  assert(!m->selfSigned);
  if (rhizome_manifest_selfsign(m))
    RETURN(WHY("Could not sign manifest"));
  assert(m->selfSigned);

  /* mark manifest as finalised */
  enum rhizome_bundle_status status = rhizome_add_manifest(m, mout);
  RETURN(status);
  OUT();
}

/* Returns 1 if the name was successfully set, 0 if not.
 */
int rhizome_manifest_set_name_from_path(rhizome_manifest *m, const char *filepath)
{
  const char *name = strrchr(filepath, '/');
  if (name)
    ++name; // skip '/'
  else
    name = filepath;
  if (!rhizome_str_is_manifest_name(name)) {
    WARNF("invalid rhizome name %s -- not used", alloca_str_toprint(name));
    return 0;
  }
  rhizome_manifest_set_name(m, name);
  return 1;
}

/* Fill in a few missing manifest fields, to make it easier to use when adding new files:
 *  - use the current time for "date" and "version"
 *  - use the given author SID, or the 'sender' if present, as the author
 *  - create an ID if there is none, otherwise authenticate the existing one
 *  - if service is file, then use the payload file's basename for "name"
 *
 * Return NULL if successful, otherwise a pointer to a static text string describing the reason for
 * the failure (always an internal/unrecoverable error).
 */
const char * rhizome_fill_manifest(rhizome_manifest *m, const char *filepath, const sid_t *authorSidp)
{
  const char *reason = NULL;

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

  /* Fill in the bundle secret and bundle ID.
   */
  int valid_haveSecret = 0;
  switch (m->haveSecret) {
  case SECRET_UNKNOWN:
    valid_haveSecret = 1;
    // If the Bundle Id is already known, then derive the bundle secret from BK if known.
    // If there is no Bundle Id, then create a new bundle Id and secret from scratch.
    if (m->has_id) {
      if (config.debug.rhizome)
	DEBUGF("discover secret for bundle bid=%s", alloca_tohex_rhizome_bid_t(m->cryptoSignPublic));
      rhizome_authenticate_author(m);
      break;
    }
    if (config.debug.rhizome)
      DEBUG("creating new bundle");
    if (rhizome_manifest_createid(m) == -1) {
      WHY(reason = "Could not bind manifest to an ID");
      return reason;
    }
    // fall through to set the BK field...
  case NEW_BUNDLE_ID:
    valid_haveSecret = 1;
    assert(m->has_id);
    if (m->authorship != ANONYMOUS) {
      if (config.debug.rhizome)
	DEBUGF("set BK field for bid=%s", alloca_tohex_rhizome_bid_t(m->cryptoSignPublic));
      rhizome_manifest_add_bundle_key(m); // set the BK field
    }
    break;
  case EXISTING_BUNDLE_ID:
    valid_haveSecret = 1;
    // If modifying an existing bundle, try to discover the bundle secret key and the author.
    assert(m->has_id);
    if (config.debug.rhizome)
      DEBUGF("modifying existing bundle bid=%s", alloca_tohex_rhizome_bid_t(m->cryptoSignPublic));
    rhizome_authenticate_author(m);
    // TODO assert that new version > old version?
  }
  if (!valid_haveSecret)
    FATALF("haveSecret = %d", m->haveSecret);

  /* Service field must already be set.
   */
  if (m->service == NULL) {
    WHYF(reason = "Missing 'service' field");
    return reason;
  }
  if (config.debug.rhizome)
    DEBUGF("manifest contains service=%s", m->service);

  /* Fill in 'date' field to current time unless already set.
   */
  if (!m->has_date) {
    rhizome_manifest_set_date(m, (int64_t) gettime_ms());
    if (config.debug.rhizome)
      DEBUGF("missing 'date', set default date=%"PRItime_ms_t, m->date);
  }

  /* Fill in 'name' field if service=file.
   */
  if (strcasecmp(RHIZOME_SERVICE_FILE, m->service) == 0) {
    if (m->name) {
      if (config.debug.rhizome)
	DEBUGF("manifest already contains name=%s", alloca_str_toprint(m->name));
    } else if (filepath)
      rhizome_manifest_set_name_from_path(m, filepath);
    else if (config.debug.rhizome)
      DEBUGF("manifest missing 'name'");
  }

  /* Fill in 'crypt' field.  Anything sent from one person to another should be considered private
   * and encrypted by default.
   */
  if (   m->payloadEncryption == PAYLOAD_CRYPT_UNKNOWN
      && m->has_sender
      && m->has_recipient
      && !is_sid_t_broadcast(m->recipient)
  ) {
    if (config.debug.rhizome)
      DEBUGF("Implicitly adding payload encryption due to presense of sender & recipient fields");
    rhizome_manifest_set_crypt(m, PAYLOAD_ENCRYPTED);
  }

  return NULL;
}

/* Work out the authorship status of the bundle without performing any cryptographic checks.
 * Sets the 'authorship' element and returns 1 if an author was found, 0 if not.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int rhizome_lookup_author(rhizome_manifest *m)
{
  IN();
  keyring_iterator it;
  
  switch (m->authorship) {
    case AUTHOR_NOT_CHECKED:
      if (config.debug.rhizome)
	DEBUGF("manifest[%d] lookup author=%s", m->manifest_record_number, alloca_tohex_sid_t(m->author));
      keyring_iterator_start(keyring, &it);
      if (keyring_find_sid(&it, &m->author)) {
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
	keyring_iterator_start(keyring, &it);
	if (keyring_find_sid(&it, &m->sender)) {
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
