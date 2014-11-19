/*
 Serval DNA - Rhizome command line interface
 Copyright (C) 2014 Serval Project Inc.
 
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

#include "cli.h"
#include "conf.h"
#include "keyring.h"
#include "commandline.h"
#include "rhizome.h"
#include "instance.h"

static void cli_put_manifest(struct cli_context *context, const rhizome_manifest *m)
{
  assert(m->filesize != RHIZOME_SIZE_UNSET);
  cli_field_name(context, "manifestid", ":"); // TODO rename to "bundleid" or "bid"
  cli_put_string(context, alloca_tohex_rhizome_bid_t(m->cryptoSignPublic), "\n");
  cli_field_name(context, "version", ":");
  cli_put_long(context, m->version, "\n");
  cli_field_name(context, "filesize", ":");
  cli_put_long(context, m->filesize, "\n");
  if (m->filesize != 0) {
    cli_field_name(context, "filehash", ":");
    cli_put_string(context, alloca_tohex_rhizome_filehash_t(m->filehash), "\n");
  }
  if (m->has_bundle_key) {
    cli_field_name(context, "BK", ":");
    cli_put_string(context, alloca_tohex_rhizome_bk_t(m->bundle_key), "\n");
  }
  if (m->has_date) {
    cli_field_name(context, "date", ":");
    cli_put_long(context, m->date, "\n");
  }
  switch (m->payloadEncryption) {
    case PAYLOAD_CRYPT_UNKNOWN:
      break;
    case PAYLOAD_CLEAR:
      cli_field_name(context, "crypt", ":");
      cli_put_long(context, 0, "\n");
      break;
    case PAYLOAD_ENCRYPTED:
      cli_field_name(context, "crypt", ":");
      cli_put_long(context, 1, "\n");
      break;
  }
  if (m->service) {
    cli_field_name(context, "service", ":");
    cli_put_string(context, m->service, "\n");
  }
  if (m->name) {
    cli_field_name(context, "name", ":");
    cli_put_string(context, m->name, "\n");
  }
  cli_field_name(context, ".readonly", ":");
  cli_put_long(context, m->haveSecret ? 0 : 1, "\n");
  if (m->haveSecret) {
    char secret[RHIZOME_BUNDLE_KEY_STRLEN + 1];
    rhizome_bytes_to_hex_upper(m->cryptoSignSecret, secret, RHIZOME_BUNDLE_KEY_BYTES);
    cli_field_name(context, ".secret", ":");
    cli_put_string(context, secret, "\n");
  }
  if (m->authorship == AUTHOR_AUTHENTIC) {
    cli_field_name(context, ".author", ":");
    cli_put_string(context, alloca_tohex_sid_t(m->author), "\n");
  }
  cli_field_name(context, ".rowid", ":");
  cli_put_long(context, m->rowid, "\n");
  cli_field_name(context, ".inserttime", ":");
  cli_put_long(context, m->inserttime, "\n");
}

DEFINE_CMD(app_rhizome_hash_file, 0,
  "Compute the Rhizome hash of a file",
  "rhizome","hash","file","<filepath>");
static int app_rhizome_hash_file(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  /* compute hash of file. We do this without a manifest, so it will necessarily
     return the hash of the file unencrypted. */
  const char *filepath;
  cli_arg(parsed, "filepath", &filepath, NULL, "");
  rhizome_filehash_t hash;
  uint64_t size;
  if (rhizome_hash_file(NULL, filepath, &hash, &size) == -1)
    return -1;
  cli_put_string(context, size ? alloca_tohex_rhizome_filehash_t(hash) : "", "\n");
  return 0;
}

DEFINE_CMD(app_rhizome_add_file, 0,
  "Add a file to Rhizome and optionally write its manifest to the given path",
  "rhizome","add","file" KEYRING_PIN_OPTIONS,"[--force-new]","<author_sid>","<filepath>","[<manifestpath>]","[<bsk>]","...");
DEFINE_CMD(app_rhizome_add_file, 0,
  "Append content to a journal bundle",
  "rhizome", "journal", "append" KEYRING_PIN_OPTIONS, "<author_sid>", "<manifestid>", "<filepath>", "[<bsk>]");
static int app_rhizome_add_file(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  const char *filepath, *manifestpath, *manifestid, *authorSidHex, *bsktext;

  int force_new = 0 == cli_arg(parsed, "--force-new", NULL, NULL, NULL);
  cli_arg(parsed, "filepath", &filepath, NULL, "");
  if (cli_arg(parsed, "author_sid", &authorSidHex, cli_optional_sid, "") == -1)
    return -1;
  cli_arg(parsed, "manifestpath", &manifestpath, NULL, "");
  cli_arg(parsed, "manifestid", &manifestid, NULL, "");
  if (cli_arg(parsed, "bsk", &bsktext, cli_optional_bundle_secret_key, NULL) == -1)
    return -1;

  sid_t authorSid;
  if (authorSidHex[0] && str_to_sid_t(&authorSid, authorSidHex) == -1)
    return WHYF("invalid author_sid: %s", authorSidHex);
  
  // treat empty string the same as null
  if (bsktext && !*bsktext)
    bsktext = NULL;
  rhizome_bk_t bsk;
  if (bsktext && str_to_rhizome_bsk_t(&bsk, bsktext) == -1)
    return WHYF("invalid bsk: \"%s\"", bsktext);
  
  unsigned nfields = (parsed->varargi == -1) ? 0 : parsed->argc - (unsigned)parsed->varargi;
  struct field {
    const char *label;
    size_t labellen;
    const char *value;
    size_t valuelen;
  }
    fields[nfields];
  if (nfields) {
    assert(parsed->varargi >= 0);
    unsigned i;
    for (i = 0; i < nfields; ++i) {
      struct field *field = &fields[i];
      unsigned n = (unsigned)parsed->varargi + i;
      assert(n < parsed->argc);
      const char *arg = parsed->args[n];
      size_t arglen = strlen(arg);
      const char *eq;
      if (arglen > 0 && arg[0] == '!') {
	  field->label = arg + 1;
	  field->labellen = arglen - 1;
	  field->value = NULL;
      } else if ((eq = strchr(arg, '='))) {
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
    }
  }

  int journal = strcasecmp(parsed->args[1], "journal")==0;

  if (create_serval_instance_dir() == -1)
    return -1;
  
  if (!(keyring = keyring_open_instance_cli(parsed)))
    return -1;
  
  int ret = -1;
  rhizome_manifest *m = NULL;
  if (rhizome_opendb() == -1)
    goto finish;
  
  /* Create a new manifest that will represent the file.  If a manifest file was supplied, then read
   * it, otherwise create a blank manifest. */
  if ((m = rhizome_new_manifest()) == NULL){
    ret = WHY("Manifest struct could not be allocated -- not added to rhizome");
    goto finish;
  }
  if (manifestpath && *manifestpath && access(manifestpath, R_OK) == 0) {
    if (config.debug.rhizome)
      DEBUGF("reading manifest from %s", manifestpath);
    /* Don't verify the manifest, because it will fail if it is incomplete.
       This is okay, because we fill in any missing bits and sanity check before
       trying to write it out. However, we do insist that whatever we load is
       parsed okay and not malformed. */
    if (rhizome_read_manifest_from_file(m, manifestpath) || m->malformed) {
      ret = WHY("Manifest file could not be loaded -- not added to rhizome");
      goto finish;
    }
  } else if (manifestid && *manifestid) {
    if (config.debug.rhizome)
      DEBUGF("Reading manifest from database");
    rhizome_bid_t bid;
    if (str_to_rhizome_bid_t(&bid, manifestid) == -1) {
      ret = WHYF("Invalid bundle ID: %s", alloca_str_toprint(manifestid));
      goto finish;
    }
    if (rhizome_retrieve_manifest(&bid, m) != RHIZOME_BUNDLE_STATUS_SAME) {
      ret = WHY("Existing manifest could not be loaded -- not added to rhizome");
      goto finish;
    }
  } else {
    if (config.debug.rhizome)
      DEBUGF("Creating new manifest");
    if (journal) {
      rhizome_manifest_set_filesize(m, 0);
      rhizome_manifest_set_tail(m, 0);
    }
  }

  if (journal && !m->is_journal){
    ret = WHY("Existing manifest is not a journal");
    goto finish;
  }
  if (!journal && m->is_journal) {
    ret = WHY("Existing manifest is a journal");
    goto finish;
  }

  if (nfields) {
    unsigned i;
    for (i = 0; i != nfields; ++i) {
      struct field *field = &fields[i];
      rhizome_manifest_remove_field(m, field->label, field->labellen);
      if (field->value) {
	const char *label = alloca_strndup(field->label, field->labellen);
	enum rhizome_manifest_parse_status status = rhizome_manifest_parse_field(m, field->label, field->labellen, field->value, field->valuelen);
	int status_ok = 0;
	switch (status) {
	  case RHIZOME_MANIFEST_ERROR:
	    ret = WHY("Fatal error while updating manifest field");
	    goto finish;
	  case RHIZOME_MANIFEST_OK:
	    status_ok = 1;
	    break;
	  case RHIZOME_MANIFEST_SYNTAX_ERROR:
	    ret = WHYF("Manifest syntax error: %s=%s", label, alloca_toprint(-1, field->value, field->valuelen));
	    goto finish;
	  case RHIZOME_MANIFEST_DUPLICATE_FIELD:
	    abort(); // should not happen, field was removed first
	  case RHIZOME_MANIFEST_INVALID:
	    ret = WHYF("Manifest invalid field: %s=%s", label, alloca_toprint(-1, field->value, field->valuelen));
	    goto finish;
	  case RHIZOME_MANIFEST_MALFORMED:
	    ret = WHYF("Manifest malformed field: %s=%s", label, alloca_toprint(-1, field->value, field->valuelen));
	    goto finish;
	  case RHIZOME_MANIFEST_OVERFLOW:
	    ret = WHYF("Too many fields in manifest at: %s=%s", label, alloca_toprint(-1, field->value, field->valuelen));
	    goto finish;
	}
	if (!status_ok)
	  FATALF("status = %d", status);
      }
    }
  }

  if (bsktext) {
    if (m->has_id) {
      if (!rhizome_apply_bundle_secret(m, &bsk)) {
	ret = WHY("Supplied bundle secret does not match Bundle Id");
	goto finish;
      }
    } else {
      if (rhizome_new_bundle_from_secret(m, &bsk) == -1) {
	ret = WHY("Failed to create bundle from given secret");
	goto finish;
      }
    }
  }
  if (m->service == NULL)
    rhizome_manifest_set_service(m, RHIZOME_SERVICE_FILE);
  if (rhizome_fill_manifest(m, filepath, *authorSidHex ? &authorSid : NULL))
    goto finish;

  enum rhizome_payload_status pstatus;
  if (journal){
    pstatus = rhizome_append_journal_file(m, 0, filepath);
    if (config.debug.rhizome)
      DEBUGF("rhizome_append_journal_file() returned %d %s", pstatus, rhizome_payload_status_message(pstatus));
  } else {
    pstatus = rhizome_stat_payload_file(m, filepath);
    if (config.debug.rhizome)
      DEBUGF("rhizome_stat_payload_file() returned %d %s", pstatus, rhizome_payload_status_message(pstatus));
    assert(m->filesize != RHIZOME_SIZE_UNSET);
    if (pstatus == RHIZOME_PAYLOAD_STATUS_NEW) {
      assert(m->filesize > 0);
      pstatus = rhizome_store_payload_file(m, filepath);
      if (config.debug.rhizome)
	DEBUGF("rhizome_store_payload_file() returned %d %s", pstatus, rhizome_payload_status_message(pstatus));
    }
  }
  enum rhizome_bundle_status status = RHIZOME_BUNDLE_STATUS_ERROR;
  int pstatus_valid = 0;
  switch (pstatus) {
    case RHIZOME_PAYLOAD_STATUS_EMPTY:
    case RHIZOME_PAYLOAD_STATUS_STORED:
    case RHIZOME_PAYLOAD_STATUS_NEW:
      pstatus_valid = 1;
      status = RHIZOME_BUNDLE_STATUS_NEW;
      break;
    case RHIZOME_PAYLOAD_STATUS_TOO_BIG:
    case RHIZOME_PAYLOAD_STATUS_EVICTED:
      pstatus_valid = 1;
      status = RHIZOME_BUNDLE_STATUS_NO_ROOM;
      INFO("Insufficient space to store payload");
      break;
    case RHIZOME_PAYLOAD_STATUS_ERROR:
      pstatus_valid = 1;
      status = RHIZOME_BUNDLE_STATUS_ERROR;
      break;
    case RHIZOME_PAYLOAD_STATUS_WRONG_SIZE:
    case RHIZOME_PAYLOAD_STATUS_WRONG_HASH:
      pstatus_valid = 1;
      status = RHIZOME_BUNDLE_STATUS_INCONSISTENT;
      break;
    case RHIZOME_PAYLOAD_STATUS_CRYPTO_FAIL:
      pstatus_valid = 1;
      status = RHIZOME_BUNDLE_STATUS_READONLY;
      break;
  }
  if (!pstatus_valid)
    FATALF("pstatus = %d", pstatus);
  rhizome_manifest *mout = NULL;
  if (status == RHIZOME_BUNDLE_STATUS_NEW) {
    if (!rhizome_manifest_validate(m) || m->malformed)
      status = RHIZOME_BUNDLE_STATUS_INVALID;
    else {
      status = rhizome_manifest_finalise(m, &mout, !force_new);
      if (mout && mout != m && !rhizome_manifest_validate(mout)) {
	WHYF("Stored manifest id=%s is invalid -- overwriting", alloca_tohex_rhizome_bid_t(mout->cryptoSignPublic));
	status = RHIZOME_BUNDLE_STATUS_NEW;
      }
    }
  }
  int status_valid = 0;
  switch (status) {
    case RHIZOME_BUNDLE_STATUS_NEW:
      if (mout && mout != m)
	rhizome_manifest_free(mout);
      mout = m;
      // fall through
    case RHIZOME_BUNDLE_STATUS_SAME:
    case RHIZOME_BUNDLE_STATUS_DUPLICATE:
    case RHIZOME_BUNDLE_STATUS_OLD:
      assert(mout != NULL);
      cli_put_manifest(context, mout);
      if (   manifestpath && *manifestpath
	  && rhizome_write_manifest_file(mout, manifestpath, 0) == -1
      )
	WHYF("Could not write manifest to %s", alloca_str_toprint(manifestpath));
      status_valid = 1;
      break;
    case RHIZOME_BUNDLE_STATUS_READONLY:
    case RHIZOME_BUNDLE_STATUS_INCONSISTENT:
    case RHIZOME_BUNDLE_STATUS_ERROR:
    case RHIZOME_BUNDLE_STATUS_INVALID:
    case RHIZOME_BUNDLE_STATUS_FAKE:
    case RHIZOME_BUNDLE_STATUS_NO_ROOM:
    case RHIZOME_BUNDLE_STATUS_BUSY:
      status_valid = 1;
      break;
    // Do not use a default: label!  With no default, if a new value is added to the enum, then the
    // compiler will issue a warning on switch statements that do not cover all the values, which is
    // a valuable tool for the developer.
  }
  if (!status_valid)
    FATALF("status=%d", status);
  if (mout && mout != m)
    rhizome_manifest_free(mout);
  ret = status;
finish:
  rhizome_manifest_free(m);
  keyring_free(keyring);
  keyring = NULL;
  return ret;
}

DEFINE_CMD(app_rhizome_import_bundle, 0,
  "Import a payload/manifest pair into Rhizome",
  "rhizome","import","bundle","<filepath>","<manifestpath>");
static int app_rhizome_import_bundle(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  const char *filepath, *manifestpath;
  cli_arg(parsed, "filepath", &filepath, NULL, "");
  cli_arg(parsed, "manifestpath", &manifestpath, NULL, "");
  if (rhizome_opendb() == -1)
    return -1;
  rhizome_manifest *m = rhizome_new_manifest();
  if (!m)
    return WHY("Out of manifests.");
  rhizome_manifest *m_out = NULL;
  enum rhizome_bundle_status status = rhizome_bundle_import_files(m, &m_out, manifestpath, filepath);
  switch (status) {
    case RHIZOME_BUNDLE_STATUS_NEW:
    case RHIZOME_BUNDLE_STATUS_SAME:
    case RHIZOME_BUNDLE_STATUS_DUPLICATE:
    case RHIZOME_BUNDLE_STATUS_OLD:
      cli_put_manifest(context, m_out);
      break;
    case RHIZOME_BUNDLE_STATUS_ERROR:
    case RHIZOME_BUNDLE_STATUS_INVALID:
    case RHIZOME_BUNDLE_STATUS_INCONSISTENT:
      break;
    default:
      FATALF("rhizome_bundle_import_files() returned %d", status);
  }
  if (m_out && m_out != m)
    rhizome_manifest_free(m_out);
  rhizome_manifest_free(m);
  return status;
}

DEFINE_CMD(app_rhizome_append_manifest, 0,
  "Append a manifest to the end of the file it belongs to.",
  "rhizome", "append", "manifest", "<filepath>", "<manifestpath>");
static int app_rhizome_append_manifest(const struct cli_parsed *parsed, struct cli_context *UNUSED(context))
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  const char *manifestpath, *filepath;
  if ( cli_arg(parsed, "manifestpath", &manifestpath, NULL, "") == -1
    || cli_arg(parsed, "filepath", &filepath, NULL, "") == -1)
    return -1;
  rhizome_manifest *m = rhizome_new_manifest();
  if (!m)
    return WHY("Out of manifests.");
  int ret = -1;
  if (   rhizome_read_manifest_from_file(m, manifestpath) != -1
      && rhizome_manifest_validate(m)
      && rhizome_manifest_verify(m)
  ) {
    if (rhizome_write_manifest_file(m, filepath, 1) != -1)
      ret = 0;
  }
  rhizome_manifest_free(m);
  return ret;
}

DEFINE_CMD(app_rhizome_delete, 0,
  "Remove the manifest, or payload, or both for the given Bundle ID from the Rhizome store",
  "rhizome","delete","manifest|payload|bundle","<manifestid>");
DEFINE_CMD(app_rhizome_delete, 0,
  "Remove the file with the given hash from the Rhizome store",
  "rhizome","delete","|file","<fileid>");
static int app_rhizome_delete(const struct cli_parsed *parsed, struct cli_context *UNUSED(context))
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  const char *manifestid, *fileid;
  if (cli_arg(parsed, "manifestid", &manifestid, cli_manifestid, NULL) == -1)
    return -1;
  if (cli_arg(parsed, "fileid", &fileid, cli_fileid, NULL) == -1)
    return -1;
  /* Ensure the Rhizome database exists and is open */
  if (create_serval_instance_dir() == -1)
    return -1;
  if (rhizome_opendb() == -1)
    return -1;
  if (!(keyring = keyring_open_instance_cli(parsed)))
    return -1;
  int ret=0;
  if (cli_arg(parsed, "file", NULL, NULL, NULL) == 0) {
    if (!fileid){
      keyring_free(keyring);
      keyring = NULL;
      return WHY("missing <fileid> argument");
    }
    rhizome_filehash_t hash;
    if (str_to_rhizome_filehash_t(&hash, fileid) == -1){
      keyring_free(keyring);
      keyring = NULL;
      return WHYF("invalid <fileid> argument: %s", alloca_str_toprint(fileid));
    }
    ret = rhizome_delete_file(&hash);
  } else {
    if (!manifestid){
      keyring_free(keyring);
      keyring = NULL;
      return WHY("missing <manifestid> argument");
    }
    rhizome_bid_t bid;
    if (str_to_rhizome_bid_t(&bid, manifestid) == -1){
      keyring_free(keyring);
      keyring = NULL;
      return WHY("Invalid manifest ID");
    }
    if (cli_arg(parsed, "bundle", NULL, NULL, NULL) == 0)
      ret = rhizome_delete_bundle(&bid);
    else if (cli_arg(parsed, "manifest", NULL, NULL, NULL) == 0)
      ret = rhizome_delete_manifest(&bid);
    else if (cli_arg(parsed, "payload", NULL, NULL, NULL) == 0)
      ret = rhizome_delete_payload(&bid);
    else{
      keyring_free(keyring);
      keyring = NULL;
      return WHY("unrecognised command");
    }
  }
  keyring_free(keyring);
  keyring = NULL;
  return ret;
}

DEFINE_CMD(app_rhizome_clean, 0,
  "Remove stale and orphaned content from the Rhizome store",
  "rhizome","clean","[verify]");
static int app_rhizome_clean(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  int verify = cli_arg(parsed, "verify", NULL, NULL, NULL) == 0;
  
  /* Ensure the Rhizome database exists and is open */
  if (create_serval_instance_dir() == -1)
    return -1;
  if (rhizome_opendb() == -1)
    return -1;
  
  if (verify)
    verify_bundles();
  struct rhizome_cleanup_report report;
  if (rhizome_cleanup(&report) == -1)
    return -1;
  cli_field_name(context, "deleted_stale_incoming_files", ":");
  cli_put_long(context, report.deleted_stale_incoming_files, "\n");
  cli_field_name(context, "deleted_orphan_files", ":");
  cli_put_long(context, report.deleted_orphan_files, "\n");
  cli_field_name(context, "deleted_orphan_fileblobs", ":");
  cli_put_long(context, report.deleted_orphan_fileblobs, "\n");
  cli_field_name(context, "deleted_orphan_manifests", ":");
  cli_put_long(context, report.deleted_orphan_manifests, "\n");
  return 0;
}

DEFINE_CMD(app_rhizome_extract, 0,
  "Export a manifest and payload file to the given paths, without decrypting.",
  "rhizome","export","bundle" KEYRING_PIN_OPTIONS,
  "<manifestid>","[<manifestpath>]","[<filepath>]");
DEFINE_CMD(app_rhizome_extract, 0,
  "Export a manifest from Rhizome and write it to the given path",
  "rhizome","export","manifest" KEYRING_PIN_OPTIONS,
  "<manifestid>","[<manifestpath>]");
DEFINE_CMD(app_rhizome_extract, 0,
  "Extract and decrypt a manifest and file to the given paths.",
  "rhizome","extract","bundle" KEYRING_PIN_OPTIONS,
  "<manifestid>","[<manifestpath>]","[<filepath>]","[<bsk>]");
DEFINE_CMD(app_rhizome_extract, 0,
  "Extract and decrypt a file from Rhizome and write it to the given path",
  "rhizome","extract","file" KEYRING_PIN_OPTIONS,
  "<manifestid>","[<filepath>]","[<bsk>]");
static int app_rhizome_extract(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  const char *manifestpath, *filepath, *manifestid, *bsktext;
  if (   cli_arg(parsed, "manifestid", &manifestid, cli_manifestid, "") == -1
      || cli_arg(parsed, "manifestpath", &manifestpath, NULL, "") == -1
      || cli_arg(parsed, "filepath", &filepath, NULL, "") == -1
      || cli_arg(parsed, "bsk", &bsktext, cli_optional_bundle_secret_key, NULL) == -1)
    return -1;
  
  int extract = strcasecmp(parsed->args[1], "extract")==0;
  
  /* Ensure the Rhizome database exists and is open */
  if (create_serval_instance_dir() == -1)
    return -1;
  if (rhizome_opendb() == -1)
    return -1;
  
  if (!(keyring = keyring_open_instance_cli(parsed)))
    return -1;
  
  rhizome_manifest *m = NULL;
  int ret=0;
  
  rhizome_bid_t bid;
  if (str_to_rhizome_bid_t(&bid, manifestid) == -1) {
    ret = WHY("Invalid manifest ID");
    goto finish;
  }
  
  // treat empty string the same as null
  if (bsktext && !*bsktext)
    bsktext = NULL;
  
  rhizome_bk_t bsk;
  if (bsktext && str_to_rhizome_bsk_t(&bsk, bsktext) == -1) {
    ret = WHYF("invalid bsk: \"%s\"", bsktext);
    goto finish;
  }

  if ((m = rhizome_new_manifest()) == NULL) {
    ret = WHY("Out of manifests");
    goto finish;
  }
  
  switch(rhizome_retrieve_manifest(&bid, m)){
    case RHIZOME_BUNDLE_STATUS_NEW: ret=1; break;
    case RHIZOME_BUNDLE_STATUS_SAME: ret=0; break;
    default: ret=-1; break;
  }
  
  if (ret==0){
    assert(m->finalised);
    if (bsktext)
      rhizome_apply_bundle_secret(m, &bsk);
    rhizome_authenticate_author(m);
    assert(m->authorship != AUTHOR_LOCAL);
    cli_put_manifest(context, m);
  }
  
  enum rhizome_payload_status pstatus = RHIZOME_PAYLOAD_STATUS_EMPTY;
  if (ret==0 && m->filesize != 0 && filepath && *filepath){
    if (extract){
      // Save the file, implicitly decrypting if required.
      pstatus = rhizome_extract_file(m, filepath);
      if (pstatus != RHIZOME_PAYLOAD_STATUS_EMPTY && pstatus != RHIZOME_PAYLOAD_STATUS_STORED)
	WHYF("rhizome_extract_file() returned %d", pstatus);
    }else{
      // Save the file without attempting to decrypt
      uint64_t length;
      pstatus = rhizome_dump_file(&m->filehash, filepath, &length);
      if (pstatus != RHIZOME_PAYLOAD_STATUS_EMPTY && pstatus != RHIZOME_PAYLOAD_STATUS_STORED)
	WHYF("rhizome_dump_file() returned %d", pstatus);
    }
  }
  
  if (ret==0 && manifestpath && *manifestpath){
    if (strcmp(manifestpath, "-") == 0) {
      // always extract a manifest to stdout, even if writing the file itself failed.
      cli_field_name(context, "manifest", ":");
      cli_write(context, m->manifestdata, m->manifest_all_bytes);
      cli_delim(context, "\n");
    } else {
      int append = (strcmp(manifestpath, filepath)==0)?1:0;
      // don't write out the manifest if we were asked to append it and writing the file failed.
      if (!append || (pstatus == RHIZOME_PAYLOAD_STATUS_EMPTY || pstatus == RHIZOME_PAYLOAD_STATUS_STORED)) {
	if (rhizome_write_manifest_file(m, manifestpath, append) == -1)
	  ret = -1;
      }
    }
  }
  switch (pstatus) {
    case RHIZOME_PAYLOAD_STATUS_EMPTY:
    case RHIZOME_PAYLOAD_STATUS_STORED:
      break;
    case RHIZOME_PAYLOAD_STATUS_NEW:
      ret = 1; // payload not found
      break;
    case RHIZOME_PAYLOAD_STATUS_ERROR:
    case RHIZOME_PAYLOAD_STATUS_WRONG_SIZE:
    case RHIZOME_PAYLOAD_STATUS_WRONG_HASH:
    case RHIZOME_PAYLOAD_STATUS_CRYPTO_FAIL:
      ret = -1;
      break;
    default:
      FATALF("pstatus = %d", pstatus);
  }
finish:
  rhizome_manifest_free(m);
  keyring_free(keyring);
  keyring = NULL;
  return ret;
}

DEFINE_CMD(app_rhizome_export_file, 0,
  "Export a file from Rhizome and write it to the given path without attempting decryption",
  "rhizome","export","file","<fileid>","[<filepath>]");
static int app_rhizome_export_file(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  const char *fileid, *filepath;
  if (   cli_arg(parsed, "filepath", &filepath, NULL, "") == -1
      || cli_arg(parsed, "fileid", &fileid, cli_fileid, NULL) == -1)
    return -1;
  rhizome_filehash_t hash;
  if (str_to_rhizome_filehash_t(&hash, fileid) == -1)
    return WHYF("invalid <fileid> argument: %s", alloca_str_toprint(fileid));
  if (create_serval_instance_dir() == -1)
    return -1;
  if (rhizome_opendb() == -1)
    return -1;
  if (!rhizome_exists(&hash))
    return 1;
  uint64_t length;
  enum rhizome_payload_status pstatus = rhizome_dump_file(&hash, filepath, &length);
  switch (pstatus) {
    case RHIZOME_PAYLOAD_STATUS_EMPTY:
    case RHIZOME_PAYLOAD_STATUS_STORED:
      break;
    case RHIZOME_PAYLOAD_STATUS_NEW:
      return 1; // payload not found
    case RHIZOME_PAYLOAD_STATUS_ERROR:
    case RHIZOME_PAYLOAD_STATUS_WRONG_SIZE:
    case RHIZOME_PAYLOAD_STATUS_WRONG_HASH:
    case RHIZOME_PAYLOAD_STATUS_CRYPTO_FAIL:
      return -1;
    default:
      FATALF("pstatus = %d", pstatus);
  }
  cli_field_name(context, "filehash", ":");
  cli_put_string(context, alloca_tohex_rhizome_filehash_t(hash), "\n");
  cli_field_name(context, "filesize", ":");
  cli_put_long(context, length, "\n");
  return 0;
}

DEFINE_CMD(app_rhizome_list, 0,
  "List all manifests and files in Rhizome",
  "rhizome","list" KEYRING_PIN_OPTIONS,
	"[<service>]","[<name>]","[<sender_sid>]","[<recipient_sid>]","[<offset>]","[<limit>]");
static int app_rhizome_list(const struct cli_parsed *parsed, struct cli_context *context)
{
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  const char *service = NULL, *name = NULL, *sender_hex = NULL, *recipient_hex = NULL, *offset_ascii = NULL, *limit_ascii = NULL;
  cli_arg(parsed, "service", &service, NULL, "");
  cli_arg(parsed, "name", &name, NULL, "");
  cli_arg(parsed, "sender_sid", &sender_hex, cli_optional_sid, "");
  cli_arg(parsed, "recipient_sid", &recipient_hex, cli_optional_sid, "");
  cli_arg(parsed, "offset", &offset_ascii, cli_uint, "0");
  cli_arg(parsed, "limit", &limit_ascii, cli_uint, "0");
  /* Create the instance directory if it does not yet exist */
  if (create_serval_instance_dir() == -1)
    return -1;
  if (!(keyring = keyring_open_instance_cli(parsed)))
    return -1;
  if (rhizome_opendb() == -1) {
    keyring_free(keyring);
    keyring = NULL;
    return -1;
  }
  size_t rowlimit = atoi(limit_ascii);
  size_t rowoffset = atoi(offset_ascii);
  struct rhizome_list_cursor cursor;
  bzero(&cursor, sizeof cursor);
  cursor.service = service && service[0] ? service : NULL;
  cursor.name = name && name[0] ? name : NULL;
  if (sender_hex && sender_hex[0]) {
    if (str_to_sid_t(&cursor.sender, sender_hex) == -1)
      return WHYF("Invalid <sender>: %s", sender_hex);
    cursor.is_sender_set = 1;
  }
  if (recipient_hex && recipient_hex[0]) {
    if (str_to_sid_t(&cursor.recipient, recipient_hex) == -1)
      return WHYF("Invalid <recipient: %s", recipient_hex);
    cursor.is_recipient_set = 1;
  }
  if (rhizome_list_open(&cursor) == -1) {
    keyring_free(keyring);
    keyring = NULL;
    return -1;
  }
  const char *headers[]={
    "_id",
    "service",
    "id",
    "version",
    "date",
    ".inserttime",
    ".author",
    ".fromhere",
    "filesize",
    "filehash",
    "sender",
    "recipient",
    "name"
  };
  cli_columns(context, NELS(headers), headers);
  size_t rowcount = 0;
  int n;
  while ((n = rhizome_list_next(&cursor)) == 1) {
    ++rowcount;
    if (rowcount <= rowoffset)
      continue;
    if (rowlimit == 0 || rowcount <= rowoffset + rowlimit) {
      rhizome_manifest *m = cursor.manifest;
      assert(m->filesize != RHIZOME_SIZE_UNSET);
      rhizome_lookup_author(m);
      cli_put_long(context, m->rowid, ":");
      cli_put_string(context, m->service, ":");
      cli_put_hexvalue(context, m->cryptoSignPublic.binary, sizeof m->cryptoSignPublic.binary, ":");
      cli_put_long(context, m->version, ":");
      cli_put_long(context, m->has_date ? m->date : 0, ":");
      cli_put_long(context, m->inserttime, ":");
      switch (m->authorship) {
	case AUTHOR_LOCAL:
	case AUTHOR_AUTHENTIC:
	  cli_put_hexvalue(context, m->author.binary, sizeof m->author.binary, ":");
	  cli_put_long(context, 1, ":");
	  break;
	default:
	  cli_put_string(context, NULL, ":");
	  cli_put_long(context, 0, ":");
	  break;
      }
      cli_put_long(context, m->filesize, ":");
      cli_put_hexvalue(context, m->filesize ? m->filehash.binary : NULL, sizeof m->filehash.binary, ":");
      cli_put_hexvalue(context, m->has_sender ? m->sender.binary : NULL, sizeof m->sender.binary, ":");
      cli_put_hexvalue(context, m->has_recipient ? m->recipient.binary : NULL, sizeof m->recipient.binary, ":");
      cli_put_string(context, m->name, "\n");
    }
  }
  rhizome_list_release(&cursor);
  keyring_free(keyring);
  keyring = NULL;
  if (n == -1)
    return -1;
  cli_row_count(context, rowcount);
  return 0;
}

