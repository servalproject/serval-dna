/*
Serval DNA configuration
Copyright (C) 2012 Serval Project Inc.

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

#include <stdio.h>
#include <sys/stat.h>
#include <ctype.h>
#include "conf.h"
#include "log.h"
#include "str.h"
#include "mem.h"

#define CONFFILE_NAME		  "serval.conf"

struct file_meta {
  time_t mtime;
  off_t size;
};

#define FILE_META_UNKNOWN ((struct file_meta){ .mtime = -1, .size = -1 })

struct cf_om_node *cf_om_root = NULL;
static struct file_meta conffile_meta = FILE_META_UNKNOWN;

int cf_limbo = 1;
struct config_main config;
static struct file_meta config_meta = FILE_META_UNKNOWN;

static const char *conffile_path()
{
  static char path[1024] = "";
  if (!path[0] && !FORMF_SERVAL_ETC_PATH(path, CONFFILE_NAME))
    abort();
  return path;
}

static int get_meta(const char *path, struct file_meta *metap)
{
  struct stat st;
  if (stat(path, &st) == -1) {
    if (errno != ENOENT)
      return WHYF_perror("stat(%s)", path);
    // Do not return FILE_META_UNKNOWN on ENOENT, otherwise reload logic breaks.  A non-existent
    // file is treated as size == 0.
    metap->size = 0;
    metap->mtime = -1;
  } else {
    metap->size = st.st_size;
    metap->mtime = st.st_mtime;
  }
  return 0;
}

static int cmp_meta(const struct file_meta *a, const struct file_meta *b)
{
  return a->mtime < b->mtime ? -1 : a->mtime > b->mtime ? 1 : a->size < b->size ? -1 : a->size > b->size ? 1 : 0;
}

static int reload(const char *path, int *resultp)
{
  struct file_meta meta;
  if (get_meta(conffile_path(), &meta) == -1)
    return -1;
  if (cmp_meta(&meta, &conffile_meta) == 0)
    return 0;
  if (conffile_meta.mtime != -1 && serverMode)
    INFOF("config file %s -- detected new version", conffile_path());
  char *buf = NULL;
  if (meta.mtime == -1) {
    WARNF("config file %s does not exist -- using all defaults", path);
  } else if (meta.size > CONFIG_FILE_MAX_SIZE) {
    WHYF("config file %s is too big (%ju bytes exceeds limit %d)", path, (uintmax_t)meta.size, CONFIG_FILE_MAX_SIZE);
    return -1;
  } else if (meta.size <= 0) {
    WARNF("config file %s is zero size -- using all defaults", path);
  } else {
    FILE *f = fopen(path, "r");
    if (f == NULL) {
      WHYF_perror("fopen(%s)", path);
      return -1;
    }
    if ((buf = emalloc(meta.size)) == NULL) {
      fclose(f);
      return -1;
    }
    if (fread(buf, meta.size, 1, f) != 1) {
      if (ferror(f))
	WHYF_perror("fread(%s, %"PRIu64")", path, (uint64_t) meta.size);
      else
	WHYF("fread(%s, %"PRIu64") hit EOF", path, (uint64_t) meta.size);
      free(buf);
      fclose(f);
      return -1;
    }
    if (fclose(f) == EOF) {
      WHYF_perror("fclose(%s)", path);
      free(buf);
      return -1;
    }
    if (serverMode)
      INFOF("config file %s successfully read %ld bytes", path, (long) meta.size);
  }
  conffile_meta = meta;
  struct cf_om_node *new_root = NULL;
  *resultp = cf_om_parse(path, buf, meta.size, &new_root);
  free(buf);
  if (*resultp == CFERROR)
    return -1;
  cf_om_free_node(&cf_om_root);
  cf_om_root = new_root;
  return 1;
}

int cf_om_reload()
{
  int result;
  return reload(conffile_path(), &result);
}

int cf_om_load()
{
  conffile_meta = FILE_META_UNKNOWN;
  return cf_om_reload();
}

int cf_om_save()
{
  if (cf_om_root) {
    const char *path = conffile_path();
    char tempfile[1024];
    FILE *outf = NULL;
    if (!FORMF_SERVAL_ETC_PATH(tempfile, CONFFILE_NAME ".temp"))
      return -1;
    if ((outf = fopen(tempfile, "w")) == NULL)
      return WHYF_perror("fopen(%s, \"w\")", tempfile);
    struct cf_om_iterator it;
    for (cf_om_iter_start(&it, cf_om_root); it.node; cf_om_iter_next(&it))
      if (it.node->text)
	fprintf(outf, "%s=%s\n", it.node->fullkey, it.node->text);
    if (fclose(outf) == EOF)
      return WHYF_perror("fclose(%s)", tempfile);
    // rename(2) is atomic, so no other process will read a half-written file.
    if (rename(tempfile, path)) {
      WHYF_perror("rename(%s, %s)", tempfile, path);
      unlink(tempfile);
      return -1;
    }
    struct file_meta meta;
    if (get_meta(path, &meta) == -1)
      return -1;
    INFOF("successfully wrote %s", path);
    conffile_meta = meta;
  }
  return 0;
}

int cf_init()
{
  cf_limbo = 1;
  conffile_meta = config_meta = FILE_META_UNKNOWN;
  memset(&config, 0, sizeof config);
  if (cf_dfl_config_main(&config) == CFERROR)
    return -1;
  return 0;
}

static int reload_and_parse(int permissive, int strict)
{
  int result = CFOK;
  if (cf_limbo)
    result = cf_dfl_config_main(&config);
  if (result == CFOK || result == CFEMPTY) {
    if (reload(conffile_path(), &result) == -1)
      result = CFERROR;
    else if (!cf_limbo && cmp_meta(&conffile_meta, &config_meta) == 0)
      return 0;
    else {
      config_meta = conffile_meta;
      if (result == CFOK || result == CFEMPTY) {
	struct config_main new_config;
	memset(&new_config, 0, sizeof new_config);
	result = cf_dfl_config_main(&new_config);
	if (result == CFOK || result == CFEMPTY) {
	  result = cf_om_root ? cf_opt_config_main(&new_config, cf_om_root) : CFEMPTY;
	  if (result == CFOK || result == CFEMPTY) {
	    result = CFOK;
	    config = new_config;
	  } else if (result != CFERROR && !strict) {
	    result &= ~CFEMPTY; // don't log "empty" as a problem
	    config = new_config;
	  }
	}
      }
    }
  }
  int ret = 1;
  if (result == CFOK) {
    logConfigChanged();
  } else {
    strbuf b = strbuf_alloca(180);
    strbuf_cf_flag_reason(b, result);
    if (strict)
      ret = WHYF("defective config file %s not loaded -- %s", conffile_path(), strbuf_str(b));
    else {
      if (!permissive)
	ret = WHYF("config file %s loaded despite defects -- %s", conffile_path(), strbuf_str(b));
      else
	WARNF("config file %s loaded despite defects -- %s", conffile_path(), strbuf_str(b));
      logConfigChanged();
    }
  }
  cf_limbo = 0; // let log messages out
  logFlush();
  return ret;
}

int cf_load()
{
  conffile_meta = config_meta = FILE_META_UNKNOWN;
  return reload_and_parse(0, 0);
}

int cf_load_strict()
{
  conffile_meta = config_meta = FILE_META_UNKNOWN;
  return reload_and_parse(0, 1);
}

int cf_load_permissive()
{
  conffile_meta = config_meta = FILE_META_UNKNOWN;
  return reload_and_parse(1, 0);
}

int cf_reload()
{
  return reload_and_parse(0, 0);
}

int cf_reload_strict()
{
  return reload_and_parse(0, 1);
}

int cf_reload_permissive()
{
  return reload_and_parse(1, 0);
}
