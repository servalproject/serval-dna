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

struct cf_om_node *cf_om_root = NULL;
static struct file_meta conffile_meta = { .mtime = -1, .size = -1 };

int cf_limbo = 1;
struct config_main config;
static struct file_meta config_meta = { .mtime = -1, .size = -1 };

static const char *conffile_path()
{
  static char path[1024] = "";
  if (!path[0] && !FORM_SERVAL_INSTANCE_PATH(path, CONFFILE_NAME))
    abort();
  return path;
}

static int get_meta(const char *path, struct file_meta *metap)
{
  struct stat st;
  if (stat(path, &st) == -1) {
    if (errno != ENOENT)
      return WHYF_perror("stat(%s)", path);
    metap->size = 0;
    metap->mtime = -1;
  } else {
    metap->size = st.st_size;
    metap->mtime = st.st_mtime;
  }
  return 0;
}

static int load()
{
  const char *path = conffile_path();
  struct file_meta meta;
  if (get_meta(path, &meta) == -1)
      return CFERROR;
  char *buf = NULL;
  if (meta.mtime == -1)
    INFOF("config file %s does not exist", path);
  else if (meta.size > CONFIG_FILE_MAX_SIZE) {
    WHYF("config file %s is too big (%ld bytes exceeds limit %ld)", path, meta.size, CONFIG_FILE_MAX_SIZE);
    return CFERROR;
  } else {
    FILE *f = fopen(path, "r");
    if (f == NULL) {
      WHYF_perror("fopen(%s)", path);
      return CFERROR;
    }
    if ((buf = emalloc(meta.size)) == NULL) {
      fclose(f);
      return CFERROR;
    }
    if (fread(buf, meta.size, 1, f) != 1) {
      if (ferror(f))
	WHYF_perror("fread(%s, %llu)", path, (unsigned long long) meta.size);
      else
	WHYF("fread(%s, %llu) hit EOF", path, (unsigned long long) meta.size);
      free(buf);
      fclose(f);
      return CFERROR;
    }
    if (fclose(f) == EOF) {
      free(buf);
      return WHYF_perror("fclose(%s)", path);
    }
    INFOF("config file %s successfully read", path);
  }
  struct cf_om_node *new_root = NULL;
  int result = cf_om_parse(path, buf, meta.size, &new_root);
  free(buf);
  if (result != CFERROR) {
    cf_om_free_node(&cf_om_root);
    cf_om_root = new_root;
    conffile_meta = meta;
  }
  return result;
}

static int has_changed(const struct file_meta *metap)
{
  const char *path = conffile_path();
  struct file_meta meta;
  if (get_meta(path, &meta) == -1)
      return -1;
  return metap->size != meta.size || metap->mtime != meta.mtime;
}

int cf_om_load()
{
  return load() == CFERROR ? -1 : 0;
}

/* Check if the config file has changed since we last read it, and if so, invalidate the buffer so
 * that the next call to read_config() will re-load it.  Returns 1 if the buffer was invalidated, 0
 * if not, -1 on error.
 *
 * TODO: when the config system is overhauled to provide proper dynamic config reloading in JNI and
 * in the servald daemon, this method will become unnecessary.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int cf_om_reload()
{
  if (!has_changed(&conffile_meta))
    return CFOK;
  if (conffile_meta.mtime != -1)
    INFOF("config file %s -- detected new version", conffile_path());
  return cf_om_load();
}

int cf_om_save()
{
  if (cf_om_root) {
    const char *path = conffile_path();
    char tempfile[1024];
    FILE *outf = NULL;
    if (!FORM_SERVAL_INSTANCE_PATH(tempfile, "serval.conf.temp"))
      return -1;
    if ((outf = fopen(tempfile, "w")) == NULL)
      return WHYF_perror("fopen(%s, \"w\")", tempfile);
    struct cf_om_iterator it;
    for (cf_om_iter_start(&it, cf_om_root); it.node; cf_om_iter_next(&it))
      if (it.node->text)
	fprintf(outf, "%s=%s\n", it.node->fullkey, it.node->text);
    if (fclose(outf) == EOF)
      return WHYF_perror("fclose(%s)", tempfile);
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
  if (cf_dfl_config_main(&config) == CFERROR)
    return -1;
  debug = config.debug;
  return 0;
}

static int load_and_parse(int permissive)
{
  int result = CFOK;
  if (cf_limbo)
    result = cf_dfl_config_main(&config);
  if (result == CFOK) {
    result = load();
    if (result == CFOK || result == CFEMPTY) {
      result = CFOK;
      struct config_main new_config;
      memset(&new_config, 0, sizeof new_config);
      result = cf_dfl_config_main(&new_config);
      if (result == CFOK) {
	result = cf_om_root ? cf_opt_config_main(&new_config, cf_om_root) : CFEMPTY;
	if (result == CFOK || result == CFEMPTY) {
	  result = CFOK;
	  config = new_config;
	  config_meta = conffile_meta;
	  cf_limbo = 0;
	} else if (result != CFERROR) {
	  result &= ~CFEMPTY;
	  config = new_config;
	  cf_limbo = 0;
	  WARN("limping along with incomplete configuration");
	}
      }
    }
  }
  debug = config.debug;
  if (result == CFOK)
    return 0;
  cf_limbo = 0; // let log messages out
  strbuf b = strbuf_alloca(180);
  strbuf_cf_flag_reason(b, result);
  if (!permissive)
    return WHYF("config file %s not loaded -- %s", conffile_path(), strbuf_str(b));
  WARNF("config file %s loaded despite problems -- %s", conffile_path(), strbuf_str(b));
  return 0;
}

static int reload_and_parse(int permissive)
{
  if (!cf_limbo && cf_om_root) {
    if (!has_changed(&config_meta))
      return 0;
    INFOF("config file %s reloading", conffile_path());
  }
  return load_and_parse(permissive);
}

int cf_load()
{
  return load_and_parse(0);
}

int cf_load_permissive()
{
  return load_and_parse(1);
}

int cf_reload()
{
  return reload_and_parse(0);
}

int cf_reload_permissive()
{
  return reload_and_parse(1);
}
