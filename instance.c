/*
Serval DNA instance directory path
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

#include <stdlib.h>
#include "instance.h"
#include "str.h"
#include "os.h"
#include "strbuf.h"
#include "strbuf_helpers.h"

/*
 * A default INSTANCE_PATH can be set on the ./configure command line, eg:
 *
 *      ./configure INSTANCE_PATH=/var/local/serval/node
 *
 * This will cause servald to never use FHS paths, and always use an instance path, even if the
 * SERVALINSTANCE_PATH environment variable is not set.
 *
 * On Android systems, the INSTANCE_PATH macro is set in Android.mk, so Android builds of servald
 * always use an instance path and never fall back to FHS paths.
 */
#ifdef ANDROID
# ifndef INSTANCE_PATH
#  error Must set INSTANCE_PATH macro on Android systems
# endif
# define SERVAL_ETC_PATH ""
# define SERVAL_RUN_PATH ""
# define SYSTEM_LOG_PATH ""
# define SERVAL_LOG_PATH ""
# define SERVAL_CACHE_PATH ""
# define SERVAL_TMP_PATH ""
# define RHIZOME_STORE_PATH ""
#endif

/* The following paths are based on the Filesystem Hierarchy Standard (FHS) 2.3
 * but can be altered using ./configure arguments, eg:
 *
 *	./configure SERVAL_LOG_PATH=/tmp/serval/log
 */

#ifndef SERVAL_ETC_PATH
#define SERVAL_ETC_PATH SYSCONFDIR "/serval"
#endif

#ifndef SERVAL_RUN_PATH
#define SERVAL_RUN_PATH LOCALSTATEDIR "/run/serval"
#endif

#ifndef SYSTEM_LOG_PATH
#define SYSTEM_LOG_PATH LOCALSTATEDIR "/log"
#endif

#ifndef SERVAL_LOG_PATH
#define SERVAL_LOG_PATH SYSTEM_LOG_PATH "/serval"
#endif

#ifndef SERVAL_CACHE_PATH
#define SERVAL_CACHE_PATH LOCALSTATEDIR "/cache/serval"
#endif

#ifndef SERVAL_TMP_PATH
#define SERVAL_TMP_PATH "/tmp/serval"
#endif

#ifndef RHIZOME_STORE_PATH
#define RHIZOME_STORE_PATH SERVAL_CACHE_PATH
#endif

static int know_instancepath = 0;
static char *instancepath = NULL;

const char *instance_path()
{
  if (!know_instancepath) {
    instancepath = getenv("SERVALINSTANCE_PATH");
#ifdef INSTANCE_PATH
    if (instancepath == NULL)
      instancepath = INSTANCE_PATH;
#endif
    know_instancepath = 1;
  }
  return instancepath;
}

static int vformf_path(struct __sourceloc __whence, strbuf b, const char *syspath, const char *fmt, va_list ap)
{
  if (fmt)
    strbuf_va_vprintf(b, fmt, ap);
  if (!strbuf_overrun(b) && (strbuf_len(b) == 0 || strbuf_str(b)[0] != '/')) {
    strbuf_reset(b);
    const char *ipath = instance_path();
#ifdef ANDROID
    assert(ipath != NULL);
#endif
    strbuf_puts(b, ipath ? ipath : syspath);
    if (fmt) {
      if (strbuf_substr(b, -1)[0] != '/')
	strbuf_putc(b, '/');
      strbuf_va_vprintf(b, fmt, ap);
    }
  }
  if (!strbuf_overrun(b))
    return 1;
  WHYF("instance path overflow (strlen %lu, sizeof buffer %lu): %s",
      (unsigned long)strbuf_count(b),
      (unsigned long)strbuf_size(b),
      alloca_str_toprint(strbuf_str(b)));
  return 0;
}

int _formf_serval_etc_path(struct __sourceloc __whence, char *buf, size_t bufsiz, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  int ret = vformf_path(__whence, strbuf_local(buf, bufsiz), SERVAL_ETC_PATH, fmt, ap);
  va_end(ap);
  return ret;
}

int _formf_serval_run_path(struct __sourceloc __whence, char *buf, size_t bufsiz, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  int ret = _vformf_serval_run_path(__whence, buf, bufsiz, fmt, ap);
  va_end(ap);
  return ret;
}

int _vformf_serval_run_path(struct __sourceloc __whence, char *buf, size_t bufsiz, const char *fmt, va_list ap)
{
  return vformf_path(__whence, strbuf_local(buf, bufsiz), SERVAL_RUN_PATH, fmt, ap);
}

strbuf strbuf_system_log_path(strbuf sb)
{
  const char *ipath = instance_path();
  strbuf_puts(sb, ipath ? ipath : SYSTEM_LOG_PATH);
  return sb;
}

strbuf strbuf_serval_log_path(strbuf sb)
{
  const char *ipath = instance_path();
  if (ipath)
    strbuf_path_join(sb, ipath, "log", NULL);
  else
    strbuf_puts(sb, SERVAL_LOG_PATH);
  return sb;
}

int _formf_serval_cache_path(struct __sourceloc __whence, char *buf, size_t bufsiz, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  int ret = vformf_path(__whence, strbuf_local(buf, bufsiz), SERVAL_CACHE_PATH, fmt, ap);
  va_end(ap);
  return ret;
}

int _formf_rhizome_store_path(struct __sourceloc __whence, char *buf, size_t bufsiz, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  int ret = vformf_path(__whence, strbuf_local(buf, bufsiz), RHIZOME_STORE_PATH, fmt, ap);
  va_end(ap);
  return ret;
}

int _formf_serval_tmp_path(struct __sourceloc __whence, char *buf, size_t bufsiz, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  int ret = vformf_path(__whence, strbuf_local(buf, bufsiz), SERVAL_TMP_PATH, fmt, ap);
  va_end(ap);
  return ret;
}

int _formf_servald_proc_path(struct __sourceloc __whence, char *buf, size_t bufsiz, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  int ret = vformf_path(__whence, strbuf_local(buf, bufsiz), SERVAL_RUN_PATH "/proc", fmt, ap);
  va_end(ap);
  return ret;
}

int create_serval_instance_dir()
{
  int ret = 0;
  char path[PATH_MAX];
  if (FORMF_SERVAL_ETC_PATH(path, NULL) && emkdirs_info(path, 0755) == -1)
    ret = -1;
  if (FORMF_SERVAL_RUN_PATH(path, NULL) && emkdirs_info(path, 0700) == -1)
    ret = -1;
  if (FORMF_SERVAL_CACHE_PATH(path, NULL) && emkdirs_info(path, 0700) == -1)
    ret = -1;
  strbuf sb = strbuf_local(path, sizeof path);
  strbuf_system_log_path(sb);
  if (!strbuf_overrun(sb) && emkdirs_info(path, 0700) == -1)
    ret = -1;
  strbuf_reset(sb);
  strbuf_serval_log_path(sb);
  if (!strbuf_overrun(sb) && emkdirs_info(path, 0700) == -1)
    ret = -1;
  if (FORMF_SERVAL_TMP_PATH(path, NULL) && emkdirs_info(path, 0700) == -1)
    ret = -1;
  if (FORMF_SERVALD_PROC_PATH(path, NULL) && emkdirs_info(path, 0755) == -1)
    ret = -1;
  if (FORMF_RHIZOME_STORE_PATH(path, NULL) && emkdirs_info(path, 0700) == -1)
    ret = -1;
  return ret;
}
