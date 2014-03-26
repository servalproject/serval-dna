/* 
Serval DNA header file - system paths
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

#ifndef __SERVAL_DNA__INSTANCE_H
#define __SERVAL_DNA__INSTANCE_H

#include "log.h"
#include "strbuf.h"

const char *instance_path(); // returns NULL if not using an instance path
int create_serval_instance_dir();

int _formf_serval_etc_path(struct __sourceloc, char *buf, size_t bufsiz, const char *fmt, ...) __attribute__((format(printf,4,5)));
int _formf_serval_run_path(struct __sourceloc, char *buf, size_t bufsiz, const char *fmt, ...) __attribute__((format(printf,4,5)));
int _vformf_serval_run_path(struct __sourceloc, char *buf, size_t bufsiz, const char *fmt, va_list);
int _formf_serval_cache_path(struct __sourceloc, char *buf, size_t bufsiz, const char *fmt, ...) __attribute__((format(printf,4,5)));
int _formf_serval_tmp_path(struct __sourceloc, char *buf, size_t bufsiz, const char *fmt, ...) __attribute__((format(printf,4,5)));
int _formf_servald_proc_path(struct __sourceloc, char *buf, size_t bufsiz, const char *fmt, ...) __attribute__((format(printf,4,5)));
int _formf_rhizome_store_path(struct __sourceloc, char *buf, size_t bufsiz, const char *fmt, ...) __attribute__((format(printf,4,5)));

#define formf_serval_etc_path(buf,bufsz,fmt,...)     _formf_serval_etc_path(__WHENCE__, buf, bufsz, fmt, ##__VA_ARGS__)
#define formf_serval_run_path(buf,bufsz,fmt,...)     _formf_serval_run_path(__WHENCE__, buf, bufsz, fmt, ##__VA_ARGS__)
#define vformf_serval_run_path(buf,bufsz,fmt,ap)     _vformf_serval_run_path(__WHENCE__, buf, bufsz, fmt, ap)
#define formf_serval_cache_path(buf,bufsz,fmt,...)   _formf_serval_cache_path(__WHENCE__, buf, bufsz, fmt, ##__VA_ARGS__)
#define formf_serval_tmp_path(buf,bufsz,fmt,...)     _formf_serval_tmp_path(__WHENCE__, buf, bufsz, fmt, ##__VA_ARGS__)
#define formf_servald_proc_path(buf,bufsz,fmt,...)   _formf_servald_proc_path(__WHENCE__, buf, bufsz, fmt, ##__VA_ARGS__)
#define formf_rhizome_store_path(buf,bufsz,fmt,...)  _formf_rhizome_store_path(__WHENCE__, buf, bufsz, fmt, ##__VA_ARGS__)

/* Handy macros for forming the absolute paths of various files, using a char[]
 * buffer whose declaration is in scope (so that sizeof(buf) will work).
 * Evaluates to true if the pathname fits into the provided buffer, false (0)
 * otherwise (after logging an error).
 */
#define FORMF_SERVAL_ETC_PATH(buf,fmt,...)    formf_serval_etc_path(buf, sizeof(buf), fmt, ##__VA_ARGS__)
#define FORMF_SERVAL_RUN_PATH(buf,fmt,...)    formf_serval_run_path(buf, sizeof(buf), fmt, ##__VA_ARGS__)
#define FORMF_SERVAL_CACHE_PATH(buf,fmt,...)  formf_serval_cache_path(buf, sizeof(buf), fmt, ##__VA_ARGS__)
#define FORMF_SERVAL_TMP_PATH(buf,fmt,...)    formf_serval_tmp_path(buf, sizeof(buf), fmt, ##__VA_ARGS__)
#define FORMF_SERVALD_PROC_PATH(buf,fmt,...)  formf_servald_proc_path(buf, sizeof(buf), fmt, ##__VA_ARGS__)
#define FORMF_RHIZOME_STORE_PATH(buf,fmt,...) formf_rhizome_store_path((buf), sizeof(buf), (fmt), ##__VA_ARGS__)

strbuf strbuf_system_log_path(strbuf sb);
strbuf strbuf_serval_log_path(strbuf sb);

#endif // __SERVAL_DNA__INSTANCE_H
