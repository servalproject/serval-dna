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

/*
 * A default INSTANCE_PATH can be set on the ./configure command line, eg:
 *
 *      ./configure INSTANCE_PATH=/var/local/serval/node
 *
 * This will cause servald to never use FHS paths, and always use an instance
 * path, even if the SERVALINSTANCE_PATH environment variable is not set.
 */
#ifdef INSTANCE_PATH
#define DEFAULT_INSTANCE_PATH INSTANCE_PATH
#else
#ifdef ANDROID
#define DEFAULT_INSTANCE_PATH "/data/data/org.servalproject/var/serval-node"
#else
#define DEFAULT_INSTANCE_PATH NULL
#endif
#endif

/* Handy statement for forming a path to an instance file in a char buffer whose declaration
 * is in scope (so that sizeof(buf) will work).  Evaluates to true if the pathname fitted into
 * the provided buffer, false (0) otherwise (after logging an error).
 */
#define FORM_SERVAL_INSTANCE_PATH(buf, path) (formf_serval_instance_path(__WHENCE__, buf, sizeof(buf), "%s", (path)))

const char *serval_instancepath();
int create_serval_instance_dir();
int formf_serval_instance_path(struct __sourceloc, char *buf, size_t bufsiz, const char *fmt, ...) __attribute__((format(printf,4,5)));
int vformf_serval_instance_path(struct __sourceloc, char *buf, size_t bufsiz, const char *fmt, va_list);

#endif // __SERVAL_DNA__INSTANCE_H
