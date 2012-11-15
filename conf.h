/*
Copyright (C) 2010-2012 Paul Gardner-Stephen, Serval Project.
 
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
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>

#ifdef ANDROID
#define DEFAULT_INSTANCE_PATH "/data/data/org.servalproject/var/serval-node"
#else
#define DEFAULT_INSTANCE_PATH "/var/serval-node"
#endif

/* Handy statement for forming a path to an instance file in a char buffer whose declaration
 * is in scope (so that sizeof(buf) will work).  Evaluates to true if the pathname fitted into
 * the provided buffer, false (0) otherwise (after logging an error).
 */
#define FORM_SERVAL_INSTANCE_PATH(buf, path) (form_serval_instance_path(buf, sizeof(buf), (path)))

int confBusy();
int confReloadIfChanged();
const char *confValueGet(const char *var, const char *defaultValue);
int confValueGetBoolean(const char *var, int defaultValue);
int64_t confValueGetInt64(const char *var, int64_t defaultValue);
int64_t confValueGetInt64Range(const char *var, int64_t defaultValue, int64_t rangemin, int64_t rangemax);
void confSetDebugFlags();
int confParseBoolean(const char *text, const char *option_name);
int confValueSet(const char *var, const char *value);
int confWrite();
int confVarCount();
const char *confVar(unsigned int index);
const char *confValue(unsigned int index);
int form_serval_instance_path(char *buf, size_t bufsiz, const char *path);
const char *trimbuildpath(const char *s);
int mkdirs(const char *path, mode_t mode);
int mkdirsn(const char *path, size_t len, mode_t mode);
const char *serval_instancepath();
void serval_setinstancepath(const char *instancepath);

