/*
Serval DNA JNI common definitions
Copyright (C) 2016 Flinders University

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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef HAVE_JNI_H
#error <jni.h> is not available
#endif

#include <jni.h>

// Stop OpenJDK 7 from foisting their UNUSED() macro on us in <jni_md.h>
// N.B. This means that "feature.h" can only be included _after_ this header
// file, because it defines UNUSED().
#ifdef UNUSED
# undef UNUSED
#endif

// Throw a Java exception and return -1.
int jni_throw(JNIEnv *env, const char *class_name, const char *msg);
