/*
Serval DNA features
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

#ifndef __SERVAL_DNA__FEATURE_H
#define __SERVAL_DNA__FEATURE_H

/* These are macros for assembling an executable out of an explicitly-listed
 * subset of "features".  A feature is an object file (.o file) that contains
 * the entire implementation of the feature, and is optional, ie, can be
 * omitted from an executable without breaking the build.
 *
 * In Serval DNA, features are joined up with their infrastructure using
 * linkage sections; see "sections.h" for more details.
 *
 * For example, a source file can add its own static function to the list of
 * all URL path-to-function mappings for the HTTPD server using
 * DECLARE_HANDLER() macro defined in "httpd.h".  There is no
 * explicitly-initialised array that lists all the URL paths; the array is
 * constructed implicitly by the linker when it assembles the "httpd" section.
 * Simply including the relevant object files in the link brings their
 * functions into the array.
 *
 * Features are also used to add commands to the CLI interface and to add
 * port-number handlers to the MDP interface.
 *
 * In order to build an executable from libservald.a, the executable needs a
 * way to specify which optional features it wishes to link in, otherwise they
 * will be omitted from the build, and as a result it will offer few or no CLI
 * commands, no MDP services, and no HTTP services.
 *
 * Each source file that implements a feature must contain a DEFINE_FEATURE()
 * macro, with the name of the feature as its argument.
 *
 * Every executable that links against libservald.a must contain a source file
 * that invokes the USE_FEATURE() macro once for every defined feature it
 * wishes to link in.  This is typically done inside the main() function, but
 * may be done within any function that is guaranteed to be included in the
 * link.
 */

#define DEFINE_FEATURE(name) \
    void _serval_feature__ ## name () {} \

#define USE_FEATURE(name) \
    do { \
      extern void _serval_feature__ ## name (); \
      _serval_feature__ ## name (); \
    } while (0)

#endif // __SERVAL_DNA__FEATURE_H
