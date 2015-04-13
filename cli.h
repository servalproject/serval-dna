/*
 Serval command line parsing and processing.
 Copyright (C) 2012,2013 Serval Project Inc.
 
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

#ifndef __SERVAL_DNA__CLI_H
#define __SERVAL_DNA__CLI_H

#include <stdint.h>
#ifdef HAVE_JNI_H
#include <jni.h>

// Stop OpenJDK 7 from foisting their UNUSED() macro on us in <jni_md.h>
#ifdef UNUSED
# undef UNUSED
#endif

#endif
#include "xprintf.h"
#include "log.h"

#define COMMAND_LINE_MAX_LABELS   (16)

struct cli_parsed;
struct cli_context{
#ifdef HAVE_JNI_H
  JNIEnv *jni_env;
  int jni_exception;
  jobject jniResults;
  char *outv_buffer;
  char *outv_current;
  char *outv_limit;
#endif
  void *context;
};

struct cli_schema {
  int (*function)(const struct cli_parsed *parsed, struct cli_context *context);
  const char *words[COMMAND_LINE_MAX_LABELS];
  uint64_t flags;
#define CLIFLAG_PERMISSIVE_CONFIG   (1<<0) /* Accept defective configuration file */
  const char *description; // describe this invocation
};

struct cli_parsed {
  const struct cli_schema *commands;
  const struct cli_schema *end_commands;
  unsigned int cmdi;
  struct labelv {
    const char *label;
    unsigned int len;
    const char *text;
  } labelv[COMMAND_LINE_MAX_LABELS];
  unsigned labelc;
  const char *const *args;
  unsigned argc;
  int varargi; // -1 means no var args
};

void _debug_cli_parsed(struct __sourceloc __whence, const struct cli_parsed *parsed);

#define DEBUG_cli_parsed(parsed) _debug_cli_parsed(__WHENCE__, parsed)

int cli_usage(const struct cli_schema *commands, const struct cli_schema *end_commands, XPRINTF xpf);
int cli_usage_args(const int argc, const char *const *args, const struct cli_schema *commands, const struct cli_schema *end_commands, XPRINTF xpf);
int cli_usage_parsed(const struct cli_parsed *parsed, XPRINTF xpf);
int cli_parse(const int argc, const char *const *args, const struct cli_schema *commands, const struct cli_schema *end_commands, struct cli_parsed *parsed);
int cli_invoke(const struct cli_parsed *parsed, struct cli_context *context);

/* First, assign 'defaultvalue' to '*dst', to guarantee that '*dst' is in a
 * known state regardless of the return value and provide the caller with an
 * alternative way to check if an argument was found.
 *
 * Then, if there is an argument labelled 'label' present on the 'parsed'
 * command line:
 *  - if a validator function was supplied (not NULL) and it returns false (0)
 *    when invoked on '*dst', return -1, otherwise
 *  - assign the argument's value as a NUL-terminated string to '*dst' and
 *    return 0.
 *
 * Otherwise, there is no argument labelled 'label', so return 1.
 */
#define cli_arg(parsed, label, dst, validator, defaultvalue) _cli_arg(__WHENCE__, parsed, label, dst, validator, defaultvalue)
int _cli_arg(struct __sourceloc __whence, const struct cli_parsed *parsed, char *label, const char **dst, int (*validator)(const char *arg), char *defaultvalue);

int cli_lookup_did(const char *text);
int cli_path_regular(const char *arg);
int cli_absolute_path(const char *arg);
int cli_optional_sid(const char *arg);
int cli_optional_bundle_secret_key(const char *arg);
int cli_bid(const char *arg);
int cli_optional_bid(const char *arg);
int cli_fileid(const char *arg);
int cli_optional_bundle_crypt_key(const char *arg);
int cli_interval_ms(const char *arg);
int cli_uint(const char *arg);
int cli_optional_did(const char *text);

#endif // __SERVAL_DNA__CLI_H
