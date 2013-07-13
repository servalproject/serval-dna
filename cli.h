/*
 Serval command line parsing and processing.
 Copyright (C) 2012,2013 Serval Project, Inc.
 
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

#ifndef __SERVALD_CLI_H
#define __SERVALD_CLI_H 

#include "xprintf.h"
#include "log.h"
#include <stdint.h>

#ifdef HAVE_JNI_H
#include <jni.h>
#endif

#define COMMAND_LINE_MAX_LABELS   (32)

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

int cli_usage(const struct cli_schema *commands, XPRINTF xpf);
int cli_usage_args(const int argc, const char *const *args, const struct cli_schema *commands, XPRINTF xpf);
int cli_usage_parsed(const struct cli_parsed *parsed, XPRINTF xpf);
int cli_parse(const int argc, const char *const *args, const struct cli_schema *commands, struct cli_parsed *parsed);
int cli_invoke(const struct cli_parsed *parsed, struct cli_context *context);
int _cli_arg(struct __sourceloc __whence, const struct cli_parsed *parsed, char *label, const char **dst, int (*validator)(const char *arg), char *defaultvalue);

#define cli_arg(parsed, label, dst, validator, defaultvalue) _cli_arg(__WHENCE__, parsed, label, dst, validator, defaultvalue)

int cli_lookup_did(const char *text);
int cli_path_regular(const char *arg);
int cli_absolute_path(const char *arg);
int cli_optional_sid(const char *arg);
int cli_optional_bundle_key(const char *arg);
int cli_manifestid(const char *arg);
int cli_fileid(const char *arg);
int cli_optional_bundle_crypt_key(const char *arg);
int cli_interval_ms(const char *arg);
int cli_uint(const char *arg);
int cli_optional_did(const char *text);

int cli_putchar(struct cli_context *context, char c);
int cli_puts(struct cli_context *context, const char *str);
int cli_printf(struct cli_context *context, const char *fmt, ...);
int cli_delim(struct cli_context *context, const char *opt);
void cli_columns(struct cli_context *context, int columns, const char *names[]);
void cli_row_count(struct cli_context *context, int rows);
void cli_field_name(struct cli_context *context, const char *name, const char *delim);
void cli_put_long(struct cli_context *context, int64_t value, const char *delim);
void cli_put_string(struct cli_context *context, const char *value, const char *delim);
void cli_put_hexvalue(struct cli_context *context, const unsigned char *value, int length, const char *delim);

#endif // __SERVALD_CLI_H 
