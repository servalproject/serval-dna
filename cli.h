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

#include "log.h"

#define COMMAND_LINE_MAX_LABELS   (32)

struct cli_parsed;

struct cli_schema {
  int (*function)(const struct cli_parsed *parsed, void *context);
  const char *words[COMMAND_LINE_MAX_LABELS];
  unsigned long long flags;
#define CLIFLAG_NONOVERLAY          (1<<0) /* Uses a legacy IPv4 DNA call instead of overlay mnetwork */
#define CLIFLAG_STANDALONE          (1<<1) /* Cannot be issued to a running instance */
#define CLIFLAG_PERMISSIVE_CONFIG   (1<<2) /* No error on bad configuration file */
  const char *description; // describe this invocation
};

struct cli_parsed {
  const struct cli_schema *command;
  struct labelv {
    const char *label;
    unsigned int len;
    const char *text;
  } labelv[COMMAND_LINE_MAX_LABELS];
  unsigned labelc;
  const char *const *args;
  unsigned argc;
  unsigned varargi;
};

void _debug_cli_parsed(struct __sourceloc __whence, const struct cli_parsed *parsed);

#define DEBUG_cli_parsed(parsed) _debug_cli_parsed(__WHENCE__, parsed)

int cli_usage(const struct cli_schema *commands);
int cli_parse(const int argc, const char *const *args, const struct cli_schema *commands, struct cli_parsed *parsed);
int cli_invoke(const struct cli_parsed *parsed, void *context);
int _cli_arg(struct __sourceloc __whence, const struct cli_parsed *parsed, char *label, const char **dst, int (*validator)(const char *arg), char *defaultvalue);

#define cli_arg(parsed, label, dst, validator, defaultvalue) _cli_arg(__WHENCE__, parsed, label, dst, validator, defaultvalue)

int cli_lookup_did(const char *text);
int cli_absolute_path(const char *arg);
int cli_optional_sid(const char *arg);
int cli_optional_bundle_key(const char *arg);
int cli_manifestid(const char *arg);
int cli_fileid(const char *arg);
int cli_optional_bundle_crypt_key(const char *arg);
int cli_uint(const char *arg);
int cli_optional_did(const char *text);

#endif // __SERVALD_CLI_H 
