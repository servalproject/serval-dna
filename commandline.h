/*
 Copyright (C) 2014,2015 Serval Project Inc.
 
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

#ifndef __SERVAL_DNA__COMMANDLINE_H
#define __SERVAL_DNA__COMMANDLINE_H

#include "section.h"

#define KEYRING_PIN_OPTION	  ,"[--keyring-pin=<pin>]"
#define KEYRING_ENTRY_PIN_OPTION  ,"[--entry-pin=<pin>]"
#define KEYRING_PIN_OPTIONS	  KEYRING_PIN_OPTION KEYRING_ENTRY_PIN_OPTION "..."

struct cli_schema;
struct cli_context;

// macros are weird sometimes ....
#define __APPEND_(X,Y) X ## Y
#define _APPEND(X,Y) __APPEND_(X,Y)

#define DEFINE_CMD(FUNC, FLAGS, HELP, WORD1, ...) \
  static int FUNC(const struct cli_parsed *parsed, struct cli_context *context); \
  static struct cli_schema _APPEND(FUNC, __LINE__) IN_SECTION(commands) = {\
    .function = FUNC, \
    .words = {WORD1, ##__VA_ARGS__, NULL}, \
    .flags = FLAGS, \
    .description = HELP \
  }

DECLARE_SECTION(struct cli_schema, commands);

#define CMD_COUNT (SECTION_START(commands) - SECTION_END(commands))

void cli_flush(struct cli_context *context);
int cli_delim(struct cli_context *context, const char *opt);
int cli_puts(struct cli_context *context, const char *str);
void cli_printf(struct cli_context *context, const char *fmt, ...) __attribute__ (( format(printf,2,3) ));
void cli_columns(struct cli_context *context, int columns, const char *names[]);
void cli_row_count(struct cli_context *context, int rows);
void cli_field_name(struct cli_context *context, const char *name, const char *delim);
void cli_put_long(struct cli_context *context, int64_t value, const char *delim);
void cli_put_string(struct cli_context *context, const char *value, const char *delim);
void cli_put_hexvalue(struct cli_context *context, const unsigned char *value, int length, const char *delim);
int cli_write(struct cli_context *context, const unsigned char *buf, size_t len);

void cli_cleanup();

#endif
