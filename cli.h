/*
Serval DNA command-line interface
Copyright (C) 2010-2013 Serval Project Inc.
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

#ifndef __SERVAL_DNA__CLI_H
#define __SERVAL_DNA__CLI_H

#include <stdint.h>
#include "xprintf.h"
#include "log.h"

#define COMMAND_LINE_MAX_LABELS   (16)

struct cli_parsed;
struct cli_context;

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

void _debug_cli_parsed(struct __sourceloc __whence, const char *tag, const struct cli_parsed *parsed);

#define DEBUG_cli_parsed(FLAG,parsed) do { if (IF_DEBUG(FLAG)) _debug_cli_parsed(__WHENCE__, #FLAG, parsed); } while (0)

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

/* Argument parsing validator runctions.
 */
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

/* Output functions.  Every command that is invoked via the CLI must use
 * exclusively the following primitives to send its response.
 *
 * The CLI output is organised as a sequence of 'fields'.  The 
 */

/* Terminate the current output field, so that the next cli_ output function
 * will start appending to a new field.
 */
void cli_delim(struct cli_context *context, const char *opt);

/* Write a buffer of data to the current field, starting a new field if necessary.
 */
void cli_write(struct cli_context *context, const char *buf, size_t len);

/* Write a null-terminated string to the current field, starting a new field if
 * necessary.  The terminating null is not included.
 */
void cli_puts(struct cli_context *context, const char *str);

/* Write a formatted string to the current field, starting a new field if
 * necessary.
 */
void cli_printf(struct cli_context *context, const char *fmt, ...) __attribute__ (( __ATTRIBUTE_format(printf,2,3) ));

/* Write a field consisting of a single long integer.  May FATAL if the current field
 * has already been written to.
 */
void cli_put_long(struct cli_context *context, int64_t value, const char *delim);

/* Write a field consisting of a single string.  May FATAL if the current field
 * has already been written to.
 */
void cli_put_string(struct cli_context *context, const char *value, const char *delim);

/* Write a field consisting of a buffer of data that should be represented in
 * ASCII hex format, eg, SID, Bundle ID, crypto key.  May FATAL if the current
 * field has already been written to.
 */
void cli_put_hexvalue(struct cli_context *context, const unsigned char *value, int length, const char *delim);

/* Write a field consisting of a buffer of binary data in unspecified format,
 * ie, not necessarily text.  FATAL if the current field has already been
 * written to.
 */
void cli_put_blob(struct cli_context *context, const unsigned char *blob, int length, const char *delim);

/* Write a list of column headers.  The column headers must be followed by N *
 * column_count fields, where N >= 0 is the number of rows in the table.  After
 * the last field, cli_end_table(N) must be called.
 */
void cli_start_table(struct cli_context *context, size_t column_count, const char *column_names[]);

/* Write a count of the number of rows just written to a table that was started
 * with cli_start_table().  This terminates the data portion of the table; no
 * more rows may be written after this.
 */
void cli_end_table(struct cli_context *context, size_t row_count);

/* Write a 'name' in a name-value field pair.  This is used when writing an
 * aggregate data item that could be represented using a struct in C.  Each
 * output field is prefixed with a text field containing its name; names are
 * usually unique.  This produces an even number of fields.
 */
void cli_field_name(struct cli_context *context, const char *name, const char *delim);

/* Force all fields written so far to be sent to the CLI client; this may not
 * have any effect.
 */
void cli_flush(struct cli_context *context);

void cli_cleanup();

/* CLI encapulation.  Every interface that can encapsulate the CLI must provide
 * a vtable of operations that realise the above output primitives in terms of
 * its own data channel.
 */

struct cli_vtable {
    void (*delim)(struct cli_context *context, const char *opt);
    void (*write)(struct cli_context *context, const char *buf, size_t len);
    void (*puts)(struct cli_context *context, const char *str);
    void (*vprintf)(struct cli_context *context, const char *fmt, va_list ap);
    void (*put_long)(struct cli_context *context, int64_t value, const char *delim);
    void (*put_string)(struct cli_context *context, const char *value, const char *delim);
    void (*put_hexvalue)(struct cli_context *context, const unsigned char *value, size_t length, const char *delim);
    void (*put_blob)(struct cli_context *context, const unsigned char *value, size_t length, const char *delim);
    void (*start_table)(struct cli_context *context, size_t column_count, const char *column_names[]);
    void (*end_table)(struct cli_context *context, size_t row_count);
    void (*field_name)(struct cli_context *context, const char *name, const char *delim);
    void (*flush)(struct cli_context *context);
};

struct cli_context {
  void *context;
  struct cli_vtable *vtable;
};

#endif // __SERVAL_DNA__CLI_H
