/*
Serval DNA command-line output primitives
Copyright (C) 2016 Flinders University
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

#include <stdlib.h>
#include <inttypes.h> // for PRId64
#include "cli_stdio.h"
#include "log.h"
#include "str.h"

static FILE *stdio_fp(struct cli_context *context)
{
  return ((struct cli_context_stdio *)(context->context))->fp;
}

static void cl_delim(struct cli_context *context, const char *opt)
{
  // Simply writes a newline to standard output (or the value of the SERVALD_OUTPUT_DELIMITER env
  // var if set).
  const char *delim = getenv("SERVALD_OUTPUT_DELIMITER");
  if (delim == NULL)
    delim = opt ? opt : "\n";
  fputs(delim, stdio_fp(context));
}

static void cl_write(struct cli_context *UNUSED(context), const char *buf, size_t len)
{
  fwrite(buf, len, 1, stdio_fp(context));
}

static void cl_puts(struct cli_context *UNUSED(context), const char *str)
{
  fputs(str, stdio_fp(context));
}

static void cl_vprintf(struct cli_context *UNUSED(context), const char *fmt, va_list ap)
{
  if (vfprintf(stdio_fp(context), fmt, ap) < 0)
    WHYF("vfprintf(%s,...) failed", alloca_str_toprint(fmt));
}

static void cl_printf(struct cli_context *context, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  cl_vprintf(context, fmt, ap);
  va_end(ap);
}

static void cl_put_long(struct cli_context *context, int64_t value, const char *delim_opt)
{
  cl_printf(context, "%" PRId64, value);
  cl_delim(context, delim_opt);
}

static void cl_put_string(struct cli_context *context, const char *value, const char *delim_opt)
{
  if (value)
    cl_puts(context, value);
  cl_delim(context, delim_opt);
}

static void cl_put_hexvalue(struct cli_context *context, const unsigned char *value, size_t length, const char *delim_opt)
{
  if (value)
    cl_puts(context, alloca_tohex(value, length));
  cl_delim(context, delim_opt);
}

static void cl_put_blob(struct cli_context *context, const unsigned char *blob, size_t length, const char *delim_opt)
{
  if (blob)
    cl_write(context, (const char *)blob, length);
  cl_delim(context, delim_opt);
}

static void cl_start_table(struct cli_context *context, size_t column_count, const char *column_names[])
{
  cli_printf(context, "%zu", column_count);
  cli_delim(context, "\n");
  size_t i;
  for (i = 0; i != column_count; ++i) {
    cli_puts(context, column_names[i]);
    if (i + 1 == column_count)
      cli_delim(context, "\n");
    else
      cli_delim(context, ":");
  }
}

static void cl_end_table(struct cli_context *UNUSED(context), size_t UNUSED(row_count))
{
}

static void cl_field_name(struct cli_context *context, const char *name, const char *delim_opt)
{
  cli_puts(context, name);
  cli_delim(context, delim_opt);
}

static void cl_flush(struct cli_context *UNUSED(context))
{
  fflush(stdio_fp(context));
}

struct cli_vtable cli_vtable_stdio = {
  .delim = cl_delim,
  .write = cl_write,
  .puts = cl_puts,
  .vprintf = cl_vprintf,
  .put_long = cl_put_long,
  .put_string = cl_put_string,
  .put_hexvalue = cl_put_hexvalue,
  .put_blob = cl_put_blob,
  .start_table = cl_start_table,
  .end_table = cl_end_table,
  .field_name = cl_field_name,
  .flush = cl_flush
};
