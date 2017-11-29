/*
Serval DNA logging
Copyright (C) 2013-2015 Serval Project Inc.
Copyright (C) 2016-2017 Flinders University

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

#include <libgen.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <unistd.h>
#include <assert.h>

#include "log.h"
#include "log_output.h"
#include "log_prolog.h"
#include "version_servald.h"
#include "instance.h"
#include "net.h"
#include "os.h"
#include "str.h"
#include "strbuf.h"
#include "strbuf_helpers.h"
#include "xprintf.h"
#include "trigger.h"

/* This thread-local variable is used to support recursion, so that log output operations like
 * open() that invoke log primitives will not cause infinite recursion, but instead will log only to
 * the output whose iterator they are currently servicing.
 */
static __thread struct log_output_iterator *current_iterator = NULL;

/* By default, if there is no log file configured, this is logged as an INFO message, but a server
 * can set this to log it at a higher level.
 */
int serval_log_level_NoLogFileConfigured = LOG_LEVEL_INFO;

/* Primitive operations for log_output_iterator.
 */

static void log_iterator_start(struct log_output_iterator *it)
{
  it->output = NULL;
  memset(it, 0, sizeof *it);
  gettimeofday(&it->tv, NULL);
  localtime_r(&it->tv.tv_sec, &it->tm);
  it->xpf = XPRINTF_NULL;
}

static int log_iterator_advance(struct log_output_iterator *it)
{
  assert(it->output != SECTION_END(logoutput));
  do {
    it->output = it->output ? it->output + 1 : SECTION_START(logoutput);
  } while (it->output != SECTION_END(logoutput) && !*it->output); // skip NULL entries
  return it->output != SECTION_END(logoutput);
}

/* In case no outputters are linked, ensure that the logoutput section exists, by adding a NULL
 * entry to it.  Otherwise you get link errors like:
 * log.c:193: error: undefined reference to '__stop_logoutput'
 */

DEFINE_LOG_OUTPUT(NULL);

/* Functions for formatting log messages.
 */

static void print_line_prefix(struct log_output_iterator *it)
{
  assert(it->output);
  struct log_output *out = *it->output;
  assert(out);

  if (out->show_pid(out))
    xprintf(it->xpf, "[%5u] ", getpid());

  if (out->show_time(out)) {
    if (it->tv.tv_sec == 0) {
      xputs("NOTIME______ ", it->xpf);
    } else {
      char buf[50];
      if (strftime(buf, sizeof buf, "%T", &it->tm) == 0)
	xputs("EMPTYTIME___ ", it->xpf);
      else
	xprintf(it->xpf, "%s.%03u ", buf, (unsigned int)it->tv.tv_usec / 1000);
    }
  }

  if (strbuf_len(&log_context)) {
    xputs("[", it->xpf);
    xputs(strbuf_str(&log_context), it->xpf);
    xputs("] ", it->xpf);
  }
}

static void whence_prefix(struct log_output_iterator *it, struct __sourceloc whence)
{
  assert(!XPRINTF_IS_NULL(it->xpf));
  if ((whence.file && whence.file[0]) || (whence.function && whence.function[0])) {
    xprint_sourceloc(it->xpf, whence);
    xputs("  ", it->xpf);
  }
}

/* Log output operations.
 */

static void log_open(struct log_output_iterator *it)
{
  assert(it->output);
  assert(*it->output);
  if ((*it->output)->open)
    (*it->output)->open(it);
}

static bool_t is_log_available(struct log_output_iterator *it)
{
  assert(it->output);
  assert(*it->output);
  return !(*it->output)->is_available || (*it->output)->is_available(it);
}

static void log_start_line(struct log_output_iterator *it, int level)
{
  assert(level >= LOG_LEVEL_SILENT);
  assert(level <= LOG_LEVEL_FATAL);
  assert(XPRINTF_IS_NULL(it->xpf));
  assert(it->output);
  assert(*it->output);
  assert((*it->output)->start_line);
  (*it->output)->start_line(it, level);
  assert(!XPRINTF_IS_NULL(it->xpf));
  print_line_prefix(it);
}

static void log_end_line(struct log_output_iterator *it, int level)
{
  assert(level >= LOG_LEVEL_SILENT);
  assert(level <= LOG_LEVEL_FATAL);
  assert(!XPRINTF_IS_NULL(it->xpf));
  assert(it->output);
  assert(*it->output);
  if ((*it->output)->end_line)
    (*it->output)->end_line(it, level);
  it->xpf = XPRINTF_NULL;
}

static void log_flush(struct log_output_iterator *it)
{
  assert(it->output);
  assert(*it->output);
  if ((*it->output)->flush)
    (*it->output)->flush(it);
}

static void log_close(struct log_output_iterator *it)
{
  assert(it->output);
  assert(*it->output);
  if ((*it->output)->close)
    (*it->output)->close(it);
}

static void log_capture_fd(struct log_output_iterator *it, int fd, bool_t *captured)
{
  assert(it->output);
  assert(*it->output);
  if ((*it->output)->capture_fd)
    (*it->output)->capture_fd(it, fd, captured);
}

/* Functions for use by log outputters.  This is the "private" API of the logging system, as
 * described in "log_output.h".
 */

const char *serval_log_level_prefix_string(int level)
{
  switch (level) {
    case LOG_LEVEL_FATAL: return "FATAL:";
    case LOG_LEVEL_ERROR: return "ERROR:";
    case LOG_LEVEL_WARN:  return "WARN: ";
    case LOG_LEVEL_HINT:  return "HINT: ";
    case LOG_LEVEL_INFO:  return "INFO: ";
    case LOG_LEVEL_DEBUG: return "DEBUG:";
    default:              return "UNKWN:";
  }
}

void serval_log_output_iterator_vprintf_nl(struct log_output_iterator *it, int level, const char *fmt, va_list ap)
{
  log_start_line(it, level);
  vxprintf(it->xpf, fmt, ap);
  log_end_line(it, level);
}

void serval_log_output_iterator_printf_nl(struct log_output_iterator *it, int level, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  serval_log_output_iterator_vprintf_nl(it, level, fmt, ap);
  va_end(ap);
}

static void print_datetime(struct log_output_iterator *it, int level)
{
  char buf[50];
  if (strftime(buf, sizeof buf, "%F %T %z", &it->tm)) {
    serval_log_output_iterator_printf_nl(it, level, "Local date/time: %s", buf);
    (*it->output)->last_tm = it->tm;
  }
}

static void print_newdate(struct log_output_iterator *it)
{
  struct log_output *out = *it->output;
  if ( it->tm.tm_mday != out->last_tm.tm_mday
    || it->tm.tm_mon != out->last_tm.tm_mon
    || it->tm.tm_year != out->last_tm.tm_year
  )
    print_datetime(it, LOG_LEVEL_INFO);
}

void serval_log_print_prolog(struct log_output_iterator *it)
{
  assert(current_iterator == NULL || current_iterator == it);
  struct log_output_iterator *save_current_iterator = current_iterator;
  current_iterator = it;
  print_datetime(it, LOG_LEVEL_INFO);
  CALL_TRIGGER(log_prolog);
  current_iterator = save_current_iterator;
}

// Put a dummy no-op trigger callback into the "log_prolog" trigger section, otherwise if no other
// object provides one, the link will fail with errors like:
// undefined reference to `__start_tr_log_prolog'
// undefined reference to `__stop_tr_log_prolog'

static void __dummy_on_log_prolog() {}
DEFINE_TRIGGER(log_prolog, __dummy_on_log_prolog);

/* Private helper functions for formatting and emitting log messages.
 */

static void iterator_vprintf_nl(struct log_output_iterator *it, int level, struct __sourceloc whence, const char *fmt, va_list ap)
{
  assert(current_iterator);
  log_start_line(it, level);
  whence_prefix(it, whence);
  va_list ap1;
  va_copy(ap1, ap);
  vxprintf(it->xpf, fmt, ap1);
  va_end(ap1);
  log_end_line(it, level);
}

/* Logging primitives.  This is the "public" API of the logging system, as described in "log.h".
 */

void serval_vlogf(int level, struct __sourceloc whence, const char *fmt, va_list ap)
{
  if (level != LOG_LEVEL_SILENT) {
    if (current_iterator) {
      // This occurs if a log primitive is invoked recursively from within a log output, which is
      // typically an open() operation calling serval_log_print_prolog(it).  In this case, the log
      // output only goes to the single output in question, not to all outputs.
      iterator_vprintf_nl(current_iterator, level, whence, fmt, ap);
    }
    else {
      struct log_output_iterator it;
      log_iterator_start(&it);
      while (log_iterator_advance(&it)) {
	struct log_output *out = *it.output;
	if (level >= out->minimum_level(out)) {
	  // If the open() operation recurses by invoking a log primitive directly, then print that
	  // message to all available outputs but avoid recursing into open() operations that are
	  // already being called.
	  if (!out->opening) {
	    out->opening = 1;
	    log_open(&it);
	    out->opening = 0;
	  }
	  if (is_log_available(&it)) {
	    current_iterator = &it;
	    print_newdate(&it);
	    iterator_vprintf_nl(&it, level, whence, fmt, ap);
	    log_flush(&it);
	    current_iterator = NULL;
	  }
	}
      }
    }
  }
}

void serval_log_flush()
{
  assert(!current_iterator);
  struct log_output_iterator it;
  log_iterator_start(&it);
  while (log_iterator_advance(&it))
    log_flush(&it);
}

void serval_log_close()
{
  assert(!current_iterator);
  struct log_output_iterator it;
  log_iterator_start(&it);
  while (log_iterator_advance(&it))
    log_close(&it);
}

bool_t serval_log_capture_fd(int fd) {
  assert(!current_iterator);
  struct log_output_iterator it;
  log_iterator_start(&it);
  bool_t captured = 0;
  while (log_iterator_advance(&it))
    log_capture_fd(&it, fd, &captured);
  return captured;
}
