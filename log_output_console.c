/*
Serval DNA logging output to console (stderr)
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

#include <stdio.h> // for fopen(), fileno()
#include <assert.h>

#include "log_output.h"
#include "feature.h"
#include "conf.h"

/* To enable logging to console (standard error), include USE_FEATURE(log_output_console) somewhere
 * in a source file that is always linked.
 */
DEFINE_FEATURE(log_output_console);

/* Private state for console log output.
 */

struct log_output_console_state {
  FILE *fp;
};

#define DISABLED ((FILE *)1)

static struct log_output_console_state static_state = {
  .fp = NULL,
};

static inline struct log_output_console_state *_state(struct log_output *out)
{
  assert(out->state);
  return (struct log_output_console_state *)(out->state);
}

/* Functions for querying configuration.
 */

static int log_console_minimum_level(const struct log_output *UNUSED(out))
{
  return config.log.console.level;
}


static bool_t log_console_show_pid(const struct log_output *UNUSED(out))
{
  return config.log.console.show_pid;
}


static bool_t log_console_show_time(const struct log_output *UNUSED(out))
{
  return config.log.console.show_time;
}

/* The open() operation.  This gets called once before each line is logged.
 */

static void open_log_console(struct log_output_iterator *it)
{
  struct log_output_console_state *state = _state(*it->output);
  if (!state->fp && state->fp != DISABLED) {
    state->fp = stderr;
    setlinebuf(state->fp);
    serval_log_print_prolog(it);
  }
}

static void suppress_fd_log_console(struct log_output_iterator *it, int fd)
{
  // If another log outputter is capturing the console's output (eg, the logfile outputer), then
  // cease logging to the console to avoid duplicate messages being sent to that output.
  struct log_output_console_state *state = _state(*it->output);
  if (state->fp && state->fp != DISABLED && fileno(state->fp) == fd) {
    fflush(state->fp);
    state->fp = DISABLED;
  }
}

static bool_t is_log_console_available(const struct log_output_iterator *it)
{
  return _state(*it->output)->fp != DISABLED;
}

static void log_console_start_line(struct log_output_iterator *it, int level)
{
  struct log_output_console_state *state = _state(*it->output);
  if (state->fp && state->fp != DISABLED) {
    it->xpf = XPRINTF_STDIO(state->fp);
    xputs(serval_log_level_prefix_string(level), it->xpf);
  }
}

static void log_console_end_line(struct log_output_iterator *it, int UNUSED(level))
{
  struct log_output_console_state *state = _state(*it->output);
  if (state->fp && state->fp != DISABLED)
    fputc('\n', state->fp);
}

void flush_log_console(struct log_output_iterator *it)
{
  struct log_output_console_state *state = _state(*it->output);
  if (state->fp && state->fp != DISABLED)
    fflush(state->fp);
}

void close_log_console(struct log_output_iterator *it)
{
  struct log_output_console_state *state = _state(*it->output);
  if (state->fp && state->fp != DISABLED) {
    // If stderr were ever made buffered, then to avoid duplicates of buffered log messages being
    // flushed from a child process, the child must close file descriptor 2 before calling
    // logClose(), and re-open it again afterwards.
    fclose(state->fp);
    state->fp = NULL;
  }
}

static struct log_output static_log_output = {
  .minimum_level = log_console_minimum_level,
  .show_pid = log_console_show_pid,
  .show_time = log_console_show_time,
  .state = &static_state,
  .open = open_log_console,
  .capture_fd = NULL,
  .suppress_fd = suppress_fd_log_console,
  .is_available = is_log_console_available,
  .start_line = log_console_start_line,
  .end_line = log_console_end_line,
  .flush = flush_log_console,
  .close = close_log_console
};

DEFINE_LOG_OUTPUT(&static_log_output);
