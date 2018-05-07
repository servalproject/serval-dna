/*
Serval DNA logging output to a delegate
Copyright 2017 Flinders University

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

#include "log.h"
#include "log_output.h"
#include "log_output_delegate.h"
#include "strbuf.h"

/* An implementation of the Serval logging API that constructs log messages in
 * a buffer then passes the buffer to a delegate.
 */

/* Private state for delegate log output.
 */

struct log_output_delegate_state {
  bool_t opened;
  // Buffer to hold log messages before the log file is open and ready for writing:
  struct strbuf	strbuf;
  char buf[8192];
};

static struct log_output_delegate_state static_state = {
  .opened = 0,
  .strbuf = STRUCT_STRBUF_EMPTY,
  .buf = ""
};

/* Functions for querying configuration.
 */

static int log_delegate_minimum_level(const struct log_output *UNUSED(out))
{
  return serval_log_delegate.minimum_level;
}

static bool_t log_delegate_show_pid(const struct log_output *UNUSED(out))
{
  return serval_log_delegate.show_pid;
}

static bool_t log_delegate_show_time(const struct log_output *UNUSED(out))
{
  return serval_log_delegate.show_time;
}

/* Log output operations.
 */

static inline struct log_output_delegate_state *_state(struct log_output *out)
{
  assert(out->state);
  return (struct log_output_delegate_state *)(out->state);
}

static bool_t is_log_delegate_available(const struct log_output_iterator *UNUSED(it))
{
  return serval_log_delegate.print != NULL;
}

static void log_delegate_open(struct log_output_iterator *it)
{
  struct log_output_delegate_state *state = _state(*it->output);
  if (serval_log_delegate.print && !state->opened) {
    state->opened = 1;
    if (serval_log_delegate.show_prolog)
      serval_log_print_prolog(it);
  }
}

static bool_t log_delegate_capture_fd(struct log_output_iterator *UNUSED(it), int fd)
{
  return serval_log_delegate.capture_fd && serval_log_delegate.capture_fd(fd);
}

static void log_delegate_suppress_fd(struct log_output_iterator *UNUSED(it), int fd)
{
  if (serval_log_delegate.suppress_fd)
    serval_log_delegate.suppress_fd(fd);
}

static void log_delegate_start_line(struct log_output_iterator *it, int UNUSED(level))
{
  struct log_output_delegate_state *state = _state(*it->output);
  strbuf sb = &state->strbuf;
  assert(strbuf_len(sb) == 0);
  strbuf_init(sb, state->buf, sizeof state->buf);
  it->xpf = XPRINTF_STRBUF(sb);
}

static void log_delegate_end_line(struct log_output_iterator *it, int level)
{
  struct log_output_delegate_state *state = _state(*it->output);
  strbuf sb = &state->strbuf;
  serval_log_delegate.print(level, strbuf_str(sb), strbuf_overrun(sb));
  strbuf_reset(sb);
}

static void flush_log_delegate(struct log_output_iterator *UNUSED(it))
{
  if (serval_log_delegate.flush)
    serval_log_delegate.flush();
}

static struct log_output static_log_output = {
  .minimum_level = log_delegate_minimum_level,
  .show_pid = log_delegate_show_pid,
  .show_time = log_delegate_show_time,
  .state = &static_state,
  .open = log_delegate_open,
  .capture_fd = log_delegate_capture_fd,
  .suppress_fd = log_delegate_suppress_fd,
  .is_available = is_log_delegate_available,
  .start_line = log_delegate_start_line,
  .end_line = log_delegate_end_line,
  .flush = flush_log_delegate,
  .close = NULL
};

DEFINE_LOG_OUTPUT(&static_log_output);

// These are defaults only; the delegate fills this in as it wishes.
struct log_delegate serval_log_delegate = {
    .minimum_level = LOG_LEVEL_INFO,
    .show_prolog = 1,
    .show_pid = 0,
    .show_time = 1,
    .print = NULL,
    .flush = NULL,
    .capture_fd = NULL,
    .suppress_fd = NULL
};
