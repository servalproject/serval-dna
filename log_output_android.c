/*
Serval DNA logging output to Android log
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

#include <android/log.h>
#include "log_output.h"
#include "feature.h"
#include "conf.h"

/* To enable logging to the Android system log, include USE_FEATURE(log_output_android) somewhere in
 * a source file that is always linked.
 */
DEFINE_FEATURE(log_output_android);

/* Private state for Android log output.
 */

struct log_output_android_state {
  char buf[1024];
  struct strbuf strbuf;
};

#define DISABLED ((FILE *)1)

static struct log_output_android_state static_state = {
  .strbuf = STRUCT_STRBUF_EMPTY
};

static inline struct log_output_android_state *_state(struct log_output *out)
{
  assert(out->state);
  return (struct log_output_android_state *)(out->state);
}

/* Functions for querying configuration.
 */

static bool_t log_android_dump_config(const struct log_output *UNUSED(out))
{
  return config.log.android.dump_config;
}


static int log_android_minimum_level(const struct log_output *UNUSED(out))
{
  return config.log.android.level;
}


static bool_t log_android_show_pid(const struct log_output *UNUSED(out))
{
  return config.log.android.show_pid;
}


static bool_t log_android_show_time(const struct log_output *UNUSED(out))
{
  return config.log.android.show_time;
}

/* Log output operations.
 */

static void log_android_start_line(struct log_output_iterator *it, int level)
{
  struct log_output *out = *it->output;
  struct log_output_android_state *state = _state(out);

  strbuf_init(&state->strbuf, state->buf, sizeof state->buf);
  it->xpf = XPRINTF_STRBUF(&state->strbuf);
}

static void log_android_end_line(struct log_output_iterator *it, int level)
{
  int alevel = ANDROID_LOG_UNKNOWN;
  switch (level) {
    case LOG_LEVEL_FATAL: alevel = ANDROID_LOG_FATAL; break;
    case LOG_LEVEL_ERROR: alevel = ANDROID_LOG_ERROR; break;
    case LOG_LEVEL_WARN:  alevel = ANDROID_LOG_WARN; break;
    case LOG_LEVEL_HINT:
    case LOG_LEVEL_INFO:  alevel = ANDROID_LOG_INFO; break;
    case LOG_LEVEL_DEBUG: alevel = ANDROID_LOG_DEBUG; break;
    default: abort();
  }
  __android_log_print(alevel, "servald", "%s", _state(*it->output)->buf);
}

static struct log_output static_log_output = {
  .dump_config = log_android_dump_config,
  .minimum_level = log_android_minimum_level,
  .show_pid = log_android_show_pid,
  .show_time = log_android_show_time,
  .state = &static_state,
  .open = NULL,
  .capture_fd = NULL,
  .is_available = NULL,
  .start_line = log_android_start_line,
  .end_line = log_android_end_line,
  .flush = NULL,
  .close = NULL
};

DEFINE_LOG_OUTPUT(&static_log_output);
