/*
Serval DNA logging output to files
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

#include <libgen.h> // for dirname()
#include <time.h> // for time_t and struct tm
#include <fcntl.h> // for open(), O_RDWR
#include <stdio.h> // for fopen(), fileno()
#include <ctype.h> // for isdigit()
#include <dirent.h> // for readdir() etc.
#include <string.h> // for strcpy()
#include <assert.h>
//#include <unistd.h> // for dup2()

#include "log_output.h"
#include "feature.h"
#include "conf.h"
#include "instance.h"
#include "strbuf.h"
#include "strbuf_helpers.h"

/* To enable logging to files, include USE_FEATURE(log_output_file) somewhere in a source file.
 */
DEFINE_FEATURE(log_output_file);

/* Private state for file log output.
 */

struct log_output_file_state {
  // The full pathname of the currently open log file:
  const char *path;
  char path_buf[400];
  // The currently open log file:
  // - NULL means open() has not been called yet, but will buffer messages until the file is opened,
  //   so is ready to accept messages
  // - OPEN_FAILED means a prior open() failed, so is not ready to accept messages
  // - otherwise, open() has created/opened a file, and is ready to accept messages
  FILE *fp;
  // The time that the currently open log file was started, used for file rotation logic:
  time_t start_time;
  // Buffer to hold log messages before the log file is open and ready for writing:
  char buf[8192];
  struct strbuf	strbuf;
  // File descriptor to redirect to the open log file.
  int capture_fd;
};

#define OPEN_FAILED ((FILE *)1)

static struct log_output_file_state static_state = {
  .path = NULL,
  .fp = NULL,
  .start_time = 0,
  .strbuf = STRUCT_STRBUF_EMPTY,
  .capture_fd = -1
};

static inline struct log_output_file_state *_state(struct log_output *out)
{
  assert(out->state);
  return (struct log_output_file_state *)(out->state);
}

/* Functions for querying configuration.
 */

static int log_file_minimum_level(const struct log_output *UNUSED(out))
{
  return config.log.file.level;
}


static bool_t log_file_show_pid(const struct log_output *UNUSED(out))
{
  return config.log.file.show_pid;
}


static bool_t log_file_show_time(const struct log_output *UNUSED(out))
{
  return config.log.file.show_time;
}

/* Functions for tracing and then logging the actions of multi-directory mkdir().
 */

struct mkdir_trace {
  struct {
    size_t	len;
    mode_t	mode;
  }	      created[10];
  size_t      created_count;
  mode_t      latest_mode;
};

static void trace_mkdir(struct __sourceloc UNUSED(whence), const char *path, mode_t mode, void *context)
{
  struct mkdir_trace *trace = context;
  trace->latest_mode = mode;
  if (trace->created_count < NELS(trace->created)) {
    trace->created[trace->created_count].len = strlen(path);
    trace->created[trace->created_count].mode = mode;
  }
  ++trace->created_count;
}

static void log_mkdir_trace(const char *dir, struct mkdir_trace *trace)
{
  unsigned i;
  for (i = 0; i < trace->created_count && i < NELS(trace->created); ++i)
    NOWHENCE(INFOF("Created %s (mode %04o)", alloca_toprint(-1, dir, trace->created[i].len), trace->created[i].mode));
  if (trace->created_count > NELS(trace->created) + 1)
    NOWHENCE(INFO("Created ..."));
  if (trace->created_count > NELS(trace->created))
    NOWHENCE(INFOF("Created %s (mode %04o)", alloca_str_toprint(dir), trace->latest_mode));
}

/* The open() operation.  This gets called once before each line is logged.
 *
 * This method writes some initial INFO message(s) at head of the log, which causes it to call
 * serval_vlogf(), but the logging system will not recurse back into this function, instead will
 * just write the log messages by calling log_file_start_line() and log_file_end_line() in this and
 * in other outputters.
 */

static void open_log_file(struct log_output_iterator *it)
{
  struct log_output *out = *it->output;
  struct log_output_file_state *state = _state(out);

  // Once an attempt to open has failed, don't try any more.
  if (state->fp == OPEN_FAILED)
    return;

  time_t start_time = 0;

  // Use the path given by the environment variable if set, mainly to support test scripts.
  // Otherwise work out the log file path from the configuration, if available.
  const char *env_path = getenv("SERVALD_LOG_FILE");
  if (env_path) 
    state->path = env_path;
  else if (!cf_limbo) {
    // Rotate the log file name if the configuration does not specify a fixed name.
    if (!config.log.file.path[0]) {
      assert(it->tv.tv_sec != 0);
      start_time = it->tv.tv_sec;
      if (config.log.file.duration) {
	// Compute the desired start time of the log file.
	start_time -= start_time % config.log.file.duration;
	// If the desired start time has advanced from the current open file's start time, then
	// close the current log file, which will cause the logic below to open the next one.
	if (state->path == state->path_buf && start_time != state->start_time) {
	  if (state->fp)
	    fclose(state->fp);
	  state->fp = NULL;
	  state->path = NULL;
	}
      }
    }
    // (Re-)compute the file path.
    if (state->path == NULL) {
      strbuf sbfile = strbuf_local_buf(state->path_buf);
      strbuf_serval_log_path(sbfile);
      strbuf_path_join(sbfile, config.log.file.directory_path, "", NULL); // ensure trailing '/'
      if (config.log.file.path[0]) {
	strbuf_path_join(sbfile, config.log.file.path, NULL);
      } else {
	assert(start_time != 0);
	struct tm tm;
	(void)localtime_r(&start_time, &tm);
	strbuf_append_strftime(sbfile, "serval-%Y%m%d%H%M%S.log", &tm);
      }
      if (strbuf_overrun(sbfile)) {
	state->fp = OPEN_FAILED;
	WHY("Cannot form log file name - buffer overrun");
      } else {
	state->path = state->path_buf;
	state->start_time = start_time;
      }
    }
  }

  // Create the log file and append to it.
  if (state->fp == NULL) {
    if (state->path == NULL) {
      if (!cf_limbo) {
	state->fp = OPEN_FAILED;
	NOWHENCE(LOGF(serval_log_level_NoLogFileConfigured, "No log file configured"));
      }
    } else {
      // Create the new log file.
      size_t dirsiz = strlen(state->path) + 1;
      char _dir[dirsiz];
      struct mkdir_trace _trace;
      bzero(&_trace, sizeof _trace);
      strcpy(_dir, state->path);
      const char *dir = dirname(_dir); // modifies _dir[]
      if (mkdirs_log(dir, 0700, trace_mkdir, &_trace) == -1) {
	state->fp = OPEN_FAILED;
	log_mkdir_trace(dir, &_trace);
	WARNF("Cannot mkdir %s - %s [errno=%d]", alloca_str_toprint(dir), strerror(errno), errno);
      } else if ((state->fp = fopen(state->path, "a")) == NULL) {
	state->fp = OPEN_FAILED;
	log_mkdir_trace(dir, &_trace);
	WARNF("Cannot create-append %s - %s [errno=%d]", state->path, strerror(errno), errno);
      } else {
	setlinebuf(state->fp);
	serval_log_print_prolog(it);
	log_mkdir_trace(dir, &_trace);
	NOWHENCE(INFOF("Logging to %s (fd %d)", state->path, fileno(state->fp)));
	// If the output has been instructed to redirect a given file descriptor to its log file,
	// then do so now.
	if (state->capture_fd != -1)
	  dup2(fileno(state->fp), state->capture_fd);
	// Update the log symlink to point to the latest log file.
	strbuf sbsymlink = strbuf_alloca(400);
	strbuf_system_log_path(sbsymlink);
	strbuf_path_join(sbsymlink, "serval.log", NULL);
	if (strbuf_overrun(sbsymlink))
	  WHY("Cannot form log symlink name - buffer overrun");
	else {
	  const char *f = state->path;
	  const char *s = strbuf_str(sbsymlink);
	  const char *relpath = f;
	  for (; *f && *f == *s; ++f, ++s)
	    if (*f == '/')
	      relpath = f;
	  while (*relpath == '/')
	    ++relpath;
	  while (*s == '/')
	    ++s;
	  if (strchr(s, '/'))
	    relpath = state->path;
	  // If racing with another process at this exact same point, then the symlink(2) call may
	  // fail with EEXIST, in which case log a warning, not an error.
	  unlink(strbuf_str(sbsymlink));
	  if (symlink(relpath, strbuf_str(sbsymlink)) == -1)
	    LOGF(errno == EEXIST ? LOG_LEVEL_WARN : LOG_LEVEL_ERROR,
		 "Cannot symlink %s -> %s - %s [errno=%d]",
		 strbuf_str(sbsymlink), relpath, strerror(errno), errno);
	  else
	    NOWHENCE(INFOF("Created symlink %s -> %s", strbuf_str(sbsymlink), relpath));
	}
	// Expire old log files.
	size_t pathsiz = strlen(state->path) + 1;
	char path[pathsiz];
	while (1) {
	  strcpy(path, state->path);
	  const char *base = basename(path); // modifies path[]
	  DIR *d = opendir(dir);
	  if (!d) {
	    WHYF("Cannot expire log files: opendir(%s) - %s [errno=%d]", dir, strerror(errno), errno);
	    break;
	  }
	  struct dirent oldest;
	  memset(&oldest, 0, sizeof oldest);
	  unsigned count = 0;
	  while (1) {
	    errno = 0;
	    struct dirent *ent = readdir(d);
	    if (ent == NULL) {
	      if (errno)
		WHYF("Cannot expire log files: readdir(%s) - %s [errno=%d]", dir, strerror(errno), errno);
	      break;
	    }
	    const char *e;
	    if (   str_startswith(ent->d_name, "serval-", &e)
		&& isdigit(e[0]) && isdigit(e[1]) && isdigit(e[2]) && isdigit(e[3]) // YYYY
		&& isdigit(e[4]) && isdigit(e[5]) // MM
		&& isdigit(e[6]) && isdigit(e[7]) // DD
		&& isdigit(e[8]) && isdigit(e[9]) // HH
		&& isdigit(e[10]) && isdigit(e[11]) // MM
		&& isdigit(e[12]) && isdigit(e[13]) // SS
		&& strcmp(&e[14], ".log") == 0
	    ) {
	      ++count;
	      if ( strcmp(ent->d_name, base) != 0
		&& (!oldest.d_name[0] || strcmp(ent->d_name, oldest.d_name) < 0)
	      )
		oldest = *ent;
	    }
	  }
	  closedir(d);
	  if (count <= config.log.file.rotate || !oldest.d_name[0])
	    break;
	  strbuf b = strbuf_local(path, pathsiz);
	  strbuf_path_join(b, dir, oldest.d_name, NULL);
	  assert(!strbuf_overrun(b));
	  NOWHENCE(INFOF("Delete %s", path));
	  unlink(path);
	}
      }
    }
  }
}

static bool_t capture_fd_log_file(struct log_output_iterator *it, int fd)
{
  bool_t captured = 0;
  // This outputter does not connect the file descriptor to an output file until the next log
  // message is output.
  _state(*it->output)->capture_fd = fd;
  // Ensure that the file descriptor is occupied, so that no other open() call can occupy it in
  // the meantime.
  int devnull;
  if ((devnull = open("/dev/null", O_RDWR, 0)) == -1)
    WHY_perror("open(\"/dev/null\")");
  else if (devnull == fd)
    captured = 1;
  else {
    if (dup2(devnull, fd) == -1)
      WHYF_perror("dup2(%d, %d)", devnull, fd);
    else
      captured = 1;
    close(devnull);
  }
  return captured;
}

static bool_t is_log_file_available(const struct log_output_iterator *it)
{
  return _state(*it->output)->fp != OPEN_FAILED;
}

static void log_file_start_line(struct log_output_iterator *it, int level)
{
  struct log_output_file_state *state = _state(*it->output);
  strbuf sb = &state->strbuf;
  if (strbuf_is_empty(sb))
    strbuf_init(sb, state->buf, sizeof state->buf);
  else if (strbuf_len(sb))
    strbuf_putc(sb, '\n');
  it->xpf = XPRINTF_STRBUF(sb);
  xputs(serval_log_level_prefix_string(level), it->xpf);
}

static void flush_log_file(struct log_output_iterator *it)
{
  struct log_output_file_state *state = _state(*it->output);
  FILE *fp = state->fp;
  strbuf sb = &state->strbuf;
  if (fp && fp != OPEN_FAILED && strbuf_len(sb) != 0) {
    fprintf(fp, "%s\n%s", strbuf_str(sb), strbuf_overrun(sb) ? "LOG OVERRUN\n" : "");
    strbuf_reset(sb);
  }
}

void close_log_file(struct log_output_iterator *it)
{
  struct log_output_file_state *state = _state(*it->output);
  FILE *fp = state->fp;
  strbuf_reset(&state->strbuf);
  if (fp && fp != OPEN_FAILED)
    fclose(fp);
  state->fp = NULL; // next open() will try again
}

static struct log_output static_log_output = {
  .minimum_level = log_file_minimum_level,
  .show_pid = log_file_show_pid,
  .show_time = log_file_show_time,
  .state = &static_state,
  .open = open_log_file,
  .capture_fd = capture_fd_log_file,
  .suppress_fd = NULL,
  .is_available = is_log_file_available,
  .start_line = log_file_start_line,
  .end_line = NULL,
  .flush = flush_log_file,
  .close = close_log_file
};

DEFINE_LOG_OUTPUT(&static_log_output);
