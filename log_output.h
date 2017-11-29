/*
Serval DNA log output
Copyright (C) 2017 Flinders University
 
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

#ifndef __SERVAL_DNA__LOG_OUTPUT_H
#define __SERVAL_DNA__LOG_OUTPUT_H

#include <sys/time.h> // for struct timeval
#include <time.h> // for struct tm
#include <stdarg.h> // for va_list
#include "lang.h" // for bool_t and _APPEND()
#include "section.h"
#include "xprintf.h"

struct log_output_iterator;

/* The log_output structure represents a single log output.  The logging
 * primitives defined in "log.h" iterate over these, so every log message is
 * sent to all available outputs.
 *
 * Each log output is represented by an instance of this struct.  The instance
 * persists for the lifetime of the process (eg, while the daemon is running),
 * and is not stored anywhere else.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
struct log_output {
  // Configuration:
  //   the minimum level logged by this output:
  int (*minimum_level)(const struct log_output *out);
  //   whether to include the Process ID in each output line:
  bool_t (*show_pid)(const struct log_output *out);
  //   whether to include the time in each output line:
  bool_t (*show_time)(const struct log_output *out);

  // State:
  //   pointer to output-specific state:
  void *state;
  //   the time stamp of the most recently logged message, used to detect when
  //   the date advances so that the date can be logged:
  struct tm last_tm;
  //   a flag to prevent recursion into the open() operation
  bool_t opening;

  // Operations:
  //
  //   Perform any setup necessary to commence outputting log messages, eg,
  //   set/update the config items above, create/rename/open files, allocate
  //   buffers, connect to server etc.; may invoke vlogMessage(), so must
  //   handle re-entry; open() gets called at the start of every call to the
  //   vlogMessage() primitive, before start_line() is called.
  void (*open)(struct log_output_iterator *it);

  //   If *capture is 0 and the output is of a persistent nature (eg, a file or
  //   system log) and is able to redirect data written to the given file
  //   descriptor to its output, then do so and set *capture to 1.
  void (*capture_fd)(struct log_output_iterator *it, int fd, bool_t *capture);

  //   Test whether output is able to handle messages; if it returns false then
  //   start_line() and end_line() will not be invoked.
  bool_t (*is_available)(const struct log_output_iterator *it);

  //   Start outputting a new line at the given level, which may involve
  //   printing a prefix to indicate the level; return an XPRINTF which can be
  //   used to print the rest of the line.
  void (*start_line)(struct log_output_iterator *it, int level);

  //   Finish outputting a line already started with start_line(), which may involve
  //   writing a suffix, but flushing should only be done by flush(), so that
  //   multi-line messages can be output with only a single flush at the end
  void (*end_line)(struct log_output_iterator *it, int level);

  //   Ensure that any buffered log output has been output; if the process were to
  //   terminate after this, the last line logged would not be lost.
  void (*flush)(struct log_output_iterator *it);

  //   Release any resources currently held by the logger without flushing, so
  //   that the next open() called in the child will re-acquire resources; this
  //   is called in a newly-forked child process to ensure that buffered log
  //   messages do not get output twice and that the child and parent do not
  //   fight over file descriptors or sockets etc.
  void (*close)(struct log_output_iterator *it);
};

/* log_output_iterator is a transient structure that is used to iterate over all the
 * log outputs.  Generally, one of these is created (as an auto variable) every
 * time a log message is generated, and destroyed immediately after the message
 * has been sent to all the log outputs.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
struct log_output_iterator {
  // State:
  struct log_output *const *output;
  // The time at which the log message is generated, in two formats:
  struct timeval tv;
  struct tm tm;
  // The xprintf() handle used to construct the log message:
  XPRINTF xpf;
};

/* Log outputters are included into an executable just by linking them in;
 * "section.h" allows the logger to iterate through them all.
 *
 * There are several ways of linking an outputter into an executable: (1) the
 * log_output_xxx.o object files can be explicitly listed on the link
 * command-line, or (2) they can be put into a library and dragged into the
 * executable by referencing them explicitly somehow, such as the "feature.h"
 * mechanism.
 */
DECLARE_SECTION(struct log_output *, logoutput);

#define DEFINE_LOG_OUTPUT(LOG_OUTPUT) \
  static struct log_output * _APPEND(__log_output, __LINE__) IN_SECTION(logoutput) = (LOG_OUTPUT)

#define LOG_OUTPUT_COUNT (SECTION_START(logoutput) - SECTION_END(logoutput))

/* Functions for use by log outputters.  These form the "private" or "backend" API of
 * the logging system.
 */

const char *serval_log_level_prefix_string(int level);

void serval_log_output_iterator_printf_nl(struct log_output_iterator *it, int level, const char *fmt, ...);
void serval_log_output_iterator_vprintf_nl(struct log_output_iterator *it, int level, const char *fmt, va_list ap);

void serval_log_print_prolog(struct log_output_iterator *it);

#endif // __SERVAL_DNA__LOG_OUTPUT_H
