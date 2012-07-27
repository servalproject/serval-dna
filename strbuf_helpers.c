/*
Serval string buffer helper functions.
Copyright (C) 2012 The Serval Project

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

#include "strbuf_helpers.h"
#include <poll.h>
#include <ctype.h>
#include <string.h>
#include <sys/wait.h>

static inline strbuf _toprint(strbuf sb, char c)
{
  if (c == '\0')
    strbuf_puts(sb, "\\0");
  else if (c == '\n')
    strbuf_puts(sb, "\\n");
  else if (c == '\r')
    strbuf_puts(sb, "\\r");
  else if (c == '\t')
    strbuf_puts(sb, "\\t");
  else if (c == '\\')
    strbuf_puts(sb, "\\\\");
  else if (c >= ' ' && c <= '~')
    strbuf_putc(sb, c);
  else
    strbuf_sprintf(sb, "\\x%02x", c);
  return sb;
}

static strbuf inline _overrun(strbuf sb, const char *suffix)
{
  if (strbuf_overrun(sb)) {
    strbuf_trunc(sb, -strlen(suffix));
    strbuf_puts(sb, suffix);
  }
  return sb;
}

static strbuf inline _overrun_quote(strbuf sb, char quote, const char *suffix)
{
  if (strbuf_overrun(sb)) {
    strbuf_trunc(sb, -strlen(suffix) - 1);
    strbuf_putc(sb, quote);
    strbuf_puts(sb, suffix);
  }
  return sb;
}

strbuf strbuf_toprint_len(strbuf sb, const char *buf, size_t len)
{
  for (; len && !strbuf_overrun(sb); ++buf, --len)
    _toprint(sb, *buf);
  return _overrun(sb, "...");
}

strbuf strbuf_toprint(strbuf sb, const char *str)
{
  for (; *str && !strbuf_overrun(sb); ++str)
    _toprint(sb, *str);
  return _overrun(sb, "...");
}

strbuf strbuf_toprint_quoted_len(strbuf sb, char quote, const char *buf, size_t len)
{
  strbuf_putc(sb, quote);
  for (; len && !strbuf_overrun(sb); ++buf, --len)
    if (*buf == quote) {
      strbuf_putc(sb, '\\');
      strbuf_putc(sb, quote);
    } else
      _toprint(sb, *buf);
  strbuf_putc(sb, quote);
  return _overrun_quote(sb, quote, "...");
}

strbuf strbuf_toprint_quoted(strbuf sb, char quote, const char *str)
{
  strbuf_putc(sb, quote);
  for (; *str && !strbuf_overrun(sb); ++str)
    if (*str == quote) {
      strbuf_putc(sb, '\\');
      strbuf_putc(sb, quote);
    } else
      _toprint(sb, *str);
  strbuf_putc(sb, quote);
  return _overrun_quote(sb, quote, "...");
}

strbuf strbuf_append_poll_events(strbuf sb, short events)
{
  static struct { short flags; const char *name; } symbols[] = {
      { POLLIN, "IN" },
      { POLLPRI, "PRI" },
      { POLLOUT, "OUT" },
      { POLLERR, "ERR" },
      { POLLHUP, "HUP" },
      { POLLNVAL, "NVAL" },
      { POLLRDNORM, "RDNORM" },
      { POLLRDBAND, "RDBAND" },
#ifdef POLLWRNORM
      { POLLWRNORM, "WRNORM" },
#endif
#ifdef POLLWRBAND
      { POLLWRBAND, "WRBAND" },
#endif
#ifdef POLLMSG
      { POLLMSG, "MSG" },
#endif
#ifdef POLLREMOVE
      { POLLREMOVE, "REMOVE" },
#endif
#ifdef POLLRDHUP
      { POLLRDHUP, "RDHUP" },
#endif
      { 0, NULL }
    }, *sp;
  int n = 0;
  for (sp = symbols; sp->name; ++sp) {
    if (events & sp->flags) {
      if (n)
	strbuf_putc(sb, '|');
      strbuf_puts(sb, sp->name);
      ++n;
    }
  }
  if (!n)
    strbuf_putc(sb, '0');
  return sb;
}

static int is_shellmeta(char c)
{
  return !(isalnum(c) || c == '.' || c == '-' || c == '/' || c == ':' || c == '+' || c == '_' || c == ',');
}

strbuf strbuf_append_shell_quote(strbuf sb, const char *word)
{
  strbuf_putc(sb, '\'');
  const char *p;
  for (p = word; *p; ++p)
    if (*p == '\'')
      strbuf_puts(sb, "'\\''");
    else
      strbuf_putc(sb, *p);
  strbuf_putc(sb, '\'');
  return sb;
}

strbuf strbuf_append_shell_quotemeta(strbuf sb, const char *word)
{
  const char *p;
  int hasmeta = 0;
  for (p = word; *p && !hasmeta; ++p)
    if (is_shellmeta(*p))
      hasmeta = 1;
  if (!word[0] || hasmeta)
    strbuf_append_shell_quote(sb, word);
  else
    strbuf_puts(sb, word);
  return sb;
}

strbuf strbuf_append_exit_status(strbuf sb, int status)
{
  if (WIFEXITED(status))
    strbuf_sprintf(sb, "exited normally with status %u", WEXITSTATUS(status));
  else if (WIFSIGNALED(status)) {
    strbuf_sprintf(sb, "terminated by signal %u (%s)", WTERMSIG(status), strsignal(WTERMSIG(status)));
#ifdef WCOREDUMP
    if (WCOREDUMP(status))
      strbuf_puts(sb, " and dumped core");
#endif
  } else if (WIFSTOPPED(status))
    strbuf_sprintf(sb, "stopped by signal %u (%s)", WSTOPSIG(status), strsignal(WSTOPSIG(status)));
#ifdef WIFCONTINUED
  else if (WIFCONTINUED(status))
    strbuf_sprintf(sb, "continued by signal %u (SIGCONT)", SIGCONT);
#endif
  return sb;
}
