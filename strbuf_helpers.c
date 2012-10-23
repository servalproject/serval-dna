/*
Serval string buffer helper functions.
Copyright (C) 2012 Serval Project Inc.

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
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

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
    strbuf_sprintf(sb, "\\x%02x", (unsigned char) c);
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
    strbuf_trunc(sb, -strlen(suffix) - (quote ? 1 : 0));
    if (quote)
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

strbuf strbuf_toprint_quoted_len(strbuf sb, const char quotes[2], const char *buf, size_t len)
{
  if (quotes && quotes[0])
    strbuf_putc(sb, quotes[0]);
  for (; len && !strbuf_overrun(sb); ++buf, --len)
    if (quotes && *buf == quotes[1]) {
      strbuf_putc(sb, '\\');
      strbuf_putc(sb, *buf);
    } else
      _toprint(sb, *buf);
  if (quotes && quotes[1])
    strbuf_putc(sb, quotes[1]);
  return _overrun_quote(sb, quotes ? quotes[1] : '\0', "...");
}

strbuf strbuf_toprint_quoted(strbuf sb, const char quotes[2], const char *str)
{
  if (quotes && quotes[0])
    strbuf_putc(sb, quotes[0]);
  for (; *str && !strbuf_overrun(sb); ++str)
    if (quotes && *str == quotes[1]) {
      strbuf_putc(sb, '\\');
      strbuf_putc(sb, *str);
    } else
      _toprint(sb, *str);
  if (quotes && quotes[1])
    strbuf_putc(sb, quotes[1]);
  return _overrun_quote(sb, quotes ? quotes[1] : '\0', "...");
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

strbuf strbuf_append_sockaddr(strbuf sb, const struct sockaddr *addr)
{
  const char *fam = NULL;
  switch (addr->sa_family) {
  case AF_UNSPEC:    fam = "AF_UNSPEC"; break;
  case AF_UNIX:	     fam = "AF_UNIX"; break;
  case AF_INET:	     fam = "AF_INET"; break;
  case AF_AX25:	     fam = "AF_AX25"; break;
  case AF_IPX:	     fam = "AF_IPX"; break;
  case AF_APPLETALK: fam = "AF_APPLETALK"; break;
  case AF_NETROM:    fam = "AF_NETROM"; break;
  case AF_BRIDGE:    fam = "AF_BRIDGE"; break;
  case AF_ATMPVC:    fam = "AF_ATMPVC"; break;
  case AF_X25:	     fam = "AF_X25"; break;
  case AF_INET6:     fam = "AF_INET6"; break;
  case AF_ROSE:	     fam = "AF_ROSE"; break;
  case AF_DECnet:    fam = "AF_DECnet"; break;
  case AF_NETBEUI:   fam = "AF_NETBEUI"; break;
  case AF_SECURITY:  fam = "AF_SECURITY"; break;
  case AF_KEY:	     fam = "AF_KEY"; break;
  case AF_NETLINK:   fam = "AF_NETLINK"; break;
  case AF_PACKET:    fam = "AF_PACKET"; break;
  case AF_ASH:	     fam = "AF_ASH"; break;
  case AF_ECONET:    fam = "AF_ECONET"; break;
  case AF_ATMSVC:    fam = "AF_ATMSVC"; break;
  case AF_SNA:	     fam = "AF_SNA"; break;
  case AF_IRDA:	     fam = "AF_IRDA"; break;
  case AF_PPPOX:     fam = "AF_PPPOX"; break;
  case AF_WANPIPE:   fam = "AF_WANPIPE"; break;
  case AF_LLC:	     fam = "AF_LLC"; break;
  case AF_TIPC:	     fam = "AF_TIPC"; break;
  case AF_BLUETOOTH: fam = "AF_BLUETOOTH"; break;
  }
  if (fam)
    strbuf_puts(sb, fam);
  else
    strbuf_sprintf(sb, "[%d]", addr->sa_family);
  switch (addr->sa_family) {
  case AF_UNIX:
    strbuf_putc(sb, ' ');
    if (addr->sa_data[0])
      strbuf_toprint_quoted_len(sb, addr->sa_data, "\"\"", sizeof addr->sa_data);
    else {
      strbuf_puts(sb, "abstract ");
      strbuf_toprint_quoted_len(sb, addr->sa_data, "\"\"", sizeof addr->sa_data);
    }
    break;
  case AF_INET: {
      const struct sockaddr_in *addr_in = (const struct sockaddr_in *) addr;
      strbuf_sprintf(sb, " %u.%u.%u.%u:%u",
	  ((unsigned char *) &addr_in->sin_addr.s_addr)[0],
	  ((unsigned char *) &addr_in->sin_addr.s_addr)[1],
	  ((unsigned char *) &addr_in->sin_addr.s_addr)[2],
	  ((unsigned char *) &addr_in->sin_addr.s_addr)[3],
	  ntohs(addr_in->sin_port)
	);
    }
    break;
  default: {
      int i;
      for (i = 0; i < sizeof addr->sa_data; ++i)
	strbuf_sprintf(sb, " %02x", addr->sa_data[i]);
    }
    break;
  }
  return sb;
}
