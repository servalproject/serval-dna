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
