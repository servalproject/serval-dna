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

/*
  Portions Copyright (C) 2013 Petter Reinholdtsen
  Some rights reserved

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
  FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
  COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.
*/

#include <ctype.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <stdarg.h>
#include <inttypes.h>
#include <sys/wait.h>
#ifdef HAVE_POLL_H
#include <poll.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#include <sys/uio.h>
#include <sys/socket.h>
#include <netdb.h>
#include "http_server.h"
#include "strbuf_helpers.h"
#include "str.h"
#include "socket.h"
#include "whence.h"

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

inline static strbuf _overrun(strbuf sb, const char *suffix)
{
  if (strbuf_overrun(sb)) {
    strbuf_trunc(sb, -strlen(suffix));
    strbuf_puts(sb, suffix);
  }
  return sb;
}

inline static strbuf _overrun_quote(strbuf sb, char quote, const char *suffix)
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

strbuf strbuf_append_sourceloc(strbuf sb, struct __sourceloc loc)
{
  xprint_sourceloc(XPRINTF_STRBUF(sb), loc);
  return sb;
}

strbuf strbuf_path_join(strbuf sb, ...)
{
  va_list ap;
  va_start(ap, sb);
  const char *segment;
  while ((segment = va_arg(ap, const char*))) {
    if (segment[0] == '/')
      strbuf_reset(sb);
    else if (strbuf_len(sb) && *strbuf_substr(sb, -1) != '/')
      strbuf_putc(sb, '/');
    strbuf_puts(sb, segment);
  }
  va_end(ap);
  return sb;
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

strbuf strbuf_append_argv(strbuf sb, int argc, const char *const *argv)
{
  int i;
  for (i = 0; i < argc; ++i) {
    if (i)
      strbuf_putc(sb, ' ');
    if (argv[i])
      strbuf_toprint_quoted(sb, "\"\"", argv[i]);
    else
      strbuf_puts(sb, "NULL");
  }
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

strbuf strbuf_append_socket_domain(strbuf sb, int domain)
{
  const char *fam = NULL;
  switch (domain) {
  case AF_UNSPEC:    fam = "AF_UNSPEC"; break;
  case AF_UNIX:	     fam = "AF_UNIX"; break;
  case AF_INET:	     fam = "AF_INET"; break;
#if 0
  // These values are not used in Serval, yet.
  case AF_BLUETOOTH: fam = "AF_BLUETOOTH"; break;
  case AF_INET6:     fam = "AF_INET6"; break;
  // These values will probably never be used in Serval.
  case AF_AX25:	     fam = "AF_AX25"; break;
  case AF_IPX:	     fam = "AF_IPX"; break;
  case AF_APPLETALK: fam = "AF_APPLETALK"; break;
  case AF_NETROM:    fam = "AF_NETROM"; break;
  case AF_BRIDGE:    fam = "AF_BRIDGE"; break;
  case AF_ATMPVC:    fam = "AF_ATMPVC"; break;
  case AF_X25:	     fam = "AF_X25"; break;
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
#endif
  }
  if (fam)
    strbuf_puts(sb, fam);
  else
    strbuf_sprintf(sb, "[%d]", domain);
  return sb;
}

strbuf strbuf_append_signal_name(strbuf sb, int signal)
{
  const char *desc = "";
  switch(signal) {
#ifdef SIGHUP
  case SIGHUP: desc = "HUP"; break;
#endif
#ifdef SIGINT
  case SIGINT: desc = "INT"; break;
#endif
#ifdef SIGQUIT
  case SIGQUIT: desc = "QUIT"; break;
#endif
#ifdef SIGILL
  case SIGILL: desc = "ILL (not reset when caught)"; break;
#endif
#ifdef SIGTRAP
  case SIGTRAP: desc = "TRAP (not reset when caught)"; break;
#endif
#ifdef SIGABRT
  case SIGABRT: desc = "ABRT"; break;
#endif
#ifdef SIGPOLL
  case SIGPOLL: desc = "POLL ([XSR] generated, not supported)"; break;
#endif
#ifdef SIGEMT
  case SIGEMT: desc = "EMT"; break;
#endif
#ifdef SIGFPE
  case SIGFPE: desc = "FPE"; break;
#endif
#ifdef SIGKILL
  case SIGKILL: desc = "KILL (cannot be caught or ignored)"; break;
#endif
#ifdef SIGBUS
  case SIGBUS: desc = "BUS"; break;
#endif
#ifdef SIGSEGV
  case SIGSEGV: desc = "SEGV"; break;
#endif
#ifdef SIGSYS
  case SIGSYS: desc = "SYS"; break;
#endif
#ifdef SIGPIPE
  case SIGPIPE: desc = "PIPE"; break;
#endif
#ifdef SIGALRM
  case SIGALRM: desc = "ALRM"; break;
#endif
#ifdef SIGTERM
  case SIGTERM: desc = "TERM"; break;
#endif
#ifdef SIGURG
  case SIGURG: desc = "URG"; break;
#endif
#ifdef SIGSTOP
  case SIGSTOP: desc = "STOP"; break;
#endif
#ifdef SIGTSTP
  case SIGTSTP: desc = "TSTP"; break;
#endif
#ifdef SIGCONT
  case SIGCONT: desc = "CONT"; break;
#endif
#ifdef SIGCHLD
  case SIGCHLD: desc = "CHLD"; break;
#endif
#ifdef SIGTTIN
  case SIGTTIN: desc = "TTIN"; break;
#endif
#ifdef SIGTTOU
  case SIGTTOU: desc = "TTOU"; break;
#endif
#ifdef SIGIO
#if SIGIO != SIGPOLL          
  case SIGIO: desc = "IO"; break;
#endif
#endif
#ifdef SIGXCPU
  case SIGXCPU: desc = "XCPU"; break;
#endif
#ifdef SIGXFSZ
  case SIGXFSZ: desc = "XFSZ"; break;
#endif
#ifdef SIGVTALRM
  case SIGVTALRM: desc = "VTALRM"; break;
#endif
#ifdef SIGPROF
  case SIGPROF: desc = "PROF"; break;
#endif
#ifdef SIGWINCH
  case SIGWINCH: desc = "WINCH"; break;
#endif
#ifdef SIGINFO
  case SIGINFO: desc = "INFO"; break;
#endif
#ifdef SIGUSR1
  case SIGUSR1: desc = "USR1"; break;
#endif
#ifdef SIGUSR2
  case SIGUSR2: desc = "USR2"; break;
#endif
  }
  strbuf_sprintf(sb, "SIG%s (%d) %s", desc, signal, strsignal(signal));
  return sb;
}

strbuf strbuf_append_socket_type(strbuf sb, int type)
{
  const char *typ = NULL;
  switch (type) {
  case SOCK_STREAM:	typ = "SOCK_STREAM"; break;
  case SOCK_DGRAM:	typ = "SOCK_DGRAM"; break;
#ifdef SOCK_RAW
  case SOCK_RAW:	typ = "SOCK_RAW"; break;
#endif
#ifdef SOCK_RDM
  case SOCK_RDM:	typ = "SOCK_RDM"; break;
#endif
#ifdef SOCK_SEQPACKET
  case SOCK_SEQPACKET:	typ = "SOCK_SEQPACKET"; break;
#endif
#ifdef SOCK_PACKET
  case SOCK_PACKET:	typ = "SOCK_PACKET"; break;
#endif
  }
  if (typ)
    strbuf_puts(sb, typ);
  else
    strbuf_sprintf(sb, "[%d]", type);
  return sb;
}

strbuf strbuf_append_in_addr(strbuf sb, const struct in_addr *addr)
{
  strbuf_sprintf(sb, "%u.%u.%u.%u",
      ((unsigned char *) &addr->s_addr)[0],
      ((unsigned char *) &addr->s_addr)[1],
      ((unsigned char *) &addr->s_addr)[2],
      ((unsigned char *) &addr->s_addr)[3]);
  return sb;
}

strbuf strbuf_append_sockaddr(strbuf sb, const struct sockaddr *addr, socklen_t addrlen)
{
  switch (addr->sa_family) {
  case AF_UNIX: {
      strbuf_puts(sb, "AF_UNIX:");
      size_t len = addrlen > sizeof addr->sa_family ? addrlen - sizeof addr->sa_family : 0;
      if (addr->sa_data[0]) {
	strbuf_toprint_quoted_len(sb, "\"\"", addr->sa_data, len);
	if (len < 2)
	  strbuf_sprintf(sb, " (addrlen=%d too short)", (int)addrlen);
	if (len == 0 || addr->sa_data[len - 1] != '\0')
	  strbuf_sprintf(sb, " (addrlen=%d, no nul terminator)", (int)addrlen);
      } else {
	strbuf_puts(sb, "abstract ");
	strbuf_toprint_quoted_len(sb, "\"\"", addr->sa_data, len);
	if (len == 0)
	  strbuf_sprintf(sb, " (addrlen=%d too short)", (int)addrlen);
      }
    }
    break;
  case AF_INET:
  case AF_INET6:{
    char name[INET6_ADDRSTRLEN];
    char service[6];
    
    if (getnameinfo(addr, addrlen, name, sizeof name, service, sizeof service, NI_NUMERICHOST|NI_NUMERICSERV)==0){
      strbuf_sprintf(sb, "%s:%s:%s", 
	addr->sa_family==AF_INET?"AF_INET":"AF_INET6", 
	name, 
	service);
      break;
    }
    // fall through
  }
  default: {
      strbuf_append_socket_domain(sb, addr->sa_family);
      size_t len = addrlen > sizeof addr->sa_family ? addrlen - sizeof addr->sa_family : 0;
      unsigned i;
      for (i = 0; i < len; ++i) {
	strbuf_putc(sb, i ? ',' : ':');
	strbuf_sprintf(sb, "%02x", addr->sa_data[i]);
      }
    }
    break;
  }
  return sb;
}

strbuf strbuf_append_socket_address(strbuf sb, const struct socket_address *addr)
{
  return strbuf_append_sockaddr(sb, &addr->addr, addr->addrlen);
}

strbuf strbuf_append_fragmented_data(strbuf sb, const struct fragmented_data *data)
{
  return strbuf_append_iovec(sb, data->iov, data->fragment_count);
}

strbuf strbuf_append_strftime(strbuf sb, const char *format, const struct tm *tm)
{
  // First, try calling strftime(3) directly on the buffer in the strbuf, if there is one and it
  // looks to be long enough.
  const size_t need = strlen(format); // heuristic, could be better
  if (strbuf_str(sb)) {
    size_t avail = strbuf_remaining(sb);
    if (avail > need) {
      size_t n = strftime(strbuf_end(sb), avail + 1, format, tm);
      if (n) {
	assert(n <= avail);
	sb->current += n;
	return sb;
      }
    }
  }
  // If that didn't work, then call strftime(3) on a temporary buffer and concatenate the result
  // into the strbuf.
  const size_t len = 500; // should be enough
  char *buf = alloca(len + 1);
  size_t n = strftime(buf, len + 1, format, tm);
  strbuf_ncat(sb, buf, n);
  return sb;
}

strbuf strbuf_append_iovec(strbuf sb, const struct iovec *iov, int iovcnt)
{
  int i;
  strbuf_putc(sb, '[');
  for (i = 0; i < iovcnt; ++i) {
    if (i)
      strbuf_puts(sb, ", ");
    strbuf_sprintf(sb, "%p#%zu", iov[i].iov_base, iov[i].iov_len);
  }
  strbuf_putc(sb, ']');
  return sb;
}

strbuf strbuf_append_time_t(strbuf sb, time_t time)
{
  struct tm tm;
  localtime_r(&time, &tm);
  strbuf_append_strftime(sb, "%Y/%m/%d %H:%M:%S %z", &tm);
  return sb;
}

strbuf strbuf_append_time_ms_t(strbuf sb, time_ms_t ms)
{
  struct tm tm;
  time_t time = ms / 1000;
  localtime_r(&time, &tm);
  strbuf_append_strftime(sb, "%Y/%m/%d %H:%M:%S", &tm);
  strbuf_sprintf(sb, ".%.03u", (unsigned)(ms % 1000));
  strbuf_append_strftime(sb, " %z", &tm);
  return sb;
}

strbuf strbuf_append_timeval(strbuf sb, const struct timeval *tv)
{
  if (tv->tv_sec < 0 || tv->tv_usec < 0 || tv->tv_usec > 999999) {
    strbuf_sprintf(sb, "INVALID{tv_sec=%ld,tv_usec=%ld}", (long)tv->tv_sec, (long)tv->tv_usec);
  } else {
    struct tm tm;
    localtime_r(&tv->tv_sec, &tm);
    strbuf_append_strftime(sb, "%Y/%m/%d %H:%M:%S", &tm);
    strbuf_sprintf(sb, ".%.06lu", (long)tv->tv_usec);
    strbuf_append_strftime(sb, " %z", &tm);
  }
  return sb;
}

strbuf strbuf_append_timespec(strbuf sb, const struct timespec *tv)
{
  if (tv->tv_sec < 0 || tv->tv_nsec < 0 || tv->tv_nsec > 999999999) {
    strbuf_sprintf(sb, "INVALID{tv_sec=%ld,tv_nsec=%ld}", (long)tv->tv_sec, tv->tv_nsec);
  } else {
    struct tm tm;
    localtime_r(&tv->tv_sec, &tm);
    strbuf_append_strftime(sb, "%Y/%m/%d %H:%M:%S", &tm);
    strbuf_sprintf(sb, ".%.09lu", tv->tv_nsec);
    strbuf_append_strftime(sb, " %z", &tm);
  }
  return sb;
}

strbuf strbuf_append_file_meta(strbuf sb, const struct file_meta *metap)
{
  strbuf_puts(sb, "{ .mtime=");
  strbuf_append_timespec(sb, &metap->mtime);
  strbuf_sprintf(sb, ", .size=%ld }", (long)metap->size);
  return sb;
}

strbuf strbuf_append_quoted_string(strbuf sb, const char *str)
{
  strbuf_putc(sb, '"');
  for (; *str; ++str) {
    if (*str == '"' || *str == '\\')
      strbuf_putc(sb, '\\');
    strbuf_putc(sb, *str);
  }
  strbuf_putc(sb, '"');
  return sb;
}

static void _html_char(strbuf sb, char c)
{
  if (c == '&')
    strbuf_puts(sb, "&amp;");
  else if (c == '<')
    strbuf_puts(sb, "&lt;");
  else if (c == '>')
    strbuf_puts(sb, "&gt;");
  else if (c == '"')
    strbuf_puts(sb, "&quot;");
  else if (c == '\'')
    strbuf_puts(sb, "&apos;");
  else if (iscntrl(c))
    strbuf_sprintf(sb, "&#%u;", (unsigned char) c);
  else
    strbuf_putc(sb, c);
}

strbuf strbuf_html_escape(strbuf sb, const char *str, size_t strlen)
{
  for (; strlen; --strlen, ++str)
    _html_char(sb, *str);
  return sb;
}

strbuf strbuf_json_null(strbuf sb)
{
  strbuf_puts(sb, "null");
  return sb;
}

strbuf strbuf_json_boolean(strbuf sb, int boolean)
{
  strbuf_puts(sb, boolean ? "true" : "false");
  return sb;
}

static const uint32_t offsetsFromUTF8[6] = {
  0x00000000UL, 0x00003080UL, 0x000E2080UL,
  0x03C82080UL, 0xFA082080UL, 0x82082080UL
};

// is start of UTF sequence
static uint8_t isutf(char c) {
  return (c & 0xC0) != 0x80;
}

static uint32_t u8_nextchar(const char *s, unsigned *i)
{
  if (!s[*i])
    return 0;
    
  uint32_t ch = 0;
  int sz = 0;

  do {
    ch <<= 6;
    ch += (unsigned char)s[(*i)++];
    sz++;
  } while (s[*i] && !isutf(s[*i]));
  ch -= offsetsFromUTF8[sz-1];

  return ch;
}

static void _json_char(strbuf sb, uint32_t c)
{
  if (c == '"' || c == '\\') {
    strbuf_putc(sb, '\\');
    strbuf_putc(sb, c);
  }
  else if (c == '\b')
    strbuf_puts(sb, "\\b");
  else if (c == '\f')
    strbuf_puts(sb, "\\f");
  else if (c == '\n')
    strbuf_puts(sb, "\\n");
  else if (c == '\r')
    strbuf_puts(sb, "\\r");
  else if (c == '\t')
    strbuf_puts(sb, "\\t");
  else if (c>0x7f || iscntrl(c))
    strbuf_sprintf(sb, "\\u%04X", c);
  else
    strbuf_putc(sb, c);
}

strbuf strbuf_json_string(strbuf sb, const char *str)
{
  if (str) {
    strbuf_putc(sb, '"');
    unsigned pos=0;
    uint32_t c;
    while((c = u8_nextchar(str, &pos)))
      _json_char(sb, c);
    strbuf_putc(sb, '"');
  } else
    strbuf_json_null(sb);
  return sb;
}

strbuf strbuf_json_string_len(strbuf sb, const char *str, size_t strlen)
{
  if (str && strlen){
    strbuf_putc(sb, '"');
    unsigned pos=0;
    uint32_t c;
    while(pos<strlen && (c = u8_nextchar(str, &pos)))
      _json_char(sb, c);
    strbuf_putc(sb, '"');
  } else
    strbuf_json_null(sb);
  return sb;
}

strbuf strbuf_json_hex(strbuf sb, const unsigned char *buf, size_t len)
{
  if (buf) {
    strbuf_putc(sb, '"');
    size_t i;
    for (i = 0; i != len; ++i) {
      strbuf_putc(sb, hexdigit_upper[*buf >> 4]);
      strbuf_putc(sb, hexdigit_upper[*buf++ & 0xf]);
    }
    strbuf_putc(sb, '"');
  } else
    strbuf_json_null(sb);
  return sb;
}

strbuf strbuf_json_atom(strbuf sb, const struct json_atom *atom)
{
  switch (atom->type) {
    case JSON_NULL:
      return strbuf_json_null(sb);
    case JSON_BOOLEAN:
      return strbuf_json_boolean(sb, atom->u.boolean);
    case JSON_INTEGER:
      strbuf_sprintf(sb, "%"PRId64, atom->u.integer);
      return sb;
    case JSON_STRING_NULTERM:
      return strbuf_json_string(sb, atom->u.string.content);
    case JSON_STRING_LENGTH:
      return strbuf_json_string_len(sb, atom->u.string.content, atom->u.string.length);
    case JSON_OBJECT: {
	strbuf_putc(sb, '{');
	size_t i;
	for (i = 0; i != atom->u.object.itemc; ++i) {
	  if (i)
	    strbuf_putc(sb, ',');
	  strbuf_json_string(sb, atom->u.object.itemv[i].key);
	  strbuf_putc(sb, ':');
	  strbuf_json_atom(sb, atom->u.object.itemv[i].value);
	}
	strbuf_putc(sb, '}');
	return sb;
      }
    case JSON_ARRAY: {
	strbuf_putc(sb, '[');
	size_t i;
	for (i = 0; i != atom->u.array.itemc; ++i) {
	  if (i)
	    strbuf_putc(sb, ',');
	  strbuf_json_atom(sb, atom->u.array.itemv[i]);
	}
	strbuf_putc(sb, ']');
	return sb;
      }
  }
  abort();
}

static strbuf strbuf_puts_repeat(strbuf sb, const char *text, size_t repeat)
{
  size_t i;
  for (i = 0; i != repeat; ++i)
    strbuf_puts(sb, text);
  return sb;
}

static strbuf strbuf_json_atom_as_text_indented(strbuf sb, const struct json_atom *atom, const char *eol, const char *tab, unsigned indent)
{
  switch (atom->type) {
    case JSON_NULL:
      return strbuf_json_null(sb);
    case JSON_BOOLEAN:
      return strbuf_puts(sb, atom->u.boolean ? "True" : "False");
    case JSON_INTEGER:
      strbuf_sprintf(sb, "%"PRId64, atom->u.integer);
      return sb;
    case JSON_STRING_NULTERM:
      return strbuf_puts(sb, atom->u.string.content);
    case JSON_STRING_LENGTH:
      return strbuf_ncat(sb, atom->u.string.content, atom->u.string.length);
    case JSON_OBJECT: {
	strbuf_puts(sb, "{");
	size_t i;
	for (i = 0; i != atom->u.object.itemc; ++i) {
	  strbuf_puts(sb, eol);
	  strbuf_puts_repeat(sb, tab, indent);
	  strbuf_puts(sb, atom->u.object.itemv[i].key);
	  strbuf_puts(sb, ": ");
	  strbuf_json_atom_as_text_indented(sb, atom->u.object.itemv[i].value, eol, tab, indent + 1);
	}
	if (i) {
	  strbuf_puts(sb, eol);
	  strbuf_puts_repeat(sb, tab, indent);
	}
	strbuf_puts(sb, "}");
	return sb;
      }
    case JSON_ARRAY: {
	strbuf_puts(sb, "[");
	size_t i;
	for (i = 0; i != atom->u.array.itemc; ++i) {
	  if (i)
	    strbuf_puts(sb, ", ");
	  strbuf_json_atom_as_text_indented(sb, atom->u.array.itemv[i], eol, tab, indent + 1);
	}
	strbuf_puts(sb, "]");
	return sb;
      }
  }
  abort();
}

strbuf strbuf_json_atom_as_text(strbuf sb, const struct json_atom *atom, const char *eol)
{
  return strbuf_json_atom_as_text_indented(sb, atom, eol, "   ", 0);
}

strbuf strbuf_json_atom_as_html(strbuf sb, const struct json_atom *atom)
{
  switch (atom->type) {
    case JSON_NULL:
      return strbuf_json_null(sb);
    case JSON_BOOLEAN:
      return strbuf_json_boolean(sb, atom->u.boolean);
    case JSON_INTEGER:
      strbuf_sprintf(sb, "%"PRId64, atom->u.integer);
      return sb;
    case JSON_STRING_NULTERM:
      return strbuf_html_escape(sb, atom->u.string.content, strlen(atom->u.string.content));
    case JSON_STRING_LENGTH:
      return strbuf_html_escape(sb, atom->u.string.content, atom->u.string.length);
    case JSON_OBJECT: {
	strbuf_puts(sb, "<dl>");
	size_t i;
	for (i = 0; i != atom->u.object.itemc; ++i) {
	strbuf_puts(sb, "\n<dt>");
	  strbuf_html_escape(sb, atom->u.object.itemv[i].key, strlen(atom->u.object.itemv[i].key));
	  strbuf_puts(sb, "</dt><dd>");
	  strbuf_json_atom_as_html(sb, atom->u.object.itemv[i].value);
	  strbuf_puts(sb, "</dd>");
	}
	strbuf_puts(sb, "\n</dl>");
	return sb;
      }
    case JSON_ARRAY: {
	strbuf_puts(sb, "<ol>");
	size_t i;
	for (i = 0; i != atom->u.array.itemc; ++i) {
	  strbuf_puts(sb, "\n<li>");
	  strbuf_json_atom_as_html(sb, atom->u.array.itemv[i]);
	  strbuf_puts(sb, "</li>");
	}
	strbuf_puts(sb, "\n</ol>");
	return sb;
      }
  }
  abort();
}

strbuf strbuf_append_http_ranges(strbuf sb, const struct http_range *ranges, unsigned nels)
{
  unsigned i;
  int first = 1;
  for (i = 0; i != nels; ++i) {
    const struct http_range *r = &ranges[i];
    switch (r->type) {
      case NIL: break;
      case CLOSED:
	strbuf_sprintf(sb, "%s%"PRIhttp_size_t"-%"PRIhttp_size_t, first ? "" : ",", r->first, r->last);
	first = 0;
	break;
      case OPEN:
	strbuf_sprintf(sb, "%s%"PRIhttp_size_t"-", first ? "" : ",", r->first);
	first = 0;
	break;
      case SUFFIX:
	strbuf_sprintf(sb, "%s-%"PRIhttp_size_t, first ? "" : ",", r->last);
	first = 0;
	break;
    }
  }
  return sb;
}

strbuf strbuf_append_mime_content_type(strbuf sb, const struct mime_content_type *ct)
{
  strbuf_puts(sb, ct->type);
  strbuf_putc(sb, '/');
  strbuf_puts(sb, ct->subtype);
  if (strlen(ct->charset) > 0) {
    strbuf_puts(sb, "; charset=");
    strbuf_append_quoted_string(sb, ct->charset);
  }
  if (strlen(ct->multipart_boundary) > 0) {
    strbuf_puts(sb, "; boundary=");
    strbuf_append_quoted_string(sb, ct->multipart_boundary);
  }
  if (strlen(ct->format) > 0) {
    strbuf_puts(sb, "; format=");
    strbuf_append_quoted_string(sb, ct->format);
  }
  return sb;
}

strbuf strbuf_append_mime_content_disposition(strbuf sb, const struct mime_content_disposition *cd)
{
  strbuf_puts(sb, cd->type);
  if (strlen(cd->name) > 0) {
    strbuf_puts(sb, "; name=");
    strbuf_append_quoted_string(sb, cd->name);
  }
  if (strlen(cd->filename) > 0) {
    strbuf_puts(sb, "; filename=");
    strbuf_append_quoted_string(sb, cd->filename);
  }
  if (cd->size)
    strbuf_sprintf(sb, "; size=%"PRIhttp_size_t, cd->size);
  struct tm tm;
  if (cd->creation_date) {
    strbuf_puts(sb, " creation_date=");
    strbuf_append_strftime(sb, "\"%a, %d %b %Y %T %z\"", gmtime_r(&cd->creation_date, &tm));
  }
  if (cd->modification_date) {
    strbuf_puts(sb, " modification_date=");
    strbuf_append_strftime(sb, "\"%a, %d %b %Y %T %z\"", gmtime_r(&cd->modification_date, &tm));
  }
  if (cd->read_date) {
    strbuf_puts(sb, " read_date=");
    strbuf_append_strftime(sb, "\"%a, %d %b %Y %T %z\"", gmtime_r(&cd->read_date, &tm));
  }
  return sb;
}
