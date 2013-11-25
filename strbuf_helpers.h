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

#ifndef __STRBUF_HELPERS_H__
#define __STRBUF_HELPERS_H__

// For socklen_t
#ifdef WIN32
#  include "win32/win32.h"
#else
#  ifdef HAVE_SYS_SOCKET_H
#    include <sys/socket.h>
#  endif
#endif

#include "strbuf.h"

/* Append a representation of the given chars in a given buffer (including nul
 * chars) in printable format, ie, with non-printable characters expanded to \n
 * \r \t \0 \\ \xHH.
 * @author Andrew Bettison <andrew@servalproject.com>
 */
strbuf strbuf_toprint_len(strbuf sb, const char *buf, size_t len);

/* Equivalent to strbuf_toprint_len(sb, str, strlen(str)).
 * @author Andrew Bettison <andrew@servalproject.com>
 */
strbuf strbuf_toprint(strbuf sb, const char *str);

/* Same as strbuf_toprint_len, but also delimits the appended printable text
 * with a given quote character and escapes that quotation char with a
 * backslash within the text.
 * @author Andrew Bettison <andrew@servalproject.com>
 */
strbuf strbuf_toprint_quoted_len(strbuf sb, const char quotes[2], const char *buf, size_t len);

/* Equivalent to strbuf_toprint_quoted_len(sb, str, strlen(str)).
 * @author Andrew Bettison <andrew@servalproject.com>
 */
strbuf strbuf_toprint_quoted(strbuf sb, const char quotes[2], const char *str);

/* Join Unix file path segments together with separator characters '/' to form
 * a complete path.  Any segment that starts with '/' is taken as the start of
 * an absolute path, and all prior segments are discarded.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
strbuf strbuf_path_join(strbuf sb, ...);

/* Append a symbolic representation of the poll(2) event flags.
 * @author Andrew Bettison <andrew@servalproject.com>
 */
strbuf strbuf_append_poll_events(strbuf sb, short events);
#define alloca_poll_events(ev)    strbuf_str(strbuf_append_poll_events(strbuf_alloca(200), (ev)))

/* Append a nul-terminated string as a single-quoted shell word which, if
 * expanded in a shell command line, would evaluate to the original string.
 * Eg:
 *    "abc"     ->  "'abc'"
 *    ""        ->  "''"
 *    "O'Toole" ->  "'O'\''Toole'"
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
strbuf strbuf_append_shell_quote(strbuf sb, const char *word);

/* Append a nul-terminated string as a shell word, quoted if it contains shell
 * metacharacters or spaces.  In other words, is acts like
 * str_append_shell_quote() but only if needed. Eg:
 *      "abc"     ->  "abc"
 *      "a b c "  ->  "'a b c '"
 *      "$abc"    ->  "'$abc'"
 *      ""        ->  "''"
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
strbuf strbuf_append_shell_quotemeta(strbuf sb, const char *word);

/* Append an array of nul-terminated strings as a space-separated sequence of
 * quoted strings.  Any NULL entry in argv[] is printed as unquoted "NULL".
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
strbuf strbuf_append_argv(strbuf sb, int argc, const char *const *argv);

/* Append a textual description of a process exit status as produced by wait(2)
 * and waitpid(2).
 * @author Andrew Bettison <andrew@servalproject.com>
 */
strbuf strbuf_append_exit_status(strbuf sb, int status);

/* Append a textual description of a socket domain code (AF_...).
 * @author Andrew Bettison <andrew@servalproject.com>
 */
strbuf strbuf_append_socket_domain(strbuf sb, int domain);
#define alloca_socket_domain(domain)    strbuf_str(strbuf_append_socket_domain(strbuf_alloca(15), domain))

/* Append a textual description of a socket type code (SOCK_...).
 * @author Andrew Bettison <andrew@servalproject.com>
 */
strbuf strbuf_append_socket_type(strbuf sb, int type);
#define alloca_socket_type(type)    strbuf_str(strbuf_append_socket_type(strbuf_alloca(15), type))

/* Append a textual description of a struct in_addr (in network order) as IPv4
 * quartet "N.N.N.N".
 * @author Andrew Bettison <andrew@servalproject.com>
 */
struct in_addr;
strbuf strbuf_append_in_addr(strbuf sb, const struct in_addr *addr);
#define alloca_in_addr(addr)    strbuf_str(strbuf_append_in_addr(strbuf_alloca(16), (const struct in_addr *)(addr)))

/* Append a textual description of a struct sockaddr_in.
 * @author Andrew Bettison <andrew@servalproject.com>
 */
struct sockaddr_in;
strbuf strbuf_append_sockaddr_in(strbuf sb, const struct sockaddr_in *addr);
#define alloca_sockaddr_in(addr)    strbuf_str(strbuf_append_sockaddr_in(strbuf_alloca(45), (const struct sockaddr_in *)(addr)))

/* Append a textual description of a struct sockaddr.
 * @author Andrew Bettison <andrew@servalproject.com>
 */
struct sockaddr;
strbuf strbuf_append_sockaddr(strbuf sb, const struct sockaddr *addr, socklen_t addrlen);
#define alloca_sockaddr(addr, addrlen)    strbuf_str(strbuf_append_sockaddr(strbuf_alloca(200), (const struct sockaddr *)(addr), (addrlen)))

struct socket_address;
strbuf strbuf_append_socket_address(strbuf sb, const struct socket_address *addr);
#define alloca_socket_address(addr)    strbuf_str(strbuf_append_socket_address(strbuf_alloca(200), (addr)))

/* Append a strftime(3) string.
 * @author Andrew Bettison <andrew@servalproject.com>
 */
struct tm;
strbuf strbuf_append_strftime(strbuf sb, const char *format, const struct tm *tm);

/* Append a representation of a struct iovec[] array.
 * @author Andrew Bettison <andrew@servalproject.com>
 */
struct iovec;
strbuf strbuf_append_iovec(strbuf sb, const struct iovec *iov, int iovcnt);
#define alloca_iovec(iov,cnt)    strbuf_str(strbuf_append_iovec(strbuf_alloca(200), (iov), (cnt)))

/* Append a string using HTTP quoted-string format: delimited by double quotes (") and
 * internal double quotes and backslash escaped by leading backslash.
 * @author Andrew Bettison <andrew@servalproject.com>
 */
strbuf strbuf_append_quoted_string(strbuf sb, const char *str);

/* Append various JSON elements.
 * @author Andrew Bettison <andrew@servalproject.com>
 */
strbuf strbuf_json_null(strbuf sb);
strbuf strbuf_json_string(strbuf sb, const char *str);
strbuf strbuf_json_hex(strbuf sb, const unsigned char *buf, size_t len);

/* Append a representation of a struct http_range[] array.
 * @author Andrew Bettison <andrew@servalproject.com>
 */
struct http_range;
strbuf strbuf_append_http_ranges(strbuf sb, const struct http_range *ranges, unsigned nels);
#define alloca_http_ranges(ra)    strbuf_str(strbuf_append_http_ranges(strbuf_alloca(25*NELS(ra)), (ra), NELS(ra)))

/* Append a representation of a struct mime_content_type in HTTP header format.
 * @author Andrew Bettison <andrew@servalproject.com>
 */
struct mime_content_type;
strbuf strbuf_append_mime_content_type(strbuf, const struct mime_content_type *);
#define alloca_mime_content_type(ct) strbuf_str(strbuf_append_mime_content_type(strbuf_alloca(500), (ct)))

/* Append a representation of a struct mime_content_disposition, in HTTP header format.
 * @author Andrew Bettison <andrew@servalproject.com>
 */
struct mime_content_disposition;
strbuf strbuf_append_mime_content_disposition(strbuf, const struct mime_content_disposition *);
#define alloca_mime_content_disposition(cd) strbuf_str(strbuf_append_mime_content_disposition(strbuf_alloca(500), (cd)))

#endif //__STRBUF_HELPERS_H__
