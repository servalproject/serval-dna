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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// For socklen_t
#ifdef WIN32
#  include "win32/win32.h"
#else
#  ifdef HAVE_SYS_SOCKET_H
#    include <sys/socket.h>
#  endif
#endif

#include "strbuf.h"
#include "os.h"

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

/* Append a symbolic representation of a struct __sourceloc.
 * @author Andrew Bettison <andrew@servalproject.com>
 */
struct __sourceloc;
strbuf strbuf_append_sourceloc(strbuf sb, struct __sourceloc);

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
#define alloca_argv(argc, argv)    strbuf_str(strbuf_append_argv(strbuf_alloca(strbuf_count(strbuf_append_argv(strbuf_alloca(0), (argc), (argv)))), (argc), (argv)))

/* Append a textual description of a process exit status as produced by wait(2)
 * and waitpid(2).
 * @author Andrew Bettison <andrew@servalproject.com>
 */
strbuf strbuf_append_exit_status(strbuf sb, int status);

/* Append a textual description of a signal as used by kill(2) and signal(2).
 * @author Andrew Bettison <andrew@servalproject.com>
 */
strbuf strbuf_append_signal_name(strbuf sb, int signal);
#define alloca_signal_name(sig)    strbuf_str(strbuf_append_signal_name(strbuf_alloca(80), (sig)))

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

/* Append a textual description of a struct sockaddr.
 * @author Andrew Bettison <andrew@servalproject.com>
 */
struct sockaddr;
strbuf strbuf_append_sockaddr(strbuf sb, const struct sockaddr *addr, socklen_t addrlen);
#define alloca_sockaddr(addr, addrlen)    strbuf_str(strbuf_append_sockaddr(strbuf_alloca(200), (const struct sockaddr *)(addr), (addrlen)))

struct socket_address;
strbuf strbuf_append_socket_address(strbuf sb, const struct socket_address *addr);
#define alloca_socket_address(addr)    strbuf_str(strbuf_append_socket_address(strbuf_alloca(200), (addr)))

struct fragmented_data;
strbuf strbuf_append_fragmented_data(strbuf sb, const struct fragmented_data *data);
#define alloca_fragmented_data(data)    strbuf_str(strbuf_append_fragmented_data(strbuf_alloca(200), (data)))

/* Append a strftime(3) string.
 * @author Andrew Bettison <andrew@servalproject.com>
 */
struct tm;
strbuf strbuf_append_strftime(strbuf sb, const char *format, const struct tm *tm);
#define alloca_strftime(fmt,tm)    strbuf_str(strbuf_append_strftime(strbuf_alloca(40), (fmt), (tm)))

/* Append a representation of a struct iovec[] array.
 * @author Andrew Bettison <andrew@servalproject.com>
 */
struct iovec;
strbuf strbuf_append_iovec(strbuf sb, const struct iovec *iov, int iovcnt);
#define alloca_iovec(iov,cnt)    strbuf_str(strbuf_append_iovec(strbuf_alloca(200), (iov), (cnt)))

/* Append a representation of a time_t value (second resolution).
 * @author Andrew Bettison <andrew@servalproject.com>
 */
strbuf strbuf_append_time_t(strbuf sb, time_t);
#define alloca_time_t(t)    strbuf_str(strbuf_append_time_t(strbuf_alloca(40), (t)))

/* Append a representation of a time_ms_t value (millisecond resolution).
 * @author Andrew Bettison <andrew@servalproject.com>
 */
strbuf strbuf_append_time_ms_t(strbuf sb, time_ms_t);
#define alloca_time_ms_t(t)    strbuf_str(strbuf_append_time_ms_t(strbuf_alloca(45), (t)))

/* Append a representation of a struct timeval (microsecond resolution).
 * @author Andrew Bettison <andrew@servalproject.com>
 */
struct timeval;
strbuf strbuf_append_timeval(strbuf sb, const struct timeval *tv);
#define alloca_timeval(tv)    strbuf_str(strbuf_append_timeval(strbuf_alloca(50), (tv)))

/* Append a representation of a struct timespec (nanosecond resolution).
 * @author Andrew Bettison <andrew@servalproject.com>
 */
struct timespec;
strbuf strbuf_append_timespec(strbuf sb, const struct timespec *tv);
#define alloca_timespec(tv)    strbuf_str(strbuf_append_timespec(strbuf_alloca(55), (tv)))

/* Append a representation of a struct file_meta.
 * @author Andrew Bettison <andrew@servalproject.com>
 */
struct file_meta;
strbuf strbuf_append_file_meta(strbuf sb, const struct file_meta *metap);
#define alloca_file_meta(metap)    strbuf_str(strbuf_append_file_meta(strbuf_alloca(80), (metap)))

/* Append a representation of routing reachable flags.
 * @author Andrew Bettison <andrew@servalproject.com>
 */
strbuf strbuf_append_reachable_flags(strbuf sb, int flags);
#define alloca_reachable_flags(flags)    strbuf_str(strbuf_append_reachable_flags(strbuf_alloca(80), (flags)))

/* Append a string using HTTP quoted-string format: delimited by double quotes (") and
 * internal double quotes and backslash escaped by leading backslash.
 * @author Andrew Bettison <andrew@servalproject.com>
 */
strbuf strbuf_append_quoted_string(strbuf sb, const char *str);

/* Append a string using HTTP token|quoted-string format: if it contains only
 * token characters, then unmodified, otherwise as a quoted-string
 * (strbuf_append_quoted_string).
 * @author Andrew Bettison <andrew@servalproject.com>
 */
strbuf strbuf_append_token_or_quoted_string(strbuf sb, const char *str);

/* Escape HTML entities.
 * @author Andrew Bettison <andrew@servalproject.com>
 */
strbuf strbuf_html_escape(strbuf sb, const char *, size_t);

/* Append various JSON elements.
 * @author Andrew Bettison <andrew@servalproject.com>
 */
strbuf strbuf_json_null(strbuf sb);
strbuf strbuf_json_boolean(strbuf sb, int boolean);
strbuf strbuf_json_integer(strbuf sb, int64_t integer);
strbuf strbuf_json_string(strbuf sb, const char *str); // str can be NULL
strbuf strbuf_json_string_len(strbuf sb, const char *str, size_t strlen); // str cannot be NULL
strbuf strbuf_json_hex(strbuf sb, const unsigned char *buf, size_t len);
struct json_key_value {
    const char *key;
    struct json_atom *value;
};
struct json_atom {
    enum json_atomic_type {
        JSON_NULL,
        JSON_BOOLEAN,           // u.boolean
        JSON_INTEGER,           // u.integer
        JSON_STRING_NULTERM,    // u.string.content (nul terminated)
        JSON_STRING_LENGTH,     // u.string.content[0 .. u.string.length-1]
        JSON_OBJECT,            // u.object.itemv[0 .. u.object.itemc].key .value
        JSON_ARRAY,             // u.array.itemv[0 .. u.object.itemc]
    } type;
    union {
        int boolean;
        int64_t integer;
        struct {
            const char *content;
            size_t length;
        } string;
        struct {
            size_t itemc;
            struct json_key_value *itemv;
        } object;
        struct {
            size_t itemc;
            struct json_atom **itemv;
        } array;
    } u;
};
strbuf strbuf_json_atom(strbuf sb, const struct json_atom *);
strbuf strbuf_json_atom_as_html(strbuf sb, const struct json_atom *);
strbuf strbuf_json_atom_as_text(strbuf sb, const struct json_atom *, const char *eol);

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
