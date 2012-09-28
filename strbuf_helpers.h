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

/* Append a symbolic representation of the poll(2) event flags.
 * @author Andrew Bettison <andrew@servalproject.com>
 */
strbuf strbuf_append_poll_events(strbuf sb, short events);

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

/* Append a textual description of a process exit status as produced by wait(2)
 * and waitpid(2).
 * @author Andrew Bettison <andrew@servalproject.com>
 */
strbuf strbuf_append_exit_status(strbuf sb, int status);

#endif //__STRBUF_HELPERS_H__
