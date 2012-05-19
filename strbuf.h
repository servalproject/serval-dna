/*
Serval string buffer primitives
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

#ifndef __STRBUF_H__
#define __STRBUF_H__

/*
    A strbuf provides a convenient set of primitives for assembling a
    null-terminated string in a fixed-size, caller-provided backing buffer,
    using a sequence of append operations.

    An append operation that would overflow the buffer is truncated, and the
    result null-terminated.  Once a truncation has occurred, the "overrun"
    property of the strbuf is true until the next strbuf_init(), and all
    subsequent appends will be fully truncated, ie, nothing more will be
    appended to the buffer.
    
    The string in the buffer is guaranteed to always be nul terminated, which
    means that the maximum strlen() of the assembled string is one less than
    the buffer size.  In other words, the following invariants always hold:
        strbuf_len(sb) < strbuf_size(sb)
        strbuf_str(sb)[strbuf_len(sb)] == '\0'

    char buf[100];
    strbuf b;
    strbuf_init(&b, buf, sizeof buf);
    strbuf_cat(&b, "text");
    strbuf_sprintf(&b, "fmt", val...);
    if (strbuf_overflow(&b))
        // error...
    else
        // use buf

    A strbuf counts the total number of chars appended to it, even ones that
    were truncated.  This count is always available via strbuf_count().

    A NULL buffer can be provided.  This causes the strbuf operations to
    perform all character counting and truncation calculations as usual, but
    not assemble the string.  This allows a strbuf to be used for calculating
    the size needed for a buffer, which the caller may then allocate and replay
    the same operations to fill.

*/

#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

typedef struct strbuf {
    char *start;
    char *end;
    char *current;
} strbuf;

/** Initialise the strbuf backing buffer.  The current backing buffer and its
 * contents are forgotten, and all strbuf operations henceforward will operate
 * on the new backing buffer.
 *
 * Immediately following strbuf_init(sb,b,n), the following properties hold:
 *      strbuf_str(sb) == b
 *      strbuf_size(sb) == n
 *      strbuf_len(sb) == 0
 *      strbuf_count(sb) == 0
 *      b == NULL || b[0] == '\0'
 *
 * If the 'buffer' argument is NULL, the strbuf operations will all act as
 * usual with the sole exception that no chars will be copied into a backing
 * buffer.  This allows strbuf to be used for summing the lengths of strings.
 *
 * If the 'size' argument is zero, the result is undefined.  A segmentation
 * violation could occur, or the calling process may be aborted.  Output may
 * be written to fd 2 (standard error), or the process may hang in a tight
 * loop.  Cats may speak in tongues and the sky may fall.  If the caller wishes
 * to avoid these things, should always ensure that 'size' is nonzero.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
void strbuf_init(strbuf *sb, char *buffer, size_t size);

/** Append a given number of characters to the strbuf, truncating if necessary to
 * avoid buffer overrun.  Return a pointer to the strbuf so that concatenations
 * can be chained in a single line: strbuf_ncat(strbuf_ncat(sb, "abc", 1), "bcd", 2);
 *
 * After these operations:
 *      n = strbuf_len(sb);
 *      c = strbuf_count(sb);
 *      strbuf_ncat(text, len);
 * the following invariants hold:
 *      strbuf_count(sb) == c + len
 *      strbuf_len(sb) >= n
 *      strbuf_len(sb) <= n + len
 *      strbuf_str(sb) == NULL || strbuf_len(sb) == n || strncmp(strbuf_str(sb) + n, text, strbuf_len(sb) - n) == 0
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
strbuf *strbuf_ncat(strbuf *sb, const char *text, size_t len);


/** Append a null-terminated string to the strbuf, truncating if necessary to
 * avoid buffer overrun.  Return a pointer to the strbuf so that concatenations
 * can be chained in a single line: strbuf_cat(strbuf_cat(sb, "a"), "b");
 *
 * After these operations:
 *      n = strbuf_len(sb);
 *      c = strbuf_count(sb);
 *      strbuf_cat(text);
 * the following invariants hold:
 *      strbuf_count(sb) == c + strlen(text)
 *      strbuf_len(sb) >= n
 *      strbuf_len(sb) <= n + strlen(text)
 *      strbuf_str(sb) == NULL || strbuf_len(sb) == n || strncmp(strbuf_str(sb) + n, text, strbuf_len(sb) - n) == 0
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
inline strbuf *strbuf_cat(strbuf *sb, const char *text) {
  return strbuf_ncat(sb, text, strlen(text));
}


/** Append the results of sprintf(fmt,...) to the string buffer, truncating if
 * necessary to avoid buffer overrun.  Return sprintf()'s return value.
 *
 * This is equivalent to char tmp[...]; sprintf(tmp, fmt, ...); strbuf_cat(tmp);
 * assuming that tmp[] is large enough to contain the entire string produced by
 * the sprintf().
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int strbuf_sprintf(strbuf *sb, const char *fmt, ...);
int strbuf_vsprintf(strbuf *sb, const char *fmt, va_list ap);

/** Return a pointer to the current null-terminated string in the strbuf.
 *
 * This is the same as the 'buffer' argument passed to the most recent
 * strbuf_init().  If the caller still has that pointer, then can safely use it
 * instead of calling strbuf_str().
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
inline char *strbuf_str(const strbuf *sb) {
  return sb->start;
}


/** Return a pointer to the substring starting at a given offset.  If the
 * offset is negative, then it is taken from the end of the string, ie, the
 * length of the string is added to it.  The returned pointer always points
 * within the string.  If offset >= strbuf_len(sb), it points to the
 * terminating nul.  If offset <= -strbuf_len(sb) then it points to
 * strbuf_str(sb).
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
char *strbuf_substr(const strbuf *sb, int offset);


/** Return the size of the backing buffer.
 *
 * This is the same as the 'size' argument passed to the most recent
 * strbuf_init().
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
inline size_t strbuf_size(const strbuf *sb) {
  return sb->end - sb->start + 1;
}


/** Return length of current string in the strbuf, not counting the terminating
 * nul.
 *
 * Invariant: strbuf_len(sb) == strlen(strbuf_str(sb))
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
inline size_t strbuf_len(const strbuf *sb) {
  return (sb->current < sb->end ? sb->current : sb->end) - sb->start;
}


/** Return the number of chars appended to the strbuf so far, not counting the
 * terminating nul.
 *
 * Invariant: strbuf_len(sb) <= strbuf_count(sb)
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
inline size_t strbuf_count(const strbuf *sb) {
  return sb->current - sb->start;
}


/** Return true iff the strbuf has been overrun, ie, any appended string has
 * been truncated since strbuf_init().
 *
 * Invariant: strbuf_overrun(sb) == strbuf_count(sb) != strbuf_len(sb)
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
inline int strbuf_is_overrun(const strbuf *sb) {
  return sb->current > sb->end;
}

#endif // __STRBUF_H__
