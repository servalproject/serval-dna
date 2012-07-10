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
    strbuf_puts(&b, "text");
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
#include <alloca.h>

#ifndef __STRBUF_INLINE
# if __GNUC__ && !__GNUC_STDC_INLINE__
#  define __STRBUF_INLINE extern inline
# else
#  define __STRBUF_INLINE inline
# endif
#endif

struct strbuf {
    char *start;
    char *end;
    char *current;
};

/* Static constant for initialising a struct strbuf to empty:
 *      struct strbuf ssb = STRUCT_STRBUF_EMPTY;
 * Immediately following this assignment, the following properties hold:
 *      strbuf_is_empty(&ssb)
 *      strbuf_len(&ssb) == 0
 *      strbuf_count(&ssb) == 0
 *      strbuf_str(&ssb) == NULL
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
#define STRUCT_STRBUF_EMPTY ((struct strbuf){NULL, (char *)NULL - 1, NULL})

typedef struct strbuf *strbuf;
typedef const struct strbuf *const_strbuf;

/** The number of bytes occupied by a strbuf (not counting its backing buffer).
 */
#define SIZEOF_STRBUF (sizeof(struct strbuf))

/** Convenience macro for allocating a strbuf and its backing buffer on the
 * stack within the calling function.  The returned strbuf is only valid for
 * the duration of the function, so it must not be returned.  See alloca(3) for
 * more information.
 *
 *      void func() {
 *          strbuf b = strbuf_alloca(1024);
 *          strbuf_puts(b, "some text");
 *          strbuf_puts(b, " some more text");
 *          printf("%s\n", strbuf_str(b));
 *      }
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
#define strbuf_alloca(size) strbuf_make(alloca(SIZEOF_STRBUF + size), SIZEOF_STRBUF + size)


/** Convenience macro for filling a strbuf from the calling function's
 * printf(3)-like variadic arguments.  The returned strbuf is only valid for
 * the duration of the function, so it must not be returned.  See alloca(3) for
 * more information.
 *
 *      #include <stdarg.h>
 *
 *      void funcf(const char *format, ...) {
 *          strbuf b = strbuf_alloca(1024);
 *          strbuf_va_printf(b, format);
 *          ...
 *      }
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
#define strbuf_va_printf(sb,fmt) do { \
            va_list __strbuf_ap; \
            va_start(__strbuf_ap, fmt); \
            strbuf_vsprintf(sb, fmt, __strbuf_ap); \
            va_end(__strbuf_ap); \
        } while (0)

/** Convenience macro to allocate a strbuf for use within the calling function,
 * based on a caller-supplied backing buffer.  The returned strbuf is only valid
 * for the duration of the function, so it must not be returned.  See alloca(3)
 * for more information.  However, the backing buffer may have any scope.
 *
 *      void func(char *buf, size_t len) {
 *          strbuf b = strbuf_local(buf, len);
 *          strbuf_puts(b, "some text");
 *          strbuf_puts(b, " some more text");
 *          printf("%s\n", strbuf_str(b));
 *      }
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
#define strbuf_local(buf,len) strbuf_init(alloca(SIZEOF_STRBUF), (buf), (len))


/** Initialise a strbuf with a caller-supplied backing buffer.  The current
 * backing buffer and its contents are forgotten, and all strbuf operations
 * henceforward will operate on the new backing buffer.  Returns its first
 * argument.
 *
 * Immediately following strbuf_init(sb,b,n), the following properties hold:
 *      strbuf_str(sb) == b
 *      strbuf_size(sb) == n
 *      strbuf_len(sb) == 0
 *      strbuf_count(sb) == 0
 *      b == NULL || b[0] == '\0'
 *
 * If the 'buffer' argument is NULL, the strbuf is marked as "empty" and all
 * subsequent strbuf operations will all act as usual with the sole exception
 * that no chars will be copied into a backing buffer.  This allows strbuf to
 * be used for summing the lengths of strings.
 *
 * If the 'size' argument is zero, then strbuf does not write into its backing
 * buffer, not even a terminating nul.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
strbuf strbuf_init(strbuf sb, char *buffer, size_t size);


/** Initialise a strbuf and its backing buffer inside the caller-supplied
 * buffer of the given size.  If the 'size' argument is less than
 * SIZEOF_STRBUF, then strbuf_make() returns NULL.
 *
 * Immediately following sb = strbuf_make(buf,len) where len >= SIZEOF_STRBUF,
 * the following properties hold:
 *      (char*) sb == buf
 *      strbuf_str(sb) == &buf[SIZEOF_STRBUF];
 *      strbuf_size(sb) == len - SIZEOF_STRBUF;
 *      strbuf_len(sb) == 0
 *      strbuf_count(sb) == 0
 *      strbuf_str(sb)[0] == '\0'
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
__STRBUF_INLINE strbuf strbuf_make(char *buffer, size_t size) {
  return size < SIZEOF_STRBUF ? NULL : strbuf_init((strbuf) buffer, buffer + SIZEOF_STRBUF, size - SIZEOF_STRBUF);
}


/** Reset a strbuf.  The current position is set to the start of the buffer, so
 * the next append will write at the start of the buffer.  The prior contents
 * of the buffer are forgotten and will be overwritten.
 *
 * Immediately following strbuf_reset(sb), the following properties hold:
 *      strbuf_len(sb) == 0
 *      strbuf_count(sb) == 0
 *      strbuf_str(sb) == NULL || strbuf_str(sb)[0] == '\0'
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
strbuf strbuf_reset(strbuf sb);


/** Append a null-terminated string to the strbuf up to a maximum number,
 * truncating if necessary to avoid buffer overrun, and terminating with a nul
 * which is not counted in the maximum.  Return a pointer to the strbuf so that
 * concatenations can be chained in a single line: eg,
 * strbuf_ncat(strbuf_ncat(sb, "abc", 1), "bcd", 2) gives a strbuf containing
 * "abc";
 *
 * After these operations:
 *      n = strbuf_len(sb);
 *      c = strbuf_count(sb);
 *      strbuf_ncat(text, len);
 * the following invariants hold:
 *      strbuf_count(sb) == c + min(strlen(text), len)
 *      strbuf_len(sb) >= n
 *      strbuf_len(sb) <= n + len
 *      strbuf_len(sb) <= n + strlen(text)
 *      strbuf_str(sb) == NULL || strbuf_len(sb) == n || strncmp(strbuf_str(sb) + n, text, strbuf_len(sb) - n) == 0
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
strbuf strbuf_ncat(strbuf sb, const char *text, size_t len);


/** Append a null-terminated string to the strbuf, truncating if necessary to
 * avoid buffer overrun.  Return a pointer to the strbuf so that concatenations
 * can be chained in a single line: strbuf_puts(strbuf_puts(sb, "a"), "b");
 *
 * After these operations:
 *      n = strbuf_len(sb);
 *      c = strbuf_count(sb);
 *      strbuf_puts(text);
 * the following invariants hold:
 *      strbuf_count(sb) == c + strlen(text)
 *      strbuf_len(sb) >= n
 *      strbuf_len(sb) <= n + strlen(text)
 *      strbuf_str(sb) == NULL || strbuf_len(sb) == n || strncmp(strbuf_str(sb) + n, text, strbuf_len(sb) - n) == 0
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
strbuf strbuf_puts(strbuf sb, const char *text);


/** Append a single character to the strbuf if there is space, and place a
 * terminating nul after it.  Return a pointer to the strbuf so that
 * concatenations can be chained in a single line.
 *
 * After these operations:
 *      n = strbuf_len(sb);
 *      c = strbuf_count(sb);
 *      strbuf_putc(ch);
 * the following invariants hold:
 *      strbuf_count(sb) == c + 1
 *      strbuf_len(sb) >= n
 *      strbuf_len(sb) <= n + 1
 *      strbuf_str(sb) == NULL || strbuf_len(sb) == n || strbuf_str(sb)[n] == ch
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
strbuf strbuf_putc(strbuf sb, char ch);


/** Append the results of sprintf(fmt,...) to the string buffer, truncating if
 * necessary to avoid buffer overrun.  Return sprintf()'s return value.
 *
 * This is equivalent to char tmp[...]; sprintf(tmp, fmt, ...); strbuf_puts(tmp);
 * assuming that tmp[] is large enough to contain the entire string produced by
 * the sprintf().
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int strbuf_sprintf(strbuf sb, const char *fmt, ...);
int strbuf_vsprintf(strbuf sb, const char *fmt, va_list ap);


/** Return a pointer to the current null-terminated string in the strbuf.
 *
 * This is the same as the 'buffer' argument passed to the most recent
 * strbuf_init().  If the caller still has that pointer, then can safely use it
 * instead of calling strbuf_str().
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
__STRBUF_INLINE char *strbuf_str(const_strbuf sb) {
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
char *strbuf_substr(const_strbuf sb, int offset);


/** Truncate the string in the strbuf to a given offset.  If the offset is
 * negative, then it is taken from the end of the string, ie, the length of the
 * string is added to it.  If the string is shorter than the given offset, then
 * it is unchanged.  Otherwise, a terminating nul char is written at the offset
 * and the string's length truncated accordingly.  Return a pointer to the
 * strbuf so that operations can be chained in a single line.
 *
 * After the operation:
 *      len = strbuf_len(sb);
 *      strbuf_trunc(sb, off);
 * the following invariants hold:
 * where len <= off, sb is unchanged;
 * where 0 <= off < len:
 *      strbuf_count(sb) == off
 *      strbuf_len(sb) == off
 * where -len <= off < 0:
 *      strbuf_count(sb) == len + off
 *      strbuf_len(sb) == len + off
 * where off < -len:
 *      strbuf_count(sb) == 0
 *      strbuf_len(sb) == 0
 *      strbuf_str(sb)[0] == '\0'
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
strbuf strbuf_trunc(strbuf sb, int offset);


/** Return true if the given strbuf is "empty", ie, not modified since being
 * initialised to STRUCT_STRBUF_EMPTY or with strbuf_init(sb, NULL, 0);
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
__STRBUF_INLINE size_t strbuf_is_empty(const_strbuf sb) {
  return sb->start == NULL && sb->end == sb->start - 1 && sb->current == NULL;
}


/** Return the size of the backing buffer.
 *
 * This is the same as the 'size' argument passed to the most recent
 * strbuf_init().
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
__STRBUF_INLINE size_t strbuf_size(const_strbuf sb) {
  return sb->end - sb->start + 1;
}


/** Return length of current string in the strbuf, not counting the terminating
 * nul.
 *
 * Invariant: strbuf_len(sb) == strlen(strbuf_str(sb))
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
__STRBUF_INLINE size_t strbuf_len(const_strbuf sb) {
  return (sb->current < sb->end ? sb->current : sb->end) - sb->start;
}


/** Return the number of chars appended to the strbuf so far, not counting the
 * terminating nul.
 *
 * Invariant: strbuf_len(sb) <= strbuf_count(sb)
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
__STRBUF_INLINE size_t strbuf_count(const_strbuf sb) {
  return sb->current - sb->start;
}


/** Return true iff the strbuf has been overrun, ie, any appended string has
 * been truncated since strbuf_init().
 *
 * Invariant: strbuf_overrun(sb) == strbuf_count(sb) != strbuf_len(sb)
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
__STRBUF_INLINE int strbuf_overrun(const_strbuf sb) {
  return sb->current > sb->end;
}

#endif // __STRBUF_H__
