/*
 Serval rotated buffer primitives
 Copyright (C) 2013 Serval Project Inc.
 
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

#ifndef __ROTBUF_H__
#define __ROTBUF_H__

#include <stdio.h> // for EOF
#include <sys/types.h> // for size_t, ssize_t
#include "log.h"

#ifndef __ROTBUF_INLINE
# if __GNUC__ && !__GNUC_STDC_INLINE__
#  define __ROTBUF_INLINE extern inline
# else
#  define __ROTBUF_INLINE inline
# endif
#endif

/* A rotated buffer is a simple buffer (pointer and length) in which the initial byte is at a given
 * offset within the buffer, and the content wraps around.  A rotbuf structure describes the buffer
 * using the buf, ebuf and start pointers.
 *
 * A rotbuf structure provides a single cursor for reading or writing the buffer, analogous to a
 * simple memory pointer in a conventional (non-rotated) buffer.
 *
 * The rotbuf structure provides a wrap counter for detecting when the cursor has wrapped around
 * back to the start position.  The wrap counter is set to 1 when the cursor has advanced exactly
 * len bytes around the buffer, and thereafter the wrap counter is incremented instead of advancing
 * the cursor, so that overflowing the buffer will not overwrite the first pass with subsequent
 * passes.
 *
 * The following invariants hold:
 *
 *  - the total cursor advance count (real + attempted read/written bytes) is
 *      wrap ? (len + wrap - 1) : ((cursor - start) MOD len)
 *
 *  - the total bytes actually read/written in the memory region:
 *      wrap ? len : ((cursor - start) MOD len)
 *
 * where MOD is the proper arithmetic modulo, not the C '%' operator which has undefined
 * semantics for negative dividends.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */

struct rotbuf {
  unsigned char *buf;
  unsigned char *ebuf;
  unsigned char *start;
  unsigned char *cursor;
  unsigned int wrap;
};

#define RBUF_NULL ((struct rotbuf){.buf = NULL, .ebuf = NULL, .start = NULL, .cursor = NULL, .wrap = 0 })

/* Initialise the given rotbuf structure to use the given memory region (buf, size) as the buffer,
 * with the given offset (rot) as the start point.  If rot exceeds size or is negative, then it is
 * used modulus the length (using proper modulus arithmetic, not the broken C '%' operator
 * semantics), to ensure it lies within the buffer.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
__ROTBUF_INLINE void rotbuf_init(struct rotbuf *rb, unsigned char *buf, size_t size, ssize_t rot)
{
  rb->buf = buf;
  rb->ebuf = buf + size;
  rb->start = buf + (rot < 0 ? size - 1 - (-1 - rot) % size : rot % size);
  rb->cursor = rb->start;
  rb->wrap = 0;
}

/* Reset the given rotbuf structure cursor to the start position.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
__ROTBUF_INLINE void rotbuf_reset(struct rotbuf *rb)
{
  rb->cursor = rb->start;
  rb->wrap = 0;
}

/* Return the total number of bytes advanced through the given rotated buffer, excluding any
 * overrun.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
__ROTBUF_INLINE size_t rotbuf_position(struct rotbuf *rb)
{
  if (rb->wrap)
    return rb->ebuf - rb->buf;
  if (rb->cursor >= rb->start)
    return rb->cursor - rb->start;
  return (rb->cursor - rb->buf) + (rb->ebuf - rb->start);
}

/* Return the total number of bytes remaining to be advanced to reach the end
 * of the given rotated buffer.  If the buffer has overrun, this will be zero.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
__ROTBUF_INLINE size_t rotbuf_remain(struct rotbuf *rb)
{
  if (rb->wrap)
    return 0;
  if (rb->cursor < rb->start)
    return rb->start - rb->cursor;
  return (rb->ebuf - rb->cursor) + (rb->start - rb->buf);
}

/* Return the total number of bytes advanced through the given rotated buffer, including any
 * overrun.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
__ROTBUF_INLINE size_t rotbuf_count(struct rotbuf *rb)
{
  return rb->wrap ? (size_t)((rb->ebuf - rb->buf) + rb->wrap - 1) : rotbuf_position(rb);
}

void rotbuf_log(struct __sourceloc __whence, int log_level, const char *prefix, const struct rotbuf *rb);

/* Advance the cursor by a given number of bytes (non negative).  Advancing the cursor over the
 * final byte in the buffer sets the 'wrap' counter to 1.  All further advances are simply added to
 * the 'wrap' counter.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
__ROTBUF_INLINE void rotbuf_advance(struct rotbuf *rb, size_t len)
{
  if (rb->wrap)
    rb->wrap += len;
  else if (len) {
    if (rb->cursor >= rb->start) {
      if ((rb->cursor += len) >= rb->ebuf) {
	rb->cursor -= rb->ebuf - rb->buf;
	if (rb->cursor >= rb->start) {
	  rb->wrap = 1 + (rb->cursor - rb->start);
	  rb->cursor = rb->start;
	}
      }
    } else if ((rb->cursor += len) >= rb->start) {
      rb->wrap = 1 + (rb->cursor - rb->start);
      rb->cursor = rb->start;
    }
  }
}

/* Fetch a byte from the rotated buffer at the current cursor position and advance the cursor.
 * Fetching the last byte from the buffer sets the 'wrap' pointer to 1.  Fetching from the buffer at
 * or beyond its length increments the 'wrap' counter and returns EOF.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
__ROTBUF_INLINE int rotbuf_getc(struct rotbuf *rb)
{
  if (rb->wrap) {
    ++rb->wrap;
    return EOF;
  }
  unsigned char c = *rb->cursor++;
  if (rb->cursor == rb->ebuf)
    rb->cursor = rb->buf;
  if (rb->cursor == rb->start)
    rb->wrap = 1;
  return c;
}

/* Fetch many bytes from the rotated buffer at the current cursor position and advance the cursor
 * over the fetched bytes.  Bytes from beyond the buffer end are written into the destination as EOF
 * and the 'wrap' counter is incremented.  Exactly equivalent to:
 *
 *    while (len--)
 *	*buf++ = rotbuf_getc(rb);
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
__ROTBUF_INLINE void rotbuf_getbuf(struct rotbuf *rb, unsigned char *buf, size_t len)
{
  // TODO optimise by using rotbuf_next_chunk() and memcpy()
  while (len--)
      *buf++ = rotbuf_getc(rb);
}

/* Append a byte to the rotated buffer at the current cursor position and advance the cursor.  If
 * the byte exactly fills the buffer then the 'wrap' counter is set to 1.  Appending to the buffer
 * at or beyond its length does not write into the buffer, but instead increments the 'wrap'
 * counter.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
__ROTBUF_INLINE void rotbuf_putc(struct rotbuf *rb, unsigned char c)
{
  if (rb->wrap)
    ++rb->wrap;
  else {
    *rb->cursor++ = c;
    if (rb->cursor == rb->ebuf)
      rb->cursor = rb->buf;
    if (rb->cursor == rb->start)
      rb->wrap = 1;
  }
}

/* Write many bytes from the rotated buffer at the current cursor position and advance the cursor
 * over the written bytes.  Bytes are not written beyond the end of the buffer, instead the 'wrap'
 * counter is incremented.  Exactly equivalent to:
 *
 *    while (len--)
 *	rotbuf_putc(rb, *buf++);
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
__ROTBUF_INLINE void rotbuf_putbuf(struct rotbuf *rb, const unsigned char *buf, size_t len)
{
  // TODO optimise by using rotbuf_next_chunk() and memcpy()
  while (len--)
    rotbuf_putc(rb, *buf++);
}

/* Return the difference between two cursors in the same rotated buffer.  Equivalent to pointer
 * subtraction in a normal (non-rotated) buffer.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
ssize_t rotbuf_delta(const struct rotbuf *origin, const struct rotbuf *dest);

/* Return a pointer/length pair describing the contiguous memory region at the current cursor, and
 * advance the cursor to the next byte after that region (ie, to the start of the next region).  If
 * the cursor is already at or past the end of the buffer, returns 0, otherwise sets *buf and *len
 * and returns 1.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int rotbuf_next_chunk(struct rotbuf *rb, unsigned char **bufp, size_t *lenp);

__ROTBUF_INLINE void rotbuf_log(struct __sourceloc __whence, int log_level, const char *prefix, const struct rotbuf *rb)
{
  LOGF(log_level, "%sbuf=%p ebuf=%p start=%p cursor=%p wrap=%u",
      prefix ? prefix : "",
      rb->buf,
      rb->ebuf,
      rb->start,
      rb->cursor,
      rb->wrap);
}

#endif // __ROTBUF_H__
