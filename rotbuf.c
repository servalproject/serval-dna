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

#define __ROTBUF_INLINE
#include <assert.h>
#include "rotbuf.h"

ssize_t rotbuf_delta(const struct rotbuf *origin, const struct rotbuf *dest)
{
  assert(origin->buf == dest->buf);
  assert(origin->ebuf == dest->ebuf);
  assert(origin->start == dest->start);
  const unsigned char *org = origin->cursor;
  const unsigned char *dst = dest->cursor;
  if (org < origin->start)
    org += origin->ebuf - origin->buf;
  assert(org >= origin->start);
  if (dst < dest->start)
    dst += dest->ebuf - dest->buf;
  assert(dst >= dest->start);
  return dst - org;
}

/* Return a pointer/length pair describing the contiguous memory region at the current cursor, and
 * advance the cursor to the next byte after that region (ie, to the start of the next region).  If
 * the cursor is already at or past the end of the buffer, returns 0, otherwise sets *buf and *len
 * and returns 1.
 *
 * @author Andrew Bettison <andrew@servalproject.com>
 */
int rotbuf_next_chunk(struct rotbuf *rb, unsigned char **bufp, size_t *lenp)
{
  if (rb->wrap)
    return 0;
  if (rb->cursor >= rb->start) {
    *bufp = rb->cursor;
    *lenp = rb->ebuf - rb->cursor;
    rb->cursor = rb->buf;
    if (rb->cursor == rb->start)
      ++rb->wrap;
    return 1;
  }
  *bufp = rb->cursor;
  *lenp = rb->start - rb->cursor;
  rb->cursor = rb->start;
  ++rb->wrap;
  return 1;
}
