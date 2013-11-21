/* 
Serval DNA FIFO primitives
Copyright (C) 2012 Serval Project, Inc.

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
 * This is a simple FIFO implementation using a circular buffer.
 *
 * Heavily inspired by http://lwn.net/Articles/101808/
 * 
 * Could probably generalise in a similar fashion to sys/queue.h
 *
 */

#include <assert.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define min(a, b)		\
   ({ __typeof__ (a) _a = (a);	\
       __typeof__ (b) _b = (b);	\
       _a < _b ? _a : _b; })

struct fifo {
    unsigned int	rdidx;
    unsigned int	wridx;
    unsigned int	size;
    unsigned int	len;
    uint8_t		buffer[0];
};

/*
 * fifo_alloc - allocates a new FIFO
 * @size: the size of the internal buffer.
 *
 */
struct fifo *
fifo_alloc(unsigned int size) {
    struct fifo		*fifo;

    if ((fifo = malloc(sizeof(struct fifo) + size)) == NULL)
	return NULL;
	
    fifo->rdidx = fifo->wridx = 0;
    fifo->size = size;
    fifo->len = 0;

    return fifo;
}

/*
 * fifo_free - frees the FIFO
 * @fifo: the fifo to be freed.
 */
void
fifo_free(struct fifo *fifo) {
    free(fifo);
}

/*
 * fifo_reset - removes the entire FIFO contents
 * @fifo: the fifo to be emptied.
 */
void
fifo_reset(struct fifo *fifo) {

    fifo->rdidx = fifo->wridx = 0;
    fifo->len = 0;
}

/*
 * fifo_put - puts some data into the FIFO
 * @fifo: the fifo to be used.
 * @buffer: the data to be added.
 * @len: the length of the data to be added.
 *
 * This function copies at most 'len' bytes from the 'buffer' into
 * the FIFO depending on the free space, and returns the number of
 * bytes copied. 
 */
unsigned int
fifo_put(struct fifo *fifo, uint8_t *buffer, unsigned int len) {
    unsigned int	total, remaining;
	
    total = remaining = min(len, fifo->size - fifo->len);
    while (remaining > 0) {
	unsigned int l = min(remaining, fifo->size - fifo->wridx);
	memcpy(fifo->buffer + fifo->wridx, buffer, l);
	fifo->wridx += l;
	fifo->wridx %= fifo->size;
	fifo->len += l;
	buffer += l;
	remaining -= l;
    }

    return total;
}

/*
 * fifo_get - gets some data from the FIFO
 * @fifo: the fifo to be used.
 * @buffer: where the data must be copied.
 * @len: the size of the destination buffer.
 *
 * This function copies at most 'len' bytes from the FIFO into the
 * 'buffer' and returns the number of copied bytes.
 */
unsigned int
fifo_get(struct fifo *fifo, uint8_t *buffer, unsigned int len) {
    unsigned int	total, remaining;

    total = remaining = min(len, fifo->len);
    while (remaining > 0) {
	unsigned int l = min(remaining, fifo->size - fifo->rdidx);
	memcpy(buffer, fifo->buffer + fifo->rdidx, l);
	fifo->rdidx += l;
	fifo->rdidx %= fifo->size;
	fifo->len -= l;
	buffer += l;
	remaining -= l;
    }

    return total;
}

/*
 * fifo_unget - puts some data into the FIFO head
 * @fifo: the fifo to be used.
 * @buffer: the data to be added.
 * @len: the length of the data to be added.
 *
 * This function copies at most 'len' bytes from the 'buffer' into
 * the FIFO depending on the free space, and returns the number of
 * bytes copied. 
 */
unsigned int
fifo_unget(struct fifo *fifo, uint8_t *buffer, unsigned int len) {
    unsigned int	total, remaining, l;
    int			dst;
    
    total = remaining = min(len, fifo->size - fifo->len);

    /* Index to start putting data back */
    dst = fifo->rdidx - len;
    while (dst < 0)
	dst += fifo->size;
    
    while (remaining > 0) {
	l = min(remaining, fifo->size - dst);
	memcpy(fifo->buffer + dst, buffer, l);

	fifo->len += l;
	buffer += l;
	remaining -= l;
    }

    fifo->rdidx = dst;
    
    return total;
}

/*
 * fifo_avail - returns the number of bytes available for reading in the FIFO
 * @fifo: the fifo to be used.
 */
unsigned int
fifo_avail(struct fifo *fifo) {
    unsigned int	result;
	
    result = fifo->len;

    return result;
}

/*
 * fifo_space - returns the number of bytes available for writing in the FIFO
 * @fifo: the fifo to be used.
 */
unsigned int
fifo_space(struct fifo *fifo) {
    unsigned int	result;
	
    result = fifo->size - fifo->len;

    return result;
}
