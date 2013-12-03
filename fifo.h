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

struct fifo;

struct fifo 	*fifo_alloc(unsigned int size);
void		fifo_free(struct fifo *fifo);
void		fifo_reset(struct fifo *fifo);
unsigned int	fifo_put(struct fifo *fifo, uint8_t *buffer, unsigned int len);
unsigned int	fifo_get(struct fifo *fifo, uint8_t *buffer, unsigned int len);
unsigned int	fifo_unget(struct fifo *fifo, uint8_t *buffer, unsigned int len);
unsigned int	fifo_avail(struct fifo *fifo);
unsigned int	fifo_space(struct fifo *fifo);
