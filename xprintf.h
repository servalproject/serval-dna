/*
Serval extensible printf.
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

#ifndef __SERVAL_DNA__XPRINTF_H
#define __SERVAL_DNA__XPRINTF_H

/* Generalised (extensible) printf framework.
 *
 * Instead of writing a function to send output to a <stdio.h> FILE stream,
 * write it to send output to an extensible stream.  Eg, this code:
 *
 *      void print_something(FILE *fp, int something) {
 *          fprintf(fp, "%d (0x%08X)", something, something);
 *      }
 *
 * Becomes:
 *
 *      void print_something(XPRINTF xpf, int something) {
 *          xprintf(xpf, "%d (0x%08X)", something, something);
 *      }
 *
 * Then, instead of writing this:
 *
 *      print_something(stdout, 10);
 *
 * you write this:
 *
 *      print_something(XPRINTF_STDIO(stdout), 10);
 *
 * But with the extensible version you can also do this:
 *
 *      struct mallocbuf mb = STRUCT_MALLOCBUF_NULL;
 *      print_something(XPRINTF_MALLOCBUF(&mb), 10);
 *      if (mb.buffer)
 *          puts(mb.buffer);
 *
 * And this:
 *
 *      void __log_vprintf(int level, const char *fmt, va_list);
 *
 *      void log_vprintf(void *context, const char *fmt, va_list ap) {
 *          __log_vprintf((int)context, fmt, ap);
 *      }
 *
 *      print_something(XPRINTF_GEN(log_vprintf, LOG_LEVEL_INFO), 10);
 */

#include <stdarg.h>
#include <unistd.h>

#include "features.h"

typedef void CONTEXT_VPRINTF(void *context, const char *fmt, va_list);

typedef struct _xprintf {
    CONTEXT_VPRINTF *func;
    void *context;
} XPRINTF;

#define _XPRINTF(F,C)       ((XPRINTF){(F),(C)})

void xprintf(XPRINTF xpf, const char *fmt, ...) __attribute__ ((__ATTRIBUTE_format(printf,2,3)));
;
void vxprintf(XPRINTF xpf, const char *fmt, va_list);
void xputs(const char *str, XPRINTF xpf);
void xputc(char c, XPRINTF xpf);

#define XPRINTF_GEN(F,C)    _XPRINTF((F),(void *)(C))

/* Standard i/o adapter.  An XPRINTF constructed with XPRINTF_STDIO(stream)
 * will write all its output to stream using fprintf(stream,...).
 */
#define XPRINTF_STDIO(S)    _XPRINTF(_cx_vprintf_stdio,(S))
CONTEXT_VPRINTF _cx_vprintf_stdio;

/* Malloc memory buffer adapter.  An XPRINTF constructed with
 * XPRINTF_MALLOCBUF(&mb) will use realloc() to allocate and grow a memory
 * buffer and fill it using sprintf(), always with a nul terminator at the end.
 * The caller must free() the buffer after use.
 */
struct mallocbuf {
    char *buffer; // Start of buffer, NULL if not allocated yet
    char *current; // Current position of terminating nul in buffer
    size_t size; // Size of current allocated buffer
};
#define STRUCT_MALLOCBUF_NULL   ((struct mallocbuf){NULL,NULL,0})
#define XPRINTF_MALLOCBUF(MB)   _XPRINTF(_cx_vprintf_mallocbuf, (MB))
CONTEXT_VPRINTF _cx_vprintf_mallocbuf;

/* Strbuf adapter.  An XPRINTF constructed with XPRINTF_STRBUF(sb) will write
 * all its output to the give strbuf using strbuf_sprintf(sb,...).
 */
#define XPRINTF_STRBUF(SB)    _XPRINTF(_cx_vprintf_strbuf,(SB))
CONTEXT_VPRINTF _cx_vprintf_strbuf;

#endif // __SERVAL_DNA__XPRINTF_H
