/*
Serval DNA logging output to a delegate
Copyright (C) 2017 Flinders University
 
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

#ifndef __SERVAL_DNA__LOG_OUTPUT_DELEGATE_H
#define __SERVAL_DNA__LOG_OUTPUT_DELEGATE_H

#include "lang.h" // for bool_t

struct log_delegate {
    bool_t show_prolog;
    int minimum_level;
    bool_t show_pid;
    bool_t show_time;
    void (*print)(int level, const char *message, bool_t overrun);
    void (*flush)();
    bool_t (*capture_fd)(int fd);
    void (*suppress_fd)(int fd);
};

extern struct log_delegate serval_log_delegate;

#endif // __SERVAL_DNA__LOG_OUTPUT_DELEGATE_H
