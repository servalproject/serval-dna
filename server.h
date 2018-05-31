/*
Serval DNA server main loop
Copyright (C) 2012-2015 Serval Project Inc.
Copyright (C) 2016 Flinders University
 
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

#ifndef __SERVAL_DNA__SERVER_H
#define __SERVAL_DNA__SERVER_H

#include "fdqueue.h"
#include "os.h" // for time_ms_t
#include "trigger.h"

enum server_mode {
    SERVER_NOT_RUNNING = 0,
    SERVER_RUNNING = 1,
    SERVER_CLOSING = 2
};

DECLARE_ALARM(server_shutdown_check);
DECLARE_ALARM(server_watchdog);
DECLARE_ALARM(server_config_reload);
DECLARE_ALARM(rhizome_sync_announce);
DECLARE_ALARM(fd_periodicstats);

extern __thread enum server_mode serverMode;

/** Return the PID of the currently running server process, return 0 if there is none.
 */
int server_pid();

int server_bind();

void server_close();

void server_loop(time_ms_t (*waiting)(time_ms_t, time_ms_t, time_ms_t), void (*wokeup)());

int server_write_proc_state(const char *path, const char *fmt, ...);
int server_unlink_proc_state(const char *path);

DECLARE_TRIGGER(startup);
DECLARE_TRIGGER(shutdown);

#endif // __SERVAL_DNA__SERVER_H
