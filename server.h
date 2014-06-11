/*
Copyright (C) 2012-2014 Serval Project Inc.
 
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

#define SERVER_RUNNING 1
#define SERVER_CLOSING 2

DECLARE_ALARM(server_shutdown_check);
DECLARE_ALARM(server_watchdog);
DECLARE_ALARM(server_config_reload);
DECLARE_ALARM(rhizome_sync_announce);
DECLARE_ALARM(fd_periodicstats);

#endif // __SERVAL_DNA__SERVER_H
