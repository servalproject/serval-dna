/* 
 Interactive console primitives
 Copyright (C) 2014 Serval Project Inc.
 
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

#ifndef __SERVAL_DNA__CONSOLE_H
#define __SERVAL_DNA__CONSOLE_H

#include "cli.h"

struct command_state;
struct command_state *command_register(struct cli_schema *commands, int fd);
uint8_t is_command_closed(struct command_state *state);
void command_close(struct command_state *state);
void command_free(struct command_state *state);

#endif // __SERVAL_DNA__CONSOLE_H
