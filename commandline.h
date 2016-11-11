/*
Serval DNA command-line parsing
Copyright (C) 2014-2015 Serval Project Inc.
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

#ifndef __SERVAL_DNA__COMMANDLINE_H
#define __SERVAL_DNA__COMMANDLINE_H

#include <stdio.h> // for FILE
#include "section.h"
#include "trigger.h"
#include "cli.h"

#define KEYRING_PIN_OPTION	  ,"[--keyring-pin=<pin>]"
#define KEYRING_ENTRY_PIN_OPTION  ,"[--entry-pin=<pin>]"
#define KEYRING_PIN_OPTIONS	  KEYRING_PIN_OPTION KEYRING_ENTRY_PIN_OPTION "..."

// macros are weird sometimes ....
#define __APPEND_(X,Y) X ## Y
#define _APPEND(X,Y) __APPEND_(X,Y)

#define DEFINE_CMD(FUNC, FLAGS, HELP, WORD1, ...) \
  static int FUNC(const struct cli_parsed *parsed, struct cli_context *context); \
  static struct cli_schema _APPEND(FUNC, __LINE__) IN_SECTION(commands) = {\
    .function = FUNC, \
    .words = {WORD1, ##__VA_ARGS__, NULL}, \
    .flags = FLAGS, \
    .description = HELP \
  }

DECLARE_SECTION(struct cli_schema, commands);

#define CMD_COUNT (SECTION_START(commands) - SECTION_END(commands))

int commandline_main(struct cli_context *context, const char *argv0, int argc, const char *const *args);
int commandline_main_stdio(FILE *output, const char *argv0, int argc, const char *const *args);

// Trigger that is called after every command has finished.  Different
// sub-systems (eg, keyring, Rhizome) use this to reset their global state
// ready for the next command.
DECLARE_TRIGGER(cmd_cleanup, struct cli_context *context);

#endif // __SERVAL_DNA__COMMANDLINE_H
