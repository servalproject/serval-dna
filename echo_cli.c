/*
Serval DNA utilities
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

#include "feature.h"
#include "commandline.h"
#include "debug.h"
#include "conf.h" // for IF_DEBUG()

DEFINE_FEATURE(cli_echo);

DEFINE_CMD(app_echo, CLIFLAG_PERMISSIVE_CONFIG,
  "Output the supplied string.",
  "echo","[-e]","[--]","...");
static int app_echo(const struct cli_parsed *parsed, struct cli_context *context)
{
  DEBUG_cli_parsed(verbose, parsed);
  int escapes = !cli_arg(parsed, "-e", NULL, NULL, NULL);
  unsigned i;
  for (i = parsed->varargi; i < parsed->argc; ++i) {
    const char *arg = parsed->args[i];
    DEBUGF(verbose, "echo:argv[%d]=\"%s\"", i, arg);
    if (escapes) {
      char buf[strlen(arg)];
      size_t len = strn_fromprint(buf, sizeof buf, arg, 0, '\0', NULL);
      cli_write(context, buf, len);
    } else
      cli_puts(context, arg);
    cli_delim(context, NULL);
  }
  return 0;
}
