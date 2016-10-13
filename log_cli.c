/*
Serval DNA logging
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
#include "log.h"
#include "conf.h" // for IF_DEBUG()

DEFINE_FEATURE(cli_log);

DEFINE_CMD(app_log, CLIFLAG_PERMISSIVE_CONFIG,
  "Log the supplied message at given level.",
  "log","error|warn|hint|info|debug","<message>");
static int app_log(const struct cli_parsed *parsed, struct cli_context *UNUSED(context))
{
  DEBUG_cli_parsed(verbose, parsed);
  assert(parsed->argc == 3);
  const char *lvl = parsed->args[1];
  const char *msg = parsed->args[2];
  int level = string_to_log_level(lvl);
  if (level == LOG_LEVEL_INVALID)
    return WHYF("invalid log level: %s", lvl);
  logMessage(level, __NOWHERE__, "%s", msg);
  return 0;
}
