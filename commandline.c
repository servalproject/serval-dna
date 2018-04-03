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

#include "commandline.h"
#include "conf.h"
#include "str.h"
#include "cli_stdio.h"

DEFINE_CMD(app_usage, CLIFLAG_PERMISSIVE_CONFIG,
  "Display command usage.",
  "help|-h|--help","...");
static int app_usage(const struct cli_parsed *parsed, struct cli_context *UNUSED(context))
{
  return cli_usage_parsed(parsed, XPRINTF_STDIO(stdout));
}

/* Parse the command line and load the configuration.  If a command was found then execute the
 * parsed command and return its return value.
 *
 * 'context' controls the command output.
 *
 * 'argv0' must be NULL or be a nul-terminated string containing the name or path of the executable.
 * It is used to emit diagnostic messages.
 *
 * 'argc' and 'args' must contain the command-line words to parse.
 */
int commandline_main(struct cli_context *context, const char *argv0, int argc, const char *const *args)
{
  fd_clearstats();
  IN();

  cf_init();

  struct cli_parsed parsed;
  int result = cli_parse(argc, args, SECTION_START(commands), SECTION_END(commands), &parsed);
  switch (result) {
  case 0:
    // Do not run the command if the configuration does not load ok.
    if (((parsed.commands[parsed.cmdi].flags & CLIFLAG_PERMISSIVE_CONFIG) ? cf_reload_permissive() : cf_reload()) != -1)
      result = cli_invoke(&parsed, context);
    else {
      strbuf b = strbuf_alloca(160);
      strbuf_append_argv(b, argc, args);
      result = WHYF("configuration defective, not running command: %s", strbuf_str(b));
    }
    break;
  case 1:
  case 2:
    // Load configuration so that log messages can get out.
    cf_reload_permissive();
    NOWHENCE(HINTF("Run \"%s help\" for more information.", argv0 ? argv0 : "servald"));
    result =-1;
    break;
  default:
    // Load configuration so that log error messages can get out.
    cf_reload_permissive();
    break;
  }

  CALL_TRIGGER(cmd_cleanup, context);

  OUT();

  if (IF_DEBUG(timing))
    fd_showstats();
  return result;
}

// Put a dummy no-op trigger callback into the "cmd_cleanup" trigger section,
// otherwise if no other object provides one, the link will fail with errors like:
// undefined reference to `__start_tr_cmd_cleanup'
// undefined reference to `__stop_tr_cmd_cleanup'

static void __dummy_on_cmd_cleanup() {}
DEFINE_TRIGGER(cmd_cleanup, __dummy_on_cmd_cleanup);

