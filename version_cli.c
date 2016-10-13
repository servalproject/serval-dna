/*
Serval DNA version and copyright
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
#include "version_servald.h"

DEFINE_FEATURE(cli_version);

DEFINE_CMD(version_message, CLIFLAG_PERMISSIVE_CONFIG,
  "Display version and copyright information.",
  "version|copyright");
static int version_message(const struct cli_parsed *UNUSED(parsed), struct cli_context *UNUSED(context))
{
  printf("Serval DNA version %s\n%s\n", version_servald, copyright_servald);
  printf("\
License GPLv2+: GNU GPL version 2 or later <http://gnu.org/licenses/gpl.html>.\n\
This is free software: you are free to change and redistribute it.\n\
There is NO WARRANTY, to the extent permitted by law.\n\
");
  return 0;
}
