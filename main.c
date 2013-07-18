/*
Serval daemon
Copyright (C) 2012 The Serval Project

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

#include "serval.h"
#include "conf.h"

int main(int argc, char **argv)
{
#if defined WIN32
  WSADATA wsa_data;
  WSAStartup(MAKEWORD(1,1), &wsa_data);
#endif
  /* Setup signal handlers */
  signal(SIGPIPE,sigPipeHandler);
  signal(SIGIO,sigIoHandler);

  srandomdev();
  server_save_argv(argc, (const char*const*)argv);
  cf_init();
  int status = parseCommandLine(NULL, argv[0], argc - 1, (const char*const*)&argv[1]);
#if defined WIN32
  WSACleanup();
#endif
  return status;
}

#if 0
#include <execinfo.h>
#define MAX_DEPTH 64
int printBackTrace()
{
  int i,depth=0;
  void *functions[MAX_DEPTH];
  char **function_names;
  
  depth = backtrace (functions, MAX_DEPTH);
  function_names = backtrace_symbols (functions, depth);
     
  for(i=0;i<depth;i++)
    fprintf(stderr,"%s\n", function_names[i]);

  return 0;
}
#endif
