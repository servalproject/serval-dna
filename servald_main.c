/*
Serval DNA main command-line entry point
Copyright (C) 2012 Serval Project Inc.
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

#include <signal.h>
#include "servald_main.h"
#include "commandline.h"
#include "cli_stdio.h"
#include "sighandlers.h"
#include "conf.h"

static void crash_handler(int signal);

int servald_main(int argc, char **argv)
{
#if defined WIN32
  WSADATA wsa_data;
  WSAStartup(MAKEWORD(1,1), &wsa_data);
#endif
  /* Catch crash signals so that we can log a backtrace before expiring. */
  struct sigaction sig;
  sig.sa_handler = crash_handler;
  sigemptyset(&sig.sa_mask); // Don't block any signals during handler
  sig.sa_flags = SA_NODEFER | SA_RESETHAND; // So the signal handler can kill the process by re-sending the same signal to itself
  sigaction(SIGSEGV, &sig, NULL);
  sigaction(SIGFPE, &sig, NULL);
  sigaction(SIGILL, &sig, NULL);
  sigaction(SIGBUS, &sig, NULL);
  sigaction(SIGABRT, &sig, NULL);

  /* Setup i/o signal handlers */
  signal(SIGPIPE, sigPipeHandler);
  signal(SIGIO, sigIoHandler);

  struct cli_context_stdio cli_context_stdio = {
    .fp = stdout
  };
  struct cli_context cli_context = {
    .vtable = &cli_vtable_stdio,
    .context = &cli_context_stdio
  };

  int status = commandline_main(&cli_context, argv[0], argc - 1, (const char*const*)&argv[1]);

#if defined WIN32
  WSACleanup();
#endif
  return status;
}

static void crash_handler(int signum)
{
  LOGF(LOG_LEVEL_FATAL, "Caught signal %s", alloca_signal_name(signum));
  dump_stack(LOG_LEVEL_FATAL);
  BACKTRACE;
  // Exit with a status code indicating the caught signal.  This involves removing the signal
  // handler for the caught signal then re-sending the same signal to ourself.  If that doesn't
  // work, then exit with an error code.
  struct sigaction sig;
  bzero(&sig, sizeof sig);
  sig.sa_flags = 0;
  sig.sa_handler = SIG_DFL;
  sigemptyset(&sig.sa_mask);
  sigaction(signum, &sig, NULL);
  INFOF("Re-sending signal %d to self", signum);
  kill(getpid(), signum); // should terminate self
  exit(-1);
}
