/* 
Serval Distributed Numbering Architecture (DNA)
Copyright (C) 2010 Paul Gardner-Stephen 

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
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>

#include "serval.h"
#include "conf.h"
#include "strbuf.h"
#include "strbuf_helpers.h"

#define PIDFILE_NAME	  "servald.pid"
#define STOPFILE_NAME	  "servald.stop"

#define EXEC_NARGS 20
char *exec_args[EXEC_NARGS + 1];
int exec_argc = 0;

int servalShutdown = 0;

static int server_getpid = 0;

void signal_handler(int signal);
void crash_handler(int signal);
int getKeyring(char *s);

/** Return the PID of the currently running server process, return 0 if there is none.
 */
int server_pid()
{
  const char *instancepath = serval_instancepath();
  struct stat st;
  if (stat(instancepath, &st) == -1) {
    WHY_perror("stat");
    return WHYF("Instance path '%s' non existant or not accessable"
	" (Set SERVALINSTANCE_PATH to specify an alternate location)",
	instancepath
      );
  }
  if ((st.st_mode & S_IFMT) != S_IFDIR)
    return WHYF("Instance path '%s' is not a directory", instancepath);
  char filename[1024];
  if (!FORM_SERVAL_INSTANCE_PATH(filename, PIDFILE_NAME))
    return -1;
  FILE *f = NULL;
  if ((f = fopen(filename, "r"))) {
    char buf[20];
    int pid = (fgets(buf, sizeof buf, f) != NULL) ? atoi(buf) : -1;
    fclose(f);
    if (pid > 0 && kill(pid, 0) != -1)
      return pid;
    INFOF("Unlinking stale pidfile %s", filename);
    unlink(filename);
  }
  return 0;
}

void server_save_argv(int argc, const char *const *argv)
{
    /* Save our argv[] to use for relaunching */
    for (exec_argc = 0; exec_argc < argc && exec_argc < EXEC_NARGS; ++exec_argc)
      exec_args[exec_argc] = strdup(argv[exec_argc]);
    exec_args[exec_argc] = NULL;
}

int server(char *backing_file)
{
  IN();
  /* For testing, it can be very helpful to delay the start of the server process, for example to
   * check that the start/stop logic is robust.
   */
  const char *delay = getenv("SERVALD_SERVER_START_DELAY");
  if (delay)
    sleep_ms(atoi(delay));

  serverMode = 1;

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

  /* Catch SIGHUP etc so that we can respond to requests to do things, eg, shut down. */
  sig.sa_handler = signal_handler;
  sigemptyset(&sig.sa_mask); // Block the same signals during handler
  sigaddset(&sig.sa_mask, SIGHUP);
  sigaddset(&sig.sa_mask, SIGINT);
  sigaddset(&sig.sa_mask, SIGQUIT);
  sig.sa_flags = 0;
  sigaction(SIGHUP, &sig, NULL);
  sigaction(SIGINT, &sig, NULL);
  sigaction(SIGQUIT, &sig, NULL);

  /* Record PID to advertise that the server is now running */
  char filename[1024];
  if (!FORM_SERVAL_INSTANCE_PATH(filename, PIDFILE_NAME))
    RETURN(-1);
  FILE *f=fopen(filename,"w");
  if (!f) {
    WHY_perror("fopen");
    RETURN(WHYF("Could not write to PID file %s", filename));
  }
  server_getpid = getpid();
  fprintf(f,"%d\n", server_getpid);
  fclose(f);
  
  overlayServerMode();

  RETURN(0);
  OUT();
}

/* Called periodically by the server process in its main loop.
 */
void server_config_reload(struct sched_ent *alarm)
{
  switch (cf_reload_strict()) {
  case -1:
    WARN("server continuing with prior config");
    break;
  case 0:
    break;
  default:
    INFO("server config successfully reloaded");
    break;
  }
  if (alarm) {
    time_ms_t now = gettime_ms();
    alarm->alarm = now + SERVER_CONFIG_RELOAD_INTERVAL_MS;
    alarm->deadline = alarm->alarm + 1000;
    schedule(alarm);
  }
}

/* Called periodically by the server process in its main loop.
 */
void server_shutdown_check(struct sched_ent *alarm)
{
  if (servalShutdown) {
    INFO("Shutdown flag set -- terminating with cleanup");
    serverCleanUp();
    exit(0);
  }
  if (server_check_stopfile() == 1) {
    INFO("Shutdown file exists -- terminating with cleanup");
    serverCleanUp();
    exit(0);
  }
  /* If this server has been supplanted with another or Serval has been uninstalled, then its PID
      file will change or be unaccessible.  In this case, shut down without all the cleanup.
      Perform this check at most once per second.  */
  static time_ms_t server_pid_time_ms = 0;
  time_ms_t now = gettime_ms();
  if (server_pid_time_ms == 0 || now - server_pid_time_ms > 1000) {
    server_pid_time_ms = now;
    if (server_pid() != server_getpid) {
      WARNF("Server pid file no longer contains pid=%d -- shutting down without cleanup", server_getpid);
      exit(1);
    }
  }
  if (alarm){
    alarm->alarm = now + 1000;
    alarm->deadline = alarm->alarm + 5000;
    schedule(alarm);
  }
}

int server_create_stopfile()
{
  char stopfile[1024];
  if (!FORM_SERVAL_INSTANCE_PATH(stopfile, STOPFILE_NAME))
    return -1;
  FILE *f;
  if ((f = fopen(stopfile, "w")) == NULL) {
    WHY_perror("fopen");
    return WHYF("Could not create stopfile '%s'", stopfile);
  }
  fclose(f);
  return 0;
}

int server_remove_stopfile()
{
  char stopfile[1024];
  if (!FORM_SERVAL_INSTANCE_PATH(stopfile, STOPFILE_NAME))
    return -1;
  if (unlink(stopfile) == -1) {
    if (errno == ENOENT)
      return 0;
    WHY_perror("unlink");
    return WHYF("Could not unlink stopfile '%s'", stopfile);
  }
  return 1;
}

int server_check_stopfile()
{
  char stopfile[1024];
  if (!FORM_SERVAL_INSTANCE_PATH(stopfile, STOPFILE_NAME))
    return -1;
  int r = access(stopfile, F_OK);
  if (r == 0)
    return 1;
  if (r == -1 && errno == ENOENT)
    return 0;
  WHY_perror("access");
  WHYF("Cannot access stopfile '%s'", stopfile);
  return -1;
}

void serverCleanUp()
{
  /* Try to remove shutdown and PID files and exit */
  server_remove_stopfile();
  char filename[1024];
  if (FORM_SERVAL_INSTANCE_PATH(filename, PIDFILE_NAME))
    unlink(filename);
  
  if (FORM_SERVAL_INSTANCE_PATH(filename, "mdp.socket")) {
    unlink(filename);
  }
  
  rhizome_close_db();
  
  dna_helper_shutdown();
}

static void signame(char *buf, size_t len, int signal)
{
  const char *desc = "";
  switch(signal) {
#ifdef SIGHUP
  case SIGHUP: desc = "HUP"; break;
#endif
#ifdef SIGINT
  case SIGINT: desc = "INT"; break;
#endif
#ifdef SIGQUIT
  case SIGQUIT: desc = "QUIT"; break;
#endif
#ifdef SIGILL
  case SIGILL: desc = "ILL (not reset when caught)"; break;
#endif
#ifdef SIGTRAP
  case SIGTRAP: desc = "TRAP (not reset when caught)"; break;
#endif
#ifdef SIGABRT
  case SIGABRT: desc = "ABRT"; break;
#endif
#ifdef SIGPOLL
  case SIGPOLL: desc = "POLL ([XSR] generated, not supported)"; break;
#endif
#ifdef SIGEMT
  case SIGEMT: desc = "EMT"; break;
#endif
#ifdef SIGFPE
  case SIGFPE: desc = "FPE"; break;
#endif
#ifdef SIGKILL
  case SIGKILL: desc = "KILL (cannot be caught or ignored)"; break;
#endif
#ifdef SIGBUS
  case SIGBUS: desc = "BUS"; break;
#endif
#ifdef SIGSEGV
  case SIGSEGV: desc = "SEGV"; break;
#endif
#ifdef SIGSYS
  case SIGSYS: desc = "SYS"; break;
#endif
#ifdef SIGPIPE
  case SIGPIPE: desc = "PIPE"; break;
#endif
#ifdef SIGALRM
  case SIGALRM: desc = "ALRM"; break;
#endif
#ifdef SIGTERM
  case SIGTERM: desc = "TERM"; break;
#endif
#ifdef SIGURG
  case SIGURG: desc = "URG"; break;
#endif
#ifdef SIGSTOP
  case SIGSTOP: desc = "STOP"; break;
#endif
#ifdef SIGTSTP
  case SIGTSTP: desc = "TSTP"; break;
#endif
#ifdef SIGCONT
  case SIGCONT: desc = "CONT"; break;
#endif
#ifdef SIGCHLD
  case SIGCHLD: desc = "CHLD"; break;
#endif
#ifdef SIGTTIN
  case SIGTTIN: desc = "TTIN"; break;
#endif
#ifdef SIGTTOU
  case SIGTTOU: desc = "TTOU"; break;
#endif
#ifdef SIGIO
#if SIGIO != SIGPOLL          
  case SIGIO: desc = "IO"; break;
#endif
#endif
#ifdef SIGXCPU
  case SIGXCPU: desc = "XCPU"; break;
#endif
#ifdef SIGXFSZ
  case SIGXFSZ: desc = "XFSZ"; break;
#endif
#ifdef SIGVTALRM
  case SIGVTALRM: desc = "VTALRM"; break;
#endif
#ifdef SIGPROF
  case SIGPROF: desc = "PROF"; break;
#endif
#ifdef SIGWINCH
  case SIGWINCH: desc = "WINCH"; break;
#endif
#ifdef SIGINFO
  case SIGINFO: desc = "INFO"; break;
#endif
#ifdef SIGUSR1
  case SIGUSR1: desc = "USR1"; break;
#endif
#ifdef SIGUSR2
  case SIGUSR2: desc = "USR2"; break;
#endif
  }
  snprintf(buf, len, "SIG%s (%d) %s", desc, signal, strsignal(signal));
  buf[len - 1] = '\0';
}

void signal_handler(int signal)
{
  switch (signal) {
    case SIGHUP:
    case SIGINT:
      /* Terminate the server process.  The shutting down should be done from the main-line code
	 rather than here, so we first try to tell the mainline code to do so.  If, however, this is
	 not the first time we have been asked to shut down, then we will do it here. */
      server_shutdown_check(NULL);
      INFO("Attempting clean shutdown");
      servalShutdown = 1;
      return;
  }
  
  char buf[80];
  signame(buf, sizeof(buf), signal);
  
  LOGF(LOG_LEVEL_FATAL, "Caught signal %s", buf);
  LOGF(LOG_LEVEL_FATAL, "The following clue may help: %s",crash_handler_clue); 
  dump_stack(LOG_LEVEL_FATAL);

  serverCleanUp();
  exit(0);
}

char crash_handler_clue[1024]="no clue";
void crash_handler(int signal)
{
  char buf[80];
  signame(buf, sizeof(buf), signal);
  LOGF(LOG_LEVEL_FATAL, "Caught signal %s", buf);
  LOGF(LOG_LEVEL_FATAL, "The following clue may help: %s",crash_handler_clue); 
  dump_stack(LOG_LEVEL_FATAL);
  
  BACKTRACE;
  if (config.server.respawn_on_crash) {
    int i;
    for(i=0;i<overlay_interface_count;i++)
      if (overlay_interfaces[i].alarm.poll.fd>-1)
	close(overlay_interfaces[i].alarm.poll.fd);
    char execpath[160];
    if (get_self_executable_path(execpath, sizeof execpath) != -1) {
      strbuf b = strbuf_alloca(1024);
      for (i = 0; i < exec_argc; ++i)
	strbuf_append_shell_quotemeta(strbuf_puts(b, i ? " " : ""), exec_args[i]);
      INFOF("Respawning %s as %s", execpath, strbuf_str(b));
      execv(execpath, exec_args);
      /* Quit if the exec() fails */
      WHY_perror("execv");
    } else {
      WHY("Cannot respawn");
    }
  }
  // Now die of the same signal, so that our exit status reflects the cause.
  INFOF("Re-sending signal %d to self", signal);
  kill(getpid(), signal);
  // If that didn't work, then die normally.
  INFOF("exit(%d)", -signal);
  exit(-signal);
}

int getKeyring(char *backing_file)
{
 if (!backing_file)
    {     
      exit(WHY("Keyring requires a backing file"));
    }
  else
    {
      if (keyring) 
	exit(WHY("Keyring being opened twice"));
      keyring=keyring_open(backing_file);
      /* unlock all entries with blank pins */
      keyring_enter_pin(keyring, "");
    }
 keyring_seed(keyring);

 return 0;
}
