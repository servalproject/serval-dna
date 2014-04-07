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

#include <dirent.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <libgen.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include "serval.h"
#include "conf.h"
#include "strbuf.h"
#include "strbuf_helpers.h"
#include "overlay_interface.h"

#define PROC_SUBDIR	  "proc"
#define PIDFILE_NAME	  "servald.pid"
#define STOPFILE_NAME	  "servald.stop"

static char pidfile_path[256];

#define EXEC_NARGS 20
char *exec_args[EXEC_NARGS + 1];
unsigned exec_argc = 0;

int servalShutdown = 0;

static int server_getpid = 0;

void signal_handler(int signal);
void crash_handler(int signal);

/** Return the PID of the currently running server process, return 0 if there is none.
 */
int server_pid()
{
  char dirname[1024];
  if (!FORMF_SERVAL_RUN_PATH(dirname, NULL))
    return -1;
  struct stat st;
  if (stat(dirname, &st) == -1)
    return WHYF_perror("stat(%s)", alloca_str_toprint(dirname));
  if ((st.st_mode & S_IFMT) != S_IFDIR)
    return WHYF("Not a directory: %s", dirname);
  const char *ppath = server_pidfile_path();
  if (ppath == NULL)
    return -1;
  const char *p = strrchr(ppath, '/');
  assert(p != NULL);

  FILE *f = fopen(ppath, "r");
  if (f == NULL) {
    if (errno != ENOENT)
      return WHYF_perror("fopen(%s,\"r\")", alloca_str_toprint(ppath));
  } else {
    char buf[20];
    int pid = (fgets(buf, sizeof buf, f) != NULL) ? atoi(buf) : -1;
    fclose(f);
    if (pid > 0 && kill(pid, 0) != -1)
      return pid;
    INFOF("Unlinking stale pidfile %s", ppath);
    unlink(ppath);
  }
  return 0;
}

const char *_server_pidfile_path(struct __sourceloc __whence)
{
  if (!pidfile_path[0]) {
    if (!FORMF_SERVAL_RUN_PATH(pidfile_path, PIDFILE_NAME))
      return NULL;
  }
  return pidfile_path;
}

void server_save_argv(int argc, const char *const *argv)
{
    /* Save our argv[] to use for relaunching */
    for (exec_argc = 0; exec_argc < (unsigned)argc && exec_argc < EXEC_NARGS; ++exec_argc)
      exec_args[exec_argc] = strdup(argv[exec_argc]);
    exec_args[exec_argc] = NULL;
}

int server()
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
  sig.sa_flags = 0;
  sigaction(SIGHUP, &sig, NULL);
  sigaction(SIGINT, &sig, NULL);

  overlayServerMode();

  RETURN(0);
  OUT();
}

int server_write_pid()
{
  /* Record PID to advertise that the server is now running */
  const char *ppath = server_pidfile_path();
  if (ppath == NULL)
    return -1;
  FILE *f = fopen(ppath, "w");
  if (!f)
    return WHYF_perror("fopen(%s,\"w\")", alloca_str_toprint(ppath));
  server_getpid = getpid();
  fprintf(f,"%d\n", server_getpid);
  fclose(f);
  return 0;
}

static int get_proc_path(const char *path, char *buf, size_t bufsiz)
{
  if (!formf_serval_run_path(buf, bufsiz, PROC_SUBDIR "/%s", path))
    return -1;
  return 0;
}

int server_write_proc_state(const char *path, const char *fmt, ...)
{
  char path_buf[400];
  if (get_proc_path(path, path_buf, sizeof path_buf)==-1)
    return -1;
    
  size_t dirsiz = strlen(path_buf) + 1;
  char dir_buf[dirsiz];
  strcpy(dir_buf, path_buf);
  const char *dir = dirname(dir_buf); // modifies dir_buf[]
  if (mkdirs_info(dir, 0700) == -1)
    return WHY_perror("mkdirs()");
  
  FILE *f = fopen(path_buf, "w");
  if (!f)
    return WHY_perror("fopen()");
  
  va_list ap;
  va_start(ap, fmt);
  vfprintf(f, fmt, ap);
  va_end(ap);
  
  fclose(f);
  return 0;
}

int server_get_proc_state(const char *path, char *buff, size_t buff_len)
{
  char path_buf[400];
  if (get_proc_path(path, path_buf, sizeof path_buf)==-1)
    return -1;
  
  FILE *f = fopen(path_buf, "r");
  if (!f)
    return -1;
  
  int ret=0;
  
  if (!fgets(buff, buff_len, f))
    ret = WHY_perror("fgets");
  
  fclose(f);
  return ret;
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
  if (!FORMF_SERVAL_RUN_PATH(stopfile, STOPFILE_NAME))
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
  if (!FORMF_SERVAL_RUN_PATH(stopfile, STOPFILE_NAME))
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
  if (!FORMF_SERVAL_RUN_PATH(stopfile, STOPFILE_NAME))
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

static void clean_proc()
{
  char path_buf[400];
  if (FORMF_SERVAL_RUN_PATH(path_buf, PROC_SUBDIR)) {
    DIR *dir;
    struct dirent *dp;
    if ((dir = opendir(path_buf)) == NULL) {
      WARNF_perror("opendir(%s)", alloca_str_toprint(path_buf));
      return;
    }
    while ((dp = readdir(dir)) != NULL) {
      if (FORMF_SERVAL_RUN_PATH(path_buf, PROC_SUBDIR "/%s", dp->d_name)) {
	struct stat st;
	if (lstat(path_buf, &st) == -1)
	  WARNF_perror("stat(%s)", path_buf);
	else if (S_ISREG(st.st_mode))
	  unlink(path_buf);
      }
    }
    closedir(dir);
  }
}

void serverCleanUp()
{
  if (serverMode){
    rhizome_close_db();
    dna_helper_shutdown();
    overlay_interface_close_all();
  }
  
  overlay_mdp_clean_socket_files();
  
  clean_proc();
  
  /* Try to remove shutdown and PID files and exit */
  server_remove_stopfile();
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
    unsigned i;
    overlay_interface_close_all();
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
