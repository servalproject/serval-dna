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
#include "overlay_packet.h"
#include "server.h"

#define PROC_SUBDIR	  "proc"
#define PIDFILE_NAME	  "servald.pid"
#define STOPFILE_NAME	  "servald.stop"

static char pidfile_path[256];

static int server_getpid = 0;

void signal_handler(int signal);

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

  /* Catch SIGHUP etc so that we can respond to requests to do things, eg, shut down. */
  struct sigaction sig;
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
DEFINE_ALARM(server_config_reload);
void server_config_reload(struct sched_ent *alarm)
{
  switch (cf_reload_strict()) {
  case -1:
    WARN("server continuing with prior config");
    break;
  case 0:
    break;
  default:
    INFO("server config reloaded");
    break;
  }
  switch (reload_mdp_packet_rules()) {
  case -1:
    WARN("server continuing with prior packet filter rules");
    break;
  case 0:
    break;
  default:
    INFO("server packet filter rules reloaded");
    break;
  }
  if (alarm) {
    time_ms_t now = gettime_ms();
    alarm->alarm = now + config.server.config_reload_interval_ms;
    alarm->deadline = alarm->alarm + 100;
    schedule(alarm);
  }
}

/* Called periodically by the server process in its main loop.
 */
DEFINE_ALARM(server_watchdog);
void server_watchdog(struct sched_ent *alarm)
{
  if (config.server.watchdog.executable[0]) {
    const char *argv[2];
    argv[0] = config.server.watchdog.executable;
    argv[1] = NULL;
    strbuf argv_sb = strbuf_append_argv(strbuf_alloca(1024), 1, argv);
    switch (fork()) {
    case 0: {
      /* Child, should fork() again to create orphan process. */
      pid_t watchdog_pid;
      switch (watchdog_pid = fork()) {
      case 0:
	/* Grandchild, should exec() watchdog. */
	close_log_file();
	signal(SIGTERM, SIG_DFL);
	close(0);
	close(1);
	close(2);
	execv(config.server.watchdog.executable, (char **)argv);
	// Don't use FATALF_perror() because we want to use _exit(2) not exit(2).
	LOGF_perror(LOG_LEVEL_FATAL, "execv(%s, [%s])",
	    alloca_str_toprint(config.server.watchdog.executable),
	    strbuf_str(argv_sb)
	  );
	break;
      case -1:
	/* grandchild fork failed */
	WHY_perror("fork");
	break;
      default:
	/* Child, report grandchild's PID. */
	if (config.debug.watchdog)
	  LOGF(LOG_LEVEL_DEBUG, "STARTED WATCHDOG pid=%u executable=%s argv=[%s]",
	      watchdog_pid,
	      alloca_str_toprint(config.server.watchdog.executable),
	      strbuf_str(argv_sb)
	    );
	do { _exit(0); } while (1);
	break;
      }
      do { _exit(-1); } while (1);
      break;
    }
    case -1:
      /* child fork failed */
      WHY_perror("fork");
      break;
    }
  }
  if (alarm) {
    time_ms_t now = gettime_ms();
    alarm->alarm = now + config.server.watchdog.interval_ms;
    alarm->deadline = alarm->alarm + 100;
    schedule(alarm);
  }
}

void cf_on_config_change()
{
  if (!serverMode)
    return;
  
  time_ms_t now = gettime_ms();
  
  dna_helper_start();
  directory_service_init();
  
  /* Periodically check for new interfaces */
  RESCHEDULE_ALARM(overlay_interface_discover, now, 100);
  
  if (link_has_neighbours())
    // send rhizome sync periodically
    RESCHEDULE_ALARM(rhizome_sync_announce, now+1000, 10000);

  if (config.server.watchdog.executable[0])
    RESCHEDULE_ALARM(server_watchdog, now+config.server.watchdog.interval_ms, 100);
  
}

/* Called periodically by the server process in its main loop.
 */
DEFINE_ALARM(server_shutdown_check);
void server_shutdown_check(struct sched_ent *alarm)
{
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
}

void signal_handler(int signal)
{
  switch (signal) {
    case SIGHUP:
    case SIGINT:
      /* Trigger the server to close gracefully after any current alarm has completed. 
         If we get a second signal, exit now.
      */
      if (serverMode==1){
	INFO("Attempting clean shutdown");
	serverMode=2;
	return;
      }
    default:
      LOGF(LOG_LEVEL_FATAL, "Caught signal %s", alloca_signal_name(signal));
      LOGF(LOG_LEVEL_FATAL, "The following clue may help: %s", crash_handler_clue); 
      dump_stack(LOG_LEVEL_FATAL);
  }
  
  serverCleanUp();
  exit(0);
}
