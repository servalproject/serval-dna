/*
Serval DNA server main loop
Copyright (C) 2010 Paul Gardner-Stephen
Copyright (C) 2011-2015 Serval Project Inc.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <dirent.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <libgen.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#ifdef HAVE_LINUX_THREADS
#include <sys/syscall.h>
#endif

#include "server.h"
#include "serval.h"
#include "rhizome.h"
#include "conf.h"
#include "log.h"
#include "str.h"
#include "numeric_str.h"
#include "strbuf.h"
#include "strbuf_helpers.h"
#include "overlay_interface.h"
#include "overlay_packet.h"
#include "keyring.h"
#include "commandline.h"
#include "mdp_client.h"
#include "route_link.h"
#include "httpd.h"
#include "debug.h"

DEFINE_FEATURE(cli_server);

#define PROC_SUBDIR	  "proc"
#define PIDFILE_NAME	  "servald.pid"
#define STOPFILE_NAME	  "servald.stop"

__thread enum server_mode serverMode = SERVER_NOT_RUNNING;

struct pid_tid {
  pid_t pid;
  pid_t tid;
};

static struct pid_tid server_pid_tid = { .pid = 0, .tid = 0 };
static int server_pidfd = -1;
static int server();
static int server_write_pid();
static void signal_handler(int signal);
static void serverCleanUp();
static const char *_server_pidfile_path(struct __sourceloc __whence);
#define server_pidfile_path() (_server_pidfile_path(__WHENCE__))

static int server_get_proc_state(const char *path, char *buff, size_t buff_len);
static void server_stop_alarms();

// Define our own gettid() and tgkill() if <unistd.h> doesn't provide them (eg, it does on Android).

#ifndef HAVE_GETTID
static pid_t gettid()
{
#ifdef HAVE_LINUX_THREADS
  return syscall(SYS_gettid);
#else
  return getpid();
#endif
}
#endif // !HAVE_GETTID

#ifdef HAVE_LINUX_THREADS
#ifndef HAVE_TGKILL
static int tgkill(int tgid, int tid, int signum)
{
  return syscall(SYS_tgkill, tgid, tid, signum);
}
#endif // !HAVE_TGKILL
#endif // HAVE_LINUX_THREADS

// Read the PID and TID from the given pidfile, returning a PID of 0 if the file does not exist, or
// a PID of -1 if the file exists but contains invalid content or is not locked by process PID,
// otherwise the PID/TID of the process that has the lock on the file.
static struct pid_tid read_pidfile(const char *path)
{
  int fd = open(path, O_RDONLY);
  if (fd == -1) {
    if (errno == ENOENT)
      return (struct pid_tid){ .pid = 0, .tid = 0 };
    WHYF_perror("open(%s, O_RDONLY)", alloca_str_toprint(path));
    return (struct pid_tid){ .pid = -1, .tid = -1 };
  }
  int32_t pid = -1;
  int32_t tid = -1;
  char buf[30];
  ssize_t len = read(fd, buf, sizeof buf);
  if (len == -1) {
    WHYF_perror("read(%s, %p, %zu)", alloca_str_toprint(path), buf, sizeof buf);
  } else if (len > 0 && (size_t)len < sizeof buf) {
    DEBUGF(server, "Read from pidfile %s: %s", path, alloca_toprint(-1, buf, len));
    buf[len] = '\0';
    const char *e = NULL;
    if (!str_to_int32(buf, 10, &pid, &e))
      pid = -1;
    else if (*e == ' ')
      str_to_int32(e + 1, 10, &tid, NULL);
    else
      tid = pid;
  } else {
    WARNF("Pidfile %s has invalid content: %s", path, alloca_toprint(-1, buf, len));
  }
  if (pid > 0) {
    // Only return a valid pid/tid if the file is currently locked by the same process that it
    // identifies.
    struct flock lock;
    bzero(&lock, sizeof lock);
    lock.l_type = F_RDLCK;
    lock.l_start = 0;
    lock.l_whence = SEEK_SET;
    lock.l_len = len;
    fcntl(fd, F_GETLK, &lock);
    if (lock.l_type == F_UNLCK || lock.l_pid != pid) {
      DEBUGF(server, "Pidfile %s is not locked by pid %d", path, pid);
      pid = tid = -1;
    }
  }
  close(fd);
  return (struct pid_tid){ .pid = pid, .tid = tid };
}

static struct pid_tid get_server_pid_tid()
{
  // If the server process closes another handle on the same file, its lock will disappear, so this
  // guards against that happening.
  if (server_pid_tid.pid == getpid())
    return server_pid_tid;
  // Attempt to read the pid, and optionally the tid (Linux thread ID) from the pid file.
  char dirname[1024];
  if (!FORMF_SERVAL_RUN_PATH(dirname, NULL))
    goto error;
  struct stat st;
  if (stat(dirname, &st) == -1) {
    WHYF_perror("stat(%s)", alloca_str_toprint(dirname));
    goto error;
  }
  if ((st.st_mode & S_IFMT) != S_IFDIR) {
    WHYF("Not a directory: %s", dirname);
    goto error;
  }
  const char *pidfile_path = server_pidfile_path();
  if (pidfile_path == NULL)
    goto error;
  assert(strrchr(pidfile_path, '/') != NULL);
  struct pid_tid id = read_pidfile(pidfile_path);
  if (id.pid == -1) {
    DEBUGF(server, "Unlinking stale pidfile %s", pidfile_path);
    unlink(pidfile_path);
    id.pid = 0;
  }
  return id;
error:
  return (struct pid_tid){ .pid = -1, .tid = -1 };
}

// Send a signal to a given process.  Returns 0 if sent, 1 if not sent because the process is non
// existent (ESRCH), or -1 if not sent due to another error (eg, EPERM).
static int send_signal(const struct pid_tid *id, int signum)
{
#ifdef HAVE_LINUX_THREADS
  if (id->tid > 0) {
    if (tgkill(id->pid, id->tid, signum) == -1) {
      if (errno == ESRCH)
	return 1;
      WHYF_perror("Cannot send %s to Servald pid=%d tid=%d (pidfile %s)", alloca_signal_name(signum), id->pid, id->tid, server_pidfile_path());
      return -1;
    }
    return 0;
  }
#endif // !HAVE_LINUX_THREADS
  if (kill(id->pid, signum) == -1) {
    if (errno == ESRCH)
      return 1;
    WHYF_perror("Cannot send %s to Servald pid=%d (pidfile %s)", alloca_signal_name(signum), id->pid, server_pidfile_path());
    return -1;
  }
  return 0;
}

static const char *_server_pidfile_path(struct __sourceloc __whence)
{
  static char pidfile_path[256];
  if (!pidfile_path[0]) {
    if (!FORMF_SERVAL_RUN_PATH(pidfile_path, PIDFILE_NAME))
      return NULL;
  }
  return pidfile_path;
}

int server_pid()
{
  return get_server_pid_tid().pid;
}

int server_bind()
{
  serverMode = SERVER_RUNNING;

  // Warn, not merely Info, if there is no configured log file.
  serval_log_level_NoLogFileConfigured = LOG_LEVEL_WARN;

  /* Catch SIGHUP etc so that we can respond to requests to do things, eg, shut down. */
  struct sigaction sig;
  bzero(&sig, sizeof sig);
  
  sig.sa_flags = 0;
  sig.sa_handler = signal_handler;
  sigemptyset(&sig.sa_mask); // Block the same signals during handler
  sigaddset(&sig.sa_mask, SIGHUP);
  sigaddset(&sig.sa_mask, SIGINT);
  sigaddset(&sig.sa_mask, SIGIO);
  
#ifdef ANDROID
// batphone depends on this constant to wake up the scheduler
// break the build if it changes.
  assert(SIGIO==29);
#endif
  
  sigaction(SIGHUP, &sig, NULL);
  sigaction(SIGINT, &sig, NULL);
  sigaction(SIGIO, &sig, NULL);

  // Perform additional startup, which should be limited to tasks like binding sockets
  // So that clients can initiate a connection once servald start has returned.
  // serverMode should be cleared to indicate failures
  // Any CPU or IO heavy initialisation should be performed in a config changed trigger

  CALL_TRIGGER(startup);
  if (serverMode == 0)
    return -1;

  // start the HTTP server if enabled
  if (httpd_server_start(config.rhizome.http.port, config.rhizome.http.port + HTTPD_PORT_RANGE)==-1) {
    serverMode = 0;
    return -1;
  }

  /* For testing, it can be very helpful to delay the start of the server process, for example to
   * check that the start/stop logic is robust.
   */
  const char *delay = getenv("SERVALD_SERVER_START_DELAY");
  if (delay){
    time_ms_t milliseconds = atoi(delay);
    DEBUGF(server, "Sleeping for %"PRId64" milliseconds", (int64_t) milliseconds);
    sleep_ms(milliseconds);
  }

  /* record PID file so that servald start can return */
  if (server_write_pid()) {
    serverMode = 0;
    return -1;
  }

  overlay_queue_init();

  time_ms_t now = gettime_ms();

  /* Calculate (and possibly show) CPU usage stats periodically */
  RESCHEDULE(&ALARM_STRUCT(fd_periodicstats), now+3000, TIME_MS_NEVER_WILL, now+3500);

  return 0;
}

void server_loop(time_ms_t (*waiting)(time_ms_t, time_ms_t, time_ms_t), void (*wokeup)())
{
  // possible race condition... Shutting down before we even started
  CALL_TRIGGER(conf_change);

  // This log message is used by tests to wait for the server to start.
  INFOF("Server initialised, entering main loop");

  /* Check for activitiy and respond to it */
  while (fd_poll2(waiting, wokeup))
    ;

  INFOF("Server finished, exiting main loop");
  fd_showstats();
  serverCleanUp();

  if (server_pidfd!=-1){
    close(server_pidfd);
    server_pidfd = -1;
    unlink(server_pidfile_path());
  }
}

static int server()
{
  IN();
  if (server_bind()==-1)
    RETURN(-1);

  server_loop(NULL, NULL);

  RETURN(0);
}

static int server_write_pid()
{
  server_write_proc_state("http_port", "%d", httpd_server_port);
  server_write_proc_state("mdp_inet_port", "%d", mdp_loopback_port);

  // Create or unlink the "primary_sid" proc state file.
  get_my_subscriber(0);

  // Create a locked pidfile to advertise that the server is now running.
  const char *pidfile_path = server_pidfile_path();
  if (pidfile_path == NULL)
    return -1;

  // The pidfile content is simply the ASCII decimal PID, optionally followed by a single space and
  // the ASCII decimal Thread ID (tid) if the server is running as a Linux thread that is not the
  // process's main thread.
  int32_t pid = server_pid_tid.pid = getpid();
  int32_t tid = server_pid_tid.tid = gettid();
  char content[30];
  size_t content_size = 0;
  {
    strbuf sb = strbuf_local_buf(content);
    strbuf_sprintf(sb, "%" PRId32, pid);
    if (tid != pid)
      strbuf_sprintf(sb, " %" PRId32, tid);
    assert(!strbuf_overrun(sb));
    content_size = strbuf_len(sb);
  }

  // The pidfile lock covers its whole content.
  struct flock lock;
  bzero(&lock, sizeof lock);
  lock.l_type = F_WRLCK;
  lock.l_start = 0;
  lock.l_whence = SEEK_SET;
  lock.l_len = content_size;

  // Form the name of the temporary pidfile.
  strbuf tmpfile_path_sb = strbuf_alloca(strlen(pidfile_path) + 25);
  strbuf_puts(tmpfile_path_sb, pidfile_path);
  strbuf_sprintf(tmpfile_path_sb, ".%d-%d", pid, tid);
  assert(!strbuf_overrun(tmpfile_path_sb));
  const char *tmpfile_path = strbuf_str(tmpfile_path_sb);

  // Create the temporary pidfile and lock it, deleting any stale temporaries if necessary.  Leave
  // the temporary pidfile open to retain the lock -- if successful it will eventually be the real
  // pidfile.
  DEBUGF(server, "unlink(%s)", alloca_str_toprint(tmpfile_path));
  unlink(tmpfile_path);
  DEBUGF(server, "open(%s, O_RDWR|O_CREAT|O_CLOEXEC)", alloca_str_toprint(tmpfile_path));
  int fd = open(tmpfile_path, O_RDWR | O_CREAT | O_CLOEXEC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  if (fd==-1)
    return WHYF_perror("Cannot create temporary pidfile: open(%s, O_RDWR|O_CREAT|O_CLOEXEC)", alloca_str_toprint(tmpfile_path));
  DEBUG(server, "lock");
  if (fcntl(fd, F_SETLK, &lock) == -1) {
    WHYF_perror("Cannot lock temporary pidfile %s: fcntl(%d, F_SETLK, &lock)", tmpfile_path, fd);
    close(fd);
    return -1;
  }
  if (ftruncate(fd, 0) == -1){
    close(fd);
    return WHYF_perror("ftruncate(%d, 0)", fd);
  }
  DEBUGF(server, "write %s", alloca_toprint(-1, content, content_size));
  if (write(fd, content, content_size) != (ssize_t)content_size){
    close(fd);
    return WHYF_perror("write(%d, %s, %zu)", fd, alloca_str_toprint(content), content_size);
  }

  // Now the locked temporary has been created, link(2) it to the pidfile's proper name, to ensure
  // that the pidfile is locked from the instant of its existence.  Note that link(2) fails if the
  // destination path already exists.  This logic prevents racing with other processes deleting
  // stale (unlocked) pidfiles.  If the link(2) fails the first time because the pidfile already
  // exists, then if the existent pidfile is locked, there is another daemon running, so bail out.
  // If the existent pidfile is not locked, then it is stale, so delete it and re-try the link.
  unsigned int tries = 0;
  while (1) {
    DEBUGF(server, "link(%s, %s)", alloca_str_toprint(tmpfile_path), alloca_str_toprint(pidfile_path));
    if (link(tmpfile_path, pidfile_path) != -1)
      break;
    if (errno == EEXIST && ++tries < 2) {
      struct pid_tid id = read_pidfile(pidfile_path);
      if (id.pid == -1) {
	DEBUGF(server, "Unlinking stale pidfile %s", pidfile_path);
	unlink(pidfile_path);
      } else if (id.pid > 0) {
	INFOF("Another daemon is running, pid=%d tid=%d", id.pid, id.tid);
	return 1;
      }
    } else {
      WARNF_perror("Cannot link temporary pidfile %s to %s", tmpfile_path, pidfile_path);
      // Android 6 wont let us link, giving a permission error (sigh), lets just rename it then
      if (rename(tmpfile_path, pidfile_path)==-1){
	WHYF_perror("Cannot link or rename temporary pidfile %s to %s", tmpfile_path, pidfile_path);
	close(fd);
	unlink(tmpfile_path);
	return -1;
      }
      break;
    }
  }
  DEBUGF(server, "Created pidfile %s", pidfile_path);

  // The link was successful, so delete the temporary pidfile but leave the pid file open so that
  // the lock remains held!
  unlink(tmpfile_path);
  server_pidfd = fd;
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
  // Only a running server process/thread may modify the proc files.
  assert(serverMode != SERVER_NOT_RUNNING);

  char path_buf[400];
  if (get_proc_path(path, path_buf, sizeof path_buf)==-1)
    return -1;
    
  // Create the directory that contains the path, if it does not already exist.
  size_t dirsiz = strlen(path_buf) + 1;
  char dir_buf[dirsiz];
  strcpy(dir_buf, path_buf);
  const char *dir = dirname(dir_buf); // modifies dir_buf[]
  if (emkdirs_info(dir, 0700) == -1)
    return -1;

  // Format the file's new content in a local buffer on the stack.
  strbuf sb;
  STRBUF_ALLOCA_FIT(sb, 1024, strbuf_va_printf(sb, fmt));
  
  // Overwrite the file, creating it if necessary, using a single write(2) system call, followed by
  // a ftruncate(2) system call (in case the file already existed and was longer than its new
  // content).  This allows potential race conditions to be avoided for files that are overwritten
  // while the server runs, as long as the written contents are always the same size, or always
  // contain a terminating sequence (eg, newline).
  int fd = open(path_buf, O_CREAT | O_WRONLY, 0700);
  if (fd == -1)
    return WHYF_perror("open(%s, O_CREAT|O_WRONLY, 0700)", alloca_str_toprint(path_buf));
  int ret = write_all(fd, strbuf_str(sb), strbuf_len(sb));
  if (ret != -1 && (ret = ftruncate(fd, strbuf_len(sb)) == -1))
    ret = WHYF_perror("ftruncate(%s, %zu)", alloca_str_toprint(path_buf), strbuf_len(sb));
  close(fd);
  return ret;
}

int server_unlink_proc_state(const char *path)
{
  // Only a running server process/thread may modify the proc files.
  assert(serverMode != SERVER_NOT_RUNNING);

  char path_buf[400];
  if (get_proc_path(path, path_buf, sizeof path_buf)==-1)
    return -1;
  if (unlink(path) == -1 && errno != ENOENT)
    return WHYF_perror("unlink(%s)", alloca_str_toprint(path));
  return 0;
}

static int server_get_proc_state(const char *path, char *buff, size_t buff_len)
{
  char path_buf[400];
  if (get_proc_path(path, path_buf, sizeof path_buf)==-1)
    return -1;
  FILE *f = fopen(path_buf, "r");
  if (!f) {
    if (errno != ENOENT)
      return WHYF_perror("fopen(%s)", alloca_str_toprint(path_buf));
    return 1;
  }
  int ret = 0;
  errno = 0; // fgets() does not set errno on end-of-file
  if (!fgets(buff, buff_len, f)) {
    if (errno)
      ret = WHYF_perror("fgets from %s", alloca_str_toprint(path_buf));
    else
      ret = 1;
  }
  fclose(f);
  return ret;
}

/* Called periodically by the server process in its main loop.
 */
DEFINE_ALARM(server_config_reload);
void server_config_reload(struct sched_ent *alarm)
{
  if (serverMode == SERVER_CLOSING){
    // All shutdown triggers should unschedule their respective alarms.  Once there are no alarms
    // left, the fd_poll2() in server_loop() will return zero.
    CALL_TRIGGER(shutdown);
    return;
  }

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
  if (alarm){
    time_ms_t now = gettime_ms();
    RESCHEDULE(alarm, 
	now+config.server.config_reload_interval_ms,
	TIME_MS_NEVER_WILL,
	now+config.server.config_reload_interval_ms+100);
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
	serval_log_close();
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
	DEBUGF(watchdog, "STARTED WATCHDOG pid=%u executable=%s argv=[%s]",
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
    if (alarm) {
      time_ms_t now = gettime_ms();
      RESCHEDULE(alarm,
	now+config.server.watchdog.interval_ms,
	now+config.server.watchdog.interval_ms,
	now+100);
    }
  }
}

DEFINE_ALARM(rhizome_clean_db);
void rhizome_clean_db(struct sched_ent *alarm)
{
  if (!config.rhizome.enable || !rhizome_database.db)
    return;
    
  time_ms_t now = gettime_ms();
  rhizome_cleanup(NULL);
  // clean up every 30 minutes or so
  RESCHEDULE(alarm, now + 30*60*1000, TIME_MS_NEVER_WILL, TIME_MS_NEVER_WILL);
}

static void server_on_config_change()
{
  if (!serverMode)
    return;
  
  time_ms_t now = gettime_ms();

  if (config.server.watchdog.executable[0])
    RESCHEDULE(&ALARM_STRUCT(server_watchdog), 
      now+config.server.watchdog.interval_ms, 
      now+config.server.watchdog.interval_ms, 
      now+100);
  
  // Periodically check for modified configuration
  RESCHEDULE(&ALARM_STRUCT(server_config_reload), 
    now+config.server.config_reload_interval_ms,
    TIME_MS_NEVER_WILL,
    now+config.server.config_reload_interval_ms+100);

  // Open the Rhizome database immediately if Rhizome is enabled and close it if disabled; this
  // cannot be deferred because is_rhizome_http_enabled() only returns true if the database is open.
  if (config.rhizome.enable){
    rhizome_opendb();
    RESCHEDULE(&ALARM_STRUCT(rhizome_clean_db), now + 30*60*1000, TIME_MS_NEVER_WILL, TIME_MS_NEVER_WILL);
  }else if(rhizome_database.db){
    rhizome_close_db();
  }
}
DEFINE_TRIGGER(conf_change, server_on_config_change);

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

void server_close(){
  if (serverMode != SERVER_RUNNING)
    return;

  DEBUGF(server,"Graceful shutdown");

  // Cause the next server_config_reload() alarm to invoke the "shutdown" trigger, which in turn
  // will cause an orderly exit from server_loop().
  serverMode = SERVER_CLOSING;

  // Schedule the server_config_reload() alarm to go off immediately.
  time_ms_t now = gettime_ms();
  RESCHEDULE(&ALARM_STRUCT(server_config_reload),
    now,
    now,
    TIME_MS_NEVER_WILL);
}

static void server_stop_alarms()
{
  DEBUGF(server,"Stopping alarms");
  unschedule(&ALARM_STRUCT(fd_periodicstats));
  unschedule(&ALARM_STRUCT(server_watchdog));
  unschedule(&ALARM_STRUCT(server_config_reload));
  unschedule(&ALARM_STRUCT(rhizome_clean_db));
}
DEFINE_TRIGGER(shutdown, server_stop_alarms);

static void serverCleanUp()
{
  assert(serverMode != SERVER_NOT_RUNNING);
  INFOF("Server cleaning up");

  // release alarms, in case we aborted without attempting a graceful close
  server_stop_alarms();

  rhizome_close_db();
  release_my_subscriber();

  serverMode = SERVER_NOT_RUNNING;
  clean_proc();
}

static void signal_handler(int signum)
{
  switch (signum) {
    case SIGIO:
      // noop to break out of poll
      return;
    case SIGHUP:
    case SIGINT:
      switch (serverMode) {
	case SERVER_RUNNING:
	  // Trigger the server to close gracefully after any current alarm has completed.
	  INFOF("Caught signal %s -- attempting clean shutdown", alloca_signal_name(signum));
	  server_close();
	  return;
	case SERVER_CLOSING:
	  // If a second signal is received before the server has gracefully shut down, then forcibly
	  // terminate it immediately.  If the server is running in a thread, then this will only call
	  // serverCleanUp() if the signal was received by the same thread that is running the server,
	  // because serverMode is thread-local.  The zero exit status indicates a clean shutdown.  So
	  // the "stop" command must send SIGHUP to the correct thread.
	  WHYF("Caught signal %s -- forced shutdown", alloca_signal_name(signum));
	  list_alarms(LOG_LEVEL_ERROR);
	  serverCleanUp();
	  exit(0);
	case SERVER_NOT_RUNNING:
	  // If this thread is not running a server, then treat the signal as immediately fatal.
	  break;
      }
      // fall through...
    default:
      LOGF(LOG_LEVEL_FATAL, "Caught signal %s", alloca_signal_name(signum));
      dump_stack(LOG_LEVEL_FATAL);
      break;
  }

  // Exit with a status code indicating the caught signal.  This involves removing the signal
  // handler for the caught signal then re-sending the same signal to ourself.
  struct sigaction sig;
  bzero(&sig, sizeof sig);
  sig.sa_flags = 0;
  sig.sa_handler = SIG_DFL;
  sigemptyset(&sig.sa_mask);
  sigaction(signum, &sig, NULL);
  kill(getpid(), signum);

  // Just in case...
  FATALF("Sending %s to self (pid=%d) did not cause exit", alloca_signal_name(signum));
}

static void cli_server_details(struct cli_context *context, const struct pid_tid *id)
{
  const char *ipath = instance_path();
  if (ipath) {
    cli_field_name(context, "instancepath", ":");
    cli_put_string(context, ipath, "\n");
  }

  cli_field_name(context, "pidfile", ":");
  cli_put_string(context, server_pidfile_path(), "\n");
  cli_field_name(context, "status", ":");
  cli_put_string(context, id->pid > 0 ? "running" : "stopped", "\n");

  if (id->pid > 0) {
    cli_field_name(context, "pid", ":");
    cli_put_long(context, id->pid, "\n");
    if (id->tid > 0 && id->tid != id->pid) {
      cli_field_name(context, "tid", ":");
      cli_put_long(context, id->tid, "\n");
    }
    char buff[256];
    if (server_get_proc_state("primary_sid", buff, sizeof buff) == 0){
      cli_field_name(context, "primary_sid", ":");
      cli_put_string(context, buff, "\n");
    }
    if (server_get_proc_state("http_port", buff, sizeof buff) == 0){
      cli_field_name(context, "http_port", ":");
      cli_put_string(context, buff, "\n");
    }
    if (server_get_proc_state("mdp_inet_port", buff, sizeof buff) == 0){
      cli_field_name(context, "mdp_inet_port", ":");
      cli_put_string(context, buff, "\n");
    }
  }
}

DEFINE_CMD(app_server_start, 0,
  "Start daemon with instance path from SERVALINSTANCE_PATH environment variable.",
  "start" KEYRING_PIN_OPTIONS, "[--seed]", "[foreground|exec <path>]");
static int app_server_start(const struct cli_parsed *parsed, struct cli_context *context)
{
  IN();
  DEBUG_cli_parsed(verbose, parsed);
  /* Process optional arguments */
  int cpid=-1;
  const char *execpath;
  if (cli_arg(parsed, "exec", &execpath, cli_absolute_path, NULL) == -1)
    RETURN(-1);
  int seed = cli_arg(parsed, "--seed", NULL, NULL, NULL) == 0;
  int foregroundP = cli_arg(parsed, "foreground", NULL, NULL, NULL) == 0;
  if (config.interfaces.ac == 0)
    NOWHENCE(WARN("No network interfaces configured (empty 'interfaces' config option)"));
  /* Create the instance directory if it does not yet exist */
  if (create_serval_instance_dir() == -1)
    RETURN(-1);
  // Work out the Process and Thread IDs of any currently running server process, by reading an
  // existing pidfile.
  struct pid_tid id = get_server_pid_tid();
  if (id.pid < 0)
    RETURN(-1);
  int ret = -1;
  // If the pidfile identifies this process, it probably means we are re-spawning after a SEGV, so
  // go ahead and do the fork/exec.
  if (id.pid > 0 && id.pid != getpid()) {
    WARNF("Server already running (pid=%d)", id.pid);
    ret = 10;
  } else {
    if (foregroundP)
      INFOF("Foreground server process %s", execpath ? execpath : "without exec");
    else
      INFOF("Starting background server %s", execpath ? execpath : "without exec");
    /* Start the Serval process.  All server settings will be read by the server process from the
       instance directory when it starts up.  */
    // Open the keyring and ensure it contains at least one unlocked identity.
    keyring = keyring_open_instance_cli(parsed);
    if (!keyring)
      RETURN(WHY("Could not open keyring file"));
    if (seed && !keyring->identities){
      if (keyring_create_identity(keyring, "")==NULL){
	ret = WHY("Could not create new identity");
	goto exit;
      }
      keyring_commit(keyring);
    }
    if (foregroundP) {
      ret = server();
      // Warning: The server is not rigorous about freeing all memory it allocates, so to avoid
      // memory leaks, the caller should exit() immediately.
      goto exit;
    }
    const char *dir = getenv("SERVALD_SERVER_CHDIR");
    if (!dir)
      dir = config.server.chdir;
    switch (cpid = fork()) {
      case -1:
	/* Main process.  Fork failed.  There is no child process. */
	WHY_perror("fork");
	goto exit;
      case 0: {
	/* Child process.  Fork then exit, to disconnect daemon from parent process, so that
	   when daemon exits it does not live on as a zombie. N.B. On Android, do not return from
	   within this process; that will unroll the JNI call stack and cause havoc -- call _exit()
	   instead (not exit(), because we want to avoid any Java atexit(3) callbacks as well).  If
	   _exit() is used on non-Android systems, then source code coverage does not get reported,
	   because it relies on an atexit() callback to write the accumulated counters into .gcda
	   files.  */
	DEBUG(verbose, "Child Process");
	// Ensure that all stdio streams are flushed before forking, so that if a child calls
	// exit(), it will not result in any buffered output being written twice to the file
	// descriptor.
	fflush(stdout);
	fflush(stderr);
	switch (fork()) {
	  case -1:
	    exit(WHY_perror("fork"));
	  case 0: {
	    /* Grandchild process.  Close logfile (so that it gets re-opened again on demand, with
	       our own file pointer), disable logging to stderr (about to get redirected to
	       /dev/null), disconnect from current directory, disconnect standard I/O streams, and
	       start a new process session so that if we are being started by an adb shell session
	       on an Android device, then we don't receive a SIGHUP when the adb shell process ends.
	     */
	    DEBUG(verbose, "Grand-Child Process, reopening log");
	    serval_log_close();
	    int fd;
	    if ((fd = open("/dev/null", O_RDWR, 0)) == -1)
	      exit(WHY_perror("open(\"/dev/null\")"));
	    if (setsid() == -1)
	      exit(WHY_perror("setsid"));
	    if (chdir(dir) == -1)
	      exit(WHYF_perror("chdir(%s)", alloca_str_toprint(dir)));
	    if (dup2(fd, STDIN_FILENO) == -1)
	      exit(WHYF_perror("dup2(%d,stdin)", fd));
	    if (dup2(fd, STDOUT_FILENO) == -1)
	      exit(WHYF_perror("dup2(%d,stdout)", fd));
	    /* Redirect standard error to the current log file, so that any diagnostic messages
	     * printed directly to stderr by libraries or child processes will end up being captured
	     * in a log file.  If standard error is not redirected, then simply direct it to
	     * /dev/null.
	     */
	    if (!serval_log_capture_fd(STDERR_FILENO) && dup2(fd, STDERR_FILENO) == -1)
	      exit(WHYF_perror("dup2(%d,stderr)", fd));
	    if (fd > STDERR_FILENO)
	      (void)close(fd);
	    /* The execpath option is provided so that a JNI call to "start" can be made which
	       creates a new server daemon process with the correct argv[0].  Otherwise, the servald
	       process appears as a process with argv[0] = "org.servalproject". */
	    if (execpath) {
	    /* Need the cast on Solaris because it defines NULL as 0L and gcc doesn't see it as a
	       sentinal. */
	      DEBUGF(verbose, "Calling execl %s start foreground", execpath);
	      execl(execpath, "servald", "start", "foreground", (void *)NULL);
	      WHYF_perror("execl(%s, \"servald\", \"start\", \"foreground\")", alloca_str_toprint(execpath));
	      exit(-1);
	    }
	    exit(server());
	    // UNREACHABLE
	  }
	}
	// TODO wait for server_write_pid() to signal more directly?
	exit(0); // Main process is waitpid()-ing for this.
      }
    }
    /* Main process.  Wait for the child process to fork the grandchild and exit. */
    waitpid(cpid, NULL, 0);
    /* Allow a few seconds for the grandchild process to report for duty. */
    time_ms_t timeout = gettime_ms() + 5000;
    do {
      sleep_ms(200); // 5 Hz
    } while ((id = get_server_pid_tid()).pid == 0 && gettime_ms() < timeout);
    if (id.pid == -1)
      goto exit;
    if (id.pid == 0) {
      WHY("Server process did not start");
      goto exit;
    }
    ret = 0;
  }
  cli_server_details(context, &id);
  cli_flush(context);
  /* Sleep before returning if env var is set.  This is used in testing, to simulate the situation
     on Android phones where the "start" command is invoked via the JNI interface and the calling
     process does not die.
   */
  const char *post_sleep = getenv("SERVALD_START_POST_SLEEP");
  if (post_sleep) {
    time_ms_t milliseconds = atoi(post_sleep);
    INFOF("Sleeping for %"PRId64" milliseconds", (int64_t) milliseconds);
    sleep_ms(milliseconds);
  }
exit:
  keyring_free(keyring);
  keyring = NULL;
  RETURN(ret);
  OUT();
}

DEFINE_CMD(app_server_stop,CLIFLAG_PERMISSIVE_CONFIG,
  "Stop a running daemon with instance path from SERVALINSTANCE_PATH environment variable.",
  "stop");
static int app_server_stop(const struct cli_parsed *parsed, struct cli_context *context)
{
  DEBUG_cli_parsed(verbose, parsed);
  const struct pid_tid id = get_server_pid_tid();
  cli_server_details(context, &id);
  /* Not running, nothing to stop */
  if (id.pid <= 0)
    return 1;
  INFOF("Stopping server (pid=%d)", id.pid);
  /* Set the stop file and signal the process */
  unsigned tries = 0;
  pid_t running = id.pid;
  while (running == id.pid) {
    if (tries >= 5) {
      WHYF("Servald pid=%d (pidfile=%s) did not stop after %d SIGHUP signals",
	   id.pid, server_pidfile_path(), tries);
      return 253;
    }
    ++tries;
    switch (send_signal(&id, SIGHUP)) {
    case -1:
      return 252;
    case 0: {
      // Allow a few seconds for the process to die.
	time_ms_t timeout = gettime_ms() + 2000;
	do
	  sleep_ms(200); // 5 Hz
	while ((running = get_server_pid_tid().pid) == id.pid && gettime_ms() < timeout);
      }
      break;
    default:
      // Process no longer exists.  DO NOT call serverCleanUp() (once used to!) because that would
      // race with a starting server process.
      running = 0;
      break;
    }
  }
  cli_field_name(context, "tries", ":");
  cli_put_long(context, tries, "\n");
  return 0;
}

DEFINE_CMD(app_server_status,CLIFLAG_PERMISSIVE_CONFIG,
   "Display information about running daemon.",
   "status");
static int app_server_status(const struct cli_parsed *parsed, struct cli_context *context)
{
  DEBUG_cli_parsed(verbose, parsed);
  const struct pid_tid id = get_server_pid_tid();
  cli_server_details(context, &id);
  return id.pid > 0 ? 0 : 1;
}
