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


#include <assert.h>
#include <dirent.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <libgen.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "serval.h"
#include "conf.h"
#include "strbuf.h"
#include "strbuf_helpers.h"
#include "overlay_interface.h"
#include "overlay_packet.h"
#include "server.h"
#include "keyring.h"
#include "commandline.h"
#include "mdp_client.h"

#define PROC_SUBDIR	  "proc"
#define PIDFILE_NAME	  "servald.pid"
#define STOPFILE_NAME	  "servald.stop"

__thread int serverMode = 0;
__thread keyring_file *keyring=NULL;

static char pidfile_path[256];
static int server_getpid = 0;
static int server_bind();
static void server_loop();
static int server();
static int server_write_pid();
static int server_unlink_pid();
static void signal_handler(int signal);
static void serverCleanUp();
static const char *_server_pidfile_path(struct __sourceloc __whence);
#define server_pidfile_path() (_server_pidfile_path(__WHENCE__))
void server_shutdown_check(struct sched_ent *alarm);

void cli_cleanup(){
  /* clean up after ourselves */
  rhizome_close_db();
  free_subscribers();
  assert(keyring==NULL);
}

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

#define server_pidfile_path() (_server_pidfile_path(__WHENCE__))
static const char *_server_pidfile_path(struct __sourceloc __whence)
{
  if (!pidfile_path[0]) {
    if (!FORMF_SERVAL_RUN_PATH(pidfile_path, PIDFILE_NAME))
      return NULL;
  }
  return pidfile_path;
}

#ifdef HAVE_JNI_H

JNIEnv *server_env=NULL;
jclass IJniServer= NULL;
jmethodID aboutToWait, wokeUp, started;
jobject JniCallback;

JNIEXPORT jint JNICALL Java_org_servalproject_servaldna_ServalDCommand_server(
  JNIEnv *env, jobject UNUSED(this), jobject callback, jobject keyring_pin, jobjectArray entry_pins)
{
  if (!IJniServer){
    IJniServer = (*env)->FindClass(env, "org/servalproject/servaldna/IJniServer");
    if (IJniServer==NULL)
      return Throw(env, "java/lang/IllegalStateException", "Unable to locate class org.servalproject.servaldna.IJniServer");
    // make sure the interface class cannot be garbage collected between invocations
    IJniServer = (jclass)(*env)->NewGlobalRef(env, IJniServer);
    if (IJniServer==NULL)
      return Throw(env, "java/lang/IllegalStateException", "Unable to create global ref to class org.servalproject.servaldna.IJniServer");
    aboutToWait = (*env)->GetMethodID(env, IJniServer, "aboutToWait", "(JJJ)J");
    if (aboutToWait==NULL)
      return Throw(env, "java/lang/IllegalStateException", "Unable to locate method aboutToWait");
    wokeUp = (*env)->GetMethodID(env, IJniServer, "wokeUp", "()V");
    if (wokeUp==NULL)
      return Throw(env, "java/lang/IllegalStateException", "Unable to locate method wokeUp");
    started = (*env)->GetMethodID(env, IJniServer, "started", "(Ljava/lang/String;III)V");
    if (started==NULL)
      return Throw(env, "java/lang/IllegalStateException", "Unable to locate method started");
  }
  
  int pid = server_pid();
  if (pid < 0)
    return -1;
  if (pid>0)
    return 1;
  
  cf_reload_strict();
  
  int ret = -1;
  
  {
    const char *cpin = keyring_pin?(*env)->GetStringUTFChars(env, keyring_pin, NULL):NULL;
    if (cpin != NULL){
      keyring = keyring_open_instance(cpin);
      (*env)->ReleaseStringUTFChars(env, keyring_pin, cpin);
    }else{
      keyring = keyring_open_instance("");
    }
  }
  
  // Always open all PIN-less entries.
  keyring_enter_pin(keyring, "");
  if (entry_pins){
    jsize len = (*env)->GetArrayLength(env, entry_pins);
    jsize i;
    for (i = 0; i < len; ++i) {
      const jstring pin = (jstring)(*env)->GetObjectArrayElement(env, entry_pins, i);
      if ((*env)->ExceptionCheck(env))
	goto end;
      const char *cpin = (*env)->GetStringUTFChars(env, pin, NULL);
      if (cpin != NULL){
	keyring_enter_pin(keyring, cpin);
	(*env)->ReleaseStringUTFChars(env, pin, cpin);
      }
    }
  }
  
  if (keyring_seed(keyring) == -1)
    goto end;
  
  if (server_env)
    goto end;
  
  server_env = env;
  JniCallback = (*env)->NewGlobalRef(env, callback);
  
  ret = server_bind();
  
  if (ret==-1)
    goto end;
  
  {
    jstring str = (jstring)(*env)->NewStringUTF(env, instance_path());
    (*env)->CallVoidMethod(env, callback, started, str, getpid(), mdp_loopback_port, httpd_server_port);
    (*env)->DeleteLocalRef(env, str);
  }
  
  server_loop();
  
end:
  
  server_env=NULL;
  if (JniCallback){
    (*env)->DeleteGlobalRef(env, JniCallback);
    JniCallback = NULL;
  }
  
  if (keyring)
    keyring_free(keyring);
  keyring = NULL;
  
  return ret;
}

static time_ms_t waiting(time_ms_t now, time_ms_t next_run, time_ms_t next_wakeup)
{
  if (server_env && JniCallback){
    jlong r = (*server_env)->CallLongMethod(server_env, JniCallback, aboutToWait, (jlong)now, (jlong)next_run, (jlong)next_wakeup);
    // stop the server if there are any issues
    if ((*server_env)->ExceptionCheck(server_env)){
      serverMode=SERVER_CLOSING;
      INFO("Stopping server due to exception");
      return now;
    }
    return r;
  }
  return next_wakeup;
}

static void wokeup()
{
  if (server_env && JniCallback){
    (*server_env)->CallVoidMethod(server_env, JniCallback, wokeUp);
    // stop the server if there are any issues
    if ((*server_env)->ExceptionCheck(server_env)){
      INFO("Stopping server due to exception");
      serverMode=SERVER_CLOSING;
    }
  }
}

#else

#define waiting NULL
#define wokeup NULL

#endif

static int server_bind()
{
  serverMode = SERVER_RUNNING;

  // Warn, not merely Info, if there is no configured log file.
  logLevel_NoLogFileConfigured = LOG_LEVEL_WARN;

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

  /* Setup up client API sockets before writing our PID file
     We want clients to be able to connect to our sockets as soon 
     as servald start has returned. But we don't want servald start
     to take very long. 
     Try to perform only minimal CPU or IO processing here.
  */
  if (overlay_mdp_setup_sockets()==-1){
    serverMode = 0;
    return -1;
  }
  
  if (monitor_setup_sockets()==-1){
    serverMode = 0;
    return -1;
  }
  
  // start the HTTP server if enabled
  if (httpd_server_start(HTTPD_PORT, HTTPD_PORT_MAX)==-1){
    serverMode = 0;
    return -1;
  }
  
  /* For testing, it can be very helpful to delay the start of the server process, for example to
   * check that the start/stop logic is robust.
   */
  const char *delay = getenv("SERVALD_SERVER_START_DELAY");
  if (delay){
    time_ms_t milliseconds = atoi(delay);
    INFOF("Sleeping for %"PRId64" milliseconds", (int64_t) milliseconds);
    sleep_ms(milliseconds);
  }
  
  /* record PID file so that servald start can return */
  if (server_write_pid()){
    serverMode = 0;
    return -1;
  }
    
  overlay_queue_init();
  
  time_ms_t now = gettime_ms();
  
  // Periodically check for server shut down
  RESCHEDULE(&ALARM_STRUCT(server_shutdown_check), now, TIME_MS_NEVER_WILL, now);
  
  overlay_mdp_bind_internal_services();
  
  olsr_init_socket();

  /* Calculate (and possibly show) CPU usage stats periodically */
  RESCHEDULE(&ALARM_STRUCT(fd_periodicstats), now+3000, TIME_MS_NEVER_WILL, now+3500);

  return 0;
}

static void server_loop()
{
  cf_on_config_change();
  
  // log message used by tests to wait for the server to start
  INFOF("Server initialised, entering main loop");
  
  /* Check for activitiy and respond to it */
  while((serverMode==SERVER_RUNNING) && fd_poll2(waiting, wokeup))
    ;
  serverCleanUp();
  
  /* It is safe to unlink the pidfile here without checking whether it actually contains our own
   * PID, because server_shutdown_check() will have been executed very recently (in fd_poll()), so
   * if the code reaches here, the check has been done recently.
   */
  server_unlink_pid();
  serverMode = 0;
}

static int server()
{
  IN();
  if (server_bind()==-1)
    RETURN(-1);
  
  server_loop();
  
  // note that we haven't tried to free all types of allocated memory used by the server.
  // so it's safer to force this process to close, instead of trying to release everything.
  exit(0);
  OUT();
}

static int server_write_pid()
{
  server_write_proc_state("http_port", "%d", httpd_server_port);
  server_write_proc_state("mdp_inet_port", "%d", mdp_loopback_port);
  
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

static int server_unlink_pid()
{
  /* Remove PID file to indicate that the server is no longer running */
  const char *ppath = server_pidfile_path();
  if (ppath == NULL)
    return -1;
  if (unlink(ppath) == -1)
    WHYF_perror("unlink(%s)", alloca_str_toprint(ppath));
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
    RESCHEDULE(alarm, 
      now+config.server.watchdog.interval_ms, 
      now+config.server.watchdog.interval_ms, 
      now+100);
  }
}

DEFINE_ALARM(rhizome_clean_db);
void rhizome_clean_db(struct sched_ent *alarm)
{
  if (!config.rhizome.enable || !rhizome_db)
    return;
    
  time_ms_t now = gettime_ms();
  rhizome_cleanup(NULL);
  // clean up every 30 minutes or so
  RESCHEDULE(alarm, now + 30*60*1000, TIME_MS_NEVER_WILL, TIME_MS_NEVER_WILL);
}

void cf_on_config_change()
{
  if (!serverMode)
    return;
  
  time_ms_t now = gettime_ms();
  
  dna_helper_start();
  directory_service_init();
  
  // check for interfaces at least once after config change
  RESCHEDULE(&ALARM_STRUCT(overlay_interface_discover), now, now, now);
  
  if (link_has_neighbours())
    // send rhizome sync periodically
    RESCHEDULE(&ALARM_STRUCT(rhizome_sync_announce), 
      now+1000, now+1000, TIME_MS_NEVER_WILL);

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

  if (config.rhizome.enable){
    rhizome_opendb();
    RESCHEDULE(&ALARM_STRUCT(rhizome_clean_db), now + 30*60*1000, TIME_MS_NEVER_WILL, TIME_MS_NEVER_WILL);
    if (config.debug.rhizome)
      RESCHEDULE(&ALARM_STRUCT(rhizome_fetch_status), now + 3000, TIME_MS_NEVER_WILL, TIME_MS_NEVER_WILL);
  }else if(rhizome_db){
    rhizome_close_db();
  }
}

/* Called periodically by the server process in its main loop.
 */
DEFINE_ALARM(server_shutdown_check);
void server_shutdown_check(struct sched_ent *alarm)
{
  // TODO we should watch a descriptor and quit when it closes
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
    RESCHEDULE(alarm, now+1000, TIME_MS_NEVER_WILL, now+1100);
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

static void serverCleanUp()
{
  assert(serverMode);
  rhizome_close_db();
  dna_helper_shutdown();
  overlay_interface_close_all();
  overlay_mdp_clean_socket_files();
  clean_proc();
}

static void signal_handler(int signal)
{
  switch (signal) {
    case SIGIO:
      // noop to break out of poll
      return;
    case SIGHUP:
    case SIGINT:
      /* Trigger the server to close gracefully after any current alarm has completed. 
         If we get a second signal, exit now.
      */
      if (serverMode==SERVER_RUNNING){
	INFO("Attempting clean shutdown");
	serverMode=SERVER_CLOSING;
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

DEFINE_CMD(app_server_start, 0, 
  "Start daemon with instance path from SERVALINSTANCE_PATH environment variable.",
  "start" KEYRING_PIN_OPTIONS, "[foreground|exec <path>]");
static int app_server_start(const struct cli_parsed *parsed, struct cli_context *context)
{
  IN();
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  /* Process optional arguments */
  int cpid=-1;
  const char *execpath;
  if (cli_arg(parsed, "exec", &execpath, cli_absolute_path, NULL) == -1)
    RETURN(-1);
  int foregroundP = cli_arg(parsed, "foreground", NULL, NULL, NULL) == 0;
  /* Create the instance directory if it does not yet exist */
  if (create_serval_instance_dir() == -1)
    RETURN(-1);
  /* Now that we know our instance path, we can ask for the default set of
     network interfaces that we will take interest in. */
  if (config.interfaces.ac == 0)
    NOWHENCE(WARN("No network interfaces configured (empty 'interfaces' config option)"));
  int pid = server_pid();
  if (pid < 0)
    RETURN(-1);
  int ret = -1;
  // If the pidfile identifies this process, it probably means we are re-spawning after a SEGV, so
  // go ahead and do the fork/exec.
  if (pid > 0 && pid != getpid()) {
    WARNF("Server already running (pid=%d)", pid);
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
    if (keyring_seed(keyring) == -1) {
      WHY("Could not seed keyring");
      goto exit;
    }
    if (foregroundP) {
      ret = server();
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
	if (config.debug.verbose)
	  DEBUG("Child Process");
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
	    if (config.debug.verbose)
	      DEBUG("Grand-Child Process, reopening log");
	    close_log_file();
	    disable_log_stderr();
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
	    if (dup2(fd, STDERR_FILENO) == -1)
	      exit(WHYF_perror("dup2(%d,stderr)", fd));
	    if (fd > 2)
	      (void)close(fd);
	    /* The execpath option is provided so that a JNI call to "start" can be made which
	       creates a new server daemon process with the correct argv[0].  Otherwise, the servald
	       process appears as a process with argv[0] = "org.servalproject". */
	    if (execpath) {
	    /* Need the cast on Solaris because it defines NULL as 0L and gcc doesn't see it as a
	       sentinal. */
	      if (config.debug.verbose)
		DEBUGF("Calling execl %s start foreground", execpath);
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
    } while ((pid = server_pid()) == 0 && gettime_ms() < timeout);
    if (pid == -1)
      goto exit;
    if (pid == 0) {
      WHY("Server process did not start");
      goto exit;
    }
    ret = 0;
  }
  const char *ipath = instance_path();
  if (ipath) {
    cli_field_name(context, "instancepath", ":");
    cli_put_string(context, ipath, "\n");
  }
  cli_field_name(context, "pidfile", ":");
  cli_put_string(context, server_pidfile_path(), "\n");
  cli_field_name(context, "pid", ":");
  cli_put_long(context, pid, "\n");
  char buff[256];
  if (server_get_proc_state("http_port", buff, sizeof buff)!=-1){
    cli_field_name(context, "http_port", ":");
    cli_put_string(context, buff, "\n");
  }
  if (server_get_proc_state("mdp_inet_port", buff, sizeof buff)!=-1){
    cli_field_name(context, "mdp_inet_port", ":");
    cli_put_string(context, buff, "\n");
  }
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
  serverMode = 0;
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
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  int			pid, tries, running;
  time_ms_t		timeout;
  const char *ipath = instance_path();
  if (ipath) {
    cli_field_name(context, "instancepath", ":");
    cli_put_string(context, ipath, "\n");
  }
  cli_field_name(context, "pidfile", ":");
  cli_put_string(context, server_pidfile_path(), "\n");
  pid = server_pid();
  /* Not running, nothing to stop */
  if (pid <= 0)
    return 1;
  INFOF("Stopping server (pid=%d)", pid);
  /* Set the stop file and signal the process */
  cli_field_name(context, "pid", ":");
  cli_put_long(context, pid, "\n");
  tries = 0;
  running = pid;
  while (running == pid) {
    if (tries >= 5) {
      WHYF("Servald pid=%d (pidfile=%s) did not stop after %d SIGHUP signals",
	   pid, server_pidfile_path(), tries);
      return 253;
    }
    ++tries;
    if (kill(pid, SIGHUP) == -1) {
      // ESRCH means process is gone, possibly we are racing with another stop, or servald just died
      // voluntarily.  We DO NOT call serverCleanUp() in this case (once used to!) because that
      // would race with a starting server process.
      if (errno == ESRCH)
	break;
      WHY_perror("kill");
      WHYF("Error sending SIGHUP to Servald pid=%d (pidfile %s)", pid, server_pidfile_path());
      return 252;
    }
    /* Allow a few seconds for the process to die. */
    timeout = gettime_ms() + 2000;
    do
      sleep_ms(200); // 5 Hz
    while ((running = server_pid()) == pid && gettime_ms() < timeout);
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
  if (config.debug.verbose)
    DEBUG_cli_parsed(parsed);
  int pid = server_pid();
  const char *ipath = instance_path();
  if (ipath) {
    cli_field_name(context, "instancepath", ":");
    cli_put_string(context, ipath, "\n");
  }
  cli_field_name(context, "pidfile", ":");
  cli_put_string(context, server_pidfile_path(), "\n");
  cli_field_name(context, "status", ":");
  cli_put_string(context, pid > 0 ? "running" : "stopped", "\n");
  if (pid > 0) {
    cli_field_name(context, "pid", ":");
    cli_put_long(context, pid, "\n");
    char buff[256];
    if (server_get_proc_state("http_port", buff, sizeof buff)!=-1){
      cli_field_name(context, "http_port", ":");
      cli_put_string(context, buff, "\n");
    }
    if (server_get_proc_state("mdp_inet_port", buff, sizeof buff)!=-1){
      cli_field_name(context, "mdp_inet_port", ":");
      cli_put_string(context, buff, "\n");
    }
  }
  return pid > 0 ? 0 : 1;
}
