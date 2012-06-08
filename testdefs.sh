# Common definitions for all test suites in test/*

testdefs_sh=$(abspath "${BASH_SOURCE[0]}")
servald_source_root="${testdefs_sh%/*}"
servald_build_root="$servald_source_root"

# Some useful regular expressions.  These must work in grep(1) as basic
# expressions, and also in sed(1).
rexp_sid='[0-9a-fA-F]\{64\}'

# Utility function for creating DNA fixtures:
#  - create a temporary directory to contain all servald-related files
#  - set $servald variable (executable under test)
#  - set SERVALINSTANCE_PATH environment variable
#  - mkdir $SERVALINSTANCE_PATH unless --no-mkdir option given
setup_servald() {
   servald=$(abspath "$servald_build_root/dna") # The DNA executable under test
   if ! [ -x "$servald" ]; then
      error "servald executable not present: $servald"
      return 1
   fi
}

# Utility function for running servald and asserting no errors:
#  - executes $servald with the given arguments
#  - asserts that standard error contains no error messages
executeOk_servald() {
   executeOk --executable="$servald" "$@"
   assertStderrGrep --matches=0 '^ERROR:'
}

# Utility function:
#  - set up environment and normal variables for the given instance name
#  - if the argument is not an instance name, then use the default instance name
#    and return 1, otherwise return 0
set_instance() {
   case "$1" in
   [A-Z]|default) set_instance_vars "$1"; return 0;;
   *) set_instance_vars "default"; return 1;;
   esac
}

# Utility function:
#  - set all the instance variables and environment variables and create the
#    instance directory for the given instance name
set_instance_vars() {
   instance_name="${1:-default}"
   export instance_dir="$TFWTMP/instance/$instance_name"
   mkdir -p "$instance_dir"
   export instance_servald_log="$instance_dir/servald.log"
   export SERVALINSTANCE_PATH="$instance_dir/servald"
   export instance_servald_pidfile="$SERVALINSTANCE_PATH/servald.pid"
}

# Utility function for setting up DNA JNI fixtures:
#  - check that libservald.so is present
#  - set LD_LIBRARY_PATH so that libservald.so can be found
setup_servald_so() {
   assert [ -r "$servald_build_root/libservald.so" ]
   export LD_LIBRARY_PATH="$servald_build_root"
}

# Utility function for setting up a fixture with a DNA server process:
#  - Ensure that no servald processes are running
#  - Start a servald server process
#  - Ensure that it is still running after one second
start_servald_server() {
   set_instance "$1" && shift
   executeOk $servald config set logfile "$instance_servald_log"
   # Start DNA server
   local -a before_pids
   local -a after_pids
   get_servald_pids before_pids
   echo "# before_pids=$before_pids"
   unset SERVALD_OUTPUT_DELIMITER
   executeOk $servald start "$@"
   tfw_cat --stdout
   get_servald_pids after_pids
   echo "# after_pids=$after_pids"
   # Assert that the servald pid file is present.
   assert --message="servald pidfile was created" [ -s "$instance_servald_pidfile" ]
   servald_pid=$(cat "$instance_servald_pidfile")
   assert --message="servald pidfile contains a valid pid" --dump-on-fail="$instance_servald_log" kill -0 "$servald_pid"
   # Assert that there is at least one new servald process running.
   local apid bpid
   local new_pids=
   local pidfile_running=false
   for apid in ${after_pids[*]}; do
      local isnew=true
      for bpid in ${before_pids[*]}; do
         if [ "$apid" -eq "$bpid" ]; then
            isnew=false
            break
         fi
      done
      if [ "$apid" -eq "$servald_pid" ]; then
         echo "# started servald process: pid=$servald_pid"
         new_pids="$new_pids $apid"
         pidfile_running=true
      elif $isnew; then
         echo "# unknown new servald process: pid=$apid"
         new_pids="$new_pids $apid"
      fi
   done
   assert --message="a new servald process is running" --dump-on-fail="$instance_servald_log" [ -n "$new_pids" ]
   assert --message="servald pidfile process is running" --dump-on-fail="$instance_servald_log" $pidfile_running
   echo "# Started servald server process $instance_name, pid=$servald_pid"
}

stop_servald_server() {
   set_instance "$1" && shift
   # Stop DNA server
   servald_pid=$(cat "$instance_servald_pidfile")
   local -a before_pids
   local -a after_pids
   get_servald_pids before_pids
   echo "# before_pids=$before_pids"
   unset SERVALD_OUTPUT_DELIMITER
   executeOk $servald stop "$@"
   tfw_cat --stdout
   echo "# Stopped servald server process $instance_name, pid=${servald_pid:-unknown}"
   get_servald_pids after_pids
   echo "# after_pids=$after_pids"
   # Assert that the servald pid file is gone.
   assert --message="servald pidfile was removed" [ ! -e "$instance_servald_pidfile" ]
   # Assert that the servald process identified by the pidfile is no longer running.
   local apid bpid
   if [ -n "$servald_pid" ]; then
      for apid in ${after_pids[*]}; do
         assert --message="servald process still running" [ "$apid" -ne "$servald_pid" ]
      done
   fi
   # Append the server log file to the test log.
   [ -s "$instance_servald_log" ] && tfw_cat "$instance_servald_log"
   # Check there is at least one fewer servald processes running.
   for bpid in ${before_pids[*]}; do
      local isgone=true
      for apid in ${after_pids[*]}; do
         if [ "$apid" -eq "$bpid" ]; then
            isgone=false
            break
         fi
      done
      if $isgone; then
         echo "# ended servald process: pid=$bpid"
      fi
   done
}

# Utility function for tearing down DNA fixtures:
#  - Kill all servald server process instances in an orderly fashion
#  - Cat any servald log file into the test log
stop_all_servald_servers() {
   if pushd "$TFWTMP/instance" >/dev/null; then
      for name in *; do
         stop_servald_server "$name"
      done
      popd >/dev/null
   fi
}

# Utility function for tearing down DNA fixtures:
#  - send a given signal to all running servald processes, identified by name
#  - return 1 if no processes were present, 0 if any signal was sent
signal_all_servald_processes() {
   local sig="$1"
   local servald_pids
   get_servald_pids servald_pids
   local pid
   local ret=1
   for pid in $servald_pids; do
      if kill -$sig "$pid"; then
         echo "# Sent SIG$sig to servald process pid=$pid"
         ret=0
      else
         error "# servald process pid=$pid not running -- SIG$sig not sent"
      fi
   done
   return $ret
}

# Utility function for tearing down DNA fixtures:
#  - terminate all running servald processes, identified by name, by sending
#    first SIGTERM then SIGHUP and finally SIGKILL
#  - assert that no more servald processes are running
kill_all_servald_processes() {
   if signal_all_servald_processes TERM; then
      sleep 2
      if signal_all_servald_processes HUP; then
         sleep 2
         signal_all_servald_processes KILL
      fi
   fi
}

# Utility function:
#  - return the PIDs of all servald processes the current user is running
get_servald_pids() {
   local var="$1"
   local servald_basename="${servald##*/}"
   if [ -z "$servald_basename" ]; then
      error "\$servald is not set"
      return 1
   fi
   local pids=$(ps -u$UID | awk -v servald="$servald_basename" '$4 == servald {print $1}')
   [ -n "$var" ] && eval "$var=($pids)"
   [ -n "$pids" ]
}

# Assertion function:
#  - assert there are no existing DNA server processes
assert_no_servald_processes() {
   local pids
   get_servald_pids pids
   assert --message="$servald_basename process(es) running: $pids" [ -z "$pids" ]
   return 0
}
