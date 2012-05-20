# Common definitions for all test suites in test/*

testdefs_sh=$(abspath "${BASH_SOURCE[0]}")
servald_source_root="${testdefs_sh%/*}"
servald_build_root="$servald_source_root"

# Utility function for setting up a fixture with a DNA server process:
#  - Ensure that no servald processes are running
#  - Start a servald server process
#  - Ensure that it is still running after one second
start_servald_server() {
   check_no_servald_processes
   # Start DNA server
   set -- $servald -v verbose -f $hlr_dat -S -n "$@"
   echo "+ run $*"
   "$@" >$DNATMP/servald.log 2>&1 &
   sleep 1
   local servald_basename="${servald##*/}"
   if [ -z "$servald_basename" ]; then
      error "cannot run test: \$servald not set"
      return 1
   fi
   pid=$(ps -u$UID | awk '$4 == "'"$servald_basename"'" {print $1}')
   if [ -z "$pid" ]; then
      echo "servald server did not start"
      tfw_cat --header=servald.log $SERVALINSTANCE_PATH/servald.log
      fail
   fi
   if ! [ -s $SERVALINSTANCE_PATH/serval.pid ] && kill -0 $(cat $SERVALINSTANCE_PATH/serval.pid); then
      echo "serval.pid was not created"
      tfw_cat --header=servald.log $SERVALINSTANCE_PATH/servald.log
      fail
   fi
   echo "# Started servald server process, pid=$pid"
}

# Utility function for tearing down DNA fixtures:
#  - If a servald server process is running, then kill it
#  - Cat any servald log file into the test log
#  - Ensure that no servald processes are running
stop_servald_server() {
   if [ -s $SERVALINSTANCE_PATH/servald.pid ]; then
      local pid=$(cat $SERVALINSTANCE_PATH/servald.pid)
      if kill $pid; then
         echo "# Killed servald process pid=$pid"
      else
         error "# Dna process pid=$pid was not running"
      fi
   fi
   if [ -s $DNATMP/servald.log ]; then
      tfw_cat --header=servald.log $DNATMP/servald.log
   fi
   check_no_servald_processes
}

# Utility function for creating DNA fixtures:
#  - Create a temporary directory to contain all servald-related files
#  - set $servald and $hlr_dat variables
#  - set SERVALINSTANCE_PATH environment variable
#  - mkdir $SERVALINSTANCE_PATH unless --no-mkdir option given
setup_servald() {
   servald=$(abspath "$servald_build_root/dna") # The DNA executable under test
   if ! [ -x "$servald" ]; then
      error "servald executable not present: $servald"
      return 1
   fi
   export DNATMP=$TFWTMP/servaldtmp
   [ "$1" = --no-mkdir ] || mkdir $DNATMP
   export SERVALINSTANCE_PATH=$DNATMP
   hlr_dat=$SERVALINSTANCE_PATH/hlr.dat
   unset SERVALD_OUTPUT_DELIMITER
}

# Utility function for setting up DNA JNI fixtures:
#  - check that libservald.so is present
#  - set LD_LIBRARY_PATH so that libservald.so can be found
setup_servald_so() {
   assert [ -r "$servald_build_root/libservald.so" ]
   export LD_LIBRARY_PATH="$servald_build_root"
}

# Utility function for managing DNA fixtures:
#  - Ensure there are no existing DNA server processes
check_no_servald_processes() {
   local servald_basename="${servald##*/}"
   if [ -z "$servald_basename" ]; then
      error "cannot run test: \$servald not set"
      return 1
   fi
   local pids=$(ps -u$UID | awk '$4 == "'"$servald_basename"'" {print $1}')
   if [ -n "$pids" ]; then
      error "cannot run test: $servald_basename process already running with pid: $pids"
      return 1
   fi
   echo "# No other $servald_basename processes running for uid=$UID"
   return 0
}
