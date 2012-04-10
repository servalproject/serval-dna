# Common definitions for all test suites in test/*

this=$(abspath "${BASH_SOURCE[0]}")

# Utility function for setting up a fixture with a DNA server process:
#  - Ensure that no dna processes are running
#  - Start a dna server process
#  - Ensure that it is still running after one second
start_dna_server() {
   check_no_dna_processes
   # Start DNA server
   $dna -v verbose -f $hlr_dat -S 1 -n "$@" >$DNATMP/dna.log 2>&1 &
   sleep 1
   pid=$(ps -u$UID | awk '$4 == "dna" {print $1}')
   if [ -z "$pid" ]; then
      echo "dna server did not start"
      tfw_cat --header=dna.log $SERVALINSTANCE_PATH/dna.log
      fail
   fi
   if ! [ -s $SERVALINSTANCE_PATH/serval.pid ] && kill -0 $(cat $SERVALINSTANCE_PATH/serval.pid); then
      echo "serval.pid was not created"
      tfw_cat --header=dna.log $SERVALINSTANCE_PATH/dna.log
      fail
   fi
   echo "# Started dna server process, pid=$pid"
}

# Utility function for tearing down DNA fixtures:
#  - If a dna server process is running, then kill it
#  - Cat any dna log file into the test log
#  - Ensure that no dna processes are running
stop_dna_server() {
   if [ -s $SERVALINSTANCE_PATH/serval.pid ]; then
      local pid=$(cat $SERVALINSTANCE_PATH/serval.pid)
      if kill $pid; then
         echo "# Killed dna process pid=$pid"
      else
         error "# Dna process pid=$pid was not running"
      fi
   fi
   if [ -s $DNATMP/dna.log ]; then
      tfw_cat --header=dna.log $DNATMP/dna.log
   fi
   check_no_dna_processes
}

# Utility function for creating DNA fixtures:
#  - Create a temporary directory to contain all dna-related files
#  - set $dna and $hlr_dat variables
#  - set SERVALINSTANCE_PATH environment variable
setup_dna() {
   dna=$(abspath "${this%/*}/dna") # The DNA executable under test
   if ! [ -x "$dna" ]; then
      error "dna executable not present: $dna"
      return 1
   fi
   export DNATMP=$TFWTMP/dnatmp
   mkdir $DNATMP
   export SERVALINSTANCE_PATH=$DNATMP
   hlr_dat=$SERVALINSTANCE_PATH/hlr.dat
}

# Utility function for managing DNA fixtures:
#  - Ensure there are no existing DNA server processes
check_no_dna_processes() {
   local pids=$(ps -u$UID | awk '$4 == "dna" {print $1}')
   if [ -n "$pids" ]; then
      error "cannot run test: dna process already running with pid: $pids"
      return 1
   fi
   echo "# No other dna processes running for uid=$UID"
   return 0
}
