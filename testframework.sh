#!/bin/bash
#
# Serval Project testing framework for Bash shell
# Copyright 2012 Serval Project, Inc.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

# This file is sourced by all testing scripts.  A typical test script looks
# like this:
#
# #!/bin/bash
# source testframework.sh
# setup() {
#   export BLAH_CONFIG=$TFWTMP/blah.conf
#   echo "username=$LOGNAME" >$BLAH_CONFIG
# }
# teardown() {
#   # $TFWTMP is always removed after every test, so no need to
#   # remove blah.conf ourselves.
# }
# doc_feature1='Feature one works'
# test_feature1() {
#   execute programUnderTest --feature1 arg1 arg2
#   assertExitStatus '==' 0
#   assertRealTime --message='ran in under half a second' '<=' 0.5
#   assertStdoutIs ""
#   assertStderrIs ""
#   tfw_cat arg1
# }
# doc_feature2='Feature two fails with status 1'
# setup_feature2() {
#   # Overrides setup(), so we have to call it ourselves explicitly
#   # here if we still want it.
#   setup
#   echo "option=specialValue" >>$BLAH_CONFIG
# }
# test_feature2() {
#   execute programUnderTest --feature2 arg1 arg2
#   assertExitStatus '==' 1
#   assertStdoutIs -e "Response:\tok\n"
#   assertStderrGrep "^ERROR: missing arg3$"
# }
# runTests "$@"

AWK=awk
SED=sed
GREP=grep
TSFMT='+%Y-%m-%d %H:%M:%S'

SYSTYPE=`uname -s`
if [ $SYSTYPE = "SunOS" ]; then
    AWK=gawk
    SED=gsed
    GREP=ggrep
fi

if [ $SYSTYPE = "Linux" ]; then
    # Get nanosecond resolution
    TSFMT='+%Y-%m-%d %H:%M:%S.%N'
fi

usage() {
   echo -n "\
Usage: $0 [options] [--]
Options:
  -h      --help            Print this usage message
  -t      --trace           Log shell "set -x" trace during tests
  -v      --verbose         Send test log to output during execution
  -j 0    --jobs            Run all tests in parallel
  -j N    --jobs=N          Run tests in parallel, at most N at a time (default
                            N=1)
  -E      --stop-on-error   Do not execute any tests after an ERROR occurs
  -F      --stop-on-failure Do not execute any tests after a FAIL occurs
  -t N    --timeout=N       Override default timeout, make it N seconds instead
                            of 60
  -f PRE  --filter=PRE      Only execute tests whose names start with PRE
  -f N    --filter=N        Only execute test number N
  -f M-N  --filter=M-N      Only execute tests with numbers in range M-N inclusive
  -f -N   --filter=-N       Only execute tests with numbers <= N
  -f N-   --filter=N-       Only execute tests with numbers >= N
  -f ...  --filter=M,N,...  Only execute tests with number M or N or ...
  -c      --coverage        Collect test coverage data
  -cg     --geninfo         Invoke geninfo(1) to produce one coverage.info file
                            per test case (requires at least one --gcno-dir)
  -cd DIR --gcno-dir=DIR    Use test coverage GCNO files under DIR (overrides
                            TFW_GCNO_PATH env var)
"
}

# Internal utility for setting shopt variables and restoring their original
# value:
#     local oo
#     _tfw_shopt oo -s extglob -u extdebug
#     ...
#     _tfw_shopt_restore oo
_tfw_shopt() {
   local _var="$1"
   shift
   local op=s
   local restore=
   while [ $# -ne 0 ]
   do
      case "$1" in
      -s) op=s;;
      -u) op=u;;
      *)
         local opt="$1"
         restore="${restore:+$restore; }shopt -$(shopt -q $opt && echo s || echo u) $opt"
         shopt -$op $opt
         ;;
      esac
      shift
   done
   eval $_var='"$restore"'
}
_tfw_shopt_restore() {
   local _var="$1"
   [ -n "${!_var}" ] && eval "${!_var}"
}

declare -a _tfw_included_tests=()
declare -a _tfw_test_names=()
declare -a _tfw_test_sourcefiles=()
declare -a _tfw_job_pgids=()
declare -a _tfw_forked_pids=()
declare -a _tfw_forked_labels=()

# The rest of this file is parsed for extended glob patterns.
_tfw_shopt _tfw_orig_shopt -s extglob

includeTests() {
   local arg
   for arg; do
      local path
      case "$arg" in
      /*) path="$(abspath "$arg")";;
      *) path="$(abspath "$_tfw_script_dir/arg")";;
      esac
      local n=$((${#BASH_LINENO[*]} - 1))
      while [ $n -gt 0 -a ${BASH_LINENO[$n]} -eq 0 ]; do
         let n=n-1
      done
      _tfw_included_tests+=("${BASH_LINENO[$n]} $arg")
   done
}

runTests() {
   [ -n "${_tfw_recursive_source}" ] && return 0
   _tfw_stdout=1
   _tfw_stderr=2
   _tfw_log_fd=
   _tfw_checkBashVersion
   export PATH="$(_tfw_abspath "${BASH_SOURCE%/*}"):$PATH"
   _tfw_checkTerminfo
   _tfw_checkCommandInPATH tfw_createfile
   _tfw_invoking_script=$(abspath "${BASH_SOURCE[1]}")
   _tfw_script_name="${_tfw_invoking_script##*/}"
   _tfw_script_dir="${_tfw_invoking_script%/*}"
   _tfw_cwd=$(abspath "$PWD")
   _tfw_tmpdir="$(_tfw_abspath -P "${TFW_TMPDIR:-${TMPDIR:-/tmp}}")"
   _tfw_tmpmain="$_tfw_tmpdir/_tfw-$$"
   _tfw_njobs=1
   _tfw_log_noise=true
   _tfw_assert_noise=true
   _tfw_logdir="${TFW_LOGDIR:-$_tfw_cwd/testlog}"
   _tfw_logdir_script="$_tfw_logdir/$_tfw_script_name"
   _tfw_list=false
   _tfw_trace=false
   _tfw_verbose=false
   _tfw_stop_on_error=false
   _tfw_stop_on_failure=false
   _tfw_default_execute_timeout=60
   _tfw_default_wait_until_timeout=60
   _tfw_timeout_override=
   _tfw_coverage=false
   _tfw_geninfo=false
   _tfw_gcno_path=()
   local allargs="$*"
   local -a filters=()
   local oo
   _tfw_shopt oo -s extglob
   while [ $# -ne 0 ]; do
      case "$1" in
      -h|--help) usage; exit 0;;
      -l|--list) _tfw_list=true;;
      -t|--trace) _tfw_trace=true;;
      -v|--verbose) _tfw_verbose=true;;
      -E|--stop-on-error) _tfw_stop_on_error=true;;
      -F|--stop-on-failure) _tfw_stop_on_failure=true;;
      -f) [ -n "$2" ] || _tfw_fatal "missing argument after option: $1"
          filters+=("$2")
          shift
          ;;
      -f*) filters+=("${1#-?}");;
      --filter=*) filters+=("${1#*=}");;
      -j) [ -n "$2" ] || _tfw_fatal "missing argument after option: $1"
          _tfw_is_uint "${2?}" || _tfw_fatal "invalid option: $1 $2"
          _tfw_njobs=${2?}
          shift
          ;;
      -j+([0-9])) _tfw_njobs="${1#-?}";;
      -j*) _tfw_fatal "invalid option: $1";;
      --jobs=+([0-9])) _tfw_njobs="${1#*=}";;
      --jobs=*) _tfw_fatal "invalid option: $1";;
      --jobs) _tfw_njobs=0;;
      -t) [ -n "$2" ] || _tfw_fatal "missing argument after option: $1"
         _tfw_is_float "${2?}" || _tfw_fatal "invalid option: $1 $2"
         _tfw_timeout_override="${2?}"
         shift
         ;;
      -t*)
         _tfw_is_float "${1#-?}" || _tfw_fatal "invalid option: $1"
         _tfw_timeout_override="${1#-?}"
         ;;
      --timeout=*)
         _tfw_is_float "${1#*=}" || _tfw_fatal "invalid option: $1"
         _tfw_timeout_override="${1#*=}"
         ;;
      -c|--coverage) _tfw_coverage=true;;
      -cg|--geninfo) _tfw_coverage=true; _tfw_geninfo=true;;
      -cd) [ -n "$2" ] || _tfw_fatal "missing argument after option: $1"
          _tfw_gcno_path+=("$2")
          shift
          ;;
      -cd*) _tfw_gcno_path+=("${1#-?}");;
      --gcno-dir=*) _tfw_gcno_path+=("${1#*=}");;
      --) shift; break;;
      -*) _tfw_fatal "unsupported option: $1";;
      *) _tfw_fatal "spurious argument: $1";;
      esac
      shift
   done
   _tfw_shopt_restore oo
   if $_tfw_verbose && [ $_tfw_njobs -ne 1 ]; then
      _tfw_fatal "--verbose is incompatible with --jobs=$_tfw_njobs"
   fi
   # Handle --gcno-dir arguments, or if none given, $TFW_GCNO_PATH env var.
   # Convert into a list of absolute directory paths.
   if [ ${#_tfw_gcno_path[*]} -eq -0 ]; then
      local oIFS="$IFS"
      IFS=:
      _tfw_gcno_path=($TFW_GCNO_PATH)
      IFS="$oIFS"
   else
      local pathdir
      for pathdir in "${_tfw_gcno_path[@]}"; do
         [ -d "$pathdir" ] || _tfw_fatal "--gcno-dir: no such directory: '$pathdir'"
      done
   fi
   _tfw_gcno_dirs=()
   local pathdir
   for pathdir in "${_tfw_gcno_path[@]}"; do
      [ -d "$pathdir" ] && _tfw_gcno_dirs+=("$(abspath "$pathdir")")
   done
   # Handle --geninfo option.
   if $_tfw_geninfo; then
      if [ ${#_tfw_gcno_dirs[*]} -eq 0 ]; then
         _tfw_fatal "--geninfo: requires at least one --gcno-dir=DIR or \$TFW_GCNO_PATH env var"
      fi
      _tfw_checkCommandInPATH geninfo
      _tfw_checkCommandInPATH gcov _tfw_gcov_path
      # Check that all source files are available.
      _tfw_extract_source_files_from_gcno "${_tfw_gcno_dirs[@]}"
      _tfw_coverage_source_basedir=.
      if [ -n "$TFW_COVERAGE_SOURCE_BASE_DIR" ]; then
         [ -d "$TFW_COVERAGE_SOURCE_BASE_DIR" ] || _tfw_fatal "--geninfo: no such directory '$TFW_COVERAGE_SOURCE_BASE_DIR' (\$TFW_COVERAGE_SOURCE_BASE_DIR)"
         _tfw_coverage_source_basedir="$TFW_COVERAGE_SOURCE_BASE_DIR"
      fi
      local src
      for src in "${_tfw_coverage_source_files[@]}"; do
         local path="$_tfw_coverage_source_basedir/$src"
         [ -r "$path" ] || _tfw_fatal "--geninfo: missing source file $path"
      done
   fi
   # Enumerate all the test cases.
   _tfw_list_tests
   # If we are only asked to list them, then do so and finish.
   if $_tfw_list; then
      local testNumber
      for ((testNumber = 1; testNumber <= ${#_tfw_test_names[*]}; ++testNumber)); do
         local testSourceFile="${_tfw_test_sourcefiles[$(($testNumber - 1))]}"
         local testName="${_tfw_test_names[$(($testNumber - 1))]}"
         if _tfw_filter_predicate "$testNumber" "$testName" "${filters[@]}"; then
            echo "$testNumber $testName ${testSourceFile#$_tfw_script_dir/}"
         fi
      done
      return 0
   fi
   # Create base temporary working directory.
   trap '_tfw_status=$?; _tfw_killtests 2>/dev/null; rm -rf "$_tfw_tmpmain"; trap - EXIT; exit $_tfw_status' EXIT SIGHUP SIGINT SIGTERM
   rm -rf "$_tfw_tmpmain"
   mkdir -p "$_tfw_tmpmain" || return $?
   # Create an empty results directory.
   _tfw_results_dir="$_tfw_tmpmain/results"
   mkdir "$_tfw_results_dir" || return $?
   # Create an empty log directory.
   mkdir -p "$_tfw_logdir_script" || return $?
   rm -r -f "$_tfw_logdir_script"/*
   # Enable job control.
   set -m
   # Iterate through all test cases, starting a new test whenever the number of
   # running tests is less than the job limit.
   _tfw_testcount=0
   _tfw_passcount=0
   _tfw_failcount=0
   _tfw_errorcount=0
   _tfw_fatalcount=0
   _tfw_job_pgids=()
   _tfw_job_pgids[0]=
   _tfw_test_number_watermark=0
   local testNumber
   local testPosition=0
   for ((testNumber = 1; testNumber <= ${#_tfw_test_names[*]}; ++testNumber)); do
      local testSourceFile="${_tfw_test_sourcefiles[$(($testNumber - 1))]}"
      local testName="${_tfw_test_names[$(($testNumber - 1))]}"
      local scriptName="${testSourceFile#$_tfw_script_dir/}"
      _tfw_filter_predicate "$testNumber" "$testName" "${filters[@]}" || continue
      let ++testPosition
      let ++_tfw_testcount
      # Wait for any existing child process to finish.
      while [ $_tfw_njobs -ne 0 -a $(_tfw_count_running_jobs) -ge $_tfw_njobs ]; do
         _tfw_wait_job_finish
         _tfw_harvest_jobs
      done
      [ $_tfw_fatalcount -ne 0 ] && break
      $_tfw_stop_on_error && [ $_tfw_errorcount -ne 0 ] && break
      $_tfw_stop_on_failure && [ $_tfw_failcount -ne 0 ] && break
      # Start the next test in a child process.
      _tfw_echo_progress $testPosition $testNumber "$testSourceFile" $testName
      if $_tfw_verbose || [ $_tfw_njobs -ne 1 ]; then
         echo
      fi
      echo "$testPosition $testNumber $testName" NONE "$testSourceFile" >"$_tfw_results_dir/$testNumber"
      (  #)#<-- fixes Vim syntax highlighting
         # The directory where this test's log.txt and other artifacts are
         # deposited.
         _tfw_logdir_test="$_tfw_logdir_script/$testNumber.$testName"
         mkdir "$_tfw_logdir_test" || _tfw_fatalexit
         # Pick a unique decimal number that must not coincide with other tests
         # being run concurrently, _including tests being run in other test
         # scripts by other users on the same host_.  We cannot simply use
         # $testNumber.  The subshell process ID is ideal.  We don't use
         # $BASHPID because MacOS only has Bash-3.2, and $BASHPID was introduced
         # in Bash-4.
         _tfw_unique=$($BASH -c 'echo $PPID')
         # All files created by this test belong inside a temporary directory.
         # The path name must be kept short because it is used to construct
         # named socket paths, which have a limited length.
         _tfw_tmp=$_tfw_tmpdir/_tfw-$_tfw_unique
         trap '_tfw_status=$?; rm -rf "$_tfw_tmp"; exit $_tfw_status' EXIT SIGHUP SIGINT SIGTERM
         mkdir $_tfw_tmp || _tfw_fatalexit
         # Set up test coverage data directory, which contains all the .gcno
         # files of the executable(s) under test.  If using geninfo(1) to
         # generate coverage info files, then link to all the source files, to
         # ensure that temporary .gcov files are created in this directory and
         # not in the repository's base directory (which would cause race
         # conditions).
         if $_tfw_coverage; then
            export GCOV_PREFIX="$_tfw_logdir_test/gcov"
            export GCOV_PREFIX_STRIP=0
            mkdir "$GCOV_PREFIX" || _tfw_fatalexit
            # Link to GCNO files.
            if [ ${#_tfw_gcno_dirs[*]} -ne 0 ]; then
               find "${_tfw_gcno_dirs[@]}" -type f -name '*.gcno' -print0 | cpio -0pdl --quiet "$GCOV_PREFIX"
            fi
            # Link source files to where geninfo(1) will always find them before
            # finding the original source files.
            if $_tfw_geninfo; then
               pushd "$_tfw_coverage_source_basedir" >/dev/null || _tfw_fatalexit
               find "${_tfw_coverage_source_files[@]}" -maxdepth 0 -print0 | cpio -0pdl --quiet "$GCOV_PREFIX"
               popd >/dev/null
            fi
         fi
         ## XXX _tfw_geninfo_initial "$scriptName/$testName" >$_tfw_tmp/log.geninfo 2>&1
         local start_time=$(_tfw_timestamp)
         local finish_time=unknown
         (  #)#<-- fixes Vim syntax highlighting
            _tfw_result=FATAL
            _tfw_stdout=5
            _tfw_stderr=5
            _tfw_log_fd=6
            BASH_XTRACEFD=7
            # Disable job control.
            set +m
            # If the test is from a different source script than the one
            # invoking us, then source that file to pull in all the test
            # definitions.
            if [ "$testSourceFile" != "$_tfw_invoking_script" ]; then
               _tfw_recursive_source=true
               source "$testSourceFile"
               unset _tfw_recursive_source
            fi
            declare -f test_$testName >/dev/null || _tfw_fatal "test_$testName not defined"
            # Where per-forked-process files get stored -- see fork().
            _tfw_process_tmp="$_tfw_tmp"
            # Environment variables and temporary directories that test cases
            # depend upon.
            export COLUMNS=80 # for ls(1) multi-column output
            export TFWSOURCE="$testSourceFile"
            export TFWLOG="$_tfw_logdir_test"
            export TFWUNIQUE=$_tfw_unique
            export TFWVAR="$_tfw_tmp/var"
            mkdir $TFWVAR || _tfw_fatalexit
            export TFWTMP="$_tfw_tmp/tmp"
            mkdir $TFWTMP || _tfw_fatalexit
            cd $TFWTMP || _tfw_fatalexit
            if $_tfw_verbose; then
               # Find the PID of the current subshell process.  Cannot use $BASHPID
               # because MacOS only has Bash-3.2, and $BASHPID was introduced in Bash-4.
               local mypid=$($BASH -c 'echo $PPID')
               # These tail processes will die when the current subshell exits.
               tail --pid=$mypid --follow $_tfw_tmp/log.stdout >&$_tfw_stdout 2>/dev/null &
               tail --pid=$mypid --follow $_tfw_tmp/log.stderr >&$_tfw_stderr 2>/dev/null &
            fi
            # Execute the test case.
            _tfw_phase=setup
            _tfw_result=ERROR
            _tfw_status=
            trap "_tfw_status=\$?; _tfw_finalise $testName; _tfw_teardown $testName; _tfw_exit" EXIT SIGHUP SIGINT SIGTERM
            _tfw_setup $testName
            _tfw_result=FAIL
            _tfw_phase=testcase
            tfw_log "# CALL test_$testName()"
            $_tfw_trace && set -x
            test_$testName
            set +x
            _tfw_result=PASS
            exit 0
         ) <&- 5>&1 5>&2 6>"$_tfw_tmp/log.stdout" 1>&6 2>"$_tfw_tmp/log.stderr" 7>"$_tfw_tmp/log.xtrace"
         local stat=$?
         finish_time=$(_tfw_timestamp)
         local result=FATAL
         case $stat in
         254) result=ERROR;;
         1) result=FAIL;;
         0) result=PASS;;
         esac
         echo "$testPosition $testNumber $testName $result $testSourceFile" >"$_tfw_results_dir/$testNumber"
         {
            echo "Name:     $testName ($scriptName)"
            echo "Result:   $result"
            echo "Started:  $start_time"
            echo "Finished: $finish_time"
            echo '++++++++++ log.stdout ++++++++++'
            cat $_tfw_tmp/log.stdout
            echo '++++++++++'
            echo '++++++++++ log.stderr ++++++++++'
            cat $_tfw_tmp/log.stderr
            echo '++++++++++'
            if $_tfw_trace; then
               echo '++++++++++ log.xtrace ++++++++++'
               cat $_tfw_tmp/log.xtrace
               echo '++++++++++'
            fi
         } >"$_tfw_logdir_test/log.txt"
         mv "$_tfw_logdir_test" "$_tfw_logdir_test.$result"
         _tfw_logdir_test="$_tfw_logdir_test.$result"
         if $_tfw_geninfo; then
            local testname=$(_tfw_string_to_identifier "$scriptName/$testName")
            local result="$_tfw_tmp/result.info"
            local coverage="$_tfw_logdir_test/coverage.info"
            {
               echo '++++++++++ log.geninfo ++++++++++'
               _tfw_run_geninfo "$coverage" --test-name "$testname" 2>&1
               echo '++++++++++'
            } >>"$_tfw_logdir_test/log.txt"
         fi
         exit 0
      ) </dev/null &
      local job=$(jobs %% 2>/dev/null | $SED -n -e '1s/^\[\([0-9]\{1,\}\)\].*/\1/p')
      if [ -n "${_tfw_job_pgids[$job]}" ]; then
         _tfw_harvest_job $job
      fi
      _tfw_job_pgids[$job]=$(jobs -p %$job 2>/dev/null)
      ln -f -s "$_tfw_results_dir/$testNumber" "$_tfw_results_dir/job-$job"
   done
   # Wait for all child processes to finish.
   while _tfw_any_running_jobs; do
      _tfw_wait_job_finish
      _tfw_harvest_jobs
   done
   # Clean up working directory.
   rm -rf "$_tfw_tmpmain"
   trap - EXIT SIGHUP SIGINT SIGTERM
   # Echo result summary and exit with success if no failures or errors.
   s=$([ $_tfw_testcount -eq 1 ] || echo s)
   echo "$_tfw_testcount test$s, $_tfw_passcount pass, $_tfw_failcount fail, $_tfw_errorcount error"
   [ $_tfw_fatalcount -eq 0 -a $_tfw_failcount -eq 0 -a $_tfw_errorcount -eq 0 ]
}

_tfw_killtests() {
   if [ $_tfw_njobs -eq 1 ]; then
      echo " killing..."
   else
      echo -n -e "\r\rKilling tests..."
   fi
   trap '' SIGHUP SIGINT SIGTERM
   local pgid
   for pgid in $(jobs -p); do
      kill -TERM -$pgid
   done
   wait
}

_tfw_count_running_jobs() {
   local count=0
   local job
   for ((job = 1; job < ${#_tfw_job_pgids[*]}; ++job)); do
      [ -n "${_tfw_job_pgids[$job]}" ] && let count=count+1
   done
   echo $count
}

_tfw_any_running_jobs() {
   local job
   for ((job = 1; job < ${#_tfw_job_pgids[*]}; ++job)); do
      [ -n "${_tfw_job_pgids[$job]}" ] && return 0
   done
   return 1
}

_tfw_wait_job_finish() {
   if [ $_tfw_njobs -eq 1 ]; then
      wait >/dev/null 2>/dev/null
   else
      # This is the only way known to get the effect of a 'wait' builtin that
      # will return when _any_ child dies (or after a one-second timeout).
      set -m
      sleep 1 &
      local spid=$!
      trap "kill -TERM $spid 2>/dev/null" SIGCHLD
      wait $spid >/dev/null 2>/dev/null
      trap - SIGCHLD
   fi
}

_tfw_harvest_jobs() {
   local job
   for ((job = 1; job < ${#_tfw_job_pgids[*]}; ++job)); do
      if [ -n "${_tfw_job_pgids[$job]}" ]; then
         jobs %$job >/dev/null 2>/dev/null || _tfw_harvest_job $job
      fi
   done
}

_tfw_harvest_job() {
   local job="$1"
   # Kill any residual processes from the test case.
   local pgid=${_tfw_job_pgids[$job]}
   [ -n "$pgid" ] && kill -TERM -$pgid 2>/dev/null
   _tfw_job_pgids[$job]=
   # Report the test script outcome.
   if [ -s "$_tfw_results_dir/job-$job" ]; then
      local testPosition
      local testNumber
      local testName
      local result
      local testSourceFile
      _tfw_unpack_words "$(<"$_tfw_results_dir/job-$job")" testPosition testNumber testName result testSourceFile
      case "$result" in
      ERROR)
         let _tfw_errorcount=_tfw_errorcount+1
         ;;
      PASS)
         let _tfw_passcount=_tfw_passcount+1
         ;;
      FAIL)
         let _tfw_failcount=_tfw_failcount+1
         ;;
      *)
         result=FATAL
         let _tfw_fatalcount=_tfw_fatalcount+1
         ;;
      esac
      local lines
      if ! $_tfw_verbose && [ $_tfw_njobs -eq 1 ]; then
         _tfw_echo_progress $testPosition $testNumber "$testSourceFile" $testName $result
         echo
      elif ! $_tfw_verbose && lines=$($_tfw_tput lines); then
         local travel=$(($_tfw_test_number_watermark - $testPosition + 1))
         if [ $travel -gt 0 -a $travel -lt $lines ] && $_tfw_tput cuu $travel ; then
            _tfw_echo_progress $testPosition $testNumber "$testSourceFile" $testName $result
            echo
            travel=$(($_tfw_test_number_watermark - $testPosition))
            [ $travel -gt 0 ] && $_tfw_tput cud $travel
         fi
      else
         _tfw_echo_progress $testPosition $testNumber "$testSourceFile" $testName $result
         echo
      fi
   else
      _tfw_echoerr "${BASH_SOURCE[1]}: job %$job terminated without result"
   fi
   rm -f "$_tfw_results_dir/job-$job"
}

_tfw_echo_progress() {
   (
      local script=
      if [ "$testSourceFile" != "$_tfw_invoking_script" ]; then
         _tfw_recursive_source=true
         source "$testSourceFile"
         unset _tfw_recursive_source
         script=" (${3#$_tfw_script_dir/})"
      fi
      local docvar="doc_$4"
      echo -n -e '\r'
      echo -n "$2 ["
      _tfw_echo_result "$5"
      echo -n "]$script ${!docvar:-$4}"
   )
   [ $1 -gt $_tfw_test_number_watermark ] && _tfw_test_number_watermark=$1
}

_tfw_echo_result() {
   local result="$1"
   case "$result" in
   ERROR | FATAL)
      $_tfw_tput setaf 1
      $_tfw_tput rev
      echo -n "$result"
      $_tfw_tput sgr0
      $_tfw_tput op
      ;;
   PASS)
      $_tfw_tput setaf 2
      echo -n "$result"
      $_tfw_tput op
      echo -n "."
      ;;
   FAIL)
      $_tfw_tput setaf 1
      echo -n "$result"
      $_tfw_tput op
      echo -n "."
      ;;
   *)
      result="$result....."
      echo -n "${result:0:5}"
      ;;
   esac
}

_tfw_extract_source_files_from_gcno() {
   # This should possibly be done by creating a binary utility that knows how to
   # disassemble GCNO files.  In the meantime, this approach seems to work:
   # simply extract all strings from all GCNO files that match *.c or *.h.
   local IFS='
'
   _tfw_coverage_source_files=($(find "$@" -type f -name '*.gcno' -print0 | xargs -0 strings | grep '\.[ch]$' | sort -u))
}

_tfw_run_geninfo() {
   local infofile="$1"
   shift
   geninfo \
      --rc lcov_tmp_dir="$_tfw_tmp" \
      --gcov-tool "$_tfw_gcov_path" \
      --output-file "$infofile" \
      --no-external \
      "$@" \
      "$_tfw_logdir_test/gcov"
   # Cook the absolute source file paths in the info file to refer to the
   # original source files, not the links we placed into the gcov subdirectory
   # in order to avoid race conditions.
   local basedir="$(abspath "$_tfw_coverage_source_basedir")"
   $SED -i -e "/^SF:/s:$_tfw_logdir_test/gcov:$basedir:" "$infofile"
}

_tfw_string_to_identifier() {
   echo "$1" | $SED -e 's/\//__/g' -e 's/[^0-9a-zA-Z_]/_/g'
}

# Internal (private) functions that are not to be invoked directly from test
# scripts.

# Add shell quotation to the given arguments, so that when expanded using
# 'eval', the exact same argument results.  This makes argument handling fully
# immune to spaces and shell metacharacters.
_tfw_shellarg() {
   local arg
   _tfw_args=()
   for arg; do
      case "$arg" in
      '' | *[^A-Za-z_0-9.,:=+\/-]* ) _tfw_args+=("'${arg//'/'\\''}'");;
      *) _tfw_args+=("$arg");;
      esac
   done
}

# Echo the absolute path of the given path, using only Bash builtins.
_tfw_abspath() {
   cdopt=-L
   if [ $# -gt 1 -a "${1:0:1}" = - ]; then
      cdopt="$1"
      shift
   fi
   case "$1" in
   */)
      builtin echo $(_tfw_abspath $cdopt "${1%/}")/
      ;;
   /*/*)
      if [ -d "$1" ]; then
         (CDPATH= builtin cd $cdopt "$1" && builtin echo "$PWD")
      else
         builtin echo $(_tfw_abspath $cdopt "${1%/*}")/"${1##*/}"
      fi
      ;;
   /*)
      echo "$1"
      ;;
   */*)
      if [ -d "$1" ]; then
         (CDPATH= builtin cd $cdopt "$1" && builtin echo "$PWD")
      else
         builtin echo $(_tfw_abspath $cdopt "${1%/*}")/"${1##*/}"
      fi
      ;;
   . | ..)
      (CDPATH= builtin cd $cdopt "$1" && builtin echo "$PWD")
      ;;
   *)
      (CDPATH= builtin cd $cdopt . && builtin echo "$PWD/$1")
      ;;
   esac
}

_tfw_timestamp() {
   local ts=$(date "$TSFMT")
   echo "${ts%[0-9][0-9][0-9][0-9][0-9][0-9]}"
}

_tfw_setup() {
   local testName="$1"
   tfw_log '# SETUP'
   case `type -t setup_$testName` in
   function)
      tfw_log "# call setup_$testName()"
      $_tfw_trace && set -x
      setup_$testName $testName
      set +x
      ;;
   *)
      tfw_log "# call setup($testName)"
      $_tfw_trace && set -x
      setup $testName
      set +x
      ;;
   esac
   tfw_log '# END SETUP'
}

_tfw_finalise() {
   local testName="$1"
   _tfw_phase=finalise
   tfw_log '# FINALISE'
   case `type -t finally_$testName` in
   function)
      tfw_log "# CALL finally_$testName()"
      $_tfw_trace && set -x
      finally_$testName
      set +x
      ;;
   *)
      tfw_log "# CALL finally($testName)"
      $_tfw_trace && set -x
      finally $testName
      set +x
      ;;
   esac
   fork_terminate_all
   fork_wait_all
   tfw_log '# END FINALLY'
}

_tfw_teardown() {
   local testName="$1"
   _tfw_phase=teardown
   tfw_log '# TEARDOWN'
   case `type -t teardown_$testName` in
   function)
      tfw_log "# CALL teardown_$testName()"
      $_tfw_trace && set -x
      teardown_$testName
      set +x
      ;;
   *)
      tfw_log "# CALL teardown($testName)"
      $_tfw_trace && set -x
      teardown $testName
      set +x
      ;;
   esac
   tfw_log '# END TEARDOWN'
}

_tfw_exit() {
   case $_tfw_status:$_tfw_result in
   254:* | *:ERROR ) exit 254;;
   1:* | *:FAIL ) exit 1;;
   0:PASS ) exit 0;;
   esac
   _tfw_fatal "_tfw_status='$_tfw_status' _tfw_result='$_tfw_result'"
}

# Executes $_tfw_executable with the given arguments.
_tfw_execute() {
   executed=$(shellarg "${_tfw_executable##*/}" "$@")
   if $_tfw_opt_core_backtrace; then
      ulimit -S -c unlimited
      rm -f core
   fi
   export TFWSTDOUT="${_tfw_stdout_file:-$_tfw_process_tmp/stdout}"
   export TFWSTDERR="${_tfw_stderr_file:-$_tfw_process_tmp/stderr}"
   {
      time -p "$_tfw_executable" "$@" >"$TFWSTDOUT" 2>"$TFWSTDERR"
   } 2>"$_tfw_process_tmp/times" &
   local subshell_pid=$!
   local timer_pid=
   local timeout=${_tfw_timeout_override:-${_tfw_opt_timeout:-${TFW_EXECUTE_TIMEOUT:-$_tfw_default_execute_timeout}}}
   if [ -n "$timeout" ]; then
      _tfw_is_float "$timeout" || error "invalid timeout '$timeout'"
   fi
   if [ -n "$timeout" ]; then
      if type pgrep >/dev/null 2>/dev/null; then
         (  #)#( <<- fixes Vim syntax colouring
            # For some reason, set -e does not work here.  So all the following
            # commands are postfixed with || exit $?
            local executable_pid=$(pgrep -P $subshell_pid) || exit $?
            [ -n "$executable_pid" ] || exit $?
            if [ -n "$timeout" ]; then
               sleep $timeout || exit $?
            fi
            kill -0 $executable_pid || exit $?
            tfw_log "# timeout after $timeout seconds, sending SIGABRT to pid $executable_pid ($executed)" || exit $?
            kill -ABRT $executable_pid || exit $?
            sleep 2 || exit $?
            kill -0 $executable_pid || exit $?
            tfw_log "# sending second SIGABRT to pid $executable_pid ($executed)" || exit $?
            kill -ABRT $executable_pid || exit $?
            sleep 2 || exit $?
            kill -0 $executable_pid || exit $?
            tfw_log "# sending SIGKILL to pid $executable_pid ($executed)" || exit $?
            kill -KILL $executable_pid || exit $?
            exit 0
         ) 2>/dev/null &
         timer_pid=$!
      else
         tfw_log "# execution timeout ($timeout seconds) not supported because pgrep(1) not available"
      fi
   fi
   wait $subshell_pid
   _tfw_exitStatus=$?
   if [ -n "$timer_pid" ]; then
      while kill -0 $timer_pid 2>/dev/null; do
         pkill -P $timer_pid 2>/dev/null
      done
      wait $timer_pid
   fi
   # Deal with core dump.
   if $_tfw_opt_core_backtrace && [ -s core ]; then
      tfw_core_backtrace "$_tfw_executable" core
   fi
   # Deal with exit status.
   if [ -n "$_tfw_opt_exit_status" ]; then
      _tfw_message="exit status ($_tfw_exitStatus) of ($executed) is $_tfw_opt_exit_status"
      _tfw_assert [ "$_tfw_exitStatus" -eq "$_tfw_opt_exit_status" ] || _tfw_failexit || return $?
      $_tfw_assert_noise && tfw_log "# assert $_tfw_message"
   else
      $_tfw_assert_noise && tfw_log "# exit status of ($executed) = $_tfw_exitStatus"
   fi
   # Parse execution time report.
   if true || [ -s "$_tfw_process_tmp/times" ]; then
      if ! _tfw_parse_times_to_milliseconds real realtime_ms ||
         ! _tfw_parse_times_to_milliseconds user usertime_ms ||
         ! _tfw_parse_times_to_milliseconds sys systime_ms
      then
         tfw_log '# malformed output from time:'
         tfw_cat -v "$_tfw_process_tmp/times"
      fi
   else
      realtime_ms=
      usertime_ms=
      systime_ms=
   fi
   return 0
}

_tfw_parse_times_to_milliseconds() {
   local label="$1"
   local var="$2"
   local milliseconds=$($AWK '$1 == "'"$label"'" {
         value = $2
         minutes = 0
         if (match(value, "[0-9]+m")) {
            minutes = substr(value, RSTART, RLENGTH - 1)
            value = substr(value, 1, RSTART - 1) substr(value, RSTART + RLENGTH)
         }
         if (substr(value, length(value)) == "s") {
            value = substr(value, 1, length(value) - 1)
         }
         if (match(value, "^[0-9]+(\\.[0-9]+)?$")) {
            seconds = value + 0
            print (minutes * 60 + seconds) * 1000
         }
      }' $_tfw_process_tmp/times)
   [ -z "$milliseconds" ] && return 1
   [ -n "$var" ] && eval $var=$milliseconds
   return 0
}

_tfw_assert() {
   if ! tfw_run "$@"; then
      _tfw_failmsg "assertion failed: ${_tfw_message:-$*}"
      _tfw_backtrace
      return 1
   fi
   return 0
}

declare -a _tfw_opt_dump_on_fail

_tfw_dump_on_fail() {
   local arg
   for arg; do
      local _found=false
      local _f
      for _f in "${_tfw_opt_dump_on_fail[@]}"; do
         if [ "$_f" = "$arg" ]; then
            _found=true
            break
         fi
      done
      $_found || _tfw_opt_dump_on_fail+=("$arg")
   done
}

_tfw_getopts() {
   local context="$1"
   shift
   _tfw_executable=
   _tfw_stdout_file=
   _tfw_stderr_file=
   _tfw_opt_core_backtrace=false
   _tfw_message=
   _tfw_opt_dump_on_fail=()
   _tfw_opt_error_on_fail=false
   _tfw_opt_exit_status=
   _tfw_opt_timeout=
   _tfw_opt_sleep=
   _tfw_opt_matches=
   _tfw_opt_line=
   _tfw_opt_line_sed=
   _tfw_opt_line_msg=
   _tfw_opt_grepopts=()
   _tfw_getopts_shift=0
   local oo
   _tfw_shopt oo -s extglob
   while [ $# -ne 0 ]; do
      case "$context:$1" in
      *:--stdout) _tfw_dump_on_fail --stdout;;
      *:--stderr) _tfw_dump_on_fail --stderr;;
      assert*:--dump-on-fail=*) _tfw_dump_on_fail "${1#*=}";;
      @(assert*|execute*|fork_wait*):--error-on-fail) _tfw_opt_error_on_fail=true;;
      assert*:--message=*) _tfw_message="${1#*=}";;
      execute:--exit-status=+([0-9])) _tfw_opt_exit_status="${1#*=}";;
      execute:--exit-status=*) _tfw_error "invalid value: $1";;
      execute*:--executable=) _tfw_error "missing value: $1";;
      execute*:--executable=*) _tfw_executable="${1#*=}";;
      execute*:--stdout-file=) _tfw_error "missing value: $1";;
      execute*:--stdout-file=*) _tfw_stdout_file="${1#*=}";;
      execute*:--stderr-file=) _tfw_error "missing value: $1";;
      execute*:--stderr-file=*) _tfw_stderr_file="${1#*=}";;
      execute*:--core-backtrace) _tfw_opt_core_backtrace=true;;
      @(execute*|wait_until):--timeout=@(+([0-9])?(.+([0-9]))|*([0-9]).+([0-9]))) _tfw_opt_timeout="${1#*=}";;
      @(execute*|wait_until):--timeout=*) _tfw_error "invalid value: $1";;
      wait_until:--sleep=*) _tfw_is_float "${1#*=}" || _tfw_error "invalid value: $1"; _tfw_opt_sleep="${1#*=}";;
      *grep:--fixed-strings) _tfw_opt_grepopts+=(-F);;
      assertcontentgrep:--matches=+([0-9])) _tfw_opt_matches="${1#*=}";;
      assertcontentgrep:--matches=*) _tfw_error "invalid value: $1";;
      assertcontentgrep:--ignore-case) _tfw_opt_grepopts+=(-i);;
      assertcontent*:--line=+([0-9])) _tfw_opt_line="${1#*=}"; _tfw_opt_line_msg="line $_tfw_opt_line";;
      assertcontent*:--line=+([0-9])..) _tfw_opt_line="${1#*=}\$"; _tfw_opt_line_msg="lines $_tfw_opt_line";;
      assertcontent*:--line=..+([0-9])) _tfw_opt_line="1${1#*=}"; _tfw_opt_line_msg="lines $_tfw_opt_line";;
      assertcontent*:--line=+([0-9])..+([0-9])) _tfw_opt_line="${1#*=}"; _tfw_opt_line_msg="lines $_tfw_opt_line";;
      assertcontent*:--line=*) _tfw_error "invalid value: $1";;
      *:--) let _tfw_getopts_shift=_tfw_getopts_shift+1; shift; break;;
      *:--*) _tfw_error "unsupported option: $1";;
      *) break;;
      esac
      let _tfw_getopts_shift=_tfw_getopts_shift+1
      shift
   done
   [ -n "$_tfw_opt_line" ] && _tfw_opt_line_sed="${_tfw_opt_line/../,}"
   case "$context" in
   execute*)
      if [ -z "$_tfw_executable" ]; then
         _tfw_executable="$1"
         let _tfw_getopts_shift=_tfw_getopts_shift+1
         shift
      fi
      [ -z "$_tfw_executable" ] && _tfw_error "missing executable argument"
      ;;
   esac
   _tfw_shopt_restore oo
   return 0
}

_tfw_is_uint() {
   local oo
   _tfw_shopt oo -s extglob
   local ret=1
   case "$1" in
   +([0-9])) ret=0;;
   esac
   _tfw_shopt_restore oo
   return $ret
}

_tfw_is_float() {
   local oo
   _tfw_shopt oo -s extglob
   local ret=1
   case "$1" in
   @(+([0-9])?(.+([0-9]))|*([0-9]).+([0-9]))) ret=0;;
   esac
   _tfw_shopt_restore oo
   return $ret
}

_tfw_matches_rexp() {
   local rexp="$1"
   shift
   local arg
   for arg; do
      if ! echo "$arg" | $GREP -q -e "$rexp"; then
         return 1
      fi
   done
   return 0
}

_tfw_parse_expr() {
   local _expr="$*"
   _tfw_expr=()
   while [ $# -ne 0 ]; do
      case "$1" in
      '&&' | '||' | '!' | '(' | ')')
         _tfw_expr+=("$1")
         shift
         ;;
      *)
         if [ $# -lt 3 ]; then
            _tfw_error "invalid expression: $_expr"
            return $?
         fi
         case "$2" in
         '==') _tfw_expr+=("[" "$1" "-eq" "$3" "]");;
         '!=') _tfw_expr+=("[" "$1" "-ne" "$3" "]");;
         '<=') _tfw_expr+=("[" "$1" "-le" "$3" "]");;
         '<') _tfw_expr+=("[" "$1" "-lt" "$3" "]");;
         '>=') _tfw_expr+=("[" "$1" "-ge" "$3" "]");;
         '>') _tfw_expr+=("[" "$1" "-gt" "$3" "]");;
         '~') _tfw_expr+=("_tfw_matches_rexp" "$3" "$1");;
         '!~') _tfw_expr+=("!" "_tfw_matches_rexp" "$3" "$1");;
         *)
            _tfw_error "invalid expression: $_expr"
            return $?
            ;;
         esac
         shift 3
         ;;
      esac
   done
   return 0
}

_tfw_assertExpr() {
   _tfw_parse_expr "$@" || return $?
   _tfw_shellarg "${_tfw_expr[@]}"
   _tfw_assert eval "${_tfw_args[@]}"
}

_tfw_get_content() {
   case "$_tfw_opt_line_sed" in
   '') cat "$1" >|"$_tfw_process_tmp/content" || error "cat failed";;
   *) $SED -n -e "${_tfw_opt_line_sed}p" "$1" >|"$_tfw_process_tmp/content" || error "sed failed";;
   esac
}

_tfw_assert_stdxxx_is() {
   local qual="$1"
   shift
   _tfw_getopts assertcontentis --$qual --stderr "$@"
   shift $((_tfw_getopts_shift - 2))
   if [ $# -lt 1 ]; then
      _tfw_error "incorrect arguments"
      return $?
   fi
   [ -r "$_tfw_process_tmp/$qual" ] || fail "no $qual" || return $?
   _tfw_get_content "$_tfw_process_tmp/$qual" || return $?
   local message="${_tfw_message:-${_tfw_opt_line_msg:+$_tfw_opt_line_msg of }$qual of ($executed) is $(shellarg "$@")}"
   echo -n "$@" >"$_tfw_process_tmp/stdxxx_is.tmp"
   if ! cmp -s "$_tfw_process_tmp/stdxxx_is.tmp" "$_tfw_process_tmp/content"; then
      _tfw_failmsg "assertion failed: $message"
      _tfw_backtrace
      return 1
   fi
   $_tfw_assert_noise && tfw_log "# assert $message"
   return 0
}

_tfw_assert_stdxxx_linecount() {
   local qual="$1"
   shift
   _tfw_getopts assert --$qual --stderr "$@"
   shift $((_tfw_getopts_shift - 2))
   if [ $# -lt 1 ]; then
      _tfw_error "incorrect arguments"
      return $?
   fi
   [ -r "$_tfw_process_tmp/$qual" ] || fail "no $qual" || return $?
   local lineCount=$(( $(cat "$_tfw_process_tmp/$qual" | wc -l) + 0 ))
   [ -z "$_tfw_message" ] && _tfw_message="$qual line count ($lineCount) $*"
   _tfw_assertExpr "$lineCount" "$@" || _tfw_failexit || return $?
   $_tfw_assert_noise && tfw_log "# assert $_tfw_message"
   return 0
}

_tfw_assert_stdxxx_grep() {
   local qual="$1"
   shift
   _tfw_getopts assertcontentgrep --$qual --stderr "$@"
   shift $((_tfw_getopts_shift - 2))
   if [ $# -ne 1 ]; then
      _tfw_error "incorrect arguments"
      return $?
   fi
   [ -r "$_tfw_process_tmp/$qual" ] || fail "no $qual" || return $?
   _tfw_get_content "$_tfw_process_tmp/$qual" || return $?
   _tfw_assert_grep "${_tfw_opt_line_msg:+$_tfw_opt_line_msg of }$qual of ($executed)" "$_tfw_process_tmp/content" "$@"
}

_tfw_assert_grep() {
   local label="$1"
   local file="$2"
   local pattern="$3"
   local message=
   if ! [ -e "$file" ]; then
      _tfw_error "$file does not exist"
      ret=$?
   elif ! [ -f "$file" ]; then
      _tfw_error "$file is not a regular file"
      ret=$?
   elif ! [ -r "$file" ]; then
      _tfw_error "$file is not readable"
      ret=$?
   else
      local matches=$(( $($GREP "${_tfw_opt_grepopts[@]}" --regexp="$pattern" "$file" | wc -l) + 0 ))
      local done=false
      local ret=0
      local info="$matches match"$([ $matches -ne 1 ] && echo "es")
      local oo
      _tfw_shopt oo -s extglob
      case "$_tfw_opt_matches" in
      '')
         done=true
         message="${_tfw_message:-$label contains a line matching \"$pattern\"}"
         if [ $matches -ne 0 ]; then
            $_tfw_assert_noise && tfw_log "# assert $message"
         else
            _tfw_failmsg "assertion failed ($info): $message"
            ret=1
         fi
         ;;
      esac
      case "$_tfw_opt_matches" in
      +([0-9]))
         done=true
         local s=$([ $_tfw_opt_matches -ne 1 ] && echo s)
         message="${_tfw_message:-$label contains exactly $_tfw_opt_matches line$s matching \"$pattern\"}"
         if [ $matches -eq $_tfw_opt_matches ]; then
            $_tfw_assert_noise && tfw_log "# assert $message"
         else
            _tfw_failmsg "assertion failed ($info): $message"
            ret=1
         fi
         ;;
      esac
      case "$_tfw_opt_matches" in
      +([0-9])-*([0-9]))
         done=true
         local bound=${_tfw_opt_matches%-*}
         local s=$([ $bound -ne 1 ] && echo s)
         message="${_tfw_message:-$label contains at least $bound line$s matching \"$pattern\"}"
         if [ $matches -ge $bound ]; then
            $_tfw_assert_noise && tfw_log "# assert $message"
         else
            _tfw_failmsg "assertion failed ($info): $message"
            ret=1
         fi
         ;;
      esac
      case "$_tfw_opt_matches" in
      *([0-9])-+([0-9]))
         done=true
         local bound=${_tfw_opt_matches#*-}
         local s=$([ $bound -ne 1 ] && echo s)
         message="${_tfw_message:-$label contains at most $bound line$s matching \"$pattern\"}"
         if [ $matches -le $bound ]; then
            $_tfw_assert_noise && tfw_log "# assert $message"
         else
            _tfw_failmsg "assertion failed ($info): $message"
            ret=1
         fi
         ;;
      esac
      if ! $done; then
         _tfw_error "unsupported value for --matches=$_tfw_opt_matches"
         ret=$?
      fi
      _tfw_shopt_restore oo
   fi
   if [ $ret -ne 0 ]; then
      _tfw_backtrace
   fi
   return $ret
}

# Write a message to the real stderr of the test script, so the user sees it
# immediately.  Also write the message to the test log, so it can be recovered
# later.
_tfw_echoerr() {
   echo "$@" >&$_tfw_stderr
   if [ $_tfw_stderr -ne 2 ]; then
      echo "$@" >&2
   fi
}

_tfw_checkBashVersion() {
   [ -z "$BASH_VERSION" ] && _tfw_fatal "not running in Bash (/bin/bash) shell"
   if [ -n "${BASH_VERSINFO[*]}" ]; then
      [ ${BASH_VERSINFO[0]} -gt 3 ] && return 0
      if [ ${BASH_VERSINFO[0]} -eq 3 ]; then
         [ ${BASH_VERSINFO[1]} -gt 2 ] && return 0
         if [ ${BASH_VERSINFO[1]} -eq 2 ]; then
            [ ${BASH_VERSINFO[2]} -ge 48 ] && return 0
         fi
      fi
   fi
   _tfw_fatal "unsupported Bash version: $BASH_VERSION"
}

_tfw_checkTerminfo() {
   _tfw_tput=false
   case $(type -p tput) in
   */tput) _tfw_tput=tput;;
   esac
}

_tfw_checkCommandInPATH() {
   local __var="$2"
   local __path="$(type -p "$1")"
   case "$__path" in
   */"${1##*/}") ;;
   *) _tfw_fatal "command not found: $1 (PATH=$PATH)"
   esac
   [ -n "$__var" ] && eval $__var='"$__path"'
   return 0
}

_tfw_count_path_components() {
   local path="$1"
   local i=0
   while [ -n "$path" ]; do
      case "$path" in
      */) path="${path%/}";;
      */*) i=$(($i + 1)); path="${path%/*}";;
      *) i=$(($i + 1)); path=;;
      esac
   done
   echo $i
}

_tfw_unpack_words() {
   local __text="$1"
   shift
   while [ $# -gt 1 ]; do
      eval "$1=\"\${__text%% *}\""
      shift
      __text="${__text#* }"
   done
   if [ $# -ne 0 ]; then
      eval "$1=\"\$__text\""
   fi
}

_tfw_find_tests() {
   (
      local oo
      _tfw_shopt oo -s extdebug
      local func
      for func in $(builtin declare -F | $SED -n -e '/^declare -f test_[A-Za-z]/s/^declare -f //p'); do
         local funcname
         local lineno
         local path
         _tfw_unpack_words "$(builtin declare -F $func)" funcname lineno path
         echo $lineno 0 ${funcname#test_} "$(abspath "$path")"
      done
      local include
      for include in "${_tfw_included_tests[@]}"; do
         local lineno
         local script
         _tfw_unpack_words "$include" lineno script
         local listline
         "$BASH" "$_tfw_script_dir/$script" --list 2>/dev/null | while read listline; do
            local number
            local name
            local path
            _tfw_unpack_words "$listline" number name path
            case "$path" in
            /*) ;;
            *) path="$(abspath "$_tfw_script_dir/$path")";;
            esac
            echo $lineno $number $name "$path"
         done
      done
      _tfw_shopt_restore oo
   ) | sort -n -k1 -k2 | $SED -e 's/^[0-9][0-9]* [0-9][0-9]* //'
}

# Return a list of test names in the _tfw_test_sourcefiles and _tfw_test_names
# array variables, in the order that the test_TestName functions were defined.
# Test names must start with an alphabetic character (not numeric or '_').
_tfw_list_tests() {
   _tfw_test_sourcefiles=()
   _tfw_test_names=()
   local oIFS="$IFS"
   IFS="
"
   local -a testlines=($(_tfw_find_tests))
   IFS="$oIFS"
   local testline
   for testline in "${testlines[@]}"; do
      local name
      local path
      _tfw_unpack_words "$testline" name path
      _tfw_test_names+=("$name")
      _tfw_test_sourcefiles+=("$path")
   done
}

_tfw_filter_predicate() {
   local number="$1"
   local name="$2"
   shift 2
   local -a filters=("$@")
   local ret=1
   local oo
   _tfw_shopt oo -s extglob
   if [ ${#filters[*]} -eq 0 ]; then
      ret=0
   else
      local filter
      for filter in "${filters[@]}"; do
         case "$filter" in
         +([0-9]))
            if [ $number -eq $filter ]; then
               ret=0
               break
            fi
            ;;
         +([0-9])*(,+([0-9])))
            local oIFS="$IFS"
            IFS=,
            local -a numbers=($filter)
            IFS="$oIFS"
            local n
            for n in ${numbers[*]}; do
               if [ $number -eq $n ]; then
                  ret=0
                  break 2
               fi
            done
            ;;
         +([0-9])-)
            local start=${filter%-}
            if [ $number -ge $start ]; then
               ret=0
               break
            fi
            ;;
         -+([0-9]))
            local end=${filter#-}
            if [ $number -le $end ]; then
               ret=0
               break
            fi
            ;;
         +([0-9])-+([0-9]))
            local start=${filter%-*}
            local end=${filter#*-}
            if [ $number -ge $start -a $number -le $end ]; then
               ret=0
               break
            fi
            ;;
         *)
            case "$name" in
            "$filter"*) ret=0; break;;
            esac
            ;;
         esac
      done
   fi
   _tfw_shopt_restore oo
   return $ret
}

# A "fail" event occurs when any assertion fails, and indicates that the test
# has not passed.  Other tests may still proceed.  A "fail" event during setup
# or teardown is treated as an error, not a failure.

_tfw_failmsg() {
   # A failure during setup or teardown is treated as an error.
   case $_tfw_phase in
   testcase|finalise)
      if ! $_tfw_opt_error_on_fail; then
         tfw_log "FAIL: $*"
         return 0;
      fi
      ;;
   esac
   tfw_log "ERROR: $*"
}

_tfw_fail() {
   _tfw_failmsg "$*"
   _tfw_backtrace
   _tfw_failexit
}

_tfw_backtrace() {
   tfw_log '#----- shell backtrace -----'
   local -i up=1
   while [ "${BASH_SOURCE[$up]}" == "${BASH_SOURCE[0]}" -a "${FUNCNAME[$up]}" != '_tfw_finalise' ]; do
      let up=up+1
   done
   local -i i=0
   while [ $up -lt $((${#FUNCNAME[*]} - 1)) ]; do
      if [ "${BASH_SOURCE[$up]}" != "${BASH_SOURCE[0]}" ]; then
         echo "[$i] ${FUNCNAME[$(($up-1))]}() called from ${FUNCNAME[$up]}() at line ${BASH_LINENO[$(($up-1))]} of ${BASH_SOURCE[$up]}" >&$_tfw_log_fd
         let i=i+1
      fi
      let up=up+1
   done
   tfw_log '#-----'
}

_tfw_failexit() {
   # When exiting a test case due to a failure, log any diagnostic output that
   # has been requested.
   tfw_cat "${_tfw_opt_dump_on_fail[@]}"
   # A failure during setup or teardown is treated as an error.  A failure
   # during finalise does not terminate execution.
   case $_tfw_phase in
   testcase)
      if ! $_tfw_opt_error_on_fail; then
         exit 1
      fi
      ;;
   finalise)
      if ! $_tfw_opt_error_on_fail; then
         case $_tfw_result in
         PASS) _tfw_result=FAIL; _tfw_status=1;;
         esac
         return 1
      fi
      ;;
   esac
   _tfw_errorexit
}

# An "error" event prevents a test from running, so it neither passes nor fails.
# Other tests may still proceed.

_tfw_errormsg() {
   [ $# -eq 0 ] && set -- "(no message)"
   local -i up=1
   local -i top=${#FUNCNAME[*]}
   let top=top-1
   while [ $up -lt $top -a "${BASH_SOURCE[$up]}" = "${BASH_SOURCE[0]}" -a "${FUNCNAME[$up]}" != '_tfw_finalise' ]; do
      let up=up+1
   done
   if [ "${BASH_SOURCE[$up]}" = "${BASH_SOURCE[0]}" ]; then
      tfw_log "ERROR: $*"
   else
      tfw_log "ERROR: in ${FUNCNAME[$up]}: $*"
   fi
}

_tfw_error() {
   _tfw_errormsg "$*"
   _tfw_backtrace
   _tfw_errorexit
}

_tfw_errorexit() {
   # Do not exit process during finalise or teardown
   _tfw_result=ERROR
   case $_tfw_phase in
   finalise|teardown) [ $_tfw_status -lt 254 ] && _tfw_status=254;;
   *) exit 254;;
   esac
   return 254
}

# A "fatal" event stops the entire test run, and generally indicates an
# insurmountable problem in the test script or in the test framework itself.

_tfw_fatalmsg() {
   _tfw_echoerr "${BASH_SOURCE[1]}: FATAL: $*"
}

_tfw_fatal() {
   [ $# -eq 0 ] && set -- exiting
   _tfw_echoerr "${BASH_SOURCE[1]}: FATAL: $*"
   _tfw_fatalexit
}

_tfw_fatalexit() {
   exit 255
}


# The following functions can be overridden by a test script to provide a
# default fixture for all test cases.

setup() {
   :
}

finally() {
   :
}

teardown() {
   :
}

# The following functions are essential for writing test cases and fixtures.

# Executes its arguments as a command in the current shell process (not in a
# child process), so that side effects like functions setting variables will
# have effect.
#  - if the exit status is non-zero, then fails the current test
#  - otherwise, logs a message indicating the assertion passed
assert() {
   _tfw_getopts assert "$@"
   shift $_tfw_getopts_shift
   [ -z "$_tfw_message" ] && _tfw_message=$(shellarg "$@")
   _tfw_assert "$@" || _tfw_failexit || return $?
   $_tfw_assert_noise && tfw_log "# assert $_tfw_message"
   return 0
}

assertExpr() {
   _tfw_getopts assertexpr "$@"
   shift $_tfw_getopts_shift
   _tfw_parse_expr "$@" || return $?
   _tfw_message="${_tfw_message:+$_tfw_message }("$@")"
   _tfw_shellarg "${_tfw_expr[@]}"
   _tfw_assert eval "${_tfw_args[@]}" || _tfw_failexit || return $?
   $_tfw_assert_noise && tfw_log "# assert $_tfw_message"
   return 0
}

fail() {
   _tfw_getopts fail "$@"
   shift $_tfw_getopts_shift
   [ $# -ne 0 ] && _tfw_failmsg "$1"
   _tfw_backtrace
   _tfw_failexit
}

error() {
   _tfw_getopts error "$@"
   shift $_tfw_getopts_shift
   [ $# -ne 0 ] && _tfw_errormsg "$1"
   _tfw_backtrace
   _tfw_errorexit
}

fatal() {
   [ $# -eq 0 ] && set -- "no reason given"
   _tfw_fatalmsg "$@"
   _tfw_backtrace
   _tfw_fatalexit
}

# Append a time stamped message to the test case's stdout log.  Will work even
# in a context that stdout (fd 1) is redirected.  Will not log anything in a
# quietened region.
tfw_log() {
   if $_tfw_log_noise; then
      local ts=$(_tfw_timestamp)
      cat >&$_tfw_log_fd <<EOF
${ts##* } $*
EOF
   fi
}

# Append the contents of a file to the test case's stdout log.  A normal 'cat'
# to stdout would also do this, but tfw_cat echoes header and footer delimiter
# lines around to content to help distinguish it, and also works even in a
# context that stdout (fd 1) is redirected.
tfw_cat() {
   local header=
   local -a show=(cat)
   for file; do
      case $file in
      --header=*)
         header="${1#*=}"
         continue
         ;;
      -v|--show-nonprinting)
         show=(cat -v)
         continue
         ;;
      -h|--hexdump)
         show=(hd '</dev/null')
         continue
         ;;
      --stdout)
         file="${TFWSTDOUT?}"
         header="${header:-stdout of ($executed)}"
         ;;
      --stderr)
         file="${TFWSTDERR?}"
         header="${header:-stderr of ($executed)}"
         ;;
      *)
         header="${header:-${file#$_tfw_tmp/}}"
         ;;
      esac
      local missing_nl=
      tfw_log "#----- $header -----"
      eval "${show[@]}" "$file" >&$_tfw_log_fd
      if [ "${show[0]}" = cat -a "$(tail -1c "$file" | wc -l)" -eq 0 ]; then
         echo >&$_tfw_log_fd
         missing_nl=" (no newline at end)"
      fi
      tfw_log "#-----$missing_nl"
      header=
      show=(cat)
   done
}

# Copy the given file(s) into the log directory, so they form part of the residue
# of the log execution (together with log.txt).
tfw_preserve() {
   local arg
   for arg; do
      if cp -a "$arg" "$_tfw_logdir_test"; then
         $_tfw_assert_noise && tfw_log "# PRESERVE" $(ls -l -d "$arg")
      else
         error "cp failed"
      fi
   done
}

# Execute the given command with log messages quietened.
tfw_nolog() {
   if [ "$1" = ! ]; then
      shift
      ! tfw_nolog "$@"
   else
      local old_log_noise=$_tfw_log_noise
      _tfw_log_noise=false
      "$@" >/dev/null
      local stat=$?
      _tfw_log_noise=$old_log_noise
      return $stat
   fi
}

# Execute the given command with successful assert log messages quietened.
tfw_quietly() {
   if [ "$1" = ! ]; then
      shift
      ! tfw_quietly "$@"
   else
      local old_assert_noise=$_tfw_assert_noise
      _tfw_assert_noise=false
      "$@" >/dev/null
      local stat=$?
      _tfw_assert_noise=$old_assert_noise
      return $stat
   fi
}

# The following functions are extremely useful for writing test cases.

# Executes its arguments as a command:
#  - captures the standard output and error in temporary files for later
#    examination
#  - captures the exit status for later assertions
#  - sets the $executed variable to a description of the command that was
#    executed
execute() {
   $_tfw_assert_noise && tfw_log "# execute" $(shellarg "$@")
   _tfw_getopts execute "$@"
   shift $_tfw_getopts_shift
   _tfw_execute "$@"
}

executeOk() {
   $_tfw_assert_noise && tfw_log "# executeOk" $(shellarg "$@")
   _tfw_getopts executeok "$@"
   _tfw_opt_exit_status=0
   _tfw_dump_on_fail --stderr
   shift $_tfw_getopts_shift
   _tfw_execute "$@"
}

tfw_core_backtrace() {
   local executable="$1"
   local corefile="$2"
   echo backtrace >"$_tfw_process_tmp/backtrace.gdb"
   tfw_log "#----- gdb backtrace from $executable $corefile -----"
   gdb -n -batch -x "$_tfw_process_tmp/backtrace.gdb" "$executable" "$corefile" </dev/null
   tfw_log "#-----"
   rm -f "$_tfw_process_tmp/backtrace.gdb"
}

assertExitStatus() {
   _tfw_getopts assertexitstatus "$@"
   shift $_tfw_getopts_shift
   [ -z "$_tfw_message" ] && _tfw_message="exit status ($_tfw_exitStatus) of ($executed) $*"
   _tfw_assertExpr "$_tfw_exitStatus" "$@" || _tfw_failexit || return $?
   $_tfw_assert_noise && tfw_log "# assert $_tfw_message"
   return 0
}

assertRealTime() {
   _tfw_getopts assertrealtime "$@"
   shift $_tfw_getopts_shift
   [ -z "$_tfw_message" ] && _tfw_message="real execution time ($realtime) of ($executed) $*"
   _tfw_assertExpr "$realtime" "$@" || _tfw_failexit || return $?
   $_tfw_assert_noise && tfw_log "# assert $_tfw_message"
   return 0
}

replayStdout() {
   cat ${TFWSTDOUT?}
}

replayStderr() {
   cat ${TFWSTDERR?}
}

assertStdoutIs() {
   _tfw_assert_stdxxx_is stdout "$@" || _tfw_failexit
}

assertStderrIs() {
   _tfw_assert_stdxxx_is stderr "$@" || _tfw_failexit
}

assertStdoutLineCount() {
   _tfw_assert_stdxxx_linecount stdout "$@" || _tfw_failexit
}

assertStderrLineCount() {
   _tfw_assert_stdxxx_linecount stderr "$@" || _tfw_failexit
}

assertStdoutGrep() {
   _tfw_assert_stdxxx_grep stdout "$@" || _tfw_failexit
}

assertStderrGrep() {
   _tfw_assert_stdxxx_grep stderr "$@" || _tfw_failexit
}

# Execute the given args as a command, like the Bash 'eval' builtin but without
# expanding the arguments.  The only difference is that leading '!' arguments
# are stripped off and invert the exit status: non-zero becomes zero, and zero
# becomes 1.  Also, barfs with an error if the command is missing (no args).
# Very useful for writing functions that take a command-with-args as a predicate
# expression, because it allows the '!' notation for inverting the sense of the
# expression.
tfw_run() {
   local sense=true
   while [ "$1" = '!' ]; do
      sense=$($sense && echo false || echo true)
      shift
   done
   [ $# -eq 0 ] && error "missing command"
   "$@"
   local status=$?
   $sense && return $status
   [ $status -eq 0 ] && return 1
   return 0
}

# Wait until a given condition is met:
#  - can specify the timeout with --timeout=SECONDS (overridden by command-line
#    option)
#  - can specify the sleep interval with --sleep=SECONDS (can be a float)
#  - the condition is a command that is executed repeatedly until returns zero
#    status
# where SECONDS may be fractional, eg, 1.5
wait_until() {
   $_tfw_assert_noise && tfw_log "# wait_until" $(shellarg "$@")
   local start=$SECONDS
   _tfw_getopts wait_until "$@"
   shift $_tfw_getopts_shift
   local timeout=${_tfw_timeout_override:-${_tfw_opt_timeout:-${TFW_WAIT_UNTIL_TIMEOUT:-${_tfw_default_wait_until_timeout:-1}}}}
   _tfw_is_float "$timeout" || error "invalid timeout '$timeout'"
   sleep $timeout &
   local timeout_pid=$!
   while true; do
      tfw_run "$@" && break
      if ! kill -0 $timeout_pid 2>/dev/null; then
         local end=$SECONDS
         fail "timeout after $((end - start)) seconds" || return $?
      fi
      sleep ${_tfw_opt_sleep:-1}
   done
   local end=$SECONDS
   $_tfw_assert_noise && tfw_log "# waited for" $((end - start)) "seconds"
   kill $timeout_pid 2>/dev/null
   return 0
}

# For managing concurrent processes that will be automatically killed when
# cleaning up.

fork() {
   _tfw_getopts fork "$@"
   shift $_tfw_getopts_shift
   local forkid=${#_tfw_forked_pids[*]}
   if _tfw_set_forklabel "$1"; then
      shift
      [ -n "$_tfw_forkid" ] && error "fork label '%$_tfw_forklabel' already in use"
   fi
   local desc="fork[$forkid]${_tfw_forklabel:+ %$_tfw_forklabel}"
   local _tfw_process_tmp="$_tfw_tmp/fork-$forkid"
   mkdir "$_tfw_process_tmp" || _tfw_fatalexit
   $_tfw_assert_noise && tfw_log "# $desc START" $(shellarg "$@")
   "$@" 6>"$_tfw_process_tmp/log.stdout" 1>&6 2>"$_tfw_process_tmp/log.stderr" 7>"$_tfw_process_tmp/log.xtrace" &
   _tfw_forked_pids[$forkid]=$!
   _tfw_forked_labels[$forkid]="$_tfw_forklabel"
   [ -n "$_tfw_forklabel" ] && eval _tfw_fork_label_$_tfw_forklabel=$forkid
   $_tfw_assert_noise && tfw_log "# $desc pid=$! STARTED"
}

fork_is_running() {
   local ret=0
   for arg; do
      _tfw_set_forklabel "$arg" || error "not a fork label '$arg'"
      [ -n "$_tfw_forkid" ] || error "no such fork: %$_tfw_forklabel"
      _tfw_fork_is_running $_tfw_forkid || ret=1
   done
   return $ret
}

assert_fork_is_running() {
   _tfw_getopts assert_fork_is_running "$@"
   shift $_tfw_getopts_shift
   local message_opt="$_tfw_message"
   for arg; do
      _tfw_set_forklabel "$arg" || error "not a fork label '$arg'"
      [ -n "$_tfw_forkid" ] || error "no such fork: %$_tfw_forklabel"
      [ -z "$message_opt" ] && _tfw_message="fork $arg is running"
      _tfw_assert _tfw_fork_is_running $_tfw_forkid || _tfw_failexit || return $?
      $_tfw_assert_noise && tfw_log "# assert $_tfw_message"
   done
   return 0
}

assert_fork_is_not_running() {
   _tfw_getopts assert_fork_is_not_running "$@"
   shift $_tfw_getopts_shift
   local message_opt="$_tfw_message"
   for arg; do
      _tfw_set_forklabel "$arg" || error "not a fork label '$arg'"
      [ -n "$_tfw_forkid" ] || error "no such fork: %$_tfw_forklabel"
      [ -z "$message_opt" ] && _tfw_message="fork $arg is not running"
      _tfw_assert ! _tfw_fork_is_running $_tfw_forkid || _tfw_failexit || return $?
      $_tfw_assert_noise && tfw_log "# assert $_tfw_message"
   done
   return 0
}

fork_terminate() {
   _tfw_getopts fork_terminate "$@"
   shift $_tfw_getopts_shift
   $_tfw_assert_noise && tfw_log "# fork_terminate $*"
   for arg; do
      _tfw_set_forklabel "$arg" || error "not a fork label '$arg'"
      [ -n "$_tfw_forkid" ] || error "no such fork: %$_tfw_forklabel"
      _tfw_forkterminate $_tfw_forkid
   done
}

fork_wait() {
   _tfw_getopts fork_wait "$@"
   shift $_tfw_getopts_shift
   $_tfw_assert_noise && tfw_log "# fork_wait $*"
   while true; do
      local running=0
      for arg; do
         _tfw_set_forklabel "$arg" || error "not a fork label '$arg'"
         [ -n "$_tfw_forkid" ] || error "no such fork: %$_tfw_forklabel"
         if ! _tfw_forkwait $_tfw_forkid; then
            let running+=1
         fi
      done
      [ $running -eq 0 ] && return 0
      sleep 1
   done
}

fork_terminate_all() {
   _tfw_getopts fork_terminate_all "$@"
   shift $_tfw_getopts_shift
   [ $# -eq 0 ] || error "unsupported arguments: $*"
   $_tfw_assert_noise && tfw_log "# fork_terminate_all"
   local forkid
   for ((forkid=0; forkid < ${#_tfw_forked_pids[*]}; ++forkid)); do
      _tfw_forkterminate $forkid
   done
}

fork_wait_all() {
   _tfw_getopts fork_wait_all "$@"
   shift $_tfw_getopts_shift
   [ $# -eq 0 ] || error "unsupported arguments: $*"
   $_tfw_assert_noise && tfw_log "# fork_wait_all"
   while true; do
      local running=0
      local forkid
      for ((forkid=0; forkid < ${#_tfw_forked_pids[*]}; ++forkid)); do
         if ! _tfw_forkwait $forkid; then
            let running+=1
         fi
      done
      [ $running -eq 0 ] && return 0
      sleep 1
   done
}

_tfw_set_forklabel() {
   local oo
   _tfw_shopt oo -s extglob
   local ret=1
   case "$1" in
   '%'+([[A-Za-z0-9]))
      _tfw_forklabel="${1#%}"
      eval _tfw_forkid="\$_tfw_fork_label_$_tfw_forklabel"
      ret=0
      ;;
   '%'*)
      error "malformed fork label '$1'"
      ret=0
      ;;
   esac
   _tfw_shopt_restore oo
   return $ret
}

_tfw_forkterminate() {
   local forkid="$1"
   [ -z "$forkid" ] && return 1
   local pid=${_tfw_forked_pids[$forkid]}
   local label=${_tfw_forked_labels[$forkid]}
   local desc="fork[$forkid]${label:+ %$label}"
   [ -z "$pid" ] && return 1
   $_tfw_assert_noise && tfw_log "# $desc kill -TERM $pid"
   kill -TERM $pid 2>/dev/null
}

_tfw_fork_is_running() {
   local forkid="$1"
   [ -z "$forkid" ] && return 1 # forkid never used
   local pid=${_tfw_forked_pids[$forkid]}
   local label=${_tfw_forked_labels[$forkid]}
   [ -z "$pid" ] && return 1 # forkid already waited for
   kill -0 $pid 2>/dev/null
}

_tfw_forkwait() {
   local forkid="$1"
   [ -z "$forkid" ] && return 0
   local pid=${_tfw_forked_pids[$forkid]}
   local label=${_tfw_forked_labels[$forkid]}
   [ -z "$pid" ] && return 0 # forkid already waited for
   kill -0 $pid 2>/dev/null && return 1 # not killed yet
   _tfw_forked_pids[$forkid]=
   wait $pid # process has already exited, so should not block
   local status=$?
   local desc="fork[$forkid]${label:+ %$label}"
   $_tfw_assert_noise && tfw_log "# $desc pid=$pid EXIT status=$status"
   echo "++++++++++ $desc log.stdout ++++++++++"
   cat $_tfw_tmp/fork-$forkid/log.stdout
   echo "++++++++++"
   echo "++++++++++ $desc log.stderr ++++++++++"
   cat $_tfw_tmp/fork-$forkid/log.stderr
   echo "++++++++++"
   if $_tfw_trace; then
      echo "++++++++++ $desc log.xtrace ++++++++++"
      cat $_tfw_tmp/fork-$forkid/log.xtrace
      echo "++++++++++"
   fi
   case $status in
   0) ;;
   143) ;; # terminated with SIGTERM (probably from fork_terminate)
   1) _tfw_fail "$desc process exited with FAIL status";;
   254) _tfw_error "$desc process exited with ERROR status";;
   255) _tfw_fatal "$desc process exited with FATAL status";;
   *) _tfw_error "$desc process exited with status=$status";;
   esac
   return 0
}

# The following functions are very convenient when writing test cases.

assertGrep() {
   _tfw_getopts assertcontentgrep "$@"
   shift $_tfw_getopts_shift
   if [ $# -ne 2 ]; then
      _tfw_error "incorrect arguments"
      return $?
   fi
   _tfw_dump_on_fail "$1"
   _tfw_get_content "$1" || return $?
   _tfw_assert_grep "${_tfw_opt_line_msg:+$_tfw_opt_line_msg of }$1" "$_tfw_tmp/content" "$2" || _tfw_failexit
}

# Compare the two arguments as dotted ascii decimal version strings.
# Return 0 if they are equal, 1 if arg1 < arg2, 2 if arg1 > arg2
tfw_cmp_version() {
   local IFS=.
   local i=0 a=($1) b=($2)
   for (( i=0; i < ${#a[@]} || i < ${#b[@]}; ++i )); do
      local ai="${a[i]:-0}"
      local bi="${b[i]:-0}"
      (( 10#$ai < 10#$bi )) && return 1
      (( 10#$ai > 10#$bi )) && return 2
   done
   return 0
}

# Format the standard input into multi columns within an output width set by the
# COLUMNS env var.
tfw_multicolumn() {
   $AWK '
      function pad(s, n) {
         return sprintf("%-" n "s", s)
      }
      {
         line[nlines++] = $0
         if (length($0) > colwid)
            colwid = length($0)
      }
      END {
         wid = 0 + ENVIRON["COLUMNS"]
         if (wid != 0) {
            ncol = int(wid / (colwid + 2))
            if (ncol < 1)
                  ncol = 1
         }
         collen = int((nlines + ncol - 1) / ncol)
         for (r = 0; r < collen; ++r) {
            for (c = 0; c < ncol; ++c) {
                  i = c * collen + r
                  if (i >= nlines)
                     break
                  printf "%s  ", pad(line[i], colwid)
            }
            printf "\n"
         }
      }
   '
}

# Create a file with the given size (default 0).
# Usage: create_file [--append] <path> [<size>]
# where: <size> is of the form Nu
#        N is decimal integer
#        u is one of kKmMgG (k=10^3, K=2^10, m=10^6, M=2^20, g=10^9, G=2^30)
create_file() {
   local args=("$@")
   case "$1" in
   --append) shift;;
   *) rm -f "$1";;
   esac
   local path="$1"
   local size="$2"
   tfw_createfile --label="$path" ${size:+--size=$size} >>"$path" || error "failed command: create_file ${args[*]}"
}

# Add quotations to the given arguments to allow them to be expanded intact
# in eval expressions.
shellarg() {
   _tfw_shellarg "$@"
   echo "${_tfw_args[*]}"
}

# Echo the absolute path (containing symlinks if given) of the given
# file/directory, which does not have to exist or even be accessible.
abspath() {
   _tfw_abspath -L "$1"
}

# Echo the absolute path (resolving all symlinks) of the given file/directory,
# which does not have to exist or even be accessible.
realpath() {
   _tfw_abspath -P "$1"
}

# Return true if all the arguments arg2... match the given grep(1) regular
# expression arg1.
matches_rexp() {
   _tfw_matches_rexp "$@"
}

# Escape all grep(1) basic regular expression metacharacters.
escape_grep_basic() {
   local re="$1"
   local nil=''
   re="${re//[\\]/\\\\$nil}"
   re="${re//./\\.}"
   re="${re//\*/\\*}"
   re="${re//^/\\^}"
   re="${re//\$/\\$}"
   re="${re//\[/\\[}"
   re="${re//\]/\\]}"
   echo "$re"
}

# Escape all egrep(1) extended regular expression metacharacters.
escape_grep_extended() {
   local re="$1"
   local nil=''
   re="${re//[\\]/\\\\$nil}"
   re="${re//./\\.}"
   re="${re//\*/\\*}"
   re="${re//\?/\\?}"
   re="${re//+/\\+}"
   re="${re//^/\\^}"
   re="${re//\$/\\$}"
   re="${re//(/\\(}";#"(fix Vim syntax highlighting)
   re="${re//)/\\)}"
   re="${re//|/\\|}"
   re="${re//\[/\\[}"
   re="${re//{/\\{}"
   echo "$re"
}

# Restore the caller's shopt preferences before returning.
_tfw_shopt_restore _tfw_orig_shopt
