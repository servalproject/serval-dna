#!/bin/bash
#
# Serval Project testing framework for Bash shell
# Copyright 2012 Paul Gardner-Stephen
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

usage() {
   echo -n "\
Usage: ${0##*/} [options] [--]
Options:
   -t, --trace             Enable shell "set -x" tracing during tests, output to test log
   -v, --verbose           Send test log to output during execution
   -j, --jobs              Run all tests in parallel (by default runs as --jobs=1)
   --jobs=N                Run tests in parallel, at most N at a time
   -E, --stop-on-error     Do not execute any tests after an ERROR occurs
   -F, --stop-on-failure   Do not execute any tests after a FAIL occurs
   --filter=PREFIX         Only execute tests whose names start with PREFIX
"
}

# Internal utility for setting shopt variables and restoring their original
# value:
#     _tfw_shopt -s extglob -u extdebug
#     ...
#     _tfw_shopt_restore
_tfw_shopt() {
   if [ -n "$_tfw_shopt_orig" ]; then
      _tfw_fatal "unrestored shopt settings: $_tfw_shopt_orig"
   fi
   _tfw_shopt_orig=
   local op=s
   while [ $# -ne 0 ]
   do
      case "$1" in
      -s) op=s;;
      -u) op=u;;
      *)
         local opt="$1"
         _tfw_shopt_orig="${restore:+$restore; }shopt -$(shopt -q $opt && echo s || echo u) $opt"
         shopt -$op $opt
         ;;
      esac
      shift
   done
}
_tfw_shopt_restore() {
   if [ -n "$_tfw_shopt_orig" ]; then
      eval "$_tfw_shopt_orig"
      _tfw_shopt_orig=
   fi
}
_tfw_shopt_orig=
declare -a _tfw_running_pids

# The rest of this file is parsed for extended glob patterns.
_tfw_shopt -s extglob

runTests() {
   _tfw_stdout=1
   _tfw_stderr=2
   _tfw_checkBashVersion
   _tfw_checkTerminfo
   _tfw_invoking_script=$(abspath "${BASH_SOURCE[1]}")
   _tfw_suite_name="${_tfw_invoking_script##*/}"
   _tfw_cwd=$(abspath "$PWD")
   _tfw_tmpdir="${TFW_TMPDIR:-${TMPDIR:-/tmp}}/_tfw-$$"
   trap '_tfw_status=$?; rm -rf "$_tfw_tmpdir"; exit $_tfw_status' EXIT SIGHUP SIGINT SIGTERM
   rm -rf "$_tfw_tmpdir"
   mkdir -p "$_tfw_tmpdir" || return $?
   _tfw_logdir="${TFW_LOGDIR:-$_tfw_cwd/testlog}/$_tfw_suite_name"
   _tfw_trace=false
   _tfw_verbose=false
   _tfw_stop_on_error=false
   _tfw_stop_on_failure=false
   local allargs="$*"
   local -a filters=()
   local njobs=1
   _tfw_shopt -s extglob
   while [ $# -ne 0 ]; do
      case "$1" in
      --help) usage; exit 0;;
      -t|--trace) _tfw_trace=true;;
      -v|--verbose) _tfw_verbose=true;;
      --filter=*) filters+=("${1#*=}");;
      -j|--jobs) njobs=0;;
      --jobs=+([0-9])) njobs="${1#*=}";;
      --jobs=*) _tfw_fatal "invalid option: $1";;
      -E|--stop-on-error) _tfw_stop_on_error=true;;
      -F|--stop-on-failure) _tfw_stop_on_failure=true;;
      --) shift; break;;
      --*) _tfw_fatal "unsupported option: $1";;
      *) _tfw_fatal "spurious argument: $1";;
      esac
      shift
   done
   _tfw_shopt_restore
   # Create an empty results directory.
   _tfw_results_dir="$_tfw_tmpdir/results"
   mkdir "$_tfw_results_dir" || return $?
   # Create an empty log directory.
   mkdir -p "$_tfw_logdir" || return $?
   rm -f "$_tfw_logdir"/*
   # Enumerate all the test cases.
   _tfw_find_tests "${filters[@]}"
   # Iterate through all test cases, starting a new test whenever the number of
   # running tests is less than the job limit.
   _tfw_passcount=0
   _tfw_failcount=0
   _tfw_errorcount=0
   _tfw_fatalcount=0
   _tfw_running_pids=()
   _tfw_test_number_watermark=0
   local testNumber
   for ((testNumber = 1; testNumber <= ${#_tfw_tests[*]}; ++testNumber)); do
      testName="${_tfw_tests[$(($testNumber - 1))]}"
      # Wait for any existing child process to finish.
      while [ $njobs -ne 0 -a ${#_tfw_running_pids[*]} -ge $njobs ]; do
         _tfw_harvest_processes
      done
      [ $_tfw_fatalcount -ne 0 ] && break
      $_tfw_stop_on_error && [ $_tfw_errorcount -ne 0 ] && break
      $_tfw_stop_on_failure && [ $_tfw_failcount -ne 0 ] && break
      # Start the next test in a child process.
      _tfw_echo_intro $testNumber $testName
      [ $njobs -ne 1 ] && echo
      (
         _tfw_unique=$BASHPID
         echo "$testNumber $testName" >"$_tfw_results_dir/$_tfw_unique"
         _tfw_tmp=/tmp/_tfw-$_tfw_unique
         trap '_tfw_status=$?; rm -rf "$_tfw_tmp"; exit $_tfw_status' EXIT SIGHUP SIGINT SIGTERM
         local start_time=$(_tfw_timestamp)
         local finish_time=unknown
         (
            _tfw_test_name="$testName"
            trap '_tfw_status=$?; _tfw_teardown; exit $_tfw_status' EXIT SIGHUP SIGINT SIGTERM
            _tfw_result=ERROR
            mkdir $_tfw_tmp || exit 255
            _tfw_setup
            _tfw_result=FAIL
            _tfw_phase=testcase
            echo "# call test_$_tfw_test_name()"
            $_tfw_trace && set -x
            test_$_tfw_test_name
            _tfw_result=PASS
            case $_tfw_result in
            PASS) exit 0;;
            FAIL) exit 1;;
            ERROR) exit 254;;
            esac
            exit 255
         )
         local stat=$?
         finish_time=$(_tfw_timestamp)
         local result=FATAL
         case $stat in
         254) result=ERROR;; 
         1) result=FAIL;;
         0) result=PASS;; 
         esac
         echo "$testNumber $testName $result" >"$_tfw_results_dir/$_tfw_unique"
         {
            echo "Name:     $testName"
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
         } >"$_tfw_logdir/$testNumber.$testName.$result"
         exit 0
      ) &
      _tfw_running_pids+=($!)
   done
   # Wait for all child processes to finish.
   while [ ${#_tfw_running_pids[*]} -ne 0 ]; do
      _tfw_harvest_processes
   done
   # Clean up working directory.
   rm -rf "$_tfw_tmpdir"
   trap - EXIT SIGHUP SIGINT SIGTERM
   # Echo result summary and exit with success if no failures or errors.
   s=$([ ${#_tfw_tests[*]} -eq 1 ] || echo s)
   echo "${#_tfw_tests[*]} test$s, $_tfw_passcount pass, $_tfw_failcount fail, $_tfw_errorcount error"
   [ $_tfw_fatalcount -eq 0 -a $_tfw_failcount -eq 0 -a $_tfw_errorcount -eq 0 ]
}

_tfw_echo_intro() {
   local docvar="doc_$2"
   echo -n "$1. ${!docvar:-$2}..."
   [ $1 -gt $_tfw_test_number_watermark ] && _tfw_test_number_watermark=$1
}

_tfw_harvest_processes() {
   trap 'kill $spid 2>/dev/null' SIGCHLD
   sleep 1 &
   spid=$!
   set -m
   wait $spid 2>/dev/null
   trap - SIGCHLD
   local -a surviving_pids=()
   local pid
   for pid in ${_tfw_running_pids[*]}; do
      if kill -0 $pid 2>/dev/null; then
         surviving_pids+=($pid)
      elif [ -s "$_tfw_results_dir/$pid" ]; then
         set -- $(<"$_tfw_results_dir/$pid")
         local testNumber="$1"
         local testName="$2"
         local result="$3"
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
         if [ $njobs -eq 1 ]; then
            echo -n " "
            _tfw_echo_result "$result"
            echo
         elif lines=$($_tfw_tput lines); then
            local travel=$(($_tfw_test_number_watermark - $testNumber + 1))
            if [ $travel -gt 0 -a $travel -lt $lines ] && $_tfw_tput cuu $travel ; then
               _tfw_echo_intro $testNumber $testName
               echo -n " "
               _tfw_echo_result "$result"
               echo
               $_tfw_tput cud $(($_tfw_test_number_watermark - $testNumber))
            fi
         else
            _tfw_echo_intro $testNumber $testName
            echo -n "$testNumber. ... "
            _tfw_echo_result "$result"
            echo
         fi
      else
         _tfw_echoerr "${BASH_SOURCE[1]}: child process $pid terminated without result"
      fi
   done
   _tfw_running_pids=(${surviving_pids[*]})
}

_tfw_echo_result() {
   local result="$1"
   case "$result" in
   ERROR | FATAL)
      $_tfw_tput setf 4
      $_tfw_tput rev
      echo -n "$result"
      $_tfw_tput sgr0
      $_tfw_tput op
      ;; 
   PASS)
      $_tfw_tput setf 2
      echo -n "$result"
      $_tfw_tput op
      ;;
   FAIL)
      $_tfw_tput setf 4
      echo -n "$result"
      $_tfw_tput op
      ;;
   *)
      echo -n "$result"
      ;;
   esac
}

# The following functions can be overridden by a test script to provide a
# default fixture for all test cases.

setup() {
   :
}

teardown() {
   :
}

# The following functions are provided to facilitate writing test cases and
# fixtures.

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
   re="${re//(/\\(}"
   re="${re//)/\\)}"
   re="${re//|/\\|}"
   re="${re//\[/\\[}"
   re="${re//{/\\{}"
   echo "$re"
}

# Executes its arguments as a command:
#  - captures the standard output and error in temporary files for later
#    examination
#  - captures the exit status for later assertions
#  - sets the $executed variable to a description of the command that was
#    executed
execute() {
   tfw_log "# execute" $(_tfw_shellarg "$@")
   _tfw_getopts execute "$@"
   shift $_tfw_getopts_shift
   _tfw_execute "$@"
}

executeOk() {
   tfw_log "# executeOk" $(_tfw_shellarg "$@")
   _tfw_getopts executeok "$@"
   _tfw_opt_exit_status=0
   _tfw_dump_on_fail --stderr
   shift $_tfw_getopts_shift
   _tfw_execute "$@"
}

# Executes its arguments as a command in the current shell process (not in a
# child process), so that side effects like functions setting variables will
# have effect.
#  - if the exit status is non-zero, then fails the current test
#  - otherwise, logs a message indicating the assertion passed
assert() {
   _tfw_getopts assert "$@"
   shift $_tfw_getopts_shift
   _tfw_assert "$@" || _tfw_failexit
   tfw_log "# assert" $(_tfw_shellarg "$@")
   return 0
}

assertExpr() {
   _tfw_getopts assertexpr "$@"
   shift $_tfw_getopts_shift
   local awkexpr=$(_tfw_expr_to_awkexpr "$@")
   _tfw_message="${_tfw_message+$_tfw_message }($awkexpr)"
   _tfw_assert _tfw_eval_awkexpr "$awkexpr" || _tfw_failexit
   tfw_log "# assertExpr" $(_tfw_shellarg "$awkexpr")
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

# Append a message to the test case's stdout log.  A normal 'echo' to stdout
# will also do this, but tfw_log will work even in a context that stdout (fd 1)
# is redirected.
tfw_log() {
   local ts=$(_tfw_timestamp)
   cat >&$_tfw_log_fd <<EOF
${ts##* } $*
EOF
}

# Append the contents of a file to the test case's stdout log.  A normal 'cat'
# to stdout would also do this, but tfw_cat echoes header and footer delimiter
# lines around to content to help distinguish it, and also works even in a
# context that stdout (fd 1) is redirected.
tfw_cat() {
   local header=
   local show_nonprinting=
   for file; do
      case $file in
      --stdout) 
         tfw_log "#--- ${header:-stdout of $executed} ---"
         cat $show_nonprinting $_tfw_tmp/stdout
         tfw_log "#---"
         header=
         show_nonprinting=
         ;;
      --stderr) 
         tfw_log "#--- ${header:-stderr of $executed} ---"
         cat $show_nonprinting $_tfw_tmp/stderr
         tfw_log "#---"
         header=
         show_nonprinting=
         ;;
      --header=*) header="${1#*=}";;
      -v|--show-nonprinting) show_nonprinting=-v;;
      *)
         tfw_log "#--- ${header:-$file} ---"
         cat $show_nonprinting "$file"
         tfw_log "#---"
         header=
         show_nonprinting=
         ;;
      esac
   done >&$_tfw_log_fd
}

assertExitStatus() {
   _tfw_getopts assertexitstatus "$@"
   shift $_tfw_getopts_shift
   [ -z "$_tfw_message" ] && _tfw_message="exit status of $executed ($_tfw_exitStatus) $*"
   _tfw_assertExpr "$_tfw_exitStatus" "$@" || _tfw_failexit
   tfw_log "# assert $_tfw_message"
   return 0
}

assertRealTime() {
   _tfw_getopts assertrealtime "$@"
   shift $_tfw_getopts_shift
   [ -z "$_tfw_message" ] && _tfw_message="real execution time of $executed ($realtime) $*"
   _tfw_assertExpr "$realtime" "$@" || _tfw_failexit
   tfw_log "# assert $_tfw_message"
   return 0
}

replayStdout() {
   cat $_tfw_tmp/stdout
}

replayStderr() {
   cat $_tfw_tmp/stderr
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

assertGrep() {
   _tfw_getopts assertgrep "$@"
   shift $_tfw_getopts_shift
   if [ $# -ne 2 ]; then
      _tfw_error "incorrect arguments"
      return 254
   fi
   _tfw_dump_on_fail "$1"
   _tfw_assert_grep "$1" "$1" "$2" || _tfw_failexit
}

# Internal (private) functions that are not to be invoked directly from test
# scripts.

# Add shell quotation to the given arguments, so that when expanded using
# 'eval', the exact same argument results.  This makes argument handling fully
# immune to spaces and shell metacharacters.
_tfw_shellarg() {
   local arg
   local -a shellarg=()
   _tfw_shopt -s extglob
   for arg; do
      case "$arg" in
      +([A-Za-z_0-9.,:=+\/-])) shellarg+=("$arg");;
      *) shellarg+=("'${arg//'/'\\''}'");;
      esac
   done
   _tfw_shopt_restore
   echo "${shellarg[@]}"
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
   local ts=$(date '+%Y-%m-%d %H:%M:%S.%N')
   echo "${ts%[0-9][0-9][0-9][0-9][0-9][0-9]}"
}

_tfw_setup() {
   _tfw_phase=setup
   exec <&- 5>&1 5>&2 6>$_tfw_tmp/log.stdout 1>&6 2>$_tfw_tmp/log.stderr 7>$_tfw_tmp/log.xtrace
   BASH_XTRACEFD=7
   _tfw_log_fd=6
   _tfw_stdout=5
   _tfw_stderr=5
   if $_tfw_verbose; then
      # These tail processes will die when the test case's subshell exits.
      tail --pid=$BASHPID --follow $_tfw_tmp/log.stdout >&$_tfw_stdout 2>/dev/null &
      tail --pid=$BASHPID --follow $_tfw_tmp/log.stderr >&$_tfw_stderr 2>/dev/null &
   fi
   export TFWUNIQUE=$_tfw_unique
   export TFWVAR=$_tfw_tmp/var
   mkdir $TFWVAR
   export TFWTMP=$_tfw_tmp/tmp
   mkdir $TFWTMP
   cd $TFWTMP
   tfw_log '# SETUP'
   case `type -t setup_$_tfw_test_name` in
   function)
      tfw_log "# call setup_$_tfw_test_name()"
      $_tfw_trace && set -x
      setup_$_tfw_test_name $_tfw_test_name
      set +x
      ;;
   *)
      tfw_log "# call setup($_tfw_test_name)"
      $_tfw_trace && set -x
      setup $_tfw_test_name
      set +x
      ;;
   esac
   tfw_log '# END SETUP'
}

_tfw_teardown() {
   _tfw_phase=teardown
   tfw_log '# TEARDOWN'
   case `type -t teardown_$_tfw_test_name` in
   function)
      tfw_log "# call teardown_$_tfw_test_name()"
      $_tfw_trace && set -x
      teardown_$_tfw_test_name
      set +x
      ;;
   *)
      tfw_log "# call teardown($_tfw_test_name)"
      $_tfw_trace && set -x
      teardown $_tfw_test_name
      set +x
      ;;
   esac
   tfw_log '# END TEARDOWN'
}

# Executes $_tfw_executable with the given arguments.
_tfw_execute() {
   executed=$(_tfw_shellarg "${_tfw_executable##*/}" "$@")
   { time -p "$_tfw_executable" "$@" >$_tfw_tmp/stdout 2>$_tfw_tmp/stderr ; } 2>$_tfw_tmp/times
   _tfw_exitStatus=$?
   # Deal with exit status.
   if [ -n "$_tfw_opt_exit_status" ]; then
      _tfw_message="exit status of $executed ($_tfw_exitStatus) is $_tfw_opt_exit_status"
      _tfw_dump_stderr_on_fail=true
      _tfw_assert [ "$_tfw_exitStatus" -eq "$_tfw_opt_exit_status" ] || _tfw_failexit
      tfw_log "# assert $_tfw_message"
   else
      tfw_log "# exit status of $executed = $_tfw_exitStatus"
   fi
   # Parse execution time report.
   if ! _tfw_parse_times_to_milliseconds real realtime_ms ||
      ! _tfw_parse_times_to_milliseconds user usertime_ms ||
      ! _tfw_parse_times_to_milliseconds sys systime_ms
   then
      tfw_log '# malformed output from time:'
      tfw_cat --header=times -v $_tfw_tmp/times
   fi
   return 0
}

_tfw_parse_times_to_milliseconds() {
   local label="$1"
   local var="$2"
   local milliseconds=$(awk '$1 == "'"$label"'" {
         value = $2
         minutes = 0
         if (match(value, "[0-9]+m")) {
            minutes = substr(value, RSTART, RLENGTH - 1)
            value = substr(value, 1, RSTART - 1) substr(value, RSTART + RLENGTH)
         }
         if (substr(value, length(value)) == "s") {
            value = substr(value, 1, length(value) - 1)
         }
         if (match(value, "^[0-9]+(\.[0-9]+)?$")) {
            seconds = value + 0
            print (minutes * 60 + seconds) * 1000
         }
      }' $_tfw_tmp/times)
   [ -z "$milliseconds" ] && return 1
   [ -n "$var" ] && eval $var=$milliseconds
   return 0
}

_tfw_assert() {
   if ! "$@"; then
      _tfw_failmsg "assertion failed: ${_tfw_message:-$*}"
      _tfw_backtrace
      return 1
   fi
   return 0
}

declare -a _tfw_opt_dump_on_fail

_tfw_dump_on_fail() {
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
   _tfw_message=
   _tfw_opt_dump_on_fail=()
   _tfw_opt_error_on_fail=false
   _tfw_opt_exit_status=
   _tfw_opt_matches=
   _tfw_opt_line=
   _tfw_getopts_shift=0
   while [ $# -ne 0 ]; do
      case "$context:$1" in
      *:--stdout) _tfw_dump_on_fail --stdout;;
      *:--stderr) _tfw_dump_on_fail --stderr;;
      assert*:--dump-on-fail=*) _tfw_dump_on_fail "${1#*=}";;
      execute:--exit-status=*) _tfw_opt_exit_status="${1#*=}";;
      execute*:--executable=*)
         _tfw_executable="${1#*=}"
         [ -z "$_tfw_executable" ] && _tfw_error "missing value: $1"
         ;;
      assert*:--error-on-fail) _tfw_opt_error_on_fail=true;;
      assert*:--message=*) _tfw_message="${1#*=}";;
      assertgrep:--matches=*) _tfw_opt_matches="${1#*=}";;
      assertfilecontent:--line=*) _tfw_opt_line="${1#*=}";;
      *:--) let _tfw_getopts_shift=_tfw_getopts_shift+1; shift; break;;
      *:--*) _tfw_error "unsupported option: $1";;
      *) break;;
      esac
      let _tfw_getopts_shift=_tfw_getopts_shift+1
      shift
   done
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
}

_tfw_expr_to_awkexpr() {
   local awkexpr=
   for arg; do
      if [ -z "${arg//[0-9]}" ]; then
         awkexpr="${awkexpr:+$awkexpr }$arg"
      else
         case $arg in
         '==' | '!=' | '<' | '<=' | '>' | '>=' | \
         '~' | '!~' | '&&' | '||' | '!' )
            awkexpr="${awkexpr:+$awkexpr }$arg"
            ;;
         *)
            arg=${arg//\\/\\\\} #} restore Vim syntax highlighting
            arg=${arg//"/\\"}
            awkexpr="${awkexpr:+$awkexpr }\"$arg\""
            ;;
         esac
      fi
   done
   echo $awkexpr
}

_tfw_eval_awkexpr() {
   local awkerrs # on separate line so we don't lose exit status
   awkerrs=$(awk "BEGIN { exit(($*) ? 0 : 1) }" </dev/null 2>&1)
   local stat=$?
   if [ -n "$awkerrs" ]; then
      _tfw_error "invalid expression: $*"
      stat=254
   fi
   return $stat
}

_tfw_assertExpr() {
   local awkexpr=$(_tfw_expr_to_awkexpr "$@")
   _tfw_assert _tfw_eval_awkexpr "$awkexpr" || _tfw_failexit
}

_tfw_assert_stdxxx_is() {
   local qual="$1"
   shift
   _tfw_getopts assertfilecontent --$qual "$@"
   shift $((_tfw_getopts_shift - 1))
   if [ $# -lt 1 ]; then
      _tfw_error "incorrect arguments"
      return 254
   fi
   _tfw_shopt -s extglob
   case "$_tfw_opt_line" in
   +([0-9]))
      sed -n -e "${_tfw_opt_line}p" "$_tfw_tmp/$qual" >"$_tfw_tmp/content"
      ;;
   '')
      ln -f "$_tfw_tmp/$qual" "$_tfw_tmp/content"
      ;;
   *)
      _tfw_error "unsupported value for --line=$_tfw_opt_line"
      _tfw_backtrace
      _tfw_shopt_restore
      return 254
      ;;
   esac
   _tfw_shopt_restore
   local message="${_tfw_message:-${_tfw_opt_line:+line $_tfw_opt_line of }$qual of $executed is $*}"
   echo -n "$@" >$_tfw_tmp/stdxxx_is.tmp
   if ! cmp --quiet $_tfw_tmp/stdxxx_is.tmp "$_tfw_tmp/content"; then
      _tfw_failmsg "assertion failed: $message"
      _tfw_backtrace
      return 1
   fi
   tfw_log "# assert $message"
   return 0
}

_tfw_assert_stdxxx_linecount() {
   local qual="$1"
   shift
   _tfw_getopts assertfilecontent --$qual "$@"
   shift $((_tfw_getopts_shift - 1))
   if [ $# -lt 1 ]; then
      _tfw_error "incorrect arguments"
      return 254
   fi
   local lineCount=$(( $(cat $_tfw_tmp/$qual | wc -l) + 0 ))
   [ -z "$_tfw_message" ] && _tfw_message="$qual line count ($lineCount) $*"
   _tfw_assertExpr "$lineCount" "$@" || _tfw_failexit
   tfw_log "# assert $_tfw_message"
   return 0
}

_tfw_assert_stdxxx_grep() {
   local qual="$1"
   shift
   _tfw_getopts assertgrep --$qual "$@"
   shift $((_tfw_getopts_shift - 1))
   if [ $# -ne 1 ]; then
      _tfw_error "incorrect arguments"
      return 254
   fi
   _tfw_assert_grep "$qual of $executed" $_tfw_tmp/$qual "$@"
}

_tfw_assert_grep() {
   local label="$1"
   local file="$2"
   local pattern="$3"
   local message=
   if ! [ -e "$file" ]; then
      _tfw_error "$file does not exist"
      ret=254
   elif ! [ -f "$file" ]; then
      _tfw_error "$file is not a regular file"
      ret=254
   elif ! [ -r "$file" ]; then
      _tfw_error "$file is not readable"
      ret=254
   else
      local matches=$(( $(grep --regexp="$pattern" "$file" | wc -l) + 0 ))
      local done=false
      local ret=0
      _tfw_shopt -s extglob
      case "$_tfw_opt_matches" in
      '')
         done=true
         message="${_tfw_message:-$label contains a line matching \"$pattern\"}"
         if [ $matches -ne 0 ]; then
            tfw_log "# assert $message"
         else
            _tfw_failmsg "assertion failed: $message"
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
            tfw_log "# assert $message"
         else
            _tfw_failmsg "assertion failed: $message"
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
            tfw_log "# assert $message"
         else
            _tfw_failmsg "assertion failed: $message"
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
            tfw_log "# assert $message"
         else
            _tfw_failmsg "assertion failed: $message"
            ret=1
         fi
         ;;
      esac
      if ! $done; then
         _tfw_error "unsupported value for --matches=$_tfw_opt_matches"
         ret=254
      fi
      _tfw_shopt_restore
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

# Return a list of test names in the _tfw_tests array variable, in the order
# that the test_TestName functions were defined.
_tfw_find_tests() {
   _tfw_tests=()
   _tfw_shopt -s extdebug
   local name
   for name in $(builtin declare -F |
         sed -n -e '/^declare -f test_./s/^declare -f test_//p' |
         while read name; do builtin declare -F "test_$name"; done |
         sort --key 2,2n --key 3,3 |
         sed -e 's/^test_//' -e 's/[    ].*//')
   do
      if [ $# -eq 0 ]; then
         _tfw_tests+=("$name")
      else
         local filter
         for filter; do
            case "$name" in
            "$filter"*) _tfw_tests+=("$name"); break;;
            esac
         done
      fi
   done
   _tfw_shopt_restore
}

# A "fail" event occurs when any assertion fails, and indicates that the test
# has not passed.  Other tests may still proceed.  A "fail" event during setup
# or teardown is treated as an error, not a failure.

_tfw_failmsg() {
   # A failure during setup or teardown is treated as an error.
   case $_tfw_phase in
   testcase)
      if ! $_tfw_opt_error_on_fail; then
         tfw_log "FAIL: $*"
         return 0;
      fi
      ;;
   esac
   tfw_log "ERROR: $*"
}

_tfw_backtrace() {
   tfw_log '#--- backtrace ---'
   local -i up=1
   while [ "${BASH_SOURCE[$up]}" == "${BASH_SOURCE[0]}" ]; do
      let up=up+1
   done
   local -i i=0
   while [ $up -lt ${#FUNCNAME[*]} -a "${BASH_SOURCE[$up]}" != "${BASH_SOURCE[0]}" ]; do
      tfw_log "[$i] ${FUNCNAME[$(($up-1))]}() called from ${FUNCNAME[$up]}() at line ${BASH_LINENO[$(($up-1))]} of ${BASH_SOURCE[$up]}"
      let up=up+1
      let i=i+1
   done
   tfw_log '#---'
}

_tfw_failexit() {
   # When exiting a test case due to a failure, log any diagnostic output that
   # has been requested.
   tfw_cat "${_tfw_opt_dump_on_fail[@]}"
   # A failure during setup or teardown is treated as an error.
   case $_tfw_phase in
   testcase)
      if ! $_tfw_opt_error_on_fail; then
         exit 1
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
   while [ $up -lt $top -a "${BASH_SOURCE[$up]}" == "${BASH_SOURCE[0]}" ]; do
      let up=up+1
   done
   tfw_log "ERROR in ${FUNCNAME[$up]}: $*"
}

_tfw_error() {
   _tfw_errormsg "ERROR: $*"
   _tfw_backtrace
   _tfw_errorexit
}

_tfw_errorexit() {
   # Do not exit process during teardown
   _tfw_result=ERROR
   case $_tfw_phase in
   teardown) [ $_tfw_status -lt 254 ] && _tfw_status=254;;
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

# Restore the caller's shopt preferences before returning.
_tfw_shopt_restore
