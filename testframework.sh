#!/bin/bash
#
# Serval Project testing framework
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
# #!/bin/sh
# . testframework.sh
# doc_feature1='Feature one works correctly'
# test_feature1() {
#   execute feature1 --options arg1 arg2
#   assertExitStatus == 0
#   assertUserTime <= 0
#   assertStdoutIs ""
#   assertStderrIs ""
# }
# doc_feature2='Name of feature two'
# test_feature2() {
#   execute feature2 --options arg1 arg2
#   assertExitStatus == 1
#   assertStdoutIs ""
#   assertStderrGrep "^ERROR: missing arg3$"
# }
# runTests

runTests() {
   _tfw_stdout=1
   _tfw_stderr=2
   _tfw_checkBashVersion
   _tfw_setup
   for testName in `_tfw_findTests` ; do
      local docvar="doc_$testName"
      _tfw_echo "${!docvar:-$testName}"
      (
         set -e
         setup
         trap 'stat=$?; teardown; exit $stat' 0
         test_$testName
      )
      stat=$?
      [ $stat -eq 255 ] && exit 255 # Bail out if _tfw_fatal was called in a test
      if [ $stat -eq 0 ]; then
         _tfw_echo PASS
      else
         _tfw_echo FAIL
      fi
   done
   return 0
}

setup() {
   : # To be overridden by the test script
}

teardown() {
   : # To be overridden by the test script
}

execute() {
   _tfw_last_argv0="$1"
   /usr/bin/time --portability --output=$_tfw_tmp/times "$@" >$_tfw_tmp/stdout 2>$_tfw_tmp/stderr
   _tfw_exitStatus=$?
}

assert() {
   local message="$1"
   shift
   [ -z "$message" ] && message="assertion $@"
   if ! "$@"; then
      fail "assertion failed: $message"
   fi
}

_tfw_cmp() {
   [ $# -ne 3 ] && _tfw_error 2 "incorrect arguments"
   local arg1="$1"
   local op="$2"
   local arg2="$3"
   case $op in
   '=='|'!='|'<'|'<='|'>'|'>=') awkop="$op";;
   '~'|'!~') awkop="$op";;
   *) _tfw_error "invalid operator: $op";;
   esac
   /usr/bin/awk -v arg1="$arg1" -v arg2="$arg2" -- 'BEGIN { exit (arg1 '"$awkop"' arg2) ? 0 : 1 }' </dev/null
}

assertCmp() {
   local message="$1 (${2:-''} $3 ${4:-''})"
   shift
   assert "$message" _tfw_cmp "$@"
   return 0
}

log() {
   _tfw_echo "$@"
}

fail() {
   _tfw_echo "$1"
   exit 1
}

assertExitStatus() {
   assertCmp "exit status of ${_tfw_last_argv0##*/} $_tfw_exitStatus $*" "$_tfw_exitStatus" "$@"
}

assertRealTime() {
   local realtime=$(awk '$1 == "real" { print $2 }' $_tfw_tmp/times)
   assertCmp "real execution time of ${_tfw_last_argv0##*/}" "$realtime" "$@"
}

replayStdout() {
   cat $_tfw_tmp/stdout
}

replayStderr() {
   cat $_tfw_tmp/stderr
}

assertStdoutIs() {
   _tfw_assert_stdxxx_is stdout "$@"
}

assertStderrIs() {
   _tfw_assert_stdxxx_is stderr "$@"
}

assertStdoutGrep() {
   _tfw_assert_stdxxx_grep stdout "$@"
}

assertStderrGrep() {
   _tfw_assert_stdxxx_grep stderr "$@"
}

_tfw_assert_stdxxx_is() {
   [ $# -ne 2 ] && _tfw_error 2 "incorrect arguments"
   if ! [ "$2" = $(/bin/cat $_tfw_tmp/$1) ]; then
      _tfw_echo "assertion failed: $1 of ${_tfw_last_argv0##*/} is \"$2\""
      _tfw_cat --$1
      exit 1
   fi
}

_tfw_assert_stdxxx_grep() {
   [ $# -ne 2 ] && _tfw_error 2 "incorrect arguments"
   if ! /bin/grep --quiet --regexp="$2" $_tfw_tmp/$1; then
      _tfw_echo "assertion failed: $1 of ${_tfw_last_argv0##*/} matches \"$2\""
      _tfw_cat --$1
      exit 1
   fi
}

_tfw_echo() {
   echo "$@" >&$_tfw_stdout
}

_tfw_echoerr() {
   echo "$@" >&$_tfw_stderr
}

_tfw_catguts() {
   for file; do
      case $file in
      --stdout) 
         echo "--- stdout of ${_tfw_last_argv0##*/} ---"
         /bin/cat $_tfw_tmp/stdout
         echo "---"
         ;;
      --stderr) 
         echo "--- stderr of ${_tfw_last_argv0##*/} ---"
         /bin/cat $_tfw_tmp/stderr
         echo "---"
         ;;
      *)
         echo "--- $file ---"
         /bin/cat "$file"
         echo "---"
         ;;
      esac
   done
}

_tfw_cat() {
   _tfw_catguts "$@" >&$_tfw_stdout
}

_tfw_caterr() {
   _tfw_catguts "$@" >&$_tfw_stderr
}

_tfw_setup() {
   _tfw_tmp=/tmp/_tfw-$$
   /bin/mkdir $_tfw_tmp
   trap 'stat=$?; _tfw_teardown; exit $stat' 0 1 2 15
   exec <&- 5>&1 5>&2 >$_tfw_tmp/log.stdout 2>$_tfw_tmp/log.stderr
   _tfw_stdout=5
   _tfw_stderr=5
   export TFWTMP=$_tfw_tmp/tmp
   /bin/mkdir $TFWTMP
}

_tfw_teardown() {
   /bin/rm -rf $_tfw_tmp
}

_tfw_checkBashVersion() {
   case $BASH_VERSION in
   [56789].* | 4.[23456789].*) ;;
   '') _tfw_fatal "not running in Bash (/bin/bash) shell";;
   *) _tfw_fatal "unsupported Bash version: $BASH_VERSION";;
   esac
}

_tfw_findTests() {
   builtin declare -F | sed -n -e '/^declare -f test_..*/s/^declare -f test_//p'
}

_tfw_error() {
   local up=1
   if [ $# -gt 1 ]; then
      case $1 in
      [1-9]) up=$1; shift;;
      esac
   fi
   echo "${BASH_SOURCE[$up]}: ERROR in ${FUNCNAME[$up]}: $*" >&$_tfw_stderr
   exit 1
}

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
