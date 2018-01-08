# Definitions for test suites using Java.
# Copyright 2014-2015 Serval Project Inc.
# Copyright 2016 Flinders University
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

testdefs_java_sh=$(abspath "${BASH_SOURCE[0]}")
java_source_root="${testdefs_java_sh%/*}"
java_build_root="$java_source_root"
java_classdir="$java_build_root/java-api/classes"
java_testclassdir="$java_build_root/java-api/testclasses"

# Utility function for setting up servald JNI fixtures:
#  - check that libservaldaemon.so is present
#  - set LD_LIBRARY_PATH so that libservaldaemon.so can be found
setup_servald_so() {
   assert [ -r "$servald_build_root/libservaldaemon.so" ]
   export LD_LIBRARY_PATH="$servald_build_root"
}

assert_java_classes_exist() {
   assert [ -r "$java_classdir/org/servalproject/servaldna/ServalDCommand.class" ]
   assert [ -r "$java_classdir/org/servalproject/servaldna/IJniResults.class" ]
   assert [ -r "$java_testclassdir/org/servalproject/test/ServalDTests.class" ]
}

_executeJava() {
   local func="${1?}"
   shift
   local opts=()
   while [ $# -ne 0 ]; do
      case "$1" in
      --) shift; break;;
      --*) opts+=("$1"); shift;;
      *) break;;
      esac
   done
   "$func" "${opts[@]}" java "-Djava.library.path=$LD_LIBRARY_PATH" -classpath "$java_classdir:$java_testclassdir" "$@"
}

_run() {
   tfw_log "$@"
   "$@"
}

runJava() {
   _executeJava _run "$@"
}

executeJava() {
   _executeJava execute --core-backtrace "$@"
}

executeJavaOk() {
   _executeJava executeOk --core-backtrace "$@"
}

# Utility function:
#
#     unset_vars_with_prefix PREFIX
#
# Unsets all shell variables whose names starting with the given PREFIX
unset_vars_with_prefix() {
   local __prefix="${1?}"
   local __varname
   for __varname in $(declare -p | sed -n -e "s/^declare -[^ ]* \($__prefix[A-Za-z0-9_]\+\)=.*/\1/p"); do
      unset $__varname
   done
}

# Utility function:
#
#     unpack_vars PREFIX TEXT
#
# parses the given TEXT which must have the form:
#
#     ident1=..., ident2=...., ... identN=...
#
# into shell variables:
#
#     PREFIXident1=...
#     PREFIXident2=...
#     ...
#     PREFIXidentN=...
#
# Sets the UNPACKED_VAR_NAMES[] array variable to a list of the names of the
# variables that were set (names include the PREFIX).
#
# Warning: overwrites existing shell variables.  Names of overwritten shell
# variables are derived directly from the output of the command, so cannot be
# controlled.  PREFIX should be used to ensure that special variables cannot
# be clobbered by accident.
unpack_vars() {
   local __prefix="${1?}"
   local __text="${2?}"
   local __oo
   tfw_shopt __oo -s extglob
   UNPACKED_VAR_NAMES=()
   while [ -n "$__text" ]; do
      case "$__text" in
      [A-Za-z_.]+([A-Za-z_.0-9])=*)
         local __ident="${__text%%=*}"
         __ident="${__ident//./__}"
         __text="${__text#*=}"
         local __value="${__text%%, [A-Za-z_.]+([A-Za-z_.0-9])=*}"
         __text="${__text:${#__value}}"
         __text="${__text#, }"
         UNPACKED_VAR_NAMES+=("$__ident")
         eval ${__prefix}${__ident}=\"\$__value\"
         ;;
      *)
         fail "cannot unpack variable from '$__text'"
         ;;
      esac
   done
   tfw_shopt_restore __oo
}

