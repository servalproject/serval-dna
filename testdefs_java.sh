# Definitions for test suites using Java.
# Copyright 2014 Serval Project Inc.
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

source "${0%/*}/../testconfig.sh"

# Utility function for setting up servald JNI fixtures:
#  - check that libserval.so is present
#  - set LD_LIBRARY_PATH so that libserval.so can be found
setup_servald_so() {
   assert [ -r "$servald_build_root/libserval.so" ]
   export LD_LIBRARY_PATH="$servald_build_root"
}

compile_java_classes() {
   assert --message='Java compiler was detected by ./configure' [ "$JAVAC" ]
   mkdir classes
   assert find "$servald_source_root"/java/ -name *.java | xargs $JAVAC -Xlint:unchecked -d classes
   assert [ -r classes/org/servalproject/servaldna/ServalDCommand.class ]
   assert [ -r classes/org/servalproject/servaldna/IJniResults.class ]
   assert [ -r classes/org/servalproject/test/ServalDTests.class ]
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
   "$func" "${opts[@]}" --core-backtrace java "-Djava.library.path=$LD_LIBRARY_PATH" -classpath "$PWD/classes" "$@"
}

executeJava() {
   _executeJava execute "$@"
}

executeJavaOk() {
   _executeJava executeOk "$@"
}

