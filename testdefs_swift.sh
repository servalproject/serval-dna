# Definitions for test suites using Swift
# Copyright 2017 Flinders University
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

swift_client_util="$servald_build_root/swift-client-api/swift-client-util"

SWIFT_TEST_USER="steve"
SWIFT_TEST_PASSWORD="jobs"

assert_swift_executable_exists() {
   executeSwiftOk help
}

# Setup function:
# - configure log diagnostics that are useful for debugging a Swift API
# - configure REST API credentials to support the Swift client
setup_swift_config() {
   local _instance="$1"
   [ -z "$_instance" ] || push_and_set_instance $_instance || return $?
   executeOk_servald config \
      set log.console.level debug \
      set log.console.show_pid on \
      set log.console.show_time on \
      set debug.http_server on \
      set debug.httpd on \
      set "api.restful.users.$SWIFT_TEST_USER.password" "$SWIFT_TEST_PASSWORD"
   [ -z "$_instance" ] || pop_instance
   return 0
}

# Setup function:
# - wait for the current instance's server to start processing REST requests
# - initialise the SWIFT_PORT_{I} shell variable with the port number of the REST
#   server running in instance {I}
# - zero the request count for the rest_request() function
wait_until_swift_server_ready() {
   local _instance
   case $1 in
   '') _instance=$instance_name;;
   +[A-Z]) _instance=${1#+};;
   *) error "invalid instance arg: $1";;
   esac
   wait_until servald_restful_http_server_started +$_instance
   local _portvar=SWIFT_TEST_PORT_$_instance
   get_servald_restful_http_server_port $_portvar +$_instance
}

executeSwiftOk() {
   local _portvar=SWIFT_TEST_PORT_$instance_name
   [ -n "${!_portvar}" ] || error "\$$_portvar is not set"
   executeOk --stdout --stderr --core-backtrace \
             --executable="$swift_client_util" \
             -- \
             --port "${!_portvar}" \
             ${SWIFT_TEST_USER:+--user "$SWIFT_TEST_USER" --password "$SWIFT_TEST_PASSWORD"} \
             "$@"
}
