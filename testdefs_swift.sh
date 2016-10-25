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

executeSwiftOk() {
   executeOk --stdout --stderr --core-backtrace \
             --executable="$swift_client_util" \
             -- \
             --port "${SWIFT_TEST_PORT?}" \
             ${SWIFT_TEST_USER:+--user "$SWIFT_TEST_USER" --password "$SWIFT_TEST_PASSWORD"} \
             "$@"
}
