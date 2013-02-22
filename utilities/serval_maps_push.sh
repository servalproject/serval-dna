#!/bin/sh

# Rhizome Maps push script
# Copyright (C) 2013 Serval Project Inc.
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

set -e

TARGET=testing
UNPACK_DIR="${1?}"
shift

cd "${TMPDIR:-/tmp}" >/dev/null

if [ -n "$RHIZOME_MIRRORD_LOG_STDOUT" ]; then
   set -x
fi

rsync -a \
   "$UNPACK_DIR/" \
   "servalp@servalproject.org:/home/servalp/maps.servalproject.org/$TARGET/admin/data/instances/"

curl -s \
   -o serval_maps_push_result.html \
   -D serval_maps_push_headers.txt \
   "http://maps.servalproject.org/$TARGET/admin/cache-update/instances/2798a6651e9caecd3d30fdc5e6a0e0f5"

response=`sed -n -e '1s/^HTTP\/1\.. //p' serval_maps_push_headers.txt` 
case $response in
2[0-9][0-9]\ *) exit 0;;
3[0-9][0-9]\ *) echo "Unexpected HTTP response: $response" >&2;;
[45][0-9][0-9]\ *) echo "HTTP error response: $response" >&2;;
*) echo "Malformed HTTP response" >&2;;
esac
if [ -n "$RHIZOME_MIRRORD_LOG_STDOUT" ]; then
   cat serval_maps_push_headers.txt
   cat serval_maps_push_result.html
fi
exit 1
