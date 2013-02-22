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

UNPACK_DIR="${1?}"
shift

cd "${TMPDIR:-/tmp}" >/dev/null

if [ -n "$RHIZOME_MIRRORD_LOG_STDOUT" ]; then
   set -x
fi

rsync -a \
   "$UNPACK_DIR/" \
   servalp@servalproject.org:/home/servalp/maps.servalproject.org/testing/admin/data/instances/

curl -s \
   -o serval_maps_push_result.html \
   -D serval_maps_push_headers.txt \
   http://maps.servalproject.org/testing/admin/cache-update/instances/2798a6651e9caecd3d30fdc5e6a0e0f5
