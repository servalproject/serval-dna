# Common definitions for MeshMS test suites.
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

# Create a file that contains no blank lines.
meshms_create_message() {
   create_file --label="$1" - $2 | sed -e '/^$/d'
}

# Add a sequence of messages of varying sizes up to 1 KiB.
meshms_add_messages() {
   local sid1="${1?}"
   local sid2="${2?}"
   local symbols="${3?}"
   shift 3
   local texts=("$@")
   local sent_since_ack=0
   local i n size msize
   local size=0
   for ((i = 0; i < ${#symbols}; ++i)); do
      local sym="${symbols:$i:1}"
      let size+=379
      let msize=size%1021
      let n=NMESSAGE++
      local text="${texts[$i]}"
      case $sym in
      '>'|'<')
         if [ -n "$text" ]; then
            TEXT[$n]="$text"
         else
            TEXT[$n]="$(meshms_create_message "message$n" $msize)"
         fi
         ;;
      esac
      case $sym in
      '>')
         MESSAGE[$n]=">"
         executeOk_servald meshms send message $sid1 $sid2 "${TEXT[$n]}"
         let ++sent_since_ack
         let ++NSENT
         ;;
      '<')
         MESSAGE[$n]="<"
         executeOk_servald meshms send message $sid2 $sid1 "${TEXT[$n]}"
         let ++NRECV
         ;;
      'A')
         MESSAGE[$n]=ACK
         [ $i -ne 0 -a $sent_since_ack -eq 0 ] && error "two ACKs in a row (at position $i)"
         executeOk_servald meshms list messages $sid2 $sid1
         let ++NACK
         ;;
      *)
         error "invalid message symbol '$sym' (at position $i)"
         ;;
      esac
   done
}
