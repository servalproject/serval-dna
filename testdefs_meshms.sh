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

MESHMS_USE_RESTFUL=false

meshms_use_restful() {
   setup_curl 7
   MESHMS_USE_RESTFUL=true
   MESHMS_RESTFUL_USER="$1"
   MESHMS_RESTFUL_PASSWORD="$2"
   get_servald_restful_http_server_port MESHMS_RESTFUL_PORT
}

meshms_list_messages() {
   local sid_sender=${1?}
   local sid_recipient=${2?}
   if $MESHMS_USE_RESTFUL; then
      executeOk curl \
            --silent --fail --show-error \
            --output meshms_list_messages.json \
            --basic --user "$MESHMS_RESTFUL_USER:$MESHMS_RESTFUL_PASSWORD" \
            "http://$addr_localhost:$MESHMS_RESTFUL_PORT/restful/meshms/$sid_sender/$sid_recipient/messagelist.json"
   else
      executeOk_servald meshms list messages $sid_sender $sid_recipient
   fi
}

meshms_send_message() {
   local sid_sender=${1?}
   local sid_recipient=${2?}
   local text="${3?}"
   if $MESHMS_USE_RESTFUL; then
      executeOk curl \
            -H "Expect:" \
            --silent --fail --show-error \
            --output meshms_send_message.json \
            --basic --user "$MESHMS_RESTFUL_USER:$MESHMS_RESTFUL_PASSWORD" \
            --form "message=$text;type=text/plain;charset=utf-8" \
            "http://$addr_localhost:$MESHMS_RESTFUL_PORT/restful/meshms/$sid_sender/$sid_recipient/sendmessage"
   else
      executeOk_servald meshms send message $sid_sender $sid_recipient "$text"
   fi
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
         meshms_send_message $sid1 $sid2 "${TEXT[$n]}"
         let ++sent_since_ack
         let ++NSENT
         ;;
      '<')
         MESSAGE[$n]="<"
         meshms_send_message $sid2 $sid1 "${TEXT[$n]}"
         let ++NRECV
         let sent_since_ack=0
         ;;
      'A')
         MESSAGE[$n]=ACK
         [ $i -ne 0 -a $sent_since_ack -eq 0 ] && error "two ACKs in a row (at position $i)"
         meshms_list_messages $sid2 $sid1
         let ++NACK
         let sent_since_ack=0
         ;;
      *)
         error "invalid message symbol '$sym' (at position $i)"
         ;;
      esac
   done
}
