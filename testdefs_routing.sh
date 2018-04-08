# Common definitions for routing tests.
#
# Copyright 2012-2015 Serval Project, Inc.
# Copyright 2016-2018 Flinders University
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

# Setup function:
# - configure log diagnostics that are useful for debugging routing
# - disable Rhizome to speed up tests
setup_route_config() {
   executeOk_servald config \
      set log.console.level debug \
      set log.console.show_pid on \
      set log.console.show_time on \
      set debug.mdprequests yes \
      set debug.linkstate yes \
      set debug.subscriber yes \
      set debug.verbose yes \
      set debug.overlayrouting yes \
      set debug.overlayinterfaces yes \
      set rhizome.enable no
}

interface_is_up() {
   $GREP "Interface .* is up" $instance_servald_log || return 1
   return 0
}

link_matches() {
   local interface_ex=".*"
   local link_type="(BROADCAST|UNICAST)"
   local via=".*"
   while [ $# -ne 0 ]; do
      case "$1" in
      --interface) interface_ex="$2"; shift 2;;
      --broadcast) link_type="BROADCAST"; shift;;
      --unicast) link_type="UNICAST"; shift;;
      --via) link_type="INDIRECT"; via="$2"; interface_ex=""; shift 2;;
      --any) via=".*"; link_type=".*"; shift;;
      *) break;;
      esac
   done
   local oIFS="$IFS"
   IFS='|'
   local sids="$*"
   IFS="$oIFS"
   local rexp="^(${sids}):${link_type}:${interface_ex}:${via}:"
   tfw_log "Looking for $rexp"
   if ! $GREP -E "$rexp" "$TFWSTDOUT"; then
      tfw_log "Link not found"
      tfw_cat --stdout
      return 1
   fi
}

has_link() {
   executeOk_servald route print
   link_matches $@
}

has_no_link() {
   has_link --any $@ || return 0
   return 1
}

path_exists() {
   local dest
   eval dest=\$$#
   local dest_sidvar=SID${dest#+}
   local dest_sids
   eval 'dest_sids=("${'$dest_sidvar'[@]}")'
   local first_inst=$1
   local next_inst=$first_inst
   shift
   local I
   for I; do
      local sidvar=SID${I#+}
      local sids
      eval 'sids=("${'$sidvar'[@]}")'
      [ "${#sids[@]}" -gt 0 ] || error "no SIDs known for identity $I"
      set_instance $next_inst
      executeOk_servald route print
      link_matches "${sids[@]}" || return 1
      [ $I = $dest ] && break
      link_matches --via ${!sidvar} "${dest_sids[@]}" || return 1
      next_inst=$I
   done
   # so we think this path should exist, check that it works
   set_instance $first_inst
   executeOk_servald --stderr mdp trace --timeout=20 "${dest_sids[0]}"
#   assertStdoutGrep "^[0-9]+:$dest_sids\$"
   tfw_cat --stdout
   return 0
}

log_routing_table() {
   executeOk_servald route print
   tfw_cat --stdout --stderr
}
