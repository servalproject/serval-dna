# Common definitions for manipulating JSON in test scripts.
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

# Utility function:
# - ensure that a given version or later of the jq(1) utility is available
# - for use in setup (fixture) functions
setup_jq() {
   JQ=$(type -P jq) || error "jq(1) command is not present"
   local minversion="${1?}"
   local ver="$("$JQ" --version 2>&1)"
   case "$ver" in
   jq-*)
      local oIFS="$IFS"
      IFS='-'
      set -- $ver
      IFS="$oIFS"
      jqversion="$2"
      ;;
   jq\ version\ *)
      set -- $ver
      jqversion="$3"
      ;;
   *)
      error "cannot parse output of jq --version: $ver"
      ;;
   esac
   tfw_cmp_version "$jqversion" "$minversion"
   case $? in
   0|2)
      export JQ
      return 0
      ;;
   esac
   error "jq(1) version $jqversion is not adequate (need $minversion or higher)"
}

# Guard function:
JQ=
jq() {
   [ -x "$JQ" ] || error "missing call to setup_jq or setup_jsonin the fixture"
   "$JQ" "$@"
}

# Setup function:
# - any test wishing to use the JSON utilities in this file must call this in
#   its setup()
setup_json() {
   setup_jq 1.3
}

assertJq() {
   local json="$1"
   local jqscript="$2"
   assert --message="$jqscript" --dump-on-fail="$json" [ "$(jq "$jqscript" "$json")" = true ]
}

assertJqCmp() {
   local opts=()
   while [ $# -gt 0 ]; do
      case "$1" in
      --) shift; break;;
      --*) opts+=("$1"); shift;;
      *) break;;
      esac
   done
   [ $# -eq 3 ] || error "invalid arguments"
   local json="$1"
   local jqscript="$2"
   local file="$3"
   jq --raw-output "$jqscript" "$json" >"$TFWTMP/jqcmp.tmp"
   assert --dump-on-fail="$TFWTMP/jqcmp.tmp" --dump-on-fail="$file" "${opts[@]}" cmp "$TFWTMP/jqcmp.tmp" "$file"
}

assertJqIs() {
   local opts=()
   while [ $# -gt 0 ]; do
      case "$1" in
      --) shift; break;;
      --*) opts+=("$1"); shift;;
      *) break;;
      esac
   done
   [ $# -eq 3 ] || error "invalid arguments"
   local json="$1"
   local jqscript="$2"
   local text="$3"
   local jqout="$(jq --raw-output "$jqscript" "$json")"
   assert "${opts[@]}" [ "$jqout" = "$text" ]
}

assertJqGrep() {
   local opts=()
   while [ $# -gt 0 ]; do
      case "$1" in
      --) shift; break;;
      --*) opts+=("$1"); shift;;
      *) break;;
      esac
   done
   [ $# -eq 3 ] || error "invalid arguments"
   local json="$1"
   local jqscript="$2"
   local pattern="$3"
   jq "$jqscript" "$json" >"$TFWTMP/jqgrep.tmp"
   assertGrep "${opts[@]}" "$TFWTMP/jqgrep.tmp" "$pattern"
}

transform_list_json() {
   # The following jq(1) incantation transforms a JSON array in from the
   # following form (which is optimised for transmission size):
   #     {
   #        "header":[ "label1", "label2", "label3", ... ],
   #        "rows":[
   #              [  row1value1, row1value2, row1value3, ... ],
   #              [  row2value1, row2value2, row2value3, ... ],
   #                 ...
   #              [  rowNvalue1, rowNvalue2, rowNvalue3, ... ]
   #           ]
   #     }
   #
   # into an array of JSON objects:
   #     [
   #        {
   #           "label1": row1value1,
   #           "label2": row1value2,
   #           "label3": row1value3,
   #           ...
   #        },
   #        {
   #           "label1": row2value1,
   #           "label2": row2value2,
   #           "label3": row2value3,
   #           ...
   #        },
   #        ...
   #        {
   #           "label1": rowNvalue1,
   #           "label2": rowNvalue2,
   #           "label3": rowNvalue3,
   #           ...
   #        }
   #     ]
   # which is much easier to test with jq(1) expressions.
   jq '
         [
            .header as $header |
            .rows as $rows |
            $rows | keys | .[] as $index |
            [ $rows[$index] as $d | $d | keys | .[] as $i | {key:$header[$i], value:$d[$i]} ] |
            from_entries |
            .["__index"] = $index
         ]
      ' "$1" >"$2"
}
