# Common definitions for rhizome test suites.
# Copyright 2012 The Serval Project, Inc.
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

# Some useful regular expressions.  These must work for grep(1) (as basic
# expressions) and also in sed(1).
rexp_service='[A-Za-z0-9_]\+'
rexp_manifestid='[0-9a-fA-F]\{64\}'
rexp_bundlekey='[0-9a-fA-F]\{64\}'
rexp_bundlesecret="$rexp_bundlekey"
rexp_filehash='[0-9a-fA-F]\{128\}'
rexp_filesize='[0-9]\{1,\}'
rexp_version='[0-9]\{1,\}'
rexp_crypt='[0-9]\{1,\}'
rexp_date='[0-9]\{1,\}'
rexp_rowid='[0-9]\{1,\}'

assert_manifest_complete() {
   local manifest="$1"
   tfw_cat -v "$manifest"
   assertGrep "$manifest" "^service=$rexp_service\$"
   assertGrep "$manifest" "^id=$rexp_manifestid\$"
   assertGrep "$manifest" "^BK=$rexp_bundlekey\$"
   assertGrep "$manifest" "^date=$rexp_date\$"
   assertGrep "$manifest" "^version=$rexp_version\$"
   assertGrep "$manifest" "^filesize=$rexp_filesize\$"
   if $GREP -q '^filesize=0$' "$manifest"; then
      assertGrep --matches=0 "$manifest" "^filehash="
   else
      assertGrep "$manifest" "^filehash=$rexp_filehash\$"
   fi
   if $GREP -q '^service=file$' "$manifest"; then
      assertGrep "$manifest" "^name="
   fi
}

# Assertion function:
# - assert that the output of a "servald rhizome list" command exactly describes the given files
assert_rhizome_list() {
   assertStdoutIs --stderr --line=1 -e '13\n'
   assertStdoutIs --stderr --line=2 -e '_id:service:id:version:date:.inserttime:.author:.fromhere:filesize:filehash:sender:recipient:name\n'
   local exactly=true
   local re__inserttime="$rexp_date"
   local re__fromhere='[01]'
   local re__author="\($rexp_sid\)\{0,1\}"
   local files=0
   local manifestname=
   local arg
   for arg; do
      case "$arg" in
      --fromhere=*) re__fromhere="${arg#*=}";;
      --author=*) re__author="${arg#*=}";;
      --manifest=*) manifestname="${arg#*=}";;
      --and-others) exactly=false;;
      --*) error "unsupported option: $arg";;
      *)
         unpack_manifest_for_grep "$arg" "$manifestname"
         assertStdoutGrep --stderr --matches=1 "^$rexp_rowid:$re_service:$re_manifestid:$re_version:$re_date:$re__inserttime:$re__author:$re__fromhere:$re_filesize:$re_filehash:$re_sender:$re_recipient:$re_name\$"
         let files+=1
         manifestname=
         ;;
      esac
   done
   $exactly && assertStdoutLineCount --stderr '==' $(($files + 2))
   rhizome_list_file_count=$(( $(replayStdout | wc -l) - 2 ))
}

# Parse the standard output produced by the immediately preceding "rhizome list"
# command into the following shell variables:
#  NCOLS the number of columns
#  NROWS the number of data rows (not counting headers)
#  HEADER[c] the C-th header label, 0 <= C <= NCOLS-1
#  <label>[R] where <label> is a header label with all non-alphanumerics
#  replaced by underscore '_' and all alphas converted to upper case, eg,
#  .author -> _AUTHOR, is the value of that column in the R-th row, 0 <=
#  R < NROWS
#
# Warning: overwrites existing shell variables.  Names of overwritten shell
# variables are derived directly from the output of rhizome list, so cannot be
# controlled.  If a prefix is supplied, all variables are prefixed with that.
rhizome_list_unpack() {
   local prefix="$1"
   {
      local n
      read n
      eval ${prefix}NCOLS=\"\$n\"
      declare -a ${prefix}HEADER
      local -a header
      local oIFS="$IFS"
      IFS=:
      read -r -a header
      IFS="$oIFS"
      eval ${prefix}HEADER="(\"\${header[@]}\")"
      local hdr
      local -a colvars=()
      for hdr in "${header[@]}"; do
         case "$hdr" in
         id)
            hdr=BID;;
         *)
            hdr="${hdr//[^A-Za-z0-9_]/_}"
            # hdr="${hdr^^*}" would do in Bash-4.0 and later
            hdr="$(echo "$hdr" | sed -e 's/.*/\U&/')"
            ;;
         esac
         colvars+=("$hdr")
      done
      local -a row
      IFS=:
      local i=0
      while eval read -r -a row; do
         local j=0
         local val
         for val in "${row[@]}"; do
            eval ${prefix}${colvars[$j]}[$i]=\"\$val\"
            let ++j
         done
         let ++i
      done
      IFS="$oIFS"
      eval ${prefix}NROWS=$i
   } < "$TFWSTDOUT"
}

rhizome_list_dump() {
   local ncols
   local -a headers
   local readvars=
   read ncols
   local oIFS="$IFS"
   IFS=:
   read -r -a headers
   IFS="$oIFS"
   local hdr
   local colvar
   for hdr in "${headers[@]}"; do
      readvars="$readvars __col_${hdr//[^A-Za-z0-9_]/_}"
   done
   eval local $readvars
   for colvar in $readvars; do
      eval "$colvar=ok"
   done
   local echoargs
   for colname; do
      case $colname in
      manifestid|bundleid) colvar=__col_id;;
      *) colvar="__col_${colname//[^A-Za-z0-9_]/_}";;
      esac
      eval [ -n "\"\${$colvar+ok}\"" ] || error "invalid column name: $colname" || return $?
      echoargs="$echoargs $colname=\"\${$colvar}\""
   done
   IFS=:
   while eval read -r $readvars; do
      eval echo $echoargs
   done
   IFS="$oIFS"
}

assert_stdout_add_file() {
   local manifestname=
   while [ $# -gt 0 ]; do
      case "$1" in
      --manifest=*) manifestname="${1#*=}"; shift;;
      --*) error "unsupported option: $1"; return 1;;
      --) shift; break;;
      *) break;;
      esac
   done
   [ $# -ge 1 ] || error "missing filename arg"
   local filename="$1"
   shift
   unpack_manifest_for_grep "$filename" "$manifestname"
   compute_filehash actual_filehash "$filename" actual_filesize
   opt_service=
   opt_manifestid=
   opt_author=
   opt_secret=
   opt_BK=
   opt_filesize=
   opt_name=false
   if replayStdout | $GREP -q '^service:file$'; then
      opt_name=true
   fi
   opt_filehash=true
   if [ "$re_crypt" = 1 ]; then
      opt_filehash=false
   fi
   fieldnames='service|manifestid|author|secret|BK|filesize|filehash|name'
   for arg; do
      case "$arg" in
      !+($fieldnames))
         fieldname="${arg#!}"
         eval opt_$fieldname=false
         ;;
      +($fieldnames)=*)
         value="${arg#*=}"
         fieldname="${arg%%=*}"
         assertStdoutGrep --matches=1 "^$fieldname:$value\$"
         ;;
      *)
         error "unsupported argument: $arg"
         ;;
      esac
   done
   ${opt_service:-true} && assertStdoutGrep --matches=1 "^service:$re_service\$"
   ${opt_manifestid:-true} && assertStdoutGrep --matches=1 "^manifestid:$re_manifestid\$"
   ${opt_author:-true} && assertStdoutGrep --matches=1 "^\.author:$rexp_sid\$"
   ${opt_secret:-true} && assertStdoutGrep --matches=1 "^\.secret:$re_secret\$"
   ${opt_BK:-true} && assertStdoutGrep --matches=1 "^BK:$re_BK\$"
   ${opt_filesize:-true} && assertStdoutGrep --matches=1 "^filesize:$actual_filesize\$"
   if replayStdout | $GREP -q '^filesize:0$'; then
      assertStdoutGrep --matches=0 "^filehash:"
   else
      ${opt_filehash:-true} && assertStdoutGrep --matches=1 "^filehash:$actual_filehash\$"
   fi
   ${opt_name:-true} && assertStdoutGrep --matches=1 "^name:$re_name\$"
}

assert_stdout_import_bundle() {
   # Output of "import bundle" is the same as "add file" but without the secret
   # or author fields.
   assert_stdout_add_file "$@" '!secret' '!author'
}

unpack_manifest_for_grep() {
   local filename="$1"
   local manifestname="${2:-$filename.manifest}"
   re_service="$rexp_service"
   re_manifestid="$rexp_manifestid"
   re_version="$rexp_version"
   re_date="$rexp_date"
   re_secret="$rexp_bundlesecret"
   re_BK="$rexp_bundlekey"
   re_sender="\($rexp_sid\)\{0,1\}"
   re_recipient="\($rexp_sid\)\{0,1\}"
   re_filesize="$rexp_filesize"
   re_filehash="\($rexp_filehash\)\{0,1\}"
   re_name=$(escape_grep_basic "${filename##*/}")
   if [ -e "$manifestname" ]; then
      re_filesize=$($SED -n -e '/^filesize=/s///p' "$manifestname")
      if [ "$filesize" = 0 ]; then
         re_filehash=
      else
         re_filehash=$($SED -n -e '/^filehash=/s///p' "$manifestname")
      fi
      re_secret="$rexp_bundlesecret"
      re_service=$($SED -n -e '/^service=/s///p' "$manifestname")
      re_service=$(escape_grep_basic "$re_service")
      re_manifestid=$($SED -n -e '/^id=/s///p' "$manifestname")
      re_version=$($SED -n -e '/^version=/s///p' "$manifestname")
      re_date=$($SED -n -e '/^date=/s///p' "$manifestname")
      re_crypt=$($SED -n -e '/^crypt=/s///p' "$manifestname")
      re_name=$($SED -n -e '/^name=/s///p' "$manifestname")
      re_name=$(escape_grep_basic "$re_name")
      re_BK=$($SED -n -e '/^BK=/s///p' "$manifestname")
      re_sender=$($SED -n -e '/^sender=/s///p' "$manifestname")
      re_recipient=$($SED -n -e '/^recipient=/s///p' "$manifestname")
   fi
}

assert_manifest_newer() {
   local manifest1="$1"
   local manifest2="$2"
   # The new manifest must have a higher version than the original.
   extract_manifest_version oldversion "$manifest1"
   extract_manifest_version newversion "$manifest2"
   assert [ $newversion -gt $oldversion ]
   # The new manifest must have a different filehash from the original.
   extract_manifest_filehash oldfilehash "$manifest1"
   extract_manifest_filehash newfilehash "$manifest2"
   assert [ $oldfilehash != $newfilehash ]
}

strip_signatures() {
   for file; do
      cat -v "$file" | $SED -e '/^^@/,$d' >"tmp.$file" && mv -f "tmp.$file" "$file"
   done
}

extract_stdout_manifestid() {
   extract_stdout_keyvalue "$1" manifestid "$rexp_manifestid"
}

extract_stdout_version() {
   extract_stdout_keyvalue "$1" version "$rexp_version"
}

extract_stdout_secret() {
   extract_stdout_keyvalue "$1" .secret "$rexp_bundlesecret"
}

extract_stdout_BK() {
   extract_stdout_keyvalue "$1" BK "$rexp_bundlekey"
}

extract_manifest() {
   local _var="$1"
   local _manifestfile="$2"
   local _label="$3"
   local _rexp="$4"
   local _value=$($SED -n -e "/^$_label=$_rexp\$/s/^$_label=//p" "$_manifestfile")
   assert --message="$_manifestfile contains valid '$_label=' line" \
          --dump-on-fail="$_manifestfile" \
          [ -n "$_value" ]
   [ -n "$_var" ] && eval $_var="\$_value"
}

extract_manifest_service() {
   extract_manifest "$1" "$2" service "$rexp_service"
}

extract_manifest_id() {
   extract_manifest "$1" "$2" id "$rexp_manifestid"
}

extract_manifest_BK() {
   extract_manifest "$1" "$2" BK "$rexp_bundlekey"
}

extract_manifest_filesize() {
   extract_manifest "$1" "$2" filesize "$rexp_filesize"
}

extract_manifest_filehash() {
   extract_manifest "$1" "$2" filehash "$rexp_filehash"
}

extract_manifest_name() {
   extract_manifest "$1" "$2" name ".*"
}

extract_manifest_version() {
   extract_manifest "$1" "$2" version "$rexp_version"
}

extract_manifest_crypt() {
   extract_manifest "$1" "$2" crypt "$rexp_crypt"
}

compute_filehash() {
   local _filehashvar="$1"
   local _file="$2"
   local _filesizevar="$3"
   local _hash=
   local _size=0
   if [ -s "$_file" ]; then
      local _hash=$($servald rhizome hash file "$_file") || error "$servald failed to compute file hash"
      [ -z "${_hash//[0-9a-fA-F]/}" ] || error "file hash contains non-hex: $_hash"
      [ "${#_hash}" -eq 128 ] || error "file hash incorrect length: $_hash"
      local _size=$(( $(cat "$filename" | wc -c) + 0 ))
   fi
   [ -n "$_filehashvar" ] && eval $_filehashvar="\$_hash"
   [ -n "$_filesizevar" ] && eval $_filesizevar="\$_size"
}

rhizome_http_server_started() {
   local logvar=LOG${1#+}
   $GREP 'RHIZOME HTTP SERVER,.*START.*port=[0-9]' "${!logvar}"
}

get_rhizome_server_port() {
   local _var="$1"
   local _logvar=LOG${2#+}
   local _port=$($SED -n -e '/RHIZOME HTTP SERVER.*START/s/.*port=\([0-9]\{1,\}\).*/\1/p' "${!_logvar}" | $SED -n '$p')
   assert --message="instance $2 Rhizome HTTP server port number is known" [ -n "$_port" ]
   if [ -n "$_var" ]; then
      eval "$_var=\$_port"
      tfw_log "$_var=$_port"
   fi
   return 0
}

# Predicate function:
#  - return true if the file bundles identified by args BID[:VERSION] has been
#    received by all the given instances args +I
#  - does this by examining the server log files of the respective instances
#    for tell-tale INFO messages
bundle_received_by() {
   local -a rexps bundles
   local restart=true
   local arg bid version rexp bundle bundlefile i
   local ret=0
   for arg; do
      case "$arg" in
      +([0-9A-F])?(:+([0-9])))
         $restart && rexps=() bundles=()
         restart=false
         bid="${arg%%:*}"
         matches_rexp "$rexp_manifestid" "$bid" || error "invalid bundle ID: $bid"
         bundles+=("$arg")
         if [ "$bid" = "$arg" ]; then
            rexps+=("RHIZOME ADD MANIFEST service=.* bid=$bid")
         else
            version="${arg#*:}"
            rexps+=("RHIZOME ADD MANIFEST service=.* bid=$bid version=$version")
         fi
         ;;
      +[A-Z])
         push_instance
         tfw_nolog set_instance $arg || return $?
         tfw_nolog assert_servald_server_status running
         for ((i = 0; i < ${#bundles[*]}; ++i)); do
            bundle="${bundles[$i]}"
            rexp="${rexps[$i]}"
            bundledir="$instance_dir/cache/bundles_received"
            bundlefile="$bundledir/$bundle"
            if [ ! -s "$bundlefile" ]; then
               [ -d "$bundledir" ] || mkdir -p "$bundledir" || error "mkdir failed"
               if grep "$rexp" "$instance_servald_log" >"$bundlefile"; then
                  tfw_log "bundle $bundle received by instance +$instance_name"
               else
                  ret=1
               fi
            fi
         done
         restart=true
         pop_instance
         ;;
      --stderr)
         for ((i = 0; i < ${#bundles[*]}; ++i)); do
            bundle="${bundles[$i]}"
            rexp="${rexps[$i]}"
            if replayStderr | grep "$rexp" >/dev/null; then
               tfw_log "bundle $bundle received by ($executed)"
            else
               ret=1
            fi
         done
         restart=true
         ;;
      *)
         error "invalid argument: $arg"
         return 1
         ;;
      esac
   done
   return $ret
}

extract_manifest_vars() {
   local manifest="${1?}"
   extract_manifest_id BID "$manifest"
   extract_manifest_version VERSION "$manifest"
   extract_manifest_filesize FILESIZE "$manifest"
   FILEHASH=
   if [ "$FILESIZE" != '0' ]; then
      extract_manifest_filehash FILEHASH "$manifest"
   fi
}

rhizome_add_file() {
   local name="$1"
   local size="${2:-64}"
   rhizome_add_files --size="$size" "$name"
   extract_manifest_vars "$name.manifest"
}

rhizome_add_files() {
   local size=64
   local sidvar="SID$instance_name"
   local -a names=()
   for arg; do
      case "$arg" in
      --size=*)
         size="${arg##*=}"
         ;;
      *)
         local name="$arg"
         [ -e "$name" ] || create_file "$name" $size
         executeOk_servald rhizome add file "${!sidvar}" "$name" "$name.manifest"
         names+=("$name")
      esac
   done
   executeOk_servald rhizome list
   assert_rhizome_list --fromhere=1 --author="${!sidvar}" "${names[@]}" --and-others
}

rhizome_update_file() {
   local orig_name="$1"
   local new_name="$2"
   [ -e "$new_name" ] || echo 'File $new_name' >"$new_name"
   local sidvar="SID$instance_name"
   [ "$new_name" != "$orig_name" ] && cp "$orig_name.manifest" "$new_name.manifest"
   $SED -i -e '/^date=/d;/^filehash=/d;/^filesize=/d;/^version=/d;/^name=/d' "$new_name.manifest"
   executeOk_servald rhizome add file "${!sidvar}" "$new_name" "$new_name.manifest"
   executeOk_servald rhizome list
   assert_rhizome_list --fromhere=1 "$new_name"
   extract_manifest_vars "$new_name.manifest"
}

assert_rhizome_received() {
   [ $# -ne 0 ] || error "missing arguments"
   local name
   local _id
   for name; do
      if [ -s "$name" ]; then
         extract_manifest_id _id "$name.manifest"
         executeOk_servald rhizome extract file "$_id" extracted
         assert cmp "$name" extracted
      fi
   done
}

