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
rexp_bundlekey='[0-9a-fA-F]\{128\}'
rexp_bundlesecret="$rexp_bundlekey"
rexp_filehash='[0-9a-fA-F]\{128\}'
rexp_filesize='[0-9]\{1,\}'
rexp_version='[0-9]\{1,\}'
rexp_date='[0-9]\{1,\}'

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
   assertStdoutIs --stderr --line=1 -e '12\n'
   assertStdoutIs --stderr --line=2 -e 'service:id:version:date:.inserttime:.author:.fromhere:filesize:filehash:sender:recipient:name\n'
   local filename
   local exactly=true
   local re__inserttime="$rexp_date"
   local re__fromhere='[01]'
   local re__author="\($rexp_sid\)\{0,1\}"
   local files=0
   for filename; do
      case "$filename" in
      --fromhere=*) re__fromhere="${filename#*=}";;
      --author=*) re__author="${filename#*=}";;
      --and-others) exactly=false;;
      --*) error "unsupported option: $filename";;
      *)
         unpack_manifest_for_grep "$filename"
         assertStdoutGrep --stderr --matches=1 "^$re_service:$re_manifestid:$re_version:$re_date:$re__inserttime:$re__author:$re__fromhere:$re_filesize:$re_filehash:$re_sender:$re_recipient:$re_name\$"
         let files+=1
         ;;
      esac
   done
   $exactly && assertStdoutLineCount --stderr '==' $(($files + 2))
}

assert_stdout_add_file() {
   [ $# -ge 1 ] || error "missing filename arg"
   local filename="${1}"
   shift
   unpack_manifest_for_grep "$filename"
   opt_name=false
   if replayStdout | $GREP -q '^service:file$'; then
      opt_name=true
   fi
   fieldnames='service|manifestid|secret|filesize|filehash|name'
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
   ${opt_secret:-true} && assertStdoutGrep --matches=1 "^secret:$re_secret\$"
   ${opt_filesize:-true} && assertStdoutGrep --matches=1 "^filesize:$re_filesize\$"
   if replayStdout | $GREP -q '^filesize:0$'; then
      assertStdoutGrep --matches=0 "^filehash:"
   else
      ${opt_filehash:-true} && assertStdoutGrep --matches=1 "^filehash:$re_filehash\$"
   fi
}

assert_stdout_import_bundle() {
   # Output of "import bundle" is the same as "add file" but without the secret.
   assert_stdout_add_file "$@" '!secret'
}

unpack_manifest_for_grep() {
   local filename="$1"
   re_service="$rexp_service"
   re_manifestid="$rexp_manifestid"
   re_version="$rexp_version"
   re_date="$rexp_date"
   re_secret="$rexp_bundlesecret"
   re_sender="\($rexp_sid\)\{0,1\}"
   re_recipient="\($rexp_sid\)\{0,1\}"
   re_name=$(escape_grep_basic "${filename##*/}")
   local filesize=$($SED -n -e '/^filesize=/s///p' "$filename.manifest" 2>/dev/null)
   if [ "$filesize" = 0 ]; then
      re_filesize=0
      re_filehash=
      re_name="\($re_name\)\{0,1\}"
   else
      re_filesize=$(( $(cat "$filename" | wc -c) + 0 ))
      compute_filehash re_filehash "$filename"
   fi
   # If there is a manifest file that looks like it matches this payload
   # file, then use its file hash to check the rhizome list '' output.
   local filehash=$($SED -n -e '/^filehash=/s///p' "$filename.manifest" 2>/dev/null)
   if [ "$filehash" = "$re_filehash" ]; then
      re_service=$($SED -n -e '/^service=/s///p' "$filename.manifest")
      re_service=$(escape_grep_basic "$re_service")
      re_manifestid=$($SED -n -e '/^id=/s///p' "$filename.manifest")
      re_version=$($SED -n -e '/^version=/s///p' "$filename.manifest")
      re_date=$($SED -n -e '/^date=/s///p' "$filename.manifest")
      re_sender=$($SED -n -e '/^sender=/s///p' "$filename.manifest")
      re_recipient=$($SED -n -e '/^recipient=/s///p' "$filename.manifest")
      case "$re_service" in
      file)
         re_name=$($SED -n -e '/^name=/s///p' "$filename.manifest")
         re_name=$(escape_grep_basic "$re_name")
         ;;
      *)
         re_name=
         re_sender="$rexp_sid"
         re_recipient="$rexp_sid"
         ;;
      esac
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

extract_stdout_secret() {
   extract_stdout_keyvalue "$1" secret "$rexp_bundlesecret"
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

compute_filehash() {
   local _var="$1"
   local _file="$2"
   local _hash=$($servald rhizome hash file "$_file") || error "$servald failed to compute file hash"
   [ -z "${_hash//[0-9a-fA-F]/}" ] || error "file hash contains non-hex: $_hash"
   [ "${#_hash}" -eq 128 ] || error "file hash incorrect length: $_hash"
   [ -n "$_var" ] && eval $_var="\$_hash"
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
